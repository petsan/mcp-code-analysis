"""
MCP Code Analysis Server — SSE transport over FastAPI/Starlette.

Exposes two tools over the Model Context Protocol:
  - analyze_code_snippet: lint/scan a raw source string with Ruff + Semgrep
  - analyze_github_repo:  shallow-clone a *public* GitHub repo and scan it

SECURITY NOTE (read this before deploying):
This process runs Ruff and Semgrep as subprocesses with a wall-clock timeout.
That is process-level isolation, not sandbox-level isolation. Ruff and Semgrep
are static analyzers — they parse and pattern-match source text, they do not
execute it — which is what makes running them directly on untrusted input a
reasonable risk to take. This design does NOT execute untrusted code and must
never be extended to add a "run this snippet" tool without a real sandbox
(gVisor, Firecracker, a container-per-request model, etc).

The GitHub-repo tool clones arbitrary public repositories. Cloning itself can
still be abused (huge repos, git attacks, malicious .gitattributes/hooks), so
we clone with hooks disabled, no submodules, depth=1, and hard caps on repo
size and file count before any scanner ever touches the checkout.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path
from typing import Any

import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.server.sse import SseServerTransport
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response
from starlette.routing import Mount, Route
from starlette.types import ASGIApp, Receive, Scope, Send

# --------------------------------------------------------------------------
# Configuration (override via environment variables at deploy time)
# --------------------------------------------------------------------------

SUBPROCESS_TIMEOUT_SECONDS = int(os.environ.get("SUBPROCESS_TIMEOUT_SECONDS", "30"))
CLONE_TIMEOUT_SECONDS = int(os.environ.get("CLONE_TIMEOUT_SECONDS", "30"))
MAX_SNIPPET_BYTES = int(os.environ.get("MAX_SNIPPET_BYTES", str(2 * 1024 * 1024)))  # 2 MiB
MAX_REPO_FILES = int(os.environ.get("MAX_REPO_FILES", "2000"))
MAX_REPO_BYTES = int(os.environ.get("MAX_REPO_BYTES", str(200 * 1024 * 1024)))  # 200 MiB
# Every named semgrep ruleset ("auto", "p/ci", "p/security-audit", etc.) is
# fetched from semgrep's registry at scan time — semgrep ships with NO
# rulesets bundled locally (confirmed by inspecting the installed package).
# The only network-free option is a rules file you author and bake into the
# image yourself. Default to "auto" and document this requirement clearly,
# rather than pretending a "local" option exists that doesn't.
SEMGREP_CONFIG = os.environ.get("SEMGREP_CONFIG", "auto")

# --------------------------------------------------------------------------
# Access control
# --------------------------------------------------------------------------
# Bearer token(s) required to reach /sse or /messages/. Comma-separated list
# supports zero-downtime rotation (add the new token, redeploy, remove the
# old one). Leave BEARER_TOKENS unset only for local development — an unset
# value disables auth entirely and is refused at startup in production-like
# environments unless ALLOW_NO_AUTH=1 is explicitly set, so a missing env
# var can't silently ship an open server.
_raw_tokens = os.environ.get("BEARER_TOKENS", "")
BEARER_TOKENS = {t.strip() for t in _raw_tokens.split(",") if t.strip()}
ALLOW_NO_AUTH = os.environ.get("ALLOW_NO_AUTH", "0") == "1"

# Comma-separated allow-list of Host headers, e.g. "myapp.onrender.com".
# Leave unset to skip host validation (fine behind most platform routers,
# which already terminate TLS on a fixed hostname before proxying here).
_allowed_hosts_raw = os.environ.get("ALLOWED_HOSTS", "")
ALLOWED_HOSTS = [h.strip() for h in _allowed_hosts_raw.split(",") if h.strip()] or None
# Set to a path (e.g. "/app/semgrep-rules.yml") to use a fully offline
# ruleset baked into the Docker image. See README for a starter rules file.

# Only allow filenames that look like a plain relative filename — no path
# traversal, no absolute paths, no embedded separators.
_SAFE_FILENAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,255}$")

# Only allow github.com HTTPS URLs of the form https://github.com/<owner>/<repo>(.git)?
_GITHUB_URL_RE = re.compile(
    r"^https://github\.com/(?P<owner>[A-Za-z0-9_.\-]+)/(?P<repo>[A-Za-z0-9_.\-]+?)(?:\.git)?/?$"
)

_WINDOWS_RESERVED_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mcp-code-analysis")


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


class InputValidationError(ValueError):
    """Raised when a tool argument fails validation. Caught and reported as a tool error."""


def _validate_filename(filename: str) -> str:
    name = filename.strip()
    if not _SAFE_FILENAME_RE.match(name):
        raise InputValidationError(
            "filename must be a plain relative filename (letters, digits, '.', '_', '-'), "
            "e.g. 'app.py' — no paths or path separators are allowed."
        )
    if ".." in name:
        raise InputValidationError("filename may not contain '..'")
    # Defense in depth: reject Windows reserved device names, in case this
    # ever runs on a Windows host (the regex above already excludes path
    # separators and null bytes, which is what matters on Linux/macOS).
    stem = name.split(".", 1)[0].upper()
    if stem in _WINDOWS_RESERVED_NAMES:
        raise InputValidationError(f"filename '{name}' is a reserved device name")
    return name


def _validate_github_url(url: str) -> tuple[str, str]:
    match = _GITHUB_URL_RE.match(url.strip())
    if not match:
        raise InputValidationError(
            "repo_url must be a public GitHub HTTPS URL of the form "
            "'https://github.com/<owner>/<repo>'."
        )
    return match.group("owner"), match.group("repo")


async def _run_subprocess(
    args: list[str], cwd: str | None = None, timeout: int = SUBPROCESS_TIMEOUT_SECONDS
) -> tuple[int, str, str]:
    """Run a subprocess with a hard timeout. Returns (returncode, stdout, stderr).

    Never raises on nonzero exit (that's normal for linters that found issues);
    raises only if the binary is missing or the timeout is exceeded, both of
    which are converted to a structured error by the caller.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            cwd=cwd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(f"required binary not found: {args[0]}") from exc

    try:
        stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise TimeoutError(f"'{' '.join(args)}' exceeded {timeout}s timeout and was killed")

    return proc.returncode, stdout_b.decode("utf-8", "replace"), stderr_b.decode("utf-8", "replace")


def _parse_ruff_json(stdout: str) -> list[dict[str, Any]]:
    try:
        data = json.loads(stdout) if stdout.strip() else []
    except json.JSONDecodeError:
        return [{"parse_error": "ruff output was not valid JSON", "raw": stdout[:2000]}]
    findings = []
    for item in data:
        findings.append(
            {
                "tool": "ruff",
                "rule": item.get("code"),
                "message": item.get("message"),
                "filename": item.get("filename"),
                "line": (item.get("location") or {}).get("row"),
                "column": (item.get("location") or {}).get("column"),
                "severity": "warning",
            }
        )
    return findings


def _parse_semgrep_json(stdout: str) -> tuple[list[dict[str, Any]], list[str]]:
    """Returns (findings, scan_errors). scan_errors surfaces semgrep's own
    `errors[]` array — e.g. a failed rule-config download — which semgrep
    reports with exit code 0, so callers must not treat "no findings" as
    "clean scan" without also checking this.
    """
    try:
        data = json.loads(stdout) if stdout.strip() else {}
    except json.JSONDecodeError:
        return (
            [{"parse_error": "semgrep output was not valid JSON", "raw": stdout[:2000]}],
            [],
        )
    findings = []
    for res in data.get("results", []):
        findings.append(
            {
                "tool": "semgrep",
                "rule": res.get("check_id"),
                "message": (res.get("extra") or {}).get("message"),
                "filename": res.get("path"),
                "line": (res.get("start") or {}).get("line"),
                "column": (res.get("start") or {}).get("col"),
                "severity": (res.get("extra") or {}).get("severity", "warning").lower(),
            }
        )
    scan_errors = [
        f"{e.get('type', 'SemgrepError')}: {e.get('message', 'unknown error')}"
        for e in data.get("errors", [])
    ]
    return findings, scan_errors


async def _scan_path(target_path: str, single_file: bool) -> dict[str, Any]:
    """Run ruff + semgrep against a file or directory and merge results.

    Each scanner is invoked independently so that one being unavailable/failing
    does not prevent the other's results from being returned.
    """
    result: dict[str, Any] = {"findings": [], "errors": []}
    target = Path(target_path)

    # --- ruff (Python-only) ---
    # A lone non-.py file explicitly passed as a target triggers a real bug:
    # on non-UTF8/binary content ruff emits a fake "E902 stream did not
    # contain valid UTF-8" finding as if it had actually linted the file —
    # confirmed by testing. So single-file scans skip ruff entirely unless
    # the extension is .py.
    # For directory (repo) scans, ruff's default directory-walk behavior
    # already discovers and lints only .py/.pyi files and silently ignores
    # everything else, including raw binary — confirmed by testing a
    # directory containing .md and binary files alongside .py, which
    # produced zero false findings. So we pass the directory straight
    # through rather than building an explicit file list (which doesn't
    # add safety here, and would risk an OS argv-length limit on very large
    # repos for no benefit).
    run_ruff = True
    if single_file:
        if target.suffix != ".py":
            run_ruff = False
    else:
        if not any(target.rglob("*.py")):
            run_ruff = False  # skip the subprocess entirely if there's nothing for ruff to lint

    if run_ruff:
        # Scan targets are temporary; avoid writing a cache in the app directory.
        ruff_args = ["ruff", "check", "--no-cache", "--output-format=json", target_path]
        try:
            rc, out, err = await _run_subprocess(ruff_args, timeout=SUBPROCESS_TIMEOUT_SECONDS)
            if rc not in (0, 1):  # 0 = clean, 1 = findings; anything else is a real error
                result["errors"].append(
                    {"tool": "ruff", "error": err.strip()[:2000] or out.strip()[:2000] or f"exit code {rc}"}
                )
            else:
                result["findings"].extend(_parse_ruff_json(out))
        except (RuntimeError, TimeoutError) as exc:
            result["errors"].append({"tool": "ruff", "error": str(exc)})

    # --- semgrep (multi-language; ruleset controlled by SEMGREP_CONFIG) ---
    semgrep_args = [
        "semgrep",
        "scan",
        f"--config={SEMGREP_CONFIG}",
        "--json",
        "--quiet",
        "--timeout",
        str(max(1, SUBPROCESS_TIMEOUT_SECONDS - 5)),
        target_path,
    ]
    try:
        rc, out, err = await _run_subprocess(semgrep_args, timeout=SUBPROCESS_TIMEOUT_SECONDS)
        if rc not in (0, 1):
            result["errors"].append(
                {"tool": "semgrep", "error": err.strip()[:2000] or out.strip()[:2000] or f"exit code {rc}"}
            )
        else:
            semgrep_findings, semgrep_scan_errors = _parse_semgrep_json(out)
            result["findings"].extend(semgrep_findings)
            # semgrep can exit 0 while still reporting internal errors (e.g. a
            # rule-config download failure) inside its own errors[] array —
            # surface those explicitly so an empty findings list is never
            # mistaken for a clean, fully-completed scan.
            for scan_err in semgrep_scan_errors:
                result["errors"].append({"tool": "semgrep", "error": scan_err})
    except (RuntimeError, TimeoutError) as exc:
        result["errors"].append({"tool": "semgrep", "error": str(exc)})

    result["finding_count"] = len(result["findings"])
    return result


def _dir_stats(root: Path) -> tuple[int, int]:
    """Return (file_count, total_bytes) for a directory tree."""
    file_count = 0
    total_bytes = 0
    for p in root.rglob("*"):
        if p.is_file():
            file_count += 1
            try:
                total_bytes += p.stat().st_size
            except OSError:
                pass
    return file_count, total_bytes


# --------------------------------------------------------------------------
# MCP tool implementations
# --------------------------------------------------------------------------


async def analyze_code_snippet(code_content: str, filename: str) -> dict[str, Any]:
    if not isinstance(code_content, str) or code_content == "":
        raise InputValidationError("code_content is required and must be a non-empty string")
    if len(code_content.encode("utf-8", "replace")) > MAX_SNIPPET_BYTES:
        raise InputValidationError(f"code_content exceeds the {MAX_SNIPPET_BYTES}-byte limit")

    safe_name = _validate_filename(filename)

    # Ephemeral, process-isolated temp dir. Never reuse; always deleted in finally.
    tmp_dir = tempfile.mkdtemp(prefix="mcp-snippet-")
    try:
        tmp_path = Path(tmp_dir) / safe_name
        tmp_path.write_text(code_content, encoding="utf-8")

        scan_result = await _scan_path(str(tmp_path), single_file=True)
        return {
            "filename": safe_name,
            **scan_result,
        }
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


async def analyze_github_repo(repo_url: str) -> dict[str, Any]:
    owner, repo = _validate_github_url(repo_url)
    clone_url = f"https://github.com/{owner}/{repo}.git"

    tmp_dir = tempfile.mkdtemp(prefix="mcp-repo-")
    try:
        clone_args = [
            "git",
            "clone",
            "--depth=1",
            "--single-branch",
            "--no-tags",
            "-c",
            "core.hooksPath=/dev/null",  # disable any hook execution
            clone_url,
            tmp_dir + "/checkout",
        ]
        rc, out, err = await _run_subprocess(clone_args, timeout=CLONE_TIMEOUT_SECONDS)
        if rc != 0:
            raise InputValidationError(f"git clone failed: {err.strip()[:1000] or 'unknown error'}")

        checkout_path = Path(tmp_dir) / "checkout"
        # Remove .git entirely — we only want working-tree content, and this
        # keeps hooks/config/objects out of reach of the scanners.
        shutil.rmtree(checkout_path / ".git", ignore_errors=True)

        file_count, total_bytes = _dir_stats(checkout_path)
        if file_count > MAX_REPO_FILES:
            raise InputValidationError(
                f"repository has {file_count} files, exceeding the {MAX_REPO_FILES}-file limit"
            )
        if total_bytes > MAX_REPO_BYTES:
            raise InputValidationError(
                f"repository is {total_bytes} bytes, exceeding the {MAX_REPO_BYTES}-byte limit"
            )

        scan_result = await _scan_path(str(checkout_path), single_file=False)
        return {
            "repo": f"{owner}/{repo}",
            "file_count": file_count,
            "total_bytes": total_bytes,
            **scan_result,
        }
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


# --------------------------------------------------------------------------
# MCP server wiring
# --------------------------------------------------------------------------

app_server: Server = Server("code-analysis-server")

TOOLS: list[types.Tool] = [
    types.Tool(
        name="analyze_code_snippet",
        description=(
            "Analyze a raw source-code string for lint and security issues using Ruff and "
            "Semgrep. The code is written to an ephemeral temp file, scanned, and deleted "
            "immediately after. Use this for reviewing a snippet the user pastes directly — "
            "not for arbitrary filesystem paths."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "code_content": {
                    "type": "string",
                    "description": "The raw source code to analyze.",
                },
                "filename": {
                    "type": "string",
                    "description": (
                        "Virtual filename used only to select the correct language parser "
                        "(e.g. 'app.py', 'server.js'). Must be a plain filename, no path "
                        "separators."
                    ),
                },
            },
            "required": ["code_content", "filename"],
        },
    ),
    types.Tool(
        name="analyze_github_repo",
        description=(
            "Shallow-clone a PUBLIC GitHub repository and scan it with Ruff and Semgrep. "
            "Subject to file-count and total-size caps; private repos and non-GitHub URLs "
            "are rejected."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "repo_url": {
                    "type": "string",
                    "description": "Public repo URL, e.g. 'https://github.com/owner/repo'.",
                },
            },
            "required": ["repo_url"],
        },
    ),
]


@app_server.list_tools()
async def list_tools() -> list[types.Tool]:
    return TOOLS


@app_server.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[types.TextContent]:
    try:
        if name == "analyze_code_snippet":
            result = await analyze_code_snippet(
                code_content=arguments.get("code_content", ""),
                filename=arguments.get("filename", ""),
            )
        elif name == "analyze_github_repo":
            result = await analyze_github_repo(repo_url=arguments.get("repo_url", ""))
        else:
            raise InputValidationError(f"unknown tool: {name}")

        return [types.TextContent(type="text", text=json.dumps(result, indent=2))]

    except InputValidationError as exc:
        logger.info("validation error in tool %s: %s", name, exc)
        return [types.TextContent(type="text", text=json.dumps({"error": str(exc)}, indent=2))]
    except Exception as exc:  # noqa: BLE001 — convert any unexpected failure into a tool error
        logger.exception("unexpected error in tool %s", name)
        return [
            types.TextContent(
                type="text",
                text=json.dumps({"error": f"internal error: {exc}"}, indent=2),
            )
        ]


# --------------------------------------------------------------------------
# ASGI app: SSE transport wiring
# --------------------------------------------------------------------------

# TransportSecuritySettings validates the Host/Origin headers on every
# request before it reaches the route — mitigates DNS-rebinding attacks
# where a malicious webpage's script tries to hit this server via the
# victim's browser using "localhost" or an internal hostname. This is
# separate from and complementary to the bearer-token check below: this
# validates *where the request claims to come from*, the token validates
# *who is allowed to make it*.
_security_settings = TransportSecuritySettings(
    enable_dns_rebinding_protection=bool(ALLOWED_HOSTS),
    allowed_hosts=ALLOWED_HOSTS or [],
)

sse_transport = SseServerTransport("/messages/", security_settings=_security_settings)


class BearerAuthMiddleware:
    """Raw ASGI middleware — rejects unauthenticated requests before they
    reach the SSE route or the MCP message handler, so an unauthorized
    caller can't consume a connection slot, a subprocess, or CPU/memory on
    this server at all.

    Written as raw ASGI (not BaseHTTPMiddleware) deliberately: BaseHTTPMiddleware
    buffers/wraps the response through an internal stream, which is a known
    source of trouble with long-lived streaming responses like SSE. Rejecting
    unauthenticated requests before the app is invoked at all sidesteps that
    entirely — confirmed against a real streaming /sse connection in testing.
    """

    def __init__(self, app: ASGIApp, tokens: set[str], allow_no_auth: bool) -> None:
        self.app = app
        self.tokens = tokens
        self.allow_no_auth = allow_no_auth

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        # Health check stays open so hosting platforms can probe liveness
        # without needing a credential.
        if path == "/healthz":
            await self.app(scope, receive, send)
            return

        if not self.tokens:
            if self.allow_no_auth:
                await self.app(scope, receive, send)
                return
            response = PlainTextResponse(
                "Server misconfigured: no BEARER_TOKENS set and ALLOW_NO_AUTH is not enabled. "
                "Refusing all requests rather than running open.",
                status_code=503,
            )
            await response(scope, receive, send)
            return

        headers = dict(scope.get("headers") or [])
        auth_header = headers.get(b"authorization", b"").decode("latin-1")
        token = None
        if auth_header.lower().startswith("bearer "):
            token = auth_header[7:].strip()

        if token is None or token not in self.tokens:
            logger.info("rejected unauthenticated request to %s", path)
            response = PlainTextResponse(
                "Unauthorized: missing or invalid bearer token.",
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )
            await response(scope, receive, send)
            return

        await self.app(scope, receive, send)


async def handle_sse(request: Request) -> Response:
    async with sse_transport.connect_sse(request.scope, request.receive, request._send) as (
        read_stream,
        write_stream,
    ):
        await app_server.run(
            read_stream,
            write_stream,
            app_server.create_initialization_options(),
        )
    # Required: return an (unused) Response to avoid a NoneType error on client disconnect.
    #
    # Note: when TransportSecuritySettings rejects a request (bad Host/Origin
    # header), connect_sse() writes the rejection response directly to the
    # ASGI `send` channel and then raises ValueError purely to unwind this
    # `async with` block — matching the SDK's own documented usage (see
    # mcp/server/sse.py's module docstring, which does not catch it either).
    # That ValueError propagates out of this function and uvicorn logs an
    # "Exception in ASGI application" traceback for it. Confirmed by testing:
    # this is cosmetic — the client still receives the correct rejection
    # status code, and the connection is cleanly closed either way; it does
    # not corrupt the response or affect subsequent requests. An earlier
    # attempt to catch and suppress this ValueError here caused a *worse*
    # bug (a second, invalid response send after the first had already
    # completed), so the exception is deliberately left unhandled — the
    # log noise is the better trade-off. If this log noise matters for your
    # alerting setup, filter on the "Request validation failed" message.
    return Response()


async def health(_request: Request) -> JSONResponse:
    return JSONResponse({"status": "ok", "service": "mcp-code-analysis-server"})


starlette_app = Starlette(
    routes=[
        Route("/sse", endpoint=handle_sse, methods=["GET"]),
        Mount("/messages/", app=sse_transport.handle_post_message),
        Route("/healthz", endpoint=health, methods=["GET"]),
    ]
)
starlette_app.add_middleware(BearerAuthMiddleware, tokens=BEARER_TOKENS, allow_no_auth=ALLOW_NO_AUTH)


if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run(starlette_app, host="0.0.0.0", port=port)
