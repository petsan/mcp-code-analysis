# MCP Code Analysis Server (SSE transport)

A FastAPI/Starlette web server exposing a Model Context Protocol (MCP) server
over HTTP Server-Sent Events, with two tools backed by `ruff` and `semgrep`:

- `analyze_code_snippet(code_content, filename)` — scans a raw source string.
- `analyze_github_repo(repo_url)` — shallow-clones a **public** GitHub repo and scans it.

## Endpoints

- `GET /sse` — opens the SSE stream; the server immediately emits an `endpoint`
  event telling the client where to POST JSON-RPC messages
  (`/messages/?session_id=...`).
- `POST /messages/` — client sends JSON-RPC tool calls here; responses come
  back over the open `/sse` stream, per the MCP spec.
- `GET /healthz` — plain liveness check for your hosting platform.

## Run locally

```bash
pip install -r requirements.txt
export BEARER_TOKENS="dev-token-please-change"
python main.py                 # listens on :8000 (or $PORT)
curl http://localhost:8000/healthz
curl -H "Authorization: Bearer dev-token-please-change" http://localhost:8000/sse
```

Without `BEARER_TOKENS` set, the server refuses every request except
`/healthz` with a `503` — it will not silently run open. For quick local
testing without a token, set `ALLOW_NO_AUTH=1` instead of `BEARER_TOKENS`.

## Deploy

```bash
docker build -t mcp-code-analysis .
docker run -p 8000:8000 mcp-code-analysis
```

Works as-is on Render, Railway, Fly.io, or an EC2 instance with the container
runtime of your choice. Set `PORT` if your platform injects a different port.

## Security model — read before exposing this publicly

This server does **not** execute untrusted code. `ruff` and `semgrep` are
static analyzers: they parse and pattern-match text, they never run it. That
is what makes it reasonable to hand them untrusted input directly inside a
plain subprocess, with no container-per-request sandbox.

### Access control

Two independent layers gate every request except `/healthz`:

1. **Bearer-token authentication** (`BearerAuthMiddleware` in `main.py`) —
   a raw ASGI middleware, not `BaseHTTPMiddleware`, specifically because
   `BaseHTTPMiddleware` is known to interfere with long-lived streaming
   responses; this was confirmed safe against a real `/sse` stream during
   testing. It rejects any request to `/sse` or `/messages/` that doesn't
   carry `Authorization: Bearer <token>` matching one of `BEARER_TOKENS`
   (comma-separated, so you can rotate tokens with zero downtime), **before**
   the request reaches the SSE transport, the MCP session, or any subprocess.
   An unauthorized caller cannot consume a connection slot, spawn a `ruff`/
   `semgrep` process, or trigger a `git clone` — the request is turned away
   at the door.

   - Set `BEARER_TOKENS` in production. If it's unset, the server responds
     `503` to everything except `/healthz` rather than running open — this
     is deliberate fail-closed behavior so a missing env var can't silently
     ship an unauthenticated server.
   - For local development only, set `ALLOW_NO_AUTH=1` to skip the token
     check entirely.

2. **Host/Origin validation** (`TransportSecuritySettings`, native to the
   `mcp` SDK) — mitigates DNS-rebinding attacks, where a malicious webpage
   running in a victim's browser tries to reach this server via `localhost`
   or an internal hostname. Set `ALLOWED_HOSTS` to a comma-separated allow-
   list (e.g. `myapp.onrender.com`) to enable it; confirmed by testing that
   a mismatched `Host` header is rejected with `421` even when the bearer
   token is valid. Left unset by default since most platform routers
   (Render, Railway, etc.) already terminate on a fixed hostname before
   proxying here, making this a defense-in-depth layer rather than the
   primary control — the bearer token is the primary control.

   Known cosmetic side effect: a request rejected by this layer causes the
   underlying SDK to raise a `ValueError` after it has already sent the
   rejection response, which uvicorn logs as an "Exception in ASGI
   application" traceback. Confirmed by testing that this does not corrupt
   the response, affect the client, or impact subsequent requests — it's
   inherent to the pinned SDK's control flow (see the comment above
   `handle_sse` in `main.py` for why it's intentionally left unhandled
   rather than "fixed" in a way that risks a worse bug).

What's actually enforced beyond access control:

- **Ephemeral files only.** Snippets are written to a fresh `tempfile.mkdtemp()`
  directory, scanned, and deleted in a `finally:` block — including on
  exceptions and timeouts.
- **Filename allow-list.** `filename` must match `^[A-Za-z0-9_.\-]{1,255}$`
  and must not contain `..` — no path traversal, no absolute paths.
- **Repo URL allow-list.** `repo_url` must match
  `https://github.com/<owner>/<repo>` exactly — no other hosts, no SSH URLs,
  no query params that could smuggle git options.
- **Clone hardening.** Clones use `--depth=1 --single-branch --no-tags` and
  `-c core.hooksPath=/dev/null`, and `.git/` is deleted immediately after
  clone — before any scanner touches the checkout — so no hook, alternate, or
  packed-ref content is ever reachable by the analyzers.
- **Size/file-count caps.** `MAX_REPO_FILES` (default 2000) and
  `MAX_REPO_BYTES` (default 200MB) are checked before scanning; oversized
  repos are rejected outright.
- **Timeouts.** Every subprocess (clone, ruff, semgrep) runs under
  `asyncio.wait_for` with a hard timeout (`SUBPROCESS_TIMEOUT_SECONDS`,
  `CLONE_TIMEOUT_SECONDS`, default 30s each) and is killed on expiry.
- **Non-root container user.** The Docker image drops to uid 1000 before
  running the app.

### What this is *not*

This is process-level isolation, not sandbox-level isolation — there is no
gVisor/Firecracker/VM boundary between the analyzer subprocess and the host.
That's an acceptable trade-off for two static analyzers, but:

- **Do not add a "run this code" / arbitrary-execution tool** to this server
  without first putting a real per-request sandbox in front of it. The
  ephemeral-tempfile pattern used here is not sufficient once the payload is
  actually executed rather than parsed.
- Semgrep runs against a **bundled, fully offline ruleset** (`semgrep-rules.yml`)
  by default — no outbound network access required. Every named registry
  config (`auto`, `p/ci`, `p/security-audit`, etc.) requires fetching from
  semgrep.dev at scan time; semgrep ships with no rulesets built in. Extend
  `semgrep-rules.yml` with more rules, or set `SEMGREP_CONFIG` to a registry
  name if outbound access is available and you want semgrep's maintained
  rulesets instead.
- There's no per-tool authorization (e.g. different tokens with different
  scopes) — every valid bearer token can call every tool. If you need
  per-caller restrictions, add that logic in `BearerAuthMiddleware` or in
  `call_tool()`.
- The per-request MCP session pattern (`app_server.run()` invoked inside
  `handle_sse`) follows the SDK's own documented example and is correct for
  this transport, where each SSE connection is an independent session with
  no shared server-loop state. Graceful shutdown behavior under SIGTERM
  during a platform redeploy was not specifically load-tested here — if
  your platform does rolling deploys under real traffic, verify in-flight
  SSE connections drain the way you expect.

## Tested

- Full auth matrix verified with real HTTP requests against the running
  server: `/healthz` open with no token; `/sse` and `/messages/` return
  `401` with no token, wrong token, or a malformed `Authorization` header;
  both entries in a comma-separated `BEARER_TOKENS` list accepted
  (confirms rotation works); server returns `503` on every non-health route
  when `BEARER_TOKENS` is unset and `ALLOW_NO_AUTH` isn't set (fail-closed,
  not fail-open); `ALLOW_NO_AUTH=1` correctly bypasses the check for local
  dev.
- `ALLOWED_HOSTS` / `TransportSecuritySettings` verified with a real
  mismatched `Host` header — rejected with `421` even with a valid bearer
  token; a matching `Host` header is accepted.
- Confirmed the real SSE stream still completes its handshake
  (`event: endpoint`) correctly with the auth middleware in front of it —
  the middleware doesn't break or buffer the streaming response.

- `main.py` imports cleanly and both tools were exercised directly (valid
  input, path-traversal filename rejection, reserved-filename rejection,
  non-GitHub URL rejection, temp directory cleanup verified).
- The live ASGI app was booted with `uvicorn` and `GET /healthz` and
  `GET /sse` (confirming the SSE `endpoint` handshake) were verified over
  real HTTP.
- Both `ruff` and `semgrep` were run for real against deliberately flawed
  code, using the bundled offline ruleset — confirmed real findings (shell
  injection, hardcoded credential, unused import, etc.) parse correctly.
- Confirmed ruff is skipped entirely for non-`.py` files/single-file scans,
  and only targets `.py` files within a repo scan — this avoids a real bug
  found during testing where ruff reports a spurious `E902` "finding" on
  binary/non-UTF8 files it never actually linted.
- Confirmed semgrep's `errors[]` field (e.g. a failed rule-config download,
  which it reports with exit code 0) is surfaced as a scan error rather than
  silently producing an empty, seemingly-clean findings list.
- Confirmed semgrep exits cleanly (code 0, empty `results`/`errors`) when
  scanning a file type outside the bundled ruleset's `languages:` list
  (e.g. `.md`, `.yaml`, a plain `Dockerfile`) — it skips unrecognized
  files rather than erroring, so no extra flag is needed for that case.
- Confirmed ruff's directory-scan mode (used for repo scans) discovers and
  lints only `.py`/`.pyi` files on its own and silently ignores everything
  else in the tree, including raw binary content — tested with a mixed
  directory of `.py`, `.md`, and binary files. Repo scans pass the
  directory straight to ruff rather than enumerating file paths, which also
  avoids any risk of hitting an OS argument-length limit on very large repos.
- Package pins in `requirements.txt` were confirmed to exist and install
  from PyPI.
- **Not tested here:** the Docker build itself (no `docker` binary available
  in this sandbox) — every dependency it installs was verified individually
  instead.
