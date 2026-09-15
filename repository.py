"""Fetch one GitHub snapshot with request-scoped credentials."""

import base64
import os
import re

from tool_logging import run_logged_subprocess


class RepositoryError(ValueError):
    pass


def validate_commit(commit):
    if not isinstance(commit, str):
        raise RepositoryError("commit_hash must be a string")
    commit = commit.strip()
    if commit and not re.fullmatch(r"[0-9a-fA-F]{40}", commit):
        raise RepositoryError("Use the full 40-character commit hash, or leave it blank for the default branch.")
    return commit.lower()


def git_environment(token):
    if not isinstance(token, str) or len(token) > 1024 or any(c.isspace() for c in token):
        raise RepositoryError("github_token must be a token without whitespace")
    env = {k: v for k, v in os.environ.items()
           if not k.startswith("GIT_") and k not in ("GH_TOKEN", "GITHUB_TOKEN")}
    env.update(GIT_TERMINAL_PROMPT="0", GCM_INTERACTIVE="never",
               GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
    if token:
        encoded = base64.b64encode(f"x-access-token:{token}".encode()).decode()
        env.update(GIT_CONFIG_COUNT="1",
                   GIT_CONFIG_KEY_0="http.https://github.com/.extraheader",
                   GIT_CONFIG_VALUE_0=f"Authorization: Basic {encoded}")
    return env


async def checkout_repository(url, destination, commit_hash="", github_token="", timeout=30):
    commit = validate_commit(commit_hash)
    env = git_environment(github_token)
    # Disable ambient credentials/hooks/config and redirect following. Credentials
    # live only in these child environments, never in URLs, argv or Git config files.
    prefix = ["git", "-c", "core.hooksPath=" + os.devnull,
              "-c", "credential.helper=", "-c", "http.followRedirects=false",
              "-c", "protocol.file.allow=never", "-c", "protocol.ext.allow=never"]

    async def run(args, cwd=None):
        try:
            rc, out, _ = await run_logged_subprocess(
                prefix + args, cwd=cwd, timeout=timeout, env=env,
                log_output=not bool(github_token))
        except (OSError, TimeoutError) as exc:
            raise RepositoryError("Git could not finish. Check server availability and retry.") from exc
        if rc:
            raise RepositoryError(
                "Repository or commit could not be fetched. Check the URL and full commit hash. "
                "For private repositories, provide a GitHub token with Contents: read access "
                "to that repository (and organization approval if required).")
        return out.strip()

    await run(["init", "--quiet", destination])
    await run(["fetch", "--depth=1", "--no-tags", url, commit or "HEAD"], destination)
    await run(["checkout", "--detach", "--force", "FETCH_HEAD"], destination)
    resolved = await run(["rev-parse", "HEAD"], destination)
    if commit and resolved.lower() != commit:
        raise RepositoryError("Fetched commit does not match the requested commit hash")
    return resolved
