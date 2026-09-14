FROM python:3.12-slim

# git is required for the analyze_github_repo tool's shallow clone.
# ca-certificates is required for HTTPS clones/pip installs.
RUN apt-get update && \
    apt-get install -y --no-install-recommends git ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
# ruff and semgrep both ship as self-contained Python wheels with their
# analysis binaries bundled in — no separate native package install needed.
RUN pip install --no-cache-dir -r requirements.txt

# Confirm both CLIs are actually on PATH at build time, so a broken image
# fails the build instead of failing silently at request time.
RUN ruff --version && semgrep --version

COPY main.py .
COPY semgrep-rules.yml .

# Fully offline by default: point SEMGREP_CONFIG at the bundled starter
# ruleset instead of the network-dependent "auto"/"p/*" registry configs.
# semgrep ships with NO rulesets built in — every named config ("auto",
# "p/ci", "p/security-audit", etc.) is fetched from semgrep.dev at scan
# time, so this is the only way to guarantee scans work with no outbound
# network access. Extend semgrep-rules.yml with more rules, or override
# SEMGREP_CONFIG at runtime if outbound access to semgrep's registry is
# available and you want their maintained rulesets instead.
ENV SEMGREP_CONFIG=/app/semgrep-rules.yml

# Run as a non-root user. Analyzer subprocesses and git clones inherit this
# uid, so a compromised/malicious scan target can't write outside /app or /tmp.
RUN useradd --create-home --uid 1000 appuser
USER appuser

ENV PORT=8000 \
    SUBPROCESS_TIMEOUT_SECONDS=30 \
    CLONE_TIMEOUT_SECONDS=30 \
    MAX_SNIPPET_BYTES=2097152 \
    MAX_REPO_FILES=2000 \
    MAX_REPO_BYTES=209715200 \
    PYTHONUNBUFFERED=1

# No default token baked into the image on purpose — a real deployment must
# set BEARER_TOKENS explicitly (e.g. via your platform's secret/env config).
# The app refuses all non-health requests with 503 if it boots without one,
# rather than silently running open. See README for details.

EXPOSE 8000

CMD ["python", "main.py"]
