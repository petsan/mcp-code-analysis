"""Stream child-process output while preserving it for analyzer parsing."""

import asyncio
import logging
import time
import uuid

logger = logging.getLogger("mcp-code-analysis")


async def run_logged_subprocess(args, cwd=None, timeout=30, env=None, log_output=True):
    run_id = uuid.uuid4().hex[:12]
    tool = args[0]
    started = time.monotonic()
    logger.info("run=%s tool=%s started", run_id, tool)
    try:
        proc = await asyncio.create_subprocess_exec(
            *args, cwd=cwd, env=env, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except OSError:
        logger.error("run=%s tool=%s failed to start", run_id, tool)
        raise

    async def drain(stream, label):
        chunks = []
        while chunk := await stream.read(4096):
            chunks.append(chunk)
            # repr escaping prevents child output from forging log lines.
            if log_output:
                logger.info("run=%s tool=%s stream=%s output=%r",
                            run_id, tool, label, chunk.decode("utf-8", "replace"))
        return b"".join(chunks).decode("utf-8", "replace")

    async def collect():
        out, err = await asyncio.gather(
            drain(proc.stdout, "stdout"), drain(proc.stderr, "stderr"))
        await proc.wait()
        return proc.returncode, out, err

    try:
        result = await asyncio.wait_for(collect(), timeout)
    except (asyncio.TimeoutError, asyncio.CancelledError) as exc:
        if proc.returncode is None:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
        await proc.wait()
        logger.warning("run=%s tool=%s status=%s elapsed=%.3fs", run_id, tool,
                       "timeout" if isinstance(exc, asyncio.TimeoutError) else "cancelled",
                       time.monotonic() - started)
        raise
    logger.info("run=%s tool=%s finished exit_code=%s elapsed=%.3fs",
                run_id, tool, result[0], time.monotonic() - started)
    return result
