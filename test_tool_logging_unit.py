import asyncio
import unittest
from unittest.mock import AsyncMock, patch

from tool_logging import run_logged_subprocess


class FakeProcess:
    def __init__(self):
        self.stdout = asyncio.StreamReader()
        self.stderr = asyncio.StreamReader()
        self.returncode = None
        self.killed = False

    async def wait(self):
        return self.returncode

    def kill(self):
        self.killed = True
        self.returncode = -9


class StreamTests(unittest.IsolatedAsyncioTestCase):
    async def test_streams_before_exit_and_preserves_bytes(self):
        proc = FakeProcess()
        with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)):
            with self.assertLogs("mcp-code-analysis", level="INFO") as logs:
                task = asyncio.create_task(run_logged_subprocess(["ruff"]))
                proc.stdout.feed_data(b'{"result":')
                proc.stderr.feed_data(b'progress\n')
                for _ in range(10):
                    await asyncio.sleep(0)
                self.assertTrue(any("progress" in line for line in logs.output))
                self.assertFalse(task.done())
                proc.stdout.feed_data(b'1}')
                proc.stdout.feed_eof()
                proc.stderr.feed_eof()
                proc.returncode = 1
                self.assertEqual(await task, (1, '{"result":1}', 'progress\n'))

    async def test_timeout_kills_process(self):
        proc = FakeProcess()
        with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)):
            with self.assertLogs("mcp-code-analysis", level="INFO") as logs:
                with self.assertRaises(TimeoutError):
                    await run_logged_subprocess(["semgrep"], timeout=.01)
        self.assertTrue(proc.killed)
        self.assertTrue(any("status=timeout" in line for line in logs.output))

    async def test_cancel_kills_process(self):
        proc = FakeProcess()
        with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)):
            with self.assertLogs("mcp-code-analysis", level="INFO"):
                task = asyncio.create_task(run_logged_subprocess(["git"]))
                for _ in range(10):
                    await asyncio.sleep(0)
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await task
        self.assertTrue(proc.killed)

    async def test_missing_binary_is_logged(self):
        with patch("asyncio.create_subprocess_exec", AsyncMock(side_effect=FileNotFoundError)):
            with self.assertLogs("mcp-code-analysis", level="ERROR"):
                with self.assertRaises(FileNotFoundError):
                    await run_logged_subprocess(["missing"])
