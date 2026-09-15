import asyncio
import sys
import unittest

from tool_logging import run_logged_subprocess


class LoggingTests(unittest.IsolatedAsyncioTestCase):
    async def test_output_is_logged_before_exit_and_preserved(self):
        with self.assertLogs("mcp-code-analysis", level="INFO") as logs:
            task = asyncio.create_task(run_logged_subprocess([
                sys.executable, "-u", "-c",
                "import sys,time; print('ready'); print('warning',file=sys.stderr); "
                "time.sleep(1); sys.exit(1)",
            ]))
            for _ in range(100):
                if any("ready" in line for line in logs.output):
                    break
                await asyncio.sleep(.01)
            self.assertTrue(any("ready" in line for line in logs.output))
            self.assertFalse(task.done())
            rc, out, err = await task
        self.assertEqual(rc, 1)
        self.assertEqual(out.strip(), "ready")
        self.assertEqual(err.strip(), "warning")
        self.assertTrue(any("exit_code=1" in line for line in logs.output))

    async def test_timeout_logs_partial_output(self):
        with self.assertLogs("mcp-code-analysis", level="INFO") as logs:
            with self.assertRaises(TimeoutError):
                await run_logged_subprocess([
                    sys.executable, "-u", "-c",
                    "import time; print('partial'); time.sleep(10)",
                ], timeout=.5)
        self.assertTrue(any("partial" in line for line in logs.output))
        self.assertTrue(any("status=timeout" in line for line in logs.output))

    async def test_missing_binary(self):
        with self.assertLogs("mcp-code-analysis", level="ERROR"):
            with self.assertRaises(FileNotFoundError):
                await run_logged_subprocess(["nonexistent-mcp-test-binary"])


if __name__ == "__main__":
    unittest.main()
