import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from repository import RepositoryError, checkout_repository, git_environment, validate_commit


class RepositoryTests(unittest.IsolatedAsyncioTestCase):
    async def test_explicit_commit_and_token(self):
        sha = "a" * 40
        runner = AsyncMock(side_effect=[(0, "", "")] * 3 + [(0, sha + "\n", "")])
        with patch("repository.run_logged_subprocess", runner):
            result = await checkout_repository("https://github.com/owner/repo.git", "checkout", sha, "secret-token")
        self.assertEqual(result, sha)
        calls = runner.call_args_list
        self.assertIn(sha, calls[1].args[0])
        self.assertIn("--depth=1", calls[1].args[0])
        for call in calls:
            self.assertNotIn("secret-token", " ".join(call.args[0]))
            self.assertFalse(call.kwargs["log_output"])
            self.assertIn("GIT_CONFIG_VALUE_0", call.kwargs["env"])

    async def test_default_branch(self):
        runner = AsyncMock(side_effect=[(0, "", "")] * 3 + [(0, "b" * 40, "")])
        with patch("repository.run_logged_subprocess", runner):
            await checkout_repository("https://github.com/owner/repo.git", "checkout")
        self.assertEqual(runner.call_args_list[1].args[0][-1], "HEAD")

    async def test_auth_error_does_not_expose_git_output(self):
        with patch("repository.run_logged_subprocess", AsyncMock(return_value=(1, "", "secret-token"))):
            with self.assertRaises(RepositoryError) as caught:
                await checkout_repository("https://github.com/owner/repo.git", "checkout", github_token="secret-token")
        self.assertNotIn("secret-token", str(caught.exception))
        self.assertIn("Contents: read", str(caught.exception))

    async def test_bad_hash_rejected_before_git(self):
        for value in ("--upload-pack=bad", "abc123", None, "g" * 40):
            with self.subTest(value=value), self.assertRaises(RepositoryError):
                validate_commit(value)

    async def test_credentials_are_request_scoped(self):
        with patch.dict(os.environ, {"GITHUB_TOKEN": "ambient", "GIT_TRACE": "1"}):
            authenticated = git_environment("one-request")
            anonymous = git_environment("")
        self.assertNotIn("GITHUB_TOKEN", authenticated)
        self.assertNotIn("GIT_TRACE", authenticated)
        self.assertNotIn("GIT_CONFIG_VALUE_0", anonymous)


class EndpointTests(unittest.TestCase):
    def test_repository_route_requires_server_auth(self):
        import main
        from starlette.testclient import TestClient
        protected = main.BearerAuthMiddleware(main.starlette_app, {"server-secret"}, False)
        with patch.object(main, "analyze_github_repo", AsyncMock()) as scan:
            response = TestClient(protected).post("/demo/scan", json={"mode": "repository"})
        self.assertEqual(response.status_code, 401)
        scan.assert_not_called()

    def test_demo_has_repository_controls(self):
        import main
        from starlette.testclient import TestClient
        page = TestClient(main.starlette_app).get("/").text
        for control in ('id="repo-url"', 'id="commit"', 'id="github-token" type="password"'):
            self.assertIn(control, page)

    def test_repo_endpoint_and_schema(self):
        import main
        from starlette.testclient import TestClient
        expected = {"repo": "owner/repo", "commit_hash": "a" * 40, "findings": [], "errors": []}
        client = TestClient(main.starlette_app)
        with patch.object(main, "analyze_github_repo", AsyncMock(return_value=expected)) as scan:
            response = client.post("/demo/scan", json={"mode": "repository", "repo_url": "https://github.com/owner/repo", "commit_hash": "a" * 40, "github_token": "test-token"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), expected)
        self.assertEqual(scan.call_args.args[-1], "test-token")
        self.assertEqual(response.headers["cache-control"], "no-store")
        props = main.TOOLS[1].inputSchema["properties"]
        self.assertIn("commit_hash", props)
        self.assertIn("github_token", props)

    def test_invalid_repo_and_hash_return_actionable_errors(self):
        import main
        from starlette.testclient import TestClient
        client = TestClient(main.starlette_app)
        for body in ({"repo_url": "https://evil.example/repo"},
                     {"repo_url": "https://github.com/owner/repo", "commit_hash": "bad"}):
            response = client.post("/demo/scan", json={"mode": "repository", **body})
            self.assertEqual(response.status_code, 400)
            self.assertIn("error", response.json())
