import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

sys.path.insert(0, str(Path(__file__).parent))
import github_app


class FakeResponse:
    def __init__(self, *, status_code=200, payload=None, text=""):
        self.status_code = status_code
        self.payload = payload or {}
        self.text = text
        self.is_error = status_code >= 400

    def raise_for_status(self):
        if self.is_error:
            request = httpx.Request("GET", "https://api.github.com/test")
            response = httpx.Response(self.status_code, request=request)
            raise httpx.HTTPStatusError(
                f"HTTP {self.status_code}",
                request=request,
                response=response,
            )

    def json(self):
        return self.payload


class FakeGitHubAppClient:
    requests = []
    check_payloads = []

    def __init__(self, *, follow_redirects, headers, **_kwargs):
        self.follow_redirects = follow_redirects
        self.headers = headers

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    async def post(self, url, json=None):
        self.requests.append(("POST", url, self.headers, json))
        if url.endswith("/access_tokens"):
            return FakeResponse(payload={"token": "installation-token"})
        return FakeResponse(payload={"id": 123})

    async def get(self, url, headers=None):
        request_headers = headers or self.headers
        self.requests.append(("GET", url, request_headers, None))
        if "/protection/required_status_checks" in url:
            return FakeResponse(
                payload={
                    "checks": [
                        {"context": github_app.CHECK_NAME, "app_id": 321}
                    ]
                }
            )
        if request_headers.get("Accept") == "application/vnd.github.diff":
            return FakeResponse(text="--- a/a.py\n+++ b/a.py\n")
        return FakeResponse(
            payload={
                "title": "A pull request",
                "user": {"login": "contributor"},
                "head": {"sha": "a" * 40},
                "base": {"sha": "b" * 40, "ref": "main"},
            }
        )

    async def patch(self, url, json=None):
        self.requests.append(("PATCH", url, self.headers, json))
        return FakeResponse()


class GitHubAppTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
        self.env = patch.dict(
            os.environ,
            {"GITHUB_APP_ID": "321", "GITHUB_APP_PRIVATE_KEY": private_key_pem},
        )
        self.env.start()
        FakeGitHubAppClient.requests = []
        FakeGitHubAppClient.check_payloads = []

    def tearDown(self):
        self.env.stop()

    async def test_fetch_uses_fixed_github_api_and_disables_redirects(self):
        with patch.object(github_app.httpx, "AsyncClient", FakeGitHubAppClient):
            metadata, diff, token = await github_app.fetch_pull_request(
                77, "owner", "project", 42
            )

        self.assertEqual(metadata["user"]["login"], "contributor")
        self.assertIn("--- a/a.py", diff)
        self.assertEqual(token, "installation-token")
        self.assertTrue(
            all(
                request[1].startswith("https://api.github.com/")
                for request in FakeGitHubAppClient.requests
            )
        )

    async def test_rejects_path_traversal_repository_names(self):
        with self.assertRaises(github_app.GitHubAppError):
            await github_app.fetch_pull_request(77, "..", "project", 42)

    async def test_creates_and_completes_required_check(self):
        with patch.object(github_app.httpx, "AsyncClient", FakeGitHubAppClient):
            check_id = await github_app.create_check_run(
                "installation-token", "owner", "project", "a" * 40
            )
            await github_app.complete_check_run(
                "installation-token",
                "owner",
                "project",
                check_id,
                conclusion="failure",
                title="Review required",
                summary="A finding needs review.",
            )

        create = FakeGitHubAppClient.requests[-2]
        update = FakeGitHubAppClient.requests[-1]
        self.assertEqual(check_id, 123)
        self.assertEqual(create[3]["name"], github_app.CHECK_NAME)
        self.assertEqual(create[3]["status"], "in_progress")
        self.assertEqual(update[3]["conclusion"], "failure")
        self.assertEqual(update[3]["status"], "completed")

    async def test_required_check_requires_this_app_id(self):
        with (
            patch.dict(os.environ, {"GITHUB_APP_ID": "321"}),
            patch.object(github_app.httpx, "AsyncClient", FakeGitHubAppClient),
        ):
            configured, reason = await github_app.required_check_configured(
                "installation-token", "owner", "project", "main"
            )

        self.assertTrue(configured)
        self.assertIn(github_app.CHECK_NAME, reason)


if __name__ == "__main__":
    unittest.main()
