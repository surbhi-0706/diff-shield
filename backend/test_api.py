import sys
import unittest
from pathlib import Path
import os
import tempfile
from unittest.mock import patch

from fastapi.testclient import TestClient
import httpx

sys.path.insert(0, str(Path(__file__).parent))
import main


class FakeGitHubResponse:
    text = ""

    def __init__(self, status_code):
        self.status_code = status_code

    def json(self):
        return {
            "title": "Example pull request",
            "user": {"login": "contributor"},
            "head": {"sha": "head-sha"},
            "base": {"sha": "base-sha"},
        }

    def raise_for_status(self):
        if self.status_code >= 400:
            request = httpx.Request(
                "GET",
                "https://api.github.com/repos/example/project/pulls/42",
            )
            response = httpx.Response(self.status_code, request=request)
            raise httpx.HTTPStatusError(
                f"HTTP {self.status_code}",
                request=request,
                response=response,
            )


class FakeGitHubClient:
    requested_url = None
    requested_urls = []
    follow_redirects = None
    request_headers = None
    response_status = 200
    response_headers = []

    def __init__(self, *, follow_redirects, headers, **_kwargs):
        type(self).follow_redirects = follow_redirects
        type(self).request_headers = headers
        type(self).response_headers = []
        type(self).requested_urls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    async def get(self, url, headers=None):
        type(self).requested_url = url
        type(self).requested_urls.append(url)
        type(self).response_headers.append(headers or {})
        return FakeGitHubResponse(status_code=type(self).response_status)


class AnalyzePRApiTests(unittest.TestCase):
    def setUp(self):
        FakeGitHubClient.response_status = 200
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_environment = patch.dict(
            os.environ,
            {
                "DIFFSHIELD_QUARANTINE_DB": str(
                    Path(self.temp_dir.name) / "api-tests.db"
                )
            },
        )
        self.db_environment.start()
        self.client = TestClient(main.app)

    def tearDown(self):
        self.db_environment.stop()
        self.temp_dir.cleanup()

    def test_api_root_lists_available_routes(self):
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "ok")
        self.assertEqual(response.json()["health"], "/health")
        self.assertEqual(response.json()["analyze_pr"], "/api/analyze-pr")

    def test_only_accepts_canonical_github_pull_request_urls(self):
        owner, repo, number, api_url = main.parse_github_pr_url(
            "https://github.com/example/project/pull/42/files?tab=files"
        )

        self.assertEqual((owner, repo, number), ("example", "project", 42))
        self.assertEqual(
            api_url,
            "https://api.github.com/repos/example/project/pulls/42",
        )

    def test_rejects_non_github_urls_without_fetching_them(self):
        invalid_urls = (
            "http://github.com/example/project/pull/42",
            "https://example.com/example/project/pull/42",
            "https://github.com.example.com/example/project/pull/42",
            "https://github.com@127.0.0.1/example/project/pull/42",
            "https://github.com:8443/example/project/pull/42",
            "https://github.com/example/project/issues/42",
        )

        class ForbiddenFetch:
            def __init__(self, **_kwargs):
                raise AssertionError("Invalid URLs must not trigger outbound requests.")

        with patch.object(main.httpx, "AsyncClient", ForbiddenFetch):
            for pr_url in invalid_urls:
                with self.subTest(pr_url=pr_url):
                    response = self.client.post(
                        "/api/analyze-pr",
                        json={"pr_url": pr_url},
                    )
                    self.assertEqual(response.status_code, 422)

    def test_fetches_only_the_canonical_github_diff_url(self):
        FakeGitHubClient.requested_url = None
        FakeGitHubClient.requested_urls = []
        FakeGitHubClient.follow_redirects = None
        FakeGitHubClient.response_status = 200
        with (
            patch.object(main.httpx, "AsyncClient", FakeGitHubClient),
            patch.dict(os.environ, {"GITHUB_TOKEN": "test-token"}),
            patch.object(main.snapshot_vault, "archive_snapshot", return_value=7),
        ):
            response = self.client.post(
                "/api/analyze-pr",
                json={
                    "pr_url": "https://github.com/example/project/pull/42",
                },
            )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(
            FakeGitHubClient.requested_url,
            "https://api.github.com/repos/example/project/pulls/42",
        )
        self.assertEqual(
            FakeGitHubClient.requested_urls,
            [
                "https://api.github.com/repos/example/project/pulls/42",
                "https://api.github.com/repos/example/project/pulls/42",
            ],
        )
        self.assertFalse(FakeGitHubClient.follow_redirects)
        self.assertEqual(
            FakeGitHubClient.request_headers["Accept"],
            "application/vnd.github.diff",
        )
        self.assertEqual(
            FakeGitHubClient.response_headers[0]["Accept"],
            "application/vnd.github+json",
        )
        self.assertEqual(
            FakeGitHubClient.response_headers[1]["Accept"],
            "application/vnd.github.diff",
        )
        self.assertEqual(
            FakeGitHubClient.request_headers["X-GitHub-Api-Version"],
            "2022-11-28",
        )
        self.assertEqual(
            FakeGitHubClient.request_headers["User-Agent"],
            "DiffShield-AppSec/1.0",
        )
        self.assertEqual(
            FakeGitHubClient.request_headers["Authorization"],
            "Bearer test-token",
        )
        self.assertNotIn("test-token", response.text)
        self.assertEqual(response.json()["repository"], "example/project")
        self.assertEqual(response.json()["pr_number"], 42)
        self.assertFalse(response.json()["baseline_available"])

    def test_omits_authorization_when_github_token_is_not_set(self):
        with (
            patch.dict(
                os.environ,
                {
                    "DIFFSHIELD_QUARANTINE_DB": str(
                        Path(self.temp_dir.name) / "api-tests.db"
                    )
                },
                clear=True,
            ),
            patch.object(main.httpx, "AsyncClient", FakeGitHubClient),
            patch.object(main.snapshot_vault, "archive_snapshot", return_value=7),
        ):
            response = self.client.post(
                "/api/analyze-pr",
                json={"pr_url": "https://github.com/example/project/pull/42"},
            )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertNotIn("Authorization", FakeGitHubClient.request_headers)

    def test_same_commit_uses_persisted_scan_without_refetching_diff(self):
        pr_url = "https://github.com/example/project/pull/42"
        with (
            patch.object(main.httpx, "AsyncClient", FakeGitHubClient),
            patch.object(main.snapshot_vault, "archive_snapshot", return_value=19),
        ):
            first = self.client.post("/api/analyze-pr", json={"pr_url": pr_url})
            FakeGitHubClient.requested_urls = []
            second = self.client.post("/api/analyze-pr", json={"pr_url": pr_url})

        self.assertEqual(first.status_code, 200, first.text)
        self.assertEqual(second.status_code, 200, second.text)
        self.assertEqual(second.json()["snapshot_id"], 19)
        self.assertEqual(
            FakeGitHubClient.requested_urls,
            ["https://api.github.com/repos/example/project/pulls/42"],
        )

    def test_maps_github_not_found_response(self):
        FakeGitHubClient.response_status = 404
        with patch.object(main.httpx, "AsyncClient", FakeGitHubClient):
            response = self.client.post(
                "/api/analyze-pr",
                json={"pr_url": "https://github.com/example/project/pull/42"},
            )
        FakeGitHubClient.response_status = 200

        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json()["detail"], "PR not found or repo is private")

    def test_maps_github_rate_limit_responses(self):
        for status_code in (403, 429):
            with self.subTest(status_code=status_code):
                FakeGitHubClient.response_status = status_code
                with patch.object(main.httpx, "AsyncClient", FakeGitHubClient):
                    response = self.client.post(
                        "/api/analyze-pr",
                        json={"pr_url": "https://github.com/example/project/pull/42"},
                    )

                self.assertEqual(response.status_code, status_code)
                self.assertEqual(
                    response.json()["detail"],
                    "GitHub rate limit reached, set GITHUB_TOKEN",
                )
        FakeGitHubClient.response_status = 200

    def test_maps_other_github_errors_to_bad_gateway(self):
        FakeGitHubClient.response_status = 500
        with patch.object(main.httpx, "AsyncClient", FakeGitHubClient):
            response = self.client.post(
                "/api/analyze-pr",
                json={"pr_url": "https://github.com/example/project/pull/42"},
            )

        self.assertEqual(response.status_code, 502)
        self.assertEqual(
            response.json()["detail"],
            "GitHub returned HTTP 500 for the pull request diff.",
        )

    def test_reports_a_supplied_baseline(self):
        with patch.object(main.snapshot_vault, "archive_snapshot", return_value=8):
            response = self.client.post(
                "/api/analyze-pr",
                json={"diff_text": "", "clean_code": "baseline"},
            )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertTrue(response.json()["baseline_available"])

    def test_rejects_both_diff_sources(self):
        response = self.client.post(
            "/api/analyze-pr",
            json={
                "pr_url": "https://github.com/example/project/pull/42",
                "diff_text": "",
            },
        )

        self.assertEqual(response.status_code, 422)

    def test_rejects_oversized_inline_diff(self):
        response = self.client.post(
            "/api/analyze-pr",
            json={"diff_text": "x" * 5_000_001},
        )

        self.assertEqual(response.status_code, 422)

    def test_cors_is_limited_to_local_ui_and_extension_origins(self):
        headers = {
            "Origin": "https://untrusted.example",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        }
        response = self.client.options("/api/analyze-pr", headers=headers)
        self.assertNotIn("access-control-allow-origin", response.headers)

        extension_origin = "chrome-extension://" + "a" * 32
        response = self.client.options(
            "/api/analyze-pr",
            headers={**headers, "Origin": extension_origin},
        )
        self.assertEqual(
            response.headers.get("access-control-allow-origin"),
            extension_origin,
        )

    def test_risk_score_is_deterministic_for_same_severity(self):
        diff = """--- a/runner.py
+++ b/runner.py
@@ -1,3 +1,1 @@
-if not is_safe(cmd):
-    raise ValueError("forbidden")
 os.system(cmd)
"""
        first = main.regression_engine.analyze_diff(diff, file_path="runner.py")
        second = main.regression_engine.analyze_diff(diff, file_path="runner.py")

        self.assertEqual(first["status"], "QUARANTINE_HOLD")
        severity_scores = {
            "CRITICAL": 94,
            "HIGH": 92,
            "MEDIUM": 90,
            "LOW": 88,
        }
        self.assertEqual(
            first["risk_score"],
            severity_scores[first["finding"]["severity"]],
        )
        self.assertEqual(first["risk_score"], second["risk_score"])


if __name__ == "__main__":
    unittest.main()
