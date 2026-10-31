import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parent))
import main


class FakeGitHubResponse:
    status_code = 200
    text = ""

    def raise_for_status(self):
        return None


class FakeGitHubClient:
    requested_url = None
    follow_redirects = None

    def __init__(self, *, follow_redirects, **_kwargs):
        type(self).follow_redirects = follow_redirects

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    async def get(self, url):
        type(self).requested_url = url
        return FakeGitHubResponse()


class AnalyzePRApiTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(main.app)

    def test_api_root_lists_available_routes(self):
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "ok")
        self.assertEqual(response.json()["health"], "/health")
        self.assertEqual(response.json()["analyze_pr"], "/api/analyze-pr")

    def test_only_accepts_canonical_github_pull_request_urls(self):
        owner, repo, number, diff_url = main.parse_github_pr_url(
            "https://github.com/example/project/pull/42/files?tab=files"
        )

        self.assertEqual((owner, repo, number), ("example", "project", 42))
        self.assertEqual(
            diff_url,
            "https://github.com/example/project/pull/42.diff",
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
        FakeGitHubClient.follow_redirects = None
        with (
            patch.object(main.httpx, "AsyncClient", FakeGitHubClient),
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
            "https://github.com/example/project/pull/42.diff",
        )
        self.assertFalse(FakeGitHubClient.follow_redirects)
        self.assertEqual(response.json()["repository"], "example/project")
        self.assertEqual(response.json()["pr_number"], 42)
        self.assertFalse(response.json()["baseline_available"])

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
