import contextlib
import io
import json
import sys
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))

import ci_check


class GitHubActionsCheckTests(unittest.TestCase):
    def test_fetch_uses_fixed_github_api_url_and_diff_headers(self):
        response = io.BytesIO(b"diff --git a/example.py b/example.py\n")
        with patch.object(ci_check, "_open_github", return_value=response) as open_github:
            diff = ci_check.fetch_pull_request_diff(
                "example/project", "42", "read-only-token"
            )

        request = open_github.call_args.args[0]
        self.assertIsInstance(request, Request)
        self.assertEqual(
            request.full_url,
            "https://api.github.com/repos/example/project/pulls/42",
        )
        self.assertEqual(request.get_header("Accept"), "application/vnd.github.diff")
        self.assertEqual(request.get_header("X-github-api-version"), "2022-11-28")
        self.assertEqual(
            request.get_header("Authorization"), "Bearer read-only-token"
        )
        self.assertTrue(diff.startswith("diff --git"))

    def test_creates_check_for_pr_head_sha(self):
        response = io.BytesIO(b'{"id": 789}')
        head_sha = "a" * 40
        with patch.object(
            ci_check, "_open_github", return_value=response
        ) as open_github:
            check_run_id = ci_check.create_required_check(
                "example/project", head_sha, "read-only-token"
            )

        request = open_github.call_args.args[0]
        self.assertEqual(
            request.full_url,
            "https://api.github.com/repos/example/project/check-runs",
        )
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(request.get_header("Accept"), "application/vnd.github+json")
        self.assertEqual(request.get_header("X-github-api-version"), "2022-11-28")
        self.assertEqual(
            json.loads(request.data),
            {
                "name": "DiffShield Security Gate",
                "head_sha": head_sha,
                "status": "in_progress",
                "output": {
                    "title": "DiffShield analysis in progress",
                    "summary": "The pull request diff is being scanned.",
                },
            },
        )
        self.assertEqual(check_run_id, 789)

    def test_completes_check_with_selected_conclusion(self):
        response = io.BytesIO(b"{}")
        with patch.object(
            ci_check, "_open_github", return_value=response
        ) as open_github:
            ci_check.complete_required_check(
                "example/project",
                789,
                "read-only-token",
                conclusion="failure",
                title="Potential regression",
                summary="Review the finding.",
            )

        request = open_github.call_args.args[0]
        self.assertEqual(
            request.full_url,
            "https://api.github.com/repos/example/project/check-runs/789",
        )
        self.assertEqual(request.get_method(), "PATCH")
        self.assertEqual(json.loads(request.data)["conclusion"], "failure")
        self.assertEqual(json.loads(request.data)["status"], "completed")

    def test_rejects_invalid_repository_or_pr_identity(self):
        for repository, pr_number in (
            ("../project", "42"),
            ("example/..", "42"),
            ("example/project", "0"),
            ("example/project", "4/2"),
        ):
            with self.subTest(repository=repository, pr_number=pr_number):
                with self.assertRaises(ci_check.ScanError):
                    ci_check.fetch_pull_request_diff(
                        repository, pr_number, "read-only-token"
                    )

    def test_maps_github_http_errors_without_exposing_response_body(self):
        for code, expected in (
            (404, "Pull request not found or repository is private."),
            (403, "GitHub API rate limit or permission error."),
            (429, "GitHub API rate limit or permission error."),
            (500, "GitHub API returned HTTP 500."),
        ):
            error = HTTPError(
                "https://api.github.com/private",
                code,
                "upstream failure",
                None,
                io.BytesIO(b"private response content"),
            )
            with self.subTest(code=code):
                with patch.object(ci_check, "_open_github", side_effect=error):
                    with self.assertRaisesRegex(ci_check.ScanError, expected):
                        ci_check.fetch_pull_request_diff(
                            "example/project", "42", "read-only-token"
                        )

    def test_analyzes_multi_file_diff_using_existing_engine(self):
        diff = (
            "--- a/merge.js\n"
            "+++ b/merge.js\n"
            "@@ @@\n"
            "-  if (key === '__proto__') continue;\n"
            "   obj[key] = src[key];\n"
        )
        verdict = ci_check.analyze_pull_request(diff, "example/project", "42")

        self.assertEqual(verdict["status"], "QUARANTINE_HOLD")
        self.assertTrue(verdict["is_regression"])
        self.assertEqual(verdict["finding"]["cve_cwe"], "CVE-2019-10744")

    def test_clean_diff_passes_existing_engine(self):
        verdict = ci_check.analyze_pull_request(
            "diff --git a/readme.md b/readme.md\n", "example/project", "42"
        )

        self.assertEqual(verdict["status"], "PASSED")
        self.assertFalse(verdict["is_regression"])

    def test_main_fails_required_check_for_suspicious_regression(self):
        environment = {
            "GITHUB_REPOSITORY": "example/project",
            "PR_NUMBER": "42",
            "PR_HEAD_SHA": "a" * 40,
            "GITHUB_TOKEN": "read-only-token",
        }
        verdict = {
            "is_regression": True,
            "risk_score": 92,
            "status": "QUARANTINE_HOLD",
            "finding": {"severity": "HIGH", "cve_cwe": "CWE-79"},
        }
        with (
            patch.dict("os.environ", environment, clear=True),
            patch.object(ci_check, "create_required_check", return_value=789),
            patch.object(ci_check, "fetch_pull_request_diff", return_value="diff"),
            patch.object(ci_check, "analyze_pull_request", return_value=verdict),
            patch.object(ci_check, "complete_required_check") as complete,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            result = ci_check.main()

        self.assertEqual(result, 1)
        self.assertEqual(complete.call_args.kwargs["conclusion"], "failure")

    def test_main_passes_required_check_for_clean_diff(self):
        environment = {
            "GITHUB_REPOSITORY": "example/project",
            "PR_NUMBER": "42",
            "PR_HEAD_SHA": "a" * 40,
            "GITHUB_TOKEN": "read-only-token",
        }
        verdict = {
            "is_regression": False,
            "risk_score": 8,
            "status": "PASSED",
            "finding": None,
        }
        with (
            patch.dict("os.environ", environment, clear=True),
            patch.object(ci_check, "create_required_check", return_value=789),
            patch.object(ci_check, "fetch_pull_request_diff", return_value="diff"),
            patch.object(ci_check, "analyze_pull_request", return_value=verdict),
            patch.object(ci_check, "complete_required_check") as complete,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            result = ci_check.main()

        self.assertEqual(result, 0)
        self.assertEqual(complete.call_args.kwargs["conclusion"], "success")


if __name__ == "__main__":
    unittest.main()
