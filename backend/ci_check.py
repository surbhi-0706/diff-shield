"""Read-only GitHub Actions entry point for scanning pull-request diffs."""

from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import HTTPRedirectHandler, Request, build_opener
import json

import regression_engine

API_BASE = "https://api.github.com"
MAX_DIFF_BYTES = 5_000_000


class ScanError(RuntimeError):
    """A safe-to-report failure while retrieving or analyzing a PR diff."""


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


def _validate_request(repository: str, pr_number: str) -> int:
    parts = repository.split("/")
    if (
        len(parts) != 2
        or not re.fullmatch(r"[A-Za-z0-9-]+", parts[0])
        or not re.fullmatch(r"[A-Za-z0-9_.-]+", parts[1])
        or parts[0] in {".", ".."}
        or parts[1] in {".", ".."}
        or not re.fullmatch(r"[1-9][0-9]*", pr_number)
    ):
        raise ScanError("Invalid repository or pull request identity.")
    return int(pr_number)


def _open_github(request: Request):
    opener = build_opener(_NoRedirect())
    return opener.open(request, timeout=30)


def fetch_pull_request_diff(repository: str, pr_number: str, token: str) -> str:
    number = _validate_request(repository, pr_number)
    if not token:
        raise ScanError("GitHub Actions did not provide an API token.")

    owner, repo = repository.split("/", maxsplit=1)
    url = (
        f"{API_BASE}/repos/{quote(owner, safe='')}/{quote(repo, safe='')}"
        f"/pulls/{number}"
    )
    request = Request(
        url,
        headers={
            "Accept": "application/vnd.github.diff",
            "Authorization": f"Bearer {token}",
            "User-Agent": "DiffShield-GitHub-Actions/1.0",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        method="GET",
    )
    try:
        with _open_github(request) as response:
            diff_bytes = response.read(MAX_DIFF_BYTES + 1)
    except HTTPError as error:
        if error.code == 404:
            raise ScanError("Pull request not found or repository is private.") from error
        if error.code in (403, 429):
            raise ScanError("GitHub API rate limit or permission error.") from error
        raise ScanError(f"GitHub API returned HTTP {error.code}.") from error
    except (URLError, TimeoutError, OSError) as error:
        raise ScanError("Could not reach the GitHub API to retrieve the pull request diff.") from error

    if len(diff_bytes) > MAX_DIFF_BYTES:
        raise ScanError("Pull request diff exceeds the 5 MB analysis limit.")
    try:
        return diff_bytes.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ScanError("GitHub returned a pull request diff that is not valid UTF-8.") from error


def create_required_check(
    repository: str, head_sha: str, token: str
) -> int:
    _validate_request(repository, "1")
    if not re.fullmatch(r"[0-9a-fA-F]{40}", head_sha):
        raise ScanError("Invalid pull request head commit SHA.")
    if not token:
        raise ScanError("GitHub Actions did not provide a check-writing token.")

    url = f"{API_BASE}/repos/{quote(repository, safe='/')}/check-runs"
    body = json.dumps(
        {
            "name": "DiffShield Security Gate",
            "head_sha": head_sha,
            "status": "in_progress",
            "output": {
                "title": "DiffShield analysis in progress",
                "summary": "The pull request diff is being scanned.",
            },
        }
    ).encode("utf-8")
    request = Request(
        url,
        data=body,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "DiffShield-GitHub-Actions/1.0",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        method="POST",
    )
    try:
        with _open_github(request) as response:
            payload = json.loads(response.read())
    except HTTPError as error:
        raise ScanError(
            f"Could not create the required check (HTTP {error.code})."
        ) from error
    except (URLError, TimeoutError, OSError, ValueError) as error:
        raise ScanError("Could not create the required GitHub check.") from error

    check_run_id = payload.get("id") if isinstance(payload, dict) else None
    if type(check_run_id) is not int or check_run_id < 1:
        raise ScanError("GitHub returned an invalid required-check identity.")
    return check_run_id


def complete_required_check(
    repository: str,
    check_run_id: int,
    token: str,
    *,
    conclusion: str,
    title: str,
    summary: str,
) -> None:
    _validate_request(repository, "1")
    if type(check_run_id) is not int or check_run_id < 1:
        raise ScanError("Invalid required-check identity.")
    if conclusion not in {"success", "failure"}:
        raise ScanError("Invalid required-check conclusion.")

    url = (
        f"{API_BASE}/repos/{quote(repository, safe='/')}"
        f"/check-runs/{check_run_id}"
    )
    body = json.dumps(
        {
            "status": "completed",
            "conclusion": conclusion,
            "completed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "output": {"title": title[:255], "summary": summary[:50_000]},
        }
    ).encode("utf-8")
    request = Request(
        url,
        data=body,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "DiffShield-GitHub-Actions/1.0",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        method="PATCH",
    )
    try:
        with _open_github(request) as response:
            response.read()
    except HTTPError as error:
        raise ScanError(
            f"Could not complete the required check (HTTP {error.code})."
        ) from error
    except (URLError, TimeoutError, OSError) as error:
        raise ScanError("Could not complete the required GitHub check.") from error


def analyze_pull_request(diff: str, repository: str, pr_number: str) -> dict:
    number = _validate_request(repository, pr_number)
    return regression_engine.analyze_diff(
        raw_diff=diff,
        repository=repository,
        pr_number=number,
        file_path="unknown",
    )


def _write_step_summary(verdict: dict) -> None:
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return

    status = verdict["status"]
    risk_score = verdict["risk_score"]
    finding = verdict.get("finding") or {}
    severity = finding.get("severity", "None")
    cve_cwe = finding.get("cve_cwe", "None")
    with open(summary_path, "a", encoding="utf-8") as summary:
        summary.write(
            "## DiffShield Security Gate\n\n"
            f"- **Result:** `{status}`\n"
            f"- **Risk score:** `{risk_score}/100`\n"
            f"- **Finding severity:** `{severity}`\n"
            f"- **Reference:** `{cve_cwe}`\n"
        )


def main() -> int:
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    pr_number = os.environ.get("PR_NUMBER", "")
    head_sha = os.environ.get("PR_HEAD_SHA", "")
    token = os.environ.get("GITHUB_TOKEN", "")
    try:
        check_run_id = create_required_check(repository, head_sha, token)
        try:
            diff = fetch_pull_request_diff(repository, pr_number, token)
            verdict = analyze_pull_request(diff, repository, pr_number)
        except ScanError as error:
            complete_required_check(
                repository,
                check_run_id,
                token,
                conclusion="failure",
                title="DiffShield analysis could not be completed",
                summary="The scan did not complete successfully. Review the workflow run.",
            )
            raise error

        _write_step_summary(verdict)
        is_regression = verdict["is_regression"]
        complete_required_check(
            repository,
            check_run_id,
            token,
            conclusion="failure" if is_regression else "success",
            title=(
                "Potential security guard regression detected"
                if is_regression
                else "No security guard regression detected"
            ),
            summary=(
                "A potential security guard regression was detected. "
                "Review the DiffShield workflow summary."
                if is_regression
                else f"No regression found (risk {verdict['risk_score']}/100)."
            ),
        )
    except ScanError as error:
        print(f"::error::{error}", file=sys.stderr)
        return 2

    if is_regression:
        print(
            "::error title=DiffShield Security Gate::"
            "Potential security guard regression detected. Review the workflow summary."
        )
        return 1

    print(f"DiffShield: no regression found (risk {verdict['risk_score']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
