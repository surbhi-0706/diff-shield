"""GitHub App authentication, PR retrieval, and required-check operations."""

from __future__ import annotations

import os
import re
import time
from urllib.parse import quote

import httpx
import jwt

API_BASE = "https://api.github.com"
CHECK_NAME = "DiffShield Security Gate"


class GitHubAppError(RuntimeError):
    """A safe-to-report GitHub App operation failure."""


def is_configured() -> bool:
    return bool(
        os.environ.get("GITHUB_APP_ID")
        and os.environ.get("GITHUB_APP_PRIVATE_KEY")
    )


def _app_jwt() -> str:
    app_id = os.environ.get("GITHUB_APP_ID")
    private_key = os.environ.get("GITHUB_APP_PRIVATE_KEY")
    if not app_id or not private_key:
        raise GitHubAppError("GitHub App credentials are not configured.")
    try:
        return jwt.encode(
            {
                "iat": int(time.time()) - 60,
                "exp": int(time.time()) + 540,
                "iss": app_id,
            },
            private_key.replace("\\n", "\n"),
            algorithm="RS256",
        )
    except (ValueError, TypeError) as error:
        raise GitHubAppError("GitHub App private key could not sign an App token.") from error


def _validate_repository(owner: str, repo: str, pr_number: int) -> None:
    if (
        not re.fullmatch(r"[A-Za-z0-9-]+", owner)
        or not re.fullmatch(r"[A-Za-z0-9_.-]+", repo)
        or owner in {".", ".."}
        or repo in {".", ".."}
        or type(pr_number) is not int
        or pr_number < 1
    ):
        raise GitHubAppError("GitHub repository or pull request identity is invalid.")


async def installation_token(installation_id: int) -> str:
    if type(installation_id) is not int or installation_id < 1:
        raise GitHubAppError("GitHub installation identity is invalid.")
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {_app_jwt()}",
        "User-Agent": "DiffShield-AppSec/1.0",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    try:
        async with httpx.AsyncClient(
            follow_redirects=False,
            timeout=20,
            headers=headers,
        ) as client:
            response = await client.post(
                f"{API_BASE}/app/installations/{installation_id}/access_tokens"
            )
            response.raise_for_status()
            payload = response.json()
    except httpx.HTTPStatusError as error:
        raise GitHubAppError(
            f"GitHub App installation token request failed (HTTP {error.response.status_code})."
        ) from error
    except (httpx.RequestError, ValueError) as error:
        raise GitHubAppError("Could not obtain a GitHub App installation token.") from error

    token = payload.get("token") if isinstance(payload, dict) else None
    if not isinstance(token, str) or not token:
        raise GitHubAppError("GitHub returned an invalid installation token response.")
    return token


def _installation_headers(token: str, accept: str = "application/vnd.github+json") -> dict[str, str]:
    return {
        "Accept": accept,
        "Authorization": f"Bearer {token}",
        "User-Agent": "DiffShield-AppSec/1.0",
        "X-GitHub-Api-Version": "2022-11-28",
    }


async def fetch_pull_request(
    installation_id: int,
    owner: str,
    repo: str,
    pr_number: int,
) -> tuple[dict, str, str]:
    """Fetch metadata and diff only from the fixed GitHub API origin."""
    _validate_repository(owner, repo, pr_number)
    token = await installation_token(installation_id)
    pr_url = f"{API_BASE}/repos/{quote(owner, safe='')}/{quote(repo, safe='')}/pulls/{pr_number}"
    try:
        async with httpx.AsyncClient(
            follow_redirects=False,
            timeout=20,
            headers=_installation_headers(token),
        ) as client:
            metadata_response = await client.get(pr_url)
            metadata_response.raise_for_status()
            metadata = metadata_response.json()
            diff_response = await client.get(
                pr_url,
                headers=_installation_headers(token, "application/vnd.github.diff"),
            )
            diff_response.raise_for_status()
    except httpx.HTTPStatusError as error:
        raise GitHubAppError(
            f"GitHub pull request fetch failed (HTTP {error.response.status_code})."
        ) from error
    except (httpx.RequestError, ValueError) as error:
        raise GitHubAppError("Could not fetch the GitHub pull request.") from error

    if not isinstance(metadata, dict):
        raise GitHubAppError("GitHub returned invalid pull request metadata.")
    try:
        if (
            not isinstance(metadata["head"]["sha"], str)
            or not isinstance(metadata["base"]["sha"], str)
            or not isinstance(metadata["user"]["login"], str)
        ):
            raise TypeError
    except (KeyError, TypeError) as error:
        raise GitHubAppError("GitHub returned incomplete pull request metadata.") from error
    diff = diff_response.text
    if len(diff) > 5_000_000:
        raise GitHubAppError("The GitHub pull request diff exceeds the 5 MB analysis limit.")
    return metadata, diff, token


async def create_check_run(
    installation_token: str,
    owner: str,
    repo: str,
    head_sha: str,
) -> int:
    _validate_repository(owner, repo, 1)
    if not re.fullmatch(r"[0-9a-fA-F]{40}", head_sha):
        raise GitHubAppError("GitHub pull request head commit SHA is invalid.")
    url = f"{API_BASE}/repos/{quote(owner, safe='')}/{quote(repo, safe='')}/check-runs"
    try:
        async with httpx.AsyncClient(
            follow_redirects=False,
            timeout=20,
            headers=_installation_headers(installation_token),
        ) as client:
            response = await client.post(
                url,
                json={
                    "name": CHECK_NAME,
                    "head_sha": head_sha,
                    "status": "in_progress",
                    "output": {
                        "title": "DiffShield analysis in progress",
                        "summary": "The pull request is being checked for security regressions.",
                    },
                },
            )
            response.raise_for_status()
            payload = response.json()
    except httpx.HTTPStatusError as error:
        raise GitHubAppError(
            f"Creating the required GitHub check failed (HTTP {error.response.status_code})."
        ) from error
    except (httpx.RequestError, ValueError) as error:
        raise GitHubAppError("Could not create the GitHub required check.") from error
    check_run_id = payload.get("id") if isinstance(payload, dict) else None
    if type(check_run_id) is not int:
        raise GitHubAppError("GitHub returned an invalid check run identity.")
    return check_run_id


async def complete_check_run(
    installation_token: str,
    owner: str,
    repo: str,
    check_run_id: int,
    *,
    conclusion: str,
    title: str,
    summary: str,
) -> None:
    _validate_repository(owner, repo, 1)
    if type(check_run_id) is not int or check_run_id < 1:
        raise GitHubAppError("GitHub check run identity is invalid.")
    if conclusion not in {"success", "failure", "neutral", "cancelled", "timed_out", "action_required"}:
        raise GitHubAppError("GitHub check conclusion is invalid.")
    url = (
        f"{API_BASE}/repos/{quote(owner, safe='')}/{quote(repo, safe='')}"
        f"/check-runs/{check_run_id}"
    )
    try:
        async with httpx.AsyncClient(
            follow_redirects=False,
            timeout=20,
            headers=_installation_headers(installation_token),
        ) as client:
            response = await client.patch(
                url,
                json={
                    "status": "completed",
                    "conclusion": conclusion,
                    "completed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "output": {
                        "title": title[:255],
                        "summary": summary[:50_000],
                    },
                },
            )
            response.raise_for_status()
    except httpx.HTTPStatusError as error:
        raise GitHubAppError(
            f"Updating the GitHub required check failed (HTTP {error.response.status_code})."
        ) from error
    except httpx.RequestError as error:
        raise GitHubAppError("Could not update the GitHub required check.") from error


async def notify_pull_request(
    installation_token: str,
    owner: str,
    repo: str,
    pr_number: int,
    *,
    finding_id: str,
    notification_type: str,
    severity: str,
    risk_score: int,
) -> None:
    _validate_repository(owner, repo, pr_number)
    if (
        not re.fullmatch(r"[A-Za-z0-9-]+", finding_id)
        or notification_type not in {"quarantine", "escalated"}
    ):
        raise GitHubAppError("DiffShield notification identity is invalid.")
    marker = f"<!-- diffshield:{finding_id}:{notification_type} -->"
    base_url = (
        f"{API_BASE}/repos/{quote(owner, safe='')}/{quote(repo, safe='')}"
        f"/issues/{pr_number}/comments"
    )
    try:
        async with httpx.AsyncClient(
            follow_redirects=False,
            timeout=20,
            headers=_installation_headers(installation_token),
        ) as client:
            response = await client.get(
                base_url,
                params={"per_page": 100, "sort": "created", "direction": "desc"},
            )
            response.raise_for_status()
            comments = response.json()
            if not isinstance(comments, list):
                raise GitHubAppError("GitHub returned invalid pull request comments.")
            if any(
                isinstance(comment, dict)
                and isinstance(comment.get("body"), str)
                and marker in comment["body"]
                for comment in comments
            ):
                return
            body = (
                f"{marker}\n"
                f"**DiffShield {notification_type}**\n\n"
                f"Finding: `{finding_id}`  \n"
                f"Severity: `{severity}` · Risk score: `{risk_score}/100`  \n"
                "Review the DiffShield finding and quarantine state before proceeding."
            )
            created = await client.post(base_url, json={"body": body})
            created.raise_for_status()
    except httpx.HTTPStatusError as error:
        raise GitHubAppError(
            f"GitHub maintainer notification failed (HTTP {error.response.status_code})."
        ) from error
    except (httpx.RequestError, ValueError) as error:
        raise GitHubAppError("Could not notify pull request maintainers.") from error


async def required_check_configured(
    installation_token: str,
    owner: str,
    repo: str,
    base_branch: str,
) -> tuple[bool, str]:
    _validate_repository(owner, repo, 1)
    if not base_branch or len(base_branch) > 255:
        return False, "The pull request base branch is unavailable."
    encoded_branch = quote(base_branch, safe="")
    url = (
        f"{API_BASE}/repos/{quote(owner, safe='')}/{quote(repo, safe='')}"
        f"/branches/{encoded_branch}/protection/required_status_checks"
    )
    try:
        async with httpx.AsyncClient(
            follow_redirects=False,
            timeout=20,
            headers=_installation_headers(installation_token),
        ) as client:
            response = await client.get(url)
    except httpx.RequestError:
        return False, "Could not verify branch protection with GitHub."
    if response.status_code == 404:
        return False, "GitHub reports no required status-check protection for the base branch."
    if response.status_code == 403:
        return False, "The GitHub App cannot read branch protection configuration."
    if response.is_error:
        return False, f"GitHub branch-protection check failed (HTTP {response.status_code})."
    try:
        payload = response.json()
    except ValueError:
        return False, "GitHub returned invalid branch-protection data."
    checks = payload.get("checks", []) if isinstance(payload, dict) else []
    app_id = os.environ.get("GITHUB_APP_ID")
    configured = any(
        isinstance(item, dict)
        and item.get("context") == CHECK_NAME
        and str(item.get("app_id")) == str(app_id)
        for item in checks
    )
    if configured:
        return True, "DiffShield Security Gate is required for this base branch."
    return False, "DiffShield Security Gate is not configured as a required check."
