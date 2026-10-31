"""
main.py - DiffShield FastAPI application.

Endpoints:
  GET  /health                              - Service liveness check
  POST /api/analyze-pr                      - Analyze a PR diff for security regressions
  GET  /api/rollback/{owner}/{repo}/{pr_number} - Retrieve rollback snapshot
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import sys
from pathlib import Path

# Ensure sibling modules are importable when uvicorn is launched from any CWD
sys.path.insert(0, str(Path(__file__).parent))

import re
import httpx
import os
import hmac
import json
import logging
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional
from urllib.parse import urlsplit

import regression_engine
import snapshot_vault
import quarantine_store
import github_app

# ---------------------------------------------------------------------------
# Application setup
# ---------------------------------------------------------------------------


async def _quarantine_escalation_worker():
    while True:
        quarantine_store.expire_overdue()
        if github_app.is_configured():
            for quarantine in quarantine_store.list_quarantines(active_only=True):
                if (
                    quarantine["state"] != "ESCALATED"
                    or not quarantine.get("check_run_id")
                    or not quarantine_store.begin_notification(
                        quarantine["finding_id"], "escalated"
                    )
                ):
                    continue
                enforcement = quarantine_store.get_repository_enforcement(
                    quarantine["repository"]
                )
                installation = (
                    quarantine_store.get_github_installation(
                        enforcement["installation_id"]
                    )
                    if enforcement
                    else None
                )
                try:
                    if (
                        enforcement is None
                        or installation is None
                        or installation["state"] != "INSTALLED"
                    ):
                        raise github_app.GitHubAppError(
                            "GitHub App installation is unavailable for escalation."
                        )
                    token = await github_app.installation_token(
                        enforcement["installation_id"]
                    )
                    owner, repo = quarantine["repository"].split("/", maxsplit=1)
                    if quarantine.get("check_run_id"):
                        await github_app.complete_check_run(
                            token,
                            owner,
                            repo,
                            quarantine["check_run_id"],
                            conclusion="failure",
                            title="DiffShield review deadline expired",
                            summary=(
                                f"Finding {quarantine['finding_id']} is escalated. "
                                "The security quarantine remains active until an authorized reviewer acts."
                            ),
                        )
                    await github_app.notify_pull_request(
                        token,
                        owner,
                        repo,
                        quarantine["pr_number"],
                        finding_id=quarantine["finding_id"],
                        notification_type="escalated",
                        severity=quarantine["severity"],
                        risk_score=quarantine["risk_score"],
                    )
                except github_app.GitHubAppError as error:
                    quarantine_store.finish_notification(
                        quarantine["finding_id"], "escalated", error=str(error)
                    )
                    logger.error(
                        "Could not notify maintainers for escalated finding %s: %s",
                        quarantine["finding_id"],
                        error,
                    )
                else:
                    quarantine_store.finish_notification(
                        quarantine["finding_id"], "escalated"
                    )
        await asyncio.sleep(30)


@asynccontextmanager
async def lifespan(_application):
    escalation_task = asyncio.create_task(_quarantine_escalation_worker())
    try:
        yield
    finally:
        escalation_task.cancel()
        try:
            await escalation_task
        except asyncio.CancelledError:
            pass


app = FastAPI(
    title="DiffShield Security Analysis API",
    description=(
        "Deterministic AST/block-level PR diff analyser that detects security-guard "
        "regressions, generates reverse patches, and stores optional supplied baselines."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_origin_regex=r"^chrome-extension://[a-p]{32}$",
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization"],
)

# Initialise the vault schema on startup
snapshot_vault.init_vault()
quarantine_store.init_db()
logger = logging.getLogger("diffshield")


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class AnalyzePRRequest(BaseModel):
    pr_url: Optional[str] = Field(
        default=None,
        max_length=2048,
        description="GitHub PR URL to fetch diff from",
    )
    diff_text: Optional[str] = Field(
        default=None,
        max_length=5_000_000,
        description="Raw unified diff text",
    )
    repository: Optional[str] = Field(default="unknown/repo", description="Repository (owner/name)")
    pr_number: Optional[int] = Field(default=0, description="Pull request number")
    file_path: Optional[str] = Field(default="unknown", description="File being analysed")
    clean_code: Optional[str] = Field(
        default=None,
        max_length=5_000_000,
        description="Pre-PR baseline code for snapshot",
    )


class QuarantineResolutionRequest(BaseModel):
    decision: str = Field(pattern=r"^(RESOLVED|REJECTED)$")
    reason: str = Field(min_length=1, max_length=4000)


def _configured_reviewers() -> dict[str, str]:
    raw_reviewers = os.environ.get("DIFFSHIELD_REVIEWER_TOKENS")
    if not raw_reviewers:
        raise HTTPException(
            status_code=503,
            detail="Quarantine resolution is not configured on this backend.",
        )
    try:
        reviewers = json.loads(raw_reviewers)
    except json.JSONDecodeError as error:
        raise HTTPException(
            status_code=503,
            detail="DIFFSHIELD_REVIEWER_TOKENS must contain a JSON object.",
        ) from error
    if (
        not isinstance(reviewers, dict)
        or not reviewers
        or any(
            not isinstance(name, str)
            or not name
            or not isinstance(token, str)
            or len(token) < 32
            for name, token in reviewers.items()
        )
    ):
        raise HTTPException(
            status_code=503,
            detail="Reviewer configuration must map identities to tokens of at least 32 characters.",
        )
    return reviewers


def _authenticated_reviewer(authorization: str | None) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="A reviewer bearer token is required.")
    provided_token = authorization.removeprefix("Bearer ")
    for identity, expected_token in _configured_reviewers().items():
        if hmac.compare_digest(provided_token, expected_token):
            return identity
    raise HTTPException(status_code=403, detail="Reviewer is not authorized.")


def _merge_protection_status(repository: str) -> dict[str, str]:
    enforcement = quarantine_store.get_repository_enforcement(repository)
    if enforcement is None:
        return {
            "status": "NOT_ENFORCED",
            "reason": "GitHub required status-check protection has not been verified.",
        }
    installation = quarantine_store.get_github_installation(
        enforcement["installation_id"]
    )
    is_enforced = bool(
        installation
        and installation["state"] == "INSTALLED"
        and enforcement["required_check_configured"]
    )
    return {
        "status": "ENFORCED" if is_enforced else "NOT_ENFORCED",
        "reason": enforcement["reason"],
    }


def parse_github_pr_url(pr_url: str) -> tuple[str, str, int, str]:
    """Validate a GitHub pull request URL and return its diff URL metadata."""

    try:
        parsed_url = urlsplit(pr_url)
        port = parsed_url.port
    except ValueError as error:
        raise HTTPException(status_code=422, detail="Invalid GitHub PR URL.") from error

    match = re.fullmatch(
        r"/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/pull/([1-9][0-9]*)(?:/.*)?",
        parsed_url.path,
    )
    if (
        parsed_url.scheme != "https"
        or parsed_url.hostname != "github.com"
        or parsed_url.username is not None
        or parsed_url.password is not None
        or port not in (None, 443)
        or match is None
    ):
        raise HTTPException(
            status_code=422,
            detail="Provide a valid https://github.com/{owner}/{repo}/pull/{number} URL.",
        )

    owner, repo, pr_number_text = match.groups()
    if owner in {".", ".."} or repo in {".", ".."}:
        raise HTTPException(
            status_code=422,
            detail="Provide a valid https://github.com/{owner}/{repo}/pull/{number} URL.",
        )
    pr_number = int(pr_number_text)
    api_url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}"
    return owner, repo, pr_number, api_url


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.get("/", summary="API entrypoint")
async def root():
    """Provide route discovery when the backend base URL is opened."""
    return {
        "service": "DiffShield Security Analysis API",
        "status": "ok",
        "health": "/health",
        "analyze_pr": "/api/analyze-pr",
        "quarantines": "/api/quarantines",
        "github_webhook": "/api/github/webhook",
        "github_status": "/api/github/status",
        "rollback": "/api/rollback/{owner}/{repo}/{pr_number}",
        "docs": "/docs",
    }


@app.get("/health", summary="Service health check")
async def health():
    """Return service status and confirm all engines are ready."""
    return {
        "status": "ok",
        "service": "DiffShield Security Analysis API",
        "version": "1.0.0",
        "engines": {
            "block_parser": "ready",
            "regression_engine": "ready",
            "snapshot_vault": "ready",
        },
    }


@app.post("/api/analyze-pr", summary="Analyze a pull request diff")
async def analyze_pr(request: AnalyzePRRequest):
    """Analyze a PR diff for security guard regressions.

    Supply either pr_url (GitHub PR URL) or diff_text (raw unified diff).
    Returns a verdict, risk score, quarantine status, and structured finding.
    """
    raw_diff: str = ""
    repository = request.repository or "unknown/repo"
    pr_number = request.pr_number or 0
    cached_scan = None

    if request.pr_url is not None and request.diff_text is not None:
        raise HTTPException(
            status_code=422,
            detail="Provide either 'pr_url' or 'diff_text', not both.",
        )

    # 1. Fetch the diff only from a validated GitHub pull request URL.
    if request.pr_url is not None:
        owner, repo, pr_number, diff_url = parse_github_pr_url(request.pr_url)
        repository = f"{owner}/{repo}"
        pr_title = None
        pr_author = None
        head_sha = None
        base_sha = None
        try:
            headers = {
                "User-Agent": "DiffShield-AppSec/1.0",
                "Accept": "application/vnd.github.diff",
                "X-GitHub-Api-Version": "2022-11-28",
            }
            github_token = os.environ.get("GITHUB_TOKEN")
            if github_token:
                headers["Authorization"] = f"Bearer {github_token}"
            async with httpx.AsyncClient(
                follow_redirects=False,
                timeout=20,
                headers=headers,
            ) as client:
                metadata_response = await client.get(
                    diff_url,
                    headers={"Accept": "application/vnd.github+json"},
                )
                metadata_response.raise_for_status()
                try:
                    pull_request = metadata_response.json()
                    pr_title = pull_request["title"]
                    pr_author = pull_request["user"]["login"]
                    head_sha = pull_request["head"]["sha"]
                    base_sha = pull_request["base"]["sha"]
                except (KeyError, TypeError, ValueError) as error:
                    raise HTTPException(
                        status_code=502,
                        detail="GitHub returned invalid pull request metadata.",
                    ) from error

                cached_scan = (
                    quarantine_store.get_scan_for_commit(
                        repository, pr_number, head_sha
                    )
                    if request.clean_code is None
                    and request.file_path in (None, "unknown")
                    else None
                )
                if (
                    cached_scan is None
                    or cached_scan["state"] in {"SCANNING", "ERROR"}
                    or not cached_scan["scan_result"]
                ):
                    response = await client.get(
                        diff_url,
                        headers={"Accept": "application/vnd.github.diff"},
                    )
                    response.raise_for_status()
                    raw_diff = response.text
                    if len(raw_diff) > 5_000_000:
                        raise HTTPException(
                            status_code=413,
                            detail="The GitHub pull request diff exceeds the 5 MB analysis limit.",
                        )
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                raise HTTPException(
                    status_code=404,
                    detail="PR not found or repo is private",
                ) from exc
            if exc.response.status_code in (403, 429):
                raise HTTPException(
                    status_code=exc.response.status_code,
                    detail="GitHub rate limit reached, set GITHUB_TOKEN",
                ) from exc
            raise HTTPException(
                status_code=502,
                detail=f"GitHub returned HTTP {exc.response.status_code} for the pull request diff.",
            ) from exc
        except httpx.RequestError as exc:
            raise HTTPException(
                status_code=502,
                detail="Could not reach GitHub to fetch the pull request diff.",
            ) from exc

    # 2. Fall back to inline diff_text
    elif request.diff_text is not None:
        raw_diff = request.diff_text
        pr_title = None
        pr_author = None
        head_sha = None
        base_sha = None

    else:
        raise HTTPException(
            status_code=422,
            detail="Provide either 'pr_url' or 'diff_text'.",
        )

    file_path = request.file_path or "unknown"
    clean_code = request.clean_code or ""

    # 3. Run regression analysis
    quarantine = None
    if cached_scan is not None and cached_scan["scan_result"]:
        verdict = cached_scan["scan_result"]
        quarantine = cached_scan
        snapshot_id = cached_scan["snapshot_id"]
        if cached_scan["state"] == "RESOLVED":
            verdict["scan_status"] = verdict["status"]
            verdict["status"] = "RESOLVED"
    else:
        verdict = regression_engine.analyze_diff(
            raw_diff=raw_diff,
            repository=repository,
            pr_number=pr_number,
            file_path=file_path,
        )
    if request.pr_url is not None and cached_scan is None:
        quarantine = quarantine_store.record_scan(
            repository=repository,
            pr_number=pr_number,
            pr_url=request.pr_url,
            pr_title=pr_title,
            pr_author=pr_author,
            head_sha=head_sha,
            base_sha=base_sha,
            finding=verdict.get("finding"),
            risk_score=verdict["risk_score"],
            scan_result=verdict,
            diff_length=len(raw_diff),
        )

    if cached_scan is None:
        snapshot_id = snapshot_vault.archive_snapshot(
            repository=repository,
            pr_number=pr_number,
            file_path=file_path,
            original_code=clean_code,
            raw_diff=raw_diff,
            baseline_available=request.clean_code is not None,
        )
        if quarantine is not None:
            quarantine_store.set_snapshot_id(
                quarantine["finding_id"], snapshot_id
            )

    if request.pr_url is not None:
        active_quarantine = quarantine_store.get_active_for_pr(repository, pr_number)
        if active_quarantine is not None and verdict["status"] in {
            "PASSED",
            "RESOLVED",
        }:
            quarantine = active_quarantine
            verdict["scan_status"] = verdict["status"]
            verdict["status"] = "QUARANTINE_HOLD"
            verdict["is_regression"] = True
            verdict["finding"] = active_quarantine["finding"]
            verdict["risk_score"] = active_quarantine["risk_score"]
            verdict["hold_hours"] = quarantine_store.QUARANTINE_HOURS

    return {
        **verdict,
        "repository": repository,
        "pr_number": pr_number,
        "file_path": file_path,
        "snapshot_id": snapshot_id,
        "baseline_available": request.clean_code is not None,
        "diff_length": (
            cached_scan["diff_length"] if cached_scan is not None else len(raw_diff)
        ),
        "quarantine": quarantine,
        "merge_protection": _merge_protection_status(repository),
    }


@app.get("/api/quarantines", summary="List persisted PR scans")
async def list_pr_quarantines(active_only: bool = False):
    return {
        "items": quarantine_store.list_quarantines(active_only=active_only),
        "merge_protection": {
            "status": "NOT_ENFORCED",
            "reason": "GitHub App checks and repository branch protection are not configured.",
        },
    }


@app.get("/api/quarantines/{finding_id}", summary="Get a persisted finding")
async def get_pr_quarantine(finding_id: str):
    finding = quarantine_store.get_quarantine(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found.")
    return {
        **finding,
        "merge_protection": _merge_protection_status(finding["repository"]),
    }


@app.post("/api/quarantines/{finding_id}/resolve", summary="Record an authorized review decision")
async def resolve_pr_quarantine(
    finding_id: str,
    request: QuarantineResolutionRequest,
    authorization: str | None = Header(default=None),
):
    reviewer = _authenticated_reviewer(authorization)
    existing = quarantine_store.get_quarantine(finding_id)
    if existing is None:
        raise HTTPException(status_code=404, detail="Finding not found.")
    enforcement = quarantine_store.get_repository_enforcement(
        existing["repository"]
    )
    if existing.get("check_run_id") is not None:
        if not github_app.is_configured() or enforcement is None:
            raise HTTPException(
                status_code=503,
                detail="The GitHub required check could not be updated; contact an administrator.",
            )
        installation = quarantine_store.get_github_installation(
            enforcement["installation_id"]
        )
        if not installation or installation["state"] != "INSTALLED":
            raise HTTPException(
                status_code=503,
                detail="The GitHub App is not installed for this repository.",
            )
    try:
        result = quarantine_store.resolve_quarantine(
            finding_id,
            reviewer_identity=reviewer,
            reason=request.reason,
            decision=request.decision,
        )
    except ValueError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error
    if result is None:
        raise HTTPException(status_code=404, detail="Finding not found.")
    if existing.get("check_run_id") is not None and enforcement is not None:
        try:
            token = await github_app.installation_token(
                enforcement["installation_id"]
            )
            owner, repo = existing["repository"].split("/", maxsplit=1)
            await github_app.complete_check_run(
                token,
                owner,
                repo,
                existing["check_run_id"],
                conclusion="success" if request.decision == "RESOLVED" else "failure",
                title=(
                    "Authorized security review completed"
                    if request.decision == "RESOLVED"
                    else "Pull request rejected by security review"
                ),
                summary=(
                    "An authorized reviewer recorded a resolution. "
                    "Review history is retained by DiffShield."
                ),
            )
        except github_app.GitHubAppError as error:
            raise HTTPException(status_code=502, detail=str(error)) from error
    return {
        **result,
        "merge_protection": _merge_protection_status(result["repository"]),
    }


@app.get("/api/github/status", summary="Report GitHub enforcement configuration")
async def github_status(repository: str | None = None):
    app_configured = github_app.is_configured() and bool(
        os.environ.get("GITHUB_WEBHOOK_SECRET")
    )
    if repository is not None:
        if not re.fullmatch(r"[A-Za-z0-9-]+/[A-Za-z0-9_.-]+", repository):
            raise HTTPException(status_code=422, detail="Invalid repository identity.")
        enforcement = quarantine_store.get_repository_enforcement(repository)
        installation = (
            quarantine_store.get_github_installation(enforcement["installation_id"])
            if enforcement
            else None
        )
        installed = bool(installation and installation["state"] == "INSTALLED")
        required = False
        reason = (
            enforcement["reason"]
            if enforcement
            else "No verified GitHub App webhook has recorded this repository."
        )
        if installed and enforcement and app_configured:
            try:
                token = await github_app.installation_token(
                    enforcement["installation_id"]
                )
                owner, repo = repository.split("/", maxsplit=1)
                required, reason = await github_app.required_check_configured(
                    token,
                    owner,
                    repo,
                    enforcement["base_branch"],
                )
                quarantine_store.record_repository_enforcement(
                    repository,
                    installation_id=enforcement["installation_id"],
                    base_branch=enforcement["base_branch"],
                    required_check_configured=required,
                    reason=reason,
                )
            except github_app.GitHubAppError as error:
                reason = str(error)
        return {
            "app_configured": app_configured,
            "installed": installed,
            "required_check_configured": required,
            "merge_protection": "ENFORCED" if required else "NOT_ENFORCED",
            "reason": reason,
        }
    installations = quarantine_store.list_github_installations()
    installed = any(item["state"] == "INSTALLED" for item in installations)
    required_check_configured = quarantine_store.has_required_check_configured()
    return {
        "app_configured": app_configured,
        "installed": installed,
        "required_check_configured": required_check_configured,
        "merge_protection": "NOT_ENFORCED",
        "reason": "Specify a repository to check its App installation and required status check."
        if app_configured
        else "GitHub App credentials are not configured.",
    }


async def _process_app_pull_request(
    *,
    installation_id: int,
    account_login: str | None,
    owner: str,
    repo: str,
    pr_number: int,
    pr_url: str,
) -> dict:
    repository = f"{owner}/{repo}"
    metadata, raw_diff, installation_token = await github_app.fetch_pull_request(
        installation_id, owner, repo, pr_number
    )
    head_sha = metadata["head"]["sha"]
    base_sha = metadata["base"]["sha"]
    pr_author = metadata["user"]["login"]
    pr_title = metadata.get("title") if isinstance(metadata.get("title"), str) else None
    base_branch = metadata.get("base", {}).get("ref")
    if not isinstance(base_branch, str):
        raise HTTPException(
            status_code=502,
            detail="GitHub returned incomplete base branch metadata.",
        )

    quarantine_store.record_github_installation(
        installation_id,
        account_login=account_login,
        state="INSTALLED",
    )
    quarantine_store.mark_scanning(
        repository=repository,
        pr_number=pr_number,
        pr_url=pr_url,
        pr_title=pr_title,
        pr_author=pr_author,
        head_sha=head_sha,
        base_sha=base_sha,
    )
    check_run_id = await github_app.create_check_run(
        installation_token, owner, repo, head_sha
    )

    verdict = regression_engine.analyze_diff(
        raw_diff=raw_diff,
        repository=repository,
        pr_number=pr_number,
        file_path="unknown",
    )
    snapshot_id = snapshot_vault.archive_snapshot(
        repository=repository,
        pr_number=pr_number,
        file_path="unknown",
        original_code="",
        raw_diff=raw_diff,
        baseline_available=False,
    )
    quarantine = quarantine_store.record_scan(
        repository=repository,
        pr_number=pr_number,
        pr_url=pr_url,
        pr_title=pr_title,
        pr_author=pr_author,
        head_sha=head_sha,
        base_sha=base_sha,
        finding=verdict.get("finding"),
        risk_score=verdict["risk_score"],
        scan_result=verdict,
        snapshot_id=snapshot_id,
        diff_length=len(raw_diff),
    )
    active_quarantine = quarantine_store.get_active_for_pr(repository, pr_number)
    if active_quarantine is not None and verdict["status"] == "PASSED":
        quarantine = active_quarantine
        verdict["scan_status"] = "PASSED"
        verdict["status"] = "QUARANTINE_HOLD"
        verdict["is_regression"] = True
        verdict["finding"] = active_quarantine["finding"]
        verdict["risk_score"] = active_quarantine["risk_score"]
        verdict["hold_hours"] = quarantine_store.QUARANTINE_HOURS

    quarantine_store.set_check_run_id(quarantine["finding_id"], check_run_id)
    required_check, enforcement_reason = await github_app.required_check_configured(
        installation_token, owner, repo, base_branch
    )
    quarantine_store.record_repository_enforcement(
        repository,
        installation_id=installation_id,
        base_branch=base_branch,
        required_check_configured=required_check,
        reason=enforcement_reason,
    )
    is_held = verdict["status"] == "QUARANTINE_HOLD"
    await github_app.complete_check_run(
        installation_token,
        owner,
        repo,
        check_run_id,
        conclusion="failure" if is_held else "success",
        title=(
            f"Security review required ({quarantine['severity']})"
            if is_held
            else "No regression detected"
        ),
        summary=(
            f"DiffShield finding {quarantine['finding_id']} requires authorized review. "
            f"Risk score: {quarantine['risk_score']}/100. "
            "The quarantine remains active until an authorized reviewer resolves it."
            if is_held
            else "DiffShield detected no security guard regression in this commit. "
            "This result is not a guarantee that the pull request is safe."
        ),
    )
    if is_held and quarantine_store.begin_notification(
        quarantine["finding_id"], "quarantine"
    ):
        try:
            await github_app.notify_pull_request(
                installation_token,
                owner,
                repo,
                pr_number,
                finding_id=quarantine["finding_id"],
                notification_type="quarantine",
                severity=quarantine["severity"],
                risk_score=quarantine["risk_score"],
            )
        except github_app.GitHubAppError as error:
            quarantine_store.finish_notification(
                quarantine["finding_id"], "quarantine", error=str(error)
            )
            raise
        quarantine_store.finish_notification(
            quarantine["finding_id"], "quarantine"
        )
    return {
        **verdict,
        "snapshot_id": snapshot_id,
        "repository": repository,
        "pr_number": pr_number,
        "quarantine": quarantine,
        "merge_protection": {
            "status": "ENFORCED" if required_check else "NOT_ENFORCED",
            "reason": enforcement_reason,
        },
    }


@app.post("/api/github/webhook", summary="Receive signed GitHub webhook events")
async def github_webhook(
    request: Request,
    x_github_event: str | None = Header(default=None),
    x_github_delivery: str | None = Header(default=None),
    x_hub_signature_256: str | None = Header(default=None),
):
    secret = os.environ.get("GITHUB_WEBHOOK_SECRET")
    if not secret:
        raise HTTPException(
            status_code=503,
            detail="GitHub webhook processing is not configured.",
        )
    if not x_github_event or not x_github_delivery or len(x_github_delivery) > 128:
        raise HTTPException(status_code=400, detail="Required GitHub webhook headers are missing.")

    raw_body = await request.body()
    expected_signature = "sha256=" + hmac.new(
        secret.encode("utf-8"), raw_body, digestmod="sha256"
    ).hexdigest()
    if not x_hub_signature_256 or not hmac.compare_digest(
        expected_signature, x_hub_signature_256
    ):
        raise HTTPException(status_code=401, detail="Invalid GitHub webhook signature.")
    try:
        payload = json.loads(raw_body)
    except json.JSONDecodeError as error:
        raise HTTPException(status_code=400, detail="Webhook body must be valid JSON.") from error
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Webhook payload must be a JSON object.")

    if not quarantine_store.begin_delivery(x_github_delivery):
        return {"status": "duplicate", "delivery_id": x_github_delivery}

    try:
        action = payload.get("action")
        installation = payload.get("installation")
        installation_id = (
            installation.get("id") if isinstance(installation, dict) else None
        )
        account = installation.get("account") if isinstance(installation, dict) else None
        account_login = (
            account.get("login") if isinstance(account, dict) else None
        )

        if x_github_event == "installation" and action in {"created", "deleted"}:
            if type(installation_id) is not int or installation_id < 1:
                raise HTTPException(status_code=400, detail="GitHub installation identity is invalid.")
            quarantine_store.record_github_installation(
                installation_id,
                account_login=account_login if isinstance(account_login, str) else None,
                state="INSTALLED" if action == "created" else "REMOVED",
            )
            quarantine_store.finish_delivery(x_github_delivery)
            return {
                "status": "processed",
                "delivery_id": x_github_delivery,
                "installation_state": "INSTALLED" if action == "created" else "REMOVED",
                "merge_protection": "NOT_ENFORCED",
            }
        if x_github_event == "pull_request" and action in {
            "opened",
            "synchronize",
            "reopened",
        }:
            repository_data = payload.get("repository")
            pull_request = payload.get("pull_request")
            if not isinstance(repository_data, dict) or not isinstance(pull_request, dict):
                raise HTTPException(status_code=400, detail="Pull request webhook data is incomplete.")
            full_name = repository_data.get("full_name")
            number = pull_request.get("number")
            repo_match = (
                re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", full_name)
                if isinstance(full_name, str)
                else None
            )
            if repo_match is None or type(number) is not int or number < 1:
                raise HTTPException(status_code=400, detail="Pull request repository identity is invalid.")
            owner, repo = full_name.split("/", maxsplit=1)
            if owner in {".", ".."} or repo in {".", ".."}:
                raise HTTPException(status_code=400, detail="Pull request repository identity is invalid.")
            pr_url = f"https://github.com/{owner}/{repo}/pull/{number}"
            parse_github_pr_url(pr_url)
            if github_app.is_configured():
                if type(installation_id) is not int or installation_id < 1:
                    raise HTTPException(
                        status_code=400,
                        detail="GitHub App installation identity is missing from this event.",
                    )
                result = await _process_app_pull_request(
                    installation_id=installation_id,
                    account_login=account_login if isinstance(account_login, str) else None,
                    owner=owner,
                    repo=repo,
                    pr_number=number,
                    pr_url=pr_url,
                )
            else:
                result = await analyze_pr(AnalyzePRRequest(pr_url=pr_url))
            quarantine = result.get("quarantine")
            quarantine_state = quarantine.get("state") if quarantine else "ERROR"
            quarantine_store.finish_delivery(x_github_delivery)
            return {
                "status": "processed",
                "delivery_id": x_github_delivery,
                "scan_status": result["status"],
                "quarantine_state": quarantine_state,
                "merge_protection": result["merge_protection"],
            }

        if x_github_event == "pull_request" and action == "closed":
            quarantine_store.finish_delivery(x_github_delivery)
            return {
                "status": "processed",
                "delivery_id": x_github_delivery,
                "note": "Closing a pull request does not automatically resolve its quarantine.",
                "merge_protection": "NOT_ENFORCED",
            }

        if x_github_event in {"installation", "pull_request"}:
            quarantine_store.finish_delivery(x_github_delivery)
            return {
                "status": "acknowledged",
                "delivery_id": x_github_delivery,
                "merge_protection": "NOT_ENFORCED",
            }

        quarantine_store.finish_delivery(x_github_delivery)
        return {
            "status": "ignored",
            "delivery_id": x_github_delivery,
            "reason": "Webhook event is not used by DiffShield.",
        }
    except github_app.GitHubAppError as error:
        quarantine_store.finish_delivery(x_github_delivery, error=str(error))
        raise HTTPException(status_code=502, detail=str(error)) from error
    except HTTPException as error:
        quarantine_store.finish_delivery(x_github_delivery, error=error.detail)
        raise


@app.get("/api/repositories", summary="List repositories with recorded scans")
async def list_repositories():
    scans = quarantine_store.list_quarantines()
    return {"repositories": sorted({scan["repository"] for scan in scans})}


@app.get(
    "/api/rollback/{owner}/{repo}/{pr_number}",
    summary="Retrieve rollback snapshot for a PR",
)
async def get_rollback(owner: str, repo: str, pr_number: int):
    """Retrieve the archived code snapshot and reverse patch for instant recovery."""
    repository = f"{owner}/{repo}"
    result = snapshot_vault.retrieve_rollback(repository=repository, pr_number=pr_number)

    if not result["found"]:
        raise HTTPException(
            status_code=404,
            detail=result["message"],
        )

    return result


# ---------------------------------------------------------------------------
# Dev entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
