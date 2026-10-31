"""
main.py - DiffShield FastAPI application.

Endpoints:
  GET  /health                              - Service liveness check
  POST /api/analyze-pr                      - Analyze a PR diff for security regressions
  GET  /api/rollback/{owner}/{repo}/{pr_number} - Retrieve rollback snapshot
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure sibling modules are importable when uvicorn is launched from any CWD
sys.path.insert(0, str(Path(__file__).parent))

import re
import httpx
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional
from urllib.parse import urlsplit

import regression_engine
import snapshot_vault

# ---------------------------------------------------------------------------
# Application setup
# ---------------------------------------------------------------------------

app = FastAPI(
    title="DiffShield Security Analysis API",
    description=(
        "Deterministic AST/block-level PR diff analyser that detects security-guard "
        "regressions, generates reverse patches, and stores optional supplied baselines."
    ),
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_origin_regex=r"^chrome-extension://[a-p]{32}$",
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

# Initialise the vault schema on startup
snapshot_vault.init_vault()


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
    pr_number = int(pr_number_text)
    diff_url = f"https://github.com/{owner}/{repo}/pull/{pr_number}.diff"
    return owner, repo, pr_number, diff_url


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


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

    if request.pr_url is not None and request.diff_text is not None:
        raise HTTPException(
            status_code=422,
            detail="Provide either 'pr_url' or 'diff_text', not both.",
        )

    # 1. Fetch the diff only from a validated GitHub pull request URL.
    if request.pr_url is not None:
        owner, repo, pr_number, diff_url = parse_github_pr_url(request.pr_url)
        repository = f"{owner}/{repo}"
        try:
            headers = {
                "User-Agent": "DiffShield-AppSec/1.0",
                "Accept": "text/plain",
            }
            async with httpx.AsyncClient(
                follow_redirects=False,
                timeout=20,
                headers=headers,
            ) as client:
                response = await client.get(diff_url)
                response.raise_for_status()
                raw_diff = response.text
                if len(raw_diff) > 5_000_000:
                    raise HTTPException(
                        status_code=413,
                        detail="The GitHub pull request diff exceeds the 5 MB analysis limit.",
                    )
        except httpx.HTTPStatusError as exc:
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

    else:
        raise HTTPException(
            status_code=422,
            detail="Provide either 'pr_url' or 'diff_text'.",
        )

    file_path = request.file_path or "unknown"
    clean_code = request.clean_code or ""

    # 3. Run regression analysis
    verdict = regression_engine.analyze_diff(
        raw_diff=raw_diff,
        repository=repository,
        pr_number=pr_number,
        file_path=file_path,
    )

    # 4. Archive snapshot regardless of verdict
    snapshot_id = snapshot_vault.archive_snapshot(
        repository=repository,
        pr_number=pr_number,
        file_path=file_path,
        original_code=clean_code,
        raw_diff=raw_diff,
        baseline_available=request.clean_code is not None,
    )

    return {
        **verdict,
        "repository": repository,
        "pr_number": pr_number,
        "file_path": file_path,
        "snapshot_id": snapshot_id,
        "baseline_available": request.clean_code is not None,
        "diff_length": len(raw_diff),
    }


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
