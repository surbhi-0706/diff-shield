
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parents[2]
DB_PATH = Path(os.getenv("DIFF_SHIELD_DB", ROOT / "diff_shield.db"))

app = FastAPI(
    title="DIFF SHIELD API",
    description="Security regression detection and adaptive PR protection.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_origin_regex=r"chrome-extension://[a-p]{32}",
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_connection():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    with get_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                repo TEXT NOT NULL,
                pr_number INTEGER,
                pr_url TEXT,
                head_sha TEXT,
                contributor_login TEXT,
                commit_author TEXT,
                committer TEXT,
                status TEXT NOT NULL,
                confidence REAL NOT NULL,
                risk_score INTEGER NOT NULL,
                severity TEXT NOT NULL,
                evidence_count INTEGER NOT NULL,
                evidence_json TEXT NOT NULL,
                hold_until TEXT,
                resolution TEXT
            )
            """
        )


initialize_database()


class ScanRequest(BaseModel):
    repo: str = Field(min_length=1, max_length=300)
    pr_number: Optional[int] = Field(default=None, ge=1)
    url: Optional[str] = None
    head_sha: Optional[str] = None
    contributor_login: Optional[str] = None
    commit_author: Optional[str] = None
    committer: Optional[str] = None

    suspicious: bool = False
    confidence: float = Field(default=0, ge=0, le=1)
    risk_score: int = Field(default=0, ge=0, le=100)
    severity: str = "LOW"
    evidence_count: int = Field(default=0, ge=0)
    evidence: list[str] = Field(default_factory=list)


class HoldResolution(BaseModel):
    resolution: str = Field(min_length=3, max_length=1000)


def require_token(authorization: Optional[str]):
    expected = os.getenv("DIFF_SHIELD_API_TOKEN")

    if not expected:
        raise HTTPException(
            status_code=503,
            detail="API token is not configured on the server.",
        )

    if authorization != f"Bearer {expected}":
        raise HTTPException(status_code=401, detail="Invalid or missing API token.")


def evaluate_policy(scan: ScanRequest):
    """
    Adaptive policy:
    - Clean: normal review.
    - High-confidence suspicious: block and prepare recovery review.
    - Uncertain suspicious: block for a 12-hour security hold.

    This API records policy decisions. It does not itself change GitHub
    branch protection or merge permissions.
    """
    if not scan.suspicious:
        return {
            "status": "CLEAN",
            "prepare_recovery": False,
            "hold_until": None,
        }

    high_confidence = (
        scan.confidence >= 0.90
        and scan.risk_score >= 85
        and scan.evidence_count >= 2
        and scan.severity.upper() in {"HIGH", "CRITICAL"}
    )

    if high_confidence:
        return {
            "status": "HIGH_CONFIDENCE",
            "prepare_recovery": True,
            "hold_until": None,
        }

    hold_until = datetime.now(timezone.utc) + timedelta(hours=12)

    return {
        "status": "REVIEW_REQUIRED",
        "prepare_recovery": False,
        "hold_until": hold_until.isoformat(),
    }


@app.get("/health")
def health():
    return {
        "service": "DIFF SHIELD",
        "status": "healthy",
        "database": "sqlite",
    }


@app.post("/api/v1/scans")
def create_scan(
    request: ScanRequest,
    authorization: Optional[str] = Header(default=None),
):
    require_token(authorization)
    decision = evaluate_policy(request)
    created_at = datetime.now(timezone.utc).isoformat()

    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO scans (
                created_at, repo, pr_number, pr_url, head_sha,
                contributor_login, commit_author, committer,
                status, confidence, risk_score, severity,
                evidence_count, evidence_json, hold_until
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                created_at,
                request.repo,
                request.pr_number,
                request.url,
                request.head_sha,
                request.contributor_login,
                request.commit_author,
                request.committer,
                decision["status"],
                request.confidence,
                request.risk_score,
                request.severity.upper(),
                request.evidence_count,
                __import__("json").dumps(request.evidence),
                decision["hold_until"],
            ),
        )
        scan_id = cursor.lastrowid

    return {
        "scan_id": scan_id,
        "repo": request.repo,
        "decision": decision,
        "created_at": created_at,
        "merge_block_requested": decision["status"] != "CLEAN",
        "message": (
            "Policy decision recorded. GitHub branch protection is not "
            "automatically changed by this endpoint."
        ),
    }


@app.get("/api/v1/scans")
def list_scans(
    authorization: Optional[str] = Header(default=None),
):
    require_token(authorization)

    with get_connection() as connection:
        rows = connection.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT 100"
        ).fetchall()

    import json

    results = []
    for row in rows:
        item = dict(row)
        item["evidence"] = json.loads(item.pop("evidence_json"))
        results.append(item)

    return {"scans": results}


@app.get("/api/v1/holds")
def list_holds(
    authorization: Optional[str] = Header(default=None),
):
    require_token(authorization)

    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT * FROM scans
            WHERE status = 'REVIEW_REQUIRED'
              AND resolution IS NULL
            ORDER BY hold_until ASC
            """
        ).fetchall()

    now = datetime.now(timezone.utc)
    holds = []

    for row in rows:
        item = dict(row)
        hold_until = datetime.fromisoformat(item["hold_until"])
        item["overdue"] = hold_until <= now
        holds.append(item)

    return {"holds": holds}


@app.post("/api/v1/holds/{scan_id}/resolve")
def resolve_hold(
    scan_id: int,
    request: HoldResolution,
    authorization: Optional[str] = Header(default=None),
):
    require_token(authorization)

    with get_connection() as connection:
        row = connection.execute(
            "SELECT id, status, resolution FROM scans WHERE id = ?",
            (scan_id,),
        ).fetchone()

        if row is None:
            raise HTTPException(status_code=404, detail="Scan not found.")

        if row["status"] != "REVIEW_REQUIRED":
            raise HTTPException(
                status_code=409,
                detail="This scan is not awaiting security review.",
            )

        if row["resolution"] is not None:
            raise HTTPException(
                status_code=409,
                detail="This hold has already been resolved.",
            )

        connection.execute(
            "UPDATE scans SET resolution = ? WHERE id = ?",
            (request.resolution, scan_id),
        )

    return {
        "scan_id": scan_id,
        "resolved": True,
        "resolution": request.resolution,
        "message": "Review resolution recorded. This does not merge or unblock a GitHub PR.",
    }
