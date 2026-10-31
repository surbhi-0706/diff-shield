"""Persistent SQLite storage for DiffShield PR findings and review history."""

from __future__ import annotations

import json
import os
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

QUARANTINE_HOURS = 12
ACTIVE_STATES = ("QUARANTINED", "REVIEW_REQUIRED", "ESCALATED", "REJECTED")


def _database_path() -> Path:
    configured = os.environ.get("DIFFSHIELD_QUARANTINE_DB")
    return Path(configured) if configured else Path(__file__).parent / "diffshield_quarantines.db"


def _connect() -> sqlite3.Connection:
    path = _database_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA foreign_keys=ON")
    return connection


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds")


def init_db() -> None:
    with _connect() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS quarantines (
                finding_id TEXT PRIMARY KEY,
                repository TEXT NOT NULL,
                pr_number INTEGER NOT NULL,
                pr_url TEXT NOT NULL,
                pr_title TEXT,
                pr_author TEXT,
                head_sha TEXT,
                base_sha TEXT,
                finding_json TEXT NOT NULL,
                scan_result_json TEXT NOT NULL DEFAULT '{}',
                snapshot_id INTEGER,
                diff_length INTEGER NOT NULL DEFAULT 0,
                severity TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                confidence REAL,
                detected_at TEXT NOT NULL,
                quarantine_started_at TEXT,
                review_deadline TEXT,
                state TEXT NOT NULL,
                review_history TEXT NOT NULL DEFAULT '[]',
                reviewer_identity TEXT,
                resolution_reason TEXT,
                check_run_id INTEGER,
                updated_at TEXT NOT NULL,
                UNIQUE(repository, pr_number, head_sha)
            );
            CREATE INDEX IF NOT EXISTS idx_quarantines_state_deadline
                ON quarantines(state, review_deadline);
            CREATE INDEX IF NOT EXISTS idx_quarantines_repository_pr
                ON quarantines(repository, pr_number);
            CREATE TABLE IF NOT EXISTS webhook_deliveries (
                delivery_id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                error TEXT,
                received_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS github_installations (
                installation_id INTEGER PRIMARY KEY,
                account_login TEXT,
                state TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS repository_enforcement (
                repository TEXT PRIMARY KEY,
                installation_id INTEGER NOT NULL,
                base_branch TEXT NOT NULL,
                required_check_configured INTEGER NOT NULL,
                reason TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS notification_events (
                finding_id TEXT NOT NULL,
                notification_type TEXT NOT NULL,
                status TEXT NOT NULL,
                error TEXT,
                updated_at TEXT NOT NULL,
                PRIMARY KEY(finding_id, notification_type)
            );
            """
        )
        columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(quarantines)")
        }
        if "pr_title" not in columns:
            connection.execute("ALTER TABLE quarantines ADD COLUMN pr_title TEXT")
        if "scan_result_json" not in columns:
            connection.execute(
                "ALTER TABLE quarantines ADD COLUMN scan_result_json TEXT NOT NULL DEFAULT '{}'"
            )
        if "snapshot_id" not in columns:
            connection.execute("ALTER TABLE quarantines ADD COLUMN snapshot_id INTEGER")
        if "diff_length" not in columns:
            connection.execute(
                "ALTER TABLE quarantines ADD COLUMN diff_length INTEGER NOT NULL DEFAULT 0"
            )


def _decode_row(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    record = dict(row)
    record["finding"] = json.loads(record.pop("finding_json"))
    record["scan_result"] = json.loads(record.pop("scan_result_json"))
    record["review_history"] = json.loads(record["review_history"])
    return record


def record_scan(
    *,
    repository: str,
    pr_number: int,
    pr_url: str,
    pr_title: str | None = None,
    pr_author: str | None,
    head_sha: str | None,
    base_sha: str | None,
    finding: dict[str, Any] | None,
    risk_score: int,
    confidence: float | None = None,
    detected_at: datetime | None = None,
    scan_result: dict[str, Any] | None = None,
    snapshot_id: int | None = None,
    diff_length: int = 0,
) -> dict[str, Any]:
    """Persist a scan; flagged findings receive a deadline exactly 12 hours later."""
    init_db()
    detected = detected_at or _now()
    state = "QUARANTINED" if finding else "CLEAN"
    started = detected if finding else None
    deadline = started + timedelta(hours=QUARANTINE_HOURS) if started else None
    finding_id = (
        str(finding.get("id") or f"DS-{uuid.uuid4().hex[:12].upper()}")
        if finding
        else f"DS-SCAN-{uuid.uuid4().hex[:12].upper()}"
    )
    serialized_finding = json.dumps(finding or {}, sort_keys=True)

    with _connect() as connection:
        connection.execute(
            """
            INSERT INTO quarantines (
                finding_id, repository, pr_number, pr_url, pr_title, pr_author, head_sha,
                base_sha, finding_json, scan_result_json, snapshot_id, diff_length,
                severity, risk_score, confidence,
                detected_at, quarantine_started_at, review_deadline, state,
                review_history, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '[]', ?)
            ON CONFLICT(repository, pr_number, head_sha) DO UPDATE SET
                pr_url=excluded.pr_url,
                pr_title=COALESCE(excluded.pr_title, quarantines.pr_title),
                pr_author=COALESCE(excluded.pr_author, quarantines.pr_author),
                base_sha=COALESCE(excluded.base_sha, quarantines.base_sha),
                finding_json=excluded.finding_json,
                scan_result_json=excluded.scan_result_json,
                snapshot_id=COALESCE(excluded.snapshot_id, quarantines.snapshot_id),
                diff_length=excluded.diff_length,
                severity=excluded.severity,
                risk_score=excluded.risk_score,
                confidence=excluded.confidence,
                detected_at=excluded.detected_at,
                quarantine_started_at=CASE
                    WHEN quarantines.state IN ('QUARANTINED', 'REVIEW_REQUIRED', 'ESCALATED', 'RESOLVED', 'REJECTED')
                    THEN quarantines.quarantine_started_at
                    ELSE excluded.quarantine_started_at
                END,
                review_deadline=CASE
                    WHEN quarantines.state IN ('QUARANTINED', 'REVIEW_REQUIRED', 'ESCALATED', 'RESOLVED', 'REJECTED')
                    THEN quarantines.review_deadline
                    ELSE excluded.review_deadline
                END,
                state=CASE
                    WHEN quarantines.state IN ('QUARANTINED', 'REVIEW_REQUIRED', 'ESCALATED', 'RESOLVED', 'REJECTED')
                    THEN quarantines.state
                    ELSE excluded.state
                END,
                updated_at=excluded.updated_at
            """,
            (
                finding_id,
                repository,
                pr_number,
                pr_url,
                pr_title,
                pr_author,
                head_sha,
                base_sha,
                serialized_finding,
                json.dumps(scan_result or {}, sort_keys=True),
                snapshot_id,
                diff_length,
                str((finding or {}).get("severity", "NONE")),
                int(risk_score),
                confidence,
                _timestamp(detected),
                _timestamp(started) if started else None,
                _timestamp(deadline) if deadline else None,
                state,
                _timestamp(_now()),
            ),
        )
        row = connection.execute(
            """
            SELECT * FROM quarantines
            WHERE repository = ? AND pr_number = ?
                AND head_sha IS ?
            """,
            (repository, pr_number, head_sha),
        ).fetchone()
    record = _decode_row(row)
    if record is None:
        raise RuntimeError("The scan record was not persisted.")
    return record


def mark_scanning(
    *,
    repository: str,
    pr_number: int,
    pr_url: str,
    pr_title: str | None,
    pr_author: str | None,
    head_sha: str,
    base_sha: str | None,
) -> None:
    init_db()
    now = _timestamp(_now())
    with _connect() as connection:
        connection.execute(
            """
            INSERT INTO quarantines (
                finding_id, repository, pr_number, pr_url, pr_title, pr_author,
                head_sha, base_sha, finding_json, severity, risk_score,
                detected_at, state, review_history, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, '{}', 'NONE', 0, ?, 'SCANNING', '[]', ?)
            ON CONFLICT(repository, pr_number, head_sha) DO UPDATE SET
                pr_url=excluded.pr_url,
                pr_title=COALESCE(excluded.pr_title, quarantines.pr_title),
                pr_author=COALESCE(excluded.pr_author, quarantines.pr_author),
                base_sha=COALESCE(excluded.base_sha, quarantines.base_sha),
                state=CASE
                    WHEN quarantines.state IN ('QUARANTINED', 'REVIEW_REQUIRED', 'ESCALATED', 'RESOLVED', 'REJECTED')
                    THEN quarantines.state
                    ELSE 'SCANNING'
                END,
                updated_at=excluded.updated_at
            """,
            (
                f"DS-SCAN-{uuid.uuid4().hex[:12].upper()}",
                repository,
                pr_number,
                pr_url,
                pr_title,
                pr_author,
                head_sha,
                base_sha,
                now,
                now,
            ),
        )


def mark_scan_error(
    repository: str,
    pr_number: int,
    head_sha: str,
    error: str,
) -> None:
    init_db()
    now = _timestamp(_now())
    with _connect() as connection:
        connection.execute(
            """
            UPDATE quarantines
            SET state = 'ERROR', finding_json = ?, updated_at = ?
            WHERE repository = ? AND pr_number = ? AND head_sha = ?
                AND state = 'SCANNING'
            """,
            (json.dumps({"error": error}), now, repository, pr_number, head_sha),
        )


def list_quarantines(*, active_only: bool = False) -> list[dict[str, Any]]:
    init_db()
    expire_overdue()
    with _connect() as connection:
        if active_only:
            placeholders = ",".join("?" for _ in ACTIVE_STATES)
            rows = connection.execute(
                f"SELECT * FROM quarantines WHERE state IN ({placeholders}) "
                "ORDER BY detected_at DESC",
                ACTIVE_STATES,
            ).fetchall()
        else:
            rows = connection.execute(
                "SELECT * FROM quarantines ORDER BY detected_at DESC"
            ).fetchall()
    return [record for row in rows if (record := _decode_row(row)) is not None]


def get_quarantine(finding_id: str) -> dict[str, Any] | None:
    init_db()
    expire_overdue()
    with _connect() as connection:
        row = connection.execute(
            "SELECT * FROM quarantines WHERE finding_id = ?", (finding_id,)
        ).fetchone()
    return _decode_row(row)


def get_scan_for_commit(
    repository: str,
    pr_number: int,
    head_sha: str,
) -> dict[str, Any] | None:
    init_db()
    with _connect() as connection:
        row = connection.execute(
            """
            SELECT * FROM quarantines
            WHERE repository = ? AND pr_number = ? AND head_sha = ?
            """,
            (repository, pr_number, head_sha),
        ).fetchone()
    return _decode_row(row)


def set_snapshot_id(finding_id: str, snapshot_id: int) -> None:
    init_db()
    with _connect() as connection:
        connection.execute(
            "UPDATE quarantines SET snapshot_id = ?, updated_at = ? WHERE finding_id = ?",
            (snapshot_id, _timestamp(_now()), finding_id),
        )


def get_active_for_pr(repository: str, pr_number: int) -> dict[str, Any] | None:
    init_db()
    expire_overdue()
    placeholders = ",".join("?" for _ in ACTIVE_STATES)
    with _connect() as connection:
        row = connection.execute(
            f"""
            SELECT * FROM quarantines
            WHERE repository = ? AND pr_number = ? AND state IN ({placeholders})
            ORDER BY detected_at ASC
            LIMIT 1
            """,
            (repository, pr_number, *ACTIVE_STATES),
        ).fetchone()
    return _decode_row(row)


def expire_overdue(*, now: datetime | None = None) -> int:
    """Persist escalation from absolute UTC deadlines; never releases a quarantine."""
    init_db()
    current_time = _timestamp(now or _now())
    with _connect() as connection:
        rows = connection.execute(
            """
            SELECT finding_id, review_history FROM quarantines
            WHERE state IN ('QUARANTINED', 'REVIEW_REQUIRED')
                AND review_deadline IS NOT NULL AND review_deadline <= ?
            """,
            (current_time,),
        ).fetchall()
        for row in rows:
            history = json.loads(row["review_history"])
            history.append(
                {"action": "ESCALATED", "at": current_time, "reason": "Review deadline expired"}
            )
            connection.execute(
                """
                UPDATE quarantines
                SET state = 'ESCALATED', review_history = ?, updated_at = ?
                WHERE finding_id = ?
                """,
                (json.dumps(history, sort_keys=True), current_time, row["finding_id"]),
            )
    return len(rows)


def resolve_quarantine(
    finding_id: str,
    *,
    reviewer_identity: str,
    reason: str,
    decision: str,
) -> dict[str, Any] | None:
    if decision not in ("RESOLVED", "REJECTED"):
        raise ValueError("Decision must be RESOLVED or REJECTED.")
    init_db()
    now = _timestamp(_now())
    with _connect() as connection:
        row = connection.execute(
            "SELECT * FROM quarantines WHERE finding_id = ?", (finding_id,)
        ).fetchone()
        if row is None:
            return None
        if row["state"] not in ACTIVE_STATES:
            raise ValueError(f"Cannot resolve a finding in {row['state']} state.")
        history = json.loads(row["review_history"])
        history.append(
            {
                "action": decision,
                "at": now,
                "reviewer": reviewer_identity,
                "reason": reason,
            }
        )
        connection.execute(
            """
            UPDATE quarantines
            SET state = ?, reviewer_identity = ?, resolution_reason = ?,
                review_history = ?, updated_at = ?
            WHERE finding_id = ?
            """,
            (decision, reviewer_identity, reason, json.dumps(history, sort_keys=True), now, finding_id),
        )
        updated = connection.execute(
            "SELECT * FROM quarantines WHERE finding_id = ?", (finding_id,)
        ).fetchone()
    return _decode_row(updated)


def begin_delivery(delivery_id: str) -> bool:
    """Return false for an already processing or completed webhook delivery."""
    init_db()
    now = _timestamp(_now())
    with _connect() as connection:
        row = connection.execute(
            "SELECT status FROM webhook_deliveries WHERE delivery_id = ?",
            (delivery_id,),
        ).fetchone()
        if row and row["status"] != "ERROR":
            return False
        connection.execute(
            """
            INSERT INTO webhook_deliveries(delivery_id, status, received_at, updated_at)
            VALUES (?, 'PROCESSING', ?, ?)
            ON CONFLICT(delivery_id) DO UPDATE SET
                status = 'PROCESSING', error = NULL, updated_at = excluded.updated_at
            """,
            (delivery_id, now, now),
        )
    return True


def finish_delivery(delivery_id: str, *, error: str | None = None) -> None:
    init_db()
    with _connect() as connection:
        connection.execute(
            """
            UPDATE webhook_deliveries SET status = ?, error = ?, updated_at = ?
            WHERE delivery_id = ?
            """,
            ("ERROR" if error else "COMPLETED", error, _timestamp(_now()), delivery_id),
        )


def set_check_run_id(finding_id: str, check_run_id: int) -> None:
    init_db()
    with _connect() as connection:
        connection.execute(
            "UPDATE quarantines SET check_run_id = ?, updated_at = ? WHERE finding_id = ?",
            (check_run_id, _timestamp(_now()), finding_id),
        )


def record_github_installation(
    installation_id: int,
    *,
    account_login: str | None,
    state: str,
) -> None:
    if type(installation_id) is not int or installation_id < 1:
        raise ValueError("GitHub installation identity is invalid.")
    if state not in {"INSTALLED", "REMOVED"}:
        raise ValueError("GitHub installation state is invalid.")
    init_db()
    with _connect() as connection:
        connection.execute(
            """
            INSERT INTO github_installations(installation_id, account_login, state, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(installation_id) DO UPDATE SET
                account_login=excluded.account_login,
                state=excluded.state,
                updated_at=excluded.updated_at
            """,
            (installation_id, account_login, state, _timestamp(_now())),
        )


def get_github_installation(installation_id: int) -> dict[str, Any] | None:
    init_db()
    with _connect() as connection:
        row = connection.execute(
            "SELECT * FROM github_installations WHERE installation_id = ?",
            (installation_id,),
        ).fetchone()
    return dict(row) if row else None


def list_github_installations() -> list[dict[str, Any]]:
    init_db()
    with _connect() as connection:
        rows = connection.execute(
            "SELECT * FROM github_installations ORDER BY updated_at DESC"
        ).fetchall()
    return [dict(row) for row in rows]


def has_required_check_configured() -> bool:
    init_db()
    with _connect() as connection:
        row = connection.execute(
            "SELECT 1 FROM repository_enforcement WHERE required_check_configured = 1 LIMIT 1"
        ).fetchone()
    return row is not None


def record_repository_enforcement(
    repository: str,
    *,
    installation_id: int,
    base_branch: str,
    required_check_configured: bool,
    reason: str,
) -> None:
    init_db()
    with _connect() as connection:
        connection.execute(
            """
            INSERT INTO repository_enforcement(
                repository, installation_id, base_branch,
                required_check_configured, reason, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(repository) DO UPDATE SET
                installation_id=excluded.installation_id,
                base_branch=excluded.base_branch,
                required_check_configured=excluded.required_check_configured,
                reason=excluded.reason,
                updated_at=excluded.updated_at
            """,
            (
                repository,
                installation_id,
                base_branch,
                int(required_check_configured),
                reason,
                _timestamp(_now()),
            ),
        )


def get_repository_enforcement(repository: str) -> dict[str, Any] | None:
    init_db()
    with _connect() as connection:
        row = connection.execute(
            "SELECT * FROM repository_enforcement WHERE repository = ?",
            (repository,),
        ).fetchone()
    if not row:
        return None
    result = dict(row)
    result["required_check_configured"] = bool(
        result["required_check_configured"]
    )
    return result


def begin_notification(finding_id: str, notification_type: str) -> bool:
    init_db()
    now = _now()
    now_text = _timestamp(now)
    with _connect() as connection:
        row = connection.execute(
            """
            SELECT status, updated_at FROM notification_events
            WHERE finding_id = ? AND notification_type = ?
            """,
            (finding_id, notification_type),
        ).fetchone()
        if row and row["status"] == "COMPLETED":
            return False
        if row and row["status"] in {"PROCESSING", "ERROR"}:
            updated = datetime.fromisoformat(row["updated_at"])
            cooldown = timedelta(minutes=10 if row["status"] == "PROCESSING" else 5)
            if now - updated < cooldown:
                return False
        connection.execute(
            """
            INSERT INTO notification_events(
                finding_id, notification_type, status, updated_at
            ) VALUES (?, ?, 'PROCESSING', ?)
            ON CONFLICT(finding_id, notification_type) DO UPDATE SET
                status = 'PROCESSING', error = NULL, updated_at = excluded.updated_at
            """,
            (finding_id, notification_type, now_text),
        )
    return True


def finish_notification(
    finding_id: str,
    notification_type: str,
    *,
    error: str | None = None,
) -> None:
    init_db()
    with _connect() as connection:
        connection.execute(
            """
            UPDATE notification_events
            SET status = ?, error = ?, updated_at = ?
            WHERE finding_id = ? AND notification_type = ?
            """,
            (
                "ERROR" if error else "COMPLETED",
                error,
                _timestamp(_now()),
                finding_id,
                notification_type,
            ),
        )
