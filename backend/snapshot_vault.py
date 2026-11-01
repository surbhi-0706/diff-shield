"""
snapshot_vault.py - Defense-in-depth code snapshot vault for DiffShield.

Stores optional pre-PR baselines and reverse patches in a local SQLite database
(diffshield_vault.db) to support reverse-patch recovery.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Database location – stored next to this file for easy discovery
# ---------------------------------------------------------------------------

_DB_PATH = Path(__file__).parent / "diffshield_vault.db"


# ---------------------------------------------------------------------------
# Schema initialisation
# ---------------------------------------------------------------------------


def init_vault() -> None:
    """Create the code_snapshots table if it does not already exist."""
    with sqlite3.connect(_DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS code_snapshots (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                repository    TEXT    NOT NULL,
                pr_number     INTEGER NOT NULL,
                file_path     TEXT    NOT NULL,
                original_code TEXT    NOT NULL,
                raw_diff      TEXT    NOT NULL,
                reverse_patch TEXT    NOT NULL,
                baseline_available INTEGER NOT NULL DEFAULT 0,
                captured_at   TEXT    NOT NULL
            )
            """
        )
        columns = {
            row[1] for row in conn.execute("PRAGMA table_info(code_snapshots)")
        }
        if "baseline_available" not in columns:
            conn.execute(
                "ALTER TABLE code_snapshots "
                "ADD COLUMN baseline_available INTEGER NOT NULL DEFAULT 0"
            )
            conn.execute(
                "UPDATE code_snapshots SET baseline_available = 1 "
                "WHERE original_code != ''"
            )
        conn.commit()


# ---------------------------------------------------------------------------
# Patch inversion
# ---------------------------------------------------------------------------


def generate_reverse_patch(raw_diff: str) -> str:
    """Invert a unified diff so it can be applied to undo the PR changes.

    Swaps ``+`` and ``-`` prefix characters while preserving context lines
    and metadata headers (@@, ---, +++).
    """
    inverted_lines: list = []
    for line in raw_diff.splitlines(keepends=True):
        if line.startswith("+") and not line.startswith("+++"):
            inverted_lines.append("-" + line[1:])
        elif line.startswith("-") and not line.startswith("---"):
            inverted_lines.append("+" + line[1:])
        else:
            inverted_lines.append(line)
    return "".join(inverted_lines)


# ---------------------------------------------------------------------------
# CRUD operations
# ---------------------------------------------------------------------------


def archive_snapshot(
    repository: str,
    pr_number: int,
    file_path: str,
    original_code: str,
    raw_diff: str,
    baseline_available: bool | None = None,
) -> int:
    """Save a reverse patch and any supplied pre-PR baseline to the vault.

    Returns the row id of the newly inserted snapshot.
    """
    init_vault()
    if baseline_available is None:
        baseline_available = bool(original_code)
    reverse_patch = generate_reverse_patch(raw_diff)
    captured_at = datetime.now(timezone.utc).isoformat()

    with sqlite3.connect(_DB_PATH) as conn:
        cursor = conn.execute(
            """
            INSERT INTO code_snapshots
                (repository, pr_number, file_path, original_code,
                 raw_diff, reverse_patch, baseline_available, captured_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                repository,
                pr_number,
                file_path,
                original_code,
                raw_diff,
                reverse_patch,
                int(baseline_available),
                captured_at,
            ),
        )
        conn.commit()
        return cursor.lastrowid


def retrieve_rollback(repository: str, pr_number: int) -> dict:
    """Return the most recent snapshot for the given repository and PR.

    Returns a dict with keys:
        found         : bool
        id            : int | None
        repository    : str
        pr_number     : int
        file_path     : str | None
        original_code : str | None
        raw_diff      : str | None
        reverse_patch : str | None
        baseline_available : bool
        captured_at   : str | None
        message       : str
    """
    init_vault()

    with sqlite3.connect(_DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(
            """
            SELECT * FROM code_snapshots
            WHERE repository = ? AND pr_number = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (repository, pr_number),
        )
        row = cursor.fetchone()

    if row is None:
        return {
            "found": False,
            "id": None,
            "repository": repository,
            "pr_number": pr_number,
            "file_path": None,
            "original_code": None,
            "raw_diff": None,
            "reverse_patch": None,
            "baseline_available": False,
            "captured_at": None,
            "message": f"No snapshot found for {repository} PR#{pr_number}.",
        }

    baseline_available = bool(row["baseline_available"])
    message = (
        "Baseline code and reverse patch retrieved. Apply reverse_patch with `git apply` to rollback."
        if baseline_available
        else "No baseline source code was supplied; the reverse patch is available. "
        "Apply reverse_patch with `git apply` to rollback."
    )

    return {
        "found": True,
        "id": row["id"],
        "repository": row["repository"],
        "pr_number": row["pr_number"],
        "file_path": row["file_path"],
        "original_code": row["original_code"],
        "raw_diff": row["raw_diff"],
        "reverse_patch": row["reverse_patch"],
        "baseline_available": baseline_available,
        "captured_at": row["captured_at"],
        "message": message,
    }
