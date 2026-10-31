"""
snapshot_vault.py - Defense-in-depth code snapshot vault for DiffShield.

Stores pre-PR baselines and reverse patches in a local SQLite database
(diffshield_vault.db) to enable 1-click git rollbacks.
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
                captured_at   TEXT    NOT NULL
            )
            """
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
) -> int:
    """Save a pre-PR baseline and its reverse patch to the vault.

    Returns the row id of the newly inserted snapshot.
    """
    init_vault()
    reverse_patch = generate_reverse_patch(raw_diff)
    captured_at = datetime.now(timezone.utc).isoformat()

    with sqlite3.connect(_DB_PATH) as conn:
        cursor = conn.execute(
            """
            INSERT INTO code_snapshots
                (repository, pr_number, file_path, original_code,
                 raw_diff, reverse_patch, captured_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                repository,
                pr_number,
                file_path,
                original_code,
                raw_diff,
                reverse_patch,
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
            "captured_at": None,
            "message": f"No snapshot found for {repository} PR#{pr_number}.",
        }

    return {
        "found": True,
        "id": row["id"],
        "repository": row["repository"],
        "pr_number": row["pr_number"],
        "file_path": row["file_path"],
        "original_code": row["original_code"],
        "raw_diff": row["raw_diff"],
        "reverse_patch": row["reverse_patch"],
        "captured_at": row["captured_at"],
        "message": "Snapshot retrieved successfully. Apply reverse_patch with `git apply` to rollback.",
    }
