"""Feedback review queue management for SOC audit and continuous evaluation (§8.2)."""

from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import sqlite3
from typing import Any, Optional

logger = logging.getLogger(__name__)

AUDIT_DB_PATH = Path("data/audit.sqlite")


def init_review_db(db_path: Path | str = AUDIT_DB_PATH) -> None:
    """Initialize review_queue table in SQLite database (§8.2)."""
    p = Path(db_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(p) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS review_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                request_id TEXT NOT NULL,
                label TEXT NOT NULL,
                note TEXT,
                content TEXT NOT NULL,
                status TEXT DEFAULT 'pending'
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_rev_status ON review_queue (status);")
        conn.commit()


def add_feedback(
    request_id: str,
    label: str,
    note: str = "",
    content: Optional[str] = None,
    db_path: Path | str = AUDIT_DB_PATH,
) -> int:
    """Submit a feedback item to review queue (§8.2)."""
    init_review_db(db_path)
    p = Path(db_path)

    # If content not supplied, look up in audit_log
    actual_content = content or ""
    if not actual_content:
        with sqlite3.connect(p) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.execute(
                "SELECT excerpt_redacted FROM audit_log WHERE request_id = ? ORDER BY id DESC LIMIT 1",
                (request_id,),
            )
            row = cur.fetchone()
            if row and row["excerpt_redacted"]:
                actual_content = row["excerpt_redacted"]
            else:
                actual_content = f"Content for {request_id}"

    with sqlite3.connect(p) as conn:
        cur = conn.execute(
            """
            INSERT INTO review_queue (request_id, label, note, content, status)
            VALUES (?, ?, ?, ?, 'pending')
            """,
            (request_id, label, note, actual_content),
        )
        conn.commit()
        return cur.lastrowid


def get_review_queue(
    status: Optional[str] = None,
    db_path: Path | str = AUDIT_DB_PATH,
) -> list[dict[str, Any]]:
    """Retrieve review queue items, optionally filtered by status (§8.2)."""
    init_review_db(db_path)
    p = Path(db_path)
    sql = "SELECT id, ts, request_id, label, note, content, status FROM review_queue"
    params: list[Any] = []
    if status:
        sql += " WHERE status = ?"
        params.append(status)
    sql += " ORDER BY id DESC"

    items = []
    with sqlite3.connect(p) as conn:
        conn.row_factory = sqlite3.Row
        for r in conn.execute(sql, params).fetchall():
            items.append({
                "id": r["id"],
                "ts": r["ts"],
                "request_id": r["request_id"],
                "label": r["label"],
                "note": r["note"] or "",
                "content": r["content"],
                "status": r["status"],
            })
    return items


def update_feedback_status(
    item_id: int,
    new_status: str,
    db_path: Path | str = AUDIT_DB_PATH,
) -> bool:
    """Approve or reject a review queue item (§8.2)."""
    init_review_db(db_path)
    p = Path(db_path)
    with sqlite3.connect(p) as conn:
        cur = conn.execute(
            "UPDATE review_queue SET status = ? WHERE id = ?",
            (new_status, item_id),
        )
        conn.commit()
        return cur.rowcount > 0


def approve_feedback(item_id: int, db_path: Path | str = AUDIT_DB_PATH) -> bool:
    return update_feedback_status(item_id, "approved", db_path)


def reject_feedback(item_id: int, db_path: Path | str = AUDIT_DB_PATH) -> bool:
    return update_feedback_status(item_id, "rejected", db_path)
