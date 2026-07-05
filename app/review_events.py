from __future__ import annotations

import json
import sqlite3
from typing import Any


class ReviewEventService:
    """Small public service for writing auditable review events."""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def record(
        self,
        *,
        question_id: int,
        event_type: str,
        source: str,
        before: dict[str, Any],
        after: dict[str, Any],
    ) -> None:
        self.conn.execute(
            """
            INSERT INTO question_review_events (
                question_id,
                event_type,
                source,
                before_json,
                after_json,
                diff_json
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                question_id,
                event_type,
                source,
                json.dumps(before, ensure_ascii=False),
                json.dumps(after, ensure_ascii=False),
                json.dumps(_dict_diff(before, after), ensure_ascii=False),
            ),
        )


def _dict_diff(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    return {
        key: {"before": before.get(key), "after": after.get(key)}
        for key in sorted(set(before) | set(after))
        if before.get(key) != after.get(key)
    }
