from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from typing import Any

from .review_events import ReviewEventService
from .structured_content import parse_json_field


class StructuredContentServiceError(RuntimeError):
    """Raised when structured candidate state cannot be changed."""


class StructuredContentService:
    """Public service for structured candidate status transitions."""

    ACTIONS = {
        "accept": ("human_reviewed", "manual_accept"),
        "downgrade": ("needs_review", "manual_downgraded"),
        "needs_review": ("needs_review", "manual_needs_review"),
    }

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.events = ReviewEventService(conn)

    def update_review_status(
        self,
        question_id: int,
        *,
        action: str,
        source: str = "web_stage11",
    ) -> dict[str, Any]:
        if action not in self.ACTIONS:
            raise StructuredContentServiceError(
                f"Unsupported structured review action: {action}"
            )
        target_status, marker = self.ACTIONS[action]
        before_row = self.conn.execute(
            """
            SELECT *
              FROM question_structured_contents
             WHERE question_id = ?
            """,
            (question_id,),
        ).fetchone()
        if before_row is None:
            raise StructuredContentServiceError(
                f"Structured content not found: {question_id}"
            )
        before = dict(before_row)
        flags = parse_json_field(before.get("quality_flags_json"), [])
        if not isinstance(flags, list):
            flags = []
        flags = _dedupe([str(flag) for flag in flags] + [marker])
        model_info = parse_json_field(before.get("model_info"), {})
        if not isinstance(model_info, dict):
            model_info = {}
        model_info["last_manual_structured_review"] = {
            "action": action,
            "target_status": target_status,
            "source": source,
            "created_at": _utc_now(),
        }
        self.conn.execute(
            """
            UPDATE question_structured_contents
               SET ai_status = ?,
                   quality_flags_json = ?,
                   model_info = ?,
                   updated_at = CURRENT_TIMESTAMP
             WHERE question_id = ?
            """,
            (
                target_status,
                json.dumps(flags, ensure_ascii=False),
                json.dumps(model_info, ensure_ascii=False),
                question_id,
            ),
        )
        after_row = self.conn.execute(
            "SELECT * FROM question_structured_contents WHERE question_id = ?",
            (question_id,),
        ).fetchone()
        after = dict(after_row) if after_row is not None else {}
        before_snapshot = structured_event_snapshot(before)
        after_snapshot = structured_event_snapshot(after)
        self.events.record(
            question_id=question_id,
            event_type="structured_status_update",
            source=source,
            before=before_snapshot,
            after=after_snapshot,
        )
        return {
            "status": "ok",
            "question_id": question_id,
            "action": action,
            "before": before_snapshot,
            "after": after_snapshot,
        }


def structured_event_snapshot(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "question_id": row.get("question_id"),
        "ai_status": row.get("ai_status"),
        "normalized_type": row.get("normalized_type"),
        "quality_flags_json": row.get("quality_flags_json"),
        "confidence": row.get("confidence"),
        "model_info": row.get("model_info"),
    }


def _dedupe(values: list[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        if value and value not in result:
            result.append(value)
    return result


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
