from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .database import connect_database, initialize_database
from .question_repository import _insert_review_event, _review_snapshot


AI_SUGGESTION_STATUSES = ("pending", "accepted", "rejected")
PROMPT_VERSION = "stage7_ai_suggestion_v1"
MOCK_MODEL_NAME = "mock-offline"
ALLOWED_UPDATE_FIELDS = (
    "question_type",
    "stem_text",
    "stem_latex",
    "answer_text",
    "analysis_latex",
    "tags_json",
    "meta_json",
)


class AiSuggestionError(RuntimeError):
    """Raised when an AI suggestion cannot be created or applied."""


def generate_ai_suggestions(
    *,
    db_path: Path | None = None,
    question_ids: tuple[int, ...] | None = None,
    mock: bool = False,
    limit: int = 1,
) -> dict[str, Any]:
    initialize_database(db_path)

    if not mock:
        return {
            "status": "skipped",
            "reason": "AI is not configured. Use --mock for a local simulated suggestion.",
            "inserted": 0,
            "suggestions": [],
        }

    with connect_database(db_path) as conn:
        rows = _load_questions_for_suggestions(conn, question_ids=question_ids, limit=limit)
        suggestions = [_insert_mock_suggestion(conn, row) for row in rows]
        conn.commit()

    return {
        "status": "ok",
        "inserted": len(suggestions),
        "suggestions": suggestions,
    }


def list_ai_suggestions(
    question_id: int,
    *,
    db_path: Path | None = None,
) -> list[dict[str, Any]]:
    initialize_database(db_path)
    with connect_database(db_path) as conn:
        rows = conn.execute(
            """
            SELECT id,
                   question_id,
                   suggestion_type,
                   input_summary,
                   suggestion_json,
                   model_name,
                   prompt_version,
                   status,
                   created_at,
                   reviewed_at
              FROM question_ai_suggestions
             WHERE question_id = ?
             ORDER BY id DESC
            """,
            (question_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def accept_ai_suggestion(
    suggestion_id: int,
    *,
    db_path: Path | None = None,
    expected_question_id: int | None = None,
) -> dict[str, Any]:
    initialize_database(db_path)
    with connect_database(db_path) as conn:
        suggestion = _load_suggestion(conn, suggestion_id)
        if suggestion["status"] != "pending":
            raise AiSuggestionError("Only pending suggestions can be accepted.")

        question_id = int(suggestion["question_id"])
        if expected_question_id is not None and expected_question_id != question_id:
            raise AiSuggestionError("AI suggestion does not belong to this question.")
        before = _review_snapshot(conn, question_id)
        if before is None:
            raise AiSuggestionError(f"Question not found: {question_id}")
        if before["review_status"] in ("reviewed", "approved"):
            raise AiSuggestionError("AI suggestions cannot overwrite reviewed or approved questions.")

        payload = _json_loads(suggestion["suggestion_json"], "suggestion_json")
        updates = _normalize_updates(payload.get("updates", {}))
        if not updates:
            raise AiSuggestionError("Suggestion does not contain supported question updates.")

        assignments = ", ".join(f"{field} = :{field}" for field in updates)
        conn.execute(
            f"""
            UPDATE questions
               SET {assignments},
                   updated_at = CURRENT_TIMESTAMP
             WHERE id = :question_id
            """,
            {**updates, "question_id": question_id},
        )
        after = _review_snapshot(conn, question_id)
        if after is None:
            raise AiSuggestionError(f"Question not found after update: {question_id}")
        _insert_review_event(
            conn,
            question_id=question_id,
            event_type="ai_suggestion_accept",
            source=f"ai_suggestion:{suggestion_id}",
            before=before,
            after=after,
        )
        conn.execute(
            """
            UPDATE question_ai_suggestions
               SET status = 'accepted',
                   reviewed_at = CURRENT_TIMESTAMP
             WHERE id = ?
            """,
            (suggestion_id,),
        )
        conn.commit()

    return {"suggestion_id": suggestion_id, "question_id": question_id, "status": "accepted"}


def reject_ai_suggestion(
    suggestion_id: int,
    *,
    db_path: Path | None = None,
    expected_question_id: int | None = None,
) -> dict[str, Any]:
    initialize_database(db_path)
    with connect_database(db_path) as conn:
        suggestion = _load_suggestion(conn, suggestion_id)
        question_id = int(suggestion["question_id"])
        if expected_question_id is not None and expected_question_id != question_id:
            raise AiSuggestionError("AI suggestion does not belong to this question.")
        if suggestion["status"] != "pending":
            raise AiSuggestionError("Only pending suggestions can be rejected.")
        conn.execute(
            """
            UPDATE question_ai_suggestions
               SET status = 'rejected',
                   reviewed_at = CURRENT_TIMESTAMP
             WHERE id = ?
            """,
            (suggestion_id,),
        )
        conn.commit()
    return {
        "suggestion_id": suggestion_id,
        "question_id": question_id,
        "status": "rejected",
    }


def _load_questions_for_suggestions(
    conn,
    *,
    question_ids: tuple[int, ...] | None,
    limit: int,
) -> list[dict[str, Any]]:
    params: list[Any] = []
    filter_sql = "WHERE q.review_status = 'pending'"
    if question_ids:
        placeholders = ", ".join("?" for _ in question_ids)
        filter_sql = f"WHERE q.id IN ({placeholders})"
        params.extend(question_ids)
    params.append(max(1, min(limit, 50)))

    rows = conn.execute(
        f"""
        SELECT q.id,
               q.qid,
               q.question_type,
               q.stem_text,
               q.stem_latex,
               q.tags_json,
               q.meta_json,
               q.bbox_json,
               q.review_status,
               qa.relative_path AS raw_crop_path
          FROM questions q
          LEFT JOIN question_assets qa
            ON qa.question_id = q.id
           AND qa.asset_kind = 'raw_crop'
         {filter_sql}
         ORDER BY q.id
         LIMIT ?
        """,
        params,
    ).fetchall()
    return [dict(row) for row in rows]


def _insert_mock_suggestion(conn, question: dict[str, Any]) -> dict[str, Any]:
    input_summary = {
        "question_id": question["id"],
        "qid": question["qid"],
        "stem_text_length": len(question["stem_text"] or ""),
        "raw_crop_path": question["raw_crop_path"],
        "meta_json": _safe_json(question["meta_json"]),
        "bbox_json": _safe_json(question["bbox_json"]),
    }
    suggestion = {
        "notes": [
            "Local mock suggestion only; no AI service was called.",
            "Review before accepting.",
        ],
        "updates": {
            "question_type": question["question_type"] or "ai_review_needed",
            "tags_json": _append_mock_tag(question["tags_json"]),
        },
    }
    cursor = conn.execute(
        """
        INSERT INTO question_ai_suggestions (
            question_id,
            suggestion_type,
            input_summary,
            suggestion_json,
            model_name,
            prompt_version,
            status
        ) VALUES (?, ?, ?, ?, ?, ?, 'pending')
        """,
        (
            question["id"],
            "mock_review",
            json.dumps(input_summary, ensure_ascii=False),
            json.dumps(suggestion, ensure_ascii=False),
            MOCK_MODEL_NAME,
            PROMPT_VERSION,
        ),
    )
    return {
        "id": int(cursor.lastrowid),
        "question_id": question["id"],
        "status": "pending",
    }


def _load_suggestion(conn, suggestion_id: int) -> dict[str, Any]:
    row = conn.execute(
        """
        SELECT id,
               question_id,
               suggestion_type,
               input_summary,
               suggestion_json,
               model_name,
               prompt_version,
               status
          FROM question_ai_suggestions
         WHERE id = ?
        """,
        (suggestion_id,),
    ).fetchone()
    if row is None:
        raise AiSuggestionError(f"AI suggestion not found: {suggestion_id}")
    return dict(row)


def _normalize_updates(updates: Any) -> dict[str, Any]:
    if not isinstance(updates, dict):
        return {}

    normalized: dict[str, Any] = {}
    for field, value in updates.items():
        if field not in ALLOWED_UPDATE_FIELDS:
            continue
        if field in ("tags_json", "meta_json"):
            text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
            _json_loads(text, field)
            normalized[field] = text
        elif field in ("stem_text", "stem_latex"):
            text = str(value or "").strip()
            if not text:
                raise AiSuggestionError(f"{field} cannot be empty.")
            normalized[field] = text
        else:
            text = str(value).strip() if value is not None else None
            normalized[field] = text or None
    return normalized


def _append_mock_tag(tags_json: str | None) -> str:
    tags = _safe_json(tags_json)
    if not isinstance(tags, list):
        tags = []
    if "ai_mock_suggestion" not in tags:
        tags.append("ai_mock_suggestion")
    return json.dumps(tags, ensure_ascii=False)


def _json_loads(value: str, field_name: str) -> Any:
    try:
        return json.loads(value or "{}")
    except json.JSONDecodeError as exc:
        raise AiSuggestionError(f"{field_name} must be valid JSON.") from exc


def _safe_json(value: str | None) -> Any:
    try:
        return json.loads(value or "{}")
    except json.JSONDecodeError:
        return {}
