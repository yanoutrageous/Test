from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .database import connect_database, connect_database_read_only, initialize_database


STRUCTURED_ALGORITHM_VERSION = "stage9_structured_v1"
STRUCTURED_STATUSES = (
    "unprocessed",
    "ai_draft",
    "ai_verified",
    "needs_review",
    "failed",
    "human_reviewed",
)
NORMALIZED_TYPES = ("choice", "multiple_choice", "blank", "solution", "unknown")


def normalize_question_type(value: str | None) -> str:
    text = (value or "").strip().lower()
    if not text:
        return "unknown"
    if "多选" in text or "multiple" in text:
        return "multiple_choice"
    if "选择" in text or "choice" in text or "single" in text:
        return "choice"
    if "填空" in text or "blank" in text:
        return "blank"
    if "解答" in text or "证明" in text or "solution" in text or "answer" in text:
        return "solution"
    return "unknown"


def initialize_structured_contents(
    *,
    db_path: Path | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    initialize_database(db_path)
    inserted = 0

    with connect_database(db_path) as conn:
        question_count = conn.execute("SELECT count(*) FROM questions").fetchone()[0]
        existing_before = conn.execute(
            "SELECT count(*) FROM question_structured_contents"
        ).fetchone()[0]
        rows = conn.execute(
            f"""
            SELECT q.id,
                   q.question_type,
                   q.stem_text,
                   q.stem_latex,
                   q.answer_text,
                   q.analysis_latex,
                   q.review_status
              FROM questions q
              LEFT JOIN question_structured_contents sc
                ON sc.question_id = q.id
             WHERE sc.question_id IS NULL
             ORDER BY q.id
             {"LIMIT ?" if limit is not None else ""}
            """,
            (max(0, limit),) if limit is not None else (),
        ).fetchall()

        for row in rows:
            source_text = row["stem_text"] or ""
            source_latex = row["stem_latex"] or source_text
            model_info = {
                "source": "questions",
                "algorithm_version": STRUCTURED_ALGORITHM_VERSION,
                "initial_review_status": row["review_status"],
            }
            conn.execute(
                """
                INSERT INTO question_structured_contents (
                    question_id,
                    source_text,
                    source_latex,
                    normalized_type,
                    stem_latex,
                    options_json,
                    blanks_json,
                    subquestions_json,
                    answer_latex,
                    analysis_latex,
                    ai_status,
                    quality_flags_json,
                    confidence,
                    model_info
                ) VALUES (?, ?, ?, ?, ?, '[]', '[]', '[]', ?, ?, 'unprocessed', '[]', NULL, ?)
                """,
                (
                    row["id"],
                    source_text,
                    source_latex,
                    normalize_question_type(row["question_type"]),
                    source_latex,
                    row["answer_text"],
                    row["analysis_latex"],
                    json.dumps(model_info, ensure_ascii=False),
                ),
            )
            inserted += 1

        conn.commit()
        total_structured = conn.execute(
            "SELECT count(*) FROM question_structured_contents"
        ).fetchone()[0]
        missing = conn.execute(
            """
            SELECT count(*)
              FROM questions q
              LEFT JOIN question_structured_contents sc
                ON sc.question_id = q.id
             WHERE sc.question_id IS NULL
            """
        ).fetchone()[0]
        status_distribution = _count_distribution(conn, "ai_status")
        type_distribution = _count_distribution(conn, "normalized_type")

    return {
        "question_count": int(question_count),
        "existing_before": int(existing_before),
        "inserted": inserted,
        "total_structured": int(total_structured),
        "missing_structured": int(missing),
        "status_distribution": status_distribution,
        "type_distribution": type_distribution,
        "algorithm_version": STRUCTURED_ALGORITHM_VERSION,
    }


def get_structured_content(
    question_id: int,
    *,
    db_path: Path | None = None,
) -> dict[str, Any] | None:
    with connect_database_read_only(db_path) as conn:
        row = conn.execute(
            """
            SELECT *
              FROM question_structured_contents
             WHERE question_id = ?
            """,
            (question_id,),
        ).fetchone()
    return dict(row) if row is not None else None


def get_structured_contents_by_question_ids(
    question_ids: list[int],
    *,
    db_path: Path | None = None,
) -> dict[int, dict[str, Any]]:
    if not question_ids:
        return {}
    unique_ids = list(dict.fromkeys(int(value) for value in question_ids))
    placeholders = ", ".join("?" for _ in unique_ids)
    with connect_database_read_only(db_path) as conn:
        rows = conn.execute(
            f"""
            SELECT *
              FROM question_structured_contents
             WHERE question_id IN ({placeholders})
            """,
            unique_ids,
        ).fetchall()
    return {int(row["question_id"]): dict(row) for row in rows}


def summarize_structured_contents(
    *,
    db_path: Path | None = None,
) -> dict[str, Any]:
    with connect_database_read_only(db_path) as conn:
        question_count = conn.execute("SELECT count(*) FROM questions").fetchone()[0]
        total_structured = conn.execute(
            "SELECT count(*) FROM question_structured_contents"
        ).fetchone()[0]
        missing = conn.execute(
            """
            SELECT count(*)
              FROM questions q
              LEFT JOIN question_structured_contents sc
                ON sc.question_id = q.id
             WHERE sc.question_id IS NULL
            """
        ).fetchone()[0]
        return {
            "question_count": int(question_count),
            "total_structured": int(total_structured),
            "missing_structured": int(missing),
            "status_distribution": _count_distribution(conn, "ai_status"),
            "type_distribution": _count_distribution(conn, "normalized_type"),
        }


def parse_json_field(value: str | None, fallback: Any) -> Any:
    try:
        return json.loads(value or "")
    except (TypeError, json.JSONDecodeError):
        return fallback


def _count_distribution(conn, field_name: str) -> dict[str, int]:
    rows = conn.execute(
        f"""
        SELECT {field_name} AS key, count(*) AS count
          FROM question_structured_contents
         GROUP BY {field_name}
         ORDER BY {field_name}
        """
    ).fetchall()
    return {str(row["key"]): int(row["count"]) for row in rows}
