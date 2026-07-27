from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Mapping

from .database import connect_database, connect_database_read_only, initialize_database


LIST_STATUSES = ("pending", "reviewed", "approved", "rejected")
EDIT_STATUSES = ("pending", "reviewed", "approved", "rejected")
STAGE14_QUEUE_FILTERS = (
    "export_ready",
    "recut",
    "visual_repair",
    "structured_repair",
    "type_review",
    "source_inferred_audit",
    "export_blocked",
    "protected",
)
REVIEW_EVENT_FIELDS = (
    "question_type",
    "stem_text",
    "stem_latex",
    "answer_text",
    "analysis_latex",
    "tags_json",
    "meta_json",
    "review_status",
)


def _row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    return {key: row[key] for key in row.keys()}


def _clean_text(value: str | None) -> str:
    return (value or "").strip()


def _empty_to_none(value: str | None) -> str | None:
    cleaned = _clean_text(value)
    return cleaned or None


def _json_text(value: str | None, *, default: str, field_name: str) -> str:
    cleaned = _clean_text(value) or default
    try:
        json.loads(cleaned)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{field_name} must be valid JSON") from exc
    return cleaned


def _normalize_status(status: str | None, *, default: str = "pending") -> str | None:
    cleaned = _clean_text(status)
    if cleaned in ("", "all"):
        return None
    if cleaned not in LIST_STATUSES:
        raise ValueError(f"Unsupported review_status: {cleaned}")
    return cleaned or default


def _filters_sql(
    *,
    status: str | None,
    question_type: str | None,
    page_range: str | None,
    batch_id: int | None = None,
    issue_only: bool = False,
    stage14_queue: str | None = None,
) -> tuple[list[str], list[Any]]:
    clauses: list[str] = []
    params: list[Any] = []

    normalized_status = _normalize_status(status)
    if normalized_status is not None:
        clauses.append("q.review_status = ?")
        params.append(normalized_status)

    cleaned_type = _empty_to_none(question_type)
    if cleaned_type is not None:
        clauses.append("q.question_type = ?")
        params.append(cleaned_type)

    cleaned_page = _empty_to_none(page_range)
    if cleaned_page is not None:
        clauses.append("q.page_range = ?")
        params.append(cleaned_page)

    if batch_id is not None:
        clauses.append(
            """
            EXISTS (
                SELECT 1
                  FROM import_batch_pages ibp
                 WHERE ibp.batch_id = ?
                   AND ibp.page_no = CAST(json_extract(q.meta_json, '$.source_page') AS INTEGER)
                   AND (ibp.source_paper_id IS NULL OR ibp.source_paper_id = q.source_paper_id)
            )
            """
        )
        params.append(batch_id)

    if issue_only:
        clauses.append(
            """
            (
                COALESCE(json_array_length(json_extract(q.meta_json, '$.split_warnings')), 0) > 0
                OR EXISTS (
                    SELECT 1
                      FROM import_batch_pages ibp_issue
                     WHERE ibp_issue.page_no = CAST(json_extract(q.meta_json, '$.source_page') AS INTEGER)
                       AND (ibp_issue.source_paper_id IS NULL OR ibp_issue.source_paper_id = q.source_paper_id)
                       AND (
                           ibp_issue.warning_candidates > 0
                           OR ibp_issue.duplicate_anchor_count > 0
                           OR ibp_issue.page_flags_json <> '[]'
                       )
                )
            )
            """
        )

    cleaned_stage14_queue = _empty_to_none(stage14_queue)
    if cleaned_stage14_queue is not None and cleaned_stage14_queue != "all":
        if cleaned_stage14_queue not in STAGE14_QUEUE_FILTERS:
            raise ValueError(f"Unsupported stage14_queue: {cleaned_stage14_queue}")
        clauses.append(
            """
            EXISTS (
                SELECT 1
                  FROM stage14_quality_queue s14_filter
                 WHERE s14_filter.question_id = q.id
                   AND (
                       s14_filter.queue_name = ?
                       OR s14_filter.queue_tags_json LIKE ?
                   )
            )
            """
        )
        params.extend([cleaned_stage14_queue, f"%{cleaned_stage14_queue}%"])

    return clauses, params


def list_questions(
    *,
    db_path: Path | None = None,
    status: str | None = "pending",
    question_type: str | None = None,
    page_range: str | None = None,
    keyword: str | None = None,
    limit: int = 100,
    batch_id: int | None = None,
    issue_only: bool = False,
    stage14_queue: str | None = None,
) -> list[dict[str, Any]]:
    capped_limit = max(1, min(limit, 5000))
    cleaned_keyword = _empty_to_none(keyword)
    clauses, params = _filters_sql(
        status=status,
        question_type=question_type,
        page_range=page_range,
        batch_id=batch_id,
        issue_only=issue_only,
        stage14_queue=stage14_queue,
    )

    with connect_database_read_only(db_path) as conn:
        if cleaned_keyword:
            where_sql = " AND ".join(clauses) if clauses else "1 = 1"
            try:
                rows = conn.execute(
                    f"""
                    SELECT q.id,
                           q.qid,
                           q.paper_name,
                           q.question_no,
                           q.question_type,
                           q.page_range,
                           q.review_status,
                           sa.source_label,
                           sa.confidence AS source_confidence,
                           s14.queue_name AS stage14_queue_name,
                           s14.queue_tags_json AS stage14_queue_tags_json,
                           s14.primary_reason AS stage14_primary_reason,
                           s14.suggested_action AS stage14_suggested_action,
                           CAST(json_extract(q.meta_json, '$.source_page') AS INTEGER) AS source_page,
                           substr(q.stem_text, 1, 180) AS stem_preview,
                           q.updated_at
                      FROM question_fts
                      JOIN questions q ON q.id = question_fts.rowid
                      LEFT JOIN question_source_attributions sa ON sa.question_id = q.id
                      LEFT JOIN stage14_quality_queue s14 ON s14.question_id = q.id
                     WHERE question_fts MATCH ?
                       AND {where_sql}
                     ORDER BY bm25(question_fts), q.id
                     LIMIT ?
                    """,
                    [cleaned_keyword, *params, capped_limit],
                ).fetchall()
            except sqlite3.OperationalError:
                rows = _list_questions_like(
                    conn,
                    status=status,
                    question_type=question_type,
                    page_range=page_range,
                    keyword=cleaned_keyword,
                    limit=capped_limit,
                    batch_id=batch_id,
                    issue_only=issue_only,
                    stage14_queue=stage14_queue,
                )
        else:
            where_sql = "WHERE " + " AND ".join(clauses) if clauses else ""
            rows = conn.execute(
                f"""
                SELECT q.id,
                       q.qid,
                       q.paper_name,
                       q.question_no,
                       q.question_type,
                       q.page_range,
                       q.review_status,
                       sa.source_label,
                       sa.confidence AS source_confidence,
                       s14.queue_name AS stage14_queue_name,
                       s14.queue_tags_json AS stage14_queue_tags_json,
                       s14.primary_reason AS stage14_primary_reason,
                       s14.suggested_action AS stage14_suggested_action,
                       CAST(json_extract(q.meta_json, '$.source_page') AS INTEGER) AS source_page,
                       substr(q.stem_text, 1, 180) AS stem_preview,
                       q.updated_at
                  FROM questions q
                  LEFT JOIN question_source_attributions sa ON sa.question_id = q.id
                  LEFT JOIN stage14_quality_queue s14 ON s14.question_id = q.id
                 {where_sql}
                 ORDER BY q.id
                 LIMIT ?
                """,
                [*params, capped_limit],
            ).fetchall()

    return [_row_to_dict(row) or {} for row in rows]


def _list_questions_like(
    conn: sqlite3.Connection,
    *,
    status: str | None,
    question_type: str | None,
    page_range: str | None,
    keyword: str,
    limit: int,
    batch_id: int | None = None,
    issue_only: bool = False,
    stage14_queue: str | None = None,
) -> list[sqlite3.Row]:
    clauses, params = _filters_sql(
        status=status,
        question_type=question_type,
        page_range=page_range,
        batch_id=batch_id,
        issue_only=issue_only,
        stage14_queue=stage14_queue,
    )
    clauses.append(
        """
        (
            q.qid LIKE ?
            OR q.paper_name LIKE ?
            OR q.question_type LIKE ?
            OR q.tags_json LIKE ?
            OR q.stem_text LIKE ?
            OR q.answer_text LIKE ?
            OR q.analysis_latex LIKE ?
        )
        """
    )
    like_value = f"%{keyword}%"
    params.extend([like_value] * 7)
    where_sql = "WHERE " + " AND ".join(clauses)
    return conn.execute(
        f"""
        SELECT q.id,
               q.qid,
               q.paper_name,
               q.question_no,
               q.question_type,
               q.page_range,
               q.review_status,
               sa.source_label,
               sa.confidence AS source_confidence,
               s14.queue_name AS stage14_queue_name,
               s14.queue_tags_json AS stage14_queue_tags_json,
               s14.primary_reason AS stage14_primary_reason,
               s14.suggested_action AS stage14_suggested_action,
               CAST(json_extract(q.meta_json, '$.source_page') AS INTEGER) AS source_page,
               substr(q.stem_text, 1, 180) AS stem_preview,
               q.updated_at
          FROM questions q
          LEFT JOIN question_source_attributions sa ON sa.question_id = q.id
          LEFT JOIN stage14_quality_queue s14 ON s14.question_id = q.id
         {where_sql}
         ORDER BY q.id
         LIMIT ?
        """,
        [*params, limit],
    ).fetchall()


def get_question_detail(
    question_id: int,
    *,
    db_path: Path | None = None,
) -> dict[str, Any] | None:
    with connect_database_read_only(db_path) as conn:
        row = conn.execute(
            """
            SELECT q.*,
                   sp.paper_code,
                   sp.title AS source_title,
                   sa.source_year,
                   sa.source_paper_name,
                   sa.source_region,
                   sa.source_stream,
                   sa.source_question_no,
                   sa.source_label,
                   sa.confidence AS source_confidence,
                   sa.attribution_flags_json AS source_attribution_flags_json,
                   sa.source_text AS source_attribution_text,
                   CAST(json_extract(q.meta_json, '$.source_page') AS INTEGER) AS source_page,
                   spa.relative_path AS page_image_path,
                   spa.bbox_json AS page_image_bbox_json,
                   spa.meta_json AS page_image_meta_json,
                   qa.relative_path AS asset_raw_crop_path,
                   qa.bbox_json AS raw_crop_bbox_json,
                   qa.meta_json AS raw_crop_meta_json,
                   us.usability_status,
                   us.render_mode AS usability_render_mode,
                   us.primary_issue AS usability_primary_issue,
                   us.issue_flags_json AS usability_issue_flags_json,
                   us.export_eligible AS usability_export_eligible,
                   eq.export_quality_status,
                   eq.render_mode AS export_quality_render_mode,
                   eq.source_usability_status AS export_quality_source_usability_status,
                   eq.export_eligible AS export_quality_export_eligible,
                   eq.blocking_reasons_json AS export_quality_blocking_reasons_json,
                   eq.quality_flags_json AS export_quality_flags_json,
                   s14.queue_name AS stage14_queue_name,
                   s14.queue_tags_json AS stage14_queue_tags_json,
                   s14.severity AS stage14_severity,
                   s14.primary_reason AS stage14_primary_reason,
                   s14.suggested_action AS stage14_suggested_action,
                   s14.flags_json AS stage14_flags_json,
                   s14.stage_version AS stage14_stage_version,
                   v14.repair_status AS stage14_visual_repair_status,
                   v14.candidate_relative_path AS stage14_visual_candidate_path,
                   v14.error_json AS stage14_visual_error_json
              FROM questions q
              JOIN source_papers sp ON sp.id = q.source_paper_id
              LEFT JOIN question_source_attributions sa ON sa.question_id = q.id
              LEFT JOIN source_paper_assets spa
                ON spa.source_paper_id = q.source_paper_id
               AND spa.asset_kind = 'page_image'
               AND spa.page_no = CAST(json_extract(q.meta_json, '$.source_page') AS INTEGER)
              LEFT JOIN question_assets qa
                ON qa.id = (
                    SELECT id
                      FROM question_assets
                     WHERE question_id = q.id
                       AND asset_kind = 'raw_crop'
                     ORDER BY id DESC
                      LIMIT 1
                )
              LEFT JOIN question_usability_states us ON us.question_id = q.id
              LEFT JOIN question_export_quality eq ON eq.question_id = q.id
              LEFT JOIN stage14_quality_queue s14 ON s14.question_id = q.id
              LEFT JOIN stage14_visual_repair_candidates v14 ON v14.question_id = q.id
             WHERE q.id = ?
            """,
            (question_id,),
        ).fetchone()
        batch_rows = []
        if row is not None:
            batch_rows = conn.execute(
                """
                SELECT b.id AS batch_id,
                       b.name AS batch_name,
                       b.batch_kind,
                       p.page_no,
                       p.candidate_count,
                       p.db_question_count,
                       p.warning_candidates,
                       p.duplicate_anchor_count,
                       p.page_flags_json
                  FROM import_batch_pages p
                  JOIN import_batches b ON b.id = p.batch_id
                 WHERE p.page_no = CAST(json_extract(?, '$.source_page') AS INTEGER)
                   AND (p.source_paper_id IS NULL OR p.source_paper_id = ?)
                 ORDER BY b.id
                """,
                (row["meta_json"], row["source_paper_id"]),
            ).fetchall()

    question = _row_to_dict(row)
    if question is not None and question.get("asset_raw_crop_path"):
        question["raw_crop_path"] = question["asset_raw_crop_path"]
    if question is not None:
        question["batch_pages"] = [_row_to_dict(batch_row) for batch_row in batch_rows]
    return question


def list_question_ids(
    *,
    db_path: Path | None = None,
    status: str | None = "pending",
    question_type: str | None = None,
    page_range: str | None = None,
    keyword: str | None = None,
    batch_id: int | None = None,
    issue_only: bool = False,
    stage14_queue: str | None = None,
    limit: int = 5000,
) -> list[int]:
    return [
        int(question["id"])
        for question in list_questions(
            db_path=db_path,
            status=status,
            question_type=question_type,
            page_range=page_range,
            keyword=keyword,
            batch_id=batch_id,
            issue_only=issue_only,
            stage14_queue=stage14_queue,
            limit=limit,
        )
    ]


def get_questions_by_ids(
    question_ids: list[int],
    *,
    db_path: Path | None = None,
) -> list[dict[str, Any]]:
    if not question_ids:
        return []

    unique_ids = list(dict.fromkeys(question_ids))
    placeholders = ", ".join("?" for _ in unique_ids)
    with connect_database_read_only(db_path) as conn:
        rows = conn.execute(
            f"""
            SELECT q.id,
                   q.qid,
                   q.paper_name,
                   q.question_no,
                   q.question_type,
                   q.stem_text,
                   q.stem_latex,
                   q.review_status,
                   q.page_range,
                   q.created_at,
                   q.updated_at,
                   sp.paper_code,
                   sp.title AS source_title,
                   sa.source_label,
                   sa.confidence AS source_confidence,
                   sa.source_year,
                   sa.source_paper_name,
                   sa.source_question_no,
                   s14.queue_name AS stage14_queue_name,
                   s14.queue_tags_json AS stage14_queue_tags_json,
                   s14.primary_reason AS stage14_primary_reason,
                   s14.suggested_action AS stage14_suggested_action
              FROM questions q
              JOIN source_papers sp ON sp.id = q.source_paper_id
              LEFT JOIN question_source_attributions sa ON sa.question_id = q.id
              LEFT JOIN stage14_quality_queue s14 ON s14.question_id = q.id
             WHERE q.id IN ({placeholders})
            """,
            unique_ids,
        ).fetchall()

    by_id = {row["id"]: _row_to_dict(row) or {} for row in rows}
    return [by_id[question_id] for question_id in question_ids if question_id in by_id]


def _review_snapshot(conn: sqlite3.Connection, question_id: int) -> dict[str, Any] | None:
    row = conn.execute(
        f"""
        SELECT {", ".join(REVIEW_EVENT_FIELDS)}
          FROM questions
         WHERE id = ?
        """,
        (question_id,),
    ).fetchone()
    return _row_to_dict(row)


def _review_diff(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    return {
        field: {"before": before.get(field), "after": after.get(field)}
        for field in REVIEW_EVENT_FIELDS
        if before.get(field) != after.get(field)
    }


def _insert_review_event(
    conn: sqlite3.Connection,
    *,
    question_id: int,
    event_type: str,
    source: str,
    before: dict[str, Any],
    after: dict[str, Any],
) -> None:
    conn.execute(
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
            json.dumps(_review_diff(before, after), ensure_ascii=False),
        ),
    )


def update_question_from_form(
    question_id: int,
    form: Mapping[str, Any],
    *,
    db_path: Path | None = None,
) -> None:
    initialize_database(db_path)

    review_status = _clean_text(str(form.get("review_status", "pending")))
    if review_status not in EDIT_STATUSES:
        raise ValueError("review_status can only be pending, reviewed, approved, or rejected")

    meta_json = _json_text(
        str(form.get("meta_json", "")),
        default="{}",
        field_name="meta_json",
    )
    if "issue_tags" in form:
        meta = json.loads(meta_json)
        issue_tags = [
            item.strip()
            for item in str(form.get("issue_tags", "")).replace("，", ",").split(",")
            if item.strip()
        ]
        if issue_tags:
            meta["issue_tags"] = issue_tags
        else:
            meta.pop("issue_tags", None)
        meta_json = json.dumps(meta, ensure_ascii=False)

    values = {
        "question_id": question_id,
        "question_type": _empty_to_none(str(form.get("question_type", ""))),
        "stem_text": _clean_text(str(form.get("stem_text", ""))),
        "stem_latex": _clean_text(str(form.get("stem_latex", ""))),
        "answer_text": _empty_to_none(str(form.get("answer_text", ""))),
        "analysis_latex": _empty_to_none(str(form.get("analysis_latex", ""))),
        "tags_json": _json_text(
            str(form.get("tags_json", "")),
            default="[]",
            field_name="tags_json",
        ),
        "meta_json": meta_json,
        "review_status": review_status,
    }

    if not values["stem_text"]:
        raise ValueError("stem_text cannot be empty")
    if not values["stem_latex"]:
        raise ValueError("stem_latex cannot be empty")

    with connect_database(db_path) as conn:
        before = _review_snapshot(conn, question_id)
        if before is None:
            raise LookupError(f"Question not found: {question_id}")

        cursor = conn.execute(
            """
            UPDATE questions
               SET question_type = :question_type,
                   stem_text = :stem_text,
                   stem_latex = :stem_latex,
                   answer_text = :answer_text,
                   analysis_latex = :analysis_latex,
                   tags_json = :tags_json,
                   meta_json = :meta_json,
                   review_status = :review_status,
                   updated_at = CURRENT_TIMESTAMP
             WHERE id = :question_id
            """,
            values,
        )
        if cursor.rowcount != 1:
            raise LookupError(f"Question not found: {question_id}")
        after = _review_snapshot(conn, question_id)
        if after is None:
            raise LookupError(f"Question not found after update: {question_id}")
        _insert_review_event(
            conn,
            question_id=question_id,
            event_type="web_update",
            source="web",
            before=before,
            after=after,
        )
        conn.commit()
