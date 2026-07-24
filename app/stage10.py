from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .config import PROJECT_ROOT
from .database import connect_database, connect_database_read_only, initialize_database
from .exports import save_html_export
from .question_repository import get_questions_by_ids
from .structured_ai import validate_ai_output_payload
from .structured_content import (
    initialize_structured_contents,
    normalize_question_type,
    parse_json_field,
)
from .structured_render import (
    attach_structured_contents,
    render_printable_paper_html,
)
from .structured_service import StructuredContentService, StructuredContentServiceError
from .structured_validation import latex_basic_renderable, validate_structured_contents


STAGE10_VERSION = "stage10_production_v1"
STAGE10_RULE_PROVIDER = "stage10_rule_agent"
STAGE10_BATCH_NAME = "stage10-production-baseline"
STAGE10_REPORT_RELATIVE_PATH = Path("docs") / "stage10_quality_report.md"
HIGH_RISK_PAGES = (1098, 1100, 1128, 1148, 1168)
FOCUS_QIDS = (
    "PDF-D02D0F16371FA96F-P1094-Q011",
    "PDF-D02D0F16371FA96F-P1094-Q012",
)
WRITABLE_STRUCTURED_STATUSES = ("unprocessed", "ai_draft", "needs_review", "failed")
PROTECTED_STRUCTURED_STATUSES = ("ai_verified", "human_reviewed")
PROTECTED_QUESTION_STATUSES = ("reviewed", "approved")
NORMALIZED_TYPE_ORDER = ("choice", "multiple_choice", "blank", "solution", "unknown")
REVIEW_REQUIRED_FLAGS = {
    "empty_source_text",
    "formula_uncertain",
    "image_question_needs_manual_review",
    "missing_page_image",
    "missing_raw_crop",
    "option_count_anomaly",
    "page_duplicate_anchors",
    "page_flags_present",
    "page_warning_candidates",
    "question_review_status_protected",
    "split_warnings_present",
    "unknown_question_type",
    "latex_ambiguous_decimal_or_log",
    "latex_fraction_after_variable_suspicious",
    "latex_garbled_geometry_symbol",
    "latex_garbled_piecewise_or_symbol",
    "latex_implicit_exponent_unconverted",
    "latex_pi_trailing_number_suspicious",
    "latex_private_use_piecewise_symbol",
    "latex_sqrt_fraction_split_suspicious",
    "latex_sqrt_trailing_number_suspicious",
    "latex_unconverted_degree_symbol",
    "latex_unconverted_overline_symbol",
    "latex_unicode_math_symbol_unconverted",
    "latex_zero_denominator_suspicious",
    "blank_placeholder_inferred",
}


class Stage10Error(RuntimeError):
    """Raised when the Stage 10 workflow cannot continue."""


def register_stage10_baseline(
    *,
    db_path: Path | None = None,
    sample_size: int = 160,
) -> dict[str, Any]:
    initialize_database(db_path)
    initialize_structured_contents(db_path=db_path)
    capped = max(100, min(sample_size, 500))

    with connect_database(db_path) as conn:
        rows = _load_stage10_rows(conn)
        selected = _select_baseline_rows(rows, capped)
        for row in selected.values():
            conn.execute(
                """
                INSERT INTO stage10_baseline_questions (
                    question_id,
                    qid,
                    source_page,
                    normalized_type,
                    risk_group,
                    reason_json
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(question_id) DO UPDATE SET
                    qid = excluded.qid,
                    source_page = excluded.source_page,
                    normalized_type = excluded.normalized_type,
                    risk_group = excluded.risk_group,
                    reason_json = excluded.reason_json,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (
                    row["question_id"],
                    row["qid"],
                    row["source_page"],
                    _infer_normalized_type(row),
                    _risk_group(row),
                    json.dumps(row["stage10_reasons"], ensure_ascii=False),
                ),
            )
        conn.commit()
        coverage = _baseline_coverage(conn)

    return {
        "status": "ok",
        "sample_size": capped,
        "selected": len(selected),
        "coverage": coverage,
        "version": STAGE10_VERSION,
    }


def isolate_high_risk_pages(*, db_path: Path | None = None) -> dict[str, Any]:
    initialize_database(db_path)
    initialize_structured_contents(db_path=db_path)
    page_results: list[dict[str, Any]] = []
    marked_questions = 0

    with connect_database(db_path) as conn:
        for page_no in HIGH_RISK_PAGES:
            stats = _load_latest_page_stats(conn, page_no)
            flags = _dedupe(
                [
                    "stage10_duplicate_anchor_isolation",
                    *stats["page_flags"],
                    "duplicate_anchors" if stats["duplicate_anchor_count"] else "",
                    "warning_candidates" if stats["warning_candidates"] else "",
                ]
            )
            isolated_count = max(
                int(stats["duplicate_anchor_count"]),
                int(stats["candidate_count"]) - int(stats["db_question_count"]),
                0,
            )
            reviewable_count = _count_reviewable_questions_on_page(conn, page_no)
            conn.execute(
                """
                INSERT INTO stage10_page_isolations (
                    source_paper_id,
                    page_no,
                    candidate_count,
                    db_question_count,
                    duplicate_anchor_count,
                    warning_candidates,
                    isolated_count,
                    reviewable_count,
                    status,
                    flags_json,
                    meta_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'needs_review', ?, ?)
                ON CONFLICT(source_paper_id, page_no) DO UPDATE SET
                    candidate_count = excluded.candidate_count,
                    db_question_count = excluded.db_question_count,
                    duplicate_anchor_count = excluded.duplicate_anchor_count,
                    warning_candidates = excluded.warning_candidates,
                    isolated_count = excluded.isolated_count,
                    reviewable_count = excluded.reviewable_count,
                    status = excluded.status,
                    flags_json = excluded.flags_json,
                    meta_json = excluded.meta_json,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (
                    stats["source_paper_id"],
                    page_no,
                    stats["candidate_count"],
                    stats["db_question_count"],
                    stats["duplicate_anchor_count"],
                    stats["warning_candidates"],
                    isolated_count,
                    reviewable_count,
                    json.dumps(flags, ensure_ascii=False),
                    json.dumps(
                        {
                            "algorithm_version": STAGE10_VERSION,
                            "source": "import_batch_pages",
                            "latest_batch_page_id": stats["batch_page_id"],
                            "created_at": _utc_now(),
                        },
                        ensure_ascii=False,
                    ),
                ),
            )
            marked_questions += _mark_high_risk_structured_rows(conn, page_no, flags)
            page_results.append(
                {
                    "page_no": page_no,
                    "candidate_count": stats["candidate_count"],
                    "db_question_count": stats["db_question_count"],
                    "duplicate_anchor_count": stats["duplicate_anchor_count"],
                    "warning_candidates": stats["warning_candidates"],
                    "isolated_count": isolated_count,
                    "reviewable_count": reviewable_count,
                    "flags": flags,
                }
            )
        conn.commit()

    return {
        "status": "ok",
        "pages": page_results,
        "marked_questions": marked_questions,
        "version": STAGE10_VERSION,
    }


def run_stage10_structure_batch(
    *,
    db_path: Path | None = None,
    target_verified: int = 100,
    max_questions: int = 350,
    sample_size: int = 160,
) -> dict[str, Any]:
    initialize_database(db_path)
    initialize_structured_contents(db_path=db_path)
    baseline = register_stage10_baseline(db_path=db_path, sample_size=sample_size)
    isolation = isolate_high_risk_pages(db_path=db_path)
    target = max(1, min(target_verified, 500))
    capped = max(1, min(max_questions, 1000))

    with connect_database(db_path) as conn:
        before_status = _status_distribution(conn)
        verified_before = int(before_status.get("ai_verified", 0))
        rows = _select_structure_rows(conn, capped)
        applied_ids: list[int] = []
        skipped: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []
        for row in rows:
            if _is_protected(row):
                skipped.append({"question_id": row["question_id"], "reason": "protected"})
                continue
            try:
                payload = _build_stage10_payload(row)
            except Exception as exc:  # noqa: BLE001 - keep row-level failures auditable.
                errors.append({"question_id": row["question_id"], "qid": row["qid"], "error": str(exc)})
                continue
            _write_structured_payload(conn, row, payload)
            applied_ids.append(int(row["question_id"]))
        conn.commit()

    validation: dict[str, Any] | None = None
    if applied_ids:
        validation = validate_structured_contents(
            db_path=db_path,
            question_ids=tuple(applied_ids),
            limit=len(applied_ids),
        )

    with connect_database(db_path) as conn:
        after_status = _status_distribution(conn)
        verified_after = int(after_status.get("ai_verified", 0))
        blockers = _quality_flag_counts(conn, statuses=("needs_review", "failed"))
        stage10_verified = _stage10_verified_count(conn)

    return {
        "status": "ok" if not errors else "partial",
        "version": STAGE10_VERSION,
        "batch_name": STAGE10_BATCH_NAME,
        "target_verified": target,
        "max_questions": capped,
        "baseline": baseline,
        "isolation": isolation,
        "verified_before": verified_before,
        "verified_after": verified_after,
        "stage10_verified": stage10_verified,
        "target_met": verified_after >= target,
        "applied": len(applied_ids),
        "skipped": skipped,
        "errors": errors,
        "validation": validation,
        "status_before": before_status,
        "status_after": after_status,
        "blockers": blockers,
    }


def write_stage10_quality_report(
    *,
    db_path: Path | None = None,
    project_root: Path = PROJECT_ROOT,
    sample_size: int = 160,
) -> dict[str, Any]:
    initialize_database(db_path)
    initialize_structured_contents(db_path=db_path)
    baseline = register_stage10_baseline(db_path=db_path, sample_size=sample_size)
    isolation = isolate_high_risk_pages(db_path=db_path)

    with connect_database(db_path) as conn:
        question_count = conn.execute("SELECT count(*) FROM questions").fetchone()[0]
        structured_count = conn.execute(
            "SELECT count(*) FROM question_structured_contents"
        ).fetchone()[0]
        status_counts = _status_distribution(conn)
        type_counts = _structured_type_distribution(conn)
        review_counts = _question_review_distribution(conn)
        baseline_coverage = _baseline_coverage(conn)
        high_risk_rows = _high_risk_isolation_rows(conn)
        blockers = _quality_flag_counts(conn, statuses=("needs_review", "failed"))
        render_stats = _render_stats(conn)
        asset_stats = _asset_stats(conn)
        event_count = conn.execute("SELECT count(*) FROM question_review_events").fetchone()[0]
        ai_suggestion_count = conn.execute(
            "SELECT count(*) FROM question_ai_suggestions"
        ).fetchone()[0]
        protected = _protected_counts(conn)
        checksum = questions_main_checksum(conn)
        stage10_verified = _stage10_verified_count(conn)

    report_path = project_root / STAGE10_REPORT_RELATIVE_PATH
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_text = _render_stage10_report(
        question_count=int(question_count),
        structured_count=int(structured_count),
        status_counts=status_counts,
        type_counts=type_counts,
        review_counts=review_counts,
        baseline=baseline,
        baseline_coverage=baseline_coverage,
        isolation=isolation,
        high_risk_rows=high_risk_rows,
        blockers=blockers,
        render_stats=render_stats,
        asset_stats=asset_stats,
        event_count=int(event_count),
        ai_suggestion_count=int(ai_suggestion_count),
        protected=protected,
        checksum=checksum,
        stage10_verified=stage10_verified,
    )
    report_path.write_text(report_text, encoding="utf-8")
    return {
        "status": "ok",
        "relative_path": STAGE10_REPORT_RELATIVE_PATH.as_posix(),
        "path": str(report_path),
        "question_count": int(question_count),
        "status_counts": status_counts,
        "type_counts": type_counts,
        "baseline": baseline_coverage,
        "high_risk_pages": high_risk_rows,
        "stage10_verified": stage10_verified,
        "checksum": checksum,
    }


def save_stage10_export_sample(
    *,
    db_path: Path | None = None,
    project_root: Path = PROJECT_ROOT,
    limit: int = 14,
) -> dict[str, Any]:
    initialize_database(db_path)
    initialize_structured_contents(db_path=db_path)
    capped = max(4, min(limit, 40))

    with connect_database(db_path) as conn:
        rows = conn.execute(
            """
            SELECT q.id,
                   q.qid,
                   sc.ai_status,
                   sc.normalized_type,
                   sc.model_info
              FROM questions q
              JOIN question_structured_contents sc ON sc.question_id = q.id
             WHERE sc.ai_status IN ('ai_verified', 'human_reviewed')
             ORDER BY
                   CASE
                       WHEN q.qid = ? THEN 0
                       WHEN q.qid = ? THEN 1
                       WHEN sc.model_info LIKE '%stage10_rule_agent%' THEN 2
                       ELSE 3
                   END,
                   CASE sc.normalized_type
                       WHEN 'choice' THEN 0
                       WHEN 'multiple_choice' THEN 1
                       WHEN 'blank' THEN 2
                       WHEN 'solution' THEN 3
                       ELSE 4
                   END,
                   q.id
             LIMIT ?
            """,
            (FOCUS_QIDS[0], FOCUS_QIDS[1], capped),
        ).fetchall()
        question_ids = [int(row["id"]) for row in rows]

    questions = get_questions_by_ids(question_ids, db_path=db_path)
    with connect_database(db_path) as conn:
        structured_rows = conn.execute(
            f"""
            SELECT *
              FROM question_structured_contents
             WHERE question_id IN ({", ".join("?" for _ in question_ids) if question_ids else "NULL"})
            """,
            question_ids,
        ).fetchall() if question_ids else []
    attach_structured_contents(questions, {int(row["question_id"]): dict(row) for row in structured_rows})
    html = render_printable_paper_html(questions, export=True, title="阶段 10 导出样张")
    result = save_html_export(
        html,
        project_root=project_root,
        filename_prefix="stage10-sample",
    )
    result.update(
        {
            "status": "ok",
            "question_count": len(questions),
            "qids": [question["qid"] for question in questions],
        }
    )
    return result


def list_structured_review_items(
    *,
    db_path: Path | None = None,
    ai_status: str | None = None,
    quality_flag: str | None = None,
    normalized_type: str | None = None,
    page: int | None = None,
    high_risk: bool = False,
    usability_status: str | None = None,
    risk_type: str | None = None,
    render_mode: str | None = None,
    stage14_queue: str | None = None,
    stage14_reason: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    capped = max(1, min(limit, 500))
    clauses = ["1 = 1"]
    params: list[Any] = []
    if ai_status and ai_status != "all":
        clauses.append("sc.ai_status = ?")
        params.append(ai_status)
    if quality_flag:
        clauses.append("sc.quality_flags_json LIKE ?")
        params.append(f"%{quality_flag}%")
    if normalized_type and normalized_type != "all":
        clauses.append("sc.normalized_type = ?")
        params.append(normalized_type)
    if page is not None:
        clauses.append("CAST(json_extract(q.meta_json, '$.source_page') AS INTEGER) = ?")
        params.append(page)
    if high_risk:
        clauses.append(
            f"CAST(json_extract(q.meta_json, '$.source_page') AS INTEGER) IN ({', '.join('?' for _ in HIGH_RISK_PAGES)})"
        )
        params.extend(HIGH_RISK_PAGES)
    if usability_status and usability_status != "all":
        clauses.append("us.usability_status = ?")
        params.append(usability_status)
    if render_mode and render_mode != "all":
        clauses.append("us.render_mode = ?")
        params.append(render_mode)
    if stage14_queue and stage14_queue != "all":
        clauses.append(
            """
            (
                s14.queue_name = ?
                OR s14.queue_tags_json LIKE ?
            )
            """
        )
        params.extend([stage14_queue, f"%{stage14_queue}%"])
    if stage14_reason:
        clauses.append("(s14.primary_reason LIKE ? OR s14.flags_json LIKE ?)")
        params.extend([f"%{stage14_reason}%", f"%{stage14_reason}%"])
    if risk_type:
        clauses.append("(us.primary_issue LIKE ? OR us.issue_flags_json LIKE ?)")
        params.extend([f"%{risk_type}%", f"%{risk_type}%"])
    params.append(capped)
    where_sql = " AND ".join(clauses)

    with connect_database_read_only(db_path) as conn:
        rows = conn.execute(
            f"""
            SELECT q.id AS question_id,
                   q.qid,
                   q.question_no,
                   q.question_type,
                   q.review_status,
                   q.page_range,
                   sa.source_label,
                   sa.confidence AS source_confidence,
                   substr(q.stem_text, 1, 180) AS stem_preview,
                   CAST(json_extract(q.meta_json, '$.source_page') AS INTEGER) AS source_page,
                   qa.relative_path AS raw_crop_path,
                   spa.relative_path AS page_image_path,
                   sc.ai_status,
                   sc.normalized_type,
                   sc.quality_flags_json,
                   sc.confidence,
                   us.usability_status,
                   us.render_mode,
                   us.primary_issue,
                   us.issue_flags_json,
                   us.export_eligible,
                   eq.export_quality_status,
                   eq.render_mode AS export_quality_render_mode,
                   eq.blocking_reasons_json AS export_quality_blocking_reasons_json,
                   eq.quality_flags_json AS export_quality_flags_json,
                   s14.queue_name AS stage14_queue_name,
                   s14.primary_reason AS stage14_primary_reason,
                   s14.suggested_action AS stage14_suggested_action,
                   s14.queue_tags_json AS stage14_queue_tags_json,
                   COALESCE(ibp.warning_candidates, 0) AS warning_candidates,
                   COALESCE(ibp.duplicate_anchor_count, 0) AS duplicate_anchor_count
              FROM question_structured_contents sc
              JOIN questions q ON q.id = sc.question_id
              LEFT JOIN question_source_attributions sa ON sa.question_id = q.id
              LEFT JOIN question_usability_states us ON us.question_id = q.id
              LEFT JOIN question_export_quality eq ON eq.question_id = q.id
              LEFT JOIN stage14_quality_queue s14 ON s14.question_id = q.id
              LEFT JOIN question_assets qa
                ON qa.id = (
                    SELECT id
                      FROM question_assets
                     WHERE question_id = q.id
                       AND asset_kind = 'raw_crop'
                     ORDER BY id DESC
                     LIMIT 1
                )
              LEFT JOIN source_paper_assets spa
                ON spa.source_paper_id = q.source_paper_id
               AND spa.asset_kind = 'page_image'
               AND spa.page_no = CAST(json_extract(q.meta_json, '$.source_page') AS INTEGER)
              LEFT JOIN import_batch_pages ibp
                ON ibp.id = (
                    SELECT id
                      FROM import_batch_pages ibp2
                     WHERE ibp2.page_no = CAST(json_extract(q.meta_json, '$.source_page') AS INTEGER)
                       AND (ibp2.source_paper_id IS NULL OR ibp2.source_paper_id = q.source_paper_id)
                     ORDER BY ibp2.updated_at DESC, ibp2.id DESC
                     LIMIT 1
                )
             WHERE {where_sql}
             ORDER BY
                   CASE sc.ai_status
                       WHEN 'needs_review' THEN 0
                       WHEN 'failed' THEN 1
                       WHEN 'unprocessed' THEN 2
                       WHEN 'ai_draft' THEN 3
                       ELSE 4
                   END,
                   q.id
             LIMIT ?
            """,
            params,
        ).fetchall()
    result = [dict(row) for row in rows]
    for row in result:
        row["quality_flags"] = parse_json_field(row.get("quality_flags_json"), [])
        row["usability_flags"] = parse_json_field(row.get("issue_flags_json"), [])
        row["export_quality_flags"] = parse_json_field(
            row.get("export_quality_flags_json"), []
        )
        row["export_quality_blocking_reasons"] = parse_json_field(
            row.get("export_quality_blocking_reasons_json"), []
        )
        row["stage14_queue_tags"] = parse_json_field(
            row.get("stage14_queue_tags_json"), []
        )
        row["high_risk"] = int(row.get("source_page") or 0) in HIGH_RISK_PAGES
    return result


def update_structured_review_status(
    question_id: int,
    *,
    action: str,
    db_path: Path | None = None,
    source: str = "web_stage10",
) -> dict[str, Any]:
    initialize_database(db_path)
    try:
        with connect_database(db_path) as conn:
            result = StructuredContentService(conn).update_review_status(
                question_id,
                action=action,
                source=source,
            )
            conn.commit()
    except StructuredContentServiceError as exc:
        raise Stage10Error(str(exc)) from exc

    return result


def questions_main_checksum(conn) -> str:
    digest = hashlib.sha256()
    rows = conn.execute(
        """
        SELECT id,
               qid,
               question_type,
               stem_text,
               stem_latex,
               answer_text,
               analysis_latex,
               review_status,
               meta_json,
               updated_at
          FROM questions
         ORDER BY id
        """
    ).fetchall()
    for row in rows:
        payload = {key: row[key] for key in row.keys()}
        digest.update(json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


def _select_baseline_rows(
    rows: list[dict[str, Any]],
    sample_size: int,
) -> dict[int, dict[str, Any]]:
    selected: dict[int, dict[str, Any]] = {}
    by_qid = {row["qid"]: row for row in rows}

    def add(row: dict[str, Any] | None, reason: str) -> None:
        if row is None or len(selected) >= sample_size:
            return
        question_id = int(row["question_id"])
        if question_id not in selected:
            selected[question_id] = {**row, "stage10_reasons": []}
        if reason not in selected[question_id]["stage10_reasons"]:
            selected[question_id]["stage10_reasons"].append(reason)

    for qid in FOCUS_QIDS:
        add(by_qid.get(qid), "stage9_verified_focus")

    for page_no in HIGH_RISK_PAGES:
        for row in rows:
            if int(row.get("source_page") or 0) == page_no:
                add(row, f"high_risk_page_{page_no}")

    type_targets = {
        "choice": 25,
        "multiple_choice": 5,
        "blank": 20,
        "solution": 20,
        "unknown": 20,
    }
    for normalized_type, target in type_targets.items():
        current = sum(
            1 for row in selected.values() if _infer_normalized_type(row) == normalized_type
        )
        for row in rows:
            if current >= target or len(selected) >= sample_size:
                break
            if _infer_normalized_type(row) == normalized_type:
                add(row, f"type_{normalized_type}")
                current += 1

    for row in rows:
        if len(selected) >= sample_size:
            break
        add(row, "fill_sample")
    return selected


def _load_stage10_rows(conn) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT q.id AS question_id,
               q.qid,
               q.source_paper_id,
               q.question_no,
               q.question_type,
               q.review_status,
               q.stem_text,
               q.stem_latex AS question_stem_latex,
               q.answer_text,
               q.analysis_latex AS question_analysis_latex,
               q.paper_name,
               q.page_range,
               q.bbox_json,
               q.meta_json,
               CAST(json_extract(q.meta_json, '$.source_page') AS INTEGER) AS source_page,
               sc.source_text,
               sc.source_latex,
               sc.normalized_type,
               sc.ai_status,
               sc.quality_flags_json,
               sc.model_info,
               qa.relative_path AS raw_crop_path,
               spa.relative_path AS page_image_path,
               COALESCE(ibp.candidate_count, 0) AS candidate_count,
               COALESCE(ibp.db_question_count, 0) AS db_question_count,
               COALESCE(ibp.warning_candidates, 0) AS warning_candidates,
               COALESCE(ibp.duplicate_anchor_count, 0) AS duplicate_anchor_count,
               COALESCE(ibp.page_flags_json, '[]') AS page_flags_json
          FROM questions q
          JOIN question_structured_contents sc ON sc.question_id = q.id
          LEFT JOIN question_assets qa
            ON qa.id = (
                SELECT id
                  FROM question_assets
                 WHERE question_id = q.id
                   AND asset_kind = 'raw_crop'
                 ORDER BY id DESC
                 LIMIT 1
            )
          LEFT JOIN source_paper_assets spa
            ON spa.source_paper_id = q.source_paper_id
           AND spa.asset_kind = 'page_image'
           AND spa.page_no = CAST(json_extract(q.meta_json, '$.source_page') AS INTEGER)
          LEFT JOIN import_batch_pages ibp
            ON ibp.id = (
                SELECT id
                  FROM import_batch_pages ibp2
                 WHERE ibp2.page_no = CAST(json_extract(q.meta_json, '$.source_page') AS INTEGER)
                   AND (ibp2.source_paper_id IS NULL OR ibp2.source_paper_id = q.source_paper_id)
                 ORDER BY ibp2.updated_at DESC, ibp2.id DESC
                 LIMIT 1
            )
         ORDER BY q.id
        """
    ).fetchall()
    return [dict(row) for row in rows]


def _select_structure_rows(conn, max_questions: int) -> list[dict[str, Any]]:
    rows = _load_stage10_rows(conn)
    eligible = []
    for row in rows:
        if _is_protected(row):
            continue
        if not _is_low_risk(row):
            continue
        source_text = str(row.get("source_text") or row.get("stem_text") or "")
        stem_text, options = _split_options(source_text)
        normalized_type = _infer_normalized_type(row)
        if normalized_type == "unknown" and len(options) == 4:
            normalized_type = "choice"
        if normalized_type == "choice" and len(options) != 4:
            continue
        if normalized_type == "multiple_choice" and len(options) < 4:
            continue
        if normalized_type == "unknown":
            continue
        if _looks_visual_question(source_text):
            continue
        priority = {
            "choice": 0,
            "multiple_choice": 1,
            "blank": 2,
            "solution": 3,
        }.get(normalized_type, 9)
        eligible.append((priority, int(row["question_id"]), row))
    eligible.sort(key=lambda item: (item[0], item[1]))
    return [row for _, _, row in eligible[:max_questions]]


def _build_stage10_payload(row: dict[str, Any]) -> dict[str, Any]:
    source_text = str(row.get("source_text") or row.get("stem_text") or "")
    normalized_type = _infer_normalized_type(row)
    stem_text, options = _split_options(source_text)
    if normalized_type == "unknown" and len(options) == 4:
        normalized_type = "choice"

    flags = ["stage10_rule_agent", "no_answer_in_source"]
    if row.get("raw_crop_path"):
        flags.append("referenced_raw_crop_image")
    else:
        flags.append("missing_raw_crop")
    if row.get("page_image_path"):
        flags.append("referenced_page_image")
    else:
        flags.append("missing_page_image")
    if _looks_visual_question(source_text):
        flags.append("image_question_needs_manual_review")
    if not source_text.strip():
        flags.append("empty_source_text")

    if normalized_type in ("choice", "multiple_choice"):
        if len(options) < 4 or (normalized_type == "choice" and len(options) != 4):
            flags.append("option_count_anomaly")
        payload_options = [
            {"label": option["label"], "text_latex": _normalize_latex_text(option["text"])}
            for option in options
        ]
        stem_latex = _normalize_latex_text(stem_text or source_text)
        blanks: list[dict[str, Any]] = []
        subquestions: list[dict[str, Any]] = []
    elif normalized_type == "blank":
        payload_options = []
        stem_latex = _normalize_latex_text(source_text)
        blanks = _extract_blanks(stem_latex)
        if not blanks:
            blanks = [{"index": 1, "placeholder_latex": "\\underline{\\hspace{3em}}"}]
            flags.append("blank_placeholder_inferred")
        subquestions = []
    elif normalized_type == "solution":
        payload_options = []
        stem_latex = _normalize_latex_text(source_text)
        blanks = []
        subquestions = _extract_subquestions(stem_latex)
    else:
        payload_options = []
        stem_latex = _normalize_latex_text(source_text)
        blanks = []
        subquestions = []
        flags.append("unknown_question_type")

    return validate_ai_output_payload(
        {
            "normalized_type": normalized_type,
            "stem_latex": stem_latex,
            "options_json": payload_options,
            "blanks_json": blanks,
            "subquestions_json": subquestions,
            "answer_latex": "",
            "analysis_latex": "",
            "confidence": _confidence_for_flags(flags),
            "quality_flags": _dedupe(flags),
        }
    )


def _write_structured_payload(conn, row: dict[str, Any], payload: dict[str, Any]) -> None:
    model_info = parse_json_field(row.get("model_info"), {})
    if not isinstance(model_info, dict):
        model_info = {}
    model_info["last_stage10"] = {
        "provider": STAGE10_RULE_PROVIDER,
        "batch_name": STAGE10_BATCH_NAME,
        "algorithm_version": STAGE10_VERSION,
        "created_at": _utc_now(),
    }
    conn.execute(
        """
        UPDATE question_structured_contents
           SET source_text = ?,
               source_latex = ?,
               normalized_type = ?,
               stem_latex = ?,
               options_json = ?,
               blanks_json = ?,
               subquestions_json = ?,
               answer_latex = ?,
               analysis_latex = ?,
               ai_status = 'ai_draft',
               quality_flags_json = ?,
               confidence = ?,
               model_info = ?,
               updated_at = CURRENT_TIMESTAMP
         WHERE question_id = ?
        """,
        (
            row.get("source_text") or row.get("stem_text") or "",
            row.get("source_latex") or row.get("question_stem_latex") or row.get("stem_text") or "",
            payload["normalized_type"],
            payload["stem_latex"],
            json.dumps(payload["options_json"], ensure_ascii=False),
            json.dumps(payload["blanks_json"], ensure_ascii=False),
            json.dumps(payload["subquestions_json"], ensure_ascii=False),
            payload.get("answer_latex"),
            payload.get("analysis_latex"),
            json.dumps(payload["quality_flags"], ensure_ascii=False),
            payload["confidence"],
            json.dumps(model_info, ensure_ascii=False),
            row["question_id"],
        ),
    )


def _mark_high_risk_structured_rows(conn, page_no: int, page_flags: list[str]) -> int:
    rows = conn.execute(
        """
        SELECT sc.question_id,
               sc.ai_status,
               sc.quality_flags_json,
               sc.model_info
          FROM question_structured_contents sc
          JOIN questions q ON q.id = sc.question_id
         WHERE CAST(json_extract(q.meta_json, '$.source_page') AS INTEGER) = ?
           AND q.review_status NOT IN ('reviewed', 'approved')
           AND sc.ai_status NOT IN ('ai_verified', 'human_reviewed')
        """,
        (page_no,),
    ).fetchall()
    updated = 0
    required_flags = [
        "page_duplicate_anchors",
        "page_warning_candidates",
        "page_flags_present",
        "page_flag_stage10_duplicate_anchor_isolated",
        *[f"page_flag_{flag}" for flag in page_flags if flag],
    ]
    for row in rows:
        existing_flags = parse_json_field(row["quality_flags_json"], [])
        if not isinstance(existing_flags, list):
            existing_flags = []
        flags = _dedupe([str(flag) for flag in existing_flags] + required_flags)
        model_info = parse_json_field(row["model_info"], {})
        if not isinstance(model_info, dict):
            model_info = {}
        model_info["last_stage10_isolation"] = {
            "page_no": page_no,
            "algorithm_version": STAGE10_VERSION,
            "created_at": _utc_now(),
        }
        target_status = "failed" if row["ai_status"] == "failed" else "needs_review"
        conn.execute(
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
                row["question_id"],
            ),
        )
        updated += 1
    return updated


def _load_latest_page_stats(conn, page_no: int) -> dict[str, Any]:
    row = conn.execute(
        """
        SELECT id AS batch_page_id,
               source_paper_id,
               page_no,
               candidate_count,
               db_question_count,
               warning_candidates,
               duplicate_anchor_count,
               page_flags_json
          FROM import_batch_pages
         WHERE page_no = ?
         ORDER BY updated_at DESC, id DESC
         LIMIT 1
        """,
        (page_no,),
    ).fetchone()
    if row is not None:
        result = dict(row)
        result["page_flags"] = parse_json_field(result.get("page_flags_json"), [])
        if not isinstance(result["page_flags"], list):
            result["page_flags"] = []
        return result
    source_row = conn.execute(
        """
        SELECT source_paper_id,
               count(*) AS db_question_count
          FROM questions
         WHERE CAST(json_extract(meta_json, '$.source_page') AS INTEGER) = ?
         GROUP BY source_paper_id
         ORDER BY db_question_count DESC
         LIMIT 1
        """,
        (page_no,),
    ).fetchone()
    return {
        "batch_page_id": None,
        "source_paper_id": source_row["source_paper_id"] if source_row else None,
        "page_no": page_no,
        "candidate_count": int(source_row["db_question_count"]) if source_row else 0,
        "db_question_count": int(source_row["db_question_count"]) if source_row else 0,
        "warning_candidates": 0,
        "duplicate_anchor_count": 0,
        "page_flags_json": "[]",
        "page_flags": [],
    }


def _count_reviewable_questions_on_page(conn, page_no: int) -> int:
    return int(
        conn.execute(
            """
            SELECT count(*)
              FROM questions q
              JOIN question_structured_contents sc ON sc.question_id = q.id
             WHERE CAST(json_extract(q.meta_json, '$.source_page') AS INTEGER) = ?
               AND q.review_status NOT IN ('reviewed', 'approved')
               AND sc.ai_status NOT IN ('ai_verified', 'human_reviewed')
            """,
            (page_no,),
        ).fetchone()[0]
    )


def _infer_normalized_type(row: dict[str, Any]) -> str:
    normalized = str(row.get("normalized_type") or "").strip()
    if normalized in NORMALIZED_TYPE_ORDER:
        return normalized
    normalized = normalize_question_type(str(row.get("question_type") or ""))
    return normalized if normalized in NORMALIZED_TYPE_ORDER else "unknown"


def _risk_group(row: dict[str, Any]) -> str:
    if _is_protected(row):
        return "protected"
    if int(row.get("duplicate_anchor_count") or 0) > 0:
        return "duplicate_anchor"
    if int(row.get("source_page") or 0) in HIGH_RISK_PAGES:
        return "high_risk"
    return "normal"


def _is_protected(row: dict[str, Any]) -> bool:
    return (
        row.get("review_status") in PROTECTED_QUESTION_STATUSES
        or row.get("ai_status") in PROTECTED_STRUCTURED_STATUSES
    )


def _is_low_risk(row: dict[str, Any]) -> bool:
    if int(row.get("source_page") or 0) in HIGH_RISK_PAGES:
        return False
    if int(row.get("warning_candidates") or 0) > 0:
        return False
    if int(row.get("duplicate_anchor_count") or 0) > 0:
        return False
    page_flags = parse_json_field(row.get("page_flags_json"), [])
    if isinstance(page_flags, list) and page_flags:
        return False
    meta = parse_json_field(row.get("meta_json"), {})
    split_warnings = meta.get("split_warnings") if isinstance(meta, dict) else None
    if isinstance(split_warnings, list) and split_warnings:
        return False
    return bool(row.get("raw_crop_path") and row.get("page_image_path"))


def _split_options(text: str) -> tuple[str, list[dict[str, str]]]:
    pattern = re.compile(r"(?:\(|（)\s*([A-H])\s*(?:\)|）)")
    matches = list(pattern.finditer(text or ""))
    if not matches:
        return text, []
    stem = text[: matches[0].start()].strip()
    options: list[dict[str, str]] = []
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        options.append(
            {
                "label": match.group(1).upper(),
                "text": text[match.end() : end].strip(),
            }
        )
    return stem, options


def _normalize_latex_text(value: str) -> str:
    raw = str(value or "").replace("\r\n", "\n").replace("\r", "\n")
    raw = re.sub(
        r"([xy])\s*2\s*\n\s*([ab])\s*2",
        lambda match: f"\\frac{{{match.group(1)}^2}}{{{match.group(2)}^2}}",
        raw,
    )
    raw = re.sub(r"π\s*\n\s*(\d+)", r"\\frac{\\pi}{\1}", raw)
    raw = re.sub(r"(?<!\d)(\d+)\s*\n\s*(\d+)(?!\d)", r"\\frac{\1}{\2}", raw)
    text = " ".join(raw.split())
    replacements = {
        "−": "-",
        "π": "\\pi",
        "√": "\\sqrt",
        "∩": "\\cap",
        "∪": "\\cup",
        "∈": "\\in",
        "∉": "\\notin",
        "⊂": "\\subset",
        "⊆": "\\subseteq",
        "⊥": "\\perp",
        "∥": "\\parallel",
        "∞": "\\infty",
        "≤": "\\le",
        "⩽": "\\le",
        "≥": "\\ge",
        "⩾": "\\ge",
        "≠": "\\ne",
        "≈": "\\approx",
        "△": "\\triangle",
        "°": "^\\circ",
        "· · ·": "\\cdots",
        "···": "\\cdots",
    }
    for source, target in replacements.items():
        text = text.replace(source, target)
    text = re.sub(r"\\sqrt\s*([A-Za-z0-9]+)", r"\\sqrt{\1}", text)
    text = re.sub(
        r"\blog\s*([2-9])(\d?\.\d+)",
        lambda match: f"\\log_{{{match.group(1)}}}{{{match.group(2)}}}",
        text,
    )
    text = re.sub(
        r"(?<![A-Za-z\\])([xyzabcmnrt])\s*([23])\b",
        r"\1^\2",
        text,
    )
    text = re.sub(r"(\))\s*([23])\b", r"\1^\2", text)
    return text.strip()


def _extract_blanks(stem_latex: str) -> list[dict[str, Any]]:
    count = len(re.findall(r"_{3,}|\\underline|\\blank|（\s*）|\(\s*\)", stem_latex or ""))
    return [
        {"index": index, "placeholder_latex": "\\underline{\\hspace{3em}}"}
        for index in range(1, count + 1)
    ]


def _extract_subquestions(stem_latex: str) -> list[dict[str, Any]]:
    matches = list(re.finditer(r"(?:\(|（)\s*(\d+)\s*(?:\)|）)", stem_latex or ""))
    if not matches:
        return []
    result: list[dict[str, Any]] = []
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(stem_latex)
        result.append(
            {
                "index": int(match.group(1)),
                "stem_latex": stem_latex[match.end() : end].strip(),
                "answer_latex": "",
            }
        )
    return result


def _looks_visual_question(text: str) -> bool:
    return any(token in (text or "") for token in ("如图", "图象", "图像", "框图", "统计图"))


def _confidence_for_flags(flags: list[str]) -> float:
    if any(_flag_requires_review(flag) for flag in flags):
        return 0.52
    return 0.84


def _flag_requires_review(flag: str) -> bool:
    return flag in REVIEW_REQUIRED_FLAGS or flag.startswith(("page_flag_", "split_warning_"))


def _status_distribution(conn) -> dict[str, int]:
    rows = conn.execute(
        """
        SELECT ai_status AS status, count(*) AS count
          FROM question_structured_contents
         GROUP BY ai_status
         ORDER BY ai_status
        """
    ).fetchall()
    return {str(row["status"]): int(row["count"]) for row in rows}


def _structured_type_distribution(conn) -> dict[str, int]:
    rows = conn.execute(
        """
        SELECT normalized_type AS type, count(*) AS count
          FROM question_structured_contents
         GROUP BY normalized_type
         ORDER BY normalized_type
        """
    ).fetchall()
    return {str(row["type"]): int(row["count"]) for row in rows}


def _question_review_distribution(conn) -> dict[str, int]:
    rows = conn.execute(
        """
        SELECT review_status AS status, count(*) AS count
          FROM questions
         GROUP BY review_status
         ORDER BY review_status
        """
    ).fetchall()
    return {str(row["status"]): int(row["count"]) for row in rows}


def _baseline_coverage(conn) -> dict[str, Any]:
    total = conn.execute("SELECT count(*) FROM stage10_baseline_questions").fetchone()[0]
    by_type = {
        row["normalized_type"]: int(row["count"])
        for row in conn.execute(
            """
            SELECT normalized_type, count(*) AS count
              FROM stage10_baseline_questions
             GROUP BY normalized_type
             ORDER BY normalized_type
            """
        ).fetchall()
    }
    by_risk = {
        row["risk_group"]: int(row["count"])
        for row in conn.execute(
            """
            SELECT risk_group, count(*) AS count
              FROM stage10_baseline_questions
             GROUP BY risk_group
             ORDER BY risk_group
            """
        ).fetchall()
    }
    high_risk_pages = [
        int(row["source_page"])
        for row in conn.execute(
            """
            SELECT DISTINCT source_page
              FROM stage10_baseline_questions
             WHERE source_page IN (1098, 1100, 1128, 1148, 1168)
             ORDER BY source_page
            """
        ).fetchall()
        if row["source_page"] is not None
    ]
    return {
        "total": int(total),
        "by_type": by_type,
        "by_risk": by_risk,
        "high_risk_pages": high_risk_pages,
    }


def _quality_flag_counts(conn, *, statuses: tuple[str, ...]) -> dict[str, int]:
    placeholders = ", ".join("?" for _ in statuses)
    rows = conn.execute(
        f"""
        SELECT quality_flags_json
          FROM question_structured_contents
         WHERE ai_status IN ({placeholders})
        """,
        statuses,
    ).fetchall()
    counter: Counter[str] = Counter()
    for row in rows:
        flags = parse_json_field(row["quality_flags_json"], [])
        if isinstance(flags, list):
            counter.update(str(flag) for flag in flags if flag)
    return dict(counter.most_common(20))


def _stage10_verified_count(conn) -> int:
    rows = conn.execute(
        """
        SELECT model_info
          FROM question_structured_contents
         WHERE ai_status = 'ai_verified'
        """
    ).fetchall()
    count = 0
    for row in rows:
        model_info = parse_json_field(row["model_info"], {})
        if isinstance(model_info, dict):
            last_stage10 = model_info.get("last_stage10")
            if isinstance(last_stage10, dict) and last_stage10.get("provider") == STAGE10_RULE_PROVIDER:
                count += 1
    return count


def _high_risk_isolation_rows(conn) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT *
          FROM stage10_page_isolations
         WHERE page_no IN (1098, 1100, 1128, 1148, 1168)
         ORDER BY page_no
        """
    ).fetchall()
    return [dict(row) for row in rows]


def _render_stats(conn) -> dict[str, int]:
    rows = conn.execute(
        """
        SELECT stem_latex,
               ai_status
          FROM question_structured_contents
        """
    ).fetchall()
    renderable_verified = 0
    verified = 0
    for row in rows:
        if row["ai_status"] in ("ai_verified", "human_reviewed"):
            verified += 1
            if latex_basic_renderable(row["stem_latex"]):
                renderable_verified += 1
    return {
        "verified_or_human": verified,
        "renderable_verified_or_human": renderable_verified,
    }


def _asset_stats(conn) -> dict[str, int]:
    question_assets = conn.execute("SELECT count(*) FROM question_assets").fetchone()[0]
    page_assets = conn.execute("SELECT count(*) FROM source_paper_assets").fetchone()[0]
    absolute_question_assets = conn.execute(
        """
        SELECT count(*)
          FROM question_assets
         WHERE relative_path LIKE '%:%' OR relative_path LIKE '/%' OR relative_path LIKE '\\%'
        """
    ).fetchone()[0]
    absolute_page_assets = conn.execute(
        """
        SELECT count(*)
          FROM source_paper_assets
         WHERE relative_path LIKE '%:%' OR relative_path LIKE '/%' OR relative_path LIKE '\\%'
        """
    ).fetchone()[0]
    return {
        "question_assets": int(question_assets),
        "page_assets": int(page_assets),
        "absolute_asset_paths": int(absolute_question_assets) + int(absolute_page_assets),
    }


def _protected_counts(conn) -> dict[str, int]:
    return {
        "reviewed_or_approved_questions": int(
            conn.execute(
                "SELECT count(*) FROM questions WHERE review_status IN ('reviewed', 'approved')"
            ).fetchone()[0]
        ),
        "trusted_structured_rows": int(
            conn.execute(
                "SELECT count(*) FROM question_structured_contents WHERE ai_status IN ('ai_verified', 'human_reviewed')"
            ).fetchone()[0]
        ),
    }


def _render_stage10_report(**data: Any) -> str:
    status_counts = data["status_counts"]
    baseline = data["baseline_coverage"]
    strict_usable_count = int(status_counts.get("ai_verified", 0)) + int(
        status_counts.get("human_reviewed", 0)
    )
    strict_target_status = "met" if strict_usable_count >= 100 else "not_met"
    blocker_lines = "\n".join(
        f"- {flag}: {count}" for flag, count in data["blockers"].items()
    ) or "- none"
    high_risk_lines = "\n".join(
        (
            f"| {row['page_no']} | {row['candidate_count']} | {row['db_question_count']} | "
            f"{row['duplicate_anchor_count']} | {row['isolated_count']} | "
            f"{row['reviewable_count']} | {row['status']} |"
        )
        for row in data["high_risk_rows"]
    )
    if not high_risk_lines:
        high_risk_lines = "| - | - | - | - | - | - | - |"
    return f"""# 阶段 10 质量报告

生成时间：{_utc_now()}

## 总览

- questions 总数：{data['question_count']}
- structured rows：{data['structured_count']}
- questions 主表校验和：`{data['checksum']}`
- 结构化状态：{json.dumps(status_counts, ensure_ascii=False, sort_keys=True)}
- 题型分布：{json.dumps(data['type_counts'], ensure_ascii=False, sort_keys=True)}
- review_status 分布：{json.dumps(data['review_counts'], ensure_ascii=False, sort_keys=True)}
- 严格可用：{strict_usable_count}
- 阶段 10 严格可用目标：{strict_target_status} / 100
- 待复核：{int(status_counts.get('needs_review', 0))}
- 失败：{int(status_counts.get('failed', 0))}
- 未处理：{int(status_counts.get('unprocessed', 0))}
- 受保护：{json.dumps(data['protected'], ensure_ascii=False, sort_keys=True)}
- 阶段 10 新增 ai_verified：{data['stage10_verified']}

## 基准集

- 基准集数量：{baseline['total']}
- 按题型：{json.dumps(baseline['by_type'], ensure_ascii=False, sort_keys=True)}
- 按风险：{json.dumps(baseline['by_risk'], ensure_ascii=False, sort_keys=True)}
- 覆盖高风险页：{baseline['high_risk_pages']}
- 说明：multiple_choice 若为 0，表示当前样本中没有可客观识别的多选题源记录，本阶段不伪造题型。

## 高风险页隔离

| page | candidates | db questions | duplicate anchors | isolated | reviewable | status |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
{high_risk_lines}

## 渲染与导出可用性

- verified/human_reviewed 可渲染：{data['render_stats']['renderable_verified_or_human']} / {data['render_stats']['verified_or_human']}
- question assets：{data['asset_stats']['question_assets']}
- page assets：{data['asset_stats']['page_assets']}
- 绝对资产路径违规：{data['asset_stats']['absolute_asset_paths']}
- question_review_events：{data['event_count']}
- question_ai_suggestions：{data['ai_suggestion_count']}
- 导出版式：按单选/多选/填空/解答/其他分区，导出时重新编号，使用本地数学呈现。

## 主要阻塞 flags

{blocker_lines}

## 客观判断

- `ai_verified` 只计入无 validator flags 的严格候选；`blank_placeholder_inferred`、公式结构可疑、未转换符号、私有区分段符号、零分母、根号拆分和重复锚点页均进入 `needs_review`。
- 阶段 10 严格可用目标当前为 {strict_target_status}；若未达 100，原因是源文本公式结构不可靠、填空空位为规则推断、视觉题/几何图形依赖原貌图、分段/图表题结构污染，不应通过放宽 validator 凑数。
- 高风险 duplicate_anchor 页已登记隔离，不再静默合并；这些页仍需要人工复核或后续切分修复。
- 未处理和 needs_review 仍是主要存量，下一阶段不应直接扩页，除非先确认复核效率和重复锚点处理成本可接受。
"""


def _structured_event_snapshot(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "question_id": row.get("question_id"),
        "ai_status": row.get("ai_status"),
        "normalized_type": row.get("normalized_type"),
        "quality_flags_json": row.get("quality_flags_json"),
        "confidence": row.get("confidence"),
        "model_info": row.get("model_info"),
    }


def _dict_diff(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    return {
        key: {"before": before.get(key), "after": after.get(key)}
        for key in sorted(set(before) | set(after))
        if before.get(key) != after.get(key)
    }


def _dedupe(values: list[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        if value and value not in result:
            result.append(value)
    return result


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
