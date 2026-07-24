from __future__ import annotations

import json
import math
import re
import struct
import zlib
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .config import PROJECT_ROOT, get_project_paths
from .database import connect_database, connect_database_read_only, initialize_database
from .export_quality import (
    EXPORT_READY_STATUSES,
    ExportQualityService,
    summarize_export_quality,
)
from .export_selection import ExportSelectionService
from .exports import save_html_export
from .paper_render import PaperRenderService
from .pdf_scan import scan_pdf_pages
from .source_attribution import (
    SourceAttributionService,
    _extract_header_from_page_text,
    _find_previous_header,
)
from .stage10 import HIGH_RISK_PAGES, questions_main_checksum
from .structured_content import initialize_structured_contents, parse_json_field
from .visual_quality import VISUAL_INSPECTOR_VERSION, VisualQualityInspector


STAGE14_VERSION = "stage14_quality_v1"
STAGE14_REPORT_RELATIVE_PATH = Path("docs") / "stage14_quality_report.md"
STAGE14_QUEUE_NAMES = (
    "export_ready",
    "recut",
    "visual_repair",
    "structured_repair",
    "type_review",
    "source_inferred_audit",
    "export_blocked",
    "protected",
)
VISUAL_REPAIR_REASONS = {
    "visual_image_low_contrast",
    "visual_image_too_small",
    "visual_image_mostly_blank",
    "visual_image_empty_pixels",
    "visual_image_unreadable",
}


class Stage14Error(RuntimeError):
    """Raised when the Stage 14 quality workflow cannot continue."""


def classify_stage14_quality_queue(
    *,
    db_path: Path | None = None,
    project_root: Path = PROJECT_ROOT,
    audit_recuts: bool = True,
    audit_sources: bool = True,
    source_audit_limit: int = 40,
    write_report: bool = False,
) -> dict[str, Any]:
    return Stage14QualityService(
        db_path=db_path,
        project_root=project_root,
    ).classify_queue(
        audit_recuts=audit_recuts,
        audit_sources=audit_sources,
        source_audit_limit=source_audit_limit,
        write_report=write_report,
    )


def generate_stage14_visual_repair_candidates(
    *,
    db_path: Path | None = None,
    project_root: Path = PROJECT_ROOT,
    limit: int | None = None,
    write_report: bool = False,
) -> dict[str, Any]:
    return Stage14QualityService(
        db_path=db_path,
        project_root=project_root,
    ).generate_visual_repair_candidates(limit=limit, write_report=write_report)


def write_stage14_quality_report(
    *,
    db_path: Path | None = None,
    project_root: Path = PROJECT_ROOT,
) -> dict[str, Any]:
    return Stage14QualityService(db_path=db_path, project_root=project_root).write_report()


def summarize_stage14_quality(
    *,
    db_path: Path | None = None,
    project_root: Path = PROJECT_ROOT,
) -> dict[str, Any]:
    return Stage14QualityService(db_path=db_path, project_root=project_root).summarize()


def save_stage14_export_sample(
    *,
    db_path: Path | None = None,
    project_root: Path = PROJECT_ROOT,
    limit: int = 24,
) -> dict[str, Any]:
    service = ExportSelectionService(db_path=db_path, project_root=project_root)
    questions = service.sample_export_questions(limit=limit)
    missing_source_label = [
        question.get("qid")
        for question in questions
        if not str(question.get("source_label") or "").strip()
    ]
    html = PaperRenderService().render_printable(
        questions,
        export=True,
        title="Stage 14 formal export sample",
        asset_url_mode="export_relative",
    )
    result = save_html_export(
        html,
        project_root=project_root,
        filename_prefix="stage14-formal-sample",
    )
    result.update(
        {
            "status": "ok",
            "question_count": len(questions),
            "qids": [question.get("qid") for question in questions],
            "missing_source_label": missing_source_label,
            "stage_version": STAGE14_VERSION,
        }
    )
    return result


def get_stage14_quality_by_question_ids(
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
              FROM stage14_quality_queue
             WHERE question_id IN ({placeholders})
            """,
            unique_ids,
        ).fetchall()
    result = {int(row["question_id"]): dict(row) for row in rows}
    for row in result.values():
        row["queue_tags"] = _json_list(row.get("queue_tags_json"))
        row["flags"] = _json_list(row.get("flags_json"))
        row["meta"] = _json_object(row.get("meta_json"))
    return result


def attach_stage14_quality_states(
    questions: list[dict[str, Any]],
    states_by_question_id: dict[int, dict[str, Any]],
) -> list[dict[str, Any]]:
    for question in questions:
        question["stage14_quality"] = states_by_question_id.get(int(question["id"]))
    return questions


class Stage14QualityService:
    def __init__(
        self,
        *,
        db_path: Path | None = None,
        project_root: Path = PROJECT_ROOT,
    ) -> None:
        self.db_path = db_path
        self.project_root = project_root

    def classify_queue(
        self,
        *,
        audit_recuts: bool = True,
        audit_sources: bool = True,
        source_audit_limit: int = 40,
        write_report: bool = False,
    ) -> dict[str, Any]:
        initialize_database(self.db_path)
        initialize_structured_contents(db_path=self.db_path)
        SourceAttributionService(
            db_path=self.db_path,
            project_root=self.project_root,
        ).ensure_source_attributions()
        ExportQualityService(
            db_path=self.db_path,
            project_root=self.project_root,
        ).ensure_export_quality_states()

        recut_result = (
            self.audit_duplicate_anchor_pages()
            if audit_recuts
            else {"status": "skipped", "audited_pages": 0}
        )
        source_result = (
            self.audit_inferred_sources(limit=source_audit_limit)
            if audit_sources and source_audit_limit != 0
            else {"status": "skipped", "audited": 0}
        )

        with connect_database(self.db_path) as conn:
            before_checksum = questions_main_checksum(conn)
            rows = _load_stage14_rows(conn)
            classified = 0
            for row in rows:
                state = _classify_queue_row(row)
                conn.execute(
                    """
                    INSERT INTO stage14_quality_queue (
                        question_id,
                        qid,
                        queue_name,
                        queue_tags_json,
                        severity,
                        primary_reason,
                        suggested_action,
                        export_quality_status,
                        usability_status,
                        structured_status,
                        normalized_type,
                        review_status,
                        source_page,
                        source_confidence,
                        source_label,
                        flags_json,
                        meta_json,
                        stage_version,
                        classified_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                    ON CONFLICT(question_id) DO UPDATE SET
                        qid = excluded.qid,
                        queue_name = excluded.queue_name,
                        queue_tags_json = excluded.queue_tags_json,
                        severity = excluded.severity,
                        primary_reason = excluded.primary_reason,
                        suggested_action = excluded.suggested_action,
                        export_quality_status = excluded.export_quality_status,
                        usability_status = excluded.usability_status,
                        structured_status = excluded.structured_status,
                        normalized_type = excluded.normalized_type,
                        review_status = excluded.review_status,
                        source_page = excluded.source_page,
                        source_confidence = excluded.source_confidence,
                        source_label = excluded.source_label,
                        flags_json = excluded.flags_json,
                        meta_json = excluded.meta_json,
                        stage_version = excluded.stage_version,
                        classified_at = excluded.classified_at,
                        updated_at = CURRENT_TIMESTAMP
                    """,
                    (
                        row["question_id"],
                        row["qid"],
                        state["queue_name"],
                        json.dumps(state["queue_tags"], ensure_ascii=False),
                        state["severity"],
                        state["primary_reason"],
                        state["suggested_action"],
                        row.get("export_quality_status") or "",
                        row.get("usability_status") or "",
                        row.get("structured_status") or "",
                        row.get("normalized_type") or "unknown",
                        row.get("review_status") or "",
                        row.get("source_page"),
                        row.get("source_confidence") or "",
                        row.get("source_label") or "",
                        json.dumps(state["flags"], ensure_ascii=False),
                        json.dumps(state["meta"], ensure_ascii=False),
                        STAGE14_VERSION,
                    ),
                )
                classified += 1
            after_checksum = questions_main_checksum(conn)
            conn.commit()

        summary = self.summarize()
        report_result = self.write_report(summary=summary) if write_report else None
        return {
            "status": "ok",
            "classified": classified,
            "stage_version": STAGE14_VERSION,
            "questions_checksum_before": before_checksum,
            "questions_checksum_after": after_checksum,
            "questions_main_unchanged": before_checksum == after_checksum,
            "recut_audit": recut_result,
            "source_audit": source_result,
            "summary": summary,
            "report": report_result,
        }

    def audit_duplicate_anchor_pages(self) -> dict[str, Any]:
        initialize_database(self.db_path)
        pages = tuple(int(page) for page in HIGH_RISK_PAGES)
        with connect_database(self.db_path) as conn:
            source_by_page = _source_paper_by_page(conn, pages)
            db_counts = _question_counts_by_page(conn, pages)
            source_paths = _source_paths(conn, source_by_page.values())

        page_results: dict[int, dict[str, Any]] = {}
        page_errors: dict[int, str] = {}
        for source_paper_id, grouped_pages in _group_pages_by_source(source_by_page).items():
            pdf_path = None
            if source_paper_id is not None and source_paths.get(source_paper_id):
                pdf_path = (self.project_root / str(source_paths[source_paper_id])).resolve()
            try:
                scan = scan_pdf_pages(
                    pages=tuple(grouped_pages),
                    pdf_path=pdf_path,
                    project_root=self.project_root,
                )
                page_results.update(
                    {int(row["page_no"]): row for row in scan.get("pages", [])}
                )
            except Exception as exc:  # noqa: BLE001 - keep page-level audit recoverable.
                for page_no in grouped_pages:
                    page_errors[int(page_no)] = str(exc)

        with connect_database(self.db_path) as conn:
            for page_no in pages:
                page = page_results.get(page_no, {})
                duplicate_anchor_count = int(page.get("duplicate_anchor_count") or 0)
                warning_candidates = int(page.get("warning_candidates") or 0)
                page_flags = [str(flag) for flag in page.get("page_flags") or []]
                db_question_count = int(db_counts.get(page_no, 0))
                source_paper_id = source_by_page.get(page_no)
                scan_error = page_errors.get(page_no)
                if scan_error:
                    status = "scan_failed"
                    action = "keep blocked; scan did not complete"
                    error_json = {"error": scan_error}
                elif duplicate_anchor_count > 0 or page_no in HIGH_RISK_PAGES:
                    status = "blocked_needs_manual_recut"
                    action = "manual page-level recut required before export"
                    error_json = {}
                elif warning_candidates or page_flags:
                    status = "candidate_recoverable"
                    action = "review candidate split warnings before promotion"
                    error_json = {}
                else:
                    status = "resolved"
                    action = "no duplicate anchor signal in current scan"
                    error_json = {}
                conn.execute(
                    """
                    INSERT INTO stage14_page_recut_audits (
                        source_paper_id,
                        page_no,
                        candidate_count,
                        db_question_count,
                        duplicate_anchor_count,
                        warning_candidates,
                        page_flags_json,
                        audit_status,
                        recovery_action,
                        error_json,
                        meta_json,
                        stage_version,
                        audited_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                    ON CONFLICT(source_paper_id, page_no, stage_version) DO UPDATE SET
                        candidate_count = excluded.candidate_count,
                        db_question_count = excluded.db_question_count,
                        duplicate_anchor_count = excluded.duplicate_anchor_count,
                        warning_candidates = excluded.warning_candidates,
                        page_flags_json = excluded.page_flags_json,
                        audit_status = excluded.audit_status,
                        recovery_action = excluded.recovery_action,
                        error_json = excluded.error_json,
                        meta_json = excluded.meta_json,
                        audited_at = excluded.audited_at,
                        updated_at = CURRENT_TIMESTAMP
                    """,
                    (
                        source_paper_id,
                        page_no,
                        int(page.get("candidate_count") or db_question_count),
                        db_question_count,
                        duplicate_anchor_count,
                        warning_candidates,
                        json.dumps(page_flags, ensure_ascii=False),
                        status,
                        action,
                        json.dumps(error_json, ensure_ascii=False),
                        json.dumps(
                            {
                                "anchor_count": int(page.get("anchor_count") or 0),
                                "text_length": int(page.get("text_length") or 0),
                                "first_anchors": page.get("first_anchors") or [],
                            },
                            ensure_ascii=False,
                        ),
                        STAGE14_VERSION,
                    ),
                )
            conn.commit()
            rows = _stage14_distribution(conn, "stage14_page_recut_audits", "audit_status")
        return {
            "status": "ok" if not page_errors else "partial",
            "audited_pages": len(pages),
            "audit_status_counts": rows,
            "scan_errors": page_errors,
        }

    def audit_inferred_sources(self, *, limit: int = 40) -> dict[str, Any]:
        initialize_database(self.db_path)
        capped = max(0, min(int(limit), 10000))
        if capped == 0:
            return {"status": "skipped", "audited": 0}
        with connect_database(self.db_path) as conn:
            rows = conn.execute(
                """
                SELECT q.id AS question_id,
                       q.qid,
                       sp.id AS source_paper_id,
                       sp.source_path,
                       sa.source_page,
                       sa.source_label,
                       sa.confidence AS source_confidence,
                       sa.source_text
                  FROM question_source_attributions sa
                  JOIN questions q ON q.id = sa.question_id
                  JOIN source_papers sp ON sp.id = q.source_paper_id
                 WHERE sa.confidence = 'inferred'
                 ORDER BY q.id
                 LIMIT ?
                """,
                (capped,),
            ).fetchall()

        grouped: dict[int, dict[str, Any]] = {}
        for row in rows:
            grouped.setdefault(
                int(row["source_paper_id"]),
                {"source_path": row["source_path"], "rows": []},
            )["rows"].append(dict(row))

        results: list[dict[str, Any]] = []
        for entry in grouped.values():
            results.extend(self._audit_inferred_source_group(entry))

        with connect_database(self.db_path) as conn:
            for result in results:
                conn.execute(
                    """
                    INSERT INTO stage14_source_audits (
                        question_id,
                        source_page,
                        source_confidence,
                        source_label,
                        audit_status,
                        flags_json,
                        meta_json,
                        stage_version,
                        audited_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                    ON CONFLICT(question_id) DO UPDATE SET
                        source_page = excluded.source_page,
                        source_confidence = excluded.source_confidence,
                        source_label = excluded.source_label,
                        audit_status = excluded.audit_status,
                        flags_json = excluded.flags_json,
                        meta_json = excluded.meta_json,
                        stage_version = excluded.stage_version,
                        audited_at = excluded.audited_at,
                        updated_at = CURRENT_TIMESTAMP
                    """,
                    (
                        result["question_id"],
                        result.get("source_page"),
                        result.get("source_confidence") or "",
                        result.get("source_label") or "",
                        result["audit_status"],
                        json.dumps(result["flags"], ensure_ascii=False),
                        json.dumps(result["meta"], ensure_ascii=False),
                        STAGE14_VERSION,
                    ),
                )
            conn.commit()
            status_counts = _stage14_distribution(conn, "stage14_source_audits", "audit_status")
        return {
            "status": "ok",
            "audited": len(results),
            "audit_status_counts": status_counts,
        }

    def _audit_inferred_source_group(self, entry: dict[str, Any]) -> list[dict[str, Any]]:
        try:
            import fitz  # type: ignore
        except ImportError:
            return [
                _source_audit_result(row, "not_checked", ["pymupdf_unavailable"], {})
                for row in entry["rows"]
            ]
        pdf_path = (self.project_root / str(entry["source_path"])).resolve()
        try:
            pdf_path.relative_to(self.project_root.resolve())
        except ValueError:
            return [
                _source_audit_result(row, "needs_manual_source_review", ["source_pdf_outside_project"], {})
                for row in entry["rows"]
            ]
        if not pdf_path.is_file():
            return [
                _source_audit_result(row, "needs_manual_source_review", ["source_pdf_missing"], {})
                for row in entry["rows"]
            ]
        try:
            document = fitz.open(pdf_path)
        except Exception as exc:  # noqa: BLE001
            return [
                _source_audit_result(
                    row,
                    "needs_manual_source_review",
                    ["source_pdf_open_failed"],
                    {"error": str(exc)},
                )
                for row in entry["rows"]
            ]

        results: list[dict[str, Any]] = []
        try:
            exact_headers: dict[int, Any] = {}
            for row in entry["rows"]:
                page_no = _int_or_none(row.get("source_page"))
                flags: list[str] = []
                meta: dict[str, Any] = {}
                if page_no is None or page_no <= 0 or page_no > len(document):
                    results.append(
                        _source_audit_result(
                            row,
                            "needs_manual_source_review",
                            ["source_page_invalid"],
                            {},
                        )
                    )
                    continue
                current = _extract_header_from_page_text(document[page_no - 1].get_text("text"))
                if current:
                    flags.append("current_page_has_header")
                    meta["current_header"] = current.raw_text
                previous = _find_previous_header(
                    document,
                    page_no=page_no,
                    exact_headers=exact_headers,
                )
                source_text = str(row.get("source_text") or "").strip()
                if previous:
                    previous_page, header = previous
                    meta["previous_header_page"] = previous_page
                    meta["previous_header"] = header.raw_text
                    if source_text and header.raw_text == source_text and not current:
                        status = "consistent_previous_header"
                        flags.append("source_text_matches_previous_header")
                    elif source_text and header.raw_text == source_text:
                        status = "needs_manual_source_review"
                        flags.append("current_header_conflicts_with_inferred_source")
                    else:
                        status = "needs_manual_source_review"
                        flags.append("previous_header_mismatch")
                else:
                    status = "needs_manual_source_review"
                    flags.append("previous_header_not_found")
                results.append(_source_audit_result(row, status, flags, meta))
        finally:
            document.close()
        return results

    def generate_visual_repair_candidates(
        self,
        *,
        limit: int | None = None,
        write_report: bool = False,
    ) -> dict[str, Any]:
        initialize_database(self.db_path)
        initialize_structured_contents(db_path=self.db_path)
        ExportQualityService(
            db_path=self.db_path,
            project_root=self.project_root,
        ).classify_all()
        with connect_database(self.db_path) as conn:
            before_checksum = questions_main_checksum(conn)
            rows = _load_visual_repair_rows(conn, limit=limit)

        inspector = VisualQualityInspector(project_root=self.project_root)
        result_counts: Counter[str] = Counter()
        processed = 0
        for row in rows:
            processed += 1
            result = self._generate_one_visual_candidate(dict(row), inspector=inspector)
            result_counts[result["repair_status"]] += 1

        ExportQualityService(
            db_path=self.db_path,
            project_root=self.project_root,
        ).classify_all()
        self.classify_queue(
            audit_recuts=False,
            audit_sources=False,
            write_report=False,
        )
        with connect_database(self.db_path) as conn:
            after_checksum = questions_main_checksum(conn)

        summary = self.summarize()
        report_result = self.write_report(summary=summary) if write_report else None
        return {
            "status": "ok",
            "processed": processed,
            "repair_status_counts": dict(sorted(result_counts.items())),
            "questions_checksum_before": before_checksum,
            "questions_checksum_after": after_checksum,
            "questions_main_unchanged": before_checksum == after_checksum,
            "visual_inspector_version": VISUAL_INSPECTOR_VERSION,
            "summary": summary,
            "report": report_result,
        }

    def _generate_one_visual_candidate(
        self,
        row: dict[str, Any],
        *,
        inspector: VisualQualityInspector,
    ) -> dict[str, Any]:
        question_id = int(row["question_id"])
        blocking = _json_list(row.get("blocking_reasons_json"))
        original_metrics = _json_object(row.get("export_quality_meta_json")).get(
            "visual_quality", {}
        )
        original_relative = str(row.get("raw_crop_path") or "")
        try:
            if not original_relative:
                raise Stage14Error("missing raw crop path")
            original_path = (self.project_root / original_relative).resolve()
            original_path.relative_to(self.project_root.resolve())
            if not original_path.is_file():
                raise Stage14Error("raw crop file missing")
            candidate_relative = _candidate_visual_path(row)
            candidate_path = self.project_root / candidate_relative
            candidate_path.parent.mkdir(parents=True, exist_ok=True)
            _write_enhanced_png_candidate(original_path, candidate_path)
            candidate_row = {
                **row,
                "raw_crop_path": candidate_relative,
                "raw_crop_page_no": row.get("raw_crop_page_no"),
                "raw_crop_bbox_json": row.get("raw_crop_bbox_json"),
            }
            visual = inspector.inspect(candidate_row)
            candidate_metrics = visual
            status = (
                "candidate_passed_visual_check"
                if visual.get("ok")
                else "candidate_failed_visual_check"
            )
            candidate_asset_id = self._register_visual_candidate_asset(
                row,
                candidate_relative=candidate_relative,
                visual=visual,
            )
            error_json: dict[str, Any] = {}
        except Exception as exc:  # noqa: BLE001 - row-level audit result.
            candidate_relative = None
            candidate_asset_id = None
            candidate_metrics = {}
            status = "failed"
            error_json = {"error": str(exc)}

        with connect_database(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO stage14_visual_repair_candidates (
                    question_id,
                    original_asset_id,
                    original_relative_path,
                    candidate_asset_id,
                    candidate_relative_path,
                    repair_status,
                    source_blocking_reasons_json,
                    source_metrics_json,
                    candidate_metrics_json,
                    error_json,
                    stage_version,
                    attempted_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(question_id) DO UPDATE SET
                    original_asset_id = excluded.original_asset_id,
                    original_relative_path = excluded.original_relative_path,
                    candidate_asset_id = excluded.candidate_asset_id,
                    candidate_relative_path = excluded.candidate_relative_path,
                    repair_status = excluded.repair_status,
                    source_blocking_reasons_json = excluded.source_blocking_reasons_json,
                    source_metrics_json = excluded.source_metrics_json,
                    candidate_metrics_json = excluded.candidate_metrics_json,
                    error_json = excluded.error_json,
                    stage_version = excluded.stage_version,
                    attempted_at = excluded.attempted_at,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (
                    question_id,
                    row.get("raw_crop_asset_id"),
                    original_relative,
                    candidate_asset_id,
                    candidate_relative,
                    status,
                    json.dumps(blocking, ensure_ascii=False),
                    json.dumps(original_metrics, ensure_ascii=False),
                    json.dumps(candidate_metrics, ensure_ascii=False),
                    json.dumps(error_json, ensure_ascii=False),
                    STAGE14_VERSION,
                ),
            )
            conn.commit()
        return {"question_id": question_id, "repair_status": status}

    def _register_visual_candidate_asset(
        self,
        row: dict[str, Any],
        *,
        candidate_relative: str,
        visual: dict[str, Any],
    ) -> int:
        meta = {
            "stage": "stage14_visual_repair_candidate",
            "stage_version": STAGE14_VERSION,
            "original_asset_id": row.get("raw_crop_asset_id"),
            "original_relative_path": row.get("raw_crop_path"),
            "visual_quality": visual,
        }
        with connect_database(self.db_path) as conn:
            existing = conn.execute(
                """
                SELECT id
                  FROM question_assets
                 WHERE question_id = ?
                   AND asset_kind = 'other'
                   AND relative_path = ?
                 ORDER BY id DESC
                 LIMIT 1
                """,
                (row["question_id"], candidate_relative),
            ).fetchone()
            if existing:
                conn.execute(
                    """
                    UPDATE question_assets
                       SET page_no = ?,
                           bbox_json = ?,
                           meta_json = ?
                     WHERE id = ?
                    """,
                    (
                        row.get("source_page"),
                        row.get("raw_crop_bbox_json") or "{}",
                        json.dumps(meta, ensure_ascii=False),
                        existing["id"],
                    ),
                )
                asset_id = int(existing["id"])
            else:
                cursor = conn.execute(
                    """
                    INSERT INTO question_assets (
                        question_id,
                        asset_kind,
                        relative_path,
                        page_no,
                        bbox_json,
                        meta_json
                    ) VALUES (?, 'other', ?, ?, ?, ?)
                    """,
                    (
                        row["question_id"],
                        candidate_relative,
                        row.get("source_page"),
                        row.get("raw_crop_bbox_json") or "{}",
                        json.dumps(meta, ensure_ascii=False),
                    ),
                )
                asset_id = int(cursor.lastrowid)
            conn.commit()
        return asset_id

    def summarize(self) -> dict[str, Any]:
        with connect_database_read_only(self.db_path) as conn:
            queue_count = int(conn.execute("SELECT count(*) FROM stage14_quality_queue").fetchone()[0])
            question_count = int(conn.execute("SELECT count(*) FROM questions").fetchone()[0])
            missing_queue = int(
                conn.execute(
                    """
                    SELECT count(*)
                      FROM questions q
                      LEFT JOIN stage14_quality_queue s14 ON s14.question_id = q.id
                     WHERE s14.question_id IS NULL
                    """
                ).fetchone()[0]
            )
            queue_counts = _stage14_distribution(conn, "stage14_quality_queue", "queue_name")
            tag_counts = _stage14_tag_counts(conn)
            reason_counts = _stage14_distribution(
                conn,
                "stage14_quality_queue",
                "primary_reason",
                where="primary_reason <> ''",
            )
            recut_status_counts = _stage14_distribution(
                conn, "stage14_page_recut_audits", "audit_status"
            )
            visual_repair_counts = _stage14_distribution(
                conn, "stage14_visual_repair_candidates", "repair_status"
            )
            source_audit_counts = _stage14_distribution(
                conn, "stage14_source_audits", "audit_status"
            )
            source_confidence = _stage14_distribution(
                conn, "question_source_attributions", "confidence"
            )
            export_quality = summarize_export_quality(
                conn=conn,
                project_root=self.project_root,
            )
            reviewed_approved = {
                row["review_status"]: int(row["count"])
                for row in conn.execute(
                    """
                    SELECT review_status, count(*) AS count
                      FROM questions
                     WHERE review_status IN ('reviewed', 'approved')
                     GROUP BY review_status
                     ORDER BY review_status
                    """
                ).fetchall()
            }
            sample_queue_rows = [
                dict(row)
                for row in conn.execute(
                    """
                    SELECT qid,
                           queue_name,
                           primary_reason,
                           source_page,
                           source_confidence,
                           export_quality_status
                      FROM stage14_quality_queue
                     WHERE queue_name <> 'export_ready'
                     ORDER BY severity DESC, question_id
                     LIMIT 20
                    """
                ).fetchall()
            ]
            high_risk_pages = [
                dict(row)
                for row in conn.execute(
                    """
                    SELECT page_no,
                           candidate_count,
                           db_question_count,
                           duplicate_anchor_count,
                           warning_candidates,
                           audit_status,
                           recovery_action
                      FROM stage14_page_recut_audits
                     ORDER BY page_no
                    """
                ).fetchall()
            ]
            visual_samples = [
                dict(row)
                for row in conn.execute(
                    """
                    SELECT q.qid,
                           v.repair_status,
                           v.original_relative_path,
                           v.candidate_relative_path
                      FROM stage14_visual_repair_candidates v
                      JOIN questions q ON q.id = v.question_id
                     ORDER BY v.id
                     LIMIT 12
                    """
                ).fetchall()
            ]
            source_audit_samples = [
                dict(row)
                for row in conn.execute(
                    """
                    SELECT q.qid,
                           a.source_page,
                           a.audit_status,
                           a.flags_json
                      FROM stage14_source_audits a
                      JOIN questions q ON q.id = a.question_id
                     ORDER BY a.id
                     LIMIT 12
                    """
                ).fetchall()
            ]
            checksum = questions_main_checksum(conn)
            review_events = int(conn.execute("SELECT count(*) FROM question_review_events").fetchone()[0])
            ai_suggestions = int(conn.execute("SELECT count(*) FROM question_ai_suggestions").fetchone()[0])

        inventory = _asset_inventory(self.project_root)
        root_html_files = sorted(path.name for path in self.project_root.glob("*.html"))
        return {
            "question_count": question_count,
            "queue_count": queue_count,
            "missing_queue": missing_queue,
            "queue_counts": queue_counts,
            "queue_tag_counts": tag_counts,
            "primary_reason_counts": reason_counts,
            "recut_status_counts": recut_status_counts,
            "visual_repair_counts": visual_repair_counts,
            "source_audit_counts": source_audit_counts,
            "source_confidence": source_confidence,
            "export_quality": export_quality,
            "reviewed_approved": reviewed_approved,
            "review_events": review_events,
            "ai_suggestions": ai_suggestions,
            "sample_queue_rows": sample_queue_rows,
            "high_risk_pages": high_risk_pages,
            "visual_repair_samples": visual_samples,
            "source_audit_samples": source_audit_samples,
            "questions_checksum": checksum,
            "asset_inventory": inventory,
            "root_html_files": root_html_files,
            "root_html_ok": root_html_files == ["试卷系统.html"],
            "stage_version": STAGE14_VERSION,
            "generated_at": _utc_now(),
        }

    def write_report(self, *, summary: dict[str, Any] | None = None) -> dict[str, Any]:
        summary = summary or self.summarize()
        if int(summary.get("queue_count") or 0) == 0 and int(summary.get("question_count") or 0):
            classify = self.classify_queue(
                audit_recuts=False,
                audit_sources=False,
                write_report=False,
            )
            summary = classify["summary"]
        report_path = self.project_root / STAGE14_REPORT_RELATIVE_PATH
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(_render_stage14_report(summary), encoding="utf-8")
        return {
            "status": "ok",
            "relative_path": STAGE14_REPORT_RELATIVE_PATH.as_posix(),
            "path": str(report_path),
            "size_bytes": report_path.stat().st_size,
            "summary": summary,
        }


def _load_stage14_rows(conn) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT q.id AS question_id,
               q.qid,
               q.review_status,
               q.question_type,
               q.bbox_json AS question_bbox_json,
               CAST(json_extract(q.meta_json, '$.source_page') AS INTEGER) AS source_page,
               sp.id AS source_paper_id,
               sp.paper_code,
               sp.source_path,
               sc.ai_status AS structured_status,
               sc.normalized_type,
               sc.quality_flags_json AS structured_flags_json,
               us.usability_status,
               us.primary_issue AS usability_primary_issue,
               us.issue_flags_json AS usability_flags_json,
               eq.export_quality_status,
               eq.render_mode AS export_render_mode,
               eq.blocking_reasons_json AS export_blocking_reasons_json,
               eq.quality_flags_json AS export_flags_json,
               sa.source_label,
               sa.confidence AS source_confidence,
               qa.id AS raw_crop_asset_id,
               qa.relative_path AS raw_crop_path,
               qa.page_no AS raw_crop_page_no,
               qa.bbox_json AS raw_crop_bbox_json,
               qa.meta_json AS raw_crop_meta_json,
               spa.relative_path AS page_image_path,
               ibp.duplicate_anchor_count,
               ibp.warning_candidates,
               ibp.page_flags_json,
               iso.duplicate_anchor_count AS isolation_duplicate_anchor_count,
               iso.status AS isolation_status
          FROM questions q
          JOIN source_papers sp ON sp.id = q.source_paper_id
          LEFT JOIN question_structured_contents sc ON sc.question_id = q.id
          LEFT JOIN question_usability_states us ON us.question_id = q.id
          LEFT JOIN question_export_quality eq ON eq.question_id = q.id
          LEFT JOIN question_source_attributions sa ON sa.question_id = q.id
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
          LEFT JOIN stage10_page_isolations iso
            ON iso.page_no = CAST(json_extract(q.meta_json, '$.source_page') AS INTEGER)
           AND (iso.source_paper_id IS NULL OR iso.source_paper_id = q.source_paper_id)
         ORDER BY q.id
        """
    ).fetchall()
    return [dict(row) for row in rows]


def _classify_queue_row(row: dict[str, Any]) -> dict[str, Any]:
    export_status = str(row.get("export_quality_status") or "unclassified")
    usability_status = str(row.get("usability_status") or "unclassified")
    structured_status = str(row.get("structured_status") or "missing")
    normalized_type = str(row.get("normalized_type") or "unknown")
    review_status = str(row.get("review_status") or "")
    source_confidence = str(row.get("source_confidence") or "")
    source_page = _int_or_none(row.get("source_page"))
    blocking = _json_list(row.get("export_blocking_reasons_json"))
    export_flags = _json_list(row.get("export_flags_json"))
    usability_flags = _json_list(row.get("usability_flags_json"))
    structured_flags = _json_list(row.get("structured_flags_json"))
    page_flags = _json_list(row.get("page_flags_json"))
    flags = _dedupe(blocking + export_flags + usability_flags + structured_flags + page_flags)

    tags: list[str] = []
    if export_status in EXPORT_READY_STATUSES:
        tags.append("export_ready")
    if source_confidence == "inferred":
        tags.append("source_inferred_audit")
    if review_status in ("reviewed", "approved"):
        tags.append("protected")
    if _needs_recut(row, source_page, blocking, flags):
        tags.append("recut")
    if _needs_visual_repair(blocking, flags):
        tags.append("visual_repair")
    if _needs_structured_repair(usability_status, structured_status, export_status, flags):
        tags.append("structured_repair")
    if normalized_type == "unknown" or usability_status == "needs_type_review" or "type_review_queue" in flags:
        tags.append("type_review")
    if export_status == "export_blocked":
        tags.append("export_blocked")
    if not tags:
        tags.append("export_blocked" if export_status != "unclassified" else "type_review")

    queue_name = _primary_queue(tags, export_status=export_status, review_status=review_status)
    reason = _primary_reason(queue_name, blocking=blocking, flags=flags, row=row)
    return {
        "queue_name": queue_name,
        "queue_tags": _dedupe(tags),
        "severity": _queue_severity(queue_name),
        "primary_reason": reason,
        "suggested_action": _suggested_action(queue_name, reason),
        "flags": flags,
        "meta": {
            "source_page": source_page,
            "stage_version": STAGE14_VERSION,
            "export_render_mode": row.get("export_render_mode"),
            "duplicate_anchor_count": int(row.get("duplicate_anchor_count") or 0),
            "warning_candidates": int(row.get("warning_candidates") or 0),
            "isolation_duplicate_anchor_count": int(
                row.get("isolation_duplicate_anchor_count") or 0
            ),
            "isolation_status": row.get("isolation_status"),
        },
    }


def _primary_queue(tags: list[str], *, export_status: str, review_status: str) -> str:
    if review_status in ("reviewed", "approved") and "protected" in tags:
        return "protected"
    if export_status in EXPORT_READY_STATUSES:
        return "export_ready"
    for name in (
        "recut",
        "visual_repair",
        "structured_repair",
        "type_review",
        "source_inferred_audit",
        "export_blocked",
        "protected",
    ):
        if name in tags:
            return name
    return "export_blocked"


def _needs_recut(
    row: dict[str, Any],
    source_page: int | None,
    blocking: list[str],
    flags: list[str],
) -> bool:
    if source_page in HIGH_RISK_PAGES:
        return True
    if int(row.get("duplicate_anchor_count") or 0) > 0:
        return True
    if int(row.get("isolation_duplicate_anchor_count") or 0) > 0:
        return True
    return any("duplicate_anchor" in flag or "needs_recut" in flag for flag in blocking + flags)


def _needs_visual_repair(blocking: list[str], flags: list[str]) -> bool:
    values = set(blocking + flags)
    return bool(values & VISUAL_REPAIR_REASONS)


def _needs_structured_repair(
    usability_status: str,
    structured_status: str,
    export_status: str,
    flags: list[str],
) -> bool:
    if export_status in EXPORT_READY_STATUSES:
        return False
    if usability_status in ("needs_formula_repair", "needs_blank_repair", "failed"):
        return True
    if structured_status in ("failed", "needs_review", "ai_draft", "unprocessed", "missing"):
        return True
    return any(
        "formula" in flag
        or "blank" in flag
        or flag.startswith("latex_")
        or "structured" in flag
        for flag in flags
    )


def _primary_reason(
    queue_name: str,
    *,
    blocking: list[str],
    flags: list[str],
    row: dict[str, Any],
) -> str:
    if queue_name == "export_ready":
        return "export_ready"
    if queue_name == "protected":
        return "review_status_protected"
    if queue_name == "recut":
        return _first_reason(
            blocking + flags,
            ("duplicate_anchor", "needs_recut", "high_risk", "stage10"),
            "page_recut_required",
        )
    if queue_name == "visual_repair":
        return _first_reason(blocking + flags, ("visual_",), "visual_quality_repair_required")
    if queue_name == "structured_repair":
        return _first_reason(
            blocking + flags,
            ("formula", "blank", "latex_", "structured", "ai_status"),
            str(row.get("usability_primary_issue") or "structured_repair_required"),
        )
    if queue_name == "type_review":
        return "unknown_question_type"
    if queue_name == "source_inferred_audit":
        return "source_confidence_inferred"
    if blocking:
        return blocking[0]
    if flags:
        return flags[0]
    return "export_blocked"


def _first_reason(values: list[str], prefixes: tuple[str, ...], default: str) -> str:
    for value in values:
        if any(prefix in value if not prefix.endswith("_") else value.startswith(prefix) for prefix in prefixes):
            return value
    return default


def _suggested_action(queue_name: str, reason: str) -> str:
    return {
        "export_ready": "eligible for formal HTML export with source_label",
        "protected": "keep manual review state; do not overwrite automatically",
        "recut": "manual recut or split correction required before export",
        "visual_repair": "review stage14 visual repair candidate before promotion",
        "structured_repair": "repair structured fields under strict validator before export",
        "type_review": "assign a normalized question type before export",
        "source_inferred_audit": "check inferred source against nearby page headers",
        "export_blocked": "keep blocked until primary reason is resolved",
    }.get(queue_name, f"review {reason}")


def _queue_severity(queue_name: str) -> int:
    return {
        "recut": 95,
        "protected": 90,
        "export_blocked": 85,
        "visual_repair": 70,
        "structured_repair": 60,
        "type_review": 50,
        "source_inferred_audit": 30,
        "export_ready": 0,
    }.get(queue_name, 80)


def _load_visual_repair_rows(conn, *, limit: int | None) -> list[dict[str, Any]]:
    limit_sql = "LIMIT ?" if limit is not None else ""
    params: list[Any] = [max(1, min(int(limit), 10000))] if limit is not None else []
    rows = conn.execute(
        f"""
        SELECT q.id AS question_id,
               q.qid,
               q.bbox_json AS question_bbox_json,
               CAST(json_extract(q.meta_json, '$.source_page') AS INTEGER) AS source_page,
               sp.paper_code,
               qa.id AS raw_crop_asset_id,
               qa.relative_path AS raw_crop_path,
               qa.page_no AS raw_crop_page_no,
               qa.bbox_json AS raw_crop_bbox_json,
               qa.meta_json AS raw_crop_meta_json,
               eq.blocking_reasons_json,
               eq.meta_json AS export_quality_meta_json,
               ibp.duplicate_anchor_count,
               iso.duplicate_anchor_count AS isolation_duplicate_anchor_count,
               spa.relative_path AS page_image_path
          FROM question_export_quality eq
          JOIN questions q ON q.id = eq.question_id
          JOIN source_papers sp ON sp.id = q.source_paper_id
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
          LEFT JOIN stage10_page_isolations iso
            ON iso.page_no = CAST(json_extract(q.meta_json, '$.source_page') AS INTEGER)
           AND (iso.source_paper_id IS NULL OR iso.source_paper_id = q.source_paper_id)
         WHERE eq.export_quality_status = 'export_blocked'
           AND (
               eq.blocking_reasons_json LIKE '%visual_image_low_contrast%'
               OR eq.blocking_reasons_json LIKE '%visual_image_too_small%'
               OR eq.blocking_reasons_json LIKE '%visual_image_mostly_blank%'
               OR eq.blocking_reasons_json LIKE '%visual_image_empty_pixels%'
               OR eq.blocking_reasons_json LIKE '%visual_image_unreadable%'
           )
         ORDER BY q.id
         {limit_sql}
        """,
        params,
    ).fetchall()
    return [dict(row) for row in rows]


def _write_enhanced_png_candidate(source_path: Path, output_path: Path) -> None:
    try:
        import fitz  # type: ignore
    except ImportError as exc:
        raise Stage14Error("pymupdf unavailable") from exc
    pix = fitz.Pixmap(str(source_path))
    try:
        if pix.n not in (1, 3) or pix.alpha:
            pix = fitz.Pixmap(fitz.csRGB, pix)
        rgb = _pixmap_to_rgb_bytes(pix)
        width = int(pix.width)
        height = int(pix.height)
        rgb = _contrast_stretch_rgb(rgb)
        zoom = 3 if width < 120 or height < 60 else 2
        scaled_width, scaled_height, scaled_rgb = _scale_nearest_rgb(width, height, rgb, zoom)
        output_path.write_bytes(_png_rgb_bytes(scaled_width, scaled_height, scaled_rgb))
    finally:
        pix = None  # release mmap-backed samples promptly on Windows


def _pixmap_to_rgb_bytes(pix: Any) -> bytes:
    components = int(pix.n)
    samples = pix.samples
    if components == 1:
        return b"".join(bytes((value, value, value)) for value in samples)
    rgb = bytearray()
    for offset in range(0, len(samples), components):
        chunk = samples[offset : offset + components]
        if len(chunk) >= 3:
            rgb.extend(chunk[:3])
    return bytes(rgb)


def _contrast_stretch_rgb(rgb: bytes) -> bytes:
    if not rgb:
        return rgb
    intensities = [
        (rgb[index] + rgb[index + 1] + rgb[index + 2]) / 3
        for index in range(0, len(rgb) - 2, 3)
    ]
    if not intensities:
        return rgb
    sorted_values = sorted(intensities)
    p05 = sorted_values[int(len(sorted_values) * 0.05)]
    p95 = sorted_values[min(len(sorted_values) - 1, int(len(sorted_values) * 0.95))]
    span = max(1.0, p95 - p05)
    out = bytearray()
    for index in range(0, len(rgb) - 2, 3):
        for channel in rgb[index : index + 3]:
            stretched = int(round((channel - p05) * 255 / span))
            out.append(max(0, min(255, stretched)))
    return bytes(out)


def _scale_nearest_rgb(width: int, height: int, rgb: bytes, scale: int) -> tuple[int, int, bytes]:
    if scale <= 1:
        return width, height, rgb
    row_size = width * 3
    out = bytearray()
    for y in range(height):
        row = rgb[y * row_size : (y + 1) * row_size]
        scaled_row = bytearray()
        for x in range(width):
            pixel = row[x * 3 : x * 3 + 3]
            scaled_row.extend(pixel * scale)
        for _ in range(scale):
            out.extend(scaled_row)
    return width * scale, height * scale, bytes(out)


def _png_rgb_bytes(width: int, height: int, rgb: bytes) -> bytes:
    def chunk(kind: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + kind
            + data
            + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
        )

    rows = []
    row_size = width * 3
    for y in range(height):
        rows.append(b"\x00" + rgb[y * row_size : (y + 1) * row_size])
    raw = zlib.compress(b"".join(rows))
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", raw)
        + chunk(b"IEND", b"")
    )


def _candidate_visual_path(row: dict[str, Any]) -> str:
    qid = _safe_filename(str(row.get("qid") or f"q{row['question_id']}"))
    paper_code = _safe_filename(str(row.get("paper_code") or "paper"))
    return (
        Path("data")
        / "assets"
        / "question_images"
        / paper_code
        / "stage14_repair"
        / f"{qid}-{STAGE14_VERSION}.png"
    ).as_posix()


def _safe_filename(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._") or "item"


def _source_audit_result(
    row: dict[str, Any],
    status: str,
    flags: list[str],
    meta: dict[str, Any],
) -> dict[str, Any]:
    return {
        "question_id": int(row["question_id"]),
        "source_page": row.get("source_page"),
        "source_confidence": row.get("source_confidence") or "",
        "source_label": row.get("source_label") or "",
        "audit_status": status,
        "flags": _dedupe(flags),
        "meta": meta,
    }


def _source_paper_by_page(conn, pages: tuple[int, ...]) -> dict[int, int | None]:
    result: dict[int, int | None] = {}
    for page_no in pages:
        row = conn.execute(
            """
            SELECT source_paper_id, count(*) AS count
              FROM questions
             WHERE CAST(json_extract(meta_json, '$.source_page') AS INTEGER) = ?
             GROUP BY source_paper_id
             ORDER BY count DESC
             LIMIT 1
            """,
            (page_no,),
        ).fetchone()
        result[page_no] = int(row["source_paper_id"]) if row else None
    return result


def _source_paths(conn, source_paper_ids: Any) -> dict[int, str]:
    ids = sorted({int(value) for value in source_paper_ids if value is not None})
    if not ids:
        return {}
    placeholders = ", ".join("?" for _ in ids)
    rows = conn.execute(
        f"""
        SELECT id, source_path
          FROM source_papers
         WHERE id IN ({placeholders})
        """,
        ids,
    ).fetchall()
    return {int(row["id"]): str(row["source_path"]) for row in rows}


def _group_pages_by_source(source_by_page: dict[int, int | None]) -> dict[int | None, list[int]]:
    grouped: dict[int | None, list[int]] = {}
    for page_no, source_paper_id in source_by_page.items():
        grouped.setdefault(source_paper_id, []).append(page_no)
    return grouped


def _question_counts_by_page(conn, pages: tuple[int, ...]) -> dict[int, int]:
    placeholders = ", ".join("?" for _ in pages)
    rows = conn.execute(
        f"""
        SELECT CAST(json_extract(meta_json, '$.source_page') AS INTEGER) AS page_no,
               count(*) AS count
          FROM questions
         WHERE CAST(json_extract(meta_json, '$.source_page') AS INTEGER) IN ({placeholders})
         GROUP BY page_no
        """,
        pages,
    ).fetchall()
    return {int(row["page_no"]): int(row["count"]) for row in rows}


def _stage14_distribution(conn, table: str, column: str, *, where: str = "1 = 1") -> dict[str, int]:
    rows = conn.execute(
        f"""
        SELECT {column} AS key, count(*) AS count
          FROM {table}
         WHERE {where}
         GROUP BY {column}
         ORDER BY {column}
        """
    ).fetchall()
    return {str(row["key"]): int(row["count"]) for row in rows if row["key"] is not None}


def _stage14_tag_counts(conn) -> dict[str, int]:
    counter: Counter[str] = Counter()
    for row in conn.execute("SELECT queue_tags_json FROM stage14_quality_queue").fetchall():
        counter.update(_json_list(row["queue_tags_json"]))
    return dict(sorted(counter.items()))


def _asset_inventory(project_root: Path) -> dict[str, Any]:
    paths = get_project_paths(project_root, require_target_pdf=False)
    assets_dir = paths.assets_dir
    exports_dir = paths.exports_dir
    db_path = paths.db_path
    asset_files = [path for path in assets_dir.rglob("*") if path.is_file()] if assets_dir.exists() else []
    export_files = [path for path in exports_dir.rglob("*") if path.is_file()] if exports_dir.exists() else []
    page_png = [path for path in paths.paper_pages_dir.rglob("*.png")] if paths.paper_pages_dir.exists() else []
    question_png = [
        path for path in paths.question_images_dir.rglob("*.png")
    ] if paths.question_images_dir.exists() else []
    stage14_png = [
        path
        for path in question_png
        if "stage14_repair" in {part.lower() for part in path.parts}
    ]
    return {
        "db_size_bytes": db_path.stat().st_size if db_path.is_file() else 0,
        "asset_file_count": len(asset_files),
        "asset_size_bytes": sum(path.stat().st_size for path in asset_files),
        "export_file_count": len(export_files),
        "export_size_bytes": sum(path.stat().st_size for path in export_files),
        "page_png_count": len(page_png),
        "question_png_count": len(question_png),
        "stage14_repair_png_count": len(stage14_png),
    }


def _render_stage14_report(summary: dict[str, Any]) -> str:
    export_quality = summary.get("export_quality", {})
    inventory = summary.get("asset_inventory", {})
    return f"""# Stage 14 Quality Report

Generated at: {summary.get('generated_at')}
Version: `{summary.get('stage_version')}`

## Scope

- Current questions: {summary.get('question_count')}
- Stage14 queue rows: {summary.get('queue_count')}
- Missing queue rows: {summary.get('missing_queue')}
- Questions checksum: `{summary.get('questions_checksum')}`
- Root HTML files: {json.dumps(summary.get('root_html_files'), ensure_ascii=False)}
- Root HTML check: {summary.get('root_html_ok')}

Stage14 does not import new PDF pages, does not mutate `questions` content/status fields, and does not promote visual repair candidates automatically.

## Export Quality

- Export quality counts: {json.dumps(export_quality.get('status_counts', {}), ensure_ascii=False, sort_keys=True)}
- Export-ready structured: {int(export_quality.get('status_counts', {}).get('export_ready_structured', 0))}
- Export-ready visual: {int(export_quality.get('status_counts', {}).get('export_ready_visual', 0))}
- Export blocked: {int(export_quality.get('status_counts', {}).get('export_blocked', 0))}
- Source confidence: {json.dumps(summary.get('source_confidence', {}), ensure_ascii=False, sort_keys=True)}
- Reviewed/approved: {json.dumps(summary.get('reviewed_approved', {}), ensure_ascii=False, sort_keys=True)}

## Queues

- Primary queue counts: {json.dumps(summary.get('queue_counts', {}), ensure_ascii=False, sort_keys=True)}
- Queue tag counts: {json.dumps(summary.get('queue_tag_counts', {}), ensure_ascii=False, sort_keys=True)}
- Primary reason counts: {json.dumps(summary.get('primary_reason_counts', {}), ensure_ascii=False, sort_keys=True)}

## Duplicate Anchor / Recut Audit

- Recut audit counts: {json.dumps(summary.get('recut_status_counts', {}), ensure_ascii=False, sort_keys=True)}

| page | candidates | db questions | duplicate anchors | warnings | status | action |
|---:|---:|---:|---:|---:|---|---|
{_markdown_page_rows(summary.get('high_risk_pages', []))}

## Visual Repair Candidates

- Visual repair status counts: {json.dumps(summary.get('visual_repair_counts', {}), ensure_ascii=False, sort_keys=True)}
- Stage14 repair PNG files: {inventory.get('stage14_repair_png_count', 0)}

{_markdown_visual_rows(summary.get('visual_repair_samples', []))}

## Inferred Source Audit

- Source audit counts: {json.dumps(summary.get('source_audit_counts', {}), ensure_ascii=False, sort_keys=True)}

{_markdown_source_audit_rows(summary.get('source_audit_samples', []))}

## Assets And Operations

- DB size bytes: {inventory.get('db_size_bytes', 0)}
- Asset files: {inventory.get('asset_file_count', 0)}
- Asset size bytes: {inventory.get('asset_size_bytes', 0)}
- Page PNG count: {inventory.get('page_png_count', 0)}
- Question PNG count: {inventory.get('question_png_count', 0)}
- Export files: {inventory.get('export_file_count', 0)}
- Review events: {summary.get('review_events')}
- AI suggestions: {summary.get('ai_suggestions')}

## Sample Blocked Rows

{_markdown_queue_rows(summary.get('sample_queue_rows', []))}

## Recommendation

Enter Stage 15 only after the blocked and repair queues are either manually resolved or accepted as excluded. Formal HTML exports must continue to select only `export_ready_*` rows with `source_label`.
"""


def _markdown_page_rows(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return "| - | - | - | - | - | - | - |"
    return "\n".join(
        (
            f"| {row.get('page_no')} | {row.get('candidate_count')} | "
            f"{row.get('db_question_count')} | {row.get('duplicate_anchor_count')} | "
            f"{row.get('warning_candidates')} | {row.get('audit_status')} | "
            f"{row.get('recovery_action')} |"
        )
        for row in rows
    )


def _markdown_visual_rows(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return "No visual repair candidate rows yet."
    lines = ["| qid | status | candidate |", "|---|---|---|"]
    for row in rows:
        lines.append(
            f"| {row.get('qid')} | {row.get('repair_status')} | "
            f"{row.get('candidate_relative_path') or ''} |"
        )
    return "\n".join(lines)


def _markdown_source_audit_rows(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return "No inferred source audit sample rows yet."
    lines = ["| qid | page | status | flags |", "|---|---:|---|---|"]
    for row in rows:
        lines.append(
            f"| {row.get('qid')} | {row.get('source_page') or ''} | "
            f"{row.get('audit_status')} | {row.get('flags_json') or '[]'} |"
        )
    return "\n".join(lines)


def _markdown_queue_rows(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return "No blocked sample rows."
    lines = ["| qid | queue | reason | page | source | export_quality |", "|---|---|---|---:|---|---|"]
    for row in rows:
        lines.append(
            f"| {row.get('qid')} | {row.get('queue_name')} | {row.get('primary_reason')} | "
            f"{row.get('source_page') or ''} | {row.get('source_confidence') or ''} | "
            f"{row.get('export_quality_status') or ''} |"
        )
    return "\n".join(lines)


def _json_list(value: Any) -> list[str]:
    data = parse_json_field(value, [])
    if not isinstance(data, list):
        return []
    return [str(item) for item in data if str(item)]


def _json_object(value: Any) -> dict[str, Any]:
    data = parse_json_field(value, {})
    return data if isinstance(data, dict) else {}


def _int_or_none(value: Any) -> int | None:
    try:
        if value is None or (isinstance(value, float) and math.isnan(value)):
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def _dedupe(values: list[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        if value and value not in result:
            result.append(value)
    return result


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()
