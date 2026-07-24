from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .config import PROJECT_ROOT
from .database import connect_database, connect_database_read_only, initialize_database
from .exports import save_html_export
from .export_quality import (
    EXPORT_QUALITY_CLASSIFICATION_VERSION,
    EXPORT_READY_STATUSES,
    ExportQualityService,
    attach_export_quality_states,
    get_export_quality_by_question_ids,
)
from .paper_render import PaperRenderService, render_export_quality_audit_html
from .risk_classifier import EXPORT_USABLE_STATUSES, USABILITY_CLASSIFICATION_VERSION
from .source_attribution import SourceAttributionService
from .stage11 import (
    attach_usability_states,
    classify_usability_states,
    get_usability_states_by_question_ids,
    summarize_usability_states,
)
from .structured_content import get_structured_contents_by_question_ids
from .structured_render import attach_structured_contents


class ExportSelectionService:
    """Select only Stage 12 export-ready questions for formal papers."""

    def __init__(
        self,
        *,
        db_path: Path | None = None,
        project_root: Path = PROJECT_ROOT,
        use_export_quality: bool = True,
    ):
        self.db_path = db_path
        self.project_root = project_root
        self.use_export_quality = use_export_quality

    def select_for_question_ids(self, question_ids: list[int]) -> dict[str, Any]:
        unique_ids = [int(value) for value in dict.fromkeys(question_ids)]
        if not unique_ids:
            return {"questions": [], "rejected": [], "eligible_ids": []}

        if self.use_export_quality:
            return self._select_by_export_quality(unique_ids)

        return self._select_by_usability(unique_ids)

    def _select_by_export_quality(self, unique_ids: list[int]) -> dict[str, Any]:
        export_quality = get_export_quality_by_question_ids(unique_ids, db_path=self.db_path)
        eligible_ids = [
            question_id
            for question_id in unique_ids
            if export_quality.get(question_id, {}).get("export_quality_status")
            in EXPORT_READY_STATUSES
            and int(export_quality.get(question_id, {}).get("export_eligible") or 0) == 1
        ]
        rejected = [
            _rejected_export_quality_row(question_id, export_quality.get(question_id))
            for question_id in unique_ids
            if question_id not in eligible_ids
        ]
        questions = self._load_questions(eligible_ids)
        structured = get_structured_contents_by_question_ids(eligible_ids, db_path=self.db_path)
        attach_structured_contents(questions, structured)
        attach_export_quality_states(questions, export_quality)
        usability = get_usability_states_by_question_ids(eligible_ids, db_path=self.db_path)
        attach_usability_states(questions, usability)
        return {
            "questions": questions,
            "rejected": rejected,
            "eligible_ids": eligible_ids,
        }

    def _select_by_usability(self, unique_ids: list[int]) -> dict[str, Any]:
        usability = get_usability_states_by_question_ids(unique_ids, db_path=self.db_path)
        eligible_ids = [
            question_id
            for question_id in unique_ids
            if usability.get(question_id, {}).get("usability_status") in EXPORT_USABLE_STATUSES
            and int(usability.get(question_id, {}).get("export_eligible") or 0) == 1
        ]
        rejected = [
            {
                "question_id": question_id,
                "usability_status": usability.get(question_id, {}).get(
                    "usability_status", "unclassified"
                ),
            }
            for question_id in unique_ids
            if question_id not in eligible_ids
        ]
        questions = self._load_questions(eligible_ids)
        structured = get_structured_contents_by_question_ids(eligible_ids, db_path=self.db_path)
        attach_structured_contents(questions, structured)
        attach_usability_states(questions, usability)
        return {
            "questions": questions,
            "rejected": rejected,
            "eligible_ids": eligible_ids,
        }

    def sample_export_questions(self, *, limit: int = 20) -> list[dict[str, Any]]:
        self.ensure_source_attributions()
        if self.use_export_quality:
            self.ensure_export_quality_states()
            return self._sample_export_quality_questions(limit=limit)

        self.ensure_usability_states()
        capped = max(1, min(limit, 100))
        with connect_database_read_only(self.db_path) as conn:
            strict_limit = max(1, capped // 2)
            strict_rows = conn.execute(
                """
                SELECT q.id
                  FROM question_usability_states us
                  JOIN questions q ON q.id = us.question_id
                 WHERE us.export_eligible = 1
                   AND us.usability_status = 'strict_structured'
                 ORDER BY q.id
                 LIMIT ?
                """,
                (strict_limit,),
            ).fetchall()
            strict_ids = [int(row["id"]) for row in strict_rows]
            visual_limit = max(0, capped - len(strict_ids))
            visual_rows = conn.execute(
                """
                SELECT q.id
                  FROM question_usability_states us
                  JOIN questions q ON q.id = us.question_id
                 WHERE us.export_eligible = 1
                   AND us.usability_status = 'visual_fallback'
                 ORDER BY q.id
                 LIMIT ?
                """,
                (visual_limit,),
            ).fetchall()
            visual_ids = [int(row["id"]) for row in visual_rows]
            if len(strict_ids) + len(visual_ids) < capped:
                remaining = capped - len(strict_ids) - len(visual_ids)
                used = strict_ids + visual_ids
                exclude_sql = (
                    f"AND q.id NOT IN ({', '.join('?' for _ in used)})" if used else ""
                )
                fill_rows = conn.execute(
                    f"""
                    SELECT q.id
                      FROM question_usability_states us
                      JOIN questions q ON q.id = us.question_id
                     WHERE us.export_eligible = 1
                       AND us.usability_status IN ('strict_structured', 'visual_fallback')
                       {exclude_sql}
                     ORDER BY q.id
                     LIMIT ?
                    """,
                    [*used, remaining],
                ).fetchall()
                visual_ids.extend(int(row["id"]) for row in fill_rows)
        return self.select_for_question_ids(strict_ids + visual_ids)["questions"]

    def _sample_export_quality_questions(self, *, limit: int) -> list[dict[str, Any]]:
        capped = max(1, min(limit, 100))
        with connect_database_read_only(self.db_path) as conn:
            structured_limit = max(1, capped // 2)
            structured_rows = conn.execute(
                """
                SELECT q.id
                  FROM question_export_quality eq
                  JOIN questions q ON q.id = eq.question_id
                 WHERE eq.export_eligible = 1
                   AND eq.export_quality_status = 'export_ready_structured'
                 ORDER BY q.id
                 LIMIT ?
                """,
                (structured_limit,),
            ).fetchall()
            structured_ids = [int(row["id"]) for row in structured_rows]
            visual_limit = max(0, capped - len(structured_ids))
            visual_rows = conn.execute(
                """
                SELECT q.id
                  FROM question_export_quality eq
                  JOIN questions q ON q.id = eq.question_id
                 WHERE eq.export_eligible = 1
                   AND eq.export_quality_status = 'export_ready_visual'
                 ORDER BY q.id
                 LIMIT ?
                """,
                (visual_limit,),
            ).fetchall()
            visual_ids = [int(row["id"]) for row in visual_rows]
            if len(structured_ids) + len(visual_ids) < capped:
                remaining = capped - len(structured_ids) - len(visual_ids)
                used = structured_ids + visual_ids
                exclude_sql = (
                    f"AND q.id NOT IN ({', '.join('?' for _ in used)})" if used else ""
                )
                fill_rows = conn.execute(
                    f"""
                    SELECT q.id
                      FROM question_export_quality eq
                      JOIN questions q ON q.id = eq.question_id
                     WHERE eq.export_eligible = 1
                       AND eq.export_quality_status IN ('export_ready_structured', 'export_ready_visual')
                       {exclude_sql}
                     ORDER BY q.id
                     LIMIT ?
                    """,
                    [*used, remaining],
                ).fetchall()
                visual_ids.extend(int(row["id"]) for row in fill_rows)
        return self.select_for_question_ids(structured_ids + visual_ids)["questions"]

    def ensure_export_quality_states(self) -> dict[str, Any]:
        return ExportQualityService(
            db_path=self.db_path,
            project_root=self.project_root,
        ).ensure_export_quality_states()

    def ensure_source_attributions(self) -> dict[str, Any]:
        return SourceAttributionService(
            db_path=self.db_path,
            project_root=self.project_root,
        ).ensure_source_attributions()

    def ensure_usability_states(self) -> dict[str, Any]:
        initialize_database(self.db_path)
        with connect_database_read_only(self.db_path) as conn:
            question_count = int(conn.execute("SELECT count(*) FROM questions").fetchone()[0])
            usability_count = int(
                conn.execute("SELECT count(*) FROM question_usability_states").fetchone()[0]
            )
            stale_count = int(
                conn.execute(
                    """
                    SELECT count(*)
                      FROM question_usability_states
                     WHERE classification_version <> ?
                    """,
                    (USABILITY_CLASSIFICATION_VERSION,),
                ).fetchone()[0]
            )
        if usability_count != question_count or stale_count:
            return classify_usability_states(
                db_path=self.db_path,
                project_root=self.project_root,
            )
        return {
            "status": "ok",
            "classified": 0,
            "classification_version": USABILITY_CLASSIFICATION_VERSION,
            "summary": summarize_usability_states(
                db_path=self.db_path,
                project_root=self.project_root,
            ),
        }

    def _load_questions(self, question_ids: list[int]) -> list[dict[str, Any]]:
        if not question_ids:
            return []
        placeholders = ", ".join("?" for _ in question_ids)
        with connect_database_read_only(self.db_path) as conn:
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
                       CAST(json_extract(q.meta_json, '$.source_page') AS INTEGER) AS source_page,
                       qa.relative_path AS raw_crop_path,
                       qa.bbox_json AS raw_crop_bbox_json,
                       qa.page_no AS raw_crop_page_no
                  FROM questions q
                  JOIN source_papers sp ON sp.id = q.source_paper_id
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
                 WHERE q.id IN ({placeholders})
                """,
                question_ids,
            ).fetchall()
        by_id = {int(row["id"]): dict(row) for row in rows}
        return [by_id[question_id] for question_id in question_ids if question_id in by_id]


def save_stage11_export_sample(
    *,
    db_path: Path | None = None,
    project_root: Path = PROJECT_ROOT,
    limit: int = 24,
) -> dict[str, Any]:
    service = ExportSelectionService(
        db_path=db_path,
        project_root=project_root,
        use_export_quality=False,
    )
    questions = service.sample_export_questions(limit=limit)
    html = PaperRenderService().render_printable(
        questions,
        export=True,
        title="阶段 11 正式样卷",
        asset_url_mode="export_relative",
    )
    result = save_html_export(
        html,
        project_root=project_root,
        filename_prefix="stage11-formal-sample",
    )
    result.update(
        {
            "status": "ok",
            "question_count": len(questions),
            "qids": [question["qid"] for question in questions],
        }
    )
    return result


def save_stage12_export_sample(
    *,
    db_path: Path | None = None,
    project_root: Path = PROJECT_ROOT,
    limit: int = 24,
) -> dict[str, Any]:
    service = ExportSelectionService(db_path=db_path, project_root=project_root)
    questions = service.sample_export_questions(limit=limit)
    renderer = PaperRenderService()
    html = renderer.render_printable(
        questions,
        export=True,
        title="阶段 12 正式样卷",
        asset_url_mode="export_relative",
    )
    result = save_html_export(
        html,
        project_root=project_root,
        filename_prefix="stage12-formal-sample",
    )
    audit = save_stage12_export_audit_sample(
        db_path=db_path,
        project_root=project_root,
    )
    result.update(
        {
            "status": "ok",
            "question_count": len(questions),
            "qids": [question["qid"] for question in questions],
            "classification_version": EXPORT_QUALITY_CLASSIFICATION_VERSION,
            "audit_relative_path": audit["relative_path"],
            "audit_path": audit["path"],
        }
    )
    return result


def save_stage12_export_audit_sample(
    *,
    db_path: Path | None = None,
    project_root: Path = PROJECT_ROOT,
    per_status: int = 3,
) -> dict[str, Any]:
    ExportQualityService(db_path=db_path, project_root=project_root).ensure_export_quality_states()
    rows_by_status: dict[str, list[dict[str, Any]]] = {}
    with connect_database(db_path) as conn:
        for status in (
            "export_ready_structured",
            "export_ready_visual",
            "export_candidate",
            "export_blocked",
        ):
            rows = conn.execute(
                """
                SELECT q.qid,
                       CAST(json_extract(q.meta_json, '$.source_page') AS INTEGER) AS source_page,
                       eq.export_quality_status,
                       eq.source_usability_status,
                       eq.render_mode,
                       eq.blocking_reasons_json,
                       eq.quality_flags_json
                  FROM question_export_quality eq
                  JOIN questions q ON q.id = eq.question_id
                 WHERE eq.export_quality_status = ?
                 ORDER BY q.id
                 LIMIT ?
                """,
                (status, max(1, min(per_status, 10))),
            ).fetchall()
            parsed = []
            for row in rows:
                item = dict(row)
                item["blocking_reasons"] = _parse_json_list(item["blocking_reasons_json"])
                item["quality_flags"] = _parse_json_list(item["quality_flags_json"])
                parsed.append(item)
            rows_by_status[status] = parsed
    html = render_export_quality_audit_html(rows_by_status)
    result = save_html_export(
        html,
        project_root=project_root,
        filename_prefix="stage12-export-quality-audit",
    )
    result.update({"status": "ok", "statuses": {key: len(value) for key, value in rows_by_status.items()}})
    return result


def _rejected_export_quality_row(
    question_id: int,
    row: dict[str, Any] | None,
) -> dict[str, Any]:
    if not row:
        return {
            "question_id": question_id,
            "export_quality_status": "unclassified",
            "blocking_reasons": ["export_quality_unclassified"],
            "quality_flags": [],
        }
    return {
        "question_id": question_id,
        "export_quality_status": row.get("export_quality_status", "unclassified"),
        "source_usability_status": row.get("source_usability_status", ""),
        "blocking_reasons": row.get("blocking_reasons", []),
        "quality_flags": row.get("quality_flags", []),
    }


def _parse_json_list(value: str | None) -> list[str]:
    try:
        parsed = json.loads(value or "[]")
    except json.JSONDecodeError:
        return []
    if not isinstance(parsed, list):
        return []
    return [str(item) for item in parsed if item]
