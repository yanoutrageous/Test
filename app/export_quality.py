from __future__ import annotations

import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .config import PROJECT_ROOT
from .database import connect_database, connect_database_read_only, initialize_database
from .risk_classifier import RiskClassifier, USABILITY_CLASSIFICATION_VERSION
from .safety.workspace_io import get_workspace_io
from .stage10 import HIGH_RISK_PAGES, questions_main_checksum
from .stage11 import classify_usability_states
from .structured_content import initialize_structured_contents, parse_json_field
from .visual_quality import VISUAL_INSPECTOR_VERSION, VisualQualityInspector


EXPORT_QUALITY_CLASSIFICATION_VERSION = "stage12_export_quality_v1"
EXPORT_READY_STATUSES = ("export_ready_structured", "export_ready_visual")
EXPORT_QUALITY_STATUSES = (
    "export_ready_structured",
    "export_ready_visual",
    "export_candidate",
    "export_blocked",
)
EXPORT_RENDER_MODES = ("structured_html", "raw_crop_image", "candidate_preview", "none")


class ExportQualityService:
    """Classify question candidates into formal export quality lanes."""

    def __init__(
        self,
        *,
        db_path: Path | None = None,
        project_root: Path = PROJECT_ROOT,
    ):
        self.db_path = db_path
        self.project_root = project_root
        self.risk_classifier = RiskClassifier(project_root=project_root)
        self.visual_inspector = VisualQualityInspector(project_root=project_root)

    def classify_all(self, *, limit: int | None = None) -> dict[str, Any]:
        initialize_database(self.db_path)
        initialize_structured_contents(db_path=self.db_path)
        self.ensure_usability_states()
        capped_limit = None if limit is None else max(1, min(limit, 10000))

        with connect_database(self.db_path) as conn:
            rows = _load_export_quality_rows(conn, limit=capped_limit)
            for row in rows:
                state = self.classify_row(row)
                conn.execute(
                    """
                    INSERT INTO question_export_quality (
                        question_id,
                        export_quality_status,
                        render_mode,
                        source_usability_status,
                        export_eligible,
                        blocking_reasons_json,
                        quality_flags_json,
                        classification_version,
                        classified_at,
                        meta_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?)
                    ON CONFLICT(question_id) DO UPDATE SET
                        export_quality_status = excluded.export_quality_status,
                        render_mode = excluded.render_mode,
                        source_usability_status = excluded.source_usability_status,
                        export_eligible = excluded.export_eligible,
                        blocking_reasons_json = excluded.blocking_reasons_json,
                        quality_flags_json = excluded.quality_flags_json,
                        classification_version = excluded.classification_version,
                        classified_at = excluded.classified_at,
                        meta_json = excluded.meta_json,
                        updated_at = CURRENT_TIMESTAMP
                    """,
                    (
                        row["question_id"],
                        state["export_quality_status"],
                        state["render_mode"],
                        state["source_usability_status"],
                        1 if state["export_eligible"] else 0,
                        json.dumps(state["blocking_reasons"], ensure_ascii=False),
                        json.dumps(state["quality_flags"], ensure_ascii=False),
                        state["classification_version"],
                        json.dumps(state["meta"], ensure_ascii=False),
                    ),
                )
            conn.commit()
            summary = summarize_export_quality(conn=conn, project_root=self.project_root)

        return {
            "status": "ok",
            "classified": len(rows),
            "classification_version": EXPORT_QUALITY_CLASSIFICATION_VERSION,
            "summary": summary,
        }

    def ensure_export_quality_states(self) -> dict[str, Any]:
        initialize_database(self.db_path)
        self.ensure_usability_states()
        with connect_database_read_only(self.db_path) as conn:
            question_count = int(conn.execute("SELECT count(*) FROM questions").fetchone()[0])
            quality_count = int(
                conn.execute("SELECT count(*) FROM question_export_quality").fetchone()[0]
            )
            stale_count = int(
                conn.execute(
                    """
                    SELECT count(*)
                      FROM question_export_quality
                     WHERE classification_version <> ?
                    """,
                    (EXPORT_QUALITY_CLASSIFICATION_VERSION,),
                ).fetchone()[0]
            )
        if quality_count != question_count or stale_count:
            return self.classify_all()
        return {
            "status": "ok",
            "classified": 0,
            "classification_version": EXPORT_QUALITY_CLASSIFICATION_VERSION,
            "question_count": question_count,
            "export_quality_count": quality_count,
            "stale_count": stale_count,
        }

    def ensure_usability_states(self) -> dict[str, Any]:
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
        return {"status": "ok", "classified": 0}

    def classify_row(self, row: dict[str, Any]) -> dict[str, Any]:
        usability_status = str(row.get("usability_status") or "unclassified")
        usability_flags = _json_list(row.get("issue_flags_json"))
        base_flags = _dedupe([f"usability_{usability_status}", *usability_flags])

        if usability_status == "strict_structured":
            strict = self.risk_classifier.strict_structured_assessment(row)
            strict_flags = _dedupe([str(flag) for flag in strict.get("flags", [])])
            if strict.get("ok") and not strict_flags:
                return _state(
                    "export_ready_structured",
                    "structured_html",
                    usability_status,
                    [],
                    _dedupe(["export_ready_structured", *base_flags]),
                    meta={"strict_structured": strict},
                    export_eligible=True,
                )
            status = (
                "export_blocked"
                if strict.get("validation_status") == "failed"
                else "export_candidate"
            )
            return _state(
                status,
                "candidate_preview" if status == "export_candidate" else "none",
                usability_status,
                _dedupe(strict_flags or ["strict_validator_not_ready"]),
                _dedupe(base_flags + strict_flags),
                meta={"strict_structured": strict},
                export_eligible=False,
            )

        if usability_status == "visual_fallback":
            visual = self.visual_inspector.inspect(row)
            visual_flags = _dedupe([str(flag) for flag in visual.get("flags", [])])
            blocking = _dedupe([str(flag) for flag in visual.get("blocking_reasons", [])])
            if visual.get("ok"):
                return _state(
                    "export_ready_visual",
                    "raw_crop_image",
                    usability_status,
                    [],
                    _dedupe(["export_ready_visual", *base_flags, *visual_flags]),
                    meta={"visual_quality": visual},
                    export_eligible=True,
                )
            return _state(
                "export_blocked" if _has_hard_visual_block(blocking) else "export_candidate",
                "none" if _has_hard_visual_block(blocking) else "candidate_preview",
                usability_status,
                blocking or visual_flags or ["visual_quality_not_ready"],
                _dedupe(base_flags + visual_flags),
                meta={"visual_quality": visual},
                export_eligible=False,
            )

        if usability_status in ("needs_recut", "failed", "protected", "unclassified"):
            reason = {
                "needs_recut": "usability_needs_recut",
                "failed": "usability_failed",
                "protected": "usability_protected",
            }.get(usability_status, "usability_unclassified")
            return _state(
                "export_blocked",
                "none",
                usability_status,
                [reason],
                _dedupe(base_flags + [reason]),
                meta={},
                export_eligible=False,
            )

        return _state(
            "export_candidate",
            "candidate_preview",
            usability_status,
            [f"usability_{usability_status}"],
            base_flags,
            meta={},
            export_eligible=False,
        )


def classify_export_quality_states(
    *,
    db_path: Path | None = None,
    project_root: Path = PROJECT_ROOT,
    limit: int | None = None,
) -> dict[str, Any]:
    return ExportQualityService(db_path=db_path, project_root=project_root).classify_all(
        limit=limit
    )


def summarize_export_quality(
    *,
    db_path: Path | None = None,
    conn=None,
    project_root: Path = PROJECT_ROOT,
) -> dict[str, Any]:
    if conn is None:
        with connect_database_read_only(db_path) as owned_conn:
            return summarize_export_quality(conn=owned_conn, project_root=project_root)

    question_count = int(conn.execute("SELECT count(*) FROM questions").fetchone()[0])
    quality_count = int(conn.execute("SELECT count(*) FROM question_export_quality").fetchone()[0])
    unclassified = int(
        conn.execute(
            """
            SELECT count(*)
              FROM questions q
              LEFT JOIN question_export_quality eq ON eq.question_id = q.id
             WHERE eq.question_id IS NULL
            """
        ).fetchone()[0]
    )
    status_counts = _distribution(conn, "export_quality_status")
    render_counts = _distribution(conn, "render_mode")
    ready_total = int(
        conn.execute(
            """
            SELECT count(*)
              FROM question_export_quality
             WHERE export_eligible = 1
               AND export_quality_status IN ('export_ready_structured', 'export_ready_visual')
            """
        ).fetchone()[0]
    )
    blocking_counts = _json_counter(conn, "blocking_reasons_json")
    quality_flag_counts = _json_counter(conn, "quality_flags_json")
    visual_downgrade_reasons = _visual_downgrade_reasons(conn)
    high_risk_pages = _high_risk_page_rows(conn)
    ready_structured_risk_hits = _ready_structured_risk_hits(conn, project_root=project_root)
    ready_visual_invalid = _ready_visual_invalid(conn, project_root=project_root)
    checksum = questions_main_checksum(conn)
    return {
        "question_count": question_count,
        "export_quality_count": quality_count,
        "unclassified": unclassified,
        "status_counts": status_counts,
        "render_counts": render_counts,
        "export_ready_total": ready_total,
        "blocking_reason_counts": blocking_counts,
        "quality_flag_counts": quality_flag_counts,
        "visual_downgrade_reasons": visual_downgrade_reasons,
        "high_risk_pages": high_risk_pages,
        "ready_structured_risk_hits": ready_structured_risk_hits,
        "ready_visual_invalid": ready_visual_invalid,
        "questions_checksum": checksum,
    }


def get_export_quality_by_question_ids(
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
              FROM question_export_quality
             WHERE question_id IN ({placeholders})
            """,
            unique_ids,
        ).fetchall()
    result = {int(row["question_id"]): dict(row) for row in rows}
    for row in result.values():
        row["blocking_reasons"] = parse_json_field(row.get("blocking_reasons_json"), [])
        row["quality_flags"] = parse_json_field(row.get("quality_flags_json"), [])
        row["meta"] = parse_json_field(row.get("meta_json"), {})
    return result


def attach_export_quality_states(
    questions: list[dict[str, Any]],
    export_quality_by_question_id: dict[int, dict[str, Any]],
) -> list[dict[str, Any]]:
    for question in questions:
        question["export_quality_state"] = export_quality_by_question_id.get(int(question["id"]))
    return questions


def write_stage12_export_quality_report(
    *,
    db_path: Path | None = None,
    project_root: Path = PROJECT_ROOT,
) -> dict[str, Any]:
    service = ExportQualityService(db_path=db_path, project_root=project_root)
    classify_result = service.classify_all()
    summary = classify_result["summary"]
    report_path = project_root / "docs" / "stage12_export_quality_report.md"
    get_workspace_io().write_text_idempotent(
        report_path,
        _render_stage12_report(summary),
    )
    return {
        "status": "ok",
        "relative_path": "docs/stage12_export_quality_report.md",
        "path": str(report_path),
        "classification_version": EXPORT_QUALITY_CLASSIFICATION_VERSION,
        "visual_inspector_version": VISUAL_INSPECTOR_VERSION,
        **summary,
    }


def _load_export_quality_rows(conn, *, limit: int | None) -> list[dict[str, Any]]:
    limit_sql = "LIMIT ?" if limit is not None else ""
    params: tuple[Any, ...] = (limit,) if limit is not None else ()
    rows = conn.execute(
        f"""
        SELECT sc.*,
               q.id AS question_id,
               q.qid,
               q.question_no,
               q.question_type,
               q.review_status,
               q.bbox_json AS question_bbox_json,
               q.page_range,
               CAST(json_extract(q.meta_json, '$.source_page') AS INTEGER) AS source_page,
               qa.relative_path AS raw_crop_path,
               qa.page_no AS raw_crop_page_no,
               qa.bbox_json AS raw_crop_bbox_json,
               qa.meta_json AS raw_crop_meta_json,
               spa.relative_path AS page_image_path,
               us.usability_status,
               us.render_mode AS usability_render_mode,
               us.primary_issue AS usability_primary_issue,
               us.issue_flags_json,
               us.export_eligible AS usability_export_eligible,
               COALESCE(ibp.duplicate_anchor_count, 0) AS duplicate_anchor_count,
               COALESCE(ibp.warning_candidates, 0) AS warning_candidates,
               COALESCE(ibp.page_flags_json, '[]') AS page_flags_json,
               COALESCE(iso.duplicate_anchor_count, 0) AS isolation_duplicate_anchor_count,
               COALESCE(iso.status, '') AS isolation_status
          FROM question_structured_contents sc
          JOIN questions q ON q.id = sc.question_id
          LEFT JOIN question_usability_states us ON us.question_id = q.id
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
         {limit_sql}
        """,
        params,
    ).fetchall()
    return [dict(row) for row in rows]


def _state(
    export_quality_status: str,
    render_mode: str,
    source_usability_status: str,
    blocking_reasons: list[str],
    quality_flags: list[str],
    *,
    meta: dict[str, Any],
    export_eligible: bool,
) -> dict[str, Any]:
    if export_quality_status not in EXPORT_QUALITY_STATUSES:
        raise ValueError(f"Unsupported export_quality_status: {export_quality_status}")
    if render_mode not in EXPORT_RENDER_MODES:
        raise ValueError(f"Unsupported render_mode: {render_mode}")
    return {
        "export_quality_status": export_quality_status,
        "render_mode": render_mode,
        "source_usability_status": source_usability_status,
        "blocking_reasons": _dedupe(blocking_reasons),
        "quality_flags": _dedupe(quality_flags),
        "export_eligible": bool(export_eligible),
        "classification_version": EXPORT_QUALITY_CLASSIFICATION_VERSION,
        "meta": meta,
    }


def _has_hard_visual_block(blocking: list[str]) -> bool:
    return any(
        flag
        in {
            "visual_missing_raw_crop",
            "visual_raw_crop_path_not_relative",
            "visual_raw_crop_outside_project",
            "visual_raw_crop_file_missing",
            "visual_raw_crop_file_empty",
            "visual_image_unreadable",
            "visual_image_empty_pixels",
            "visual_image_too_small",
            "visual_image_mostly_blank",
            "visual_image_low_contrast",
            "visual_high_risk_duplicate_anchor_page",
            "visual_duplicate_anchor_page_stats",
            "visual_duplicate_anchor_isolation",
        }
        for flag in blocking
    )


def _distribution(conn, field_name: str) -> dict[str, int]:
    rows = conn.execute(
        f"""
        SELECT {field_name} AS key, count(*) AS count
          FROM question_export_quality
         GROUP BY {field_name}
         ORDER BY {field_name}
        """
    ).fetchall()
    return {str(row["key"]): int(row["count"]) for row in rows}


def _json_counter(conn, field_name: str) -> dict[str, int]:
    rows = conn.execute(f"SELECT {field_name} AS value FROM question_export_quality").fetchall()
    counter: Counter[str] = Counter()
    for row in rows:
        values = parse_json_field(row["value"], [])
        if isinstance(values, list):
            counter.update(str(value) for value in values if value)
    return dict(counter.most_common(40))


def _visual_downgrade_reasons(conn) -> dict[str, int]:
    rows = conn.execute(
        """
        SELECT blocking_reasons_json, quality_flags_json
          FROM question_export_quality
         WHERE source_usability_status = 'visual_fallback'
           AND export_quality_status <> 'export_ready_visual'
        """
    ).fetchall()
    counter: Counter[str] = Counter()
    for row in rows:
        reasons = parse_json_field(row["blocking_reasons_json"], [])
        if not reasons:
            reasons = parse_json_field(row["quality_flags_json"], [])
        if isinstance(reasons, list):
            counter.update(str(reason) for reason in reasons if reason)
    return dict(counter.most_common(20))


def _high_risk_page_rows(conn) -> list[dict[str, Any]]:
    rows = conn.execute(
        f"""
        SELECT CAST(json_extract(q.meta_json, '$.source_page') AS INTEGER) AS page_no,
               eq.export_quality_status,
               count(*) AS count
          FROM question_export_quality eq
          JOIN questions q ON q.id = eq.question_id
         WHERE CAST(json_extract(q.meta_json, '$.source_page') AS INTEGER)
               IN ({", ".join("?" for _ in HIGH_RISK_PAGES)})
         GROUP BY page_no, eq.export_quality_status
         ORDER BY page_no, eq.export_quality_status
        """,
        HIGH_RISK_PAGES,
    ).fetchall()
    return [dict(row) for row in rows]


def _ready_structured_risk_hits(conn, *, project_root: Path) -> list[dict[str, Any]]:
    classifier = RiskClassifier(project_root=project_root)
    rows = [
        row
        for row in _load_export_quality_rows(conn, limit=None)
        if _quality_status(conn, int(row["question_id"])) == "export_ready_structured"
    ]
    hits: list[dict[str, Any]] = []
    for row in rows:
        strict = classifier.strict_structured_assessment(row)
        flags = list(strict.get("flags", []))
        if not strict.get("ok") or flags:
            hits.append(
                {
                    "question_id": int(row["question_id"]),
                    "qid": row.get("qid"),
                    "flags": flags,
                    "validation_status": strict.get("validation_status"),
                }
            )
    return hits


def _ready_visual_invalid(conn, *, project_root: Path) -> list[dict[str, Any]]:
    inspector = VisualQualityInspector(project_root=project_root)
    rows = [
        row
        for row in _load_export_quality_rows(conn, limit=None)
        if _quality_status(conn, int(row["question_id"])) == "export_ready_visual"
    ]
    invalid: list[dict[str, Any]] = []
    for row in rows:
        visual = inspector.inspect(row)
        if not visual["ok"]:
            invalid.append(
                {
                    "question_id": int(row["question_id"]),
                    "qid": row.get("qid"),
                    "blocking_reasons": visual["blocking_reasons"],
                    "flags": visual["flags"],
                }
            )
    return invalid


def _quality_status(conn, question_id: int) -> str | None:
    row = conn.execute(
        "SELECT export_quality_status FROM question_export_quality WHERE question_id = ?",
        (question_id,),
    ).fetchone()
    return str(row["export_quality_status"]) if row else None


def _json_list(value: str | None) -> list[str]:
    parsed = parse_json_field(value, [])
    if not isinstance(parsed, list):
        return []
    return [str(item) for item in parsed if item]


def _dedupe(values: list[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        if value and value not in result:
            result.append(value)
    return result


def _render_stage12_report(summary: dict[str, Any]) -> str:
    status_counts = summary["status_counts"]
    blocking_lines = "\n".join(
        f"- {reason}: {count}" for reason, count in summary["blocking_reason_counts"].items()
    ) or "- none"
    visual_lines = "\n".join(
        f"- {reason}: {count}" for reason, count in summary["visual_downgrade_reasons"].items()
    ) or "- none"
    high_risk_lines = "\n".join(
        f"| {row['page_no']} | {row['export_quality_status']} | {row['count']} |"
        for row in summary["high_risk_pages"]
    ) or "| - | - | - |"
    return f"""# 阶段 12 导出质量报告

生成时间：{_utc_now()}

## 总览

- questions 总数：{summary['question_count']}
- export quality rows：{summary['export_quality_count']}
- unclassified：{summary['unclassified']}
- questions 主表校验和：`{summary['questions_checksum']}`
- 分类版本：`{EXPORT_QUALITY_CLASSIFICATION_VERSION}`
- 视觉检测版本：`{VISUAL_INSPECTOR_VERSION}`
- 导出质量状态：{json.dumps(summary['status_counts'], ensure_ascii=False, sort_keys=True)}
- render_mode：{json.dumps(summary['render_counts'], ensure_ascii=False, sort_keys=True)}
- export_ready_structured：{int(status_counts.get('export_ready_structured', 0))}
- export_ready_visual：{int(status_counts.get('export_ready_visual', 0))}
- export_candidate：{int(status_counts.get('export_candidate', 0))}
- export_blocked：{int(status_counts.get('export_blocked', 0))}
- export_ready_total：{summary['export_ready_total']}

## 视觉降级原因 Top

{visual_lines}

## 阻塞原因 Top

{blocking_lines}

## 高风险页

| page | export_quality_status | count |
| --- | --- | ---: |
{high_risk_lines}

## 验证口径

- `export_ready_structured` 只来自 `strict_structured` 且重新通过当前 validator、风险命中为 0。
- `export_ready_visual` 只来自 `visual_fallback` 且题级图路径相对、存在、非空、可读取、尺寸/宽高比/空白率/对比度达标，并且 page/bbox 关联可信。
- `export_candidate`、`export_blocked`、`needs_recut`、`protected` 和 `failed` 不进入正式导出。
- duplicate_anchor 高风险页不得进入 ready。
- ready structured 风险命中：{len(summary['ready_structured_risk_hits'])}
- ready visual 失效：{len(summary['ready_visual_invalid'])}
"""


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
