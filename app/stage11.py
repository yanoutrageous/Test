from __future__ import annotations

import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .config import PROJECT_ROOT
from .database import connect_database, initialize_database
from .risk_classifier import (
    EXPORT_USABLE_STATUSES,
    USABILITY_CLASSIFICATION_VERSION,
    RiskClassifier,
)
from .stage10 import HIGH_RISK_PAGES, questions_main_checksum
from .structured_content import initialize_structured_contents, parse_json_field


STAGE11_REPORT_RELATIVE_PATH = Path("docs") / "stage11_quality_report.md"


def classify_usability_states(
    *,
    db_path: Path | None = None,
    project_root: Path = PROJECT_ROOT,
    limit: int | None = None,
) -> dict[str, Any]:
    initialize_database(db_path)
    initialize_structured_contents(db_path=db_path)
    classifier = RiskClassifier(project_root=project_root)
    capped_limit = None if limit is None else max(1, min(limit, 10000))

    with connect_database(db_path) as conn:
        rows = _load_classification_rows(conn, limit=capped_limit)
        for row in rows:
            state = classifier.classify(row)
            conn.execute(
                """
                INSERT INTO question_usability_states (
                    question_id,
                    usability_status,
                    render_mode,
                    primary_issue,
                    issue_flags_json,
                    export_eligible,
                    classification_version,
                    classified_at,
                    meta_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?)
                ON CONFLICT(question_id) DO UPDATE SET
                    usability_status = excluded.usability_status,
                    render_mode = excluded.render_mode,
                    primary_issue = excluded.primary_issue,
                    issue_flags_json = excluded.issue_flags_json,
                    export_eligible = excluded.export_eligible,
                    classification_version = excluded.classification_version,
                    classified_at = excluded.classified_at,
                    meta_json = excluded.meta_json,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (
                    row["question_id"],
                    state["usability_status"],
                    state["render_mode"],
                    state["primary_issue"],
                    json.dumps(state["issue_flags"], ensure_ascii=False),
                    1 if state["export_eligible"] else 0,
                    state["classification_version"],
                    json.dumps(
                        {
                            **state["meta"],
                            "qid": row.get("qid"),
                            "source_page": row.get("source_page"),
                            "ai_status": row.get("ai_status"),
                            "normalized_type": row.get("normalized_type"),
                        },
                        ensure_ascii=False,
                    ),
                ),
            )
        conn.commit()
        summary = summarize_usability_states(conn=conn, project_root=project_root)

    return {
        "status": "ok",
        "classified": len(rows),
        "classification_version": USABILITY_CLASSIFICATION_VERSION,
        "summary": summary,
    }


def summarize_usability_states(
    *,
    db_path: Path | None = None,
    conn=None,
    project_root: Path = PROJECT_ROOT,
) -> dict[str, Any]:
    if conn is None:
        initialize_database(db_path)
        with connect_database(db_path) as owned_conn:
            return summarize_usability_states(conn=owned_conn, project_root=project_root)

    question_count = int(conn.execute("SELECT count(*) FROM questions").fetchone()[0])
    usability_count = int(
        conn.execute("SELECT count(*) FROM question_usability_states").fetchone()[0]
    )
    unclassified = int(
        conn.execute(
            """
            SELECT count(*)
              FROM questions q
              LEFT JOIN question_usability_states us ON us.question_id = q.id
             WHERE us.question_id IS NULL
            """
        ).fetchone()[0]
    )
    status_counts = _distribution(conn, "usability_status")
    render_counts = _distribution(conn, "render_mode")
    export_usable = int(
        conn.execute(
            """
            SELECT count(*)
              FROM question_usability_states
             WHERE export_eligible = 1
               AND usability_status IN ('strict_structured', 'visual_fallback')
            """
        ).fetchone()[0]
    )
    issue_counts = _issue_flag_counts(conn)
    queue_counts = _queue_counts(conn)
    high_risk_pages = _high_risk_page_rows(conn)
    strict_risk_hits = _strict_risk_hits(conn, project_root=project_root)
    visual_invalid = _visual_fallback_invalid(conn, project_root=project_root)
    checksum = questions_main_checksum(conn)
    return {
        "question_count": question_count,
        "usability_count": usability_count,
        "unclassified": unclassified,
        "status_counts": status_counts,
        "render_counts": render_counts,
        "export_usable": export_usable,
        "issue_counts": issue_counts,
        "queue_counts": queue_counts,
        "high_risk_pages": high_risk_pages,
        "strict_risk_hits": strict_risk_hits,
        "visual_fallback_invalid": visual_invalid,
        "questions_checksum": checksum,
    }


def get_usability_states_by_question_ids(
    question_ids: list[int],
    *,
    db_path: Path | None = None,
) -> dict[int, dict[str, Any]]:
    if not question_ids:
        return {}
    initialize_database(db_path)
    unique_ids = list(dict.fromkeys(int(value) for value in question_ids))
    placeholders = ", ".join("?" for _ in unique_ids)
    with connect_database(db_path) as conn:
        rows = conn.execute(
            f"""
            SELECT *
              FROM question_usability_states
             WHERE question_id IN ({placeholders})
            """,
            unique_ids,
        ).fetchall()
    result = {int(row["question_id"]): dict(row) for row in rows}
    for row in result.values():
        row["issue_flags"] = parse_json_field(row.get("issue_flags_json"), [])
        row["meta"] = parse_json_field(row.get("meta_json"), {})
    return result


def attach_usability_states(
    questions: list[dict[str, Any]],
    usability_by_question_id: dict[int, dict[str, Any]],
) -> list[dict[str, Any]]:
    for question in questions:
        question["usability_state"] = usability_by_question_id.get(int(question["id"]))
    return questions


def write_stage11_quality_report(
    *,
    db_path: Path | None = None,
    project_root: Path = PROJECT_ROOT,
) -> dict[str, Any]:
    classify_result = classify_usability_states(
        db_path=db_path,
        project_root=project_root,
    )
    summary = classify_result["summary"]
    report_path = project_root / STAGE11_REPORT_RELATIVE_PATH
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_text = _render_stage11_report(summary)
    report_path.write_text(report_text, encoding="utf-8")
    return {
        "status": "ok",
        "relative_path": STAGE11_REPORT_RELATIVE_PATH.as_posix(),
        "path": str(report_path),
        "classification_version": USABILITY_CLASSIFICATION_VERSION,
        **summary,
    }


def _load_classification_rows(conn, *, limit: int | None) -> list[dict[str, Any]]:
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
               COALESCE(ibp.duplicate_anchor_count, 0) AS duplicate_anchor_count,
               COALESCE(ibp.warning_candidates, 0) AS warning_candidates,
               COALESCE(ibp.page_flags_json, '[]') AS page_flags_json,
               COALESCE(iso.duplicate_anchor_count, 0) AS isolation_duplicate_anchor_count,
               COALESCE(iso.status, '') AS isolation_status
          FROM question_structured_contents sc
          JOIN questions q ON q.id = sc.question_id
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


def _distribution(conn, field_name: str) -> dict[str, int]:
    rows = conn.execute(
        f"""
        SELECT {field_name} AS key, count(*) AS count
          FROM question_usability_states
         GROUP BY {field_name}
         ORDER BY {field_name}
        """
    ).fetchall()
    return {str(row["key"]): int(row["count"]) for row in rows}


def _issue_flag_counts(conn) -> dict[str, int]:
    rows = conn.execute("SELECT issue_flags_json FROM question_usability_states").fetchall()
    counter: Counter[str] = Counter()
    for row in rows:
        flags = parse_json_field(row["issue_flags_json"], [])
        if isinstance(flags, list):
            counter.update(str(flag) for flag in flags if flag)
    return dict(counter.most_common(40))


def _queue_counts(conn) -> dict[str, int]:
    rows = conn.execute(
        """
        SELECT usability_status, issue_flags_json
          FROM question_usability_states
        """
    ).fetchall()
    counters = {
        "formula": 0,
        "blank": 0,
        "piecewise": 0,
        "visual_dependency": 0,
        "unknown_type": 0,
        "recut_duplicate_anchor": 0,
        "failed": 0,
    }
    for row in rows:
        flags = parse_json_field(row["issue_flags_json"], [])
        if not isinstance(flags, list):
            flags = []
        flags = [str(flag) for flag in flags]
        if any(flag.startswith("latex_") or flag.startswith("formula_") for flag in flags):
            counters["formula"] += 1
        if any("blank" in flag for flag in flags):
            counters["blank"] += 1
        if any("piecewise" in flag or "private_use" in flag for flag in flags):
            counters["piecewise"] += 1
        if any("visual" in flag or "image" in flag or flag.startswith("referenced_") for flag in flags):
            counters["visual_dependency"] += 1
        if "type_review_queue" in flags or "unknown_question_type" in flags:
            counters["unknown_type"] += 1
        if "duplicate_anchor_needs_recut" in flags or "stage10_high_risk_page" in flags:
            counters["recut_duplicate_anchor"] += 1
        if row["usability_status"] == "failed" or "structured_failed_without_visual_fallback" in flags:
            counters["failed"] += 1
    return counters


def _high_risk_page_rows(conn) -> list[dict[str, Any]]:
    rows = conn.execute(
        f"""
        SELECT CAST(json_extract(q.meta_json, '$.source_page') AS INTEGER) AS page_no,
               us.usability_status,
               count(*) AS count
          FROM question_usability_states us
          JOIN questions q ON q.id = us.question_id
         WHERE CAST(json_extract(q.meta_json, '$.source_page') AS INTEGER)
               IN ({", ".join("?" for _ in HIGH_RISK_PAGES)})
         GROUP BY page_no, us.usability_status
         ORDER BY page_no, us.usability_status
        """,
        HIGH_RISK_PAGES,
    ).fetchall()
    return [dict(row) for row in rows]


def _strict_risk_hits(conn, *, project_root: Path) -> list[dict[str, Any]]:
    classifier = RiskClassifier(project_root=project_root)
    rows = [
        row
        for row in _load_classification_rows(conn, limit=None)
        if _state_status(conn, int(row["question_id"])) == "strict_structured"
    ]
    hits: list[dict[str, Any]] = []
    for row in rows:
        strict = classifier.strict_structured_assessment(row)
        if not strict["ok"] or strict["flags"]:
            hits.append(
                {
                    "question_id": int(row["question_id"]),
                    "qid": row.get("qid"),
                    "flags": strict["flags"],
                    "validation_status": strict.get("validation_status"),
                }
            )
    return hits


def _visual_fallback_invalid(conn, *, project_root: Path) -> list[dict[str, Any]]:
    classifier = RiskClassifier(project_root=project_root)
    rows = [
        row
        for row in _load_classification_rows(conn, limit=None)
        if _state_status(conn, int(row["question_id"])) == "visual_fallback"
    ]
    invalid: list[dict[str, Any]] = []
    for row in rows:
        visual = classifier.visual_fallback_assessment(row)
        if not visual["ok"]:
            invalid.append(
                {
                    "question_id": int(row["question_id"]),
                    "qid": row.get("qid"),
                    "flags": visual["flags"],
                }
            )
    return invalid


def _state_status(conn, question_id: int) -> str | None:
    row = conn.execute(
        "SELECT usability_status FROM question_usability_states WHERE question_id = ?",
        (question_id,),
    ).fetchone()
    return str(row["usability_status"]) if row else None


def _render_stage11_report(summary: dict[str, Any]) -> str:
    status_counts = summary["status_counts"]
    needs_total = sum(
        int(status_counts.get(status, 0))
        for status in (
            "needs_formula_repair",
            "needs_blank_repair",
            "needs_type_review",
            "needs_recut",
        )
    )
    issue_lines = "\n".join(
        f"- {flag}: {count}" for flag, count in summary["issue_counts"].items()
    ) or "- none"
    high_risk_lines = "\n".join(
        f"| {row['page_no']} | {row['usability_status']} | {row['count']} |"
        for row in summary["high_risk_pages"]
    ) or "| - | - | - |"
    return f"""# 阶段 11 质量报告

生成时间：{_utc_now()}

## 总览

- questions 总数：{summary['question_count']}
- usability rows：{summary['usability_count']}
- unclassified：{summary['unclassified']}
- questions 主表校验和：`{summary['questions_checksum']}`
- 分类版本：`{USABILITY_CLASSIFICATION_VERSION}`
- 可用性状态：{json.dumps(summary['status_counts'], ensure_ascii=False, sort_keys=True)}
- render_mode：{json.dumps(summary['render_counts'], ensure_ascii=False, sort_keys=True)}
- export_usable：{summary['export_usable']}
- strict_structured：{int(status_counts.get('strict_structured', 0))}
- visual_fallback：{int(status_counts.get('visual_fallback', 0))}
- needs_* 合计：{needs_total}
- failed：{int(status_counts.get('failed', 0))}
- protected：{int(status_counts.get('protected', 0))}

## 专项队列

- 公式：{summary['queue_counts']['formula']}
- 填空：{summary['queue_counts']['blank']}
- 分段函数/私有区符号：{summary['queue_counts']['piecewise']}
- 图表/视觉依赖：{summary['queue_counts']['visual_dependency']}
- unknown 题型：{summary['queue_counts']['unknown_type']}
- 重切/重复锚点：{summary['queue_counts']['recut_duplicate_anchor']}
- 失败：{summary['queue_counts']['failed']}

## 高风险页

| page | usability_status | count |
| --- | --- | ---: |
{high_risk_lines}

## 主要 flags

{issue_lines}

## 验证口径

- `strict_structured` 只来自当前 `ai_verified` 或 `human_reviewed` 且重新通过 validator 的结构化候选。
- `visual_fallback` 不改变 `ai_status`，只表示题级裁切图存在、非空、路径相对，并且页码与 bbox 关联可信。
- `needs_*` 和 `failed` 默认不进入正式导出；正式导出只选择 `strict_structured` 与 `visual_fallback`。
- duplicate_anchor 高风险页进入 `needs_recut`，不得静默作为正式可用题进入导出。
- strict 风险命中：{len(summary['strict_risk_hits'])}
- visual_fallback 资产失效：{len(summary['visual_fallback_invalid'])}
"""


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
