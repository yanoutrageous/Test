from __future__ import annotations

import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .config import PROJECT_ROOT
from .database import connect_database, initialize_database
from .structured_ai import (
    StructuredAiError,
    get_structured_ai_provider_status,
    run_structured_ai_corrections,
)
from .structured_content import initialize_structured_contents, summarize_structured_contents
from .structured_validation import latex_basic_renderable, validate_structured_contents


REPORT_RELATIVE_PATH = Path("docs") / "stage9_quality_report.md"
HIGH_RISK_PAGES = (1098, 1100, 1128, 1148, 1168)
SAMPLE_TYPES = ("choice", "blank", "solution", "unknown")
FOCUS_QIDS = (
    "PDF-D02D0F16371FA96F-P1094-Q011",
    "PDF-D02D0F16371FA96F-P1094-Q012",
)
LATEX_QUALITY_FLAGS = {
    "latex_ambiguous_decimal_or_log",
    "latex_implicit_exponent_unconverted",
    "latex_unicode_math_symbol_unconverted",
}


def write_stage9_quality_report(
    *,
    db_path: Path | None = None,
    project_root: Path = PROJECT_ROOT,
    sample_size: int = 120,
    run_queue: bool = True,
) -> dict[str, Any]:
    initialize_database(db_path)
    init_result = initialize_structured_contents(db_path=db_path)

    with connect_database(db_path) as conn:
        sample_rows = _select_sample_rows(conn, sample_size=max(1, sample_size))
        sample_ids = tuple(int(row["question_id"]) for row in sample_rows)

    ai_result: dict[str, Any] = {
        "status": "not_run",
        "reason": "queue run disabled",
        "considered": 0,
        "updated_unavailable": 0,
        "drafted": 0,
        "provider_status": get_structured_ai_provider_status(project_root=project_root),
    }
    if run_queue and sample_ids:
        try:
            ai_result = run_structured_ai_corrections(
                db_path=db_path,
                question_ids=sample_ids,
                limit=len(sample_ids),
                project_root=project_root,
            )
            ai_result["provider_status"] = get_structured_ai_provider_status(
                project_root=project_root
            )
        except StructuredAiError as exc:
            ai_result = {
                "status": "error",
                "reason": str(exc),
                "considered": len(sample_ids),
                "updated_unavailable": 0,
                "drafted": 0,
                "provider_status": get_structured_ai_provider_status(
                    project_root=project_root
                ),
            }
    validation_result = validate_structured_contents(db_path=db_path, limit=sample_size)

    with connect_database(db_path) as conn:
        sample_rows = _load_sample_rows(conn, sample_ids)
        report_stats = _build_report_stats(conn, sample_rows, validation_result, ai_result)

    output_path = project_root / REPORT_RELATIVE_PATH
    output_path.parent.mkdir(parents=True, exist_ok=True)
    text = _render_report_v2(
        init_result=init_result,
        structured_summary=summarize_structured_contents(db_path=db_path),
        sample_rows=sample_rows,
        ai_result=ai_result,
        validation_result=validation_result,
        report_stats=report_stats,
    )
    output_path.write_text(text, encoding="utf-8")
    return {
        "relative_path": REPORT_RELATIVE_PATH.as_posix(),
        "path": str(output_path),
        "sample_count": len(sample_rows),
        "ai_provider_status": ai_result.get("status"),
        "ai_provider_config": ai_result.get("provider_status"),
        "ai_drafted": ai_result.get("drafted", 0),
        "validation": validation_result,
        "structured_init": init_result,
        "stats": report_stats,
    }


def _select_sample_rows(conn, *, sample_size: int) -> list[dict[str, Any]]:
    rows = _load_candidate_rows(conn)
    by_id = {int(row["question_id"]): row for row in rows}
    selected: dict[int, dict[str, Any]] = {}

    def add(row: dict[str, Any]) -> None:
        if len(selected) < sample_size:
            selected[int(row["question_id"])] = row

    for page_no in HIGH_RISK_PAGES:
        for row in rows:
            if int(row["source_page"] or 0) == page_no:
                add(row)
            if len(selected) >= sample_size:
                break

    per_type_target = max(1, sample_size // max(1, len(SAMPLE_TYPES)) // 2)
    for normalized_type in SAMPLE_TYPES:
        current = sum(
            1 for row in selected.values() if row["normalized_type"] == normalized_type
        )
        for row in rows:
            if current >= per_type_target or len(selected) >= sample_size:
                break
            if row["normalized_type"] == normalized_type and int(row["question_id"]) not in selected:
                add(row)
                current += 1

    for row in rows:
        if len(selected) >= sample_size:
            break
        if int(row["question_id"]) not in selected:
            add(row)

    return [by_id[question_id] for question_id in selected]


def _load_candidate_rows(conn) -> list[dict[str, Any]]:
    return [
        dict(row)
        for row in conn.execute(
            """
            SELECT q.id AS question_id,
                   q.qid,
                   q.question_no,
                   q.question_type,
                   q.review_status,
                   q.page_range,
                   CAST(json_extract(q.meta_json, '$.source_page') AS INTEGER) AS source_page,
                   sc.normalized_type,
                   sc.ai_status,
                   sc.stem_latex,
                   sc.source_latex,
                   sc.quality_flags_json,
                   sc.confidence
              FROM questions q
              JOIN question_structured_contents sc ON sc.question_id = q.id
             ORDER BY q.id
            """
        ).fetchall()
    ]


def _load_sample_rows(conn, sample_ids: tuple[int, ...]) -> list[dict[str, Any]]:
    if not sample_ids:
        return []
    placeholders = ", ".join("?" for _ in sample_ids)
    rows = conn.execute(
        f"""
        SELECT q.id AS question_id,
               q.qid,
               q.question_no,
               q.question_type,
               q.review_status,
               q.page_range,
               CAST(json_extract(q.meta_json, '$.source_page') AS INTEGER) AS source_page,
               sc.normalized_type,
               sc.ai_status,
               sc.stem_latex,
               sc.source_latex,
               sc.quality_flags_json,
               sc.confidence
          FROM questions q
          JOIN question_structured_contents sc ON sc.question_id = q.id
         WHERE q.id IN ({placeholders})
         ORDER BY q.id
        """,
        sample_ids,
    ).fetchall()
    by_id = {int(row["question_id"]): dict(row) for row in rows}
    return [by_id[question_id] for question_id in sample_ids if question_id in by_id]


def _build_report_stats(
    conn,
    sample_rows: list[dict[str, Any]],
    validation_result: dict[str, Any],
    ai_result: dict[str, Any],
) -> dict[str, Any]:
    sample_type_counts = Counter(row["normalized_type"] for row in sample_rows)
    sample_status_counts = Counter(row["ai_status"] for row in sample_rows)
    sample_page_counts = Counter(int(row["source_page"] or 0) for row in sample_rows)
    flag_counts = Counter()
    latex_pass = 0
    for row in sample_rows:
        flags = _safe_list(row["quality_flags_json"])
        flag_counts.update(str(flag) for flag in flags)
        if latex_basic_renderable(row["stem_latex"] or row["source_latex"] or ""):
            latex_pass += 1

    high_risk_rows = conn.execute(
        f"""
        SELECT page_no,
               max(candidate_count) AS candidate_count,
               max(db_question_count) AS db_question_count,
               max(warning_candidates) AS warning_candidates,
               max(duplicate_anchor_count) AS duplicate_anchor_count,
               max(page_flags_json) AS page_flags_json
          FROM import_batch_pages
         WHERE page_no IN ({", ".join("?" for _ in HIGH_RISK_PAGES)})
         GROUP BY page_no
         ORDER BY page_no
        """,
        HIGH_RISK_PAGES,
    ).fetchall()
    status_distribution = {
        row["ai_status"]: row["count"]
        for row in conn.execute(
            """
            SELECT ai_status, count(*) AS count
              FROM question_structured_contents
             GROUP BY ai_status
             ORDER BY ai_status
            """
        ).fetchall()
    }
    question_status_distribution = {
        row["review_status"]: row["count"]
        for row in conn.execute(
            """
            SELECT review_status, count(*) AS count
              FROM questions
             GROUP BY review_status
             ORDER BY review_status
            """
        ).fetchall()
    }
    counts = {
        "questions": conn.execute("SELECT count(*) FROM questions").fetchone()[0],
        "question_structured_contents": conn.execute(
            "SELECT count(*) FROM question_structured_contents"
        ).fetchone()[0],
        "question_assets": conn.execute("SELECT count(*) FROM question_assets").fetchone()[0],
        "source_paper_assets": conn.execute(
            "SELECT count(*) FROM source_paper_assets"
        ).fetchone()[0],
        "question_review_events": conn.execute(
            "SELECT count(*) FROM question_review_events"
        ).fetchone()[0],
        "question_ai_suggestions": conn.execute(
            "SELECT count(*) FROM question_ai_suggestions"
        ).fetchone()[0],
    }
    codex_agent_rows = conn.execute(
        """
        SELECT ai_status, count(*) AS count
          FROM question_structured_contents
         WHERE json_extract(model_info, '$.provider') = 'codex_agent'
         GROUP BY ai_status
         ORDER BY ai_status
        """
    ).fetchall()
    codex_batches = conn.execute(
        """
        SELECT COALESCE(json_extract(model_info, '$.batch_name'), '') AS batch_name,
               count(*) AS count
          FROM question_structured_contents
         WHERE json_extract(model_info, '$.provider') = 'codex_agent'
         GROUP BY batch_name
         ORDER BY batch_name
        """
    ).fetchall()
    structured_rows = conn.execute(
        """
        SELECT ai_status, quality_flags_json
          FROM question_structured_contents
        """
    ).fetchall()
    latex_quality_downgraded = 0
    latex_quality_flagged = 0
    for row in structured_rows:
        flags = {str(flag) for flag in _safe_list(row["quality_flags_json"])}
        if flags & LATEX_QUALITY_FLAGS:
            latex_quality_flagged += 1
            if row["ai_status"] == "needs_review":
                latex_quality_downgraded += 1
    focus_statuses = conn.execute(
        f"""
        SELECT q.qid,
               sc.ai_status,
               sc.normalized_type,
               sc.quality_flags_json
          FROM questions q
          JOIN question_structured_contents sc ON sc.question_id = q.id
         WHERE q.qid IN ({", ".join("?" for _ in FOCUS_QIDS)})
         ORDER BY q.qid
        """,
        FOCUS_QIDS,
    ).fetchall()
    return {
        "counts": counts,
        "structured_status_distribution": status_distribution,
        "question_status_distribution": question_status_distribution,
        "sample_type_counts": dict(sample_type_counts),
        "sample_status_counts": dict(sample_status_counts),
        "sample_page_counts": dict(sample_page_counts),
        "sample_high_risk_pages": {
            str(page): sample_page_counts.get(page, 0) for page in HIGH_RISK_PAGES
        },
        "quality_flag_counts": dict(flag_counts),
        "latex_basic_pass_count": latex_pass,
        "latex_basic_total": len(sample_rows),
        "high_risk_pages": [dict(row) for row in high_risk_rows],
        "validation_status_counts": validation_result.get("status_counts", {}),
        "ai_run_status": ai_result.get("status"),
        "ai_run_reason": ai_result.get("reason"),
        "codex_agent_status_distribution": {
            row["ai_status"]: row["count"] for row in codex_agent_rows
        },
        "codex_agent_batches": {row["batch_name"]: row["count"] for row in codex_batches},
        "processed_structured_count": counts["question_structured_contents"]
        - status_distribution.get("unprocessed", 0),
        "strict_usable_count": status_distribution.get("ai_verified", 0)
        + status_distribution.get("human_reviewed", 0),
        "latex_quality_flagged_count": latex_quality_flagged,
        "latex_quality_downgraded_count": latex_quality_downgraded,
        "focus_statuses": [dict(row) for row in focus_statuses],
    }


def _render_high_risk_pages(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return "- 暂无 import_batch_pages 高风险页记录。"
    lines = []
    for row in rows:
        lines.append(
            "- page {page_no}: candidates={candidate_count}, db_questions={db_question_count}, "
            "warnings={warning_candidates}, duplicate_anchors={duplicate_anchor_count}, flags={flags}".format(
                page_no=row["page_no"],
                candidate_count=row["candidate_count"],
                db_question_count=row["db_question_count"],
                warning_candidates=row["warning_candidates"],
                duplicate_anchor_count=row["duplicate_anchor_count"],
                flags=row["page_flags_json"],
            )
        )
    return "\n".join(lines)


def _render_focus_statuses(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return "- 未找到专项样例记录。"
    lines = []
    for row in rows:
        lines.append(
            "- {qid}: ai_status={status}, normalized_type={normalized_type}, flags={flags}".format(
                qid=row["qid"],
                status=row["ai_status"],
                normalized_type=row["normalized_type"],
                flags=row["quality_flags_json"],
            )
        )
    return "\n".join(lines)


def _safe_list(value: str | None) -> list[Any]:
    try:
        parsed = json.loads(value or "[]")
    except json.JSONDecodeError:
        return []
    return parsed if isinstance(parsed, list) else []


def _format_rate(numerator: int, denominator: int) -> str:
    if denominator <= 0:
        return "n/a"
    return f"{numerator}/{denominator} ({numerator / denominator:.2%})"


def _render_report_v2(
    *,
    init_result: dict[str, Any],
    structured_summary: dict[str, Any],
    sample_rows: list[dict[str, Any]],
    ai_result: dict[str, Any],
    validation_result: dict[str, Any],
    report_stats: dict[str, Any],
) -> str:
    generated_at = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    latex_rate = _format_rate(
        report_stats["latex_basic_pass_count"],
        report_stats["latex_basic_total"],
    )
    verified_count = structured_summary["status_distribution"].get("ai_verified", 0)
    human_count = structured_summary["status_distribution"].get("human_reviewed", 0)
    usable_count = verified_count + human_count
    usable_rate = _format_rate(usable_count, structured_summary["total_structured"])
    sample_ids_preview = ", ".join(row["qid"] for row in sample_rows[:20])
    if len(sample_rows) > 20:
        sample_ids_preview += ", ..."

    provider_status = ai_result.get("status")
    codex_agent_total = sum(report_stats["codex_agent_status_distribution"].values())
    if provider_status == "skipped":
        provider_text = "无真实配置，未调用 AI provider"
    elif provider_status == "not_run":
        provider_text = "未运行外部 provider 队列"
    elif provider_status == "error":
        provider_text = f"配置或调用失败：{ai_result.get('reason', '')}"
    elif ai_result.get("drafted", 0):
        provider_text = f"已产生 AI 草稿 {ai_result.get('drafted')}"
    else:
        provider_text = str(provider_status)
    codex_text = (
        f"Codex 代理已写入结构化副本 {codex_agent_total} 条"
        if codex_agent_total
        else "Codex 代理尚未写入真实库结构化副本"
    )
    if codex_agent_total:
        judgement = (
            "- 当前已完成结构化表、AI provider 抽象、无配置真实库保护、程序化校验器、Web 详情/预览/导出接入，以及 Codex 代理式 JSONL 校正闭环。\n"
            "- Codex 代理只写入 `question_structured_contents`，不覆盖 `questions` 主表；高风险、缺图、公式不确定、选项异常和未可靠 LaTeX 化内容会进入 `needs_review`。\n"
            "- Web 详情、组卷预览和 HTML 导出已接入本地数学呈现脚本；数据库仍只存 LaTeX 源。\n"
            "- 不建议自动全量覆盖或进入全卷扩容；建议先人工复核 `needs_review` 与高风险页，再决定是否扩大样本。"
        )
    else:
        judgement = (
            "- 当前已完成结构化表、AI provider 抽象、mock 临时库验证、无配置真实库保护、程序化校验器、Web 详情/预览/导出接入。\n"
            "- 已补充本地 OpenAI-compatible provider 路径；provider URL 必须是 loopback，非本机地址会被拒绝。\n"
            "- 由于本机未配置可用真实 AI provider，真实库没有产生可验收的 AI 草稿，`ai_verified` 仍为 0；这不是内容质量通过，而是外部 AI 环节未接入。\n"
            "- 不建议进入自动批量 AI 覆盖或阶段 10 全面扩展；建议先接入可审计的本地或明确授权 AI provider，并在 120 题样本上人工抽查结构化结果后再扩大。"
        )

    return f"""# 阶段 9 质量报告

生成时间：{generated_at}

## 范围

- 阶段 9 目标：AI 题面结构化校正与 LaTeX 渲染闭环。
- 本轮不继续扩页，不处理全 1207 页，不覆盖 `questions.reviewed/approved` 主数据。
- 真实 AI provider 状态：{provider_text}
- Codex 代理状态：{codex_text}
- mock AI 仅在 pytest/临时库验证；真实库未写入 mock 草稿。

## 结构化模型覆盖

- questions 总数：{structured_summary['question_count']}
- question_structured_contents 总数：{structured_summary['total_structured']}
- 缺失结构化记录：{structured_summary['missing_structured']}
- 初始化本次新增：{init_result['inserted']}
- ai_status 分布：{json.dumps(structured_summary['status_distribution'], ensure_ascii=False)}
- normalized_type 分布：{json.dumps(structured_summary['type_distribution'], ensure_ascii=False)}
- 可直接用于结构化导出的状态占比（ai_verified + human_reviewed）：{usable_rate}

## 样本

- 代表性样本数量：{len(sample_rows)}
- 样本覆盖题型：{json.dumps(report_stats['sample_type_counts'], ensure_ascii=False)}
- 样本覆盖状态：{json.dumps(report_stats['sample_status_counts'], ensure_ascii=False)}
- 高风险页样本覆盖：{json.dumps(report_stats['sample_high_risk_pages'], ensure_ascii=False)}
- 样本前 20 个 qid：{sample_ids_preview}

## AI 队列

- provider：{ai_result.get('provider') or 'none'}
- 状态：{ai_result.get('status')}
- 原因：{ai_result.get('reason', '')}
- provider_config：{json.dumps(ai_result.get('provider_status', {}), ensure_ascii=False)}
- 本轮考虑样本：{ai_result.get('considered', 0)}
- 写入不可用标记：{ai_result.get('updated_unavailable', 0)}
- 写入 AI 草稿：{ai_result.get('drafted', 0)}

## Codex 代理校正

- Codex 代理写入总数：{codex_agent_total}
- Codex 代理状态分布：{json.dumps(report_stats['codex_agent_status_distribution'], ensure_ascii=False)}
- Codex 代理批次分布：{json.dumps(report_stats['codex_agent_batches'], ensure_ascii=False)}

## 自动质量验收

- 本轮校验草稿数：{validation_result.get('validated', 0)}
- 校验结果分布：{json.dumps(validation_result.get('status_counts', {}), ensure_ascii=False)}
- LaTeX 基础可渲染性（样本 stem_latex/source_latex 括号与定界符）：{latex_rate}
- 结构化通过率（真实库 ai_verified + human_reviewed / 全部结构化记录）：{usable_rate}
- 质量标记分布：{json.dumps(report_stats['quality_flag_counts'], ensure_ascii=False)}

## 严格可用口径

- 已结构化处理数（非 unprocessed）：{report_stats['processed_structured_count']}
- 严格可直接使用数（ai_verified + human_reviewed）：{report_stats['strict_usable_count']}
- LaTeX 质量风险标记数：{report_stats['latex_quality_flagged_count']}
- 因 LaTeX 质量风险降级为 needs_review 数：{report_stats['latex_quality_downgraded_count']}

## 专项样例状态

{_render_focus_statuses(report_stats['focus_statuses'])}

## 高风险页跟踪

{_render_high_risk_pages(report_stats['high_risk_pages'])}

## 资产与审计

- question_assets：{report_stats['counts']['question_assets']}
- source_paper_assets：{report_stats['counts']['source_paper_assets']}
- question_review_events：{report_stats['counts']['question_review_events']}
- question_ai_suggestions：{report_stats['counts']['question_ai_suggestions']}
- questions 状态分布：{json.dumps(report_stats['question_status_distribution'], ensure_ascii=False)}

## 判断

{judgement}
"""
