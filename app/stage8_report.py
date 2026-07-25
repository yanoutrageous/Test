from __future__ import annotations

import json
import sqlite3
import time
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

from .config import PROJECT_ROOT, get_project_paths
from .database import connect_database, initialize_database
from .safety.workspace_io import get_workspace_io


def _json_loads(value: str | None, default: Any) -> Any:
    try:
        return json.loads(value or "")
    except (TypeError, json.JSONDecodeError):
        return default


def _dir_size(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(item.stat().st_size for item in path.rglob("*") if item.is_file())


def _count_files(path: Path, pattern: str) -> int:
    if not path.exists():
        return 0
    return sum(1 for item in path.rglob(pattern) if item.is_file())


def _percent(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return round(numerator * 100 / denominator, 2)


def _measure_sql_performance(conn) -> list[dict[str, Any]]:
    checks: list[tuple[str, str, tuple[Any, ...]]] = [
        (
            "status_count",
            "SELECT review_status, count(*) FROM questions GROUP BY review_status",
            (),
        ),
        (
            "question_list_50",
            "SELECT id, qid FROM questions ORDER BY id LIMIT 50",
            (),
        ),
        (
            "fts_keyword_50",
            """
            SELECT q.id, q.qid
              FROM question_fts
              JOIN questions q ON q.id = question_fts.rowid
             WHERE question_fts MATCH ?
             LIMIT 50
            """,
            ("函数",),
        ),
    ]
    results: list[dict[str, Any]] = []
    for name, sql, params in checks:
        try:
            started = time.perf_counter()
            rows = conn.execute(sql, params).fetchall()
            duration_ms = max(0, int((time.perf_counter() - started) * 1000))
        except sqlite3.OperationalError as exc:
            results.append(
                {
                    "name": name,
                    "ok": False,
                    "duration_ms": None,
                    "rows": 0,
                    "error": str(exc),
                }
            )
        else:
            results.append(
                {
                    "name": name,
                    "ok": True,
                    "duration_ms": duration_ms,
                    "rows": len(rows),
                    "error": "",
                }
            )
    return results


def _measure_web_performance(
    *,
    db_path: Path,
    project_root: Path,
    latest_batch_id: int | None,
    sample_question_id: int | None,
) -> list[dict[str, Any]]:
    from .web import create_app

    paths = [
        "/questions?status=all&limit=50",
        "/batches",
        "/paper-basket",
    ]
    if latest_batch_id is not None:
        paths.append(f"/questions?status=all&batch_id={latest_batch_id}&issue_only=1&limit=50")
        paths.append(f"/batches/{latest_batch_id}")
    if sample_question_id is not None:
        paths.append(f"/questions/{sample_question_id}?status=all&limit=50")

    app = create_app(db_path=db_path, project_root=project_root)
    client = app.test_client()
    results: list[dict[str, Any]] = []
    for path in paths:
        started = time.perf_counter()
        response = client.get(path)
        duration_ms = max(0, int((time.perf_counter() - started) * 1000))
        body = response.get_data()
        results.append(
            {
                "path": path,
                "status_code": response.status_code,
                "duration_ms": duration_ms,
                "bytes": len(body),
            }
        )
    return results


def build_stage8_quality_report(
    *,
    db_path: Path | None = None,
    project_root: Path = PROJECT_ROOT,
) -> str:
    initialize_database(db_path)
    paths = get_project_paths(project_root)
    resolved_db_path = db_path or paths.db_path

    with connect_database(resolved_db_path) as conn:
        batches = [
            dict(row)
            for row in conn.execute(
                """
                SELECT *
                  FROM import_batches
                 ORDER BY id
                """
            ).fetchall()
        ]
        pages = [
            dict(row)
            for row in conn.execute(
                """
                SELECT p.*, b.name AS batch_name, b.batch_kind
                  FROM import_batch_pages p
                  JOIN import_batches b ON b.id = p.batch_id
                 ORDER BY b.id, p.page_no
                """
            ).fetchall()
        ]
        counts = {
            "source_papers": conn.execute("SELECT count(*) FROM source_papers").fetchone()[0],
            "source_paper_assets": conn.execute(
                "SELECT count(*) FROM source_paper_assets"
            ).fetchone()[0],
            "questions": conn.execute("SELECT count(*) FROM questions").fetchone()[0],
            "question_assets": conn.execute("SELECT count(*) FROM question_assets").fetchone()[0],
            "question_review_events": conn.execute(
                "SELECT count(*) FROM question_review_events"
            ).fetchone()[0],
            "question_ai_suggestions": conn.execute(
                "SELECT count(*) FROM question_ai_suggestions"
            ).fetchone()[0],
            "import_batches": len(batches),
            "import_batch_pages": len(pages),
        }
        status_distribution = {
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
        page_question_counts = {
            int(row["page_no"]): int(row["count"])
            for row in conn.execute(
                """
                SELECT CAST(json_extract(meta_json, '$.source_page') AS INTEGER) AS page_no,
                       count(*) AS count
                  FROM questions
                 GROUP BY page_no
                """
            ).fetchall()
            if row["page_no"] is not None
        }
        sample_question_row = conn.execute(
            "SELECT id FROM questions ORDER BY id LIMIT 1"
        ).fetchone()
        sample_question_id = int(sample_question_row["id"]) if sample_question_row else None
        latest_batch_id = int(batches[-1]["id"]) if batches else None
        sql_performance = _measure_sql_performance(conn)

    web_performance = _measure_web_performance(
        db_path=resolved_db_path,
        project_root=project_root,
        latest_batch_id=latest_batch_id,
        sample_question_id=sample_question_id,
    )

    flag_counter: Counter[str] = Counter()
    anomalous_pages: list[dict[str, Any]] = []
    duplicate_anchor_pages: list[dict[str, Any]] = []
    failed_pages: list[dict[str, Any]] = []
    for page in pages:
        flags = _json_loads(page["page_flags_json"], [])
        for flag in flags:
            flag_counter[str(flag)] += 1
        if flags or page["warning_candidates"] or page["duplicate_anchor_count"]:
            anomalous_pages.append(page)
        if page["duplicate_anchor_count"]:
            duplicate_anchor_pages.append(page)
        if page["status"] == "failed":
            failed_pages.append(page)

    distinct_pages = sorted({int(page["page_no"]) for page in pages})
    total_candidates = sum(int(page["candidate_count"]) for page in pages)
    total_db_questions_for_batch_pages = sum(
        page_question_counts.get(page_no, 0) for page_no in distinct_pages
    )
    total_warning_candidates = sum(int(page["warning_candidates"]) for page in pages)
    total_duplicate_anchors = sum(int(page["duplicate_anchor_count"]) for page in pages)
    anomalous_page_nos = {int(page["page_no"]) for page in anomalous_pages}
    flagged_question_estimate = sum(
        page_question_counts.get(page_no, 0) for page_no in anomalous_page_nos
    )
    pending_count = int(status_distribution.get("pending", 0))
    normal_pending_estimate = max(0, pending_count - flagged_question_estimate)
    manual_minutes_low = round((normal_pending_estimate * 45 + flagged_question_estimate * 120) / 60, 1)
    manual_minutes_high = round((normal_pending_estimate * 90 + flagged_question_estimate * 240) / 60, 1)
    total_duration_ms = sum(
        int(batch["duration_ms"]) for batch in batches if batch["duration_ms"] is not None
    )

    lines: list[str] = []
    lines.append("# 阶段 8 质量报告")
    lines.append("")
    lines.append(f"生成时间：{datetime.now().isoformat(timespec='seconds')}")
    lines.append("")
    lines.append("## 总览")
    lines.append("")
    lines.append(f"- 批次数：{counts['import_batches']}")
    lines.append(f"- 批次页记录数：{counts['import_batch_pages']}")
    lines.append(f"- 去重页数：{len(distinct_pages)}")
    lines.append(f"- 批次页扫描候选题数：{total_candidates}")
    lines.append(f"- 批次页当前入库题数：{total_db_questions_for_batch_pages}")
    lines.append(f"- warning 候选题数：{total_warning_candidates}")
    lines.append(f"- duplicate_anchor 总数：{total_duplicate_anchors}")
    lines.append(f"- 题库总题数：{counts['questions']}")
    lines.append(f"- 题级资产数：{counts['question_assets']}")
    lines.append(f"- 页面资产数：{counts['source_paper_assets']}")
    lines.append(f"- 复核审计事件数：{counts['question_review_events']}")
    lines.append(f"- AI 建议数：{counts['question_ai_suggestions']}")
    lines.append(f"- 状态分布：{json.dumps(status_distribution, ensure_ascii=False)}")
    lines.append("")
    lines.append("## 质量比例")
    lines.append("")
    lines.append(f"- 候选入库比例：{_percent(total_db_questions_for_batch_pages, total_candidates)}%")
    lines.append(f"- warning 候选比例：{_percent(total_warning_candidates, total_candidates)}%")
    lines.append(f"- duplicate_anchor 锚点/候选比例：{_percent(total_duplicate_anchors, total_candidates)}%")
    lines.append(f"- 异常页比例：{_percent(len(anomalous_pages), len(pages))}%")
    lines.append(f"- duplicate_anchor 页比例：{_percent(len(duplicate_anchor_pages), len(pages))}%")
    lines.append(f"- 估算需优先复核题数：{flagged_question_estimate}")
    lines.append("")
    lines.append("## 存储")
    lines.append("")
    lines.append(f"- SQLite 大小：{resolved_db_path.stat().st_size if resolved_db_path.exists() else 0} bytes")
    lines.append(f"- 页面 PNG 数：{_count_files(paths.paper_pages_dir, '*.png')}")
    lines.append(f"- 题级 PNG 数：{_count_files(paths.question_images_dir, '*.png')}")
    lines.append(f"- assets 目录大小：{_dir_size(paths.assets_dir)} bytes")
    lines.append(f"- exports HTML 数：{_count_files(paths.exports_dir, '*.html')}")
    lines.append("")
    lines.append("## 性能")
    lines.append("")
    lines.append(f"- 扩容批次端到端耗时合计：{total_duration_ms} ms")
    lines.append("- 当前历史批次只保存端到端 `duration_ms`；未回填 scan/import/split/crop 分段耗时。")
    lines.append("")
    lines.append("SQLite 轻量查询：")
    lines.append("")
    lines.append("| check | ok | rows | duration_ms | error |")
    lines.append("|---|---|---:|---:|---|")
    for item in sql_performance:
        duration = "" if item["duration_ms"] is None else item["duration_ms"]
        lines.append(
            f"| {item['name']} | {item['ok']} | {item['rows']} | {duration} | {item['error']} |"
        )
    lines.append("")
    lines.append("Flask test client 响应：")
    lines.append("")
    lines.append("| path | status | bytes | duration_ms |")
    lines.append("|---|---:|---:|---:|")
    for item in web_performance:
        lines.append(
            f"| `{item['path']}` | {item['status_code']} | {item['bytes']} | {item['duration_ms']} |"
        )
    lines.append("")
    lines.append("## 批次")
    lines.append("")
    lines.append("| id | name | kind | status | pages | duration_ms | backup |")
    lines.append("|---:|---|---|---|---:|---:|---|")
    for batch in batches:
        lines.append(
            "| {id} | {name} | {kind} | {status} | {pages} | {duration} | {backup} |".format(
                id=batch["id"],
                name=batch["name"],
                kind=batch["batch_kind"],
                status=batch["status"],
                pages=batch["page_count"],
                duration=batch["duration_ms"] if batch["duration_ms"] is not None else "",
                backup=batch["backup_path"] or "",
            )
        )
    lines.append("")
    lines.append("## 异常页")
    lines.append("")
    if anomalous_pages:
        lines.append("| batch | page | candidates | db_questions | warnings | duplicate_anchors | flags |")
        lines.append("|---|---:|---:|---:|---:|---:|---|")
        for page in anomalous_pages:
            flags = ", ".join(_json_loads(page["page_flags_json"], []))
            lines.append(
                f"| {page['batch_name']} | {page['page_no']} | {page['candidate_count']} | "
                f"{page['db_question_count']} | {page['warning_candidates']} | "
                f"{page['duplicate_anchor_count']} | {flags} |"
            )
    else:
        lines.append("未记录异常页。")
    lines.append("")
    lines.append("## 标记统计")
    lines.append("")
    if flag_counter:
        for flag, count in sorted(flag_counter.items()):
            lines.append(f"- {flag}: {count}")
    else:
        lines.append("- 暂无 page_flags。")
    lines.append("")
    lines.append("## 失败页")
    lines.append("")
    if failed_pages:
        for page in failed_pages:
            lines.append(f"- {page['batch_name']} page {page['page_no']}: {page['error_json']}")
    else:
        lines.append("暂无失败页。")
    lines.append("")
    lines.append("## 复核成本估算")
    lines.append("")
    lines.append(f"- 当前 pending 题数：{pending_count}")
    lines.append(f"- 异常页关联题数估算：{flagged_question_estimate}")
    lines.append(
        f"- 粗略人工复核耗时：{manual_minutes_low}~{manual_minutes_high} 分钟"
        "（普通题按 45~90 秒/题，异常页题按 2~4 分钟/题估算）。"
    )
    lines.append("")
    lines.append("## 风险判断")
    lines.append("")
    if duplicate_anchor_pages:
        lines.append(
            "- 已出现 duplicate_anchor 页，当前 qid 以页码和题号生成，重复题号候选可能合并为同一入库题，需要人工抽查。"
        )
    else:
        lines.append("- 当前批次未记录 duplicate_anchor 页。")
    if failed_pages:
        lines.append("- 存在失败页，进入下一阶段前应先定位错误并决定是否回滚或重跑。")
    else:
        lines.append("- 当前未记录失败页。")
    lines.append("- 阶段 8 不自动批准题目；所有自动切分结果仍应进入人工复核。")
    if duplicate_anchor_pages or _percent(total_warning_candidates, total_candidates) >= 5:
        lines.append(
            "- 不建议直接进入 300/500/全量扩容；建议先修正重复锚点合并策略，并优先人工抽查异常页后再决定下一轮样本。"
        )
    elif failed_pages:
        lines.append("- 不建议进入阶段 9，需先处理失败页。")
    else:
        lines.append("- 可考虑进入下一阶段，但仍应继续保留批次闸门和抽样复核。")
    lines.append("")
    return "\n".join(lines)


def write_stage8_quality_report(
    *,
    db_path: Path | None = None,
    project_root: Path = PROJECT_ROOT,
    output_path: Path | None = None,
) -> dict[str, Any]:
    report = build_stage8_quality_report(db_path=db_path, project_root=project_root)
    target = output_path or (project_root / "docs" / "stage8_quality_report.md")
    receipt = get_workspace_io().write_text_idempotent(target, report)
    return {
        "path": str(target),
        "relative_path": target.resolve().relative_to(project_root.resolve()).as_posix(),
        "size_bytes": receipt.size_bytes,
    }
