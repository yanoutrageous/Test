from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import PROJECT_ROOT
from .database import connect_database, connect_database_read_only, initialize_database
from .safety.workspace_io import get_workspace_io


SOURCE_ATTRIBUTION_VERSION = "source_attribution_v2"
COLLECTION_TITLE_PATTERNS = ("全编", "汇编", "合集", "真题全编")
REPORT_RELATIVE_PATH = Path("docs/stage13_source_attribution_report.md")


@dataclass(frozen=True)
class SourceHeader:
    year: int | None
    paper_name: str
    region: str | None
    stream: str | None
    raw_text: str


@dataclass(frozen=True)
class HeaderResolution:
    header: SourceHeader
    confidence: str
    flags: tuple[str, ...]


class SourceAttributionService:
    """Build per-question source labels without mutating the questions table."""

    def __init__(
        self,
        *,
        db_path: Path | None = None,
        project_root: Path = PROJECT_ROOT,
    ) -> None:
        self.db_path = db_path
        self.project_root = project_root

    def ensure_source_attributions(self) -> dict[str, Any]:
        initialize_database(self.db_path)
        with connect_database_read_only(self.db_path) as conn:
            question_count = int(conn.execute("SELECT count(*) FROM questions").fetchone()[0])
            attribution_count = int(
                conn.execute("SELECT count(*) FROM question_source_attributions").fetchone()[0]
            )
            stale_count = int(
                conn.execute(
                    """
                    SELECT count(*)
                      FROM question_source_attributions
                     WHERE attribution_version <> ?
                    """,
                    (SOURCE_ATTRIBUTION_VERSION,),
                ).fetchone()[0]
            )
            missing_count = int(
                conn.execute(
                    """
                    SELECT count(*)
                      FROM questions q
                      LEFT JOIN question_source_attributions sa ON sa.question_id = q.id
                     WHERE sa.question_id IS NULL
                    """
                ).fetchone()[0]
            )
        if question_count and (
            attribution_count != question_count or stale_count or missing_count
        ):
            return self.rebuild()
        return {
            "status": "ok",
            "processed": 0,
            "inserted": 0,
            "updated": 0,
            "attribution_version": SOURCE_ATTRIBUTION_VERSION,
            "summary": self.summarize(),
        }

    def rebuild(
        self,
        *,
        limit: int | None = None,
        write_report: bool = True,
    ) -> dict[str, Any]:
        initialize_database(self.db_path)
        capped_limit = None if limit is None else max(1, min(int(limit), 100000))

        with connect_database(self.db_path) as conn:
            query = """
                SELECT q.id AS question_id,
                       q.qid,
                       q.year,
                       q.paper_name,
                       q.region,
                       q.stream,
                       q.question_no,
                       CAST(json_extract(q.meta_json, '$.source_page') AS INTEGER) AS source_page,
                       sp.id AS source_paper_id,
                       sp.title AS source_title,
                       sp.source_path
                  FROM questions q
                  JOIN source_papers sp ON sp.id = q.source_paper_id
                 ORDER BY q.id
            """
            params: list[Any] = []
            if capped_limit is not None:
                query += " LIMIT ?"
                params.append(capped_limit)
            rows = conn.execute(query, params).fetchall()

            headers = _load_headers_for_rows(rows, project_root=self.project_root)
            inserted = 0
            updated = 0
            for row in rows:
                attribution = build_source_attribution(dict(row), headers=headers)
                existing = conn.execute(
                    """
                    SELECT id
                      FROM question_source_attributions
                     WHERE question_id = ?
                    """,
                    (attribution["question_id"],),
                ).fetchone()
                conn.execute(
                    """
                    INSERT INTO question_source_attributions (
                        question_id,
                        source_year,
                        source_paper_name,
                        source_region,
                        source_stream,
                        source_question_no,
                        source_page,
                        source_label,
                        confidence,
                        attribution_flags_json,
                        source_text,
                        attribution_version,
                        updated_at
                    ) VALUES (
                        :question_id,
                        :source_year,
                        :source_paper_name,
                        :source_region,
                        :source_stream,
                        :source_question_no,
                        :source_page,
                        :source_label,
                        :confidence,
                        :attribution_flags_json,
                        :source_text,
                        :attribution_version,
                        CURRENT_TIMESTAMP
                    )
                    ON CONFLICT(question_id) DO UPDATE SET
                        source_year = excluded.source_year,
                        source_paper_name = excluded.source_paper_name,
                        source_region = excluded.source_region,
                        source_stream = excluded.source_stream,
                        source_question_no = excluded.source_question_no,
                        source_page = excluded.source_page,
                        source_label = excluded.source_label,
                        confidence = excluded.confidence,
                        attribution_flags_json = excluded.attribution_flags_json,
                        source_text = excluded.source_text,
                        attribution_version = excluded.attribution_version,
                        updated_at = CURRENT_TIMESTAMP
                    """,
                    attribution,
                )
                if existing is None:
                    inserted += 1
                else:
                    updated += 1
            conn.commit()

        summary = self.summarize()
        result: dict[str, Any] = {
            "status": "ok",
            "processed": len(rows),
            "inserted": inserted,
            "updated": updated,
            "attribution_version": SOURCE_ATTRIBUTION_VERSION,
            "summary": summary,
        }
        if write_report:
            report = self.write_report(summary=summary)
            result["report_path"] = report["path"]
            result["report_relative_path"] = report["relative_path"]
        return result

    def summarize(self) -> dict[str, Any]:
        with connect_database_read_only(self.db_path) as conn:
            question_count = int(conn.execute("SELECT count(*) FROM questions").fetchone()[0])
            attribution_count = int(
                conn.execute("SELECT count(*) FROM question_source_attributions").fetchone()[0]
            )
            confidence_distribution = {
                row["confidence"]: int(row["count"])
                for row in conn.execute(
                    """
                    SELECT confidence, count(*) AS count
                      FROM question_source_attributions
                     GROUP BY confidence
                     ORDER BY confidence
                    """
                ).fetchall()
            }
            year_distribution = {
                str(row["source_year"]): int(row["count"])
                for row in conn.execute(
                    """
                    SELECT source_year, count(*) AS count
                      FROM question_source_attributions
                     WHERE source_year IS NOT NULL
                     GROUP BY source_year
                     ORDER BY source_year
                    """
                ).fetchall()
            }
            flag_distribution = _flag_distribution(conn)
            missing_rows = [
                dict(row)
                for row in conn.execute(
                    """
                    SELECT q.id, q.qid
                      FROM questions q
                      LEFT JOIN question_source_attributions sa ON sa.question_id = q.id
                     WHERE sa.question_id IS NULL
                     ORDER BY q.id
                     LIMIT 20
                    """
                ).fetchall()
            ]
            missing_count = int(
                conn.execute(
                    """
                    SELECT count(*)
                      FROM questions q
                      LEFT JOIN question_source_attributions sa ON sa.question_id = q.id
                     WHERE sa.question_id IS NULL
                    """
                ).fetchone()[0]
            )
            orphan_rows = [
                dict(row)
                for row in conn.execute(
                    """
                    SELECT sa.id, sa.question_id, sa.source_label
                      FROM question_source_attributions sa
                      LEFT JOIN questions q ON q.id = sa.question_id
                     WHERE q.id IS NULL
                     ORDER BY sa.id
                     LIMIT 20
                    """
                ).fetchall()
            ]
            orphan_count = int(
                conn.execute(
                    """
                    SELECT count(*)
                      FROM question_source_attributions sa
                      LEFT JOIN questions q ON q.id = sa.question_id
                     WHERE q.id IS NULL
                    """
                ).fetchone()[0]
            )
            sample_rows = [
                dict(row)
                for row in conn.execute(
                    """
                    SELECT q.qid,
                           sa.source_label,
                           sa.confidence,
                           sa.source_page,
                           sa.source_text,
                           sa.attribution_flags_json
                      FROM question_source_attributions sa
                      JOIN questions q ON q.id = sa.question_id
                     ORDER BY
                           CASE sa.confidence
                               WHEN 'exact' THEN 0
                               WHEN 'inferred' THEN 1
                               ELSE 2
                           END,
                           q.id
                     LIMIT 8
                    """
                ).fetchall()
            ]
            samples_by_confidence = {
                confidence: [
                    dict(row)
                    for row in conn.execute(
                        """
                        SELECT q.qid,
                               sa.source_label,
                               sa.confidence,
                               sa.source_page,
                               sa.source_text,
                               sa.attribution_flags_json
                          FROM question_source_attributions sa
                          JOIN questions q ON q.id = sa.question_id
                         WHERE sa.confidence = ?
                         ORDER BY q.id
                         LIMIT 5
                        """,
                        (confidence,),
                    ).fetchall()
                ]
                for confidence in ("exact", "inferred", "unknown")
            }

        confidence_distribution = {
            key: int(confidence_distribution.get(key, 0))
            for key in ("exact", "inferred", "unknown")
        }
        fallback_flags = {
            key: value
            for key, value in flag_distribution.items()
            if "fallback" in key
            or "missing" in key
            or "unknown" in key
            or "inferred" in key
            or "suppressed" in key
        }
        return {
            "question_count": question_count,
            "attribution_count": attribution_count,
            "total": attribution_count,
            "exact": confidence_distribution["exact"],
            "inferred": confidence_distribution["inferred"],
            "unknown": confidence_distribution["unknown"],
            "missing": missing_count,
            "orphan_count": orphan_count,
            "confidence_distribution": confidence_distribution,
            "year_distribution": year_distribution,
            "flag_distribution": flag_distribution,
            "fallback_flags": fallback_flags,
            "missing_sample": missing_rows,
            "orphan_sample": orphan_rows,
            "samples": sample_rows,
            "samples_by_confidence": samples_by_confidence,
            "attribution_version": SOURCE_ATTRIBUTION_VERSION,
        }

    def write_report(self, *, summary: dict[str, Any] | None = None) -> dict[str, Any]:
        summary = summary or self.summarize()
        report_path = self.project_root / REPORT_RELATIVE_PATH
        receipt = get_workspace_io().write_text_idempotent(
            report_path,
            _render_report_markdown(summary),
        )
        return {
            "status": "ok",
            "path": str(report_path),
            "relative_path": str(REPORT_RELATIVE_PATH).replace("\\", "/"),
            "size_bytes": receipt.size_bytes,
        }


def rebuild_source_attributions(
    *,
    db_path: Path | None = None,
    project_root: Path = PROJECT_ROOT,
    limit: int | None = None,
) -> dict[str, Any]:
    return SourceAttributionService(
        db_path=db_path,
        project_root=project_root,
    ).rebuild(limit=limit)


def summarize_source_attributions(*, db_path: Path | None = None) -> dict[str, Any]:
    return SourceAttributionService(db_path=db_path).summarize()


def write_stage13_source_attribution_report(
    *,
    db_path: Path | None = None,
    project_root: Path = PROJECT_ROOT,
) -> dict[str, Any]:
    return SourceAttributionService(
        db_path=db_path,
        project_root=project_root,
    ).write_report()


def build_source_attribution(
    row: dict[str, Any],
    *,
    headers: dict[tuple[int, int], HeaderResolution],
) -> dict[str, Any]:
    source_page = _optional_int(row.get("source_page"))
    question_no = _clean(row.get("question_no"))
    resolution = None
    if source_page is not None:
        resolution = headers.get((int(row["source_paper_id"]), source_page))

    source_title = _clean(row.get("source_title"))
    question_paper_name = _clean(row.get("paper_name"))
    fallback_paper_name = question_paper_name or source_title
    source_year = _optional_int(row.get("year"))
    source_paper_name = fallback_paper_name or None
    source_region = _clean(row.get("region"))
    source_stream = _clean(row.get("stream"))
    source_text = None
    flags: list[str] = []

    has_collection_title = _looks_like_collection(source_title) or _looks_like_collection(
        question_paper_name
    )
    if has_collection_title:
        flags.append("compiled_source_pdf")

    if resolution:
        header = resolution.header
        source_year = header.year
        source_paper_name = header.paper_name
        source_region = header.region
        source_stream = header.stream
        source_text = header.raw_text
        flags.extend(resolution.flags)
    else:
        flags.append("source_header_missing")
        if source_paper_name and _looks_like_collection(source_paper_name):
            source_paper_name = None
            flags.append("compiled_source_name_suppressed")

    if source_year is None:
        flags.append("missing_source_year")
    if not source_paper_name:
        flags.append("missing_source_paper_name")
    if not question_no:
        flags.append("missing_source_question_no")
    else:
        flags.append("source_question_no_traced")
    if source_page is not None:
        flags.append("source_page_traced")

    if (
        resolution
        and resolution.confidence == "exact"
        and source_year
        and source_paper_name
        and question_no
    ):
        confidence = "exact"
        source_label = f"{source_year} {source_paper_name} 第{question_no}题"
    elif resolution and source_paper_name and question_no and source_page is not None:
        confidence = "inferred"
        flags.append("source_label_inferred_from_header_context")
        year_prefix = f"{source_year} " if source_year else ""
        source_label = (
            f"{year_prefix}{source_paper_name} / p{source_page:04d} / 题号 {question_no}"
        )
    elif source_paper_name and question_no and source_page is not None:
        confidence = "inferred"
        flags.append("source_label_fallback_page")
        year_prefix = f"{source_year} " if source_year else ""
        source_label = (
            f"{year_prefix}{source_paper_name} / p{source_page:04d} / 题号 {question_no}"
        )
    else:
        confidence = "unknown"
        flags.append("source_label_incomplete")
        page_part = f" / p{source_page:04d}" if source_page is not None else ""
        question_part = f" / 题号 {question_no}" if question_no else ""
        source_label = f"未知原始卷{page_part}{question_part} / {row['qid']}"

    return {
        "question_id": int(row["question_id"]),
        "source_year": source_year,
        "source_paper_name": source_paper_name or None,
        "source_region": source_region or None,
        "source_stream": source_stream or None,
        "source_question_no": question_no or None,
        "source_page": source_page,
        "source_label": source_label,
        "confidence": confidence,
        "attribution_flags_json": json.dumps(sorted(set(flags)), ensure_ascii=False),
        "source_text": source_text,
        "attribution_version": SOURCE_ATTRIBUTION_VERSION,
    }


def parse_source_header_line(line: str) -> SourceHeader | None:
    cleaned = " ".join(str(line or "").strip().split())
    match = re.match(r"^(?P<year>(?:19|20)\d{2})\s*(?P<title>.+)$", cleaned)
    if not match:
        return None
    year = int(match.group("year"))
    title = match.group("title").strip()
    if not title:
        return None
    return SourceHeader(
        year=year,
        paper_name=title,
        region=_infer_region(title),
        stream=_infer_stream(title),
        raw_text=cleaned,
    )


def _load_headers_for_rows(
    rows: list[Any],
    *,
    project_root: Path,
) -> dict[tuple[int, int], HeaderResolution]:
    wanted: dict[int, dict[str, Any]] = {}
    for row in rows:
        source_page = _optional_int(row["source_page"])
        if source_page is None:
            continue
        paper_id = int(row["source_paper_id"])
        entry = wanted.setdefault(
            paper_id,
            {
                "source_path": str(row["source_path"]),
                "pages": set(),
            },
        )
        entry["pages"].add(source_page)

    headers: dict[tuple[int, int], HeaderResolution] = {}
    try:
        import fitz  # type: ignore
    except ImportError:
        return headers

    for paper_id, entry in wanted.items():
        pdf_path = (project_root / entry["source_path"]).resolve()
        try:
            pdf_path.relative_to(project_root.resolve())
        except ValueError:
            continue
        if not pdf_path.is_file():
            continue
        try:
            document = fitz.open(pdf_path)
        except Exception:
            continue
        try:
            exact_headers: dict[int, SourceHeader] = {}
            for page_no in sorted(entry["pages"]):
                if page_no <= 0 or page_no > len(document):
                    continue
                header = _extract_header_from_page_text(document[page_no - 1].get_text("text"))
                if header:
                    exact_headers[page_no] = header
                    headers[(paper_id, page_no)] = HeaderResolution(
                        header=header,
                        confidence="exact",
                        flags=("source_header_extracted",),
                    )
            for page_no in sorted(entry["pages"]):
                if (paper_id, page_no) in headers or page_no <= 0 or page_no > len(document):
                    continue
                previous = _find_previous_header(
                    document,
                    page_no=page_no,
                    exact_headers=exact_headers,
                )
                if previous:
                    previous_page, header = previous
                    headers[(paper_id, page_no)] = HeaderResolution(
                        header=header,
                        confidence="inferred",
                        flags=(
                            "source_header_inferred_from_previous_page",
                            f"source_header_inferred_distance_{page_no - previous_page}",
                        ),
                    )
        finally:
            document.close()
    return headers


def _find_previous_header(
    document: Any,
    *,
    page_no: int,
    exact_headers: dict[int, SourceHeader],
    max_lookback: int = 3,
) -> tuple[int, SourceHeader] | None:
    for previous_page in range(page_no - 1, max(page_no - max_lookback, 1) - 1, -1):
        if previous_page in exact_headers:
            return previous_page, exact_headers[previous_page]
        header = _extract_header_from_page_text(document[previous_page - 1].get_text("text"))
        if header:
            exact_headers[previous_page] = header
            return previous_page, header
    return None


def _extract_header_from_page_text(text: str) -> SourceHeader | None:
    for line in str(text or "").splitlines()[:12]:
        header = parse_source_header_line(line)
        if header:
            return header
    return None


def _infer_stream(title: str) -> str | None:
    inner = _paren_inner(title)
    target = inner or title
    if re.search(r"(?:理科|理)(?:\s*$|卷|[)）])", target):
        return "理科"
    if re.search(r"(?:文科|文)(?:\s*$|卷|[)）])", target):
        return "文科"
    return None


def _infer_region(title: str) -> str | None:
    inner = _paren_inner(title)
    if not inner:
        return None
    region = re.sub(r"\s+", "", inner)
    region = re.sub(r"(理科?|文科?)$", "", region)
    return region or None


def _paren_inner(title: str) -> str | None:
    match = re.search(r"[（(]([^）)]+)[）)]", title)
    if not match:
        return None
    return match.group(1).strip() or None


def _looks_like_collection(value: str | None) -> bool:
    text = _clean(value)
    return any(pattern in text for pattern in COLLECTION_TITLE_PATTERNS)


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _optional_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _flag_distribution(conn) -> dict[str, int]:
    rows = conn.execute(
        "SELECT attribution_flags_json FROM question_source_attributions"
    ).fetchall()
    counts: dict[str, int] = {}
    for row in rows:
        try:
            flags = json.loads(row["attribution_flags_json"] or "[]")
        except json.JSONDecodeError:
            flags = []
        if not isinstance(flags, list):
            continue
        for flag in flags:
            counts[str(flag)] = counts.get(str(flag), 0) + 1
    return dict(sorted(counts.items()))


def _render_report_markdown(summary: dict[str, Any]) -> str:
    lines = [
        "# 阶段 13 来源归属报告",
        "",
        "## 总览",
        "",
        f"- questions：{summary['question_count']}",
        f"- question_source_attributions：{summary['attribution_count']}",
        f"- missing：{summary['missing']}",
        f"- orphan：{summary['orphan_count']}",
        f"- exact：{summary['exact']}",
        f"- inferred：{summary['inferred']}",
        f"- unknown：{summary['unknown']}",
        f"- attribution_version：{summary['attribution_version']}",
        "",
        "## 置信度口径",
        "",
        "- `exact`：当前题所在 PDF 页可稳定读到页眉年份和原卷名，并同时具备题号。",
        "- `inferred`：当前页无页眉，但可从相邻前页页眉或已有非编纂来源字段推断；不视为精确来源。",
        "- `unknown`：无法确认原始卷名或年份；不会把编纂书名伪造成真实原卷名。",
        "",
        "## 年份分布",
        "",
    ]
    if summary["year_distribution"]:
        for year, count in summary["year_distribution"].items():
            lines.append(f"- {year}：{count}")
    else:
        lines.append("- none")
    lines.extend(["", "## Flags", ""])
    if summary["flag_distribution"]:
        for flag, count in summary["flag_distribution"].items():
            lines.append(f"- `{flag}`：{count}")
    else:
        lines.append("- none")
    lines.extend(["", "## 样例", ""])
    for confidence in ("exact", "inferred", "unknown"):
        lines.append(f"### {confidence}")
        samples = summary["samples_by_confidence"].get(confidence, [])
        if not samples:
            lines.append("- none")
        for row in samples[:5]:
            flags = ", ".join(_parse_flags(row.get("attribution_flags_json")))
            header = row.get("source_text") or ""
            lines.append(
                f"- `{row['qid']}`：{row['source_label']} / {row['confidence']}"
                f"{' / header: ' + header if header else ''}"
                f"{' / flags: ' + flags if flags else ''}"
            )
        lines.append("")
    lines.extend(
        [
            "## 边界",
            "",
            "- 本阶段不新增 PDF 导入批次，不扩页，不处理全 1207 页。",
            "- 本阶段只写候选侧来源归属表，不修改 `questions` 主表题干、题号、状态、答案或解析。",
            "- 后续任意试卷导入必须先登记来源，再进入切分、复核和导出链路。",
            "",
        ]
    )
    return "\n".join(lines)


def _parse_flags(value: str | None) -> list[str]:
    try:
        parsed = json.loads(value or "[]")
    except json.JSONDecodeError:
        return []
    if not isinstance(parsed, list):
        return []
    return [str(item) for item in parsed if item]
