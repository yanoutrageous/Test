from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from app.cli import main
from app.database import connect_database, initialize_database
from app.source_attribution import (
    SourceAttributionService,
    parse_source_header_line,
    summarize_source_attributions,
)
from app.stage10 import questions_main_checksum


def _create_source_pdf(path: Path) -> None:
    fitz = pytest.importorskip("fitz")
    path.parent.mkdir(parents=True, exist_ok=True)
    doc = fitz.open()
    page1 = doc.new_page(width=420, height=600)
    page1.insert_text((36, 48), "2024 National Math Paper (I)")
    page1.insert_text((36, 78), "1. first question text")
    page2 = doc.new_page(width=420, height=600)
    page2.insert_text((36, 48), "2. continuation question text")
    doc.save(path)
    doc.close()


def _insert_source_paper(conn: sqlite3.Connection) -> int:
    cursor = conn.execute(
        """
        INSERT INTO source_papers (
            paper_code,
            title,
            source_path,
            page_count,
            import_mode,
            meta_json
        ) VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            "PDF-STAGE13",
            "1977—2024高考数学真题全编",
            "Base/stage13.pdf",
            2,
            "born_digital",
            "{}",
        ),
    )
    return int(cursor.lastrowid)


def _insert_question(
    conn: sqlite3.Connection,
    source_paper_id: int,
    *,
    qid: str,
    question_no: str,
    source_page: int | None,
) -> int:
    meta = {"algorithm_version": "stage13-test"}
    page_range = ""
    if source_page is not None:
        meta["source_page"] = source_page
        page_range = f"p{source_page:04d}"
    cursor = conn.execute(
        """
        INSERT INTO questions (
            qid,
            source_paper_id,
            paper_name,
            question_no,
            question_type,
            stem_latex,
            stem_text,
            tags_json,
            image_refs_json,
            page_range,
            bbox_json,
            review_status,
            meta_json,
            content_hash
        ) VALUES (?, ?, ?, ?, ?, ?, ?, '[]', '[]', ?, '{}', 'pending', ?, ?)
        """,
        (
            qid,
            source_paper_id,
            "1977—2024高考数学真题全编",
            question_no,
            "选择题",
            f"{qid} latex",
            f"{qid} searchable text",
            page_range,
            json.dumps(meta, ensure_ascii=False),
            f"hash-{qid}",
        ),
    )
    return int(cursor.lastrowid)


def _prepare_stage13_db(tmp_path: Path) -> tuple[Path, Path, dict[str, int]]:
    project_root = tmp_path / "project"
    _create_source_pdf(project_root / "Base" / "stage13.pdf")
    db_path = project_root / "data" / "db" / "question_bank.sqlite3"
    initialize_database(db_path)
    with connect_database(db_path) as conn:
        source_paper_id = _insert_source_paper(conn)
        ids = {
            "exact": _insert_question(
                conn,
                source_paper_id,
                qid="STAGE13-EXACT",
                question_no="1",
                source_page=1,
            ),
            "inferred": _insert_question(
                conn,
                source_paper_id,
                qid="STAGE13-INFERRED",
                question_no="2",
                source_page=2,
            ),
            "unknown": _insert_question(
                conn,
                source_paper_id,
                qid="STAGE13-UNKNOWN",
                question_no="3",
                source_page=None,
            ),
        }
        conn.commit()
    return project_root, db_path, ids


def test_parse_source_header_line_extracts_year_and_name() -> None:
    header = parse_source_header_line("2024 National Math Paper (I)")

    assert header is not None
    assert header.year == 2024
    assert header.paper_name == "National Math Paper (I)"
    assert header.raw_text == "2024 National Math Paper (I)"


def test_rebuild_source_attributions_classifies_exact_inferred_and_unknown(
    tmp_path: Path,
) -> None:
    project_root, db_path, ids = _prepare_stage13_db(tmp_path)
    service = SourceAttributionService(db_path=db_path, project_root=project_root)
    with connect_database(db_path) as conn:
        before_checksum = questions_main_checksum(conn)

    result = service.rebuild()

    with connect_database(db_path) as conn:
        after_checksum = questions_main_checksum(conn)
        rows = {
            row["question_id"]: dict(row)
            for row in conn.execute(
                """
                SELECT question_id,
                       source_label,
                       confidence,
                       source_year,
                       source_paper_name,
                       attribution_flags_json,
                       source_text
                  FROM question_source_attributions
                """
            ).fetchall()
        }

    assert result["summary"]["question_count"] == 3
    assert result["summary"]["attribution_count"] == 3
    assert result["summary"]["missing"] == 0
    assert rows[ids["exact"]]["confidence"] == "exact"
    assert rows[ids["exact"]]["source_year"] == 2024
    assert rows[ids["exact"]]["source_paper_name"] == "National Math Paper (I)"
    assert "2024 National Math Paper (I) 第1题" in rows[ids["exact"]]["source_label"]
    assert "source_header_extracted" in json.loads(
        rows[ids["exact"]]["attribution_flags_json"]
    )
    assert rows[ids["inferred"]]["confidence"] == "inferred"
    assert rows[ids["inferred"]]["source_label"] == (
        "2024 National Math Paper (I) / p0002 / 题号 2"
    )
    assert "source_header_inferred_from_previous_page" in json.loads(
        rows[ids["inferred"]]["attribution_flags_json"]
    )
    assert rows[ids["unknown"]]["confidence"] == "unknown"
    assert rows[ids["unknown"]]["source_paper_name"] is None
    assert rows[ids["unknown"]]["source_label"].startswith("未知原始卷")
    assert "compiled_source_name_suppressed" in json.loads(
        rows[ids["unknown"]]["attribution_flags_json"]
    )
    assert after_checksum == before_checksum


def test_stage13_cli_status_and_report(tmp_path: Path) -> None:
    project_root, db_path, _ = _prepare_stage13_db(tmp_path)

    assert main(["rebuild-source-attributions", "--db-path", str(db_path)]) == 0
    assert main(["source-attribution-status", "--db-path", str(db_path)]) == 0
    assert main(["stage13-report", "--db-path", str(db_path)]) == 0

    summary = summarize_source_attributions(db_path=db_path)
    report = project_root / "docs" / "stage13_source_attribution_report.md"
    assert summary["missing"] == 0
    assert summary["exact"] == 1
    assert summary["inferred"] == 1
    assert summary["unknown"] == 1
    assert report.is_file()
    text = report.read_text(encoding="utf-8")
    assert "阶段 13 来源归属报告" in text
    assert "exact：1" in text
    assert "inferred：1" in text
    assert "unknown：1" in text
    assert "不会把编纂书名伪造成真实原卷名" in text
