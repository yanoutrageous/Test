from __future__ import annotations

import sqlite3
from pathlib import Path

from app.database import connect_database, initialize_database
from app.pdf_scan import scan_pdf_pages


def _create_scan_pdf(path: Path) -> None:
    import fitz

    path.parent.mkdir(parents=True, exist_ok=True)
    doc = fitz.open()
    page = doc.new_page(width=300, height=400)
    page.insert_text((30, 60), "1. stage7 scan alpha question with enough text for stats")
    page.insert_text((30, 90), "continued body text for alpha candidate")
    page.insert_text((30, 130), "2. stage7 scan beta question with enough text for stats")
    page.insert_text((30, 160), "continued body text for beta candidate")

    page = doc.new_page(width=300, height=400)
    page.insert_text((30, 60), "stage7 scan appendix without numbered anchors")
    page.insert_text((30, 90), "more plain text but still no candidate anchors")

    doc.save(path)
    doc.close()


def _counts(conn: sqlite3.Connection) -> dict[str, int]:
    return {
        "source_papers": conn.execute("SELECT count(*) FROM source_papers").fetchone()[0],
        "source_paper_assets": conn.execute(
            "SELECT count(*) FROM source_paper_assets"
        ).fetchone()[0],
        "questions": conn.execute("SELECT count(*) FROM questions").fetchone()[0],
        "question_assets": conn.execute("SELECT count(*) FROM question_assets").fetchone()[0],
        "question_search_content": conn.execute(
            "SELECT count(*) FROM question_search_content"
        ).fetchone()[0],
    }


def test_scan_pdf_pages_reports_stats_without_writing_database(tmp_path: Path) -> None:
    project_root = tmp_path / "project"
    pdf_path = project_root / "Base" / "sample.pdf"
    db_path = project_root / "data" / "db" / "question_bank.sqlite3"
    _create_scan_pdf(pdf_path)
    initialize_database(db_path)

    with connect_database(db_path) as conn:
        before = _counts(conn)

    result = scan_pdf_pages(pages=(1, 2), pdf_path=pdf_path, project_root=project_root)

    with connect_database(db_path) as conn:
        after = _counts(conn)

    assert before == after
    assert result["summary"]["page_count"] == 2
    assert result["summary"]["total_candidates"] == 2
    first, second = result["pages"]
    assert first["page_no"] == 1
    assert first["anchor_count"] == 2
    assert first["first_anchors"] == [1, 2]
    assert first["duplicate_anchor_count"] == 0
    assert first["candidate_count"] == 2
    assert first["warning_candidates"] == 0
    assert first["warning_reasons"] == []
    assert second["page_no"] == 2
    assert second["anchor_count"] == 0
    assert second["candidate_count"] == 0
    assert "no_anchors" in second["page_flags"]
    assert "no_candidates" in second["page_flags"]
