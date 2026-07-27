from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from app.database import connect_database, initialize_database
from app.import_batches import (
    create_import_batch,
    get_import_batch,
    list_import_batches,
    register_baseline_batch,
    run_import_batch,
)
from app.stage8_report import write_stage8_quality_report
from app.project_root import PROJECT_ROOT, ROOT_MARKER_NAME


def _create_pdf(path: Path, page_count: int = 3) -> None:
    import fitz

    path.parent.mkdir(parents=True, exist_ok=True)
    doc = fitz.open()
    for index in range(page_count):
        page = doc.new_page(width=320, height=420)
        page.insert_text((36, 70), "1. batch alpha question with enough searchable text")
        page.insert_text((36, 100), "continued alpha body for batch processing")
        page.insert_text((36, 150), "2. batch beta question with enough searchable text")
        page.insert_text((36, 180), "continued beta body for batch processing")
    doc.save(path)
    doc.close()


def _prepare_project(tmp_path: Path) -> tuple[Path, Path, Path]:
    project_root = tmp_path / "project"
    pdf_path = project_root / "Base" / "sample.pdf"
    db_path = project_root / "data" / "db" / "question_bank.sqlite3"
    _create_pdf(pdf_path)
    (project_root / ROOT_MARKER_NAME).write_bytes(
        (PROJECT_ROOT / ROOT_MARKER_NAME).read_bytes()
    )
    initialize_database(db_path)
    return project_root, db_path, pdf_path


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
        ("PDF-BATCH", "Batch Paper", "Base/sample.pdf", 3, "born_digital", "{}"),
    )
    return int(cursor.lastrowid)


def _insert_question(conn: sqlite3.Connection, source_paper_id: int) -> int:
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
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "PDF-BATCH-P0001-Q001",
            source_paper_id,
            "Batch Paper",
            "1",
            "选择题",
            "baseline latex",
            "baseline stem",
            "[]",
            "[]",
            "p0001",
            json.dumps({"page": 1, "x0": 10, "y0": 10, "x1": 100, "y1": 80}),
            "pending",
            json.dumps({"source_page": 1, "algorithm_version": "test"}),
            "baseline-hash",
        ),
    )
    return int(cursor.lastrowid)


def test_create_import_batch_records_pages(tmp_path: Path) -> None:
    _project_root, db_path, _pdf_path = _prepare_project(tmp_path)

    batch = create_import_batch(
        name="stage8-test-create",
        pages=(1, 2, 3),
        db_path=db_path,
        project_root=tmp_path / "project",
    )
    shown = get_import_batch(name="stage8-test-create", db_path=db_path)
    listed = list_import_batches(db_path=db_path)

    assert batch["name"] == "stage8-test-create"
    assert batch["page_spec"] == "1-3"
    assert batch["page_count"] == 3
    assert [page["page_no"] for page in shown["pages"]] == [1, 2, 3]
    assert listed[0]["name"] == "stage8-test-create"


def test_register_baseline_batch_does_not_change_questions(tmp_path: Path) -> None:
    project_root, db_path, _pdf_path = _prepare_project(tmp_path)
    with connect_database(db_path) as conn:
        source_paper_id = _insert_source_paper(conn)
        _insert_question(conn, source_paper_id)
        conn.commit()
        before_questions = conn.execute("SELECT count(*) FROM questions").fetchone()[0]

    batch = register_baseline_batch(
        name="stage8-baseline-test",
        pages=(1, 2),
        db_path=db_path,
        project_root=project_root,
    )

    with connect_database(db_path) as conn:
        after_questions = conn.execute("SELECT count(*) FROM questions").fetchone()[0]
        page_rows = conn.execute(
            """
            SELECT page_no, candidate_count, db_question_count, status
              FROM import_batch_pages
             WHERE batch_id = ?
             ORDER BY page_no
            """,
            (batch["id"],),
        ).fetchall()

    assert after_questions == before_questions
    assert batch["status"] == "done"
    assert [row["status"] for row in page_rows] == ["done", "done"]
    assert page_rows[0]["candidate_count"] == 2
    assert page_rows[0]["db_question_count"] == 1


def test_run_import_batch_records_stats_and_backup(tmp_path: Path) -> None:
    project_root, db_path, _pdf_path = _prepare_project(tmp_path)

    batch = run_import_batch(
        name="stage8-run-test",
        pages=(1, 2),
        db_path=db_path,
        project_root=project_root,
        dpi=72,
    )

    assert batch["status"] == "done"
    assert batch["backup_path"].startswith("backups/BACKUP-")
    assert (project_root / batch["backup_path"]).is_file()
    assert (
        project_root / Path(batch["backup_path"]).parent / "manifest.json"
    ).is_file()
    pages = batch["pages"]
    assert [page["status"] for page in pages] == ["done", "done"]
    assert [page["candidate_count"] for page in pages] == [2, 2]
    assert [page["db_question_count"] for page in pages] == [2, 2]
    with connect_database(db_path) as conn:
        assert conn.execute("SELECT count(*) FROM source_paper_assets").fetchone()[0] == 2
        assert conn.execute("SELECT count(*) FROM questions").fetchone()[0] == 4
        assert conn.execute("SELECT count(*) FROM question_assets").fetchone()[0] == 4
        assert conn.execute("SELECT count(*) FROM question_search_content").fetchone()[0] == 4


def test_stage8_report_uses_batch_statistics(tmp_path: Path) -> None:
    project_root, db_path, _pdf_path = _prepare_project(tmp_path)
    run_import_batch(
        name="stage8-report-test",
        pages=(1,),
        db_path=db_path,
        project_root=project_root,
        dpi=72,
    )

    result = write_stage8_quality_report(db_path=db_path, project_root=project_root)
    report_text = (project_root / result["relative_path"]).read_text(encoding="utf-8")

    assert result["relative_path"] == "docs/stage8_quality_report.md"
    assert "stage8-report-test" in report_text
    assert "批次数：1" in report_text
    assert "批次页扫描候选题数：2" in report_text
    assert "## 质量比例" in report_text
    assert "## 性能" in report_text
    assert "## 复核成本估算" in report_text
