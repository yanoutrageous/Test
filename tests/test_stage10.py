from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from app.cli import main
from app.database import connect_database, initialize_database
from app.stage10 import (
    HIGH_RISK_PAGES,
    questions_main_checksum,
    run_stage10_structure_batch,
    save_stage10_export_sample,
    write_stage10_quality_report,
)
from app.structured_content import initialize_structured_contents


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
        ("PDF-D02D0F16371FA96F", "Stage 10 Paper", "Base/sample.pdf", 1200, "born_digital", "{}"),
    )
    return int(cursor.lastrowid)


def _insert_page_asset(conn: sqlite3.Connection, source_paper_id: int, page_no: int) -> None:
    conn.execute(
        """
        INSERT OR IGNORE INTO source_paper_assets (
            source_paper_id,
            asset_kind,
            relative_path,
            page_no,
            bbox_json,
            meta_json
        ) VALUES (?, 'page_image', ?, ?, '{}', '{}')
        """,
        (
            source_paper_id,
            f"data/assets/paper_pages/PDF-D02D0F16371FA96F/page_{page_no:04d}_144dpi.png",
            page_no,
        ),
    )


def _insert_question(
    conn: sqlite3.Connection,
    source_paper_id: int,
    *,
    qid: str,
    question_no: str,
    question_type: str | None,
    stem_text: str,
    source_page: int,
    review_status: str = "pending",
) -> int:
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
            qid,
            source_paper_id,
            "Stage 10 Paper",
            question_no,
            question_type,
            stem_text,
            stem_text,
            "[]",
            "[]",
            f"p{source_page:04d}",
            json.dumps({"page": source_page, "x0": 1, "y0": 2, "x1": 100, "y1": 80}),
            review_status,
            json.dumps({"source_page": source_page, "split_warnings": []}),
            f"hash-{qid}",
        ),
    )
    question_id = int(cursor.lastrowid)
    conn.execute(
        """
        INSERT INTO question_assets (
            question_id,
            asset_kind,
            relative_path,
            page_no,
            bbox_json,
            meta_json
        ) VALUES (?, 'raw_crop', ?, ?, '{}', '{}')
        """,
        (
            question_id,
            f"data/assets/question_images/PDF-D02D0F16371FA96F/{qid}.png",
            source_page,
        ),
    )
    _insert_page_asset(conn, source_paper_id, source_page)
    return question_id


def _insert_batch_page(
    conn: sqlite3.Connection,
    source_paper_id: int,
    *,
    page_no: int,
    candidate_count: int,
    db_question_count: int,
    warnings: int = 0,
    duplicates: int = 0,
) -> None:
    conn.execute(
        """
        INSERT INTO import_batches (
            batch_code,
            name,
            batch_kind,
            source_paper_id,
            page_spec,
            page_count,
            algorithm_version,
            status
        ) VALUES (?, ?, 'baseline', ?, ?, 1, 'test', 'done')
        """,
        (f"BATCH-STAGE10-{page_no}", f"stage10-batch-{page_no}", source_paper_id, str(page_no)),
    )
    batch_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    flags = ["duplicate_anchors"] if duplicates else []
    conn.execute(
        """
        INSERT INTO import_batch_pages (
            batch_id,
            source_paper_id,
            page_no,
            status,
            candidate_count,
            db_question_count,
            warning_candidates,
            duplicate_anchor_count,
            page_flags_json,
            warning_reasons_json
        ) VALUES (?, ?, ?, 'done', ?, ?, ?, ?, ?, '[]')
        """,
        (
            batch_id,
            source_paper_id,
            page_no,
            candidate_count,
            db_question_count,
            warnings,
            duplicates,
            json.dumps(flags),
        ),
    )


def _set_verified(conn: sqlite3.Connection, question_id: int) -> None:
    conn.execute(
        """
        UPDATE question_structured_contents
           SET ai_status = 'ai_verified',
               normalized_type = 'choice',
               stem_latex = source_latex,
               options_json = ?,
               quality_flags_json = '[]',
               model_info = ?
         WHERE question_id = ?
        """,
        (
            json.dumps(
                [
                    {"label": "A", "text_latex": "1"},
                    {"label": "B", "text_latex": "2"},
                    {"label": "C", "text_latex": "3"},
                    {"label": "D", "text_latex": "4"},
                ],
                ensure_ascii=False,
            ),
            json.dumps({"test": "stage9-verified"}, ensure_ascii=False),
            question_id,
        ),
    )


def _prepare_stage10_db(tmp_path: Path) -> tuple[Path, Path, dict[str, int]]:
    project_root = tmp_path / "project"
    (project_root / "Base").mkdir(parents=True)
    (project_root / "Base" / "sample.pdf").write_bytes(b"%PDF-1.4\n")
    db_path = project_root / "data" / "db" / "question_bank.sqlite3"
    initialize_database(db_path)
    ids: dict[str, int] = {}
    with connect_database(db_path) as conn:
        source_paper_id = _insert_source_paper(conn)
        ids["q011"] = _insert_question(
            conn,
            source_paper_id,
            qid="PDF-D02D0F16371FA96F-P1094-Q011",
            question_no="11",
            question_type="choice",
            stem_text="11. Focus verified enough text (A) 1 (B) 2 (C) 3 (D) 4",
            source_page=1094,
        )
        ids["q012"] = _insert_question(
            conn,
            source_paper_id,
            qid="PDF-D02D0F16371FA96F-P1094-Q012",
            question_no="12",
            question_type="choice",
            stem_text="12. Focus verified enough text (A) 1 (B) 2 (C) 3 (D) 4",
            source_page=1094,
        )
        for index in range(1, 7):
            ids[f"choice_{index}"] = _insert_question(
                conn,
                source_paper_id,
                qid=f"PDF-STAGE10-P1090-Q{index:03d}",
                question_no=str(index),
                question_type="choice",
                stem_text=(
                    f"{index}. Low risk x2 choice with enough source text "
                    "(A) 1 (B) 2 (C) 3 (D) 4"
                ),
                source_page=1090,
            )
        ids["multiple"] = _insert_question(
            conn,
            source_paper_id,
            qid="PDF-STAGE10-P1091-Q001",
            question_no="1",
            question_type="multiple choice",
            stem_text="1. Multiple choice enough source text (A) 1 (B) 2 (C) 3 (D) 4",
            source_page=1091,
        )
        ids["blank"] = _insert_question(
            conn,
            source_paper_id,
            qid="PDF-STAGE10-P1091-Q002",
            question_no="2",
            question_type="blank",
            stem_text="2. Fill the blank with enough source text",
            source_page=1091,
        )
        ids["solution"] = _insert_question(
            conn,
            source_paper_id,
            qid="PDF-STAGE10-P1091-Q003",
            question_no="3",
            question_type="solution",
            stem_text="3. Solve with enough source text (1) prove the statement",
            source_page=1091,
        )
        ids["unknown"] = _insert_question(
            conn,
            source_paper_id,
            qid="PDF-STAGE10-P1091-Q004",
            question_no="4",
            question_type=None,
            stem_text="4. Unknown but enough source text",
            source_page=1091,
        )
        ids["reviewed"] = _insert_question(
            conn,
            source_paper_id,
            qid="PDF-STAGE10-P1091-Q005",
            question_no="5",
            question_type="choice",
            stem_text="5. Reviewed protected enough source text (A) 1 (B) 2 (C) 3 (D) 4",
            source_page=1091,
            review_status="reviewed",
        )
        ids["high_risk"] = _insert_question(
            conn,
            source_paper_id,
            qid="PDF-STAGE10-P1098-Q001",
            question_no="1",
            question_type="choice",
            stem_text="1. High risk enough source text (A) 1 (B) 2 (C) 3 (D) 4",
            source_page=1098,
        )
        _insert_batch_page(
            conn,
            source_paper_id,
            page_no=1098,
            candidate_count=25,
            db_question_count=18,
            warnings=8,
            duplicates=7,
        )
        conn.commit()
    initialize_structured_contents(db_path=db_path)
    with connect_database(db_path) as conn:
        _set_verified(conn, ids["q011"])
        _set_verified(conn, ids["q012"])
        conn.commit()
    return project_root, db_path, ids


def test_stage10_structure_batch_baseline_isolation_and_report(tmp_path: Path) -> None:
    project_root, db_path, ids = _prepare_stage10_db(tmp_path)
    with connect_database(db_path) as conn:
        before_checksum = questions_main_checksum(conn)

    result = run_stage10_structure_batch(
        db_path=db_path,
        target_verified=6,
        max_questions=8,
        sample_size=100,
    )
    report = write_stage10_quality_report(
        db_path=db_path,
        project_root=project_root,
        sample_size=100,
    )

    assert result["target_met"] is True
    assert result["verified_after"] >= 6
    assert result["baseline"]["coverage"]["total"] >= 1
    assert 1098 in result["baseline"]["coverage"]["high_risk_pages"]
    assert report["status_counts"]["ai_verified"] >= 6
    assert (project_root / "docs" / "stage10_quality_report.md").is_file()

    with connect_database(db_path) as conn:
        after_checksum = questions_main_checksum(conn)
        isolation = conn.execute(
            """
            SELECT candidate_count, db_question_count, duplicate_anchor_count, isolated_count
              FROM stage10_page_isolations
             WHERE page_no = 1098
            """
        ).fetchone()
        high_risk = conn.execute(
            """
            SELECT ai_status, quality_flags_json
              FROM question_structured_contents
             WHERE question_id = ?
            """,
            (ids["high_risk"],),
        ).fetchone()
        reviewed = conn.execute(
            "SELECT ai_status FROM question_structured_contents WHERE question_id = ?",
            (ids["reviewed"],),
        ).fetchone()
        blank = conn.execute(
            """
            SELECT ai_status, quality_flags_json
              FROM question_structured_contents
             WHERE question_id = ?
            """,
            (ids["blank"],),
        ).fetchone()

    assert after_checksum == before_checksum
    assert isolation["candidate_count"] == 25
    assert isolation["db_question_count"] == 18
    assert isolation["duplicate_anchor_count"] == 7
    assert isolation["isolated_count"] == 7
    assert high_risk["ai_status"] == "needs_review"
    assert "page_flag_stage10_duplicate_anchor_isolated" in json.loads(
        high_risk["quality_flags_json"]
    )
    assert blank["ai_status"] == "needs_review"
    assert "blank_placeholder_inferred" in json.loads(blank["quality_flags_json"])
    assert reviewed["ai_status"] == "unprocessed"
    assert set(HIGH_RISK_PAGES) >= {1098, 1100, 1128, 1148, 1168}


def test_stage10_cli_and_export_sample(tmp_path: Path) -> None:
    project_root, db_path, _ = _prepare_stage10_db(tmp_path)

    assert (
        main(
            [
                "stage10-structure-batch",
                "--db-path",
                str(db_path),
                "--target-verified",
                "6",
                "--max-questions",
                "8",
            ]
        )
        == 0
    )
    assert main(["stage10-report", "--db-path", str(db_path)]) == 0
    assert main(["stage10-export-sample", "--db-path", str(db_path), "--limit", "8"]) == 0

    report_path = project_root / "docs" / "stage10_quality_report.md"
    exports = list((project_root / "data" / "exports").glob("stage10-sample-*.html"))

    assert report_path.is_file()
    assert exports
    html = exports[0].read_text(encoding="utf-8")
    assert "阶段 10 导出样张" in html
    assert "一、单项选择题" in html
    assert "local-math-renderer" in html
    assert "PDF-D02D0F16371FA96F-P1094-Q011" in html

    direct = save_stage10_export_sample(db_path=db_path, project_root=project_root, limit=8)
    assert direct["status"] == "ok"
    assert direct["question_count"] >= 2
