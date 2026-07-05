from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from app.cli import main
from app.codex_structure import (
    apply_codex_structure_jsonl,
    export_codex_structure_batch,
    run_codex_structure_batch,
)
from app.database import connect_database, initialize_database
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
        (
            "PDF-D02D0F16371FA96F",
            "Codex Paper",
            "Base/sample.pdf",
            1200,
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
            "Codex Paper",
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
    return int(cursor.lastrowid)


def _insert_assets(conn: sqlite3.Connection, source_paper_id: int, question_id: int, qid: str) -> None:
    conn.execute(
        """
        INSERT OR IGNORE INTO source_paper_assets (
            source_paper_id, asset_kind, relative_path, page_no, bbox_json, meta_json
        ) VALUES (?, 'page_image', ?, 1094, '{}', '{}')
        """,
        (source_paper_id, "data/assets/paper_pages/PDF-D02D0F16371FA96F/page_1094_144dpi.png"),
    )
    conn.execute(
        """
        INSERT INTO question_assets (
            question_id, asset_kind, relative_path, page_no, bbox_json, meta_json
        ) VALUES (?, 'raw_crop', ?, 1094, '{}', '{}')
        """,
        (
            question_id,
            f"data/assets/question_images/PDF-D02D0F16371FA96F/{qid}.png",
        ),
    )


def _insert_import_batch_page(
    conn: sqlite3.Connection,
    source_paper_id: int,
    *,
    page_no: int,
    warnings: int = 0,
    duplicates: int = 0,
) -> None:
    conn.execute(
        """
        INSERT INTO import_batches (
            batch_code, name, batch_kind, source_paper_id, page_spec, page_count, algorithm_version, status
        ) VALUES (?, ?, 'baseline', ?, ?, 1, 'test', 'done')
        """,
        (f"BATCH-{page_no}", f"batch-{page_no}", source_paper_id, str(page_no)),
    )
    batch_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    flags = ["duplicate_anchors"] if duplicates else []
    if warnings:
        flags.append("warning_candidates")
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
        ) VALUES (?, ?, ?, 'done', 2, 2, ?, ?, ?, '[]')
        """,
        (batch_id, source_paper_id, page_no, warnings, duplicates, json.dumps(flags)),
    )


def _prepare_db(tmp_path: Path) -> tuple[Path, int, int, int]:
    db_path = tmp_path / "question_bank.sqlite3"
    initialize_database(db_path)
    q011_text = (
        "11. 设F 为双曲线C: x2\na2 −y2\nb2 = 1 (a > 0, b > 0) 的右焦点, O 为坐标原点,"
        "以OF 为直径的圆与圆x2 + y2 = a2 交于P, Q 两点. 若|PQ| = |OF|, 则 C 的离心率为 ( )"
        "(A) √ 2 (B) √ 3 (C) 2 (D) √ 5"
    )
    with connect_database(db_path) as conn:
        source_paper_id = _insert_source_paper(conn)
        q011_id = _insert_question(
            conn,
            source_paper_id,
            qid="PDF-D02D0F16371FA96F-P1094-Q011",
            question_no="11",
            question_type="选择题",
            stem_text=q011_text,
            source_page=1094,
        )
        _insert_assets(conn, source_paper_id, q011_id, "PDF-D02D0F16371FA96F-P1094-Q011")
        reviewed_id = _insert_question(
            conn,
            source_paper_id,
            qid="PDF-D02D0F16371FA96F-P1094-Q012",
            question_no="12",
            question_type="选择题",
            stem_text="12. reviewed source (A) 1 (B) 2 (C) 3 (D) 4",
            source_page=1094,
            review_status="reviewed",
        )
        _insert_assets(conn, source_paper_id, reviewed_id, "PDF-D02D0F16371FA96F-P1094-Q012")
        high_risk_id = _insert_question(
            conn,
            source_paper_id,
            qid="PDF-D02D0F16371FA96F-P1098-Q003",
            question_no="3",
            question_type="选择题",
            stem_text="3. high risk text (A) 0.5 (B) 0.6 (C) 0.7 (D) 0.8",
            source_page=1098,
        )
        _insert_import_batch_page(conn, source_paper_id, page_no=1094)
        _insert_import_batch_page(conn, source_paper_id, page_no=1098, warnings=8, duplicates=7)
        conn.commit()
    initialize_structured_contents(db_path=db_path)
    return db_path, q011_id, reviewed_id, high_risk_id


def test_codex_structure_batch_writes_structured_copy_only(tmp_path: Path) -> None:
    db_path, q011_id, reviewed_id, high_risk_id = _prepare_db(tmp_path)
    output_path = tmp_path / "exports" / "stage9_codex_3.jsonl"

    result = run_codex_structure_batch(
        db_path=db_path,
        sample_size=3,
        batch_name="stage9-codex-test",
        output_path=output_path,
        project_root=tmp_path,
    )

    assert result["status"] == "ok"
    assert output_path.is_file()
    with connect_database(db_path) as conn:
        q011 = conn.execute(
            """
            SELECT q.stem_text AS original_stem,
                   sc.stem_latex,
                   sc.options_json,
                   sc.ai_status,
                   sc.model_info
              FROM questions q
              JOIN question_structured_contents sc ON sc.question_id = q.id
             WHERE q.id = ?
            """,
            (q011_id,),
        ).fetchone()
        reviewed = conn.execute(
            "SELECT stem_latex, ai_status FROM question_structured_contents WHERE question_id = ?",
            (reviewed_id,),
        ).fetchone()
        high_risk = conn.execute(
            "SELECT ai_status, quality_flags_json FROM question_structured_contents WHERE question_id = ?",
            (high_risk_id,),
        ).fetchone()

    assert q011["ai_status"] == "ai_verified"
    assert "\\frac{x^2}{a^2}" in q011["stem_latex"]
    assert "\\sqrt{5}" in q011["options_json"]
    assert q011["original_stem"].startswith("11. 设F 为双曲线")
    assert json.loads(q011["model_info"])["provider"] == "codex_agent"
    assert reviewed["ai_status"] == "unprocessed"
    assert reviewed["stem_latex"].startswith("12. reviewed source")
    assert high_risk["ai_status"] == "needs_review"
    assert "page_duplicate_anchors" in json.loads(high_risk["quality_flags_json"])


def test_codex_structure_export_and_apply_cli(tmp_path: Path) -> None:
    db_path, _, _, _ = _prepare_db(tmp_path)
    output_path = tmp_path / "stage9_codex_2.jsonl"

    assert (
        main(
            [
                "codex-structure-export",
                "--db-path",
                str(db_path),
                "--sample-size",
                "2",
                "--batch-name",
                "stage9-codex-cli",
                "--output",
                str(output_path),
            ]
        )
        == 0
    )
    with connect_database(db_path) as conn:
        conn.execute(
            "UPDATE question_structured_contents SET ai_status='unprocessed', quality_flags_json='[]'"
        )
        conn.commit()

    assert (
        main(
            [
                "codex-structure-apply",
                "--db-path",
                str(db_path),
                "--input",
                str(output_path),
                "--batch-name",
                "stage9-codex-cli",
            ]
        )
        == 0
    )
    with connect_database(db_path) as conn:
        status = conn.execute(
            """
            SELECT ai_status
              FROM question_structured_contents sc
              JOIN questions q ON q.id = sc.question_id
             WHERE q.qid = 'PDF-D02D0F16371FA96F-P1094-Q011'
            """
        ).fetchone()[0]
    assert status == "ai_verified"


def test_codex_structure_apply_reports_invalid_jsonl_record(tmp_path: Path) -> None:
    db_path, _, _, _ = _prepare_db(tmp_path)
    bad_jsonl = tmp_path / "bad.jsonl"
    bad_jsonl.write_text(
        json.dumps({"qid": "PDF-D02D0F16371FA96F-P1094-Q011", "payload": {"normalized_type": "choice"}}),
        encoding="utf-8",
    )

    result = apply_codex_structure_jsonl(
        db_path=db_path,
        input_path=bad_jsonl,
        batch_name="bad",
        project_root=tmp_path,
    )

    assert result["status"] == "error"
    assert result["applied"] == 0
    assert "stem_latex cannot be empty" in result["errors"][0]["error"]
