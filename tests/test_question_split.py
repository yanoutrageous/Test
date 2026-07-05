from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from app.database import connect_database, initialize_database
from app.question_split import (
    ALGORITHM_VERSION,
    PageTextBlock,
    detect_question_anchor,
    parse_split_pages,
    split_blocks_into_candidates,
    write_question_candidates,
)


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
            "PDF-SPLIT-TEST",
            "Split Test Paper",
            "Base/sample.pdf",
            2,
            "born_digital",
            json.dumps({"test": True}),
        ),
    )
    return int(cursor.lastrowid)


def _block(index: int, text: str, x0: float = 10, y0: float = 10) -> PageTextBlock:
    return PageTextBlock(
        page_no=1090,
        block_index=index,
        bbox=(x0, y0 + index * 10, x0 + 100, y0 + index * 10 + 8),
        text=text,
    )


def _sample_candidates(source_paper_id: int):
    blocks = (
        _block(0, "一、选择题"),
        _block(1, "1. 已知集合 M, 求交集"),
        _block(2, "(A) alpha (B) beta"),
        _block(3, "3. 非连续题号示例"),
        _block(4, "后续文字"),
    )
    return split_blocks_into_candidates(
        blocks,
        source_paper_id=source_paper_id,
        paper_code="PDF-SPLIT-TEST",
        paper_title="Split Test Paper",
        page_no=1090,
    )


def test_parse_split_pages_supports_ranges() -> None:
    assert parse_split_pages("1090-1092,1091,1105") == (1090, 1091, 1092, 1105)


def test_detect_question_anchor_supports_arabic_number_dot() -> None:
    assert detect_question_anchor("1. 已知集合") == 1
    assert detect_question_anchor("17. △ABC 的内角") == 17
    assert detect_question_anchor("  9．全角句点") == 9
    assert detect_question_anchor("(A) alpha") is None
    assert detect_question_anchor("一、选择题") is None


def test_split_blocks_into_candidates_marks_pending_warnings() -> None:
    candidates = _sample_candidates(source_paper_id=1)

    assert [candidate.question_no for candidate in candidates] == ["1", "3"]
    assert all(candidate.question_type == "选择题" for candidate in candidates)
    assert candidates[0].split_warnings == ()
    assert "question_number_non_contiguous" in candidates[1].split_warnings
    assert candidates[0].qid == "PDF-SPLIT-TEST-P1090-Q001"
    assert candidates[1].qid == "PDF-SPLIT-TEST-P1090-Q003"


def test_write_question_candidates_is_idempotent_and_pending(tmp_path: Path) -> None:
    db_path = tmp_path / "question_bank.sqlite3"
    initialize_database(db_path)

    with connect_database(db_path) as conn:
        source_paper_id = _insert_source_paper(conn)
        conn.commit()

    candidates = _sample_candidates(source_paper_id)
    first = write_question_candidates(candidates, db_path=db_path)
    second = write_question_candidates(candidates, db_path=db_path)

    assert first["inserted"] == 2
    assert first["updated"] == 0
    assert first["skipped_reviewed"] == 0
    assert second["inserted"] == 0
    assert second["updated"] == 2
    assert second["skipped_reviewed"] == 0

    with connect_database(db_path) as conn:
        assert conn.execute("SELECT count(*) FROM questions").fetchone()[0] == 2
        assert (
            conn.execute(
                "SELECT count(*) FROM questions WHERE review_status = 'pending'"
            ).fetchone()[0]
            == 2
        )
        assert (
            conn.execute(
                "SELECT count(*) FROM questions WHERE review_status = 'approved'"
            ).fetchone()[0]
            == 0
        )
        assert (
            conn.execute("SELECT count(*) FROM question_search_content").fetchone()[0]
            == 2
        )
        hits = conn.execute(
            "SELECT qid FROM question_fts WHERE question_fts MATCH ?",
            ("alpha",),
        ).fetchall()
        row = conn.execute(
            """
            SELECT meta_json
              FROM questions
             WHERE qid = 'PDF-SPLIT-TEST-P1090-Q003'
            """
        ).fetchone()

    assert [hit["qid"] for hit in hits] == ["PDF-SPLIT-TEST-P1090-Q001"]
    meta = json.loads(row["meta_json"])
    assert meta["algorithm_version"] == ALGORITHM_VERSION
    assert meta["source_page"] == 1090
    assert "question_number_non_contiguous" in meta["split_warnings"]


def test_write_question_candidates_skips_reviewed_records(tmp_path: Path) -> None:
    db_path = tmp_path / "question_bank.sqlite3"
    initialize_database(db_path)

    with connect_database(db_path) as conn:
        source_paper_id = _insert_source_paper(conn)
        conn.commit()

    candidates = _sample_candidates(source_paper_id)
    first = write_question_candidates(candidates, db_path=db_path)
    assert first["inserted"] == 2

    reviewed_qid = candidates[0].qid
    with connect_database(db_path) as conn:
        conn.execute(
            """
            UPDATE questions
               SET stem_text = ?,
                   stem_latex = ?,
                   review_status = 'reviewed',
                   meta_json = ?,
                   updated_at = CURRENT_TIMESTAMP
             WHERE qid = ?
            """,
            (
                "human reviewed stem",
                "human reviewed latex",
                json.dumps({"manual_review": True}),
                reviewed_qid,
            ),
        )
        conn.commit()

    second = write_question_candidates(candidates, db_path=db_path)

    assert second["inserted"] == 0
    assert second["updated"] == 1
    assert second["skipped_reviewed"] == 1

    with connect_database(db_path) as conn:
        reviewed_row = conn.execute(
            """
            SELECT stem_text, stem_latex, review_status, meta_json
              FROM questions
             WHERE qid = ?
            """,
            (reviewed_qid,),
        ).fetchone()
        approved_count = conn.execute(
            "SELECT count(*) FROM questions WHERE review_status = 'approved'"
        ).fetchone()[0]

    assert reviewed_row["stem_text"] == "human reviewed stem"
    assert reviewed_row["stem_latex"] == "human reviewed latex"
    assert reviewed_row["review_status"] == "reviewed"
    assert json.loads(reviewed_row["meta_json"]) == {"manual_review": True}
    assert approved_count == 0
