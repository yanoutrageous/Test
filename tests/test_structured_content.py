from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from app.cli import main
from app.database import connect_database, initialize_database
from app.structured_content import (
    get_structured_content,
    initialize_structured_contents,
    normalize_question_type,
    summarize_structured_contents,
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
        ("PDF-STRUCTURED", "Structured Paper", "Base/sample.pdf", 1, "born_digital", "{}"),
    )
    return int(cursor.lastrowid)


def _insert_question(
    conn: sqlite3.Connection,
    source_paper_id: int,
    *,
    qid: str,
    question_type: str | None,
    stem_text: str,
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
            "Structured Paper",
            qid.rsplit("Q", 1)[-1],
            question_type,
            f"{stem_text} latex",
            stem_text,
            "[]",
            "[]",
            "p0001",
            json.dumps({"page": 1}),
            review_status,
            json.dumps({"source_page": 1}),
            f"hash-{qid}",
        ),
    )
    return int(cursor.lastrowid)


def test_normalize_question_type() -> None:
    assert normalize_question_type("选择题") == "choice"
    assert normalize_question_type("多选题") == "multiple_choice"
    assert normalize_question_type("填空题") == "blank"
    assert normalize_question_type("解答题") == "solution"
    assert normalize_question_type(None) == "unknown"


def test_initialize_structured_contents_is_idempotent_and_preserves_questions(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "question_bank.sqlite3"
    initialize_database(db_path)

    with connect_database(db_path) as conn:
        source_paper_id = _insert_source_paper(conn)
        choice_id = _insert_question(
            conn,
            source_paper_id,
            qid="PDF-STRUCTURED-Q001",
            question_type="选择题",
            stem_text="choice source text",
        )
        _insert_question(
            conn,
            source_paper_id,
            qid="PDF-STRUCTURED-Q002",
            question_type=None,
            stem_text="unknown source text",
            review_status="reviewed",
        )
        conn.commit()
        before = [
            dict(row)
            for row in conn.execute(
                "SELECT id, stem_text, stem_latex, review_status, updated_at FROM questions ORDER BY id"
            ).fetchall()
        ]

    first = initialize_structured_contents(db_path=db_path)
    second = initialize_structured_contents(db_path=db_path)
    summary = summarize_structured_contents(db_path=db_path)

    assert first["question_count"] == 2
    assert first["inserted"] == 2
    assert first["total_structured"] == 2
    assert first["missing_structured"] == 0
    assert first["status_distribution"] == {"unprocessed": 2}
    assert second["inserted"] == 0
    assert summary["type_distribution"] == {"choice": 1, "unknown": 1}

    structured = get_structured_content(choice_id, db_path=db_path)
    assert structured is not None
    assert structured["source_text"] == "choice source text"
    assert structured["source_latex"] == "choice source text latex"
    assert structured["stem_latex"] == "choice source text latex"
    assert structured["normalized_type"] == "choice"
    assert structured["ai_status"] == "unprocessed"
    assert json.loads(structured["options_json"]) == []
    assert json.loads(structured["quality_flags_json"]) == []

    with connect_database(db_path) as conn:
        after = [
            dict(row)
            for row in conn.execute(
                "SELECT id, stem_text, stem_latex, review_status, updated_at FROM questions ORDER BY id"
            ).fetchall()
        ]
    assert after == before


def test_structured_content_cascades_and_rejects_invalid_status(tmp_path: Path) -> None:
    db_path = tmp_path / "question_bank.sqlite3"
    initialize_database(db_path)

    with connect_database(db_path) as conn:
        source_paper_id = _insert_source_paper(conn)
        question_id = _insert_question(
            conn,
            source_paper_id,
            qid="PDF-STRUCTURED-Q003",
            question_type="填空题",
            stem_text="blank source text",
        )
        conn.commit()

    initialize_structured_contents(db_path=db_path)

    with connect_database(db_path) as conn:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                """
                UPDATE question_structured_contents
                   SET ai_status = 'approved'
                 WHERE question_id = ?
                """,
                (question_id,),
            )

        conn.execute("DELETE FROM questions WHERE id = ?", (question_id,))
        conn.commit()
        assert conn.execute(
            "SELECT count(*) FROM question_structured_contents"
        ).fetchone()[0] == 0


def test_cli_initializes_structured_content(tmp_path: Path) -> None:
    db_path = tmp_path / "question_bank.sqlite3"
    initialize_database(db_path)
    with connect_database(db_path) as conn:
        source_paper_id = _insert_source_paper(conn)
        _insert_question(
            conn,
            source_paper_id,
            qid="PDF-STRUCTURED-Q004",
            question_type="解答题",
            stem_text="solution source text",
        )
        conn.commit()

    assert main(["init-structured-content", "--db-path", str(db_path)]) == 0
    assert main(["structured-status", "--db-path", str(db_path)]) == 0
    with connect_database(db_path) as conn:
        row = conn.execute(
            "SELECT normalized_type, ai_status FROM question_structured_contents"
        ).fetchone()
    assert row["normalized_type"] == "solution"
    assert row["ai_status"] == "unprocessed"
