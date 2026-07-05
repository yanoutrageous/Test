from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from app.cli import main
from app.database import connect_database, initialize_database
from app.structured_content import initialize_structured_contents
from app.structured_validation import validate_structured_contents


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
        ("PDF-VALIDATE", "Validation Paper", "Base/sample.pdf", 1, "born_digital", "{}"),
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
            "Validation Paper",
            question_no,
            question_type,
            stem_text,
            stem_text,
            "[]",
            "[]",
            "p0001",
            "{}",
            "pending",
            json.dumps({"source_page": 1}),
            f"hash-{qid}",
        ),
    )
    return int(cursor.lastrowid)


def _set_draft(
    conn: sqlite3.Connection,
    question_id: int,
    *,
    normalized_type: str,
    stem_latex: str,
    options: list | dict | None = None,
    blanks: list | dict | None = None,
    subquestions: list | dict | None = None,
) -> None:
    conn.execute(
        """
        UPDATE question_structured_contents
           SET normalized_type = ?,
               stem_latex = ?,
               options_json = ?,
               blanks_json = ?,
               subquestions_json = ?,
               ai_status = 'ai_draft',
               quality_flags_json = '[]',
               model_info = '{}'
         WHERE question_id = ?
        """,
        (
            normalized_type,
            stem_latex,
            json.dumps([] if options is None else options, ensure_ascii=False),
            json.dumps([] if blanks is None else blanks, ensure_ascii=False),
            json.dumps([] if subquestions is None else subquestions, ensure_ascii=False),
            question_id,
        ),
    )


def _prepare_validation_db(tmp_path: Path) -> tuple[Path, dict[str, int]]:
    db_path = tmp_path / "question_bank.sqlite3"
    initialize_database(db_path)
    ids: dict[str, int] = {}
    with connect_database(db_path) as conn:
        source_paper_id = _insert_source_paper(conn)
        ids["choice"] = _insert_question(
            conn,
            source_paper_id,
            qid="PDF-VALIDATE-Q001",
            question_no="1",
            question_type="选择题",
            stem_text="1. Choose 2+2=4 with enough text",
        )
        ids["blank"] = _insert_question(
            conn,
            source_paper_id,
            qid="PDF-VALIDATE-Q002",
            question_no="2",
            question_type="填空题",
            stem_text="2. Fill 5 into the expression with enough text",
        )
        ids["solution"] = _insert_question(
            conn,
            source_paper_id,
            qid="PDF-VALIDATE-Q003",
            question_no="3",
            question_type="解答题",
            stem_text="3. Solve the problem. (1) prove the result with enough text",
        )
        ids["unknown"] = _insert_question(
            conn,
            source_paper_id,
            qid="PDF-VALIDATE-Q004",
            question_no="4",
            question_type=None,
            stem_text="4. Unknown type with enough text",
        )
        ids["malformed"] = _insert_question(
            conn,
            source_paper_id,
            qid="PDF-VALIDATE-Q005",
            question_no="5",
            question_type="选择题",
            stem_text="5. Malformed options with enough text",
        )
        ids["latex_risk"] = _insert_question(
            conn,
            source_paper_id,
            qid="PDF-VALIDATE-Q006",
            question_no="6",
            question_type="选择题",
            stem_text="6. Risky math has x2 and log20.2 with enough text",
        )
        conn.commit()

    initialize_structured_contents(db_path=db_path)
    with connect_database(db_path) as conn:
        options = [
            {"label": "A", "text_latex": "1"},
            {"label": "B", "text_latex": "2"},
            {"label": "C", "text_latex": "3"},
            {"label": "D", "text_latex": "4"},
        ]
        _set_draft(
            conn,
            ids["choice"],
            normalized_type="choice",
            stem_latex="1. Choose 2+2=4 with enough text",
            options=options,
        )
        _set_draft(
            conn,
            ids["blank"],
            normalized_type="blank",
            stem_latex="2. Fill 5 into the expression with enough text",
            blanks=[],
        )
        _set_draft(
            conn,
            ids["solution"],
            normalized_type="solution",
            stem_latex="3. Solve the problem. (1) prove the result with enough text",
            subquestions=[
                {
                    "index": 1,
                    "stem_latex": "prove the result",
                    "answer_latex": "",
                }
            ],
        )
        _set_draft(
            conn,
            ids["unknown"],
            normalized_type="unknown",
            stem_latex="4. Unknown type with enough text",
        )
        _set_draft(
            conn,
            ids["malformed"],
            normalized_type="choice",
            stem_latex="5. Malformed options with enough text",
            options={},
        )
        _set_draft(
            conn,
            ids["latex_risk"],
            normalized_type="choice",
            stem_latex=(
                "6. Risky math has x2, log20.2, x\\frac{2}{6}, "
                "\\pi 2, \\sqrt{5} 5, \\sqrt{M}\\frac{2}{2}, "
                "\\frac{100}{0}, \uf8f1 \uf8f2 \uf8f3, \u00afz, 255\u25e6 and # \u00bb AB"
            ),
            options=options,
        )
        conn.commit()
    return db_path, ids


def test_validate_structured_contents_updates_expected_statuses(tmp_path: Path) -> None:
    db_path, ids = _prepare_validation_db(tmp_path)

    result = validate_structured_contents(db_path=db_path, limit=10)

    assert result["validated"] == 6
    assert result["status_counts"] == {
        "ai_verified": 2,
        "failed": 1,
        "needs_review": 3,
    }
    with connect_database(db_path) as conn:
        statuses = {
            row["question_id"]: (row["ai_status"], json.loads(row["quality_flags_json"]))
            for row in conn.execute(
                """
                SELECT question_id, ai_status, quality_flags_json
                  FROM question_structured_contents
                """
            ).fetchall()
        }
        approved_count = conn.execute(
            "SELECT count(*) FROM questions WHERE review_status = 'approved'"
        ).fetchone()[0]

    assert statuses[ids["choice"]][0] == "ai_verified"
    assert statuses[ids["solution"]][0] == "ai_verified"
    assert statuses[ids["blank"]][0] == "needs_review"
    assert "blank_missing_placeholder" in statuses[ids["blank"]][1]
    assert statuses[ids["unknown"]][0] == "needs_review"
    assert "unknown_question_type" in statuses[ids["unknown"]][1]
    assert statuses[ids["malformed"]][0] == "failed"
    assert "options_json_not_list" in statuses[ids["malformed"]][1]
    assert statuses[ids["latex_risk"]][0] == "needs_review"
    assert "latex_implicit_exponent_unconverted" in statuses[ids["latex_risk"]][1]
    assert "latex_ambiguous_decimal_or_log" in statuses[ids["latex_risk"]][1]
    assert "latex_fraction_after_variable_suspicious" in statuses[ids["latex_risk"]][1]
    assert "latex_pi_trailing_number_suspicious" in statuses[ids["latex_risk"]][1]
    assert "latex_private_use_piecewise_symbol" in statuses[ids["latex_risk"]][1]
    assert "latex_sqrt_fraction_split_suspicious" in statuses[ids["latex_risk"]][1]
    assert "latex_sqrt_trailing_number_suspicious" in statuses[ids["latex_risk"]][1]
    assert "latex_unconverted_overline_symbol" in statuses[ids["latex_risk"]][1]
    assert "latex_unconverted_degree_symbol" in statuses[ids["latex_risk"]][1]
    assert "latex_garbled_geometry_symbol" in statuses[ids["latex_risk"]][1]
    assert "latex_zero_denominator_suspicious" in statuses[ids["latex_risk"]][1]
    assert approved_count == 0


def test_validate_structured_content_cli(tmp_path: Path) -> None:
    db_path, ids = _prepare_validation_db(tmp_path)

    assert main(["validate-structured-content", "--db-path", str(db_path), "--limit", "1"]) == 0

    with connect_database(db_path) as conn:
        row = conn.execute(
            "SELECT ai_status FROM question_structured_contents WHERE question_id = ?",
            (ids["choice"],),
        ).fetchone()
    assert row["ai_status"] == "ai_verified"


def test_revalidating_ai_verified_downgrades_audit_risks(tmp_path: Path) -> None:
    db_path, ids = _prepare_validation_db(tmp_path)
    with connect_database(db_path) as conn:
        conn.execute(
            """
            UPDATE question_structured_contents
               SET ai_status = 'ai_verified',
                   stem_latex = ?,
                   options_json = ?,
                   quality_flags_json = '[]'
             WHERE question_id = ?
            """,
            (
                (
                    "1. x\\frac{2}{6} plus \\pi 2 and \\sqrt{5} 5 "
                    "with \\sqrt{M}\\frac{2}{2}, \\frac{100}{0}, "
                    "\uf8f1 \uf8f2 \uf8f3 and # \u00bb AB"
                ),
                json.dumps(
                    [
                        {"label": "A", "text_latex": "1"},
                        {"label": "B", "text_latex": "2"},
                        {"label": "C", "text_latex": "3"},
                        {"label": "D", "text_latex": "4"},
                    ],
                    ensure_ascii=False,
                ),
                ids["choice"],
            ),
        )
        conn.execute(
            """
            UPDATE question_structured_contents
               SET ai_status = 'ai_verified',
                   blanks_json = ?,
                   quality_flags_json = ?
             WHERE question_id = ?
            """,
            (
                json.dumps([{"index": 1, "placeholder_latex": "\\underline{\\hspace{3em}}"}]),
                json.dumps(["blank_placeholder_inferred"]),
                ids["blank"],
            ),
        )
        conn.commit()

    result = validate_structured_contents(
        db_path=db_path,
        statuses=("ai_verified",),
        limit=10,
    )

    assert result["validated"] == 2
    assert result["status_counts"] == {"needs_review": 2}
    with connect_database(db_path) as conn:
        rows = {
            row["question_id"]: (row["ai_status"], json.loads(row["quality_flags_json"]))
            for row in conn.execute(
                """
                SELECT question_id, ai_status, quality_flags_json
                  FROM question_structured_contents
                 WHERE question_id IN (?, ?)
                """,
                (ids["choice"], ids["blank"]),
            ).fetchall()
        }

    assert rows[ids["choice"]][0] == "needs_review"
    assert "latex_fraction_after_variable_suspicious" in rows[ids["choice"]][1]
    assert "latex_pi_trailing_number_suspicious" in rows[ids["choice"]][1]
    assert "latex_private_use_piecewise_symbol" in rows[ids["choice"]][1]
    assert "latex_sqrt_fraction_split_suspicious" in rows[ids["choice"]][1]
    assert "latex_sqrt_trailing_number_suspicious" in rows[ids["choice"]][1]
    assert "latex_garbled_geometry_symbol" in rows[ids["choice"]][1]
    assert "latex_zero_denominator_suspicious" in rows[ids["choice"]][1]
    assert rows[ids["blank"]][0] == "needs_review"
    assert "blank_placeholder_inferred" in rows[ids["blank"]][1]
