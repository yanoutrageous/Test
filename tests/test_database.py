from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from app.database import connect_database, initialize_database, list_schema_objects


def _insert_source_paper(conn: sqlite3.Connection) -> int:
    cursor = conn.execute(
        """
        INSERT INTO source_papers (
            paper_code,
            title,
            year,
            subject,
            source_path,
            page_count,
            import_mode,
            meta_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "SAMPLE-PAPER",
            "Sample Paper",
            2024,
            "math",
            "Base/sample.pdf",
            1,
            "manual",
            json.dumps({"stage": 2}),
        ),
    )
    return int(cursor.lastrowid)


def _insert_question(conn: sqlite3.Connection, source_paper_id: int) -> int:
    cursor = conn.execute(
        """
        INSERT INTO questions (
            qid,
            source_paper_id,
            language_code,
            subject,
            year,
            paper_name,
            question_no,
            question_type,
            stem_latex,
            stem_text,
            answer_text,
            analysis_latex,
            tags_json,
            image_refs_json,
            raw_crop_path,
            bbox_json,
            meta_json,
            content_hash
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "SAMPLE-Q001",
            source_paper_id,
            "zh-CN",
            "math",
            2024,
            "Sample Paper",
            "1",
            "calculation",
            "alpha polynomial",
            "alpha polynomial question",
            "answer alpha",
            "analysis alpha",
            json.dumps(["algebra", "polynomial"]),
            json.dumps(["assets/question_images/SAMPLE/Q001/raw.png"]),
            "assets/question_images/SAMPLE/Q001/raw.png",
            json.dumps({"page": 1}),
            json.dumps({"fixture": True}),
            "sample-content-hash",
        ),
    )
    return int(cursor.lastrowid)


def _search_terms(conn: sqlite3.Connection, term: str) -> list[str]:
    return [
        row["qid"]
        for row in conn.execute(
            "SELECT qid FROM question_fts WHERE question_fts MATCH ? ORDER BY rowid",
            (term,),
        ).fetchall()
    ]


def test_initialize_database_is_idempotent(tmp_path: Path) -> None:
    db_path = tmp_path / "question_bank.sqlite3"

    first = initialize_database(db_path)
    second = initialize_database(db_path)

    assert Path(first["db_path"]) == db_path
    assert first["created"] is True
    assert second["created"] is False
    assert second["existed_before"] is True
    assert db_path.exists()


def test_schema_contains_core_tables_indexes_and_triggers(tmp_path: Path) -> None:
    db_path = tmp_path / "question_bank.sqlite3"
    initialize_database(db_path)

    objects = list_schema_objects(db_path)

    for table in (
        "source_papers",
        "questions",
        "question_assets",
        "source_paper_assets",
        "question_review_events",
        "question_ai_suggestions",
        "question_structured_contents",
        "question_usability_states",
        "question_export_quality",
        "question_source_attributions",
        "import_batches",
        "import_batch_pages",
        "question_search_content",
        "question_fts",
    ):
        assert table in objects["table"]

    for trigger in ("trg_questions_ai", "trg_questions_au", "trg_questions_ad"):
        assert trigger in objects["trigger"]

    assert "idx_questions_year" in objects["index"]
    assert "idx_question_assets_question" in objects["index"]
    assert "idx_question_assets_unique_raw_crop" in objects["index"]
    assert "idx_question_review_events_question" in objects["index"]
    assert "idx_question_review_events_type" in objects["index"]
    assert "idx_question_review_events_created" in objects["index"]
    assert "idx_question_ai_suggestions_question" in objects["index"]
    assert "idx_question_ai_suggestions_status" in objects["index"]
    assert "idx_question_ai_suggestions_type" in objects["index"]
    assert "idx_question_structured_contents_question" in objects["index"]
    assert "idx_question_structured_contents_status" in objects["index"]
    assert "idx_question_structured_contents_type" in objects["index"]
    assert "idx_question_usability_states_question" in objects["index"]
    assert "idx_question_usability_states_status" in objects["index"]
    assert "idx_question_usability_states_render_mode" in objects["index"]
    assert "idx_question_usability_states_export_eligible" in objects["index"]
    assert "idx_question_usability_states_primary_issue" in objects["index"]
    assert "idx_question_export_quality_question" in objects["index"]
    assert "idx_question_export_quality_status" in objects["index"]
    assert "idx_question_export_quality_render_mode" in objects["index"]
    assert "idx_question_export_quality_export_eligible" in objects["index"]
    assert "idx_question_export_quality_source_usability" in objects["index"]
    assert "idx_question_source_attributions_question" in objects["index"]
    assert "idx_question_source_attributions_year" in objects["index"]
    assert "idx_question_source_attributions_confidence" in objects["index"]
    assert "idx_question_source_attributions_source_page" in objects["index"]
    assert "idx_question_source_attributions_paper_name" in objects["index"]
    assert "idx_question_source_attributions_question_no" in objects["index"]
    assert "idx_import_batches_status" in objects["index"]
    assert "idx_import_batches_kind" in objects["index"]
    assert "idx_import_batches_source" in objects["index"]
    assert "idx_import_batch_pages_batch" in objects["index"]
    assert "idx_import_batch_pages_page" in objects["index"]
    assert "idx_import_batch_pages_status" in objects["index"]
    assert "idx_source_paper_assets_source" in objects["index"]
    assert "idx_source_paper_assets_kind" in objects["index"]
    assert "idx_source_paper_assets_page" in objects["index"]
    assert "idx_source_paper_assets_unique_page" in objects["index"]


def test_schema_does_not_define_blob_columns(tmp_path: Path) -> None:
    db_path = tmp_path / "question_bank.sqlite3"
    initialize_database(db_path)

    with connect_database(db_path) as conn:
        for table in (
            "source_papers",
            "questions",
            "question_assets",
            "source_paper_assets",
            "question_review_events",
            "question_ai_suggestions",
            "question_structured_contents",
            "question_usability_states",
            "question_export_quality",
            "question_source_attributions",
            "import_batches",
            "import_batch_pages",
        ):
            columns = conn.execute(f"PRAGMA table_info({table})").fetchall()
            for column in columns:
                assert "BLOB" not in column["type"].upper()


def test_question_crud_synchronizes_fts_and_assets(tmp_path: Path) -> None:
    db_path = tmp_path / "question_bank.sqlite3"
    initialize_database(db_path)

    with connect_database(db_path) as conn:
        source_paper_id = _insert_source_paper(conn)
        question_id = _insert_question(conn, source_paper_id)
        conn.execute(
            """
            INSERT INTO question_assets (
                question_id,
                asset_kind,
                relative_path,
                page_no,
                bbox_json
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                question_id,
                "raw_crop",
                "assets/question_images/SAMPLE/Q001/raw.png",
                1,
                json.dumps({"x0": 0, "y0": 0, "x1": 10, "y1": 10}),
            ),
        )
        conn.commit()

        assert _search_terms(conn, "alpha") == ["SAMPLE-Q001"]
        assert conn.execute("SELECT count(*) FROM question_search_content").fetchone()[0] == 1
        assert conn.execute("SELECT count(*) FROM question_assets").fetchone()[0] == 1

        conn.execute(
            """
            UPDATE questions
               SET stem_text = ?,
                   answer_text = ?,
                   analysis_latex = ?,
                   tags_json = ?,
                   updated_at = CURRENT_TIMESTAMP
             WHERE id = ?
            """,
            (
                "gamma integral question",
                "answer gamma",
                "analysis gamma",
                json.dumps(["calculus", "integral"]),
                question_id,
            ),
        )
        conn.commit()

        assert _search_terms(conn, "gamma") == ["SAMPLE-Q001"]
        assert _search_terms(conn, "alpha") == []

        conn.execute("DELETE FROM questions WHERE id = ?", (question_id,))
        conn.commit()

        assert _search_terms(conn, "gamma") == []
        assert conn.execute("SELECT count(*) FROM question_search_content").fetchone()[0] == 0
        assert conn.execute("SELECT count(*) FROM question_assets").fetchone()[0] == 0


def test_asset_paths_must_be_relative(tmp_path: Path) -> None:
    db_path = tmp_path / "question_bank.sqlite3"
    initialize_database(db_path)

    with connect_database(db_path) as conn:
        source_paper_id = _insert_source_paper(conn)
        question_id = _insert_question(conn, source_paper_id)

        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                """
                INSERT INTO question_assets (
                    question_id,
                    asset_kind,
                    relative_path
                ) VALUES (?, ?, ?)
                """,
                (question_id, "raw_crop", "C:/absolute/raw.png"),
            )


def test_question_assets_allows_only_one_raw_crop_per_question(tmp_path: Path) -> None:
    db_path = tmp_path / "question_bank.sqlite3"
    initialize_database(db_path)

    with connect_database(db_path) as conn:
        source_paper_id = _insert_source_paper(conn)
        question_id = _insert_question(conn, source_paper_id)
        conn.execute(
            """
            INSERT INTO question_assets (
                question_id,
                asset_kind,
                relative_path
            ) VALUES (?, ?, ?)
            """,
            (question_id, "raw_crop", "assets/question_images/SAMPLE/Q001/raw.png"),
        )

        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                """
                INSERT INTO question_assets (
                    question_id,
                    asset_kind,
                    relative_path
                ) VALUES (?, ?, ?)
                """,
                (
                    question_id,
                    "raw_crop",
                    "assets/question_images/SAMPLE/Q001/raw_again.png",
                ),
            )

        conn.execute(
            """
            INSERT INTO question_assets (
                question_id,
                asset_kind,
                relative_path
            ) VALUES (?, ?, ?)
            """,
            (question_id, "figure", "assets/question_images/SAMPLE/Q001/figure.png"),
        )


def test_source_paper_assets_insert_and_cascade_delete(tmp_path: Path) -> None:
    db_path = tmp_path / "question_bank.sqlite3"
    initialize_database(db_path)

    with connect_database(db_path) as conn:
        source_paper_id = _insert_source_paper(conn)
        conn.execute(
            """
            INSERT INTO source_paper_assets (
                source_paper_id,
                asset_kind,
                relative_path,
                page_no,
                bbox_json,
                meta_json
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                source_paper_id,
                "page_image",
                "assets/paper_pages/SAMPLE/page_0001.png",
                1,
                json.dumps({"page": 1}),
                json.dumps({"dpi": 200}),
            ),
        )
        conn.commit()

        assert conn.execute("SELECT count(*) FROM source_paper_assets").fetchone()[0] == 1

        conn.execute("DELETE FROM source_papers WHERE id = ?", (source_paper_id,))
        conn.commit()

        assert conn.execute("SELECT count(*) FROM source_paper_assets").fetchone()[0] == 0


def test_source_paper_assets_reject_absolute_paths(tmp_path: Path) -> None:
    db_path = tmp_path / "question_bank.sqlite3"
    initialize_database(db_path)

    with connect_database(db_path) as conn:
        source_paper_id = _insert_source_paper(conn)

        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                """
                INSERT INTO source_paper_assets (
                    source_paper_id,
                    asset_kind,
                    relative_path,
                    page_no
                ) VALUES (?, ?, ?, ?)
                """,
                (source_paper_id, "page_image", "C:/absolute/page_0001.png", 1),
            )
