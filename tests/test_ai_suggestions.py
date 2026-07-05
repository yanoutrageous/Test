from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from app.ai_suggestions import (
    AiSuggestionError,
    accept_ai_suggestion,
    generate_ai_suggestions,
    reject_ai_suggestion,
)
from app.cli import main
from app.database import connect_database, initialize_database
from app.web import create_app


def _create_project(tmp_path: Path) -> tuple[Path, Path]:
    project_root = tmp_path / "project"
    (project_root / "Base").mkdir(parents=True)
    (project_root / "Base" / "sample.pdf").write_bytes(b"%PDF-1.4\n")
    db_path = project_root / "data" / "db" / "question_bank.sqlite3"
    initialize_database(db_path)
    return project_root, db_path


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
        ("PDF-AI-TEST", "AI Test Paper", "Base/sample.pdf", 1, "born_digital", "{}"),
    )
    return int(cursor.lastrowid)


def _insert_question(
    conn: sqlite3.Connection,
    source_paper_id: int,
    *,
    qid: str = "AI-Q001",
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
            "AI Test Paper",
            "1",
            None,
            "ai latex",
            "stage7 ai suggestion stem",
            "[]",
            "[]",
            "p0001",
            json.dumps({"page": 1, "x0": 10, "y0": 20, "x1": 110, "y1": 90}),
            review_status,
            json.dumps({"source_page": 1}),
            f"hash-{qid}",
        ),
    )
    return int(cursor.lastrowid)


def _prepare_question(tmp_path: Path, *, review_status: str = "pending") -> tuple[Path, Path, int]:
    project_root, db_path = _create_project(tmp_path)
    with connect_database(db_path) as conn:
        source_paper_id = _insert_source_paper(conn)
        question_id = _insert_question(conn, source_paper_id, review_status=review_status)
        conn.commit()
    return project_root, db_path, question_id


def test_ai_suggest_without_configuration_skips_and_writes_nothing(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _project_root, db_path, _question_id = _prepare_question(tmp_path)

    result = generate_ai_suggestions(db_path=db_path)
    exit_code = main(["ai-suggest", "--db-path", str(db_path)])
    output = capsys.readouterr().out

    assert result["status"] == "skipped"
    assert result["inserted"] == 0
    assert exit_code == 0
    assert '"status": "skipped"' in output
    with connect_database(db_path) as conn:
        assert conn.execute("SELECT count(*) FROM question_ai_suggestions").fetchone()[0] == 0


def test_mock_suggestion_accept_updates_question_and_writes_review_event(tmp_path: Path) -> None:
    _project_root, db_path, question_id = _prepare_question(tmp_path)
    result = generate_ai_suggestions(
        db_path=db_path,
        question_ids=(question_id,),
        mock=True,
    )
    suggestion_id = result["suggestions"][0]["id"]

    accepted = accept_ai_suggestion(suggestion_id, db_path=db_path)

    assert accepted["status"] == "accepted"
    with connect_database(db_path) as conn:
        question = conn.execute(
            "SELECT tags_json FROM questions WHERE id = ?",
            (question_id,),
        ).fetchone()
        suggestion = conn.execute(
            "SELECT status, reviewed_at FROM question_ai_suggestions WHERE id = ?",
            (suggestion_id,),
        ).fetchone()
        event = conn.execute(
            """
            SELECT event_type, source, diff_json
              FROM question_review_events
             WHERE question_id = ?
            """,
            (question_id,),
        ).fetchone()

    assert "ai_mock_suggestion" in json.loads(question["tags_json"])
    assert suggestion["status"] == "accepted"
    assert suggestion["reviewed_at"] is not None
    assert event["event_type"] == "ai_suggestion_accept"
    assert event["source"] == f"ai_suggestion:{suggestion_id}"
    assert "tags_json" in json.loads(event["diff_json"])


def test_reject_suggestion_does_not_modify_question(tmp_path: Path) -> None:
    _project_root, db_path, question_id = _prepare_question(tmp_path)
    result = generate_ai_suggestions(
        db_path=db_path,
        question_ids=(question_id,),
        mock=True,
    )
    suggestion_id = result["suggestions"][0]["id"]
    with connect_database(db_path) as conn:
        before = dict(
            conn.execute(
                "SELECT tags_json, question_type FROM questions WHERE id = ?",
                (question_id,),
            ).fetchone()
        )

    rejected = reject_ai_suggestion(suggestion_id, db_path=db_path)

    with connect_database(db_path) as conn:
        after = dict(
            conn.execute(
                "SELECT tags_json, question_type FROM questions WHERE id = ?",
                (question_id,),
            ).fetchone()
        )
        suggestion = conn.execute(
            "SELECT status, reviewed_at FROM question_ai_suggestions WHERE id = ?",
            (suggestion_id,),
        ).fetchone()
        event_count = conn.execute(
            "SELECT count(*) FROM question_review_events WHERE question_id = ?",
            (question_id,),
        ).fetchone()[0]

    assert rejected["status"] == "rejected"
    assert after == before
    assert suggestion["status"] == "rejected"
    assert suggestion["reviewed_at"] is not None
    assert event_count == 0


def test_accept_suggestion_does_not_overwrite_reviewed_question(tmp_path: Path) -> None:
    _project_root, db_path, question_id = _prepare_question(tmp_path, review_status="reviewed")
    result = generate_ai_suggestions(
        db_path=db_path,
        question_ids=(question_id,),
        mock=True,
    )
    suggestion_id = result["suggestions"][0]["id"]

    with pytest.raises(AiSuggestionError, match="reviewed or approved"):
        accept_ai_suggestion(suggestion_id, db_path=db_path)

    with connect_database(db_path) as conn:
        question = conn.execute(
            "SELECT tags_json, review_status FROM questions WHERE id = ?",
            (question_id,),
        ).fetchone()
        suggestion = conn.execute(
            "SELECT status FROM question_ai_suggestions WHERE id = ?",
            (suggestion_id,),
        ).fetchone()
        event_count = conn.execute(
            "SELECT count(*) FROM question_review_events WHERE question_id = ?",
            (question_id,),
        ).fetchone()[0]

    assert json.loads(question["tags_json"]) == []
    assert question["review_status"] == "reviewed"
    assert suggestion["status"] == "pending"
    assert event_count == 0


def test_web_displays_and_rejects_ai_suggestion_without_question_update(tmp_path: Path) -> None:
    project_root, db_path, question_id = _prepare_question(tmp_path)
    result = generate_ai_suggestions(
        db_path=db_path,
        question_ids=(question_id,),
        mock=True,
    )
    suggestion_id = result["suggestions"][0]["id"]
    app = create_app(db_path=db_path, project_root=project_root)
    app.config.update(TESTING=True)
    client = app.test_client()

    detail = client.get(f"/questions/{question_id}")
    rejected = client.post(f"/questions/{question_id}/ai-suggestions/{suggestion_id}/reject")

    assert detail.status_code == 200
    text = detail.get_data(as_text=True)
    assert "AI Suggestions" in text
    assert "mock_review" in text
    assert rejected.status_code == 302
    with connect_database(db_path) as conn:
        question = conn.execute(
            "SELECT tags_json FROM questions WHERE id = ?",
            (question_id,),
        ).fetchone()
        suggestion = conn.execute(
            "SELECT status FROM question_ai_suggestions WHERE id = ?",
            (suggestion_id,),
        ).fetchone()
    assert json.loads(question["tags_json"]) == []
    assert suggestion["status"] == "rejected"


def test_web_accepts_ai_suggestion_and_writes_review_event(tmp_path: Path) -> None:
    project_root, db_path, question_id = _prepare_question(tmp_path)
    result = generate_ai_suggestions(
        db_path=db_path,
        question_ids=(question_id,),
        mock=True,
    )
    suggestion_id = result["suggestions"][0]["id"]
    app = create_app(db_path=db_path, project_root=project_root)
    app.config.update(TESTING=True)
    client = app.test_client()

    response = client.post(f"/questions/{question_id}/ai-suggestions/{suggestion_id}/accept")

    assert response.status_code == 302
    with connect_database(db_path) as conn:
        question = conn.execute(
            "SELECT tags_json FROM questions WHERE id = ?",
            (question_id,),
        ).fetchone()
        suggestion = conn.execute(
            "SELECT status FROM question_ai_suggestions WHERE id = ?",
            (suggestion_id,),
        ).fetchone()
        event = conn.execute(
            "SELECT event_type FROM question_review_events WHERE question_id = ?",
            (question_id,),
        ).fetchone()
    assert "ai_mock_suggestion" in json.loads(question["tags_json"])
    assert suggestion["status"] == "accepted"
    assert event["event_type"] == "ai_suggestion_accept"
