from __future__ import annotations

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import sqlite3
import threading
from pathlib import Path
from typing import Any

import pytest

from app.cli import main
from app.database import connect_database, initialize_database
from app.structured_ai import (
    ENV_BASE_URL,
    ENV_INCLUDE_IMAGES,
    ENV_MODEL,
    ENV_PROVIDER,
    ENV_TIMEOUT,
    LOCAL_OPENAI_PROVIDER,
    StructuredAiError,
    get_structured_ai_provider_status,
    run_structured_ai_corrections,
    validate_ai_output_payload,
)
from app.structured_content import initialize_structured_contents


@pytest.fixture(autouse=True)
def _clear_structured_ai_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (ENV_PROVIDER, ENV_BASE_URL, ENV_MODEL, ENV_TIMEOUT, ENV_INCLUDE_IMAGES):
        monkeypatch.delenv(name, raising=False)


@contextmanager
def _local_openai_server(response_payload: dict[str, Any]):
    requests: list[dict[str, Any]] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length).decode("utf-8")
            requests.append(json.loads(body))
            response = {
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(response_payload, ensure_ascii=False)
                        }
                    }
                ]
            }
            data = json.dumps(response).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, format: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        yield f"http://{host}:{port}/v1", requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


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
        ("PDF-AI", "AI Paper", "Base/sample.pdf", 1, "born_digital", "{}"),
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
            "PDF-AI-Q001",
            source_paper_id,
            "AI Paper",
            "1",
            "选择题",
            "AI source latex",
            "AI source text",
            "[]",
            "[]",
            "p0001",
            json.dumps({"page": 1, "x0": 10, "y0": 20, "x1": 100, "y1": 80}),
            "pending",
            json.dumps({"source_page": 1}),
            "hash-ai-q001",
        ),
    )
    return int(cursor.lastrowid)


def _prepare_db(tmp_path: Path) -> tuple[Path, int]:
    db_path = tmp_path / "question_bank.sqlite3"
    initialize_database(db_path)
    with connect_database(db_path) as conn:
        source_paper_id = _insert_source_paper(conn)
        question_id = _insert_question(conn, source_paper_id)
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
                "data/assets/paper_pages/PDF-AI/page_0001.png",
                1,
                "{}",
                "{}",
            ),
        )
        conn.execute(
            """
            INSERT INTO question_assets (
                question_id,
                asset_kind,
                relative_path,
                page_no,
                bbox_json,
                meta_json
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                question_id,
                "raw_crop",
                "data/assets/question_images/PDF-AI/Q001.png",
                1,
                "{}",
                "{}",
            ),
        )
        conn.commit()
    initialize_structured_contents(db_path=db_path)
    return db_path, question_id


def test_unconfigured_provider_marks_unavailable_without_drafting(tmp_path: Path) -> None:
    db_path, question_id = _prepare_db(tmp_path)

    result = run_structured_ai_corrections(db_path=db_path, limit=1)

    assert result["status"] == "skipped"
    assert result["updated_unavailable"] == 1
    assert result["drafted"] == 0
    with connect_database(db_path) as conn:
        row = conn.execute(
            """
            SELECT ai_status, quality_flags_json, model_info, stem_latex
              FROM question_structured_contents
             WHERE question_id = ?
            """,
            (question_id,),
        ).fetchone()
    assert row["ai_status"] == "unprocessed"
    assert json.loads(row["quality_flags_json"]) == ["ai_provider_unavailable"]
    assert json.loads(row["model_info"])["last_ai_attempt"]["status"] == "unavailable"
    assert row["stem_latex"] == "AI source latex"


def test_provider_config_status_reports_unconfigured() -> None:
    status = get_structured_ai_provider_status()

    assert status["configured"] is False
    assert status["provider"] == "unconfigured"
    assert status["local_only"] is True


def test_ai_structure_config_cli_reports_status() -> None:
    assert main(["ai-structure-config"]) == 0


def test_mock_provider_requires_explicit_non_default_db() -> None:
    with pytest.raises(StructuredAiError, match="explicit --db-path"):
        run_structured_ai_corrections(mock=True)


def test_mock_provider_writes_ai_draft_to_temp_db_only(tmp_path: Path) -> None:
    db_path, question_id = _prepare_db(tmp_path)
    with connect_database(db_path) as conn:
        before_question = dict(
            conn.execute(
                "SELECT stem_text, stem_latex, review_status, updated_at FROM questions WHERE id = ?",
                (question_id,),
            ).fetchone()
        )

    result = run_structured_ai_corrections(
        db_path=db_path,
        question_ids=(question_id,),
        mock=True,
    )

    assert result["status"] == "ok"
    assert result["drafted"] == 1
    with connect_database(db_path) as conn:
        row = conn.execute(
            """
            SELECT ai_status,
                   normalized_type,
                   options_json,
                   quality_flags_json,
                   model_info,
                   confidence
              FROM question_structured_contents
             WHERE question_id = ?
            """,
            (question_id,),
        ).fetchone()
        after_question = dict(
            conn.execute(
                "SELECT stem_text, stem_latex, review_status, updated_at FROM questions WHERE id = ?",
                (question_id,),
            ).fetchone()
        )

    assert row["ai_status"] == "ai_draft"
    assert row["normalized_type"] == "choice"
    assert len(json.loads(row["options_json"])) == 4
    assert json.loads(row["quality_flags_json"]) == ["mock_ai_output"]
    model_info = json.loads(row["model_info"])
    assert model_info["provider"] == "mock"
    assert model_info["input"]["raw_crop_path"] == "data/assets/question_images/PDF-AI/Q001.png"
    assert ":" not in model_info["input"]["raw_crop_path"]
    assert model_info["input"]["page_image_path"] == "data/assets/paper_pages/PDF-AI/page_0001.png"
    assert row["confidence"] == 0.5
    assert after_question == before_question


def test_local_provider_rejects_non_loopback_url(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path, _question_id = _prepare_db(tmp_path)
    monkeypatch.setenv(ENV_PROVIDER, LOCAL_OPENAI_PROVIDER)
    monkeypatch.setenv(ENV_MODEL, "local-test-model")
    monkeypatch.setenv(ENV_BASE_URL, "https://example.com/v1")

    with pytest.raises(StructuredAiError, match="loopback"):
        run_structured_ai_corrections(db_path=db_path, limit=1)


def test_local_openai_provider_writes_ai_draft_from_loopback_server(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_path, question_id = _prepare_db(tmp_path)
    provider_payload = {
        "normalized_type": "choice",
        "stem_latex": "local provider latex",
        "options_json": [
            {"label": "A", "text_latex": "1"},
            {"label": "B", "text_latex": "2"},
            {"label": "C", "text_latex": "3"},
            {"label": "D", "text_latex": "4"},
        ],
        "blanks_json": [],
        "subquestions_json": [],
        "answer_latex": None,
        "analysis_latex": None,
        "confidence": 0.82,
        "quality_flags": ["local_provider_test"],
    }
    with connect_database(db_path) as conn:
        before_question = dict(
            conn.execute(
                "SELECT stem_text, stem_latex, review_status, updated_at FROM questions WHERE id = ?",
                (question_id,),
            ).fetchone()
        )

    with _local_openai_server(provider_payload) as (base_url, requests):
        monkeypatch.setenv(ENV_PROVIDER, LOCAL_OPENAI_PROVIDER)
        monkeypatch.setenv(ENV_MODEL, "local-test-model")
        monkeypatch.setenv(ENV_BASE_URL, base_url)
        result = run_structured_ai_corrections(
            db_path=db_path,
            question_ids=(question_id,),
            limit=1,
        )

    assert result["status"] == "ok"
    assert result["drafted"] == 1
    assert requests
    assert requests[0]["model"] == "local-test-model"
    assert "raw_crop_path" in requests[0]["messages"][1]["content"]
    with connect_database(db_path) as conn:
        row = conn.execute(
            """
            SELECT ai_status,
                   stem_latex,
                   quality_flags_json,
                   model_info,
                   confidence
              FROM question_structured_contents
             WHERE question_id = ?
            """,
            (question_id,),
        ).fetchone()
        after_question = dict(
            conn.execute(
                "SELECT stem_text, stem_latex, review_status, updated_at FROM questions WHERE id = ?",
                (question_id,),
            ).fetchone()
        )

    assert row["ai_status"] == "ai_draft"
    assert row["stem_latex"] == "local provider latex"
    assert json.loads(row["quality_flags_json"]) == ["local_provider_test"]
    model_info = json.loads(row["model_info"])
    assert model_info["provider"] == LOCAL_OPENAI_PROVIDER
    assert model_info["model"] == "local-test-model"
    assert row["confidence"] == 0.82
    assert after_question == before_question


def test_validate_ai_output_payload_rejects_invalid_json_shape() -> None:
    with pytest.raises(StructuredAiError, match="normalized_type"):
        validate_ai_output_payload({"normalized_type": "essay", "stem_latex": "x"})

    with pytest.raises(StructuredAiError, match="stem_latex"):
        validate_ai_output_payload({"normalized_type": "choice", "stem_latex": ""})

    with pytest.raises(StructuredAiError, match="options_json"):
        validate_ai_output_payload(
            {"normalized_type": "choice", "stem_latex": "x", "options_json": {}}
        )
