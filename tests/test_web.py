from __future__ import annotations

import json
import sqlite3
import struct
import zlib
from pathlib import Path

import pytest

from app import create_app
from app.database import connect_database, initialize_database
from app.structured_content import initialize_structured_contents
from app.web import BASKET_SESSION_KEY


def _png_bytes(width: int = 120, height: int = 80) -> bytes:
    rows = []
    for y in range(height):
        row = bytearray()
        for x in range(width):
            is_content = 20 <= x <= 96 and 24 <= y <= 48
            row.extend(b"\x00\x00\x00" if is_content else b"\xff\xff\xff")
        rows.append(b"\x00" + bytes(row))
    raw = zlib.compress(b"".join(rows))

    def chunk(kind: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + kind
            + data
            + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
        )

    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", raw)
        + chunk(b"IEND", b"")
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
            "PDF-WEB-TEST",
            "Web Test Paper",
            "Base/sample.pdf",
            1,
            "born_digital",
            json.dumps({"test": True}),
        ),
    )
    return int(cursor.lastrowid)


def _insert_page_asset(conn: sqlite3.Connection, source_paper_id: int, relative_path: str) -> None:
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
            relative_path,
            1,
            json.dumps({"page": 1}),
            json.dumps({"dpi": 144}),
        ),
    )


def _insert_raw_crop_asset(
    conn: sqlite3.Connection,
    *,
    question_id: int,
    relative_path: str,
) -> None:
    conn.execute(
        """
        INSERT INTO question_assets (
            question_id,
            asset_kind,
            relative_path,
            page_no,
            bbox_json,
            meta_json
        ) VALUES (?, 'raw_crop', ?, 1, ?, '{}')
        """,
        (
            question_id,
            relative_path,
            json.dumps({"page": 1, "x0": 10, "y0": 20, "x1": 110, "y1": 90}),
        ),
    )


def _insert_question(
    conn: sqlite3.Connection,
    *,
    source_paper_id: int,
    qid: str,
    question_no: str,
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
            "Web Test Paper",
            question_no,
            "选择题",
            stem_text,
            stem_text,
            json.dumps(["函数"]),
            "[]",
            "p0001",
            json.dumps({"page": 1, "x0": 10, "y0": 20, "x1": 110, "y1": 90}),
            review_status,
            json.dumps({"source_page": 1, "algorithm_version": "test"}),
            f"hash-{qid}",
        ),
    )
    return int(cursor.lastrowid)


def _set_verified_choice_structured(db_path: Path, question_id: int) -> None:
    initialize_structured_contents(db_path=db_path)
    options = [
        {"label": "A", "text_latex": "alpha"},
        {"label": "B", "text_latex": "beta"},
        {"label": "C", "text_latex": "gamma"},
        {"label": "D", "text_latex": "delta"},
    ]
    with connect_database(db_path) as conn:
        conn.execute(
            """
            UPDATE question_structured_contents
               SET ai_status = 'ai_verified',
                   normalized_type = 'choice',
                   stem_latex = ?,
                   options_json = ?,
                   quality_flags_json = '[]',
                   model_info = ?
            WHERE question_id = ?
            """,
            (
                r"stage5 structured latex token $\frac{x^2}{a^2}$",
                json.dumps(options, ensure_ascii=False),
                json.dumps({"test": "stage11-web"}, ensure_ascii=False),
                question_id,
            ),
        )
        conn.commit()


def _set_needs_review_structured(db_path: Path, question_id: int) -> None:
    initialize_structured_contents(db_path=db_path)
    with connect_database(db_path) as conn:
        conn.execute(
            """
            UPDATE question_structured_contents
               SET ai_status = 'needs_review',
                   normalized_type = 'choice',
                   stem_latex = source_latex,
                   quality_flags_json = ?,
                   model_info = ?
             WHERE question_id = ?
            """,
            (
                json.dumps(["page_duplicate_anchors"], ensure_ascii=False),
                json.dumps({"test": "stage10-web"}, ensure_ascii=False),
                question_id,
            ),
        )
        conn.commit()


@pytest.fixture()
def web_fixture(tmp_path: Path) -> dict[str, object]:
    project_root = tmp_path / "project"
    (project_root / "Base").mkdir(parents=True)
    (project_root / "Base" / "sample.pdf").write_bytes(b"%PDF-1.4\n")

    asset_relative_path = "data/assets/paper_pages/PDF-WEB-TEST/page_0001.png"
    asset_path = project_root / asset_relative_path
    asset_path.parent.mkdir(parents=True)
    asset_path.write_bytes(b"fake-png")
    crop_relative_path = "data/assets/question_images/PDF-WEB-TEST/WEB-Q001.png"
    crop_path = project_root / crop_relative_path
    crop_path.parent.mkdir(parents=True)
    crop_path.write_bytes(_png_bytes())

    db_path = project_root / "data" / "db" / "question_bank.sqlite3"
    initialize_database(db_path)

    with connect_database(db_path) as conn:
        source_paper_id = _insert_source_paper(conn)
        _insert_page_asset(conn, source_paper_id, asset_relative_path)
        pending_id = _insert_question(
            conn,
            source_paper_id=source_paper_id,
            qid="WEB-Q001",
            question_no="1",
            stem_text="stage5alpha pending stem",
        )
        reviewed_id = _insert_question(
            conn,
            source_paper_id=source_paper_id,
            qid="WEB-Q002",
            question_no="2",
            stem_text="stage5beta reviewed stem",
            review_status="reviewed",
        )
        _insert_raw_crop_asset(
            conn,
            question_id=pending_id,
            relative_path=crop_relative_path,
        )
        batch_cursor = conn.execute(
            """
            INSERT INTO import_batches (
                batch_code,
                name,
                batch_kind,
                source_paper_id,
                page_spec,
                page_count,
                algorithm_version,
                status,
                notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "BATCH-WEB-TEST",
                "stage8-web-test",
                "expansion",
                source_paper_id,
                "1",
                1,
                "test",
                "done",
                "test batch",
            ),
        )
        batch_id = int(batch_cursor.lastrowid)
        conn.execute(
            """
            INSERT INTO import_batch_pages (
                batch_id,
                source_paper_id,
                page_no,
                status,
                text_length,
                block_count,
                anchor_count,
                duplicate_anchor_count,
                candidate_count,
                db_question_count,
                warning_candidates,
                skipped_reviewed,
                page_flags_json,
                warning_reasons_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                batch_id,
                source_paper_id,
                1,
                "done",
                120,
                4,
                2,
                1,
                2,
                2,
                1,
                0,
                json.dumps(["duplicate_anchors"]),
                json.dumps(["duplicate_anchor_count"]),
            ),
        )
        conn.commit()

    return {
        "db_path": db_path,
        "project_root": project_root,
        "pending_id": pending_id,
        "reviewed_id": reviewed_id,
        "batch_id": batch_id,
        "asset_relative_path": asset_relative_path,
        "crop_relative_path": crop_relative_path,
    }


def test_health_endpoint_returns_project_status(tmp_path: Path) -> None:
    fitz = pytest.importorskip("fitz")
    project_root = tmp_path / "health-project"
    (project_root / "Base").mkdir(parents=True)
    pdf_path = project_root / "Base" / "sample.pdf"
    document = fitz.open()
    document.new_page()
    document.save(pdf_path)
    document.close()

    app = create_app(project_root=project_root)
    client = app.test_client()

    response = client.get("/health")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "ok"
    assert payload["dependencies"]["flask"]["ok"] is True
    assert payload["dependencies"]["pymupdf"]["ok"] is True
    assert payload["sqlite"]["ok"] is True
    assert payload["target_pdf"]["exists"] is True
    assert payload["target_pdf"]["readable"] is True
    assert payload["target_pdf"]["path"].endswith(".pdf")


def test_health_endpoint_reports_multiple_pdfs_as_warning(tmp_path: Path) -> None:
    project_root = tmp_path / "health-multi-project"
    (project_root / "Base").mkdir(parents=True)
    (project_root / "Base" / "a.pdf").write_bytes(b"%PDF-1.4\n")
    (project_root / "Base" / "b.pdf").write_bytes(b"%PDF-1.4\n")

    app = create_app(project_root=project_root)
    client = app.test_client()

    response = client.get("/health")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "ok"
    assert payload["target_pdf"]["resolved"] is False
    assert payload["target_pdf"]["candidates"] == ["a.pdf", "b.pdf"]
    assert payload["warnings"]


def test_questions_list_defaults_to_pending(web_fixture: dict[str, object]) -> None:
    app = create_app(
        db_path=web_fixture["db_path"],
        project_root=web_fixture["project_root"],
    )
    client = app.test_client()

    response = client.get("/questions")

    assert response.status_code == 200
    text = response.get_data(as_text=True)
    assert "WEB-Q001" in text
    assert "WEB-Q002" not in text
    assert "pending" in text
    assert "Web Test Paper / p0001 / 题号 1" in text
    assert "inferred" in text
    assert "加入组卷" in text


def test_question_detail_displays_page_asset_and_bbox(web_fixture: dict[str, object]) -> None:
    app = create_app(
        db_path=web_fixture["db_path"],
        project_root=web_fixture["project_root"],
    )
    client = app.test_client()

    response = client.get(f"/questions/{web_fixture['pending_id']}")
    asset_response = client.get(f"/assets/{web_fixture['asset_relative_path']}")

    assert response.status_code == 200
    text = response.get_data(as_text=True)
    assert "WEB-Q001" in text
    assert "stage5alpha pending stem" in text
    assert "Web Test Paper / p0001 / 题号 1" in text
    assert "来源置信" in text
    assert "inferred" in text
    assert web_fixture["asset_relative_path"] in text
    assert web_fixture["crop_relative_path"] in text
    assert "x0" in text
    assert "110" in text
    assert "可用性状态" in text
    assert "visual_fallback" in text
    assert "导出质量状态" in text
    assert "export_ready_visual" in text
    assert asset_response.status_code == 200
    assert asset_response.data == b"fake-png"


def test_question_detail_displays_structured_content(web_fixture: dict[str, object]) -> None:
    db_path = web_fixture["db_path"]
    _set_verified_choice_structured(db_path, int(web_fixture["pending_id"]))
    app = create_app(db_path=db_path, project_root=web_fixture["project_root"])
    client = app.test_client()

    response = client.get(f"/questions/{web_fixture['pending_id']}")

    assert response.status_code == 200
    text = response.get_data(as_text=True)
    assert "Structured Content" in text
    assert "stage5 structured latex token" in text
    assert "ai_verified" in text
    assert "options_json" in text
    assert "local-math-renderer" in text
    assert "data-local-math" in text
    assert "math-frac" in text


def test_post_saves_fields_and_updates_fts(web_fixture: dict[str, object]) -> None:
    db_path = web_fixture["db_path"]
    app = create_app(db_path=db_path, project_root=web_fixture["project_root"])
    client = app.test_client()

    response = client.post(
        f"/questions/{web_fixture['pending_id']}",
        data={
            "review_status": "reviewed",
            "question_type": "填空题",
            "stem_text": "updated stage5savedtoken stem",
            "stem_latex": "updated stage5savedtoken latex",
            "answer_text": "42",
            "analysis_latex": "analysis stage5savedtoken",
            "tags_json": json.dumps(["更新"]),
            "meta_json": json.dumps({"source_page": 1, "algorithm_version": "test"}),
        },
    )

    assert response.status_code == 302
    with connect_database(db_path) as conn:
        row = conn.execute(
            """
            SELECT question_type, stem_text, review_status
              FROM questions
             WHERE id = ?
            """,
            (web_fixture["pending_id"],),
        ).fetchone()
        approved_count = conn.execute(
            "SELECT count(*) FROM questions WHERE review_status = 'approved'"
        ).fetchone()[0]
        fts_hits = conn.execute(
            "SELECT qid FROM question_fts WHERE question_fts MATCH ?",
            ("stage5savedtoken",),
        ).fetchall()
        event = conn.execute(
            """
            SELECT event_type, source, before_json, after_json, diff_json
              FROM question_review_events
             WHERE question_id = ?
             ORDER BY id DESC
             LIMIT 1
            """,
            (web_fixture["pending_id"],),
        ).fetchone()

    assert row["question_type"] == "填空题"
    assert row["stem_text"] == "updated stage5savedtoken stem"
    assert row["review_status"] == "reviewed"
    assert approved_count == 0
    assert [hit["qid"] for hit in fts_hits] == ["WEB-Q001"]
    assert event["event_type"] == "web_update"
    assert event["source"] == "web"
    assert json.loads(event["before_json"])["review_status"] == "pending"
    assert json.loads(event["after_json"])["review_status"] == "reviewed"
    assert "stem_text" in json.loads(event["diff_json"])


def test_post_allows_manual_approved_and_records_event(web_fixture: dict[str, object]) -> None:
    db_path = web_fixture["db_path"]
    app = create_app(db_path=db_path, project_root=web_fixture["project_root"])
    client = app.test_client()

    response = client.post(
        f"/questions/{web_fixture['pending_id']}",
        data={
            "review_status": "approved",
            "question_type": "选择题",
            "stem_text": "stage5alpha pending stem",
            "stem_latex": "stage5alpha pending stem",
            "answer_text": "",
            "analysis_latex": "",
            "tags_json": "[]",
            "meta_json": json.dumps({"source_page": 1, "algorithm_version": "test"}),
        },
    )

    assert response.status_code == 302
    with connect_database(db_path) as conn:
        row = conn.execute(
            "SELECT review_status FROM questions WHERE id = ?",
            (web_fixture["pending_id"],),
        ).fetchone()
        event = conn.execute(
            """
            SELECT event_type, source, before_json, after_json, diff_json
              FROM question_review_events
             WHERE question_id = ?
             ORDER BY id DESC
             LIMIT 1
            """,
            (web_fixture["pending_id"],),
        ).fetchone()

    assert row["review_status"] == "approved"
    assert event["event_type"] == "web_update"
    assert event["source"] == "web"
    assert json.loads(event["before_json"])["review_status"] == "pending"
    assert json.loads(event["after_json"])["review_status"] == "approved"
    assert "review_status" in json.loads(event["diff_json"])


def test_questions_search_filters_status_type_and_page(web_fixture: dict[str, object]) -> None:
    app = create_app(
        db_path=web_fixture["db_path"],
        project_root=web_fixture["project_root"],
    )
    client = app.test_client()

    pending_response = client.get(
        "/questions?q=stage5alpha&question_type=%E9%80%89%E6%8B%A9%E9%A2%98&page_range=p0001"
    )
    reviewed_response = client.get("/questions?status=reviewed&q=stage5beta")

    assert pending_response.status_code == 200
    assert reviewed_response.status_code == 200
    pending_text = pending_response.get_data(as_text=True)
    reviewed_text = reviewed_response.get_data(as_text=True)
    assert "WEB-Q001" in pending_text
    assert "WEB-Q002" not in pending_text
    assert "WEB-Q002" in reviewed_text


def test_batch_and_issue_filters_show_operational_context(
    web_fixture: dict[str, object],
) -> None:
    app = create_app(
        db_path=web_fixture["db_path"],
        project_root=web_fixture["project_root"],
    )
    client = app.test_client()
    batch_id = int(web_fixture["batch_id"])

    batches_response = client.get("/batches")
    batch_response = client.get(f"/batches/{batch_id}")
    filtered_response = client.get(
        f"/questions?status=all&batch_id={batch_id}&issue_only=1&limit=100"
    )
    detail_response = client.get(
        f"/questions/{web_fixture['pending_id']}?status=all&batch_id={batch_id}&issue_only=1&limit=100"
    )

    assert batches_response.status_code == 200
    assert batch_response.status_code == 200
    assert filtered_response.status_code == 200
    assert detail_response.status_code == 200

    batches_text = batches_response.get_data(as_text=True)
    batch_text = batch_response.get_data(as_text=True)
    filtered_text = filtered_response.get_data(as_text=True)
    detail_text = detail_response.get_data(as_text=True)

    assert "stage8-web-test" in batches_text
    assert "duplicate_anchors" in batch_text
    assert "WEB-Q001" in filtered_text
    assert "WEB-Q002" in filtered_text
    assert "批次页状态" in detail_text
    assert "stage8-web-test" in detail_text
    assert "下一题" in detail_text


def test_structured_review_workbench_filters_and_updates_structured_only(
    web_fixture: dict[str, object],
) -> None:
    db_path = web_fixture["db_path"]
    pending_id = int(web_fixture["pending_id"])
    _set_needs_review_structured(db_path, pending_id)
    app = create_app(db_path=db_path, project_root=web_fixture["project_root"])
    client = app.test_client()

    with connect_database(db_path) as conn:
        before_question = dict(
            conn.execute(
                "SELECT stem_text, review_status, updated_at FROM questions WHERE id = ?",
                (pending_id,),
            ).fetchone()
        )

    response = client.get(
        "/structured-review?ai_status=needs_review&quality_flag=page_duplicate_anchors"
        "&page=1&usability_status=visual_fallback&risk_type=duplicate&render_mode=raw_crop_image"
    )

    assert response.status_code == 200
    text = response.get_data(as_text=True)
    assert "WEB-Q001" in text
    assert "page_duplicate_anchors" in text
    assert "visual_fallback" in text
    assert "export_ready_visual" in text

    accept_response = client.post(
        f"/structured-review/{pending_id}/status",
        data={"action": "accept", "next": "/structured-review?ai_status=human_reviewed"},
    )

    assert accept_response.status_code == 302
    with connect_database(db_path) as conn:
        after_question = dict(
            conn.execute(
                "SELECT stem_text, review_status, updated_at FROM questions WHERE id = ?",
                (pending_id,),
            ).fetchone()
        )
        structured = conn.execute(
            """
            SELECT ai_status, quality_flags_json
              FROM question_structured_contents
             WHERE question_id = ?
            """,
            (pending_id,),
        ).fetchone()
        event = conn.execute(
            """
            SELECT event_type, source, before_json, after_json, diff_json
              FROM question_review_events
             WHERE question_id = ?
             ORDER BY id DESC
             LIMIT 1
            """,
            (pending_id,),
        ).fetchone()

    assert after_question == before_question
    assert structured["ai_status"] == "human_reviewed"
    assert "manual_accept" in json.loads(structured["quality_flags_json"])
    assert event["event_type"] == "structured_status_update"
    assert event["source"] == "web_stage10"
    assert json.loads(event["before_json"])["ai_status"] == "needs_review"
    assert json.loads(event["after_json"])["ai_status"] == "human_reviewed"
    assert "ai_status" in json.loads(event["diff_json"])


def test_save_and_next_preserves_context_and_writes_issue_tags(
    web_fixture: dict[str, object],
) -> None:
    db_path = web_fixture["db_path"]
    app = create_app(db_path=db_path, project_root=web_fixture["project_root"])
    client = app.test_client()
    batch_id = int(web_fixture["batch_id"])

    response = client.post(
        f"/questions/{web_fixture['pending_id']}",
        data={
            "status": "all",
            "batch_id": str(batch_id),
            "issue_only": "1",
            "limit": "100",
            "save_next": "1",
            "review_status": "reviewed",
            "question_type": "选择题",
            "stem_text": "updated stage8next stem",
            "stem_latex": "updated stage8next latex",
            "answer_text": "",
            "analysis_latex": "",
            "tags_json": "[]",
            "issue_tags": "切分异常, 缺图",
            "meta_json": json.dumps({"source_page": 1, "algorithm_version": "test"}),
        },
    )

    assert response.status_code == 302
    assert f"/questions/{web_fixture['reviewed_id']}" in response.headers["Location"]
    assert "batch_id=" in response.headers["Location"]
    assert "issue_only=1" in response.headers["Location"]

    with connect_database(db_path) as conn:
        row = conn.execute(
            """
            SELECT stem_text, review_status, meta_json
              FROM questions
             WHERE id = ?
            """,
            (web_fixture["pending_id"],),
        ).fetchone()
        event = conn.execute(
            """
            SELECT event_type, source, after_json, diff_json
              FROM question_review_events
             WHERE question_id = ?
             ORDER BY id DESC
             LIMIT 1
            """,
            (web_fixture["pending_id"],),
        ).fetchone()

    meta = json.loads(row["meta_json"])
    assert row["stem_text"] == "updated stage8next stem"
    assert row["review_status"] == "reviewed"
    assert meta["issue_tags"] == ["切分异常", "缺图"]
    assert event["event_type"] == "web_update"
    assert event["source"] == "web"
    assert json.loads(event["after_json"])["review_status"] == "reviewed"
    assert "meta_json" in json.loads(event["diff_json"])


def test_paper_basket_flow_exports_html_without_modifying_questions(
    web_fixture: dict[str, object],
) -> None:
    db_path = web_fixture["db_path"]
    app = create_app(db_path=db_path, project_root=web_fixture["project_root"])
    client = app.test_client()

    with connect_database(db_path) as conn:
        before_rows = [
            dict(row)
            for row in conn.execute(
                """
                SELECT id, qid, stem_text, review_status, updated_at
                  FROM questions
                 ORDER BY id
                """
            ).fetchall()
        ]

    pending_id = int(web_fixture["pending_id"])
    reviewed_id = int(web_fixture["reviewed_id"])

    assert client.post(f"/paper-basket/add/{pending_id}").status_code == 302
    assert client.post(f"/paper-basket/add/{pending_id}").status_code == 302
    with client.session_transaction() as session:
        assert session[BASKET_SESSION_KEY] == [pending_id]

    assert client.post(f"/paper-basket/add/{reviewed_id}").status_code == 302
    basket_response = client.get("/paper-basket")
    assert basket_response.status_code == 200
    basket_text = basket_response.get_data(as_text=True)
    assert basket_text.count("WEB-Q001") == 1
    assert basket_text.index("WEB-Q001") < basket_text.index("WEB-Q002")

    assert client.post(f"/paper-basket/move/{reviewed_id}/up").status_code == 302
    with client.session_transaction() as session:
        assert session[BASKET_SESSION_KEY] == [reviewed_id, pending_id]

    assert client.post(f"/paper-basket/move/{reviewed_id}/down").status_code == 302
    with client.session_transaction() as session:
        assert session[BASKET_SESSION_KEY] == [pending_id, reviewed_id]

    preview_response = client.get("/paper-preview")
    assert preview_response.status_code == 200
    preview_text = preview_response.get_data(as_text=True)
    assert "source:export_ready_visual" in preview_text
    assert "Web Test Paper / p0001 / 题号 1" in preview_text
    assert web_fixture["crop_relative_path"] in preview_text
    assert "stage5beta reviewed stem" not in preview_text
    assert "window.print" in preview_text

    export_response = client.get("/paper-export")
    assert export_response.status_code == 200
    assert export_response.headers["Content-Disposition"] == "attachment; filename=exam-paper.html"
    export_text = export_response.get_data(as_text=True)
    assert "<!doctype html>" in export_text.lower()
    assert "可打印试卷" in export_text
    assert "一、单项选择题" in export_text
    assert "source:export_ready_visual" in export_text
    assert "Web Test Paper / p0001 / 题号 1" in export_text
    assert web_fixture["crop_relative_path"] in export_text
    assert "stage5beta reviewed stem" not in export_text
    assert "window.print" not in export_text

    save_response = client.post("/paper-export/save")
    assert save_response.status_code == 200
    save_text = save_response.get_data(as_text=True)
    assert "data/exports/exam-paper-" in save_text
    export_files = list((Path(web_fixture["project_root"]) / "data" / "exports").glob("*.html"))
    assert len(export_files) == 1
    assert export_files[0].stat().st_size > 0
    saved_html = export_files[0].read_text(encoding="utf-8")
    assert "source:export_ready_visual" in saved_html
    assert "Web Test Paper / p0001 / 题号 1" in saved_html
    assert "../assets/question_images/PDF-WEB-TEST/WEB-Q001.png" in saved_html

    assert client.post(f"/paper-basket/remove/{pending_id}").status_code == 302
    with client.session_transaction() as session:
        assert session[BASKET_SESSION_KEY] == [reviewed_id]

    assert client.post("/paper-basket/clear").status_code == 302
    with client.session_transaction() as session:
        assert session[BASKET_SESSION_KEY] == []

    with connect_database(db_path) as conn:
        after_rows = [
            dict(row)
            for row in conn.execute(
                """
                SELECT id, qid, stem_text, review_status, updated_at
                  FROM questions
                 ORDER BY id
                """
            ).fetchall()
        ]

    assert after_rows == before_rows


def test_paper_preview_and_export_prefer_verified_structured_content(
    web_fixture: dict[str, object],
) -> None:
    db_path = web_fixture["db_path"]
    _set_verified_choice_structured(db_path, int(web_fixture["pending_id"]))
    app = create_app(db_path=db_path, project_root=web_fixture["project_root"])
    client = app.test_client()
    pending_id = int(web_fixture["pending_id"])
    reviewed_id = int(web_fixture["reviewed_id"])

    assert client.post(f"/paper-basket/add/{pending_id}").status_code == 302
    assert client.post(f"/paper-basket/add/{reviewed_id}").status_code == 302

    preview_response = client.get("/paper-preview")
    export_response = client.get("/paper-export")

    assert preview_response.status_code == 200
    assert export_response.status_code == 200
    preview_text = preview_response.get_data(as_text=True)
    export_text = export_response.get_data(as_text=True)
    assert "stage5 structured latex token" in preview_text
    assert "stage5alpha pending stem" not in preview_text
    assert "options-4" in preview_text
    assert "local-math-renderer" in preview_text
    assert "data-local-math" in preview_text
    assert "math-frac" in preview_text
    assert "candidate:unprocessed" not in preview_text
    assert "stage5beta reviewed stem" not in preview_text
    assert "source:export_ready_structured" in preview_text
    assert "Web Test Paper / p0001 / 题号 1" in preview_text
    assert "stage5 structured latex token" in export_text
    assert "local-math-renderer" in export_text
    assert "data-local-math" in export_text
    assert "math-frac" in export_text
    assert "source:export_ready_structured" in export_text
    assert "Web Test Paper / p0001 / 题号 1" in export_text
    assert "window.print" not in export_text
