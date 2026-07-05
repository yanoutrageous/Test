from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from app.consistency import check_consistency
from app.database import connect_database, initialize_database
from app.exports import save_html_export
from app.question_assets import crop_question_assets
from app.question_repository import get_question_detail
from app.search_index import rebuild_search_index
from app.source_attribution import rebuild_source_attributions
from app.structured_content import initialize_structured_contents


def _create_project(tmp_path: Path) -> tuple[Path, Path]:
    project_root = tmp_path / "project"
    (project_root / "Base").mkdir(parents=True)
    (project_root / "Base" / "sample.pdf").write_bytes(b"%PDF-1.4\n")
    db_path = project_root / "data" / "db" / "question_bank.sqlite3"
    initialize_database(db_path)
    return project_root, db_path


def _create_page_png(path: Path) -> None:
    import fitz

    path.parent.mkdir(parents=True, exist_ok=True)
    doc = fitz.open()
    page = doc.new_page(width=200, height=100)
    page.insert_text((20, 40), "sample question page")
    page.insert_text((20, 70), "more text")
    pixmap = page.get_pixmap()
    pixmap.save(path)
    doc.close()


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
            "PDF-STAGE7",
            "Stage 7 Paper",
            "Base/sample.pdf",
            1,
            "born_digital",
            "{}",
        ),
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
            "PDF-STAGE7-P0001-Q001",
            source_paper_id,
            "Stage 7 Paper",
            "1",
            "选择题",
            "stage7alpha latex",
            "stage7alpha searchable text",
            "[]",
            "[]",
            "p0001",
            json.dumps({"page": 1, "x0": 10, "y0": 10, "x1": 160, "y1": 80}),
            "pending",
            json.dumps({"source_page": 1, "algorithm_version": "test"}),
            "stage7-hash",
        ),
    )
    return int(cursor.lastrowid)


def _prepare_question_with_page_asset(project_root: Path, db_path: Path) -> int:
    page_relative_path = "data/assets/paper_pages/PDF-STAGE7/page_0001_72dpi.png"
    _create_page_png(project_root / page_relative_path)
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
                page_relative_path,
                1,
                json.dumps({"page_width": 200, "page_height": 100}),
                json.dumps({"dpi": 72, "paper_code": "PDF-STAGE7"}),
            ),
        )
        conn.commit()
    return question_id


def test_rebuild_search_index_is_idempotent_and_restores_hits(tmp_path: Path) -> None:
    project_root, db_path = _create_project(tmp_path)
    _prepare_question_with_page_asset(project_root, db_path)

    with connect_database(db_path) as conn:
        conn.execute("DELETE FROM question_search_content")
        conn.execute("INSERT INTO question_fts(question_fts) VALUES ('rebuild')")
        conn.commit()

    first = rebuild_search_index(db_path=db_path)
    second = rebuild_search_index(db_path=db_path)

    assert first == second
    assert first["synced"] is True
    with connect_database(db_path) as conn:
        hits = conn.execute(
            "SELECT qid FROM question_fts WHERE question_fts MATCH ?",
            ("stage7alpha",),
        ).fetchall()
    assert [hit["qid"] for hit in hits] == ["PDF-STAGE7-P0001-Q001"]


def test_save_html_export_writes_timestamped_file(tmp_path: Path) -> None:
    project_root, _db_path = _create_project(tmp_path)

    first = save_html_export("<!doctype html><p>stage7 export</p>", project_root=project_root)
    second = save_html_export("<!doctype html><p>stage7 export</p>", project_root=project_root)

    assert first["relative_path"].startswith("data/exports/exam-paper-")
    assert second["relative_path"].startswith("data/exports/exam-paper-")
    assert first["relative_path"] != second["relative_path"]
    assert (project_root / first["relative_path"]).read_text(encoding="utf-8").startswith(
        "<!doctype html>"
    )
    assert first["size_bytes"] > 0


def test_crop_question_assets_writes_relative_png_and_consistency_passes(tmp_path: Path) -> None:
    project_root, db_path = _create_project(tmp_path)
    question_id = _prepare_question_with_page_asset(project_root, db_path)

    result = crop_question_assets(db_path=db_path, project_root=project_root)

    assert result["questions_considered"] == 1
    assert result["updated_records"] == 1
    assert result["raw_crop_assets"] == 1
    assert result["skipped"] == []
    with connect_database(db_path) as conn:
        asset = conn.execute(
            """
            SELECT question_id, asset_kind, relative_path
              FROM question_assets
             WHERE question_id = ?
            """,
            (question_id,),
        ).fetchone()

    assert asset["asset_kind"] == "raw_crop"
    assert asset["relative_path"].startswith("data/assets/question_images/PDF-STAGE7/")
    assert ":" not in asset["relative_path"]
    output_path = project_root / asset["relative_path"]
    assert output_path.exists()
    assert output_path.stat().st_size > 0
    detail = get_question_detail(question_id, db_path=db_path)
    assert detail["raw_crop_path"] == asset["relative_path"]

    initialize_structured_contents(db_path=db_path)
    rebuild_source_attributions(db_path=db_path, project_root=project_root)
    consistency = check_consistency(db_path=db_path, project_root=project_root)
    assert consistency["ok"] is True
    assert consistency["counts"]["question_assets"] == 1
