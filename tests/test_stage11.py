from __future__ import annotations

import json
import sqlite3
import struct
import zlib
from pathlib import Path

from app.cli import main
from app.database import connect_database, initialize_database
from app.export_selection import ExportSelectionService, save_stage11_export_sample
from app.stage10 import questions_main_checksum
from app.stage11 import classify_usability_states, write_stage11_quality_report
from app.structured_content import initialize_structured_contents
from app.structured_render import render_printable_paper_html


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
        ("PDF-STAGE11", "Stage 11 Paper", "Base/sample.pdf", 1200, "born_digital", "{}"),
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
        ) VALUES (?, 'page_image', ?, ?, ?, '{}')
        """,
        (
            source_paper_id,
            f"data/assets/paper_pages/PDF-STAGE11/page_{page_no:04d}.png",
            page_no,
            json.dumps({"page": page_no, "x0": 0, "y0": 0, "x1": 200, "y1": 300}),
        ),
    )


def _insert_question(
    conn: sqlite3.Connection,
    source_paper_id: int,
    *,
    qid: str,
    question_no: str,
    question_type: str | None,
    source_page: int,
    stem_text: str,
    review_status: str = "pending",
    with_crop: bool = True,
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
        ) VALUES (?, ?, ?, ?, ?, ?, ?, '[]', '[]', ?, ?, ?, ?, ?)
        """,
        (
            qid,
            source_paper_id,
            "Stage 11 Paper",
            question_no,
            question_type,
            stem_text,
            stem_text,
            f"p{source_page:04d}",
            json.dumps({"page": source_page, "x0": 10, "y0": 20, "x1": 110, "y1": 90}),
            review_status,
            json.dumps({"source_page": source_page, "split_warnings": []}),
            f"hash-{qid}",
        ),
    )
    question_id = int(cursor.lastrowid)
    if with_crop:
        conn.execute(
            """
            INSERT INTO question_assets (
                question_id,
                asset_kind,
                relative_path,
                page_no,
                bbox_json,
                meta_json
            ) VALUES (?, 'raw_crop', ?, ?, ?, '{}')
            """,
            (
                question_id,
                f"data/assets/question_images/PDF-STAGE11/{qid}.png",
                source_page,
                json.dumps({"page": source_page, "x0": 10, "y0": 20, "x1": 110, "y1": 90}),
            ),
        )
    _insert_page_asset(conn, source_paper_id, source_page)
    return question_id


def _write_asset_files(project_root: Path, qids: list[str], pages: list[int]) -> None:
    for page_no in pages:
        page_path = project_root / f"data/assets/paper_pages/PDF-STAGE11/page_{page_no:04d}.png"
        page_path.parent.mkdir(parents=True, exist_ok=True)
        page_path.write_bytes(b"page-png")
    for qid in qids:
        crop_path = project_root / f"data/assets/question_images/PDF-STAGE11/{qid}.png"
        crop_path.parent.mkdir(parents=True, exist_ok=True)
        crop_path.write_bytes(_png_bytes())


def _prepare_stage11_db(tmp_path: Path) -> tuple[Path, Path, dict[str, int]]:
    project_root = tmp_path / "project"
    (project_root / "Base").mkdir(parents=True)
    (project_root / "Base" / "sample.pdf").write_bytes(b"%PDF-1.4\n")
    db_path = project_root / "data" / "db" / "question_bank.sqlite3"
    initialize_database(db_path)
    ids: dict[str, int] = {}
    with connect_database(db_path) as conn:
        source_paper_id = _insert_source_paper(conn)
        ids["strict"] = _insert_question(
            conn,
            source_paper_id,
            qid="STAGE11-STRICT",
            question_no="1",
            question_type="choice",
            source_page=1090,
            stem_text="Strict verified source text alpha beta gamma delta",
        )
        ids["visual"] = _insert_question(
            conn,
            source_paper_id,
            qid="STAGE11-VISUAL",
            question_no="2",
            question_type="blank",
            source_page=1091,
            stem_text="Visual fallback source text with enough words",
        )
        ids["recut"] = _insert_question(
            conn,
            source_paper_id,
            qid="STAGE11-RECUT",
            question_no="3",
            question_type="choice",
            source_page=1098,
            stem_text="High risk duplicate anchor source text",
        )
        ids["protected"] = _insert_question(
            conn,
            source_paper_id,
            qid="STAGE11-PROTECTED",
            question_no="4",
            question_type="choice",
            source_page=1092,
            stem_text="Protected reviewed source text",
            review_status="reviewed",
        )
        ids["formula"] = _insert_question(
            conn,
            source_paper_id,
            qid="STAGE11-FORMULA",
            question_no="5",
            question_type="choice",
            source_page=1093,
            stem_text="Formula repair source text",
            with_crop=False,
        )
        conn.commit()
    initialize_structured_contents(db_path=db_path)
    with connect_database(db_path) as conn:
        conn.execute(
            """
            UPDATE question_structured_contents
               SET ai_status = 'ai_verified',
                   normalized_type = 'choice',
                   stem_latex = 'Strict verified latex alpha beta gamma',
                   options_json = ?,
                   quality_flags_json = '[]'
             WHERE question_id = ?
            """,
            (
                json.dumps(
                    [
                        {"label": "A", "text_latex": "alpha"},
                        {"label": "B", "text_latex": "beta"},
                        {"label": "C", "text_latex": "gamma"},
                        {"label": "D", "text_latex": "delta"},
                    ]
                ),
                ids["strict"],
            ),
        )
        conn.execute(
            """
            UPDATE question_structured_contents
               SET ai_status = 'needs_review',
                   quality_flags_json = ?
             WHERE question_id = ?
            """,
            (json.dumps(["latex_pi_trailing_number_suspicious"]), ids["formula"]),
        )
        conn.commit()
    _write_asset_files(
        project_root,
        ["STAGE11-STRICT", "STAGE11-VISUAL", "STAGE11-RECUT", "STAGE11-PROTECTED"],
        [1090, 1091, 1092, 1093, 1098],
    )
    return project_root, db_path, ids


def test_stage11_classifies_all_questions_without_touching_questions(tmp_path: Path) -> None:
    project_root, db_path, ids = _prepare_stage11_db(tmp_path)
    with connect_database(db_path) as conn:
        before_checksum = questions_main_checksum(conn)

    result = classify_usability_states(db_path=db_path, project_root=project_root)

    with connect_database(db_path) as conn:
        after_checksum = questions_main_checksum(conn)
        states = {
            row["question_id"]: row["usability_status"]
            for row in conn.execute(
                "SELECT question_id, usability_status FROM question_usability_states"
            ).fetchall()
        }

    assert result["summary"]["question_count"] == 5
    assert result["summary"]["usability_count"] == 5
    assert result["summary"]["unclassified"] == 0
    assert result["summary"]["strict_risk_hits"] == []
    assert result["summary"]["visual_fallback_invalid"] == []
    assert states[ids["strict"]] == "strict_structured"
    assert states[ids["visual"]] == "visual_fallback"
    assert states[ids["recut"]] == "needs_recut"
    assert states[ids["protected"]] == "protected"
    assert states[ids["formula"]] == "needs_formula_repair"
    assert after_checksum == before_checksum


def test_stage11_export_selection_uses_only_strict_and_visual(tmp_path: Path) -> None:
    project_root, db_path, ids = _prepare_stage11_db(tmp_path)
    classify_usability_states(db_path=db_path, project_root=project_root)
    service = ExportSelectionService(
        db_path=db_path,
        project_root=project_root,
        use_export_quality=False,
    )

    result = service.select_for_question_ids(
        [ids["strict"], ids["visual"], ids["recut"], ids["protected"], ids["formula"]]
    )
    html = render_printable_paper_html(
        result["questions"],
        export=True,
        title="Stage 11 Test",
        asset_url_mode="export_relative",
    )

    assert [question["id"] for question in result["questions"]] == [
        ids["strict"],
        ids["visual"],
    ]
    assert len(result["rejected"]) == 3
    assert "Strict verified latex" in html
    assert "source:strict_structured" in html
    assert "source:visual_fallback" in html
    assert "../assets/question_images/PDF-STAGE11/STAGE11-VISUAL.png" in html
    assert "High risk duplicate anchor" not in html
    assert "Formula repair source" not in html


def test_stage11_cli_report_and_export_sample(tmp_path: Path) -> None:
    project_root, db_path, _ = _prepare_stage11_db(tmp_path)

    assert main(["stage11-classify-usability", "--db-path", str(db_path)]) == 0
    assert main(["usability-status", "--db-path", str(db_path)]) == 0
    assert main(["stage11-report", "--db-path", str(db_path)]) == 0
    assert main(["stage11-export-sample", "--db-path", str(db_path), "--limit", "5"]) == 0

    report = project_root / "docs" / "stage11_quality_report.md"
    exports = list((project_root / "data" / "exports").glob("stage11-formal-sample-*.html"))
    assert report.is_file()
    report_text = report.read_text(encoding="utf-8")
    assert "unclassified：0" in report_text
    assert "strict_structured" in report_text
    assert exports
    html = exports[0].read_text(encoding="utf-8")
    assert "阶段 11 正式样卷" in html
    assert "source:visual_fallback" in html

    direct = save_stage11_export_sample(db_path=db_path, project_root=project_root, limit=5)
    assert direct["status"] == "ok"
    assert direct["question_count"] == 2
