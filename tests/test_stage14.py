from __future__ import annotations

import json
from pathlib import Path

from app import create_app
from app.cli import main
from app.database import connect_database
from app.export_quality import classify_export_quality_states
from app.stage10 import questions_main_checksum
from app.stage14 import (
    classify_stage14_quality_queue,
    generate_stage14_visual_repair_candidates,
    save_stage14_export_sample,
    summarize_stage14_quality,
)
from tests.test_stage11 import _png_bytes, _prepare_stage11_db


def test_stage14_quality_queue_classifies_without_touching_questions(tmp_path: Path) -> None:
    project_root, db_path, ids = _prepare_stage11_db(tmp_path)
    classify_export_quality_states(db_path=db_path, project_root=project_root)
    with connect_database(db_path) as conn:
        before_checksum = questions_main_checksum(conn)

    result = classify_stage14_quality_queue(
        db_path=db_path,
        project_root=project_root,
        audit_recuts=False,
        audit_sources=False,
    )

    with connect_database(db_path) as conn:
        after_checksum = questions_main_checksum(conn)
        rows = {
            row["question_id"]: dict(row)
            for row in conn.execute(
                """
                SELECT question_id, queue_name, queue_tags_json, primary_reason
                  FROM stage14_quality_queue
                """
            ).fetchall()
        }
        approved_count = conn.execute(
            "SELECT count(*) FROM questions WHERE review_status = 'approved'"
        ).fetchone()[0]

    assert result["classified"] == 5
    assert result["questions_main_unchanged"] is True
    assert after_checksum == before_checksum
    assert approved_count == 0
    assert rows[ids["strict"]]["queue_name"] == "export_ready"
    assert rows[ids["visual"]]["queue_name"] == "export_ready"
    assert rows[ids["recut"]]["queue_name"] == "recut"
    assert rows[ids["protected"]]["queue_name"] == "protected"
    assert rows[ids["formula"]]["queue_name"] == "structured_repair"
    assert "export_ready" in json.loads(rows[ids["strict"]]["queue_tags_json"])


def test_stage14_visual_repair_writes_versioned_candidate_only(tmp_path: Path) -> None:
    project_root, db_path, ids = _prepare_stage11_db(tmp_path)
    small_crop = project_root / "data/assets/question_images/PDF-STAGE11/STAGE11-VISUAL.png"
    small_crop.write_bytes(_png_bytes(width=20, height=10))
    classify_export_quality_states(db_path=db_path, project_root=project_root)
    with connect_database(db_path) as conn:
        before_checksum = questions_main_checksum(conn)
        raw_crop_before = conn.execute(
            """
            SELECT relative_path
              FROM question_assets
             WHERE question_id = ?
               AND asset_kind = 'raw_crop'
            """,
            (ids["visual"],),
        ).fetchone()["relative_path"]

    result = generate_stage14_visual_repair_candidates(
        db_path=db_path,
        project_root=project_root,
    )

    with connect_database(db_path) as conn:
        after_checksum = questions_main_checksum(conn)
        raw_crop_after = conn.execute(
            """
            SELECT relative_path
              FROM question_assets
             WHERE question_id = ?
               AND asset_kind = 'raw_crop'
            """,
            (ids["visual"],),
        ).fetchone()["relative_path"]
        candidate = conn.execute(
            """
            SELECT repair_status, candidate_relative_path
              FROM stage14_visual_repair_candidates
             WHERE question_id = ?
            """,
            (ids["visual"],),
        ).fetchone()

    assert result["questions_main_unchanged"] is True
    assert after_checksum == before_checksum
    assert raw_crop_after == raw_crop_before
    assert candidate["repair_status"] in {
        "candidate_passed_visual_check",
        "candidate_failed_visual_check",
    }
    assert candidate["candidate_relative_path"].startswith("data/assets/question_images/")
    assert "stage14_repair" in candidate["candidate_relative_path"]
    assert (project_root / candidate["candidate_relative_path"]).is_file()


def test_stage14_cli_web_and_export_sample(tmp_path: Path) -> None:
    project_root, db_path, ids = _prepare_stage11_db(tmp_path)

    assert (
        main(
            [
                "stage14-classify-quality",
                "--db-path",
                str(db_path),
                "--no-recut-audit",
                "--no-source-audit",
            ]
        )
        == 0
    )
    assert main(["stage14-status", "--db-path", str(db_path)]) == 0
    assert main(["stage14-report", "--db-path", str(db_path)]) == 0
    assert main(["stage14-export-sample", "--db-path", str(db_path), "--limit", "5"]) == 0

    summary = summarize_stage14_quality(db_path=db_path, project_root=project_root)
    report = project_root / "docs" / "stage14_quality_report.md"
    exports = list((project_root / "data" / "exports").glob("stage14-formal-sample-*.html"))
    assert summary["queue_count"] == 5
    assert summary["missing_queue"] == 0
    assert summary["queue_counts"]["structured_repair"] == 1
    assert report.is_file()
    assert exports
    html = exports[0].read_text(encoding="utf-8")
    assert "source:export_ready_structured" in html
    assert "source:export_ready_visual" in html
    assert "STAGE11-RECUT" not in html
    assert "D:\\" not in html

    direct = save_stage14_export_sample(db_path=db_path, project_root=project_root, limit=5)
    assert direct["status"] == "ok"
    assert direct["question_count"] == 2
    assert direct["missing_source_label"] == []

    app = create_app(db_path=db_path, project_root=project_root)
    client = app.test_client()
    response = client.get("/questions?status=all&stage14_queue=structured_repair&limit=100")
    detail = client.get(f"/questions/{ids['formula']}?status=all&stage14_queue=structured_repair")
    structured = client.get("/structured-review?ai_status=all&stage14_queue=recut&limit=100")

    assert response.status_code == 200
    assert "STAGE11-FORMULA" in response.get_data(as_text=True)
    assert "STAGE11-STRICT" not in response.get_data(as_text=True)
    assert detail.status_code == 200
    assert "Stage14" in detail.get_data(as_text=True)
    assert "structured_repair" in detail.get_data(as_text=True)
    assert structured.status_code == 200
    assert "STAGE11-RECUT" in structured.get_data(as_text=True)
