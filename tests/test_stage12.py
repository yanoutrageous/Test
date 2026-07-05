from __future__ import annotations

from pathlib import Path

from app.cli import main
from app.database import connect_database
from app.export_quality import (
    classify_export_quality_states,
    summarize_export_quality,
)
from app.export_selection import ExportSelectionService, save_stage12_export_sample
from app.paper_render import PaperRenderService
from app.stage10 import questions_main_checksum
from tests.test_stage11 import _prepare_stage11_db


def test_stage12_classifies_export_quality_without_touching_questions(tmp_path: Path) -> None:
    project_root, db_path, ids = _prepare_stage11_db(tmp_path)
    with connect_database(db_path) as conn:
        before_checksum = questions_main_checksum(conn)

    result = classify_export_quality_states(db_path=db_path, project_root=project_root)

    with connect_database(db_path) as conn:
        after_checksum = questions_main_checksum(conn)
        states = {
            row["question_id"]: row["export_quality_status"]
            for row in conn.execute(
                "SELECT question_id, export_quality_status FROM question_export_quality"
            ).fetchall()
        }

    summary = result["summary"]
    assert summary["question_count"] == 5
    assert summary["export_quality_count"] == 5
    assert summary["unclassified"] == 0
    assert summary["ready_structured_risk_hits"] == []
    assert summary["ready_visual_invalid"] == []
    assert states[ids["strict"]] == "export_ready_structured"
    assert states[ids["visual"]] == "export_ready_visual"
    assert states[ids["recut"]] == "export_blocked"
    assert states[ids["protected"]] == "export_blocked"
    assert states[ids["formula"]] == "export_candidate"
    assert after_checksum == before_checksum


def test_stage12_export_selection_uses_only_ready_questions(tmp_path: Path) -> None:
    project_root, db_path, ids = _prepare_stage11_db(tmp_path)
    classify_export_quality_states(db_path=db_path, project_root=project_root)
    service = ExportSelectionService(db_path=db_path, project_root=project_root)

    result = service.select_for_question_ids(
        [ids["strict"], ids["visual"], ids["recut"], ids["protected"], ids["formula"]]
    )
    html = PaperRenderService().render_printable(
        result["questions"],
        rejected=result["rejected"],
        export=True,
        title="Stage 12 Test",
        asset_url_mode="export_relative",
    )

    assert [question["id"] for question in result["questions"]] == [
        ids["strict"],
        ids["visual"],
    ]
    assert len(result["rejected"]) == 3
    assert "Strict verified latex" in html
    assert "source:export_ready_structured" in html
    assert "source:export_ready_visual" in html
    assert "../assets/question_images/PDF-STAGE11/STAGE11-VISUAL.png" in html
    assert "High risk duplicate anchor" not in html
    assert "Formula repair source" not in html
    assert "已排除题目" in html
    assert "export_blocked" in html
    assert "export_candidate" in html


def test_stage12_cli_report_and_export_sample(tmp_path: Path) -> None:
    project_root, db_path, _ = _prepare_stage11_db(tmp_path)

    assert main(["stage12-classify-export-quality", "--db-path", str(db_path)]) == 0
    assert main(["export-quality-status", "--db-path", str(db_path)]) == 0
    assert main(["stage12-report", "--db-path", str(db_path)]) == 0
    assert main(["stage12-export-sample", "--db-path", str(db_path), "--limit", "5"]) == 0

    summary = summarize_export_quality(db_path=db_path, project_root=project_root)
    assert summary["unclassified"] == 0
    assert summary["status_counts"]["export_ready_structured"] == 1
    assert summary["status_counts"]["export_ready_visual"] == 1

    report = project_root / "docs" / "stage12_export_quality_report.md"
    exports = list((project_root / "data" / "exports").glob("stage12-formal-sample-*.html"))
    audits = list((project_root / "data" / "exports").glob("stage12-export-quality-audit-*.html"))
    assert report.is_file()
    report_text = report.read_text(encoding="utf-8")
    assert "unclassified：0" in report_text
    assert "export_ready_structured" in report_text
    assert exports
    assert audits
    html = exports[0].read_text(encoding="utf-8")
    assert "阶段 12 正式样卷" in html
    assert "source:export_ready_structured" in html
    assert "source:export_ready_visual" in html
    assert "export_candidate" not in html
    assert "export_blocked" not in html
    assert "D:\\" not in html

    direct = save_stage12_export_sample(db_path=db_path, project_root=project_root, limit=5)
    assert direct["status"] == "ok"
    assert direct["question_count"] == 2
    assert direct["audit_relative_path"].startswith("data/exports/")
