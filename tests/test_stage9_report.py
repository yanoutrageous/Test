from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from app.cli import main
from app.database import connect_database, initialize_database
from app.stage9_report import write_stage9_quality_report
from app.structured_ai import ENV_BASE_URL, ENV_INCLUDE_IMAGES, ENV_MODEL, ENV_PROVIDER, ENV_TIMEOUT
from app.structured_content import initialize_structured_contents


@pytest.fixture(autouse=True)
def _clear_ai_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (ENV_PROVIDER, ENV_BASE_URL, ENV_MODEL, ENV_TIMEOUT, ENV_INCLUDE_IMAGES):
        monkeypatch.delenv(name, raising=False)


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
        ("PDF-STAGE9", "Stage 9 Paper", "Base/sample.pdf", 1200, "born_digital", "{}"),
    )
    return int(cursor.lastrowid)


def _insert_question(
    conn: sqlite3.Connection,
    source_paper_id: int,
    *,
    index: int,
    question_type: str | None,
    source_page: int,
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
            f"PDF-STAGE9-Q{index:03d}",
            source_paper_id,
            "Stage 9 Paper",
            str(index),
            question_type,
            f"{index}. stage9 report source latex",
            f"{index}. stage9 report source text",
            "[]",
            "[]",
            f"p{source_page:04d}",
            "{}",
            "pending",
            json.dumps({"source_page": source_page}),
            f"hash-stage9-{index}",
        ),
    )
    return int(cursor.lastrowid)


def _prepare_report_db(tmp_path: Path) -> tuple[Path, Path]:
    project_root = tmp_path / "project"
    db_path = project_root / "data" / "db" / "question_bank.sqlite3"
    initialize_database(db_path)
    with connect_database(db_path) as conn:
        source_paper_id = _insert_source_paper(conn)
        for index, question_type in enumerate(("选择题", "填空题", "解答题", None), start=1):
            _insert_question(
                conn,
                source_paper_id,
                index=index,
                question_type=question_type,
                source_page=1098 if index == 1 else 1100 + index,
            )
        conn.execute(
            """
            INSERT INTO import_batches (
                batch_code,
                name,
                batch_kind,
                source_paper_id,
                page_spec,
                page_count,
                algorithm_version,
                status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            ("BATCH-STAGE9", "stage9-report-test", "baseline", source_paper_id, "1098", 1, "test", "done"),
        )
        batch_id = conn.execute("SELECT id FROM import_batches").fetchone()[0]
        conn.execute(
            """
            INSERT INTO import_batch_pages (
                batch_id,
                source_paper_id,
                page_no,
                status,
                candidate_count,
                db_question_count,
                warning_candidates,
                duplicate_anchor_count,
                page_flags_json,
                warning_reasons_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                batch_id,
                source_paper_id,
                1098,
                "done",
                25,
                18,
                7,
                7,
                json.dumps(["duplicate_anchors"]),
                json.dumps(["duplicate_anchor_count"]),
            ),
        )
        conn.commit()
    initialize_structured_contents(db_path=db_path)
    return project_root, db_path


def test_stage9_report_writes_quality_report_and_marks_provider_unavailable(
    tmp_path: Path,
) -> None:
    project_root, db_path = _prepare_report_db(tmp_path)

    result = write_stage9_quality_report(
        db_path=db_path,
        project_root=project_root,
        sample_size=4,
    )

    report_path = project_root / result["relative_path"]
    assert report_path.is_file()
    report_text = report_path.read_text(encoding="utf-8")
    assert "阶段 9 质量报告" in report_text
    assert "真实 AI provider 状态：无真实配置" in report_text
    assert "代表性样本数量：4" in report_text
    assert "page 1098" in report_text
    assert result["sample_count"] == 4
    assert result["ai_provider_status"] == "skipped"
    assert result["ai_drafted"] == 0

    with connect_database(db_path) as conn:
        unavailable = conn.execute(
            """
            SELECT count(*)
              FROM question_structured_contents
             WHERE quality_flags_json LIKE '%ai_provider_unavailable%'
            """
        ).fetchone()[0]
    assert unavailable == 4


def test_stage9_report_cli(tmp_path: Path) -> None:
    project_root, db_path = _prepare_report_db(tmp_path)

    assert main(["stage9-report", "--db-path", str(db_path), "--sample-size", "2"]) == 0
    assert (project_root / "docs" / "stage9_quality_report.md").is_file()
