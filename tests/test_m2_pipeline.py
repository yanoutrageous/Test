from __future__ import annotations

import json
import shutil
import sqlite3
from dataclasses import replace
from pathlib import Path

import app.m2_pipeline as m2
from app.m1_pipeline import M1PipelineConfig, load_copy_payload


def _candidates() -> tuple[m2.CandidateQuestion, ...]:
    return m2.load_candidate_pool(m2.M2PipelineConfig())


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def test_real_candidate_pool_full_blueprint_is_exact_and_deterministic() -> None:
    candidates = _candidates()
    spec = m2.full_blueprint_spec()

    first = m2.solve_blueprint(candidates, spec)
    second = m2.solve_blueprint(candidates, spec)

    assert len(candidates) == 19
    assert first == second
    assert first.feasible is True
    assert first.coverage == {
        "question_count": 19,
        "type_counts": {
            "单项选择题": 8,
            "填空题": 3,
            "多项选择题": 3,
            "解答题": 5,
        },
        "total_points": 150,
        "design_difficulty_sum": 46,
        "expected_time_seconds": 6600,
        "years": [2026],
        "approved_count": 19,
        "answer_ready_count": 19,
        "analysis_ready_count": 19,
    }
    assert first.diagnostics["hard_constraints_satisfied"] is True
    assert first.diagnostics["hard_constraints_relaxed"] is False
    assert first.diagnostics["duplicate_conflicts"] == []
    assert first.diagnostics["similarity_policy"] == "EXACT-CONTENT-HASH-V1"


def test_candidate_pool_ignores_pending_questions_from_user_imports(
    tmp_path: Path,
    monkeypatch,
) -> None:
    source_root = tmp_path / "runtime"
    default = m2.M2PipelineConfig()
    derived_relative = default.m1_derived_root.relative_to(m2.PROJECT_ROOT)
    database_relative = default.m1_database_path.relative_to(m2.PROJECT_ROOT)
    derived_target = source_root / derived_relative
    database_target = source_root / database_relative
    shutil.copytree(default.m1_derived_root, derived_target)
    database_target.parent.mkdir(parents=True)
    shutil.copy2(default.m1_database_path, database_target)

    with sqlite3.connect(database_target) as connection:
        cursor = connection.execute("SELECT * FROM questions ORDER BY id LIMIT 1")
        columns = [row[0] for row in cursor.description]
        source = dict(zip(columns, cursor.fetchone(), strict=True))
        source.pop("id")
        source.update(
            {
                "content_hash": "0" * 64,
                "meta_json": json.dumps(
                    {
                        "algorithm_version": "stage4_page_anchor_v2_lines",
                        "source_page": 1130,
                    }
                ),
                "qid": "PDF-EXTERNAL-P1130-Q001",
                "review_status": "pending",
            }
        )
        names = tuple(source)
        connection.execute(
            f"""
            INSERT INTO questions ({", ".join(names)})
            VALUES ({", ".join("?" for _ in names)})
            """,
            tuple(source[name] for name in names),
        )
        connection.commit()

    monkeypatch.setattr(m2, "PROJECT_ROOT", source_root)
    candidates = m2.load_candidate_pool(m2.M2PipelineConfig())

    assert len(candidates) == 19
    assert all(row.qid != "PDF-EXTERNAL-P1130-Q001" for row in candidates)


def test_infeasible_blueprint_reports_conflict_without_relaxation() -> None:
    result = m2.solve_blueprint(_candidates(), m2.infeasible_blueprint_spec())

    assert result.feasible is False
    assert result.selected_revision_ids == ()
    assert "total_points_or_time_incompatible_with_type_counts" in result.unsat_core
    assert "hard_constraints_not_relaxed" in result.unsat_core
    assert result.diagnostics["hard_constraints_relaxed"] is False


def test_exact_duplicate_is_a_hard_similarity_conflict() -> None:
    candidates = _candidates()
    duplicate_pool = (
        candidates[0],
        replace(candidates[1], content_hash=candidates[0].content_hash),
        *candidates[2:],
    )

    result = m2.solve_blueprint(duplicate_pool, m2.full_blueprint_spec())

    assert result.feasible is False
    assert "exact_content_hash_duplicate_conflict" in result.unsat_core
    assert "hard_constraints_not_relaxed" in result.unsat_core
    assert result.diagnostics["hard_constraints_relaxed"] is False


def test_blueprint_ui_locks_replaces_reorders_and_keeps_history() -> None:
    flow = m2.run_blueprint_ui_flow(_candidates())

    assert flow["home_status"] == 200
    assert flow["solve_status"] == 200
    assert flow["lock_status"] == 200
    assert flow["replace_status"] == 200
    assert flow["reorder_status"] == 200
    assert flow["infeasible_status"] == 409
    assert flow["locked_question_revision_id"] in flow["final_selection"]
    assert flow["removed_question_revision_id"] not in flow["final_selection"]
    assert [entry["action"] for entry in flow["history"]] == [
        "solve",
        "lock",
        "replace",
        "reorder",
        "diagnose_infeasible",
    ]
    assert flow["infeasible_unsat_core"]


def test_frozen_paper_does_not_drift_after_catalog_mutation() -> None:
    candidates = _candidates()
    result = m2.solve_blueprint(candidates, m2.full_blueprint_spec())
    frozen = m2.build_frozen_paper_snapshot(candidates, result)
    frozen_before = _canonical(frozen)
    mutated_candidates = (
        replace(candidates[0], answer_sha256="0" * 64),
        *candidates[1:],
    )

    regenerated = m2.build_frozen_paper_snapshot(mutated_candidates, result)

    assert _canonical(frozen) == frozen_before
    assert _canonical(regenerated) != frozen_before
    assert frozen["question_revision_ids"] == list(result.selected_revision_ids)
    assert frozen["coverage"]["total_points"] == 150


def test_five_document_sources_and_answer_sheets_are_deterministic() -> None:
    candidates = _candidates()
    config = M1PipelineConfig()
    paper = load_copy_payload(config.paper_copy_id).payload
    answer = load_copy_payload(config.answer_copy_id).payload
    analysis = load_copy_payload(config.analysis_copy_id).payload

    student = m2._repage_pdf_to_editable_b5(
        paper,
        title="M2 student paper / editable B5 184x260",
    )
    teacher_questions = m2._repage_pdf_to_editable_b5(
        paper,
        title="M2 teacher questions / editable B5 184x260",
    )
    teacher_answers = m2._repage_pdf_to_editable_b5(
        answer,
        title="M2 teacher answers / editable B5 184x260",
    )
    teacher = m2._compose_pdfs((teacher_questions, teacher_answers))
    assert student == m2._repage_pdf_to_editable_b5(
        paper,
        title="M2 student paper / editable B5 184x260",
    )
    assert teacher == m2._compose_pdfs((teacher_questions, teacher_answers))
    assert m2._pdf_summary(paper)["page_count"] == 4
    assert m2._pdf_summary(student)["page_count"] == 4
    assert m2._pdf_summary(teacher)["page_count"] == 15
    assert m2._pdf_summary(answer)["page_count"] == 11
    assert m2._pdf_summary(analysis)["page_count"] == 63
    for role_payload in (student, teacher):
        assert all(
            abs(page["width_pt"] - m2.EDITABLE_B5_WIDTH_MM * 72 / 25.4)
            <= 0.01
            and abs(
                page["height_pt"] - m2.EDITABLE_B5_HEIGHT_MM * 72 / 25.4
            )
            <= 0.01
            for page in m2._pdf_summary(role_payload)["pages"]
        )

    for family, expected_pages in (
        ("A4-MULTIPAGE", 6),
        ("A3-DUPLEX", 2),
    ):
        first = m2.render_answer_sheet(
            candidates,
            source_payload=paper,
            family=family,
        )
        second = m2.render_answer_sheet(
            candidates,
            source_payload=paper,
            family=family,
        )
        summary = m2._pdf_summary(first)
        assert first == second
        assert summary["page_count"] == expected_pages
        assert summary["unembedded_font_count"] == 0
        assert all(
            f"Q{question_no:02d}" in summary["text"]
            for question_no in range(1, 20)
        )


def test_m2_paths_are_portable_and_project_relative() -> None:
    config = m2.M2PipelineConfig()

    for path in (
        config.job_root,
        config.bundle_staging_root,
        config.bundle_target_root,
        config.m1_database_path,
        config.m1_derived_root,
    ):
        assert path.is_relative_to(Path.cwd())
