from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from app.ir_contracts import (
    FIGURE_IR_SCHEMA_ID,
    PAPER_IR_SCHEMA_ID,
    QUESTION_IR_SCHEMA_ID,
    IrContractError,
    IrVersionError,
    assert_dependencies_available,
    canonical_json_bytes,
    dependency_revision_ids,
    ir_sha256,
    migrate_ir_document,
    rollback_ir_document,
    validate_figure_ir,
    validate_ir_document,
    validate_paper_ir,
    validate_question_ir,
)


def _text(text: str = "text") -> dict[str, object]:
    return {
        "kind": "text",
        "text": text,
        "style": "normal",
        "extensions": {},
    }


def _source_ref() -> dict[str, object]:
    return {
        "source_file_revision_id": "SOURCE-FILE-REV-001",
        "page_no": 2,
        "region": {
            "coordinate_space": "pdf_points_top_left",
            "units": "pt",
            "page_width": 595,
            "page_height": 842,
            "x0": 10,
            "y0": 20,
            "x1": 300,
            "y1": 400,
            "dpi": None,
            "extensions": {},
        },
        "transforms": [
            {
                "sequence": 1,
                "kind": "crop",
                "input_coordinate_space": "pdf_points_top_left",
                "output_coordinate_space": "pixels_top_left",
                "matrix_3x3": [1, 0, -10, 0, 1, -20, 0, 0, 1],
                "algorithm": "contracted-affine-v1",
                "parameters": {"dpi": 200},
                "extensions": {},
            }
        ],
        "extensions": {},
    }


def question_ir() -> dict[str, object]:
    figure_block = {
        "kind": "figure",
        "figure_revision_id": "FIGURE-REV-001",
        "caption_blocks": [_text("Figure 1")],
        "extensions": {},
    }
    return {
        "schema_id": QUESTION_IR_SCHEMA_ID,
        "schema_version": "1.0",
        "ir_id": "QUESTION-IR-001",
        "revision_id": "QUESTION-IR-REV-001",
        "question_type": "selection",
        "blocks": [_text("Choose one."), figure_block],
        "options": [
            {"label": "A", "blocks": [_text("1")], "extensions": {}},
            {"label": "B", "blocks": [_text("2")], "extensions": {}},
        ],
        "subquestions": [],
        "figure_revision_ids": ["FIGURE-REV-001"],
        "answer_blocks": [_text("A")],
        "solution_blocks": [_text("Because.")],
        "scoring_points": [
            {
                "scoring_point_revision_id": "SCORING-REV-001",
                "points": 4,
                "criteria_blocks": [_text("Correct answer.")],
                "extensions": {},
            }
        ],
        "source_refs": [_source_ref()],
        "points": 4,
        "design_difficulty": 3,
        "observed_p": 0.62,
        "expected_time_seconds": 180,
        "observed_item_time_seconds": None,
        "observed_item_time_source": None,
        "extensions": {},
    }


def geometry_figure_ir() -> dict[str, object]:
    return {
        "schema_id": FIGURE_IR_SCHEMA_ID,
        "schema_version": "1.0",
        "ir_id": "FIGURE-IR-001",
        "revision_id": "FIGURE-IR-REV-001",
        "figure_kind": "geometry",
        "content": {
            "coordinate_space": "cartesian_2d",
            "points": [
                {
                    "id": "POINT-A",
                    "x": 0,
                    "y": 0,
                    "z": None,
                    "label": "A",
                    "extensions": {},
                },
                {
                    "id": "POINT-B",
                    "x": 1,
                    "y": 1,
                    "z": None,
                    "label": "B",
                    "extensions": {},
                },
            ],
            "primitives": [
                {
                    "id": "SEGMENT-AB",
                    "kind": "segment",
                    "refs": ["POINT-A", "POINT-B"],
                    "parameters": {},
                    "extensions": {},
                }
            ],
            "constraints": [
                {
                    "kind": "collinear",
                    "refs": ["POINT-A", "POINT-B"],
                    "value": None,
                    "extensions": {},
                }
            ],
            "annotations": [_text("AB")],
            "extensions": {},
        },
        "source_refs": [_source_ref()],
        "original_asset_ref": "Copy/figures/original.svg",
        "fallback_asset_ref": "assets/figures/fallback.svg",
        "style": {
            "monochrome": True,
            "line_width_pt": 0.75,
            "font_role": "FONT-ROLE-MATH",
            "extensions": {},
        },
        "extensions": {},
    }


def function_figure_ir() -> dict[str, object]:
    document = geometry_figure_ir()
    document["ir_id"] = "FIGURE-IR-002"
    document["revision_id"] = "FIGURE-IR-REV-002"
    document["figure_kind"] = "function"
    document["content"] = {
        "expressions": [
            {
                "id": "FUNCTION-001",
                "latex": "y=x^2",
                "domain": [-2, 2],
                "extensions": {},
            }
        ],
        "sample_interval": [-2, 2],
        "axes": {
            "x_range": [-2, 2],
            "y_range": [-1, 5],
            "x_label": "x",
            "y_label": "y",
            "show_grid": False,
            "extensions": {},
        },
        "special_points": [
            {
                "id": "POINT-O",
                "x": 0,
                "y": 0,
                "label": "O",
                "extensions": {},
            }
        ],
        "asymptotes": [],
        "extensions": {},
    }
    return document


def statistics_figure_ir() -> dict[str, object]:
    document = geometry_figure_ir()
    document["ir_id"] = "FIGURE-IR-003"
    document["revision_id"] = "FIGURE-IR-REV-003"
    document["figure_kind"] = "statistics"
    document["content"] = {
        "series": [
            {
                "id": "SERIES-001",
                "label": "frequency",
                "values": [2, 5, 3],
                "extensions": {},
            }
        ],
        "bin_width": 1,
        "ticks": {"x": [0, 1, 2, 3], "y": [0, 5]},
        "axes": {
            "x_range": [0, 3],
            "y_range": [0, 6],
            "x_label": "group",
            "y_label": "frequency",
            "show_grid": True,
            "extensions": {},
        },
        "legend": False,
        "extensions": {},
    }
    return document


def paper_ir() -> dict[str, object]:
    return {
        "schema_id": PAPER_IR_SCHEMA_ID,
        "schema_version": "1.0",
        "ir_id": "PAPER-IR-001",
        "revision_id": "PAPER-IR-REV-001",
        "paper_revision_id": "PAPER-REV-001",
        "document_roles": [
            "answer",
            "answer_sheet",
            "detailed_solution",
            "student",
            "teacher",
        ],
        "template_revision_id": "TEMPLATE-REV-001",
        "title_blocks": [_text("Test Paper")],
        "instruction_blocks": [_text("Answer all questions.")],
        "sections": [
            {
                "section_id": "SECTION-001",
                "title_blocks": [_text("Section I")],
                "question_entries": [
                    {
                        "question_revision_id": "QUESTION-REV-001",
                        "display_number": "1",
                        "points": 4,
                        "options_layout": "four_columns",
                        "answer_space_mm": None,
                        "page_break_before": False,
                        "extensions": {},
                    }
                ],
                "page_break_before": False,
                "extensions": {},
            }
        ],
        "header_blocks": [],
        "footer_blocks": [],
        "template_tokens": {"body.font.role": "FONT-ROLE-BODY", "margin.top.mm": 20},
        "declared_total_points": 4,
        "source_refs": [],
        "extensions": {},
    }


def test_question_ir_round_trip_is_canonical_and_stable() -> None:
    document = question_ir()
    validated = validate_question_ir(document)

    assert json.loads(canonical_json_bytes(validated)) == document
    assert ir_sha256(document) == ir_sha256(copy.deepcopy(document))


@pytest.mark.parametrize(
    "factory",
    [geometry_figure_ir, function_figure_ir, statistics_figure_ir],
)
def test_all_figure_ir_semantic_kinds_validate(factory) -> None:
    document = factory()

    assert validate_figure_ir(document) == document
    assert validate_ir_document(document) == document


def test_paper_ir_freezes_exact_question_and_template_revisions() -> None:
    document = paper_ir()

    assert validate_paper_ir(document) == document
    assert document["document_roles"] == sorted(document["document_roles"])
    assert dependency_revision_ids(document) == (
        "QUESTION-REV-001",
        "TEMPLATE-REV-001",
    )


def test_dependency_gate_fails_closed_on_stale_or_missing_revision() -> None:
    required = dependency_revision_ids(question_ir())

    assert "SOURCE-FILE-REV-001" in required
    assert "FIGURE-REV-001" in required
    with pytest.raises(IrContractError, match="missing"):
        assert_dependencies_available(question_ir(), required[:-1])
    assert assert_dependencies_available(question_ir(), required) == required


def test_v1_to_v09_rollback_and_forward_migration_are_lossless() -> None:
    current = question_ir()

    legacy = rollback_ir_document(current)
    restored = migrate_ir_document(legacy)

    assert restored == current
    assert legacy["schema_version"] == "0.9"
    assert legacy["id"] == current["ir_id"]
    assert "ir_id" not in legacy


def test_rollback_rejects_nonempty_extensions() -> None:
    document = question_ir()
    document["extensions"] = {"x-test-future": True}

    with pytest.raises(IrVersionError, match="losslessly"):
        rollback_ir_document(document)


@pytest.mark.parametrize(
    ("mutator", "message"),
    [
        (
            lambda value: value["source_refs"][0]["region"].__setitem__("units", "px"),
            "units does not match",
        ),
        (
            lambda value: value["source_refs"][0]["transforms"][0].__setitem__(
                "sequence", 2
            ),
            "sequence must be contiguous",
        ),
        (
            lambda value: value["source_refs"][0]["transforms"][0].__setitem__(
                "input_coordinate_space", "pixels_top_left"
            ),
            "coordinate spaces must form a chain",
        ),
        (
            lambda value: value.__setitem__("figure_revision_ids", []),
            "exactly match",
        ),
        (
            lambda value: value["scoring_points"][0].__setitem__("points", 3),
            "point sum",
        ),
        (
            lambda value: value.__setitem__("observed_item_time_seconds", 30),
            "present together",
        ),
        (
            lambda value: value.__setitem__("unknown", True),
            "unknown fields",
        ),
    ],
)
def test_question_ir_rejects_lossy_or_ambiguous_state(mutator, message: str) -> None:
    document = question_ir()
    mutator(document)

    with pytest.raises(IrContractError, match=message):
        validate_question_ir(document)


def test_paper_ir_rejects_total_or_latest_revision_drift() -> None:
    wrong_total = paper_ir()
    wrong_total["declared_total_points"] = 5
    with pytest.raises(IrContractError, match="point sum"):
        validate_paper_ir(wrong_total)

    latest = paper_ir()
    latest["sections"][0]["question_entries"][0]["question_revision_id"] = "LATEST"
    with pytest.raises(IrContractError, match="latest-version alias"):
        validate_paper_ir(latest)


def test_figure_ir_rejects_unknown_geometry_references() -> None:
    document = geometry_figure_ir()
    document["content"]["primitives"][0]["refs"] = ["POINT-A", "POINT-Z"]

    with pytest.raises(IrContractError, match="unknown point"):
        validate_figure_ir(document)


@pytest.mark.parametrize(
    ("schema_name", "fixture"),
    [
        ("question-ir-v1.schema.json", question_ir),
        ("figure-ir-v1.schema.json", geometry_figure_ir),
        ("paper-ir-v1.schema.json", paper_ir),
    ],
)
def test_json_schema_envelopes_match_runtime_contracts(
    schema_name: str,
    fixture,
) -> None:
    schema = json.loads(
        (Path("contracts") / "m0" / schema_name).read_text(encoding="utf-8")
    )

    assert set(schema["required"]) == set(fixture())
    assert schema["additionalProperties"] is False
