from __future__ import annotations

import copy
import json
import math
from pathlib import Path

import pytest

from app.gold_registry import (
    GOLD_REGISTRY_PATH,
    GoldRegistryError,
    load_gold_registry,
    load_measurement_synthetic,
    load_template_families,
    load_visual_thresholds,
    validate_gold_bundle,
    validate_gold_registry,
    validate_measurement_synthetic,
    validate_visual_thresholds,
)
from Task.tools.build_gold_registry_preview import _entry_from_members


def _json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def test_gold_bundle_covers_every_truth_role_and_template_family() -> None:
    result = validate_gold_bundle()

    assert result["entry_count"] == 18
    assert result["template_family_count"] == 12
    assert result["synthetic_measurement_subject_count"] == 8
    assert result["truth_roles"] == [
        "content",
        "failure",
        "figure",
        "measurement",
        "scoring",
        "tag",
        "template",
        "visual",
    ]


def test_gold_registry_contains_only_sanitized_logical_locators() -> None:
    registry = load_gold_registry()
    raw = GOLD_REGISTRY_PATH.read_text(encoding="utf-8")

    assert "E:\\" not in raw
    assert "C:\\" not in raw
    assert "AAA命题" not in raw
    assert "filename" not in raw
    assert "source_path" not in raw
    assert "absolute_path" not in raw
    assert all(
        member["member_id"].startswith("MEMBER-")
        for entry in registry["entries"]
        for member in entry["members"]
    )
    assert all(
        entry["test_copy_ref"] is None
        for entry in registry["entries"]
        if entry["copy_policy"] == "copy-on-use"
    )
    assert all(
        entry["confirmation"]["actor_ref"]
        in {"USER-PROVIDED-BASELINE", "SYNTHETIC-FIXTURE-AUDIT"}
        for entry in registry["entries"]
    )


def test_known_baseline_fingerprints_match_observed_reference_facts() -> None:
    registry = load_gold_registry()
    entries = {entry["logical_id"]: entry for entry in registry["entries"]}

    assert entries["REF-VIS-NEW9"]["page_count"] == 91
    assert any(
        math.isclose(width, 210.0, abs_tol=0.1)
        and math.isclose(height, 297.0, abs_tol=0.1)
        for width, height in entries["REF-VIS-NEW9"]["page_sizes_mm"]
    )
    assert any(
        math.isclose(width, 182.0, abs_tol=0.1)
        and math.isclose(height, 257.0, abs_tol=0.1)
        for width, height in entries["REF-VIS-NEW9"]["page_sizes_mm"]
    )
    assert entries["REF-CONTENT-HISTORY"]["page_count"] == 1207
    assert entries["REF-FIG-BROKEN-SVG"]["expected_outcome"] == "reject"
    assert (
        entries["REF-FIG-BROKEN-SVG"]["members"][0]["structural_status"]
        == "invalid_expected"
    )
    assert entries["REF-TAG-EVIDENCE-SET"]["pii_classification"] == "unknown"


def test_gold_registry_detects_member_and_aggregate_tampering() -> None:
    registry = load_gold_registry()
    registry["entries"][0]["members"][0]["sha256"] = "b" * 64

    with pytest.raises(GoldRegistryError, match="aggregate_sha256"):
        validate_gold_registry(registry)


def test_gold_registry_detects_top_level_tampering() -> None:
    registry = load_gold_registry()
    registry["extensions"] = {"x-test-note": "changed"}

    with pytest.raises(GoldRegistryError, match="registry_sha256"):
        validate_gold_registry(registry)


def test_visual_thresholds_cannot_be_silently_loosened() -> None:
    thresholds = load_visual_thresholds()
    thresholds["critical_anchor_max_mm"] = 0.51

    with pytest.raises(GoldRegistryError, match="exceed"):
        validate_visual_thresholds(thresholds)

    thresholds = load_visual_thresholds()
    thresholds["crop_pixels_allowed"] = 1
    with pytest.raises(GoldRegistryError, match="must be zero"):
        validate_visual_thresholds(thresholds)

    thresholds = load_visual_thresholds()
    thresholds["page_size_representation_tolerance_mm"] = 0.02
    with pytest.raises(GoldRegistryError, match="exceeds"):
        validate_visual_thresholds(thresholds)


def test_template_families_keep_distinct_fixed_page_sizes() -> None:
    templates = load_template_families()
    fixed = {
        family["template_family_id"]: (family["width_mm"], family["height_mm"])
        for family in templates["families"]
        if family["size_mode"] == "fixed"
    }

    assert fixed["TEMPLATE-COMPACT-176X250"] == (176, 250)
    assert fixed["TEMPLATE-NEW9-B5-182X257"] == (182, 257)
    assert fixed["TEMPLATE-EDITABLE-B5-184X260"] == (184, 260)
    assert fixed["TEMPLATE-OFFICIAL-A4"] == (210, 297)
    assert fixed["TEMPLATE-TRUE-QUESTION-A3-LANDSCAPE"] == (420, 297)


def test_synthetic_measurement_fixture_contains_no_personal_fields_and_correct_p() -> None:
    fixture = load_measurement_synthetic()
    forbidden = {"name", "student_id", "school", "class", "ip", "qq", "email", "phone"}

    def keys(value):
        if isinstance(value, dict):
            for key, item in value.items():
                yield key.casefold()
                yield from keys(item)
        elif isinstance(value, list):
            for item in value:
                yield from keys(item)

    assert fixture["synthetic"] is True
    assert forbidden.isdisjoint(set(keys(fixture)))
    assert fixture["time_semantics"]["observed_item_time_available"] is False
    for item_id, maximum in fixture["item_max_points"].items():
        scores = [row["item_scores"][item_id] for row in fixture["responses"]]
        observed = sum(scores) / (len(scores) * maximum)
        assert math.isclose(
            observed,
            fixture["expected_item_difficulty_p"][item_id],
            abs_tol=1e-9,
        )


def test_synthetic_measurement_rejects_score_or_time_semantic_tampering() -> None:
    fixture = load_measurement_synthetic()
    fixture["responses"][0]["item_scores"]["ITEM-001"] = 99
    with pytest.raises(GoldRegistryError, match="exceeds its maximum"):
        validate_measurement_synthetic(fixture)

    fixture = load_measurement_synthetic()
    fixture["time_semantics"]["observed_item_time_available"] = True
    with pytest.raises(GoldRegistryError, match="time semantics"):
        validate_measurement_synthetic(fixture)


def test_source_plan_is_sorted_and_private_mapping_is_git_ignored() -> None:
    plan = _json(Path("gold/m0/gold-source-plan-v1.json"))
    logical_ids = [entry["logical_id"] for entry in plan["entries"]]
    ignore_text = Path(".gitignore").read_text(encoding="utf-8")

    assert logical_ids == sorted(set(logical_ids))
    assert "Task/local/" in ignore_text
    assert "REF-MEASUREMENT-SYNTHETIC" in logical_ids


def test_preview_aggregate_is_deterministic_and_does_not_need_source_names() -> None:
    plan = _json(Path("gold/m0/gold-source-plan-v1.json"))
    synthetic_plan = next(
        entry
        for entry in plan["entries"]
        if entry["logical_id"] == "REF-MEASUREMENT-SYNTHETIC"
    )
    first = {
        "sha256": "1" * 64,
        "bytes": 10,
        "format": ".json",
        "page_count": None,
        "page_sizes_mm": [],
        "structural_status": "readable",
        "extensions": {},
    }
    second = {
        "sha256": "0" * 64,
        "bytes": 20,
        "format": ".json",
        "page_count": None,
        "page_sizes_mm": [],
        "structural_status": "readable",
        "extensions": {},
    }

    confirmation = plan["confirmation_policy"]["synthetic"]
    forward = _entry_from_members(
        copy.deepcopy(synthetic_plan),
        [first, second],
        confirmation=confirmation,
    )
    reverse = _entry_from_members(
        copy.deepcopy(synthetic_plan),
        [second, first],
        confirmation=confirmation,
    )

    assert forward == reverse
    assert set(forward["members"][0]) == {
        "member_id",
        "sha256",
        "bytes",
        "format",
        "page_count",
        "page_sizes_mm",
        "structural_status",
        "extensions",
    }


@pytest.mark.parametrize(
    ("schema_name", "artifact_name"),
    [
        ("gold-registry-v1.schema.json", "gold-registry-v1.json"),
        ("template-families-v1.schema.json", "template-families-v1.json"),
        ("visual-thresholds-v1.schema.json", "visual-thresholds-v1.json"),
        ("measurement-synthetic-v1.schema.json", "measurement-synthetic-v1.json"),
    ],
)
def test_gold_json_schema_envelopes_match_artifacts(
    schema_name: str,
    artifact_name: str,
) -> None:
    schema = _json(Path("contracts/m0") / schema_name)
    artifact = _json(Path("gold/m0") / artifact_name)

    assert set(schema["required"]) == set(artifact)
    assert schema["additionalProperties"] is False
