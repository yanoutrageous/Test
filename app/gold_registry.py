from __future__ import annotations

import hashlib
import json
import math
import re
from datetime import date
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping

from .project_root import PROJECT_ROOT


GOLD_REGISTRY_SCHEMA_ID = "LOCAL_EXAM_BANK_GOLD_REGISTRY"
TEMPLATE_FAMILIES_SCHEMA_ID = "LOCAL_EXAM_BANK_TEMPLATE_FAMILIES"
VISUAL_THRESHOLDS_SCHEMA_ID = "LOCAL_EXAM_BANK_VISUAL_THRESHOLDS"
MEASUREMENT_SYNTHETIC_SCHEMA_ID = "LOCAL_EXAM_BANK_SYNTHETIC_MEASUREMENT"
GOLD_SCHEMA_VERSION = "1.0"

GOLD_ROOT = PROJECT_ROOT / "gold" / "m0"
GOLD_REGISTRY_PATH = GOLD_ROOT / "gold-registry-v1.json"
TEMPLATE_FAMILIES_PATH = GOLD_ROOT / "template-families-v1.json"
VISUAL_THRESHOLDS_PATH = GOLD_ROOT / "visual-thresholds-v1.json"
MEASUREMENT_SYNTHETIC_PATH = GOLD_ROOT / "measurement-synthetic-v1.json"

TRUTH_ROLES = frozenset(
    {
        "visual",
        "content",
        "scoring",
        "figure",
        "measurement",
        "failure",
        "tag",
        "template",
    }
)
EXPECTED_OUTCOMES = frozenset({"pass", "review", "reject"})
LICENSE_STATUSES = frozenset(
    {
        "synthetic",
        "user-owned",
        "local-use-only",
        "redistributable",
        "unverified",
    }
)
PII_CLASSIFICATIONS = frozenset({"none", "internal", "restricted", "unknown"})
SOURCE_KINDS = frozenset({"file", "set", "synthetic"})
TEMPLATE_DOCUMENT_ROLES = frozenset(
    {"student", "teacher", "answer", "detailed_solution", "answer_sheet"}
)

_ID_PATTERN = re.compile(r"[A-Z][A-Z0-9._-]{2,127}")
_LOGICAL_ID_PATTERN = re.compile(r"REF-[A-Z0-9][A-Z0-9._-]{2,127}")
_MEMBER_ID_PATTERN = re.compile(r"MEMBER-\d{3,5}")
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
_FORMAT_PATTERN = re.compile(r"\.[a-z0-9]{1,12}")
_EXTENSION_KEY_PATTERN = re.compile(r"x-[a-z0-9][a-z0-9._-]{0,62}")


class GoldRegistryError(ValueError):
    pass


def _fail(message: str) -> None:
    raise GoldRegistryError(message)


def _exact(value: Mapping[str, Any], fields: Iterable[str], context: str) -> None:
    expected = frozenset(fields)
    actual = frozenset(value)
    missing = expected - actual
    unknown = actual - expected
    if missing:
        _fail(f"{context} is missing fields: {', '.join(sorted(missing))}")
    if unknown:
        _fail(f"{context} has unknown fields: {', '.join(sorted(unknown))}")


def _identifier(value: Any, context: str, *, logical: bool = False) -> str:
    pattern = _LOGICAL_ID_PATTERN if logical else _ID_PATTERN
    if type(value) is not str or not pattern.fullmatch(value):
        _fail(f"{context} is not a contracted identifier")
    return value


def _sha256(value: Any, context: str) -> str:
    if type(value) is not str or not _SHA256_PATTERN.fullmatch(value):
        _fail(f"{context} must be a lowercase SHA-256")
    return value


def _number(
    value: Any,
    context: str,
    *,
    minimum: float | None = None,
) -> float:
    if type(value) not in (int, float) or not math.isfinite(float(value)):
        _fail(f"{context} must be a finite number")
    converted = float(value)
    if minimum is not None and converted < minimum:
        _fail(f"{context} must be >= {minimum}")
    return converted


def _extensions(value: Any, context: str) -> None:
    if type(value) is not dict:
        _fail(f"{context} must be an object")
    for key, item in value.items():
        if type(key) is not str or not _EXTENSION_KEY_PATTERN.fullmatch(key):
            _fail(f"{context} keys must use the x-* namespace")
        _json_value(item, f"{context}.{key}")


def _json_value(value: Any, context: str, depth: int = 0) -> None:
    if depth > 20:
        _fail(f"{context} exceeds the maximum JSON depth")
    if value is None or type(value) in (str, int, bool):
        return
    if type(value) is float:
        if not math.isfinite(value):
            _fail(f"{context} contains a non-finite number")
        return
    if type(value) is list:
        for index, item in enumerate(value):
            _json_value(item, f"{context}[{index}]", depth + 1)
        return
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str or not key:
                _fail(f"{context} contains an invalid key")
            _json_value(item, f"{context}.{key}", depth + 1)
        return
    _fail(f"{context} contains a non-JSON value")


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise GoldRegistryError("gold artifact contains non-canonical JSON") from exc


def _clone(value: Mapping[str, Any]) -> dict[str, Any]:
    return json.loads(_canonical_bytes(value).decode("utf-8"))


def _string_list(
    value: Any,
    context: str,
    *,
    allowed: frozenset[str] | None = None,
    identifiers: bool = False,
) -> list[str]:
    if type(value) is not list:
        _fail(f"{context} must be a list")
    result: list[str] = []
    for index, item in enumerate(value):
        if type(item) is not str or not item:
            _fail(f"{context}[{index}] must be a non-empty string")
        if allowed is not None and item not in allowed:
            _fail(f"{context}[{index}] is unsupported")
        if identifiers:
            _identifier(item, f"{context}[{index}]")
        result.append(item)
    if result != sorted(set(result)):
        _fail(f"{context} must be unique and sorted")
    return result


def _page_sizes(value: Any, context: str) -> list[tuple[float, float]]:
    if type(value) is not list:
        _fail(f"{context} must be a list")
    result: list[tuple[float, float]] = []
    for index, item in enumerate(value):
        if type(item) is not list or len(item) != 2:
            _fail(f"{context}[{index}] must contain width and height")
        width = _number(item[0], f"{context}[{index}][0]", minimum=0.001)
        height = _number(item[1], f"{context}[{index}][1]", minimum=0.001)
        result.append((width, height))
    if result != sorted(set(result)):
        _fail(f"{context} must be unique and sorted")
    return result


def _relative_path_or_null(value: Any, context: str) -> None:
    if value is None:
        return
    if type(value) is not str or not value or "\\" in value or ":" in value:
        _fail(f"{context} must be a normalized project-relative path or null")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or any(part in ("", ".", "..") for part in path.parts)
        or path.as_posix() != value
    ):
        _fail(f"{context} must not be absolute or traverse parents")


def _validate_member(value: Any, context: str) -> None:
    if type(value) is not dict:
        _fail(f"{context} must be an object")
    _exact(
        value,
        {
            "member_id",
            "sha256",
            "bytes",
            "format",
            "page_count",
            "page_sizes_mm",
            "structural_status",
            "extensions",
        },
        context,
    )
    if type(value["member_id"]) is not str or not _MEMBER_ID_PATTERN.fullmatch(
        value["member_id"]
    ):
        _fail(f"{context}.member_id must be opaque")
    _sha256(value["sha256"], f"{context}.sha256")
    if type(value["bytes"]) is not int or value["bytes"] < 0:
        _fail(f"{context}.bytes must be a non-negative integer")
    if type(value["format"]) is not str or not _FORMAT_PATTERN.fullmatch(
        value["format"]
    ):
        _fail(f"{context}.format is invalid")
    if value["page_count"] is not None and (
        type(value["page_count"]) is not int or value["page_count"] < 1
    ):
        _fail(f"{context}.page_count must be positive or null")
    _page_sizes(value["page_sizes_mm"], f"{context}.page_sizes_mm")
    if value["structural_status"] not in {
        "readable",
        "invalid_expected",
        "not_applicable",
    }:
        _fail(f"{context}.structural_status is invalid")
    _extensions(value["extensions"], f"{context}.extensions")
    forbidden = {"path", "name", "filename", "source_path", "absolute_path"}
    if forbidden & set(value):
        _fail(f"{context} exposes a source locator")


def _validate_confirmation(value: Any, context: str) -> None:
    if type(value) is not dict:
        _fail(f"{context} must be an object")
    _exact(
        value,
        {
            "status",
            "actor_ref",
            "confirmed_on",
            "gold_revision",
            "change_reason",
            "previous_aggregate_sha256",
        },
        context,
    )
    if value["status"] not in {
        "user-provided-project-baseline",
        "synthetic-fixture-verified",
    }:
        _fail(f"{context}.status is unsupported")
    _identifier(value["actor_ref"], f"{context}.actor_ref")
    if type(value["confirmed_on"]) is not str:
        _fail(f"{context}.confirmed_on must be an ISO date")
    try:
        date.fromisoformat(value["confirmed_on"])
    except ValueError as exc:
        raise GoldRegistryError(f"{context}.confirmed_on must be a real ISO date") from exc
    if type(value["gold_revision"]) is not int or value["gold_revision"] < 1:
        _fail(f"{context}.gold_revision must be positive")
    if (
        type(value["change_reason"]) is not str
        or not value["change_reason"]
        or len(value["change_reason"]) > 256
    ):
        _fail(f"{context}.change_reason must be a bounded non-empty string")
    previous = value["previous_aggregate_sha256"]
    if value["gold_revision"] == 1:
        if previous is not None:
            _fail(f"{context} initial revision cannot have a predecessor")
    elif previous is None:
        _fail(f"{context} later revisions require a predecessor digest")
    else:
        _sha256(previous, f"{context}.previous_aggregate_sha256")


def _validate_registry_entry(value: Any, context: str) -> None:
    if type(value) is not dict:
        _fail(f"{context} must be an object")
    _exact(
        value,
        {
            "logical_id",
            "truth_roles",
            "source_kind",
            "member_count",
            "total_bytes",
            "aggregate_sha256",
            "formats",
            "page_count",
            "page_sizes_mm",
            "template_family_ids",
            "requirement_ids",
            "risk_ids",
            "license_status",
            "pii_classification",
            "expected_outcome",
            "verification_status",
            "local_mapping_required",
            "copy_policy",
            "test_copy_ref",
            "baseline_authority",
            "confirmation",
            "members",
            "extensions",
        },
        context,
    )
    _identifier(value["logical_id"], f"{context}.logical_id", logical=True)
    _string_list(
        value["truth_roles"],
        f"{context}.truth_roles",
        allowed=TRUTH_ROLES,
    )
    if not value["truth_roles"]:
        _fail(f"{context}.truth_roles cannot be empty")
    if value["source_kind"] not in SOURCE_KINDS:
        _fail(f"{context}.source_kind is invalid")
    if type(value["member_count"]) is not int or value["member_count"] < 1:
        _fail(f"{context}.member_count must be positive")
    if type(value["total_bytes"]) is not int or value["total_bytes"] < 0:
        _fail(f"{context}.total_bytes must be non-negative")
    _sha256(value["aggregate_sha256"], f"{context}.aggregate_sha256")
    formats = _string_list(value["formats"], f"{context}.formats")
    if not formats or any(not _FORMAT_PATTERN.fullmatch(item) for item in formats):
        _fail(f"{context}.formats is invalid")
    if value["page_count"] is not None and (
        type(value["page_count"]) is not int or value["page_count"] < 1
    ):
        _fail(f"{context}.page_count must be positive or null")
    _page_sizes(value["page_sizes_mm"], f"{context}.page_sizes_mm")
    _string_list(
        value["template_family_ids"],
        f"{context}.template_family_ids",
        identifiers=True,
    )
    requirements = _string_list(
        value["requirement_ids"], f"{context}.requirement_ids"
    )
    if not requirements or any(not item.startswith("M0-") for item in requirements):
        _fail(f"{context}.requirement_ids must contain M0 requirements")
    risks = _string_list(value["risk_ids"], f"{context}.risk_ids")
    if any(not re.fullmatch(r"R-\d{3}", item) for item in risks):
        _fail(f"{context}.risk_ids is invalid")
    if value["license_status"] not in LICENSE_STATUSES:
        _fail(f"{context}.license_status is invalid")
    if value["pii_classification"] not in PII_CLASSIFICATIONS:
        _fail(f"{context}.pii_classification is invalid")
    if value["expected_outcome"] not in EXPECTED_OUTCOMES:
        _fail(f"{context}.expected_outcome is invalid")
    if value["verification_status"] not in {
        "machine_fingerprinted_role_from_project_baseline",
        "synthetic_verified",
    }:
        _fail(f"{context}.verification_status is invalid")
    if type(value["local_mapping_required"]) is not bool:
        _fail(f"{context}.local_mapping_required must be boolean")
    if value["copy_policy"] not in {"copy-on-use", "synthetic-in-git"}:
        _fail(f"{context}.copy_policy is invalid")
    _relative_path_or_null(value["test_copy_ref"], f"{context}.test_copy_ref")
    if value["copy_policy"] == "synthetic-in-git" and value["test_copy_ref"] is None:
        _fail(f"{context} synthetic entries require test_copy_ref")
    if value["copy_policy"] == "copy-on-use" and value["test_copy_ref"] is not None:
        _fail(f"{context} copy-on-use entries cannot claim an existing Test copy")
    if (
        type(value["baseline_authority"]) is not str
        or value["baseline_authority"] != "Task/11_REFERENCE_BASELINE.md"
    ):
        _fail(f"{context}.baseline_authority is unsupported")
    _validate_confirmation(value["confirmation"], f"{context}.confirmation")
    if value["source_kind"] == "synthetic":
        if (
            value["license_status"] != "synthetic"
            or value["pii_classification"] != "none"
            or value["verification_status"] != "synthetic_verified"
            or value["local_mapping_required"] is not False
            or value["copy_policy"] != "synthetic-in-git"
            or value["confirmation"]["status"] != "synthetic-fixture-verified"
        ):
            _fail(f"{context} synthetic governance fields are inconsistent")
    elif (
        value["verification_status"]
        != "machine_fingerprinted_role_from_project_baseline"
        or value["local_mapping_required"] is not True
        or value["copy_policy"] != "copy-on-use"
        or value["confirmation"]["status"]
        != "user-provided-project-baseline"
    ):
        _fail(f"{context} external governance fields are inconsistent")
    members = value["members"]
    if type(members) is not list or len(members) != value["member_count"]:
        _fail(f"{context}.members does not match member_count")
    for index, member in enumerate(members):
        _validate_member(member, f"{context}.members[{index}]")
        expected_member_id = f"MEMBER-{index + 1:03d}"
        if member["member_id"] != expected_member_id:
            _fail(f"{context}.members must use contiguous opaque member ids")
    if sum(member["bytes"] for member in members) != value["total_bytes"]:
        _fail(f"{context}.total_bytes does not match members")
    if sorted({member["format"] for member in members}) != formats:
        _fail(f"{context}.formats does not match members")
    member_pages = [member["page_count"] for member in members]
    if all(item is not None for item in member_pages):
        if value["page_count"] != sum(int(item) for item in member_pages):
            _fail(f"{context}.page_count does not match members")
    elif value["page_count"] is not None:
        _fail(f"{context}.page_count must be null when a member count is unknown")
    all_sizes = sorted(
        {
            tuple(size)
            for member in members
            for size in member["page_sizes_mm"]
        }
    )
    if [list(item) for item in all_sizes] != value["page_sizes_mm"]:
        _fail(f"{context}.page_sizes_mm does not match members")
    aggregate_payload = [
        {
            "bytes": member["bytes"],
            "format": member["format"],
            "page_count": member["page_count"],
            "page_sizes_mm": member["page_sizes_mm"],
            "sha256": member["sha256"],
            "structural_status": member["structural_status"],
        }
        for member in members
    ]
    aggregate = hashlib.sha256(_canonical_bytes({"members": aggregate_payload})).hexdigest()
    if aggregate != value["aggregate_sha256"]:
        _fail(f"{context}.aggregate_sha256 does not match members")
    _extensions(value["extensions"], f"{context}.extensions")


def validate_gold_registry(document: Any) -> dict[str, Any]:
    if type(document) is not dict:
        _fail("gold registry must be an object")
    _exact(
        document,
        {
            "schema_id",
            "schema_version",
            "registry_id",
            "baseline_authority",
            "entries",
            "required_truth_roles",
            "required_template_family_ids",
            "extensions",
            "registry_sha256",
        },
        "gold registry",
    )
    if document["schema_id"] != GOLD_REGISTRY_SCHEMA_ID:
        _fail("gold registry schema_id is unsupported")
    if document["schema_version"] != GOLD_SCHEMA_VERSION:
        _fail("gold registry schema_version is unsupported")
    _identifier(document["registry_id"], "gold registry registry_id")
    if document["baseline_authority"] != "Task/11_REFERENCE_BASELINE.md":
        _fail("gold registry baseline_authority is unsupported")
    required_roles = _string_list(
        document["required_truth_roles"],
        "gold registry required_truth_roles",
        allowed=TRUTH_ROLES,
    )
    if set(required_roles) != TRUTH_ROLES:
        _fail("gold registry must require every truth role")
    required_families = _string_list(
        document["required_template_family_ids"],
        "gold registry required_template_family_ids",
        identifiers=True,
    )
    if not required_families:
        _fail("gold registry required_template_family_ids cannot be empty")
    entries = document["entries"]
    if type(entries) is not list or not entries:
        _fail("gold registry entries must be a non-empty list")
    logical_ids: list[str] = []
    covered_roles: set[str] = set()
    covered_families: set[str] = set()
    for index, entry in enumerate(entries):
        _validate_registry_entry(entry, f"gold registry entries[{index}]")
        logical_ids.append(entry["logical_id"])
        covered_roles.update(entry["truth_roles"])
        covered_families.update(entry["template_family_ids"])
    if logical_ids != sorted(set(logical_ids)):
        _fail("gold registry entries must be unique and sorted by logical_id")
    if covered_roles != set(required_roles):
        _fail("gold registry truth-role coverage is incomplete")
    if not set(required_families).issubset(covered_families):
        _fail("gold registry template-family coverage is incomplete")
    _extensions(document["extensions"], "gold registry extensions")
    expected = hashlib.sha256(
        _canonical_bytes(
            {
                key: value
                for key, value in document.items()
                if key != "registry_sha256"
            }
        )
    ).hexdigest()
    _sha256(document["registry_sha256"], "gold registry registry_sha256")
    if document["registry_sha256"] != expected:
        _fail("gold registry registry_sha256 does not match its payload")
    return _clone(document)


def validate_template_families(document: Any) -> dict[str, Any]:
    if type(document) is not dict:
        _fail("template families must be an object")
    _exact(
        document,
        {"schema_id", "schema_version", "families", "extensions"},
        "template families",
    )
    if document["schema_id"] != TEMPLATE_FAMILIES_SCHEMA_ID:
        _fail("template families schema_id is unsupported")
    if document["schema_version"] != GOLD_SCHEMA_VERSION:
        _fail("template families schema_version is unsupported")
    families = document["families"]
    if type(families) is not list or not families:
        _fail("template families must contain entries")
    identifiers: list[str] = []
    for index, family in enumerate(families):
        context = f"template families[{index}]"
        if type(family) is not dict:
            _fail(f"{context} must be an object")
        _exact(
            family,
            {
                "template_family_id",
                "label",
                "size_mode",
                "width_mm",
                "height_mm",
                "orientation",
                "document_roles",
                "reference_logical_ids",
                "extensions",
            },
            context,
        )
        identifiers.append(
            _identifier(family["template_family_id"], f"{context}.template_family_id")
        )
        if type(family["label"]) is not str or not family["label"]:
            _fail(f"{context}.label must be non-empty")
        if family["size_mode"] not in {"fixed", "reference-dependent", "not-applicable"}:
            _fail(f"{context}.size_mode is invalid")
        if family["size_mode"] == "fixed":
            _number(family["width_mm"], f"{context}.width_mm", minimum=0.001)
            _number(family["height_mm"], f"{context}.height_mm", minimum=0.001)
        elif family["width_mm"] is not None or family["height_mm"] is not None:
            _fail(f"{context} non-fixed sizes must be null")
        if family["orientation"] not in {
            "portrait",
            "landscape",
            "reference-dependent",
            "not-applicable",
        }:
            _fail(f"{context}.orientation is invalid")
        roles = _string_list(
            family["document_roles"],
            f"{context}.document_roles",
            allowed=TEMPLATE_DOCUMENT_ROLES,
        )
        if not roles:
            _fail(f"{context}.document_roles cannot be empty")
        reference_ids = family["reference_logical_ids"]
        if type(reference_ids) is not list or not reference_ids:
            _fail(f"{context}.reference_logical_ids must be non-empty")
        for ref_index, logical_id in enumerate(reference_ids):
            _identifier(
                logical_id,
                f"{context}.reference_logical_ids[{ref_index}]",
                logical=True,
            )
        if reference_ids != sorted(set(reference_ids)):
            _fail(f"{context}.reference_logical_ids must be unique and sorted")
        _extensions(family["extensions"], f"{context}.extensions")
    if identifiers != sorted(set(identifiers)):
        _fail("template families must be unique and sorted")
    _extensions(document["extensions"], "template families extensions")
    return _clone(document)


def validate_visual_thresholds(document: Any) -> dict[str, Any]:
    if type(document) is not dict:
        _fail("visual thresholds must be an object")
    _exact(
        document,
        {
            "schema_id",
            "schema_version",
            "engine_lock_required",
            "raster_dpi",
            "color_space",
            "page_size_policy",
            "page_size_representation_tolerance_mm",
            "page_count_policy",
            "critical_anchor_max_mm",
            "major_anchor_max_mm",
            "crop_pixels_allowed",
            "overflow_pixels_allowed",
            "silent_font_substitutions_allowed",
            "pixel_metric_role",
            "manual_overlay_required",
            "change_control",
            "extensions",
        },
        "visual thresholds",
    )
    if document["schema_id"] != VISUAL_THRESHOLDS_SCHEMA_ID:
        _fail("visual thresholds schema_id is unsupported")
    if document["schema_version"] != GOLD_SCHEMA_VERSION:
        _fail("visual thresholds schema_version is unsupported")
    if document["engine_lock_required"] is not True:
        _fail("visual thresholds must require an engine lock")
    if type(document["raster_dpi"]) is not int or document["raster_dpi"] < 72:
        _fail("visual thresholds raster_dpi is too low")
    if document["color_space"] != "sRGB":
        _fail("visual thresholds color_space must be sRGB")
    if document["page_size_policy"] != "exact-reference":
        _fail("visual thresholds page_size_policy must be exact-reference")
    representation_tolerance = _number(
        document["page_size_representation_tolerance_mm"],
        "page_size_representation_tolerance_mm",
        minimum=0,
    )
    if representation_tolerance > 0.01:
        _fail("visual page-size representation tolerance exceeds 0.01 mm")
    if document["page_count_policy"] != "exact":
        _fail("visual thresholds page_count_policy must be exact")
    critical = _number(
        document["critical_anchor_max_mm"],
        "critical_anchor_max_mm",
        minimum=0,
    )
    major = _number(
        document["major_anchor_max_mm"],
        "major_anchor_max_mm",
        minimum=0,
    )
    if critical > 0.5 or major > 1.0 or critical > major:
        _fail("visual anchor thresholds exceed the M0 contract")
    for field in (
        "crop_pixels_allowed",
        "overflow_pixels_allowed",
        "silent_font_substitutions_allowed",
    ):
        if document[field] != 0:
            _fail(f"visual thresholds {field} must be zero")
    if document["pixel_metric_role"] != "diagnostic-not-sole-gate":
        _fail("visual thresholds pixel_metric_role is invalid")
    if document["manual_overlay_required"] is not True:
        _fail("visual thresholds must require manual overlay")
    if document["change_control"] != "D2_ADR_INDEPENDENT_AUDIT":
        _fail("visual thresholds change_control is invalid")
    _extensions(document["extensions"], "visual thresholds extensions")
    return _clone(document)


def validate_measurement_synthetic(document: Any) -> dict[str, Any]:
    if type(document) is not dict:
        _fail("synthetic measurement fixture must be an object")
    _exact(
        document,
        {
            "schema_id",
            "schema_version",
            "dataset_id",
            "synthetic",
            "item_max_points",
            "responses",
            "expected_item_difficulty_p",
            "time_semantics",
            "extensions",
        },
        "synthetic measurement fixture",
    )
    if document["schema_id"] != MEASUREMENT_SYNTHETIC_SCHEMA_ID:
        _fail("synthetic measurement schema_id is unsupported")
    if document["schema_version"] != GOLD_SCHEMA_VERSION:
        _fail("synthetic measurement schema_version is unsupported")
    _identifier(document["dataset_id"], "synthetic measurement dataset_id")
    if document["synthetic"] is not True:
        _fail("measurement fixture must be explicitly synthetic")
    maxima = document["item_max_points"]
    if type(maxima) is not dict or not maxima:
        _fail("synthetic measurement item_max_points must be non-empty")
    item_ids = sorted(maxima)
    if list(maxima) != item_ids:
        _fail("synthetic measurement item_max_points must be sorted")
    for item_id in item_ids:
        maximum = maxima[item_id]
        _identifier(item_id, f"synthetic measurement item {item_id}")
        _number(maximum, f"synthetic measurement maximum {item_id}", minimum=0.000001)
    responses = document["responses"]
    if type(responses) is not list or len(responses) < 2:
        _fail("synthetic measurement responses must contain at least two rows")
    subject_ids: list[str] = []
    observed_scores: dict[str, list[float]] = {item_id: [] for item_id in item_ids}
    for index, response in enumerate(responses):
        context = f"synthetic measurement responses[{index}]"
        if type(response) is not dict:
            _fail(f"{context} must be an object")
        _exact(
            response,
            {"synthetic_subject_id", "whole_paper_minutes", "item_scores"},
            context,
        )
        subject_ids.append(
            _identifier(response["synthetic_subject_id"], f"{context}.synthetic_subject_id")
        )
        if (
            type(response["whole_paper_minutes"]) is not int
            or response["whole_paper_minutes"] < 1
        ):
            _fail(f"{context}.whole_paper_minutes must be positive")
        scores = response["item_scores"]
        if type(scores) is not dict or list(scores) != item_ids:
            _fail(f"{context}.item_scores must exactly match sorted item ids")
        for item_id in item_ids:
            score = scores[item_id]
            converted = _number(
                score,
                f"{context}.item_scores.{item_id}",
                minimum=0,
            )
            if converted > float(maxima[item_id]):
                _fail(f"{context}.item_scores.{item_id} exceeds its maximum")
            observed_scores[item_id] = [*observed_scores[item_id], converted]
    if subject_ids != sorted(set(subject_ids)):
        _fail("synthetic measurement subject ids must be unique and sorted")
    expected = document["expected_item_difficulty_p"]
    if type(expected) is not dict or list(expected) != item_ids:
        _fail("expected_item_difficulty_p must exactly match sorted item ids")
    for item_id in item_ids:
        declared = expected[item_id]
        declared_value = _number(
            declared,
            f"expected_item_difficulty_p.{item_id}",
            minimum=0,
        )
        if declared_value > 1:
            _fail(f"expected_item_difficulty_p.{item_id} must be <= 1")
        calculated = sum(observed_scores[item_id]) / (
            len(responses) * float(maxima[item_id])
        )
        if not math.isclose(calculated, declared_value, rel_tol=0, abs_tol=1e-9):
            _fail(f"expected_item_difficulty_p.{item_id} does not match responses")
    time_semantics = document["time_semantics"]
    if type(time_semantics) is not dict:
        _fail("synthetic measurement time_semantics must be an object")
    _exact(
        time_semantics,
        {
            "whole_paper_time_available",
            "observed_item_time_available",
            "observed_item_time_policy",
        },
        "synthetic measurement time_semantics",
    )
    if (
        time_semantics["whole_paper_time_available"] is not True
        or time_semantics["observed_item_time_available"] is not False
        or time_semantics["observed_item_time_policy"] != "must-remain-null"
    ):
        _fail("synthetic measurement time semantics are unsupported")
    _extensions(document["extensions"], "synthetic measurement extensions")
    return _clone(document)


def _load_json(path: Path) -> dict[str, Any]:
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise GoldRegistryError(f"cannot read gold artifact: {path.name}") from exc
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise GoldRegistryError(f"gold artifact is not UTF-8: {path.name}") from exc
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise GoldRegistryError(f"gold artifact is invalid JSON: {path.name}") from exc
    if type(value) is not dict:
        _fail(f"gold artifact root must be an object: {path.name}")
    return value


def load_gold_registry(path: Path = GOLD_REGISTRY_PATH) -> dict[str, Any]:
    return validate_gold_registry(_load_json(path))


def load_template_families(path: Path = TEMPLATE_FAMILIES_PATH) -> dict[str, Any]:
    return validate_template_families(_load_json(path))


def load_visual_thresholds(path: Path = VISUAL_THRESHOLDS_PATH) -> dict[str, Any]:
    return validate_visual_thresholds(_load_json(path))


def load_measurement_synthetic(
    path: Path = MEASUREMENT_SYNTHETIC_PATH,
) -> dict[str, Any]:
    return validate_measurement_synthetic(_load_json(path))


def validate_gold_bundle(
    *,
    registry_path: Path = GOLD_REGISTRY_PATH,
    template_path: Path = TEMPLATE_FAMILIES_PATH,
    thresholds_path: Path = VISUAL_THRESHOLDS_PATH,
    measurement_path: Path = MEASUREMENT_SYNTHETIC_PATH,
) -> dict[str, Any]:
    registry = load_gold_registry(registry_path)
    templates = load_template_families(template_path)
    thresholds = load_visual_thresholds(thresholds_path)
    measurement = load_measurement_synthetic(measurement_path)
    template_ids = {item["template_family_id"] for item in templates["families"]}
    if template_ids != set(registry["required_template_family_ids"]):
        _fail("gold registry and template-family catalog do not cover the same ids")
    entry_ids = {item["logical_id"] for item in registry["entries"]}
    for family in templates["families"]:
        missing = set(family["reference_logical_ids"]) - entry_ids
        if missing:
            _fail(
                "template family references missing gold ids: "
                + ", ".join(sorted(missing))
            )
    return {
        "schema_version": GOLD_SCHEMA_VERSION,
        "registry_sha256": registry["registry_sha256"],
        "entry_count": len(registry["entries"]),
        "template_family_count": len(templates["families"]),
        "synthetic_measurement_subject_count": len(measurement["responses"]),
        "truth_roles": sorted(
            {
                role
                for entry in registry["entries"]
                for role in entry["truth_roles"]
            }
        ),
        "thresholds": thresholds,
    }
