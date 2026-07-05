from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .config import PROJECT_ROOT
from .stage10 import HIGH_RISK_PAGES
from .structured_content import parse_json_field
from .structured_validation import validate_structured_row


USABILITY_CLASSIFICATION_VERSION = "stage11_usability_v1"
USABILITY_STATUSES = (
    "strict_structured",
    "visual_fallback",
    "needs_formula_repair",
    "needs_blank_repair",
    "needs_type_review",
    "needs_recut",
    "failed",
    "protected",
)
EXPORT_USABLE_STATUSES = ("strict_structured", "visual_fallback")
RENDER_MODES = ("structured_html", "raw_crop_image", "candidate_preview", "none")
STRICT_STRUCTURED_AI_STATUSES = ("ai_verified", "human_reviewed")
PROTECTED_QUESTION_STATUSES = ("reviewed", "approved")


class RiskClassifier:
    """Classify a question candidate into Stage 11 usability lanes."""

    def __init__(self, *, project_root: Path = PROJECT_ROOT):
        self.project_root = project_root

    def classify(self, row: dict[str, Any]) -> dict[str, Any]:
        issue_flags = _dedupe(_quality_flags(row))
        source_page = _int_or_none(row.get("source_page"))
        ai_status = str(row.get("ai_status") or "missing")
        normalized_type = str(row.get("normalized_type") or "unknown")
        if ai_status and ai_status != "missing":
            issue_flags.append(f"ai_status_{ai_status}")

        visual = self.visual_fallback_assessment(row)
        strict = self.strict_structured_assessment(row)
        for flag in visual["flags"]:
            if flag not in issue_flags:
                issue_flags.append(flag)
        for flag in strict["flags"]:
            if flag not in issue_flags:
                issue_flags.append(flag)

        if row.get("review_status") in PROTECTED_QUESTION_STATUSES:
            return _state(
                "protected",
                "none",
                "question_review_status_protected",
                _dedupe(issue_flags + ["question_review_status_protected"]),
                export_eligible=False,
                meta={"visual_fallback": visual, "strict_structured": strict},
            )

        recut_flags = self.recut_flags(row, source_page)
        if recut_flags:
            return _state(
                "needs_recut",
                "none",
                recut_flags[0],
                _dedupe(issue_flags + recut_flags),
                export_eligible=False,
                meta={"visual_fallback": visual, "strict_structured": strict},
            )

        if strict["ok"]:
            return _state(
                "strict_structured",
                "structured_html",
                "",
                _dedupe(["strict_structured_ready"]),
                export_eligible=True,
                meta={"strict_structured": strict},
            )

        repair_flags = self.repair_flags(issue_flags, normalized_type=normalized_type)
        if visual["ok"]:
            return _state(
                "visual_fallback",
                "raw_crop_image",
                repair_flags[0] if repair_flags else "structured_not_strict",
                _dedupe(issue_flags + repair_flags + ["visual_fallback_ready"]),
                export_eligible=True,
                meta={"visual_fallback": visual, "strict_structured": strict},
            )

        if ai_status == "failed":
            return _state(
                "failed",
                "none",
                "structured_failed_without_visual_fallback",
                _dedupe(issue_flags + repair_flags + ["structured_failed_without_visual_fallback"]),
                export_eligible=False,
                meta={"visual_fallback": visual, "strict_structured": strict},
            )

        if any(_is_formula_flag(flag) for flag in repair_flags + issue_flags):
            status = "needs_formula_repair"
        elif any(_is_blank_flag(flag) for flag in repair_flags + issue_flags):
            status = "needs_blank_repair"
        else:
            status = "needs_type_review"
        primary = (repair_flags + issue_flags + ["unclassified_candidate"])[0]
        return _state(
            status,
            "candidate_preview",
            primary,
            _dedupe(issue_flags + repair_flags),
            export_eligible=False,
            meta={"visual_fallback": visual, "strict_structured": strict},
        )

    def strict_structured_assessment(self, row: dict[str, Any]) -> dict[str, Any]:
        ai_status = str(row.get("ai_status") or "")
        if ai_status not in STRICT_STRUCTURED_AI_STATUSES:
            return {"ok": False, "flags": ["structured_status_not_strict"]}
        result = validate_structured_row(row)
        flags = list(result["flags"]) + list(result["fatal_flags"])
        return {
            "ok": result["status"] == "ai_verified",
            "flags": flags,
            "validation_status": result["status"],
        }

    def visual_fallback_assessment(self, row: dict[str, Any]) -> dict[str, Any]:
        flags: list[str] = []
        relative_path = str(row.get("raw_crop_path") or "")
        source_page = _int_or_none(row.get("source_page"))
        crop_page = _int_or_none(row.get("raw_crop_page_no"))

        if not relative_path:
            flags.append("visual_missing_raw_crop")
        elif not _is_relative_database_path(relative_path):
            flags.append("visual_raw_crop_path_not_relative")
        else:
            target = (self.project_root / relative_path).resolve()
            try:
                target.relative_to(self.project_root.resolve())
            except ValueError:
                flags.append("visual_raw_crop_outside_project")
            if not target.is_file():
                flags.append("visual_raw_crop_file_missing")
            elif target.stat().st_size <= 0:
                flags.append("visual_raw_crop_file_empty")

        if source_page is None:
            flags.append("visual_missing_source_page")
        if crop_page is None:
            flags.append("visual_missing_raw_crop_page")
        elif source_page is not None and crop_page != source_page:
            flags.append("visual_raw_crop_page_mismatch")

        if not _bbox_is_credible(row.get("raw_crop_bbox_json")):
            flags.append("visual_raw_crop_bbox_missing")
        if not _bbox_is_credible(row.get("question_bbox_json")):
            flags.append("visual_question_bbox_missing")

        page_path = str(row.get("page_image_path") or "")
        if not page_path:
            flags.append("visual_missing_page_image")
        elif not _is_relative_database_path(page_path):
            flags.append("visual_page_image_path_not_relative")

        return {"ok": not flags, "flags": _dedupe(flags)}

    def recut_flags(self, row: dict[str, Any], source_page: int | None) -> list[str]:
        flags: list[str] = []
        duplicate_count = int(row.get("duplicate_anchor_count") or 0)
        isolation_duplicate_count = int(row.get("isolation_duplicate_anchor_count") or 0)
        isolation_status = str(row.get("isolation_status") or "")
        high_risk_page = source_page in HIGH_RISK_PAGES
        if high_risk_page:
            flags.append("stage10_high_risk_page")
        if high_risk_page and (duplicate_count > 0 or isolation_duplicate_count > 0):
            flags.append("duplicate_anchor_needs_recut")
        if isolation_status and isolation_status != "resolved":
            flags.append(f"stage10_isolation_{isolation_status}")
        page_flags = parse_json_field(row.get("page_flags_json"), [])
        if (
            high_risk_page
            and isinstance(page_flags, list)
            and any("duplicate" in str(flag) for flag in page_flags)
        ):
            flags.append("page_flags_duplicate_anchor")
        return _dedupe(flags)

    def repair_flags(self, issue_flags: list[str], *, normalized_type: str) -> list[str]:
        flags: list[str] = []
        if any(_is_formula_flag(flag) for flag in issue_flags):
            flags.append("formula_repair_queue")
        if any(_is_blank_flag(flag) for flag in issue_flags):
            flags.append("blank_repair_queue")
        if normalized_type == "unknown" or "unknown_question_type" in issue_flags:
            flags.append("type_review_queue")
        if any(_is_visual_dependency_flag(flag) for flag in issue_flags):
            flags.append("visual_dependency_queue")
        if "structured_status_not_strict" in issue_flags:
            flags.append("structured_candidate_not_strict")
        return _dedupe(flags)


def _state(
    usability_status: str,
    render_mode: str,
    primary_issue: str,
    issue_flags: list[str],
    *,
    export_eligible: bool,
    meta: dict[str, Any],
) -> dict[str, Any]:
    if usability_status not in USABILITY_STATUSES:
        raise ValueError(f"Unsupported usability_status: {usability_status}")
    if render_mode not in RENDER_MODES:
        raise ValueError(f"Unsupported render_mode: {render_mode}")
    return {
        "usability_status": usability_status,
        "render_mode": render_mode,
        "primary_issue": primary_issue,
        "issue_flags": _dedupe(issue_flags),
        "export_eligible": bool(export_eligible),
        "classification_version": USABILITY_CLASSIFICATION_VERSION,
        "meta": meta,
    }


def _quality_flags(row: dict[str, Any]) -> list[str]:
    flags = parse_json_field(row.get("quality_flags_json"), [])
    return [str(flag) for flag in flags if flag] if isinstance(flags, list) else []


def _bbox_is_credible(value: str | None) -> bool:
    data = parse_json_field(value, {})
    if not isinstance(data, dict):
        return False
    try:
        x0 = float(data["x0"])
        y0 = float(data["y0"])
        x1 = float(data["x1"])
        y1 = float(data["y1"])
    except (KeyError, TypeError, ValueError):
        return False
    return x1 > x0 and y1 > y0


def _is_relative_database_path(value: str | None) -> bool:
    if not value:
        return False
    return ":" not in value and not value.startswith("/") and not value.startswith("\\")


def _is_formula_flag(flag: str) -> bool:
    return flag.startswith("latex_") or flag.startswith("formula_") or flag in {
        "numbers_or_symbols_may_be_missing",
        "source_latex_unbalanced_delimiters",
        "latex_unbalanced_delimiters",
    }


def _is_blank_flag(flag: str) -> bool:
    return flag.startswith("blank_") or "blank" in flag


def _is_visual_dependency_flag(flag: str) -> bool:
    return "image" in flag or "visual" in flag or flag.startswith("referenced_")


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _dedupe(values: list[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        if value and value not in result:
            result.append(value)
    return result
