from __future__ import annotations

import math
from pathlib import Path
from statistics import mean, pstdev
from typing import Any

from .config import PROJECT_ROOT
from .stage10 import HIGH_RISK_PAGES
from .structured_content import parse_json_field


VISUAL_INSPECTOR_VERSION = "stage12_visual_quality_v1"


class VisualQualityInspector:
    """Inspect raw crop images before they are allowed into formal export."""

    def __init__(self, *, project_root: Path = PROJECT_ROOT):
        self.project_root = project_root

    def inspect(self, row: dict[str, Any]) -> dict[str, Any]:
        flags: list[str] = []
        blocking: list[str] = []
        metrics: dict[str, Any] = {"version": VISUAL_INSPECTOR_VERSION}
        relative_path = str(row.get("raw_crop_path") or "")
        source_page = _int_or_none(row.get("source_page"))
        crop_page = _int_or_none(row.get("raw_crop_page_no"))

        target: Path | None = None
        if not relative_path:
            _add_block(flags, blocking, "visual_missing_raw_crop")
        elif not _is_relative_database_path(relative_path):
            _add_block(flags, blocking, "visual_raw_crop_path_not_relative")
        else:
            target = (self.project_root / relative_path).resolve()
            try:
                target.relative_to(self.project_root.resolve())
            except ValueError:
                _add_block(flags, blocking, "visual_raw_crop_outside_project")
            if not target.is_file():
                _add_block(flags, blocking, "visual_raw_crop_file_missing")
            elif target.stat().st_size <= 0:
                _add_block(flags, blocking, "visual_raw_crop_file_empty")
            else:
                metrics["file_size_bytes"] = target.stat().st_size

        if source_page is None:
            _add_block(flags, blocking, "visual_missing_source_page")
        if crop_page is None:
            _add_block(flags, blocking, "visual_missing_raw_crop_page")
        elif source_page is not None and crop_page != source_page:
            _add_block(flags, blocking, "visual_raw_crop_page_mismatch")

        if source_page in HIGH_RISK_PAGES:
            _add_block(flags, blocking, "visual_high_risk_duplicate_anchor_page")
        if int(row.get("duplicate_anchor_count") or 0) > 0:
            flags.append("visual_duplicate_anchor_page_stats")
        if int(row.get("isolation_duplicate_anchor_count") or 0) > 0:
            _add_block(flags, blocking, "visual_duplicate_anchor_isolation")

        if not _bbox_is_credible(row.get("raw_crop_bbox_json")):
            _add_block(flags, blocking, "visual_raw_crop_bbox_missing")
        if not _bbox_is_credible(row.get("question_bbox_json")):
            _add_block(flags, blocking, "visual_question_bbox_missing")

        page_path = str(row.get("page_image_path") or "")
        if not page_path:
            _add_block(flags, blocking, "visual_missing_page_image")
        elif not _is_relative_database_path(page_path):
            _add_block(flags, blocking, "visual_page_image_path_not_relative")

        if target is not None and target.is_file() and target.stat().st_size > 0:
            image_result = _inspect_image_pixels(target)
            metrics.update(image_result["metrics"])
            flags.extend(image_result["flags"])
            blocking.extend(image_result["blocking_reasons"])

        flags = _dedupe(flags)
        blocking = _dedupe(blocking)
        return {
            "ok": not blocking,
            "flags": flags,
            "blocking_reasons": blocking,
            "metrics": metrics,
        }


def _inspect_image_pixels(path: Path) -> dict[str, Any]:
    try:
        import fitz  # type: ignore

        pix = fitz.Pixmap(str(path))
    except Exception as exc:  # noqa: BLE001 - keep the row-level reason auditable.
        return {
            "flags": ["visual_image_unreadable"],
            "blocking_reasons": ["visual_image_unreadable"],
            "metrics": {"image_error": str(exc)},
        }

    width = int(pix.width)
    height = int(pix.height)
    components = int(pix.n)
    alpha = bool(getattr(pix, "alpha", 0))
    color_components = max(1, components - 1 if alpha and components > 1 else components)
    samples = pix.samples
    flags: list[str] = []
    blocking: list[str] = []
    metrics: dict[str, Any] = {
        "width": width,
        "height": height,
        "component_count": components,
        "alpha": alpha,
    }

    if width < 40 or height < 20:
        _add_block(flags, blocking, "visual_image_too_small")
    ratio = width / height if height else math.inf
    metrics["aspect_ratio"] = round(ratio, 4) if math.isfinite(ratio) else None
    if ratio < 0.12 or ratio > 24:
        _add_block(flags, blocking, "visual_image_aspect_ratio_extreme")

    if not samples or width <= 0 or height <= 0 or components <= 0:
        _add_block(flags, blocking, "visual_image_empty_pixels")
        return {"flags": _dedupe(flags), "blocking_reasons": _dedupe(blocking), "metrics": metrics}

    step = max(1, (width * height) // 80000)
    intensities: list[float] = []
    content_count = 0
    near_white_count = 0
    edge_hits = {"left": 0, "right": 0, "top": 0, "bottom": 0}
    sampled = 0
    for pixel_index in range(0, width * height, step):
        offset = pixel_index * components
        channels = samples[offset : offset + color_components]
        if not channels:
            continue
        intensity = sum(channels) / len(channels)
        intensities.append(intensity)
        sampled += 1
        if intensity >= 245:
            near_white_count += 1
        if intensity < 235:
            content_count += 1
            x = pixel_index % width
            y = pixel_index // width
            edge_x = max(2, int(width * 0.015))
            edge_y = max(2, int(height * 0.015))
            if x <= edge_x:
                edge_hits["left"] += 1
            if x >= width - edge_x - 1:
                edge_hits["right"] += 1
            if y <= edge_y:
                edge_hits["top"] += 1
            if y >= height - edge_y - 1:
                edge_hits["bottom"] += 1

    if not intensities:
        _add_block(flags, blocking, "visual_image_empty_pixels")
        return {"flags": _dedupe(flags), "blocking_reasons": _dedupe(blocking), "metrics": metrics}

    sorted_values = sorted(intensities)
    p05 = sorted_values[int(len(sorted_values) * 0.05)]
    p95 = sorted_values[min(len(sorted_values) - 1, int(len(sorted_values) * 0.95))]
    white_ratio = near_white_count / sampled if sampled else 1.0
    content_ratio = content_count / sampled if sampled else 0.0
    stddev = pstdev(intensities) if len(intensities) > 1 else 0.0
    metrics.update(
        {
            "sampled_pixels": sampled,
            "mean_intensity": round(mean(intensities), 4),
            "stddev_intensity": round(stddev, 4),
            "p05_intensity": round(p05, 4),
            "p95_intensity": round(p95, 4),
            "near_white_ratio": round(white_ratio, 6),
            "content_ratio": round(content_ratio, 6),
            "edge_hits": edge_hits,
        }
    )

    if white_ratio >= 0.997 and content_ratio <= 0.003:
        _add_block(flags, blocking, "visual_image_mostly_blank")
    if (p95 - p05) < 18 or stddev < 4:
        _add_block(flags, blocking, "visual_image_low_contrast")
    if content_count > 0:
        touched_edges = [edge for edge, count in edge_hits.items() if count > 0]
        if touched_edges:
            flags.append("visual_content_touches_edge")
            metrics["content_touched_edges"] = touched_edges

    return {"flags": _dedupe(flags), "blocking_reasons": _dedupe(blocking), "metrics": metrics}


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


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _add_block(flags: list[str], blocking: list[str], flag: str) -> None:
    flags.append(flag)
    blocking.append(flag)


def _dedupe(values: list[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        if value and value not in result:
            result.append(value)
    return result
