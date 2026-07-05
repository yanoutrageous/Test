from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from .config import PROJECT_ROOT, get_project_paths


def _relative_to_project(path: Path, project_root: Path) -> str:
    return path.resolve().relative_to(project_root.resolve()).as_posix()


def save_html_export(
    html: str,
    *,
    project_root: Path = PROJECT_ROOT,
    timestamp: datetime | None = None,
    filename_prefix: str = "exam-paper",
) -> dict[str, Any]:
    paths = get_project_paths(project_root, require_target_pdf=False)
    paths.exports_dir.mkdir(parents=True, exist_ok=True)

    stamp = (timestamp or datetime.now()).strftime("%Y%m%d-%H%M%S")
    index = 0
    while True:
        suffix = "" if index == 0 else f"-{index}"
        output_path = paths.exports_dir / f"{filename_prefix}-{stamp}{suffix}.html"
        if not output_path.exists():
            break
        index += 1

    output_path.write_text(html, encoding="utf-8")
    return {
        "path": str(output_path),
        "relative_path": _relative_to_project(output_path, project_root),
        "size_bytes": output_path.stat().st_size,
    }
