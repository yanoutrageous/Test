from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from .config import PROJECT_ROOT, get_project_paths
from .safety.workspace_io import WorkspaceIOCode, WorkspaceIOError, get_workspace_io


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
    workspace_io = get_workspace_io()
    workspace_io.ensure_directory(paths.exports_dir)

    stamp = (timestamp or datetime.now()).strftime("%Y%m%d-%H%M%S")
    index = 0
    while True:
        suffix = "" if index == 0 else f"-{index}"
        output_path = paths.exports_dir / f"{filename_prefix}-{stamp}{suffix}.html"
        try:
            receipt = workspace_io.create_new_text(output_path, html)
            break
        except WorkspaceIOError as error:
            if error.code is not WorkspaceIOCode.TARGET_CONFLICT:
                raise
            index += 1
    return {
        "path": str(output_path),
        "relative_path": _relative_to_project(output_path, project_root),
        "size_bytes": receipt.size_bytes,
    }
