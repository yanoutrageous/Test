from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

import app.project_root as project_root_module
from app.project_root import (
    PATH_STORAGE_POLICY,
    PROJECT_ROOT,
    PROJECT_ROOT_CONTRACT,
    PROJECT_ROOT_MARKER_SHA256,
    ROOT_MARKER_NAME,
    ROOT_POLICY,
    ROOT_PROJECT_ID,
    ProjectRootError,
    inspect_project_root,
)


def _build_relocated_copy(tmp_path: Path) -> tuple[Path, Path]:
    relocated_root = tmp_path / "迁移后的 项目"
    module_path = relocated_root / "app" / "project_root.py"
    module_path.parent.mkdir(parents=True)
    module_path.write_text("# relocation validation fixture\n", encoding="utf-8")
    (relocated_root / ROOT_MARKER_NAME).write_bytes(
        (PROJECT_ROOT / ROOT_MARKER_NAME).read_bytes()
    )
    return relocated_root, module_path


def test_current_project_root_contract_is_verified_and_path_free() -> None:
    marker = json.loads((PROJECT_ROOT / ROOT_MARKER_NAME).read_text(encoding="utf-8"))

    assert PROJECT_ROOT_CONTRACT.root == PROJECT_ROOT
    assert PROJECT_ROOT_CONTRACT.filesystem == "NTFS"
    assert PROJECT_ROOT_CONTRACT.marker_sha256 == PROJECT_ROOT_MARKER_SHA256
    assert marker == {
        "path_storage": PATH_STORAGE_POLICY,
        "project_id": ROOT_PROJECT_ID,
        "root_policy": ROOT_POLICY,
        "schema_version": "1.0",
    }
    serialized = json.dumps(marker, ensure_ascii=False)
    assert str(PROJECT_ROOT) not in serialized
    assert "D:\\" not in serialized
    assert "E:\\" not in serialized


def test_relocated_unicode_and_space_root_validates_on_same_ntfs_volume(
    tmp_path: Path,
) -> None:
    relocated_root, module_path = _build_relocated_copy(tmp_path)

    contract = inspect_project_root(
        relocated_root,
        expected_module_path=module_path,
    )

    assert contract.root == relocated_root
    assert contract.filesystem == "NTFS"
    assert contract.marker_sha256 == PROJECT_ROOT_MARKER_SHA256


def test_relative_root_is_never_accepted_as_authority() -> None:
    with pytest.raises(ProjectRootError, match="already be absolute"):
        inspect_project_root(Path("portable-copy"))


def test_changed_root_marker_is_rejected(tmp_path: Path) -> None:
    relocated_root, _ = _build_relocated_copy(tmp_path)
    marker_path = relocated_root / ROOT_MARKER_NAME
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    marker["root_policy"] = "CALLER_SELECTED_ROOT"
    marker_path.write_text(
        json.dumps(marker, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )

    with pytest.raises(ProjectRootError, match="reviewed contract"):
        inspect_project_root(relocated_root)


def test_hardlinked_root_marker_is_rejected(tmp_path: Path) -> None:
    relocated_root, _ = _build_relocated_copy(tmp_path)
    marker_path = relocated_root / ROOT_MARKER_NAME
    hardlink_path = relocated_root / "marker-hardlink.json"
    os.link(marker_path, hardlink_path)

    try:
        with pytest.raises(ProjectRootError, match="single-link"):
            inspect_project_root(relocated_root)
    finally:
        hardlink_path.unlink()


def test_non_ntfs_root_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    relocated_root, _ = _build_relocated_copy(tmp_path)
    monkeypatch.setattr(project_root_module, "_filesystem_name", lambda _: "EXFAT")

    with pytest.raises(ProjectRootError, match="requires NTFS"):
        inspect_project_root(relocated_root)
