from __future__ import annotations

import ctypes
import hashlib
import json
import ntpath
import os
import stat
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath


ROOT_MARKER_NAME = ".exam-bank-root.json"
ROOT_MARKER_SCHEMA_VERSION = "1.0"
ROOT_PROJECT_ID = "YANOUTRAGEOUS-LOCAL-EXAM-BANK"
ROOT_POLICY = "PORTABLE_LOCAL_NTFS_V1"
PATH_STORAGE_POLICY = "PROJECT_RELATIVE_V1"
_ROOT_MARKER_MAX_BYTES = 4096
_REPARSE_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_EXPECTED_ROOT_MARKER = {
    "path_storage": PATH_STORAGE_POLICY,
    "project_id": ROOT_PROJECT_ID,
    "root_policy": ROOT_POLICY,
    "schema_version": ROOT_MARKER_SCHEMA_VERSION,
}
_EXPECTED_ROOT_MARKER_BYTES = (
    json.dumps(
        _EXPECTED_ROOT_MARKER,
        ensure_ascii=True,
        indent=2,
        sort_keys=True,
    )
    + "\n"
).encode("utf-8")


class ProjectRootError(RuntimeError):
    """Raised when the repository cannot prove its portable local root."""


@dataclass(frozen=True)
class ProjectRootContract:
    root: Path
    marker_path: Path
    marker_sha256: str
    filesystem: str


def _absolute_lexical(path: str | os.PathLike[str]) -> Path:
    raw = os.fspath(path)
    if type(raw) is not str:
        raise ProjectRootError("project-root paths must be Unicode strings")
    if not ntpath.isabs(raw):
        raise ProjectRootError("project-root paths must already be absolute")
    return Path(ntpath.normpath(raw))


def _same_path(left: Path, right: Path) -> bool:
    return ntpath.normcase(str(left)) == ntpath.normcase(str(right))


def _identity_signature(identity: os.stat_result) -> tuple[int, ...]:
    return (
        int(identity.st_mode),
        int(identity.st_dev),
        int(identity.st_ino),
        int(identity.st_nlink),
        int(identity.st_size),
        int(getattr(identity, "st_mtime_ns", 0)),
        int(getattr(identity, "st_file_attributes", 0)),
        int(getattr(identity, "st_reparse_tag", 0)),
    )


def _reject_reparse(path: Path, identity: os.stat_result) -> None:
    attributes = int(getattr(identity, "st_file_attributes", 0))
    reparse_tag = int(getattr(identity, "st_reparse_tag", 0))
    if stat.S_ISLNK(identity.st_mode) or attributes & _REPARSE_ATTRIBUTE or reparse_tag:
        raise ProjectRootError(f"project-root path chain contains a reparse object: {path}")


def _verify_existing_chain(path: Path) -> os.stat_result:
    final_identity: os.stat_result | None = None
    components = (*reversed(path.parents), path)
    for index, component in enumerate(components):
        try:
            identity = os.lstat(component)
        except OSError as exc:
            raise ProjectRootError(
                f"project-root path cannot be inspected: {component}"
            ) from exc
        _reject_reparse(component, identity)
        if index < len(components) - 1 and not stat.S_ISDIR(identity.st_mode):
            raise ProjectRootError(
                f"project-root ancestor is not a directory: {component}"
            )
        final_identity = identity
    if final_identity is None:
        raise ProjectRootError("project-root path chain is empty")
    return final_identity


def _read_verified_marker(marker_path: Path) -> bytes:
    before = _verify_existing_chain(marker_path)
    if (
        not stat.S_ISREG(before.st_mode)
        or int(before.st_nlink) != 1
        or int(before.st_size) < 1
        or int(before.st_size) > _ROOT_MARKER_MAX_BYTES
    ):
        raise ProjectRootError(
            "project-root marker must be a small single-link regular file"
        )

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(marker_path, flags)
    except OSError as exc:
        raise ProjectRootError("project-root marker could not be opened") from exc
    try:
        opened = os.fstat(descriptor)
        _reject_reparse(marker_path, opened)
        if (
            not stat.S_ISREG(opened.st_mode)
            or int(opened.st_nlink) != 1
            or _identity_signature(opened) != _identity_signature(before)
        ):
            raise ProjectRootError("project-root marker identity changed before reading")
        chunks: list[bytes] = []
        total = 0
        while total <= _ROOT_MARKER_MAX_BYTES:
            chunk = os.read(descriptor, min(1024, _ROOT_MARKER_MAX_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        if total > _ROOT_MARKER_MAX_BYTES:
            raise ProjectRootError("project-root marker exceeds its size limit")
        after_handle = os.fstat(descriptor)
    finally:
        os.close(descriptor)

    after_path = _verify_existing_chain(marker_path)
    if (
        _identity_signature(after_handle) != _identity_signature(opened)
        or _identity_signature(after_path) != _identity_signature(opened)
    ):
        raise ProjectRootError("project-root marker identity changed while reading")
    payload = b"".join(chunks)
    if payload != _EXPECTED_ROOT_MARKER_BYTES:
        raise ProjectRootError("project-root marker does not match the reviewed contract")
    return payload


def _filesystem_name(path: Path) -> str:
    if os.name != "nt":
        raise ProjectRootError("portable production roots require Windows and NTFS")

    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetVolumePathNameW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPWSTR,
        wintypes.DWORD,
    ]
    kernel32.GetVolumePathNameW.restype = wintypes.BOOL
    kernel32.GetVolumeInformationW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPWSTR,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPWSTR,
        wintypes.DWORD,
    ]
    kernel32.GetVolumeInformationW.restype = wintypes.BOOL

    volume_path = ctypes.create_unicode_buffer(32768)
    if not kernel32.GetVolumePathNameW(str(path), volume_path, len(volume_path)):
        raise ProjectRootError(
            f"cannot identify the project-root volume: winerror={ctypes.get_last_error()}"
        )
    filesystem = ctypes.create_unicode_buffer(256)
    serial = wintypes.DWORD()
    maximum_component_length = wintypes.DWORD()
    filesystem_flags = wintypes.DWORD()
    if not kernel32.GetVolumeInformationW(
        volume_path.value,
        None,
        0,
        ctypes.byref(serial),
        ctypes.byref(maximum_component_length),
        ctypes.byref(filesystem_flags),
        filesystem,
        len(filesystem),
    ):
        raise ProjectRootError(
            f"cannot inspect the project-root filesystem: winerror={ctypes.get_last_error()}"
        )
    return filesystem.value.upper()


def inspect_project_root(
    candidate: str | os.PathLike[str],
    *,
    expected_module_path: str | os.PathLike[str] | None = None,
) -> ProjectRootContract:
    """Validate a candidate copy without granting it production write authority."""

    root = _absolute_lexical(candidate)
    windows_root = PureWindowsPath(str(root))
    if (
        not windows_root.drive
        or str(root).startswith(("\\\\", "//"))
        or len(windows_root.anchor) != 3
        or windows_root.anchor[1:] != ":\\"
        or len(windows_root.parts) < 2
    ):
        raise ProjectRootError(
            "project root must be below, and not equal to, a local drive root"
        )

    root_identity = _verify_existing_chain(root)
    if not stat.S_ISDIR(root_identity.st_mode):
        raise ProjectRootError("project root is not a directory")

    marker_path = root / ROOT_MARKER_NAME
    marker_payload = _read_verified_marker(marker_path)
    filesystem = _filesystem_name(root)
    if filesystem != "NTFS":
        raise ProjectRootError(
            f"project root requires NTFS, observed filesystem: {filesystem or '<unknown>'}"
        )

    if expected_module_path is not None:
        module_path = _absolute_lexical(expected_module_path)
        expected_path = root / "app" / "project_root.py"
        if not _same_path(module_path, expected_path):
            raise ProjectRootError(
                "project-root authority was not loaded from the contracted module location"
            )
        module_identity = _verify_existing_chain(module_path)
        if not stat.S_ISREG(module_identity.st_mode) or int(module_identity.st_nlink) != 1:
            raise ProjectRootError(
                "project-root authority module must be a single-link regular file"
            )

    return ProjectRootContract(
        root=root,
        marker_path=marker_path,
        marker_sha256=hashlib.sha256(marker_payload).hexdigest(),
        filesystem=filesystem,
    )


def _discover_project_root(
    _module_path_literal: str = __file__,
) -> ProjectRootContract:
    module_path = _absolute_lexical(_module_path_literal)
    if module_path.name != "project_root.py" or module_path.parent.name.casefold() != "app":
        raise ProjectRootError("project-root authority has an unexpected module layout")
    return inspect_project_root(
        module_path.parent.parent,
        expected_module_path=module_path,
    )


PROJECT_ROOT_CONTRACT = _discover_project_root()
PROJECT_ROOT = PROJECT_ROOT_CONTRACT.root
PROJECT_ROOT_MARKER_SHA256 = PROJECT_ROOT_CONTRACT.marker_sha256


def main() -> int:
    print(
        json.dumps(
            {
                "filesystem": PROJECT_ROOT_CONTRACT.filesystem,
                "marker": ROOT_MARKER_NAME,
                "marker_sha256": PROJECT_ROOT_MARKER_SHA256,
                "path_storage": PATH_STORAGE_POLICY,
                "project_id": ROOT_PROJECT_ID,
                "project_root": str(PROJECT_ROOT),
                "root_policy": ROOT_POLICY,
                "schema_version": ROOT_MARKER_SCHEMA_VERSION,
                "status": "VERIFIED",
            },
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
