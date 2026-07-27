from __future__ import annotations

import hashlib
import json
import ntpath
import os
import pickle
import re
import stat
import subprocess
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path, PureWindowsPath
from typing import Any

import pytest

from app.config import PROJECT_ROOT
from app.workspace_guard import (
    ExpectedKind,
    GuardErrorCode,
    NativePathProbe,
    PathIntent,
    WorkspaceGuard,
    WorkspaceGuardConfigurationError,
    WorkspacePathChangedError,
    WorkspacePathRejectedError,
)


_REPARSE_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_LAB_ROOT_ENV = "M0_TEST_LAB_ROOT"


@pytest.fixture(scope="session", autouse=True)
def require_safe_test_laboratory(tmp_path_factory: pytest.TempPathFactory) -> None:
    project_root = Path(ntpath.normpath(ntpath.abspath(str(PROJECT_ROOT))))
    allowed_parent = project_root / "tmp" / "test_lab"
    raw_run_root = os.environ.get(_LAB_ROOT_ENV)
    if not raw_run_root:
        pytest.fail(f"{_LAB_ROOT_ENV} must identify a unique Test-local run directory")
    run_root = Path(ntpath.normpath(ntpath.abspath(raw_run_root)))
    relative_run = _windows_relative_parts(run_root, allowed_parent)
    if relative_run is None or len(relative_run) != 1 or not run_root.name.startswith("RUN-"):
        pytest.fail(
            f"unsafe test run root {run_root}; expected {allowed_parent}\\RUN-<unique-id>"
        )

    basetemp = Path(
        ntpath.normpath(ntpath.abspath(str(tmp_path_factory.getbasetemp())))
    )
    if not _is_windows_descendant(basetemp, run_root) or basetemp == run_root:
        pytest.fail(f"pytest basetemp escaped the declared run root: {basetemp}")
    for name in ("TEMP", "TMP", "PYTHONPYCACHEPREFIX"):
        raw_value = os.environ.get(name)
        if not raw_value:
            pytest.fail(f"{name} must be redirected into the declared run root")
        value = Path(ntpath.normpath(ntpath.abspath(raw_value)))
        if not _is_windows_descendant(value, run_root):
            pytest.fail(f"{name} escaped the declared run root: {value}")

    for component in (*reversed(basetemp.parents), basetemp):
        try:
            identity = os.lstat(component)
        except OSError as exc:
            pytest.fail(f"cannot inspect test laboratory component {component}: {exc}")
        attributes = int(getattr(identity, "st_file_attributes", 0))
        reparse_tag = int(getattr(identity, "st_reparse_tag", 0))
        if stat.S_ISLNK(identity.st_mode) or attributes & _REPARSE_ATTRIBUTE or reparse_tag:
            pytest.fail(f"test laboratory chain contains a reparse point: {component}")

    marker_path = run_root / ".safety-marker.json"
    try:
        marker = json.loads(marker_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        pytest.fail(f"missing or invalid Test-local safety marker: {exc}")
    expected_marker = {
        "schema_version": "1.0",
        "run_id": run_root.name,
        "project_root": str(project_root),
        "purpose": "M0-S1 WorkspaceGuard safety laboratory",
        "cleanup_policy": "retain-until-manifested-quarantine",
    }
    for key, expected in expected_marker.items():
        if marker.get(key) != expected:
            pytest.fail(f"safety marker field {key!r} does not match this run")


@dataclass
class _FakeStat:
    st_dev: int
    st_ino: int
    st_mode: int
    st_file_attributes: int
    st_reparse_tag: int
    st_nlink: int


class _CountingProbe:
    def __init__(self) -> None:
        self.native = NativePathProbe()
        self.calls: list[Path] = []
        self.overrides: dict[str, Any] = {}

    def lstat(self, path: Path) -> Any:
        self.calls.append(path)
        key = ntpath.normcase(str(path))
        if key in self.overrides:
            value = self.overrides[key]
            if isinstance(value, BaseException):
                raise value
            return value
        return self.native.lstat(path)


@dataclass(frozen=True)
class _Lab:
    root: Path
    project: Path
    project2: Path
    protected: Path
    sentinel: Path
    guard: WorkspaceGuard
    probe: _CountingProbe


@pytest.fixture
def guard_lab(tmp_path: Path) -> _Lab:
    resolved_tmp = Path(ntpath.normpath(ntpath.abspath(str(tmp_path))))
    resolved_project_root = Path(ntpath.normpath(ntpath.abspath(str(PROJECT_ROOT))))
    assert _is_windows_descendant(resolved_tmp, resolved_project_root), (
        "WorkspaceGuard tests require --basetemp under PROJECT_ROOT/tmp/test_lab"
    )

    project = tmp_path / "project"
    project2 = tmp_path / "project2"
    protected = tmp_path / "protected"
    project.mkdir()
    project2.mkdir()
    protected.mkdir()
    sentinel = protected / "sentinel.bin"
    sentinel.write_bytes(b"protected-workspace-guard-sentinel")
    probe = _CountingProbe()
    guard = WorkspaceGuard(PROJECT_ROOT, project, probe=probe)
    probe.calls.clear()
    return _Lab(tmp_path, project, project2, protected, sentinel, guard, probe)


def _is_windows_descendant(candidate: Path, root: Path) -> bool:
    candidate_parts = tuple(ntpath.normcase(part) for part in candidate.parts)
    root_parts = tuple(ntpath.normcase(part) for part in root.parts)
    return len(candidate_parts) >= len(root_parts) and candidate_parts[: len(root_parts)] == root_parts


def _windows_relative_parts(candidate: Path, root: Path) -> tuple[str, ...] | None:
    candidate_parts = PureWindowsPath(str(candidate)).parts
    root_parts = PureWindowsPath(str(root)).parts
    if len(candidate_parts) < len(root_parts):
        return None
    for candidate_part, root_part in zip(candidate_parts, root_parts, strict=False):
        if ntpath.normcase(candidate_part) != ntpath.normcase(root_part):
            return None
    return tuple(candidate_parts[len(root_parts) :])


def _extended_test_local_path(path: Path) -> str:
    """Return an OS-only extended path for a path already confined to test_lab."""

    normalized = ntpath.normpath(str(path))
    project_root = Path(ntpath.normpath(ntpath.abspath(str(PROJECT_ROOT))))
    test_lab_root = project_root / "tmp" / "test_lab"
    candidate = Path(normalized)
    assert candidate != test_lab_root
    assert _is_windows_descendant(candidate, test_lab_root)
    drive, tail = ntpath.splitdrive(normalized)
    assert re.fullmatch(r"[A-Za-z]:", drive)
    assert tail.startswith("\\") and not tail.startswith("\\\\")
    assert not normalized.casefold().startswith(("\\\\?\\", "\\\\.\\", "\\??\\"))
    return "\\\\?\\" + normalized


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _fake_stat(source: Any, **changes: int) -> _FakeStat:
    values = {
        "st_dev": int(getattr(source, "st_dev", 0)),
        "st_ino": int(getattr(source, "st_ino", 0)),
        "st_mode": int(getattr(source, "st_mode", 0)),
        "st_file_attributes": int(getattr(source, "st_file_attributes", 0)),
        "st_reparse_tag": int(getattr(source, "st_reparse_tag", 0)),
        "st_nlink": int(getattr(source, "st_nlink", 1)),
    }
    values.update(changes)
    return _FakeStat(**values)


def _controlled_mklink_junction(link: Path, target: Path, lab_root: Path) -> None:
    assert _is_windows_descendant(link, lab_root)
    assert _is_windows_descendant(target, lab_root)
    assert not link.exists()
    assert target.is_dir()

    system_root = os.environ.get("SystemRoot")
    if not system_root:
        pytest.fail("SystemRoot is required for the audited cmd.exe allow-list")
    cmd = Path(system_root) / "System32" / "cmd.exe"
    cmd_identity = os.lstat(cmd)
    assert stat.S_ISREG(cmd_identity.st_mode)
    assert not int(getattr(cmd_identity, "st_file_attributes", 0)) & _REPARSE_ATTRIBUTE

    process_temp = lab_root / (
        "external-process-temp-"
        + hashlib.sha256(str(link).encode("utf-8", "strict")).hexdigest()[:12]
    )
    process_temp.mkdir(exist_ok=False)
    child_environment = {
        "ComSpec": str(cmd),
        "SystemRoot": str(Path(system_root)),
        "TEMP": str(process_temp),
        "TMP": str(process_temp),
    }
    result = subprocess.run(
        [str(cmd), "/d", "/q", "/c", "mklink", "/J", str(link), str(target)],
        cwd=lab_root,
        env=child_environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        check=False,
        timeout=10,
    )
    assert result.returncode == 0, (result.stdout, result.stderr)


def _remove_expected_reparse(link: Path, lab_root: Path, *, reason: str) -> None:
    assert _is_windows_descendant(link, lab_root)
    identity = os.lstat(link)
    attributes = int(getattr(identity, "st_file_attributes", 0))
    reparse_tag = int(getattr(identity, "st_reparse_tag", 0))
    assert stat.S_ISLNK(identity.st_mode) or attributes & _REPARSE_ATTRIBUTE or reparse_tag
    manifest = {
        "schema_version": "1.0",
        "run_id": os.environ.get(_LAB_ROOT_ENV, "UNKNOWN").rsplit("\\", 1)[-1],
        "job_id": "M0-S1-WORKSPACE-GUARD",
        "recorded_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "action": "remove-exact-test-reparse-node",
        "reason": reason,
        "path": str(link),
        "device": int(identity.st_dev),
        "inode": int(identity.st_ino),
        "file_attributes": attributes,
        "reparse_tag": reparse_tag,
        "recursive": False,
    }
    manifest_path = lab_root / f"cleanup-{reason}.json"
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    os.rmdir(link)
    assert not os.path.lexists(link)
    result = {
        "schema_version": "1.0",
        "run_id": manifest["run_id"],
        "job_id": manifest["job_id"],
        "finished_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "path": str(link),
        "action_completed": True,
        "path_no_longer_exists": not os.path.lexists(link),
    }
    (lab_root / f"cleanup-{reason}-result.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def test_authorizes_new_chinese_path_without_side_effects(guard_lab: _Lab) -> None:
    target = Path("题库") / "2026全国Ⅱ卷" / "第01题.json"
    absolute_target = guard_lab.project / target
    parent = absolute_target.parent

    ticket = guard_lab.guard.authorize(
        target,
        intent=PathIntent.NEW_WRITE,
        expected_kind=ExpectedKind.FILE,
    )

    assert ticket.path == Path(ntpath.normpath(str(absolute_target)))
    assert ticket.relative_path == target
    assert ticket.exists is False
    assert ticket.nearest_existing_ancestor == guard_lab.project
    assert not parent.exists()
    assert not absolute_target.exists()


def test_authorizes_existing_read_and_absolute_project_path(guard_lab: _Lab) -> None:
    directory = guard_lab.project / "资料"
    directory.mkdir()
    target = directory / "题目.txt"
    target.write_text("只读", encoding="utf-8")

    relative = guard_lab.guard.authorize(
        Path("资料") / "题目.txt",
        intent=PathIntent.EXISTING_READ,
        expected_kind=ExpectedKind.FILE,
    )
    absolute = guard_lab.guard.authorize(
        target,
        intent=PathIntent.EXISTING_READ,
        expected_kind=ExpectedKind.FILE,
    )

    assert relative.path == absolute.path == target
    assert relative.exists is True


def test_workspace_root_can_be_read_but_not_mutated(guard_lab: _Lab) -> None:
    read_ticket = guard_lab.guard.authorize(
        guard_lab.project,
        intent=PathIntent.EXISTING_READ,
        expected_kind=ExpectedKind.DIRECTORY,
    )
    assert read_ticket.relative_path == Path(".")

    with pytest.raises(WorkspacePathRejectedError) as error:
        guard_lab.guard.authorize(
            guard_lab.project,
            intent=PathIntent.QUARANTINE_SOURCE,
            expected_kind=ExpectedKind.DIRECTORY,
        )
    assert error.value.code is GuardErrorCode.WORKSPACE_ROOT_TARGET


@pytest.mark.parametrize(
    ("requested", "expected_code"),
    [
        (None, GuardErrorCode.EMPTY_PATH),
        ("", GuardErrorCode.EMPTY_PATH),
        ("   ", GuardErrorCode.EMPTY_PATH),
        (".", GuardErrorCode.IMPLICIT_CWD),
        (r".\file.txt", GuardErrorCode.IMPLICIT_CWD),
        (r"..\protected\sentinel.bin", GuardErrorCode.PARENT_TRAVERSAL),
        (r"safe/../escape.txt", GuardErrorCode.PARENT_TRAVERSAL),
        (r"%TEMP%\file.txt", GuardErrorCode.UNEXPANDED_VARIABLE),
        (r"$env:TEMP\file.txt", GuardErrorCode.UNEXPANDED_VARIABLE),
        (r"${TEMP}\file.txt", GuardErrorCode.UNEXPANDED_VARIABLE),
        (r"~\file.txt", GuardErrorCode.UNEXPANDED_VARIABLE),
        (r"\\server\share\file.txt", GuardErrorCode.UNC_PATH),
        (r"//server/share/file.txt", GuardErrorCode.UNC_PATH),
        (r"\\?\D:\file.txt", GuardErrorCode.DEVICE_PATH),
        (r"\\.\PhysicalDrive0", GuardErrorCode.DEVICE_PATH),
        (r"\??\D:\file.txt", GuardErrorCode.DEVICE_PATH),
        (r"\Windows\file.txt", GuardErrorCode.ROOTED_NO_DRIVE),
        (r"D:relative.txt", GuardErrorCode.DRIVE_RELATIVE),
        (r"data\file.txt:stream", GuardErrorCode.ADS),
        ("data\\bad\x00name", GuardErrorCode.CONTROL_CHARACTER),
        (r"data\*.txt", GuardErrorCode.INVALID_CHARACTER),
        (r"data\name.", GuardErrorCode.TRAILING_DOT_OR_SPACE),
        ("data\\name ", GuardErrorCode.TRAILING_DOT_OR_SPACE),
        (r"data\CON.txt", GuardErrorCode.RESERVED_NAME),
        (r"data\NUL\file.txt", GuardErrorCode.RESERVED_NAME),
        (r"data\COM1.log", GuardErrorCode.RESERVED_NAME),
        (r"data\LPT³.txt", GuardErrorCode.RESERVED_NAME),
    ],
)
def test_lexical_attacks_are_rejected_before_filesystem_probe(
    guard_lab: _Lab,
    requested: str | None,
    expected_code: GuardErrorCode,
) -> None:
    sentinel_before = _sha256(guard_lab.sentinel)

    with pytest.raises(WorkspacePathRejectedError) as error:
        guard_lab.guard.authorize(requested, intent=PathIntent.NEW_WRITE)

    assert error.value.code is expected_code
    assert guard_lab.probe.calls == []
    assert _sha256(guard_lab.sentinel) == sentinel_before


def test_wrong_drive_is_rejected_before_probe(guard_lab: _Lab) -> None:
    wrong_drive = "C:" if guard_lab.project.drive.upper() != "C:" else "Z:"
    with pytest.raises(WorkspacePathRejectedError) as error:
        guard_lab.guard.authorize(
            wrong_drive + r"\outside\file.txt",
            intent=PathIntent.NEW_WRITE,
        )
    assert error.value.code is GuardErrorCode.WRONG_DRIVE
    assert guard_lab.probe.calls == []


@pytest.mark.parametrize("target_name", ["project2", "protected", "ｐｒｏｊｅｃｔ"])
def test_sibling_and_confusable_prefixes_are_outside_workspace(
    guard_lab: _Lab,
    target_name: str,
) -> None:
    target = guard_lab.root / target_name
    if not target.exists():
        target.mkdir()
    guard_lab.probe.calls.clear()
    with pytest.raises(WorkspacePathRejectedError) as error:
        guard_lab.guard.authorize(target / "escape.txt", intent=PathIntent.NEW_WRITE)
    assert error.value.code is GuardErrorCode.OUTSIDE_WORKSPACE
    assert guard_lab.probe.calls == []


def test_constructor_rejects_workspace_outside_authorization(tmp_path: Path) -> None:
    authorization = tmp_path / "authorization"
    outside = tmp_path / "authorization2"
    authorization.mkdir()
    outside.mkdir()

    with pytest.raises(WorkspaceGuardConfigurationError) as error:
        WorkspaceGuard(authorization, outside)

    assert error.value.code is GuardErrorCode.OUTSIDE_AUTH_ROOT


def test_constructor_rejects_missing_or_file_workspace(tmp_path: Path) -> None:
    authorization = tmp_path / "authorization"
    authorization.mkdir()
    missing = authorization / "missing"
    with pytest.raises(WorkspaceGuardConfigurationError) as missing_error:
        WorkspaceGuard(authorization, missing)
    assert missing_error.value.code is GuardErrorCode.ROOT_NOT_FOUND

    file_workspace = authorization / "file.txt"
    file_workspace.write_text("not a directory", encoding="utf-8")
    with pytest.raises(WorkspaceGuardConfigurationError) as file_error:
        WorkspaceGuard(authorization, file_workspace)
    assert file_error.value.code is GuardErrorCode.ROOT_NOT_DIRECTORY


def test_missing_existing_target_is_rejected_without_creation(guard_lab: _Lab) -> None:
    target = guard_lab.project / "missing" / "file.txt"
    with pytest.raises(WorkspacePathRejectedError) as error:
        guard_lab.guard.authorize(
            target,
            intent=PathIntent.EXISTING_READ,
            expected_kind=ExpectedKind.FILE,
        )
    assert error.value.code is GuardErrorCode.NOT_FOUND
    assert not target.parent.exists()


def test_new_write_rejects_existing_target(guard_lab: _Lab) -> None:
    target = guard_lab.project / "already.txt"
    target.write_text("existing", encoding="utf-8")
    with pytest.raises(WorkspacePathRejectedError) as error:
        guard_lab.guard.authorize(target, intent=PathIntent.NEW_WRITE)
    assert error.value.code is GuardErrorCode.TARGET_ALREADY_EXISTS


def test_synthetic_reparse_parent_is_rejected(guard_lab: _Lab) -> None:
    parent = guard_lab.project / "linked"
    parent.mkdir()
    native = guard_lab.probe.native.lstat(parent)
    guard_lab.probe.overrides[ntpath.normcase(str(parent))] = _fake_stat(
        native,
        st_file_attributes=int(getattr(native, "st_file_attributes", 0))
        | getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400),
    )

    with pytest.raises(WorkspacePathRejectedError) as error:
        guard_lab.guard.authorize(parent / "future.txt", intent=PathIntent.NEW_WRITE)

    assert error.value.code is GuardErrorCode.REPARSE_POINT
    assert error.value.component == str(parent)


def test_real_directory_junction_is_rejected(guard_lab: _Lab) -> None:
    link = guard_lab.project / "junction"
    sentinel_before = _sha256(guard_lab.sentinel)
    _controlled_mklink_junction(link, guard_lab.protected, guard_lab.root)
    try:
        with pytest.raises(WorkspacePathRejectedError) as error:
            guard_lab.guard.authorize(
                link / "new-child.txt",
                intent=PathIntent.NEW_WRITE,
            )
        assert error.value.code is GuardErrorCode.REPARSE_POINT
        assert _sha256(guard_lab.sentinel) == sentinel_before
    finally:
        _remove_expected_reparse(
            link,
            guard_lab.root,
            reason="real-directory-junction",
        )


def test_real_directory_symlink_is_rejected(guard_lab: _Lab) -> None:
    link = guard_lab.project / "symlink"
    sentinel_before = _sha256(guard_lab.sentinel)
    try:
        os.symlink(guard_lab.protected, link, target_is_directory=True)
    except OSError as exc:  # A skipped symlink would leave this gate unverified.
        pytest.fail(f"Test-local directory symlink could not be created: {exc}")
    try:
        with pytest.raises(WorkspacePathRejectedError) as error:
            guard_lab.guard.authorize(
                link / "sentinel.bin",
                intent=PathIntent.EXISTING_READ,
            )
        assert error.value.code is GuardErrorCode.REPARSE_POINT
        assert _sha256(guard_lab.sentinel) == sentinel_before
    finally:
        _remove_expected_reparse(
            link,
            guard_lab.root,
            reason="real-directory-symlink",
        )


def test_existing_hardlink_is_readable_but_not_mutable(guard_lab: _Lab) -> None:
    alias = guard_lab.project / "hardlink.bin"
    sentinel_before = _sha256(guard_lab.sentinel)
    os.link(guard_lab.sentinel, alias)
    try:
        read_ticket = guard_lab.guard.authorize(
            alias,
            intent=PathIntent.EXISTING_READ,
            expected_kind=ExpectedKind.FILE,
        )
        assert read_ticket.exists is True

        with pytest.raises(WorkspacePathRejectedError) as error:
            guard_lab.guard.authorize(
                alias,
                intent=PathIntent.EXISTING_WRITE,
                expected_kind=ExpectedKind.FILE,
            )
        assert error.value.code is GuardErrorCode.HARDLINK_WRITE_TARGET
        assert _sha256(guard_lab.sentinel) == sentinel_before
    finally:
        alias_identity = os.lstat(alias)
        sentinel_identity = os.lstat(guard_lab.sentinel)
        assert _is_windows_descendant(alias, guard_lab.root)
        assert alias_identity.st_dev == sentinel_identity.st_dev
        assert alias_identity.st_ino == sentinel_identity.st_ino
        assert alias_identity.st_nlink > 1
        cleanup_manifest = {
            "schema_version": "1.0",
            "run_id": os.environ.get(_LAB_ROOT_ENV, "UNKNOWN").rsplit("\\", 1)[-1],
            "job_id": "M0-S1-WORKSPACE-GUARD",
            "recorded_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            "action": "unlink-exact-test-hardlink-alias",
            "path": str(alias),
            "device": int(alias_identity.st_dev),
            "inode": int(alias_identity.st_ino),
            "nlink": int(alias_identity.st_nlink),
            "recursive": False,
        }
        (guard_lab.root / "cleanup-real-hardlink.json").write_text(
            json.dumps(cleanup_manifest, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        os.unlink(alias)
        assert not os.path.lexists(alias)
        cleanup_result = {
            "schema_version": "1.0",
            "run_id": cleanup_manifest["run_id"],
            "job_id": cleanup_manifest["job_id"],
            "finished_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            "path": str(alias),
            "action_completed": True,
            "path_no_longer_exists": not os.path.lexists(alias),
            "protected_sentinel_sha256_after": _sha256(guard_lab.sentinel),
        }
        (guard_lab.root / "cleanup-real-hardlink-result.json").write_text(
            json.dumps(cleanup_result, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )


def test_revalidate_detects_parent_identity_change(guard_lab: _Lab) -> None:
    parent = guard_lab.project / "stable-parent"
    parent.mkdir()
    ticket = guard_lab.guard.authorize(
        parent / "future.txt",
        intent=PathIntent.NEW_WRITE,
    )
    native = guard_lab.probe.native.lstat(parent)
    guard_lab.probe.overrides[ntpath.normcase(str(parent))] = _fake_stat(
        native,
        st_ino=int(getattr(native, "st_ino", 0)) + 1,
    )

    with pytest.raises(WorkspacePathChangedError) as error:
        guard_lab.guard.revalidate(ticket)

    assert error.value.code is GuardErrorCode.PATH_STATE_CHANGED


def test_filesystem_inspection_errors_fail_closed(guard_lab: _Lab) -> None:
    parent = guard_lab.project / "unreadable"
    parent.mkdir()
    guard_lab.probe.overrides[ntpath.normcase(str(parent))] = PermissionError("denied")

    with pytest.raises(WorkspacePathRejectedError) as error:
        guard_lab.guard.authorize(parent / "file.txt", intent=PathIntent.NEW_WRITE)

    assert error.value.code is GuardErrorCode.PERMISSION_DENIED


@pytest.mark.parametrize("workspace", ["", "   "])
def test_constructor_rejects_explicit_empty_workspace(
    tmp_path: Path,
    workspace: str,
) -> None:
    authorization = tmp_path / "authorization"
    authorization.mkdir()

    with pytest.raises(WorkspaceGuardConfigurationError) as error:
        WorkspaceGuard(authorization, workspace)

    assert error.value.code is GuardErrorCode.EMPTY_PATH


@pytest.mark.parametrize("bad_root", [None, b"D:\\unsafe"])
def test_constructor_reports_invalid_root_as_configuration_error(
    bad_root: Any,
) -> None:
    with pytest.raises(WorkspaceGuardConfigurationError):
        WorkspaceGuard(bad_root)  # type: ignore[arg-type]


def test_invalid_policy_values_fail_before_filesystem_probe(guard_lab: _Lab) -> None:
    with pytest.raises(WorkspacePathRejectedError) as intent_error:
        guard_lab.guard.authorize(
            "future.txt",
            intent="NEW_WRITE",  # type: ignore[arg-type]
        )
    assert intent_error.value.code is GuardErrorCode.INVALID_POLICY
    assert guard_lab.probe.calls == []

    with pytest.raises(WorkspacePathRejectedError) as kind_error:
        guard_lab.guard.authorize(
            "future.txt",
            intent=PathIntent.NEW_WRITE,
            expected_kind="FILE",  # type: ignore[arg-type]
        )
    assert kind_error.value.code is GuardErrorCode.INVALID_POLICY
    assert guard_lab.probe.calls == []


def test_create_directory_requires_explicit_directory_and_missing_target(
    guard_lab: _Lab,
) -> None:
    with pytest.raises(WorkspacePathRejectedError) as policy_error:
        guard_lab.guard.authorize(
            "新目录",
            intent=PathIntent.CREATE_DIRECTORY,
        )
    assert policy_error.value.code is GuardErrorCode.INVALID_POLICY
    assert guard_lab.probe.calls == []

    ticket = guard_lab.guard.authorize(
        "新目录",
        intent=PathIntent.CREATE_DIRECTORY,
        expected_kind=ExpectedKind.DIRECTORY,
    )
    assert not ticket.exists
    assert not ticket.path.exists()

    existing = guard_lab.project / "已有目录"
    existing.mkdir()
    with pytest.raises(WorkspacePathRejectedError) as exists_error:
        guard_lab.guard.authorize(
            existing,
            intent=PathIntent.CREATE_DIRECTORY,
            expected_kind=ExpectedKind.DIRECTORY,
        )
    assert exists_error.value.code is GuardErrorCode.TARGET_ALREADY_EXISTS


@pytest.mark.parametrize(
    "intent",
    [intent for intent in PathIntent if intent is not PathIntent.EXISTING_READ],
)
def test_every_mutating_intent_rejects_workspace_root(
    guard_lab: _Lab,
    intent: PathIntent,
) -> None:
    expected_kind = (
        ExpectedKind.DIRECTORY
        if intent is PathIntent.CREATE_DIRECTORY
        else ExpectedKind.ANY
    )
    with pytest.raises(WorkspacePathRejectedError) as error:
        guard_lab.guard.authorize(
            guard_lab.project,
            intent=intent,
            expected_kind=expected_kind,
        )
    assert error.value.code is GuardErrorCode.WORKSPACE_ROOT_TARGET


def test_expected_kind_mismatch_fails_closed(guard_lab: _Lab) -> None:
    file_path = guard_lab.project / "file.txt"
    directory_path = guard_lab.project / "directory"
    file_path.write_text("file", encoding="utf-8")
    directory_path.mkdir()

    with pytest.raises(WorkspacePathRejectedError) as file_error:
        guard_lab.guard.authorize(
            file_path,
            intent=PathIntent.EXISTING_READ,
            expected_kind=ExpectedKind.DIRECTORY,
        )
    assert file_error.value.code is GuardErrorCode.TYPE_MISMATCH

    with pytest.raises(WorkspacePathRejectedError) as directory_error:
        guard_lab.guard.authorize(
            directory_path,
            intent=PathIntent.EXISTING_READ,
            expected_kind=ExpectedKind.FILE,
        )
    assert directory_error.value.code is GuardErrorCode.TYPE_MISMATCH


def test_long_chinese_new_path_and_case_variant_root_are_safe(guard_lab: _Lab) -> None:
    long_relative = Path(*[("章节" + str(index) + "数" * 50) for index in range(5)]) / "题目.json"
    assert len(str(guard_lab.project / long_relative)) > 260

    long_ticket = guard_lab.guard.authorize(
        long_relative,
        intent=PathIntent.NEW_WRITE,
        expected_kind=ExpectedKind.FILE,
    )
    assert long_ticket.relative_path == long_relative
    assert not (guard_lab.project / long_relative.parts[0]).exists()

    case_variant = Path(str(guard_lab.project).swapcase()) / "大小写.txt"
    case_ticket = guard_lab.guard.authorize(
        case_variant,
        intent=PathIntent.NEW_WRITE,
        expected_kind=ExpectedKind.FILE,
    )
    assert case_ticket.path == guard_lab.project / "大小写.txt"
    assert not case_ticket.path.exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows extended-path behavior")
def test_existing_long_local_path_is_probed_but_extended_user_path_is_rejected(
    guard_lab: _Lab,
) -> None:
    current = guard_lab.project
    index = 0
    while len(str(current / "payload.bin")) < 280:
        current /= f"长路径-{index:02d}-" + "数" * 48
        os.mkdir(_extended_test_local_path(current))
        index += 1

    target = current / "payload.bin"
    with open(_extended_test_local_path(target), "xb") as stream:
        stream.write(b"workspace-guard-long-path")
    assert len(str(target)) >= 280

    guard_lab.probe.calls.clear()
    ticket = guard_lab.guard.authorize(
        target,
        intent=PathIntent.EXISTING_READ,
        expected_kind=ExpectedKind.FILE,
    )

    assert ticket.path == target
    assert ticket.exists is True
    assert guard_lab.probe.calls
    assert all(
        not str(observed).casefold().startswith("\\\\?\\")
        for observed in guard_lab.probe.calls
    )

    guard_lab.probe.calls.clear()
    with pytest.raises(WorkspacePathRejectedError) as error:
        guard_lab.guard.authorize(
            _extended_test_local_path(target),
            intent=PathIntent.EXISTING_READ,
            expected_kind=ExpectedKind.FILE,
        )
    assert error.value.code is GuardErrorCode.DEVICE_PATH
    assert guard_lab.probe.calls == []


@pytest.mark.skipif(os.name != "nt", reason="Windows local-drive path contract")
@pytest.mark.parametrize(
    "requested",
    [
        r"relative\file.txt",
        r"\root-relative\file.txt",
        r"D:drive-relative.txt",
        r"\\server\share\file.txt",
        r"\\?\D:\file.txt",
        r"\\.\PhysicalDrive0",
        r"\??\D:\file.txt",
    ],
)
def test_native_probe_does_not_expand_non_local_or_non_absolute_paths(
    requested: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_lstat(path: object) -> os.stat_result:
        pytest.fail(f"unsafe path reached os.lstat: {path!r}")

    monkeypatch.setattr(os, "lstat", unexpected_lstat)
    with pytest.raises(OSError):
        NativePathProbe().lstat(Path(requested))


def test_nonzero_reparse_tag_is_rejected_even_without_attribute(
    guard_lab: _Lab,
) -> None:
    parent = guard_lab.project / "tagged"
    parent.mkdir()
    native = guard_lab.probe.native.lstat(parent)
    guard_lab.probe.overrides[ntpath.normcase(str(parent))] = _fake_stat(
        native,
        st_file_attributes=0,
        st_reparse_tag=0xA000000C,
    )

    with pytest.raises(WorkspacePathRejectedError) as error:
        guard_lab.guard.authorize(parent / "future.txt", intent=PathIntent.NEW_WRITE)

    assert error.value.code is GuardErrorCode.REPARSE_POINT


def test_generic_filesystem_error_fails_closed(guard_lab: _Lab) -> None:
    parent = guard_lab.project / "broken"
    parent.mkdir()
    guard_lab.probe.overrides[ntpath.normcase(str(parent))] = OSError("broken")

    with pytest.raises(WorkspacePathRejectedError) as error:
        guard_lab.guard.authorize(parent / "file.txt", intent=PathIntent.NEW_WRITE)

    assert error.value.code is GuardErrorCode.FILESYSTEM_INSPECTION_FAILED


def test_revalidate_detects_real_parent_replacement(guard_lab: _Lab) -> None:
    parent = guard_lab.project / "replaceable-parent"
    parent.mkdir()
    ticket = guard_lab.guard.authorize(
        parent / "future.txt",
        intent=PathIntent.NEW_WRITE,
    )
    original = guard_lab.project / "replaceable-parent-original"
    os.rename(parent, original)
    parent.mkdir()

    with pytest.raises(WorkspacePathChangedError) as error:
        guard_lab.guard.revalidate(ticket)

    assert error.value.code is GuardErrorCode.PATH_STATE_CHANGED
    assert not ticket.path.exists()


def test_revalidate_detects_new_target_appearing(guard_lab: _Lab) -> None:
    target = guard_lab.project / "appeared.txt"
    ticket = guard_lab.guard.authorize(target, intent=PathIntent.NEW_WRITE)
    target.write_text("appeared after authorization", encoding="utf-8")

    with pytest.raises(WorkspacePathChangedError) as error:
        guard_lab.guard.revalidate(ticket)

    assert error.value.code is GuardErrorCode.PATH_STATE_CHANGED


def test_authorize_rejects_workspace_ancestor_replaced_by_junction(
    tmp_path: Path,
) -> None:
    authorization = tmp_path / "authorization"
    container = authorization / "container"
    workspace = container / "project"
    protected = tmp_path / "protected-root"
    protected_workspace = protected / "project"
    workspace.mkdir(parents=True)
    protected_workspace.mkdir(parents=True)
    sentinel = protected_workspace / "sentinel.bin"
    sentinel.write_bytes(b"workspace-ancestor-junction-sentinel")
    sentinel_before = _sha256(sentinel)
    guard = WorkspaceGuard(authorization, workspace)

    original = authorization / "container-original"
    os.rename(container, original)
    _controlled_mklink_junction(container, protected, tmp_path)
    try:
        with pytest.raises(WorkspacePathRejectedError) as error:
            guard.authorize("escape.txt", intent=PathIntent.NEW_WRITE)
        assert error.value.code in {
            GuardErrorCode.REPARSE_POINT,
            GuardErrorCode.PATH_STATE_CHANGED,
        }
        assert not (protected_workspace / "escape.txt").exists()
        assert _sha256(sentinel) == sentinel_before
    finally:
        _remove_expected_reparse(
            container,
            tmp_path,
            reason="workspace-ancestor-junction",
        )
        os.rename(original, container)


def test_revalidate_fails_closed_when_workspace_disappears(guard_lab: _Lab) -> None:
    ticket = guard_lab.guard.authorize("future.txt", intent=PathIntent.NEW_WRITE)
    moved_workspace = guard_lab.root / "project-moved-after-authorization"
    os.rename(guard_lab.project, moved_workspace)

    with pytest.raises(WorkspacePathChangedError) as error:
        guard_lab.guard.revalidate(ticket)

    assert error.value.code is GuardErrorCode.PATH_STATE_CHANGED


def test_append_and_quarantine_target_have_explicit_existence_semantics(
    guard_lab: _Lab,
) -> None:
    existing = guard_lab.project / "append.log"
    existing.write_text("existing\n", encoding="utf-8")
    append_ticket = guard_lab.guard.authorize(
        existing,
        intent=PathIntent.APPEND_EXISTING,
        expected_kind=ExpectedKind.FILE,
    )
    assert append_ticket.exists

    with pytest.raises(WorkspacePathRejectedError) as missing_append:
        guard_lab.guard.authorize(
            guard_lab.project / "missing.log",
            intent=PathIntent.APPEND_EXISTING,
            expected_kind=ExpectedKind.FILE,
        )
    assert missing_append.value.code is GuardErrorCode.NOT_FOUND

    quarantine_target = guard_lab.project / "quarantine-target.bin"
    target_ticket = guard_lab.guard.authorize(
        quarantine_target,
        intent=PathIntent.QUARANTINE_TARGET,
    )
    assert not target_ticket.exists

    with pytest.raises(WorkspacePathRejectedError) as existing_target:
        guard_lab.guard.authorize(
            existing,
            intent=PathIntent.QUARANTINE_TARGET,
        )
    assert existing_target.value.code is GuardErrorCode.TARGET_ALREADY_EXISTS


def test_ticket_cannot_be_revalidated_by_another_guard_instance(
    guard_lab: _Lab,
) -> None:
    ticket = guard_lab.guard.authorize("future.txt", intent=PathIntent.NEW_WRITE)
    other_guard = WorkspaceGuard(PROJECT_ROOT, guard_lab.project)

    with pytest.raises(WorkspacePathChangedError) as error:
        other_guard.revalidate(ticket)

    assert error.value.code is GuardErrorCode.TICKET_ISSUER_MISMATCH


@pytest.mark.parametrize(
    ("changes", "expected_code"),
    [
        ({"intent": PathIntent.EXISTING_WRITE}, GuardErrorCode.TICKET_CLAIMS_MISMATCH),
        ({"expected_kind": ExpectedKind.DIRECTORY}, GuardErrorCode.TICKET_CLAIMS_MISMATCH),
        ({"exists": False}, GuardErrorCode.TICKET_CLAIMS_MISMATCH),
        ({"ticket_id": "FORGED-001"}, GuardErrorCode.TICKET_NOT_ISSUED),
        ({"authenticator": b"forged"}, GuardErrorCode.TICKET_MAC_MISMATCH),
    ],
)
def test_registered_ticket_rejects_claim_and_mac_tampering(
    guard_lab: _Lab,
    changes: dict[str, Any],
    expected_code: GuardErrorCode,
) -> None:
    existing = guard_lab.project / "existing.txt"
    existing.write_text("safe", encoding="utf-8")
    read_ticket = guard_lab.guard.authorize(
        existing,
        intent=PathIntent.EXISTING_READ,
        expected_kind=ExpectedKind.FILE,
    )
    forged = replace(read_ticket, **changes)

    with pytest.raises(WorkspacePathChangedError) as error:
        guard_lab.guard.revalidate(forged)

    assert error.value.code is expected_code


def test_guard_ticket_audit_summary_never_contains_absolute_or_requested_path(
    guard_lab: _Lab,
) -> None:
    ticket = guard_lab.guard.authorize(
        "future.txt",
        intent=PathIntent.NEW_WRITE,
        expected_kind=ExpectedKind.FILE,
    )
    rendered = str(ticket.to_audit_dict())

    assert str(guard_lab.project) not in rendered
    assert "future.txt" not in rendered
    assert ticket.ticket_id in rendered
    representation = repr(ticket) + " ".join(repr(item) for item in ticket.chain_snapshot)
    assert str(guard_lab.project) not in representation
    assert "future.txt" not in representation
    assert "D:" not in representation
    with pytest.raises(TypeError):
        pickle.dumps(ticket)


def test_exact_ticket_release_recovers_registry_capacity_without_path_access(
    guard_lab: _Lab,
) -> None:
    ticket = guard_lab.guard.authorize(
        "future-release.txt",
        intent=PathIntent.NEW_WRITE,
        expected_kind=ExpectedKind.FILE,
    )
    assert guard_lab.guard.live_ticket_count == 1
    assert guard_lab.guard.release(ticket)
    assert guard_lab.guard.live_ticket_count == 0
    assert not guard_lab.guard.release(ticket)
    with pytest.raises(WorkspacePathChangedError) as released:
        guard_lab.guard.revalidate(ticket)
    assert released.value.code is GuardErrorCode.TICKET_NOT_ISSUED
