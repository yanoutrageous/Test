from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import scripts.run_safe_pytest as launcher_module

from scripts.run_safe_pytest import (
    RUN_ID_PATTERN,
    SafetyStop,
    _WindowsJob,
    _WindowsProtectedTreeFence,
    _WindowsProtectedTreeWatcher,
    _build_command,
    _effective_exit_code,
    _junit_evidence,
    _protected_tree_snapshot,
    _regular_file_evidence,
    _relative_parts,
    _run_test_process,
    _snapshot_changes,
    _verify_run_tree_no_reparse,
    _write_json_exclusive,
    main,
)


def _pid_is_running(pid: int) -> bool:
    if os.name != "nt":
        try:
            os.kill(pid, 0)
        except OSError:
            return False
        return True
    import ctypes

    synchronize = 0x00100000
    wait_timeout = 0x00000102
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
    kernel32.WaitForSingleObject.restype = ctypes.c_ulong
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int
    handle = kernel32.OpenProcess(synchronize, False, pid)
    if not handle:
        return False
    try:
        return int(kernel32.WaitForSingleObject(handle, 0)) == wait_timeout
    finally:
        kernel32.CloseHandle(handle)


@pytest.mark.parametrize(
    "run_id",
    [
        r"RUN-..\BASE",
        "RUN-../BASE",
        r"D:\RUN-ESCAPE",
        "RUN-WITH SPACE",
        "not-a-run",
        "",
    ],
)
def test_launcher_rejects_path_syntax_in_run_id_without_writing(run_id: str) -> None:
    with pytest.raises(SafetyStop):
        main(["--run-id", run_id, "--mode", "full"])


def test_run_id_contract_accepts_a_unique_safe_identifier() -> None:
    assert RUN_ID_PATTERN.fullmatch("RUN-20260711-M0-S1-UNIT-001")


def test_evidence_json_round_trips_an_unpaired_utf16_code_unit(
    tmp_path: Path,
) -> None:
    evidence = tmp_path / "evidence.json"
    value = "malformed-\udedf-name"

    _write_json_exclusive(evidence, {"value": value})

    raw = evidence.read_bytes()
    assert b"\\udedf" in raw
    assert json.loads(raw)["value"] == value


def test_component_containment_rejects_test2_prefix(tmp_path: Path) -> None:
    allowed = tmp_path / "Test"
    sibling = tmp_path / "Test2" / "RUN-SAFE-001"
    candidate = allowed / "RUN-SAFE-001"

    assert _relative_parts(candidate, allowed) == ("RUN-SAFE-001",)
    assert _relative_parts(sibling, allowed) is None


def test_launcher_builds_fixed_test_local_outputs(tmp_path: Path) -> None:
    run_root = tmp_path / "RUN-SAFE-001"
    run_root.mkdir()

    command, basetemp, junit = _build_command(
        tmp_path,
        run_root,
        mode="guard",
        exclude_symlink=True,
    )

    assert basetemp == run_root / "pytest-basetemp"
    assert junit == run_root / "junit.xml"
    assert "tests/test_workspace_guard.py" in command
    assert "--basetemp" in command
    assert "--junitxml" in command
    assert "no:cacheprovider" in command
    assert "not test_real_directory_symlink_is_rejected" in command


def test_writer_mode_has_a_fixed_non_injectable_regression_selection(
    tmp_path: Path,
) -> None:
    run_root = tmp_path / "RUN-WRITER-MODE"
    run_root.mkdir()

    command, basetemp, junit = _build_command(
        tmp_path,
        run_root,
        mode="writer",
        exclude_symlink=True,
    )

    assert basetemp == run_root / "pytest-basetemp"
    assert junit == run_root / "junit.xml"
    assert command == [
        sys.executable,
        "-m",
        "pytest",
        "tests/test_windows_handle_writer.py",
        "tests/test_segment_ledger.py",
        "tests/test_job_operation.py",
        "tests/test_workspace_guard.py",
        "tests/test_workspace_policy.py",
        "tests/test_write_entry_inventory.py",
        "tests/test_safe_pytest_launcher.py",
        "-q",
        "-p",
        "no:cacheprovider",
        "-k",
        "not test_real_directory_symlink_is_rejected",
        "--basetemp",
        str(basetemp),
        "--junitxml",
        str(junit),
    ]


def test_s3d_mode_has_a_fixed_non_injectable_selection(tmp_path: Path) -> None:
    run_root = tmp_path / "RUN-S3D-MODE"
    run_root.mkdir()
    command, _basetemp, _junit = _build_command(
        tmp_path,
        run_root,
        mode="s3d",
        exclude_symlink=True,
    )
    assert command[3:6] == [
        "tests/test_job_operation.py",
        "tests/test_windows_handle_writer.py",
        "tests/test_segment_ledger.py",
    ]


def test_launcher_refuses_to_reuse_existing_basetemp(tmp_path: Path) -> None:
    run_root = tmp_path / "RUN-SAFE-002"
    run_root.mkdir()
    (run_root / "pytest-basetemp").mkdir()

    with pytest.raises(SafetyStop, match="must not exist"):
        _build_command(
            tmp_path,
            run_root,
            mode="full",
            exclude_symlink=False,
        )


def test_symlink_mode_cannot_hide_its_only_gate(tmp_path: Path) -> None:
    run_root = tmp_path / "RUN-SAFE-003"
    run_root.mkdir()

    with pytest.raises(SafetyStop, match="cannot exclude"):
        _build_command(
            tmp_path,
            run_root,
            mode="symlink",
            exclude_symlink=True,
        )


def test_protected_tree_snapshot_detects_new_source_and_sqlite_sidecar(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    run_root = project / "tmp" / "test_lab" / "RUN-SAFE-004"
    run_root.mkdir(parents=True)
    database = project / "data" / "db" / "question_bank.sqlite3"
    database.parent.mkdir(parents=True)
    database.write_bytes(b"main")
    app_file = project / "app" / "module.py"
    app_file.parent.mkdir()
    app_file.write_text("VALUE = 1\n", encoding="utf-8")

    before = _protected_tree_snapshot(project, excluded_root=run_root)
    (database.parent / "question_bank.sqlite3-wal").write_bytes(b"wal")
    (app_file.parent / "new_module.py").write_text("VALUE = 2\n", encoding="utf-8")
    after = _protected_tree_snapshot(project, excluded_root=run_root)

    changed = _snapshot_changes(before, after)
    assert "F:data/db/question_bank.sqlite3-wal" in changed
    assert "F:app/new_module.py" in changed


def test_protected_tree_snapshot_ignores_only_the_current_run_root(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    current_run = project / "tmp" / "test_lab" / "RUN-SAFE-005"
    previous_run = project / "tmp" / "test_lab" / "RUN-SAFE-OLD"
    current_run.mkdir(parents=True)
    previous_run.mkdir(parents=True)
    (current_run / "live.txt").write_text("before", encoding="utf-8")
    previous_file = previous_run / "evidence.txt"
    previous_file.write_text("before", encoding="utf-8")

    before = _protected_tree_snapshot(project, excluded_root=current_run)
    (current_run / "live.txt").write_text("after", encoding="utf-8")
    previous_file.write_text("after", encoding="utf-8")
    after = _protected_tree_snapshot(project, excluded_root=current_run)

    changed = _snapshot_changes(before, after)
    assert all("RUN-SAFE-005" not in item for item in changed)
    assert "F:tmp/test_lab/RUN-SAFE-OLD/evidence.txt" in changed


def test_protected_snapshot_accepts_only_fully_internal_hardlink_groups(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    excluded = project / "current-run"
    excluded.mkdir(parents=True)
    original = project / "original.bin"
    original.write_bytes(b"same-inode")
    internal_link = project / "internal-link.bin"
    os.link(original, internal_link)
    try:
        snapshot = _protected_tree_snapshot(project, excluded_root=excluded)
        assert "F:original.bin" in snapshot
        assert "F:internal-link.bin" in snapshot
    finally:
        internal_link.unlink()

    excluded_link = excluded / "excluded-link.bin"
    os.link(original, excluded_link)
    try:
        with pytest.raises(SafetyStop, match="not wholly contained"):
            _protected_tree_snapshot(project, excluded_root=excluded)
    finally:
        excluded_link.unlink()
    assert os.stat(original).st_nlink == 1


def test_protected_snapshot_detects_directory_metadata_change(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    excluded = project / "excluded"
    excluded.mkdir(parents=True)
    before = _protected_tree_snapshot(project, excluded_root=excluded)
    identity = project.stat()
    os.utime(
        project,
        ns=(identity.st_atime_ns, identity.st_mtime_ns + 10_000_000),
    )
    after = _protected_tree_snapshot(project, excluded_root=excluded)
    assert "D:." in _snapshot_changes(before, after)


def test_runtime_watcher_detects_transient_create_delete(tmp_path: Path) -> None:
    project = tmp_path / "project"
    excluded = project / "excluded"
    excluded.mkdir(parents=True)
    watcher = _WindowsProtectedTreeWatcher(project, excluded_root=excluded)
    transient = project / "transient"
    transient.mkdir()
    transient.rmdir()
    changes, error = watcher.finish()
    assert error is None
    assert any(change.endswith(":transient") for change in changes)


def test_runtime_watcher_ignores_only_its_excluded_root(tmp_path: Path) -> None:
    project = tmp_path / "project"
    excluded = project / "excluded"
    excluded.mkdir(parents=True)
    watcher = _WindowsProtectedTreeWatcher(project, excluded_root=excluded)
    (excluded / "allowed.txt").write_text("inside exclusion", encoding="utf-8")
    changes, error = watcher.finish()
    assert error is None
    assert changes == ()


def test_runtime_watcher_cannot_be_stopped_by_an_early_drain_marker(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    excluded = project / "excluded"
    excluded.mkdir(parents=True)
    watcher = _WindowsProtectedTreeWatcher(project, excluded_root=excluded)
    early_drain = object.__getattribute__(watcher, "_drain_path")
    early_drain.write_text("forged early drain", encoding="utf-8")
    early_drain.unlink()
    transient = project / "must-be-observed"
    transient.mkdir()
    transient.rmdir()
    changes, error = watcher.finish()
    assert error is None
    assert any(change.endswith(":must-be-observed") for change in changes)


def test_runtime_watcher_fails_closed_on_unexpected_io_cancellation(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    excluded = project / "excluded"
    excluded.mkdir(parents=True)
    watcher = _WindowsProtectedTreeWatcher(project, excluded_root=excluded)
    kernel32 = object.__getattribute__(watcher, "_kernel32")
    handle = object.__getattribute__(watcher, "_handle")
    cancelled = bool(kernel32.CancelIoEx(handle, None))
    thread = object.__getattribute__(watcher, "_thread")
    thread.join(timeout=5)
    _changes, error = watcher.finish()
    assert cancelled
    assert error is not None
    assert "monitor" in error


def test_protected_tree_fence_blocks_direct_protected_file_write(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    excluded = project / "excluded"
    excluded.mkdir(parents=True)
    protected = project / "protected.bin"
    protected.write_bytes(b"immutable")
    snapshot = _protected_tree_snapshot(project, excluded_root=excluded)
    fence = _WindowsProtectedTreeFence(
        project,
        excluded_root=excluded,
        snapshot=snapshot,
    )
    alias = excluded / "alias.bin"
    alias_created = False
    try:
        with pytest.raises(OSError):
            protected.write_bytes(b"tampered")
        assert protected.read_bytes() == b"immutable"
        try:
            os.link(protected, alias)
            alias_created = True
        except OSError:
            pass
        if alias_created:
            with pytest.raises(OSError):
                alias.write_bytes(b"tampered-through-alias")
            assert protected.read_bytes() == b"immutable"
    finally:
        _count, error = fence.finish()
        assert error is None
        if alias_created:
            alias.unlink()
    assert protected.read_bytes() == b"immutable"
    assert protected.stat().st_nlink == 1


def test_test_lab_hardlink_guard_rejects_source_outside_current_run(
    tmp_path: Path,
) -> None:
    outside_source = Path(__file__).resolve()
    destination = tmp_path / "forbidden-alias.py"
    with pytest.raises(PermissionError, match="SAFE_TEST_HARDLINK_DENIED"):
        os.link(outside_source, destination)
    assert not destination.exists()


def test_test_lab_hardlink_guard_rejects_nt_link_outside_current_run(
    tmp_path: Path,
) -> None:
    outside_source = Path(__file__).resolve()
    destination = tmp_path / "forbidden-nt-alias.py"
    nt_module = __import__("nt")
    with pytest.raises(PermissionError, match="SAFE_TEST_HARDLINK_DENIED"):
        nt_module.link(outside_source, destination)
    assert not destination.exists()


def test_python_child_inherits_cross_boundary_hardlink_guard(
    tmp_path: Path,
) -> None:
    outside_source = Path(__file__).resolve()
    destination = tmp_path / "forbidden-child-alias.py"
    completed = subprocess.run(
        [
            sys.executable,
            "-B",
            "-c",
            (
                "import os; "
                f"os.link({str(outside_source)!r}, {str(destination)!r})"
            ),
        ],
        cwd=Path(__file__).parent.parent,
        env=os.environ.copy(),
        text=True,
        capture_output=True,
        check=False,
        timeout=10,
    )
    assert completed.returncode != 0
    assert "SAFE_TEST_HARDLINK_DENIED" in completed.stderr
    assert not destination.exists()


def test_python_child_script_argument_is_not_misread_as_interpreter_flag() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-B",
            "-c",
            "import sys; assert sys.argv[1] == '-SESSION'",
            "-SESSION",
        ],
        cwd=Path(__file__).parent.parent,
        env=os.environ.copy(),
        check=False,
        timeout=10,
    )
    assert completed.returncode == 0


@pytest.mark.parametrize(
    ("case", "interpreter_arguments"),
    [
        ("separate-s", ("-S", "-c")),
        ("separate-e", ("-E", "-c")),
        ("separate-i", ("-I", "-c")),
        ("combined-ic", ("-Ic",)),
        ("combined-sc", ("-Sc",)),
        ("combined-ec", ("-Ec",)),
        ("warning-then-i", ("-W", "ignore", "-I", "-c")),
        ("xoption-then-s", ("-X", "dev", "-S", "-c")),
        ("combined-i-warning", ("-IWignore", "-c")),
        ("combined-i-xoption", ("-IXdev", "-c")),
    ],
)
def test_python_child_cannot_disable_bootstrap_with_isolation_flag(
    tmp_path: Path,
    case: str,
    interpreter_arguments: tuple[str, ...],
) -> None:
    sentinel = tmp_path / f"child-{case}.ran"
    with pytest.raises(PermissionError, match="SAFE_TEST_PROCESS_DENIED"):
        subprocess.run(
            [
                sys.executable,
                *interpreter_arguments,
                f"from pathlib import Path; Path({str(sentinel)!r}).write_text('ran')",
            ],
            cwd=Path(__file__).parent.parent,
            env=os.environ.copy(),
            check=False,
            timeout=10,
        )
    assert not sentinel.exists()


@pytest.mark.parametrize(
    "removed_name",
    ["M0_TEST_LAB_ROOT", "M0_TEST_HARDLINK_GUARD_REQUIRED", "PYTHONPATH"],
)
def test_python_child_cannot_strip_required_guard_environment(
    tmp_path: Path,
    removed_name: str,
) -> None:
    sentinel = tmp_path / f"child-without-{removed_name}.ran"
    environment = os.environ.copy()
    environment.pop(removed_name, None)
    with pytest.raises(PermissionError, match="SAFE_TEST_PROCESS_DENIED"):
        subprocess.run(
            [
                sys.executable,
                "-B",
                "-c",
                f"from pathlib import Path; Path({str(sentinel)!r}).write_text('ran')",
            ],
            cwd=Path(__file__).parent.parent,
            env=environment,
            check=False,
            timeout=10,
        )
    assert not sentinel.exists()


def test_ctypes_cannot_resolve_native_hardlink_api() -> None:
    import ctypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    with pytest.raises(PermissionError, match="SAFE_TEST_PROCESS_DENIED"):
        getattr(kernel32, "CreateHardLinkW")


def test_ctypes_cannot_resolve_native_process_api() -> None:
    import ctypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    with pytest.raises(PermissionError, match="SAFE_TEST_PROCESS_DENIED"):
        getattr(kernel32, "CreateProcessW")


@pytest.mark.parametrize(
    "event",
    [
        "os.system",
        "os.startfile",
        "os.startfile/2",
        "os.exec",
        "os.spawn",
        "os.posix_spawn",
    ],
)
def test_alternate_process_audit_events_fail_closed(event: str) -> None:
    import sitecustomize

    audit_hook = getattr(sitecustomize, "_INSTALLED_AUDIT_HOOK")
    with pytest.raises(PermissionError, match="SAFE_TEST_PROCESS_DENIED"):
        audit_hook(event, ())


@pytest.mark.parametrize(
    "command",
    [
        ["fsutil", "hardlink", "list", "never-run"],
        ["cmd.exe", "/d", "/c", "mklink", "/H", "never", "run"],
        ["powershell.exe", "-NoProfile", "New-Item", "-ItemType", "HardLink"],
    ],
)
def test_native_hardlink_commands_are_rejected_before_process_creation(
    command: list[str],
) -> None:
    with pytest.raises(PermissionError, match="SAFE_TEST_PROCESS_DENIED"):
        subprocess.run(command, check=False, timeout=10)


def test_cmd_trampoline_cannot_launch_isolated_python(tmp_path: Path) -> None:
    sentinel = tmp_path / "cmd-trampoline.ran"
    cmd = Path(os.environ["SystemRoot"]) / "System32" / "cmd.exe"
    with pytest.raises(PermissionError, match="SAFE_TEST_PROCESS_DENIED"):
        subprocess.run(
            [
                str(cmd),
                "/d",
                "/q",
                "/c",
                sys.executable,
                "-I",
                "-c",
                f"from pathlib import Path; Path({str(sentinel)!r}).write_text('ran')",
            ],
            cwd=tmp_path,
            env=os.environ.copy(),
            check=False,
            timeout=10,
        )
    assert not sentinel.exists()


def test_fake_direct_pytest_canary_cannot_bypass_child_guard(tmp_path: Path) -> None:
    sentinel = tmp_path / "fake-canary.ran"
    environment = os.environ.copy()
    for name in (
        "M0_TEST_LAB_ROOT",
        "M0_TEST_LAB_TOKEN",
        "M0_TEST_HARDLINK_GUARD_ACTIVE",
        "M0_TEST_HARDLINK_GUARD_REQUIRED",
        "PYTHONPATH",
    ):
        environment.pop(name, None)
    environment["M0_TEST_DIRECT_PYTEST_CANARY"] = "1"
    with pytest.raises(PermissionError, match="SAFE_TEST_PROCESS_DENIED"):
        subprocess.run(
            [
                sys.executable,
                "-c",
                f"from pathlib import Path; Path({str(sentinel)!r}).write_text('ran')",
                "tests/test_safe_pytest_launcher.py",
                "--collect-only",
                "--basetemp",
                str(tmp_path),
            ],
            cwd=Path(__file__).parent.parent,
            env=environment,
            check=False,
            timeout=10,
        )
    assert not sentinel.exists()


def test_immutable_run_evidence_detects_content_and_identity_change(
    tmp_path: Path,
) -> None:
    evidence = tmp_path / "run-manifest.json"
    evidence.write_text('{"safe": true}\n', encoding="utf-8")
    before = _regular_file_evidence(evidence)
    evidence.write_text('{"safe": false}\n', encoding="utf-8")
    after = _regular_file_evidence(evidence)
    assert before != after


def test_junit_evidence_requires_regular_valid_zero_or_nonzero_counts(
    tmp_path: Path,
) -> None:
    junit = tmp_path / "junit.xml"
    junit.write_text(
        '<testsuites><testsuite tests="2" failures="0" errors="0" skipped="1">'
        '<testcase name="ok"/><testcase name="skip"><skipped/></testcase>'
        '</testsuite></testsuites>',
        encoding="utf-8",
    )
    evidence = _junit_evidence(junit)
    assert evidence["tests"] == 2
    assert evidence["failures"] == 0
    assert evidence["errors"] == 0
    junit.write_text("<testsuites>", encoding="utf-8")
    with pytest.raises(SafetyStop, match="JUnit XML is invalid"):
        _junit_evidence(junit)


def test_junit_evidence_rejects_hardlinked_output(tmp_path: Path) -> None:
    original = tmp_path / "original.xml"
    original.write_text(
        '<testsuite tests="1" failures="0" errors="0" skipped="0" />',
        encoding="utf-8",
    )
    linked = tmp_path / "junit.xml"
    os.link(original, linked)
    try:
        with pytest.raises(SafetyStop, match="exactly one hard link"):
            _junit_evidence(linked)
    finally:
        linked.unlink()
    assert os.stat(original).st_nlink == 1


def test_junit_evidence_rejects_aggregate_and_status_tree_mismatch(
    tmp_path: Path,
) -> None:
    junit = tmp_path / "junit.xml"
    junit.write_text(
        '<testsuite tests="1" failures="0" errors="0" skipped="0">'
        '<testcase name="hidden"><failure/></testcase></testsuite>',
        encoding="utf-8",
    )
    with pytest.raises(SafetyStop, match="aggregate counts"):
        _junit_evidence(junit)

    junit.write_text(
        '<testsuite tests="0" failures="1" errors="0" skipped="0">'
        '<failure/></testsuite>',
        encoding="utf-8",
    )
    with pytest.raises(SafetyStop, match="direct testcase children"):
        _junit_evidence(junit)


def test_run_tree_verifier_accepts_a_regular_isolated_tree(tmp_path: Path) -> None:
    run_root = tmp_path / "RUN-SAFE-VERIFY"
    run_root.mkdir()
    (run_root / "regular.txt").write_text("safe", encoding="utf-8")
    _verify_run_tree_no_reparse(run_root)
    nested = run_root / "nested"
    nested.mkdir()
    _verify_run_tree_no_reparse(run_root)


def test_run_tree_depth_counts_file_component_at_exact_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(launcher_module, "RUN_TREE_MAX_DEPTH", 2)
    run_root = tmp_path / "RUN-SAFE-DEPTH"
    nested = run_root / "a"
    nested.mkdir(parents=True)
    (nested / "exact.bin").write_bytes(b"x")
    metrics = _verify_run_tree_no_reparse(run_root)
    assert metrics["maximum_depth"] == 2
    deeper = nested / "b"
    deeper.mkdir()
    (deeper / "overflow.bin").write_bytes(b"x")
    with pytest.raises(SafetyStop, match="file depth"):
        _verify_run_tree_no_reparse(run_root)


def test_run_tree_verifier_rejects_hardlinks_without_leaving_them(
    tmp_path: Path,
) -> None:
    run_root = tmp_path / "RUN-SAFE-HARDLINK"
    run_root.mkdir()
    original = run_root / "original.bin"
    linked = run_root / "linked.bin"
    original.write_bytes(b"hardlink")
    os.link(original, linked)
    try:
        with pytest.raises(SafetyStop, match="multiple hard links"):
            _verify_run_tree_no_reparse(run_root)
    finally:
        linked.unlink()
    _verify_run_tree_no_reparse(run_root)


def test_run_tree_verifier_reports_fixed_metrics_and_rejects_ads(
    tmp_path: Path,
) -> None:
    run_root = tmp_path / "RUN-SAFE-ADS"
    run_root.mkdir()
    target = run_root / "regular.bin"
    target.write_bytes(b"safe")
    metrics = _verify_run_tree_no_reparse(run_root)
    assert metrics["file_count"] == 1
    assert metrics["total_bytes"] == 4
    stream = f"{target}:synthetic"
    with open(stream, "wb") as handle:
        handle.write(b"ads")
    try:
        with pytest.raises(SafetyStop, match="alternate data stream"):
            _verify_run_tree_no_reparse(run_root)
    finally:
        os.remove(stream)
    _verify_run_tree_no_reparse(run_root)
    directory_stream = f"{run_root}:synthetic-directory"
    from app.safety.windows_handle_writer import _WindowsApi

    api = _WindowsApi()
    directory_stream_handle = api.open_handle(
        Path(directory_stream),
        access=api.GENERIC_WRITE,
        share=api.FILE_SHARE_READ | api.FILE_SHARE_WRITE | api.FILE_SHARE_DELETE,
        disposition=api.CREATE_NEW,
        flags=api.FILE_FLAG_OPEN_REPARSE_POINT | api.FILE_FLAG_BACKUP_SEMANTICS,
    )
    api.close(directory_stream_handle)
    try:
        with pytest.raises(SafetyStop, match="alternate data stream"):
            _verify_run_tree_no_reparse(run_root)
    finally:
        os.remove(directory_stream)
    _verify_run_tree_no_reparse(run_root)


def test_process_job_reports_and_kills_an_unexpected_background_child(
    tmp_path: Path,
) -> None:
    child_pid = tmp_path / "background-child.pid"
    child_code = (
        "import pathlib,subprocess,sys; "
        "child=subprocess.Popen([sys.executable, '-B', '-c', "
        "'import time; time.sleep(30)']); "
        f"pathlib.Path({str(child_pid)!r}).write_text(str(child.pid), encoding='ascii')"
    )
    exit_code, timed_out, tree_terminated, budget_error, _budget_peak = _run_test_process(
        [sys.executable, "-B", "-c", child_code],
        project_root=Path(__file__).parent.parent,
        run_root=tmp_path,
        environment=os.environ.copy(),
        timeout_seconds=10,
    )
    assert exit_code == 0
    assert not timed_out
    assert not tree_terminated
    assert budget_error is None
    pid = int(child_pid.read_text(encoding="ascii"))
    assert not _pid_is_running(pid)


def test_process_job_terminates_the_full_tree_on_timeout(tmp_path: Path) -> None:
    child_pid = tmp_path / "timeout-child.pid"
    parent_code = (
        "import pathlib,subprocess,sys,time; "
        "child=subprocess.Popen([sys.executable, '-B', '-c', "
        "'import time; time.sleep(30)']); "
        f"pathlib.Path({str(child_pid)!r}).write_text(str(child.pid), encoding='ascii'); "
        "time.sleep(30)"
    )
    exit_code, timed_out, tree_terminated, budget_error, _budget_peak = _run_test_process(
        [sys.executable, "-B", "-c", parent_code],
        project_root=Path(__file__).parent.parent,
        run_root=tmp_path,
        environment=os.environ.copy(),
        timeout_seconds=1,
    )
    assert exit_code == 124
    assert timed_out
    assert tree_terminated
    assert budget_error is None
    pid = int(child_pid.read_text(encoding="ascii"))
    assert not _pid_is_running(pid)


def test_process_job_terminates_when_runtime_run_budget_is_exceeded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(launcher_module, "RUN_TREE_MAX_TOTAL_BYTES", 32)
    payload = tmp_path / "oversize.bin"
    code = (
        "from pathlib import Path; import time; "
        f"Path({str(payload)!r}).write_bytes(b'x' * 4096); time.sleep(30)"
    )
    exit_code, timed_out, tree_terminated, budget_error, budget_peak = _run_test_process(
        [sys.executable, "-B", "-c", code],
        project_root=Path(__file__).parent.parent,
        run_root=tmp_path,
        environment=os.environ.copy(),
        timeout_seconds=10,
    )
    assert exit_code == 94
    assert not timed_out
    assert tree_terminated
    assert budget_error is not None
    assert budget_peak["total_bytes"] <= 32


def test_process_job_terminates_when_runtime_file_depth_exceeds_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(launcher_module, "RUN_TREE_MAX_DEPTH", 1)
    nested = tmp_path / "nested"
    code = (
        "from pathlib import Path; import time; "
        f"p=Path({str(nested)!r}); p.mkdir(); (p/'overflow.bin').write_bytes(b'x'); "
        "time.sleep(30)"
    )
    exit_code, timed_out, tree_terminated, budget_error, _budget_peak = _run_test_process(
        [sys.executable, "-B", "-c", code],
        project_root=Path(__file__).parent.parent,
        run_root=tmp_path,
        environment=os.environ.copy(),
        timeout_seconds=10,
    )
    assert exit_code == 94
    assert not timed_out
    assert tree_terminated
    assert budget_error is not None


@pytest.mark.skipif(os.name != "nt", reason="Windows suspended-process contract")
@pytest.mark.parametrize("failure_method", ["assign", "resume_process"])
def test_job_setup_failure_never_runs_suspended_child(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_method: str,
) -> None:
    sentinel = tmp_path / f"{failure_method}.ran"

    def fail(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError(f"forced {failure_method} failure")

    monkeypatch.setattr(_WindowsJob, failure_method, fail)
    with pytest.raises(RuntimeError, match=failure_method):
        _run_test_process(
            [
                sys.executable,
                "-B",
                "-c",
                f"from pathlib import Path; Path({str(sentinel)!r}).write_text('ran')",
            ],
            project_root=Path(__file__).parent.parent,
            run_root=tmp_path,
            environment=os.environ.copy(),
            timeout_seconds=5,
        )
    assert not sentinel.exists()


def test_effective_exit_code_records_protected_state_gate_and_skips() -> None:
    base = {
        "pytest_exit_code": 0,
        "junit_valid": True,
        "junit_details": {"tests": 1, "failures": 0, "errors": 0, "skipped": 0},
        "process_tree_terminated": True,
        "run_tree_safe": True,
        "immutable_evidence_unchanged": True,
        "database_unchanged": True,
        "protected_tree_unchanged": True,
        "protected_runtime_monitor_valid": True,
        "protected_runtime_unchanged": True,
        "protected_handle_fence_valid": True,
    }
    assert _effective_exit_code(**base) == 0
    assert _effective_exit_code(**{**base, "pytest_exit_code": 1}) == 1
    assert _effective_exit_code(**{**base, "process_tree_terminated": False}) != 0
    assert _effective_exit_code(**{**base, "run_tree_safe": False}) != 0
    assert _effective_exit_code(**{**base, "immutable_evidence_unchanged": False}) != 0
    assert _effective_exit_code(**{**base, "database_unchanged": False}) == 97
    assert _effective_exit_code(**{**base, "protected_tree_unchanged": False}) == 97
    assert _effective_exit_code(
        **{**base, "protected_runtime_monitor_valid": False}
    ) == 97
    assert _effective_exit_code(
        **{**base, "protected_runtime_unchanged": False}
    ) == 97
    assert _effective_exit_code(
        **{**base, "protected_handle_fence_valid": False}
    ) == 97
    assert _effective_exit_code(
        **{
            **base,
            "junit_details": {
                "tests": 1,
                "failures": 0,
                "errors": 0,
                "skipped": 1,
            },
        }
    ) == 98
    for field in ("failures", "errors"):
        details = {"tests": 1, "failures": 0, "errors": 0, "skipped": 0}
        details[field] = 1
        assert _effective_exit_code(**{**base, "junit_details": details}) == 98
    assert _effective_exit_code(
        **{
            **base,
            "junit_details": {
                "tests": 0,
                "failures": 0,
                "errors": 0,
                "skipped": 0,
            },
        }
    ) == 98


def test_direct_pytest_canary_rejects_injected_plugin_environment(
    tmp_path: Path,
) -> None:
    basetemp = tmp_path / "injected-plugin-basetemp"
    basetemp.mkdir()
    environment = os.environ.copy()
    for name in (
        "M0_TEST_LAB_ROOT",
        "M0_TEST_LAB_TOKEN",
        "M0_TEST_HARDLINK_GUARD_ACTIVE",
        "M0_TEST_HARDLINK_GUARD_REQUIRED",
        "PYTHONPATH",
        "PYTEST_ADDOPTS",
        "PYTEST_PLUGINS",
    ):
        environment.pop(name, None)
    environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    environment["M0_TEST_DIRECT_PYTEST_CANARY"] = "1"
    environment["PYTEST_PLUGINS"] = "injected_plugin_must_not_load"
    with pytest.raises(PermissionError, match="SAFE_TEST_PROCESS_DENIED"):
        subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "tests/test_safe_pytest_launcher.py",
                "--collect-only",
                "-q",
                "-p",
                "no:cacheprovider",
                "--basetemp",
                str(basetemp),
            ],
            cwd=Path(__file__).parent.parent,
            env=environment,
            check=False,
            timeout=10,
        )


def test_direct_pytest_is_rejected_before_existing_basetemp_is_touched(
    tmp_path: Path,
) -> None:
    protected_basetemp = tmp_path / "protected-basetemp"
    protected_basetemp.mkdir()
    sentinel = protected_basetemp / "sentinel.bin"
    sentinel.write_bytes(b"direct-pytest-must-not-delete-this")
    sentinel_before = hashlib.sha256(sentinel.read_bytes()).hexdigest()

    environment = os.environ.copy()
    environment.pop("M0_TEST_LAB_ROOT", None)
    environment.pop("M0_TEST_LAB_TOKEN", None)
    environment.pop("M0_TEST_HARDLINK_GUARD_ACTIVE", None)
    environment.pop("M0_TEST_HARDLINK_GUARD_REQUIRED", None)
    environment.pop("PYTHONPATH", None)
    environment.pop("PYTEST_ADDOPTS", None)
    environment.pop("PYTEST_PLUGINS", None)
    environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    environment["M0_TEST_DIRECT_PYTEST_CANARY"] = "1"
    project_root = Path(__file__).parent.parent
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "tests/test_safe_pytest_launcher.py",
            "--collect-only",
            "-q",
            "-p",
            "no:cacheprovider",
            "--basetemp",
            str(protected_basetemp),
        ],
        cwd=project_root,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        check=False,
        timeout=30,
    )

    assert completed.returncode != 0
    combined_output = completed.stdout + completed.stderr
    assert b"SAFE_TEST_LAB_REQUIRED" in combined_output
    assert sentinel.is_file()
    assert hashlib.sha256(sentinel.read_bytes()).hexdigest() == sentinel_before
