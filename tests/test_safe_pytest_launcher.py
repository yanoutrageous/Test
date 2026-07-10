from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.run_safe_pytest import (
    RUN_ID_PATTERN,
    SafetyStop,
    _build_command,
    _relative_parts,
    main,
)


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
    environment.pop("PYTEST_ADDOPTS", None)
    environment.pop("PYTEST_PLUGINS", None)
    environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
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
