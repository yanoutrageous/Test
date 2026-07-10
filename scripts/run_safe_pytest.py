from __future__ import annotations

import argparse
import hashlib
import json
import ntpath
import os
import re
import secrets
import stat
import subprocess
import sys
from datetime import datetime
from pathlib import Path, PureWindowsPath
from typing import Any, Sequence


EXPECTED_PROJECT_ROOT = Path(r"D:\AAA命题\Test")
RUN_ID_PATTERN = re.compile(r"RUN-[A-Z0-9][A-Z0-9-]{5,80}")
REPARSE_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
SYMLINK_TEST = "test_real_directory_symlink_is_rejected"


class SafetyStop(RuntimeError):
    pass


def _absolute_lexical(path: str | os.PathLike[str]) -> Path:
    return Path(ntpath.normpath(ntpath.abspath(os.fspath(path))))


def _same_path(left: Path, right: Path) -> bool:
    return ntpath.normcase(str(left)) == ntpath.normcase(str(right))


def _relative_parts(candidate: Path, root: Path) -> tuple[str, ...] | None:
    candidate_parts = PureWindowsPath(str(candidate)).parts
    root_parts = PureWindowsPath(str(root)).parts
    if len(candidate_parts) < len(root_parts):
        return None
    for candidate_part, root_part in zip(candidate_parts, root_parts, strict=False):
        if ntpath.normcase(candidate_part) != ntpath.normcase(root_part):
            return None
    return tuple(candidate_parts[len(root_parts) :])


def _lstat_no_reparse(path: Path) -> os.stat_result:
    try:
        identity = os.lstat(path)
    except OSError as exc:
        raise SafetyStop(f"cannot inspect required path {path}: {exc}") from exc
    attributes = int(getattr(identity, "st_file_attributes", 0))
    reparse_tag = int(getattr(identity, "st_reparse_tag", 0))
    if stat.S_ISLNK(identity.st_mode) or attributes & REPARSE_ATTRIBUTE or reparse_tag:
        raise SafetyStop(f"reparse point in safety-critical path chain: {path}")
    return identity


def _verify_existing_chain(path: Path) -> None:
    for component in (*reversed(path.parents), path):
        _lstat_no_reparse(component)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _write_json_exclusive(path: Path, payload: dict[str, Any]) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")


def _build_command(
    project_root: Path,
    run_root: Path,
    *,
    mode: str,
    exclude_symlink: bool,
) -> tuple[list[str], Path, Path]:
    basetemp = run_root / "pytest-basetemp"
    junit = run_root / "junit.xml"
    if os.path.lexists(basetemp) or os.path.lexists(junit):
        raise SafetyStop("basetemp and junit targets must not exist before pytest starts")

    selection: list[str]
    if mode == "full":
        selection = []
    elif mode == "guard":
        selection = ["tests/test_workspace_guard.py"]
    elif mode == "symlink":
        selection = [f"tests/test_workspace_guard.py::{SYMLINK_TEST}"]
    else:  # pragma: no cover - argparse constrains this value.
        raise SafetyStop(f"unsupported mode: {mode}")

    if mode == "symlink" and exclude_symlink:
        raise SafetyStop("the symlink-only mode cannot exclude the symlink gate")
    command = [
        sys.executable,
        "-m",
        "pytest",
        *selection,
        "-q",
        "-p",
        "no:cacheprovider",
    ]
    if exclude_symlink:
        command.extend(["-k", f"not {SYMLINK_TEST}"])
    command.extend(
        [
            "--basetemp",
            str(basetemp),
            "--junitxml",
            str(junit),
        ]
    )
    return command, basetemp, junit


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run pytest in a new, fail-closed Test-local safety laboratory.",
    )
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--mode", choices=("full", "guard", "symlink"), required=True)
    parser.add_argument(
        "--exclude-symlink",
        action="store_true",
        help="Run all selected tests except the separately audited symlink privilege gate.",
    )
    parser.add_argument("--timeout-seconds", type=int, default=900)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    if not RUN_ID_PATTERN.fullmatch(args.run_id):
        raise SafetyStop("run ID must match RUN-[A-Z0-9-] and contain no path syntax")
    if not 1 <= args.timeout_seconds <= 3600:
        raise SafetyStop("timeout must be between 1 and 3600 seconds")

    project_root = _absolute_lexical(Path(__file__).parent.parent)
    expected_root = _absolute_lexical(EXPECTED_PROJECT_ROOT)
    if not _same_path(project_root, expected_root):
        raise SafetyStop(
            f"launcher is outside the contracted project root: {project_root}"
        )
    expected_python = project_root / ".venv" / "Scripts" / "python.exe"
    if not _same_path(_absolute_lexical(sys.executable), expected_python):
        raise SafetyStop(f"use the audited project Python: {expected_python}")

    test_lab_root = project_root / "tmp" / "test_lab"
    _verify_existing_chain(expected_python)
    _verify_existing_chain(test_lab_root)
    if not test_lab_root.is_dir():
        raise SafetyStop(f"test laboratory parent is not a directory: {test_lab_root}")

    run_root = test_lab_root / args.run_id
    if _relative_parts(run_root, test_lab_root) != (args.run_id,):
        raise SafetyStop(f"run root escaped the direct test_lab child boundary: {run_root}")
    if os.path.lexists(run_root):
        raise SafetyStop(f"refusing to reuse or delete an existing run: {run_root}")
    os.mkdir(run_root)
    _verify_existing_chain(run_root)

    temp_root = run_root / "temp"
    pycache_root = run_root / "pycache"
    cache_root = run_root / "cache"
    os.mkdir(temp_root)
    os.mkdir(pycache_root)
    os.mkdir(cache_root)
    _lstat_no_reparse(temp_root)
    _lstat_no_reparse(pycache_root)
    _lstat_no_reparse(cache_root)

    created_at = datetime.now().astimezone().isoformat(timespec="seconds")
    launch_token = secrets.token_urlsafe(32)
    launch_token_sha256 = hashlib.sha256(launch_token.encode("utf-8")).hexdigest()
    marker = {
        "schema_version": "1.0",
        "run_id": args.run_id,
        "project_root": str(project_root),
        "purpose": "M0-S1 WorkspaceGuard safety laboratory",
        "cleanup_policy": "retain-until-manifested-quarantine",
        "created_at": created_at,
        "launch_token_sha256": launch_token_sha256,
    }
    _write_json_exclusive(run_root / ".safety-marker.json", marker)

    command, basetemp, junit = _build_command(
        project_root,
        run_root,
        mode=args.mode,
        exclude_symlink=args.exclude_symlink,
    )
    database = project_root / "data" / "db" / "question_bank.sqlite3"
    source_files = [
        project_root / "app" / "workspace_guard.py",
        project_root / "tests" / "test_workspace_guard.py",
        project_root / "tests" / "test_safe_pytest_launcher.py",
        project_root / "tests" / "conftest.py",
        _absolute_lexical(__file__),
    ]
    for source_file in (*source_files, database):
        _verify_existing_chain(source_file)
        if not source_file.is_file():
            raise SafetyStop(f"required evidence input is not a file: {source_file}")

    database_before = _sha256(database)
    environment = os.environ.copy()
    for untrusted_name in (
        "COVERAGE_FILE",
        "COVERAGE_PROCESS_START",
        "PYTHONHOME",
        "PYTHONPATH",
        "PYTEST_ADDOPTS",
        "PYTEST_PLUGINS",
    ):
        environment.pop(untrusted_name, None)
    environment.update(
        {
            "M0_TEST_LAB_ROOT": str(run_root),
            "M0_TEST_LAB_TOKEN": launch_token,
            "TEMP": str(temp_root),
            "TMP": str(temp_root),
            "XDG_CACHE_HOME": str(cache_root),
            "MPLCONFIGDIR": str(cache_root / "matplotlib"),
            "PYTHONPYCACHEPREFIX": str(pycache_root),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        }
    )
    manifest = {
        "schema_version": "1.0",
        "run_id": args.run_id,
        "created_at": created_at,
        "mode": args.mode,
        "exclude_symlink": bool(args.exclude_symlink),
        "project_root": str(project_root),
        "run_root": str(run_root),
        "basetemp": str(basetemp),
        "junit": str(junit),
        "command": command,
        "timeout_seconds": args.timeout_seconds,
        "launch_token_sha256": launch_token_sha256,
        "environment": {
            name: environment[name]
            for name in (
                "M0_TEST_LAB_ROOT",
                "TEMP",
                "TMP",
                "XDG_CACHE_HOME",
                "MPLCONFIGDIR",
                "PYTHONPYCACHEPREFIX",
                "PYTHONDONTWRITEBYTECODE",
                "PYTHONNOUSERSITE",
                "PYTEST_DISABLE_PLUGIN_AUTOLOAD",
            )
        },
        "source_sha256": {
            str(path.relative_to(project_root)): _sha256(path) for path in source_files
        },
        "activity_database": str(database.relative_to(project_root)),
        "activity_database_sha256_before": database_before,
    }
    _write_json_exclusive(run_root / "run-manifest.json", manifest)

    timed_out = False
    try:
        completed = subprocess.run(
            command,
            cwd=project_root,
            env=environment,
            shell=False,
            check=False,
            timeout=args.timeout_seconds,
        )
        pytest_exit_code = int(completed.returncode)
    except subprocess.TimeoutExpired:
        timed_out = True
        pytest_exit_code = 124

    database_after = _sha256(database)
    database_unchanged = database_before == database_after
    result = {
        "schema_version": "1.0",
        "run_id": args.run_id,
        "finished_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "pytest_exit_code": pytest_exit_code,
        "timed_out": timed_out,
        "junit_exists": junit.is_file(),
        "junit_sha256": _sha256(junit) if junit.is_file() else None,
        "activity_database_sha256_before": database_before,
        "activity_database_sha256_after": database_after,
        "activity_database_unchanged": database_unchanged,
    }
    _write_json_exclusive(run_root / "run-result.json", result)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    if not database_unchanged:
        return 97
    return pytest_exit_code


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SafetyStop as exc:
        print(f"SAFETY_STOP: {exc}", file=sys.stderr)
        raise SystemExit(96) from exc
