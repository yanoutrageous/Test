from __future__ import annotations

import hashlib
import json
import ntpath
import os
import stat
from pathlib import Path, PureWindowsPath
from typing import Any

import pytest


EXPECTED_PROJECT_ROOT = Path(r"D:\AAA命题\Test")
REPARSE_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


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


def _fail(message: str) -> None:
    raise pytest.UsageError(f"SAFE_TEST_LAB_REQUIRED: {message}")


def _verify_existing_chain(path: Path) -> None:
    for component in (*reversed(path.parents), path):
        try:
            identity = os.lstat(component)
        except OSError as exc:
            _fail(f"cannot inspect required path {component}: {exc}")
        attributes = int(getattr(identity, "st_file_attributes", 0))
        reparse_tag = int(getattr(identity, "st_reparse_tag", 0))
        if stat.S_ISLNK(identity.st_mode) or attributes & REPARSE_ATTRIBUTE or reparse_tag:
            _fail(f"reparse point in test path chain: {component}")


def _read_json(path: Path) -> dict[str, Any]:
    _verify_existing_chain(path)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        _fail(f"cannot read safety evidence {path}: {exc}")
    if not isinstance(payload, dict):
        _fail(f"safety evidence is not a JSON object: {path}")
    return payload


@pytest.hookimpl(tryfirst=True)
def pytest_configure(config: pytest.Config) -> None:
    project_root = _absolute_lexical(Path(__file__).parent.parent)
    expected_root = _absolute_lexical(EXPECTED_PROJECT_ROOT)
    if not _same_path(project_root, expected_root):
        _fail(f"tests are outside the contracted project root: {project_root}")
    if not _same_path(_absolute_lexical(Path.cwd()), project_root):
        _fail(f"pytest cwd must be the project root: {project_root}")
    if not _same_path(_absolute_lexical(config.rootpath), project_root):
        _fail(f"pytest rootpath must be the project root: {project_root}")

    raw_run_root = os.environ.get("M0_TEST_LAB_ROOT")
    launch_token = os.environ.get("M0_TEST_LAB_TOKEN")
    if not raw_run_root or not launch_token:
        _fail("use scripts/run_safe_pytest.py; direct pytest execution is forbidden")
    run_root = _absolute_lexical(raw_run_root)
    test_lab_root = project_root / "tmp" / "test_lab"
    relative_run = _relative_parts(run_root, test_lab_root)
    if relative_run != (run_root.name,) or not run_root.name.startswith("RUN-"):
        _fail(f"run root is not a direct unique test_lab child: {run_root}")
    _verify_existing_chain(run_root)

    marker = _read_json(run_root / ".safety-marker.json")
    manifest = _read_json(run_root / "run-manifest.json")
    token_sha256 = hashlib.sha256(launch_token.encode("utf-8")).hexdigest()
    for payload_name, payload in (("marker", marker), ("manifest", manifest)):
        if payload.get("run_id") != run_root.name:
            _fail(f"{payload_name} run ID does not match the selected run")
        if payload.get("launch_token_sha256") != token_sha256:
            _fail(f"{payload_name} launch token does not match this process")
    if not _same_path(_absolute_lexical(marker.get("project_root", "")), project_root):
        _fail("marker project root does not match the contracted root")
    if not _same_path(_absolute_lexical(manifest.get("project_root", "")), project_root):
        _fail("manifest project root does not match the contracted root")

    expected_basetemp = run_root / "pytest-basetemp"
    configured_basetemp = config.getoption("basetemp")
    if not configured_basetemp or not _same_path(
        _absolute_lexical(configured_basetemp),
        expected_basetemp,
    ):
        _fail(f"--basetemp must be exactly {expected_basetemp}")
    if os.path.lexists(expected_basetemp):
        _fail(f"pytest basetemp already exists before fixture initialization: {expected_basetemp}")
    if not _same_path(_absolute_lexical(manifest.get("basetemp", "")), expected_basetemp):
        _fail("manifest basetemp does not match the command-line target")

    expected_junit = run_root / "junit.xml"
    configured_junit = config.getoption("xmlpath")
    if not configured_junit or not _same_path(
        _absolute_lexical(configured_junit),
        expected_junit,
    ):
        _fail(f"--junitxml must be exactly {expected_junit}")
    if not _same_path(_absolute_lexical(manifest.get("junit", "")), expected_junit):
        _fail("manifest junit target does not match the command-line target")

    if os.environ.get("PYTEST_DISABLE_PLUGIN_AUTOLOAD") != "1":
        _fail("pytest plugin autoload must be disabled")
    for forbidden_name in (
        "COVERAGE_FILE",
        "COVERAGE_PROCESS_START",
        "PYTHONHOME",
        "PYTHONPATH",
        "PYTEST_ADDOPTS",
        "PYTEST_PLUGINS",
    ):
        if os.environ.get(forbidden_name):
            _fail(f"untrusted environment variable is present: {forbidden_name}")
    if config.pluginmanager.hasplugin("cacheprovider"):
        _fail("pytest cacheprovider must be disabled")
