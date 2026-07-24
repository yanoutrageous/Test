from __future__ import annotations

import hashlib
import json
import ntpath
import os
import stat
from pathlib import Path, PureWindowsPath
from threading import Lock
from typing import Any

import pytest

from app.project_root import PROJECT_ROOT as VERIFIED_PROJECT_ROOT
from scripts.run_safe_pytest import (
    SOURCE_WITNESS_FILE_NAME,
    SOURCE_WITNESS_MAX_BYTES,
    SOURCE_WITNESS_MAX_SOURCES,
    SOURCE_WITNESS_SCHEMA_VERSION,
    SOURCE_WITNESS_SCOPE,
    SOURCE_WITNESS_SOURCE_MAX_BYTES,
    SafetyStop,
    _WindowsStreamInspector,
    _canonical_json_bytes,
    _sign_source_witness_payload,
    _source_witness_locator_id,
)


REPARSE_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_SOURCE_WITNESS_REGISTRY: dict[str, dict[str, Any]] = {}
_SOURCE_WITNESS_LOCK = Lock()
_SOURCE_WITNESS_FINISHED = False


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


def _source_witness_context() -> tuple[Path, Path, str]:
    raw_run_root = os.environ.get("M0_TEST_LAB_ROOT")
    launch_token = os.environ.get("M0_TEST_LAB_TOKEN")
    if not raw_run_root or not launch_token:
        _fail("synthetic source registration requires the safe launcher")
    run_root = _absolute_lexical(raw_run_root)
    project_root = _absolute_lexical(Path(__file__).parent.parent)
    test_lab_root = project_root / "tmp" / "test_lab"
    relative_run = _relative_parts(run_root, test_lab_root)
    if relative_run != (run_root.name,) or not run_root.name.startswith("RUN-"):
        _fail("synthetic source registration has an invalid run root")
    _verify_existing_chain(run_root)
    return run_root, run_root / "external", launch_token


def _is_plain(identity: os.stat_result) -> bool:
    attributes = int(getattr(identity, "st_file_attributes", 0))
    reparse_tag = int(getattr(identity, "st_reparse_tag", 0))
    return not (
        stat.S_ISLNK(identity.st_mode)
        or attributes & REPARSE_ATTRIBUTE
        or reparse_tag
    )


def _parent_identity(identity: os.stat_result) -> dict[str, int]:
    return {
        "device": int(identity.st_dev),
        "inode": int(identity.st_ino),
        "mode": int(identity.st_mode),
        "file_attributes": int(getattr(identity, "st_file_attributes", 0)),
        "reparse_tag": int(getattr(identity, "st_reparse_tag", 0)),
    }


def _source_metadata(identity: os.stat_result) -> dict[str, int]:
    return {
        "device": int(identity.st_dev),
        "inode": int(identity.st_ino),
        "mode": int(identity.st_mode),
        "file_attributes": int(getattr(identity, "st_file_attributes", 0)),
        "reparse_tag": int(getattr(identity, "st_reparse_tag", 0)),
        "nlink": int(identity.st_nlink),
        "size": int(identity.st_size),
        "mtime_ns": int(identity.st_mtime_ns),
    }


def _source_has_default_stream_only(source: Path) -> bool:
    if os.name != "nt":
        return True
    try:
        _WindowsStreamInspector().require_default_stream_only(source)
    except SafetyStop:
        return False
    return True


def _capture_parent(
    run_root: Path,
    parent: Path,
) -> dict[str, int] | None:
    relative = _relative_parts(parent, run_root)
    if relative is None:
        return None
    current = run_root
    components = (None, *relative)
    final_identity: os.stat_result | None = None
    for component in components:
        if component is not None:
            current = current / component
        try:
            identity = os.lstat(current)
        except OSError:
            return None
        if not _is_plain(identity) or not stat.S_ISDIR(identity.st_mode):
            return None
        final_identity = identity
    if final_identity is None or int(final_identity.st_ino) <= 0:
        return None
    return _parent_identity(final_identity)


def _capture_synthetic_source(
    run_root: Path,
    source: Path,
) -> tuple[dict[str, int] | None, dict[str, Any] | None]:
    parent_before = _capture_parent(run_root, source.parent)
    if parent_before is None:
        return None, None
    try:
        path_before = os.lstat(source)
    except OSError:
        return parent_before, None
    if (
        not _is_plain(path_before)
        or not stat.S_ISREG(path_before.st_mode)
        or int(path_before.st_ino) <= 0
        or int(path_before.st_size) < 0
        or int(path_before.st_size) > SOURCE_WITNESS_SOURCE_MAX_BYTES
        or not _source_has_default_stream_only(source)
    ):
        return parent_before, None
    try:
        digest = hashlib.sha256()
        with source.open("rb") as handle:
            handle_before = os.fstat(handle.fileno())
            if (
                not _is_plain(handle_before)
                or not stat.S_ISREG(handle_before.st_mode)
                or _source_metadata(handle_before) != _source_metadata(path_before)
            ):
                return parent_before, None
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
            handle_after = os.fstat(handle.fileno())
    except OSError:
        return parent_before, None
    if _source_metadata(handle_before) != _source_metadata(handle_after):
        return parent_before, None
    try:
        path_after = os.lstat(source)
    except OSError:
        return parent_before, None
    if (
        not _is_plain(path_after)
        or not stat.S_ISREG(path_after.st_mode)
        or _source_metadata(path_after) != _source_metadata(handle_after)
        or not _source_has_default_stream_only(source)
    ):
        return parent_before, None
    parent_after = _capture_parent(run_root, source.parent)
    if parent_after is None or parent_after != parent_before:
        return parent_after, None
    try:
        path_bound = os.lstat(source)
    except OSError:
        return parent_after, None
    parent_bound = _capture_parent(run_root, source.parent)
    if (
        not _is_plain(path_bound)
        or not stat.S_ISREG(path_bound.st_mode)
        or _source_metadata(path_bound) != _source_metadata(handle_after)
        or not _source_has_default_stream_only(source)
        or parent_bound != parent_after
    ):
        return parent_bound, None
    return parent_bound, {
        **_source_metadata(handle_after),
        "sha256": digest.hexdigest(),
        "default_stream_only": True,
    }


def register_synthetic_source(path: str | os.PathLike[str]) -> str:
    """Register a synthetic source for registration/final snapshot comparison."""

    global _SOURCE_WITNESS_FINISHED
    run_root, external_root, launch_token = _source_witness_context()
    try:
        source = _absolute_lexical(path)
    except (TypeError, ValueError, OSError):
        _fail("synthetic source registration received an invalid path")
    relative = _relative_parts(source, external_root)
    if not relative or any(
        component in {"", ".", ".."}
        or ":" in component
        or component.rstrip(" .") != component
        for component in relative
    ):
        _fail("synthetic source must be below the current run external root")
    path_key = ntpath.normcase(str(source))
    source_id = _source_witness_locator_id(path_key, launch_token)
    with _SOURCE_WITNESS_LOCK:
        if _SOURCE_WITNESS_FINISHED:
            _fail("synthetic source registration is closed")
        existing = _SOURCE_WITNESS_REGISTRY.get(path_key)
        parent_before, source_before = _capture_synthetic_source(run_root, source)
        if (
            parent_before is None
            or source_before is None
            or source_before["nlink"] != 1
        ):
            _fail("synthetic source is not a stable single-link regular file")
        if existing is not None:
            if (
                existing["source_id"] != source_id
                or existing["parent_before"] != parent_before
                or existing["source_before"] != source_before
            ):
                _fail("synthetic source changed during duplicate registration")
            return source_id
        if len(_SOURCE_WITNESS_REGISTRY) >= SOURCE_WITNESS_MAX_SOURCES:
            _fail("synthetic source registration exceeds its fixed limit")
        _SOURCE_WITNESS_REGISTRY[path_key] = {
            "path": source,
            "source_id": source_id,
            "parent_before": parent_before,
            "source_before": source_before,
        }
    return source_id


def _write_source_witness_exclusive(path: Path, payload: dict[str, Any]) -> None:
    raw = _canonical_json_bytes(payload) + b"\n"
    if not raw or len(raw) > SOURCE_WITNESS_MAX_BYTES:
        _fail("source witness result exceeds its fixed byte limit")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError:
        _fail("source witness result cannot be created exclusively")
    try:
        remaining = memoryview(raw)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                _fail("source witness result could not be written completely")
            remaining = remaining[written:]
        os.fsync(descriptor)
    except OSError:
        _fail("source witness result could not be written completely")
    finally:
        os.close(descriptor)
    try:
        identity = os.lstat(path)
    except OSError:
        _fail("source witness result cannot be re-opened")
    if (
        not _is_plain(identity)
        or not stat.S_ISREG(identity.st_mode)
        or identity.st_nlink != 1
        or identity.st_size != len(raw)
    ):
        _fail("source witness result is not a stable single-link regular file")


@pytest.hookimpl(trylast=True)
def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    del session, exitstatus
    global _SOURCE_WITNESS_FINISHED
    run_root, _external_root, launch_token = _source_witness_context()
    with _SOURCE_WITNESS_LOCK:
        if _SOURCE_WITNESS_FINISHED:
            _fail("source witness finalization was invoked more than once")
        _SOURCE_WITNESS_FINISHED = True
        entries: list[dict[str, Any]] = []
        for record in sorted(
            _SOURCE_WITNESS_REGISTRY.values(),
            key=lambda item: item["source_id"],
        ):
            parent_after, source_after = _capture_synthetic_source(
                run_root,
                record["path"],
            )
            final_state_matches_registration = (
                parent_after == record["parent_before"]
                and source_after == record["source_before"]
            )
            entries.append(
                {
                    "source_id": record["source_id"],
                    "parent_before": record["parent_before"],
                    "source_before": record["source_before"],
                    "parent_after": parent_after,
                    "source_after": source_after,
                    "final_state_matches_registration": (
                        final_state_matches_registration
                    ),
                }
            )
    matching_final_state_count = sum(
        1 for entry in entries if entry["final_state_matches_registration"]
    )
    unsigned = {
        "schema_version": SOURCE_WITNESS_SCHEMA_VERSION,
        "run_id": run_root.name,
        "launch_token_sha256": hashlib.sha256(
            launch_token.encode("utf-8", "strict")
        ).hexdigest(),
        "source_count": len(entries),
        "matching_final_state_count": matching_final_state_count,
        "mismatched_final_state_count": len(entries) - matching_final_state_count,
        "witness_scope": SOURCE_WITNESS_SCOPE,
        "registered_source_final_state_matches": (
            matching_final_state_count == len(entries)
        ),
        "sources": entries,
    }
    signed = _sign_source_witness_payload(unsigned, launch_token)
    _write_source_witness_exclusive(
        run_root / SOURCE_WITNESS_FILE_NAME,
        signed,
    )


@pytest.hookimpl(tryfirst=True)
def pytest_configure(config: pytest.Config) -> None:
    project_root = _absolute_lexical(Path(__file__).parent.parent)
    expected_root = _absolute_lexical(VERIFIED_PROJECT_ROOT)
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
    try:
        sitecustomize = __import__("sitecustomize")
    except ImportError as exc:
        _fail(f"cannot import the audited test bootstrap: {exc}")
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
        "PYTEST_ADDOPTS",
        "PYTEST_PLUGINS",
    ):
        if os.environ.get(forbidden_name):
            _fail(f"untrusted environment variable is present: {forbidden_name}")
    if config.pluginmanager.hasplugin("cacheprovider"):
        _fail("pytest cacheprovider must be disabled")
    expected_bootstrap = project_root / "tests" / "safe_bootstrap"
    configured_bootstrap = os.environ.get("PYTHONPATH")
    if not configured_bootstrap or not _same_path(
        _absolute_lexical(configured_bootstrap),
        expected_bootstrap,
    ):
        _fail("PYTHONPATH must select only the audited test bootstrap")
    _verify_existing_chain(expected_bootstrap / "sitecustomize.py")
    if os.environ.get("M0_TEST_HARDLINK_GUARD_REQUIRED") != "1":
        _fail("test hardlink guard was not required by the launcher")
    if os.environ.get("M0_TEST_HARDLINK_GUARD_ACTIVE") != "1":
        _fail("test hardlink guard did not activate before pytest startup")
    if os.environ.get("M0_TEST_DIRECT_PYTEST_CANARY"):
        _fail("direct-pytest canary permission leaked into the normal test process")
    loaded_bootstrap = _absolute_lexical(Path(sitecustomize.__file__))
    if not _same_path(loaded_bootstrap, expected_bootstrap / "sitecustomize.py"):
        _fail("the loaded sitecustomize is not the audited test bootstrap")
    installed_guard = getattr(sitecustomize, "_INSTALLED_LINK_GUARD", None)
    if installed_guard is None or os.link is not installed_guard:
        _fail("the audited hardlink guard is not installed on os.link")
    if os.name == "nt" and __import__("nt").link is not installed_guard:
        _fail("the audited hardlink guard is not installed on nt.link")
