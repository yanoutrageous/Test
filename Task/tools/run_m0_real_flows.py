from __future__ import annotations

import hashlib
import json
import ntpath
import os
import stat
import subprocess
import sys
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path, PureWindowsPath
from typing import Any


_IMPORT_PROJECT_ROOT = Path(
    ntpath.normpath(ntpath.abspath(os.fspath(Path(__file__).parents[2])))
)
if not any(
    ntpath.normcase(entry) == ntpath.normcase(str(_IMPORT_PROJECT_ROOT))
    for entry in sys.path
    if type(entry) is str
):
    sys.path.insert(0, str(_IMPORT_PROJECT_ROOT))

import fitz

from app.database import connect_database_read_only, initialize_database
from app.database_backup import DatabaseBackupService, validate_database
from app.database_migrations import CURRENT_SCHEMA_VERSION, inspect_migration_state
from app.gold_registry import load_gold_registry, validate_gold_bundle
from app.project_root import (
    PROJECT_ROOT,
    ROOT_MARKER_NAME,
    ProjectRootError,
    inspect_project_root,
)
from app.safety.context import DataClassification
from app.safety.workspace_io import WorkspaceIOError, get_workspace_io
from app.source_copy import (
    COPY_PAYLOAD_NAME,
    COPY_PROVENANCE_NAME,
    copy_registered_external_file,
)


RUN_ID = "RUN-20260725-M0-S6-FLOWS-145"
COPY_ID = "COPY-M0-S6-ANSWER-SHEET-20260725"
COPY_JOB_ID = "JOB-M0-S6-REAL-COPY"
BACKUP_ID = "BACKUP-M0-S6-RESCUE-20260725"
MIGRATED_STATE_ID = "STATE-M0-S6-MIGRATED-20260725"
ROLLBACK_STATE_ID = "STATE-M0-S6-ROLLBACK-20260725"
MIGRATION_JOB_ID = "JOB-M0-S6-MIGRATE"
ROLLBACK_JOB_ID = "JOB-M0-S6-ROLLBACK"
GOLD_LOGICAL_ID = "REF-ANSWER-SHEET-GOLD"
GOLD_MEMBER_ID = "MEMBER-001"
FLOW_SCHEMA_VERSION = "1.0"
_REPARSE_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_json(payload: dict[str, Any]) -> bytes:
    return (
        json.dumps(
            payload,
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
            separators=(",", ": "),
        )
        + "\n"
    ).encode("ascii")


def _database_logical_digest(path: Path) -> str:
    with closing(connect_database_read_only(path, immutable=True)) as connection:
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        dump = "\n".join(connection.iterdump())
    return _sha256(f"user_version={version}\n{dump}\n".encode("utf-8"))


def _database_counts(path: Path) -> dict[str, int]:
    with closing(connect_database_read_only(path, immutable=True)) as connection:
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        return {
            table: int(connection.execute(f'SELECT count(*) FROM "{table}"').fetchone()[0])
            for table in ("source_papers", "questions", "question_search_content")
            if table in tables
        }


def _gold_member() -> tuple[dict[str, Any], dict[str, Any]]:
    registry = load_gold_registry()
    entry = next(
        item for item in registry["entries"] if item["logical_id"] == GOLD_LOGICAL_ID
    )
    member = next(
        item for item in entry["members"] if item["member_id"] == GOLD_MEMBER_ID
    )
    return entry, member


def _expect_root_rejection(candidate: str | os.PathLike[str]) -> str:
    try:
        inspect_project_root(candidate)
    except ProjectRootError as exc:
        return type(exc).__name__
    raise RuntimeError("malicious or invalid project root was accepted")


def _run_marker_flow(
    workspace: Any,
    acceptance_relative: Path,
) -> dict[str, Any]:
    marker_bytes = workspace.read_bytes(ROOT_MARKER_NAME, maximum_bytes=4096)
    roots_relative = acceptance_relative / "portable-roots"
    positive_relative = roots_relative / "迁移 根 空格"
    positive_root = workspace.ensure_directory(positive_relative)
    workspace.create_new_bytes(positive_relative / ROOT_MARKER_NAME, marker_bytes)
    positive = inspect_project_root(positive_root)

    missing_relative = roots_relative / "missing-marker"
    missing_root = workspace.ensure_directory(missing_relative)
    missing_result = _expect_root_rejection(missing_root)

    tampered_relative = roots_relative / "tampered-marker"
    tampered_root = workspace.ensure_directory(tampered_relative)
    workspace.create_new_bytes(tampered_relative / ROOT_MARKER_NAME, b"{}\n")
    tampered_result = _expect_root_rejection(tampered_root)

    hardlink_relative = roots_relative / "hardlink-marker"
    hardlink_root = workspace.ensure_directory(hardlink_relative)
    hardlink_source = hardlink_root / "marker-source.bin"
    hardlink_marker = hardlink_root / ROOT_MARKER_NAME
    workspace.create_new_bytes(hardlink_relative / hardlink_source.name, marker_bytes)
    os.link(hardlink_source, hardlink_marker)
    try:
        hardlink_result = _expect_root_rejection(hardlink_root)
    finally:
        marker_identity = os.lstat(hardlink_marker)
        if (
            hardlink_marker.parent != hardlink_root
            or not stat.S_ISREG(marker_identity.st_mode)
            or int(marker_identity.st_nlink) < 2
        ):
            raise RuntimeError("hardlink attack fixture identity changed")
        os.unlink(hardlink_marker)

    reparse_relative = roots_relative / "reparse-root"
    reparse_root = PROJECT_ROOT / reparse_relative
    junction = subprocess.run(
        [
            "cmd.exe",
            "/d",
            "/c",
            "mklink",
            "/J",
            str(reparse_root),
            str(positive_root),
        ],
        cwd=PROJECT_ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=10,
    )
    if junction.returncode == 0:
        try:
            reparse_result = _expect_root_rejection(reparse_root)
            reparse_mode = "DIRECT_JUNCTION_REJECTED"
        finally:
            identity = os.lstat(reparse_root)
            if (
                reparse_root.parent != PROJECT_ROOT / roots_relative
                or not int(getattr(identity, "st_file_attributes", 0))
                & _REPARSE_ATTRIBUTE
            ):
                raise RuntimeError("junction attack fixture identity changed")
            os.rmdir(reparse_root)
    else:
        reparse_result = "ProjectRootError"
        reparse_mode = "HOST_CAPABILITY_UNAVAILABLE_COVERED_BY_RUN_144"

    drive_root = PureWindowsPath(str(PROJECT_ROOT)).anchor
    invalid_roots = {
        "drive_root": _expect_root_rejection(drive_root),
        "hardlink_marker": hardlink_result,
        "missing_marker": missing_result,
        "reparse": reparse_result,
        "tampered_marker": tampered_result,
        "unc": _expect_root_rejection(r"\\localhost\C$\M0-S6-invalid-root"),
    }
    if any(result != "ProjectRootError" for result in invalid_roots.values()):
        raise RuntimeError("one or more invalid roots did not fail closed")
    return {
        "automated_gate_run": "RUN-20260725-M0-S6-144",
        "filesystem": positive.filesystem,
        "invalid_roots": invalid_roots,
        "marker_sha256": positive.marker_sha256,
        "positive_migrated_root": "PASS",
        "reparse_evidence_mode": reparse_mode,
        "status": "PASS",
    }


def _run_fresh_state_flow(
    workspace: Any,
    acceptance_relative: Path,
) -> dict[str, Any]:
    fresh_relative = acceptance_relative / "fresh-state" / "新电脑 空格"
    required_directories = (
        fresh_relative / "data" / "db",
        fresh_relative / "assets" / "question_images",
        fresh_relative / "assets" / "paper_pages",
        fresh_relative / "exports",
        fresh_relative / "backups",
    )
    for relative in required_directories:
        workspace.ensure_directory(relative)
    database_path = PROJECT_ROOT / fresh_relative / "data" / "db" / "fresh.sqlite3"
    initialized = initialize_database(database_path)
    validation = validate_database(database_path, require_current=True)
    if (
        initialized["created"] is not True
        or validation.schema_version != CURRENT_SCHEMA_VERSION
        or not validation.valid
        or any(not (PROJECT_ROOT / relative).is_dir() for relative in required_directories)
    ):
        raise RuntimeError("fresh-state initialization did not meet the M0 contract")
    return {
        "created": True,
        "database_relative_path": database_path.relative_to(PROJECT_ROOT).as_posix(),
        "directory_count": len(required_directories),
        "integrity_check": validation.integrity_check,
        "foreign_key_violations": validation.foreign_key_violations,
        "schema_version": validation.schema_version,
        "status": "PASS",
    }


def _run_copy_and_gold_flow(source_path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    gold_summary = validate_gold_bundle()
    gold_entry, gold_member = _gold_member()
    receipt = copy_registered_external_file(
        source_path,
        logical_source_id=GOLD_LOGICAL_ID,
        copy_id=COPY_ID,
        job_id=COPY_JOB_ID,
        purpose="M0-REAL-FLOW",
        classification=DataClassification.INTERNAL,
    )
    workspace = get_workspace_io()
    target_relative = Path(receipt.target_relative_path)
    payload = workspace.read_bytes(
        target_relative / COPY_PAYLOAD_NAME,
        maximum_bytes=gold_member["bytes"],
    )
    provenance_bytes = workspace.read_bytes(
        target_relative / COPY_PROVENANCE_NAME,
        maximum_bytes=64 * 1024,
    )
    provenance = json.loads(provenance_bytes.decode("ascii"))
    redacted = (
        os.fspath(source_path).encode("utf-8") not in provenance_bytes
        and source_path.name.encode("utf-8") not in provenance_bytes
    )
    if (
        receipt.payload_sha256 != gold_member["sha256"]
        or receipt.payload_bytes != gold_member["bytes"]
        or _sha256(payload) != gold_member["sha256"]
        or provenance["source"]["logical_id"] != GOLD_LOGICAL_ID
        or provenance["source"]["sha256"] != gold_member["sha256"]
        or not redacted
    ):
        raise RuntimeError("registered Copy differs from the selected gold member")

    with fitz.open(stream=payload, filetype="pdf") as document:
        page_count = document.page_count
        first_page = document.load_page(0)
        observed_mm = [
            round(float(first_page.rect.width) * 25.4 / 72.0, 3),
            round(float(first_page.rect.height) * 25.4 / 72.0, 3),
        ]
    expected_mm = gold_member["page_sizes_mm"][0]
    if (
        page_count != gold_member["page_count"]
        or any(abs(observed - expected) > 0.02 for observed, expected in zip(observed_mm, expected_mm))
    ):
        raise RuntimeError("representative Copy page differs from the gold registry")

    copy_flow = {
        "copy_id": receipt.copy_id,
        "payload_bytes": receipt.payload_bytes,
        "payload_sha256": receipt.payload_sha256,
        "provenance_path_redacted": redacted,
        "provenance_sha256": receipt.provenance_sha256,
        "source_final_reverified": bool(receipt.source_verification_sha256),
        "status": "PASS",
        "target_relative_path": receipt.target_relative_path,
    }
    gold_flow = {
        "gold_entry_count": gold_summary["entry_count"],
        "logical_id": gold_entry["logical_id"],
        "member_id": gold_member["member_id"],
        "page_count": page_count,
        "representative_page": 1,
        "representative_page_size_mm": observed_mm,
        "status": "PASS",
        "template_family_count": gold_summary["template_family_count"],
    }
    return copy_flow, gold_flow


def _run_write_boundary_flow(
    workspace: Any,
    acceptance_relative: Path,
) -> dict[str, Any]:
    legal_relative = acceptance_relative / "legal-write" / "中文 空格" / "合法写入.txt"
    legal = workspace.create_new_text(legal_relative, "M0 合法项目内写入\n")
    if workspace.read_bytes(legal_relative, maximum_bytes=64) != "M0 合法项目内写入\n".encode(
        "utf-8"
    ):
        raise RuntimeError("legal in-project write could not be read back")

    sibling_target = PROJECT_ROOT.parent / f"{RUN_ID}-outside-must-not-exist.bin"
    c_target = Path(f"C:\\{RUN_ID}-outside-must-not-exist.bin")
    if os.path.lexists(sibling_target) or os.path.lexists(c_target):
        raise RuntimeError("outside-write sentinel already exists")
    attempts: tuple[tuple[str, str | Path, Path | None], ...] = (
        ("sibling", sibling_target, sibling_target),
        ("other_drive_location", c_target, c_target),
        ("drive_root", PureWindowsPath(str(PROJECT_ROOT)).anchor, None),
        ("unc", r"\\localhost\C$\M0-S6-outside.bin", None),
        ("device", r"\\.\NUL", None),
        ("relative_traversal", Path("..") / sibling_target.name, sibling_target),
        ("alternate_stream", legal_relative.with_name("合法写入.txt:stream"), None),
    )
    rejections: dict[str, str] = {}
    for name, requested, sentinel in attempts:
        before = os.path.lexists(sentinel) if sentinel is not None else False
        try:
            workspace.create_new_bytes(requested, b"M0-OUTSIDE-WRITE-MUST-FAIL")
        except WorkspaceIOError as exc:
            rejections[name] = exc.code.value
        else:
            raise RuntimeError(f"outside write was accepted: {name}")
        after = os.path.lexists(sentinel) if sentinel is not None else False
        if before != after:
            raise RuntimeError(f"rejected outside write changed a sentinel: {name}")
    if len(rejections) != len(attempts):
        raise RuntimeError("outside-write rejection evidence is incomplete")
    return {
        "legal_write": legal.to_dict(),
        "outside_attempt_count": len(attempts),
        "outside_rejections": rejections,
        "outside_side_effect_count": 0,
        "status": "PASS",
    }


def _run_migration_roundtrip() -> dict[str, Any]:
    service = DatabaseBackupService(PROJECT_ROOT)
    active_path = service.active_database_path
    active_digest = _database_logical_digest(active_path)
    active_counts = _database_counts(active_path)
    with closing(connect_database_read_only(active_path, immutable=True)) as connection:
        active_version = inspect_migration_state(connection).schema_version
    if active_version != 0:
        raise RuntimeError("M0 migration rehearsal requires the unchanged legacy activity DB")

    migration = service.stage_migrated_copy(
        backup_id=BACKUP_ID,
        state_id=MIGRATED_STATE_ID,
        job_id=MIGRATION_JOB_ID,
        minimum_free_bytes=0,
    )
    migrated_path = PROJECT_ROOT / migration.migrated_state.database_relative_path
    migrated_counts = _database_counts(migrated_path)
    if (
        not migration.active_database_unchanged
        or migration.migrated_state.validation.schema_version
        != CURRENT_SCHEMA_VERSION
        or migrated_counts != active_counts
    ):
        raise RuntimeError("database migration copy did not preserve legacy data")

    rollback = service.restore_backup(
        backup_id=BACKUP_ID,
        state_id=ROLLBACK_STATE_ID,
        job_id=ROLLBACK_JOB_ID,
    )
    rollback_path = PROJECT_ROOT / rollback.database_relative_path
    rollback_digest = _database_logical_digest(rollback_path)
    rollback_counts = _database_counts(rollback_path)
    with closing(connect_database_read_only(rollback_path, immutable=True)) as connection:
        rollback_version = inspect_migration_state(connection).schema_version
        old_read_query_succeeded = (
            int(connection.execute("SELECT count(*) FROM source_papers").fetchone()[0])
            == rollback_counts["source_papers"]
        )
    if (
        rollback_version != 0
        or rollback_digest != active_digest
        or rollback_counts != active_counts
        or not old_read_query_succeeded
    ):
        raise RuntimeError("database rollback did not restore the old read contract")
    return {
        "active_database_unchanged_during_migration": True,
        "backup_id": BACKUP_ID,
        "data_counts_preserved": True,
        "integrity_check": migration.migrated_state.validation.integrity_check,
        "foreign_key_violations": migration.migrated_state.validation.foreign_key_violations,
        "migrated_schema_version": migration.migrated_state.validation.schema_version,
        "migrated_state_id": MIGRATED_STATE_ID,
        "old_read_path_started": old_read_query_succeeded,
        "rollback_schema_version": rollback_version,
        "rollback_state_id": ROLLBACK_STATE_ID,
        "status": "PASS",
    }


def main() -> int:
    raw_source = os.environ.get("M0_REAL_SOURCE_PATH")
    if not raw_source:
        raise RuntimeError("M0_REAL_SOURCE_PATH is required")
    source_path = Path(raw_source)
    workspace = get_workspace_io()
    acceptance_relative = Path("tmp") / "acceptance" / RUN_ID
    acceptance_root = PROJECT_ROOT / acceptance_relative
    if os.path.lexists(acceptance_root):
        raise RuntimeError("M0 real-flow run ID already exists")
    workspace.ensure_directory(acceptance_relative)

    active_path = PROJECT_ROOT / "data" / "db" / "question_bank.sqlite3"
    active_before = {
        "bytes": active_path.stat().st_size,
        "mtime_ns": active_path.stat().st_mtime_ns,
        "sha256": _sha256_file(active_path),
    }
    flows: dict[str, Any] = {}
    flows["fresh_state"] = _run_fresh_state_flow(workspace, acceptance_relative)
    flows["portable_root"] = _run_marker_flow(workspace, acceptance_relative)
    copy_flow, gold_flow = _run_copy_and_gold_flow(source_path)
    flows["registered_external_copy"] = copy_flow
    flows["write_boundary"] = _run_write_boundary_flow(
        workspace,
        acceptance_relative,
    )
    flows["migration_roundtrip"] = _run_migration_roundtrip()
    flows["gold_location"] = gold_flow

    active_after = {
        "bytes": active_path.stat().st_size,
        "mtime_ns": active_path.stat().st_mtime_ns,
        "sha256": _sha256_file(active_path),
    }
    if active_after != active_before:
        raise RuntimeError("activity database changed during M0 real flows")
    payload = {
        "activity_database": {
            "bytes": active_after["bytes"],
            "mtime_unchanged": True,
            "sha256": active_after["sha256"],
            "unchanged": True,
        },
        "decision": "PASS",
        "flows": flows,
        "generated_at": datetime.now(UTC).isoformat(),
        "run_id": RUN_ID,
        "schema_version": FLOW_SCHEMA_VERSION,
    }
    serialized = _canonical_json(payload)
    raw_source_bytes = os.fspath(source_path).encode("utf-8")
    if raw_source_bytes in serialized or source_path.name.encode("utf-8") in serialized:
        raise RuntimeError("flow evidence disclosed the external physical locator")
    report_relative = acceptance_relative / "m0-real-flow-evidence.json"
    receipt = workspace.create_new_bytes(report_relative, serialized)
    print(
        json.dumps(
            {
                "decision": "PASS",
                "report_relative_path": report_relative.as_posix(),
                "report_sha256": receipt.sha256,
                "run_id": RUN_ID,
            },
            ensure_ascii=True,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
