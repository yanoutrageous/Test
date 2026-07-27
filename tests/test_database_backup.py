from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

import app.database_backup as database_backup_module
from app.database import connect_database_read_only, initialize_database, read_schema
from app.database_backup import (
    BACKUP_MANIFEST_NAME,
    BACKUP_SNAPSHOT_NAME,
    BackupFailurePoint,
    DatabaseBackupCode,
    DatabaseBackupError,
    DatabaseBackupService,
    STATE_DATABASE_NAME,
    validate_database,
)
from app.database_migrations import CURRENT_SCHEMA_VERSION, inspect_migration_state
from app.project_root import PROJECT_ROOT, ROOT_MARKER_NAME


def _canonical_json(payload: dict[str, object]) -> bytes:
    return (
        json.dumps(
            payload,
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
            separators=(",", ": "),
        )
        + "\n"
    ).encode("utf-8")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _project_root(tmp_path: Path, *, legacy: bool = False) -> tuple[Path, Path]:
    root = tmp_path / "可迁移 项目"
    root.mkdir()
    (root / ROOT_MARKER_NAME).write_bytes(
        (PROJECT_ROOT / ROOT_MARKER_NAME).read_bytes()
    )
    db_path = root / "data" / "db" / "question_bank.sqlite3"
    db_path.parent.mkdir(parents=True)
    if legacy:
        with sqlite3.connect(db_path) as conn:
            conn.executescript(read_schema())
            conn.execute(
                """
                INSERT INTO source_papers (
                    paper_code,
                    title,
                    source_path,
                    meta_json
                ) VALUES (?, ?, ?, ?)
                """,
                ("LEGACY-BACKUP", "Legacy backup", "Base/legacy.pdf", "{}"),
            )
            conn.commit()
    else:
        initialize_database(db_path)
    return root, db_path


def _insert_source(path: Path, code: str) -> None:
    with sqlite3.connect(path) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute(
            """
            INSERT INTO source_papers (
                paper_code,
                title,
                source_path,
                meta_json
            ) VALUES (?, ?, ?, ?)
            """,
            (code, code, f"Base/{code}.pdf", "{}"),
        )
        conn.commit()


def _fail_at(point: BackupFailurePoint) -> BackupFailurePoint:
    return point


def test_backup_api_captures_committed_wal_state_without_mutating_source(
    tmp_path: Path,
) -> None:
    root, db_path = _project_root(tmp_path)
    writer = sqlite3.connect(db_path)
    try:
        assert writer.execute("PRAGMA journal_mode = WAL").fetchone()[0] == "wal"
        writer.execute("PRAGMA wal_autocheckpoint = 0")
        writer.execute(
            """
            INSERT INTO source_papers (
                paper_code,
                title,
                source_path,
                meta_json
            ) VALUES ('WAL-ONLY', 'WAL only', 'Base/wal.pdf', '{}')
            """
        )
        writer.commit()
        wal_path = Path(f"{db_path}-wal")
        assert wal_path.exists() and wal_path.stat().st_size > 0
        source_main_before = _sha256(db_path)

        service = DatabaseBackupService(root)
        receipt = service.create_backup(
            backup_id="BACKUP-S4-WAL",
            job_id="JOB-S4-WAL",
            minimum_free_bytes=0,
        )

        assert _sha256(db_path) == source_main_before
        snapshot = root / receipt.snapshot_relative_path
        with connect_database_read_only(snapshot) as conn:
            assert conn.execute(
                "SELECT count(*) FROM source_papers WHERE paper_code = 'WAL-ONLY'"
            ).fetchone()[0] == 1
        assert receipt.validation.valid is True
        assert receipt.validation.schema_version == CURRENT_SCHEMA_VERSION
    finally:
        writer.close()


def test_backup_manifest_is_relative_hashed_and_recoverable(tmp_path: Path) -> None:
    root, db_path = _project_root(tmp_path)
    _insert_source(db_path, "ROUNDTRIP")
    service = DatabaseBackupService(root)

    backup = service.create_backup(
        backup_id="BACKUP-S4-ROUNDTRIP",
        job_id="JOB-S4-BACKUP",
        minimum_free_bytes=0,
    )
    restored = service.restore_backup(
        backup_id=backup.backup_id,
        state_id="STATE-S4-RESTORED",
        job_id="JOB-S4-RESTORE",
    )

    manifest_path = root / backup.backup_relative_path / BACKUP_MANIFEST_NAME
    manifest_text = manifest_path.read_text(encoding="utf-8")
    manifest = json.loads(manifest_text)
    assert str(root) not in manifest_text
    assert manifest["source"]["relative_path"] == "data/db/question_bank.sqlite3"
    assert manifest["files"][0]["role"] == "SQLITE_BACKUP_API_SNAPSHOT"
    assert manifest["files"][0]["sha256"] == backup.snapshot_sha256
    restored_db = root / restored.database_relative_path
    assert restored.database_sha256 == _sha256(restored_db)
    with connect_database_read_only(restored_db) as conn:
        assert conn.execute(
            "SELECT count(*) FROM source_papers WHERE paper_code = 'ROUNDTRIP'"
        ).fetchone()[0] == 1


@pytest.mark.parametrize(
    "point",
    (
        BackupFailurePoint.AFTER_SNAPSHOT,
        BackupFailurePoint.AFTER_MANIFEST,
        BackupFailurePoint.AFTER_PUBLISH,
    ),
)
def test_backup_interruption_reconciles_without_overwrite(
    tmp_path: Path,
    point: BackupFailurePoint,
) -> None:
    root, _db_path = _project_root(tmp_path)
    service = DatabaseBackupService(root)

    with pytest.raises(DatabaseBackupError, match=point.value):
        service.create_backup(
            backup_id="BACKUP-S4-INTERRUPT",
            job_id="JOB-S4-INTERRUPT",
            minimum_free_bytes=0,
            failpoint=_fail_at(point),
        )

    retry = service.create_backup(
        backup_id="BACKUP-S4-INTERRUPT",
        job_id="JOB-S4-INTERRUPT",
        minimum_free_bytes=0,
    )
    assert retry.validation.valid is True
    assert retry.idempotent is (point is BackupFailurePoint.AFTER_PUBLISH)
    assert service.validate_backup(retry.backup_id).snapshot_sha256 == retry.snapshot_sha256


@pytest.mark.parametrize(
    "point",
    (
        BackupFailurePoint.AFTER_SNAPSHOT,
        BackupFailurePoint.AFTER_MANIFEST,
        BackupFailurePoint.AFTER_PUBLISH,
    ),
)
def test_real_process_backup_crash_reconciles_without_overwrite(
    tmp_path: Path,
    point: BackupFailurePoint,
) -> None:
    root, _db_path = _project_root(tmp_path)
    child_code = r"""
import os
import sys
from pathlib import Path
import app.database_backup as backup_module
from app.database_backup import BackupFailurePoint, DatabaseBackupService

expected = sys.argv[2]
exit_code = int(sys.argv[3])

def crash(configured, observed):
    if configured is observed and observed.value == expected:
        os._exit(exit_code)

backup_module._call_failpoint = crash
DatabaseBackupService(Path(sys.argv[1])).create_backup(
    backup_id="BACKUP-S4-REAL-CRASH",
    job_id="JOB-S4-REAL-CRASH",
    minimum_free_bytes=0,
    failpoint=BackupFailurePoint(expected),
)
raise AssertionError("configured backup crash point did not terminate the child")
"""
    completed = subprocess.run(
        [
            sys.executable,
            "-B",
            "-c",
            child_code,
            str(root),
            point.value,
            "82",
        ],
        cwd=Path(__file__).parent.parent,
        env=os.environ.copy(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=30,
    )
    assert completed.returncode == 82

    retry = DatabaseBackupService(root).create_backup(
        backup_id="BACKUP-S4-REAL-CRASH",
        job_id="JOB-S4-REAL-CRASH",
        minimum_free_bytes=0,
    )
    assert retry.validation.valid is True
    assert retry.idempotent is (point is BackupFailurePoint.AFTER_PUBLISH)


@pytest.mark.parametrize(
    "point",
    (
        BackupFailurePoint.RESTORE_AFTER_DATABASE,
        BackupFailurePoint.RESTORE_AFTER_MANIFEST,
        BackupFailurePoint.RESTORE_AFTER_PUBLISH,
    ),
)
def test_restore_interruption_reconciles_without_switching_active_database(
    tmp_path: Path,
    point: BackupFailurePoint,
) -> None:
    root, db_path = _project_root(tmp_path)
    service = DatabaseBackupService(root)
    backup = service.create_backup(
        backup_id="BACKUP-S4-RESTORE-INTERRUPT",
        job_id="JOB-S4-RESTORE-SOURCE",
        minimum_free_bytes=0,
    )
    active_before = _sha256(db_path)

    with pytest.raises(DatabaseBackupError, match=point.value):
        service.restore_backup(
            backup_id=backup.backup_id,
            state_id="STATE-S4-RESTORE-INTERRUPT",
            job_id="JOB-S4-RESTORE-INTERRUPT",
            failpoint=_fail_at(point),
        )

    retry = service.restore_backup(
        backup_id=backup.backup_id,
        state_id="STATE-S4-RESTORE-INTERRUPT",
        job_id="JOB-S4-RESTORE-INTERRUPT",
    )
    assert retry.idempotent is (point is BackupFailurePoint.RESTORE_AFTER_PUBLISH)
    assert _sha256(db_path) == active_before


def test_backup_tamper_missing_extra_and_traversal_are_rejected(
    tmp_path: Path,
) -> None:
    root, _db_path = _project_root(tmp_path)
    service = DatabaseBackupService(root)
    receipt = service.create_backup(
        backup_id="BACKUP-S4-TAMPER",
        job_id="JOB-S4-TAMPER",
        minimum_free_bytes=0,
    )
    backup_root = root / receipt.backup_relative_path
    snapshot = backup_root / BACKUP_SNAPSHOT_NAME
    original_snapshot = snapshot.read_bytes()

    with snapshot.open("r+b") as handle:
        handle.seek(max(0, len(original_snapshot) // 2))
        handle.write(b"TAMPER")
    with pytest.raises(DatabaseBackupError) as captured:
        service.validate_backup(receipt.backup_id)
    assert captured.value.code in {
        DatabaseBackupCode.DATABASE_INVALID,
        DatabaseBackupCode.MANIFEST_INVALID,
    }
    snapshot.write_bytes(original_snapshot)

    extra = backup_root / "undeclared.bin"
    extra.write_bytes(b"extra")
    with pytest.raises(DatabaseBackupError) as captured:
        service.validate_backup(receipt.backup_id)
    assert captured.value.code is DatabaseBackupCode.MANIFEST_INVALID
    extra.unlink()

    manifest_path = backup_root / BACKUP_MANIFEST_NAME
    original_manifest = manifest_path.read_bytes()
    manifest = json.loads(original_manifest)
    manifest["files"][0]["relative_path"] = "../database.sqlite3"
    manifest_path.write_bytes(_canonical_json(manifest))
    with pytest.raises(DatabaseBackupError) as captured:
        service.validate_backup(receipt.backup_id)
    assert captured.value.code is DatabaseBackupCode.MANIFEST_INVALID


def test_missing_backup_file_cannot_publish_a_restore_state(tmp_path: Path) -> None:
    root, _db_path = _project_root(tmp_path)
    service = DatabaseBackupService(root)
    receipt = service.create_backup(
        backup_id="BACKUP-S4-MISSING",
        job_id="JOB-S4-MISSING",
        minimum_free_bytes=0,
    )
    snapshot = root / receipt.snapshot_relative_path
    retained = snapshot.with_suffix(".retained")
    snapshot.rename(retained)

    with pytest.raises(DatabaseBackupError):
        service.restore_backup(
            backup_id=receipt.backup_id,
            state_id="STATE-S4-MISSING",
            job_id="JOB-S4-MISSING-RESTORE",
        )
    assert not (root / "data" / "db" / "versions" / "STATE-S4-MISSING").exists()
    assert retained.exists()


def test_corrupt_interrupted_stage_is_retained_and_new_job_can_retry(
    tmp_path: Path,
) -> None:
    root, _db_path = _project_root(tmp_path)
    service = DatabaseBackupService(root)
    with pytest.raises(DatabaseBackupError):
        service.create_backup(
            backup_id="BACKUP-S4-RETAIN",
            job_id="JOB-S4-FAILED",
            minimum_free_bytes=0,
            failpoint=_fail_at(BackupFailurePoint.AFTER_SNAPSHOT),
        )
    failed_snapshot = (
        root
        / "tmp"
        / "jobs"
        / "INTERNAL"
        / "JOB-S4-FAILED"
        / "backup"
        / "BACKUP-S4-RETAIN"
        / BACKUP_SNAPSHOT_NAME
    )
    failed_snapshot.write_bytes(b"not a database")
    with pytest.raises(DatabaseBackupError):
        service.create_backup(
            backup_id="BACKUP-S4-RETAIN",
            job_id="JOB-S4-FAILED",
            minimum_free_bytes=0,
        )
    assert failed_snapshot.read_bytes() == b"not a database"

    retry = service.create_backup(
        backup_id="BACKUP-S4-RETAIN",
        job_id="JOB-S4-RETRY",
        minimum_free_bytes=0,
    )
    assert retry.validation.valid is True
    assert failed_snapshot.read_bytes() == b"not a database"


def test_malformed_interrupted_manifest_is_rejected_without_rewrite(
    tmp_path: Path,
) -> None:
    root, _db_path = _project_root(tmp_path)
    service = DatabaseBackupService(root)
    with pytest.raises(DatabaseBackupError):
        service.create_backup(
            backup_id="BACKUP-S4-BAD-MANIFEST",
            job_id="JOB-S4-BAD-MANIFEST",
            minimum_free_bytes=0,
            failpoint=_fail_at(BackupFailurePoint.AFTER_MANIFEST),
        )
    failed_manifest = (
        root
        / "tmp"
        / "jobs"
        / "INTERNAL"
        / "JOB-S4-BAD-MANIFEST"
        / "backup"
        / "BACKUP-S4-BAD-MANIFEST"
        / BACKUP_MANIFEST_NAME
    )
    failed_manifest.write_bytes(b"{not-json")

    with pytest.raises(DatabaseBackupError) as captured:
        service.create_backup(
            backup_id="BACKUP-S4-BAD-MANIFEST",
            job_id="JOB-S4-BAD-MANIFEST",
            minimum_free_bytes=0,
        )

    assert captured.value.code is DatabaseBackupCode.MANIFEST_INVALID
    assert failed_manifest.read_bytes() == b"{not-json"


def test_space_preflight_stops_without_creating_backup(tmp_path: Path, monkeypatch) -> None:
    root, _db_path = _project_root(tmp_path)
    service = DatabaseBackupService(root)
    monkeypatch.setattr(
        database_backup_module.shutil,
        "disk_usage",
        lambda _path: SimpleNamespace(free=0),
    )

    with pytest.raises(DatabaseBackupError) as captured:
        service.create_backup(
            backup_id="BACKUP-S4-NOSPACE",
            job_id="JOB-S4-NOSPACE",
        )

    assert captured.value.code is DatabaseBackupCode.INSUFFICIENT_SPACE
    assert not (root / "backups" / "BACKUP-S4-NOSPACE").exists()


def test_legacy_database_migrates_only_in_copy_and_rescue_rolls_back(
    tmp_path: Path,
) -> None:
    root, active_db = _project_root(tmp_path, legacy=True)
    service = DatabaseBackupService(root)
    active_before = _sha256(active_db)

    result = service.stage_migrated_copy(
        backup_id="BACKUP-S4-RESCUE",
        state_id="STATE-S4-MIGRATED",
        job_id="JOB-S4-MIGRATE",
        minimum_free_bytes=0,
    )

    assert result.active_database_unchanged is True
    assert _sha256(active_db) == active_before
    with connect_database_read_only(active_db) as conn:
        assert inspect_migration_state(conn).schema_version == 0
    migrated = root / result.migrated_state.database_relative_path
    with connect_database_read_only(migrated) as conn:
        assert inspect_migration_state(conn).schema_version == CURRENT_SCHEMA_VERSION
        assert conn.execute(
            "SELECT count(*) FROM source_papers WHERE paper_code = 'LEGACY-BACKUP'"
        ).fetchone()[0] == 1

    rollback = service.restore_backup(
        backup_id="BACKUP-S4-RESCUE",
        state_id="STATE-S4-ROLLBACK",
        job_id="JOB-S4-ROLLBACK",
    )
    rollback_db = root / rollback.database_relative_path
    with connect_database_read_only(rollback_db) as conn:
        assert inspect_migration_state(conn).schema_version == 0
        assert conn.execute(
            "SELECT count(*) FROM source_papers WHERE paper_code = 'LEGACY-BACKUP'"
        ).fetchone()[0] == 1
    assert _sha256(active_db) == active_before


def test_migration_copy_interruption_resumes_and_never_mutates_active(
    tmp_path: Path,
) -> None:
    root, active_db = _project_root(tmp_path, legacy=True)
    service = DatabaseBackupService(root)
    active_before = _sha256(active_db)

    with pytest.raises(DatabaseBackupError):
        service.stage_migrated_copy(
            backup_id="BACKUP-S4-MIGRATE-INTERRUPT",
            state_id="STATE-S4-MIGRATE-INTERRUPT",
            job_id="JOB-S4-MIGRATE-INTERRUPT",
            minimum_free_bytes=0,
            failpoint=_fail_at(BackupFailurePoint.MIGRATE_AFTER_SCHEMA),
        )

    retry = service.stage_migrated_copy(
        backup_id="BACKUP-S4-MIGRATE-INTERRUPT",
        state_id="STATE-S4-MIGRATE-INTERRUPT",
        job_id="JOB-S4-MIGRATE-INTERRUPT",
        minimum_free_bytes=0,
    )
    assert retry.migrated_state.validation.schema_version == CURRENT_SCHEMA_VERSION
    assert _sha256(active_db) == active_before


def test_backup_service_rejects_path_ids_and_hardlinked_source(tmp_path: Path) -> None:
    root, db_path = _project_root(tmp_path)
    service = DatabaseBackupService(root)
    with pytest.raises(DatabaseBackupError) as captured:
        service.create_backup(
            backup_id="../ESCAPE",
            job_id="JOB-S4-ID",
            minimum_free_bytes=0,
        )
    assert captured.value.code is DatabaseBackupCode.INVALID_ID

    alias = db_path.with_name("hardlink.sqlite3")
    os.link(db_path, alias)
    try:
        with pytest.raises(DatabaseBackupError) as captured:
            service.create_backup(
                backup_id="BACKUP-S4-HARDLINK",
                job_id="JOB-S4-HARDLINK",
                minimum_free_bytes=0,
            )
        assert captured.value.code is DatabaseBackupCode.INVALID_PATH
    finally:
        alias.unlink()


def test_validate_database_rejects_business_path_traversal(tmp_path: Path) -> None:
    _root, db_path = _project_root(tmp_path)
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO source_papers (
                paper_code,
                title,
                source_path,
                meta_json
            ) VALUES ('TRAVERSAL', 'Traversal', '../outside.pdf', '{}')
            """
        )
        conn.commit()

    with pytest.raises(DatabaseBackupError) as captured:
        validate_database(db_path)
    assert captured.value.code is DatabaseBackupCode.DATABASE_INVALID
