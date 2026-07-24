from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import stat
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from .database import connect_database_read_only
from .database_migrations import (
    CURRENT_SCHEMA_VERSION,
    DatabaseMigrationError,
    inspect_migration_state,
    migrate_database,
)
from .project_root import ProjectRootError, inspect_project_root
from .safety.context import ContextError, validate_safe_id


BACKUP_MANIFEST_SCHEMA_VERSION = "1.0"
STATE_MANIFEST_SCHEMA_VERSION = "1.0"
BACKUP_SNAPSHOT_NAME = "database.sqlite3"
BACKUP_MANIFEST_NAME = "manifest.json"
STATE_DATABASE_NAME = "question_bank.sqlite3"
STATE_MANIFEST_NAME = "state-manifest.json"
MAX_MANIFEST_BYTES = 64 * 1024
MAX_DATABASE_BYTES = 16 * 1024 * 1024 * 1024
DEFAULT_MINIMUM_FREE_BYTES = 64 * 1024 * 1024
_REPARSE_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


class DatabaseBackupCode(StrEnum):
    INVALID_ROOT = "INVALID_ROOT"
    INVALID_ID = "INVALID_ID"
    INVALID_PATH = "INVALID_PATH"
    INSUFFICIENT_SPACE = "INSUFFICIENT_SPACE"
    SOURCE_INVALID = "SOURCE_INVALID"
    DATABASE_INVALID = "DATABASE_INVALID"
    MANIFEST_INVALID = "MANIFEST_INVALID"
    STAGING_CONFLICT = "STAGING_CONFLICT"
    PUBLISH_CONFLICT = "PUBLISH_CONFLICT"
    BACKUP_FAILED = "BACKUP_FAILED"
    RESTORE_FAILED = "RESTORE_FAILED"
    MIGRATION_FAILED = "MIGRATION_FAILED"


class BackupFailurePoint(StrEnum):
    AFTER_SNAPSHOT = "AFTER_SNAPSHOT"
    AFTER_MANIFEST = "AFTER_MANIFEST"
    AFTER_PUBLISH = "AFTER_PUBLISH"
    RESTORE_AFTER_DATABASE = "RESTORE_AFTER_DATABASE"
    RESTORE_AFTER_MANIFEST = "RESTORE_AFTER_MANIFEST"
    RESTORE_AFTER_PUBLISH = "RESTORE_AFTER_PUBLISH"
    MIGRATE_AFTER_RESCUE = "MIGRATE_AFTER_RESCUE"
    MIGRATE_AFTER_DATABASE_COPY = "MIGRATE_AFTER_DATABASE_COPY"
    MIGRATE_AFTER_SCHEMA = "MIGRATE_AFTER_SCHEMA"
    MIGRATE_AFTER_MANIFEST = "MIGRATE_AFTER_MANIFEST"
    MIGRATE_AFTER_PUBLISH = "MIGRATE_AFTER_PUBLISH"


class DatabaseBackupError(RuntimeError):
    def __init__(self, code: DatabaseBackupCode, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class DatabaseValidation:
    schema_version: int
    schema_fingerprint: str
    integrity_check: str
    foreign_key_violations: int
    business_invariant_violations: tuple[str, ...]
    page_count: int
    page_size: int

    @property
    def valid(self) -> bool:
        return (
            self.integrity_check == "ok"
            and self.foreign_key_violations == 0
            and not self.business_invariant_violations
        )

    def to_manifest_dict(self) -> dict[str, Any]:
        return {
            "business_invariant_violations": list(
                self.business_invariant_violations
            ),
            "foreign_key_violations": self.foreign_key_violations,
            "integrity_check": self.integrity_check,
            "page_count": self.page_count,
            "page_size": self.page_size,
            "schema_fingerprint": self.schema_fingerprint,
            "schema_version": self.schema_version,
            "valid": self.valid,
        }


@dataclass(frozen=True, slots=True)
class BackupReceipt:
    backup_id: str
    backup_relative_path: str
    snapshot_relative_path: str
    snapshot_sha256: str
    snapshot_bytes: int
    manifest_sha256: str
    validation: DatabaseValidation
    idempotent: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "backup_id": self.backup_id,
            "backup_relative_path": self.backup_relative_path,
            "snapshot_relative_path": self.snapshot_relative_path,
            "snapshot_sha256": self.snapshot_sha256,
            "snapshot_bytes": self.snapshot_bytes,
            "manifest_sha256": self.manifest_sha256,
            "validation": self.validation.to_manifest_dict(),
            "idempotent": self.idempotent,
        }


@dataclass(frozen=True, slots=True)
class StateReceipt:
    state_id: str
    state_kind: str
    state_relative_path: str
    database_relative_path: str
    database_sha256: str
    database_bytes: int
    manifest_sha256: str
    source_backup_id: str
    validation: DatabaseValidation
    idempotent: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "state_id": self.state_id,
            "state_kind": self.state_kind,
            "state_relative_path": self.state_relative_path,
            "database_relative_path": self.database_relative_path,
            "database_sha256": self.database_sha256,
            "database_bytes": self.database_bytes,
            "manifest_sha256": self.manifest_sha256,
            "source_backup_id": self.source_backup_id,
            "validation": self.validation.to_manifest_dict(),
            "idempotent": self.idempotent,
        }


@dataclass(frozen=True, slots=True)
class MigrationCopyReceipt:
    rescue_backup: BackupReceipt
    migrated_state: StateReceipt
    active_database_sha256_before: str
    active_database_sha256_after: str

    @property
    def active_database_unchanged(self) -> bool:
        return (
            self.active_database_sha256_before
            == self.active_database_sha256_after
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "rescue_backup": self.rescue_backup.to_dict(),
            "migrated_state": self.migrated_state.to_dict(),
            "active_database_sha256_before": self.active_database_sha256_before,
            "active_database_sha256_after": self.active_database_sha256_after,
            "active_database_unchanged": self.active_database_unchanged,
        }


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
    ).encode("utf-8")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                return digest.hexdigest()
            digest.update(chunk)


def _reject_reparse(path: Path, identity: os.stat_result) -> None:
    if (
        stat.S_ISLNK(identity.st_mode)
        or int(getattr(identity, "st_file_attributes", 0)) & _REPARSE_ATTRIBUTE
        or int(getattr(identity, "st_reparse_tag", 0))
    ):
        raise DatabaseBackupError(
            DatabaseBackupCode.INVALID_PATH,
            f"database operation path contains a reparse object: {path}",
        )


def _inspect_directory(path: Path) -> None:
    try:
        identity = os.lstat(path)
    except OSError as exc:
        raise DatabaseBackupError(
            DatabaseBackupCode.INVALID_PATH,
            "required database operation directory cannot be inspected",
        ) from exc
    _reject_reparse(path, identity)
    if not stat.S_ISDIR(identity.st_mode):
        raise DatabaseBackupError(
            DatabaseBackupCode.INVALID_PATH,
            "database operation path contains a non-directory component",
        )


def _inspect_regular_file(path: Path, *, maximum_bytes: int = MAX_DATABASE_BYTES) -> None:
    try:
        identity = os.lstat(path)
    except OSError as exc:
        raise DatabaseBackupError(
            DatabaseBackupCode.INVALID_PATH,
            "required database operation file cannot be inspected",
        ) from exc
    _reject_reparse(path, identity)
    if (
        not stat.S_ISREG(identity.st_mode)
        or int(identity.st_nlink) != 1
        or int(identity.st_size) < 1
        or int(identity.st_size) > maximum_bytes
    ):
        raise DatabaseBackupError(
            DatabaseBackupCode.INVALID_PATH,
            "database operation file must be a bounded single-link regular file",
        )


def _ensure_directory(parent: Path, name: str) -> Path:
    _inspect_directory(parent)
    child = parent / name
    if os.path.lexists(child):
        _inspect_directory(child)
    else:
        try:
            os.mkdir(child)
        except OSError as exc:
            raise DatabaseBackupError(
                DatabaseBackupCode.INVALID_PATH,
                "fixed database operation directory could not be created",
            ) from exc
        _inspect_directory(child)
    return child


def _write_exclusive(path: Path, payload: bytes) -> None:
    if len(payload) < 1 or len(payload) > MAX_MANIFEST_BYTES:
        raise DatabaseBackupError(
            DatabaseBackupCode.MANIFEST_INVALID,
            "manifest payload is outside its fixed size boundary",
        )
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
            0o600,
        )
    except OSError as exc:
        raise DatabaseBackupError(
            DatabaseBackupCode.STAGING_CONFLICT,
            "manifest target already exists or cannot be created exclusively",
        ) from exc
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise DatabaseBackupError(
                    DatabaseBackupCode.BACKUP_FAILED,
                    "manifest write made no progress",
                )
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _inspect_regular_file(path, maximum_bytes=MAX_MANIFEST_BYTES)
    if path.read_bytes() != payload:
        raise DatabaseBackupError(
            DatabaseBackupCode.MANIFEST_INVALID,
            "manifest readback differs from the staged payload",
        )


def _safe_relative_path(value: object, *, field_name: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise DatabaseBackupError(
            DatabaseBackupCode.MANIFEST_INVALID,
            f"{field_name} must be a non-empty relative path",
        )
    windows = PureWindowsPath(value)
    posix = PurePosixPath(value.replace("\\", "/"))
    if (
        windows.is_absolute()
        or bool(windows.drive)
        or posix.is_absolute()
        or any(part in {"", ".", ".."} for part in posix.parts)
        or "\\" in value
        or posix.as_posix() != value
    ):
        raise DatabaseBackupError(
            DatabaseBackupCode.MANIFEST_INVALID,
            f"{field_name} is not a canonical project-relative path",
        )
    return posix.as_posix()


def _validate_id(value: str, *, field_name: str) -> str:
    try:
        return validate_safe_id(value, field_name=field_name)
    except ContextError as exc:
        raise DatabaseBackupError(
            DatabaseBackupCode.INVALID_ID,
            f"{field_name} is not a canonical safe identifier",
        ) from exc


def _table_names(conn: sqlite3.Connection) -> set[str]:
    return {
        str(row[0])
        for row in conn.execute(
            """
            SELECT name
              FROM sqlite_schema
             WHERE type IN ('table', 'view')
               AND name NOT LIKE 'sqlite_%'
            """
        ).fetchall()
    }


def _column_names(conn: sqlite3.Connection, table: str) -> set[str]:
    escaped = table.replace('"', '""')
    return {
        str(row[1])
        for row in conn.execute(f'PRAGMA table_info("{escaped}")').fetchall()
    }


def _database_path_violations(conn: sqlite3.Connection) -> list[str]:
    configured = (
        ("source_papers", "source_path"),
        ("questions", "raw_crop_path"),
        ("question_assets", "relative_path"),
        ("source_paper_assets", "relative_path"),
        ("import_batches", "backup_path"),
    )
    tables = _table_names(conn)
    violations: list[str] = []
    for table, column in configured:
        if table not in tables or column not in _column_names(conn, table):
            continue
        escaped_table = table.replace('"', '""')
        escaped_column = column.replace('"', '""')
        rows = conn.execute(
            f'SELECT rowid, "{escaped_column}" FROM "{escaped_table}" '
            f'WHERE "{escaped_column}" IS NOT NULL'
        ).fetchall()
        for rowid, value in rows:
            try:
                _safe_relative_path(value, field_name=f"{table}.{column}")
            except DatabaseBackupError:
                violations.append(f"{table}.{column}:rowid={int(rowid)}")
                if len(violations) >= 100:
                    return violations
    return violations


def _business_invariant_violations(conn: sqlite3.Connection) -> tuple[str, ...]:
    tables = _table_names(conn)
    violations = _database_path_violations(conn)
    if {"questions", "question_search_content"}.issubset(tables):
        questions = int(conn.execute("SELECT count(*) FROM questions").fetchone()[0])
        search_content = int(
            conn.execute("SELECT count(*) FROM question_search_content").fetchone()[0]
        )
        if questions != search_content:
            violations.append(
                f"questions/search_content count mismatch:{questions}/{search_content}"
            )
    if {"question_search_content", "question_fts"}.issubset(tables):
        search_content = int(
            conn.execute("SELECT count(*) FROM question_search_content").fetchone()[0]
        )
        fts = int(conn.execute("SELECT count(*) FROM question_fts").fetchone()[0])
        if search_content != fts:
            violations.append(f"search_content/fts count mismatch:{search_content}/{fts}")
    return tuple(sorted(violations))


def validate_database(
    db_path: Path,
    *,
    require_current: bool = False,
) -> DatabaseValidation:
    path = Path(db_path)
    _inspect_regular_file(path)
    try:
        with closing(connect_database_read_only(path)) as conn:
            integrity_rows = [
                str(row[0]) for row in conn.execute("PRAGMA integrity_check").fetchall()
            ]
            integrity = "ok" if integrity_rows == ["ok"] else ";".join(integrity_rows[:20])
            foreign_key_violations = len(
                conn.execute("PRAGMA foreign_key_check").fetchall()
            )
            state = inspect_migration_state(conn)
            if require_current and state.schema_version != CURRENT_SCHEMA_VERSION:
                raise DatabaseBackupError(
                    DatabaseBackupCode.DATABASE_INVALID,
                    "database does not use the current published schema version",
                )
            business = _business_invariant_violations(conn)
            page_count = int(conn.execute("PRAGMA page_count").fetchone()[0])
            page_size = int(conn.execute("PRAGMA page_size").fetchone()[0])
    except DatabaseBackupError:
        raise
    except (DatabaseMigrationError, sqlite3.DatabaseError, OSError) as exc:
        raise DatabaseBackupError(
            DatabaseBackupCode.DATABASE_INVALID,
            "database validation could not complete",
        ) from exc
    validation = DatabaseValidation(
        schema_version=state.schema_version,
        schema_fingerprint=state.schema_fingerprint,
        integrity_check=integrity,
        foreign_key_violations=foreign_key_violations,
        business_invariant_violations=business,
        page_count=page_count,
        page_size=page_size,
    )
    if not validation.valid:
        raise DatabaseBackupError(
            DatabaseBackupCode.DATABASE_INVALID,
            "database failed integrity, foreign-key, or business-invariant validation",
        )
    return validation


def _sqlite_backup(
    source: Path,
    target: Path,
) -> None:
    if os.path.lexists(target):
        raise DatabaseBackupError(
            DatabaseBackupCode.STAGING_CONFLICT,
            "SQLite Backup API target already exists",
        )
    source_conn = connect_database_read_only(source)
    target_conn: sqlite3.Connection | None = None
    try:
        target_conn = sqlite3.connect(target)
        target_conn.execute("PRAGMA foreign_keys = ON")

        source_conn.backup(
            target_conn,
            pages=128,
            sleep=0.01,
        )
        target_conn.commit()
        journal_mode = str(
            target_conn.execute("PRAGMA journal_mode").fetchone()[0]
        ).lower()
        if journal_mode == "wal":
            checkpoint = target_conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
            if checkpoint is None or int(checkpoint[0]) != 0:
                raise DatabaseBackupError(
                    DatabaseBackupCode.BACKUP_FAILED,
                    "staged WAL snapshot could not be checkpointed",
                )
            journal_mode = str(
                target_conn.execute("PRAGMA journal_mode = DELETE").fetchone()[0]
            ).lower()
        if journal_mode != "delete":
            raise DatabaseBackupError(
                DatabaseBackupCode.BACKUP_FAILED,
                "staged database could not be normalized to a single-file snapshot",
            )
        target_conn.commit()
    except BaseException:
        if target_conn is not None and target_conn.in_transaction:
            target_conn.rollback()
        raise
    finally:
        if target_conn is not None:
            target_conn.close()
        source_conn.close()
    _inspect_regular_file(target)
    for suffix in ("-wal", "-shm", "-journal"):
        if os.path.lexists(Path(f"{target}{suffix}")):
            raise DatabaseBackupError(
                DatabaseBackupCode.BACKUP_FAILED,
                "SQLite left an undeclared sidecar beside the staged snapshot",
            )
    descriptor = os.open(target, os.O_RDWR | getattr(os, "O_BINARY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _call_failpoint(
    failpoint: BackupFailurePoint | None,
    point: BackupFailurePoint,
) -> None:
    if failpoint is point:
        if point.name.startswith("RESTORE_"):
            code = DatabaseBackupCode.RESTORE_FAILED
        elif point.name.startswith("MIGRATE_"):
            code = DatabaseBackupCode.MIGRATION_FAILED
        else:
            code = DatabaseBackupCode.BACKUP_FAILED
        raise DatabaseBackupError(
            code,
            f"injected database interruption at {point.value}",
        )


class DatabaseBackupService:
    """Fixed-root SQLite snapshot, staging restore, and migration-copy service."""

    def __init__(self, project_root: Path) -> None:
        try:
            contract = inspect_project_root(Path(project_root))
        except ProjectRootError as exc:
            raise DatabaseBackupError(
                DatabaseBackupCode.INVALID_ROOT,
                "database backup service requires a verified portable project root",
            ) from exc
        self._root = contract.root
        self._active_db = self._root / "data" / "db" / "question_bank.sqlite3"

    @property
    def project_root(self) -> Path:
        return self._root

    @property
    def active_database_path(self) -> Path:
        return self._active_db

    def _relative(self, path: Path) -> str:
        try:
            return path.relative_to(self._root).as_posix()
        except ValueError as exc:
            raise DatabaseBackupError(
                DatabaseBackupCode.INVALID_PATH,
                "database operation path escaped the verified project root",
            ) from exc

    def _fixed_parent(self, *parts: str) -> Path:
        current = self._root
        _inspect_directory(current)
        for part in parts:
            current = _ensure_directory(current, part)
        return current

    def _job_operation_root(self, job_id: str, operation: str) -> Path:
        job_id = _validate_id(job_id, field_name="job_id")
        operation_root = self._fixed_parent("tmp", "jobs", "INTERNAL", job_id)
        return _ensure_directory(operation_root, operation)

    def _space_preflight(self, *, minimum_free_bytes: int) -> None:
        if minimum_free_bytes < 0:
            raise DatabaseBackupError(
                DatabaseBackupCode.INSUFFICIENT_SPACE,
                "minimum free-space reserve cannot be negative",
            )
        source_bytes = 0
        for suffix in ("", "-wal", "-shm"):
            candidate = Path(f"{self._active_db}{suffix}")
            if os.path.lexists(candidate):
                _inspect_regular_file(candidate)
                source_bytes += int(os.lstat(candidate).st_size)
        required = max(
            int(minimum_free_bytes),
            min(MAX_DATABASE_BYTES, source_bytes * 2 + 1024 * 1024),
        )
        free = int(shutil.disk_usage(self._root).free)
        if free < required:
            raise DatabaseBackupError(
                DatabaseBackupCode.INSUFFICIENT_SPACE,
                "insufficient free space for a consistent database snapshot",
            )

    def _backup_manifest(
        self,
        *,
        backup_id: str,
        snapshot_path: Path,
        validation: DatabaseValidation,
    ) -> dict[str, Any]:
        return {
            "backup_id": backup_id,
            "created_at": datetime.now(UTC).isoformat(),
            "files": [
                {
                    "bytes": int(snapshot_path.stat().st_size),
                    "relative_path": BACKUP_SNAPSHOT_NAME,
                    "role": "SQLITE_BACKUP_API_SNAPSHOT",
                    "sha256": _sha256_file(snapshot_path),
                }
            ],
            "manifest_schema_version": BACKUP_MANIFEST_SCHEMA_VERSION,
            "source": {
                "relative_path": self._relative(self._active_db),
                "role": "ACTIVE_DATABASE",
                "schema_version": validation.schema_version,
            },
            "validation": validation.to_manifest_dict(),
        }

    def _backup_receipt(
        self,
        backup_root: Path,
        *,
        expected_backup_id: str,
        idempotent: bool,
    ) -> BackupReceipt:
        _inspect_directory(backup_root)
        names = {entry.name for entry in backup_root.iterdir()}
        if names != {BACKUP_SNAPSHOT_NAME, BACKUP_MANIFEST_NAME}:
            raise DatabaseBackupError(
                DatabaseBackupCode.MANIFEST_INVALID,
                "backup set contains missing or undeclared files",
            )
        manifest_path = backup_root / BACKUP_MANIFEST_NAME
        snapshot_path = backup_root / BACKUP_SNAPSHOT_NAME
        _inspect_regular_file(manifest_path, maximum_bytes=MAX_MANIFEST_BYTES)
        _inspect_regular_file(snapshot_path)
        payload = manifest_path.read_bytes()
        if len(payload) > MAX_MANIFEST_BYTES:
            raise DatabaseBackupError(
                DatabaseBackupCode.MANIFEST_INVALID,
                "backup manifest exceeds its size boundary",
            )
        try:
            manifest = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DatabaseBackupError(
                DatabaseBackupCode.MANIFEST_INVALID,
                "backup manifest is not canonical UTF-8 JSON",
            ) from exc
        if type(manifest) is not dict or payload != _canonical_json(manifest):
            raise DatabaseBackupError(
                DatabaseBackupCode.MANIFEST_INVALID,
                "backup manifest is not in canonical form",
            )
        if set(manifest) != {
            "backup_id",
            "created_at",
            "files",
            "manifest_schema_version",
            "source",
            "validation",
        }:
            raise DatabaseBackupError(
                DatabaseBackupCode.MANIFEST_INVALID,
                "backup manifest has an unexpected shape",
            )
        if (
            manifest["backup_id"] != expected_backup_id
            or manifest["manifest_schema_version"] != BACKUP_MANIFEST_SCHEMA_VERSION
        ):
            raise DatabaseBackupError(
                DatabaseBackupCode.MANIFEST_INVALID,
                "backup manifest identity or schema version differs",
            )
        try:
            created_at = datetime.fromisoformat(manifest["created_at"])
        except (TypeError, ValueError) as exc:
            raise DatabaseBackupError(
                DatabaseBackupCode.MANIFEST_INVALID,
                "backup manifest timestamp is invalid",
            ) from exc
        if created_at.tzinfo is None or created_at.utcoffset() is None:
            raise DatabaseBackupError(
                DatabaseBackupCode.MANIFEST_INVALID,
                "backup manifest timestamp has no timezone",
            )
        source = manifest["source"]
        if type(source) is not dict or set(source) != {
            "relative_path",
            "role",
            "schema_version",
        }:
            raise DatabaseBackupError(
                DatabaseBackupCode.MANIFEST_INVALID,
                "backup source descriptor has an unexpected shape",
            )
        if (
            _safe_relative_path(source["relative_path"], field_name="source.relative_path")
            != "data/db/question_bank.sqlite3"
            or source["role"] != "ACTIVE_DATABASE"
            or type(source["schema_version"]) is not int
        ):
            raise DatabaseBackupError(
                DatabaseBackupCode.MANIFEST_INVALID,
                "backup source descriptor is invalid",
            )
        files = manifest["files"]
        if type(files) is not list or len(files) != 1 or type(files[0]) is not dict:
            raise DatabaseBackupError(
                DatabaseBackupCode.MANIFEST_INVALID,
                "backup manifest must declare exactly one database snapshot",
            )
        file_row = files[0]
        if set(file_row) != {"bytes", "relative_path", "role", "sha256"}:
            raise DatabaseBackupError(
                DatabaseBackupCode.MANIFEST_INVALID,
                "backup snapshot descriptor has an unexpected shape",
            )
        if (
            _safe_relative_path(
                file_row["relative_path"],
                field_name="files[0].relative_path",
            )
            != BACKUP_SNAPSHOT_NAME
            or file_row["role"] != "SQLITE_BACKUP_API_SNAPSHOT"
            or type(file_row["bytes"]) is not int
            or file_row["bytes"] != snapshot_path.stat().st_size
            or not isinstance(file_row["sha256"], str)
            or file_row["sha256"] != _sha256_file(snapshot_path)
        ):
            raise DatabaseBackupError(
                DatabaseBackupCode.MANIFEST_INVALID,
                "backup snapshot bytes or hash differ from the manifest",
            )
        validation = validate_database(snapshot_path)
        if (
            manifest["validation"] != validation.to_manifest_dict()
            or source["schema_version"] != validation.schema_version
        ):
            raise DatabaseBackupError(
                DatabaseBackupCode.MANIFEST_INVALID,
                "backup validation evidence differs from the restored snapshot",
            )
        return BackupReceipt(
            backup_id=expected_backup_id,
            backup_relative_path=self._relative(backup_root),
            snapshot_relative_path=self._relative(snapshot_path),
            snapshot_sha256=file_row["sha256"],
            snapshot_bytes=file_row["bytes"],
            manifest_sha256=hashlib.sha256(payload).hexdigest(),
            validation=validation,
            idempotent=idempotent,
        )

    def create_backup(
        self,
        *,
        backup_id: str,
        job_id: str,
        minimum_free_bytes: int = DEFAULT_MINIMUM_FREE_BYTES,
        failpoint: BackupFailurePoint | None = None,
    ) -> BackupReceipt:
        backup_id = _validate_id(backup_id, field_name="backup_id")
        job_id = _validate_id(job_id, field_name="job_id")
        if failpoint is not None and not isinstance(failpoint, BackupFailurePoint):
            raise DatabaseBackupError(
                DatabaseBackupCode.BACKUP_FAILED,
                "failpoint must be a published BackupFailurePoint",
            )
        _inspect_regular_file(self._active_db)
        try:
            source_validation = validate_database(self._active_db)
        except DatabaseBackupError as exc:
            raise DatabaseBackupError(
                DatabaseBackupCode.SOURCE_INVALID,
                "active database cannot be used as a backup source",
            ) from exc

        backups_parent = self._fixed_parent("backups")
        final_root = backups_parent / backup_id
        if os.path.lexists(final_root):
            return self._backup_receipt(
                final_root,
                expected_backup_id=backup_id,
                idempotent=True,
            )
        self._space_preflight(minimum_free_bytes=minimum_free_bytes)
        stage_parent = self._job_operation_root(job_id, "backup")
        stage_root = _ensure_directory(stage_parent, backup_id)
        snapshot_path = stage_root / BACKUP_SNAPSHOT_NAME
        manifest_path = stage_root / BACKUP_MANIFEST_NAME

        if os.path.lexists(snapshot_path):
            validation = validate_database(snapshot_path)
        else:
            try:
                _sqlite_backup(self._active_db, snapshot_path)
                validation = validate_database(snapshot_path)
            except DatabaseBackupError:
                raise
            except BaseException as exc:
                raise DatabaseBackupError(
                    DatabaseBackupCode.BACKUP_FAILED,
                    "SQLite Backup API snapshot failed",
                ) from exc
        _call_failpoint(failpoint, BackupFailurePoint.AFTER_SNAPSHOT)

        expected_manifest = self._backup_manifest(
            backup_id=backup_id,
            snapshot_path=snapshot_path,
            validation=validation,
        )
        if os.path.lexists(manifest_path):
            _inspect_regular_file(
                manifest_path,
                maximum_bytes=MAX_MANIFEST_BYTES,
            )
            existing = manifest_path.read_bytes()
            try:
                parsed_existing = json.loads(existing.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise DatabaseBackupError(
                    DatabaseBackupCode.MANIFEST_INVALID,
                    "staged backup manifest is not valid UTF-8 JSON",
                ) from exc
            if (
                type(parsed_existing) is not dict
                or existing != _canonical_json(parsed_existing)
            ):
                raise DatabaseBackupError(
                    DatabaseBackupCode.MANIFEST_INVALID,
                    "staged backup manifest is not canonical",
                )
        else:
            _write_exclusive(manifest_path, _canonical_json(expected_manifest))
        staged_receipt = self._backup_receipt(
            stage_root,
            expected_backup_id=backup_id,
            idempotent=False,
        )
        if staged_receipt.validation.schema_fingerprint != source_validation.schema_fingerprint:
            raise DatabaseBackupError(
                DatabaseBackupCode.BACKUP_FAILED,
                "backup snapshot schema differs from the validated source",
            )
        _call_failpoint(failpoint, BackupFailurePoint.AFTER_MANIFEST)

        if os.path.lexists(final_root):
            raise DatabaseBackupError(
                DatabaseBackupCode.PUBLISH_CONFLICT,
                "backup target appeared before no-replace publication",
            )
        try:
            os.rename(stage_root, final_root)
        except OSError as exc:
            raise DatabaseBackupError(
                DatabaseBackupCode.PUBLISH_CONFLICT,
                "backup set could not be published without replacement",
            ) from exc
        _call_failpoint(failpoint, BackupFailurePoint.AFTER_PUBLISH)
        return self._backup_receipt(
            final_root,
            expected_backup_id=backup_id,
            idempotent=False,
        )

    def validate_backup(self, backup_id: str) -> BackupReceipt:
        backup_id = _validate_id(backup_id, field_name="backup_id")
        return self._backup_receipt(
            self._root / "backups" / backup_id,
            expected_backup_id=backup_id,
            idempotent=True,
        )

    def _state_manifest(
        self,
        *,
        state_id: str,
        state_kind: str,
        source_backup_id: str,
        database_path: Path,
        validation: DatabaseValidation,
        from_schema_version: int,
    ) -> dict[str, Any]:
        return {
            "created_at": datetime.now(UTC).isoformat(),
            "database": {
                "bytes": int(database_path.stat().st_size),
                "relative_path": STATE_DATABASE_NAME,
                "role": "RESTORED_SQLITE_STATE",
                "sha256": _sha256_file(database_path),
            },
            "from_schema_version": from_schema_version,
            "manifest_schema_version": STATE_MANIFEST_SCHEMA_VERSION,
            "source_backup_id": source_backup_id,
            "state_id": state_id,
            "state_kind": state_kind,
            "to_schema_version": validation.schema_version,
            "validation": validation.to_manifest_dict(),
        }

    def _state_receipt(
        self,
        state_root: Path,
        *,
        expected_state_id: str,
        expected_backup_id: str,
        expected_kind: str,
        idempotent: bool,
    ) -> StateReceipt:
        _inspect_directory(state_root)
        names = {entry.name for entry in state_root.iterdir()}
        if names != {STATE_DATABASE_NAME, STATE_MANIFEST_NAME}:
            raise DatabaseBackupError(
                DatabaseBackupCode.MANIFEST_INVALID,
                "database state contains missing or undeclared files",
            )
        database_path = state_root / STATE_DATABASE_NAME
        manifest_path = state_root / STATE_MANIFEST_NAME
        _inspect_regular_file(database_path)
        _inspect_regular_file(manifest_path, maximum_bytes=MAX_MANIFEST_BYTES)
        payload = manifest_path.read_bytes()
        try:
            manifest = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DatabaseBackupError(
                DatabaseBackupCode.MANIFEST_INVALID,
                "database state manifest is invalid JSON",
            ) from exc
        if type(manifest) is not dict or payload != _canonical_json(manifest):
            raise DatabaseBackupError(
                DatabaseBackupCode.MANIFEST_INVALID,
                "database state manifest is not canonical",
            )
        expected_keys = {
            "created_at",
            "database",
            "from_schema_version",
            "manifest_schema_version",
            "source_backup_id",
            "state_id",
            "state_kind",
            "to_schema_version",
            "validation",
        }
        if set(manifest) != expected_keys:
            raise DatabaseBackupError(
                DatabaseBackupCode.MANIFEST_INVALID,
                "database state manifest has an unexpected shape",
            )
        if (
            manifest["manifest_schema_version"] != STATE_MANIFEST_SCHEMA_VERSION
            or manifest["state_id"] != expected_state_id
            or manifest["source_backup_id"] != expected_backup_id
            or manifest["state_kind"] != expected_kind
            or type(manifest["from_schema_version"]) is not int
            or type(manifest["to_schema_version"]) is not int
        ):
            raise DatabaseBackupError(
                DatabaseBackupCode.MANIFEST_INVALID,
                "database state identity differs from the requested operation",
            )
        database = manifest["database"]
        if type(database) is not dict or set(database) != {
            "bytes",
            "relative_path",
            "role",
            "sha256",
        }:
            raise DatabaseBackupError(
                DatabaseBackupCode.MANIFEST_INVALID,
                "database state file descriptor has an unexpected shape",
            )
        if (
            _safe_relative_path(
                database["relative_path"],
                field_name="database.relative_path",
            )
            != STATE_DATABASE_NAME
            or database["role"] != "RESTORED_SQLITE_STATE"
            or type(database["bytes"]) is not int
            or database["bytes"] != database_path.stat().st_size
            or not isinstance(database["sha256"], str)
            or database["sha256"] != _sha256_file(database_path)
        ):
            raise DatabaseBackupError(
                DatabaseBackupCode.MANIFEST_INVALID,
                "database state bytes or hash differ from the manifest",
            )
        validation = validate_database(
            database_path,
            require_current=(expected_kind == "MIGRATED_COPY"),
        )
        if (
            manifest["validation"] != validation.to_manifest_dict()
            or manifest["to_schema_version"] != validation.schema_version
        ):
            raise DatabaseBackupError(
                DatabaseBackupCode.MANIFEST_INVALID,
                "database state validation evidence differs from the database",
            )
        return StateReceipt(
            state_id=expected_state_id,
            state_kind=expected_kind,
            state_relative_path=self._relative(state_root),
            database_relative_path=self._relative(database_path),
            database_sha256=database["sha256"],
            database_bytes=database["bytes"],
            manifest_sha256=hashlib.sha256(payload).hexdigest(),
            source_backup_id=expected_backup_id,
            validation=validation,
            idempotent=idempotent,
        )

    def _publish_state(
        self,
        *,
        stage_root: Path,
        state_id: str,
        source_backup_id: str,
        state_kind: str,
        idempotent: bool,
    ) -> StateReceipt:
        versions_parent = self._fixed_parent("data", "db", "versions")
        final_root = versions_parent / state_id
        if os.path.lexists(final_root):
            return self._state_receipt(
                final_root,
                expected_state_id=state_id,
                expected_backup_id=source_backup_id,
                expected_kind=state_kind,
                idempotent=True,
            )
        try:
            os.rename(stage_root, final_root)
        except OSError as exc:
            raise DatabaseBackupError(
                DatabaseBackupCode.PUBLISH_CONFLICT,
                "database state could not be published without replacement",
            ) from exc
        return self._state_receipt(
            final_root,
            expected_state_id=state_id,
            expected_backup_id=source_backup_id,
            expected_kind=state_kind,
            idempotent=idempotent,
        )

    def restore_backup(
        self,
        *,
        backup_id: str,
        state_id: str,
        job_id: str,
        failpoint: BackupFailurePoint | None = None,
    ) -> StateReceipt:
        backup_id = _validate_id(backup_id, field_name="backup_id")
        state_id = _validate_id(state_id, field_name="state_id")
        job_id = _validate_id(job_id, field_name="job_id")
        if failpoint is not None and not isinstance(failpoint, BackupFailurePoint):
            raise DatabaseBackupError(
                DatabaseBackupCode.RESTORE_FAILED,
                "failpoint must be a published BackupFailurePoint",
            )
        backup = self.validate_backup(backup_id)
        versions_parent = self._fixed_parent("data", "db", "versions")
        final_root = versions_parent / state_id
        if os.path.lexists(final_root):
            return self._state_receipt(
                final_root,
                expected_state_id=state_id,
                expected_backup_id=backup_id,
                expected_kind="RESTORED_BACKUP",
                idempotent=True,
            )
        stage_parent = self._job_operation_root(job_id, "restore")
        stage_root = _ensure_directory(stage_parent, state_id)
        database_path = stage_root / STATE_DATABASE_NAME
        if os.path.lexists(database_path):
            validation = validate_database(database_path)
        else:
            _sqlite_backup(
                self._root / backup.snapshot_relative_path,
                database_path,
            )
            validation = validate_database(database_path)
        _call_failpoint(failpoint, BackupFailurePoint.RESTORE_AFTER_DATABASE)
        manifest_path = stage_root / STATE_MANIFEST_NAME
        manifest = self._state_manifest(
            state_id=state_id,
            state_kind="RESTORED_BACKUP",
            source_backup_id=backup_id,
            database_path=database_path,
            validation=validation,
            from_schema_version=backup.validation.schema_version,
        )
        if not os.path.lexists(manifest_path):
            _write_exclusive(manifest_path, _canonical_json(manifest))
        self._state_receipt(
            stage_root,
            expected_state_id=state_id,
            expected_backup_id=backup_id,
            expected_kind="RESTORED_BACKUP",
            idempotent=False,
        )
        _call_failpoint(failpoint, BackupFailurePoint.RESTORE_AFTER_MANIFEST)
        receipt = self._publish_state(
            stage_root=stage_root,
            state_id=state_id,
            source_backup_id=backup_id,
            state_kind="RESTORED_BACKUP",
            idempotent=False,
        )
        _call_failpoint(failpoint, BackupFailurePoint.RESTORE_AFTER_PUBLISH)
        return receipt

    def stage_migrated_copy(
        self,
        *,
        backup_id: str,
        state_id: str,
        job_id: str,
        minimum_free_bytes: int = DEFAULT_MINIMUM_FREE_BYTES,
        failpoint: BackupFailurePoint | None = None,
    ) -> MigrationCopyReceipt:
        backup_id = _validate_id(backup_id, field_name="backup_id")
        state_id = _validate_id(state_id, field_name="state_id")
        job_id = _validate_id(job_id, field_name="job_id")
        if failpoint is not None and not isinstance(failpoint, BackupFailurePoint):
            raise DatabaseBackupError(
                DatabaseBackupCode.MIGRATION_FAILED,
                "failpoint must be a published BackupFailurePoint",
            )
        active_before = _sha256_file(self._active_db)
        rescue = self.create_backup(
            backup_id=backup_id,
            job_id=job_id,
            minimum_free_bytes=minimum_free_bytes,
        )
        _call_failpoint(failpoint, BackupFailurePoint.MIGRATE_AFTER_RESCUE)

        versions_parent = self._fixed_parent("data", "db", "versions")
        final_root = versions_parent / state_id
        if os.path.lexists(final_root):
            state = self._state_receipt(
                final_root,
                expected_state_id=state_id,
                expected_backup_id=backup_id,
                expected_kind="MIGRATED_COPY",
                idempotent=True,
            )
            active_after = _sha256_file(self._active_db)
            return MigrationCopyReceipt(rescue, state, active_before, active_after)

        stage_parent = self._job_operation_root(job_id, "migration")
        stage_root = _ensure_directory(stage_parent, state_id)
        database_path = stage_root / STATE_DATABASE_NAME
        if not os.path.lexists(database_path):
            _sqlite_backup(
                self._root / rescue.snapshot_relative_path,
                database_path,
            )
        validate_database(database_path)
        _call_failpoint(failpoint, BackupFailurePoint.MIGRATE_AFTER_DATABASE_COPY)
        try:
            migrate_database(database_path, execution_id=job_id)
        except DatabaseMigrationError as exc:
            raise DatabaseBackupError(
                DatabaseBackupCode.MIGRATION_FAILED,
                "staged database migration failed",
            ) from exc
        validation = validate_database(database_path, require_current=True)
        _call_failpoint(failpoint, BackupFailurePoint.MIGRATE_AFTER_SCHEMA)
        manifest_path = stage_root / STATE_MANIFEST_NAME
        manifest = self._state_manifest(
            state_id=state_id,
            state_kind="MIGRATED_COPY",
            source_backup_id=backup_id,
            database_path=database_path,
            validation=validation,
            from_schema_version=rescue.validation.schema_version,
        )
        if not os.path.lexists(manifest_path):
            _write_exclusive(manifest_path, _canonical_json(manifest))
        self._state_receipt(
            stage_root,
            expected_state_id=state_id,
            expected_backup_id=backup_id,
            expected_kind="MIGRATED_COPY",
            idempotent=False,
        )
        _call_failpoint(failpoint, BackupFailurePoint.MIGRATE_AFTER_MANIFEST)
        state = self._publish_state(
            stage_root=stage_root,
            state_id=state_id,
            source_backup_id=backup_id,
            state_kind="MIGRATED_COPY",
            idempotent=False,
        )
        _call_failpoint(failpoint, BackupFailurePoint.MIGRATE_AFTER_PUBLISH)
        active_after = _sha256_file(self._active_db)
        if active_before != active_after:
            raise DatabaseBackupError(
                DatabaseBackupCode.MIGRATION_FAILED,
                "active database changed while migration was confined to its staged copy",
            )
        return MigrationCopyReceipt(rescue, state, active_before, active_after)
