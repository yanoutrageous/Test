from __future__ import annotations

import hashlib
import os
import re
import sqlite3
import stat
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from functools import lru_cache
from pathlib import Path
from typing import Any


SCHEMA_PATH = Path(__file__).with_name("schema.sql")
CURRENT_SCHEMA_VERSION = 1
MIGRATION_ID = "0001_INITIAL_LEGACY_BASELINE"
MIGRATION_COMPATIBILITY = "LEGACY_MONOLITHIC_SCHEMA_TO_V1"
MIGRATION_SQL_SHA256 = (
    "ee853feec02eda2b1c221f98b916c699469bb999fce96792caf4b1769028ac96"
)
_SAFE_EXECUTION_ID = re.compile(r"^[A-Z0-9](?:[A-Z0-9_-]{0,126}[A-Z0-9])?$")
_REPARSE_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)

_MIGRATION_TABLE_SQL = """
CREATE TABLE schema_migrations (
    version             INTEGER PRIMARY KEY,
    migration_id        TEXT NOT NULL UNIQUE,
    sql_sha256          TEXT NOT NULL,
    compatibility       TEXT NOT NULL,
    execution_id        TEXT NOT NULL,
    applied_at          TEXT NOT NULL,
    CHECK (version > 0),
    CHECK (length(sql_sha256) = 64)
)
""".strip()


class DatabaseMigrationCode(StrEnum):
    INVALID_PATH = "INVALID_PATH"
    CATALOG_TAMPERED = "CATALOG_TAMPERED"
    UNSUPPORTED_SCHEMA = "UNSUPPORTED_SCHEMA"
    SCHEMA_DIVERGED = "SCHEMA_DIVERGED"
    HISTORY_DIVERGED = "HISTORY_DIVERGED"
    MIGRATION_FAILED = "MIGRATION_FAILED"


class MigrationFailurePoint(StrEnum):
    BEFORE_BEGIN = "BEFORE_BEGIN"
    AFTER_SCHEMA = "AFTER_SCHEMA"
    AFTER_RECORD = "AFTER_RECORD"
    BEFORE_COMMIT = "BEFORE_COMMIT"
    AFTER_COMMIT = "AFTER_COMMIT"


class DatabaseMigrationError(RuntimeError):
    def __init__(self, code: DatabaseMigrationCode, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class MigrationState:
    schema_version: int
    current_schema_version: int
    legacy_compatible: bool
    applied_migrations: tuple[str, ...]
    schema_fingerprint: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "current_schema_version": self.current_schema_version,
            "legacy_compatible": self.legacy_compatible,
            "applied_migrations": list(self.applied_migrations),
            "schema_fingerprint": self.schema_fingerprint,
        }


@dataclass(frozen=True, slots=True)
class MigrationResult:
    db_path: str
    from_version: int
    to_version: int
    applied: bool
    migration_id: str | None
    state: MigrationState

    def to_dict(self) -> dict[str, Any]:
        return {
            "db_path": self.db_path,
            "from_version": self.from_version,
            "to_version": self.to_version,
            "applied": self.applied,
            "migration_id": self.migration_id,
            "state": self.state.to_dict(),
        }


def _normalized_utf8(payload: bytes) -> bytes:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DatabaseMigrationError(
            DatabaseMigrationCode.CATALOG_TAMPERED,
            "migration SQL is not valid UTF-8",
        ) from exc
    return text.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")


def read_migration_sql() -> str:
    payload = SCHEMA_PATH.read_bytes()
    normalized = _normalized_utf8(payload)
    observed = hashlib.sha256(normalized).hexdigest()
    if observed != MIGRATION_SQL_SHA256:
        raise DatabaseMigrationError(
            DatabaseMigrationCode.CATALOG_TAMPERED,
            "published migration SQL checksum differs from the append-only catalog",
        )
    return normalized.decode("utf-8")


def _validate_execution_id(execution_id: str) -> str:
    if not isinstance(execution_id, str) or _SAFE_EXECUTION_ID.fullmatch(execution_id) is None:
        raise DatabaseMigrationError(
            DatabaseMigrationCode.MIGRATION_FAILED,
            "execution_id must use 1-128 canonical uppercase ASCII characters",
        )
    return execution_id


def _reject_reparse(path: Path, identity: os.stat_result) -> None:
    if (
        stat.S_ISLNK(identity.st_mode)
        or int(getattr(identity, "st_file_attributes", 0)) & _REPARSE_ATTRIBUTE
        or int(getattr(identity, "st_reparse_tag", 0))
    ):
        raise DatabaseMigrationError(
            DatabaseMigrationCode.INVALID_PATH,
            f"database path chain contains a reparse object: {path}",
        )


def _validate_database_path(path: Path, *, must_exist: bool) -> Path:
    if not path.is_absolute():
        raise DatabaseMigrationError(
            DatabaseMigrationCode.INVALID_PATH,
            "database path must already be absolute",
        )
    if not path.parent.exists() or not path.parent.is_dir():
        raise DatabaseMigrationError(
            DatabaseMigrationCode.INVALID_PATH,
            "database parent directory must already exist",
        )
    for component in (*reversed(path.parent.parents), path.parent):
        try:
            identity = os.lstat(component)
        except OSError as exc:
            raise DatabaseMigrationError(
                DatabaseMigrationCode.INVALID_PATH,
                "database parent path cannot be inspected",
            ) from exc
        _reject_reparse(component, identity)
        if not stat.S_ISDIR(identity.st_mode):
            raise DatabaseMigrationError(
                DatabaseMigrationCode.INVALID_PATH,
                "database parent path contains a non-directory component",
            )

    if os.path.lexists(path):
        try:
            identity = os.lstat(path)
        except OSError as exc:
            raise DatabaseMigrationError(
                DatabaseMigrationCode.INVALID_PATH,
                "database file cannot be inspected",
            ) from exc
        _reject_reparse(path, identity)
        if not stat.S_ISREG(identity.st_mode) or int(identity.st_nlink) != 1:
            raise DatabaseMigrationError(
                DatabaseMigrationCode.INVALID_PATH,
                "database must be a single-link regular file",
            )
    elif must_exist:
        raise DatabaseMigrationError(
            DatabaseMigrationCode.INVALID_PATH,
            "database file does not exist",
        )
    return path


def _iter_sql_statements(script: str) -> Iterator[str]:
    buffer: list[str] = []
    for line in script.splitlines(keepends=True):
        buffer.append(line)
        candidate = "".join(buffer)
        if sqlite3.complete_statement(candidate):
            statement = candidate.strip()
            if statement:
                yield statement
            buffer.clear()
    remainder = "".join(buffer).strip()
    if remainder:
        raise DatabaseMigrationError(
            DatabaseMigrationCode.CATALOG_TAMPERED,
            "migration SQL ends with an incomplete statement",
        )


def _normalize_schema_sql(sql: str) -> str:
    return " ".join(sql.rstrip().rstrip(";").split())


def _schema_objects(conn: sqlite3.Connection) -> dict[tuple[str, str], str]:
    rows = conn.execute(
        """
        SELECT type, name, sql
          FROM sqlite_schema
         WHERE name NOT LIKE 'sqlite_%'
           AND sql IS NOT NULL
         ORDER BY type, name
        """
    ).fetchall()
    return {
        (str(row[0]), str(row[1])): _normalize_schema_sql(str(row[2]))
        for row in rows
    }


def _schema_fingerprint(objects: dict[tuple[str, str], str]) -> str:
    canonical = "\n".join(
        f"{kind}\0{name}\0{objects[(kind, name)]}"
        for kind, name in sorted(objects)
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


@lru_cache(maxsize=1)
def _expected_base_objects() -> dict[tuple[str, str], str]:
    sql = read_migration_sql()
    conn = sqlite3.connect(":memory:")
    try:
        conn.executescript(sql)
        return _schema_objects(conn)
    finally:
        conn.close()


@lru_cache(maxsize=1)
def _expected_current_objects() -> dict[tuple[str, str], str]:
    conn = sqlite3.connect(":memory:")
    try:
        conn.executescript(read_migration_sql())
        conn.execute(_MIGRATION_TABLE_SQL)
        return _schema_objects(conn)
    finally:
        conn.close()


def _require_legacy_compatible(actual: dict[tuple[str, str], str]) -> None:
    expected = _expected_base_objects()
    unexpected = sorted(set(actual) - set(expected))
    changed = sorted(
        key for key in set(actual) & set(expected) if actual[key] != expected[key]
    )
    if unexpected or changed:
        raise DatabaseMigrationError(
            DatabaseMigrationCode.SCHEMA_DIVERGED,
            "legacy schema contains unknown or changed objects and cannot be adopted safely",
        )


def _require_current_schema(actual: dict[tuple[str, str], str]) -> None:
    expected = _expected_current_objects()
    if actual != expected:
        raise DatabaseMigrationError(
            DatabaseMigrationCode.SCHEMA_DIVERGED,
            "versioned database schema differs from the published migration catalog",
        )


def _has_object(
    objects: dict[tuple[str, str], str],
    *,
    kind: str,
    name: str,
) -> bool:
    return (kind, name) in objects


def inspect_migration_state(conn: sqlite3.Connection) -> MigrationState:
    version = int(conn.execute("PRAGMA user_version").fetchone()[0])
    objects = _schema_objects(conn)
    has_history = _has_object(objects, kind="table", name="schema_migrations")

    if version == 0 and not has_history:
        _require_legacy_compatible(objects)
        return MigrationState(
            schema_version=0,
            current_schema_version=CURRENT_SCHEMA_VERSION,
            legacy_compatible=True,
            applied_migrations=(),
            schema_fingerprint=_schema_fingerprint(objects),
        )
    if version != CURRENT_SCHEMA_VERSION:
        raise DatabaseMigrationError(
            DatabaseMigrationCode.UNSUPPORTED_SCHEMA,
            f"database schema version {version} is not supported",
        )
    if not has_history:
        raise DatabaseMigrationError(
            DatabaseMigrationCode.HISTORY_DIVERGED,
            "database user_version is set but migration history is missing",
        )

    rows = conn.execute(
        """
        SELECT version, migration_id, sql_sha256, compatibility
          FROM schema_migrations
         ORDER BY version
        """
    ).fetchall()
    expected = [
        (
            CURRENT_SCHEMA_VERSION,
            MIGRATION_ID,
            MIGRATION_SQL_SHA256,
            MIGRATION_COMPATIBILITY,
        )
    ]
    observed = [tuple(row) for row in rows]
    if observed != expected:
        raise DatabaseMigrationError(
            DatabaseMigrationCode.HISTORY_DIVERGED,
            "database migration history differs from the append-only catalog",
        )
    _require_current_schema(objects)
    return MigrationState(
        schema_version=version,
        current_schema_version=CURRENT_SCHEMA_VERSION,
        legacy_compatible=False,
        applied_migrations=(MIGRATION_ID,),
        schema_fingerprint=_schema_fingerprint(objects),
    )


def _call_failpoint(
    failpoint: MigrationFailurePoint | None,
    point: MigrationFailurePoint,
) -> None:
    if failpoint is point:
        raise DatabaseMigrationError(
            DatabaseMigrationCode.MIGRATION_FAILED,
            f"injected migration interruption at {point.value}",
        )


def migrate_database(
    db_path: Path,
    *,
    execution_id: str = "INITIALIZE",
    failpoint: MigrationFailurePoint | None = None,
) -> MigrationResult:
    sql = read_migration_sql()
    execution_id = _validate_execution_id(execution_id)
    if failpoint is not None and not isinstance(failpoint, MigrationFailurePoint):
        raise DatabaseMigrationError(
            DatabaseMigrationCode.MIGRATION_FAILED,
            "failpoint must be a published MigrationFailurePoint",
        )
    path = _validate_database_path(Path(db_path), must_exist=False)

    conn = sqlite3.connect(path, isolation_level=None)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        before = inspect_migration_state(conn)
        if before.schema_version == CURRENT_SCHEMA_VERSION:
            return MigrationResult(
                db_path=str(path),
                from_version=before.schema_version,
                to_version=before.schema_version,
                applied=False,
                migration_id=None,
                state=before,
            )

        _call_failpoint(failpoint, MigrationFailurePoint.BEFORE_BEGIN)
        try:
            conn.execute("BEGIN IMMEDIATE")
            for statement in _iter_sql_statements(sql):
                conn.execute(statement)
            _call_failpoint(failpoint, MigrationFailurePoint.AFTER_SCHEMA)
            conn.execute(_MIGRATION_TABLE_SQL)
            conn.execute(
                """
                INSERT INTO schema_migrations (
                    version,
                    migration_id,
                    sql_sha256,
                    compatibility,
                    execution_id,
                    applied_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    CURRENT_SCHEMA_VERSION,
                    MIGRATION_ID,
                    MIGRATION_SQL_SHA256,
                    MIGRATION_COMPATIBILITY,
                    execution_id,
                    datetime.now(UTC).isoformat(),
                ),
            )
            _call_failpoint(failpoint, MigrationFailurePoint.AFTER_RECORD)
            conn.execute(f"PRAGMA user_version = {CURRENT_SCHEMA_VERSION}")
            _call_failpoint(failpoint, MigrationFailurePoint.BEFORE_COMMIT)
            conn.commit()
            _call_failpoint(failpoint, MigrationFailurePoint.AFTER_COMMIT)
        except BaseException:
            if conn.in_transaction:
                conn.rollback()
            raise

        after = inspect_migration_state(conn)
        return MigrationResult(
            db_path=str(path),
            from_version=before.schema_version,
            to_version=after.schema_version,
            applied=True,
            migration_id=MIGRATION_ID,
            state=after,
        )
    except DatabaseMigrationError:
        raise
    except BaseException:
        raise
    finally:
        conn.close()
        if path.exists():
            _validate_database_path(path, must_exist=True)
