from __future__ import annotations

import hashlib
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

import app.database_migrations as migrations
from app.database import (
    connect_database_read_only,
    database_schema_state,
    initialize_database,
    read_schema,
)
from app.database_migrations import (
    CURRENT_SCHEMA_VERSION,
    DatabaseMigrationCode,
    DatabaseMigrationError,
    MIGRATION_ID,
    MIGRATION_SQL_SHA256,
    MigrationFailurePoint,
    migrate_database,
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _legacy_database(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as conn:
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
            ("LEGACY-PAPER", "Legacy paper", "Base/legacy.pdf", "{}"),
        )
        conn.commit()
    assert database_schema_state(path)["schema_version"] == 0


def test_published_migration_checksum_uses_checkout_independent_utf8_lf() -> None:
    raw = migrations.SCHEMA_PATH.read_bytes()
    normalized = (
        raw.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")
    )
    assert hashlib.sha256(normalized).hexdigest() == MIGRATION_SQL_SHA256


def test_fresh_database_initialization_records_append_only_version(tmp_path: Path) -> None:
    path = (tmp_path / "fresh" / "question_bank.sqlite3").resolve()

    first = initialize_database(path)
    second = initialize_database(path)
    state = database_schema_state(path)

    assert first["migration"]["from_version"] == 0
    assert first["migration"]["to_version"] == CURRENT_SCHEMA_VERSION
    assert first["migration"]["applied"] is True
    assert second["migration"]["applied"] is False
    assert state["schema_version"] == CURRENT_SCHEMA_VERSION
    assert state["applied_migrations"] == [MIGRATION_ID]
    with connect_database_read_only(path) as conn:
        row = conn.execute(
            """
            SELECT version, migration_id, sql_sha256, compatibility
              FROM schema_migrations
            """
        ).fetchone()
        assert tuple(row) == (
            CURRENT_SCHEMA_VERSION,
            MIGRATION_ID,
            MIGRATION_SQL_SHA256,
            migrations.MIGRATION_COMPATIBILITY,
        )


def test_read_only_connection_does_not_create_or_mutate_database(tmp_path: Path) -> None:
    path = (tmp_path / "read-only" / "question_bank.sqlite3").resolve()
    initialize_database(path)
    before_hash = _sha256(path)
    before_names = sorted(item.name for item in path.parent.iterdir())

    with connect_database_read_only(path, immutable=True) as conn:
        assert conn.execute("PRAGMA query_only").fetchone()[0] == 1
        assert conn.execute("SELECT count(*) FROM source_papers").fetchone()[0] == 0
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            conn.execute(
                "INSERT INTO source_papers "
                "(paper_code, title, source_path) VALUES ('X', 'X', 'Base/x.pdf')"
            )

    assert _sha256(path) == before_hash
    assert sorted(item.name for item in path.parent.iterdir()) == before_names
    missing = (tmp_path / "read-only" / "missing.sqlite3").resolve()
    with pytest.raises(FileNotFoundError):
        connect_database_read_only(missing)
    assert not missing.exists()


def test_legacy_schema_and_data_migrate_forward_without_loss(tmp_path: Path) -> None:
    path = (tmp_path / "legacy" / "question_bank.sqlite3").resolve()
    _legacy_database(path)
    before = _sha256(path)

    result = migrate_database(path, execution_id="M0-S4-LEGACY")

    assert result.from_version == 0
    assert result.to_version == CURRENT_SCHEMA_VERSION
    assert result.applied is True
    assert _sha256(path) != before
    with connect_database_read_only(path) as conn:
        assert conn.execute(
            "SELECT paper_code FROM source_papers"
        ).fetchone()[0] == "LEGACY-PAPER"
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert conn.execute("PRAGMA foreign_key_check").fetchall() == []


@pytest.mark.parametrize(
    "point",
    (
        MigrationFailurePoint.AFTER_SCHEMA,
        MigrationFailurePoint.AFTER_RECORD,
        MigrationFailurePoint.BEFORE_COMMIT,
    ),
)
def test_interrupted_transaction_rolls_back_and_retry_is_idempotent(
    tmp_path: Path,
    point: MigrationFailurePoint,
) -> None:
    path = (tmp_path / point.value / "question_bank.sqlite3").resolve()
    path.parent.mkdir(parents=True)

    with pytest.raises(DatabaseMigrationError, match=point.value) as captured:
        migrate_database(path, execution_id="M0-S4-INTERRUPT", failpoint=point)
    assert captured.value.code is DatabaseMigrationCode.MIGRATION_FAILED

    with sqlite3.connect(path) as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 0
        assert conn.execute(
            "SELECT count(*) FROM sqlite_schema WHERE name = 'schema_migrations'"
        ).fetchone()[0] == 0

    retry = migrate_database(path, execution_id="M0-S4-RETRY")
    assert retry.applied is True
    assert database_schema_state(path)["schema_version"] == CURRENT_SCHEMA_VERSION


def test_failure_after_commit_reconciles_as_one_applied_migration(tmp_path: Path) -> None:
    path = (tmp_path / "after-commit" / "question_bank.sqlite3").resolve()
    path.parent.mkdir(parents=True)

    with pytest.raises(DatabaseMigrationError, match="AFTER_COMMIT"):
        migrate_database(
            path,
            execution_id="M0-S4-AFTER-COMMIT",
            failpoint=MigrationFailurePoint.AFTER_COMMIT,
        )

    retry = migrate_database(path, execution_id="M0-S4-RECONCILE")
    assert retry.applied is False
    with connect_database_read_only(path) as conn:
        assert conn.execute("SELECT count(*) FROM schema_migrations").fetchone()[0] == 1


@pytest.mark.parametrize(
    "point",
    (
        MigrationFailurePoint.AFTER_SCHEMA,
        MigrationFailurePoint.AFTER_RECORD,
        MigrationFailurePoint.BEFORE_COMMIT,
    ),
)
def test_real_process_migration_crash_recovers_transaction_once(
    tmp_path: Path,
    point: MigrationFailurePoint,
) -> None:
    path = (tmp_path / f"real-{point.value}" / "question_bank.sqlite3").resolve()
    path.parent.mkdir(parents=True)
    child_code = r"""
import os
import sys
from pathlib import Path
import app.database_migrations as migration_module
from app.database_migrations import MigrationFailurePoint, migrate_database

expected = sys.argv[2]
exit_code = int(sys.argv[3])

def crash(configured, observed):
    if configured is observed and observed.value == expected:
        os._exit(exit_code)

migration_module._call_failpoint = crash
migrate_database(
    Path(sys.argv[1]),
    execution_id="M0-S4-REAL-CRASH",
    failpoint=MigrationFailurePoint(expected),
)
raise AssertionError("configured migration crash point did not terminate the child")
"""
    completed = subprocess.run(
        [
            sys.executable,
            "-B",
            "-c",
            child_code,
            str(path),
            point.value,
            "81",
        ],
        cwd=Path(__file__).parent.parent,
        env=os.environ.copy(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=30,
    )
    assert completed.returncode == 81

    retry = migrate_database(path, execution_id="M0-S4-REAL-RECOVER")
    assert retry.applied is True
    with connect_database_read_only(path) as conn:
        assert conn.execute("SELECT count(*) FROM schema_migrations").fetchone()[0] == 1
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"


def test_unknown_legacy_schema_is_rejected_without_mutation(tmp_path: Path) -> None:
    path = (tmp_path / "diverged" / "question_bank.sqlite3").resolve()
    path.parent.mkdir(parents=True)
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE rogue_object (id INTEGER PRIMARY KEY)")
        conn.commit()
    before = _sha256(path)

    with pytest.raises(DatabaseMigrationError) as captured:
        migrate_database(path, execution_id="M0-S4-DIVERGED")

    assert captured.value.code is DatabaseMigrationCode.SCHEMA_DIVERGED
    assert _sha256(path) == before


def test_tampered_migration_history_and_future_versions_fail_closed(
    tmp_path: Path,
) -> None:
    history = (tmp_path / "history" / "question_bank.sqlite3").resolve()
    initialize_database(history)
    with sqlite3.connect(history) as conn:
        conn.execute(
            "UPDATE schema_migrations SET sql_sha256 = ?",
            ("0" * 64,),
        )
        conn.commit()
    with pytest.raises(DatabaseMigrationError) as captured:
        migrate_database(history, execution_id="M0-S4-HISTORY")
    assert captured.value.code is DatabaseMigrationCode.HISTORY_DIVERGED

    future = (tmp_path / "future" / "question_bank.sqlite3").resolve()
    initialize_database(future)
    with sqlite3.connect(future) as conn:
        conn.execute("PRAGMA user_version = 999")
    with pytest.raises(DatabaseMigrationError) as captured:
        migrate_database(future, execution_id="M0-S4-FUTURE")
    assert captured.value.code is DatabaseMigrationCode.UNSUPPORTED_SCHEMA


def test_catalog_checksum_tamper_is_rejected_before_database_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = (tmp_path / "catalog" / "question_bank.sqlite3").resolve()
    path.parent.mkdir(parents=True)
    monkeypatch.setattr(migrations, "MIGRATION_SQL_SHA256", "0" * 64)

    with pytest.raises(DatabaseMigrationError) as captured:
        migrate_database(path, execution_id="M0-S4-CATALOG")

    assert captured.value.code is DatabaseMigrationCode.CATALOG_TAMPERED
    assert not path.exists()


def test_migration_rejects_hardlinked_database(tmp_path: Path) -> None:
    path = (tmp_path / "hardlink" / "question_bank.sqlite3").resolve()
    initialize_database(path)
    alias = path.with_name("alias.sqlite3")
    os.link(path, alias)
    try:
        with pytest.raises(DatabaseMigrationError) as captured:
            migrate_database(path, execution_id="M0-S4-HARDLINK")
        assert captured.value.code is DatabaseMigrationCode.INVALID_PATH
    finally:
        alias.unlink()
