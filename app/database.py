from __future__ import annotations

import os
import sqlite3
import stat
from contextlib import closing
from pathlib import Path
from typing import Any
from urllib.parse import quote

from .config import ensure_storage_directories, get_project_paths
from .database_migrations import (
    SCHEMA_PATH,
    inspect_migration_state,
    migrate_database,
)
from .safety.workspace_io import get_workspace_io


_REPARSE_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


class _ManagedConnection(sqlite3.Connection):
    """Commit/rollback like sqlite3, then release the Windows file handles."""

    _workspace_mutation_lease: Any = None

    def close(self) -> None:
        lease = self._workspace_mutation_lease
        self._workspace_mutation_lease = None
        try:
            super().close()
        finally:
            if lease is not None:
                lease.__exit__(None, None, None)

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: Any,
    ) -> bool:
        try:
            return bool(super().__exit__(exc_type, exc_value, traceback))
        finally:
            self.close()


def connect_database(db_path: Path | None = None) -> sqlite3.Connection:
    requested = (
        Path(db_path)
        if db_path is not None
        else get_project_paths(require_target_pdf=False).db_path
    )
    lease = get_workspace_io().database_mutation_lease(requested)
    path = lease.__enter__()
    conn: _ManagedConnection | None = None
    try:
        conn = sqlite3.connect(path, factory=_ManagedConnection)
        conn._workspace_mutation_lease = lease
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn
    except BaseException:
        if conn is None:
            lease.__exit__(None, None, None)
        else:
            conn.close()
        raise


def _read_only_uri(path: Path, *, immutable: bool) -> str:
    normalized = path.resolve(strict=True).as_posix()
    parameters = "mode=ro"
    if immutable:
        parameters += "&immutable=1"
    return f"file:{quote(normalized, safe='/:')}?{parameters}"


def _validate_read_only_database(path: Path) -> Path:
    if not path.is_absolute():
        raise FileNotFoundError("read-only database path must already be absolute")
    if not os.path.lexists(path):
        raise FileNotFoundError("read-only database file was not found")
    path = get_workspace_io().validate_read_file_path(path)
    identity = os.lstat(path)
    if (
        stat.S_ISLNK(identity.st_mode)
        or int(getattr(identity, "st_file_attributes", 0)) & _REPARSE_ATTRIBUTE
        or int(getattr(identity, "st_reparse_tag", 0))
        or not stat.S_ISREG(identity.st_mode)
        or int(identity.st_nlink) != 1
    ):
        raise OSError("read-only database must be a single-link regular file")
    return path


def connect_database_read_only(
    db_path: Path | None = None,
    *,
    immutable: bool = False,
) -> sqlite3.Connection:
    path = db_path or get_project_paths(require_target_pdf=False).db_path
    path = _validate_read_only_database(Path(path))
    conn = sqlite3.connect(
        _read_only_uri(path, immutable=immutable),
        uri=True,
        isolation_level=None,
        factory=_ManagedConnection,
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only = ON")
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def read_schema() -> str:
    return SCHEMA_PATH.read_text(encoding="utf-8").replace("\r\n", "\n").replace("\r", "\n")


def initialize_database(db_path: Path | None = None) -> dict[str, Any]:
    if db_path is None:
        paths = ensure_storage_directories(require_target_pdf=False)
        resolved_db_path = paths.db_path
    else:
        paths = get_project_paths(require_target_pdf=False)
        requested_db_path = Path(db_path)
        get_workspace_io().ensure_directory(requested_db_path.parent)
        resolved_db_path = (
            requested_db_path
            if requested_db_path.is_absolute()
            else get_workspace_io().project_root / requested_db_path
        )
    existed_before = resolved_db_path.exists()

    migration = migrate_database(resolved_db_path)

    return {
        "db_path": str(resolved_db_path),
        "created": not existed_before and resolved_db_path.exists(),
        "existed_before": existed_before,
        "assets": {
            "assets_dir": str(paths.assets_dir),
            "question_images_dir": str(paths.question_images_dir),
            "paper_pages_dir": str(paths.paper_pages_dir),
        },
        "db_backups": {
            "db_backups_dir": str(paths.db_backups_dir),
        },
        "exports": {
            "exports_dir": str(paths.exports_dir),
        },
        "migration": migration.to_dict(),
    }


def list_schema_objects(
    db_path: Path | None = None,
    *,
    read_only: bool = True,
) -> dict[str, list[str]]:
    connector = connect_database_read_only if read_only else connect_database
    with closing(connector(db_path)) as conn:
        rows = conn.execute(
            """
            SELECT type, name
              FROM sqlite_master
             WHERE name NOT LIKE 'sqlite_%'
             ORDER BY type, name
            """
        ).fetchall()

    result: dict[str, list[str]] = {"table": [], "index": [], "trigger": [], "view": []}
    for row in rows:
        result.setdefault(row["type"], []).append(row["name"])
    return result


def database_schema_state(db_path: Path | None = None) -> dict[str, Any]:
    with closing(connect_database_read_only(db_path)) as conn:
        return inspect_migration_state(conn).to_dict()
