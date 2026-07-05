from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from .config import ensure_storage_directories, get_project_paths


SCHEMA_PATH = Path(__file__).with_name("schema.sql")


def connect_database(db_path: Path | None = None) -> sqlite3.Connection:
    path = db_path or get_project_paths(require_target_pdf=False).db_path
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def read_schema() -> str:
    return SCHEMA_PATH.read_text(encoding="utf-8")


def initialize_database(db_path: Path | None = None) -> dict[str, Any]:
    paths = ensure_storage_directories(require_target_pdf=False)
    resolved_db_path = db_path or paths.db_path
    resolved_db_path.parent.mkdir(parents=True, exist_ok=True)
    existed_before = resolved_db_path.exists()

    with connect_database(resolved_db_path) as conn:
        conn.executescript(read_schema())
        conn.commit()

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
    }


def list_schema_objects(db_path: Path | None = None) -> dict[str, list[str]]:
    with connect_database(db_path) as conn:
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
