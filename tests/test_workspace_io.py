from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

import pytest

from app.config import PROJECT_ROOT
from app.safety.workspace_io import (
    WorkspaceIOCode,
    WorkspaceIOError,
    get_workspace_io,
)


def test_workspace_io_creates_unicode_tree_and_idempotent_file(
    tmp_path: Path,
) -> None:
    workspace_io = get_workspace_io()
    target = tmp_path / "中文 空格" / "nested" / "receipt.json"
    payload = b'{"ok":true}\n'

    receipt = workspace_io.create_new_bytes(target, payload)
    repeated = workspace_io.write_bytes_idempotent(target, payload)

    assert target.read_bytes() == payload
    assert receipt.relative_path == target.relative_to(PROJECT_ROOT).as_posix()
    assert receipt.sha256 == hashlib.sha256(payload).hexdigest()
    assert receipt.idempotent is False
    assert repeated.idempotent is True
    assert repeated.sha256 == receipt.sha256


def test_workspace_io_refuses_conflicting_immutable_write(tmp_path: Path) -> None:
    workspace_io = get_workspace_io()
    target = tmp_path / "conflict.bin"
    workspace_io.create_new_bytes(target, b"first")

    with pytest.raises(WorkspaceIOError) as error:
        workspace_io.write_bytes_idempotent(target, b"second")

    assert error.value.code is WorkspaceIOCode.TARGET_CONFLICT
    assert target.read_bytes() == b"first"


def test_workspace_io_rejects_outside_path_without_side_effect() -> None:
    workspace_io = get_workspace_io()
    target = PROJECT_ROOT.parent / "M0-S6-outside-write-must-not-exist.bin"
    assert not target.exists()

    with pytest.raises(WorkspaceIOError) as error:
        workspace_io.create_new_bytes(target, b"forbidden")

    assert error.value.code is WorkspaceIOCode.PATH_REJECTED
    assert not target.exists()


def test_database_mutation_lease_pins_fresh_sqlite_file(tmp_path: Path) -> None:
    workspace_io = get_workspace_io()
    database_path = tmp_path / "数据库 空格" / "fresh.sqlite3"

    with workspace_io.database_mutation_lease(database_path) as leased_path:
        assert leased_path == database_path
        with sqlite3.connect(leased_path) as connection:
            connection.execute("CREATE TABLE sample (id INTEGER PRIMARY KEY)")
            connection.execute("INSERT INTO sample DEFAULT VALUES")

    with sqlite3.connect(
        f"file:{database_path.as_posix()}?mode=ro",
        uri=True,
    ) as connection:
        assert connection.execute("SELECT count(*) FROM sample").fetchone()[0] == 1


def test_workspace_io_moves_directory_without_replacement(tmp_path: Path) -> None:
    workspace_io = get_workspace_io()
    source = tmp_path / "staging" / "backup-0001"
    target = tmp_path / "published" / "backup-0001"
    source.mkdir(parents=True)
    target.parent.mkdir(parents=True)
    (source / "manifest.json").write_bytes(b'{"complete":true}\n')

    receipt = workspace_io.move_directory_no_replace(source, target)

    assert not source.exists()
    assert (target / "manifest.json").read_bytes() == b'{"complete":true}\n'
    assert receipt.operation == "MOVE_DIRECTORY_NO_REPLACE"
    assert receipt.capability_state == "HANDLE_BOUND_DIRECTORY_MOVE_V1"


def test_workspace_io_directory_move_refuses_existing_target(
    tmp_path: Path,
) -> None:
    workspace_io = get_workspace_io()
    source = tmp_path / "source"
    target = tmp_path / "target"
    source.mkdir()
    target.mkdir()
    (source / "source.txt").write_text("source", encoding="utf-8")
    (target / "target.txt").write_text("target", encoding="utf-8")

    with pytest.raises(WorkspaceIOError) as error:
        workspace_io.move_directory_no_replace(source, target)

    assert error.value.code is WorkspaceIOCode.TARGET_CONFLICT
    assert (source / "source.txt").read_text(encoding="utf-8") == "source"
    assert (target / "target.txt").read_text(encoding="utf-8") == "target"
