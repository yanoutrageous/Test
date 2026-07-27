from __future__ import annotations

import argparse
import hashlib
import json
import ntpath
import os
import stat
import sys
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

from app.project_root import PROJECT_ROOT as VERIFIED_PROJECT_ROOT
from app.safety.static_audit import (
    CONTROL_BINDING_CONTRACT,
    CONTROL_BINDING_RELATIVE_PATH,
    CONTROL_BINDING_SCHEMA_VERSION,
    SCANNER_VERSION,
    MigrationStatus,
    WritePrimitiveKind,
    _canonical_sha256,
    _pretty_json_bytes,
    recommended_control_binding,
    scan_production_unbound_entries,
    scan_production_write_entries,
)


REPARSE_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


class ControlBindingBuildStop(RuntimeError):
    pass


def _absolute_lexical(path: str | os.PathLike[str]) -> Path:
    return Path(ntpath.normpath(ntpath.abspath(os.fspath(path))))


def _same_path(left: Path, right: Path) -> bool:
    return ntpath.normcase(str(left)) == ntpath.normcase(str(right))


def _relative_parts(candidate: Path, root: Path) -> tuple[str, ...] | None:
    candidate_parts = PureWindowsPath(str(candidate)).parts
    root_parts = PureWindowsPath(str(root)).parts
    if len(candidate_parts) < len(root_parts):
        return None
    for actual, expected in zip(candidate_parts, root_parts, strict=False):
        if ntpath.normcase(actual) != ntpath.normcase(expected):
            return None
    return tuple(candidate_parts[len(root_parts) :])


def _verify_existing_chain(path: Path) -> None:
    for component in (*reversed(path.parents), path):
        try:
            identity = os.lstat(component)
        except OSError as exc:
            raise ControlBindingBuildStop(
                "required binding path cannot be inspected"
            ) from exc
        if (
            stat.S_ISLNK(identity.st_mode)
            or int(getattr(identity, "st_file_attributes", 0)) & REPARSE_ATTRIBUTE
            or int(getattr(identity, "st_reparse_tag", 0))
        ):
            raise ControlBindingBuildStop(
                "binding path chain contains a reparse object"
            )
        if stat.S_ISREG(identity.st_mode) and int(identity.st_nlink) != 1:
            raise ControlBindingBuildStop(
                "binding path chain contains a hardlinked file"
            )


def _row_for_entry(entry: Any) -> dict[str, str]:
    if (
        entry.control_binding_id is not None
        or entry.migration_status is not MigrationStatus.UNMIGRATED_BLOCKED
    ):
        raise ControlBindingBuildStop("raw inventory unexpectedly contains a binding")
    recommendation = recommended_control_binding(entry)
    if recommendation is None:
        raise ControlBindingBuildStop(
            f"no fixed control is eligible for {entry.entry_id}"
        )
    control_id, migration_status = recommendation
    if (
        entry.kind is WritePrimitiveKind.UNKNOWN_DYNAMIC_CAPABILITY
        or migration_status is MigrationStatus.UNMIGRATED_BLOCKED
    ):
        raise ControlBindingBuildStop(
            f"entry {entry.entry_id} is not eligible for publication"
        )
    return {
        "control_id": control_id,
        "entry_id": entry.entry_id,
        "file": entry.file,
        "kind": entry.kind.value,
        "migration_status": migration_status.value,
        "source_sha256": entry.source_sha256,
        "statement_fingerprint": entry.statement_fingerprint,
    }


def _build_payload() -> dict[str, Any]:
    entries = scan_production_unbound_entries()
    if not entries:
        raise ControlBindingBuildStop("raw inventory is empty")
    rows = [_row_for_entry(entry) for entry in entries]
    entry_ids = [row["entry_id"] for row in rows]
    if len(set(entry_ids)) != len(entry_ids):
        raise ControlBindingBuildStop("raw inventory contains duplicate entry IDs")
    return {
        "binding_contract": CONTROL_BINDING_CONTRACT,
        "binding_count": len(rows),
        "bindings": rows,
        "bindings_digest_sha256": _canonical_sha256(rows),
        "scanner_version": SCANNER_VERSION,
        "schema_version": CONTROL_BINDING_SCHEMA_VERSION,
    }


def _write_exclusive(path: Path, payload: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
        0o600,
    )
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise ControlBindingBuildStop("binding write made no progress")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _verify_existing_chain(path)
    if path.read_bytes() != payload:
        raise ControlBindingBuildStop("binding readback differs from generated bytes")


def _validate_existing_contract(path: Path) -> None:
    _verify_existing_chain(path)
    data = path.read_bytes()
    if not data or len(data) > 2 * 1024 * 1024:
        raise ControlBindingBuildStop(
            "existing binding contract has invalid bytes"
        )
    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ControlBindingBuildStop(
            "existing binding contract is not UTF-8 JSON"
        ) from exc
    expected_keys = {
        "binding_contract",
        "binding_count",
        "bindings",
        "bindings_digest_sha256",
        "scanner_version",
        "schema_version",
    }
    rows = payload.get("bindings") if type(payload) is dict else None
    if (
        type(payload) is not dict
        or set(payload) != expected_keys
        or payload["binding_contract"] != CONTROL_BINDING_CONTRACT
        or payload["schema_version"] != CONTROL_BINDING_SCHEMA_VERSION
        or type(rows) is not list
        or type(payload["binding_count"]) is not int
        or payload["binding_count"] != len(rows)
        or payload["bindings_digest_sha256"] != _canonical_sha256(rows)
    ):
        raise ControlBindingBuildStop(
            "existing binding contract failed integrity validation"
        )


def _publish(path: Path, payload: bytes, *, replace_existing: bool) -> None:
    if not os.path.lexists(path):
        if replace_existing:
            raise ControlBindingBuildStop(
                "replacement was requested but the binding target is absent"
            )
        _write_exclusive(path, payload)
        return
    if not replace_existing:
        raise ControlBindingBuildStop(
            "binding target already exists; use --replace after an audited source change"
        )
    _validate_existing_contract(path)
    staged = path.with_name(path.name + ".next")
    if os.path.lexists(staged):
        raise ControlBindingBuildStop("binding replacement staging file exists")
    _write_exclusive(staged, payload)
    os.replace(staged, path)
    _verify_existing_chain(path)
    if path.read_bytes() != payload:
        raise ControlBindingBuildStop(
            "replaced binding readback differs from generated bytes"
        )


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build the exact tracked M0 write-control binding contract.",
    )
    parser.add_argument(
        "--replace",
        action="store_true",
        help="Replace one validated existing contract after an audited source change.",
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    project_root = _absolute_lexical(Path(__file__).parents[2])
    expected_root = _absolute_lexical(VERIFIED_PROJECT_ROOT)
    if not _same_path(project_root, expected_root):
        raise ControlBindingBuildStop(
            "binding tool is outside the contracted project root"
        )
    if not _same_path(_absolute_lexical(Path.cwd()), project_root):
        raise ControlBindingBuildStop(
            "binding tool cwd must be the contracted project root"
        )
    expected_python = project_root / ".venv" / "Scripts" / "python.exe"
    if not _same_path(_absolute_lexical(sys.executable), expected_python):
        raise ControlBindingBuildStop(
            "binding tool requires the project virtual environment"
        )
    _verify_existing_chain(project_root)

    target = project_root / CONTROL_BINDING_RELATIVE_PATH
    expected_parts = tuple(CONTROL_BINDING_RELATIVE_PATH.parts)
    if _relative_parts(target, project_root) != expected_parts:
        raise ControlBindingBuildStop("binding target escaped its fixed namespace")
    _verify_existing_chain(target.parent)

    payload = _build_payload()
    serialized = _pretty_json_bytes(payload)
    if len(serialized) > 2 * 1024 * 1024:
        raise ControlBindingBuildStop("binding contract exceeds its fixed size limit")
    _publish(target, serialized, replace_existing=args.replace)

    applied = scan_production_write_entries()
    if (
        len(applied) != payload["binding_count"]
        or any(entry.control_binding_id is None for entry in applied)
        or any(
            entry.migration_status is MigrationStatus.UNMIGRATED_BLOCKED
            for entry in applied
        )
    ):
        raise ControlBindingBuildStop(
            "published binding contract did not bind the complete inventory"
        )
    result = {
        "binding_count": payload["binding_count"],
        "bindings_digest_sha256": payload["bindings_digest_sha256"],
        "file_sha256": hashlib.sha256(serialized).hexdigest(),
        "path": CONTROL_BINDING_RELATIVE_PATH.as_posix(),
        "scanner_version": SCANNER_VERSION,
        "status": "PUBLISHED_AND_RESCANNED",
    }
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ControlBindingBuildStop as exc:
        raise SystemExit(f"CONTROL_BINDING_BUILD_STOP: {exc}") from None
