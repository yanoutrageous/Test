from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sqlite3
import stat
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Callable, Iterable

from flask import Flask, Response, jsonify, render_template_string, request, send_file

from .database import connect_database_read_only
from .database_backup import (
    DatabaseBackupError,
    _sqlite_backup,
    validate_database,
)
from .m3_pipeline import (
    M3PipelineConfig,
    M3PipelineError,
    M3WorkbenchState,
    _verify_m3_root,
    create_m3_app,
)
from .project_root import PROJECT_ROOT, ProjectRootError, inspect_project_root
from .safety.context import ContextError, validate_safe_id
from .safety.workspace_io import WorkspaceIOError, get_workspace_io


M4_PIPELINE_VERSION = "M4-BACKUP-RESTORE-ACTIVATION-V1"
M4_MANIFEST_SCHEMA_VERSION = "1.0"
M4_STATE_SCHEMA_VERSION = "1.0"
M4_POINTER_SCHEMA_VERSION = "1.0"
M4_GATE_SCHEMA_VERSION = "1.0"
M4_FIXED_TIMESTAMP = "2026-07-25T00:00:00Z"
M4_MAX_MANIFEST_BYTES = 8 * 1024 * 1024
M4_MAX_FILE_BYTES = 128 * 1024 * 1024
M4_MAX_LOGICAL_BYTES = 2 * 1024 * 1024 * 1024
M4_MAX_FILE_COUNT = 4096
M4_MAX_TREE_DEPTH = 32
M4_MAX_BACKUP_CHAIN = 8
M4_DEFAULT_RESERVE_BYTES = 256 * 1024 * 1024
M4_CHUNK_BYTES = 1024 * 1024

M4_ACCEPTED_M1_STATE_ID = "STATE-M1-YANYAN-REV-002"
M4_ACCEPTED_M2_EXPORT_ID = "EXPORT-M2-YANYAN-FULL-150-REV-002"
M4_ACCEPTED_M3_STATE_ID = "STATE-M3-YANYAN-REV-002"
M4_ACCEPTED_TAXONOMY_ID = "TAXONOMY-M3-MATH-V1"
M4_ACCEPTED_TEMPLATE_ID = "TEMPLATE-M3-B5-REV-002"

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_WINDOWS_RESERVED_RE = re.compile(
    r"^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$",
    re.IGNORECASE,
)
_REPARSE_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


class M4Code(StrEnum):
    INVALID_ROOT = "INVALID_ROOT"
    INVALID_ID = "INVALID_ID"
    INVALID_PATH = "INVALID_PATH"
    RESOURCE_LIMIT = "RESOURCE_LIMIT"
    INSUFFICIENT_SPACE = "INSUFFICIENT_SPACE"
    SOURCE_INVALID = "SOURCE_INVALID"
    MANIFEST_INVALID = "MANIFEST_INVALID"
    BACKUP_INVALID = "BACKUP_INVALID"
    BACKUP_FAILED = "BACKUP_FAILED"
    RESTORE_FAILED = "RESTORE_FAILED"
    ACTIVATION_DENIED = "ACTIVATION_DENIED"
    ACTIVATION_FAILED = "ACTIVATION_FAILED"
    CANCELLED = "CANCELLED"
    CONFLICT = "CONFLICT"


class M4FailurePoint(StrEnum):
    BACKUP_AFTER_BLOBS = "BACKUP_AFTER_BLOBS"
    BACKUP_AFTER_MANIFEST = "BACKUP_AFTER_MANIFEST"
    BACKUP_AFTER_PUBLISH = "BACKUP_AFTER_PUBLISH"
    RESTORE_AFTER_FILES = "RESTORE_AFTER_FILES"
    RESTORE_AFTER_MANIFEST = "RESTORE_AFTER_MANIFEST"
    RESTORE_AFTER_PUBLISH = "RESTORE_AFTER_PUBLISH"
    ACTIVATE_AFTER_RESCUE = "ACTIVATE_AFTER_RESCUE"
    ACTIVATE_AFTER_SWITCH = "ACTIVATE_AFTER_SWITCH"


class M4Error(RuntimeError):
    def __init__(self, code: M4Code, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"{code.value}: {message}")


class M4Cancelled(M4Error):
    def __init__(self, message: str = "M4 job was cancelled at a safe checkpoint") -> None:
        super().__init__(M4Code.CANCELLED, message)


@dataclass(frozen=True, slots=True)
class M4RuntimeLayout:
    database_path: str = (
        "data/db/versions/STATE-M1-YANYAN-REV-002/question_bank.sqlite3"
    )
    source_copy_root: str = "Copy/source"
    m1_derived_root: str = (
        "data/derived/papers/M1-REAL-PIPELINE/"
        "PAPER-YANYAN-202605/REV-002"
    )
    m2_export_root: str = (
        "data/exports/M2/EXPORT-M2-YANYAN-FULL-150-REV-002"
    )
    m3_state_root: str = "data/derived/M3/STATE-M3-YANYAN-REV-002"
    templates_root: str = "data/templates"
    audit_head_path: str = "state/audit-head.json"

    def __post_init__(self) -> None:
        for field_name, value in self.to_dict().items():
            _safe_relative_path(value, field_name=f"runtime_layout.{field_name}")

    def to_dict(self) -> dict[str, str]:
        return {
            "audit_head_path": self.audit_head_path,
            "database_path": self.database_path,
            "m1_derived_root": self.m1_derived_root,
            "m2_export_root": self.m2_export_root,
            "m3_state_root": self.m3_state_root,
            "source_copy_root": self.source_copy_root,
            "templates_root": self.templates_root,
        }

    @classmethod
    def from_dict(cls, payload: object) -> M4RuntimeLayout:
        if type(payload) is not dict or set(payload) != {
            "audit_head_path",
            "database_path",
            "m1_derived_root",
            "m2_export_root",
            "m3_state_root",
            "source_copy_root",
            "templates_root",
        }:
            raise M4Error(
                M4Code.MANIFEST_INVALID,
                "runtime layout has an unexpected shape",
            )
        return M4RuntimeLayout(
            audit_head_path=str(payload["audit_head_path"]),
            database_path=str(payload["database_path"]),
            m1_derived_root=str(payload["m1_derived_root"]),
            m2_export_root=str(payload["m2_export_root"]),
            m3_state_root=str(payload["m3_state_root"]),
            source_copy_root=str(payload["source_copy_root"]),
            templates_root=str(payload["templates_root"]),
        )


@dataclass(frozen=True, slots=True)
class M4RuntimeDescriptor:
    active_state_id: str
    source_root_relative: str
    layout: M4RuntimeLayout
    source_backup_id: str | None = None
    state_manifest_sha256: str | None = None
    generation: int = 0

    def __post_init__(self) -> None:
        _safe_id(self.active_state_id, field_name="active_state_id")
        _safe_source_root(self.source_root_relative)
        if self.source_backup_id is not None:
            _safe_id(self.source_backup_id, field_name="source_backup_id")
        if self.state_manifest_sha256 is not None:
            _sha256_value(
                self.state_manifest_sha256,
                field_name="state_manifest_sha256",
            )
        if type(self.generation) is not int or self.generation < 0:
            raise M4Error(
                M4Code.MANIFEST_INVALID,
                "active-state generation must be a non-negative integer",
            )

    def source_root(self, project_root: Path = PROJECT_ROOT) -> Path:
        if self.source_root_relative == ".":
            return project_root
        return project_root.joinpath(
            *PurePosixPath(self.source_root_relative).parts
        )

    def resolve(self, logical_path: str, project_root: Path = PROJECT_ROOT) -> Path:
        canonical = _safe_relative_path(logical_path, field_name="logical_path")
        return self.source_root(project_root).joinpath(
            *PurePosixPath(canonical).parts
        )

    def to_pointer_payload(
        self,
        *,
        activated_at: str,
        activation_gate_sha256: str,
        rescue_backup_id: str,
        predecessor: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "activated_at": activated_at,
            "activation_gate_sha256": activation_gate_sha256,
            "active_state_id": self.active_state_id,
            "generation": self.generation,
            "layout": self.layout.to_dict(),
            "pointer_schema_version": M4_POINTER_SCHEMA_VERSION,
            "predecessor": predecessor,
            "rescue_backup_id": rescue_backup_id,
            "source_backup_id": self.source_backup_id,
            "source_root_relative": self.source_root_relative,
            "state_manifest_sha256": self.state_manifest_sha256,
            "status": "ACTIVE",
        }


@dataclass(frozen=True, slots=True)
class M4BackupReceipt:
    backup_id: str
    backup_kind: str
    parent_backup_id: str | None
    file_count: int
    logical_bytes: int
    stored_blob_count: int
    stored_bytes: int
    reused_file_count: int
    manifest_sha256: str
    database_sha256: str
    validation_status: str
    idempotent: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "backup_id": self.backup_id,
            "backup_kind": self.backup_kind,
            "database_sha256": self.database_sha256,
            "file_count": self.file_count,
            "idempotent": self.idempotent,
            "logical_bytes": self.logical_bytes,
            "manifest_sha256": self.manifest_sha256,
            "parent_backup_id": self.parent_backup_id,
            "reused_file_count": self.reused_file_count,
            "stored_blob_count": self.stored_blob_count,
            "stored_bytes": self.stored_bytes,
            "validation_status": self.validation_status,
        }


@dataclass(frozen=True, slots=True)
class M4RestoreReceipt:
    state_id: str
    source_backup_id: str
    state_relative_path: str
    file_count: int
    logical_bytes: int
    state_manifest_sha256: str
    activation_gate_sha256: str
    verification_sha256: str
    journey_count: int
    idempotent: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "activation_gate_sha256": self.activation_gate_sha256,
            "file_count": self.file_count,
            "idempotent": self.idempotent,
            "journey_count": self.journey_count,
            "logical_bytes": self.logical_bytes,
            "source_backup_id": self.source_backup_id,
            "state_id": self.state_id,
            "state_manifest_sha256": self.state_manifest_sha256,
            "state_relative_path": self.state_relative_path,
            "verification_sha256": self.verification_sha256,
        }


def _canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            indent=2,
            sort_keys=True,
            separators=(",", ": "),
        )
        + "\n"
    ).encode("utf-8")


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(M4_CHUNK_BYTES)
            if not chunk:
                return digest.hexdigest()
            digest.update(chunk)


def _sha256_value(value: object, *, field_name: str) -> str:
    if type(value) is not str or not _SHA256_RE.fullmatch(value):
        raise M4Error(
            M4Code.MANIFEST_INVALID,
            f"{field_name} must be a lowercase SHA-256 digest",
        )
    return value


def _safe_id(value: object, *, field_name: str) -> str:
    if type(value) is not str:
        raise M4Error(
            M4Code.INVALID_ID,
            f"{field_name} must be a canonical identifier",
        )
    try:
        return validate_safe_id(value, field_name=field_name)
    except ContextError as exc:
        raise M4Error(
            M4Code.INVALID_ID,
            f"{field_name} must be a canonical identifier",
        ) from exc


def _safe_relative_path(value: object, *, field_name: str) -> str:
    if type(value) is not str or not value or "\x00" in value:
        raise M4Error(
            M4Code.INVALID_PATH,
            f"{field_name} must be a non-empty project-relative path",
        )
    windows = PureWindowsPath(value)
    posix = PurePosixPath(value)
    if (
        windows.is_absolute()
        or bool(windows.drive)
        or posix.is_absolute()
        or "\\" in value
        or ":" in value
        or posix.as_posix() != value
        or len(posix.parts) > M4_MAX_TREE_DEPTH
        or any(part in {"", ".", ".."} for part in posix.parts)
    ):
        raise M4Error(
            M4Code.INVALID_PATH,
            f"{field_name} is not a canonical safe relative path",
        )
    for part in posix.parts:
        name_root = part.split(".", 1)[0]
        if (
            part.endswith((" ", "."))
            or len(part.encode("utf-8")) > 240
            or _WINDOWS_RESERVED_RE.fullmatch(name_root) is not None
        ):
            raise M4Error(
                M4Code.INVALID_PATH,
                f"{field_name} contains an unsafe Windows path component",
            )
    return posix.as_posix()


def _safe_source_root(value: object) -> str:
    if value == ".":
        return "."
    canonical = _safe_relative_path(value, field_name="source_root_relative")
    parts = PurePosixPath(canonical).parts
    if (
        len(parts) >= 4
        and (
            parts[:2] == ("data", "snapshots")
            or parts[:3] == ("tmp", "jobs", "INTERNAL")
        )
    ):
        return canonical
    raise M4Error(
        M4Code.INVALID_PATH,
        "runtime source root must be a restored snapshot or INTERNAL staging root",
    )


def _relative_to_project(path: Path, project_root: Path = PROJECT_ROOT) -> str:
    try:
        relative = path.resolve().relative_to(project_root.resolve())
    except ValueError as exc:
        raise M4Error(
            M4Code.INVALID_PATH,
            "M4 path escaped the verified project root",
        ) from exc
    if relative == Path("."):
        return "."
    return _safe_relative_path(relative.as_posix(), field_name="project_relative_path")


def _is_reparse(identity: os.stat_result) -> bool:
    return bool(
        stat.S_ISLNK(identity.st_mode)
        or int(getattr(identity, "st_file_attributes", 0)) & _REPARSE_ATTRIBUTE
        or int(getattr(identity, "st_reparse_tag", 0))
    )


def _inspect_directory(path: Path) -> os.stat_result:
    try:
        identity = os.lstat(path)
    except OSError as exc:
        raise M4Error(
            M4Code.INVALID_PATH,
            "required M4 directory is missing or cannot be inspected",
        ) from exc
    if _is_reparse(identity) or not stat.S_ISDIR(identity.st_mode):
        raise M4Error(
            M4Code.INVALID_PATH,
            "M4 directory path contains a link, reparse object, or non-directory",
        )
    return identity


def _inspect_file(
    path: Path,
    *,
    maximum_bytes: int = M4_MAX_FILE_BYTES,
    allow_empty: bool = True,
) -> os.stat_result:
    try:
        identity = os.lstat(path)
    except OSError as exc:
        raise M4Error(
            M4Code.INVALID_PATH,
            "required M4 file is missing or cannot be inspected",
        ) from exc
    if (
        _is_reparse(identity)
        or not stat.S_ISREG(identity.st_mode)
        or int(identity.st_nlink) != 1
        or int(identity.st_size) > maximum_bytes
        or (not allow_empty and int(identity.st_size) < 1)
    ):
        raise M4Error(
            M4Code.INVALID_PATH,
            "M4 file must be a bounded single-link regular file",
        )
    return identity


def _read_bounded(
    path: Path,
    *,
    maximum_bytes: int = M4_MAX_FILE_BYTES,
    allow_empty: bool = True,
) -> bytes:
    before = _inspect_file(
        path,
        maximum_bytes=maximum_bytes,
        allow_empty=allow_empty,
    )
    payload = path.read_bytes()
    after = _inspect_file(
        path,
        maximum_bytes=maximum_bytes,
        allow_empty=allow_empty,
    )
    if (
        int(before.st_dev) != int(after.st_dev)
        or int(before.st_ino) != int(after.st_ino)
        or int(before.st_size) != int(after.st_size)
        or len(payload) != int(after.st_size)
    ):
        raise M4Error(
            M4Code.SOURCE_INVALID,
            "M4 source identity or size changed during its bounded read",
        )
    return payload


def _read_json(
    path: Path,
    *,
    maximum_bytes: int = M4_MAX_MANIFEST_BYTES,
) -> tuple[dict[str, Any], bytes]:
    payload = _read_bounded(
        path,
        maximum_bytes=maximum_bytes,
        allow_empty=False,
    )
    try:
        document = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise M4Error(
            M4Code.MANIFEST_INVALID,
            "M4 JSON document is not valid UTF-8 JSON",
        ) from exc
    if type(document) is not dict or payload != _canonical_json_bytes(document):
        raise M4Error(
            M4Code.MANIFEST_INVALID,
            "M4 JSON document is not in canonical form",
        )
    return document, payload


def _ensure_directory(path: Path) -> Path:
    try:
        created = get_workspace_io().ensure_directory(path)
    except WorkspaceIOError as exc:
        raise M4Error(
            M4Code.INVALID_PATH,
            "M4 directory could not be created inside the fixed workspace",
        ) from exc
    _inspect_directory(created)
    return created


def _write_new_or_same(path: Path, payload: bytes) -> dict[str, Any]:
    if len(payload) > M4_MAX_FILE_BYTES:
        raise M4Error(
            M4Code.RESOURCE_LIMIT,
            "M4 payload exceeds the single-file boundary",
        )
    try:
        receipt = get_workspace_io().write_bytes_idempotent(path, payload)
    except WorkspaceIOError as exc:
        raise M4Error(
            M4Code.CONFLICT,
            "M4 immutable output already exists with different bytes",
        ) from exc
    return {
        "bytes": receipt.size_bytes,
        "relative_path": receipt.relative_path,
        "sha256": receipt.sha256,
        "idempotent": receipt.idempotent,
    }


def _walk_regular_files(root: Path) -> list[tuple[Path, str]]:
    _inspect_directory(root)
    rows: list[tuple[Path, str]] = []
    stack: list[tuple[Path, PurePosixPath]] = [(root, PurePosixPath("."))]
    while stack:
        directory, prefix = stack.pop()
        _inspect_directory(directory)
        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError as exc:
            raise M4Error(
                M4Code.INVALID_PATH,
                "M4 source tree could not be enumerated",
            ) from exc
        for entry in reversed(entries):
            name = _safe_relative_path(entry.name, field_name="source_component")
            relative = PurePosixPath(name) if prefix == PurePosixPath(".") else prefix / name
            if len(relative.parts) > M4_MAX_TREE_DEPTH:
                raise M4Error(
                    M4Code.RESOURCE_LIMIT,
                    "M4 source tree exceeds the maximum depth",
                )
            path = Path(entry.path)
            identity = os.lstat(path)
            if _is_reparse(identity):
                raise M4Error(
                    M4Code.INVALID_PATH,
                    "M4 source tree contains a link or reparse object",
                )
            if stat.S_ISDIR(identity.st_mode):
                stack.append((path, relative))
            elif stat.S_ISREG(identity.st_mode):
                _inspect_file(path)
                rows.append((path, relative.as_posix()))
            else:
                raise M4Error(
                    M4Code.INVALID_PATH,
                    "M4 source tree contains a non-regular filesystem object",
                )
            if len(rows) > M4_MAX_FILE_COUNT:
                raise M4Error(
                    M4Code.RESOURCE_LIMIT,
                    "M4 source tree exceeds the maximum file count",
                )
    return sorted(rows, key=lambda item: item[1])


def _call_failpoint(
    selected: M4FailurePoint | None,
    point: M4FailurePoint,
) -> None:
    if selected is point:
        if point.name.startswith("BACKUP_"):
            code = M4Code.BACKUP_FAILED
        elif point.name.startswith("RESTORE_"):
            code = M4Code.RESTORE_FAILED
        else:
            code = M4Code.ACTIVATION_FAILED
        raise M4Error(code, f"injected M4 interruption at {point.value}")


def _emit_progress(
    callback: Callable[[dict[str, Any]], None] | None,
    payload: dict[str, Any],
) -> None:
    """Emit one in-memory progress snapshot through the caller callback."""

    if callback is not None:
        callback(payload)


def _validate_timestamp(value: object, *, field_name: str) -> str:
    if type(value) is not str:
        raise M4Error(
            M4Code.MANIFEST_INVALID,
            f"{field_name} must be a timezone-aware timestamp",
        )
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise M4Error(
            M4Code.MANIFEST_INVALID,
            f"{field_name} is not a valid timestamp",
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise M4Error(
            M4Code.MANIFEST_INVALID,
            f"{field_name} must include a timezone",
        )
    return value


def _role_for_path(logical_path: str) -> str:
    if logical_path.endswith("/question_bank.sqlite3"):
        return "SQLITE_BACKUP_API_SNAPSHOT"
    if logical_path.startswith("Copy/source/"):
        return (
            "PROJECT_ORIGINAL_PROVENANCE"
            if logical_path.endswith("/provenance.json")
            else "PROJECT_ORIGINAL_COPY"
        )
    if logical_path.startswith("data/derived/papers/"):
        return "APPROVED_M1_DERIVED_ASSET"
    if logical_path.startswith("data/derived/M3/"):
        if "/taxonomy/" in logical_path:
            return "APPROVED_TAXONOMY"
        if "/templates/" in logical_path:
            return "APPROVED_TEMPLATE_ASSET"
        if "/search/" in logical_path:
            return "REBUILDABLE_INDEX_AND_SEARCH_DESCRIPTOR"
        if "/audit/" in logical_path:
            return "M3_AUDIT_EVIDENCE"
        return "APPROVED_M3_DERIVED_ASSET"
    if logical_path.startswith("data/exports/M2/"):
        return "PUBLISHED_EXPORT_SNAPSHOT"
    if logical_path.startswith("data/templates/"):
        return "TEMPLATE_CONFIGURATION"
    if logical_path.startswith("data/state/"):
        return "M5_PERSISTED_USER_STATE"
    if logical_path == "state/audit-head.json":
        return "AUDIT_HEAD"
    if logical_path == "state/predecessor-active-state.json":
        return "PREDECESSOR_ACTIVE_STATE"
    return "APPROVED_RUNTIME_ASSET"


def _audit_head_payload(
    runtime: M4RuntimeDescriptor,
    project_root: Path,
) -> bytes:
    manifest_paths = {
        "m1_artifact_manifest": (
            runtime.resolve(runtime.layout.m1_derived_root, project_root)
            / "artifact-manifest.json"
        ),
        "m2_bundle_manifest": (
            runtime.resolve(runtime.layout.m2_export_root, project_root)
            / "bundle-manifest.json"
        ),
        "m3_state_manifest": (
            runtime.resolve(runtime.layout.m3_state_root, project_root)
            / "state-manifest.json"
        ),
    }
    heads: dict[str, str] = {}
    for key, path in sorted(manifest_paths.items()):
        heads[key] = _sha256_file(path)
    source_root = runtime.resolve(runtime.layout.source_copy_root, project_root)
    source_files = _walk_regular_files(source_root)
    document = {
        "accepted_ids": {
            "m1_state_id": M4_ACCEPTED_M1_STATE_ID,
            "m2_export_id": M4_ACCEPTED_M2_EXPORT_ID,
            "m3_state_id": M4_ACCEPTED_M3_STATE_ID,
            "taxonomy_release_id": M4_ACCEPTED_TAXONOMY_ID,
            "template_revision_id": M4_ACCEPTED_TEMPLATE_ID,
        },
        "active_state_id": runtime.active_state_id,
        "manifest_heads": heads,
        "network_required": False,
        "pipeline_version": M4_PIPELINE_VERSION,
        "schema_version": "1.0",
        "source_copy_file_count": len(source_files),
        "source_copy_tree_sha256": _sha256_bytes(
            _canonical_json_bytes(
                [
                    {
                        "relative_path": relative,
                        "sha256": _sha256_file(path),
                    }
                    for path, relative in source_files
                ]
            )
        ),
    }
    return _canonical_json_bytes(document)


def _runtime_workbench(files_root: Path, layout: M4RuntimeLayout) -> M3WorkbenchState:
    document_path = (
        files_root.joinpath(*PurePosixPath(layout.m3_state_root).parts)
        / "workbench-state.json"
    )
    document, _ = _read_json(document_path)
    expected = {
        "active_template_revision_id",
        "assertions",
        "basket",
        "documents",
        "figures",
        "history",
        "schema_version",
        "semantic_index",
        "solution_overrides",
        "taxonomy",
        "templates",
    }
    if set(document) != expected or document["schema_version"] != "1.0":
        raise M4Error(
            M4Code.MANIFEST_INVALID,
            "restored M3 workbench state has an unexpected shape",
        )
    return M3WorkbenchState(
        figures=document["figures"],
        taxonomy=document["taxonomy"],
        assertions=document["assertions"],
        documents=document["documents"],
        semantic_index=document["semantic_index"],
        templates=document["templates"],
        active_template_revision_id=document["active_template_revision_id"],
        history=document["history"],
        basket=document["basket"],
        solution_overrides=document["solution_overrides"],
    )


def create_recovered_runtime_app(
    files_root: Path,
    *,
    layout: M4RuntimeLayout = M4RuntimeLayout(),
    workbench: M3WorkbenchState | None = None,
) -> Flask:
    files_root = Path(files_root)
    _inspect_directory(files_root)
    source_root_relative = _relative_to_project(files_root)
    workbench = workbench or _runtime_workbench(files_root, layout)
    config = M3PipelineConfig(data_source_root_relative=source_root_relative)
    app = create_m3_app(workbench, config=config)

    @app.get("/runtime/questions/<qid>")
    def recovered_question(qid: str) -> Response:
        document = workbench.documents.get(qid)
        if document is None:
            return jsonify({"error": "unknown qid"}), 404
        return jsonify(
            {
                "qid": qid,
                "question_revision_id": document["question_revision_id"],
                "review_status": document["review_status"],
                "source": {
                    "paper_revision_id": document["paper_revision_id"],
                    "page": document["source_page"],
                    "crop_relative_path": document[
                        "source_crop_relative_path"
                    ],
                },
                "stem_text": document["stem_text"],
            }
        )

    @app.get("/runtime/bundles/<role>")
    def recovered_bundle(role: str) -> Response:
        export_root = files_root.joinpath(
            *PurePosixPath(layout.m2_export_root).parts
        )
        manifest, _ = _read_json(export_root / "bundle-manifest.json")
        documents = manifest.get("documents")
        if type(documents) is not dict or role not in documents:
            return jsonify({"error": "unknown document role"}), 404
        row = documents[role]
        if type(row) is not dict:
            return jsonify({"error": "invalid document metadata"}), 409
        relative_path = _safe_relative_path(
            row["relative_path"],
            field_name="documents.relative_path",
        )
        path = files_root.joinpath(*PurePosixPath(relative_path).parts)
        payload = _read_bounded(path)
        if (
            len(payload) != row["bytes"]
            or _sha256_bytes(payload) != row["sha256"]
        ):
            return jsonify({"error": "document verification failed"}), 409
        return send_file(
            path,
            mimetype="application/pdf",
            as_attachment=False,
            download_name=path.name,
            conditional=False,
        )

    return app


def run_recovered_runtime_journey(
    files_root: Path,
    *,
    layout: M4RuntimeLayout = M4RuntimeLayout(),
) -> dict[str, Any]:
    app = create_recovered_runtime_app(files_root, layout=layout)
    events: list[dict[str, Any]] = []

    def expect(journey_id: str, response: Any, expected: int = 200) -> Any:
        if response.status_code != expected:
            raise M4Error(
                M4Code.RESTORE_FAILED,
                f"{journey_id} expected HTTP {expected}, got {response.status_code}",
            )
        events.append(
            {
                "http_status": int(response.status_code),
                "journey_id": journey_id,
                "passed": True,
            }
        )
        return response

    with app.test_client() as client:
        expect("UJ-061-START", client.get("/"))
        search = expect(
            "UJ-061-SEARCH",
            client.get("/search", query_string={"q": "函数", "limit": 5}),
        ).get_json()
        if type(search) is not dict or not search.get("results"):
            raise M4Error(
                M4Code.RESTORE_FAILED,
                "restored search returned no representative result",
            )
        qid = str(search["results"][0]["qid"])
        question = expect(
            "UJ-061-OPEN-QUESTION",
            client.get(f"/runtime/questions/{qid}"),
        ).get_json()
        if question.get("review_status") != "approved":
            raise M4Error(
                M4Code.RESTORE_FAILED,
                "restored representative question is not approved",
            )
        basket = expect(
            "UJ-061-BASKET",
            client.post("/basket", data={"qid": qid}),
        ).get_json()
        if (
            type(basket.get("basket")) is not list
            or qid not in basket["basket"]
            or int(basket.get("count", 0)) < 1
        ):
            raise M4Error(
                M4Code.RESTORE_FAILED,
                "restored basket did not retain the selected question",
            )
        geometry = _runtime_workbench(files_root, layout).figures["geometry"]
        revisions = geometry["revisions"]
        figure = next(
            revisions[revision_id]
            for revision_id in revisions
            if revisions[revision_id]["representation"] == "original"
        )
        expect(
            "UJ-061-FIGURE",
            client.get(
                "/figures/geometry/"
                + str(figure["domain_revision"]["revision_id"])
            ),
        )
        student = expect(
            "UJ-061-EXPORT",
            client.get("/runtime/bundles/student"),
        )
        if not student.data.startswith(b"%PDF-"):
            raise M4Error(
                M4Code.RESTORE_FAILED,
                "restored student export is not a readable PDF",
            )
    return {
        "events": events,
        "journey_count": len(events),
        "status": "PASS",
    }


class M4BackupService:
    """Full/incremental backup, staging restore, and pointer activation service."""

    def __init__(self, project_root: Path = PROJECT_ROOT) -> None:
        try:
            contract = inspect_project_root(Path(project_root))
        except ProjectRootError as exc:
            raise M4Error(
                M4Code.INVALID_ROOT,
                "M4 service requires a verified portable project root",
            ) from exc
        if contract.root.resolve() != PROJECT_ROOT.resolve():
            raise M4Error(
                M4Code.INVALID_ROOT,
                "M4 production service cannot be redirected to another root",
            )
        self._root = contract.root
        self._workspace = get_workspace_io()
        self._layout = M4RuntimeLayout()

    @property
    def project_root(self) -> Path:
        return self._root

    @property
    def active_pointer_path(self) -> Path:
        return self._root / "data" / "db" / "active-state.json"

    def _job_root(self, job_id: str) -> Path:
        job_id = _safe_id(job_id, field_name="job_id")
        return _ensure_directory(
            self._root / "tmp" / "jobs" / "INTERNAL" / job_id
        )

    def _backup_root(self, backup_id: str) -> Path:
        backup_id = _safe_id(backup_id, field_name="backup_id")
        return self._root / "backups" / backup_id

    def _state_root(self, state_id: str) -> Path:
        state_id = _safe_id(state_id, field_name="state_id")
        return self._root / "data" / "snapshots" / state_id

    def _implicit_runtime(self) -> M4RuntimeDescriptor:
        return M4RuntimeDescriptor(
            active_state_id=M4_ACCEPTED_M3_STATE_ID,
            source_root_relative=".",
            layout=self._layout,
            generation=0,
        )

    def _pointer_predecessor(
        self,
        runtime: M4RuntimeDescriptor,
    ) -> dict[str, Any]:
        return {
            "active_state_id": runtime.active_state_id,
            "generation": runtime.generation,
            "layout": runtime.layout.to_dict(),
            "source_backup_id": runtime.source_backup_id,
            "source_root_relative": runtime.source_root_relative,
            "state_manifest_sha256": runtime.state_manifest_sha256,
        }

    def current_runtime(self) -> M4RuntimeDescriptor:
        if not os.path.lexists(self.active_pointer_path):
            return self._implicit_runtime()
        pointer, _ = _read_json(
            self.active_pointer_path,
            maximum_bytes=512 * 1024,
        )
        expected = {
            "activated_at",
            "activation_gate_sha256",
            "active_state_id",
            "generation",
            "layout",
            "pointer_schema_version",
            "predecessor",
            "rescue_backup_id",
            "source_backup_id",
            "source_root_relative",
            "state_manifest_sha256",
            "status",
        }
        if (
            set(pointer) != expected
            or pointer["pointer_schema_version"] != M4_POINTER_SCHEMA_VERSION
            or pointer["status"] != "ACTIVE"
            or type(pointer["predecessor"]) is not dict
        ):
            raise M4Error(
                M4Code.MANIFEST_INVALID,
                "active-state pointer has an unexpected shape",
            )
        _validate_timestamp(pointer["activated_at"], field_name="activated_at")
        _sha256_value(
            pointer["activation_gate_sha256"],
            field_name="activation_gate_sha256",
        )
        _safe_id(pointer["rescue_backup_id"], field_name="rescue_backup_id")
        runtime = M4RuntimeDescriptor(
            active_state_id=str(pointer["active_state_id"]),
            source_root_relative=str(pointer["source_root_relative"]),
            layout=M4RuntimeLayout.from_dict(pointer["layout"]),
            source_backup_id=(
                None
                if pointer["source_backup_id"] is None
                else str(pointer["source_backup_id"])
            ),
            state_manifest_sha256=(
                None
                if pointer["state_manifest_sha256"] is None
                else str(pointer["state_manifest_sha256"])
            ),
            generation=int(pointer["generation"]),
        )
        source_root = runtime.source_root(self._root)
        _inspect_directory(source_root)
        if runtime.source_root_relative != ".":
            state_manifest = source_root.parent / "state-manifest.json"
            if _sha256_file(state_manifest) != runtime.state_manifest_sha256:
                raise M4Error(
                    M4Code.MANIFEST_INVALID,
                    "active-state pointer does not match its immutable state manifest",
                )
        return runtime

    def _runtime_sources(
        self,
        runtime: M4RuntimeDescriptor,
    ) -> list[tuple[Path | None, str, str, bytes | None]]:
        rows: list[tuple[Path | None, str, str, bytes | None]] = []
        database = runtime.resolve(runtime.layout.database_path, self._root)
        _inspect_file(database, allow_empty=False)
        rows.append(
            (
                database,
                runtime.layout.database_path,
                "SQLITE_BACKUP_API_SNAPSHOT",
                None,
            )
        )
        for logical_root in (
            runtime.layout.source_copy_root,
            runtime.layout.m1_derived_root,
            runtime.layout.m2_export_root,
            runtime.layout.m3_state_root,
            runtime.layout.templates_root,
        ):
            physical_root = runtime.resolve(logical_root, self._root)
            for physical, suffix in _walk_regular_files(physical_root):
                logical = (
                    logical_root
                    if suffix == "."
                    else f"{logical_root}/{suffix}"
                )
                rows.append((physical, logical, _role_for_path(logical), None))
        optional_state_root = runtime.resolve("data/state", self._root)
        if os.path.lexists(optional_state_root):
            for physical, suffix in _walk_regular_files(optional_state_root):
                logical = (
                    "data/state"
                    if suffix == "."
                    else f"data/state/{suffix}"
                )
                rows.append(
                    (
                        physical,
                        logical,
                        "M5_PERSISTED_USER_STATE",
                        None,
                    )
                )
        audit_payload = _audit_head_payload(runtime, self._root)
        rows.append(
            (
                None,
                runtime.layout.audit_head_path,
                "AUDIT_HEAD",
                audit_payload,
            )
        )
        if os.path.lexists(self.active_pointer_path):
            pointer_payload = _read_bounded(
                self.active_pointer_path,
                maximum_bytes=512 * 1024,
                allow_empty=False,
            )
            rows.append(
                (
                    None,
                    "state/predecessor-active-state.json",
                    "PREDECESSOR_ACTIVE_STATE",
                    pointer_payload,
                )
            )
        logical_paths = [row[1] for row in rows]
        if len(logical_paths) != len(set(logical_paths)):
            raise M4Error(
                M4Code.SOURCE_INVALID,
                "M4 source scope contains duplicate logical paths",
            )
        if len(rows) > M4_MAX_FILE_COUNT:
            raise M4Error(
                M4Code.RESOURCE_LIMIT,
                "M4 source scope exceeds the maximum file count",
            )
        return sorted(rows, key=lambda row: row[1])

    def _space_preflight(
        self,
        *,
        required_bytes: int,
        reserve_bytes: int,
        available_bytes_override: int | None,
    ) -> int:
        if (
            type(required_bytes) is not int
            or required_bytes < 0
            or type(reserve_bytes) is not int
            or reserve_bytes < 0
        ):
            raise M4Error(
                M4Code.INSUFFICIENT_SPACE,
                "M4 space preflight received invalid byte counts",
            )
        free = (
            int(available_bytes_override)
            if available_bytes_override is not None
            else int(shutil.disk_usage(self._root).free)
        )
        if free < required_bytes + reserve_bytes:
            raise M4Error(
                M4Code.INSUFFICIENT_SPACE,
                "insufficient space; M4 stopped before publishing or deleting anything",
            )
        return free

    def _load_manifest(
        self,
        backup_id: str,
        *,
        root_override: Path | None = None,
    ) -> tuple[dict[str, Any], bytes]:
        root = root_override or self._backup_root(backup_id)
        _inspect_directory(root)
        return _read_json(root / "manifest.json")

    def _validate_manifest_shape(
        self,
        manifest: dict[str, Any],
        *,
        backup_id: str,
    ) -> None:
        expected = {
            "audit_head_sha256",
            "backup_id",
            "backup_kind",
            "created_at",
            "deduplication",
            "exclusions",
            "files",
            "manifest_schema_version",
            "parent_backup_id",
            "pipeline_version",
            "runtime_layout",
            "source_active_state_id",
            "storage",
        }
        if (
            set(manifest) != expected
            or manifest["manifest_schema_version"]
            != M4_MANIFEST_SCHEMA_VERSION
            or manifest["pipeline_version"] != M4_PIPELINE_VERSION
            or manifest["backup_id"] != backup_id
            or manifest["backup_kind"] not in {"full", "incremental", "rescue"}
        ):
            raise M4Error(
                M4Code.MANIFEST_INVALID,
                "backup manifest identity or shape is invalid",
            )
        _validate_timestamp(manifest["created_at"], field_name="created_at")
        _safe_id(
            manifest["source_active_state_id"],
            field_name="source_active_state_id",
        )
        M4RuntimeLayout.from_dict(manifest["runtime_layout"])
        if manifest["backup_kind"] == "full":
            if manifest["parent_backup_id"] is not None:
                raise M4Error(
                    M4Code.MANIFEST_INVALID,
                    "full backup cannot declare a parent",
                )
        else:
            _safe_id(
                manifest["parent_backup_id"],
                field_name="parent_backup_id",
            )
            if manifest["parent_backup_id"] == backup_id:
                raise M4Error(
                    M4Code.MANIFEST_INVALID,
                    "backup cannot refer to itself as its parent",
                )
        if manifest["exclusions"] != [
            "Copy/restricted",
            "browser-state",
            "data/cache",
            "tmp",
            "unpublished-failure-artifacts",
        ]:
            raise M4Error(
                M4Code.MANIFEST_INVALID,
                "backup exclusions do not match the published M4 policy",
            )

    def _ancestor_ids(
        self,
        backup_id: str,
        manifest: dict[str, Any],
        *,
        stack: tuple[str, ...],
    ) -> tuple[str, ...]:
        parent = manifest["parent_backup_id"]
        if parent is None:
            return ()
        if parent in stack or len(stack) >= M4_MAX_BACKUP_CHAIN:
            raise M4Error(
                M4Code.MANIFEST_INVALID,
                "backup parent chain is cyclic or exceeds its fixed depth",
            )
        parent_manifest, _ = self._load_manifest(parent)
        self._validate_manifest_shape(parent_manifest, backup_id=parent)
        return (parent,) + self._ancestor_ids(
            parent,
            parent_manifest,
            stack=(*stack, parent),
        )

    def validate_backup(
        self,
        backup_id: str,
        *,
        root_override: Path | None = None,
        idempotent: bool = True,
    ) -> M4BackupReceipt:
        backup_id = _safe_id(backup_id, field_name="backup_id")
        root = root_override or self._backup_root(backup_id)
        manifest, manifest_payload = self._load_manifest(
            backup_id,
            root_override=root,
        )
        self._validate_manifest_shape(manifest, backup_id=backup_id)
        ancestors = self._ancestor_ids(
            backup_id,
            manifest,
            stack=(backup_id,),
        )
        allowed_storage_ids = {backup_id, *ancestors}
        files = manifest["files"]
        storage = manifest["storage"]
        deduplication = manifest["deduplication"]
        if (
            type(files) is not list
            or not files
            or len(files) > M4_MAX_FILE_COUNT
            or type(storage) is not dict
            or type(deduplication) is not dict
        ):
            raise M4Error(
                M4Code.MANIFEST_INVALID,
                "backup file or storage inventory is invalid",
            )
        logical_paths: set[str] = set()
        database_rows: list[dict[str, Any]] = []
        self_blobs: dict[str, tuple[int, str]] = {}
        logical_bytes = 0
        reused = 0
        for index, row in enumerate(files):
            if type(row) is not dict or set(row) != {
                "blob",
                "bytes",
                "logical_path",
                "role",
                "sha256",
            }:
                raise M4Error(
                    M4Code.MANIFEST_INVALID,
                    f"backup file row {index} has an unexpected shape",
                )
            logical_path = _safe_relative_path(
                row["logical_path"],
                field_name=f"files[{index}].logical_path",
            )
            if logical_path in logical_paths:
                raise M4Error(
                    M4Code.MANIFEST_INVALID,
                    "backup manifest contains duplicate logical paths",
                )
            logical_paths.add(logical_path)
            if (
                type(row["bytes"]) is not int
                or row["bytes"] < 0
                or row["bytes"] > M4_MAX_FILE_BYTES
                or type(row["role"]) is not str
                or row["role"] != _role_for_path(logical_path)
            ):
                raise M4Error(
                    M4Code.MANIFEST_INVALID,
                    "backup file size or role is invalid",
                )
            digest = _sha256_value(
                row["sha256"],
                field_name=f"files[{index}].sha256",
            )
            blob = row["blob"]
            if type(blob) is not dict or set(blob) != {
                "backup_id",
                "relative_path",
            }:
                raise M4Error(
                    M4Code.MANIFEST_INVALID,
                    "backup blob locator has an unexpected shape",
                )
            storage_id = _safe_id(
                blob["backup_id"],
                field_name=f"files[{index}].blob.backup_id",
            )
            blob_relative = _safe_relative_path(
                blob["relative_path"],
                field_name=f"files[{index}].blob.relative_path",
            )
            if (
                storage_id not in allowed_storage_ids
                or blob_relative != f"blobs/{digest}.blob"
            ):
                raise M4Error(
                    M4Code.MANIFEST_INVALID,
                    "backup blob locator is not self or an authenticated ancestor",
                )
            blob_root = root if storage_id == backup_id else self._backup_root(storage_id)
            blob_path = blob_root.joinpath(*PurePosixPath(blob_relative).parts)
            blob_identity = _inspect_file(
                blob_path,
                maximum_bytes=M4_MAX_FILE_BYTES,
            )
            if (
                int(blob_identity.st_size) != row["bytes"]
                or _sha256_file(blob_path) != digest
            ):
                raise M4Error(
                    M4Code.BACKUP_INVALID,
                    "backup blob bytes or hash differ from the manifest",
                )
            if storage_id == backup_id:
                self_blobs[digest] = (row["bytes"], blob_relative)
            else:
                reused += 1
            logical_bytes += row["bytes"]
            if row["role"] == "SQLITE_BACKUP_API_SNAPSHOT":
                database_rows.append(row)
        if (
            len(database_rows) != 1
            or logical_bytes > M4_MAX_LOGICAL_BYTES
            or manifest["audit_head_sha256"]
            != next(
                (
                    row["sha256"]
                    for row in files
                    if row["logical_path"] == "state/audit-head.json"
                ),
                None,
            )
        ):
            raise M4Error(
                M4Code.MANIFEST_INVALID,
                "backup database, byte total, or audit head is invalid",
            )
        database = database_rows[0]
        database_blob = database["blob"]
        database_root = (
            root
            if database_blob["backup_id"] == backup_id
            else self._backup_root(database_blob["backup_id"])
        )
        validation = validate_database(
            database_root.joinpath(
                *PurePosixPath(database_blob["relative_path"]).parts
            ),
            require_current=True,
        )
        if not validation.valid:
            raise M4Error(
                M4Code.BACKUP_INVALID,
                "backup database failed validation",
            )
        actual_files = {
            path.relative_to(root).as_posix()
            for path in root.rglob("*")
            if path.is_file()
        }
        expected_files = {
            "manifest.json",
            *(relative for _, relative in self_blobs.values()),
        }
        if actual_files != expected_files:
            raise M4Error(
                M4Code.MANIFEST_INVALID,
                "backup directory contains missing or undeclared files",
            )
        stored_bytes = sum(size for size, _ in self_blobs.values())
        expected_storage = {
            "logical_bytes": logical_bytes,
            "stored_blob_count": len(self_blobs),
            "stored_bytes": stored_bytes,
        }
        expected_dedup = {
            "algorithm": "SHA256_CONTENT_ADDRESS_V1",
            "reused_file_count": reused,
            "unique_content_count": len(
                {str(row["sha256"]) for row in files}
            ),
        }
        if storage != expected_storage or deduplication != expected_dedup:
            raise M4Error(
                M4Code.MANIFEST_INVALID,
                "backup storage or deduplication summary is inconsistent",
            )
        return M4BackupReceipt(
            backup_id=backup_id,
            backup_kind=str(manifest["backup_kind"]),
            parent_backup_id=manifest["parent_backup_id"],
            file_count=len(files),
            logical_bytes=logical_bytes,
            stored_blob_count=len(self_blobs),
            stored_bytes=stored_bytes,
            reused_file_count=reused,
            manifest_sha256=_sha256_bytes(manifest_payload),
            database_sha256=str(database["sha256"]),
            validation_status="VALID",
            idempotent=idempotent,
        )

    def _parent_blob_map(
        self,
        parent_backup_id: str | None,
    ) -> dict[str, dict[str, str]]:
        if parent_backup_id is None:
            return {}
        self.validate_backup(parent_backup_id)
        manifest, _ = self._load_manifest(parent_backup_id)
        result: dict[str, dict[str, str]] = {}
        for row in manifest["files"]:
            result[str(row["sha256"])] = {
                "backup_id": str(row["blob"]["backup_id"]),
                "relative_path": str(row["blob"]["relative_path"]),
            }
        return result

    def create_backup(
        self,
        *,
        backup_id: str,
        job_id: str,
        backup_kind: str = "full",
        parent_backup_id: str | None = None,
        reserve_bytes: int = M4_DEFAULT_RESERVE_BYTES,
        available_bytes_override: int | None = None,
        failure_point: M4FailurePoint | None = None,
        cancel_after_files: int | None = None,
        progress: Callable[[dict[str, Any]], None] | None = None,
    ) -> M4BackupReceipt:
        backup_id = _safe_id(backup_id, field_name="backup_id")
        job_id = _safe_id(job_id, field_name="job_id")
        if backup_kind not in {"full", "incremental", "rescue"}:
            raise M4Error(
                M4Code.MANIFEST_INVALID,
                "backup kind must be full, incremental, or rescue",
            )
        if backup_kind == "full":
            if parent_backup_id is not None:
                raise M4Error(
                    M4Code.MANIFEST_INVALID,
                    "full backup cannot use a parent backup",
                )
        else:
            parent_backup_id = _safe_id(
                parent_backup_id,
                field_name="parent_backup_id",
            )
            if parent_backup_id == backup_id:
                raise M4Error(
                    M4Code.MANIFEST_INVALID,
                    "backup cannot use itself as its parent",
                )
        if failure_point is not None and not isinstance(
            failure_point,
            M4FailurePoint,
        ):
            raise M4Error(
                M4Code.BACKUP_FAILED,
                "failure point must be a published M4FailurePoint",
            )
        if cancel_after_files is not None and (
            type(cancel_after_files) is not int or cancel_after_files < 1
        ):
            raise M4Error(
                M4Code.CANCELLED,
                "cancel-after-files must be a positive integer",
            )
        final_root = self._backup_root(backup_id)
        if os.path.lexists(final_root):
            return self.validate_backup(backup_id, idempotent=True)

        runtime = self.current_runtime()
        sources = self._runtime_sources(runtime)
        estimated_bytes = sum(
            (
                len(generated)
                if generated is not None
                else int(_inspect_file(path).st_size)
            )
            for path, _, _, generated in sources
            if path is not None or generated is not None
        )
        if estimated_bytes > M4_MAX_LOGICAL_BYTES:
            raise M4Error(
                M4Code.RESOURCE_LIMIT,
                "M4 active state exceeds the published logical-size boundary",
            )
        free_before = self._space_preflight(
            required_bytes=estimated_bytes
            + int(_inspect_file(runtime.resolve(runtime.layout.database_path, self._root)).st_size),
            reserve_bytes=reserve_bytes,
            available_bytes_override=available_bytes_override,
        )
        parent_blobs = self._parent_blob_map(parent_backup_id)
        job_root = self._job_root(job_id)
        work_root = _ensure_directory(job_root / "backup-work" / backup_id)
        stage_parent = _ensure_directory(job_root / "backup-set")
        stage_root = _ensure_directory(stage_parent / backup_id)
        blobs_root = _ensure_directory(stage_root / "blobs")
        manifest_path = stage_root / "manifest.json"
        if os.path.lexists(manifest_path):
            staged = self.validate_backup(
                backup_id,
                root_override=stage_root,
                idempotent=False,
            )
            _ensure_directory(final_root.parent)
            self._workspace.move_directory_no_replace(stage_root, final_root)
            return self.validate_backup(backup_id, idempotent=staged.idempotent)

        _emit_progress(
            progress,
            {
                "bytes_total": estimated_bytes,
                "file_count": len(sources),
                "phase": "SPACE_PREFLIGHT",
                "percent": 0,
                "free_bytes_before": free_before,
            },
        )

        database_source = runtime.resolve(runtime.layout.database_path, self._root)
        database_work = work_root / "database.sqlite3"
        if os.path.lexists(database_work):
            validate_database(database_work, require_current=True)
        else:
            try:
                _sqlite_backup(database_source, database_work)
            except DatabaseBackupError as exc:
                raise M4Error(
                    M4Code.BACKUP_FAILED,
                    "SQLite Backup API could not create the M4 snapshot",
                ) from exc
            validate_database(database_work, require_current=True)

        file_rows: list[dict[str, Any]] = []
        self_blob_sizes: dict[str, int] = {}
        logical_done = 0
        processed = 0
        audit_head_sha256 = ""
        for physical, logical_path, role, generated_payload in sources:
            if role == "SQLITE_BACKUP_API_SNAPSHOT":
                payload = _read_bounded(
                    database_work,
                    maximum_bytes=M4_MAX_FILE_BYTES,
                    allow_empty=False,
                )
            elif generated_payload is not None:
                payload = generated_payload
            elif physical is not None:
                payload = _read_bounded(physical)
            else:  # pragma: no cover - construction above is exhaustive.
                raise M4Error(
                    M4Code.SOURCE_INVALID,
                    "M4 source row has no readable payload",
                )
            digest = _sha256_bytes(payload)
            blob_relative = f"blobs/{digest}.blob"
            inherited = parent_blobs.get(digest)
            if inherited is not None:
                blob_locator = inherited
            else:
                blob_path = stage_root.joinpath(
                    *PurePosixPath(blob_relative).parts
                )
                _write_new_or_same(blob_path, payload)
                self_blob_sizes.setdefault(digest, len(payload))
                blob_locator = {
                    "backup_id": backup_id,
                    "relative_path": blob_relative,
                }
            row = {
                "blob": blob_locator,
                "bytes": len(payload),
                "logical_path": logical_path,
                "role": role,
                "sha256": digest,
            }
            file_rows.append(row)
            if logical_path == runtime.layout.audit_head_path:
                audit_head_sha256 = digest
            logical_done += len(payload)
            processed += 1
            _emit_progress(
                progress,
                {
                    "bytes_done": logical_done,
                    "bytes_total": estimated_bytes,
                    "files_done": processed,
                    "files_total": len(sources),
                    "phase": "HASH_AND_DEDUPLICATE",
                    "percent": min(
                        90,
                        int((processed / max(1, len(sources))) * 90),
                    ),
                },
            )
            if cancel_after_files is not None and processed >= cancel_after_files:
                raise M4Cancelled()

        _call_failpoint(
            failure_point,
            M4FailurePoint.BACKUP_AFTER_BLOBS,
        )
        logical_bytes = sum(int(row["bytes"]) for row in file_rows)
        reused_file_count = sum(
            row["blob"]["backup_id"] != backup_id for row in file_rows
        )
        manifest = {
            "audit_head_sha256": audit_head_sha256,
            "backup_id": backup_id,
            "backup_kind": backup_kind,
            "created_at": datetime.now(UTC).isoformat(),
            "deduplication": {
                "algorithm": "SHA256_CONTENT_ADDRESS_V1",
                "reused_file_count": reused_file_count,
                "unique_content_count": len(
                    {str(row["sha256"]) for row in file_rows}
                ),
            },
            "exclusions": [
                "Copy/restricted",
                "browser-state",
                "data/cache",
                "tmp",
                "unpublished-failure-artifacts",
            ],
            "files": file_rows,
            "manifest_schema_version": M4_MANIFEST_SCHEMA_VERSION,
            "parent_backup_id": parent_backup_id,
            "pipeline_version": M4_PIPELINE_VERSION,
            "runtime_layout": runtime.layout.to_dict(),
            "source_active_state_id": runtime.active_state_id,
            "storage": {
                "logical_bytes": logical_bytes,
                "stored_blob_count": len(self_blob_sizes),
                "stored_bytes": sum(self_blob_sizes.values()),
            },
        }
        _write_new_or_same(manifest_path, _canonical_json_bytes(manifest))
        staged = self.validate_backup(
            backup_id,
            root_override=stage_root,
            idempotent=False,
        )
        _call_failpoint(
            failure_point,
            M4FailurePoint.BACKUP_AFTER_MANIFEST,
        )
        if os.path.lexists(final_root):
            raise M4Error(
                M4Code.CONFLICT,
                "backup target appeared before no-replace publication",
            )
        _ensure_directory(final_root.parent)
        try:
            self._workspace.move_directory_no_replace(stage_root, final_root)
        except WorkspaceIOError as exc:
            raise M4Error(
                M4Code.CONFLICT,
                "backup could not be published without replacement",
            ) from exc
        _call_failpoint(
            failure_point,
            M4FailurePoint.BACKUP_AFTER_PUBLISH,
        )
        receipt = self.validate_backup(backup_id, idempotent=False)
        _emit_progress(
            progress,
            {
                "bytes_done": receipt.logical_bytes,
                "bytes_total": receipt.logical_bytes,
                "files_done": receipt.file_count,
                "files_total": receipt.file_count,
                "phase": "PUBLISHED_AND_VERIFIED",
                "percent": 100,
            },
        )
        return receipt

    def list_backups(self) -> dict[str, Any]:
        backups_root = self._root / "backups"
        if not os.path.lexists(backups_root):
            return {
                "backups": [],
                "invalid_candidate_count": 0,
                "selectable_backup_ids": [],
            }
        _inspect_directory(backups_root)
        valid: list[dict[str, Any]] = []
        invalid: list[dict[str, str]] = []
        for entry in sorted(os.scandir(backups_root), key=lambda item: item.name):
            try:
                backup_id = _safe_id(entry.name, field_name="backup_id")
                identity = os.lstat(entry.path)
                if _is_reparse(identity) or not stat.S_ISDIR(identity.st_mode):
                    raise M4Error(
                        M4Code.INVALID_PATH,
                        "backup candidate is not a regular directory",
                    )
                valid.append(self.validate_backup(backup_id).to_dict())
            except M4Error as exc:
                invalid.append(
                    {
                        "candidate_id": entry.name,
                        "code": exc.code.value,
                    }
                )
        return {
            "backups": valid,
            "invalid_candidate_count": len(invalid),
            "invalid_candidates": invalid,
            "selectable_backup_ids": [row["backup_id"] for row in valid],
        }

    def _resolved_blob_path(
        self,
        backup_id: str,
        backup_root: Path,
        row: dict[str, Any],
    ) -> Path:
        storage_id = str(row["blob"]["backup_id"])
        root = backup_root if storage_id == backup_id else self._backup_root(storage_id)
        return root.joinpath(
            *PurePosixPath(str(row["blob"]["relative_path"])).parts
        )

    def _verify_m1_assets(
        self,
        files_root: Path,
        layout: M4RuntimeLayout,
    ) -> dict[str, Any]:
        m1_root = files_root.joinpath(
            *PurePosixPath(layout.m1_derived_root).parts
        )
        manifest, _ = _read_json(m1_root / "artifact-manifest.json")
        if (
            manifest.get("schema_version") != "1.0"
            or manifest.get("question_count") != 19
            or manifest.get("declared_total_points") != 150
            or manifest.get("paper_revision_id")
            != "PAPER-YANYAN-202605-REV-002"
            or type(manifest.get("artifacts")) is not list
        ):
            raise M4Error(
                M4Code.RESTORE_FAILED,
                "restored M1 manifest identity or counts are invalid",
            )
        for row in manifest["artifacts"]:
            relative = _safe_relative_path(
                row.get("relative_path"),
                field_name="m1.artifacts.relative_path",
            )
            path = files_root.joinpath(*PurePosixPath(relative).parts)
            identity = _inspect_file(path)
            if (
                int(identity.st_size) != row.get("size_bytes")
                or _sha256_file(path) != row.get("sha256")
            ):
                raise M4Error(
                    M4Code.RESTORE_FAILED,
                    "restored M1 artifact differs from its accepted manifest",
                )
        return {
            "artifact_count": len(manifest["artifacts"]),
            "paper_revision_id": manifest["paper_revision_id"],
            "question_count": manifest["question_count"],
        }

    def _verify_m2_assets(
        self,
        files_root: Path,
        layout: M4RuntimeLayout,
    ) -> dict[str, Any]:
        export_root = files_root.joinpath(
            *PurePosixPath(layout.m2_export_root).parts
        )
        manifest, manifest_payload = _read_json(
            export_root / "bundle-manifest.json"
        )
        roles = ("answer", "answer_sheet", "detailed_solution", "student", "teacher")
        if (
            manifest.get("schema_version") != "1.0"
            or manifest.get("export_id") != M4_ACCEPTED_M2_EXPORT_ID
            or manifest.get("question_count") != 19
            or manifest.get("declared_total_points") != 150
            or tuple(manifest.get("document_roles", ())) != roles
            or set(manifest.get("documents", {})) != set(roles)
            or type(manifest.get("artifacts")) is not list
        ):
            raise M4Error(
                M4Code.RESTORE_FAILED,
                "restored M2 bundle identity or role mapping is invalid",
            )
        for row in manifest["artifacts"]:
            relative = _safe_relative_path(
                row.get("relative_path"),
                field_name="m2.artifacts.relative_path",
            )
            path = files_root.joinpath(*PurePosixPath(relative).parts)
            identity = _inspect_file(path)
            if (
                int(identity.st_size) != row.get("bytes")
                or _sha256_file(path) != row.get("sha256")
            ):
                raise M4Error(
                    M4Code.RESTORE_FAILED,
                    "restored M2 artifact differs from its bundle manifest",
                )
        documents_payload = manifest["documents"]
        if type(documents_payload) is not dict:
            raise M4Error(
                M4Code.RESTORE_FAILED,
                "restored M2 document metadata is not an object",
            )
        documents: dict[str, str] = {}
        for role in roles:
            row = documents_payload[role]
            if type(row) is not dict:
                raise M4Error(
                    M4Code.RESTORE_FAILED,
                    "restored M2 document metadata row is not an object",
                )
            relative = _safe_relative_path(
                row["relative_path"],
                field_name=f"m2.documents.{role}.relative_path",
            )
            path = files_root.joinpath(*PurePosixPath(relative).parts)
            payload = _read_bounded(path)
            if (
                not payload.startswith(b"%PDF-")
                or len(payload) != row["bytes"]
                or _sha256_bytes(payload) != row["sha256"]
            ):
                raise M4Error(
                    M4Code.RESTORE_FAILED,
                    "restored M2 document failed PDF or hash validation",
                )
            documents[role] = str(row["sha256"])
        return {
            "bundle_manifest_sha256": _sha256_bytes(manifest_payload),
            "document_count": len(documents),
            "document_sha256": documents,
            "export_id": manifest["export_id"],
        }

    def _state_manifest(
        self,
        *,
        state_id: str,
        backup_id: str,
        backup_manifest_sha256: str,
        backup_manifest: dict[str, Any],
    ) -> dict[str, Any]:
        files = [
            {
                "bytes": int(row["bytes"]),
                "logical_path": str(row["logical_path"]),
                "role": str(row["role"]),
                "sha256": str(row["sha256"]),
            }
            for row in backup_manifest["files"]
        ]
        return {
            "activation_gate_required": True,
            "created_at": datetime.now(UTC).isoformat(),
            "file_count": len(files),
            "files": files,
            "logical_bytes": sum(int(row["bytes"]) for row in files),
            "pipeline_version": M4_PIPELINE_VERSION,
            "runtime_layout": backup_manifest["runtime_layout"],
            "source_backup_id": backup_id,
            "source_backup_manifest_sha256": backup_manifest_sha256,
            "state_id": state_id,
            "state_schema_version": M4_STATE_SCHEMA_VERSION,
        }

    def _verify_state_root(
        self,
        state_id: str,
        state_root: Path,
        *,
        require_gate: bool,
        run_journey: bool,
    ) -> dict[str, Any]:
        state_id = _safe_id(state_id, field_name="state_id")
        _inspect_directory(state_root)
        manifest, manifest_payload = _read_json(
            state_root / "state-manifest.json"
        )
        expected = {
            "activation_gate_required",
            "created_at",
            "file_count",
            "files",
            "logical_bytes",
            "pipeline_version",
            "runtime_layout",
            "source_backup_id",
            "source_backup_manifest_sha256",
            "state_id",
            "state_schema_version",
        }
        if (
            set(manifest) != expected
            or manifest["state_schema_version"] != M4_STATE_SCHEMA_VERSION
            or manifest["pipeline_version"] != M4_PIPELINE_VERSION
            or manifest["state_id"] != state_id
            or manifest["activation_gate_required"] is not True
        ):
            raise M4Error(
                M4Code.MANIFEST_INVALID,
                "restored state manifest identity or shape is invalid",
            )
        _validate_timestamp(manifest["created_at"], field_name="created_at")
        backup_id = _safe_id(
            manifest["source_backup_id"],
            field_name="source_backup_id",
        )
        backup_receipt = self.validate_backup(backup_id)
        if (
            backup_receipt.manifest_sha256
            != manifest["source_backup_manifest_sha256"]
        ):
            raise M4Error(
                M4Code.RESTORE_FAILED,
                "restored state no longer matches its immutable backup manifest",
            )
        layout = M4RuntimeLayout.from_dict(manifest["runtime_layout"])
        files = manifest["files"]
        if (
            type(files) is not list
            or len(files) != manifest["file_count"]
            or len(files) > M4_MAX_FILE_COUNT
        ):
            raise M4Error(
                M4Code.MANIFEST_INVALID,
                "restored state file inventory is invalid",
            )
        files_root = state_root / "files"
        _inspect_directory(files_root)
        expected_files: set[str] = set()
        total = 0
        for index, row in enumerate(files):
            if type(row) is not dict or set(row) != {
                "bytes",
                "logical_path",
                "role",
                "sha256",
            }:
                raise M4Error(
                    M4Code.MANIFEST_INVALID,
                    f"restored state file row {index} has an unexpected shape",
                )
            relative = _safe_relative_path(
                row["logical_path"],
                field_name=f"files[{index}].logical_path",
            )
            if relative in expected_files:
                raise M4Error(
                    M4Code.MANIFEST_INVALID,
                    "restored state contains duplicate logical paths",
                )
            expected_files.add(relative)
            if row["role"] != _role_for_path(relative):
                raise M4Error(
                    M4Code.MANIFEST_INVALID,
                    "restored state file role is inconsistent",
                )
            digest = _sha256_value(
                row["sha256"],
                field_name=f"files[{index}].sha256",
            )
            path = files_root.joinpath(*PurePosixPath(relative).parts)
            identity = _inspect_file(path)
            if (
                int(identity.st_size) != row["bytes"]
                or _sha256_file(path) != digest
            ):
                raise M4Error(
                    M4Code.RESTORE_FAILED,
                    "restored state file differs from its manifest",
                )
            total += int(identity.st_size)
        actual_files = {
            path.relative_to(files_root).as_posix()
            for path in files_root.rglob("*")
            if path.is_file()
        }
        if (
            actual_files != expected_files
            or total != manifest["logical_bytes"]
            or total > M4_MAX_LOGICAL_BYTES
        ):
            raise M4Error(
                M4Code.RESTORE_FAILED,
                "restored state contains missing, extra, or over-limit content",
            )
        database_path = files_root.joinpath(
            *PurePosixPath(layout.database_path).parts
        )
        database = validate_database(database_path, require_current=True)
        with connect_database_read_only(database_path, immutable=True) as connection:
            question_count = int(
                connection.execute("SELECT count(*) FROM questions").fetchone()[0]
            )
            source_paper_count = int(
                connection.execute("SELECT count(*) FROM source_papers").fetchone()[0]
            )
            approved_count = int(
                connection.execute(
                    "SELECT count(*) FROM questions WHERE review_status = 'approved'"
                ).fetchone()[0]
            )
        if (question_count, source_paper_count, approved_count) != (19, 1, 19):
            raise M4Error(
                M4Code.RESTORE_FAILED,
                "restored database business row counts are not the accepted M1 state",
            )
        m1 = self._verify_m1_assets(files_root, layout)
        m2 = self._verify_m2_assets(files_root, layout)
        try:
            m3 = _verify_m3_root(
                M3PipelineConfig(),
                files_root.joinpath(
                    *PurePosixPath(layout.m3_state_root).parts
                ),
            )
        except M3PipelineError as exc:
            raise M4Error(
                M4Code.RESTORE_FAILED,
                "restored M3 state failed its accepted manifest gate",
            ) from exc
        journey = (
            run_recovered_runtime_journey(files_root, layout=layout)
            if run_journey
            else {"journey_count": 0, "status": "NOT_RUN"}
        )
        verification = {
            "database": {
                "approved_question_count": approved_count,
                "foreign_key_violations": database.foreign_key_violations,
                "integrity_check": database.integrity_check,
                "question_count": question_count,
                "schema_version": database.schema_version,
                "source_paper_count": source_paper_count,
            },
            "file_count": len(files),
            "journey": journey,
            "logical_bytes": total,
            "m1": m1,
            "m2": m2,
            "m3": m3,
            "source_backup_id": backup_id,
            "state_id": state_id,
            "state_manifest_sha256": _sha256_bytes(manifest_payload),
            "status": "PASS",
        }
        verification_sha256 = _sha256_bytes(
            _canonical_json_bytes(verification)
        )
        verification["verification_sha256"] = verification_sha256
        gate_path = state_root / "activation-gate.json"
        if require_gate:
            gate, gate_payload = _read_json(
                gate_path,
                maximum_bytes=1024 * 1024,
            )
            if (
                set(gate)
                != {
                    "created_at",
                    "gate_schema_version",
                    "journey_count",
                    "passed",
                    "source_backup_id",
                    "state_id",
                    "state_manifest_sha256",
                    "verification_sha256",
                }
                or gate["gate_schema_version"] != M4_GATE_SCHEMA_VERSION
                or gate["state_id"] != state_id
                or gate["source_backup_id"] != backup_id
                or gate["state_manifest_sha256"]
                != verification["state_manifest_sha256"]
                or gate["verification_sha256"] != verification_sha256
                or gate["journey_count"] != journey["journey_count"]
                or gate["passed"] is not True
            ):
                raise M4Error(
                    M4Code.ACTIVATION_DENIED,
                    "restored state activation gate does not match fresh verification",
                )
            _validate_timestamp(gate["created_at"], field_name="gate.created_at")
            verification["activation_gate_sha256"] = _sha256_bytes(gate_payload)
        elif os.path.lexists(gate_path):
            raise M4Error(
                M4Code.MANIFEST_INVALID,
                "activation gate appeared before independent state verification",
            )
        return verification

    def verify_state(
        self,
        state_id: str,
        *,
        root_override: Path | None = None,
        run_journey: bool = True,
    ) -> dict[str, Any]:
        state_id = _safe_id(state_id, field_name="state_id")
        root = root_override or self._state_root(state_id)
        return self._verify_state_root(
            state_id,
            root,
            require_gate=True,
            run_journey=run_journey,
        )

    def _restore_receipt(
        self,
        state_id: str,
        state_root: Path,
        *,
        idempotent: bool,
    ) -> M4RestoreReceipt:
        verification = self._verify_state_root(
            state_id,
            state_root,
            require_gate=True,
            run_journey=True,
        )
        return M4RestoreReceipt(
            state_id=state_id,
            source_backup_id=str(verification["source_backup_id"]),
            state_relative_path=_relative_to_project(state_root, self._root),
            file_count=int(verification["file_count"]),
            logical_bytes=int(verification["logical_bytes"]),
            state_manifest_sha256=str(
                verification["state_manifest_sha256"]
            ),
            activation_gate_sha256=str(
                verification["activation_gate_sha256"]
            ),
            verification_sha256=str(
                verification["verification_sha256"]
            ),
            journey_count=int(verification["journey"]["journey_count"]),
            idempotent=idempotent,
        )

    def restore_backup(
        self,
        *,
        backup_id: str,
        state_id: str,
        job_id: str,
        reserve_bytes: int = M4_DEFAULT_RESERVE_BYTES,
        available_bytes_override: int | None = None,
        failure_point: M4FailurePoint | None = None,
        cancel_after_files: int | None = None,
        progress: Callable[[dict[str, Any]], None] | None = None,
    ) -> M4RestoreReceipt:
        backup_id = _safe_id(backup_id, field_name="backup_id")
        state_id = _safe_id(state_id, field_name="state_id")
        job_id = _safe_id(job_id, field_name="job_id")
        if failure_point is not None and not isinstance(
            failure_point,
            M4FailurePoint,
        ):
            raise M4Error(
                M4Code.RESTORE_FAILED,
                "failure point must be a published M4FailurePoint",
            )
        backup = self.validate_backup(backup_id)
        backup_root = self._backup_root(backup_id)
        backup_manifest, backup_manifest_payload = self._load_manifest(backup_id)
        final_root = self._state_root(state_id)
        if os.path.lexists(final_root):
            return self._restore_receipt(
                state_id,
                final_root,
                idempotent=True,
            )
        self._space_preflight(
            required_bytes=backup.logical_bytes,
            reserve_bytes=reserve_bytes,
            available_bytes_override=available_bytes_override,
        )
        job_root = self._job_root(job_id)
        stage_parent = _ensure_directory(job_root / "restore-state")
        stage_root = _ensure_directory(stage_parent / state_id)
        files_root = _ensure_directory(stage_root / "files")
        state_manifest_path = stage_root / "state-manifest.json"
        if os.path.lexists(state_manifest_path):
            gate_path = stage_root / "activation-gate.json"
            if not os.path.lexists(gate_path):
                preliminary = self._verify_state_root(
                    state_id,
                    stage_root,
                    require_gate=False,
                    run_journey=True,
                )
                gate = {
                    "created_at": datetime.now(UTC).isoformat(),
                    "gate_schema_version": M4_GATE_SCHEMA_VERSION,
                    "journey_count": preliminary["journey"]["journey_count"],
                    "passed": True,
                    "source_backup_id": backup_id,
                    "state_id": state_id,
                    "state_manifest_sha256": preliminary[
                        "state_manifest_sha256"
                    ],
                    "verification_sha256": preliminary[
                        "verification_sha256"
                    ],
                }
                _write_new_or_same(
                    gate_path,
                    _canonical_json_bytes(gate),
                )
            staged = self._restore_receipt(
                state_id,
                stage_root,
                idempotent=False,
            )
            _ensure_directory(final_root.parent)
            self._workspace.move_directory_no_replace(stage_root, final_root)
            published = self._restore_receipt(
                state_id,
                final_root,
                idempotent=staged.idempotent,
            )
            if (
                published.state_manifest_sha256
                != staged.state_manifest_sha256
                or published.verification_sha256
                != staged.verification_sha256
            ):
                raise M4Error(
                    M4Code.RESTORE_FAILED,
                    "resumed restore changed during no-replace publication",
                )
            return published
        processed = 0
        bytes_done = 0
        for row in backup_manifest["files"]:
            logical = _safe_relative_path(
                row["logical_path"],
                field_name="files.logical_path",
            )
            blob_path = self._resolved_blob_path(
                backup_id,
                backup_root,
                row,
            )
            payload = _read_bounded(blob_path)
            if (
                len(payload) != row["bytes"]
                or _sha256_bytes(payload) != row["sha256"]
            ):
                raise M4Error(
                    M4Code.BACKUP_INVALID,
                    "backup blob changed during restore",
                )
            target = files_root.joinpath(*PurePosixPath(logical).parts)
            _write_new_or_same(target, payload)
            processed += 1
            bytes_done += len(payload)
            _emit_progress(
                progress,
                {
                    "bytes_done": bytes_done,
                    "bytes_total": backup.logical_bytes,
                    "files_done": processed,
                    "files_total": backup.file_count,
                    "phase": "RESTORE_STAGING",
                    "percent": min(
                        80,
                        int((processed / max(1, backup.file_count)) * 80),
                    ),
                },
            )
            if cancel_after_files is not None and processed >= cancel_after_files:
                raise M4Cancelled()
        _call_failpoint(
            failure_point,
            M4FailurePoint.RESTORE_AFTER_FILES,
        )
        state_manifest = self._state_manifest(
            state_id=state_id,
            backup_id=backup_id,
            backup_manifest_sha256=_sha256_bytes(backup_manifest_payload),
            backup_manifest=backup_manifest,
        )
        _write_new_or_same(
            state_manifest_path,
            _canonical_json_bytes(state_manifest),
        )
        preliminary = self._verify_state_root(
            state_id,
            stage_root,
            require_gate=False,
            run_journey=True,
        )
        gate = {
            "created_at": datetime.now(UTC).isoformat(),
            "gate_schema_version": M4_GATE_SCHEMA_VERSION,
            "journey_count": preliminary["journey"]["journey_count"],
            "passed": True,
            "source_backup_id": backup_id,
            "state_id": state_id,
            "state_manifest_sha256": preliminary["state_manifest_sha256"],
            "verification_sha256": preliminary["verification_sha256"],
        }
        _write_new_or_same(
            stage_root / "activation-gate.json",
            _canonical_json_bytes(gate),
        )
        staged = self._restore_receipt(
            state_id,
            stage_root,
            idempotent=False,
        )
        _call_failpoint(
            failure_point,
            M4FailurePoint.RESTORE_AFTER_MANIFEST,
        )
        _ensure_directory(final_root.parent)
        if os.path.lexists(final_root):
            raise M4Error(
                M4Code.CONFLICT,
                "restore target appeared before no-replace publication",
            )
        try:
            self._workspace.move_directory_no_replace(stage_root, final_root)
        except WorkspaceIOError as exc:
            raise M4Error(
                M4Code.CONFLICT,
                "restored state could not be published without replacement",
            ) from exc
        _call_failpoint(
            failure_point,
            M4FailurePoint.RESTORE_AFTER_PUBLISH,
        )
        receipt = self._restore_receipt(
            state_id,
            final_root,
            idempotent=False,
        )
        if (
            receipt.state_manifest_sha256 != staged.state_manifest_sha256
            or receipt.verification_sha256 != staged.verification_sha256
        ):
            raise M4Error(
                M4Code.RESTORE_FAILED,
                "published restored state differs from verified staging",
            )
        _emit_progress(
            progress,
            {
                "bytes_done": receipt.logical_bytes,
                "bytes_total": receipt.logical_bytes,
                "files_done": receipt.file_count,
                "files_total": receipt.file_count,
                "phase": "STAGED_VERIFIED_AND_PUBLISHED",
                "percent": 100,
            },
        )
        return receipt

    def _write_pointer_candidate(
        self,
        *,
        job_root: Path,
        label: str,
        payload: bytes,
    ) -> Path:
        digest = _sha256_bytes(payload)
        candidate = job_root / "activation" / f"{label}-{digest}.json"
        _write_new_or_same(candidate, payload)
        return candidate

    def _replace_active_pointer(self, candidate: Path) -> None:
        _inspect_file(candidate, maximum_bytes=512 * 1024, allow_empty=False)
        _ensure_directory(self.active_pointer_path.parent)
        if os.path.lexists(self.active_pointer_path):
            _inspect_file(
                self.active_pointer_path,
                maximum_bytes=512 * 1024,
                allow_empty=False,
            )
        try:
            os.replace(candidate, self.active_pointer_path)
        except OSError as exc:
            raise M4Error(
                M4Code.ACTIVATION_FAILED,
                "active-state pointer could not be atomically replaced",
            ) from exc
        _inspect_file(
            self.active_pointer_path,
            maximum_bytes=512 * 1024,
            allow_empty=False,
        )

    def _restore_pointer_after_failure(
        self,
        *,
        job_root: Path,
        previous_payload: bytes | None,
    ) -> None:
        if previous_payload is not None:
            candidate = self._write_pointer_candidate(
                job_root=job_root,
                label="automatic-rollback",
                payload=previous_payload,
            )
            self._replace_active_pointer(candidate)
            if _read_bounded(
                self.active_pointer_path,
                maximum_bytes=512 * 1024,
                allow_empty=False,
            ) != previous_payload:
                raise M4Error(
                    M4Code.ACTIVATION_FAILED,
                    "automatic rollback pointer readback failed",
                )
            return
        if not os.path.lexists(self.active_pointer_path):
            return
        failed_payload = _read_bounded(
            self.active_pointer_path,
            maximum_bytes=512 * 1024,
            allow_empty=False,
        )
        failed_target = (
            job_root
            / "activation"
            / f"failed-pointer-{_sha256_bytes(failed_payload)}.json"
        )
        _ensure_directory(failed_target.parent)
        if os.path.lexists(failed_target):
            existing = _read_bounded(
                failed_target,
                maximum_bytes=512 * 1024,
                allow_empty=False,
            )
            if existing != failed_payload:
                raise M4Error(
                    M4Code.ACTIVATION_FAILED,
                    "failed-pointer recovery target has conflicting bytes",
                )
            failed_target = (
                job_root
                / "activation"
                / f"failed-pointer-{time.time_ns()}.json"
            )
        try:
            os.replace(self.active_pointer_path, failed_target)
        except OSError as exc:
            raise M4Error(
                M4Code.ACTIVATION_FAILED,
                "new pointer could not be moved aside during automatic rollback",
            ) from exc
        if os.path.lexists(self.active_pointer_path):
            raise M4Error(
                M4Code.ACTIVATION_FAILED,
                "automatic rollback did not restore the implicit active state",
            )

    def activate_state(
        self,
        *,
        state_id: str,
        job_id: str,
        rescue_backup_id: str,
        parent_backup_id: str,
        failure_point: M4FailurePoint | None = None,
    ) -> dict[str, Any]:
        state_id = _safe_id(state_id, field_name="state_id")
        job_id = _safe_id(job_id, field_name="job_id")
        rescue_backup_id = _safe_id(
            rescue_backup_id,
            field_name="rescue_backup_id",
        )
        parent_backup_id = _safe_id(
            parent_backup_id,
            field_name="parent_backup_id",
        )
        if failure_point is not None and not isinstance(
            failure_point,
            M4FailurePoint,
        ):
            raise M4Error(
                M4Code.ACTIVATION_FAILED,
                "failure point must be a published M4FailurePoint",
            )
        state_root = self._state_root(state_id)
        verification = self.verify_state(state_id, run_journey=True)
        gate_payload = _read_bounded(
            state_root / "activation-gate.json",
            maximum_bytes=1024 * 1024,
            allow_empty=False,
        )
        gate_sha256 = _sha256_bytes(gate_payload)
        if gate_sha256 != verification["activation_gate_sha256"]:
            raise M4Error(
                M4Code.ACTIVATION_DENIED,
                "activation gate changed after state verification",
            )
        state_manifest, state_manifest_payload = _read_json(
            state_root / "state-manifest.json"
        )
        layout = M4RuntimeLayout.from_dict(state_manifest["runtime_layout"])
        current = self.current_runtime()
        previous_payload = (
            _read_bounded(
                self.active_pointer_path,
                maximum_bytes=512 * 1024,
                allow_empty=False,
            )
            if os.path.lexists(self.active_pointer_path)
            else None
        )
        rescue = self.create_backup(
            backup_id=rescue_backup_id,
            job_id=job_id,
            backup_kind="rescue",
            parent_backup_id=parent_backup_id,
        )
        _call_failpoint(
            failure_point,
            M4FailurePoint.ACTIVATE_AFTER_RESCUE,
        )
        runtime = M4RuntimeDescriptor(
            active_state_id=state_id,
            source_root_relative=(
                f"data/snapshots/{state_id}/files"
            ),
            layout=layout,
            source_backup_id=str(state_manifest["source_backup_id"]),
            state_manifest_sha256=_sha256_bytes(state_manifest_payload),
            generation=current.generation + 1,
        )
        pointer = runtime.to_pointer_payload(
            activated_at=datetime.now(UTC).isoformat(),
            activation_gate_sha256=gate_sha256,
            rescue_backup_id=rescue_backup_id,
            predecessor=self._pointer_predecessor(current),
        )
        pointer_payload = _canonical_json_bytes(pointer)
        job_root = self._job_root(job_id)
        candidate = self._write_pointer_candidate(
            job_root=job_root,
            label="active-state",
            payload=pointer_payload,
        )
        switched = False
        try:
            self._replace_active_pointer(candidate)
            switched = True
            if _read_bounded(
                self.active_pointer_path,
                maximum_bytes=512 * 1024,
                allow_empty=False,
            ) != pointer_payload:
                raise M4Error(
                    M4Code.ACTIVATION_FAILED,
                    "active-state pointer readback differs after switch",
                )
            _call_failpoint(
                failure_point,
                M4FailurePoint.ACTIVATE_AFTER_SWITCH,
            )
            observed = self.current_runtime()
            if (
                observed.active_state_id != state_id
                or observed.state_manifest_sha256
                != runtime.state_manifest_sha256
            ):
                raise M4Error(
                    M4Code.ACTIVATION_FAILED,
                    "active-state resolver did not observe the switched state",
                )
            restarted = run_recovered_runtime_journey(
                observed.source_root(self._root),
                layout=observed.layout,
            )
        except BaseException as exc:
            if switched:
                self._restore_pointer_after_failure(
                    job_root=job_root,
                    previous_payload=previous_payload,
                )
            if isinstance(exc, M4Error):
                raise
            raise M4Error(
                M4Code.ACTIVATION_FAILED,
                "active-state activation failed and was rolled back",
            ) from exc
        return {
            "activation_gate_sha256": gate_sha256,
            "active_state_id": state_id,
            "automatic_rollback_required": False,
            "generation": runtime.generation,
            "maintenance_mode_enforced": True,
            "pointer_sha256": _sha256_bytes(pointer_payload),
            "rescue_backup": rescue.to_dict(),
            "restart_journey": restarted,
            "status": "ACTIVE",
        }

    def rollback_active_state(
        self,
        *,
        job_id: str,
        rescue_backup_id: str,
    ) -> dict[str, Any]:
        job_id = _safe_id(job_id, field_name="job_id")
        rescue_backup_id = _safe_id(
            rescue_backup_id,
            field_name="rescue_backup_id",
        )
        if not os.path.lexists(self.active_pointer_path):
            raise M4Error(
                M4Code.ACTIVATION_DENIED,
                "there is no explicit active-state pointer to roll back",
            )
        pointer, pointer_payload = _read_json(
            self.active_pointer_path,
            maximum_bytes=512 * 1024,
        )
        predecessor = pointer.get("predecessor")
        if type(predecessor) is not dict or set(predecessor) != {
            "active_state_id",
            "generation",
            "layout",
            "source_backup_id",
            "source_root_relative",
            "state_manifest_sha256",
        }:
            raise M4Error(
                M4Code.ACTIVATION_DENIED,
                "active-state pointer does not contain a valid predecessor",
            )
        current = self.current_runtime()
        rescue = self.create_backup(
            backup_id=rescue_backup_id,
            job_id=job_id,
            backup_kind="rescue",
            parent_backup_id=str(pointer["source_backup_id"]),
        )
        predecessor_runtime = M4RuntimeDescriptor(
            active_state_id=str(predecessor["active_state_id"]),
            source_root_relative=str(predecessor["source_root_relative"]),
            layout=M4RuntimeLayout.from_dict(predecessor["layout"]),
            source_backup_id=(
                None
                if predecessor["source_backup_id"] is None
                else str(predecessor["source_backup_id"])
            ),
            state_manifest_sha256=(
                None
                if predecessor["state_manifest_sha256"] is None
                else str(predecessor["state_manifest_sha256"])
            ),
            generation=current.generation + 1,
        )
        rollback_pointer = predecessor_runtime.to_pointer_payload(
            activated_at=datetime.now(UTC).isoformat(),
            activation_gate_sha256=str(pointer["activation_gate_sha256"]),
            rescue_backup_id=rescue_backup_id,
            predecessor=self._pointer_predecessor(current),
        )
        rollback_payload = _canonical_json_bytes(rollback_pointer)
        job_root = self._job_root(job_id)
        candidate = self._write_pointer_candidate(
            job_root=job_root,
            label="rollback-state",
            payload=rollback_payload,
        )
        try:
            self._replace_active_pointer(candidate)
            observed = self.current_runtime()
            if (
                observed.active_state_id != predecessor_runtime.active_state_id
                or observed.source_root_relative
                != predecessor_runtime.source_root_relative
            ):
                raise M4Error(
                    M4Code.ACTIVATION_FAILED,
                    "rollback pointer did not resolve to the predecessor state",
                )
            restarted = run_recovered_runtime_journey(
                observed.source_root(self._root),
                layout=observed.layout,
            )
        except BaseException as exc:
            original_candidate = self._write_pointer_candidate(
                job_root=job_root,
                label="rollback-failure-recover-current",
                payload=pointer_payload,
            )
            self._replace_active_pointer(original_candidate)
            if isinstance(exc, M4Error):
                raise
            raise M4Error(
                M4Code.ACTIVATION_FAILED,
                "rollback failed and the prior active pointer was restored",
            ) from exc
        return {
            "active_state_id": observed.active_state_id,
            "generation": observed.generation,
            "pointer_sha256": _sha256_bytes(rollback_payload),
            "rescue_backup": rescue.to_dict(),
            "restart_journey": restarted,
            "rolled_back_from_state_id": current.active_state_id,
            "status": "ROLLED_BACK",
        }


_M4_MAINTENANCE_PAGE = """
<!doctype html>
<html lang="zh-CN">
<head><meta charset="utf-8"><title>本地题库备份与恢复</title></head>
<body>
  <h1>备份、恢复与活动状态</h1>
  <p id="active-state">{{ active_state }}</p>
  <p id="same-volume-limit">
    当前备份位于同一产品根所在卷，只能防误删和逻辑损坏，不能防整盘故障。
  </p>
  <p id="selectable-count">{{ selectable_count }}</p>
  <ul>
  {% for backup in backups %}
    <li>{{ backup.backup_id }} / {{ backup.backup_kind }} /
        {{ backup.logical_bytes }} bytes / {{ backup.validation_status }}</li>
  {% endfor %}
  </ul>
</body>
</html>
"""


def create_m4_app(
    service: M4BackupService | None = None,
    *,
    workbench: M3WorkbenchState | None = None,
) -> Flask:
    service = service or M4BackupService()
    runtime = service.current_runtime()
    app = create_recovered_runtime_app(
        runtime.source_root(service.project_root),
        layout=runtime.layout,
        workbench=workbench,
    )
    app.config.update(TESTING=True, JSON_AS_ASCII=False)

    @app.errorhandler(M4Error)
    def handle_m4_error(error: M4Error) -> tuple[Response, int]:
        status = 409
        if error.code in {
            M4Code.INVALID_ID,
            M4Code.INVALID_PATH,
            M4Code.MANIFEST_INVALID,
        }:
            status = 400
        elif error.code is M4Code.INSUFFICIENT_SPACE:
            status = 507
        return (
            jsonify(
                {
                    "code": error.code.value,
                    "message": error.message,
                    "status": "error",
                }
            ),
            status,
        )

    @app.get("/maintenance")
    def maintenance_home() -> str:
        catalog = service.list_backups()
        active = service.current_runtime()
        return render_template_string(
            _M4_MAINTENANCE_PAGE,
            active_state=active.active_state_id,
            backups=catalog["backups"],
            selectable_count=len(catalog["selectable_backup_ids"]),
        )

    @app.get("/maintenance/status")
    def maintenance_status() -> Response:
        active = service.current_runtime()
        catalog = service.list_backups()
        return jsonify(
            {
                "active_state_id": active.active_state_id,
                "generation": active.generation,
                "offline": True,
                "same_volume_disaster_protection": False,
                **catalog,
            }
        )

    @app.get("/maintenance/backups/<backup_id>")
    def backup_detail(backup_id: str) -> Response:
        return jsonify(service.validate_backup(backup_id).to_dict())

    @app.post("/maintenance/backups")
    def backup_create() -> Response:
        progress: list[dict[str, Any]] = []
        receipt = service.create_backup(
            backup_id=str(request.form.get("backup_id", "")),
            job_id=str(request.form.get("job_id", "")),
            backup_kind=str(request.form.get("backup_kind", "full")),
            parent_backup_id=(
                str(request.form["parent_backup_id"])
                if request.form.get("parent_backup_id")
                else None
            ),
            progress=progress.append,
        )
        return jsonify(
            {
                "progress": progress,
                "receipt": receipt.to_dict(),
                "status": "ok",
            }
        )

    @app.post("/maintenance/backups/<backup_id>/restore")
    def backup_restore(backup_id: str) -> Response:
        progress: list[dict[str, Any]] = []
        receipt = service.restore_backup(
            backup_id=backup_id,
            state_id=str(request.form.get("state_id", "")),
            job_id=str(request.form.get("job_id", "")),
            progress=progress.append,
        )
        return jsonify(
            {
                "activation_required": True,
                "progress": progress,
                "receipt": receipt.to_dict(),
                "status": "staged_and_verified",
            }
        )

    @app.post("/maintenance/states/<state_id>/activate")
    def state_activate(state_id: str) -> Response:
        result = service.activate_state(
            state_id=state_id,
            job_id=str(request.form.get("job_id", "")),
            rescue_backup_id=str(
                request.form.get("rescue_backup_id", "")
            ),
            parent_backup_id=str(
                request.form.get("parent_backup_id", "")
            ),
        )
        return jsonify(result)

    @app.post("/maintenance/rollback")
    def state_rollback() -> Response:
        return jsonify(
            service.rollback_active_state(
                job_id=str(request.form.get("job_id", "")),
                rescue_backup_id=str(
                    request.form.get("rescue_backup_id", "")
                ),
            )
        )

    return app
