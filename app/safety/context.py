from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


_SAFE_ID = re.compile(r"^[A-Z0-9](?:[A-Z0-9_-]{0,126}[A-Z0-9])?$")


class ContextError(ValueError):
    pass


class Caller(StrEnum):
    CONTROL_SERVICE = "CONTROL_SERVICE"
    WEB = "WEB"
    CLI = "CLI"
    DATABASE_SERVICE = "DATABASE_SERVICE"
    IMPORT_SERVICE = "IMPORT_SERVICE"
    ASSET_SERVICE = "ASSET_SERVICE"
    EXPORT_SERVICE = "EXPORT_SERVICE"
    REPORT_SERVICE = "REPORT_SERVICE"
    BACKUP_SERVICE = "BACKUP_SERVICE"
    AUDIT_SERVICE = "AUDIT_SERVICE"
    TEST_LAB = "TEST_LAB"


class Purpose(StrEnum):
    READ_REFERENCE = "READ_REFERENCE"
    READ_CONTROL = "READ_CONTROL"
    READ_DATABASE = "READ_DATABASE"
    INITIALIZE_STATE = "INITIALIZE_STATE"
    MUTATE_DATABASE = "MUTATE_DATABASE"
    COPY_SOURCE = "COPY_SOURCE"
    BUILD_DERIVED = "BUILD_DERIVED"
    BUILD_EXPORT = "BUILD_EXPORT"
    APPEND_AUDIT = "APPEND_AUDIT"
    BACKUP = "BACKUP"
    RESTORE = "RESTORE"
    QUARANTINE = "QUARANTINE"
    TEST = "TEST"


class ScopeKind(StrEnum):
    RUN_ID = "RUN_ID"
    COPY_ID = "COPY_ID"
    JOB_ID = "JOB_ID"
    STATE_ID = "STATE_ID"
    OBJECT_ID = "OBJECT_ID"
    REVISION_ID = "REVISION_ID"
    PIPELINE_ID = "PIPELINE_ID"
    INDEX_ID = "INDEX_ID"
    EXPORT_ID = "EXPORT_ID"
    BACKUP_ID = "BACKUP_ID"
    MANIFEST_ID = "MANIFEST_ID"
    CHECKPOINT_ID = "CHECKPOINT_ID"
    OPERATION_ID = "OPERATION_ID"


class DataClassification(StrEnum):
    INTERNAL = "INTERNAL"
    RESTRICTED = "RESTRICTED"


def validate_safe_id(value: str, *, field_name: str) -> str:
    if not isinstance(value, str) or not _SAFE_ID.fullmatch(value):
        raise ContextError(
            f"{field_name} must use 1-128 canonical uppercase ASCII letters, digits, '-' or '_'"
        )
    if value in {".", ".."} or "/" in value or "\\" in value:
        raise ContextError(f"{field_name} contains forbidden path syntax")
    return value


@dataclass(frozen=True, slots=True)
class ScopeId:
    kind: ScopeKind
    value: str

    def __post_init__(self) -> None:
        if type(self.kind) is not ScopeKind:
            raise ContextError("scope kind must be a ScopeKind value")
        validate_safe_id(self.value, field_name=f"scope[{self.kind.value}]")

    def to_audit_dict(self) -> dict[str, str | None]:
        return {"kind": self.kind.value, "value": None}

    def __repr__(self) -> str:
        return f"ScopeId(kind='{self.kind.value}', value='<redacted>')"

    def __reduce__(self) -> Any:
        raise TypeError("scope identifiers cannot be serialized")


@dataclass(frozen=True, slots=True)
class OperationContext:
    run_id: str
    job_id: str
    operation_id: str
    caller: Caller
    purpose: Purpose
    scopes: tuple[ScopeId, ...] = ()
    manifest_id: str | None = None
    classification: DataClassification = DataClassification.INTERNAL
    authority_id: str | None = field(default=None, repr=False, compare=False)
    authority_ticket_id: str | None = field(default=None, repr=False, compare=False)
    authenticator: bytes = field(default=b"", repr=False, compare=False)

    def __post_init__(self) -> None:
        validate_safe_id(self.run_id, field_name="run_id")
        validate_safe_id(self.job_id, field_name="job_id")
        validate_safe_id(self.operation_id, field_name="operation_id")
        if type(self.caller) is not Caller:
            raise ContextError("caller must be a Caller value")
        if type(self.purpose) is not Purpose:
            raise ContextError("purpose must be a Purpose value")
        if type(self.classification) is not DataClassification:
            raise ContextError("classification must be a DataClassification value")
        if type(self.scopes) is not tuple or any(
            type(scope) is not ScopeId for scope in self.scopes
        ):
            raise ContextError("scopes must be a tuple of ScopeId values")
        kinds = [scope.kind for scope in self.scopes]
        if len(kinds) != len(set(kinds)):
            raise ContextError("scope kinds cannot be repeated")
        if self.manifest_id is not None:
            validate_safe_id(self.manifest_id, field_name="manifest_id")
        authority_parts = (
            self.authority_id is not None,
            self.authority_ticket_id is not None,
            bool(self.authenticator),
        )
        if any(authority_parts) and not all(authority_parts):
            raise ContextError("context authority fields must be present together")
        if self.authority_id is not None:
            validate_safe_id(self.authority_id, field_name="authority_id")
            validate_safe_id(
                self.authority_ticket_id or "",
                field_name="authority_ticket_id",
            )
            if type(self.authenticator) is not bytes or len(self.authenticator) != 32:
                raise ContextError("context authenticator must be exactly 32 bytes")

        job_scope = self.scope_value(ScopeKind.JOB_ID)
        if job_scope is not None and job_scope != self.job_id:
            raise ContextError("JOB_ID scope must equal context.job_id")
        manifest_scope = self.scope_value(ScopeKind.MANIFEST_ID)
        if (self.manifest_id is None) != (manifest_scope is None):
            raise ContextError(
                "manifest_id and MANIFEST_ID scope must either both be present or both be absent"
            )
        if self.manifest_id is not None and manifest_scope != self.manifest_id:
            raise ContextError("MANIFEST_ID scope must equal context.manifest_id")
        run_scope = self.scope_value(ScopeKind.RUN_ID)
        if run_scope is not None and run_scope != self.run_id:
            raise ContextError("RUN_ID scope must equal context.run_id")
        operation_scope = self.scope_value(ScopeKind.OPERATION_ID)
        if operation_scope is not None and operation_scope != self.operation_id:
            raise ContextError("OPERATION_ID scope must equal context.operation_id")

    def scope_value(self, kind: ScopeKind) -> str | None:
        for scope in self.scopes:
            if scope.kind is kind:
                return scope.value
        return None

    @property
    def authority_bound(self) -> bool:
        return self.authority_id is not None

    def _claims_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "job_id": self.job_id,
            "operation_id": self.operation_id,
            "caller": self.caller.value,
            "purpose": self.purpose.value,
            "scopes": [
                {"kind": scope.kind.value, "value": scope.value}
                for scope in sorted(self.scopes, key=lambda item: item.kind.value)
            ],
            "manifest_id": self.manifest_id,
            "classification": self.classification.value,
        }

    def to_audit_dict(self) -> dict[str, Any]:
        if self.classification is DataClassification.RESTRICTED:
            return {
                "run_id": None,
                "job_id": None,
                "operation_id": None,
                "caller": None,
                "purpose": None,
                "scopes": [
                    {"kind": scope.kind.value, "value": None}
                    for scope in sorted(self.scopes, key=lambda item: item.kind.value)
                ],
                "manifest_id": None,
                "classification": self.classification.value,
            }
        return self._claims_dict()

    def __repr__(self) -> str:
        return (
            "OperationContext(classification="
            f"'{self.classification.value}', scope_kinds="
            f"{tuple(scope.kind.value for scope in self.scopes)!r}, ids='<redacted>')"
        )

    def __reduce__(self) -> Any:
        raise TypeError("operation contexts cannot be serialized")

    @property
    def digest(self) -> str:
        canonical = json.dumps(
            self._claims_dict(),
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        return hashlib.sha256(canonical).hexdigest()
