from __future__ import annotations

import hashlib
import json
import ntpath
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path, PureWindowsPath
from typing import Any

from app.workspace_guard import ExpectedKind, GuardedPath, PathIntent

from .context import (
    Caller,
    DataClassification,
    OperationContext,
    Purpose,
    ScopeKind,
    validate_safe_id,
)


POLICY_ID = "LOCAL-EXAM-BANK-WORKSPACE"
POLICY_VERSION = "M0-S2-V6"
EXPECTED_POLICY_DIGEST = (
    "315a036ad41c1ac77379c430fc667de470e03376513d9fd8cb6f92d6ae0110b4"
)


class NamespaceId(StrEnum):
    GIT_INTERNAL = "GIT_INTERNAL"
    BASE_REFERENCE = "BASE_REFERENCE"
    TASK_CONTROL = "TASK_CONTROL"
    COPY_SOURCE = "COPY_SOURCE"
    COPY_RESTRICTED = "COPY_RESTRICTED"
    COPY_WORK_INTERNAL = "COPY_WORK_INTERNAL"
    COPY_WORK_RESTRICTED = "COPY_WORK_RESTRICTED"
    COPY_WORK = "COPY_WORK"
    COPY_LEDGER = "COPY_LEDGER"
    ACTIVE_DATABASE = "ACTIVE_DATABASE"
    DATABASE_SIDECAR = "DATABASE_SIDECAR"
    DATABASE_DIRECTORY = "DATABASE_DIRECTORY"
    DATABASE_VERSION = "DATABASE_VERSION"
    ACTIVE_STATE_POINTER = "ACTIVE_STATE_POINTER"
    ORIGINAL_OBJECT = "ORIGINAL_OBJECT"
    DERIVED_REVISION = "DERIVED_REVISION"
    INDEX_VERSION = "INDEX_VERSION"
    TEMPLATE_REVISION = "TEMPLATE_REVISION"
    EXPORT_BUNDLE = "EXPORT_BUNDLE"
    SNAPSHOT = "SNAPSHOT"
    BACKUP_SET = "BACKUP_SET"
    AUDIT_LOG = "AUDIT_LOG"
    JOB_WORKSPACE_INTERNAL = "JOB_WORKSPACE_INTERNAL"
    JOB_WORKSPACE_RESTRICTED = "JOB_WORKSPACE_RESTRICTED"
    JOB_WORKSPACE = "JOB_WORKSPACE"
    QUARANTINE_INTERNAL = "QUARANTINE_INTERNAL"
    QUARANTINE_RESTRICTED = "QUARANTINE_RESTRICTED"
    QUARANTINE = "QUARANTINE"
    LEGACY_ASSET = "LEGACY_ASSET"
    LEGACY_DB_BACKUP = "LEGACY_DB_BACKUP"
    UNCLASSIFIED = "UNCLASSIFIED"


class NamespaceMode(StrEnum):
    FORBIDDEN = "FORBIDDEN"
    READ_ONLY = "READ_ONLY"
    IMMUTABLE_OBJECT_STORE = "IMMUTABLE_OBJECT_STORE"
    VERSIONED_STORE = "VERSIONED_STORE"
    JOB_MUTABLE = "JOB_MUTABLE"
    APPEND_ONLY = "APPEND_ONLY"
    DATABASE_CONTROLLED = "DATABASE_CONTROLLED"
    ATOMIC_POINTER = "ATOMIC_POINTER"
    QUARANTINE_ONLY = "QUARANTINE_ONLY"
    LEGACY_READ_ONLY = "LEGACY_READ_ONLY"
    UNCLASSIFIED = "UNCLASSIFIED"


class AuditPathMode(StrEnum):
    RELATIVE = "RELATIVE"
    HMAC_ONLY = "HMAC_ONLY"


class PolicyErrorCode(StrEnum):
    FORBIDDEN_NAMESPACE = "FORBIDDEN_NAMESPACE"
    PROTECTED_NAMESPACE = "PROTECTED_NAMESPACE"
    UNCLASSIFIED_ACCESS = "UNCLASSIFIED_ACCESS"
    UNCLASSIFIED_MUTATION = "UNCLASSIFIED_MUTATION"
    CALLER_NOT_ALLOWED = "CALLER_NOT_ALLOWED"
    PURPOSE_NOT_ALLOWED = "PURPOSE_NOT_ALLOWED"
    RESTRICTED_CONTEXT_REQUIRED = "RESTRICTED_CONTEXT_REQUIRED"
    CLASSIFICATION_MISMATCH = "CLASSIFICATION_MISMATCH"
    SCOPE_REQUIRED = "SCOPE_REQUIRED"
    SCOPE_MISMATCH = "SCOPE_MISMATCH"
    MINIMUM_DEPTH = "MINIMUM_DEPTH"
    MAXIMUM_DEPTH = "MAXIMUM_DEPTH"
    OBJECT_ROOT_REQUIRED = "OBJECT_ROOT_REQUIRED"
    EXPECTED_KIND_REQUIRED = "EXPECTED_KIND_REQUIRED"
    PAIR_AUTHORIZATION_REQUIRED = "PAIR_AUTHORIZATION_REQUIRED"
    PAIR_POLICY_DENIED = "PAIR_POLICY_DENIED"
    PAIR_TOPOLOGY_INVALID = "PAIR_TOPOLOGY_INVALID"
    ABSOLUTE_PATH_FORBIDDEN = "ABSOLUTE_PATH_FORBIDDEN"
    PRODUCTION_ROOT_MISMATCH = "PRODUCTION_ROOT_MISMATCH"
    BOUNDARY_STATE_CHANGED = "BOUNDARY_STATE_CHANGED"
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    WRITER_UNAVAILABLE = "WRITER_UNAVAILABLE"
    TICKET_CONTEXT_MISMATCH = "TICKET_CONTEXT_MISMATCH"
    TICKET_POLICY_MISMATCH = "TICKET_POLICY_MISMATCH"
    TICKET_NOT_ISSUED = "TICKET_NOT_ISSUED"
    TICKET_TAMPERED = "TICKET_TAMPERED"
    PAIR_NOT_ISSUED = "PAIR_NOT_ISSUED"
    PAIR_MEMBER_MISMATCH = "PAIR_MEMBER_MISMATCH"
    MANIFEST_BINDING_REQUIRED = "MANIFEST_BINDING_REQUIRED"
    MANIFEST_BINDING_INVALID = "MANIFEST_BINDING_INVALID"
    AUDIT_RECORD_FAILED = "AUDIT_RECORD_FAILED"


class NamespacePolicyError(PermissionError):
    """A path-free policy error safe to expose at the service boundary."""

    def __init__(
        self,
        code: PolicyErrorCode,
        *,
        namespace: NamespaceId,
        intent: PathIntent,
        message: str,
    ) -> None:
        self.code = code
        self.namespace = namespace
        self.intent = intent
        self.message = message
        super().__init__(f"{code.value}: {message}")


class PolicyIntegrityError(RuntimeError):
    """Raised when an already-constructed policy changes in memory."""


@dataclass(frozen=True, slots=True)
class ScopeBinding:
    tail_index: int
    scope_kind: ScopeKind


@dataclass(frozen=True, slots=True)
class NamespaceRule:
    namespace: NamespaceId
    prefix: tuple[str, ...]
    mode: NamespaceMode
    minimum_tail_depth: int = 0
    maximum_tail_depth: int | None = None
    object_root_depth: int | None = None
    scope_bindings: tuple[ScopeBinding, ...] = ()
    normal_intents: frozenset[PathIntent] = frozenset()
    paired_intents: frozenset[PathIntent] = frozenset()
    read_callers: frozenset[Caller] = frozenset()
    read_purposes: frozenset[Purpose] = frozenset()
    read_actor_pairs: frozenset[tuple[Caller, Purpose]] = frozenset()
    mutation_callers: frozenset[Caller] = frozenset()
    mutation_purposes: frozenset[Purpose] = frozenset()
    mutation_capabilities: frozenset[
        tuple[PathIntent, ExpectedKind, Caller, Purpose]
    ] = frozenset()
    normal_mutation_kinds: frozenset[ExpectedKind] = frozenset()
    paired_kinds: frozenset[ExpectedKind] = frozenset()
    restricted: bool = False
    audit_path_mode: AuditPathMode = AuditPathMode.RELATIVE

    @property
    def normalized_prefix(self) -> tuple[str, ...]:
        return tuple(ntpath.normcase(component) for component in self.prefix)

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "namespace": self.namespace.value,
            "prefix": list(self.prefix),
            "mode": self.mode.value,
            "minimum_tail_depth": self.minimum_tail_depth,
            "maximum_tail_depth": self.maximum_tail_depth,
            "object_root_depth": self.object_root_depth,
            "scope_bindings": [
                {"tail_index": binding.tail_index, "scope": binding.scope_kind.value}
                for binding in self.scope_bindings
            ],
            "normal_intents": sorted(item.value for item in self.normal_intents),
            "paired_intents": sorted(item.value for item in self.paired_intents),
            "read_callers": sorted(item.value for item in self.read_callers),
            "read_purposes": sorted(item.value for item in self.read_purposes),
            "read_actor_pairs": [
                {"caller": caller.value, "purpose": purpose.value}
                for caller, purpose in sorted(
                    self.read_actor_pairs,
                    key=lambda item: (item[0].value, item[1].value),
                )
            ],
            "mutation_callers": sorted(item.value for item in self.mutation_callers),
            "mutation_purposes": sorted(item.value for item in self.mutation_purposes),
            "mutation_capabilities": [
                {
                    "intent": intent.value,
                    "expected_kind": kind.value,
                    "caller": caller.value,
                    "purpose": purpose.value,
                }
                for intent, kind, caller, purpose in sorted(
                    self.mutation_capabilities,
                    key=lambda item: (
                        item[0].value,
                        item[1].value,
                        item[2].value,
                        item[3].value,
                    ),
                )
            ],
            "normal_mutation_kinds": sorted(
                item.value for item in self.normal_mutation_kinds
            ),
            "paired_kinds": sorted(item.value for item in self.paired_kinds),
            "restricted": self.restricted,
            "audit_path_mode": self.audit_path_mode.value,
        }


_READ = frozenset({PathIntent.EXISTING_READ})
_JOB_MUTATIONS = frozenset(
    {
        PathIntent.NEW_WRITE,
        PathIntent.EXISTING_WRITE,
        PathIntent.APPEND_EXISTING,
        PathIntent.CREATE_DIRECTORY,
    }
)
_FILE_MUTATIONS = frozenset(
    {PathIntent.NEW_WRITE, PathIntent.EXISTING_WRITE}
)
_APPEND_FILE = frozenset(
    {PathIntent.NEW_WRITE, PathIntent.APPEND_EXISTING}
)
_PUBLISH_TARGET = frozenset({PathIntent.MOVE_TARGET})
_JOB_PAIR_SOURCE = frozenset(
    {PathIntent.MOVE_SOURCE, PathIntent.QUARANTINE_SOURCE}
)
_QUARANTINE_SOURCE = frozenset({PathIntent.QUARANTINE_SOURCE})
_QUARANTINE_TARGET = frozenset({PathIntent.QUARANTINE_TARGET})

_REFERENCE_CALLERS = frozenset(
    {
        Caller.IMPORT_SERVICE,
        Caller.ASSET_SERVICE,
        Caller.EXPORT_SERVICE,
        Caller.REPORT_SERVICE,
        Caller.BACKUP_SERVICE,
    }
)
_REFERENCE_PURPOSES = frozenset(
    {
        Purpose.READ_REFERENCE,
        Purpose.COPY_SOURCE,
        Purpose.BUILD_DERIVED,
        Purpose.BUILD_EXPORT,
        Purpose.BACKUP,
        Purpose.RESTORE,
    }
)
_JOB_CALLERS = frozenset(
    {
        Caller.DATABASE_SERVICE,
        Caller.IMPORT_SERVICE,
        Caller.ASSET_SERVICE,
        Caller.EXPORT_SERVICE,
        Caller.REPORT_SERVICE,
        Caller.BACKUP_SERVICE,
        Caller.TEST_LAB,
    }
)
_JOB_PURPOSES = frozenset(
    {
        Purpose.INITIALIZE_STATE,
        Purpose.MUTATE_DATABASE,
        Purpose.COPY_SOURCE,
        Purpose.BUILD_DERIVED,
        Purpose.BUILD_EXPORT,
        Purpose.BACKUP,
        Purpose.RESTORE,
        Purpose.QUARANTINE,
        Purpose.TEST,
    }
)
_INTERNAL_JOB_ACTORS = (
    (Caller.DATABASE_SERVICE, Purpose.INITIALIZE_STATE),
    (Caller.DATABASE_SERVICE, Purpose.MUTATE_DATABASE),
    (Caller.DATABASE_SERVICE, Purpose.BUILD_DERIVED),
    (Caller.IMPORT_SERVICE, Purpose.COPY_SOURCE),
    (Caller.IMPORT_SERVICE, Purpose.BUILD_DERIVED),
    (Caller.ASSET_SERVICE, Purpose.BUILD_DERIVED),
    (Caller.EXPORT_SERVICE, Purpose.BUILD_EXPORT),
    (Caller.REPORT_SERVICE, Purpose.BUILD_EXPORT),
    (Caller.BACKUP_SERVICE, Purpose.BACKUP),
    (Caller.BACKUP_SERVICE, Purpose.RESTORE),
    (Caller.TEST_LAB, Purpose.TEST),
)
_INTERNAL_JOB_MOVE_ACTORS = (
    (Caller.IMPORT_SERVICE, Purpose.COPY_SOURCE),
    (Caller.IMPORT_SERVICE, Purpose.BUILD_DERIVED),
    (Caller.DATABASE_SERVICE, Purpose.INITIALIZE_STATE),
    (Caller.DATABASE_SERVICE, Purpose.BUILD_DERIVED),
    (Caller.ASSET_SERVICE, Purpose.BUILD_DERIVED),
    (Caller.EXPORT_SERVICE, Purpose.BUILD_EXPORT),
    (Caller.BACKUP_SERVICE, Purpose.BACKUP),
    (Caller.BACKUP_SERVICE, Purpose.RESTORE),
)
_INTERNAL_COPY_MOVE_ACTORS = (
    (Caller.IMPORT_SERVICE, Purpose.COPY_SOURCE),
)
_RESTRICTED_JOB_ACTORS = (
    (Caller.IMPORT_SERVICE, Purpose.COPY_SOURCE),
    (Caller.IMPORT_SERVICE, Purpose.BUILD_DERIVED),
)
_QUARANTINE_ACTORS = (
    (Caller.DATABASE_SERVICE, Purpose.QUARANTINE),
    (Caller.IMPORT_SERVICE, Purpose.QUARANTINE),
    (Caller.ASSET_SERVICE, Purpose.QUARANTINE),
    (Caller.EXPORT_SERVICE, Purpose.QUARANTINE),
    (Caller.REPORT_SERVICE, Purpose.QUARANTINE),
    (Caller.BACKUP_SERVICE, Purpose.QUARANTINE),
    (Caller.TEST_LAB, Purpose.QUARANTINE),
)
_INTERNAL_QUARANTINE_READ_ACTORS = (
    (Caller.AUDIT_SERVICE, Purpose.QUARANTINE),
    (Caller.AUDIT_SERVICE, Purpose.READ_CONTROL),
    (Caller.BACKUP_SERVICE, Purpose.RESTORE),
    (Caller.CONTROL_SERVICE, Purpose.READ_CONTROL),
)
_RESTRICTED_NAMESPACES = frozenset(
    {
        NamespaceId.COPY_RESTRICTED,
        NamespaceId.COPY_WORK_RESTRICTED,
        NamespaceId.JOB_WORKSPACE_RESTRICTED,
        NamespaceId.QUARANTINE_RESTRICTED,
    }
)
_INTERNAL_CLASSIFIED_NAMESPACES = frozenset(
    {
        NamespaceId.COPY_WORK_INTERNAL,
        NamespaceId.JOB_WORKSPACE_INTERNAL,
        NamespaceId.QUARANTINE_INTERNAL,
    }
)
_EXACT_ACTOR_METADATA_NAMESPACES = _RESTRICTED_NAMESPACES | frozenset(
    {
        NamespaceId.COPY_WORK_INTERNAL,
        NamespaceId.JOB_WORKSPACE_INTERNAL,
        NamespaceId.QUARANTINE_INTERNAL,
    }
)
_FIXED_NAMESPACE_PREFIXES: dict[NamespaceId, frozenset[tuple[str, ...]]] = {
    NamespaceId.GIT_INTERNAL: frozenset({(".git",)}),
    NamespaceId.BASE_REFERENCE: frozenset({("Base",)}),
    NamespaceId.TASK_CONTROL: frozenset({("Task",)}),
    NamespaceId.COPY_SOURCE: frozenset({("Copy", "source")}),
    NamespaceId.COPY_RESTRICTED: frozenset({("Copy", "restricted")}),
    NamespaceId.COPY_WORK_INTERNAL: frozenset({("Copy", "work", "INTERNAL")}),
    NamespaceId.COPY_WORK_RESTRICTED: frozenset(
        {("Copy", "work", "RESTRICTED")}
    ),
    NamespaceId.COPY_WORK: frozenset({("Copy", "work")}),
    NamespaceId.COPY_LEDGER: frozenset({("Copy", "ledger", "events.jsonl")}),
    NamespaceId.ACTIVE_DATABASE: frozenset(
        {("data", "db", "question_bank.sqlite3")}
    ),
    NamespaceId.DATABASE_SIDECAR: frozenset(
        {
            ("data", "db", "question_bank.sqlite3-wal"),
            ("data", "db", "question_bank.sqlite3-shm"),
            ("data", "db", "question_bank.sqlite3-journal"),
        }
    ),
    NamespaceId.DATABASE_DIRECTORY: frozenset({("data", "db")}),
    NamespaceId.DATABASE_VERSION: frozenset({("data", "db", "versions")}),
    NamespaceId.ACTIVE_STATE_POINTER: frozenset(
        {("data", "db", "active-state.json")}
    ),
    NamespaceId.ORIGINAL_OBJECT: frozenset({("data", "originals")}),
    NamespaceId.DERIVED_REVISION: frozenset({("data", "derived")}),
    NamespaceId.INDEX_VERSION: frozenset({("data", "indexes")}),
    NamespaceId.TEMPLATE_REVISION: frozenset({("data", "templates")}),
    NamespaceId.EXPORT_BUNDLE: frozenset({("data", "exports")}),
    NamespaceId.SNAPSHOT: frozenset({("data", "snapshots")}),
    NamespaceId.BACKUP_SET: frozenset({("backups",)}),
    NamespaceId.AUDIT_LOG: frozenset({("logs", "audit", "events.jsonl")}),
    NamespaceId.JOB_WORKSPACE_INTERNAL: frozenset(
        {("tmp", "jobs", "INTERNAL")}
    ),
    NamespaceId.JOB_WORKSPACE_RESTRICTED: frozenset(
        {("tmp", "jobs", "RESTRICTED")}
    ),
    NamespaceId.JOB_WORKSPACE: frozenset({("tmp", "jobs")}),
    NamespaceId.QUARANTINE_INTERNAL: frozenset(
        {("data", "quarantine", "INTERNAL")}
    ),
    NamespaceId.QUARANTINE_RESTRICTED: frozenset(
        {("data", "quarantine", "RESTRICTED")}
    ),
    NamespaceId.QUARANTINE: frozenset({("data", "quarantine")}),
    NamespaceId.LEGACY_ASSET: frozenset({("data", "assets")}),
    NamespaceId.LEGACY_DB_BACKUP: frozenset({("data", "db", "backups")}),
}
_FIXED_SCOPE_BINDINGS: dict[NamespaceId, tuple[ScopeBinding, ...]] = {
    NamespaceId.COPY_SOURCE: (ScopeBinding(0, ScopeKind.COPY_ID),),
    NamespaceId.COPY_RESTRICTED: (ScopeBinding(0, ScopeKind.COPY_ID),),
    NamespaceId.COPY_WORK_INTERNAL: (
        ScopeBinding(0, ScopeKind.COPY_ID),
        ScopeBinding(1, ScopeKind.JOB_ID),
    ),
    NamespaceId.COPY_WORK_RESTRICTED: (
        ScopeBinding(0, ScopeKind.COPY_ID),
        ScopeBinding(1, ScopeKind.JOB_ID),
    ),
    NamespaceId.DATABASE_VERSION: (ScopeBinding(0, ScopeKind.STATE_ID),),
    NamespaceId.ORIGINAL_OBJECT: (ScopeBinding(0, ScopeKind.OBJECT_ID),),
    NamespaceId.DERIVED_REVISION: (
        ScopeBinding(1, ScopeKind.PIPELINE_ID),
        ScopeBinding(2, ScopeKind.OBJECT_ID),
        ScopeBinding(3, ScopeKind.REVISION_ID),
    ),
    NamespaceId.INDEX_VERSION: (ScopeBinding(0, ScopeKind.INDEX_ID),),
    NamespaceId.TEMPLATE_REVISION: (
        ScopeBinding(0, ScopeKind.OBJECT_ID),
        ScopeBinding(1, ScopeKind.REVISION_ID),
    ),
    NamespaceId.EXPORT_BUNDLE: (ScopeBinding(0, ScopeKind.EXPORT_ID),),
    NamespaceId.SNAPSHOT: (ScopeBinding(0, ScopeKind.STATE_ID),),
    NamespaceId.BACKUP_SET: (ScopeBinding(0, ScopeKind.BACKUP_ID),),
    NamespaceId.JOB_WORKSPACE_INTERNAL: (ScopeBinding(0, ScopeKind.JOB_ID),),
    NamespaceId.JOB_WORKSPACE_RESTRICTED: (ScopeBinding(0, ScopeKind.JOB_ID),),
}
_FIXED_PAIRED_DEPTHS: dict[NamespaceId, tuple[int, int]] = {
    NamespaceId.COPY_SOURCE: (1, 1),
    NamespaceId.COPY_RESTRICTED: (1, 1),
    NamespaceId.COPY_WORK_INTERNAL: (2, 4),
    NamespaceId.COPY_WORK_RESTRICTED: (2, 4),
    NamespaceId.DATABASE_VERSION: (1, 1),
    NamespaceId.ORIGINAL_OBJECT: (1, 1),
    NamespaceId.DERIVED_REVISION: (4, 4),
    NamespaceId.INDEX_VERSION: (1, 1),
    NamespaceId.TEMPLATE_REVISION: (2, 2),
    NamespaceId.EXPORT_BUNDLE: (1, 1),
    NamespaceId.SNAPSHOT: (1, 1),
    NamespaceId.BACKUP_SET: (1, 1),
    NamespaceId.JOB_WORKSPACE_INTERNAL: (1, 3),
    NamespaceId.JOB_WORKSPACE_RESTRICTED: (1, 3),
    NamespaceId.QUARANTINE_INTERNAL: (2, 2),
    NamespaceId.QUARANTINE_RESTRICTED: (2, 2),
}
_DIRECTORY_ONLY = frozenset({ExpectedKind.DIRECTORY})
_FILE_ONLY = frozenset({ExpectedKind.FILE})


def _validate_mode_contract(rule: NamespaceRule) -> None:
    allowed: dict[
        NamespaceMode,
        tuple[
            frozenset[PathIntent],
            frozenset[PathIntent],
            frozenset[ExpectedKind],
            frozenset[ExpectedKind],
        ],
    ] = {
        NamespaceMode.FORBIDDEN: (frozenset(), frozenset(), frozenset(), frozenset()),
        NamespaceMode.UNCLASSIFIED: (frozenset(), frozenset(), frozenset(), frozenset()),
        NamespaceMode.READ_ONLY: (_READ, frozenset(), frozenset(), frozenset()),
        NamespaceMode.LEGACY_READ_ONLY: (_READ, frozenset(), frozenset(), frozenset()),
        NamespaceMode.IMMUTABLE_OBJECT_STORE: (
            _READ,
            _PUBLISH_TARGET | _QUARANTINE_SOURCE,
            frozenset(),
            _DIRECTORY_ONLY,
        ),
        NamespaceMode.VERSIONED_STORE: (
            _READ,
            _PUBLISH_TARGET,
            frozenset(),
            _DIRECTORY_ONLY,
        ),
        NamespaceMode.JOB_MUTABLE: (
            _READ | _JOB_MUTATIONS,
            _JOB_PAIR_SOURCE,
            frozenset({ExpectedKind.FILE, ExpectedKind.DIRECTORY}),
            _DIRECTORY_ONLY,
        ),
        NamespaceMode.APPEND_ONLY: (
            _READ | _APPEND_FILE,
            frozenset(),
            _FILE_ONLY,
            frozenset(),
        ),
        NamespaceMode.DATABASE_CONTROLLED: (
            _READ | _FILE_MUTATIONS,
            frozenset(),
            _FILE_ONLY,
            frozenset(),
        ),
        NamespaceMode.ATOMIC_POINTER: (
            _READ,
            frozenset(),
            frozenset(),
            frozenset(),
        ),
        NamespaceMode.QUARANTINE_ONLY: (
            _READ,
            _QUARANTINE_TARGET,
            frozenset(),
            _DIRECTORY_ONLY,
        ),
    }
    normal, paired, normal_kinds, paired_kinds = allowed[rule.mode]
    if not rule.normal_intents <= normal:
        raise ValueError(f"{rule.mode.value} namespace contains an invalid normal intent")
    if not rule.paired_intents <= paired:
        raise ValueError(f"{rule.mode.value} namespace contains an invalid paired intent")
    if not rule.normal_mutation_kinds <= normal_kinds:
        raise ValueError(f"{rule.mode.value} namespace contains an invalid mutation kind")
    if not rule.paired_kinds <= paired_kinds:
        raise ValueError(f"{rule.mode.value} namespace contains an invalid paired kind")
    if not any(intent.mutating for intent in rule.normal_intents) and rule.normal_mutation_kinds:
        raise ValueError("namespace declares normal mutation kinds without a mutation intent")
    if not rule.paired_intents and rule.paired_kinds:
        raise ValueError("namespace declares paired kinds without a paired intent")
    if rule.mode in {
        NamespaceMode.APPEND_ONLY,
        NamespaceMode.DATABASE_CONTROLLED,
        NamespaceMode.ATOMIC_POINTER,
    } and (rule.minimum_tail_depth != 0 or rule.maximum_tail_depth != 0):
        raise ValueError(f"{rule.mode.value} namespace must identify one exact file")


DEFAULT_RULES: tuple[NamespaceRule, ...] = (
    NamespaceRule(
        NamespaceId.GIT_INTERNAL,
        (".git",),
        NamespaceMode.FORBIDDEN,
        audit_path_mode=AuditPathMode.HMAC_ONLY,
    ),
    NamespaceRule(
        NamespaceId.BASE_REFERENCE,
        ("Base",),
        NamespaceMode.READ_ONLY,
        minimum_tail_depth=1,
        normal_intents=_READ,
        read_callers=_REFERENCE_CALLERS,
        read_purposes=_REFERENCE_PURPOSES,
    ),
    NamespaceRule(
        NamespaceId.TASK_CONTROL,
        ("Task",),
        NamespaceMode.READ_ONLY,
        minimum_tail_depth=1,
        normal_intents=_READ,
        read_callers=frozenset({Caller.CONTROL_SERVICE, Caller.AUDIT_SERVICE}),
        read_purposes=frozenset({Purpose.READ_CONTROL}),
    ),
    NamespaceRule(
        NamespaceId.COPY_SOURCE,
        ("Copy", "source"),
        NamespaceMode.IMMUTABLE_OBJECT_STORE,
        minimum_tail_depth=1,
        object_root_depth=1,
        scope_bindings=(ScopeBinding(0, ScopeKind.COPY_ID),),
        normal_intents=_READ,
        paired_intents=_PUBLISH_TARGET,
        read_callers=frozenset(
            {Caller.IMPORT_SERVICE, Caller.ASSET_SERVICE, Caller.BACKUP_SERVICE}
        ),
        read_purposes=frozenset(
            {Purpose.READ_REFERENCE, Purpose.COPY_SOURCE, Purpose.BACKUP}
        ),
        mutation_callers=frozenset({Caller.IMPORT_SERVICE}),
        mutation_purposes=frozenset({Purpose.COPY_SOURCE}),
        paired_kinds=_DIRECTORY_ONLY,
    ),
    NamespaceRule(
        NamespaceId.COPY_RESTRICTED,
        ("Copy", "restricted"),
        NamespaceMode.IMMUTABLE_OBJECT_STORE,
        minimum_tail_depth=1,
        object_root_depth=1,
        scope_bindings=(ScopeBinding(0, ScopeKind.COPY_ID),),
        normal_intents=_READ,
        paired_intents=_PUBLISH_TARGET | _QUARANTINE_SOURCE,
        read_callers=frozenset({Caller.IMPORT_SERVICE}),
        read_purposes=frozenset({Purpose.READ_REFERENCE, Purpose.COPY_SOURCE}),
        read_actor_pairs=frozenset(
            {
                (Caller.IMPORT_SERVICE, Purpose.READ_REFERENCE),
                (Caller.IMPORT_SERVICE, Purpose.COPY_SOURCE),
            }
        ),
        mutation_callers=frozenset({Caller.IMPORT_SERVICE}),
        mutation_purposes=frozenset({Purpose.COPY_SOURCE, Purpose.QUARANTINE}),
        mutation_capabilities=frozenset(
            {
                (
                    PathIntent.MOVE_TARGET,
                    ExpectedKind.DIRECTORY,
                    Caller.IMPORT_SERVICE,
                    Purpose.COPY_SOURCE,
                ),
                (
                    PathIntent.QUARANTINE_SOURCE,
                    ExpectedKind.DIRECTORY,
                    Caller.IMPORT_SERVICE,
                    Purpose.QUARANTINE,
                ),
            }
        ),
        paired_kinds=_DIRECTORY_ONLY,
        restricted=True,
        audit_path_mode=AuditPathMode.HMAC_ONLY,
    ),
    NamespaceRule(
        NamespaceId.COPY_WORK_INTERNAL,
        ("Copy", "work", "INTERNAL"),
        NamespaceMode.JOB_MUTABLE,
        minimum_tail_depth=2,
        object_root_depth=4,
        scope_bindings=(
            ScopeBinding(0, ScopeKind.COPY_ID),
            ScopeBinding(1, ScopeKind.JOB_ID),
        ),
        normal_intents=_READ | _JOB_MUTATIONS,
        paired_intents=_JOB_PAIR_SOURCE,
        read_callers=frozenset(caller for caller, _ in _INTERNAL_JOB_ACTORS),
        read_purposes=frozenset(purpose for _, purpose in _INTERNAL_JOB_ACTORS),
        read_actor_pairs=frozenset(_INTERNAL_JOB_ACTORS),
        mutation_callers=frozenset(
            caller
            for caller, _ in (
                _INTERNAL_JOB_ACTORS
                + _QUARANTINE_ACTORS
                + _INTERNAL_COPY_MOVE_ACTORS
            )
        ),
        mutation_purposes=frozenset(
            purpose
            for _, purpose in (
                _INTERNAL_JOB_ACTORS
                + _QUARANTINE_ACTORS
                + _INTERNAL_COPY_MOVE_ACTORS
            )
        ),
        mutation_capabilities=(
            frozenset(
                (
                    intent,
                    (
                        ExpectedKind.DIRECTORY
                        if intent is PathIntent.CREATE_DIRECTORY
                        else ExpectedKind.FILE
                    ),
                    caller,
                    purpose,
                )
                for caller, purpose in _INTERNAL_JOB_ACTORS
                for intent in _JOB_MUTATIONS
            )
            | frozenset(
                (
                    PathIntent.QUARANTINE_SOURCE,
                    ExpectedKind.DIRECTORY,
                    caller,
                    purpose,
                )
                for caller, purpose in _QUARANTINE_ACTORS
            )
            | frozenset(
                (
                    PathIntent.MOVE_SOURCE,
                    ExpectedKind.DIRECTORY,
                    caller,
                    purpose,
                )
                for caller, purpose in _INTERNAL_COPY_MOVE_ACTORS
            )
        ),
        normal_mutation_kinds=frozenset(
            {ExpectedKind.FILE, ExpectedKind.DIRECTORY}
        ),
        paired_kinds=_DIRECTORY_ONLY,
    ),
    NamespaceRule(
        NamespaceId.COPY_WORK_RESTRICTED,
        ("Copy", "work", "RESTRICTED"),
        NamespaceMode.JOB_MUTABLE,
        minimum_tail_depth=2,
        object_root_depth=4,
        scope_bindings=(
            ScopeBinding(0, ScopeKind.COPY_ID),
            ScopeBinding(1, ScopeKind.JOB_ID),
        ),
        normal_intents=_READ | _JOB_MUTATIONS,
        paired_intents=_QUARANTINE_SOURCE,
        read_callers=frozenset(caller for caller, _ in _RESTRICTED_JOB_ACTORS),
        read_purposes=frozenset(purpose for _, purpose in _RESTRICTED_JOB_ACTORS),
        read_actor_pairs=frozenset(_RESTRICTED_JOB_ACTORS),
        mutation_callers=frozenset(
            caller for caller, _ in _RESTRICTED_JOB_ACTORS + _QUARANTINE_ACTORS
        ),
        mutation_purposes=frozenset(
            purpose for _, purpose in _RESTRICTED_JOB_ACTORS + _QUARANTINE_ACTORS
        ),
        mutation_capabilities=(
            frozenset(
                (
                    intent,
                    (
                        ExpectedKind.DIRECTORY
                        if intent is PathIntent.CREATE_DIRECTORY
                        else ExpectedKind.FILE
                    ),
                    caller,
                    purpose,
                )
                for caller, purpose in _RESTRICTED_JOB_ACTORS
                for intent in _JOB_MUTATIONS
            )
            | frozenset(
                (
                    PathIntent.QUARANTINE_SOURCE,
                    ExpectedKind.DIRECTORY,
                    caller,
                    purpose,
                )
                for caller, purpose in _QUARANTINE_ACTORS
            )
        ),
        normal_mutation_kinds=frozenset(
            {ExpectedKind.FILE, ExpectedKind.DIRECTORY}
        ),
        paired_kinds=_DIRECTORY_ONLY,
        restricted=True,
        audit_path_mode=AuditPathMode.HMAC_ONLY,
    ),
    NamespaceRule(
        NamespaceId.COPY_WORK,
        ("Copy", "work"),
        NamespaceMode.FORBIDDEN,
        audit_path_mode=AuditPathMode.HMAC_ONLY,
    ),
    NamespaceRule(
        NamespaceId.COPY_LEDGER,
        ("Copy", "ledger", "events.jsonl"),
        NamespaceMode.APPEND_ONLY,
        maximum_tail_depth=0,
        normal_intents=_READ | _APPEND_FILE,
        read_callers=frozenset(
            {Caller.IMPORT_SERVICE, Caller.AUDIT_SERVICE, Caller.BACKUP_SERVICE}
        ),
        read_purposes=frozenset(
            {Purpose.COPY_SOURCE, Purpose.READ_CONTROL, Purpose.BACKUP}
        ),
        mutation_callers=frozenset({Caller.IMPORT_SERVICE, Caller.AUDIT_SERVICE}),
        mutation_purposes=frozenset({Purpose.COPY_SOURCE, Purpose.APPEND_AUDIT}),
        normal_mutation_kinds=_FILE_ONLY,
    ),
    NamespaceRule(
        NamespaceId.ACTIVE_STATE_POINTER,
        ("data", "db", "active-state.json"),
        NamespaceMode.ATOMIC_POINTER,
        maximum_tail_depth=0,
        normal_intents=_READ,
        read_callers=frozenset(
            {Caller.DATABASE_SERVICE, Caller.BACKUP_SERVICE, Caller.CONTROL_SERVICE}
        ),
        read_purposes=frozenset(
            {Purpose.READ_DATABASE, Purpose.READ_CONTROL, Purpose.BACKUP, Purpose.RESTORE}
        ),
    ),
    NamespaceRule(
        NamespaceId.LEGACY_DB_BACKUP,
        ("data", "db", "backups"),
        NamespaceMode.LEGACY_READ_ONLY,
        minimum_tail_depth=1,
        normal_intents=_READ,
        read_callers=frozenset({Caller.DATABASE_SERVICE, Caller.BACKUP_SERVICE}),
        read_purposes=frozenset({Purpose.READ_DATABASE, Purpose.BACKUP, Purpose.RESTORE}),
    ),
    NamespaceRule(
        NamespaceId.DATABASE_VERSION,
        ("data", "db", "versions"),
        NamespaceMode.VERSIONED_STORE,
        minimum_tail_depth=1,
        object_root_depth=1,
        scope_bindings=(ScopeBinding(0, ScopeKind.STATE_ID),),
        normal_intents=_READ,
        paired_intents=_PUBLISH_TARGET,
        read_callers=frozenset({Caller.DATABASE_SERVICE, Caller.BACKUP_SERVICE}),
        read_purposes=frozenset(
            {Purpose.READ_DATABASE, Purpose.INITIALIZE_STATE, Purpose.BACKUP, Purpose.RESTORE}
        ),
        mutation_callers=frozenset({Caller.DATABASE_SERVICE, Caller.BACKUP_SERVICE}),
        mutation_purposes=frozenset(
            {Purpose.INITIALIZE_STATE, Purpose.BACKUP, Purpose.RESTORE}
        ),
        paired_kinds=_DIRECTORY_ONLY,
    ),
    NamespaceRule(
        NamespaceId.ACTIVE_DATABASE,
        ("data", "db", "question_bank.sqlite3"),
        NamespaceMode.DATABASE_CONTROLLED,
        maximum_tail_depth=0,
        normal_intents=_READ | _FILE_MUTATIONS,
        read_callers=frozenset({Caller.DATABASE_SERVICE}),
        read_purposes=frozenset(
            {Purpose.READ_DATABASE, Purpose.INITIALIZE_STATE, Purpose.MUTATE_DATABASE, Purpose.BACKUP}
        ),
        mutation_callers=frozenset({Caller.DATABASE_SERVICE}),
        mutation_purposes=frozenset(
            {Purpose.INITIALIZE_STATE, Purpose.MUTATE_DATABASE}
        ),
        normal_mutation_kinds=_FILE_ONLY,
    ),
    *(
        NamespaceRule(
            NamespaceId.DATABASE_SIDECAR,
            ("data", "db", f"question_bank.sqlite3{suffix}"),
            NamespaceMode.DATABASE_CONTROLLED,
            maximum_tail_depth=0,
            normal_intents=_READ | _FILE_MUTATIONS,
            read_callers=frozenset({Caller.DATABASE_SERVICE}),
            read_purposes=frozenset(
                {Purpose.READ_DATABASE, Purpose.INITIALIZE_STATE, Purpose.MUTATE_DATABASE}
            ),
            mutation_callers=frozenset({Caller.DATABASE_SERVICE}),
            mutation_purposes=frozenset(
                {Purpose.INITIALIZE_STATE, Purpose.MUTATE_DATABASE}
            ),
            normal_mutation_kinds=_FILE_ONLY,
        )
        for suffix in ("-wal", "-shm", "-journal")
    ),
    NamespaceRule(
        NamespaceId.DATABASE_DIRECTORY,
        ("data", "db"),
        NamespaceMode.FORBIDDEN,
        audit_path_mode=AuditPathMode.HMAC_ONLY,
    ),
    NamespaceRule(
        NamespaceId.ORIGINAL_OBJECT,
        ("data", "originals"),
        NamespaceMode.IMMUTABLE_OBJECT_STORE,
        minimum_tail_depth=1,
        object_root_depth=1,
        scope_bindings=(ScopeBinding(0, ScopeKind.OBJECT_ID),),
        normal_intents=_READ,
        paired_intents=_PUBLISH_TARGET,
        read_callers=_REFERENCE_CALLERS,
        read_purposes=_REFERENCE_PURPOSES,
        mutation_callers=frozenset({Caller.IMPORT_SERVICE}),
        mutation_purposes=frozenset({Purpose.COPY_SOURCE}),
        paired_kinds=_DIRECTORY_ONLY,
    ),
    NamespaceRule(
        NamespaceId.DERIVED_REVISION,
        ("data", "derived"),
        NamespaceMode.VERSIONED_STORE,
        minimum_tail_depth=4,
        object_root_depth=4,
        scope_bindings=(
            ScopeBinding(1, ScopeKind.PIPELINE_ID),
            ScopeBinding(2, ScopeKind.OBJECT_ID),
            ScopeBinding(3, ScopeKind.REVISION_ID),
        ),
        normal_intents=_READ,
        paired_intents=_PUBLISH_TARGET,
        read_callers=frozenset(
            {Caller.IMPORT_SERVICE, Caller.ASSET_SERVICE, Caller.EXPORT_SERVICE, Caller.BACKUP_SERVICE}
        ),
        read_purposes=frozenset(
            {Purpose.READ_REFERENCE, Purpose.BUILD_DERIVED, Purpose.BUILD_EXPORT, Purpose.BACKUP}
        ),
        mutation_callers=frozenset({Caller.IMPORT_SERVICE, Caller.ASSET_SERVICE}),
        mutation_purposes=frozenset({Purpose.BUILD_DERIVED}),
        paired_kinds=_DIRECTORY_ONLY,
    ),
    NamespaceRule(
        NamespaceId.INDEX_VERSION,
        ("data", "indexes"),
        NamespaceMode.VERSIONED_STORE,
        minimum_tail_depth=1,
        object_root_depth=1,
        scope_bindings=(ScopeBinding(0, ScopeKind.INDEX_ID),),
        normal_intents=_READ,
        paired_intents=_PUBLISH_TARGET,
        read_callers=frozenset({Caller.DATABASE_SERVICE, Caller.BACKUP_SERVICE}),
        read_purposes=frozenset({Purpose.READ_DATABASE, Purpose.BUILD_DERIVED, Purpose.BACKUP}),
        mutation_callers=frozenset({Caller.DATABASE_SERVICE}),
        mutation_purposes=frozenset({Purpose.BUILD_DERIVED}),
        paired_kinds=_DIRECTORY_ONLY,
    ),
    NamespaceRule(
        NamespaceId.TEMPLATE_REVISION,
        ("data", "templates"),
        NamespaceMode.VERSIONED_STORE,
        minimum_tail_depth=2,
        object_root_depth=2,
        scope_bindings=(
            ScopeBinding(0, ScopeKind.OBJECT_ID),
            ScopeBinding(1, ScopeKind.REVISION_ID),
        ),
        normal_intents=_READ,
        paired_intents=_PUBLISH_TARGET,
        read_callers=frozenset({Caller.EXPORT_SERVICE, Caller.BACKUP_SERVICE}),
        read_purposes=frozenset({Purpose.BUILD_EXPORT, Purpose.BACKUP, Purpose.RESTORE}),
        mutation_callers=frozenset({Caller.EXPORT_SERVICE}),
        mutation_purposes=frozenset({Purpose.BUILD_EXPORT}),
        paired_kinds=_DIRECTORY_ONLY,
    ),
    NamespaceRule(
        NamespaceId.EXPORT_BUNDLE,
        ("data", "exports"),
        NamespaceMode.VERSIONED_STORE,
        minimum_tail_depth=1,
        object_root_depth=1,
        scope_bindings=(ScopeBinding(0, ScopeKind.EXPORT_ID),),
        normal_intents=_READ,
        paired_intents=_PUBLISH_TARGET,
        read_callers=frozenset(
            {Caller.EXPORT_SERVICE, Caller.REPORT_SERVICE, Caller.BACKUP_SERVICE}
        ),
        read_purposes=frozenset({Purpose.BUILD_EXPORT, Purpose.BACKUP, Purpose.RESTORE}),
        mutation_callers=frozenset({Caller.EXPORT_SERVICE}),
        mutation_purposes=frozenset({Purpose.BUILD_EXPORT}),
        paired_kinds=_DIRECTORY_ONLY,
    ),
    NamespaceRule(
        NamespaceId.SNAPSHOT,
        ("data", "snapshots"),
        NamespaceMode.VERSIONED_STORE,
        minimum_tail_depth=1,
        object_root_depth=1,
        scope_bindings=(ScopeBinding(0, ScopeKind.STATE_ID),),
        normal_intents=_READ,
        paired_intents=_PUBLISH_TARGET,
        read_callers=frozenset({Caller.DATABASE_SERVICE, Caller.BACKUP_SERVICE}),
        read_purposes=frozenset({Purpose.BACKUP, Purpose.RESTORE, Purpose.READ_DATABASE}),
        mutation_callers=frozenset({Caller.DATABASE_SERVICE, Caller.BACKUP_SERVICE}),
        mutation_purposes=frozenset({Purpose.BACKUP, Purpose.RESTORE}),
        paired_kinds=_DIRECTORY_ONLY,
    ),
    NamespaceRule(
        NamespaceId.BACKUP_SET,
        ("backups",),
        NamespaceMode.VERSIONED_STORE,
        minimum_tail_depth=1,
        object_root_depth=1,
        scope_bindings=(ScopeBinding(0, ScopeKind.BACKUP_ID),),
        normal_intents=_READ,
        paired_intents=_PUBLISH_TARGET,
        read_callers=frozenset({Caller.BACKUP_SERVICE}),
        read_purposes=frozenset({Purpose.BACKUP, Purpose.RESTORE}),
        mutation_callers=frozenset({Caller.BACKUP_SERVICE}),
        mutation_purposes=frozenset({Purpose.BACKUP}),
        paired_kinds=_DIRECTORY_ONLY,
    ),
    NamespaceRule(
        NamespaceId.AUDIT_LOG,
        ("logs", "audit", "events.jsonl"),
        NamespaceMode.APPEND_ONLY,
        maximum_tail_depth=0,
        normal_intents=_READ | _APPEND_FILE,
        read_callers=frozenset(
            {Caller.AUDIT_SERVICE, Caller.REPORT_SERVICE, Caller.BACKUP_SERVICE}
        ),
        read_purposes=frozenset(
            {Purpose.APPEND_AUDIT, Purpose.READ_CONTROL, Purpose.BACKUP}
        ),
        mutation_callers=frozenset({Caller.AUDIT_SERVICE}),
        mutation_purposes=frozenset({Purpose.APPEND_AUDIT}),
        normal_mutation_kinds=_FILE_ONLY,
        audit_path_mode=AuditPathMode.HMAC_ONLY,
    ),
    NamespaceRule(
        NamespaceId.JOB_WORKSPACE_INTERNAL,
        ("tmp", "jobs", "INTERNAL"),
        NamespaceMode.JOB_MUTABLE,
        minimum_tail_depth=1,
        object_root_depth=3,
        scope_bindings=(ScopeBinding(0, ScopeKind.JOB_ID),),
        normal_intents=_READ | _JOB_MUTATIONS,
        paired_intents=_JOB_PAIR_SOURCE,
        read_callers=frozenset(caller for caller, _ in _INTERNAL_JOB_ACTORS),
        read_purposes=frozenset(purpose for _, purpose in _INTERNAL_JOB_ACTORS),
        read_actor_pairs=frozenset(_INTERNAL_JOB_ACTORS),
        mutation_callers=frozenset(
            caller
            for caller, _ in (
                _INTERNAL_JOB_ACTORS
                + _QUARANTINE_ACTORS
                + _INTERNAL_JOB_MOVE_ACTORS
            )
        ),
        mutation_purposes=frozenset(
            purpose
            for _, purpose in (
                _INTERNAL_JOB_ACTORS
                + _QUARANTINE_ACTORS
                + _INTERNAL_JOB_MOVE_ACTORS
            )
        ),
        mutation_capabilities=(
            frozenset(
                (
                    intent,
                    (
                        ExpectedKind.DIRECTORY
                        if intent is PathIntent.CREATE_DIRECTORY
                        else ExpectedKind.FILE
                    ),
                    caller,
                    purpose,
                )
                for caller, purpose in _INTERNAL_JOB_ACTORS
                for intent in _JOB_MUTATIONS
            )
            | frozenset(
                (
                    PathIntent.QUARANTINE_SOURCE,
                    ExpectedKind.DIRECTORY,
                    caller,
                    purpose,
                )
                for caller, purpose in _QUARANTINE_ACTORS
            )
            | frozenset(
                (
                    PathIntent.MOVE_SOURCE,
                    ExpectedKind.DIRECTORY,
                    caller,
                    purpose,
                )
                for caller, purpose in _INTERNAL_JOB_MOVE_ACTORS
            )
        ),
        normal_mutation_kinds=frozenset(
            {ExpectedKind.FILE, ExpectedKind.DIRECTORY}
        ),
        paired_kinds=_DIRECTORY_ONLY,
    ),
    NamespaceRule(
        NamespaceId.JOB_WORKSPACE_RESTRICTED,
        ("tmp", "jobs", "RESTRICTED"),
        NamespaceMode.JOB_MUTABLE,
        minimum_tail_depth=1,
        object_root_depth=3,
        scope_bindings=(ScopeBinding(0, ScopeKind.JOB_ID),),
        normal_intents=_READ | _JOB_MUTATIONS,
        paired_intents=_JOB_PAIR_SOURCE,
        read_callers=frozenset(caller for caller, _ in _RESTRICTED_JOB_ACTORS),
        read_purposes=frozenset(purpose for _, purpose in _RESTRICTED_JOB_ACTORS),
        read_actor_pairs=frozenset(_RESTRICTED_JOB_ACTORS),
        mutation_callers=frozenset(
            caller for caller, _ in _RESTRICTED_JOB_ACTORS + _QUARANTINE_ACTORS
        ),
        mutation_purposes=frozenset(
            purpose for _, purpose in _RESTRICTED_JOB_ACTORS + _QUARANTINE_ACTORS
        ),
        mutation_capabilities=(
            frozenset(
                (
                    intent,
                    (
                        ExpectedKind.DIRECTORY
                        if intent is PathIntent.CREATE_DIRECTORY
                        else ExpectedKind.FILE
                    ),
                    caller,
                    purpose,
                )
                for caller, purpose in _RESTRICTED_JOB_ACTORS
                for intent in _JOB_MUTATIONS
            )
            | frozenset(
                (
                    PathIntent.QUARANTINE_SOURCE,
                    ExpectedKind.DIRECTORY,
                    caller,
                    purpose,
                )
                for caller, purpose in _QUARANTINE_ACTORS
            )
            | frozenset(
                {
                    (
                        PathIntent.MOVE_SOURCE,
                        ExpectedKind.DIRECTORY,
                        Caller.IMPORT_SERVICE,
                        Purpose.COPY_SOURCE,
                    )
                }
            )
        ),
        normal_mutation_kinds=frozenset(
            {ExpectedKind.FILE, ExpectedKind.DIRECTORY}
        ),
        paired_kinds=_DIRECTORY_ONLY,
        restricted=True,
        audit_path_mode=AuditPathMode.HMAC_ONLY,
    ),
    NamespaceRule(
        NamespaceId.JOB_WORKSPACE,
        ("tmp", "jobs"),
        NamespaceMode.FORBIDDEN,
        audit_path_mode=AuditPathMode.HMAC_ONLY,
    ),
    NamespaceRule(
        NamespaceId.QUARANTINE_INTERNAL,
        ("data", "quarantine", "INTERNAL"),
        NamespaceMode.QUARANTINE_ONLY,
        minimum_tail_depth=2,
        object_root_depth=2,
        normal_intents=_READ,
        paired_intents=_QUARANTINE_TARGET,
        read_callers=frozenset(
            caller for caller, _ in _INTERNAL_QUARANTINE_READ_ACTORS
        ),
        read_purposes=frozenset(
            purpose for _, purpose in _INTERNAL_QUARANTINE_READ_ACTORS
        ),
        read_actor_pairs=frozenset(_INTERNAL_QUARANTINE_READ_ACTORS),
        mutation_callers=frozenset(caller for caller, _ in _QUARANTINE_ACTORS),
        mutation_purposes=frozenset({Purpose.QUARANTINE}),
        mutation_capabilities=frozenset(
            (
                PathIntent.QUARANTINE_TARGET,
                ExpectedKind.DIRECTORY,
                caller,
                purpose,
            )
            for caller, purpose in _QUARANTINE_ACTORS
        ),
        paired_kinds=_DIRECTORY_ONLY,
        audit_path_mode=AuditPathMode.HMAC_ONLY,
    ),
    NamespaceRule(
        NamespaceId.QUARANTINE_RESTRICTED,
        ("data", "quarantine", "RESTRICTED"),
        NamespaceMode.QUARANTINE_ONLY,
        minimum_tail_depth=2,
        object_root_depth=2,
        normal_intents=_READ,
        paired_intents=_QUARANTINE_TARGET,
        read_callers=frozenset({Caller.AUDIT_SERVICE, Caller.CONTROL_SERVICE}),
        read_purposes=frozenset({Purpose.QUARANTINE, Purpose.READ_CONTROL}),
        read_actor_pairs=frozenset(
            {
                (Caller.AUDIT_SERVICE, Purpose.QUARANTINE),
                (Caller.AUDIT_SERVICE, Purpose.READ_CONTROL),
                (Caller.CONTROL_SERVICE, Purpose.READ_CONTROL),
            }
        ),
        mutation_callers=frozenset(caller for caller, _ in _QUARANTINE_ACTORS),
        mutation_purposes=frozenset({Purpose.QUARANTINE}),
        mutation_capabilities=frozenset(
            (
                PathIntent.QUARANTINE_TARGET,
                ExpectedKind.DIRECTORY,
                caller,
                purpose,
            )
            for caller, purpose in _QUARANTINE_ACTORS
        ),
        paired_kinds=_DIRECTORY_ONLY,
        restricted=True,
        audit_path_mode=AuditPathMode.HMAC_ONLY,
    ),
    NamespaceRule(
        NamespaceId.QUARANTINE,
        ("data", "quarantine"),
        NamespaceMode.FORBIDDEN,
        audit_path_mode=AuditPathMode.HMAC_ONLY,
    ),
    NamespaceRule(
        NamespaceId.LEGACY_ASSET,
        ("data", "assets"),
        NamespaceMode.LEGACY_READ_ONLY,
        minimum_tail_depth=1,
        normal_intents=_READ,
        read_callers=_REFERENCE_CALLERS,
        read_purposes=_REFERENCE_PURPOSES,
    ),
)


@dataclass(frozen=True, slots=True)
class CapabilityGrant:
    namespace: NamespaceId
    intent: PathIntent
    expected_kind: ExpectedKind
    caller: Caller
    purpose: Purpose
    paired: bool = False
    required_scopes: frozenset[ScopeKind] = frozenset()

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "namespace": self.namespace.value,
            "intent": self.intent.value,
            "expected_kind": self.expected_kind.value,
            "caller": self.caller.value,
            "purpose": self.purpose.value,
            "paired": self.paired,
            "required_scopes": sorted(scope.value for scope in self.required_scopes),
        }


def _grants(
    namespace: NamespaceId,
    actors: tuple[tuple[Caller, Purpose], ...],
    intent_kinds: tuple[tuple[PathIntent, ExpectedKind], ...],
    *,
    paired: bool = False,
    required_scopes: frozenset[ScopeKind] = frozenset(),
) -> tuple[CapabilityGrant, ...]:
    return tuple(
        CapabilityGrant(
            namespace=namespace,
            intent=intent,
            expected_kind=kind,
            caller=caller,
            purpose=purpose,
            paired=paired,
            required_scopes=required_scopes,
        )
        for caller, purpose in actors
        for intent, kind in intent_kinds
    )


_READ_ANY = ((PathIntent.EXISTING_READ, ExpectedKind.ANY),)
_FILE_WRITE = (
    (PathIntent.NEW_WRITE, ExpectedKind.FILE),
    (PathIntent.EXISTING_WRITE, ExpectedKind.FILE),
)
_APPEND_WRITE = (
    (PathIntent.NEW_WRITE, ExpectedKind.FILE),
    (PathIntent.APPEND_EXISTING, ExpectedKind.FILE),
)
_JOB_WRITE = (
    (PathIntent.NEW_WRITE, ExpectedKind.FILE),
    (PathIntent.EXISTING_WRITE, ExpectedKind.FILE),
    (PathIntent.APPEND_EXISTING, ExpectedKind.FILE),
    (PathIntent.CREATE_DIRECTORY, ExpectedKind.DIRECTORY),
)
_PUBLISH_DIRECTORY = ((PathIntent.MOVE_TARGET, ExpectedKind.DIRECTORY),)
_PAIR_SOURCE_DIRECTORY = (
    (PathIntent.MOVE_SOURCE, ExpectedKind.DIRECTORY),
    (PathIntent.QUARANTINE_SOURCE, ExpectedKind.DIRECTORY),
)
_QUARANTINE_SOURCE_DIRECTORY = (
    (PathIntent.QUARANTINE_SOURCE, ExpectedKind.DIRECTORY),
)
_QUARANTINE_TARGET_DIRECTORY = (
    (PathIntent.QUARANTINE_TARGET, ExpectedKind.DIRECTORY),
)

_REFERENCE_ACTORS = (
    (Caller.IMPORT_SERVICE, Purpose.READ_REFERENCE),
    (Caller.IMPORT_SERVICE, Purpose.COPY_SOURCE),
    (Caller.ASSET_SERVICE, Purpose.READ_REFERENCE),
    (Caller.ASSET_SERVICE, Purpose.BUILD_DERIVED),
    (Caller.EXPORT_SERVICE, Purpose.READ_REFERENCE),
    (Caller.EXPORT_SERVICE, Purpose.BUILD_EXPORT),
    (Caller.REPORT_SERVICE, Purpose.READ_REFERENCE),
    (Caller.REPORT_SERVICE, Purpose.BUILD_EXPORT),
    (Caller.BACKUP_SERVICE, Purpose.BACKUP),
    (Caller.BACKUP_SERVICE, Purpose.RESTORE),
)
_JOB_ACTORS = _INTERNAL_JOB_ACTORS
EXACT_GRANTS: tuple[CapabilityGrant, ...] = (
    *_grants(NamespaceId.BASE_REFERENCE, _REFERENCE_ACTORS, _READ_ANY),
    *_grants(
        NamespaceId.TASK_CONTROL,
        (
            (Caller.CONTROL_SERVICE, Purpose.READ_CONTROL),
            (Caller.AUDIT_SERVICE, Purpose.READ_CONTROL),
        ),
        _READ_ANY,
    ),
    *_grants(
        NamespaceId.COPY_SOURCE,
        (
            (Caller.IMPORT_SERVICE, Purpose.READ_REFERENCE),
            (Caller.IMPORT_SERVICE, Purpose.COPY_SOURCE),
            (Caller.ASSET_SERVICE, Purpose.READ_REFERENCE),
            (Caller.BACKUP_SERVICE, Purpose.BACKUP),
        ),
        _READ_ANY,
    ),
    *_grants(
        NamespaceId.COPY_SOURCE,
        ((Caller.IMPORT_SERVICE, Purpose.COPY_SOURCE),),
        _PUBLISH_DIRECTORY,
        paired=True,
    ),
    *_grants(
        NamespaceId.COPY_RESTRICTED,
        (
            (Caller.IMPORT_SERVICE, Purpose.READ_REFERENCE),
            (Caller.IMPORT_SERVICE, Purpose.COPY_SOURCE),
        ),
        _READ_ANY,
    ),
    *_grants(
        NamespaceId.COPY_RESTRICTED,
        ((Caller.IMPORT_SERVICE, Purpose.COPY_SOURCE),),
        _PUBLISH_DIRECTORY,
        paired=True,
    ),
    *_grants(
        NamespaceId.COPY_RESTRICTED,
        ((Caller.IMPORT_SERVICE, Purpose.QUARANTINE),),
        _QUARANTINE_SOURCE_DIRECTORY,
        paired=True,
    ),
    *(
        grant
        for namespace in (
            NamespaceId.COPY_WORK_INTERNAL,
            NamespaceId.JOB_WORKSPACE_INTERNAL,
        )
        for grant in (
            *_grants(namespace, _JOB_ACTORS, _READ_ANY),
            *_grants(namespace, _JOB_ACTORS, _JOB_WRITE),
            *_grants(
                namespace,
                _QUARANTINE_ACTORS,
                _QUARANTINE_SOURCE_DIRECTORY,
                paired=True,
            ),
        )
    ),
    *(
        grant
        for namespace in (
            NamespaceId.COPY_WORK_RESTRICTED,
            NamespaceId.JOB_WORKSPACE_RESTRICTED,
        )
        for grant in (
            *_grants(namespace, _RESTRICTED_JOB_ACTORS, _READ_ANY),
            *_grants(namespace, _RESTRICTED_JOB_ACTORS, _JOB_WRITE),
            *_grants(
                namespace,
                _QUARANTINE_ACTORS,
                _QUARANTINE_SOURCE_DIRECTORY,
                paired=True,
            ),
        )
    ),
    *_grants(
        NamespaceId.JOB_WORKSPACE_INTERNAL,
        (
            (Caller.IMPORT_SERVICE, Purpose.COPY_SOURCE),
            (Caller.IMPORT_SERVICE, Purpose.BUILD_DERIVED),
            (Caller.DATABASE_SERVICE, Purpose.INITIALIZE_STATE),
            (Caller.DATABASE_SERVICE, Purpose.BUILD_DERIVED),
            (Caller.ASSET_SERVICE, Purpose.BUILD_DERIVED),
            (Caller.EXPORT_SERVICE, Purpose.BUILD_EXPORT),
            (Caller.BACKUP_SERVICE, Purpose.BACKUP),
            (Caller.BACKUP_SERVICE, Purpose.RESTORE),
        ),
        ((PathIntent.MOVE_SOURCE, ExpectedKind.DIRECTORY),),
        paired=True,
    ),
    *_grants(
        NamespaceId.COPY_WORK_INTERNAL,
        ((Caller.IMPORT_SERVICE, Purpose.COPY_SOURCE),),
        ((PathIntent.MOVE_SOURCE, ExpectedKind.DIRECTORY),),
        paired=True,
    ),
    *_grants(
        NamespaceId.JOB_WORKSPACE_RESTRICTED,
        ((Caller.IMPORT_SERVICE, Purpose.COPY_SOURCE),),
        ((PathIntent.MOVE_SOURCE, ExpectedKind.DIRECTORY),),
        paired=True,
    ),
    *_grants(
        NamespaceId.COPY_LEDGER,
        (
            (Caller.IMPORT_SERVICE, Purpose.COPY_SOURCE),
            (Caller.AUDIT_SERVICE, Purpose.READ_CONTROL),
            (Caller.BACKUP_SERVICE, Purpose.BACKUP),
        ),
        _READ_ANY,
    ),
    *_grants(
        NamespaceId.COPY_LEDGER,
        (
            (Caller.IMPORT_SERVICE, Purpose.COPY_SOURCE),
            (Caller.AUDIT_SERVICE, Purpose.APPEND_AUDIT),
        ),
        _APPEND_WRITE,
        required_scopes=frozenset({ScopeKind.COPY_ID}),
    ),
    *_grants(
        NamespaceId.ACTIVE_STATE_POINTER,
        (
            (Caller.DATABASE_SERVICE, Purpose.READ_DATABASE),
            (Caller.CONTROL_SERVICE, Purpose.READ_CONTROL),
            (Caller.BACKUP_SERVICE, Purpose.BACKUP),
            (Caller.BACKUP_SERVICE, Purpose.RESTORE),
        ),
        _READ_ANY,
    ),
    *_grants(
        NamespaceId.LEGACY_DB_BACKUP,
        (
            (Caller.DATABASE_SERVICE, Purpose.READ_DATABASE),
            (Caller.BACKUP_SERVICE, Purpose.BACKUP),
            (Caller.BACKUP_SERVICE, Purpose.RESTORE),
        ),
        _READ_ANY,
    ),
    *_grants(
        NamespaceId.DATABASE_VERSION,
        (
            (Caller.DATABASE_SERVICE, Purpose.READ_DATABASE),
            (Caller.DATABASE_SERVICE, Purpose.INITIALIZE_STATE),
            (Caller.BACKUP_SERVICE, Purpose.BACKUP),
            (Caller.BACKUP_SERVICE, Purpose.RESTORE),
        ),
        _READ_ANY,
    ),
    *_grants(
        NamespaceId.DATABASE_VERSION,
        (
            (Caller.DATABASE_SERVICE, Purpose.INITIALIZE_STATE),
            (Caller.BACKUP_SERVICE, Purpose.BACKUP),
            (Caller.BACKUP_SERVICE, Purpose.RESTORE),
        ),
        _PUBLISH_DIRECTORY,
        paired=True,
    ),
    *_grants(
        NamespaceId.ACTIVE_DATABASE,
        (
            (Caller.DATABASE_SERVICE, Purpose.READ_DATABASE),
            (Caller.DATABASE_SERVICE, Purpose.INITIALIZE_STATE),
            (Caller.DATABASE_SERVICE, Purpose.MUTATE_DATABASE),
            (Caller.DATABASE_SERVICE, Purpose.BACKUP),
        ),
        _READ_ANY,
    ),
    *_grants(
        NamespaceId.ACTIVE_DATABASE,
        (
            (Caller.DATABASE_SERVICE, Purpose.INITIALIZE_STATE),
            (Caller.DATABASE_SERVICE, Purpose.MUTATE_DATABASE),
        ),
        _FILE_WRITE,
    ),
    *_grants(
        NamespaceId.DATABASE_SIDECAR,
        (
            (Caller.DATABASE_SERVICE, Purpose.READ_DATABASE),
            (Caller.DATABASE_SERVICE, Purpose.INITIALIZE_STATE),
            (Caller.DATABASE_SERVICE, Purpose.MUTATE_DATABASE),
        ),
        _READ_ANY,
    ),
    *_grants(
        NamespaceId.DATABASE_SIDECAR,
        (
            (Caller.DATABASE_SERVICE, Purpose.INITIALIZE_STATE),
            (Caller.DATABASE_SERVICE, Purpose.MUTATE_DATABASE),
        ),
        _FILE_WRITE,
    ),
    *_grants(NamespaceId.ORIGINAL_OBJECT, _REFERENCE_ACTORS, _READ_ANY),
    *_grants(
        NamespaceId.ORIGINAL_OBJECT,
        ((Caller.IMPORT_SERVICE, Purpose.COPY_SOURCE),),
        _PUBLISH_DIRECTORY,
        paired=True,
    ),
    *_grants(
        NamespaceId.DERIVED_REVISION,
        (
            (Caller.IMPORT_SERVICE, Purpose.BUILD_DERIVED),
            (Caller.ASSET_SERVICE, Purpose.BUILD_DERIVED),
            (Caller.EXPORT_SERVICE, Purpose.BUILD_EXPORT),
            (Caller.BACKUP_SERVICE, Purpose.BACKUP),
        ),
        _READ_ANY,
    ),
    *_grants(
        NamespaceId.DERIVED_REVISION,
        (
            (Caller.IMPORT_SERVICE, Purpose.BUILD_DERIVED),
            (Caller.ASSET_SERVICE, Purpose.BUILD_DERIVED),
        ),
        _PUBLISH_DIRECTORY,
        paired=True,
    ),
    *_grants(
        NamespaceId.INDEX_VERSION,
        (
            (Caller.DATABASE_SERVICE, Purpose.READ_DATABASE),
            (Caller.DATABASE_SERVICE, Purpose.BUILD_DERIVED),
            (Caller.BACKUP_SERVICE, Purpose.BACKUP),
        ),
        _READ_ANY,
    ),
    *_grants(
        NamespaceId.INDEX_VERSION,
        ((Caller.DATABASE_SERVICE, Purpose.BUILD_DERIVED),),
        _PUBLISH_DIRECTORY,
        paired=True,
    ),
    *_grants(
        NamespaceId.TEMPLATE_REVISION,
        (
            (Caller.EXPORT_SERVICE, Purpose.BUILD_EXPORT),
            (Caller.BACKUP_SERVICE, Purpose.BACKUP),
            (Caller.BACKUP_SERVICE, Purpose.RESTORE),
        ),
        _READ_ANY,
    ),
    *_grants(
        NamespaceId.TEMPLATE_REVISION,
        ((Caller.EXPORT_SERVICE, Purpose.BUILD_EXPORT),),
        _PUBLISH_DIRECTORY,
        paired=True,
    ),
    *_grants(
        NamespaceId.EXPORT_BUNDLE,
        (
            (Caller.EXPORT_SERVICE, Purpose.BUILD_EXPORT),
            (Caller.REPORT_SERVICE, Purpose.BUILD_EXPORT),
            (Caller.BACKUP_SERVICE, Purpose.BACKUP),
            (Caller.BACKUP_SERVICE, Purpose.RESTORE),
        ),
        _READ_ANY,
    ),
    *_grants(
        NamespaceId.EXPORT_BUNDLE,
        ((Caller.EXPORT_SERVICE, Purpose.BUILD_EXPORT),),
        _PUBLISH_DIRECTORY,
        paired=True,
    ),
    *_grants(
        NamespaceId.SNAPSHOT,
        (
            (Caller.DATABASE_SERVICE, Purpose.READ_DATABASE),
            (Caller.DATABASE_SERVICE, Purpose.BACKUP),
            (Caller.BACKUP_SERVICE, Purpose.BACKUP),
            (Caller.BACKUP_SERVICE, Purpose.RESTORE),
        ),
        _READ_ANY,
    ),
    *_grants(
        NamespaceId.SNAPSHOT,
        (
            (Caller.BACKUP_SERVICE, Purpose.BACKUP),
            (Caller.BACKUP_SERVICE, Purpose.RESTORE),
        ),
        _PUBLISH_DIRECTORY,
        paired=True,
    ),
    *_grants(
        NamespaceId.BACKUP_SET,
        (
            (Caller.BACKUP_SERVICE, Purpose.BACKUP),
            (Caller.BACKUP_SERVICE, Purpose.RESTORE),
        ),
        _READ_ANY,
    ),
    *_grants(
        NamespaceId.BACKUP_SET,
        ((Caller.BACKUP_SERVICE, Purpose.BACKUP),),
        _PUBLISH_DIRECTORY,
        paired=True,
    ),
    *_grants(
        NamespaceId.AUDIT_LOG,
        (
            (Caller.AUDIT_SERVICE, Purpose.APPEND_AUDIT),
            (Caller.AUDIT_SERVICE, Purpose.READ_CONTROL),
            (Caller.REPORT_SERVICE, Purpose.READ_CONTROL),
            (Caller.BACKUP_SERVICE, Purpose.BACKUP),
        ),
        _READ_ANY,
    ),
    *_grants(
        NamespaceId.AUDIT_LOG,
        ((Caller.AUDIT_SERVICE, Purpose.APPEND_AUDIT),),
        _APPEND_WRITE,
        required_scopes=frozenset({ScopeKind.RUN_ID, ScopeKind.OPERATION_ID}),
    ),
    *_grants(
        NamespaceId.QUARANTINE_INTERNAL,
        (
            (Caller.AUDIT_SERVICE, Purpose.QUARANTINE),
            (Caller.AUDIT_SERVICE, Purpose.READ_CONTROL),
            (Caller.BACKUP_SERVICE, Purpose.RESTORE),
            (Caller.CONTROL_SERVICE, Purpose.READ_CONTROL),
        ),
        _READ_ANY,
    ),
    *_grants(
        NamespaceId.QUARANTINE_RESTRICTED,
        (
            (Caller.AUDIT_SERVICE, Purpose.QUARANTINE),
            (Caller.AUDIT_SERVICE, Purpose.READ_CONTROL),
            (Caller.CONTROL_SERVICE, Purpose.READ_CONTROL),
        ),
        _READ_ANY,
    ),
    *(
        grant
        for namespace in (
            NamespaceId.QUARANTINE_INTERNAL,
            NamespaceId.QUARANTINE_RESTRICTED,
        )
        for grant in _grants(
            namespace,
            _QUARANTINE_ACTORS,
            _QUARANTINE_TARGET_DIRECTORY,
            paired=True,
        )
    ),
    *_grants(NamespaceId.LEGACY_ASSET, _REFERENCE_ACTORS, _READ_ANY),
)


_FIXED_REQUIRED_SCOPES: dict[
    tuple[NamespaceId, bool, PathIntent, ExpectedKind, Caller, Purpose],
    frozenset[ScopeKind],
] = {
    (
        NamespaceId.COPY_LEDGER,
        False,
        intent,
        ExpectedKind.FILE,
        caller,
        purpose,
    ): frozenset({ScopeKind.COPY_ID})
    for intent in (PathIntent.NEW_WRITE, PathIntent.APPEND_EXISTING)
    for caller, purpose in (
        (Caller.IMPORT_SERVICE, Purpose.COPY_SOURCE),
        (Caller.AUDIT_SERVICE, Purpose.APPEND_AUDIT),
    )
}
_FIXED_REQUIRED_SCOPES.update(
    {
        (
            NamespaceId.AUDIT_LOG,
            False,
            intent,
            ExpectedKind.FILE,
            Caller.AUDIT_SERVICE,
            Purpose.APPEND_AUDIT,
        ): frozenset({ScopeKind.RUN_ID, ScopeKind.OPERATION_ID})
        for intent in (PathIntent.NEW_WRITE, PathIntent.APPEND_EXISTING)
    }
)


@dataclass(frozen=True, slots=True)
class NamespaceDecision:
    rule: NamespaceRule
    relative_path: Path
    tail: tuple[str, ...]

    @property
    def namespace(self) -> NamespaceId:
        return self.rule.namespace

    @property
    def effective_classification(self) -> DataClassification:
        return (
            DataClassification.RESTRICTED
            if self.rule.restricted
            else DataClassification.INTERNAL
        )


def _validate_namespace_rule_types(rule: object) -> None:
    if type(rule) is not NamespaceRule:
        raise ValueError("namespace rules must be exact NamespaceRule values")
    if type(rule.namespace) is not NamespaceId:
        raise ValueError("namespace rule namespace must be an exact NamespaceId")
    if type(rule.prefix) is not tuple or any(
        type(component) is not str for component in rule.prefix
    ):
        raise ValueError("namespace rule prefix must be an exact tuple of strings")
    if type(rule.mode) is not NamespaceMode:
        raise ValueError("namespace rule mode must be an exact NamespaceMode")
    if type(rule.minimum_tail_depth) is not int:
        raise ValueError("namespace rule minimum depth must be an exact integer")
    if rule.maximum_tail_depth is not None and type(rule.maximum_tail_depth) is not int:
        raise ValueError("namespace rule maximum depth must be an exact integer or None")
    if rule.object_root_depth is not None and type(rule.object_root_depth) is not int:
        raise ValueError("namespace rule object depth must be an exact integer or None")
    if type(rule.scope_bindings) is not tuple or any(
        type(binding) is not ScopeBinding
        or type(binding.tail_index) is not int
        or type(binding.scope_kind) is not ScopeKind
        for binding in rule.scope_bindings
    ):
        raise ValueError("namespace rule scope bindings must use exact policy types")
    exact_sets: tuple[tuple[object, type[object], str], ...] = (
        (rule.normal_intents, PathIntent, "normal intents"),
        (rule.paired_intents, PathIntent, "paired intents"),
        (rule.read_callers, Caller, "read callers"),
        (rule.read_purposes, Purpose, "read purposes"),
        (rule.mutation_callers, Caller, "mutation callers"),
        (rule.mutation_purposes, Purpose, "mutation purposes"),
        (rule.normal_mutation_kinds, ExpectedKind, "normal mutation kinds"),
        (rule.paired_kinds, ExpectedKind, "paired kinds"),
    )
    for values, expected_type, field_name in exact_sets:
        if type(values) is not frozenset or any(
            type(item) is not expected_type for item in values
        ):
            raise ValueError(
                f"namespace rule {field_name} must be an exact frozenset of policy enums"
            )
    if type(rule.read_actor_pairs) is not frozenset or any(
        type(pair) is not tuple
        or len(pair) != 2
        or type(pair[0]) is not Caller
        or type(pair[1]) is not Purpose
        for pair in rule.read_actor_pairs
    ):
        raise ValueError("namespace rule read actor pairs must use exact policy types")
    if type(rule.mutation_capabilities) is not frozenset or any(
        type(capability) is not tuple
        or len(capability) != 4
        or type(capability[0]) is not PathIntent
        or type(capability[1]) is not ExpectedKind
        or type(capability[2]) is not Caller
        or type(capability[3]) is not Purpose
        for capability in rule.mutation_capabilities
    ):
        raise ValueError(
            "namespace rule mutation capabilities must use exact policy types"
        )
    if type(rule.restricted) is not bool:
        raise ValueError("namespace rule restricted flag must be an exact bool")
    if type(rule.audit_path_mode) is not AuditPathMode:
        raise ValueError("namespace rule audit mode must be an exact AuditPathMode")


def _validate_capability_grant_types(grant: object) -> None:
    if type(grant) is not CapabilityGrant:
        raise ValueError("capability grants must be exact CapabilityGrant values")
    if (
        type(grant.namespace) is not NamespaceId
        or type(grant.intent) is not PathIntent
        or type(grant.expected_kind) is not ExpectedKind
        or type(grant.caller) is not Caller
        or type(grant.purpose) is not Purpose
        or type(grant.paired) is not bool
        or type(grant.required_scopes) is not frozenset
        or any(type(scope) is not ScopeKind for scope in grant.required_scopes)
    ):
        raise ValueError("capability grant fields must use exact policy types")


def _clone_namespace_rule(rule: NamespaceRule) -> NamespaceRule:
    return NamespaceRule(
        namespace=rule.namespace,
        prefix=tuple(component for component in rule.prefix),
        mode=rule.mode,
        minimum_tail_depth=rule.minimum_tail_depth,
        maximum_tail_depth=rule.maximum_tail_depth,
        object_root_depth=rule.object_root_depth,
        scope_bindings=tuple(
            ScopeBinding(binding.tail_index, binding.scope_kind)
            for binding in rule.scope_bindings
        ),
        normal_intents=frozenset(item for item in rule.normal_intents),
        paired_intents=frozenset(item for item in rule.paired_intents),
        read_callers=frozenset(item for item in rule.read_callers),
        read_purposes=frozenset(item for item in rule.read_purposes),
        read_actor_pairs=frozenset(
            (caller, purpose) for caller, purpose in rule.read_actor_pairs
        ),
        mutation_callers=frozenset(item for item in rule.mutation_callers),
        mutation_purposes=frozenset(item for item in rule.mutation_purposes),
        mutation_capabilities=frozenset(
            (intent, kind, caller, purpose)
            for intent, kind, caller, purpose in rule.mutation_capabilities
        ),
        normal_mutation_kinds=frozenset(
            item for item in rule.normal_mutation_kinds
        ),
        paired_kinds=frozenset(item for item in rule.paired_kinds),
        restricted=rule.restricted,
        audit_path_mode=rule.audit_path_mode,
    )


def _clone_capability_grant(grant: CapabilityGrant) -> CapabilityGrant:
    return CapabilityGrant(
        namespace=grant.namespace,
        intent=grant.intent,
        expected_kind=grant.expected_kind,
        caller=grant.caller,
        purpose=grant.purpose,
        paired=grant.paired,
        required_scopes=frozenset(scope for scope in grant.required_scopes),
    )


def _policy_digest(
    rules: tuple[NamespaceRule, ...],
    grants: tuple[CapabilityGrant, ...],
) -> str:
    canonical = json.dumps(
        {
            "rules": [rule.to_canonical_dict() for rule in rules],
            "grants": [grant.to_canonical_dict() for grant in grants],
        },
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(canonical).hexdigest()


class NamespacePolicy:
    def __init__(
        self,
        rules: tuple[NamespaceRule, ...] = DEFAULT_RULES,
        grants: tuple[CapabilityGrant, ...] = EXACT_GRANTS,
    ) -> None:
        if type(rules) is not tuple:
            raise ValueError("namespace policy rules must be an exact tuple")
        if type(grants) is not tuple:
            raise ValueError("namespace policy grants must be an exact tuple")
        if not rules:
            raise ValueError("namespace policy requires at least one rule")
        for rule in rules:
            _validate_namespace_rule_types(rule)
        for grant in grants:
            _validate_capability_grant_types(grant)
        if len(set(grants)) != len(grants):
            raise ValueError("namespace capability grants cannot be duplicated")
        seen: set[tuple[str, ...]] = set()
        for rule in rules:
            if type(rule.mode) is not NamespaceMode:
                raise ValueError("namespace rule mode must be an exact NamespaceMode")
            if type(rule.prefix) is not tuple or not rule.prefix or any(
                type(component) is not str or not component
                for component in rule.prefix
            ):
                raise ValueError("namespace rule prefixes cannot be empty")
            fixed_prefixes = _FIXED_NAMESPACE_PREFIXES.get(rule.namespace)
            if fixed_prefixes is None or rule.prefix not in fixed_prefixes:
                raise ValueError(
                    "namespace prefix is fixed by policy"
                )
            if rule.minimum_tail_depth < 0:
                raise ValueError("minimum_tail_depth cannot be negative")
            if (
                rule.maximum_tail_depth is not None
                and rule.maximum_tail_depth < rule.minimum_tail_depth
            ):
                raise ValueError("maximum_tail_depth is smaller than minimum_tail_depth")
            if rule.object_root_depth is not None and rule.object_root_depth < 0:
                raise ValueError("object_root_depth cannot be negative")
            binding_indices = [binding.tail_index for binding in rule.scope_bindings]
            binding_kinds = [binding.scope_kind for binding in rule.scope_bindings]
            if any(index < 0 for index in binding_indices):
                raise ValueError("scope binding indices cannot be negative")
            if len(binding_indices) != len(set(binding_indices)) or len(binding_kinds) != len(
                set(binding_kinds)
            ):
                raise ValueError("scope bindings cannot duplicate an index or scope kind")
            if any(index >= rule.minimum_tail_depth for index in binding_indices):
                raise ValueError("scope bindings must exist at minimum namespace depth")
            if rule.object_root_depth is not None and (
                rule.object_root_depth < rule.minimum_tail_depth
                or (
                    rule.maximum_tail_depth is not None
                    and rule.object_root_depth > rule.maximum_tail_depth
                )
            ):
                raise ValueError("object_root_depth must lie within namespace depth bounds")
            expected_bindings = _FIXED_SCOPE_BINDINGS.get(rule.namespace, ())
            if rule.scope_bindings != expected_bindings:
                raise ValueError("namespace scope bindings are fixed by policy")
            expected_depths = _FIXED_PAIRED_DEPTHS.get(rule.namespace)
            if expected_depths is not None and (
                rule.minimum_tail_depth,
                rule.object_root_depth,
            ) != expected_depths:
                raise ValueError("paired namespace depths are fixed by policy")
            if rule.normal_intents & rule.paired_intents:
                raise ValueError("normal and paired intents cannot overlap")
            if rule.restricted and rule.audit_path_mode is not AuditPathMode.HMAC_ONLY:
                raise ValueError("restricted namespaces require HMAC-only audit paths")
            if rule.restricted is not (rule.namespace in _RESTRICTED_NAMESPACES):
                raise ValueError(
                    "namespace restricted classification contradicts its fixed partition"
                )
            if rule.namespace in _INTERNAL_CLASSIFIED_NAMESPACES and rule.restricted:
                raise ValueError("internal classified namespace cannot be restricted")
            if any(
                type(caller) is not Caller or type(purpose) is not Purpose
                for caller, purpose in rule.read_actor_pairs
            ):
                raise ValueError("read actor pairs must use exact enum values")
            if rule.read_actor_pairs and (
                rule.read_callers
                != frozenset(caller for caller, _ in rule.read_actor_pairs)
                or rule.read_purposes
                != frozenset(purpose for _, purpose in rule.read_actor_pairs)
            ):
                raise ValueError(
                    "read caller/purpose projections exceed exact actor pairs"
                )
            if any(
                type(intent) is not PathIntent
                or type(kind) is not ExpectedKind
                or type(caller) is not Caller
                or type(purpose) is not Purpose
                for intent, kind, caller, purpose in rule.mutation_capabilities
            ):
                raise ValueError("mutation capabilities must use exact enum values")
            if rule.mutation_capabilities and (
                rule.mutation_callers
                != frozenset(
                    caller
                    for _, _, caller, _ in rule.mutation_capabilities
                )
                or rule.mutation_purposes
                != frozenset(
                    purpose
                    for _, _, _, purpose in rule.mutation_capabilities
                )
            ):
                raise ValueError(
                    "mutation caller/purpose projections exceed exact capabilities"
                )
            for intent, kind, _caller, _purpose in rule.mutation_capabilities:
                if intent in rule.paired_intents:
                    allowed_kinds = rule.paired_kinds
                elif intent in rule.normal_intents and intent.mutating:
                    allowed_kinds = rule.normal_mutation_kinds
                else:
                    raise ValueError(
                        "mutation capability references an undeclared mutation intent"
                    )
                if kind not in allowed_kinds:
                    raise ValueError(
                        "mutation capability kind contradicts its namespace intent"
                    )
            if (
                rule.namespace in _EXACT_ACTOR_METADATA_NAMESPACES
                and PathIntent.EXISTING_READ in rule.normal_intents
                and not rule.read_actor_pairs
            ):
                raise ValueError("namespace requires exact read actor pairs")
            if rule.namespace in _EXACT_ACTOR_METADATA_NAMESPACES and (
                any(intent.mutating for intent in rule.normal_intents)
                or rule.paired_intents
            ) and not rule.mutation_capabilities:
                raise ValueError("namespace requires exact mutation capabilities")
            if rule.paired_intents and (
                rule.object_root_depth is None or not rule.paired_kinds
            ):
                raise ValueError("paired namespace capabilities require root depth and kinds")
            if any(intent.mutating for intent in rule.normal_intents) and not rule.normal_mutation_kinds:
                raise ValueError("normal mutation capabilities require explicit kinds")
            if rule.mode in {NamespaceMode.READ_ONLY, NamespaceMode.LEGACY_READ_ONLY} and (
                any(intent.mutating for intent in rule.normal_intents)
                or rule.paired_intents
            ):
                raise ValueError("read-only namespace contains a mutation capability")
            if rule.mode in {NamespaceMode.FORBIDDEN, NamespaceMode.UNCLASSIFIED} and (
                rule.normal_intents or rule.paired_intents
            ):
                raise ValueError("forbidden or unclassified namespace contains capabilities")
            if rule.mode is NamespaceMode.APPEND_ONLY and (
                any(
                    intent.mutating
                    and intent not in {PathIntent.NEW_WRITE, PathIntent.APPEND_EXISTING}
                    for intent in rule.normal_intents
                )
                or rule.paired_intents
                or any(
                    kind is not ExpectedKind.FILE
                    for kind in rule.normal_mutation_kinds
                )
            ):
                raise ValueError("append-only namespace contains a non-append capability")
            _validate_mode_contract(rule)
            if rule.normalized_prefix in seen:
                raise ValueError(f"duplicate namespace prefix: {rule.prefix!r}")
            seen.add(rule.normalized_prefix)
        observed_namespace_prefixes = {
            (rule.namespace, rule.prefix) for rule in rules
        }
        expected_namespace_prefixes = {
            (namespace, prefix)
            for namespace, prefixes in _FIXED_NAMESPACE_PREFIXES.items()
            for prefix in prefixes
        }
        if observed_namespace_prefixes != expected_namespace_prefixes:
            raise ValueError("namespace rule set does not match the fixed policy topology")
        self._rules = tuple(
            _clone_namespace_rule(rule)
            for rule in sorted(
                rules,
                key=lambda item: (-len(item.prefix), item.normalized_prefix),
            )
        )
        self._grants = tuple(
            _clone_capability_grant(grant)
            for grant in sorted(
                grants,
                key=lambda item: (
                    item.namespace.value,
                    item.paired,
                    item.intent.value,
                    item.expected_kind.value,
                    item.caller.value,
                    item.purpose.value,
                    tuple(
                        scope.value
                        for scope in sorted(
                            item.required_scopes,
                            key=lambda value: value.value,
                        )
                    ),
                ),
            )
        )
        self.__paired_seal: object | None = None
        rule_by_namespace: dict[NamespaceId, list[NamespaceRule]] = {}
        for rule in self._rules:
            rule_by_namespace.setdefault(rule.namespace, []).append(rule)
        for grant in self._grants:
            scope_key = (
                grant.namespace,
                grant.paired,
                grant.intent,
                grant.expected_kind,
                grant.caller,
                grant.purpose,
            )
            expected_scopes = _FIXED_REQUIRED_SCOPES.get(scope_key, frozenset())
            if grant.required_scopes != expected_scopes:
                raise ValueError(
                    "capability grant required scopes contradict the fixed policy"
                )
            candidates = rule_by_namespace.get(grant.namespace, [])
            matching = tuple(
                rule
                for rule in candidates
                if grant.intent
                in (rule.paired_intents if grant.paired else rule.normal_intents)
            )
            if not matching:
                raise ValueError(
                    f"capability grant has no matching namespace intent: {grant!r}"
                )
            valid_match = False
            for rule in matching:
                if grant.paired or grant.intent.mutating:
                    allowed_callers = rule.mutation_callers
                    allowed_purposes = rule.mutation_purposes
                    allowed_capabilities = rule.mutation_capabilities
                    allowed_kinds = (
                        rule.paired_kinds
                        if grant.paired
                        else rule.normal_mutation_kinds
                    )
                else:
                    allowed_callers = rule.read_callers
                    allowed_purposes = rule.read_purposes
                    allowed_capabilities = frozenset()
                    allowed_kinds = frozenset({ExpectedKind.ANY})
                if (
                    grant.caller in allowed_callers
                    and grant.purpose in allowed_purposes
                    and (
                        (
                            not grant.intent.mutating
                            and not grant.paired
                            and (
                                not rule.read_actor_pairs
                                or (grant.caller, grant.purpose)
                                in rule.read_actor_pairs
                            )
                        )
                        or (
                            (grant.intent.mutating or grant.paired)
                            and (
                                not allowed_capabilities
                                or (
                                    grant.intent,
                                    grant.expected_kind,
                                    grant.caller,
                                    grant.purpose,
                                )
                                in allowed_capabilities
                            )
                        )
                    )
                    and grant.expected_kind in allowed_kinds
                ):
                    valid_match = True
                    break
            if not valid_match:
                raise ValueError(
                    "capability grant contradicts namespace actor, purpose, or kind constraints"
                )
        grant_keys = {
            (grant.namespace, grant.paired, grant.intent) for grant in self._grants
        }
        for rule in self._rules:
            if rule.mode in {NamespaceMode.FORBIDDEN, NamespaceMode.UNCLASSIFIED}:
                continue
            for intent in rule.normal_intents:
                if (rule.namespace, False, intent) not in grant_keys:
                    raise ValueError(
                        f"namespace normal capability has no exact grant: {rule.namespace}/{intent}"
                    )
            for intent in rule.paired_intents:
                if (rule.namespace, True, intent) not in grant_keys:
                    raise ValueError(
                        f"namespace paired capability has no exact grant: {rule.namespace}/{intent}"
                    )
        for rule in self._rules:
            if rule.namespace not in _EXACT_ACTOR_METADATA_NAMESPACES:
                continue
            actual_read_pairs = frozenset(
                (grant.caller, grant.purpose)
                for grant in self._grants
                if grant.namespace is rule.namespace
                and not grant.paired
                and grant.intent is PathIntent.EXISTING_READ
            )
            actual_mutation_capabilities = frozenset(
                (
                    grant.intent,
                    grant.expected_kind,
                    grant.caller,
                    grant.purpose,
                )
                for grant in self._grants
                if grant.namespace is rule.namespace
                and (grant.paired or grant.intent.mutating)
            )
            if actual_read_pairs != rule.read_actor_pairs:
                raise ValueError(
                    "namespace read actor metadata does not equal exact grants"
                )
            if actual_mutation_capabilities != rule.mutation_capabilities:
                raise ValueError(
                    "namespace mutation metadata does not equal exact grants"
                )
        if frozenset(self._grants) != frozenset(EXACT_GRANTS):
            raise ValueError("namespace capability grant set is fixed by policy")
        self._digest = _policy_digest(self._rules, self._grants)
        if self._digest != EXPECTED_POLICY_DIGEST:
            raise ValueError("namespace policy digest differs from the reviewed policy")

    def _assert_integrity(self) -> None:
        try:
            if type(self._rules) is not tuple or type(self._grants) is not tuple:
                raise ValueError("policy storage containers changed type")
            for rule in self._rules:
                _validate_namespace_rule_types(rule)
            for grant in self._grants:
                _validate_capability_grant_types(grant)
            current = _policy_digest(self._rules, self._grants)
        except Exception as exc:
            raise PolicyIntegrityError(
                "namespace policy integrity cannot be recomputed"
            ) from exc
        if current != self._digest:
            raise PolicyIntegrityError("namespace policy changed after construction")

    @property
    def rules(self) -> tuple[NamespaceRule, ...]:
        self._assert_integrity()
        return tuple(_clone_namespace_rule(rule) for rule in self._rules)

    @property
    def digest(self) -> str:
        self._assert_integrity()
        return self._digest

    @property
    def grants(self) -> tuple[CapabilityGrant, ...]:
        self._assert_integrity()
        return tuple(_clone_capability_grant(grant) for grant in self._grants)

    def classify(self, relative_path: Path) -> NamespaceDecision:
        self._assert_integrity()
        components = _relative_components(relative_path)
        normalized = tuple(ntpath.normcase(component) for component in components)
        for rule in self._rules:
            prefix = rule.normalized_prefix
            if len(normalized) >= len(prefix) and normalized[: len(prefix)] == prefix:
                return NamespaceDecision(
                    rule=_clone_namespace_rule(rule),
                    relative_path=relative_path,
                    tail=components[len(prefix) :],
                )
        fallback = NamespaceRule(
            NamespaceId.UNCLASSIFIED,
            ("<unclassified>",),
            NamespaceMode.UNCLASSIFIED,
            audit_path_mode=AuditPathMode.HMAC_ONLY,
        )
        return NamespaceDecision(fallback, relative_path, components)

    def authorize(
        self,
        ticket: GuardedPath,
        context: OperationContext,
    ) -> NamespaceDecision:
        if ticket.intent in {
            PathIntent.MOVE_SOURCE,
            PathIntent.MOVE_TARGET,
            PathIntent.QUARANTINE_SOURCE,
            PathIntent.QUARANTINE_TARGET,
        }:
            decision = self.classify(ticket.relative_path)
            self._reject(
                PolicyErrorCode.PAIR_AUTHORIZATION_REQUIRED,
                ticket,
                decision,
                "move and quarantine intents require the boundary pair API",
            )
        return self.__authorize(ticket, context)

    def _install_boundary_pair_seal(self, seal: object) -> None:
        from . import production_guard as boundary_module

        boundary_policy_type = getattr(
            boundary_module,
            "_BoundaryNamespacePolicy",
            None,
        )
        if type(self) is not boundary_policy_type:
            raise PermissionError("pair seal installation is boundary-only")
        if self.__paired_seal is not None or seal is None:
            raise PermissionError("pair seal installation is one-time")
        self.__paired_seal = seal

    def __authorize(
        self,
        ticket: GuardedPath,
        context: OperationContext,
        *,
        pair_seal: object | None = None,
    ) -> NamespaceDecision:
        self._assert_integrity()
        if type(ticket) is not GuardedPath or type(context) is not OperationContext:
            raise TypeError("policy requires GuardedPath and OperationContext values")
        decision = self.classify(ticket.relative_path)
        if pair_seal is not None and (
            self.__paired_seal is None or pair_seal is not self.__paired_seal
        ):
            self._reject(
                PolicyErrorCode.PAIR_AUTHORIZATION_REQUIRED,
                ticket,
                decision,
                "paired policy mode is sealed inside the production boundary",
            )
        paired = pair_seal is not None and pair_seal is self.__paired_seal
        rule = decision.rule
        if rule.mode is NamespaceMode.FORBIDDEN:
            self._reject(
                PolicyErrorCode.FORBIDDEN_NAMESPACE,
                ticket,
                decision,
                "product runtime cannot access this namespace",
            )
        if rule.mode is NamespaceMode.UNCLASSIFIED:
            code = (
                PolicyErrorCode.UNCLASSIFIED_MUTATION
                if ticket.intent.mutating
                else PolicyErrorCode.UNCLASSIFIED_ACCESS
            )
            self._reject(code, ticket, decision, "unclassified paths are denied")
        if rule.restricted and context.classification is not DataClassification.RESTRICTED:
            self._reject(
                PolicyErrorCode.RESTRICTED_CONTEXT_REQUIRED,
                ticket,
                decision,
                "restricted namespace requires a restricted operation context",
            )
        if rule.namespace in {
            NamespaceId.COPY_WORK_INTERNAL,
            NamespaceId.JOB_WORKSPACE_INTERNAL,
            NamespaceId.QUARANTINE_INTERNAL,
        } and context.classification is not DataClassification.INTERNAL:
            self._reject(
                PolicyErrorCode.CLASSIFICATION_MISMATCH,
                ticket,
                decision,
                "restricted context cannot access an internal classified partition",
            )
        if (
            ticket.intent.mutating
            and rule.namespace
            in {NamespaceId.ACTIVE_DATABASE, NamespaceId.DATABASE_SIDECAR}
            and context.classification is not DataClassification.INTERNAL
        ):
            self._reject(
                PolicyErrorCode.CLASSIFICATION_MISMATCH,
                ticket,
                decision,
                "restricted context cannot mutate the internal active database",
            )
        if len(decision.tail) < rule.minimum_tail_depth:
            self._reject(
                PolicyErrorCode.MINIMUM_DEPTH,
                ticket,
                decision,
                "target is shallower than the namespace boundary",
            )
        if (
            rule.maximum_tail_depth is not None
            and len(decision.tail) > rule.maximum_tail_depth
        ):
            self._reject(
                PolicyErrorCode.MAXIMUM_DEPTH,
                ticket,
                decision,
                "target is deeper than the exact namespace boundary",
            )
        self._validate_scope_bindings(ticket, context, decision)

        allowed_intents = rule.paired_intents if paired else rule.normal_intents
        if ticket.intent not in allowed_intents:
            self._reject(
                PolicyErrorCode.PROTECTED_NAMESPACE,
                ticket,
                decision,
                "operation is not allowed by the namespace capability",
            )
        if paired:
            if rule.object_root_depth is None or len(decision.tail) != rule.object_root_depth:
                self._reject(
                    PolicyErrorCode.OBJECT_ROOT_REQUIRED,
                    ticket,
                    decision,
                    "paired operations require the exact namespace object root",
                )
            if ticket.expected_kind not in rule.paired_kinds:
                self._reject(
                    PolicyErrorCode.EXPECTED_KIND_REQUIRED,
                    ticket,
                    decision,
                    "paired operation requires an explicit allowed object kind",
                )
        elif ticket.intent.mutating:
            if ticket.expected_kind not in rule.normal_mutation_kinds:
                self._reject(
                    PolicyErrorCode.EXPECTED_KIND_REQUIRED,
                    ticket,
                    decision,
                    "mutation requires an explicit allowed object kind",
                )

        self._validate_exact_grant(ticket, context, decision, paired=paired)
        return decision

    def _validate_exact_grant(
        self,
        ticket: GuardedPath,
        context: OperationContext,
        decision: NamespaceDecision,
        *,
        paired: bool,
    ) -> None:
        candidates = tuple(
            grant
            for grant in self._grants
            if grant.namespace is decision.namespace
            and grant.paired is paired
            and grant.intent is ticket.intent
        )
        caller_candidates = tuple(
            grant for grant in candidates if grant.caller is context.caller
        )
        if not caller_candidates:
            self._reject(
                PolicyErrorCode.CALLER_NOT_ALLOWED,
                ticket,
                decision,
                "caller is not allowed for this exact capability",
            )
        purpose_candidates = tuple(
            grant for grant in caller_candidates if grant.purpose is context.purpose
        )
        if not purpose_candidates:
            self._reject(
                PolicyErrorCode.PURPOSE_NOT_ALLOWED,
                ticket,
                decision,
                "caller and purpose combination is not allowed",
            )
        kind_candidates = tuple(
            grant
            for grant in purpose_candidates
            if grant.expected_kind is ExpectedKind.ANY
            or grant.expected_kind is ticket.expected_kind
        )
        if not kind_candidates:
            self._reject(
                PolicyErrorCode.EXPECTED_KIND_REQUIRED,
                ticket,
                decision,
                "expected kind is not allowed for this exact capability",
            )
        for grant in kind_candidates:
            if all(context.scope_value(scope) is not None for scope in grant.required_scopes):
                return
        self._reject(
            PolicyErrorCode.SCOPE_REQUIRED,
            ticket,
            decision,
            "the exact capability requires additional operation scopes",
        )

    @staticmethod
    def _validate_scope_bindings(
        ticket: GuardedPath,
        context: OperationContext,
        decision: NamespaceDecision,
    ) -> None:
        for binding in decision.rule.scope_bindings:
            expected = context.scope_value(binding.scope_kind)
            if expected is None:
                NamespacePolicy._reject(
                    PolicyErrorCode.SCOPE_REQUIRED,
                    ticket,
                    decision,
                    f"{binding.scope_kind.value} scope is required",
                )
            if binding.tail_index >= len(decision.tail):
                NamespacePolicy._reject(
                    PolicyErrorCode.MINIMUM_DEPTH,
                    ticket,
                    decision,
                    "scope-bound path component is missing",
                )
            actual = decision.tail[binding.tail_index]
            if ntpath.normcase(actual) != ntpath.normcase(expected):
                NamespacePolicy._reject(
                    PolicyErrorCode.SCOPE_MISMATCH,
                    ticket,
                    decision,
                    f"path component does not match {binding.scope_kind.value} scope",
                )

    @staticmethod
    def _reject(
        code: PolicyErrorCode,
        ticket: GuardedPath,
        decision: NamespaceDecision,
        message: str,
    ) -> None:
        raise NamespacePolicyError(
            code,
            namespace=decision.namespace,
            intent=ticket.intent,
            message=message,
        )


def _relative_components(relative_path: Path) -> tuple[str, ...]:
    text = str(relative_path)
    if text in {"", "."}:
        return ()
    pure = PureWindowsPath(text)
    return tuple(part for part in pure.parts if part not in {"", "."})
