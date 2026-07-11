from __future__ import annotations

import hashlib
import hmac
import json
import ntpath
import re
import secrets
import threading
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path, PureWindowsPath
from typing import Any, NoReturn

from app.safety.context import DataClassification, validate_safe_id
from app.safety.segment_ledger import AuditKeyRevision, canonical_json_bytes
from app.safety.windows_handle_writer import (
    HandleWriterCode,
    HandleWriterError,
    RuntimeMutexLease,
    _WindowsHandleWriter,
)


_OPERATION_LEDGER_CONSTRUCTOR = object()
_SEGMENT_ROOT = Path("logs") / "operations" / "segments"
_SEGMENT_FILE = re.compile(
    r"^(?P<sequence>[0-9]{20})-(?P<sha>[0-9a-f]{64})\.json$"
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_UTC_SECONDS = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_MAX_SEGMENTS = 4096
_MAX_SEGMENT_BYTES = 512 * 1024
_MAX_TRANSITION_SEGMENT_BYTES = 64 * 1024
_MAX_LEDGER_BYTES = 64 * 1024 * 1024
_TRANSACTION_SEGMENT_RESERVATION = 5
RECOVERY_GUARANTEE_SCOPE = "COOPERATIVE_APPLICATION_WRITERS_ONLY"


class OperationLedgerCode(StrEnum):
    INVALID_REQUEST = "INVALID_REQUEST"
    MUTEX_INVALID = "MUTEX_INVALID"
    UNKNOWN_ENTRY = "UNKNOWN_ENTRY"
    CHAIN_CORRUPT = "CHAIN_CORRUPT"
    AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"
    TRANSITION_CONFLICT = "TRANSITION_CONFLICT"
    ILLEGAL_TRANSITION = "ILLEGAL_TRANSITION"
    RESOURCE_LIMIT = "RESOURCE_LIMIT"
    STORAGE_FAILURE = "STORAGE_FAILURE"
    RECOVERY_CONTRADICTION = "RECOVERY_CONTRADICTION"
    LEDGER_SEALED = "LEDGER_SEALED"


class OperationLedgerError(RuntimeError):
    def __init__(self, code: OperationLedgerCode, message: str) -> None:
        self.code = code
        super().__init__(f"{code.value}: {message}")

    def __repr__(self) -> str:
        return f"OperationLedgerError(code='{self.code.value}', details='<redacted>')"


def _raise_without_context(error: OperationLedgerError) -> NoReturn:
    error.__traceback__ = None
    error.__context__ = None
    error.__cause__ = None
    error.__suppress_context__ = True
    raise error from None


class OperationState(StrEnum):
    PREPARED = "PREPARED"
    ABORTED = "ABORTED"
    MUTATED = "MUTATED"
    POSTCONDITION_VERIFIED = "POSTCONDITION_VERIFIED"
    COMMITTED = "COMMITTED"
    IN_DOUBT = "IN_DOUBT"
    RECOVERED_COMMIT = "RECOVERED_COMMIT"
    RECOVERED_ABORT = "RECOVERED_ABORT"


class OperationCompletionKind(StrEnum):
    NATIVE_COMMIT = "NATIVE_COMMIT"
    RECOVERED_COMMIT_WITH_NATIVE_MUTATION = "RECOVERED_COMMIT_WITH_NATIVE_MUTATION"
    RECOVERED_COMMIT_OBSERVATION_ONLY = "RECOVERED_COMMIT_OBSERVATION_ONLY"


_TERMINAL_STATES = frozenset(
    {
        OperationState.ABORTED,
        OperationState.COMMITTED,
        OperationState.RECOVERED_ABORT,
        OperationState.RECOVERED_COMMIT,
    }
)
_ALLOWED_TRANSITIONS: frozenset[tuple[OperationState | None, OperationState]] = (
    frozenset(
        {
            (None, OperationState.PREPARED),
            (OperationState.PREPARED, OperationState.ABORTED),
            (OperationState.PREPARED, OperationState.MUTATED),
            (OperationState.PREPARED, OperationState.IN_DOUBT),
            (OperationState.MUTATED, OperationState.POSTCONDITION_VERIFIED),
            (OperationState.MUTATED, OperationState.IN_DOUBT),
            (OperationState.POSTCONDITION_VERIFIED, OperationState.COMMITTED),
            (OperationState.POSTCONDITION_VERIFIED, OperationState.IN_DOUBT),
            (OperationState.IN_DOUBT, OperationState.RECOVERED_COMMIT),
            (OperationState.IN_DOUBT, OperationState.RECOVERED_ABORT),
            (OperationState.PREPARED, OperationState.RECOVERED_COMMIT),
            (OperationState.PREPARED, OperationState.RECOVERED_ABORT),
            (OperationState.MUTATED, OperationState.RECOVERED_COMMIT),
            (OperationState.POSTCONDITION_VERIFIED, OperationState.RECOVERED_COMMIT),
        }
    )
)


def _now_utc_seconds() -> str:
    return datetime.now(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _validate_utc_seconds(value: str) -> str:
    if type(value) is not str or not _UTC_SECONDS.fullmatch(value):
        raise OperationLedgerError(
            OperationLedgerCode.INVALID_REQUEST,
            "transition time must use canonical UTC seconds",
        )
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError:
        raise OperationLedgerError(
            OperationLedgerCode.INVALID_REQUEST,
            "transition time is not a real UTC instant",
        ) from None
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise OperationLedgerError(
            OperationLedgerCode.INVALID_REQUEST,
            "transition time is not canonical",
        )
    return value


def _require_sha256(value: str, field_name: str) -> str:
    if type(value) is not str or not _SHA256.fullmatch(value):
        raise OperationLedgerError(
            OperationLedgerCode.INVALID_REQUEST,
            f"{field_name} must be a canonical lowercase SHA-256 digest",
        )
    return value


def _decode_ascii_json(payload: bytes) -> Any:
    return json.loads(
        payload.decode("ascii", "strict"),
        parse_float=lambda _value: (_ for _ in ()).throw(ValueError()),
        parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
    )


def _safe_relative(value: str, field_name: str) -> str:
    if type(value) is not str or not value or len(value.encode("utf-8")) > 2048:
        raise OperationLedgerError(
            OperationLedgerCode.INVALID_REQUEST,
            f"{field_name} must be a bounded project-relative locator",
        )
    pure = PureWindowsPath(value.replace("/", "\\"))
    if (
        pure.is_absolute()
        or pure.drive
        or pure.root
        or any(part in {"", ".", ".."} for part in pure.parts)
        or ":" in value
        or "\0" in value
    ):
        raise OperationLedgerError(
            OperationLedgerCode.INVALID_REQUEST,
            f"{field_name} is not a safe project-relative locator",
        )
    canonical = "/".join(pure.parts)
    if canonical != value:
        raise OperationLedgerError(
            OperationLedgerCode.INVALID_REQUEST,
            f"{field_name} must use canonical forward-slash form",
        )
    return canonical


@dataclass(frozen=True, slots=True)
class OperationTreeEvidence:
    manifest_sha256: str
    source_tree_sha256: str
    topology_sha256: str
    durable_identity_sha256: str
    entry_count: int
    total_bytes: int

    def __post_init__(self) -> None:
        for name in (
            "manifest_sha256",
            "source_tree_sha256",
            "topology_sha256",
            "durable_identity_sha256",
        ):
            _require_sha256(getattr(self, name), name)
        if type(self.entry_count) is not int or self.entry_count < 1:
            raise OperationLedgerError(
                OperationLedgerCode.INVALID_REQUEST,
                "operation tree evidence requires a positive entry count",
            )
        if type(self.total_bytes) is not int or self.total_bytes < 0:
            raise OperationLedgerError(
                OperationLedgerCode.INVALID_REQUEST,
                "operation tree evidence requires non-negative bytes",
            )

    @property
    def digest(self) -> str:
        return hashlib.sha256(
            b"OPERATION-TREE-EVIDENCE-V1\0" + canonical_json_bytes(self.to_json())
        ).hexdigest()

    def to_json(self) -> dict[str, Any]:
        return {
            "durable_identity_sha256": self.durable_identity_sha256,
            "entry_count": self.entry_count,
            "manifest_sha256": self.manifest_sha256,
            "source_tree_sha256": self.source_tree_sha256,
            "topology_sha256": self.topology_sha256,
            "total_bytes": self.total_bytes,
        }


@dataclass(frozen=True, slots=True)
class OperationTransition:
    transition_id: str
    transaction_id: str
    operation_id: str
    pair_id: str
    previous_state: OperationState | None
    next_state: OperationState
    context_binding_sha256: str
    manifest_sha256: str
    budget_sha256: str
    source_locator: str
    target_locator: str
    source_evidence: OperationTreeEvidence
    target_evidence: OperationTreeEvidence | None
    audit_ledger_head_sha256: str
    mutation_attempted: bool
    native_mutation_receipt_sha256: str | None = None
    recovery_observation_receipt_sha256: str | None = None
    completion_kind: OperationCompletionKind | None = None
    recovery_guarantee_scope: str | None = None
    recovery_authority_head_sha256: str | None = None
    error_code: str | None = None
    recovery_reason: str | None = None
    classification: DataClassification = DataClassification.INTERNAL

    def __post_init__(self) -> None:
        for name in ("transition_id", "transaction_id", "operation_id", "pair_id"):
            try:
                validate_safe_id(getattr(self, name), field_name=name)
            except Exception:
                raise OperationLedgerError(
                    OperationLedgerCode.INVALID_REQUEST,
                    f"{name} is not a canonical safe identifier",
                ) from None
        if (
            (self.previous_state, self.next_state) not in _ALLOWED_TRANSITIONS
            or type(self.next_state) is not OperationState
            or (self.previous_state is not None and type(self.previous_state) is not OperationState)
        ):
            raise OperationLedgerError(
                OperationLedgerCode.ILLEGAL_TRANSITION,
                "operation state transition is not allowed",
            )
        for name in (
            "context_binding_sha256",
            "manifest_sha256",
            "budget_sha256",
            "audit_ledger_head_sha256",
        ):
            _require_sha256(getattr(self, name), name)
        if self.native_mutation_receipt_sha256 is not None:
            _require_sha256(
                self.native_mutation_receipt_sha256,
                "native_mutation_receipt_sha256",
            )
        if self.recovery_observation_receipt_sha256 is not None:
            _require_sha256(
                self.recovery_observation_receipt_sha256,
                "recovery_observation_receipt_sha256",
            )
        if self.recovery_authority_head_sha256 is not None:
            _require_sha256(
                self.recovery_authority_head_sha256,
                "recovery_authority_head_sha256",
            )
        if self.completion_kind is not None and type(self.completion_kind) is not OperationCompletionKind:
            raise OperationLedgerError(
                OperationLedgerCode.INVALID_REQUEST,
                "operation completion kind is not exact",
            )
        _safe_relative(self.source_locator, "source_locator")
        _safe_relative(self.target_locator, "target_locator")
        if (
            type(self.source_evidence) is not OperationTreeEvidence
            or (
                self.target_evidence is not None
                and type(self.target_evidence) is not OperationTreeEvidence
            )
            or type(self.mutation_attempted) is not bool
            or type(self.classification) is not DataClassification
            or self.classification is not DataClassification.INTERNAL
        ):
            raise OperationLedgerError(
                OperationLedgerCode.INVALID_REQUEST,
                "S3-E operation transitions require exact INTERNAL evidence values",
            )
        if self.error_code is not None:
            try:
                validate_safe_id(self.error_code, field_name="error_code")
            except Exception:
                raise OperationLedgerError(
                    OperationLedgerCode.INVALID_REQUEST,
                    "operation error code is not canonical",
                ) from None
        if self.recovery_reason is not None:
            try:
                validate_safe_id(self.recovery_reason, field_name="recovery_reason")
            except Exception:
                raise OperationLedgerError(
                    OperationLedgerCode.INVALID_REQUEST,
                    "operation recovery reason is not canonical",
                ) from None
        if self.next_state is OperationState.PREPARED and (
            self.mutation_attempted
            or self.target_evidence is not None
            or self.native_mutation_receipt_sha256 is not None
            or self.recovery_observation_receipt_sha256 is not None
            or self.completion_kind is not None
            or self.error_code is not None
        ):
            raise OperationLedgerError(
                OperationLedgerCode.INVALID_REQUEST,
                "PREPARED must precede every mutation attempt",
            )
        recovered_states = {
            OperationState.RECOVERED_COMMIT,
            OperationState.RECOVERED_ABORT,
        }
        if (self.next_state in recovered_states) != (self.recovery_reason is not None):
            raise OperationLedgerError(
                OperationLedgerCode.INVALID_REQUEST,
                "only recovery terminal states require a recovery reason",
            )
        if self.next_state in recovered_states:
            if self.recovery_guarantee_scope != RECOVERY_GUARANTEE_SCOPE:
                raise OperationLedgerError(
                    OperationLedgerCode.INVALID_REQUEST,
                    "recovery fact must declare the cooperative-writer guarantee scope",
                )
            if self.recovery_authority_head_sha256 is None:
                raise OperationLedgerError(
                    OperationLedgerCode.INVALID_REQUEST,
                    "recovery fact requires its authenticated current audit head",
                )
        elif self.recovery_guarantee_scope is not None:
            raise OperationLedgerError(
                OperationLedgerCode.INVALID_REQUEST,
                "non-recovery states cannot claim a recovery guarantee scope",
            )
        elif self.recovery_authority_head_sha256 is not None:
            raise OperationLedgerError(
                OperationLedgerCode.INVALID_REQUEST,
                "non-recovery states cannot claim a recovery authority head",
            )
        failure_states = {OperationState.ABORTED, OperationState.IN_DOUBT}
        if (self.next_state in failure_states) != (self.error_code is not None):
            raise OperationLedgerError(
                OperationLedgerCode.INVALID_REQUEST,
                "only failed operation states require an error code",
            )
        if self.next_state in {
            OperationState.MUTATED,
            OperationState.POSTCONDITION_VERIFIED,
            OperationState.COMMITTED,
        } and (
            not self.mutation_attempted
            or self.native_mutation_receipt_sha256 is None
        ):
            raise OperationLedgerError(
                OperationLedgerCode.INVALID_REQUEST,
                "post-mutation states require a durable mutation receipt binding",
            )
        if self.next_state in {
            OperationState.POSTCONDITION_VERIFIED,
            OperationState.COMMITTED,
            OperationState.RECOVERED_COMMIT,
        } and self.target_evidence is None:
            raise OperationLedgerError(
                OperationLedgerCode.INVALID_REQUEST,
                "verified commit states require target tree evidence",
            )
        if self.next_state is OperationState.ABORTED and (
            self.mutation_attempted
            or self.target_evidence is not None
            or self.native_mutation_receipt_sha256 is not None
            or self.recovery_observation_receipt_sha256 is not None
        ):
            raise OperationLedgerError(
                OperationLedgerCode.INVALID_REQUEST,
                "ABORTED is valid only before mutation and without mutation evidence",
            )
        if self.next_state is OperationState.MUTATED and self.target_evidence is not None:
            raise OperationLedgerError(
                OperationLedgerCode.INVALID_REQUEST,
                "MUTATED precedes independent target verification",
            )
        if self.next_state is OperationState.IN_DOUBT and not self.mutation_attempted:
            raise OperationLedgerError(
                OperationLedgerCode.INVALID_REQUEST,
                "IN_DOUBT requires entry into the native mutation boundary",
            )
        if self.next_state is OperationState.RECOVERED_ABORT and (
            self.target_evidence is not None
            or self.native_mutation_receipt_sha256 is not None
            or self.recovery_observation_receipt_sha256 is not None
        ):
            raise OperationLedgerError(
                OperationLedgerCode.INVALID_REQUEST,
                "RECOVERED_ABORT cannot claim target or mutation receipt evidence",
            )
        expected_recovery_reason = {
            OperationState.RECOVERED_ABORT: "SOURCE_EXACT_TARGET_ABSENT",
            OperationState.RECOVERED_COMMIT: "SOURCE_ABSENT_TARGET_EXACT",
        }.get(self.next_state)
        if expected_recovery_reason is not None and self.recovery_reason != expected_recovery_reason:
            raise OperationLedgerError(
                OperationLedgerCode.INVALID_REQUEST,
                "recovery reason does not match its exact filesystem truth",
            )
        if self.next_state is OperationState.RECOVERED_COMMIT and not self.mutation_attempted:
            raise OperationLedgerError(
                OperationLedgerCode.INVALID_REQUEST,
                "RECOVERED_COMMIT requires a durable mutation-attempt fact",
            )
        if self.target_evidence is not None and self.target_evidence != self.source_evidence:
            raise OperationLedgerError(
                OperationLedgerCode.INVALID_REQUEST,
                "target evidence must be the exact PREPARED source tree evidence",
            )
        expected_completion: OperationCompletionKind | None = None
        if self.next_state is OperationState.COMMITTED:
            expected_completion = OperationCompletionKind.NATIVE_COMMIT
        elif self.next_state is OperationState.RECOVERED_COMMIT:
            if self.recovery_observation_receipt_sha256 is None:
                raise OperationLedgerError(
                    OperationLedgerCode.INVALID_REQUEST,
                    "RECOVERED_COMMIT requires a typed recovery observation receipt",
                )
            expected_completion = (
                OperationCompletionKind.RECOVERED_COMMIT_WITH_NATIVE_MUTATION
                if self.native_mutation_receipt_sha256 is not None
                else OperationCompletionKind.RECOVERED_COMMIT_OBSERVATION_ONLY
            )
        elif self.recovery_observation_receipt_sha256 is not None:
            raise OperationLedgerError(
                OperationLedgerCode.INVALID_REQUEST,
                "only RECOVERED_COMMIT may carry a recovery observation receipt",
            )
        if self.completion_kind is not expected_completion:
            raise OperationLedgerError(
                OperationLedgerCode.INVALID_REQUEST,
                "operation completion kind differs from its terminal evidence",
            )

    @property
    def digest(self) -> str:
        return hashlib.sha256(
            b"OPERATION-TRANSITION-V1\0" + canonical_json_bytes(self.to_json())
        ).hexdigest()

    def to_json(self) -> dict[str, Any]:
        return {
            "audit_ledger_head_sha256": self.audit_ledger_head_sha256,
            "budget_sha256": self.budget_sha256,
            "classification": self.classification.value,
            "context_binding_sha256": self.context_binding_sha256,
            "error_code": self.error_code,
            "manifest_sha256": self.manifest_sha256,
            "mutation_attempted": self.mutation_attempted,
            "native_mutation_receipt_sha256": self.native_mutation_receipt_sha256,
            "recovery_observation_receipt_sha256": self.recovery_observation_receipt_sha256,
            "completion_kind": (
                None if self.completion_kind is None else self.completion_kind.value
            ),
            "next_state": self.next_state.value,
            "operation_id": self.operation_id,
            "pair_id": self.pair_id,
            "previous_state": (
                None if self.previous_state is None else self.previous_state.value
            ),
            "recovery_reason": self.recovery_reason,
            "recovery_guarantee_scope": self.recovery_guarantee_scope,
            "recovery_authority_head_sha256": self.recovery_authority_head_sha256,
            "redaction_mode": "SAFE_RELATIVE",
            "source_evidence": self.source_evidence.to_json(),
            "source_locator": self.source_locator,
            "target_evidence": (
                None if self.target_evidence is None else self.target_evidence.to_json()
            ),
            "target_locator": self.target_locator,
            "transaction_id": self.transaction_id,
            "transition_id": self.transition_id,
        }


def _build_recovery_observation_receipt_sha256(
    previous: OperationTransition,
    target_evidence: OperationTreeEvidence,
    recovery_authority_head_sha256: str,
) -> str:
    if (
        type(previous) is not OperationTransition
        or type(target_evidence) is not OperationTreeEvidence
    ):
        raise OperationLedgerError(
            OperationLedgerCode.INVALID_REQUEST,
            "recovery observation receipt requires exact durable evidence",
        )
    _require_sha256(
        recovery_authority_head_sha256,
        "recovery_authority_head_sha256",
    )
    return hashlib.sha256(
        b"M0-RECOVERY-OBSERVATION-RECEIPT-V1\0"
        + bytes.fromhex(previous.digest)
        + previous.transaction_id.encode("ascii")
        + bytes.fromhex(target_evidence.digest)
        + bytes.fromhex(recovery_authority_head_sha256)
        + RECOVERY_GUARANTEE_SCOPE.encode("ascii")
        + b"SOURCE_ABSENT_TARGET_EXACT"
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class OperationLedgerHead:
    epoch_id: str
    last_sequence: int
    last_segment_sha256: str
    segment_count: int
    unresolved_transaction_ids: tuple[str, ...]
    startup_observed_abandoned_mutex: bool = False


@dataclass(frozen=True, slots=True)
class OperationSegmentReceipt:
    epoch_id: str
    sequence: int
    segment_sha256: str
    transition_id: str
    transition_sha256: str
    transaction_id: str
    state: OperationState
    replayed: bool = False
    capability_state: str = "TEST_LOCAL_DURABLE_OPERATION_SEGMENT"


@dataclass(frozen=True, slots=True)
class _ParsedSegment:
    sequence: int
    segment_sha256: str
    previous_segment_sha256: str | None
    kind: str
    transition: OperationTransition | None
    transition_sha256: str | None


def _evidence_from_json(value: Any) -> OperationTreeEvidence:
    if type(value) is not dict or set(value) != {
        "durable_identity_sha256",
        "entry_count",
        "manifest_sha256",
        "source_tree_sha256",
        "topology_sha256",
        "total_bytes",
    }:
        raise OperationLedgerError(
            OperationLedgerCode.CHAIN_CORRUPT,
            "operation evidence has an invalid exact shape",
        )
    try:
        return OperationTreeEvidence(**value)
    except OperationLedgerError as exc:
        raise OperationLedgerError(
            OperationLedgerCode.CHAIN_CORRUPT,
            "operation evidence is invalid",
        ) from exc


def _transition_from_json(value: Any) -> OperationTransition:
    expected = {
        "audit_ledger_head_sha256",
        "budget_sha256",
        "classification",
        "context_binding_sha256",
        "error_code",
        "manifest_sha256",
        "mutation_attempted",
        "native_mutation_receipt_sha256",
        "recovery_observation_receipt_sha256",
        "completion_kind",
        "next_state",
        "operation_id",
        "pair_id",
        "previous_state",
        "recovery_reason",
        "recovery_guarantee_scope",
        "recovery_authority_head_sha256",
        "redaction_mode",
        "source_evidence",
        "source_locator",
        "target_evidence",
        "target_locator",
        "transaction_id",
        "transition_id",
    }
    if type(value) is not dict or set(value) != expected or value["redaction_mode"] != "SAFE_RELATIVE":
        raise OperationLedgerError(
            OperationLedgerCode.CHAIN_CORRUPT,
            "operation transition has an invalid exact shape",
        )
    try:
        return OperationTransition(
            transition_id=value["transition_id"],
            transaction_id=value["transaction_id"],
            operation_id=value["operation_id"],
            pair_id=value["pair_id"],
            previous_state=(
                None
                if value["previous_state"] is None
                else OperationState(value["previous_state"])
            ),
            next_state=OperationState(value["next_state"]),
            context_binding_sha256=value["context_binding_sha256"],
            manifest_sha256=value["manifest_sha256"],
            budget_sha256=value["budget_sha256"],
            source_locator=value["source_locator"],
            target_locator=value["target_locator"],
            source_evidence=_evidence_from_json(value["source_evidence"]),
            target_evidence=(
                None
                if value["target_evidence"] is None
                else _evidence_from_json(value["target_evidence"])
            ),
            audit_ledger_head_sha256=value["audit_ledger_head_sha256"],
            mutation_attempted=value["mutation_attempted"],
            native_mutation_receipt_sha256=value["native_mutation_receipt_sha256"],
            recovery_observation_receipt_sha256=value[
                "recovery_observation_receipt_sha256"
            ],
            completion_kind=(
                None
                if value["completion_kind"] is None
                else OperationCompletionKind(value["completion_kind"])
            ),
            error_code=value["error_code"],
            recovery_reason=value["recovery_reason"],
            recovery_guarantee_scope=value["recovery_guarantee_scope"],
            recovery_authority_head_sha256=value[
                "recovery_authority_head_sha256"
            ],
            classification=DataClassification(value["classification"]),
        )
    except (KeyError, TypeError, ValueError, OperationLedgerError) as exc:
        raise OperationLedgerError(
            OperationLedgerCode.CHAIN_CORRUPT,
            "operation transition failed canonical validation",
        ) from exc


class DurableOperationLedger:
    def __init__(
        self,
        storage: _WindowsHandleWriter,
        revision: AuditKeyRevision,
        *,
        epoch_id: str,
        policy_digest: str,
        known_revisions: tuple[AuditKeyRevision, ...] = (),
        initialize: bool = False,
        initialized_at_utc: str | None = None,
        _runtime_mutex_lease: RuntimeMutexLease | None = None,
        _constructor: object | None = None,
    ) -> None:
        if (
            _constructor is not _OPERATION_LEDGER_CONSTRUCTOR
            or type(storage) is not _WindowsHandleWriter
            or type(revision) is not AuditKeyRevision
            or type(known_revisions) is not tuple
            or any(type(item) is not AuditKeyRevision for item in known_revisions)
            or type(initialize) is not bool
            or (not initialize and initialized_at_utc is not None)
        ):
            raise OperationLedgerError(
                OperationLedgerCode.INVALID_REQUEST,
                "operation ledger requires its exact Test-local factory authority",
            )
        try:
            self._epoch_id = validate_safe_id(epoch_id, field_name="epoch_id")
        except Exception:
            raise OperationLedgerError(
                OperationLedgerCode.INVALID_REQUEST,
                "operation ledger epoch is not canonical",
            ) from None
        self._policy_digest = _require_sha256(policy_digest, "policy_digest")
        self._storage = storage
        revisions: dict[str, AuditKeyRevision] = {revision.revision_id: revision}
        for item in known_revisions:
            existing = revisions.get(item.revision_id)
            if existing is not None and existing != item:
                raise OperationLedgerError(
                    OperationLedgerCode.AUTHENTICATION_FAILED,
                    "operation ledger revision inventory contains a conflict",
                )
            revisions[item.revision_id] = item
        self._known_revisions = revisions
        self._revision = revision
        self._operation_key = hmac.new(
            revision.segment_hmac_key,
            b"OPERATION-SEGMENT-AUTH-V1\0",
            hashlib.sha256,
        ).digest()
        self._operation_key_id = hashlib.sha256(
            b"OPERATION-KEY-ID-V1\0" + self._operation_key
        ).hexdigest()
        self._lock = threading.RLock()
        self._sealed_code: OperationLedgerCode | None = None
        self._segments: tuple[_ParsedSegment, ...] = ()
        self._transition_receipts: dict[str, OperationSegmentReceipt] = {}
        self._transaction_history: dict[str, tuple[OperationTransition, ...]] = {}
        self._total_segment_bytes = 0
        self._head: OperationLedgerHead | None = None
        try:
            if _runtime_mutex_lease is None:
                with storage.acquire_runtime_mutex() as lease:
                    self._startup_under_mutex(
                        lease,
                        initialize=initialize,
                        initialized_at_utc=initialized_at_utc,
                    )
            else:
                self._startup_under_mutex(
                    _runtime_mutex_lease,
                    initialize=initialize,
                    initialized_at_utc=initialized_at_utc,
                )
        except OperationLedgerError as exc:
            self._seal(exc.code)
            _raise_without_context(
                OperationLedgerError(
                    exc.code,
                    f"operation ledger startup failed safely ({exc})",
                )
            )
        except HandleWriterError:
            self._seal(OperationLedgerCode.STORAGE_FAILURE)
            _raise_without_context(
                OperationLedgerError(
                    OperationLedgerCode.STORAGE_FAILURE,
                    "operation ledger storage startup failed safely",
                )
            )
        except Exception:
            self._seal(OperationLedgerCode.CHAIN_CORRUPT)
            _raise_without_context(
                OperationLedgerError(
                    OperationLedgerCode.CHAIN_CORRUPT,
                    "operation ledger startup rejected an unexpected invalid encoding",
                )
            )

    @property
    def head(self) -> OperationLedgerHead:
        with self._lock:
            self._require_open()
            if self._head is None:
                raise OperationLedgerError(
                    OperationLedgerCode.LEDGER_SEALED,
                    "operation ledger head is unavailable",
                )
            return self._head

    @property
    def signing_revision_id(self) -> str:
        with self._lock:
            self._require_open()
            return self._revision.revision_id

    def durable_identity_digest(self, volume_serial: int, file_id: bytes) -> str:
        if (
            type(volume_serial) is not int
            or volume_serial < 0
            or type(file_id) is not bytes
            or len(file_id) != 16
        ):
            raise OperationLedgerError(
                OperationLedgerCode.INVALID_REQUEST,
                "durable identity input is invalid",
            )
        return hmac.new(
            self._operation_key,
            b"OPERATION-ROOT-IDENTITY-V1\0"
            + volume_serial.to_bytes(8, "little", signed=False)
            + file_id,
            hashlib.sha256,
        ).hexdigest()

    def _startup_under_mutex(
        self,
        lease: RuntimeMutexLease,
        *,
        initialize: bool,
        initialized_at_utc: str | None,
    ) -> None:
        self._require_mutex(lease)
        if not initialize:
            self._select_persisted_revision_under_mutex()
        self._scan_under_mutex(startup_abandoned=lease.abandoned, allow_empty=initialize)
        if initialize:
            if self._segments:
                raise OperationLedgerError(
                    OperationLedgerCode.INVALID_REQUEST,
                    "operation ledger initialization requires an empty store",
                )
            self._publish_genesis(initialized_at_utc or _now_utc_seconds())
            self._scan_under_mutex(startup_abandoned=lease.abandoned, allow_empty=False)
        elif not self._segments:
            raise OperationLedgerError(
                OperationLedgerCode.CHAIN_CORRUPT,
                "opened operation ledger is missing genesis",
            )

    def _rescan_under_existing_mutex(
        self,
        lease: RuntimeMutexLease,
    ) -> OperationLedgerHead:
        self._require_mutex(lease)
        with self._lock:
            self._require_open()
            try:
                self._scan_under_mutex(
                    startup_abandoned=lease.abandoned,
                    allow_empty=False,
                )
            except OperationLedgerError as exc:
                self._seal(exc.code)
                raise
            except Exception:
                self._seal(OperationLedgerCode.CHAIN_CORRUPT)
                raise OperationLedgerError(
                    OperationLedgerCode.CHAIN_CORRUPT,
                    "operation ledger rescan failed canonical validation",
                ) from None
            return self.head

    def _append_transition_under_existing_mutex(
        self,
        lease: RuntimeMutexLease,
        transition: OperationTransition,
        *,
        created_at_utc: str | None = None,
    ) -> OperationSegmentReceipt:
        self._require_mutex(lease)
        if type(transition) is not OperationTransition:
            raise OperationLedgerError(
                OperationLedgerCode.INVALID_REQUEST,
                "operation append requires an exact transition",
            )
        created = _validate_utc_seconds(created_at_utc or _now_utc_seconds())
        with self._lock:
            self._require_open()
            try:
                self._scan_under_mutex(startup_abandoned=False, allow_empty=False)
            except OperationLedgerError as exc:
                self._seal(exc.code)
                raise
            except Exception:
                self._seal(OperationLedgerCode.CHAIN_CORRUPT)
                raise OperationLedgerError(
                    OperationLedgerCode.CHAIN_CORRUPT,
                    "operation ledger pre-append rescan failed canonical validation",
                ) from None
            replay = self._transition_receipts.get(transition.transition_id)
            if replay is not None:
                existing = next(
                    (
                        item
                        for history in self._transaction_history.values()
                        for item in history
                        if item.transition_id == transition.transition_id
                    ),
                    None,
                )
                if existing is None or existing != transition:
                    self._seal(OperationLedgerCode.TRANSITION_CONFLICT)
                    raise OperationLedgerError(
                        OperationLedgerCode.TRANSITION_CONFLICT,
                        "transition ID replay differs from committed content",
                    )
                return replace(replay, replayed=True)
            self._validate_next_transition(transition)
            head = self.head
            sequence = head.last_sequence + 1
            payload, segment_sha = self._build_segment(
                sequence=sequence,
                previous=head.last_segment_sha256,
                created_at_utc=created,
                kind="OPERATION_TRANSITION",
                transition=transition,
            )
            self._require_append_capacity(transition, payload)
            self._publish_segment(sequence, segment_sha, payload)
            try:
                self._scan_under_mutex(startup_abandoned=False, allow_empty=False)
            except OperationLedgerError as exc:
                self._seal(exc.code)
                raise
            except Exception:
                self._seal(OperationLedgerCode.CHAIN_CORRUPT)
                raise OperationLedgerError(
                    OperationLedgerCode.CHAIN_CORRUPT,
                    "operation ledger post-append rescan failed canonical validation",
                ) from None
            committed = self._transition_receipts.get(transition.transition_id)
            if committed is None or committed.segment_sha256 != segment_sha:
                self._seal(OperationLedgerCode.STORAGE_FAILURE)
                raise OperationLedgerError(
                    OperationLedgerCode.STORAGE_FAILURE,
                    "published transition is absent after full-chain rescan",
                )
            return committed

    def unresolved_under_existing_mutex(
        self,
        lease: RuntimeMutexLease,
    ) -> tuple[OperationTransition, ...]:
        self._rescan_under_existing_mutex(lease)
        return tuple(
            history[-1]
            for transaction_id, history in sorted(self._transaction_history.items())
            if history[-1].next_state not in _TERMINAL_STATES
        )

    def operation_result_under_existing_mutex(
        self,
        lease: RuntimeMutexLease,
        operation_id: str,
    ) -> tuple[OperationTransition, OperationSegmentReceipt] | None:
        try:
            canonical_operation_id = validate_safe_id(
                operation_id,
                field_name="operation_id",
            )
        except Exception:
            raise OperationLedgerError(
                OperationLedgerCode.INVALID_REQUEST,
                "operation lookup identity is not canonical",
            ) from None
        self._rescan_under_existing_mutex(lease)
        matches = tuple(
            history[-1]
            for history in self._transaction_history.values()
            if history[0].operation_id == canonical_operation_id
        )
        if not matches:
            return None
        if len(matches) != 1:
            self._seal(OperationLedgerCode.TRANSITION_CONFLICT)
            raise OperationLedgerError(
                OperationLedgerCode.TRANSITION_CONFLICT,
                "operation ID maps to multiple durable transactions",
            )
        transition = matches[0]
        receipt = self._transition_receipts.get(transition.transition_id)
        if receipt is None:
            self._seal(OperationLedgerCode.CHAIN_CORRUPT)
            raise OperationLedgerError(
                OperationLedgerCode.CHAIN_CORRUPT,
                "operation terminal transition receipt is missing",
            )
        return transition, receipt

    def transaction_result_under_existing_mutex(
        self,
        lease: RuntimeMutexLease,
        transaction_id: str,
    ) -> tuple[OperationTransition, OperationSegmentReceipt] | None:
        try:
            canonical_transaction_id = validate_safe_id(
                transaction_id,
                field_name="transaction_id",
            )
        except Exception:
            raise OperationLedgerError(
                OperationLedgerCode.INVALID_REQUEST,
                "transaction lookup identity is not canonical",
            ) from None
        self._rescan_under_existing_mutex(lease)
        history = self._transaction_history.get(canonical_transaction_id)
        if not history:
            return None
        transition = history[-1]
        receipt = self._transition_receipts.get(transition.transition_id)
        if receipt is None:
            self._seal(OperationLedgerCode.CHAIN_CORRUPT)
            raise OperationLedgerError(
                OperationLedgerCode.CHAIN_CORRUPT,
                "transaction transition receipt is missing",
            )
        return transition, receipt

    def bound_audit_heads_under_existing_mutex(
        self,
        lease: RuntimeMutexLease,
    ) -> tuple[str, ...]:
        self._rescan_under_existing_mutex(lease)
        heads = {
            transition.audit_ledger_head_sha256
            for history in self._transaction_history.values()
            for transition in history[:1]
        }
        heads.update(
            transition.recovery_authority_head_sha256
            for history in self._transaction_history.values()
            for transition in history
            if transition.recovery_authority_head_sha256 is not None
        )
        return tuple(sorted(heads))

    def _seal_cross_ledger_contradiction(self) -> NoReturn:
        self._seal(OperationLedgerCode.CHAIN_CORRUPT)
        raise OperationLedgerError(
            OperationLedgerCode.CHAIN_CORRUPT,
            "operation facts reference an audit head outside the authenticated chain",
        ) from None

    def _seal_recovery_contradiction(self) -> NoReturn:
        self._seal(OperationLedgerCode.RECOVERY_CONTRADICTION)
        raise OperationLedgerError(
            OperationLedgerCode.RECOVERY_CONTRADICTION,
            "filesystem recovery evidence is ambiguous or contradicts the ledger",
        ) from None

    def _validate_next_transition(self, transition: OperationTransition) -> None:
        history = self._transaction_history.get(transition.transaction_id, ())
        if not history:
            if transition.previous_state is not None:
                raise OperationLedgerError(
                    OperationLedgerCode.ILLEGAL_TRANSITION,
                    "new transaction must begin at PREPARED",
                )
            if any(
                existing[0].operation_id == transition.operation_id
                for existing in self._transaction_history.values()
            ):
                raise OperationLedgerError(
                    OperationLedgerCode.TRANSITION_CONFLICT,
                    "operation ID was already bound to another transaction",
                )
            return
        previous = history[-1]
        if previous.next_state in _TERMINAL_STATES:
            raise OperationLedgerError(
                OperationLedgerCode.ILLEGAL_TRANSITION,
                "terminal transaction cannot advance",
            )
        stable_fields = (
            "operation_id",
            "pair_id",
            "context_binding_sha256",
            "manifest_sha256",
            "budget_sha256",
            "source_locator",
            "target_locator",
            "source_evidence",
            "audit_ledger_head_sha256",
            "classification",
        )
        if transition.previous_state is not previous.next_state or any(
            getattr(transition, name) != getattr(previous, name) for name in stable_fields
        ):
            raise OperationLedgerError(
                OperationLedgerCode.TRANSITION_CONFLICT,
                "operation transition changed its immutable transaction binding",
            )
        if (
            previous.native_mutation_receipt_sha256 is not None
            and transition.native_mutation_receipt_sha256
            != previous.native_mutation_receipt_sha256
        ) or (
            previous.target_evidence is not None
            and transition.target_evidence != previous.target_evidence
        ):
            raise OperationLedgerError(
                OperationLedgerCode.TRANSITION_CONFLICT,
                "operation transition changed durable mutation or target evidence",
            )
        if (
            previous.recovery_observation_receipt_sha256 is not None
            and transition.recovery_observation_receipt_sha256
            != previous.recovery_observation_receipt_sha256
        ):
            raise OperationLedgerError(
                OperationLedgerCode.TRANSITION_CONFLICT,
                "operation transition changed durable recovery evidence",
            )
        if previous.mutation_attempted and not transition.mutation_attempted:
            raise OperationLedgerError(
                OperationLedgerCode.TRANSITION_CONFLICT,
                "operation transition reversed the durable mutation-attempt fact",
            )
        if transition.next_state is OperationState.RECOVERED_COMMIT:
            target = transition.target_evidence
            authority_head = transition.recovery_authority_head_sha256
            if (
                target is None
                or authority_head is None
                or transition.recovery_observation_receipt_sha256
                != _build_recovery_observation_receipt_sha256(
                    previous,
                    target,
                    authority_head,
                )
            ):
                raise OperationLedgerError(
                    OperationLedgerCode.TRANSITION_CONFLICT,
                    "recovery observation receipt differs from its prior durable facts",
                )

    def _require_append_capacity(
        self,
        transition: OperationTransition,
        payload: bytes,
    ) -> None:
        if len(payload) > _MAX_TRANSITION_SEGMENT_BYTES:
            raise OperationLedgerError(
                OperationLedgerCode.RESOURCE_LIMIT,
                "operation transition exceeds its fixed transaction byte limit",
            )
        is_new = not self._transaction_history.get(transition.transaction_id)
        required_segments = _TRANSACTION_SEGMENT_RESERVATION if is_new else 1
        required_bytes = (
            _TRANSACTION_SEGMENT_RESERVATION * _MAX_TRANSITION_SEGMENT_BYTES
            if is_new
            else len(payload)
        )
        if (
            len(self._segments) + required_segments > _MAX_SEGMENTS
            or self._total_segment_bytes + required_bytes > _MAX_LEDGER_BYTES
        ):
            raise OperationLedgerError(
                OperationLedgerCode.RESOURCE_LIMIT,
                "operation ledger lacks capacity for the complete transaction lifecycle",
            )

    def _select_persisted_revision_under_mutex(self) -> None:
        """Select the genesis-bound key before authenticating the complete chain."""

        try:
            snapshot = self._storage.read_flat_directory(
                _SEGMENT_ROOT / self._epoch_id,
                maximum_entries=_MAX_SEGMENTS,
                maximum_file_bytes=_MAX_SEGMENT_BYTES,
                maximum_total_bytes=_MAX_LEDGER_BYTES,
            )
        except HandleWriterError as exc:
            raise OperationLedgerError(
                OperationLedgerCode.STORAGE_FAILURE,
                "operation genesis cannot be read for key selection",
            ) from exc
        candidates = []
        for entry in snapshot.entries:
            match = _SEGMENT_FILE.fullmatch(entry.name)
            if match is None:
                raise OperationLedgerError(
                    OperationLedgerCode.UNKNOWN_ENTRY,
                    "operation segment store contains an unknown or pending entry",
                )
            if int(match.group("sequence")) == 0:
                candidates.append(entry.payload)
        if len(candidates) != 1:
            raise OperationLedgerError(
                OperationLedgerCode.CHAIN_CORRUPT,
                "operation ledger requires exactly one genesis segment",
            )
        try:
            value = _decode_ascii_json(candidates[0])
            revision_id = value["key_revision_id"]
        except (UnicodeError, ValueError, TypeError, KeyError):
            raise OperationLedgerError(
                OperationLedgerCode.CHAIN_CORRUPT,
                "operation genesis cannot select a canonical key revision",
            ) from None
        if type(revision_id) is not str:
            raise OperationLedgerError(
                OperationLedgerCode.CHAIN_CORRUPT,
                "operation genesis key revision identity is not canonical",
            )
        try:
            validate_safe_id(revision_id, field_name="key_revision_id")
        except Exception:
            raise OperationLedgerError(
                OperationLedgerCode.CHAIN_CORRUPT,
                "operation genesis key revision identity is not canonical",
            ) from None
        revision = self._known_revisions.get(revision_id)
        if revision is None:
            raise OperationLedgerError(
                OperationLedgerCode.AUTHENTICATION_FAILED,
                "operation genesis key revision is unavailable",
            )
        self._revision = revision
        self._operation_key = hmac.new(
            revision.segment_hmac_key,
            b"OPERATION-SEGMENT-AUTH-V1\0",
            hashlib.sha256,
        ).digest()
        self._operation_key_id = hashlib.sha256(
            b"OPERATION-KEY-ID-V1\0" + self._operation_key
        ).hexdigest()

    def _publish_genesis(self, created_at_utc: str) -> None:
        created = _validate_utc_seconds(created_at_utc)
        payload, segment_sha = self._build_segment(
            sequence=0,
            previous=None,
            created_at_utc=created,
            kind="GENESIS",
            transition=None,
        )
        self._publish_segment(0, segment_sha, payload)

    def _build_segment(
        self,
        *,
        sequence: int,
        previous: str | None,
        created_at_utc: str,
        kind: str,
        transition: OperationTransition | None,
    ) -> tuple[bytes, str]:
        body = {
            "created_at_utc": created_at_utc,
            "epoch_id": self._epoch_id,
            "key_id": self._operation_key_id,
            "key_revision_id": self._revision.revision_id,
            "key_revision_sha256": self._revision.revision_sha256,
            "ledger_id": "OPERATION",
            "policy_digest": self._policy_digest,
            "previous_segment_sha256": previous,
            "schema_id": "M0-OPERATION-SEGMENT",
            "schema_version": "1.0",
            "segment_kind": kind,
            "sequence": sequence,
            "transition": None if transition is None else transition.to_json(),
            "transition_sha256": None if transition is None else transition.digest,
        }
        body_bytes = canonical_json_bytes(body)
        segment_sha = hashlib.sha256(b"OPERATION-SEGMENT-V1\0" + body_bytes).hexdigest()
        envelope = dict(body)
        envelope["segment_hmac_sha256"] = hmac.new(
            self._operation_key,
            b"OPERATION-SEGMENT-V1\0" + body_bytes,
            hashlib.sha256,
        ).hexdigest()
        envelope["segment_sha256"] = segment_sha
        return canonical_json_bytes(envelope), segment_sha

    def _publish_segment(self, sequence: int, segment_sha: str, payload: bytes) -> None:
        if len(payload) > _MAX_SEGMENT_BYTES:
            raise OperationLedgerError(
                OperationLedgerCode.RESOURCE_LIMIT,
                "operation segment exceeds its fixed byte limit",
            )
        directory = _SEGMENT_ROOT / self._epoch_id
        final_name = f"{sequence:020d}-{segment_sha}.json"
        pending = (
            f"PENDING-{sequence:020d}-{segment_sha[:24]}-"
            f"{secrets.token_hex(8).upper()}.json"
        )
        try:
            self._storage.publish_new_file(
                directory / pending,
                directory / final_name,
                payload,
                expected_sha256=hashlib.sha256(payload).hexdigest(),
            )
        except HandleWriterError as exc:
            self._seal(OperationLedgerCode.STORAGE_FAILURE)
            raise OperationLedgerError(
                OperationLedgerCode.STORAGE_FAILURE,
                f"operation segment publication failed safely ({exc.code.value})",
            ) from exc

    def _scan_under_mutex(self, *, startup_abandoned: bool, allow_empty: bool) -> None:
        try:
            snapshot = self._storage.read_flat_directory(
                _SEGMENT_ROOT / self._epoch_id,
                maximum_entries=_MAX_SEGMENTS,
                maximum_file_bytes=_MAX_SEGMENT_BYTES,
                maximum_total_bytes=_MAX_LEDGER_BYTES,
            )
        except HandleWriterError as exc:
            raise OperationLedgerError(
                OperationLedgerCode.STORAGE_FAILURE,
                "operation segment store cannot be read",
            ) from exc
        files: list[tuple[int, str, bytes]] = []
        for entry in snapshot.entries:
            match = _SEGMENT_FILE.fullmatch(entry.name)
            if match is None:
                raise OperationLedgerError(
                    OperationLedgerCode.UNKNOWN_ENTRY,
                    "operation segment store contains an unknown or pending entry",
                )
            files.append((int(match.group("sequence")), entry.name, entry.payload))
        files.sort(key=lambda item: item[0])
        segments: list[_ParsedSegment] = []
        receipts: dict[str, OperationSegmentReceipt] = {}
        histories: dict[str, list[OperationTransition]] = {}
        previous: str | None = None
        for expected_sequence, (_numeric, name, payload) in enumerate(files):
            parsed = self._parse_segment(
                name,
                payload,
                expected_sequence=expected_sequence,
                expected_previous=previous,
            )
            if parsed.kind == "GENESIS":
                if expected_sequence != 0 or parsed.transition is not None:
                    raise OperationLedgerError(
                        OperationLedgerCode.CHAIN_CORRUPT,
                        "operation genesis placement is invalid",
                    )
            else:
                transition = parsed.transition
                if transition is None or parsed.transition_sha256 is None:
                    raise OperationLedgerError(
                        OperationLedgerCode.CHAIN_CORRUPT,
                        "operation transition segment is incomplete",
                    )
                if transition.transition_id in receipts:
                    raise OperationLedgerError(
                        OperationLedgerCode.TRANSITION_CONFLICT,
                        "operation chain repeats a transition ID",
                    )
                history = histories.setdefault(transition.transaction_id, [])
                previous_transition = history[-1] if history else None
                if previous_transition is None:
                    if transition.previous_state is not None:
                        raise OperationLedgerError(
                            OperationLedgerCode.ILLEGAL_TRANSITION,
                            "operation history does not start at PREPARED",
                        )
                    if any(
                        existing[0].operation_id == transition.operation_id
                        for transaction, existing in histories.items()
                        if transaction != transition.transaction_id and existing
                    ):
                        raise OperationLedgerError(
                            OperationLedgerCode.TRANSITION_CONFLICT,
                            "operation chain reuses an operation ID",
                        )
                else:
                    stable_fields = (
                        "operation_id",
                        "pair_id",
                        "context_binding_sha256",
                        "manifest_sha256",
                        "budget_sha256",
                        "source_locator",
                        "target_locator",
                        "source_evidence",
                        "audit_ledger_head_sha256",
                        "classification",
                    )
                    if (
                        transition.previous_state is not previous_transition.next_state
                        or previous_transition.next_state in _TERMINAL_STATES
                        or any(
                            getattr(transition, field) != getattr(previous_transition, field)
                            for field in stable_fields
                        )
                    ):
                        raise OperationLedgerError(
                            OperationLedgerCode.TRANSITION_CONFLICT,
                            "operation history changed an immutable binding or state",
                        )
                    if (
                        previous_transition.native_mutation_receipt_sha256 is not None
                        and transition.native_mutation_receipt_sha256
                        != previous_transition.native_mutation_receipt_sha256
                    ) or (
                        previous_transition.target_evidence is not None
                        and transition.target_evidence
                        != previous_transition.target_evidence
                    ):
                        raise OperationLedgerError(
                            OperationLedgerCode.TRANSITION_CONFLICT,
                            "operation history changed durable mutation or target evidence",
                        )
                    if (
                        previous_transition.recovery_observation_receipt_sha256
                        is not None
                        and transition.recovery_observation_receipt_sha256
                        != previous_transition.recovery_observation_receipt_sha256
                    ):
                        raise OperationLedgerError(
                            OperationLedgerCode.TRANSITION_CONFLICT,
                            "operation history changed durable recovery evidence",
                        )
                    if previous_transition.mutation_attempted and not transition.mutation_attempted:
                        raise OperationLedgerError(
                            OperationLedgerCode.TRANSITION_CONFLICT,
                            "operation history reversed the durable mutation-attempt fact",
                        )
                    if transition.next_state is OperationState.RECOVERED_COMMIT:
                        target = transition.target_evidence
                        authority_head = transition.recovery_authority_head_sha256
                        if (
                            target is None
                            or authority_head is None
                            or transition.recovery_observation_receipt_sha256
                            != _build_recovery_observation_receipt_sha256(
                                previous_transition,
                                target,
                                authority_head,
                            )
                        ):
                            raise OperationLedgerError(
                                OperationLedgerCode.TRANSITION_CONFLICT,
                                "operation history contains an invalid recovery receipt",
                            )
                history.append(transition)
                receipts[transition.transition_id] = OperationSegmentReceipt(
                    epoch_id=self._epoch_id,
                    sequence=expected_sequence,
                    segment_sha256=parsed.segment_sha256,
                    transition_id=transition.transition_id,
                    transition_sha256=parsed.transition_sha256,
                    transaction_id=transition.transaction_id,
                    state=transition.next_state,
                )
            segments.append(parsed)
            previous = parsed.segment_sha256
        if not segments and not allow_empty:
            raise OperationLedgerError(
                OperationLedgerCode.CHAIN_CORRUPT,
                "operation ledger is missing its immutable genesis",
            )
        if segments and segments[0].kind != "GENESIS":
            raise OperationLedgerError(
                OperationLedgerCode.CHAIN_CORRUPT,
                "operation ledger does not begin with genesis",
            )
        unresolved = tuple(
            sorted(
                transaction_id
                for transaction_id, history in histories.items()
                if history[-1].next_state not in _TERMINAL_STATES
            )
        )
        self._segments = tuple(segments)
        self._total_segment_bytes = sum(len(item[2]) for item in files)
        self._transition_receipts = receipts
        self._transaction_history = {
            key: tuple(value) for key, value in histories.items()
        }
        self._head = OperationLedgerHead(
            epoch_id=self._epoch_id,
            last_sequence=len(segments) - 1,
            last_segment_sha256=previous or "0" * 64,
            segment_count=len(segments),
            unresolved_transaction_ids=unresolved,
            startup_observed_abandoned_mutex=startup_abandoned,
        )

    def _parse_segment(
        self,
        name: str,
        payload: bytes,
        *,
        expected_sequence: int,
        expected_previous: str | None,
    ) -> _ParsedSegment:
        if len(payload) > _MAX_SEGMENT_BYTES or not payload.endswith(b"\n"):
            raise OperationLedgerError(
                OperationLedgerCode.CHAIN_CORRUPT,
                "operation segment bytes are not canonical",
            )
        try:
            value = json.loads(
                payload.decode("ascii", "strict"),
                parse_float=lambda _value: (_ for _ in ()).throw(ValueError()),
                parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
            )
        except (UnicodeError, ValueError, TypeError):
            raise OperationLedgerError(
                OperationLedgerCode.CHAIN_CORRUPT,
                "operation segment JSON is invalid",
            ) from None
        expected_keys = {
            "created_at_utc",
            "epoch_id",
            "key_id",
            "key_revision_id",
            "key_revision_sha256",
            "ledger_id",
            "policy_digest",
            "previous_segment_sha256",
            "schema_id",
            "schema_version",
            "segment_hmac_sha256",
            "segment_kind",
            "segment_sha256",
            "sequence",
            "transition",
            "transition_sha256",
        }
        try:
            canonical_envelope = canonical_json_bytes(value)
        except Exception:
            raise OperationLedgerError(
                OperationLedgerCode.CHAIN_CORRUPT,
                "operation segment canonicalization failed safely",
            ) from None
        if type(value) is not dict or set(value) != expected_keys or canonical_envelope != payload:
            raise OperationLedgerError(
                OperationLedgerCode.CHAIN_CORRUPT,
                "operation segment has an invalid exact envelope",
            )
        body = dict(value)
        supplied_hmac = body.pop("segment_hmac_sha256")
        supplied_sha = body.pop("segment_sha256")
        try:
            body_bytes = canonical_json_bytes(body)
        except Exception:
            raise OperationLedgerError(
                OperationLedgerCode.CHAIN_CORRUPT,
                "operation segment body canonicalization failed safely",
            ) from None
        computed_sha = hashlib.sha256(b"OPERATION-SEGMENT-V1\0" + body_bytes).hexdigest()
        computed_hmac = hmac.new(
            self._operation_key,
            b"OPERATION-SEGMENT-V1\0" + body_bytes,
            hashlib.sha256,
        ).hexdigest()
        match = _SEGMENT_FILE.fullmatch(name)
        if (
            match is None
            or value["sequence"] != expected_sequence
            or int(match.group("sequence")) != expected_sequence
            or match.group("sha") != supplied_sha
            or supplied_sha != computed_sha
            or not isinstance(supplied_hmac, str)
            or not hmac.compare_digest(supplied_hmac, computed_hmac)
            or value["previous_segment_sha256"] != expected_previous
            or value["epoch_id"] != self._epoch_id
            or value["ledger_id"] != "OPERATION"
            or value["schema_id"] != "M0-OPERATION-SEGMENT"
            or value["schema_version"] != "1.0"
            or value["policy_digest"] != self._policy_digest
            or value["key_id"] != self._operation_key_id
            or value["key_revision_id"] != self._revision.revision_id
            or value["key_revision_sha256"] != self._revision.revision_sha256
        ):
            raise OperationLedgerError(
                OperationLedgerCode.AUTHENTICATION_FAILED,
                "operation segment chain or authenticator differs",
            )
        _validate_utc_seconds(value["created_at_utc"])
        kind = value["segment_kind"]
        if kind not in {"GENESIS", "OPERATION_TRANSITION"}:
            raise OperationLedgerError(
                OperationLedgerCode.CHAIN_CORRUPT,
                "operation segment kind is unknown",
            )
        transition = None
        transition_sha = value["transition_sha256"]
        if kind == "GENESIS":
            if value["transition"] is not None or transition_sha is not None:
                raise OperationLedgerError(
                    OperationLedgerCode.CHAIN_CORRUPT,
                    "operation genesis must not contain a transition",
                )
        else:
            transition = _transition_from_json(value["transition"])
            if transition_sha != transition.digest:
                raise OperationLedgerError(
                    OperationLedgerCode.CHAIN_CORRUPT,
                    "operation transition digest differs",
                )
        return _ParsedSegment(
            sequence=expected_sequence,
            segment_sha256=computed_sha,
            previous_segment_sha256=expected_previous,
            kind=kind,
            transition=transition,
            transition_sha256=transition_sha,
        )

    def _require_mutex(self, lease: RuntimeMutexLease) -> None:
        if type(lease) is not RuntimeMutexLease or lease._writer is not self._storage:
            raise OperationLedgerError(
                OperationLedgerCode.MUTEX_INVALID,
                "operation ledger requires its exact storage mutex lease",
            )
        try:
            lease._assert_live_owner(self._storage)
        except HandleWriterError:
            raise OperationLedgerError(
                OperationLedgerCode.MUTEX_INVALID,
                "operation ledger mutex is not live on its owner thread",
            ) from None

    def _seal(self, code: OperationLedgerCode) -> None:
        if self._sealed_code is None:
            self._sealed_code = code
        self._storage.seal_after_indeterminate_mutation()

    def _require_open(self) -> None:
        if self._sealed_code is not None:
            raise OperationLedgerError(
                OperationLedgerCode.LEDGER_SEALED,
                "operation ledger is sealed after an unsafe or indeterminate state",
            )


__all__ = [
    "DurableOperationLedger",
    "OperationLedgerCode",
    "OperationLedgerError",
    "OperationLedgerHead",
    "OperationCompletionKind",
    "OperationSegmentReceipt",
    "OperationState",
    "OperationTransition",
    "OperationTreeEvidence",
    "RECOVERY_GUARANTEE_SCOPE",
]
