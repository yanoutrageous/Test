from __future__ import annotations

import hashlib
import hmac
import json
import ntpath
import os
import re
import secrets
import stat
import threading
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path, PureWindowsPath
from typing import Any, Callable, Generic, TypeVar

from app import config as app_config
from app.project_root import PROJECT_ROOT as _VERIFIED_PROJECT_ROOT
from app.workspace_guard import (
    ExpectedKind,
    GuardedPath,
    PathIdentity,
    PathIntent,
    WorkspaceGuard,
    WorkspaceGuardError,
)
from app.safety.windows_handle_writer import (
    HandleWriterCode,
    HandleWriterError,
    RuntimeMutexLease,
    _HANDLE_WRITER_CONSTRUCTOR,
    _WindowsApi,
    _WindowsHandleWriter,
)
from app.safety.segment_ledger import (
    AuditKeyRevisionStore,
    DurableAuditLedger,
    DurableAuditSink,
    LedgerCode,
    LedgerError,
    _LEDGER_CONSTRUCTOR,
    _build_genesis_segment_bytes,
    build_key_revision_bytes,
)
from app.safety.operation_ledger import (
    DurableOperationLedger,
    OperationCompletionKind,
    OperationLedgerError,
    OperationLocatorMode,
    OperationLocatorRole,
    OperationSegmentReceipt,
    OperationState,
    OperationTransition,
    OperationTreeEvidence,
    _OPERATION_LEDGER_CONSTRUCTOR,
    RECOVERY_GUARANTEE_SCOPE,
    _build_recovery_observation_receipt_sha256,
    _resolve_reviewed_operation_epochs_under_existing_mutex,
)
from app.safety.copy_ledger import (
    CopyLedgerCode,
    CopyLedgerError,
    DurableCopyLedgers,
    _COPY_LEDGERS_CONSTRUCTOR,
    _derive_copy_ledger_epoch_id,
)
from app.safety.external_source import _create_synthetic_reference_read_policy
from app.safety.copy_operation import (
    _TestLocalCopyOperation,
    _COPY_OPERATION_CONSTRUCTOR,
)
from app.safety.job_operation import (
    DeclaredTreeManifest,
    JobResourceBudget,
    _JOB_RUNTIME_CONSTRUCTOR,
    _TestJobRuntime,
    _build_test_job_runtime,
)

from .audit_events import (
    AuditAction,
    AuditDecision,
    AuditEvent,
    AuditReceipt,
    AuditSink,
    CapabilityKind,
    CollectingAuditSink,
    PairRole,
    audit_receipt,
    create_audit_event,
)
from .context import (
    Caller,
    ContextError,
    DataClassification,
    OperationContext,
    Purpose,
    ScopeKind,
    validate_safe_id,
)
from .namespace_policy import (
    POLICY_VERSION,
    AuditPathMode,
    NamespaceDecision,
    NamespaceId,
    NamespaceMode,
    NamespacePolicy,
    NamespacePolicyError,
    PolicyErrorCode,
    ScopeBinding,
)


def _contract_root(_root: Path = _VERIFIED_PROJECT_ROOT) -> Path:
    return _root


CONTRACT_PROJECT_ROOT = _contract_root()
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_QUARANTINE_DATE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
_QUARANTINE_PAIR_ID = re.compile(r"^[0-9]{8}[0-9A-F]{24}$")
_TOKEN_CONSTRUCTOR = object()
_JOB_CONTEXT_PIN_CONSTRUCTOR = object()
_PAIR_RESERVATION_CONSTRUCTOR = object()
_RECOVERY_LOCATOR_CONSTRUCTOR = object()
_RESTRICTED_RECOVERY_PURPOSE_PUBLISH = "PUBLISH_RECOVERY"
_RESTRICTED_RECOVERY_PURPOSE_COPY = "COPY_RECONCILE"
_RESTRICTED_RECOVERY_PURPOSES = frozenset(
    {
        _RESTRICTED_RECOVERY_PURPOSE_PUBLISH,
        _RESTRICTED_RECOVERY_PURPOSE_COPY,
    }
)
_RESTRICTED_COPY_RECOVERY_SCOPE_KINDS = frozenset(
    {
        ScopeKind.RUN_ID,
        ScopeKind.COPY_LEDGER_EPOCH_ID,
        ScopeKind.JOB_ID,
        ScopeKind.OPERATION_ID,
        ScopeKind.MANIFEST_ID,
        ScopeKind.COPY_ID,
        ScopeKind.CHECKPOINT_ID,
    }
)
_PRODUCTION_BOUNDARY_CONSTRUCTOR = object()
_AUDIT_AUTHORITY_CONSTRUCTOR = object()
_MAX_REGISTRY_ITEMS = 4096
_MAX_TOMBSTONES = 8192
_ResultValue = TypeVar("_ResultValue")
_PRODUCTION_BOUNDARY_LOCK = threading.Lock()
_production_boundary_singleton: ProductionWorkspaceBoundary | None = None


@dataclass(frozen=True, slots=True)
class _AuditAuthority:
    sink: DurableAuditSink = field(repr=False)
    ledger: DurableAuditLedger = field(repr=False, compare=False)
    key_store: AuditKeyRevisionStore = field(repr=False, compare=False)
    writer: _WindowsHandleWriter = field(repr=False, compare=False)
    _constructor: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if (
            self._constructor is not _AUDIT_AUTHORITY_CONSTRUCTOR
            or type(self.sink) is not DurableAuditSink
            or type(self.ledger) is not DurableAuditLedger
            or type(self.key_store) is not AuditKeyRevisionStore
            or type(self.writer) is not _WindowsHandleWriter
            or self.sink._ledger is not self.ledger
            or self.ledger._key_store is not self.key_store
            or self.ledger._storage is not self.writer
            or self.key_store._storage is not self.writer
        ):
            raise TypeError("audit authority is restricted to the fixed boundary factory")

    def __reduce__(self) -> Any:
        raise TypeError("audit authorities cannot be serialized")


class BoundaryErrorCode(StrEnum):
    PRODUCTION_ROOT_MISMATCH = "PRODUCTION_ROOT_MISMATCH"
    ABSOLUTE_PATH_FORBIDDEN = "ABSOLUTE_PATH_FORBIDDEN"
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    INVALID_CONTEXT = "INVALID_CONTEXT"
    PATH_REJECTED = "PATH_REJECTED"
    POLICY_DENIED = "POLICY_DENIED"
    CANDIDATE_ONLY = "CANDIDATE_ONLY"
    CANDIDATE_NOT_ISSUED = "CANDIDATE_NOT_ISSUED"
    CANDIDATE_ISSUER_MISMATCH = "CANDIDATE_ISSUER_MISMATCH"
    CANDIDATE_MAC_MISMATCH = "CANDIDATE_MAC_MISMATCH"
    CANDIDATE_CONTEXT_MISMATCH = "CANDIDATE_CONTEXT_MISMATCH"
    CANDIDATE_POLICY_MISMATCH = "CANDIDATE_POLICY_MISMATCH"
    CANDIDATE_PAIR_REQUIRED = "CANDIDATE_PAIR_REQUIRED"
    CANDIDATE_ALREADY_USED = "CANDIDATE_ALREADY_USED"
    PAIR_NOT_ISSUED = "PAIR_NOT_ISSUED"
    PAIR_ISSUER_MISMATCH = "PAIR_ISSUER_MISMATCH"
    PAIR_MAC_MISMATCH = "PAIR_MAC_MISMATCH"
    PAIR_CONTEXT_MISMATCH = "PAIR_CONTEXT_MISMATCH"
    PAIR_POLICY_MISMATCH = "PAIR_POLICY_MISMATCH"
    PAIR_MEMBER_MISMATCH = "PAIR_MEMBER_MISMATCH"
    PAIR_ALREADY_USED = "PAIR_ALREADY_USED"
    PAIR_TOPOLOGY_DENIED = "PAIR_TOPOLOGY_DENIED"
    PAIR_TOPOLOGY_CHANGED = "PAIR_TOPOLOGY_CHANGED"
    MANIFEST_BINDING_REQUIRED = "MANIFEST_BINDING_REQUIRED"
    MANIFEST_BINDING_INVALID = "MANIFEST_BINDING_INVALID"
    MANIFEST_CONTEXT_MISMATCH = "MANIFEST_CONTEXT_MISMATCH"
    REGISTRY_CAPACITY_EXCEEDED = "REGISTRY_CAPACITY_EXCEEDED"
    BOUNDARY_STATE_CHANGED = "BOUNDARY_STATE_CHANGED"
    AUDIT_RECORD_FAILED = "AUDIT_RECORD_FAILED"


class ProductionBoundaryError(PermissionError):
    """Path-free error returned by the production candidate boundary."""

    def __init__(
        self,
        code: BoundaryErrorCode,
        message: str,
        *,
        detail_code: str | None = None,
        operation_reference: str | None = None,
    ) -> None:
        self.code = code
        self.detail_code = detail_code
        self.operation_reference = operation_reference
        self.message = message
        super().__init__(f"{code.value}: {message}")


def _validate_quarantine_date(value: str) -> str:
    if type(value) is not str or not _QUARANTINE_DATE.fullmatch(value):
        raise ProductionBoundaryError(
            BoundaryErrorCode.INVALID_ARGUMENT,
            "quarantine date is invalid",
        )
    try:
        parsed = datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError:
        raise ProductionBoundaryError(
            BoundaryErrorCode.INVALID_ARGUMENT,
            "quarantine date is invalid",
        ) from None
    if parsed.isoformat() != value:
        raise ProductionBoundaryError(
            BoundaryErrorCode.INVALID_ARGUMENT,
            "quarantine date is non-canonical",
        )
    return value


def _quarantine_date_from_pair_id(value: str) -> str:
    if type(value) is not str or not _QUARANTINE_PAIR_ID.fullmatch(value):
        raise ProductionBoundaryError(
            BoundaryErrorCode.INVALID_ARGUMENT,
            "quarantine recovery pair ID is invalid",
        )
    compact_date = value[:8]
    return _validate_quarantine_date(
        f"{compact_date[:4]}-{compact_date[4:6]}-{compact_date[6:8]}"
    )


class WriterUnavailableError(ProductionBoundaryError):
    def __init__(self, operation_reference: str | None = None) -> None:
        super().__init__(
            BoundaryErrorCode.CANDIDATE_ONLY,
            "M0-S2 has no production writer; mutation capabilities are unavailable",
            operation_reference=operation_reference,
        )


@dataclass(frozen=True, slots=True)
class BoundaryFailure:
    """Traceback-free public representation of a boundary rejection."""

    code: BoundaryErrorCode
    message: str
    detail_code: str | None = None
    operation_reference: str | None = None

    @classmethod
    def from_exception(cls, error: Exception) -> BoundaryFailure:
        if isinstance(error, ProductionBoundaryError):
            return cls(
                code=error.code,
                message=error.message,
                detail_code=error.detail_code,
                operation_reference=error.operation_reference,
            )
        return cls(
            code=BoundaryErrorCode.INVALID_ARGUMENT,
            message="candidate request failed safely",
            detail_code="UNEXPECTED_INTERNAL_ERROR",
        )

    def to_error(self) -> ProductionBoundaryError:
        return ProductionBoundaryError(
            self.code,
            self.message,
            detail_code=self.detail_code,
            operation_reference=self.operation_reference,
        )


@dataclass(frozen=True, slots=True)
class BoundaryResult(Generic[_ResultValue]):
    """A production result that never retains an internal exception or traceback."""

    value: _ResultValue | None = None
    failure: BoundaryFailure | None = None

    def __post_init__(self) -> None:
        if (self.value is None) == (self.failure is None):
            raise ValueError("boundary result must contain exactly one value or failure")

    @property
    def ok(self) -> bool:
        return self.failure is None

    @classmethod
    def success(cls, value: _ResultValue) -> BoundaryResult[_ResultValue]:
        if value is None:
            raise ValueError("successful boundary results require a value")
        return cls(value=value)

    @classmethod
    def failed(cls, error: Exception) -> BoundaryResult[_ResultValue]:
        return cls(failure=BoundaryFailure.from_exception(error))

    def require(self) -> _ResultValue:
        failure = self.failure
        if failure is not None:
            raise failure.to_error() from None
        value = self.value
        if value is None:  # Defensive against low-level object tampering.
            raise ProductionBoundaryError(
                BoundaryErrorCode.BOUNDARY_STATE_CHANGED,
                "boundary result state is invalid",
            )
        return value


class PairKind(StrEnum):
    PUBLISH = "PUBLISH"
    QUARANTINE = "QUARANTINE"


class CapabilityLifecycle(StrEnum):
    ISSUED = "ISSUED"
    RESERVED = "RESERVED"
    CONSUMED = "CONSUMED"
    FAILED = "FAILED"


@dataclass(frozen=True, slots=True)
class PairEvidence:
    manifest_id: str
    manifest_sha256: str
    source_tree_sha256: str
    entry_count: int
    total_bytes: int
    checkpoint_id: str
    checkpoint_manifest_sha256: str

    def __post_init__(self) -> None:
        validate_safe_id(self.manifest_id, field_name="manifest_id")
        validate_safe_id(self.checkpoint_id, field_name="checkpoint_id")
        for field_name in (
            "manifest_sha256",
            "source_tree_sha256",
            "checkpoint_manifest_sha256",
        ):
            if not _SHA256.fullmatch(getattr(self, field_name)):
                raise ContextError(
                    f"{field_name} must be a canonical lowercase SHA-256 digest"
                )
        if type(self.entry_count) is not int or self.entry_count < 1:
            raise ContextError("entry_count must be a positive integer")
        if type(self.total_bytes) is not int or self.total_bytes < 0:
            raise ContextError("total_bytes must be a non-negative integer")

    @property
    def digest(self) -> str:
        return _canonical_digest(
            {
                "manifest_id": self.manifest_id,
                "manifest_sha256": self.manifest_sha256,
                "source_tree_sha256": self.source_tree_sha256,
                "entry_count": self.entry_count,
                "total_bytes": self.total_bytes,
                "checkpoint_id": self.checkpoint_id,
                "checkpoint_manifest_sha256": self.checkpoint_manifest_sha256,
            },
            domain="PAIR-EVIDENCE-V1",
        )

    def __repr__(self) -> str:
        return "PairEvidence(ids='<redacted>', digests='<redacted>')"

    def __reduce__(self) -> Any:
        raise TypeError("pair evidence cannot be serialized")


class CandidateTicket:
    """Opaque candidate handle. It deliberately contains no filesystem path."""

    __slots__ = (
        "__ticket_id",
        "__boundary_instance_id",
        "__authenticator",
    )

    def __init__(
        self,
        ticket_id: str,
        boundary_instance_id: str,
        authenticator: bytes,
        *,
        _constructor: object,
    ) -> None:
        if _constructor is not _TOKEN_CONSTRUCTOR:
            raise TypeError("CandidateTicket is issued only by a workspace boundary")
        self.__ticket_id = ticket_id
        self.__boundary_instance_id = boundary_instance_id
        self.__authenticator = bytes(authenticator)

    @property
    def ticket_version(self) -> str:
        return "CANDIDATE-TOKEN-V2"

    def _read_claims(self, constructor: object) -> tuple[str, str, bytes]:
        if constructor is not _TOKEN_CONSTRUCTOR:
            raise TypeError("candidate claims are private")
        return self.__ticket_id, self.__boundary_instance_id, self.__authenticator

    def __repr__(self) -> str:
        return "CandidateTicket(ticket_version='CANDIDATE-TOKEN-V2', opaque=True)"

    def __reduce__(self) -> Any:
        raise TypeError("candidate capabilities cannot be serialized")


class _PairCandidateBase:
    __slots__ = ("__pair_id", "__boundary_instance_id", "__authenticator")

    token_kind: PairKind

    def __init__(
        self,
        pair_id: str,
        boundary_instance_id: str,
        authenticator: bytes,
        *,
        _constructor: object,
    ) -> None:
        if _constructor is not _TOKEN_CONSTRUCTOR:
            raise TypeError("pair candidates are issued only by a workspace boundary")
        self.__pair_id = pair_id
        self.__boundary_instance_id = boundary_instance_id
        self.__authenticator = bytes(authenticator)

    @property
    def ticket_version(self) -> str:
        return "PAIR-CANDIDATE-TOKEN-V2"

    def _read_claims(self, constructor: object) -> tuple[str, str, bytes]:
        if constructor is not _TOKEN_CONSTRUCTOR:
            raise TypeError("pair claims are private")
        return self.__pair_id, self.__boundary_instance_id, self.__authenticator

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(ticket_version='PAIR-CANDIDATE-TOKEN-V2', "
            "opaque=True)"
        )

    def __reduce__(self) -> Any:
        raise TypeError("pair capabilities cannot be serialized")


class MovePairCandidate(_PairCandidateBase):
    token_kind = PairKind.PUBLISH


class QuarantinePairCandidate(_PairCandidateBase):
    token_kind = PairKind.QUARANTINE


@dataclass(frozen=True, slots=True)
class CandidateDescriptor:
    ticket_id: str
    namespace: NamespaceId
    namespace_mode: NamespaceMode
    intent: PathIntent
    expected_kind: ExpectedKind
    pair_id: str | None
    pair_role: PairRole | None
    capability_state: str = "CANDIDATE_ONLY"


@dataclass(frozen=True, slots=True)
class PairDescriptor:
    pair_id: str
    kind: PairKind
    source_namespace: NamespaceId
    target_namespace: NamespaceId
    expected_kind: ExpectedKind
    evidence_digest: str
    topology_digest: str
    capability_state: str = "CANDIDATE_ONLY"


@dataclass(frozen=True, slots=True)
class _CandidateRecord:
    ticket_id: str
    core: GuardedPath
    context_digest: str
    context_ticket_id: str
    policy_version: str
    policy_digest: str
    namespace: NamespaceId
    namespace_mode: NamespaceMode
    pair_id: str | None
    pair_role: PairRole | None
    topology_digest: str | None
    evidence_digest: str | None
    authenticator: bytes
    lifecycle: CapabilityLifecycle = CapabilityLifecycle.ISSUED


@dataclass(frozen=True, slots=True)
class _ContextRecord:
    ticket_id: str
    claims_digest: str
    authenticator: bytes


class _JobContextPin:
    __slots__ = (
        "_core",
        "_ticket_id",
        "_pin_id",
        "_binding_sha256",
        "_owner_thread",
        "_closed",
    )

    def __init__(
        self,
        core: _BoundaryCore,
        ticket_id: str,
        pin_id: str,
        binding_sha256: str,
        *,
        _constructor: object,
    ) -> None:
        if _constructor is not _JOB_CONTEXT_PIN_CONSTRUCTOR:
            raise TypeError("job context pins require the fixed boundary core")
        self._core = core
        self._ticket_id = ticket_id
        self._pin_id = pin_id
        self._binding_sha256 = binding_sha256
        self._owner_thread = threading.get_ident()
        self._closed = False

    def __repr__(self) -> str:
        state = "CLOSED" if self._closed else "LIVE"
        return f"_JobContextPin(state='{state}', binding='<redacted>')"

    def __reduce__(self) -> Any:
        raise TypeError("job context pins cannot be serialized")


@dataclass(frozen=True, slots=True)
class _PairRecord:
    pair_id: str
    kind: PairKind
    source_ticket_id: str
    target_ticket_id: str
    context_digest: str
    context_ticket_id: str
    policy_version: str
    policy_digest: str
    expected_kind: ExpectedKind
    source_namespace: NamespaceId
    target_namespace: NamespaceId
    topology_digest: str
    evidence: PairEvidence
    effective_classification: DataClassification
    issued_date_utc: str
    authenticator: bytes
    lifecycle: CapabilityLifecycle = CapabilityLifecycle.ISSUED


class _ReservedPairLease:
    """Exact, thread-bound authority for one RESERVED pair lifecycle."""

    __slots__ = (
        "_core",
        "_pair",
        "_source",
        "_target",
        "_context_digest",
        "_context_pin",
        "_context_binding",
        "_owner_thread",
        "_closed",
    )

    def __init__(
        self,
        core: _BoundaryCore,
        pair: _PairRecord,
        source: _CandidateRecord,
        target: _CandidateRecord,
        context_digest: str,
        context_pin: _JobContextPin | None,
        context_binding: str | None,
        *,
        _constructor: object,
    ) -> None:
        if (
            _constructor is not _PAIR_RESERVATION_CONSTRUCTOR
            or type(pair) is not _PairRecord
            or type(source) is not _CandidateRecord
            or type(target) is not _CandidateRecord
            or pair.lifecycle is not CapabilityLifecycle.RESERVED
            or source.lifecycle is not CapabilityLifecycle.RESERVED
            or target.lifecycle is not CapabilityLifecycle.RESERVED
        ):
            raise TypeError("reserved pair leases require exact RESERVED records")
        self._core = core
        self._pair = pair
        self._source = source
        self._target = target
        self._context_digest = context_digest
        self._context_pin = context_pin
        self._context_binding = context_binding
        self._owner_thread = threading.get_ident()
        self._closed = False

    def __repr__(self) -> str:
        state = "CLOSED" if self._closed else "LIVE"
        return f"_ReservedPairLease(state='{state}', pair='<redacted>')"

    def __reduce__(self) -> Any:
        raise TypeError("reserved pair leases cannot be serialized")


@dataclass(frozen=True, slots=True)
class _ReservedPairView:
    pair_id: str
    kind: PairKind
    source_relative_path: Path
    target_relative_path: Path
    evidence: PairEvidence
    topology_digest: str
    effective_classification: DataClassification

    def __reduce__(self) -> Any:
        raise TypeError("reserved pair views cannot be serialized")


@dataclass(frozen=True, slots=True, repr=False)
class _RestrictedRecoveryLocatorRecord:
    """Boundary-owned authority truth for one opaque recovery locator."""

    locator_id: str = field(repr=False)
    core_instance_id: str = field(repr=False)
    purpose: str = field(repr=False)
    context: OperationContext = field(repr=False, compare=False)
    context_digest: str = field(repr=False)
    context_ticket_id: str = field(repr=False)
    transaction_id: str = field(repr=False)
    owner_thread: int = field(repr=False)
    owner_thread_object: threading.Thread = field(repr=False, compare=False)
    owner_thread_object_binding_sha256: str = field(repr=False)
    source_relative_path: Path = field(repr=False)
    target_relative_path: Path = field(repr=False)
    policy_version: str = field(repr=False)
    policy_digest: str = field(repr=False)
    binding_sha256: str = field(repr=False)
    capability_authenticator: bytes = field(repr=False)
    lifecycle: CapabilityLifecycle = CapabilityLifecycle.ISSUED

    def __repr__(self) -> str:
        return (
            "_RestrictedRecoveryLocatorRecord("
            f"lifecycle='{self.lifecycle.value}', locator='<redacted>')"
        )

    def __reduce__(self) -> Any:
        raise TypeError("restricted recovery locator records cannot be serialized")


class _RestrictedRecoveryLocatorCapability:
    """Opaque handle to boundary-owned, single-use recovery authority."""

    __slots__ = ("__locator_id", "__authenticator")

    def __init__(
        self,
        locator_id: str,
        authenticator: bytes,
        *,
        _constructor: object,
    ) -> None:
        if (
            _constructor is not _RECOVERY_LOCATOR_CONSTRUCTOR
            or type(locator_id) is not str
            or not _SHA256.fullmatch(locator_id)
            or type(authenticator) is not bytes
            or len(authenticator) != hashlib.sha256().digest_size
        ):
            raise TypeError("restricted recovery locators require boundary authority")
        self.__locator_id = locator_id
        self.__authenticator = bytes(authenticator)

    def _read(self, constructor: object) -> tuple[str, bytes]:
        if constructor is not _RECOVERY_LOCATOR_CONSTRUCTOR:
            raise TypeError("restricted recovery locator capabilities are opaque")
        return self.__locator_id, self.__authenticator

    def __repr__(self) -> str:
        return "_RestrictedRecoveryLocatorCapability(opaque=True)"

    def __reduce__(self) -> Any:
        raise TypeError("restricted recovery locator capabilities cannot be serialized")


class _BoundaryPairClaim:
    __slots__ = ("__payload", "__authenticator")

    def __init__(
        self,
        payload: dict[str, Any],
        authenticator: bytes,
        *,
        _constructor: object,
    ) -> None:
        if _constructor is not _TOKEN_CONSTRUCTOR:
            raise TypeError("boundary pair claims are sealed")
        self.__payload = dict(payload)
        self.__authenticator = bytes(authenticator)

    def _read(self, constructor: object) -> tuple[dict[str, Any], bytes]:
        if constructor is not _TOKEN_CONSTRUCTOR:
            raise TypeError("boundary pair claims are opaque")
        return dict(self.__payload), self.__authenticator

    def __repr__(self) -> str:
        return "_BoundaryPairClaim(opaque=True)"

    def __reduce__(self) -> Any:
        raise TypeError("boundary pair claims cannot be serialized")


class _BoundaryNamespacePolicy(NamespacePolicy):
    """Sealed pair-capable policy owned only by the fixed boundary core."""

    __slots__ = ("__pair_claim_key", "__pair_policy_seal")

    def __init__(self, *, _constructor: object) -> None:
        if _constructor is not _PRODUCTION_BOUNDARY_CONSTRUCTOR:
            raise TypeError("pair-capable policy construction is boundary-only")
        super().__init__()
        self.__pair_claim_key = secrets.token_bytes(32)
        self.__pair_policy_seal = object()
        self._install_boundary_pair_seal(self.__pair_policy_seal)

    def _authorize_pair(
        self,
        source: GuardedPath,
        target: GuardedPath,
        context: OperationContext,
        *,
        pair_id: str,
        evidence_digest: str,
    ) -> tuple[NamespaceDecision, NamespaceDecision]:
        if type(source) is not GuardedPath or type(target) is not GuardedPath:
            raise TypeError("paired authorization requires exact GuardedPath values")
        if type(context) is not OperationContext:
            raise TypeError("paired authorization requires an exact OperationContext")
        validate_safe_id(pair_id, field_name="pair_id")
        if not _SHA256.fullmatch(evidence_digest):
            raise ValueError("evidence_digest must be a lowercase SHA-256 digest")
        valid_intents = {
            (PathIntent.MOVE_SOURCE, PathIntent.MOVE_TARGET),
            (PathIntent.QUARANTINE_SOURCE, PathIntent.QUARANTINE_TARGET),
        }
        if (source.intent, target.intent) not in valid_intents:
            decision = self.classify(source.relative_path)
            self._reject(
                PolicyErrorCode.PAIR_TOPOLOGY_INVALID,
                source,
                decision,
                "paired policy members have incompatible intents",
            )
        payload = self._pair_claim_payload(
            source,
            target,
            context,
            pair_id=pair_id,
            evidence_digest=evidence_digest,
        )
        authenticator = hmac.new(
            self.__pair_claim_key,
            b"BOUNDARY-POLICY-PAIR-V1\0" + _canonical_json_bytes(payload),
            hashlib.sha256,
        ).digest()
        claim = _BoundaryPairClaim(
            payload,
            authenticator,
            _constructor=_TOKEN_CONSTRUCTOR,
        )
        return (
            self._authorize_pair_member(source, context, claim=claim, role="source"),
            self._authorize_pair_member(target, context, claim=claim, role="target"),
        )

    def _authorize_pair_member(
        self,
        ticket: GuardedPath,
        context: OperationContext,
        *,
        claim: _BoundaryPairClaim,
        role: str,
    ) -> NamespaceDecision:
        if type(claim) is not _BoundaryPairClaim or role not in {"source", "target"}:
            raise TypeError("paired policy member requires an exact opaque claim")
        payload, supplied = claim._read(_TOKEN_CONSTRUCTOR)
        expected = hmac.new(
            self.__pair_claim_key,
            b"BOUNDARY-POLICY-PAIR-V1\0" + _canonical_json_bytes(payload),
            hashlib.sha256,
        ).digest()
        if not hmac.compare_digest(supplied, expected):
            raise PermissionError("boundary pair claim authenticator is invalid")
        prefix = f"{role}_"
        expected_member = {
            f"{prefix}ticket_id": ticket.ticket_id,
            f"{prefix}path": ticket.relative_path.as_posix(),
            f"{prefix}intent": ticket.intent.value,
            f"{prefix}kind": ticket.expected_kind.value,
            "context_digest": context.digest,
            "context_ticket_id": context.authority_ticket_id or "",
            "policy_digest": self.digest,
        }
        if any(payload.get(key) != value for key, value in expected_member.items()):
            raise PermissionError("boundary pair claim does not match this member")
        return self._NamespacePolicy__authorize(
            ticket,
            context,
            pair_seal=self.__pair_policy_seal,
        )

    def _pair_claim_payload(
        self,
        source: GuardedPath,
        target: GuardedPath,
        context: OperationContext,
        *,
        pair_id: str,
        evidence_digest: str,
    ) -> dict[str, Any]:
        return {
            "pair_id": pair_id,
            "evidence_digest": evidence_digest,
            "context_digest": context.digest,
            "context_ticket_id": context.authority_ticket_id or "",
            "policy_digest": self.digest,
            "source_ticket_id": source.ticket_id,
            "source_path": source.relative_path.as_posix(),
            "source_intent": source.intent.value,
            "source_kind": source.expected_kind.value,
            "target_ticket_id": target.ticket_id,
            "target_path": target.relative_path.as_posix(),
            "target_intent": target.intent.value,
            "target_kind": target.expected_kind.value,
        }


class _BoundaryCore:
    def __init__(
        self,
        *,
        guard: WorkspaceGuard,
        expected_workspace_root: Path,
        audit_sink: AuditSink | None = None,
        audit_authority: _AuditAuthority | None = None,
    ) -> None:
        if audit_sink is not None and audit_authority is not None:
            raise TypeError("audit sink and durable audit authority are mutually exclusive")
        if audit_authority is not None and type(audit_authority) is not _AuditAuthority:
            raise TypeError("durable audit authority must be factory-issued")
        self.__guard = guard
        self.__expected_workspace_root = _absolute_lexical(expected_workspace_root)
        self.__policy = _BoundaryNamespacePolicy(
            _constructor=_PRODUCTION_BOUNDARY_CONSTRUCTOR,
        )
        self.__policy_digest = self.__policy.digest
        self.__instance_id = secrets.token_hex(16).upper()
        self.__candidate_key = secrets.token_bytes(32)
        self.__pair_key = secrets.token_bytes(32)
        self.__context_authority_id = secrets.token_hex(16).upper()
        self.__context_key = secrets.token_bytes(32)
        self.__audit_hmac_key = secrets.token_bytes(32)
        self.__audit_authority = audit_authority
        self.__durable_audit_sink = (
            None if audit_authority is None else audit_authority.sink
        )
        self.__audit_sink = (
            audit_sink or CollectingAuditSink()
            if audit_authority is None
            else audit_authority.sink
        )
        self.__candidate_records: dict[str, _CandidateRecord] = {}
        self.__pair_records: dict[str, _PairRecord] = {}
        self.__context_records: dict[str, _ContextRecord] = {}
        self.__job_context_pins: dict[str, _JobContextPin] = {}
        self.__pair_reservations: dict[str, _ReservedPairLease] = {}
        self.__restricted_recovery_records: dict[
            str,
            _RestrictedRecoveryLocatorRecord,
        ] = {}
        self.__candidate_tombstones: dict[str, CapabilityLifecycle] = {}
        self.__pair_tombstones: dict[str, CapabilityLifecycle] = {}
        self.__lock = threading.RLock()
        self._assert_invariants()

    @property
    def project_root(self) -> Path:
        return self.__guard.workspace_root

    @property
    def policy_digest(self) -> str:
        return self.__policy.digest

    @property
    def audit_events(self) -> tuple[AuditEvent, ...]:
        events = getattr(self.__audit_sink, "events", ())
        return tuple(events)

    @property
    def diagnostic_registry_counts(self) -> dict[str, int]:
        """Path-free counts exposed only through the Test-local facade."""

        with self.__lock:
            counts = {
                "candidate_live": len(self.__candidate_records),
                "pair_live": len(self.__pair_records),
                "context_live": len(self.__context_records),
                "job_context_pins": len(self.__job_context_pins),
                "pair_reservations": len(self.__pair_reservations),
                "restricted_recovery_live": len(
                    self.__restricted_recovery_records
                ),
                "candidate_tombstones": len(self.__candidate_tombstones),
                "pair_tombstones": len(self.__pair_tombstones),
                "pair_consumed_tombstones": sum(
                    state is CapabilityLifecycle.CONSUMED
                    for state in self.__pair_tombstones.values()
                ),
                "pair_failed_tombstones": sum(
                    state is CapabilityLifecycle.FAILED
                    for state in self.__pair_tombstones.values()
                ),
            }
        counts["guard_live"] = self.__guard.live_ticket_count
        return counts

    def issue_candidate(
        self,
        relative_path: str | os.PathLike[str],
        *,
        intent: PathIntent,
        expected_kind: ExpectedKind,
        context: OperationContext,
        allow_mutation_candidate: bool,
    ) -> CandidateTicket:
        safe_relative: Path | None = None
        safe_context = context if type(context) is OperationContext else None
        core: GuardedPath | None = None
        failure: ProductionBoundaryError | None = None
        try:
            self._assert_invariants()
            self._validate_request_types(intent, expected_kind, context)
            safe_relative = self._require_relative(relative_path)
            if intent.mutating and not allow_mutation_candidate:
                raise WriterUnavailableError(_public_operation_reference(context))
            with self.__lock:
                self._ensure_registry_capacity(candidate_items=1, pair_items=0)
            core = self.__guard.authorize(
                safe_relative,
                intent=intent,
                expected_kind=expected_kind,
            )
            decision = self.__policy.authorize(core, context)
            self._attest_copy_ledger_read(decision, context)
            record, token = self._build_single_candidate(core, decision, context)
            effective = _boundary_effective_classification(context, decision)
            with self.__lock:
                self._ensure_registry_capacity(candidate_items=1, pair_items=0)
                self._validate_context_authority(context)
                self.__candidate_records[record.ticket_id] = record
                try:
                    self._record_audit_factory(
                        lambda audit_hmac_key: (
                            self._candidate_event(
                                record,
                                context=context,
                                decision=decision,
                                action=AuditAction.ISSUE,
                                audit_hmac_key=audit_hmac_key,
                            ),
                        ),
                        (
                            None
                            if effective is DataClassification.RESTRICTED
                            else _public_operation_reference(context)
                        ),
                    )
                except Exception:
                    self.__candidate_records.pop(record.ticket_id, None)
                    raise
            return token
        except Exception as exc:
            if core is not None:
                try:
                    self._release_core_tickets(core)
                except Exception as cleanup_error:
                    exc = cleanup_error
            failure = self._failure_after_denial(
                error=exc,
                relative_path=safe_relative,
                intent=intent,
                expected_kind=expected_kind,
                context=safe_context,
                capability_kind=CapabilityKind.SINGLE,
            )
        raise failure from None

    def _attest_copy_ledger_read(
        self,
        decision: NamespaceDecision,
        context: OperationContext,
    ) -> None:
        """Bind public Copy-ledger reads to an authenticated run/epoch map.

        NamespacePolicy validates the path shape and scope equality.  It is not
        itself storage authority, so the fixed boundary additionally derives
        the opaque epoch from the in-memory RUN_ID and every audit-activated
        revision under the durable writer mutex.  No raw RUN_ID or attestation
        registry is persisted.  The resulting read ticket authenticates this
        path mapping only; a consumer must still parse and HMAC-verify the
        segment through DurableCopyLedgers before treating its bytes as fact.
        """

        if decision.namespace not in {
            NamespaceId.COPY_SOURCE_LEDGER,
            NamespaceId.COPY_OPERATION_LEDGER,
        }:
            return
        authority = self.__audit_authority
        try:
            scoped_run = context.scope_value(ScopeKind.RUN_ID)
            scoped_epoch = context.scope_value(
                ScopeKind.COPY_LEDGER_EPOCH_ID
            )
            if (
                type(authority) is not _AuditAuthority
                or decision.rule.scope_bindings
                != (ScopeBinding(0, ScopeKind.COPY_LEDGER_EPOCH_ID),)
                or len(decision.tail) != 2
                or scoped_run != context.run_id
                or scoped_epoch is None
                or decision.tail[0] != scoped_epoch
            ):
                raise ValueError("copy ledger read attestation is unavailable")
            with authority.writer.acquire_runtime_mutex() as lease:
                authority.ledger._rescan_under_existing_mutex(lease)
                activated_revision_ids = set(
                    authority.ledger._activated_revision_ids_under_existing_mutex(
                        lease
                    )
                )
                inventory = authority.key_store._load_all_under_mutex()
                if activated_revision_ids - set(inventory):
                    raise ValueError(
                        "copy ledger read revision inventory is incomplete"
                    )
                matching = tuple(
                    revision
                    for revision_id, revision in sorted(inventory.items())
                    if revision_id in activated_revision_ids
                    and hmac.compare_digest(
                        scoped_epoch,
                        _derive_copy_ledger_epoch_id(
                            revision,
                            context.run_id,
                        ),
                    )
                )
            if len(matching) != 1:
                raise ValueError(
                    "copy ledger read run/epoch mapping is not unique"
                )
        except Exception:
            raise ProductionBoundaryError(
                BoundaryErrorCode.POLICY_DENIED,
                "copy ledger read requires authenticated run/epoch ancestry",
                operation_reference=None,
            ) from None

    def issue_test_context(
        self,
        *,
        run_id: str,
        job_id: str,
        operation_id: str,
        caller: Any,
        purpose: Any,
        scopes: tuple[Any, ...] = (),
        manifest_id: str | None = None,
        classification: DataClassification = DataClassification.INTERNAL,
    ) -> OperationContext:
        """Issue a context only for the private Test-local boundary."""

        ticket_id = secrets.token_hex(16).upper()
        unsigned = OperationContext(
            run_id=run_id,
            job_id=job_id,
            operation_id=operation_id,
            caller=caller,
            purpose=purpose,
            scopes=scopes,
            manifest_id=manifest_id,
            classification=classification,
            authority_id=self.__context_authority_id,
            authority_ticket_id=ticket_id,
            authenticator=b"\0" * 32,
        )
        authenticator = self._context_authenticator(ticket_id, unsigned)
        context = replace(unsigned, authenticator=authenticator)
        record = _ContextRecord(
            ticket_id=ticket_id,
            claims_digest=context.digest,
            authenticator=authenticator,
        )
        with self.__lock:
            if len(self.__context_records) >= _MAX_REGISTRY_ITEMS:
                raise ProductionBoundaryError(
                    BoundaryErrorCode.REGISTRY_CAPACITY_EXCEEDED,
                    "context authority registry capacity was reached",
                )
            self.__context_records[ticket_id] = record
        return context

    def release_test_context(self, context: OperationContext) -> bool:
        """Revoke a Test-local operation context after its operation closes."""

        self._assert_invariants()
        ticket_id = self._validate_context_claim(context)
        cores: list[GuardedPath] = []
        with self.__lock:
            record = self.__context_records.get(ticket_id)
            if record is None:
                return False
            if record.claims_digest != context.digest or not hmac.compare_digest(
                record.authenticator,
                context.authenticator,
            ):
                raise ProductionBoundaryError(
                    BoundaryErrorCode.INVALID_CONTEXT,
                    "operation context authority binding is invalid",
                )
            if ticket_id in self.__job_context_pins:
                raise ProductionBoundaryError(
                    BoundaryErrorCode.INVALID_CONTEXT,
                    "operation context cannot close while a job operation is pinned",
                )
            related_candidates = tuple(
                candidate
                for candidate in self.__candidate_records.values()
                if candidate.context_ticket_id == ticket_id
            )
            related_pairs = tuple(
                pair
                for pair in self.__pair_records.values()
                if pair.context_ticket_id == ticket_id
            )
            if any(
                candidate.lifecycle is CapabilityLifecycle.RESERVED
                for candidate in related_candidates
            ) or any(pair.lifecycle is CapabilityLifecycle.RESERVED for pair in related_pairs) or any(
                lease._pair.context_ticket_id == ticket_id
                for lease in self.__pair_reservations.values()
            ):
                raise ProductionBoundaryError(
                    BoundaryErrorCode.INVALID_CONTEXT,
                    "operation context cannot close while a capability is reserved",
                )
            for pair in related_pairs:
                self.__pair_records.pop(pair.pair_id, None)
                self._remember_tombstone(self.__pair_tombstones, pair.pair_id)
            for candidate in related_candidates:
                self.__candidate_records.pop(candidate.ticket_id, None)
                self._remember_tombstone(
                    self.__candidate_tombstones,
                    candidate.ticket_id,
                )
                cores.append(candidate.core)
            self._revoke_restricted_recovery_records(ticket_id)
            del self.__context_records[ticket_id]
        if cores:
            self._release_core_tickets(*cores)
        return True

    def issue_restricted_recovery_locator(
        self,
        context: OperationContext,
        transaction_id: str,
        *,
        _purpose: str = _RESTRICTED_RECOVERY_PURPOSE_PUBLISH,
        _quarantine_pair_id: str | None = None,
    ) -> _RestrictedRecoveryLocatorCapability:
        """Issue an opaque handle to boundary-owned RESTRICTED recovery authority."""

        self._assert_invariants()
        if type(_purpose) is not str or _purpose not in _RESTRICTED_RECOVERY_PURPOSES:
            raise ProductionBoundaryError(
                BoundaryErrorCode.INVALID_ARGUMENT,
                "restricted recovery purpose is invalid",
            )
        try:
            canonical_transaction = validate_safe_id(
                transaction_id,
                field_name="transaction_id",
            )
        except Exception:
            raise ProductionBoundaryError(
                BoundaryErrorCode.INVALID_ARGUMENT,
                "restricted recovery transaction is invalid",
            ) from None
        self._validate_context_authority(context)
        source, target = self._derive_restricted_recovery_paths(
            context,
            _purpose,
            quarantine_pair_id=_quarantine_pair_id,
        )
        ticket_id = context.authority_ticket_id
        if ticket_id is None:
            raise AssertionError("validated recovery context lost its authority")
        owner_thread = threading.get_ident()
        owner_thread_object = threading.current_thread()
        if owner_thread_object.ident != owner_thread:
            raise ProductionBoundaryError(
                BoundaryErrorCode.BOUNDARY_STATE_CHANGED,
                "restricted recovery thread identity changed during issue",
            )
        owner_thread_object_binding = (
            self._restricted_recovery_owner_thread_object_binding(
                owner_thread_object
            )
        )
        with self.__lock:
            self._validate_context_authority(context)
            if len(self.__restricted_recovery_records) >= _MAX_REGISTRY_ITEMS:
                raise ProductionBoundaryError(
                    BoundaryErrorCode.REGISTRY_CAPACITY_EXCEEDED,
                    "restricted recovery registry capacity was reached",
                )
            locator_id = secrets.token_hex(32)
            if locator_id in self.__restricted_recovery_records:
                raise ProductionBoundaryError(
                    BoundaryErrorCode.BOUNDARY_STATE_CHANGED,
                    "restricted recovery locator collision was rejected",
                )
            binding = self._restricted_recovery_locator_binding(
                locator_id,
                context,
                canonical_transaction,
                source,
                target,
                _purpose,
                owner_thread,
                owner_thread_object_binding,
            )
            authenticator = self._restricted_recovery_capability_authenticator(
                locator_id,
                binding,
            )
            capability = _RestrictedRecoveryLocatorCapability(
                locator_id,
                authenticator,
                _constructor=_RECOVERY_LOCATOR_CONSTRUCTOR,
            )
            self.__restricted_recovery_records[locator_id] = (
                _RestrictedRecoveryLocatorRecord(
                    locator_id=locator_id,
                    core_instance_id=self.__instance_id,
                    purpose=_purpose,
                    context=context,
                    context_digest=context.digest,
                    context_ticket_id=ticket_id,
                    transaction_id=canonical_transaction,
                    owner_thread=owner_thread,
                    owner_thread_object=owner_thread_object,
                    owner_thread_object_binding_sha256=(
                        owner_thread_object_binding
                    ),
                    source_relative_path=Path(source),
                    target_relative_path=Path(target),
                    policy_version=POLICY_VERSION,
                    policy_digest=self.__policy.digest,
                    binding_sha256=binding,
                    capability_authenticator=authenticator,
                )
            )
            return capability

    def issue_restricted_copy_recovery_locator(
        self,
        context: OperationContext,
    ) -> _RestrictedRecoveryLocatorCapability:
        """Issue one Copy-reconcile locator for this exact live context."""

        binding_id = self._restricted_copy_recovery_binding_id(context)
        return self.issue_restricted_recovery_locator(
            context,
            binding_id,
            _purpose=_RESTRICTED_RECOVERY_PURPOSE_COPY,
        )

    def consume_restricted_recovery_locator(
        self,
        capability: _RestrictedRecoveryLocatorCapability,
        transaction_id: str,
        *,
        _purpose: str = _RESTRICTED_RECOVERY_PURPOSE_PUBLISH,
        _expected_context: OperationContext | None = None,
    ) -> tuple[Path, Path]:
        """Validate and consume an opaque locator before any recovery observe."""

        self._assert_invariants()
        if type(_purpose) is not str or _purpose not in _RESTRICTED_RECOVERY_PURPOSES:
            raise ProductionBoundaryError(
                BoundaryErrorCode.INVALID_ARGUMENT,
                "restricted recovery purpose is invalid",
            )
        try:
            canonical_transaction = validate_safe_id(
                transaction_id,
                field_name="transaction_id",
            )
        except Exception:
            raise ProductionBoundaryError(
                BoundaryErrorCode.INVALID_ARGUMENT,
                "restricted recovery transaction is invalid",
            ) from None
        if type(capability) is not _RestrictedRecoveryLocatorCapability:
            raise ProductionBoundaryError(
                BoundaryErrorCode.INVALID_ARGUMENT,
                "restricted recovery requires its exact locator capability",
            )
        try:
            locator_id, supplied_authenticator = capability._read(
                _RECOVERY_LOCATOR_CONSTRUCTOR
            )
        except Exception:
            raise ProductionBoundaryError(
                BoundaryErrorCode.INVALID_CONTEXT,
                "restricted recovery locator is consumed, foreign, or changed",
            ) from None
        if (
            type(locator_id) is not str
            or not _SHA256.fullmatch(locator_id)
            or type(supplied_authenticator) is not bytes
            or len(supplied_authenticator) != hashlib.sha256().digest_size
        ):
            raise ProductionBoundaryError(
                BoundaryErrorCode.INVALID_CONTEXT,
                "restricted recovery locator is consumed, foreign, or changed",
            )
        with self.__lock:
            record = self.__restricted_recovery_records.get(locator_id)
            valid = type(record) is _RestrictedRecoveryLocatorRecord
            if valid:
                assert record is not None
                try:
                    current_owner_thread = threading.get_ident()
                    current_owner_thread_object = threading.current_thread()
                    current_owner_thread_object_binding = (
                        self._restricted_recovery_owner_thread_object_binding(
                            current_owner_thread_object
                        )
                    )
                    quarantine_pair_id = (
                        record.target_relative_path.name
                        if record.context.purpose is Purpose.QUARANTINE
                        else None
                    )
                    expected_source, expected_target = (
                        self._derive_restricted_recovery_paths(
                            record.context,
                            record.purpose,
                            quarantine_pair_id=quarantine_pair_id,
                        )
                    )
                    self._validate_context_authority(record.context)
                    expected_binding = self._restricted_recovery_locator_binding(
                        record.locator_id,
                        record.context,
                        record.transaction_id,
                        expected_source,
                        expected_target,
                        record.purpose,
                        current_owner_thread,
                        current_owner_thread_object_binding,
                    )
                    expected_authenticator = (
                        self._restricted_recovery_capability_authenticator(
                            record.locator_id,
                            expected_binding,
                        )
                    )
                    valid = (
                        type(record.locator_id) is str
                        and record.locator_id == locator_id
                        and type(record.core_instance_id) is str
                        and record.core_instance_id == self.__instance_id
                        and type(record.purpose) is str
                        and record.purpose == _purpose
                        and type(record.context_digest) is str
                        and record.context_digest == record.context.digest
                        and type(record.context_ticket_id) is str
                        and record.context_ticket_id
                        == record.context.authority_ticket_id
                        and type(record.transaction_id) is str
                        and record.transaction_id == canonical_transaction
                        and type(record.owner_thread) is int
                        and record.owner_thread == current_owner_thread
                        and isinstance(record.owner_thread_object, threading.Thread)
                        and record.owner_thread_object
                        is current_owner_thread_object
                        and record.owner_thread_object.ident == record.owner_thread
                        and type(record.owner_thread_object_binding_sha256) is str
                        and _SHA256.fullmatch(
                            record.owner_thread_object_binding_sha256
                        )
                        is not None
                        and hmac.compare_digest(
                            record.owner_thread_object_binding_sha256,
                            current_owner_thread_object_binding,
                        )
                        and type(record.source_relative_path) is type(expected_source)
                        and type(record.target_relative_path) is type(expected_target)
                        and record.source_relative_path.as_posix()
                        == expected_source.as_posix()
                        and record.target_relative_path.as_posix()
                        == expected_target.as_posix()
                        and type(record.policy_version) is str
                        and record.policy_version == POLICY_VERSION
                        and type(record.policy_digest) is str
                        and record.policy_digest == self.__policy.digest
                        and record.lifecycle is CapabilityLifecycle.ISSUED
                        and type(record.binding_sha256) is str
                        and _SHA256.fullmatch(record.binding_sha256) is not None
                        and type(record.capability_authenticator) is bytes
                        and len(record.capability_authenticator)
                        == hashlib.sha256().digest_size
                        and (
                            _expected_context is None
                            or record.context is _expected_context
                        )
                        and hmac.compare_digest(
                            record.binding_sha256,
                            expected_binding,
                        )
                        and hmac.compare_digest(
                            record.capability_authenticator,
                            expected_authenticator,
                        )
                        and hmac.compare_digest(
                            supplied_authenticator,
                            expected_authenticator,
                        )
                    )
                    if valid and record.purpose == _RESTRICTED_RECOVERY_PURPOSE_COPY:
                        valid = (
                            record.transaction_id
                            == self._restricted_copy_recovery_binding_id(
                                record.context
                            )
                        )
                except Exception:
                    valid = False
            if not valid or record is None:
                raise ProductionBoundaryError(
                    BoundaryErrorCode.INVALID_CONTEXT,
                    "restricted recovery locator is consumed, foreign, or changed",
                )
            removed = self.__restricted_recovery_records.pop(locator_id, None)
            if removed is not record:
                if removed is not None:
                    self.__restricted_recovery_records[locator_id] = removed
                raise ProductionBoundaryError(
                    BoundaryErrorCode.BOUNDARY_STATE_CHANGED,
                    "restricted recovery registry changed during consume",
                )
            return (
                expected_source,
                expected_target,
            )

    def consume_restricted_copy_recovery_locator(
        self,
        capability: _RestrictedRecoveryLocatorCapability,
        context: OperationContext,
    ) -> tuple[Path, Path]:
        """Consume a Copy-reconcile locator only for its exact issuing context."""

        binding_id = self._restricted_copy_recovery_binding_id(context)
        return self.consume_restricted_recovery_locator(
            capability,
            binding_id,
            _purpose=_RESTRICTED_RECOVERY_PURPOSE_COPY,
            _expected_context=context,
        )

    def _restricted_copy_recovery_binding_id(
        self,
        context: OperationContext,
    ) -> str:
        self._validate_context_authority(context)
        scope_kinds = frozenset(scope.kind for scope in context.scopes)
        if (
            scope_kinds != _RESTRICTED_COPY_RECOVERY_SCOPE_KINDS
            or context.classification is not DataClassification.RESTRICTED
            or context.caller is not Caller.IMPORT_SERVICE
            or context.purpose is not Purpose.COPY_SOURCE
            or context.scope_value(ScopeKind.RUN_ID) != context.run_id
            or context.scope_value(ScopeKind.JOB_ID) != context.job_id
            or context.scope_value(ScopeKind.OPERATION_ID) != context.operation_id
            or context.scope_value(ScopeKind.MANIFEST_ID) != context.manifest_id
        ):
            raise ProductionBoundaryError(
                BoundaryErrorCode.INVALID_CONTEXT,
                "restricted Copy recovery context is not exact",
                operation_reference=_public_operation_reference(context),
            )
        ticket_id = context.authority_ticket_id
        if ticket_id is None:
            raise AssertionError("validated Copy recovery context lost its authority")
        return f"COPYREC-{ticket_id}"

    def _derive_restricted_recovery_paths(
        self,
        context: OperationContext,
        purpose: str,
        *,
        quarantine_pair_id: str | None = None,
    ) -> tuple[Path, Path]:
        scope_values = {scope.kind: scope.value for scope in context.scopes}
        publish_scope_kinds = frozenset(
            {
                ScopeKind.RUN_ID,
                ScopeKind.JOB_ID,
                ScopeKind.OPERATION_ID,
                ScopeKind.MANIFEST_ID,
                ScopeKind.COPY_ID,
                ScopeKind.CHECKPOINT_ID,
            }
        )
        scope_kinds = frozenset(scope_values)
        scopes_are_exact = (
            scope_kinds == _RESTRICTED_COPY_RECOVERY_SCOPE_KINDS
            if purpose == _RESTRICTED_RECOVERY_PURPOSE_COPY
            else scope_kinds
            in (publish_scope_kinds, _RESTRICTED_COPY_RECOVERY_SCOPE_KINDS)
        )
        quarantine_recovery = (
            type(context) is OperationContext
            and purpose == _RESTRICTED_RECOVERY_PURPOSE_PUBLISH
            and context.purpose is Purpose.QUARANTINE
        )
        expected_context_purpose = (
            Purpose.QUARANTINE
            if quarantine_recovery
            else Purpose.COPY_SOURCE
        )
        if (
            type(context) is not OperationContext
            or type(purpose) is not str
            or purpose not in _RESTRICTED_RECOVERY_PURPOSES
            or not scopes_are_exact
            or context.classification is not DataClassification.RESTRICTED
            or context.caller is not Caller.IMPORT_SERVICE
            or context.purpose is not expected_context_purpose
            or scope_values.get(ScopeKind.RUN_ID) != context.run_id
            or scope_values.get(ScopeKind.JOB_ID) != context.job_id
            or scope_values.get(ScopeKind.OPERATION_ID) != context.operation_id
            or scope_values.get(ScopeKind.MANIFEST_ID) != context.manifest_id
        ):
            raise ProductionBoundaryError(
                BoundaryErrorCode.INVALID_CONTEXT,
                "restricted recovery context is not exact",
                operation_reference=_public_operation_reference(
                    context if type(context) is OperationContext else None
                ),
            )
        copy_id = scope_values.get(ScopeKind.COPY_ID)
        if copy_id is None or context.manifest_id is None:
            raise AssertionError("validated recovery scopes became unavailable")
        if quarantine_recovery:
            if type(quarantine_pair_id) is not str:
                raise ProductionBoundaryError(
                    BoundaryErrorCode.INVALID_ARGUMENT,
                    "quarantine recovery requires its authenticated pair ID",
                )
            quarantine_date = _quarantine_date_from_pair_id(
                quarantine_pair_id
            )
            return (
                Path("Copy") / "restricted" / copy_id,
                Path("data")
                / "quarantine"
                / DataClassification.RESTRICTED.value
                / quarantine_date
                / quarantine_pair_id,
            )
        if quarantine_pair_id is not None:
            raise ProductionBoundaryError(
                BoundaryErrorCode.INVALID_ARGUMENT,
                "non-quarantine recovery cannot carry a quarantine pair ID",
            )
        return (
            Path("tmp")
            / "jobs"
            / DataClassification.RESTRICTED.value
            / context.job_id
            / "publish"
            / context.manifest_id,
            Path("Copy") / "restricted" / copy_id,
        )

    def _restricted_recovery_locator_binding(
        self,
        locator_id: str,
        context: OperationContext,
        transaction_id: str,
        source: Path,
        target: Path,
        purpose: str,
        owner_thread: int,
        owner_thread_object_binding_sha256: str,
    ) -> str:
        payload = _canonical_json_bytes(
            {
                "locator_id": locator_id,
                "core_instance_id": self.__instance_id,
                "purpose": purpose,
                "context_digest": context.digest,
                "context_ticket_id": context.authority_ticket_id,
                "transaction_id": transaction_id,
                "owner_thread": owner_thread,
                "owner_thread_object_binding_sha256": (
                    owner_thread_object_binding_sha256
                ),
                "source_relative_path": source.as_posix(),
                "target_relative_path": target.as_posix(),
                "policy_version": POLICY_VERSION,
                "policy_digest": self.__policy.digest,
            }
        )
        return hmac.new(
            self.__context_key,
            b"M0-RESTRICTED-RECOVERY-LOCATOR-V4\0" + payload,
            hashlib.sha256,
        ).hexdigest()

    def _restricted_recovery_owner_thread_object_binding(
        self,
        owner_thread_object: threading.Thread,
    ) -> str:
        """Bind one live Thread object while its strong registry reference exists."""

        if (
            not isinstance(owner_thread_object, threading.Thread)
            or owner_thread_object.ident is None
        ):
            raise ProductionBoundaryError(
                BoundaryErrorCode.BOUNDARY_STATE_CHANGED,
                "restricted recovery thread object is invalid",
            )
        return hmac.new(
            self.__context_key,
            (
                b"M0-RESTRICTED-RECOVERY-OWNER-THREAD-OBJECT-V1\0"
                + self.__instance_id.encode("ascii")
                + b"\0"
                + str(id(owner_thread_object)).encode("ascii")
            ),
            hashlib.sha256,
        ).hexdigest()

    def _restricted_recovery_capability_authenticator(
        self,
        locator_id: str,
        binding_sha256: str,
    ) -> bytes:
        return hmac.new(
            self.__context_key,
            b"M0-RESTRICTED-RECOVERY-CAPABILITY-V1\0"
            + locator_id.encode("ascii")
            + b"\0"
            + binding_sha256.encode("ascii"),
            hashlib.sha256,
        ).digest()

    def _revoke_restricted_recovery_records(self, context_ticket_id: str) -> None:
        """Remove every live locator for a context while ``__lock`` is held."""

        locator_ids = tuple(
            locator_id
            for locator_id, record in self.__restricted_recovery_records.items()
            if record.context_ticket_id == context_ticket_id
        )
        for locator_id in locator_ids:
            self.__restricted_recovery_records.pop(locator_id, None)

    def pin_test_job_context(
        self,
        context: OperationContext,
        binding_sha256: str,
    ) -> _JobContextPin:
        if type(binding_sha256) is not str or not _SHA256.fullmatch(binding_sha256):
            raise ProductionBoundaryError(
                BoundaryErrorCode.INVALID_CONTEXT,
                "job operation context binding is invalid",
            )
        ticket_id = self._validate_context_claim(context)
        with self.__lock:
            record = self.__context_records.get(ticket_id)
            if (
                record is None
                or record.claims_digest != context.digest
                or not hmac.compare_digest(record.authenticator, context.authenticator)
            ):
                raise ProductionBoundaryError(
                    BoundaryErrorCode.INVALID_CONTEXT,
                    "job operation context is not registered under this authority",
                )
            if ticket_id in self.__job_context_pins:
                raise ProductionBoundaryError(
                    BoundaryErrorCode.INVALID_CONTEXT,
                    "job operation context is already pinned",
                )
            pin = _JobContextPin(
                self,
                ticket_id,
                secrets.token_hex(16).upper(),
                binding_sha256,
                _constructor=_JOB_CONTEXT_PIN_CONSTRUCTOR,
            )
            self.__job_context_pins[ticket_id] = pin
            return pin

    def validate_test_job_context_pin(
        self,
        context: OperationContext,
        pin: _JobContextPin,
        binding_sha256: str,
    ) -> str:
        ticket_id = self._validate_context_claim(context)
        with self.__lock:
            record = self.__context_records.get(ticket_id)
            current = self.__job_context_pins.get(ticket_id)
            valid = (
                type(pin) is _JobContextPin
                and current is pin
                and not pin._closed
                and pin._core is self
                and pin._ticket_id == ticket_id
                and pin._binding_sha256 == binding_sha256
                and pin._owner_thread == threading.get_ident()
                and record is not None
                and record.claims_digest == context.digest
                and hmac.compare_digest(record.authenticator, context.authenticator)
            )
        if not valid:
            raise ProductionBoundaryError(
                BoundaryErrorCode.INVALID_CONTEXT,
                "job operation context pin is closed, foreign, or changed",
            )
        return context.digest

    def unpin_test_job_context_after_failed_begin(
        self,
        context: OperationContext,
        pin: _JobContextPin,
        binding_sha256: str,
    ) -> None:
        ticket_id = self._validate_context_claim(context)
        with self.__lock:
            current = self.__job_context_pins.get(ticket_id)
            if (
                type(pin) is not _JobContextPin
                or current is not pin
                or pin._closed
                or pin._core is not self
                or pin._ticket_id != ticket_id
                or pin._binding_sha256 != binding_sha256
                or pin._owner_thread != threading.get_ident()
            ):
                raise ProductionBoundaryError(
                    BoundaryErrorCode.INVALID_CONTEXT,
                    "failed-begin job context pin is not live and exact",
                )
            del self.__job_context_pins[ticket_id]
            pin._closed = True

    def finish_test_job_context(
        self,
        context: OperationContext,
        pin: _JobContextPin,
        binding_sha256: str,
    ) -> None:
        """Atomically consume the job pin and revoke its operation context."""

        self._assert_invariants()
        ticket_id = self._validate_context_claim(context)
        cores: list[GuardedPath] = []
        with self.__lock:
            record = self.__context_records.get(ticket_id)
            current = self.__job_context_pins.get(ticket_id)
            if (
                type(pin) is not _JobContextPin
                or current is not pin
                or pin._closed
                or pin._core is not self
                or pin._ticket_id != ticket_id
                or pin._binding_sha256 != binding_sha256
                or pin._owner_thread != threading.get_ident()
                or record is None
                or record.claims_digest != context.digest
                or not hmac.compare_digest(record.authenticator, context.authenticator)
            ):
                raise ProductionBoundaryError(
                    BoundaryErrorCode.INVALID_CONTEXT,
                    "job operation context pin cannot be consumed",
                )
            related_candidates = tuple(
                candidate
                for candidate in self.__candidate_records.values()
                if candidate.context_ticket_id == ticket_id
            )
            related_pairs = tuple(
                pair
                for pair in self.__pair_records.values()
                if pair.context_ticket_id == ticket_id
            )
            if any(
                candidate.lifecycle is CapabilityLifecycle.RESERVED
                for candidate in related_candidates
            ) or any(pair.lifecycle is CapabilityLifecycle.RESERVED for pair in related_pairs) or any(
                lease._pair.context_ticket_id == ticket_id
                for lease in self.__pair_reservations.values()
            ):
                raise ProductionBoundaryError(
                    BoundaryErrorCode.INVALID_CONTEXT,
                    "job operation context still owns a reserved capability",
                )
            for pair in related_pairs:
                self.__pair_records.pop(pair.pair_id, None)
                self._remember_tombstone(self.__pair_tombstones, pair.pair_id)
            for candidate in related_candidates:
                self.__candidate_records.pop(candidate.ticket_id, None)
                self._remember_tombstone(self.__candidate_tombstones, candidate.ticket_id)
                cores.append(candidate.core)
            self._revoke_restricted_recovery_records(ticket_id)
            del self.__job_context_pins[ticket_id]
            del self.__context_records[ticket_id]
            pin._closed = True
        if cores:
            self._release_core_tickets(*cores)

    def revalidate_candidate(
        self,
        ticket: CandidateTicket,
        *,
        context: OperationContext,
    ) -> CandidateTicket:
        safe_context = context if type(context) is OperationContext else None
        record: _CandidateRecord | None = None
        failure: ProductionBoundaryError | None = None
        try:
            self._assert_invariants()
            if type(context) is not OperationContext:
                raise ProductionBoundaryError(
                    BoundaryErrorCode.INVALID_CONTEXT,
                    "operation context is invalid",
                )
            self._validate_context_authority(context)
            record = self._reserve_candidate(ticket, context)
            current_core = self.__guard.revalidate(record.core)
            decision = self.__policy.authorize(current_core, context)
            self._attest_copy_ledger_read(decision, context)
            self._verify_candidate_decision(record, current_core, decision)
            effective = _boundary_effective_classification(
                context,
                decision,
            )
            self._record_audit_factory(
                lambda audit_hmac_key: (
                    self._candidate_event(
                        record,
                        context=context,
                        decision=decision,
                        action=AuditAction.REVALIDATE,
                        audit_hmac_key=audit_hmac_key,
                    ),
                ),
                (
                    None
                    if effective is DataClassification.RESTRICTED
                    else _public_operation_reference(context)
                ),
            )
            self._finish_candidate(record.ticket_id, CapabilityLifecycle.CONSUMED)
            return ticket
        except Exception as exc:
            if record is not None:
                self._finish_candidate(record.ticket_id, CapabilityLifecycle.FAILED)
            failure = self._failure_after_denial(
                error=exc,
                relative_path=record.core.relative_path if record else None,
                intent=record.core.intent if record else PathIntent.EXISTING_READ,
                expected_kind=(record.core.expected_kind if record else ExpectedKind.ANY),
                context=safe_context,
                capability_kind=CapabilityKind.SINGLE,
                ticket_id=record.ticket_id if record else None,
            )
        raise failure from None

    def issue_publish_pair(
        self,
        source_path: str | os.PathLike[str],
        target_path: str | os.PathLike[str],
        *,
        evidence: PairEvidence,
        context: OperationContext,
    ) -> MovePairCandidate:
        return self._issue_pair(
            kind=PairKind.PUBLISH,
            source_path=source_path,
            target_path=target_path,
            evidence=evidence,
            context=context,
        )

    def issue_publish_pair_for_job(
        self,
        source_path: str | os.PathLike[str],
        target_path: str | os.PathLike[str],
        *,
        evidence: PairEvidence,
        context: OperationContext,
        context_pin: _JobContextPin,
        context_binding: str,
        runtime_mutex_lease: RuntimeMutexLease,
    ) -> MovePairCandidate:
        validated = self.validate_test_job_context_pin(
            context,
            context_pin,
            context_binding,
        )
        if validated != context.digest:
            raise ProductionBoundaryError(
                BoundaryErrorCode.INVALID_CONTEXT,
                "job pair issuance lost its exact context pin",
                operation_reference=_public_operation_reference(context),
            )
        result = self._issue_pair(
            kind=PairKind.PUBLISH,
            source_path=source_path,
            target_path=target_path,
            evidence=evidence,
            context=context,
            runtime_mutex_lease=runtime_mutex_lease,
        )
        if type(result) is not MovePairCandidate:
            raise ProductionBoundaryError(
                BoundaryErrorCode.BOUNDARY_STATE_CHANGED,
                "job pair issuance returned a changed capability type",
        )
        return result

    def issue_quarantine_pair_for_job(
        self,
        source_path: str | os.PathLike[str],
        *,
        quarantine_date: str,
        evidence: PairEvidence,
        context: OperationContext,
        context_pin: _JobContextPin,
        context_binding: str,
        runtime_mutex_lease: RuntimeMutexLease,
    ) -> QuarantinePairCandidate:
        validated = self.validate_test_job_context_pin(
            context,
            context_pin,
            context_binding,
        )
        if validated != context.digest:
            raise ProductionBoundaryError(
                BoundaryErrorCode.INVALID_CONTEXT,
                "job quarantine issuance lost its exact context pin",
                operation_reference=_public_operation_reference(context),
            )
        result = self._issue_pair(
            kind=PairKind.QUARANTINE,
            source_path=source_path,
            target_path=None,
            evidence=evidence,
            context=context,
            runtime_mutex_lease=runtime_mutex_lease,
            quarantine_date=quarantine_date,
        )
        if type(result) is not QuarantinePairCandidate:
            raise ProductionBoundaryError(
                BoundaryErrorCode.BOUNDARY_STATE_CHANGED,
                "job quarantine issuance returned a changed capability type",
            )
        return result

    def reserve_publish_pair_for_job(
        self,
        token: MovePairCandidate,
        *,
        context: OperationContext,
        context_pin: _JobContextPin,
        context_binding: str,
        runtime_mutex_lease: RuntimeMutexLease,
    ) -> tuple[_ReservedPairLease, _ReservedPairView]:
        reservation: _ReservedPairLease | None = None
        try:
            reservation = self._reserve_pair(
                token,
                context,
                context_pin=context_pin,
                context_binding=context_binding,
            )
            if reservation._pair.kind is not PairKind.PUBLISH:
                raise ProductionBoundaryError(
                    BoundaryErrorCode.PAIR_MEMBER_MISMATCH,
                    "job publish requires a publish pair capability",
                    operation_reference=_public_operation_reference(context),
                )
            view = self._revalidate_reserved_pair(
                reservation,
                context,
                runtime_mutex_lease=runtime_mutex_lease,
            )
            return reservation, view
        except Exception:
            if reservation is not None and not reservation._closed:
                self._finish_pair(reservation, CapabilityLifecycle.FAILED)
            raise

    def reserve_quarantine_pair_for_job(
        self,
        token: QuarantinePairCandidate,
        *,
        context: OperationContext,
        context_pin: _JobContextPin,
        context_binding: str,
        runtime_mutex_lease: RuntimeMutexLease,
    ) -> tuple[_ReservedPairLease, _ReservedPairView]:
        reservation: _ReservedPairLease | None = None
        try:
            reservation = self._reserve_pair(
                token,
                context,
                context_pin=context_pin,
                context_binding=context_binding,
            )
            if reservation._pair.kind is not PairKind.QUARANTINE:
                raise ProductionBoundaryError(
                    BoundaryErrorCode.PAIR_MEMBER_MISMATCH,
                    "job quarantine requires a quarantine pair capability",
                    operation_reference=_public_operation_reference(context),
                )
            view = self._revalidate_reserved_pair(
                reservation,
                context,
                runtime_mutex_lease=runtime_mutex_lease,
            )
            return reservation, view
        except Exception:
            if reservation is not None and not reservation._closed:
                self._finish_pair(reservation, CapabilityLifecycle.FAILED)
            raise

    def finish_reserved_pair_for_job(
        self,
        reservation: _ReservedPairLease,
        *,
        context: OperationContext,
        context_pin: _JobContextPin,
        context_binding: str,
        lifecycle: CapabilityLifecycle,
    ) -> None:
        if (
            type(reservation) is not _ReservedPairLease
            or reservation._context_pin is not context_pin
            or reservation._context_binding != context_binding
        ):
            raise ProductionBoundaryError(
                BoundaryErrorCode.BOUNDARY_STATE_CHANGED,
                "job pair finalization authority differs",
            )
        validated = self.validate_test_job_context_pin(
            context,
            context_pin,
            context_binding,
        )
        if validated != context.digest:
            raise ProductionBoundaryError(
                BoundaryErrorCode.INVALID_CONTEXT,
                "job pair finalization lost its exact context pin",
            )
        self._finish_pair(reservation, lifecycle)

    def validate_reserved_pair_for_job(
        self,
        reservation: _ReservedPairLease,
        *,
        context: OperationContext,
        context_pin: _JobContextPin,
        context_binding: str,
        runtime_mutex_lease: RuntimeMutexLease,
    ) -> _ReservedPairView:
        if (
            type(reservation) is not _ReservedPairLease
            or reservation._context_pin is not context_pin
            or reservation._context_binding != context_binding
        ):
            raise ProductionBoundaryError(
                BoundaryErrorCode.BOUNDARY_STATE_CHANGED,
                "job pair validation authority differs",
            )
        validated = self.validate_test_job_context_pin(
            context,
            context_pin,
            context_binding,
        )
        if validated != context.digest:
            raise ProductionBoundaryError(
                BoundaryErrorCode.INVALID_CONTEXT,
                "job pair validation lost its exact context pin",
            )
        return self._revalidate_reserved_pair(
            reservation,
            context,
            runtime_mutex_lease=runtime_mutex_lease,
        )

    def issue_quarantine_pair(
        self,
        source_path: str | os.PathLike[str],
        *,
        evidence: PairEvidence,
        context: OperationContext,
    ) -> QuarantinePairCandidate:
        return self._issue_pair(
            kind=PairKind.QUARANTINE,
            source_path=source_path,
            target_path=None,
            evidence=evidence,
            context=context,
        )

    def _issue_pair(
        self,
        *,
        kind: PairKind,
        source_path: str | os.PathLike[str],
        target_path: str | os.PathLike[str] | None,
        evidence: PairEvidence,
        context: OperationContext,
        runtime_mutex_lease: RuntimeMutexLease | None = None,
        quarantine_date: str | None = None,
    ) -> MovePairCandidate | QuarantinePairCandidate:
        pair_id = secrets.token_hex(16).upper()
        source_relative: Path | None = None
        target_relative: Path | None = None
        source_core: GuardedPath | None = None
        target_core: GuardedPath | None = None
        safe_context = context if type(context) is OperationContext else None
        failure: ProductionBoundaryError | None = None
        try:
            self._assert_invariants()
            if type(context) is not OperationContext:
                raise ProductionBoundaryError(
                    BoundaryErrorCode.INVALID_CONTEXT,
                    "operation context is invalid",
            )
            self._validate_context_authority(context)
            evidence = self._validate_evidence_context(evidence, context)
            with self.__lock:
                self._ensure_registry_capacity(candidate_items=2, pair_items=1)
            source_relative = self._require_relative(source_path)
            source_core = self.__guard.authorize(
                source_relative,
                intent=(
                    PathIntent.MOVE_SOURCE
                    if kind is PairKind.PUBLISH
                    else PathIntent.QUARANTINE_SOURCE
                ),
                expected_kind=ExpectedKind.DIRECTORY,
            )
            source_preview = self.__policy.classify(source_core.relative_path)

            if kind is PairKind.PUBLISH:
                if quarantine_date is not None:
                    raise ProductionBoundaryError(
                        BoundaryErrorCode.INVALID_ARGUMENT,
                        "publish cannot carry a quarantine date",
                    )
                if target_path is None:
                    raise ProductionBoundaryError(
                        BoundaryErrorCode.INVALID_ARGUMENT,
                        "publish target is required",
                    )
                target_relative = self._require_relative(target_path)
                target_intent = PathIntent.MOVE_TARGET
            else:
                if context.purpose is not Purpose.QUARANTINE:
                    raise ProductionBoundaryError(
                        BoundaryErrorCode.MANIFEST_CONTEXT_MISMATCH,
                        "quarantine requires QUARANTINE purpose",
                        operation_reference=_public_operation_reference(context),
                    )
                source_restricted = (
                    source_preview.effective_classification
                    is DataClassification.RESTRICTED
                )
                target_classification = (
                    DataClassification.RESTRICTED
                    if source_restricted
                    else context.classification
                )
                canonical_quarantine_date = (
                    datetime.now(UTC).date().isoformat()
                    if quarantine_date is None
                    else _validate_quarantine_date(quarantine_date)
                )
                pair_id = (
                    canonical_quarantine_date.replace("-", "")
                    + secrets.token_hex(12).upper()
                )
                target_relative = Path(
                    "data",
                    "quarantine",
                    target_classification.value,
                    canonical_quarantine_date,
                    pair_id,
                )
                target_intent = PathIntent.QUARANTINE_TARGET

            target_core = self.__guard.authorize(
                target_relative,
                intent=target_intent,
                expected_kind=ExpectedKind.DIRECTORY,
            )
            source_decision, target_decision = self.__policy._authorize_pair(
                source_core,
                target_core,
                context,
                pair_id=pair_id,
                evidence_digest=evidence.digest,
            )
            if kind is PairKind.PUBLISH:
                self._validate_staging_source(source_decision, evidence)
            self._validate_classification_flow(
                context,
                source_decision,
                target_decision,
            )
            self._validate_pair_topology(
                kind,
                source_core,
                source_decision,
                target_core,
                target_decision,
            )
            effective_classification = _max_classification(
                context.classification,
                source_decision.effective_classification,
                target_decision.effective_classification,
            )
            topology_digest = self._topology_digest(
                kind,
                pair_id,
                source_core,
                source_decision,
                target_core,
                target_decision,
                evidence,
            )
            source_record = self._build_pair_member(
                pair_id=pair_id,
                role=PairRole.SOURCE,
                core=source_core,
                decision=source_decision,
                context=context,
                topology_digest=topology_digest,
                evidence=evidence,
            )
            target_record = self._build_pair_member(
                pair_id=pair_id,
                role=PairRole.TARGET,
                core=target_core,
                decision=target_decision,
                context=context,
                topology_digest=topology_digest,
                evidence=evidence,
            )
            pair_record = _PairRecord(
                pair_id=pair_id,
                kind=kind,
                source_ticket_id=source_record.ticket_id,
                target_ticket_id=target_record.ticket_id,
                context_digest=context.digest,
                context_ticket_id=context.authority_ticket_id or "",
                policy_version=POLICY_VERSION,
                policy_digest=self.__policy.digest,
                expected_kind=ExpectedKind.DIRECTORY,
                source_namespace=source_decision.namespace,
                target_namespace=target_decision.namespace,
                topology_digest=topology_digest,
                evidence=evidence,
                effective_classification=effective_classification,
                issued_date_utc=datetime.now(UTC).date().isoformat(),
                authenticator=b"",
            )
            pair_mac = self._pair_authenticator(pair_record)
            pair_record = replace(pair_record, authenticator=pair_mac)
            if kind is PairKind.PUBLISH:
                pair_token = MovePairCandidate(
                    pair_id,
                    self.__instance_id,
                    pair_mac,
                    _constructor=_TOKEN_CONSTRUCTOR,
                )
            else:
                pair_token = QuarantinePairCandidate(
                    pair_id,
                    self.__instance_id,
                    pair_mac,
                    _constructor=_TOKEN_CONSTRUCTOR,
                )
            with self.__lock:
                self._ensure_registry_capacity(candidate_items=2, pair_items=1)
                self._validate_context_authority(context)
                self.__candidate_records[source_record.ticket_id] = source_record
                self.__candidate_records[target_record.ticket_id] = target_record
                self.__pair_records[pair_id] = pair_record
                try:
                    self._record_audit_factory(
                        lambda audit_hmac_key: (
                            self._pair_member_event(
                                source_record,
                                pair_record,
                                context=context,
                                decision=source_decision,
                                action=AuditAction.ISSUE,
                                audit_hmac_key=audit_hmac_key,
                            ),
                            self._pair_member_event(
                                target_record,
                                pair_record,
                                context=context,
                                decision=target_decision,
                                action=AuditAction.ISSUE,
                                audit_hmac_key=audit_hmac_key,
                            ),
                        ),
                        _public_operation_reference(context),
                        runtime_mutex_lease=runtime_mutex_lease,
                    )
                except Exception:
                    self.__candidate_records.pop(source_record.ticket_id, None)
                    self.__candidate_records.pop(target_record.ticket_id, None)
                    self.__pair_records.pop(pair_id, None)
                    raise
            return pair_token
        except Exception as exc:
            issued_cores = tuple(
                core for core in (source_core, target_core) if core is not None
            )
            if issued_cores:
                try:
                    self._release_core_tickets(*issued_cores)
                except Exception as cleanup_error:
                    exc = cleanup_error
            failure = self._failure_after_denial(
                error=exc,
                relative_path=target_relative or source_relative,
                intent=(
                    PathIntent.MOVE_TARGET
                    if kind is PairKind.PUBLISH
                    else PathIntent.QUARANTINE_TARGET
                ),
                expected_kind=ExpectedKind.DIRECTORY,
                context=safe_context,
                capability_kind=(
                    CapabilityKind.PUBLISH_PAIR
                    if kind is PairKind.PUBLISH
                    else CapabilityKind.QUARANTINE_PAIR
                ),
                pair_id=pair_id,
            )
        raise failure from None

    def revalidate_pair(
        self,
        token: MovePairCandidate | QuarantinePairCandidate,
        *,
        context: OperationContext,
    ) -> MovePairCandidate | QuarantinePairCandidate:
        safe_context = context if type(context) is OperationContext else None
        reservation: _ReservedPairLease | None = None
        pair_record: _PairRecord | None = None
        failure: ProductionBoundaryError | None = None
        try:
            self._assert_invariants()
            if type(context) is not OperationContext:
                raise ProductionBoundaryError(
                    BoundaryErrorCode.INVALID_CONTEXT,
                    "operation context is invalid",
                )
            self._validate_context_authority(context)
            reservation = self._reserve_pair(
                token,
                context,
            )
            pair_record = reservation._pair
            self._revalidate_reserved_pair(reservation, context)
            self._finish_pair(reservation, CapabilityLifecycle.CONSUMED)
            return token
        except Exception as exc:
            if reservation is not None and not reservation._closed:
                try:
                    self._finish_pair(reservation, CapabilityLifecycle.FAILED)
                except Exception as cleanup_error:
                    exc = cleanup_error
            failure = self._failure_after_denial(
                error=exc,
                relative_path=None,
                intent=PathIntent.MOVE_SOURCE,
                expected_kind=ExpectedKind.DIRECTORY,
                context=safe_context,
                capability_kind=(
                    CapabilityKind.PUBLISH_PAIR
                    if pair_record is None or pair_record.kind is PairKind.PUBLISH
                    else CapabilityKind.QUARANTINE_PAIR
                ),
                pair_id=pair_record.pair_id if pair_record else None,
            )
        raise failure from None

    def _revalidate_reserved_pair(
        self,
        reservation: _ReservedPairLease,
        context: OperationContext,
        *,
        runtime_mutex_lease: RuntimeMutexLease | None = None,
    ) -> _ReservedPairView:
        if (
            type(reservation) is not _ReservedPairLease
            or reservation._core is not self
            or reservation._closed
            or reservation._owner_thread != threading.get_ident()
            or reservation._context_digest != context.digest
        ):
            raise ProductionBoundaryError(
                BoundaryErrorCode.BOUNDARY_STATE_CHANGED,
                "pair reservation is closed, foreign, replayed, or cross-thread",
                operation_reference=_public_operation_reference(context),
            )
        if reservation._context_pin is not None:
            validated = self.validate_test_job_context_pin(
                context,
                reservation._context_pin,
                reservation._context_binding or "",
            )
            if validated != context.digest:
                raise ProductionBoundaryError(
                    BoundaryErrorCode.INVALID_CONTEXT,
                    "pair reservation lost its job context pin",
                    operation_reference=_public_operation_reference(context),
                )
        with self.__lock:
            pair_record = reservation._pair
            source_record = reservation._source
            target_record = reservation._target
            if (
                self.__pair_reservations.get(pair_record.pair_id) is not reservation
                or self.__pair_records.get(pair_record.pair_id) is not pair_record
                or self.__candidate_records.get(source_record.ticket_id)
                is not source_record
                or self.__candidate_records.get(target_record.ticket_id)
                is not target_record
            ):
                raise ProductionBoundaryError(
                    BoundaryErrorCode.BOUNDARY_STATE_CHANGED,
                    "pair reservation registry changed during revalidation",
                    operation_reference=_public_operation_reference(context),
                )
        self._validate_evidence_context(pair_record.evidence, context)
        source_core = self.__guard.revalidate(source_record.core)
        target_core = self.__guard.revalidate(target_record.core)
        source_decision, target_decision = self.__policy._authorize_pair(
            source_core,
            target_core,
            context,
            pair_id=pair_record.pair_id,
            evidence_digest=pair_record.evidence.digest,
        )
        self._verify_candidate_decision(source_record, source_core, source_decision)
        self._verify_candidate_decision(target_record, target_core, target_decision)
        self._validate_classification_flow(context, source_decision, target_decision)
        self._validate_pair_topology(
            pair_record.kind,
            source_core,
            source_decision,
            target_core,
            target_decision,
        )
        topology_digest = self._topology_digest(
            pair_record.kind,
            pair_record.pair_id,
            source_core,
            source_decision,
            target_core,
            target_decision,
            pair_record.evidence,
        )
        if topology_digest != pair_record.topology_digest:
            raise ProductionBoundaryError(
                BoundaryErrorCode.PAIR_TOPOLOGY_CHANGED,
                "pair topology changed after candidate issuance",
                operation_reference=_public_operation_reference(context),
            )
        self._record_audit_factory(
            lambda audit_hmac_key: (
                self._pair_member_event(
                    source_record,
                    pair_record,
                    context=context,
                    decision=source_decision,
                    action=AuditAction.REVALIDATE,
                    audit_hmac_key=audit_hmac_key,
                ),
                self._pair_member_event(
                    target_record,
                    pair_record,
                    context=context,
                    decision=target_decision,
                    action=AuditAction.REVALIDATE,
                    audit_hmac_key=audit_hmac_key,
                ),
            ),
            _public_operation_reference(context),
            runtime_mutex_lease=runtime_mutex_lease,
        )
        return _ReservedPairView(
            pair_id=pair_record.pair_id,
            kind=pair_record.kind,
            source_relative_path=source_core.relative_path,
            target_relative_path=target_core.relative_path,
            evidence=pair_record.evidence,
            topology_digest=pair_record.topology_digest,
            effective_classification=pair_record.effective_classification,
        )

    def describe_candidate(
        self,
        ticket: CandidateTicket,
        *,
        context: OperationContext,
    ) -> CandidateDescriptor:
        self._validate_context_authority(context)
        record = self._validate_candidate_token(ticket, context)
        if record.lifecycle is not CapabilityLifecycle.ISSUED:
            raise ProductionBoundaryError(
                BoundaryErrorCode.CANDIDATE_ALREADY_USED,
                "candidate capability is no longer available",
                operation_reference=_public_operation_reference(context),
            )
        restricted = context.classification is DataClassification.RESTRICTED
        return CandidateDescriptor(
            ticket_id=(
                self._descriptor_hmac("CANDIDATE", record.ticket_id)
                if restricted
                else record.ticket_id
            ),
            namespace=record.namespace,
            namespace_mode=record.namespace_mode,
            intent=record.core.intent,
            expected_kind=record.core.expected_kind,
            pair_id=(
                self._descriptor_hmac("PAIR", record.pair_id)
                if restricted and record.pair_id is not None
                else record.pair_id
            ),
            pair_role=record.pair_role,
        )

    def describe_pair(
        self,
        token: MovePairCandidate | QuarantinePairCandidate,
        *,
        context: OperationContext,
    ) -> PairDescriptor:
        self._validate_context_authority(context)
        record = self._validate_pair_token(token, context)
        if record.lifecycle is not CapabilityLifecycle.ISSUED:
            raise ProductionBoundaryError(
                BoundaryErrorCode.PAIR_ALREADY_USED,
                "pair capability is no longer available",
                operation_reference=_public_operation_reference(context),
            )
        restricted = context.classification is DataClassification.RESTRICTED
        return PairDescriptor(
            pair_id=(
                self._descriptor_hmac("PAIR", record.pair_id)
                if restricted
                else record.pair_id
            ),
            kind=record.kind,
            source_namespace=record.source_namespace,
            target_namespace=record.target_namespace,
            expected_kind=record.expected_kind,
            evidence_digest=(
                self._descriptor_hmac("EVIDENCE", record.evidence.digest)
                if restricted
                else record.evidence.digest
            ),
            topology_digest=(
                self._descriptor_hmac("TOPOLOGY", record.topology_digest)
                if restricted
                else record.topology_digest
            ),
        )

    def _descriptor_hmac(self, domain: str, value: str) -> str:
        return hmac.new(
            self.__audit_hmac_key,
            f"BOUNDARY-DESCRIPTOR-{domain}-V1\0".encode("ascii")
            + value.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def _build_single_candidate(
        self,
        core: GuardedPath,
        decision: NamespaceDecision,
        context: OperationContext,
    ) -> tuple[_CandidateRecord, CandidateTicket]:
        ticket_id = secrets.token_hex(16).upper()
        record = _CandidateRecord(
            ticket_id=ticket_id,
            core=core,
            context_digest=context.digest,
            context_ticket_id=context.authority_ticket_id or "",
            policy_version=POLICY_VERSION,
            policy_digest=self.__policy.digest,
            namespace=decision.namespace,
            namespace_mode=decision.rule.mode,
            pair_id=None,
            pair_role=None,
            topology_digest=None,
            evidence_digest=None,
            authenticator=b"",
        )
        authenticator = self._candidate_authenticator(record)
        record = replace(record, authenticator=authenticator)
        token = CandidateTicket(
            ticket_id,
            self.__instance_id,
            authenticator,
            _constructor=_TOKEN_CONSTRUCTOR,
        )
        return record, token

    def _build_pair_member(
        self,
        *,
        pair_id: str,
        role: PairRole,
        core: GuardedPath,
        decision: NamespaceDecision,
        context: OperationContext,
        topology_digest: str,
        evidence: PairEvidence,
    ) -> _CandidateRecord:
        record = _CandidateRecord(
            ticket_id=secrets.token_hex(16).upper(),
            core=core,
            context_digest=context.digest,
            context_ticket_id=context.authority_ticket_id or "",
            policy_version=POLICY_VERSION,
            policy_digest=self.__policy.digest,
            namespace=decision.namespace,
            namespace_mode=decision.rule.mode,
            pair_id=pair_id,
            pair_role=role,
            topology_digest=topology_digest,
            evidence_digest=evidence.digest,
            authenticator=b"",
        )
        return replace(record, authenticator=self._candidate_authenticator(record))

    def _validate_candidate_token(
        self,
        ticket: CandidateTicket,
        context: OperationContext,
    ) -> _CandidateRecord:
        if type(ticket) is not CandidateTicket:
            raise ProductionBoundaryError(
                BoundaryErrorCode.CANDIDATE_NOT_ISSUED,
                "candidate token type is invalid",
                operation_reference=_public_operation_reference(context),
            )
        ticket_id, boundary_instance_id, supplied = ticket._read_claims(
            _TOKEN_CONSTRUCTOR
        )
        if boundary_instance_id != self.__instance_id:
            raise ProductionBoundaryError(
                BoundaryErrorCode.CANDIDATE_ISSUER_MISMATCH,
                "candidate token belongs to another boundary",
                operation_reference=_public_operation_reference(context),
            )
        record = self.__candidate_records.get(ticket_id)
        if record is None:
            if ticket_id in self.__candidate_tombstones:
                raise ProductionBoundaryError(
                    BoundaryErrorCode.CANDIDATE_ALREADY_USED,
                    "candidate capability is no longer available",
                    operation_reference=_public_operation_reference(context),
                )
            raise ProductionBoundaryError(
                BoundaryErrorCode.CANDIDATE_NOT_ISSUED,
                "candidate token was not issued by this boundary",
                operation_reference=_public_operation_reference(context),
            )
        expected = self._candidate_authenticator(record)
        if not (
            hmac.compare_digest(supplied, record.authenticator)
            and hmac.compare_digest(supplied, expected)
        ):
            raise ProductionBoundaryError(
                BoundaryErrorCode.CANDIDATE_MAC_MISMATCH,
                "candidate token authenticator is invalid",
                operation_reference=_public_operation_reference(context),
            )
        if (
            record.context_digest != context.digest
            or record.context_ticket_id != (context.authority_ticket_id or "")
        ):
            raise ProductionBoundaryError(
                BoundaryErrorCode.CANDIDATE_CONTEXT_MISMATCH,
                "candidate token belongs to another operation context",
                operation_reference=_public_operation_reference(context),
            )
        if (
            record.policy_version != POLICY_VERSION
            or record.policy_digest != self.__policy.digest
        ):
            raise ProductionBoundaryError(
                BoundaryErrorCode.CANDIDATE_POLICY_MISMATCH,
                "candidate token belongs to another policy version",
                operation_reference=_public_operation_reference(context),
            )
        return record

    def _reserve_candidate(
        self,
        ticket: CandidateTicket,
        context: OperationContext,
    ) -> _CandidateRecord:
        with self.__lock:
            record = self._validate_candidate_token(ticket, context)
            if record.pair_id is not None:
                raise ProductionBoundaryError(
                    BoundaryErrorCode.CANDIDATE_PAIR_REQUIRED,
                    "a pair member cannot be used as a standalone candidate",
                    operation_reference=_public_operation_reference(context),
                )
            if record.lifecycle is not CapabilityLifecycle.ISSUED:
                raise ProductionBoundaryError(
                    BoundaryErrorCode.CANDIDATE_ALREADY_USED,
                    "candidate capability is no longer available",
                    operation_reference=_public_operation_reference(context),
                )
            self.__candidate_records[record.ticket_id] = replace(
                record,
                lifecycle=CapabilityLifecycle.RESERVED,
            )
            return record

    def _finish_candidate(
        self,
        ticket_id: str,
        lifecycle: CapabilityLifecycle,
    ) -> None:
        core: GuardedPath | None = None
        with self.__lock:
            current = self.__candidate_records.get(ticket_id)
            if current is not None and current.lifecycle is CapabilityLifecycle.RESERVED:
                core = current.core
                del self.__candidate_records[ticket_id]
                self._remember_tombstone(
                    self.__candidate_tombstones,
                    ticket_id,
                    lifecycle,
                )
        if core is not None:
            self._release_core_tickets(core)

    def _validate_pair_token(
        self,
        token: MovePairCandidate | QuarantinePairCandidate,
        context: OperationContext,
    ) -> _PairRecord:
        if type(token) not in {MovePairCandidate, QuarantinePairCandidate}:
            raise ProductionBoundaryError(
                BoundaryErrorCode.PAIR_NOT_ISSUED,
                "pair token type is invalid",
                operation_reference=_public_operation_reference(context),
            )
        pair_id, boundary_instance_id, supplied = token._read_claims(
            _TOKEN_CONSTRUCTOR
        )
        if boundary_instance_id != self.__instance_id:
            raise ProductionBoundaryError(
                BoundaryErrorCode.PAIR_ISSUER_MISMATCH,
                "pair token belongs to another boundary",
                operation_reference=_public_operation_reference(context),
            )
        record = self.__pair_records.get(pair_id)
        if record is None:
            if pair_id in self.__pair_tombstones:
                raise ProductionBoundaryError(
                    BoundaryErrorCode.PAIR_ALREADY_USED,
                    "pair capability is no longer available",
                    operation_reference=_public_operation_reference(context),
                )
            raise ProductionBoundaryError(
                BoundaryErrorCode.PAIR_NOT_ISSUED,
                "pair token was not issued by this boundary",
                operation_reference=_public_operation_reference(context),
            )
        expected_type = (
            MovePairCandidate if record.kind is PairKind.PUBLISH else QuarantinePairCandidate
        )
        if type(token) is not expected_type:
            raise ProductionBoundaryError(
                BoundaryErrorCode.PAIR_MEMBER_MISMATCH,
                "pair token kind differs from the registered pair",
                operation_reference=_public_operation_reference(context),
            )
        expected = self._pair_authenticator(record)
        if not (
            hmac.compare_digest(supplied, record.authenticator)
            and hmac.compare_digest(supplied, expected)
        ):
            raise ProductionBoundaryError(
                BoundaryErrorCode.PAIR_MAC_MISMATCH,
                "pair token authenticator is invalid",
                operation_reference=_public_operation_reference(context),
            )
        if (
            record.context_digest != context.digest
            or record.context_ticket_id != (context.authority_ticket_id or "")
        ):
            raise ProductionBoundaryError(
                BoundaryErrorCode.PAIR_CONTEXT_MISMATCH,
                "pair token belongs to another operation context",
                operation_reference=_public_operation_reference(context),
            )
        if (
            record.policy_version != POLICY_VERSION
            or record.policy_digest != self.__policy.digest
        ):
            raise ProductionBoundaryError(
                BoundaryErrorCode.PAIR_POLICY_MISMATCH,
                "pair token belongs to another policy version",
                operation_reference=_public_operation_reference(context),
            )
        return record

    def _reserve_pair(
        self,
        token: MovePairCandidate | QuarantinePairCandidate,
        context: OperationContext,
        *,
        context_pin: _JobContextPin | None = None,
        context_binding: str | None = None,
    ) -> _ReservedPairLease:
        with self.__lock:
            if (context_pin is None) != (context_binding is None):
                raise ProductionBoundaryError(
                    BoundaryErrorCode.INVALID_CONTEXT,
                    "pair reservation context pin binding is incomplete",
                    operation_reference=_public_operation_reference(context),
                )
            if context_pin is not None:
                validated = self.validate_test_job_context_pin(
                    context,
                    context_pin,
                    context_binding or "",
                )
                if validated != context.digest:
                    raise ProductionBoundaryError(
                        BoundaryErrorCode.INVALID_CONTEXT,
                        "pair reservation context pin changed",
                        operation_reference=_public_operation_reference(context),
                    )
            pair = self._validate_pair_token(token, context)
            if pair.lifecycle is not CapabilityLifecycle.ISSUED:
                raise ProductionBoundaryError(
                    BoundaryErrorCode.PAIR_ALREADY_USED,
                    "pair capability is no longer available",
                    operation_reference=_public_operation_reference(context),
                )
            source = self.__candidate_records.get(pair.source_ticket_id)
            target = self.__candidate_records.get(pair.target_ticket_id)
            if source is None or target is None:
                raise ProductionBoundaryError(
                    BoundaryErrorCode.PAIR_MEMBER_MISMATCH,
                    "pair member registry is incomplete",
                    operation_reference=_public_operation_reference(context),
                )
            if (
                source.lifecycle is not CapabilityLifecycle.ISSUED
                or target.lifecycle is not CapabilityLifecycle.ISSUED
                or source.pair_id != pair.pair_id
                or source.pair_role is not PairRole.SOURCE
                or target.pair_id != pair.pair_id
                or target.pair_role is not PairRole.TARGET
            ):
                raise ProductionBoundaryError(
                    BoundaryErrorCode.PAIR_MEMBER_MISMATCH,
                    "pair members are unavailable or do not match their roles",
                    operation_reference=_public_operation_reference(context),
                )
            reserved_pair = replace(
                pair,
                lifecycle=CapabilityLifecycle.RESERVED,
            )
            reserved_source = replace(
                source,
                lifecycle=CapabilityLifecycle.RESERVED,
            )
            reserved_target = replace(
                target,
                lifecycle=CapabilityLifecycle.RESERVED,
            )
            lease = _ReservedPairLease(
                self,
                reserved_pair,
                reserved_source,
                reserved_target,
                context.digest,
                context_pin,
                context_binding,
                _constructor=_PAIR_RESERVATION_CONSTRUCTOR,
            )
            self.__pair_records[pair.pair_id] = reserved_pair
            self.__candidate_records[source.ticket_id] = reserved_source
            self.__candidate_records[target.ticket_id] = reserved_target
            self.__pair_reservations[pair.pair_id] = lease
            return lease

    def _finish_pair(
        self,
        lease: _ReservedPairLease,
        lifecycle: CapabilityLifecycle,
    ) -> None:
        if (
            type(lease) is not _ReservedPairLease
            or lease._core is not self
            or lease._owner_thread != threading.get_ident()
            or lease._closed
            or lifecycle
            not in {CapabilityLifecycle.CONSUMED, CapabilityLifecycle.FAILED}
        ):
            raise ProductionBoundaryError(
                BoundaryErrorCode.BOUNDARY_STATE_CHANGED,
                "pair reservation cannot enter the requested terminal state",
            )
        cores: list[GuardedPath] = []
        with self.__lock:
            pair = lease._pair
            current_pair = self.__pair_records.get(pair.pair_id)
            current_source = self.__candidate_records.get(pair.source_ticket_id)
            current_target = self.__candidate_records.get(pair.target_ticket_id)
            if (
                self.__pair_reservations.get(pair.pair_id) is not lease
                or current_pair is not pair
                or current_source is not lease._source
                or current_target is not lease._target
                or pair.lifecycle is not CapabilityLifecycle.RESERVED
                or current_source.lifecycle is not CapabilityLifecycle.RESERVED
                or current_target.lifecycle is not CapabilityLifecycle.RESERVED
            ):
                raise ProductionBoundaryError(
                    BoundaryErrorCode.BOUNDARY_STATE_CHANGED,
                    "pair reservation registry changed before finalization",
                )
            del self.__pair_reservations[pair.pair_id]
            del self.__pair_records[pair.pair_id]
            del self.__candidate_records[pair.source_ticket_id]
            del self.__candidate_records[pair.target_ticket_id]
            self._remember_tombstone(
                self.__pair_tombstones,
                pair.pair_id,
                lifecycle,
            )
            for member in (lease._source, lease._target):
                cores.append(member.core)
                self._remember_tombstone(
                    self.__candidate_tombstones,
                    member.ticket_id,
                    lifecycle,
                )
            lease._closed = True
        if cores:
            self._release_core_tickets(*cores)

    @staticmethod
    def _remember_tombstone(
        registry: dict[str, CapabilityLifecycle],
        identifier: str,
        lifecycle: CapabilityLifecycle = CapabilityLifecycle.FAILED,
    ) -> None:
        if lifecycle not in {
            CapabilityLifecycle.CONSUMED,
            CapabilityLifecycle.FAILED,
        }:
            raise ProductionBoundaryError(
                BoundaryErrorCode.BOUNDARY_STATE_CHANGED,
                "capability tombstone requires an exact terminal lifecycle",
            )
        registry[identifier] = lifecycle
        while len(registry) > _MAX_TOMBSTONES:
            del registry[next(iter(registry))]

    def _release_core_tickets(self, *tickets: GuardedPath) -> None:
        cleanup_failure: ProductionBoundaryError | None = None
        for ticket in tickets:
            try:
                released = self.__guard.release(ticket)
            except WorkspaceGuardError as error:
                cleanup_failure = ProductionBoundaryError(
                    BoundaryErrorCode.BOUNDARY_STATE_CHANGED,
                    "core ticket cleanup failed",
                    detail_code=error.code.value,
                )
                continue
            if not released and cleanup_failure is None:
                cleanup_failure = ProductionBoundaryError(
                    BoundaryErrorCode.BOUNDARY_STATE_CHANGED,
                    "core ticket cleanup found no live capability",
                )
        if cleanup_failure is not None:
            raise cleanup_failure from None

    @staticmethod
    def _verify_candidate_decision(
        record: _CandidateRecord,
        current_core: GuardedPath,
        decision: NamespaceDecision,
    ) -> None:
        if (
            record.core.ticket_id != current_core.ticket_id
            or record.namespace is not decision.namespace
            or record.namespace_mode is not decision.rule.mode
            or record.core.intent is not current_core.intent
            or record.core.expected_kind is not current_core.expected_kind
        ):
            raise ProductionBoundaryError(
                BoundaryErrorCode.CANDIDATE_POLICY_MISMATCH,
                "candidate claims changed during revalidation",
            )

    def _candidate_authenticator(self, record: _CandidateRecord) -> bytes:
        payload = _canonical_json_bytes(self._candidate_payload(record))
        return hmac.new(
            self.__candidate_key,
            b"BOUNDARY-CANDIDATE-V2\0" + payload,
            hashlib.sha256,
        ).digest()

    def _context_authenticator(
        self,
        ticket_id: str,
        context: OperationContext,
    ) -> bytes:
        payload = _canonical_json_bytes(
            {
                "authority_id": self.__context_authority_id,
                "ticket_id": ticket_id,
                "claims_digest": context.digest,
            }
        )
        return hmac.new(
            self.__context_key,
            b"BOUNDARY-CONTEXT-V1\0" + payload,
            hashlib.sha256,
        ).digest()

    def _validate_context_claim(self, context: OperationContext) -> str:
        if type(context) is not OperationContext or not context.authority_bound:
            raise ProductionBoundaryError(
                BoundaryErrorCode.INVALID_CONTEXT,
                "operation context was not issued by this boundary",
                operation_reference=_public_operation_reference(context if type(context) is OperationContext else None),
            )
        if context.authority_id != self.__context_authority_id:
            raise ProductionBoundaryError(
                BoundaryErrorCode.INVALID_CONTEXT,
                "operation context belongs to another authority",
                operation_reference=_public_operation_reference(context),
            )
        ticket_id = context.authority_ticket_id or ""
        expected = self._context_authenticator(ticket_id, context)
        if not hmac.compare_digest(context.authenticator, expected):
            raise ProductionBoundaryError(
                BoundaryErrorCode.INVALID_CONTEXT,
                "operation context authority binding is invalid",
                operation_reference=_public_operation_reference(context),
            )
        return ticket_id

    def _validate_context_authority(self, context: OperationContext) -> None:
        ticket_id = self._validate_context_claim(context)
        with self.__lock:
            record = self.__context_records.get(ticket_id)
        if record is None:
            raise ProductionBoundaryError(
                BoundaryErrorCode.INVALID_CONTEXT,
                "operation context is not registered",
                operation_reference=_public_operation_reference(context),
            )
        if (
            record.claims_digest != context.digest
            or not hmac.compare_digest(context.authenticator, record.authenticator)
        ):
            raise ProductionBoundaryError(
                BoundaryErrorCode.INVALID_CONTEXT,
                "operation context authority binding is invalid",
                operation_reference=_public_operation_reference(context),
            )

    def _pair_authenticator(self, record: _PairRecord) -> bytes:
        payload = _canonical_json_bytes(self._pair_payload(record))
        return hmac.new(
            self.__pair_key,
            b"BOUNDARY-PAIR-V2\0" + payload,
            hashlib.sha256,
        ).digest()

    @staticmethod
    def _candidate_payload(record: _CandidateRecord) -> dict[str, Any]:
        return {
            "ticket_id": record.ticket_id,
            "core_ticket_id": record.core.ticket_id,
            "relative_path": record.core.relative_path.as_posix(),
            "intent": record.core.intent.value,
            "expected_kind": record.core.expected_kind.value,
            "context_digest": record.context_digest,
            "context_ticket_id": record.context_ticket_id,
            "policy_version": record.policy_version,
            "policy_digest": record.policy_digest,
            "namespace": record.namespace.value,
            "namespace_mode": record.namespace_mode.value,
            "pair_id": record.pair_id,
            "pair_role": record.pair_role.value if record.pair_role else None,
            "topology_digest": record.topology_digest,
            "evidence_digest": record.evidence_digest,
        }

    @staticmethod
    def _pair_payload(record: _PairRecord) -> dict[str, Any]:
        return {
            "pair_id": record.pair_id,
            "kind": record.kind.value,
            "source_ticket_id": record.source_ticket_id,
            "target_ticket_id": record.target_ticket_id,
            "context_digest": record.context_digest,
            "context_ticket_id": record.context_ticket_id,
            "policy_version": record.policy_version,
            "policy_digest": record.policy_digest,
            "expected_kind": record.expected_kind.value,
            "source_namespace": record.source_namespace.value,
            "target_namespace": record.target_namespace.value,
            "topology_digest": record.topology_digest,
            "evidence_digest": record.evidence.digest,
            "effective_classification": record.effective_classification.value,
            "issued_date_utc": record.issued_date_utc,
        }

    def _validate_request_types(
        self,
        intent: PathIntent,
        expected_kind: ExpectedKind,
        context: OperationContext,
    ) -> None:
        if not isinstance(intent, PathIntent):
            raise ProductionBoundaryError(
                BoundaryErrorCode.INVALID_ARGUMENT,
                "intent must be a PathIntent value",
            )
        if not isinstance(expected_kind, ExpectedKind):
            raise ProductionBoundaryError(
                BoundaryErrorCode.INVALID_ARGUMENT,
                "expected_kind must be an ExpectedKind value",
            )
        if type(context) is not OperationContext:
            raise ProductionBoundaryError(
                BoundaryErrorCode.INVALID_CONTEXT,
                "context must be an OperationContext value",
            )
        self._validate_context_authority(context)

    @staticmethod
    def _validate_evidence_context(
        evidence: PairEvidence,
        context: OperationContext,
    ) -> PairEvidence:
        if type(evidence) is not PairEvidence:
            raise ProductionBoundaryError(
                BoundaryErrorCode.MANIFEST_BINDING_INVALID,
                "pair evidence must be a PairEvidence value",
                operation_reference=_public_operation_reference(context),
            )
        snapshot = PairEvidence(
            manifest_id=evidence.manifest_id,
            manifest_sha256=evidence.manifest_sha256,
            source_tree_sha256=evidence.source_tree_sha256,
            entry_count=evidence.entry_count,
            total_bytes=evidence.total_bytes,
            checkpoint_id=evidence.checkpoint_id,
            checkpoint_manifest_sha256=evidence.checkpoint_manifest_sha256,
        )
        if context.manifest_id is None:
            raise ProductionBoundaryError(
                BoundaryErrorCode.MANIFEST_BINDING_REQUIRED,
                "pair operations require context.manifest_id",
                operation_reference=_public_operation_reference(context),
            )
        if (
            context.manifest_id != snapshot.manifest_id
            or context.scope_value(ScopeKind.MANIFEST_ID) != snapshot.manifest_id
        ):
            raise ProductionBoundaryError(
                BoundaryErrorCode.MANIFEST_CONTEXT_MISMATCH,
                "manifest evidence does not match the operation context",
                operation_reference=_public_operation_reference(context),
            )
        if context.scope_value(ScopeKind.CHECKPOINT_ID) != snapshot.checkpoint_id:
            raise ProductionBoundaryError(
                BoundaryErrorCode.MANIFEST_CONTEXT_MISMATCH,
                "checkpoint evidence does not match the operation context",
                operation_reference=_public_operation_reference(context),
            )
        return snapshot

    @staticmethod
    def _validate_staging_source(
        decision: NamespaceDecision,
        evidence: PairEvidence,
    ) -> None:
        tail = decision.tail
        if decision.namespace in {
            NamespaceId.JOB_WORKSPACE_INTERNAL,
            NamespaceId.JOB_WORKSPACE_RESTRICTED,
        }:
            valid = len(tail) == 3 and ntpath.normcase(tail[1]) == "publish"
        elif decision.namespace in {
            NamespaceId.COPY_WORK_INTERNAL,
            NamespaceId.COPY_WORK_RESTRICTED,
        }:
            valid = len(tail) == 4 and ntpath.normcase(tail[2]) == "publish"
        elif decision.namespace is NamespaceId.COPY_RESTRICTED:
            valid = len(tail) == 1
        else:
            valid = False
        if decision.namespace in {
            NamespaceId.JOB_WORKSPACE_INTERNAL,
            NamespaceId.JOB_WORKSPACE_RESTRICTED,
            NamespaceId.COPY_WORK_INTERNAL,
            NamespaceId.COPY_WORK_RESTRICTED,
        }:
            valid = valid and ntpath.normcase(tail[-1]) == ntpath.normcase(
                evidence.manifest_id
            )
        if not valid:
            raise ProductionBoundaryError(
                BoundaryErrorCode.PAIR_TOPOLOGY_DENIED,
                "source must be an exact manifest-bound staging object root",
            )

    @staticmethod
    def _validate_classification_flow(
        context: OperationContext,
        source_decision: NamespaceDecision,
        target_decision: NamespaceDecision,
    ) -> None:
        effective_source = _max_classification(
            context.classification,
            source_decision.effective_classification,
        )
        if (
            effective_source is DataClassification.RESTRICTED
            and target_decision.effective_classification
            is not DataClassification.RESTRICTED
        ):
            raise ProductionBoundaryError(
                BoundaryErrorCode.PAIR_TOPOLOGY_DENIED,
                "restricted pair data cannot be published into an internal namespace",
                operation_reference=_public_operation_reference(context),
            )

    def _validate_pair_topology(
        self,
        kind: PairKind,
        source_core: GuardedPath,
        source_decision: NamespaceDecision,
        target_core: GuardedPath,
        target_decision: NamespaceDecision,
    ) -> None:
        if source_core.expected_kind is not ExpectedKind.DIRECTORY or target_core.expected_kind is not ExpectedKind.DIRECTORY:
            raise ProductionBoundaryError(
                BoundaryErrorCode.PAIR_TOPOLOGY_DENIED,
                "pair members must be directory object roots",
            )
        if _same_or_ancestor(source_core.relative_path, target_core.relative_path) or _same_or_ancestor(
            target_core.relative_path, source_core.relative_path
        ):
            raise ProductionBoundaryError(
                BoundaryErrorCode.PAIR_TOPOLOGY_DENIED,
                "pair members cannot be equal or ancestor-related",
            )
        if not self.__policy.allows_pair_topology(
            kind.value,
            source_decision.namespace,
            target_decision.namespace,
        ):
            raise ProductionBoundaryError(
                BoundaryErrorCode.PAIR_TOPOLOGY_DENIED,
                "source-to-target namespace transition is not allowed",
            )

    @staticmethod
    def _topology_digest(
        kind: PairKind,
        pair_id: str,
        source_core: GuardedPath,
        source_decision: NamespaceDecision,
        target_core: GuardedPath,
        target_decision: NamespaceDecision,
        evidence: PairEvidence,
    ) -> str:
        return _canonical_digest(
            {
                "kind": kind.value,
                "pair_id": pair_id,
                "source_path": source_core.relative_path.as_posix(),
                "source_namespace": source_decision.namespace.value,
                "source_intent": source_core.intent.value,
                "target_path": target_core.relative_path.as_posix(),
                "target_namespace": target_decision.namespace.value,
                "target_intent": target_core.intent.value,
                "expected_kind": ExpectedKind.DIRECTORY.value,
                "evidence_digest": evidence.digest,
            },
            domain="PAIR-TOPOLOGY-V1",
        )

    def _candidate_event(
        self,
        record: _CandidateRecord,
        *,
        context: OperationContext,
        decision: NamespaceDecision,
        action: AuditAction,
        audit_hmac_key: bytes,
    ) -> AuditEvent:
        return create_audit_event(
            decision=AuditDecision.CANDIDATE_ALLOW,
            action=action,
            capability_kind=CapabilityKind.SINGLE,
            error_code=None,
            context=context,
            effective_classification=_boundary_effective_classification(
                context,
                decision,
            ),
            path_mode=decision.rule.audit_path_mode,
            policy_digest=self.__policy.digest,
            boundary_instance_id=self.__instance_id,
            ticket_id=record.ticket_id,
            pair_id=None,
            pair_role=None,
            namespace=record.namespace,
            intent=record.core.intent,
            expected_kind=record.core.expected_kind,
            relative_path=record.core.relative_path,
            audit_hmac_key=audit_hmac_key,
        )

    def _pair_member_event(
        self,
        record: _CandidateRecord,
        pair: _PairRecord,
        *,
        context: OperationContext,
        decision: NamespaceDecision,
        action: AuditAction,
        audit_hmac_key: bytes,
    ) -> AuditEvent:
        return create_audit_event(
            decision=AuditDecision.CANDIDATE_ALLOW,
            action=action,
            capability_kind=(
                CapabilityKind.PUBLISH_PAIR
                if pair.kind is PairKind.PUBLISH
                else CapabilityKind.QUARANTINE_PAIR
            ),
            error_code=None,
            context=context,
            effective_classification=pair.effective_classification,
            path_mode=decision.rule.audit_path_mode,
            policy_digest=self.__policy.digest,
            boundary_instance_id=self.__instance_id,
            ticket_id=record.ticket_id,
            pair_id=pair.pair_id,
            pair_role=record.pair_role,
            namespace=record.namespace,
            intent=record.core.intent,
            expected_kind=record.core.expected_kind,
            relative_path=record.core.relative_path,
            audit_hmac_key=audit_hmac_key,
            manifest_sha256=pair.evidence.manifest_sha256,
            source_tree_sha256=pair.evidence.source_tree_sha256,
            checkpoint_id=pair.evidence.checkpoint_id,
            topology_digest=pair.topology_digest,
            evidence_digest=pair.evidence.digest,
        )

    def _record_denial(
        self,
        *,
        error: Exception,
        relative_path: Path | None,
        intent: PathIntent,
        expected_kind: ExpectedKind,
        context: OperationContext | None,
        capability_kind: CapabilityKind,
        ticket_id: str | None = None,
        pair_id: str | None = None,
    ) -> None:
        effective = (
            context.classification if context else DataClassification.INTERNAL
        )
        try:
            decision = self.__policy.classify(relative_path or Path("REJECTED"))
            effective = _boundary_effective_classification(
                context,
                decision,
            )
            detail_code = _exception_detail_code(error)
            self._record_audit_factory(
                lambda audit_hmac_key: (
                    create_audit_event(
                        decision=AuditDecision.DENY,
                        action=AuditAction.DENY,
                        capability_kind=capability_kind,
                        error_code=detail_code,
                        context=context,
                        effective_classification=effective,
                        path_mode=AuditPathMode.HMAC_ONLY,
                        policy_digest=self.__policy.digest,
                        boundary_instance_id=self.__instance_id,
                        ticket_id=ticket_id,
                        pair_id=pair_id,
                        pair_role=None,
                        namespace=decision.namespace,
                        intent=(
                            intent
                            if isinstance(intent, PathIntent)
                            else PathIntent.EXISTING_READ
                        ),
                        expected_kind=(
                            expected_kind
                            if isinstance(expected_kind, ExpectedKind)
                            else ExpectedKind.ANY
                        ),
                        relative_path=relative_path,
                        audit_hmac_key=audit_hmac_key,
                    ),
                ),
                (
                    None
                    if effective is DataClassification.RESTRICTED
                    else _public_operation_reference(context)
                ),
            )
        except ProductionBoundaryError:
            raise
        except Exception as audit_error:
            raise ProductionBoundaryError(
                BoundaryErrorCode.AUDIT_RECORD_FAILED,
                "security denial could not be recorded",
                operation_reference=(
                    None
                    if effective is DataClassification.RESTRICTED
                    else _public_operation_reference(context)
                ),
            ) from audit_error

    def _failure_after_denial(
        self,
        *,
        error: Exception,
        relative_path: Path | None,
        intent: PathIntent,
        expected_kind: ExpectedKind,
        context: OperationContext | None,
        capability_kind: CapabilityKind,
        ticket_id: str | None = None,
        pair_id: str | None = None,
    ) -> ProductionBoundaryError:
        decision = self.__policy.classify(relative_path or Path("REJECTED"))
        redact = (
            _boundary_effective_classification(context, decision)
            is DataClassification.RESTRICTED
        )
        if not (
            isinstance(error, ProductionBoundaryError)
            and error.code is BoundaryErrorCode.AUDIT_RECORD_FAILED
        ):
            try:
                self._record_denial(
                    error=error,
                    relative_path=relative_path,
                    intent=intent,
                    expected_kind=expected_kind,
                    context=context,
                    capability_kind=capability_kind,
                    ticket_id=ticket_id,
                    pair_id=pair_id,
                )
            except Exception as audit_error:
                return self._public_error(audit_error, context, redact=redact)
        return self._public_error(error, context, redact=redact)

    def _record_audit_factory(
        self,
        builder: Callable[[bytes], tuple[AuditEvent, ...]],
        operation_reference: str | None,
        *,
        runtime_mutex_lease: RuntimeMutexLease | None = None,
    ) -> None:
        try:
            if self.__durable_audit_sink is not None:
                receipt = (
                    self.__durable_audit_sink.record_factory(builder)
                    if runtime_mutex_lease is None
                    else self.__durable_audit_sink._record_factory_under_existing_mutex(
                        runtime_mutex_lease,
                        builder,
                    )
                )
                if type(receipt) is not AuditReceipt:
                    raise ValueError("durable audit sink returned an invalid receipt type")
            else:
                if runtime_mutex_lease is not None:
                    raise ValueError(
                        "under-lease audit append requires the durable audit authority"
                    )
                events = builder(self.__audit_hmac_key)
                receipt = self.__audit_sink.record_batch(events)
                expected = audit_receipt(events)
                if type(receipt) is not AuditReceipt or receipt != expected:
                    raise ValueError("audit sink returned an invalid batch receipt")
        except Exception as exc:
            raise ProductionBoundaryError(
                BoundaryErrorCode.AUDIT_RECORD_FAILED,
                "candidate audit event could not be recorded",
                operation_reference=operation_reference,
            ) from exc

    def _ensure_registry_capacity(
        self,
        *,
        candidate_items: int,
        pair_items: int,
    ) -> None:
        if (
            len(self.__candidate_records) + candidate_items > _MAX_REGISTRY_ITEMS
            or len(self.__pair_records) + pair_items > _MAX_REGISTRY_ITEMS
        ):
            raise ProductionBoundaryError(
                BoundaryErrorCode.REGISTRY_CAPACITY_EXCEEDED,
                "candidate registry capacity was reached",
            )

    def _assert_invariants(self) -> None:
        if not _same_path(self.__guard.authorization_root, _contract_root()):
            raise ProductionBoundaryError(
                BoundaryErrorCode.BOUNDARY_STATE_CHANGED,
                "authorization root no longer matches the execution contract",
            )
        if not _same_path(self.__guard.workspace_root, self.__expected_workspace_root):
            raise ProductionBoundaryError(
                BoundaryErrorCode.BOUNDARY_STATE_CHANGED,
                "workspace root no longer matches the boundary factory",
            )
        if self.__policy.digest != self.__policy_digest:
            raise ProductionBoundaryError(
                BoundaryErrorCode.BOUNDARY_STATE_CHANGED,
                "namespace policy changed after boundary creation",
            )
        with self.__lock:
            try:
                restricted_registry_valid = (
                    type(self.__restricted_recovery_records) is dict
                    and len(self.__restricted_recovery_records)
                    <= _MAX_REGISTRY_ITEMS
                    and all(
                        type(locator_id) is str
                        and _SHA256.fullmatch(locator_id) is not None
                        and type(record) is _RestrictedRecoveryLocatorRecord
                        and record.locator_id == locator_id
                        and record.lifecycle is CapabilityLifecycle.ISSUED
                        and type(record.context) is OperationContext
                        and type(record.context_ticket_id) is str
                        and record.context.authority_ticket_id
                        == record.context_ticket_id
                        and record.context_ticket_id in self.__context_records
                        and type(record.owner_thread) is int
                        and isinstance(record.owner_thread_object, threading.Thread)
                        and record.owner_thread_object.ident == record.owner_thread
                        and type(record.owner_thread_object_binding_sha256) is str
                        and _SHA256.fullmatch(
                            record.owner_thread_object_binding_sha256
                        )
                        is not None
                        and hmac.compare_digest(
                            record.owner_thread_object_binding_sha256,
                            self._restricted_recovery_owner_thread_object_binding(
                                record.owner_thread_object
                            ),
                        )
                        and type(record.source_relative_path) is type(Path())
                        and type(record.target_relative_path) is type(Path())
                        and not record.source_relative_path.is_absolute()
                        and not record.target_relative_path.is_absolute()
                        and record.source_relative_path != Path()
                        and record.target_relative_path != Path()
                        and all(
                            part not in {"", ".", ".."}
                            for part in record.source_relative_path.parts
                        )
                        and all(
                            part not in {"", ".", ".."}
                            for part in record.target_relative_path.parts
                        )
                        for locator_id, record in self.__restricted_recovery_records.items()
                    )
                )
            except Exception:
                restricted_registry_valid = False
            if not restricted_registry_valid:
                raise ProductionBoundaryError(
                    BoundaryErrorCode.BOUNDARY_STATE_CHANGED,
                    "restricted recovery registry invariant changed",
                )
            for pair_id, lease in self.__pair_reservations.items():
                pair = self.__pair_records.get(pair_id)
                if (
                    type(lease) is not _ReservedPairLease
                    or lease._core is not self
                    or lease._closed
                    or pair is not lease._pair
                    or pair.lifecycle is not CapabilityLifecycle.RESERVED
                    or self.__candidate_records.get(pair.source_ticket_id)
                    is not lease._source
                    or self.__candidate_records.get(pair.target_ticket_id)
                    is not lease._target
                ):
                    raise ProductionBoundaryError(
                        BoundaryErrorCode.BOUNDARY_STATE_CHANGED,
                        "pair reservation registry invariant changed",
                    )

    @staticmethod
    def _require_relative(value: str | os.PathLike[str]) -> Path:
        try:
            raw = os.fspath(value)
        except TypeError as exc:
            raise ProductionBoundaryError(
                BoundaryErrorCode.ABSOLUTE_PATH_FORBIDDEN,
                "production paths must be relative text paths",
            ) from exc
        if not isinstance(raw, str):
            raise ProductionBoundaryError(
                BoundaryErrorCode.ABSOLUTE_PATH_FORBIDDEN,
                "byte paths are forbidden",
            )
        pure = PureWindowsPath(raw.replace("/", "\\"))
        if pure.is_absolute() or pure.drive or pure.root:
            raise ProductionBoundaryError(
                BoundaryErrorCode.ABSOLUTE_PATH_FORBIDDEN,
                "production APIs accept project-relative paths only",
            )
        return Path(raw)

    @staticmethod
    def _public_error(
        error: Exception,
        context: OperationContext | None,
        *,
        redact: bool = False,
    ) -> ProductionBoundaryError:
        if isinstance(error, ProductionBoundaryError):
            error.__traceback__ = None
            error.__cause__ = None
            error.__context__ = None
            error.__suppress_context__ = True
            if redact or (
                context is not None
                and context.classification is DataClassification.RESTRICTED
            ):
                error.operation_reference = None
            return error
        operation_reference = None if redact else _public_operation_reference(context)
        if isinstance(error, NamespacePolicyError):
            return ProductionBoundaryError(
                BoundaryErrorCode.POLICY_DENIED,
                "namespace policy denied the requested capability",
                detail_code=error.code.value,
                operation_reference=operation_reference,
            )
        if isinstance(error, WorkspaceGuardError):
            return ProductionBoundaryError(
                BoundaryErrorCode.PATH_REJECTED,
                "workspace path validation rejected the request",
                detail_code=error.code.value,
                operation_reference=operation_reference,
            )
        if isinstance(error, ContextError):
            return ProductionBoundaryError(
                BoundaryErrorCode.INVALID_CONTEXT,
                "operation context or evidence is invalid",
                operation_reference=operation_reference,
            )
        return ProductionBoundaryError(
            BoundaryErrorCode.INVALID_ARGUMENT,
            "candidate request is invalid",
            detail_code=type(error).__name__,
            operation_reference=operation_reference,
        )


class ProductionWorkspaceBoundary:
    """Fixed-root, candidate-only production boundary with no injected dependencies."""

    __slots__ = ("__core",)

    def __init__(self, *, _constructor: object | None = None) -> None:
        if _constructor is not _PRODUCTION_BOUNDARY_CONSTRUCTOR:
            raise TypeError("ProductionWorkspaceBoundary is available only from its fixed singleton factory")
        root = _contract_root()
        self.__core = _BoundaryCore(
            guard=WorkspaceGuard(root),
            expected_workspace_root=root,
        )

    @property
    def project_root(self) -> Path:
        return self.__core.project_root

    @property
    def policy_digest(self) -> str:
        return self.__core.policy_digest

    @property
    def writer_available(self) -> bool:
        return False

    @property
    def audit_events(self) -> tuple[AuditEvent, ...]:
        return self.__core.audit_events

    def require_writer(self) -> None:
        raise WriterUnavailableError()

    def authorize(
        self,
        relative_path: str | os.PathLike[str],
        *,
        intent: PathIntent,
        expected_kind: ExpectedKind,
        context: OperationContext,
    ) -> BoundaryResult[CandidateTicket]:
        try:
            value = self.__core.issue_candidate(
                relative_path,
                intent=intent,
                expected_kind=expected_kind,
                context=context,
                allow_mutation_candidate=False,
            )
        except Exception as error:
            return BoundaryResult.failed(error)
        return BoundaryResult.success(value)

    def revalidate(
        self,
        ticket: CandidateTicket,
        *,
        context: OperationContext,
    ) -> BoundaryResult[CandidateTicket]:
        try:
            value = self.__core.revalidate_candidate(ticket, context=context)
        except Exception as error:
            return BoundaryResult.failed(error)
        return BoundaryResult.success(value)

    def describe_candidate(
        self,
        ticket: CandidateTicket,
        *,
        context: OperationContext,
    ) -> BoundaryResult[CandidateDescriptor]:
        try:
            value = self.__core.describe_candidate(ticket, context=context)
        except Exception as error:
            return BoundaryResult.failed(error)
        return BoundaryResult.success(value)


class _TestWorkspaceBoundary:
    __slots__ = ("__core",)

    def __init__(
        self,
        workspace_root: Path,
        audit_sink: AuditSink | None = None,
        *,
        audit_authority: _AuditAuthority | None = None,
        shared_guard: WorkspaceGuard | None = None,
    ) -> None:
        root = _contract_root()
        self.__core = _BoundaryCore(
            guard=shared_guard or WorkspaceGuard(root, workspace_root),
            expected_workspace_root=workspace_root,
            audit_sink=audit_sink,
            audit_authority=audit_authority,
        )

    @property
    def project_root(self) -> Path:
        return self.__core.project_root

    @property
    def policy_digest(self) -> str:
        return self.__core.policy_digest

    @property
    def writer_available(self) -> bool:
        return False

    @property
    def audit_events(self) -> tuple[AuditEvent, ...]:
        return self.__core.audit_events

    @property
    def diagnostic_registry_counts(self) -> dict[str, int]:
        return self.__core.diagnostic_registry_counts

    def require_writer(self) -> None:
        raise WriterUnavailableError()

    def issue_context(
        self,
        *,
        run_id: str,
        job_id: str,
        operation_id: str,
        caller: Any,
        purpose: Any,
        scopes: tuple[Any, ...] = (),
        manifest_id: str | None = None,
        classification: DataClassification = DataClassification.INTERNAL,
    ) -> OperationContext:
        return self.__core.issue_test_context(
            run_id=run_id,
            job_id=job_id,
            operation_id=operation_id,
            caller=caller,
            purpose=purpose,
            scopes=scopes,
            manifest_id=manifest_id,
            classification=classification,
        )

    def release_context(self, context: OperationContext) -> bool:
        return self.__core.release_test_context(context)

    def _validate_job_operation_context(self, context: OperationContext) -> str:
        self.__core._validate_context_authority(context)
        return context.digest

    def _issue_restricted_recovery_locator(
        self,
        context: OperationContext,
        transaction_id: str,
        *,
        quarantine_pair_id: str | None = None,
    ) -> _RestrictedRecoveryLocatorCapability:
        return self.__core.issue_restricted_recovery_locator(
            context,
            transaction_id,
            _quarantine_pair_id=quarantine_pair_id,
        )

    def _consume_restricted_recovery_locator(
        self,
        capability: _RestrictedRecoveryLocatorCapability,
        transaction_id: str,
    ) -> tuple[Path, Path]:
        return self.__core.consume_restricted_recovery_locator(
            capability,
            transaction_id,
        )

    def _issue_restricted_copy_recovery_locator(
        self,
        context: OperationContext,
    ) -> _RestrictedRecoveryLocatorCapability:
        return self.__core.issue_restricted_copy_recovery_locator(context)

    def _consume_restricted_copy_recovery_locator(
        self,
        capability: _RestrictedRecoveryLocatorCapability,
        context: OperationContext,
    ) -> tuple[Path, Path]:
        return self.__core.consume_restricted_copy_recovery_locator(
            capability,
            context,
        )

    def _pin_job_operation_context(
        self,
        context: OperationContext,
        binding_sha256: str,
    ) -> _JobContextPin:
        return self.__core.pin_test_job_context(context, binding_sha256)

    def _validate_job_operation_pin(
        self,
        context: OperationContext,
        pin: _JobContextPin,
        binding_sha256: str,
    ) -> str:
        return self.__core.validate_test_job_context_pin(
            context,
            pin,
            binding_sha256,
        )

    def _unpin_job_operation_context_after_failed_begin(
        self,
        context: OperationContext,
        pin: _JobContextPin,
        binding_sha256: str,
    ) -> None:
        self.__core.unpin_test_job_context_after_failed_begin(
            context,
            pin,
            binding_sha256,
        )

    def _finish_job_operation_context(
        self,
        context: OperationContext,
        pin: _JobContextPin,
        binding_sha256: str,
    ) -> None:
        self.__core.finish_test_job_context(context, pin, binding_sha256)

    def _issue_publish_pair_for_job(
        self,
        source_path: str | os.PathLike[str],
        target_path: str | os.PathLike[str],
        *,
        manifest_id: str,
        manifest_sha256: str,
        source_tree_sha256: str,
        entry_count: int,
        total_bytes: int,
        checkpoint_id: str,
        checkpoint_manifest_sha256: str,
        context: OperationContext,
        pin: _JobContextPin,
        binding_sha256: str,
        runtime_mutex_lease: RuntimeMutexLease,
    ) -> MovePairCandidate:
        return self.__core.issue_publish_pair_for_job(
            source_path,
            target_path,
            evidence=PairEvidence(
                manifest_id=manifest_id,
                manifest_sha256=manifest_sha256,
                source_tree_sha256=source_tree_sha256,
                entry_count=entry_count,
                total_bytes=total_bytes,
                checkpoint_id=checkpoint_id,
                checkpoint_manifest_sha256=checkpoint_manifest_sha256,
            ),
            context=context,
            context_pin=pin,
            context_binding=binding_sha256,
            runtime_mutex_lease=runtime_mutex_lease,
        )

    def _issue_quarantine_pair_for_job(
        self,
        source_path: str | os.PathLike[str],
        *,
        quarantine_date: str,
        manifest_id: str,
        manifest_sha256: str,
        source_tree_sha256: str,
        entry_count: int,
        total_bytes: int,
        checkpoint_id: str,
        checkpoint_manifest_sha256: str,
        context: OperationContext,
        pin: _JobContextPin,
        binding_sha256: str,
        runtime_mutex_lease: RuntimeMutexLease,
    ) -> QuarantinePairCandidate:
        return self.__core.issue_quarantine_pair_for_job(
            source_path,
            quarantine_date=quarantine_date,
            evidence=PairEvidence(
                manifest_id=manifest_id,
                manifest_sha256=manifest_sha256,
                source_tree_sha256=source_tree_sha256,
                entry_count=entry_count,
                total_bytes=total_bytes,
                checkpoint_id=checkpoint_id,
                checkpoint_manifest_sha256=checkpoint_manifest_sha256,
            ),
            context=context,
            context_pin=pin,
            context_binding=binding_sha256,
            runtime_mutex_lease=runtime_mutex_lease,
        )

    def _reserve_publish_pair_for_job(
        self,
        token: MovePairCandidate,
        *,
        context: OperationContext,
        pin: _JobContextPin,
        binding_sha256: str,
        runtime_mutex_lease: RuntimeMutexLease,
    ) -> tuple[_ReservedPairLease, _ReservedPairView]:
        return self.__core.reserve_publish_pair_for_job(
            token,
            context=context,
            context_pin=pin,
            context_binding=binding_sha256,
            runtime_mutex_lease=runtime_mutex_lease,
        )

    def _reserve_quarantine_pair_for_job(
        self,
        token: QuarantinePairCandidate,
        *,
        context: OperationContext,
        pin: _JobContextPin,
        binding_sha256: str,
        runtime_mutex_lease: RuntimeMutexLease,
    ) -> tuple[_ReservedPairLease, _ReservedPairView]:
        return self.__core.reserve_quarantine_pair_for_job(
            token,
            context=context,
            context_pin=pin,
            context_binding=binding_sha256,
            runtime_mutex_lease=runtime_mutex_lease,
        )

    def _finish_reserved_pair_for_job(
        self,
        reservation: _ReservedPairLease,
        *,
        context: OperationContext,
        pin: _JobContextPin,
        binding_sha256: str,
        lifecycle: str,
    ) -> None:
        try:
            terminal = CapabilityLifecycle(lifecycle)
        except (TypeError, ValueError):
            raise ProductionBoundaryError(
                BoundaryErrorCode.INVALID_ARGUMENT,
                "job pair terminal lifecycle is invalid",
            ) from None
        self.__core.finish_reserved_pair_for_job(
            reservation,
            context=context,
            context_pin=pin,
            context_binding=binding_sha256,
            lifecycle=terminal,
        )

    def _validate_reserved_pair_for_job(
        self,
        reservation: _ReservedPairLease,
        *,
        context: OperationContext,
        pin: _JobContextPin,
        binding_sha256: str,
        runtime_mutex_lease: RuntimeMutexLease,
    ) -> _ReservedPairView:
        return self.__core.validate_reserved_pair_for_job(
            reservation,
            context=context,
            context_pin=pin,
            context_binding=binding_sha256,
            runtime_mutex_lease=runtime_mutex_lease,
        )

    def authorize(
        self,
        relative_path: str | os.PathLike[str],
        *,
        intent: PathIntent,
        expected_kind: ExpectedKind,
        context: OperationContext,
    ) -> CandidateTicket:
        return self.__core.issue_candidate(
            relative_path,
            intent=intent,
            expected_kind=expected_kind,
            context=context,
            allow_mutation_candidate=True,
        )

    def revalidate(
        self,
        ticket: CandidateTicket,
        *,
        context: OperationContext,
    ) -> CandidateTicket:
        return self.__core.revalidate_candidate(ticket, context=context)

    def authorize_publish(
        self,
        source_path: str | os.PathLike[str],
        target_path: str | os.PathLike[str],
        *,
        evidence: PairEvidence,
        context: OperationContext,
    ) -> MovePairCandidate:
        return self.__core.issue_publish_pair(
            source_path,
            target_path,
            evidence=evidence,
            context=context,
        )

    def authorize_quarantine(
        self,
        source_path: str | os.PathLike[str],
        *,
        evidence: PairEvidence,
        context: OperationContext,
    ) -> QuarantinePairCandidate:
        return self.__core.issue_quarantine_pair(
            source_path,
            evidence=evidence,
            context=context,
        )

    def revalidate_pair(
        self,
        token: MovePairCandidate | QuarantinePairCandidate,
        *,
        context: OperationContext,
    ) -> MovePairCandidate | QuarantinePairCandidate:
        return self.__core.revalidate_pair(token, context=context)

    def describe_candidate(
        self,
        ticket: CandidateTicket,
        *,
        context: OperationContext,
    ) -> CandidateDescriptor:
        return self.__core.describe_candidate(ticket, context=context)

    def describe_pair(
        self,
        token: MovePairCandidate | QuarantinePairCandidate,
        *,
        context: OperationContext,
    ) -> PairDescriptor:
        return self.__core.describe_pair(token, context=context)


def get_production_boundary() -> ProductionWorkspaceBoundary:
    global _production_boundary_singleton

    configured = _absolute_lexical(app_config.PROJECT_ROOT)
    expected = _absolute_lexical(_contract_root())
    if not _same_path(configured, expected):
        raise ProductionBoundaryError(
            BoundaryErrorCode.PRODUCTION_ROOT_MISMATCH,
            "configured project root differs from the immutable execution contract",
        )
    boundary = _production_boundary_singleton
    if boundary is not None:
        return boundary
    with _PRODUCTION_BOUNDARY_LOCK:
        boundary = _production_boundary_singleton
        if boundary is None:
            boundary = ProductionWorkspaceBoundary(
                _constructor=_PRODUCTION_BOUNDARY_CONSTRUCTOR,
            )
            _production_boundary_singleton = boundary
        return boundary


def _reset_production_boundary_for_tests() -> None:
    """Reset the singleton only inside a safe-launcher Test laboratory."""

    global _production_boundary_singleton

    run_root = os.environ.get("M0_TEST_LAB_ROOT", "")
    expected_prefix = str(_contract_root() / "tmp" / "test_lab" / "RUN-")
    if not run_root or not str(run_root).casefold().startswith(expected_prefix.casefold()):
        raise ProductionBoundaryError(
            BoundaryErrorCode.PRODUCTION_ROOT_MISMATCH,
            "production boundary reset is available only to the safe test laboratory",
        )
    with _PRODUCTION_BOUNDARY_LOCK:
        _production_boundary_singleton = None


def _create_test_boundary(
    workspace_root: Path,
    *,
    audit_sink: AuditSink | None = None,
) -> _TestWorkspaceBoundary:
    """Private test factory restricted to an existing Test-local RUN laboratory."""

    workspace = _absolute_lexical(workspace_root)
    test_lab_root = _absolute_lexical(_contract_root() / "tmp" / "test_lab")
    workspace_parts = PureWindowsPath(str(workspace)).parts
    lab_parts = PureWindowsPath(str(test_lab_root)).parts
    if len(workspace_parts) <= len(lab_parts) + 1:
        raise ProductionBoundaryError(
            BoundaryErrorCode.PRODUCTION_ROOT_MISMATCH,
            "test workspace is not deep enough below tmp/test_lab",
        )
    for candidate, expected in zip(workspace_parts, lab_parts, strict=False):
        if ntpath.normcase(candidate) != ntpath.normcase(expected):
            raise ProductionBoundaryError(
                BoundaryErrorCode.PRODUCTION_ROOT_MISMATCH,
                "test workspace escaped the fixed Test-local laboratory",
            )
    tail = workspace_parts[len(lab_parts) :]
    if not tail[0].startswith("RUN-") or ntpath.normcase(tail[-1]) != "project":
        raise ProductionBoundaryError(
            BoundaryErrorCode.PRODUCTION_ROOT_MISMATCH,
            "test workspace must be inside a RUN-* laboratory and end in project",
        )
    return _TestWorkspaceBoundary(workspace, audit_sink=audit_sink)


def _test_path_identity(path: Path, identity: Any) -> PathIdentity:
    return PathIdentity(
        path=path,
        device=int(identity.st_dev),
        inode=int(identity.st_ino),
        mode=int(identity.st_mode),
        file_attributes=int(getattr(identity, "st_file_attributes", 0)),
        reparse_tag=int(getattr(identity, "st_reparse_tag", 0)),
        nlink=int(identity.st_nlink),
    )


def _test_factory_fence_paths(run_root: Path, workspace: Path) -> tuple[tuple[Path, bool], ...]:
    contract_root = _contract_root()
    test_lab_root = contract_root / "tmp" / "test_lab"
    run_parts = PureWindowsPath(str(run_root)).parts
    workspace_parts = PureWindowsPath(str(workspace)).parts
    candidates: list[tuple[Path, bool]] = [
        (contract_root, True),
        (contract_root / "tmp", True),
        (test_lab_root, True),
        (run_root, True),
    ]
    current = run_root
    for part in workspace_parts[len(run_parts) :]:
        current = current / part
        candidates.append((current, True))
    candidates.append((run_root / ".safety-marker.json", False))
    result: list[tuple[Path, bool]] = []
    seen: set[str] = set()
    for path, is_directory in candidates:
        normalized = ntpath.normcase(ntpath.normpath(str(path)))
        if normalized not in seen:
            seen.add(normalized)
            result.append((path, is_directory))
    return tuple(result)


class _TestFactoryFenceAuthority:
    """Non-writing authority used only while the factory binds its handle chain."""

    def authorize(self, *_args: Any, **_kwargs: Any) -> GuardedPath:
        raise HandleWriterError(
            HandleWriterCode.INVALID_TEST_WORKSPACE,
            "factory fence verifier cannot issue capabilities",
        )

    def revalidate(self, _ticket: GuardedPath) -> GuardedPath:
        raise HandleWriterError(
            HandleWriterCode.INVALID_TEST_WORKSPACE,
            "factory fence verifier cannot revalidate capabilities",
        )

    def release(self, _ticket: GuardedPath) -> bool:
        return False


def _create_test_handle_writer(workspace_root: Path) -> _WindowsHandleWriter:
    """Private Test-only writer factory owned by the fixed boundary service."""

    if os.name != "nt":
        raise HandleWriterError(
            HandleWriterCode.UNSUPPORTED_PLATFORM,
            "the handle kernel requires Windows",
        )
    raw_run_root = os.environ.get("M0_TEST_LAB_ROOT")
    launch_token = os.environ.get("M0_TEST_LAB_TOKEN")
    if not raw_run_root or not launch_token:
        raise HandleWriterError(
            HandleWriterCode.INVALID_TEST_WORKSPACE,
            "writer factory requires the active safe-launcher authority",
        )
    workspace = _absolute_lexical(workspace_root)
    run_root = _absolute_lexical(raw_run_root)
    test_lab_root = _absolute_lexical(_contract_root() / "tmp" / "test_lab")
    run_parts = PureWindowsPath(str(run_root)).parts
    workspace_parts = PureWindowsPath(str(workspace)).parts
    lab_parts = PureWindowsPath(str(test_lab_root)).parts
    if (
        len(run_parts) != len(lab_parts) + 1
        or any(
            ntpath.normcase(actual) != ntpath.normcase(expected)
            for actual, expected in zip(run_parts, lab_parts, strict=False)
        )
        or run_parts[-1][:4] != "RUN-"
    ):
        raise HandleWriterError(
            HandleWriterCode.INVALID_TEST_WORKSPACE,
            "safe-launcher authority is outside the fixed safety laboratory",
        )
    if len(workspace_parts) <= len(run_parts) or any(
        ntpath.normcase(actual) != ntpath.normcase(expected)
        for actual, expected in zip(workspace_parts, run_parts, strict=False)
    ):
        raise HandleWriterError(
            HandleWriterCode.INVALID_TEST_WORKSPACE,
            "test workspace escaped the active safe-launcher run",
        )
    if ntpath.normcase(workspace_parts[-1]) != "project":
        raise HandleWriterError(
            HandleWriterCode.INVALID_TEST_WORKSPACE,
            "test workspace must end in project",
        )
    marker_path = run_root / ".safety-marker.json"
    api = _WindowsApi()
    verifier = _WindowsHandleWriter(
        _TestFactoryFenceAuthority(),
        _constructor=_HANDLE_WRITER_CONSTRUCTOR,
        api=api,
        workspace_root=workspace,
    )
    fence_handles: list[int] = []
    fence_identities: list[PathIdentity] = []
    writer: _WindowsHandleWriter | None = None
    marker: dict[str, Any] | None = None
    failure: tuple[HandleWriterCode, int | None, str] | None = None
    try:
        for path, is_directory in _test_factory_fence_paths(run_root, workspace):
            inspected = os.lstat(path)
            if bool(stat.S_ISDIR(inspected.st_mode)) != is_directory:
                raise HandleWriterError(
                    HandleWriterCode.INVALID_TEST_WORKSPACE,
                    "test writer factory path has an invalid object type",
                )
            identity = _test_path_identity(path, inspected)
            flags = api.FILE_FLAG_OPEN_REPARSE_POINT
            if is_directory:
                flags |= api.FILE_FLAG_BACKUP_SEMANTICS
            handle = api.open_handle(
                path,
                access=api.GENERIC_READ,
                share=api.FILE_SHARE_READ,
                disposition=api.OPEN_EXISTING,
                flags=flags,
            )
            fence_handles.append(handle)
            fence_identities.append(identity)
            observed = verifier._observe_identity(handle)
            verifier._verify_identity(identity, observed)
            verifier._verify_final_path(handle, identity.path)
            verifier._verify_path_matches_handle(identity.path, observed)
            if not is_directory:
                verifier._require_regular_single_link(observed)
                if observed.end_of_file < 2 or observed.end_of_file > 64 * 1024:
                    raise HandleWriterError(
                        HandleWriterCode.INVALID_TEST_WORKSPACE,
                        "safe-launcher marker has an invalid bounded size",
                    )
                marker_bytes = verifier._read_bounded_handle(handle, 64 * 1024)
                after_read = verifier._observe_identity(handle)
                if (
                    len(marker_bytes) != observed.end_of_file
                    or not verifier._same_object(observed, after_read)
                    or after_read.end_of_file != observed.end_of_file
                    or after_read.last_write_time != observed.last_write_time
                    or after_read.change_time != observed.change_time
                ):
                    raise HandleWriterError(
                        HandleWriterCode.INVALID_TEST_WORKSPACE,
                        "safe-launcher marker changed during its verified read",
                    )
                decoded = json.loads(str(marker_bytes, "utf-8", "strict"))
                marker = decoded if isinstance(decoded, dict) else None

        marker_identity = fence_identities[-1]
        workspace_identity = fence_identities[-2]
        marker_project_root = (
            marker.get("project_root") if isinstance(marker, dict) else None
        )
        marker_valid = (
            stat.S_ISREG(marker_identity.mode)
            and marker_identity.nlink == 1
            and not marker_identity.file_attributes
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            and not marker_identity.reparse_tag
            and isinstance(marker, dict)
            and marker.get("run_id") == run_root.name
            and marker.get("schema_version") == "1.0"
            and marker.get("purpose") == "M0-S1 WorkspaceGuard safety laboratory"
            and marker.get("cleanup_policy")
            == "retain-until-manifested-quarantine"
            and isinstance(marker_project_root, str)
            and _same_path(_absolute_lexical(marker_project_root), _contract_root())
            and marker.get("launch_token_sha256")
            == hashlib.sha256(launch_token.encode("utf-8")).hexdigest()
        )
        if not marker_valid or not stat.S_ISDIR(workspace_identity.mode):
            raise HandleWriterError(
                HandleWriterCode.INVALID_TEST_WORKSPACE,
                "test workspace or safe-launcher marker is invalid",
            )

        guard = WorkspaceGuard(_contract_root(), workspace)
        writer = _WindowsHandleWriter(
            guard,
            _constructor=_HANDLE_WRITER_CONSTRUCTOR,
            api=api,
            workspace_root=workspace,
        )
        for handle, identity in zip(
            fence_handles,
            fence_identities,
            strict=True,
        ):
            observed = writer._observe_identity(handle)
            writer._verify_identity(identity, observed)
            writer._verify_final_path(handle, identity.path)
            writer._verify_path_matches_handle(identity.path, observed)
    except HandleWriterError as exc:
        failure = (
            exc.code,
            exc.winerror,
            "test writer factory rejected an unsafe or changed laboratory",
        )
    except BaseException:
        failure = (
            HandleWriterCode.INVALID_TEST_WORKSPACE,
            None,
            "test writer factory could not bind the active laboratory",
        )
    finally:
        handles_to_close = fence_handles
        fence_handles = []
        try:
            (writer or verifier)._close_all(handles_to_close)
        except HandleWriterError as exc:
            failure = (
                exc.code,
                exc.winerror,
                "test writer factory could not close its verified fences",
            )
        except BaseException:
            failure = (
                HandleWriterCode.HANDLE_CLOSE_FAILED,
                None,
                "test writer factory could not close its verified fences",
            )
    if failure is not None:
        code, winerror, message = failure
        raise HandleWriterError(code, message, winerror=winerror) from None
    if writer is None:
        raise HandleWriterError(
            HandleWriterCode.INVALID_TEST_WORKSPACE,
            "test writer factory did not construct a writer",
        ) from None
    return writer


@dataclass(frozen=True, slots=True)
class _TestDurableBoundaryBundle:
    boundary: _TestWorkspaceBoundary
    ledger: DurableAuditLedger = field(repr=False)
    key_store: AuditKeyRevisionStore = field(repr=False)
    writer: _WindowsHandleWriter = field(repr=False)

    def __reduce__(self) -> Any:
        raise TypeError("durable test boundary bundles cannot be serialized")


def _create_test_durable_boundary(
    workspace_root: Path,
    *,
    initialize: bool = False,
    epoch_id: str,
    initial_revision_sequence: int,
    initial_revision_id: str,
    master_key: bytes,
    key_created_at_utc: str | None = None,
    ledger_initialized_at_utc: str | None = None,
) -> _TestDurableBoundaryBundle:
    """Private Test-only durable audit factory; production remains disconnected."""

    if type(initialize) is not bool:
        raise LedgerError(
            code=LedgerCode.INVALID_REQUEST,
            message="durable audit mode must be an exact boolean",
        )
    writer = _create_test_handle_writer(workspace_root)
    key_store = AuditKeyRevisionStore(
        writer,
        _constructor=_LEDGER_CONSTRUCTOR,
    )
    effective_key_created_at = key_created_at_utc or (
        datetime.now(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")
        if initialize
        else "2000-01-01T00:00:00Z"
    )
    expected_payload, expected_revision = build_key_revision_bytes(
        revision_sequence=initial_revision_sequence,
        revision_id=initial_revision_id,
        created_at_utc=effective_key_created_at,
        master_key=master_key,
    )
    effective_ledger_initialized_at = (
        ledger_initialized_at_utc
        or datetime.now(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")
        if initialize
        else None
    )
    if initialize:
        _genesis_payload, _genesis_sha, _genesis_batch, _genesis_records = (
            _build_genesis_segment_bytes(
                epoch_id=epoch_id,
                created_at_utc=effective_ledger_initialized_at,
                revision=expected_revision,
            )
        )
        del _genesis_payload, _genesis_sha, _genesis_batch, _genesis_records
    with writer.acquire_runtime_mutex() as lease:
        existing = key_store._load_all_under_mutex()
        revision = existing.get(initial_revision_id)
        if initialize:
            if initial_revision_sequence != 1 or existing:
                raise LedgerError(
                    code=LedgerCode.INVALID_REQUEST,
                    message="durable audit initialization requires an exact empty key store",
                )
            segment_snapshot = writer.read_flat_directory(
                Path("logs") / "audit" / "segments" / epoch_id,
                maximum_entries=4096,
                maximum_file_bytes=2 * 1024 * 1024,
                maximum_total_bytes=64 * 1024 * 1024,
            )
            if segment_snapshot.entries:
                raise LedgerError(
                    code=LedgerCode.INVALID_REQUEST,
                    message="durable audit initialization requires an exact empty segment store",
                )
            revision = key_store._create_revision_under_mutex(
                expected_payload,
                expected_revision,
            )
        if revision is None:
            raise LedgerError(
                code=LedgerCode.KEY_NOT_FOUND,
                message="durable audit open requires its existing initial key revision",
            )
        if (
            revision.revision_sequence != expected_revision.revision_sequence
            or revision.master_key_sha256 != expected_revision.master_key_sha256
            or revision.audit_hmac_key_id != expected_revision.audit_hmac_key_id
            or revision.segment_key_id != expected_revision.segment_key_id
            or (
                key_created_at_utc is not None
                and revision.revision_sha256 != expected_revision.revision_sha256
            )
        ):
            raise LedgerError(
                code=LedgerCode.KEY_CONFLICT,
                message="existing durable audit key differs from the requested revision",
            )
        ledger = DurableAuditLedger(
            writer,
            key_store,
            epoch_id=epoch_id,
            initial_revision_id=initial_revision_id,
            initialize=initialize,
            initialized_at_utc=effective_ledger_initialized_at,
            _runtime_mutex_lease=lease,
            _constructor=_LEDGER_CONSTRUCTOR,
        )
    authority = _AuditAuthority(
        sink=DurableAuditSink(
            ledger,
            _constructor=_LEDGER_CONSTRUCTOR,
        ),
        ledger=ledger,
        key_store=key_store,
        writer=writer,
        _constructor=_AUDIT_AUTHORITY_CONSTRUCTOR,
    )
    boundary = _TestWorkspaceBoundary(
        _absolute_lexical(workspace_root),
        audit_authority=authority,
        shared_guard=writer._path_authority,
    )
    return _TestDurableBoundaryBundle(
        boundary=boundary,
        ledger=ledger,
        key_store=key_store,
        writer=writer,
    )


def _create_test_job_runtime(
    bundle: _TestDurableBoundaryBundle,
    *,
    operation_ledger: DurableOperationLedger | None = None,
) -> _TestJobRuntime:
    """Private S3-D factory; production boundary intentionally has no peer API."""

    if type(bundle) is not _TestDurableBoundaryBundle:
        raise ProductionBoundaryError(
            BoundaryErrorCode.INVALID_ARGUMENT,
            "job runtime requires an exact durable Test-local bundle",
        )
    if operation_ledger is not None and type(operation_ledger) is not DurableOperationLedger:
        raise ProductionBoundaryError(
            BoundaryErrorCode.INVALID_ARGUMENT,
            "job runtime operation ledger must be an exact durable authority",
        )
    return _build_test_job_runtime(
        bundle.boundary,
        bundle.writer,
        bundle.ledger,
        bundle.writer._workspace_root,
        operation_ledger=operation_ledger,
        _constructor=_JOB_RUNTIME_CONSTRUCTOR,
    )


def _create_test_operation_ledger(
    bundle: _TestDurableBoundaryBundle,
    *,
    epoch_id: str,
    initialize: bool = False,
    initialized_at_utc: str | None = None,
) -> DurableOperationLedger:
    """Private S3-E operation ledger factory; production remains disconnected."""

    if type(bundle) is not _TestDurableBoundaryBundle or type(initialize) is not bool:
        raise ProductionBoundaryError(
            BoundaryErrorCode.INVALID_ARGUMENT,
            "operation ledger requires an exact durable Test-local bundle",
        )
    try:
        with bundle.writer.acquire_runtime_mutex() as lease:
            bundle.ledger._rescan_under_existing_mutex(lease)
            audit_policy_digest = bundle.ledger.policy_digest
            if (
                initialize
                and audit_policy_digest != bundle.boundary.policy_digest
            ):
                raise ProductionBoundaryError(
                    BoundaryErrorCode.INVALID_ARGUMENT,
                    "new operation epochs require the current authenticated audit policy",
                )
            revision = bundle.ledger._active_revision()
            activated_revision_ids = set(
                bundle.ledger._activated_revision_ids_under_existing_mutex(lease)
            )
            known_revisions = tuple(
                revision
                for _revision_id, revision in sorted(
                    bundle.key_store._load_all_under_mutex().items()
                )
                if _revision_id in activated_revision_ids
            )
            operation_ledger = DurableOperationLedger(
                bundle.writer,
                revision,
                epoch_id=epoch_id,
                policy_digest=bundle.boundary.policy_digest,
                known_revisions=known_revisions,
                initialize=initialize,
                initialized_at_utc=initialized_at_utc,
                _runtime_mutex_lease=lease,
                _constructor=_OPERATION_LEDGER_CONSTRUCTOR,
            )
            if operation_ledger.policy_digest != audit_policy_digest:
                operation_ledger._seal_cross_ledger_contradiction()
            bound_heads = operation_ledger.bound_audit_heads_under_existing_mutex(
                lease
            )
            if not bundle.ledger._contains_all_segment_sha256_under_existing_mutex(
                lease,
                bound_heads,
            ):
                operation_ledger._seal_cross_ledger_contradiction()
            return operation_ledger
    except OperationLedgerError:
        raise


def _create_test_copy_ledgers(
    bundle: _TestDurableBoundaryBundle,
    operation_ledger: DurableOperationLedger,
    *,
    epoch_id: str,
    run_scope_id: str,
    initialize: bool = False,
    initialized_at_utc: str | None = None,
) -> DurableCopyLedgers:
    """Construct both S3-F chains under the co-owned Test-local mutex."""

    if (
        type(bundle) is not _TestDurableBoundaryBundle
        or type(operation_ledger) is not DurableOperationLedger
        or type(initialize) is not bool
    ):
        raise ProductionBoundaryError(
            BoundaryErrorCode.INVALID_ARGUMENT,
            "copy ledgers require exact Test-local durable authorities",
        )
    try:
        canonical_epoch = validate_safe_id(epoch_id, field_name="epoch_id")
        canonical_run_scope = validate_safe_id(
            run_scope_id,
            field_name="run_scope_id",
        )
    except Exception:
        raise ProductionBoundaryError(
            BoundaryErrorCode.INVALID_ARGUMENT,
            "copy ledger epoch or run scope is invalid",
        ) from None
    try:
        with bundle.writer.acquire_runtime_mutex() as lease:
            audit_head = bundle.ledger._rescan_under_existing_mutex(lease)
            operation_ledger._rescan_under_existing_mutex(lease)
            audit_policy_digest = bundle.ledger.policy_digest
            activated_revision_ids = set(
                bundle.ledger._activated_revision_ids_under_existing_mutex(lease)
            )
            if (
                audit_policy_digest != bundle.boundary.policy_digest
                or operation_ledger.policy_digest != audit_policy_digest
                or operation_ledger.signing_revision_id not in activated_revision_ids
                or (
                    initialize
                    and operation_ledger.signing_revision_id
                    != audit_head.active_revision_id
                )
            ):
                raise ProductionBoundaryError(
                    BoundaryErrorCode.INVALID_ARGUMENT,
                    "copy ledgers require one authenticated current-policy ancestry",
                )
            revision = bundle.ledger._active_revision()
            revision_inventory = bundle.key_store._load_all_under_mutex()
            if (
                revision.revision_id not in activated_revision_ids
                or activated_revision_ids - set(revision_inventory)
            ):
                raise ProductionBoundaryError(
                    BoundaryErrorCode.INVALID_ARGUMENT,
                    "copy ledgers require every activated audit revision",
                )
            known_revisions = tuple(
                item
                for revision_id, item in sorted(
                    revision_inventory.items()
                )
                if revision_id in activated_revision_ids
            )
            with _resolve_reviewed_operation_epochs_under_existing_mutex(
                bundle.writer,
                revision,
                policy_digest=bundle.boundary.policy_digest,
                activated_revisions=known_revisions,
                lease=lease,
            ) as resolved_operation_ledgers:
                audit_inventory = (
                    bundle.ledger.authenticated_segment_sha256s_under_existing_mutex(
                        lease
                    )
                )
                resolved_by_epoch = {
                    item.head.epoch_id: item
                    for item in resolved_operation_ledgers
                }
                selected_operation = resolved_by_epoch.get(
                    operation_ledger.head.epoch_id
                )
                if (
                    selected_operation is None
                    or selected_operation.head != operation_ledger.head
                    or any(
                        item.policy_digest != audit_policy_digest
                        or item.signing_revision_id not in activated_revision_ids
                        or not set(
                            item.bound_audit_heads_under_existing_mutex(lease)
                        ).issubset(set(audit_inventory))
                        for item in resolved_operation_ledgers
                    )
                ):
                    operation_ledger._seal_cross_ledger_contradiction()
                if initialize:
                    DurableCopyLedgers._preflight_new_epoch_under_existing_mutex(
                        bundle.writer,
                        revision,
                        epoch_id=canonical_epoch,
                        run_scope_id=canonical_run_scope,
                        policy_digest=bundle.boundary.policy_digest,
                        activated_revisions=known_revisions,
                        audit_ledger=bundle.ledger,
                        operation_ledgers=resolved_operation_ledgers,
                        lease=lease,
                    )
                ledgers = DurableCopyLedgers(
                    bundle.writer,
                    revision,
                    epoch_id=canonical_epoch,
                    run_scope_id=canonical_run_scope,
                    policy_digest=bundle.boundary.policy_digest,
                    known_revisions=known_revisions,
                    audit_ledger=bundle.ledger,
                    initialize=initialize,
                    initialized_at_utc=initialized_at_utc,
                    _runtime_mutex_lease=lease,
                    _constructor=_COPY_LEDGERS_CONSTRUCTOR,
                )
                if (
                    ledgers.signing_revision_id
                    != operation_ledger.signing_revision_id
                    or (
                        initialize
                        and ledgers.signing_revision_id
                        != audit_head.active_revision_id
                    )
                ):
                    ledgers._seal(CopyLedgerCode.CROSS_REFERENCE_INVALID)
                    raise ProductionBoundaryError(
                        BoundaryErrorCode.INVALID_ARGUMENT,
                        "copy and publish ledgers do not share one activated revision",
                    )
                ancestor_capability = (
                    ledgers._issue_authenticated_ancestors_under_existing_mutex(
                        lease,
                        bundle.ledger,
                        operation_ledger,
                    )
                )
                ledgers._verify_external_ancestors_under_existing_mutex(
                    lease,
                    ancestor_capability,
                )
                ledgers._validate_full_dag_with_operation_epochs_under_existing_mutex(
                    lease,
                    bundle.ledger,
                    resolved_operation_ledgers,
                )
                return ledgers
    except (CopyLedgerError, OperationLedgerError):
        raise


def _create_test_copy_operation(
    bundle: _TestDurableBoundaryBundle,
    operation_ledger: DurableOperationLedger,
    copy_ledgers: DurableCopyLedgers,
    context: OperationContext,
    manifest: DeclaredTreeManifest,
    budget: JobResourceBudget,
) -> _TestLocalCopyOperation:
    """Issue the only S3-F orchestrator from co-owned exact authorities."""

    if (
        type(bundle) is not _TestDurableBoundaryBundle
        or type(operation_ledger) is not DurableOperationLedger
        or type(copy_ledgers) is not DurableCopyLedgers
        or type(context) is not OperationContext
        or type(manifest) is not DeclaredTreeManifest
        or type(budget) is not JobResourceBudget
        or copy_ledgers._storage is not bundle.writer
    ):
        raise ProductionBoundaryError(
            BoundaryErrorCode.INVALID_ARGUMENT,
            "copy operation requires exact co-owned Test-local authorities",
        )
    copy_id = context.scope_value(ScopeKind.COPY_ID)
    copy_epoch_id = context.scope_value(ScopeKind.COPY_LEDGER_EPOCH_ID)
    if (
        copy_id is None
        or copy_epoch_id is None
        or copy_epoch_id != copy_ledgers.storage_epoch_id
        or not copy_ledgers.matches_run_scope(context.run_id)
    ):
        raise ProductionBoundaryError(
            BoundaryErrorCode.INVALID_CONTEXT,
            "copy operation context has no exact Copy and ledger scopes",
            operation_reference=_public_operation_reference(context),
        )
    runtime = _create_test_job_runtime(
        bundle,
        operation_ledger=operation_ledger,
    )
    _TestLocalCopyOperation._validate_source_independent_preconditions(
        runtime,
        copy_ledgers,
        context,
        manifest,
        budget,
    )
    source_policy = None
    operation = None
    try:
        source_policy = _create_synthetic_reference_read_policy(
            bundle.writer._workspace_root,
            copy_id=copy_id,
            classification=context.classification,
        )
        operation = _TestLocalCopyOperation(
            runtime,
            copy_ledgers,
            source_policy,
            context,
            manifest,
            budget,
            _constructor=_COPY_OPERATION_CONSTRUCTOR,
        )
        return operation
    finally:
        if source_policy is not None and operation is None:
            source_policy.close()


def _reconcile_test_publish_operation(
    bundle: _TestDurableBoundaryBundle,
    operation_ledger: DurableOperationLedger,
    transaction_id: str,
    budget: JobResourceBudget,
    *,
    restricted_locator_capability: _RestrictedRecoveryLocatorCapability | None = None,
) -> OperationSegmentReceipt:
    """Append a recovery fact only when source/target truth is unambiguous.

    Recovery never moves, overwrites or deletes anything.  It performs two
    complete handle scans for every existing side under the same application
    mutex and either appends RECOVERED_* or seals both authorities.
    """

    if (
        type(bundle) is not _TestDurableBoundaryBundle
        or type(operation_ledger) is not DurableOperationLedger
        or type(budget) is not JobResourceBudget
    ):
        raise ProductionBoundaryError(
            BoundaryErrorCode.INVALID_ARGUMENT,
            "publish reconciliation requires exact Test-local authorities",
        )
    try:
        validate_safe_id(transaction_id, field_name="transaction_id")
    except Exception:
        raise ProductionBoundaryError(
            BoundaryErrorCode.INVALID_ARGUMENT,
            "publish reconciliation transaction ID is invalid",
        ) from None

    source_locator_for_scan = ""
    target_locator_for_scan = ""

    def observe_once(locator: str) -> OperationTreeEvidence | None:
        absolute = bundle.writer._workspace_root.joinpath(*locator.split("/"))
        if not os.path.lexists(absolute):
            return None
        try:
            snapshot, root = bundle.writer._observe_existing_tree_snapshot(
                Path(*locator.split("/")),
                budget.tree_budget,
            )
        except HandleWriterError:
            operation_ledger._seal_recovery_contradiction()
        return OperationTreeEvidence(
            manifest_sha256=snapshot.manifest_sha256,
            source_tree_sha256=snapshot.source_tree_sha256,
            topology_sha256=snapshot.topology_sha256,
            durable_identity_sha256=(
                operation_ledger.durable_tree_evidence_identity_digest(
                    root.volume_serial,
                    root.file_id,
                    snapshot.tree_identity_material,
                )
            ),
            entry_count=snapshot.entry_count,
            total_bytes=snapshot.total_bytes,
        )

    def observe_pair() -> tuple[OperationTreeEvidence | None, OperationTreeEvidence | None]:
        first = (
            observe_once(source_locator_for_scan),
            observe_once(target_locator_for_scan),
        )
        second = (
            observe_once(source_locator_for_scan),
            observe_once(target_locator_for_scan),
        )
        if first != second:
            operation_ledger._seal_recovery_contradiction()
        return second

    with bundle.writer.acquire_runtime_mutex() as lease:
        result = operation_ledger.transaction_result_under_existing_mutex(
            lease,
            transaction_id,
        )
        if result is None:
            operation_ledger._seal_recovery_contradiction()
        previous, existing_receipt = result
        if previous.locator_mode is OperationLocatorMode.HMAC_ONLY:
            try:
                restricted_source_relative_path, restricted_target_relative_path = (
                    bundle.boundary._consume_restricted_recovery_locator(
                        restricted_locator_capability,
                        transaction_id,
                    )
                )
            except ProductionBoundaryError:
                operation_ledger._seal_recovery_contradiction()
            source_locator_for_scan = restricted_source_relative_path.as_posix()
            target_locator_for_scan = restricted_target_relative_path.as_posix()
            try:
                source_match = (
                    operation_ledger.locator_hmac(
                        source_locator_for_scan,
                        transaction_id=previous.transaction_id,
                        role=OperationLocatorRole.SOURCE,
                    )
                    == previous.source_locator
                )
                target_match = (
                    operation_ledger.locator_hmac(
                        target_locator_for_scan,
                        transaction_id=previous.transaction_id,
                        role=OperationLocatorRole.TARGET,
                    )
                    == previous.target_locator
                )
            except OperationLedgerError:
                operation_ledger._seal_recovery_contradiction()
            if not source_match or not target_match:
                operation_ledger._seal_recovery_contradiction()
        else:
            if restricted_locator_capability is not None:
                operation_ledger._seal_recovery_contradiction()
            source_locator_for_scan = previous.source_locator
            target_locator_for_scan = previous.target_locator
        current_audit_head = bundle.ledger._rescan_under_existing_mutex(lease)
        if (
            budget.digest != previous.budget_sha256
            or not bundle.ledger._contains_segment_sha256_under_existing_mutex(
                lease,
                previous.audit_ledger_head_sha256,
            )
        ):
            operation_ledger._seal_recovery_contradiction()
        if previous.next_state in {
            OperationState.ABORTED,
            OperationState.COMMITTED,
            OperationState.RECOVERED_ABORT,
            OperationState.RECOVERED_COMMIT,
        }:
            return existing_receipt
        source, target = observe_pair()
        source_exact = source == previous.source_evidence
        target_exact = target == previous.source_evidence
        source_absent = source is None
        target_absent = target is None
        next_state: OperationState
        mutation_attempted: bool
        target_evidence: OperationTreeEvidence | None
        reason: str
        if source_exact and target_absent and (
            previous.next_state is OperationState.PREPARED
            or (
                previous.next_state is OperationState.IN_DOUBT
                and previous.native_mutation_receipt_sha256 is None
            )
        ):
            next_state = OperationState.RECOVERED_ABORT
            mutation_attempted = previous.mutation_attempted
            target_evidence = None
            reason = "SOURCE_EXACT_TARGET_ABSENT"
        elif source_absent and target_exact and previous.next_state in {
            OperationState.PREPARED,
            OperationState.MUTATED,
            OperationState.POSTCONDITION_VERIFIED,
            OperationState.IN_DOUBT,
        }:
            next_state = OperationState.RECOVERED_COMMIT
            mutation_attempted = True
            target_evidence = target
            reason = "SOURCE_ABSENT_TARGET_EXACT"
        else:
            operation_ledger._seal_recovery_contradiction()
        transition_id = "TRN-" + hashlib.sha256(
            b"M0-RECOVERY-TRANSITION-ID-V1\0"
            + transaction_id.encode("ascii")
            + bytes(previous.next_state.value, "ascii")
            + next_state.value.encode("ascii")
        ).hexdigest().upper()[:32]
        native_mutation_receipt_sha256 = previous.native_mutation_receipt_sha256
        recovery_observation_receipt_sha256: str | None = None
        completion_kind = None
        if next_state is OperationState.RECOVERED_COMMIT and target_evidence is not None:
            recovery_observation_receipt_sha256 = (
                _build_recovery_observation_receipt_sha256(
                    previous,
                    target_evidence,
                    current_audit_head.last_segment_sha256 or "0" * 64,
                )
            )
            completion_kind = (
                OperationCompletionKind.RECOVERED_COMMIT_WITH_NATIVE_MUTATION
                if native_mutation_receipt_sha256 is not None
                else OperationCompletionKind.RECOVERED_COMMIT_OBSERVATION_ONLY
            )
        transition = OperationTransition(
            transition_id=transition_id,
            transaction_id=previous.transaction_id,
            operation_id=previous.operation_id,
            pair_id=previous.pair_id,
            previous_state=previous.next_state,
            next_state=next_state,
            context_binding_sha256=previous.context_binding_sha256,
            manifest_sha256=previous.manifest_sha256,
            budget_sha256=previous.budget_sha256,
            source_locator=previous.source_locator,
            target_locator=previous.target_locator,
            source_evidence=previous.source_evidence,
            target_evidence=target_evidence,
            audit_ledger_head_sha256=previous.audit_ledger_head_sha256,
            mutation_attempted=mutation_attempted,
            native_mutation_receipt_sha256=native_mutation_receipt_sha256,
            recovery_observation_receipt_sha256=(
                recovery_observation_receipt_sha256
            ),
            completion_kind=completion_kind,
            recovery_reason=reason,
            recovery_guarantee_scope=RECOVERY_GUARANTEE_SCOPE,
            recovery_authority_head_sha256=(
                current_audit_head.last_segment_sha256 or "0" * 64
            ),
            locator_mode=previous.locator_mode,
            classification=previous.classification,
        )
        recovery_receipt = operation_ledger._append_transition_under_existing_mutex(
            lease,
            transition,
        )
        if observe_pair() != (source, target):
            operation_ledger._seal_recovery_contradiction()
        return recovery_receipt


def _canonical_json_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _canonical_digest(payload: dict[str, Any], *, domain: str) -> str:
    return hashlib.sha256(
        domain.encode("ascii") + b"\0" + _canonical_json_bytes(payload)
    ).hexdigest()


def _same_or_ancestor(left: Path, right: Path) -> bool:
    left_parts = tuple(ntpath.normcase(part) for part in PureWindowsPath(str(left)).parts)
    right_parts = tuple(ntpath.normcase(part) for part in PureWindowsPath(str(right)).parts)
    return len(right_parts) >= len(left_parts) and right_parts[: len(left_parts)] == left_parts


def _max_classification(
    *values: DataClassification,
) -> DataClassification:
    return (
        DataClassification.RESTRICTED
        if DataClassification.RESTRICTED in values
        else DataClassification.INTERNAL
    )


def _boundary_effective_classification(
    context: OperationContext | None,
    decision: NamespaceDecision,
) -> DataClassification:
    if decision.namespace in {
        NamespaceId.COPY_SOURCE_LEDGER,
        NamespaceId.COPY_OPERATION_LEDGER,
    }:
        return DataClassification.RESTRICTED
    return _max_classification(
        (
            context.classification
            if context is not None
            else DataClassification.INTERNAL
        ),
        decision.effective_classification,
    )


def _public_operation_reference(context: OperationContext | None) -> str | None:
    if context is None or context.classification is DataClassification.RESTRICTED:
        return None
    return context.operation_id


def _exception_detail_code(error: Exception) -> str:
    code = getattr(error, "code", None)
    return code.value if isinstance(code, StrEnum) else type(error).__name__


def _same_path(left: Path, right: Path) -> bool:
    return ntpath.normcase(str(_absolute_lexical(left))) == ntpath.normcase(
        str(_absolute_lexical(right))
    )


def _absolute_lexical(path: str | os.PathLike[str]) -> Path:
    return Path(ntpath.normpath(ntpath.abspath(os.fspath(path))))
