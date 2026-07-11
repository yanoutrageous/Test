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
)


def _contract_root(_literal: str = r"D:\AAA命题\Test") -> Path:
    return Path(_literal)


CONTRACT_PROJECT_ROOT = _contract_root()
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_TOKEN_CONSTRUCTOR = object()
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
    _constructor: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if (
            self._constructor is not _AUDIT_AUTHORITY_CONSTRUCTOR
            or type(self.sink) is not DurableAuditSink
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


_PUBLISH_TOPOLOGY: frozenset[tuple[NamespaceId, NamespaceId]] = frozenset(
    {
        (NamespaceId.JOB_WORKSPACE_INTERNAL, NamespaceId.COPY_SOURCE),
        (NamespaceId.JOB_WORKSPACE_INTERNAL, NamespaceId.ORIGINAL_OBJECT),
        (NamespaceId.COPY_WORK_INTERNAL, NamespaceId.ORIGINAL_OBJECT),
        (NamespaceId.JOB_WORKSPACE_INTERNAL, NamespaceId.DATABASE_VERSION),
        (NamespaceId.JOB_WORKSPACE_INTERNAL, NamespaceId.DERIVED_REVISION),
        (NamespaceId.JOB_WORKSPACE_INTERNAL, NamespaceId.INDEX_VERSION),
        (NamespaceId.JOB_WORKSPACE_INTERNAL, NamespaceId.TEMPLATE_REVISION),
        (NamespaceId.JOB_WORKSPACE_INTERNAL, NamespaceId.EXPORT_BUNDLE),
        (NamespaceId.JOB_WORKSPACE_INTERNAL, NamespaceId.SNAPSHOT),
        (NamespaceId.JOB_WORKSPACE_INTERNAL, NamespaceId.BACKUP_SET),
        (NamespaceId.JOB_WORKSPACE_RESTRICTED, NamespaceId.COPY_RESTRICTED),
    }
)
_QUARANTINE_SOURCE_NAMESPACES = frozenset(
    {
        NamespaceId.JOB_WORKSPACE_INTERNAL,
        NamespaceId.JOB_WORKSPACE_RESTRICTED,
        NamespaceId.COPY_WORK_INTERNAL,
        NamespaceId.COPY_WORK_RESTRICTED,
        NamespaceId.COPY_RESTRICTED,
    }
)
_QUARANTINE_TARGET_NAMESPACES = frozenset(
    {NamespaceId.QUARANTINE_INTERNAL, NamespaceId.QUARANTINE_RESTRICTED}
)


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
        self.__candidate_tombstones: dict[str, None] = {}
        self.__pair_tombstones: dict[str, None] = {}
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
                "candidate_tombstones": len(self.__candidate_tombstones),
                "pair_tombstones": len(self.__pair_tombstones),
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
            record, token = self._build_single_candidate(core, decision, context)
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
                        _public_operation_reference(context),
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
            ) or any(pair.lifecycle is CapabilityLifecycle.RESERVED for pair in related_pairs):
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
            del self.__context_records[ticket_id]
        if cores:
            self._release_core_tickets(*cores)
        return True

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
            self._verify_candidate_decision(record, current_core, decision)
            effective = _max_classification(
                context.classification,
                decision.effective_classification,
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
                target_relative = Path(
                    "data",
                    "quarantine",
                    target_classification.value,
                    datetime.now(UTC).date().isoformat(),
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
            pair_record, source_record, target_record = self._reserve_pair(
                token,
                context,
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
            self._validate_classification_flow(
                context,
                source_decision,
                target_decision,
            )
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
            )
            self._finish_pair(pair_record, CapabilityLifecycle.CONSUMED)
            return token
        except Exception as exc:
            if pair_record is not None:
                self._finish_pair(pair_record, CapabilityLifecycle.FAILED)
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
                self._remember_tombstone(self.__candidate_tombstones, ticket_id)
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
    ) -> tuple[_PairRecord, _CandidateRecord, _CandidateRecord]:
        with self.__lock:
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
            self.__pair_records[pair.pair_id] = replace(
                pair,
                lifecycle=CapabilityLifecycle.RESERVED,
            )
            self.__candidate_records[source.ticket_id] = replace(
                source,
                lifecycle=CapabilityLifecycle.RESERVED,
            )
            self.__candidate_records[target.ticket_id] = replace(
                target,
                lifecycle=CapabilityLifecycle.RESERVED,
            )
            return pair, source, target

    def _finish_pair(
        self,
        pair: _PairRecord,
        lifecycle: CapabilityLifecycle,
    ) -> None:
        cores: list[GuardedPath] = []
        with self.__lock:
            current_pair = self.__pair_records.get(pair.pair_id)
            if (
                current_pair is not None
                and current_pair.lifecycle is CapabilityLifecycle.RESERVED
            ):
                del self.__pair_records[pair.pair_id]
                self._remember_tombstone(self.__pair_tombstones, pair.pair_id)
            for ticket_id in (pair.source_ticket_id, pair.target_ticket_id):
                member = self.__candidate_records.get(ticket_id)
                if (
                    member is not None
                    and member.lifecycle is CapabilityLifecycle.RESERVED
                ):
                    cores.append(member.core)
                    del self.__candidate_records[ticket_id]
                    self._remember_tombstone(
                        self.__candidate_tombstones,
                        ticket_id,
                    )
        if cores:
            self._release_core_tickets(*cores)

    @staticmethod
    def _remember_tombstone(registry: dict[str, None], identifier: str) -> None:
        registry[identifier] = None
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

    @staticmethod
    def _validate_pair_topology(
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
        if kind is PairKind.PUBLISH:
            if (source_decision.namespace, target_decision.namespace) not in _PUBLISH_TOPOLOGY:
                raise ProductionBoundaryError(
                    BoundaryErrorCode.PAIR_TOPOLOGY_DENIED,
                    "source-to-target namespace transition is not allowed",
                )
        elif (
            source_decision.namespace not in _QUARANTINE_SOURCE_NAMESPACES
            or target_decision.namespace not in _QUARANTINE_TARGET_NAMESPACES
        ):
            raise ProductionBoundaryError(
                BoundaryErrorCode.PAIR_TOPOLOGY_DENIED,
                "quarantine topology is not allowed",
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
            effective_classification=_max_classification(
                context.classification,
                decision.effective_classification,
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
            effective = _max_classification(
                context.classification if context else DataClassification.INTERNAL,
                decision.effective_classification,
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
            _max_classification(
                context.classification if context else DataClassification.INTERNAL,
                decision.effective_classification,
            )
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
    ) -> None:
        try:
            if self.__durable_audit_sink is not None:
                receipt = self.__durable_audit_sink.record_factory(builder)
                if type(receipt) is not AuditReceipt:
                    raise ValueError("durable audit sink returned an invalid receipt type")
            else:
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
    ) -> None:
        root = _contract_root()
        self.__core = _BoundaryCore(
            guard=WorkspaceGuard(root, workspace_root),
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
        _constructor=_AUDIT_AUTHORITY_CONSTRUCTOR,
    )
    boundary = _TestWorkspaceBoundary(
        _absolute_lexical(workspace_root),
        audit_authority=authority,
    )
    return _TestDurableBoundaryBundle(
        boundary=boundary,
        ledger=ledger,
        key_store=key_store,
    )


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
