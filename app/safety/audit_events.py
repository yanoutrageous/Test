from __future__ import annotations

import hashlib
import hmac
import json
import ntpath
import secrets
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path, PureWindowsPath
from typing import Protocol

from app.workspace_guard import ExpectedKind, PathIntent

from .context import DataClassification, OperationContext
from .namespace_policy import (
    POLICY_ID,
    POLICY_VERSION,
    AuditPathMode,
    NamespaceId,
)


class AuditDecision(StrEnum):
    CANDIDATE_ALLOW = "CANDIDATE_ALLOW"
    DENY = "DENY"


class AuditAction(StrEnum):
    ISSUE = "ISSUE"
    REVALIDATE = "REVALIDATE"
    DENY = "DENY"


class CapabilityKind(StrEnum):
    SINGLE = "SINGLE"
    PUBLISH_PAIR = "PUBLISH_PAIR"
    QUARANTINE_PAIR = "QUARANTINE_PAIR"


class PairRole(StrEnum):
    SOURCE = "SOURCE"
    TARGET = "TARGET"


class RedactionMode(StrEnum):
    SAFE_RELATIVE = "SAFE_RELATIVE"
    HMAC_ONLY = "HMAC_ONLY"


@dataclass(frozen=True, slots=True)
class AuditEvent:
    event_version: str
    event_id: str
    occurred_at_utc: str
    decision: AuditDecision
    action: AuditAction
    capability_kind: CapabilityKind
    capability_state: str
    error_code: str | None
    classification: DataClassification
    redaction_mode: RedactionMode
    context_digest: str | None
    context_hmac_sha256: str | None
    run_id: str | None
    job_id: str | None
    operation_id: str | None
    caller: str | None
    purpose: str | None
    policy_id: str
    policy_version: str
    policy_digest: str
    boundary_instance_id: str
    ticket_id: str | None
    pair_id: str | None
    pair_role: PairRole | None
    namespace: NamespaceId
    intent: PathIntent
    expected_kind: ExpectedKind
    safe_relative_path: str | None
    path_hmac_sha256: str | None
    path_depth: int | None
    hmac_key_id: str
    manifest_id: str | None
    manifest_sha256: str | None
    source_tree_sha256: str | None
    checkpoint_id: str | None
    topology_digest: str | None
    evidence_digest: str | None

    def to_dict(self) -> dict[str, str | int | None]:
        return {
            "event_version": self.event_version,
            "event_id": self.event_id,
            "occurred_at_utc": self.occurred_at_utc,
            "decision": self.decision.value,
            "action": self.action.value,
            "capability_kind": self.capability_kind.value,
            "capability_state": self.capability_state,
            "error_code": self.error_code,
            "classification": self.classification.value,
            "redaction_mode": self.redaction_mode.value,
            "context_digest": self.context_digest,
            "context_hmac_sha256": self.context_hmac_sha256,
            "run_id": self.run_id,
            "job_id": self.job_id,
            "operation_id": self.operation_id,
            "caller": self.caller,
            "purpose": self.purpose,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "policy_digest": self.policy_digest,
            "boundary_instance_id": self.boundary_instance_id,
            "ticket_id": self.ticket_id,
            "pair_id": self.pair_id,
            "pair_role": self.pair_role.value if self.pair_role else None,
            "namespace": self.namespace.value,
            "intent": self.intent.value,
            "expected_kind": self.expected_kind.value,
            "safe_relative_path": self.safe_relative_path,
            "path_hmac_sha256": self.path_hmac_sha256,
            "path_depth": self.path_depth,
            "hmac_key_id": self.hmac_key_id,
            "manifest_id": self.manifest_id,
            "manifest_sha256": self.manifest_sha256,
            "source_tree_sha256": self.source_tree_sha256,
            "checkpoint_id": self.checkpoint_id,
            "topology_digest": self.topology_digest,
            "evidence_digest": self.evidence_digest,
        }


@dataclass(frozen=True, slots=True)
class AuditReceipt:
    event_ids: tuple[str, ...]
    batch_sha256: str


class AuditSinkCapacityError(RuntimeError):
    pass


class AuditSink(Protocol):
    def record(self, event: AuditEvent) -> AuditReceipt: ...

    def record_batch(self, events: tuple[AuditEvent, ...]) -> AuditReceipt: ...


class CollectingAuditSink:
    """Fail-closed in-memory S2 sink; never a production audit ledger."""

    def __init__(self, *, capacity: int = 32768) -> None:
        if capacity <= 0:
            raise ValueError("audit sink capacity must be positive")
        self._capacity = capacity
        self._events: list[AuditEvent] = []
        self._lock = threading.RLock()

    @property
    def events(self) -> tuple[AuditEvent, ...]:
        with self._lock:
            return tuple(self._events)

    def record(self, event: AuditEvent) -> AuditReceipt:
        return self.record_batch((event,))

    def record_batch(self, events: tuple[AuditEvent, ...]) -> AuditReceipt:
        if not events:
            raise ValueError("audit batches cannot be empty")
        receipt = audit_receipt(events)
        with self._lock:
            if len(self._events) + len(events) > self._capacity:
                raise AuditSinkCapacityError("audit sink capacity would be exceeded")
            self._events.extend(events)
        return receipt


def audit_hmac_key_id(key: bytes) -> str:
    return hashlib.sha256(b"AUDIT-KEY-ID-V1\0" + key).hexdigest()[:16].upper()


def audit_receipt(events: tuple[AuditEvent, ...]) -> AuditReceipt:
    canonical = json.dumps(
        [event.to_dict() for event in events],
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return AuditReceipt(
        event_ids=tuple(event.event_id for event in events),
        batch_sha256=hashlib.sha256(b"AUDIT-BATCH-V1\0" + canonical).hexdigest(),
    )


def create_audit_event(
    *,
    decision: AuditDecision,
    action: AuditAction,
    capability_kind: CapabilityKind,
    error_code: str | None,
    context: OperationContext | None,
    effective_classification: DataClassification,
    path_mode: AuditPathMode,
    policy_digest: str,
    boundary_instance_id: str,
    ticket_id: str | None,
    pair_id: str | None,
    pair_role: PairRole | None,
    namespace: NamespaceId,
    intent: PathIntent,
    expected_kind: ExpectedKind,
    relative_path: Path | None,
    audit_hmac_key: bytes,
    manifest_sha256: str | None = None,
    source_tree_sha256: str | None = None,
    checkpoint_id: str | None = None,
    topology_digest: str | None = None,
    evidence_digest: str | None = None,
) -> AuditEvent:
    restricted = effective_classification is DataClassification.RESTRICTED
    use_hmac_path = restricted or path_mode is AuditPathMode.HMAC_ONLY or decision is AuditDecision.DENY
    canonical_path = _canonical_relative_path(relative_path)
    if canonical_path is None:
        visible_path = None
        path_hmac = None
        path_depth = None
    elif use_hmac_path:
        visible_path = None
        path_hmac = _hmac_hex(audit_hmac_key, b"AUDIT-PATH-V1\0", canonical_path)
        path_depth = len(PureWindowsPath(canonical_path).parts)
    else:
        visible_path = canonical_path.replace("\\", "/")
        path_hmac = None
        path_depth = len(PureWindowsPath(canonical_path).parts)

    if context is None:
        context_digest = None
        context_hmac = _hmac_hex(
            audit_hmac_key,
            b"AUDIT-CONTEXT-V1\0",
            "INVALID-CONTEXT",
        )
        run_id = job_id = operation_id = caller = purpose = manifest_id = None
    elif restricted:
        context_digest = None
        context_hmac = _hmac_hex(
            audit_hmac_key,
            b"AUDIT-CONTEXT-V1\0",
            context.digest,
        )
        run_id = job_id = operation_id = caller = purpose = manifest_id = None
    else:
        context_digest = context.digest
        context_hmac = None
        run_id = context.run_id
        job_id = context.job_id
        operation_id = context.operation_id
        caller = context.caller.value
        purpose = context.purpose.value
        manifest_id = context.manifest_id

    if restricted:
        visible_boundary_id = _hmac_optional(
            audit_hmac_key,
            b"AUDIT-BOUNDARY-ID-V1\0",
            boundary_instance_id,
        )
        visible_ticket_id = _hmac_optional(
            audit_hmac_key,
            b"AUDIT-TICKET-ID-V1\0",
            ticket_id,
        )
        visible_pair_id = _hmac_optional(
            audit_hmac_key,
            b"AUDIT-PAIR-ID-V1\0",
            pair_id,
        )
        visible_manifest_sha256 = _hmac_optional(
            audit_hmac_key,
            b"AUDIT-MANIFEST-HASH-V1\0",
            manifest_sha256,
        )
        visible_tree_sha256 = _hmac_optional(
            audit_hmac_key,
            b"AUDIT-TREE-HASH-V1\0",
            source_tree_sha256,
        )
        visible_topology_digest = _hmac_optional(
            audit_hmac_key,
            b"AUDIT-TOPOLOGY-DIGEST-V1\0",
            topology_digest,
        )
        visible_evidence_digest = _hmac_optional(
            audit_hmac_key,
            b"AUDIT-EVIDENCE-DIGEST-V1\0",
            evidence_digest,
        )
    else:
        visible_boundary_id = boundary_instance_id
        visible_ticket_id = ticket_id
        visible_pair_id = pair_id
        visible_manifest_sha256 = manifest_sha256
        visible_tree_sha256 = source_tree_sha256
        visible_topology_digest = topology_digest
        visible_evidence_digest = evidence_digest

    return AuditEvent(
        event_version="2.1",
        event_id=secrets.token_hex(16).upper(),
        occurred_at_utc=datetime.now(UTC).isoformat(timespec="seconds").replace(
            "+00:00", "Z"
        ),
        decision=decision,
        action=action,
        capability_kind=capability_kind,
        capability_state="CANDIDATE_ONLY",
        error_code=error_code,
        classification=effective_classification,
        redaction_mode=(
            RedactionMode.HMAC_ONLY if use_hmac_path else RedactionMode.SAFE_RELATIVE
        ),
        context_digest=context_digest,
        context_hmac_sha256=context_hmac,
        run_id=run_id,
        job_id=job_id,
        operation_id=operation_id,
        caller=caller,
        purpose=purpose,
        policy_id=POLICY_ID,
        policy_version=POLICY_VERSION,
        policy_digest=policy_digest,
        boundary_instance_id=visible_boundary_id or "REDACTED",
        ticket_id=visible_ticket_id,
        pair_id=visible_pair_id,
        pair_role=pair_role,
        namespace=namespace,
        intent=intent,
        expected_kind=expected_kind,
        safe_relative_path=visible_path,
        path_hmac_sha256=path_hmac,
        path_depth=None if restricted else path_depth,
        hmac_key_id=audit_hmac_key_id(audit_hmac_key),
        manifest_id=manifest_id,
        manifest_sha256=visible_manifest_sha256,
        source_tree_sha256=visible_tree_sha256,
        checkpoint_id=None if restricted else checkpoint_id,
        topology_digest=visible_topology_digest,
        evidence_digest=visible_evidence_digest,
    )


def _canonical_relative_path(relative_path: Path | None) -> str | None:
    if relative_path is None:
        return None
    return ntpath.normcase(ntpath.normpath(str(PureWindowsPath(str(relative_path)))))


def _hmac_hex(key: bytes, domain: bytes, value: str) -> str:
    return hmac.new(key, domain + value.encode("utf-8"), hashlib.sha256).hexdigest()


def _hmac_optional(key: bytes, domain: bytes, value: str | None) -> str | None:
    return None if value is None else _hmac_hex(key, domain, value)
