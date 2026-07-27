from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import threading
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path, PureWindowsPath
from typing import Any, NoReturn

from app.safety.context import DataClassification, validate_safe_id
from app.safety.external_source import (
    SYNTHETIC_REFERENCE_PAYLOAD_NAME,
    SYNTHETIC_REFERENCE_POLICY_DIGEST,
)
from app.safety.job_operation import (
    DeclaredTreeEntry,
    DeclaredTreeManifest,
    JobOperationError,
)
from app.safety.operation_ledger import (
    DurableOperationLedger,
    OperationLedgerError,
    OperationLocatorMode,
    OperationLocatorRole,
    OperationSegmentReceipt,
    OperationState,
    OperationTransition,
    OperationTreeEvidence,
)
from app.safety.segment_ledger import (
    AuditKeyRevision,
    DurableAuditLedger,
    LedgerError,
    canonical_json_bytes,
    parse_canonical_json_bytes,
)
from app.safety.windows_handle_writer import (
    HandleWriterError,
    RuntimeMutexLease,
    TreeEntryKind,
    _WindowsHandleWriter,
)


_COPY_LEDGERS_CONSTRUCTOR = object()
_AUTHENTICATED_COPY_ANCESTORS_CONSTRUCTOR = object()
_SOURCE_ROOT = Path("Copy") / "ledger" / "source" / "segments"
_COPY_ROOT = Path("Copy") / "ledger" / "copy" / "segments"
_SEGMENT_FILE = re.compile(
    r"^(?P<sequence>[0-9]{20})-(?P<sha>[0-9a-f]{64})\.json$"
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_OPAQUE_EPOCH_ID = re.compile(r"^[0-9A-F]{64}$")
_RESTRICTED_OPERATION_REFERENCE = re.compile(r"^OPREF-[0-9A-F]{32}$")
_OPAQUE_PUBLISH_TRANSACTION_REFERENCE = re.compile(r"^TXN-[0-9A-F]{32}$")
_RESTRICTED_PAIR_REFERENCE = re.compile(r"^[0-9A-F]{32}$")
_UTC_SECONDS = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
)
_MAX_SEGMENTS = 4096
_MAX_SEGMENT_BYTES = 512 * 1024
_MAX_LEDGER_BYTES = 64 * 1024 * 1024
_MAX_SOURCE_SEGMENT_BYTES = 64 * 1024
_MAX_COPY_TRANSITION_SEGMENT_BYTES = 128 * 1024
_MAX_COPY_FILE_BYTES = 64 * 1024 * 1024
_COPY_LIFECYCLE_SEGMENTS = 5
_COPY_PROVENANCE_VALIDATION_MANIFEST_ID = "MANIFEST-COPY-PROVENANCE"
COPY_PROVENANCE_FILE_NAME = "provenance.json"
COPY_PROVENANCE_MAX_BYTES = 16 * 1024


class CopyLedgerCode(StrEnum):
    INVALID_REQUEST = "INVALID_REQUEST"
    MUTEX_INVALID = "MUTEX_INVALID"
    UNKNOWN_ENTRY = "UNKNOWN_ENTRY"
    CHAIN_CORRUPT = "CHAIN_CORRUPT"
    AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"
    CROSS_REFERENCE_INVALID = "CROSS_REFERENCE_INVALID"
    RECORD_CONFLICT = "RECORD_CONFLICT"
    TRANSITION_CONFLICT = "TRANSITION_CONFLICT"
    ILLEGAL_TRANSITION = "ILLEGAL_TRANSITION"
    RESOURCE_LIMIT = "RESOURCE_LIMIT"
    ROTATION_BLOCKED = "ROTATION_BLOCKED"
    STORAGE_FAILURE = "STORAGE_FAILURE"
    LEDGER_SEALED = "LEDGER_SEALED"


_COPY_LEDGER_PUBLIC_MESSAGES = {
    CopyLedgerCode.INVALID_REQUEST: "copy ledger request rejected",
    CopyLedgerCode.MUTEX_INVALID: "copy ledger mutex rejected",
    CopyLedgerCode.UNKNOWN_ENTRY: "copy ledger entry rejected",
    CopyLedgerCode.CHAIN_CORRUPT: "copy ledger chain rejected",
    CopyLedgerCode.AUTHENTICATION_FAILED: "copy ledger authentication rejected",
    CopyLedgerCode.CROSS_REFERENCE_INVALID: "copy ledger cross-reference rejected",
    CopyLedgerCode.RECORD_CONFLICT: "copy ledger record conflict",
    CopyLedgerCode.TRANSITION_CONFLICT: "copy ledger transition conflict",
    CopyLedgerCode.ILLEGAL_TRANSITION: "copy ledger transition rejected",
    CopyLedgerCode.RESOURCE_LIMIT: "copy ledger resource limit reached",
    CopyLedgerCode.ROTATION_BLOCKED: "copy ledger rotation is blocked",
    CopyLedgerCode.STORAGE_FAILURE: "copy ledger storage operation failed",
    CopyLedgerCode.LEDGER_SEALED: "copy ledger is sealed",
}


class CopyLedgerError(RuntimeError):
    def __init__(self, code: CopyLedgerCode, message: str) -> None:
        self.code = code
        super().__init__(f"{code.value}: {_COPY_LEDGER_PUBLIC_MESSAGES[code]}")

    def __repr__(self) -> str:
        return f"CopyLedgerError(code='{self.code.value}', details='<redacted>')"

    def __reduce__(self) -> Any:
        raise TypeError("copy ledger errors cannot be serialized")


def _raise_without_context(error: CopyLedgerError) -> NoReturn:
    error.__traceback__ = None
    error.__context__ = None
    error.__cause__ = None
    error.__suppress_context__ = True
    raise error from None


class CopyLedgerKind(StrEnum):
    COPY_SOURCE = "COPY_SOURCE"
    COPY_OPERATION = "COPY_OPERATION"


class CopyLocatorMode(StrEnum):
    SAFE_RELATIVE = "SAFE_RELATIVE"
    HMAC_ONLY = "HMAC_ONLY"


class CopyState(StrEnum):
    PREPARED = "PREPARED"
    ABORTED = "ABORTED"
    MUTATED = "MUTATED"
    POSTCONDITION_VERIFIED = "POSTCONDITION_VERIFIED"
    COMMITTED = "COMMITTED"
    IN_DOUBT = "IN_DOUBT"
    RECOVERED_COMMIT = "RECOVERED_COMMIT"
    RECOVERED_ABORT = "RECOVERED_ABORT"


class CopyPublishPlanKind(StrEnum):
    UNSTARTED = "UNSTARTED"
    RESERVED = "RESERVED"


_TERMINAL_STATES = frozenset(
    {
        CopyState.ABORTED,
        CopyState.COMMITTED,
        CopyState.RECOVERED_ABORT,
        CopyState.RECOVERED_COMMIT,
    }
)
_ALLOWED_TRANSITIONS: frozenset[tuple[CopyState | None, CopyState]] = frozenset(
    {
        (None, CopyState.PREPARED),
        (None, CopyState.RECOVERED_ABORT),
        (CopyState.PREPARED, CopyState.ABORTED),
        (CopyState.PREPARED, CopyState.MUTATED),
        (CopyState.PREPARED, CopyState.IN_DOUBT),
        (CopyState.MUTATED, CopyState.POSTCONDITION_VERIFIED),
        (CopyState.MUTATED, CopyState.IN_DOUBT),
        (CopyState.POSTCONDITION_VERIFIED, CopyState.COMMITTED),
        (CopyState.POSTCONDITION_VERIFIED, CopyState.IN_DOUBT),
        (CopyState.PREPARED, CopyState.RECOVERED_COMMIT),
        (CopyState.PREPARED, CopyState.RECOVERED_ABORT),
        (CopyState.MUTATED, CopyState.RECOVERED_COMMIT),
        (CopyState.POSTCONDITION_VERIFIED, CopyState.RECOVERED_COMMIT),
        (CopyState.IN_DOUBT, CopyState.RECOVERED_COMMIT),
        (CopyState.IN_DOUBT, CopyState.RECOVERED_ABORT),
    }
)


def _now_utc_seconds() -> str:
    return datetime.now(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _derive_copy_ledger_epoch_id(
    revision: AuditKeyRevision,
    run_scope_id: str,
) -> str:
    """Derive the path epoch without serializing the raw RUN_ID.

    This helper remains private because callers without the exact activated audit
    revision must not be able to mint a storage locator.  The bounded retry only
    handles pathological short scope identifiers whose literal text happens to
    occur in the hexadecimal HMAC representation.
    """

    if type(revision) is not AuditKeyRevision:
        raise CopyLedgerError(
            CopyLedgerCode.INVALID_REQUEST,
            "copy epoch derivation requires an exact signing revision",
        )
    canonical_scope = _safe_id(run_scope_id, "run_scope_id")
    encoded_scope = canonical_scope.encode("ascii")
    for counter in range(4096):
        candidate = hmac.new(
            revision.segment_hmac_key,
            b"COPY-LEDGER-OPAQUE-EPOCH-V1\0"
            + counter.to_bytes(4, "big")
            + b"\0"
            + encoded_scope,
            hashlib.sha256,
        ).hexdigest().upper()
        if canonical_scope.upper() not in candidate:
            return candidate
    raise CopyLedgerError(
        CopyLedgerCode.INVALID_REQUEST,
        "copy run scope cannot be represented by an opaque storage epoch",
    )


def _copy_epoch_pair_presence(
    storage: _WindowsHandleWriter,
    epoch_id: str,
) -> tuple[bool, bool]:
    """Observe whether either exact epoch store has a directory entry.

    This is only an existence probe.  A present entry is subsequently opened
    and authenticated by the handle writer; ``lstat`` is used so a broken
    symlink/reparse entry is not mistaken for an absent epoch and skipped.
    """

    if type(storage) is not _WindowsHandleWriter:
        raise CopyLedgerError(
            CopyLedgerCode.INVALID_REQUEST,
            "copy epoch presence requires exact Test-local storage",
        )
    canonical_epoch = _safe_id(epoch_id, "epoch_id")
    if _OPAQUE_EPOCH_ID.fullmatch(canonical_epoch) is None:
        raise CopyLedgerError(
            CopyLedgerCode.INVALID_REQUEST,
            "copy epoch presence requires an opaque epoch identifier",
        )

    def present(relative: Path) -> bool:
        try:
            os.lstat(storage._workspace_root / relative)
            return True
        except FileNotFoundError:
            return False
        except OSError:
            raise CopyLedgerError(
                CopyLedgerCode.STORAGE_FAILURE,
                "copy epoch presence cannot be observed safely",
            ) from None

    return (
        present(_SOURCE_ROOT / canonical_epoch),
        present(_COPY_ROOT / canonical_epoch),
    )


def _validate_utc_seconds(value: str) -> str:
    if type(value) is not str or not _UTC_SECONDS.fullmatch(value):
        raise CopyLedgerError(
            CopyLedgerCode.INVALID_REQUEST,
            "segment time must use canonical UTC seconds",
        )
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError:
        raise CopyLedgerError(
            CopyLedgerCode.INVALID_REQUEST,
            "segment time is not a real UTC instant",
        ) from None
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise CopyLedgerError(
            CopyLedgerCode.INVALID_REQUEST,
            "segment time is not canonical",
        )
    return value


def _require_sha256(value: Any, field_name: str, *, nonzero: bool = False) -> str:
    if (
        type(value) is not str
        or not _SHA256.fullmatch(value)
        or (nonzero and value == "0" * 64)
    ):
        raise CopyLedgerError(
            CopyLedgerCode.INVALID_REQUEST,
            f"{field_name} must be a canonical lowercase SHA-256 digest",
        )
    return value


def _safe_id(value: Any, field_name: str) -> str:
    try:
        return validate_safe_id(value, field_name=field_name)
    except Exception:
        raise CopyLedgerError(
            CopyLedgerCode.INVALID_REQUEST,
            f"{field_name} is not a canonical opaque identifier",
        ) from None


def _opaque_publish_transaction_id(value: Any) -> str:
    canonical = _safe_id(value, "publish_transaction_id")
    if _OPAQUE_PUBLISH_TRANSACTION_REFERENCE.fullmatch(canonical) is None:
        raise CopyLedgerError(
            CopyLedgerCode.INVALID_REQUEST,
            "publish transaction must be one factory-issued opaque reference",
        )
    return canonical


def _safe_relative(value: Any, field_name: str) -> str:
    if type(value) is not str or not value or len(value.encode("utf-8")) > 2048:
        raise CopyLedgerError(
            CopyLedgerCode.INVALID_REQUEST,
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
        raise CopyLedgerError(
            CopyLedgerCode.INVALID_REQUEST,
            f"{field_name} is not a safe project-relative locator",
        )
    canonical = "/".join(pure.parts)
    if canonical != value:
        raise CopyLedgerError(
            CopyLedgerCode.INVALID_REQUEST,
            f"{field_name} must use canonical forward-slash form",
        )
    return canonical


@dataclass(frozen=True, slots=True)
class CopyLocator:
    mode: CopyLocatorMode
    value: str

    def __post_init__(self) -> None:
        if type(self.mode) is not CopyLocatorMode:
            raise CopyLedgerError(
                CopyLedgerCode.INVALID_REQUEST,
                "locator mode must be exact",
            )
        if self.mode is CopyLocatorMode.SAFE_RELATIVE:
            _safe_relative(self.value, "locator")
        else:
            _require_sha256(self.value, "locator_hmac_sha256", nonzero=True)

    def to_json(self) -> dict[str, Any]:
        return {
            "hmac_sha256": self.value if self.mode is CopyLocatorMode.HMAC_ONLY else None,
            "mode": self.mode.value,
            "safe_relative_path": (
                self.value if self.mode is CopyLocatorMode.SAFE_RELATIVE else None
            ),
        }

    def __repr__(self) -> str:
        return f"CopyLocator(mode='{self.mode.value}', value='<redacted>')"

    def __reduce__(self) -> Any:
        raise TypeError("copy locators cannot be serialized")


@dataclass(frozen=True, slots=True)
class CopyFileEvidence:
    identity_hmac_sha256: str
    size_bytes: int
    sha256: str
    change_evidence_sha256: str

    def __post_init__(self) -> None:
        _require_sha256(self.identity_hmac_sha256, "identity_hmac_sha256", nonzero=True)
        _require_sha256(self.sha256, "sha256")
        _require_sha256(
            self.change_evidence_sha256,
            "change_evidence_sha256",
            nonzero=True,
        )
        if (
            type(self.size_bytes) is not int
            or self.size_bytes < 0
            or self.size_bytes > _MAX_COPY_FILE_BYTES
        ):
            raise CopyLedgerError(
                CopyLedgerCode.INVALID_REQUEST,
                "copy file evidence exceeds the single-file size boundary",
            )

    @property
    def digest(self) -> str:
        return hashlib.sha256(
            b"COPY-FILE-EVIDENCE-V1\0" + canonical_json_bytes(self.to_json())
        ).hexdigest()

    def to_json(self) -> dict[str, Any]:
        return {
            "change_evidence_sha256": self.change_evidence_sha256,
            "identity_hmac_sha256": self.identity_hmac_sha256,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
        }

    def __repr__(self) -> str:
        return f"CopyFileEvidence(size_bytes={self.size_bytes}, evidence='<redacted>')"

    def __reduce__(self) -> Any:
        raise TypeError("copy file evidence cannot be serialized")


@dataclass(frozen=True, slots=True)
class CopyProvenanceMaterial:
    """Exact immutable provenance object and its derived two-file manifest."""

    provenance_bytes: bytes
    provenance_sha256: str
    payload_manifest_sha256: str
    publish_manifest: DeclaredTreeManifest

    def __post_init__(self) -> None:
        if (
            type(self.provenance_bytes) is not bytes
            or not self.provenance_bytes
            or len(self.provenance_bytes) > COPY_PROVENANCE_MAX_BYTES
            or hashlib.sha256(self.provenance_bytes).hexdigest()
            != self.provenance_sha256
            or type(self.publish_manifest) is not DeclaredTreeManifest
        ):
            raise CopyLedgerError(
                CopyLedgerCode.INVALID_REQUEST,
                "copy provenance material is not exact",
            )
        _require_sha256(
            self.payload_manifest_sha256,
            "payload_manifest_sha256",
            nonzero=True,
        )
        if (
            len(self.publish_manifest.entries) != 2
            or tuple(entry.relative_path for entry in self.publish_manifest.entries)
            != (SYNTHETIC_REFERENCE_PAYLOAD_NAME, COPY_PROVENANCE_FILE_NAME)
        ):
            raise CopyLedgerError(
                CopyLedgerCode.INVALID_REQUEST,
                "copy provenance publish manifest is not the exact two-file contract",
            )
        payload_entry, provenance_entry = self.publish_manifest.entries
        try:
            payload_manifest = DeclaredTreeManifest(
                manifest_id=self.publish_manifest.manifest_id,
                classification=self.publish_manifest.classification,
                entries=(payload_entry,),
            )
        except JobOperationError:
            raise CopyLedgerError(
                CopyLedgerCode.INVALID_REQUEST,
                "copy provenance payload manifest is invalid",
            ) from None
        if (
            payload_manifest.manifest_sha256 != self.payload_manifest_sha256
            or payload_entry.kind is not TreeEntryKind.FILE
            or provenance_entry.kind is not TreeEntryKind.FILE
            or provenance_entry.size_bytes != len(self.provenance_bytes)
            or provenance_entry.sha256 != self.provenance_sha256
        ):
            raise CopyLedgerError(
                CopyLedgerCode.INVALID_REQUEST,
                "copy provenance material and manifest entries differ",
            )

    def __repr__(self) -> str:
        return "CopyProvenanceMaterial(material='<redacted>')"

    def __reduce__(self) -> Any:
        raise TypeError("copy provenance material cannot be serialized")


@dataclass(frozen=True, slots=True)
class CopyTargetEvidence:
    root_identity_hmac_sha256: str
    tree_identity_hmac_sha256: str
    payload: CopyFileEvidence
    provenance: CopyFileEvidence
    manifest_sha256: str
    tree_sha256: str
    topology_sha256: str
    entry_count: int
    total_bytes: int

    def __post_init__(self) -> None:
        _require_sha256(
            self.root_identity_hmac_sha256,
            "root_identity_hmac_sha256",
            nonzero=True,
        )
        _require_sha256(
            self.tree_identity_hmac_sha256,
            "tree_identity_hmac_sha256",
            nonzero=True,
        )
        if (
            type(self.payload) is not CopyFileEvidence
            or type(self.provenance) is not CopyFileEvidence
        ):
            raise CopyLedgerError(
                CopyLedgerCode.INVALID_REQUEST,
                "target evidence requires exact payload and provenance evidence",
            )
        for name in ("manifest_sha256", "tree_sha256", "topology_sha256"):
            _require_sha256(getattr(self, name), name)
        if type(self.entry_count) is not int or self.entry_count != 2:
            raise CopyLedgerError(
                CopyLedgerCode.INVALID_REQUEST,
                "target evidence requires the exact payload and provenance entries",
            )
        if (
            type(self.total_bytes) is not int
            or self.total_bytes
            != self.payload.size_bytes + self.provenance.size_bytes
        ):
            raise CopyLedgerError(
                CopyLedgerCode.INVALID_REQUEST,
                "target evidence total bytes must equal payload plus provenance",
            )

    @property
    def digest(self) -> str:
        return hashlib.sha256(
            b"COPY-TARGET-EVIDENCE-V2\0" + canonical_json_bytes(self.to_json())
        ).hexdigest()

    def to_json(self) -> dict[str, Any]:
        return {
            "entry_count": self.entry_count,
            "manifest_sha256": self.manifest_sha256,
            "payload": self.payload.to_json(),
            "provenance": self.provenance.to_json(),
            "root_identity_hmac_sha256": self.root_identity_hmac_sha256,
            "tree_identity_hmac_sha256": self.tree_identity_hmac_sha256,
            "topology_sha256": self.topology_sha256,
            "total_bytes": self.total_bytes,
            "tree_sha256": self.tree_sha256,
        }

    def __repr__(self) -> str:
        return "CopyTargetEvidence(evidence='<redacted>')"

    def __reduce__(self) -> Any:
        raise TypeError("copy target evidence cannot be serialized")


@dataclass(frozen=True, slots=True)
class CopySourceRecord:
    record_id: str
    transaction_binding_sha256: str
    copy_binding_sha256: str
    reference_policy_digest: str
    audit_ancestor_sha256: str
    classification: DataClassification
    source_locator: CopyLocator
    source_evidence: CopyFileEvidence

    def __post_init__(self) -> None:
        _require_sha256(self.record_id, "record_id", nonzero=True)
        for name in (
            "transaction_binding_sha256",
            "copy_binding_sha256",
            "reference_policy_digest",
            "audit_ancestor_sha256",
        ):
            _require_sha256(getattr(self, name), name, nonzero=True)
        if self.reference_policy_digest != SYNTHETIC_REFERENCE_POLICY_DIGEST:
            raise CopyLedgerError(
                CopyLedgerCode.INVALID_REQUEST,
                "source reference policy differs from the frozen contract",
            )
        if type(self.classification) is not DataClassification:
            raise CopyLedgerError(
                CopyLedgerCode.INVALID_REQUEST,
                "source classification must be exact",
            )
        if (
            type(self.source_locator) is not CopyLocator
            or self.source_locator.mode is not CopyLocatorMode.HMAC_ONLY
            or type(self.source_evidence) is not CopyFileEvidence
        ):
            raise CopyLedgerError(
                CopyLedgerCode.INVALID_REQUEST,
                "external source records require HMAC-only locator and exact evidence",
            )

    @property
    def digest(self) -> str:
        return hashlib.sha256(
            b"COPY-SOURCE-RECORD-V1\0" + canonical_json_bytes(self.to_json())
        ).hexdigest()

    def to_json(self) -> dict[str, Any]:
        return {
            "audit_ancestor_sha256": self.audit_ancestor_sha256,
            "classification": self.classification.value,
            "copy_binding_sha256": self.copy_binding_sha256,
            "record_id": self.record_id,
            "reference_policy_digest": self.reference_policy_digest,
            "source_evidence": self.source_evidence.to_json(),
            "source_locator": self.source_locator.to_json(),
            "transaction_binding_sha256": self.transaction_binding_sha256,
        }

    def __repr__(self) -> str:
        return (
            "CopySourceRecord(classification='"
            f"{self.classification.value}', record='<redacted>')"
        )

    def __reduce__(self) -> Any:
        raise TypeError("copy source records cannot be serialized")


@dataclass(frozen=True, slots=True)
class CopySourceAnchor:
    epoch_id: str
    sequence: int
    segment_sha256: str
    record_id: str
    record_sha256: str

    def __post_init__(self) -> None:
        _safe_id(self.epoch_id, "epoch_id")
        if _OPAQUE_EPOCH_ID.fullmatch(self.epoch_id) is None:
            raise CopyLedgerError(
                CopyLedgerCode.INVALID_REQUEST,
                "source anchor epoch must be opaque",
            )
        if type(self.sequence) is not int or self.sequence < 1:
            raise CopyLedgerError(
                CopyLedgerCode.INVALID_REQUEST,
                "source anchor sequence must follow genesis",
            )
        for name in ("segment_sha256", "record_id", "record_sha256"):
            _require_sha256(getattr(self, name), name, nonzero=True)

    def to_json(self) -> dict[str, Any]:
        return {
            "epoch_id": self.epoch_id,
            "record_id": self.record_id,
            "record_sha256": self.record_sha256,
            "segment_sha256": self.segment_sha256,
            "sequence": self.sequence,
        }

    def __repr__(self) -> str:
        return "CopySourceAnchor(anchor='<redacted>')"

    def __reduce__(self) -> Any:
        raise TypeError("copy source anchors cannot be serialized")


@dataclass(frozen=True, slots=True)
class CopyPublishOperationPlan:
    """Persisted typed publish plan used by fresh-process ancestry verification.

    A RESERVED plan freezes its reservation-time audit head; the eventual
    operation transition may authenticate a later head on the same chain.
    """

    kind: CopyPublishPlanKind
    operation_reference_hmac_sha256: str
    context_binding_sha256: str
    manifest_sha256: str
    budget_sha256: str
    classification: DataClassification
    publish_transaction_reference_hmac_sha256: str | None = None
    pair_reference_hmac_sha256: str | None = None
    locator_mode: OperationLocatorMode | None = None
    source_locator_hmac_sha256: str | None = None
    target_locator_hmac_sha256: str | None = None
    source_evidence: OperationTreeEvidence | None = None
    audit_ancestor_sha256: str | None = None

    def __post_init__(self) -> None:
        if type(self.kind) is not CopyPublishPlanKind:
            raise CopyLedgerError(
                CopyLedgerCode.INVALID_REQUEST,
                "publish plan kind must be exact",
            )
        _require_sha256(
            self.operation_reference_hmac_sha256,
            "operation_reference_hmac_sha256",
            nonzero=True,
        )
        for name in (
            "context_binding_sha256",
            "manifest_sha256",
            "budget_sha256",
        ):
            _require_sha256(getattr(self, name), name, nonzero=True)
        if type(self.classification) is not DataClassification:
            raise CopyLedgerError(
                CopyLedgerCode.INVALID_REQUEST,
                "publish plan classification must be exact",
            )
        reserved_values = (
            self.publish_transaction_reference_hmac_sha256,
            self.pair_reference_hmac_sha256,
            self.locator_mode,
            self.source_locator_hmac_sha256,
            self.target_locator_hmac_sha256,
            self.source_evidence,
            self.audit_ancestor_sha256,
        )
        if self.kind is CopyPublishPlanKind.UNSTARTED:
            if any(value is not None for value in reserved_values):
                raise CopyLedgerError(
                    CopyLedgerCode.INVALID_REQUEST,
                    "unstarted publish plans cannot claim reservation evidence",
                )
            return
        if any(value is None for value in reserved_values):
            raise CopyLedgerError(
                CopyLedgerCode.INVALID_REQUEST,
                "reserved publish plans require every typed reservation fact",
            )
        for name in (
            "publish_transaction_reference_hmac_sha256",
            "pair_reference_hmac_sha256",
            "source_locator_hmac_sha256",
            "target_locator_hmac_sha256",
        ):
            _require_sha256(getattr(self, name), name, nonzero=True)
        _require_sha256(
            self.audit_ancestor_sha256,
            "operation_audit_ancestor_sha256",
            nonzero=True,
        )
        if (
            type(self.locator_mode) is not OperationLocatorMode
            or type(self.source_evidence) is not OperationTreeEvidence
        ):
            raise CopyLedgerError(
                CopyLedgerCode.INVALID_REQUEST,
                "reserved publish plan types are not exact",
            )
        expected_mode = (
            OperationLocatorMode.HMAC_ONLY
            if self.classification is DataClassification.RESTRICTED
            else OperationLocatorMode.SAFE_RELATIVE
        )
        if self.locator_mode is not expected_mode:
            raise CopyLedgerError(
                CopyLedgerCode.INVALID_REQUEST,
                "publish plan classification and locator mode differ",
            )
        if (
            self.source_evidence.manifest_sha256 != self.manifest_sha256
        ):
            raise CopyLedgerError(
                CopyLedgerCode.INVALID_REQUEST,
                "publish plan manifest and observed source tree differ",
            )

    def to_json(self) -> dict[str, Any]:
        return {
            "audit_ancestor_sha256": self.audit_ancestor_sha256,
            "budget_sha256": self.budget_sha256,
            "classification": self.classification.value,
            "context_binding_sha256": self.context_binding_sha256,
            "kind": self.kind.value,
            "locator_mode": (
                None if self.locator_mode is None else self.locator_mode.value
            ),
            "manifest_sha256": self.manifest_sha256,
            "operation_reference_hmac_sha256": (
                self.operation_reference_hmac_sha256
            ),
            "pair_reference_hmac_sha256": self.pair_reference_hmac_sha256,
            "publish_transaction_reference_hmac_sha256": (
                self.publish_transaction_reference_hmac_sha256
            ),
            "source_evidence": (
                None if self.source_evidence is None else self.source_evidence.to_json()
            ),
            "source_locator_hmac_sha256": self.source_locator_hmac_sha256,
            "target_locator_hmac_sha256": self.target_locator_hmac_sha256,
        }

    def to_binding_json(self) -> dict[str, Any]:
        return self.to_json()

    def __repr__(self) -> str:
        return (
            "CopyPublishOperationPlan(kind='"
            f"{self.kind.value}', plan='<redacted>')"
        )

    def __reduce__(self) -> Any:
        raise TypeError("copy publish operation plans cannot be serialized")


@dataclass(frozen=True, slots=True)
class CopyOperationAbsenceWitness:
    """Authenticated prefix observation proving one expected operation was absent."""

    operation_epoch_reference_hmac_sha256: str
    observation_head_sha256: str
    observation_segment_count: int
    expected_operation_reference_hmac_sha256: str
    expected_publish_transaction_hmac_sha256: str | None
    authenticator_sha256: str

    def __post_init__(self) -> None:
        for name in (
            "operation_epoch_reference_hmac_sha256",
            "observation_head_sha256",
            "expected_operation_reference_hmac_sha256",
            "authenticator_sha256",
        ):
            _require_sha256(getattr(self, name), name, nonzero=True)
        if self.expected_publish_transaction_hmac_sha256 is not None:
            _require_sha256(
                self.expected_publish_transaction_hmac_sha256,
                "expected_publish_transaction_hmac_sha256",
                nonzero=True,
            )
        if (
            type(self.observation_segment_count) is not int
            or self.observation_segment_count < 1
            or self.observation_segment_count > _MAX_SEGMENTS
        ):
            raise CopyLedgerError(
                CopyLedgerCode.INVALID_REQUEST,
                "operation absence witness count is outside the ledger boundary",
            )

    def unsigned_json(self) -> dict[str, Any]:
        return {
            "expected_operation_reference_hmac_sha256": (
                self.expected_operation_reference_hmac_sha256
            ),
            "expected_publish_transaction_hmac_sha256": (
                self.expected_publish_transaction_hmac_sha256
            ),
            "observation_head_sha256": self.observation_head_sha256,
            "observation_segment_count": self.observation_segment_count,
            "operation_epoch_reference_hmac_sha256": (
                self.operation_epoch_reference_hmac_sha256
            ),
        }

    def to_json(self) -> dict[str, Any]:
        return {
            **self.unsigned_json(),
            "authenticator_sha256": self.authenticator_sha256,
        }

    def __repr__(self) -> str:
        return "CopyOperationAbsenceWitness(witness='<redacted>')"

    def __reduce__(self) -> Any:
        raise TypeError("copy operation absence witnesses cannot be serialized")


@dataclass(frozen=True, slots=True)
class CopyTransition:
    transition_id: str
    transaction_binding_sha256: str
    copy_binding_sha256: str
    previous_state: CopyState | None
    next_state: CopyState
    source_anchor: CopySourceAnchor
    audit_ancestor_sha256: str
    classification: DataClassification
    target_locator: CopyLocator
    expected_manifest_sha256: str
    provenance_metadata_sha256: str
    budget_sha256: str
    publish_operation_binding_sha256: str
    publish_operation_plan: CopyPublishOperationPlan
    mutation_attempted: bool
    publish_transaction_id: str | None = None
    publish_terminal_segment_sha256: str | None = None
    publish_terminal_state: OperationState | None = None
    publish_operation_absence_witness: CopyOperationAbsenceWitness | None = None
    target_evidence: CopyTargetEvidence | None = None
    error_code: str | None = None
    recovery_reason: str | None = None
    recovery_authority_head_sha256: str | None = None

    def __post_init__(self) -> None:
        for name in (
            "transition_id",
            "transaction_binding_sha256",
            "copy_binding_sha256",
            "audit_ancestor_sha256",
            "expected_manifest_sha256",
            "provenance_metadata_sha256",
            "budget_sha256",
            "publish_operation_binding_sha256",
        ):
            _require_sha256(getattr(self, name), name, nonzero=True)
        if (
            type(self.next_state) is not CopyState
            or (self.previous_state is not None and type(self.previous_state) is not CopyState)
            or (self.previous_state, self.next_state) not in _ALLOWED_TRANSITIONS
        ):
            raise CopyLedgerError(
                CopyLedgerCode.ILLEGAL_TRANSITION,
                "copy state transition is not allowed",
            )
        if (
            type(self.source_anchor) is not CopySourceAnchor
            or type(self.classification) is not DataClassification
            or type(self.target_locator) is not CopyLocator
            or type(self.publish_operation_plan) is not CopyPublishOperationPlan
            or type(self.mutation_attempted) is not bool
            or (
                self.target_evidence is not None
                and type(self.target_evidence) is not CopyTargetEvidence
            )
        ):
            raise CopyLedgerError(
                CopyLedgerCode.INVALID_REQUEST,
                "copy transition requires exact typed values",
            )
        expected_plan_kind = (
            CopyPublishPlanKind.UNSTARTED
            if (
                self.previous_state is None
                and self.next_state is CopyState.RECOVERED_ABORT
            )
            else CopyPublishPlanKind.RESERVED
        )
        if (
            self.publish_operation_plan.kind is not expected_plan_kind
            or self.publish_operation_plan.classification is not self.classification
            or self.publish_operation_plan.manifest_sha256
            != self.expected_manifest_sha256
            or self.publish_operation_plan.budget_sha256 != self.budget_sha256
            or (
                self.publish_transaction_id is None
                and self.publish_operation_plan.kind
                is not CopyPublishPlanKind.UNSTARTED
            )
            or (
                self.publish_transaction_id is not None
                and self.publish_operation_plan.kind
                is not CopyPublishPlanKind.RESERVED
            )
        ):
            raise CopyLedgerError(
                CopyLedgerCode.INVALID_REQUEST,
                "copy transition and persisted publish plan differ",
            )
        if self.target_locator.mode is not CopyLocatorMode.HMAC_ONLY:
            raise CopyLedgerError(
                CopyLedgerCode.INVALID_REQUEST,
                "copy target locators must remain opaque in every classification",
            )
        if self.publish_terminal_segment_sha256 is not None:
            _require_sha256(
                self.publish_terminal_segment_sha256,
                "publish_terminal_segment_sha256",
                nonzero=True,
            )
        if (
            self.publish_terminal_state is not None
            and type(self.publish_terminal_state) is not OperationState
        ):
            raise CopyLedgerError(
                CopyLedgerCode.INVALID_REQUEST,
                "publish terminal state must be exact",
            )
        if (
            self.publish_operation_absence_witness is not None
            and type(self.publish_operation_absence_witness)
            is not CopyOperationAbsenceWitness
        ):
            raise CopyLedgerError(
                CopyLedgerCode.INVALID_REQUEST,
                "publish operation absence witness must be exact",
            )
        if self.publish_transaction_id is not None:
            _opaque_publish_transaction_id(self.publish_transaction_id)
        source_only_recovered_abort = (
            self.previous_state is None
            and self.next_state is CopyState.RECOVERED_ABORT
        )
        if not source_only_recovered_abort and self.publish_transaction_id is None:
            raise CopyLedgerError(
                CopyLedgerCode.INVALID_REQUEST,
                "copy lifecycle requires its exact publish transaction from PREPARED",
            )
        if source_only_recovered_abort and self.publish_transaction_id is not None:
            raise CopyLedgerError(
                CopyLedgerCode.INVALID_REQUEST,
                "source-only recovery abort cannot claim a publish transaction",
            )
        terminal_pair = (
            self.publish_terminal_segment_sha256 is not None,
            self.publish_terminal_state is not None,
        )
        if terminal_pair[0] != terminal_pair[1]:
            raise CopyLedgerError(
                CopyLedgerCode.INVALID_REQUEST,
                "publish terminal state and segment must be present together",
            )
        if terminal_pair[0] and self.publish_transaction_id is None:
            raise CopyLedgerError(
                CopyLedgerCode.INVALID_REQUEST,
                "publish terminal requires its exact publish transaction",
            )
        if terminal_pair[0] and self.publish_operation_absence_witness is not None:
            raise CopyLedgerError(
                CopyLedgerCode.INVALID_REQUEST,
                "publish terminal and absence witness are mutually exclusive",
            )
        if self.recovery_authority_head_sha256 is not None:
            _require_sha256(
                self.recovery_authority_head_sha256,
                "recovery_authority_head_sha256",
                nonzero=True,
            )
        failed = self.next_state in {CopyState.ABORTED, CopyState.IN_DOUBT}
        if failed != (self.error_code is not None):
            raise CopyLedgerError(
                CopyLedgerCode.INVALID_REQUEST,
                "only failed copy states require an error code",
            )
        if self.error_code is not None:
            _safe_id(self.error_code, "error_code")
        recovered = self.next_state in {
            CopyState.RECOVERED_ABORT,
            CopyState.RECOVERED_COMMIT,
        }
        if recovered != (self.recovery_reason is not None):
            raise CopyLedgerError(
                CopyLedgerCode.INVALID_REQUEST,
                "only recovered copy states require a recovery reason",
            )
        if recovered != (self.recovery_authority_head_sha256 is not None):
            raise CopyLedgerError(
                CopyLedgerCode.INVALID_REQUEST,
                "recovery state must bind its authenticated recovery authority",
            )
        if self.recovery_reason is not None:
            _safe_id(self.recovery_reason, "recovery_reason")
        if self.next_state is CopyState.RECOVERED_ABORT and self.recovery_reason != (
            "PUBLISH_NOT_NATIVE_TARGET_ABSENT_SOURCE_EXACT"
        ):
            raise CopyLedgerError(
                CopyLedgerCode.INVALID_REQUEST,
                "recovered abort reason differs from the frozen truth table",
            )
        if self.next_state is CopyState.RECOVERED_COMMIT and self.recovery_reason != (
            "PUBLISH_COMMITTED_TARGET_EXACT_SOURCE_EXACT"
        ):
            raise CopyLedgerError(
                CopyLedgerCode.INVALID_REQUEST,
                "recovered commit reason differs from the frozen truth table",
            )
        mutation_required = self.next_state in {
            CopyState.MUTATED,
            CopyState.POSTCONDITION_VERIFIED,
            CopyState.COMMITTED,
            CopyState.IN_DOUBT,
            CopyState.RECOVERED_COMMIT,
        }
        if mutation_required and not self.mutation_attempted:
            raise CopyLedgerError(
                CopyLedgerCode.INVALID_REQUEST,
                "post-boundary copy states require the mutation-attempt fact",
            )
        if self.next_state in {CopyState.PREPARED, CopyState.ABORTED} and self.mutation_attempted:
            raise CopyLedgerError(
                CopyLedgerCode.INVALID_REQUEST,
                "pre-mutation copy states cannot claim mutation",
            )
        committed_publish_required = self.next_state in {
            CopyState.MUTATED,
            CopyState.POSTCONDITION_VERIFIED,
            CopyState.COMMITTED,
            CopyState.RECOVERED_COMMIT,
        }
        if committed_publish_required and (
            self.publish_terminal_segment_sha256 is None
            or self.publish_terminal_state
            not in {OperationState.COMMITTED, OperationState.RECOVERED_COMMIT}
            or self.publish_operation_absence_witness is not None
        ):
            raise CopyLedgerError(
                CopyLedgerCode.INVALID_REQUEST,
                "copy state has an invalid publish-terminal binding",
            )
        abort_resolution_required = self.next_state in {
            CopyState.ABORTED,
            CopyState.RECOVERED_ABORT,
        }
        if abort_resolution_required:
            exact_abort_terminal = (
                self.publish_terminal_segment_sha256 is not None
                and self.publish_terminal_state
                in {OperationState.ABORTED, OperationState.RECOVERED_ABORT}
                and self.publish_operation_absence_witness is None
            )
            exact_absence = (
                self.publish_terminal_segment_sha256 is None
                and self.publish_terminal_state is None
                and self.publish_operation_absence_witness is not None
            )
            if exact_abort_terminal == exact_absence:
                raise CopyLedgerError(
                    CopyLedgerCode.INVALID_REQUEST,
                    "abort state requires exactly one typed terminal or absence witness",
                )
        if self.next_state is CopyState.PREPARED and (
            self.publish_terminal_segment_sha256 is not None
            or self.publish_terminal_state is not None
            or self.publish_operation_absence_witness is not None
        ):
            raise CopyLedgerError(
                CopyLedgerCode.INVALID_REQUEST,
                "unresolved copy state cannot claim a publish resolution",
            )
        if self.next_state is CopyState.IN_DOUBT and (
            self.publish_operation_absence_witness is not None
            or (
                self.publish_terminal_state is not None
                and self.publish_terminal_state
                not in {OperationState.COMMITTED, OperationState.RECOVERED_COMMIT}
            )
        ):
            raise CopyLedgerError(
                CopyLedgerCode.INVALID_REQUEST,
                "in-doubt Copy state has an invalid publish resolution",
            )
        if source_only_recovered_abort and (
            self.publish_operation_absence_witness is None
            or self.publish_terminal_segment_sha256 is not None
        ):
            raise CopyLedgerError(
                CopyLedgerCode.INVALID_REQUEST,
                "source-only recovery abort requires an authenticated absence witness",
            )
        target_required = self.next_state in {
            CopyState.POSTCONDITION_VERIFIED,
            CopyState.COMMITTED,
            CopyState.RECOVERED_COMMIT,
        }
        if target_required and self.target_evidence is None:
            raise CopyLedgerError(
                CopyLedgerCode.INVALID_REQUEST,
                "copy state has an invalid target-evidence binding",
            )
        if self.next_state in {
            CopyState.PREPARED,
            CopyState.ABORTED,
            CopyState.MUTATED,
            CopyState.RECOVERED_ABORT,
        } and self.target_evidence is not None:
            raise CopyLedgerError(
                CopyLedgerCode.INVALID_REQUEST,
                "copy state cannot claim target evidence",
            )
        if self.target_evidence is not None and (
            self.target_evidence.manifest_sha256 != self.expected_manifest_sha256
        ):
            raise CopyLedgerError(
                CopyLedgerCode.INVALID_REQUEST,
                "target manifest differs from PREPARED",
            )

    @property
    def digest(self) -> str:
        return hashlib.sha256(
            b"COPY-TRANSITION-V4\0" + canonical_json_bytes(self.to_json())
        ).hexdigest()

    def to_json(self) -> dict[str, Any]:
        return {
            "audit_ancestor_sha256": self.audit_ancestor_sha256,
            "budget_sha256": self.budget_sha256,
            "classification": self.classification.value,
            "copy_binding_sha256": self.copy_binding_sha256,
            "error_code": self.error_code,
            "expected_manifest_sha256": self.expected_manifest_sha256,
            "mutation_attempted": self.mutation_attempted,
            "next_state": self.next_state.value,
            "previous_state": None if self.previous_state is None else self.previous_state.value,
            "provenance_metadata_sha256": self.provenance_metadata_sha256,
            "publish_operation_binding_sha256": self.publish_operation_binding_sha256,
            "publish_operation_plan": self.publish_operation_plan.to_json(),
            "publish_operation_absence_witness": (
                None
                if self.publish_operation_absence_witness is None
                else self.publish_operation_absence_witness.to_json()
            ),
            "publish_terminal_segment_sha256": self.publish_terminal_segment_sha256,
            "publish_terminal_state": (
                None
                if self.publish_terminal_state is None
                else self.publish_terminal_state.value
            ),
            "publish_transaction_id": self.publish_transaction_id,
            "recovery_authority_head_sha256": self.recovery_authority_head_sha256,
            "recovery_reason": self.recovery_reason,
            "source_anchor": self.source_anchor.to_json(),
            "target_evidence": (
                None if self.target_evidence is None else self.target_evidence.to_json()
            ),
            "target_locator": self.target_locator.to_json(),
            "transaction_binding_sha256": self.transaction_binding_sha256,
            "transition_id": self.transition_id,
        }

    def __repr__(self) -> str:
        return (
            "CopyTransition(state='"
            f"{self.next_state.value}', classification='{self.classification.value}', "
            "binding='<redacted>')"
        )

    def __reduce__(self) -> Any:
        raise TypeError("copy transitions cannot be serialized")


@dataclass(frozen=True, slots=True)
class CopyLedgerHead:
    ledger_kind: CopyLedgerKind
    epoch_id: str
    key_id: str
    last_sequence: int
    last_segment_sha256: str
    segment_count: int
    total_segment_bytes: int
    startup_observed_abandoned_mutex: bool = False

    def __reduce__(self) -> Any:
        raise TypeError("copy ledger heads cannot be serialized")


@dataclass(frozen=True, slots=True)
class CopyLedgersHead:
    source: CopyLedgerHead
    copy: CopyLedgerHead
    pending_source_count: int

    def __reduce__(self) -> Any:
        raise TypeError("copy ledger pair heads cannot be serialized")


@dataclass(frozen=True, slots=True)
class CopySourceReceipt:
    epoch_id: str
    sequence: int
    segment_sha256: str
    record_id: str
    record_sha256: str
    replayed: bool = False
    capability_state: str = "TEST_LOCAL_AUTHENTICATED_COPY_SOURCE"

    @property
    def anchor(self) -> CopySourceAnchor:
        return CopySourceAnchor(
            epoch_id=self.epoch_id,
            sequence=self.sequence,
            segment_sha256=self.segment_sha256,
            record_id=self.record_id,
            record_sha256=self.record_sha256,
        )

    def __repr__(self) -> str:
        return (
            "CopySourceReceipt(sequence="
            f"{self.sequence}, replayed={self.replayed}, receipt='<redacted>')"
        )

    def __reduce__(self) -> Any:
        raise TypeError("copy source receipts cannot be serialized")


def build_copy_provenance_material(
    source: CopySourceRecord,
    receipt: CopySourceReceipt,
    *,
    manifest_id: str,
) -> CopyProvenanceMaterial:
    """Derive the exact immutable provenance file and publish manifest.

    The provenance object binds the authenticated source ledger anchor and full
    source record.  Its embedded one-file manifest digest avoids the circular
    dependency that would arise from embedding the final two-file manifest.
    """

    if type(source) is not CopySourceRecord or type(receipt) is not CopySourceReceipt:
        raise CopyLedgerError(
            CopyLedgerCode.INVALID_REQUEST,
            "copy provenance requires exact source record and receipt types",
        )
    canonical_manifest_id = _safe_id(manifest_id, "manifest_id")
    try:
        anchor = receipt.anchor
    except CopyLedgerError:
        raise CopyLedgerError(
            CopyLedgerCode.INVALID_REQUEST,
            "copy provenance receipt anchor is invalid",
        ) from None
    if (
        receipt.record_id != source.record_id
        or receipt.record_sha256 != source.digest
        or anchor.record_id != source.record_id
        or anchor.record_sha256 != source.digest
    ):
        raise CopyLedgerError(
            CopyLedgerCode.INVALID_REQUEST,
            "copy provenance source and receipt do not match",
        )
    try:
        payload_manifest = DeclaredTreeManifest(
            manifest_id=canonical_manifest_id,
            classification=source.classification,
            entries=(
                DeclaredTreeEntry(
                    relative_path=SYNTHETIC_REFERENCE_PAYLOAD_NAME,
                    kind=TreeEntryKind.FILE,
                    size_bytes=source.source_evidence.size_bytes,
                    sha256=source.source_evidence.sha256,
                ),
            ),
        )
        provenance_bytes = canonical_json_bytes(
            {
                "payload_manifest_sha256": payload_manifest.manifest_sha256,
                "schema_id": "M0-COPY-PROVENANCE",
                "schema_version": "1.0",
                "source_anchor": anchor.to_json(),
                "source_record": source.to_json(),
            }
        )
        if len(provenance_bytes) > COPY_PROVENANCE_MAX_BYTES:
            raise CopyLedgerError(
                CopyLedgerCode.RESOURCE_LIMIT,
                "copy provenance exceeds its immutable byte boundary",
            )
        provenance_sha256 = hashlib.sha256(provenance_bytes).hexdigest()
        publish_manifest = DeclaredTreeManifest(
            manifest_id=canonical_manifest_id,
            classification=source.classification,
            entries=(
                payload_manifest.entries[0],
                DeclaredTreeEntry(
                    relative_path=COPY_PROVENANCE_FILE_NAME,
                    kind=TreeEntryKind.FILE,
                    size_bytes=len(provenance_bytes),
                    sha256=provenance_sha256,
                ),
            ),
        )
    except JobOperationError:
        raise CopyLedgerError(
            CopyLedgerCode.INVALID_REQUEST,
            "copy provenance manifest failed exact validation",
        ) from None
    return CopyProvenanceMaterial(
        provenance_bytes=provenance_bytes,
        provenance_sha256=provenance_sha256,
        payload_manifest_sha256=payload_manifest.manifest_sha256,
        publish_manifest=publish_manifest,
    )


@dataclass(frozen=True, slots=True)
class CopyTransitionReceipt:
    epoch_id: str
    sequence: int
    segment_sha256: str
    transition_id: str
    transition_sha256: str
    transaction_binding_sha256: str
    state: CopyState
    replayed: bool = False
    capability_state: str = "TEST_LOCAL_AUTHENTICATED_COPY_TRANSITION"

    def __repr__(self) -> str:
        return (
            "CopyTransitionReceipt(sequence="
            f"{self.sequence}, state='{self.state.value}', replayed={self.replayed}, "
            "receipt='<redacted>')"
        )

    def __reduce__(self) -> Any:
        raise TypeError("copy transition receipts cannot be serialized")


@dataclass(frozen=True, slots=True)
class _KindConfig:
    kind: CopyLedgerKind
    root: Path
    schema_version: str
    hash_domain: bytes
    auth_domain: bytes
    key_id_domain: bytes
    record_kind: str
    record_domain: bytes
    record_limit: int


_CONFIGS = {
    CopyLedgerKind.COPY_SOURCE: _KindConfig(
        CopyLedgerKind.COPY_SOURCE,
        _SOURCE_ROOT,
        "1.0",
        b"COPY-SOURCE-SEGMENT-V1\0",
        b"COPY-SOURCE-SEGMENT-AUTH-V1\0",
        b"COPY-SOURCE-KEY-ID-V1\0",
        "SOURCE_OBSERVED",
        b"COPY-SOURCE-RECORD-V1\0",
        _MAX_SOURCE_SEGMENT_BYTES,
    ),
    CopyLedgerKind.COPY_OPERATION: _KindConfig(
        CopyLedgerKind.COPY_OPERATION,
        _COPY_ROOT,
        "1.3",
        b"COPY-OPERATION-SEGMENT-V4\0",
        b"COPY-OPERATION-SEGMENT-AUTH-V4\0",
        b"COPY-OPERATION-KEY-ID-V4\0",
        "COPY_TRANSITION",
        b"COPY-TRANSITION-V4\0",
        _MAX_COPY_TRANSITION_SEGMENT_BYTES,
    ),
}


@dataclass(frozen=True, slots=True)
class _ParsedSegment:
    sequence: int
    segment_sha256: str
    previous_segment_sha256: str | None
    segment_kind: str
    record: CopySourceRecord | CopyTransition | None
    record_sha256: str | None
    size_bytes: int


def _locator_from_json(value: Any) -> CopyLocator:
    if type(value) is not dict or set(value) != {
        "hmac_sha256",
        "mode",
        "safe_relative_path",
    }:
        raise CopyLedgerError(CopyLedgerCode.CHAIN_CORRUPT, "locator shape is invalid")
    try:
        mode = CopyLocatorMode(value["mode"])
        selected = value["safe_relative_path"] if mode is CopyLocatorMode.SAFE_RELATIVE else value["hmac_sha256"]
        if (
            (mode is CopyLocatorMode.SAFE_RELATIVE and value["hmac_sha256"] is not None)
            or (mode is CopyLocatorMode.HMAC_ONLY and value["safe_relative_path"] is not None)
        ):
            raise ValueError
        return CopyLocator(mode, selected)
    except (TypeError, ValueError, CopyLedgerError):
        raise CopyLedgerError(CopyLedgerCode.CHAIN_CORRUPT, "locator failed validation") from None


def _file_evidence_from_json(value: Any) -> CopyFileEvidence:
    if type(value) is not dict or set(value) != {
        "change_evidence_sha256",
        "identity_hmac_sha256",
        "sha256",
        "size_bytes",
    }:
        raise CopyLedgerError(CopyLedgerCode.CHAIN_CORRUPT, "file evidence shape is invalid")
    try:
        return CopyFileEvidence(**value)
    except (TypeError, CopyLedgerError):
        raise CopyLedgerError(CopyLedgerCode.CHAIN_CORRUPT, "file evidence failed validation") from None


def _target_evidence_from_json(value: Any) -> CopyTargetEvidence:
    if type(value) is not dict or set(value) != {
        "entry_count",
        "manifest_sha256",
        "payload",
        "provenance",
        "root_identity_hmac_sha256",
        "tree_identity_hmac_sha256",
        "topology_sha256",
        "total_bytes",
        "tree_sha256",
    }:
        raise CopyLedgerError(CopyLedgerCode.CHAIN_CORRUPT, "target evidence shape is invalid")
    try:
        return CopyTargetEvidence(
            root_identity_hmac_sha256=value["root_identity_hmac_sha256"],
            tree_identity_hmac_sha256=value["tree_identity_hmac_sha256"],
            payload=_file_evidence_from_json(value["payload"]),
            provenance=_file_evidence_from_json(value["provenance"]),
            manifest_sha256=value["manifest_sha256"],
            tree_sha256=value["tree_sha256"],
            topology_sha256=value["topology_sha256"],
            entry_count=value["entry_count"],
            total_bytes=value["total_bytes"],
        )
    except (TypeError, CopyLedgerError):
        raise CopyLedgerError(CopyLedgerCode.CHAIN_CORRUPT, "target evidence failed validation") from None


def _anchor_from_json(value: Any) -> CopySourceAnchor:
    if type(value) is not dict or set(value) != {
        "epoch_id",
        "record_id",
        "record_sha256",
        "segment_sha256",
        "sequence",
    }:
        raise CopyLedgerError(CopyLedgerCode.CHAIN_CORRUPT, "source anchor shape is invalid")
    try:
        return CopySourceAnchor(**value)
    except (TypeError, CopyLedgerError):
        raise CopyLedgerError(CopyLedgerCode.CHAIN_CORRUPT, "source anchor failed validation") from None


def _source_from_json(value: Any) -> CopySourceRecord:
    expected = {
        "audit_ancestor_sha256",
        "classification",
        "copy_binding_sha256",
        "record_id",
        "reference_policy_digest",
        "source_evidence",
        "source_locator",
        "transaction_binding_sha256",
    }
    if type(value) is not dict or set(value) != expected:
        raise CopyLedgerError(CopyLedgerCode.CHAIN_CORRUPT, "source record shape is invalid")
    try:
        return CopySourceRecord(
            record_id=value["record_id"],
            transaction_binding_sha256=value["transaction_binding_sha256"],
            copy_binding_sha256=value["copy_binding_sha256"],
            reference_policy_digest=value["reference_policy_digest"],
            audit_ancestor_sha256=value["audit_ancestor_sha256"],
            classification=DataClassification(value["classification"]),
            source_locator=_locator_from_json(value["source_locator"]),
            source_evidence=_file_evidence_from_json(value["source_evidence"]),
        )
    except (TypeError, ValueError, CopyLedgerError):
        raise CopyLedgerError(CopyLedgerCode.CHAIN_CORRUPT, "source record failed validation") from None


def _absence_witness_from_json(value: Any) -> CopyOperationAbsenceWitness:
    expected = {
        "authenticator_sha256",
        "expected_operation_reference_hmac_sha256",
        "expected_publish_transaction_hmac_sha256",
        "observation_head_sha256",
        "observation_segment_count",
        "operation_epoch_reference_hmac_sha256",
    }
    if type(value) is not dict or set(value) != expected:
        raise CopyLedgerError(
            CopyLedgerCode.CHAIN_CORRUPT,
            "operation absence witness shape is invalid",
        )
    try:
        return CopyOperationAbsenceWitness(**value)
    except (TypeError, CopyLedgerError):
        raise CopyLedgerError(
            CopyLedgerCode.CHAIN_CORRUPT,
            "operation absence witness failed validation",
        ) from None


def _operation_tree_evidence_from_json(value: Any) -> OperationTreeEvidence:
    expected = {
        "durable_identity_sha256",
        "entry_count",
        "manifest_sha256",
        "source_tree_sha256",
        "topology_sha256",
        "total_bytes",
    }
    if type(value) is not dict or set(value) != expected:
        raise CopyLedgerError(
            CopyLedgerCode.CHAIN_CORRUPT,
            "persisted publish source evidence shape is invalid",
        )
    try:
        return OperationTreeEvidence(**value)
    except (TypeError, OperationLedgerError):
        raise CopyLedgerError(
            CopyLedgerCode.CHAIN_CORRUPT,
            "persisted publish source evidence failed validation",
        ) from None


def _publish_operation_plan_from_json(value: Any) -> CopyPublishOperationPlan:
    expected = {
        "audit_ancestor_sha256",
        "budget_sha256",
        "classification",
        "context_binding_sha256",
        "kind",
        "locator_mode",
        "manifest_sha256",
        "operation_reference_hmac_sha256",
        "pair_reference_hmac_sha256",
        "publish_transaction_reference_hmac_sha256",
        "source_evidence",
        "source_locator_hmac_sha256",
        "target_locator_hmac_sha256",
    }
    if type(value) is not dict or set(value) != expected:
        raise CopyLedgerError(
            CopyLedgerCode.CHAIN_CORRUPT,
            "persisted publish operation plan shape is invalid",
        )
    try:
        return CopyPublishOperationPlan(
            kind=CopyPublishPlanKind(value["kind"]),
            operation_reference_hmac_sha256=(
                value["operation_reference_hmac_sha256"]
            ),
            context_binding_sha256=value["context_binding_sha256"],
            manifest_sha256=value["manifest_sha256"],
            budget_sha256=value["budget_sha256"],
            classification=DataClassification(value["classification"]),
            publish_transaction_reference_hmac_sha256=(
                value["publish_transaction_reference_hmac_sha256"]
            ),
            pair_reference_hmac_sha256=value["pair_reference_hmac_sha256"],
            locator_mode=(
                None
                if value["locator_mode"] is None
                else OperationLocatorMode(value["locator_mode"])
            ),
            source_locator_hmac_sha256=value["source_locator_hmac_sha256"],
            target_locator_hmac_sha256=value["target_locator_hmac_sha256"],
            source_evidence=(
                None
                if value["source_evidence"] is None
                else _operation_tree_evidence_from_json(
                    value["source_evidence"]
                )
            ),
            audit_ancestor_sha256=value["audit_ancestor_sha256"],
        )
    except (TypeError, ValueError, CopyLedgerError):
        raise CopyLedgerError(
            CopyLedgerCode.CHAIN_CORRUPT,
            "persisted publish operation plan failed validation",
        ) from None


def _transition_from_json(value: Any) -> CopyTransition:
    expected = {
        "audit_ancestor_sha256",
        "budget_sha256",
        "classification",
        "copy_binding_sha256",
        "error_code",
        "expected_manifest_sha256",
        "mutation_attempted",
        "next_state",
        "previous_state",
        "provenance_metadata_sha256",
        "publish_operation_binding_sha256",
        "publish_operation_absence_witness",
        "publish_terminal_segment_sha256",
        "publish_terminal_state",
        "publish_operation_plan",
        "publish_transaction_id",
        "recovery_authority_head_sha256",
        "recovery_reason",
        "source_anchor",
        "target_evidence",
        "target_locator",
        "transaction_binding_sha256",
        "transition_id",
    }
    if type(value) is not dict or set(value) != expected:
        raise CopyLedgerError(CopyLedgerCode.CHAIN_CORRUPT, "copy transition shape is invalid")
    try:
        return CopyTransition(
            transition_id=value["transition_id"],
            transaction_binding_sha256=value["transaction_binding_sha256"],
            copy_binding_sha256=value["copy_binding_sha256"],
            previous_state=(None if value["previous_state"] is None else CopyState(value["previous_state"])),
            next_state=CopyState(value["next_state"]),
            source_anchor=_anchor_from_json(value["source_anchor"]),
            audit_ancestor_sha256=value["audit_ancestor_sha256"],
            classification=DataClassification(value["classification"]),
            target_locator=_locator_from_json(value["target_locator"]),
            expected_manifest_sha256=value["expected_manifest_sha256"],
            provenance_metadata_sha256=value["provenance_metadata_sha256"],
            budget_sha256=value["budget_sha256"],
            publish_operation_binding_sha256=value[
                "publish_operation_binding_sha256"
            ],
            publish_operation_plan=_publish_operation_plan_from_json(
                value["publish_operation_plan"]
            ),
            mutation_attempted=value["mutation_attempted"],
            publish_transaction_id=value["publish_transaction_id"],
            publish_terminal_segment_sha256=value["publish_terminal_segment_sha256"],
            publish_terminal_state=(
                None
                if value["publish_terminal_state"] is None
                else OperationState(value["publish_terminal_state"])
            ),
            publish_operation_absence_witness=(
                None
                if value["publish_operation_absence_witness"] is None
                else _absence_witness_from_json(
                    value["publish_operation_absence_witness"]
                )
            ),
            target_evidence=(None if value["target_evidence"] is None else _target_evidence_from_json(value["target_evidence"])),
            error_code=value["error_code"],
            recovery_reason=value["recovery_reason"],
            recovery_authority_head_sha256=value["recovery_authority_head_sha256"],
        )
    except (TypeError, ValueError, CopyLedgerError):
        raise CopyLedgerError(CopyLedgerCode.CHAIN_CORRUPT, "copy transition failed validation") from None


class _CopyChain:
    def __init__(
        self,
        storage: _WindowsHandleWriter,
        revision: AuditKeyRevision,
        *,
        config: _KindConfig,
        epoch_id: str,
        run_scope_hmac_sha256: str,
        policy_digest: str,
    ) -> None:
        self.storage = storage
        self.revision = revision
        self.config = config
        self.epoch_id = epoch_id
        self.run_scope_hmac_sha256 = run_scope_hmac_sha256
        self.policy_digest = policy_digest
        self.auth_key = hmac.new(
            revision.segment_hmac_key,
            config.auth_domain,
            hashlib.sha256,
        ).digest()
        self.key_id = hashlib.sha256(config.key_id_domain + self.auth_key).hexdigest()
        self.segments: tuple[_ParsedSegment, ...] = ()
        self.total_bytes = 0
        self.startup_abandoned = False

    @property
    def directory(self) -> Path:
        return self.config.root / self.epoch_id

    @property
    def head(self) -> CopyLedgerHead:
        previous = self.segments[-1].segment_sha256 if self.segments else "0" * 64
        return CopyLedgerHead(
            ledger_kind=self.config.kind,
            epoch_id=self.epoch_id,
            key_id=self.key_id,
            last_sequence=len(self.segments) - 1,
            last_segment_sha256=previous,
            segment_count=len(self.segments),
            total_segment_bytes=self.total_bytes,
            startup_observed_abandoned_mutex=self.startup_abandoned,
        )

    def build_segment(
        self,
        *,
        sequence: int,
        previous: str | None,
        created_at_utc: str,
        segment_kind: str,
        record: CopySourceRecord | CopyTransition | None,
    ) -> tuple[bytes, str]:
        body = {
            "created_at_utc": created_at_utc,
            "epoch_id": self.epoch_id,
            "key_id": self.key_id,
            "key_revision_id": self.revision.revision_id,
            "key_revision_sha256": self.revision.revision_sha256,
            "ledger_kind": self.config.kind.value,
            "policy_digest": self.policy_digest,
            "previous_segment_sha256": previous,
            "record": None if record is None else record.to_json(),
            "record_sha256": None if record is None else record.digest,
            "run_scope_hmac_sha256": self.run_scope_hmac_sha256,
            "schema_id": "M0-COPY-LEDGER-SEGMENT",
            "schema_version": self.config.schema_version,
            "segment_kind": segment_kind,
            "sequence": sequence,
        }
        body_bytes = canonical_json_bytes(body)
        segment_sha = hashlib.sha256(self.config.hash_domain + body_bytes).hexdigest()
        envelope = dict(body)
        envelope["segment_auth_hmac_sha256"] = hmac.new(
            self.auth_key,
            self.config.auth_domain + body_bytes,
            hashlib.sha256,
        ).hexdigest()
        envelope["segment_sha256"] = segment_sha
        return canonical_json_bytes(envelope), segment_sha

    def publish(self, sequence: int, segment_sha: str, payload: bytes) -> None:
        if len(payload) > _MAX_SEGMENT_BYTES:
            raise CopyLedgerError(CopyLedgerCode.RESOURCE_LIMIT, "copy segment exceeds its fixed byte limit")
        final_name = f"{sequence:020d}-{segment_sha}.json"
        pending_name = f"PENDING-{sequence:020d}-{segment_sha[:24]}-{secrets.token_hex(8).upper()}.json"
        try:
            self.storage.publish_new_file(
                self.directory / pending_name,
                self.directory / final_name,
                payload,
                expected_sha256=hashlib.sha256(payload).hexdigest(),
            )
        except HandleWriterError as exc:
            raise CopyLedgerError(
                CopyLedgerCode.STORAGE_FAILURE,
                f"copy segment publication failed safely ({exc.code.value})",
            ) from exc

    def scan(self, *, allow_empty: bool, startup_abandoned: bool) -> tuple[_ParsedSegment, ...]:
        try:
            snapshot = self.storage.read_flat_directory(
                self.directory,
                maximum_entries=_MAX_SEGMENTS,
                maximum_file_bytes=_MAX_SEGMENT_BYTES,
                maximum_total_bytes=_MAX_LEDGER_BYTES,
            )
        except HandleWriterError as exc:
            raise CopyLedgerError(CopyLedgerCode.STORAGE_FAILURE, "copy segment store cannot be read") from exc
        files: list[tuple[int, str, bytes]] = []
        for entry in snapshot.entries:
            match = _SEGMENT_FILE.fullmatch(entry.name)
            if match is None:
                raise CopyLedgerError(
                    CopyLedgerCode.UNKNOWN_ENTRY,
                    "copy segment store contains an unknown or pending entry",
                )
            files.append((int(match.group("sequence")), entry.name, entry.payload))
        files.sort(key=lambda item: (item[0], item[1]))
        parsed_segments: list[_ParsedSegment] = []
        previous: str | None = None
        for expected, (numeric, name, payload) in enumerate(files):
            if numeric != expected:
                raise CopyLedgerError(
                    CopyLedgerCode.CHAIN_CORRUPT,
                    "copy segment chain has a gap or fork",
                )
            parsed = self.parse_segment(
                name,
                payload,
                expected_sequence=expected,
                expected_previous=previous,
            )
            if expected == 0:
                if parsed.segment_kind != "GENESIS" or parsed.record is not None:
                    raise CopyLedgerError(CopyLedgerCode.CHAIN_CORRUPT, "copy genesis placement is invalid")
            elif parsed.segment_kind != self.config.record_kind or parsed.record is None:
                raise CopyLedgerError(CopyLedgerCode.CHAIN_CORRUPT, "copy record segment kind is invalid")
            parsed_segments.append(parsed)
            previous = parsed.segment_sha256
        if not parsed_segments and not allow_empty:
            raise CopyLedgerError(CopyLedgerCode.CHAIN_CORRUPT, "copy ledger is missing immutable genesis")
        self.segments = tuple(parsed_segments)
        self.total_bytes = sum(len(payload) for _, _, payload in files)
        self.startup_abandoned = startup_abandoned
        return self.segments

    def parse_segment(
        self,
        name: str,
        payload: bytes,
        *,
        expected_sequence: int,
        expected_previous: str | None,
    ) -> _ParsedSegment:
        try:
            value = parse_canonical_json_bytes(payload, maximum_bytes=_MAX_SEGMENT_BYTES)
        except LedgerError:
            raise CopyLedgerError(CopyLedgerCode.CHAIN_CORRUPT, "copy segment bytes are not canonical") from None
        expected_fields = {
            "created_at_utc", "epoch_id", "key_id", "key_revision_id",
            "key_revision_sha256", "ledger_kind", "policy_digest",
            "previous_segment_sha256", "record", "record_sha256",
            "run_scope_hmac_sha256", "schema_id", "schema_version",
            "segment_auth_hmac_sha256", "segment_kind", "segment_sha256", "sequence",
        }
        if type(value) is not dict or set(value) != expected_fields:
            raise CopyLedgerError(CopyLedgerCode.CHAIN_CORRUPT, "copy segment envelope shape is invalid")
        body = dict(value)
        supplied_auth = body.pop("segment_auth_hmac_sha256")
        supplied_sha = body.pop("segment_sha256")
        try:
            body_bytes = canonical_json_bytes(body)
        except LedgerError:
            raise CopyLedgerError(CopyLedgerCode.CHAIN_CORRUPT, "copy segment body is not canonical") from None
        computed_sha = hashlib.sha256(self.config.hash_domain + body_bytes).hexdigest()
        computed_auth = hmac.new(
            self.auth_key,
            self.config.auth_domain + body_bytes,
            hashlib.sha256,
        ).hexdigest()
        match = _SEGMENT_FILE.fullmatch(name)
        if (
            match is None
            or type(value["sequence"]) is not int
            or value["sequence"] != expected_sequence
            or int(match.group("sequence")) != expected_sequence
            or match.group("sha") != supplied_sha
            or supplied_sha != computed_sha
            or type(supplied_auth) is not str
            or not hmac.compare_digest(supplied_auth, computed_auth)
            or value["previous_segment_sha256"] != expected_previous
            or value["epoch_id"] != self.epoch_id
            or value["ledger_kind"] != self.config.kind.value
            or value["policy_digest"] != self.policy_digest
            or value["run_scope_hmac_sha256"] != self.run_scope_hmac_sha256
            or value["key_id"] != self.key_id
            or value["key_revision_id"] != self.revision.revision_id
            or value["key_revision_sha256"] != self.revision.revision_sha256
            or value["schema_id"] != "M0-COPY-LEDGER-SEGMENT"
            or value["schema_version"] != self.config.schema_version
        ):
            raise CopyLedgerError(CopyLedgerCode.AUTHENTICATION_FAILED, "copy segment authenticator or chain differs")
        try:
            _validate_utc_seconds(value["created_at_utc"])
        except CopyLedgerError:
            raise CopyLedgerError(CopyLedgerCode.CHAIN_CORRUPT, "copy segment time is invalid") from None
        kind = value["segment_kind"]
        record: CopySourceRecord | CopyTransition | None = None
        if kind == "GENESIS":
            if value["record"] is not None or value["record_sha256"] is not None:
                raise CopyLedgerError(CopyLedgerCode.CHAIN_CORRUPT, "copy genesis contains a record")
        elif kind == self.config.record_kind:
            record = _source_from_json(value["record"]) if self.config.kind is CopyLedgerKind.COPY_SOURCE else _transition_from_json(value["record"])
            if value["record_sha256"] != record.digest:
                raise CopyLedgerError(CopyLedgerCode.CHAIN_CORRUPT, "copy record digest differs")
        else:
            raise CopyLedgerError(CopyLedgerCode.CHAIN_CORRUPT, "copy segment kind is unknown")
        return _ParsedSegment(
            sequence=expected_sequence,
            segment_sha256=computed_sha,
            previous_segment_sha256=expected_previous,
            segment_kind=kind,
            record=record,
            record_sha256=value["record_sha256"],
            size_bytes=len(payload),
        )


class _AuthenticatedCopyAncestors:
    """Opaque, one-shot proof made from the exact authenticated ledger objects."""

    __slots__ = (
        "_copy_ledgers",
        "_storage",
        "_lease",
        "_audit_ledger",
        "_operation_ledger",
        "_audit_segment_sha256s",
        "_publish_segment_sha256s",
        "_publish_terminal_binding_sha256s",
        "_copy_cross_reference_sha256",
        "_nonce",
        "_binding_sha256",
        "_owner_thread",
        "_state",
    )

    def __init__(
        self,
        copy_ledgers: DurableCopyLedgers,
        storage: _WindowsHandleWriter,
        lease: RuntimeMutexLease,
        audit_ledger: DurableAuditLedger,
        operation_ledger: DurableOperationLedger,
        audit_segment_sha256s: tuple[str, ...],
        publish_segment_sha256s: tuple[str, ...],
        publish_terminal_binding_sha256s: tuple[str, ...],
        copy_cross_reference_sha256: str,
        nonce: str,
        binding_sha256: str,
        *,
        _constructor: object,
    ) -> None:
        if _constructor is not _AUTHENTICATED_COPY_ANCESTORS_CONSTRUCTOR:
            raise TypeError("authenticated Copy ancestors require ledger authority")
        self._copy_ledgers = copy_ledgers
        self._storage = storage
        self._lease = lease
        self._audit_ledger = audit_ledger
        self._operation_ledger = operation_ledger
        self._audit_segment_sha256s = audit_segment_sha256s
        self._publish_segment_sha256s = publish_segment_sha256s
        self._publish_terminal_binding_sha256s = publish_terminal_binding_sha256s
        self._copy_cross_reference_sha256 = copy_cross_reference_sha256
        self._nonce = nonce
        self._binding_sha256 = binding_sha256
        self._owner_thread = threading.get_ident()
        self._state = "ISSUED"

    def __repr__(self) -> str:
        return (
            "_AuthenticatedCopyAncestors(state='"
            f"{self._state}', ancestors='<redacted>')"
        )

    def __reduce__(self) -> Any:
        raise TypeError("authenticated Copy ancestor capabilities cannot be serialized")


class DurableCopyLedgers:
    """Test-local dual ledger core. Construction is intentionally private."""

    def __init__(
        self,
        storage: _WindowsHandleWriter,
        revision: AuditKeyRevision,
        *,
        epoch_id: str,
        run_scope_id: str,
        policy_digest: str,
        known_revisions: tuple[AuditKeyRevision, ...] = (),
        audit_ledger: DurableAuditLedger | None = None,
        initialize: bool = False,
        initialized_at_utc: str | None = None,
        _runtime_mutex_lease: RuntimeMutexLease | None = None,
        _constructor: object | None = None,
    ) -> None:
        if (
            _constructor is not _COPY_LEDGERS_CONSTRUCTOR
            or type(storage) is not _WindowsHandleWriter
            or type(revision) is not AuditKeyRevision
            or type(known_revisions) is not tuple
            or any(type(item) is not AuditKeyRevision for item in known_revisions)
            or (
                audit_ledger is not None
                and (
                    type(audit_ledger) is not DurableAuditLedger
                    or audit_ledger._storage is not storage
                )
            )
            or type(initialize) is not bool
            or (not initialize and initialized_at_utc is not None)
        ):
            raise CopyLedgerError(
                CopyLedgerCode.INVALID_REQUEST,
                "copy ledgers require their exact Test-local factory authority",
            )
        self._storage = storage
        self._audit_ledger = audit_ledger
        self._epoch_id = _safe_id(epoch_id, "epoch_id")
        if _OPAQUE_EPOCH_ID.fullmatch(self._epoch_id) is None:
            raise CopyLedgerError(
                CopyLedgerCode.INVALID_REQUEST,
                "copy ledger epoch must be an exact opaque HMAC identifier",
            )
        self._run_scope_id = _safe_id(run_scope_id, "run_scope_id")
        self._policy_digest = _require_sha256(policy_digest, "policy_digest", nonzero=True)
        revisions = {revision.revision_id: revision}
        for item in known_revisions:
            existing = revisions.get(item.revision_id)
            if existing is not None and existing != item:
                raise CopyLedgerError(CopyLedgerCode.AUTHENTICATION_FAILED, "copy revision inventory conflicts")
            revisions[item.revision_id] = item
        matching_revisions = tuple(
            item
            for item in revisions.values()
            if hmac.compare_digest(
                self._epoch_id,
                _derive_copy_ledger_epoch_id(item, self._run_scope_id),
            )
        )
        if (
            len(matching_revisions) != 1
            or (
                initialize
                and matching_revisions[0].revision_id != revision.revision_id
            )
        ):
            raise CopyLedgerError(
                CopyLedgerCode.INVALID_REQUEST,
                "copy ledger epoch does not authenticate its exact run scope",
            )
        self._known_revisions = revisions
        self._revision = revision
        self._requested_revision_id = revision.revision_id
        self._run_scope_hmac_sha256 = self._derive_run_scope_hmac(revision)
        self._append_enabled = True
        self._lock = threading.RLock()
        self._sealed_code: CopyLedgerCode | None = None
        self._source_records: dict[str, CopySourceRecord] = {}
        self._source_by_transaction: dict[str, CopySourceRecord] = {}
        self._source_receipts: dict[str, CopySourceReceipt] = {}
        self._copy_histories: dict[str, tuple[CopyTransition, ...]] = {}
        self._transition_receipts: dict[str, CopyTransitionReceipt] = {}
        self._configure_chains()
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
        except CopyLedgerError as exc:
            self._seal(exc.code)
            _raise_without_context(
                CopyLedgerError(exc.code, f"copy ledger startup failed safely ({exc})")
            )
        except HandleWriterError:
            self._seal(CopyLedgerCode.STORAGE_FAILURE)
            _raise_without_context(
                CopyLedgerError(CopyLedgerCode.STORAGE_FAILURE, "copy ledger storage startup failed safely")
            )
        except Exception:
            self._seal(CopyLedgerCode.CHAIN_CORRUPT)
            _raise_without_context(
                CopyLedgerError(CopyLedgerCode.CHAIN_CORRUPT, "copy ledger startup rejected invalid encoding")
            )

    @staticmethod
    def _preflight_new_epoch_under_existing_mutex(
        storage: _WindowsHandleWriter,
        active_revision: AuditKeyRevision,
        *,
        epoch_id: str,
        run_scope_id: str,
        policy_digest: str,
        activated_revisions: tuple[AuditKeyRevision, ...],
        audit_ledger: DurableAuditLedger,
        operation_ledgers: tuple[DurableOperationLedger, ...],
        lease: RuntimeMutexLease,
    ) -> tuple[CopyLedgersHead, ...]:
        """Prove rotation safety before either new genesis can be published.

        The raw logical RUN_ID exists only in this in-memory derivation.  Every
        present historical epoch is reopened under the same runtime mutex and
        its two chains are authenticated.  Corrupt/asymmetric history seals the
        writer; healthy pending history merely blocks rotation so callers can
        reopen that prior epoch for replay or terminal recovery.

        Every historical Copy pair is also resolved against the complete,
        authenticated operation-epoch catalog and the audit chain before a new
        genesis is allowed.
        """

        if (
            type(storage) is not _WindowsHandleWriter
            or type(active_revision) is not AuditKeyRevision
            or type(activated_revisions) is not tuple
            or not activated_revisions
            or any(
                type(item) is not AuditKeyRevision
                for item in activated_revisions
            )
            or type(audit_ledger) is not DurableAuditLedger
            or audit_ledger._storage is not storage
            or type(operation_ledgers) is not tuple
            or not operation_ledgers
            or any(
                type(item) is not DurableOperationLedger
                or item._storage is not storage
                for item in operation_ledgers
            )
            or type(lease) is not RuntimeMutexLease
            or lease._writer is not storage
        ):
            raise CopyLedgerError(
                CopyLedgerCode.INVALID_REQUEST,
                "copy epoch rotation requires exact activated authorities",
            )
        try:
            lease._assert_live_owner(storage)
        except HandleWriterError:
            raise CopyLedgerError(
                CopyLedgerCode.MUTEX_INVALID,
                "copy epoch rotation requires the live owner mutex",
            ) from None

        canonical_epoch = _safe_id(epoch_id, "epoch_id")
        canonical_scope = _safe_id(run_scope_id, "run_scope_id")
        canonical_policy = _require_sha256(
            policy_digest,
            "policy_digest",
            nonzero=True,
        )
        if _OPAQUE_EPOCH_ID.fullmatch(canonical_epoch) is None:
            raise CopyLedgerError(
                CopyLedgerCode.INVALID_REQUEST,
                "new copy epoch must be an exact opaque HMAC identifier",
            )

        revisions: dict[str, AuditKeyRevision] = {}
        sequences: set[int] = set()
        mapped_epochs: dict[str, str] = {}
        for item in activated_revisions:
            existing = revisions.get(item.revision_id)
            if existing is not None and existing != item:
                raise CopyLedgerError(
                    CopyLedgerCode.AUTHENTICATION_FAILED,
                    "activated copy revision inventory conflicts",
                )
            if item.revision_sequence in sequences and existing is None:
                raise CopyLedgerError(
                    CopyLedgerCode.AUTHENTICATION_FAILED,
                    "activated copy revision sequence is ambiguous",
                )
            revisions[item.revision_id] = item
            sequences.add(item.revision_sequence)
            mapped_epoch = _derive_copy_ledger_epoch_id(item, canonical_scope)
            mapped_revision_id = mapped_epochs.get(mapped_epoch)
            if (
                mapped_revision_id is not None
                and mapped_revision_id != item.revision_id
            ):
                raise CopyLedgerError(
                    CopyLedgerCode.AUTHENTICATION_FAILED,
                    "activated revisions map the run scope ambiguously",
                )
            mapped_epochs[mapped_epoch] = item.revision_id

        authenticated_active = revisions.get(active_revision.revision_id)
        expected_active_epoch = _derive_copy_ledger_epoch_id(
            active_revision,
            canonical_scope,
        )
        if (
            authenticated_active != active_revision
            or not hmac.compare_digest(canonical_epoch, expected_active_epoch)
            or mapped_epochs.get(canonical_epoch) != active_revision.revision_id
        ):
            raise CopyLedgerError(
                CopyLedgerCode.INVALID_REQUEST,
                "new copy epoch does not map the active revision and run scope",
            )

        historical_heads: list[CopyLedgersHead] = []
        pending_history = False
        ordered_revisions = tuple(
            sorted(
                revisions.values(),
                key=lambda item: (item.revision_sequence, item.revision_id),
            )
        )
        for historical_revision in ordered_revisions:
            if historical_revision.revision_id == active_revision.revision_id:
                continue
            historical_epoch = _derive_copy_ledger_epoch_id(
                historical_revision,
                canonical_scope,
            )
            try:
                source_present, copy_present = _copy_epoch_pair_presence(
                    storage,
                    historical_epoch,
                )
            except CopyLedgerError:
                storage.seal_after_indeterminate_mutation()
                raise
            if not source_present and not copy_present:
                continue
            if source_present != copy_present:
                storage.seal_after_indeterminate_mutation()
                raise CopyLedgerError(
                    CopyLedgerCode.CROSS_REFERENCE_INVALID,
                    "historical copy epoch stores are asymmetric",
                )
            try:
                historical = DurableCopyLedgers(
                    storage,
                    active_revision,
                    epoch_id=historical_epoch,
                    run_scope_id=canonical_scope,
                    policy_digest=canonical_policy,
                    known_revisions=ordered_revisions,
                    initialize=False,
                    _runtime_mutex_lease=lease,
                    _constructor=_COPY_LEDGERS_CONSTRUCTOR,
                )
                historical._validate_full_dag_with_operation_epochs_under_existing_mutex(
                    lease,
                    audit_ledger,
                    operation_ledgers,
                )
                historical_head = historical.head
            except CopyLedgerError:
                storage.seal_after_indeterminate_mutation()
                raise
            historical_heads.append(historical_head)
            pending_history = (
                pending_history
                or historical_head.pending_source_count > 0
            )

        if pending_history:
            raise CopyLedgerError(
                CopyLedgerCode.ROTATION_BLOCKED,
                "historical copy epoch requires terminal recovery",
            )
        return tuple(historical_heads)

    def _configure_chains(self) -> None:
        self._source_chain = _CopyChain(
            self._storage,
            self._revision,
            config=_CONFIGS[CopyLedgerKind.COPY_SOURCE],
            epoch_id=self._epoch_id,
            run_scope_hmac_sha256=self._run_scope_hmac_sha256,
            policy_digest=self._policy_digest,
        )
        self._copy_chain = _CopyChain(
            self._storage,
            self._revision,
            config=_CONFIGS[CopyLedgerKind.COPY_OPERATION],
            epoch_id=self._epoch_id,
            run_scope_hmac_sha256=self._run_scope_hmac_sha256,
            policy_digest=self._policy_digest,
        )

    def _derive_run_scope_hmac(self, revision: AuditKeyRevision) -> str:
        return hmac.new(
            revision.segment_hmac_key,
            b"COPY-RUN-SCOPE-HMAC-V1\0" + self._run_scope_id.encode("ascii"),
            hashlib.sha256,
        ).hexdigest()

    def __repr__(self) -> str:
        return "DurableCopyLedgers(epoch='<redacted>', state='<redacted>')"

    def __reduce__(self) -> Any:
        raise TypeError("durable copy ledgers cannot be serialized")

    @property
    def head(self) -> CopyLedgersHead:
        with self._lock:
            self._require_open()
            return CopyLedgersHead(
                source=self._source_chain.head,
                copy=self._copy_chain.head,
                pending_source_count=self._pending_source_count(),
            )

    @property
    def signing_revision_id(self) -> str:
        with self._lock:
            self._require_open()
            return self._revision.revision_id

    @property
    def storage_epoch_id(self) -> str:
        with self._lock:
            self._require_open()
            return self._epoch_id

    def matches_run_scope(self, run_scope_id: str) -> bool:
        """Verify a raw in-memory RUN_ID against both durable scope bindings."""

        try:
            canonical = _safe_id(run_scope_id, "run_scope_id")
            expected_scope_hmac = hmac.new(
                self._revision.segment_hmac_key,
                b"COPY-RUN-SCOPE-HMAC-V1\0" + canonical.encode("ascii"),
                hashlib.sha256,
            ).hexdigest()
            expected_epoch = _derive_copy_ledger_epoch_id(
                self._revision,
                canonical,
            )
        except CopyLedgerError:
            return False
        with self._lock:
            self._require_open()
            return hmac.compare_digest(
                self._run_scope_hmac_sha256,
                expected_scope_hmac,
            ) and hmac.compare_digest(self._epoch_id, expected_epoch)

    def target_locator(
        self,
        relative_locator: str,
        classification: DataClassification,
    ) -> CopyLocator:
        """Project a Copy target through the ledger's role-separated key domain."""

        canonical = _safe_relative(relative_locator, "target_relative_locator")
        if type(classification) is not DataClassification:
            raise CopyLedgerError(
                CopyLedgerCode.INVALID_REQUEST,
                "target locator classification must be exact",
            )
        with self._lock:
            self._require_open()
            digest = hmac.new(
                self._copy_chain.auth_key,
                b"COPY-TARGET-LOCATOR-V1\0"
                + self._epoch_id.encode("ascii")
                + b"\0"
                + self._run_scope_hmac_sha256.encode("ascii")
                + b"\0TARGET\0"
                + canonical.encode("utf-8", "strict"),
                hashlib.sha256,
            ).hexdigest()
        return CopyLocator(CopyLocatorMode.HMAC_ONLY, digest)

    def transaction_binding(
        self,
        *,
        context_sha256: str,
        manifest_sha256: str,
        budget_sha256: str,
        source_reference_sha256: str,
        classification: DataClassification,
    ) -> str:
        fields = {
            "budget_sha256": _require_sha256(budget_sha256, "budget_sha256"),
            "classification": (
                classification.value
                if type(classification) is DataClassification
                else ""
            ),
            "context_sha256": _require_sha256(context_sha256, "context_sha256"),
            "manifest_sha256": _require_sha256(manifest_sha256, "manifest_sha256"),
            "source_reference_sha256": _require_sha256(
                source_reference_sha256,
                "source_reference_sha256",
                nonzero=True,
            ),
        }
        if type(classification) is not DataClassification:
            raise CopyLedgerError(
                CopyLedgerCode.INVALID_REQUEST,
                "transaction binding classification must be exact",
            )
        return self._binding_hmac(b"COPY-TRANSACTION-BINDING-V1", fields)

    def copy_object_binding(
        self,
        *,
        context_sha256: str,
        copy_id: str,
        source_reference_sha256: str,
        classification: DataClassification,
    ) -> str:
        canonical_copy_id = _safe_id(copy_id, "copy_id")
        fields = {
            "classification": (
                classification.value
                if type(classification) is DataClassification
                else ""
            ),
            "context_sha256": _require_sha256(context_sha256, "context_sha256"),
            "copy_id": canonical_copy_id,
            "source_reference_sha256": _require_sha256(
                source_reference_sha256,
                "source_reference_sha256",
                nonzero=True,
            ),
        }
        if type(classification) is not DataClassification:
            raise CopyLedgerError(
                CopyLedgerCode.INVALID_REQUEST,
                "copy binding classification must be exact",
            )
        return self._binding_hmac(b"COPY-OBJECT-BINDING-V1", fields)

    def publish_operation_binding(
        self,
        *,
        plan: CopyPublishOperationPlan,
        operation_reference: str,
        publish_transaction_id: str | None,
        transaction_binding_sha256: str,
        copy_binding_sha256: str,
        source_anchor: CopySourceAnchor,
        copy_audit_ancestor_sha256: str,
        target_locator: CopyLocator,
        source_relative_locator: str,
        target_relative_locator: str,
        operation_ledger: DurableOperationLedger,
    ) -> str:
        """Issue an HMAC only after exact cross-ledger locator-plan validation."""

        canonical_source = _safe_relative(
            source_relative_locator,
            "source_relative_locator",
        )
        canonical_target = _safe_relative(
            target_relative_locator,
            "target_relative_locator",
        )
        if (
            type(plan) is not CopyPublishOperationPlan
            or type(source_anchor) is not CopySourceAnchor
            or type(target_locator) is not CopyLocator
            or target_locator.mode is not CopyLocatorMode.HMAC_ONLY
            or type(operation_ledger) is not DurableOperationLedger
            or operation_ledger._storage is not self._storage
            or target_locator
            != self.target_locator(canonical_target, plan.classification)
            or not hmac.compare_digest(
                plan.operation_reference_hmac_sha256,
                self._operation_reference_hmac(operation_reference),
            )
        ):
            raise CopyLedgerError(
                CopyLedgerCode.INVALID_REQUEST,
                "publish operation binding requires exact co-located plan values",
            )
        if plan.kind is CopyPublishPlanKind.RESERVED:
            if (
                type(publish_transaction_id) is not str
                or plan.locator_mode is None
                or plan.source_locator_hmac_sha256 is None
                or plan.target_locator_hmac_sha256 is None
                or plan.publish_transaction_reference_hmac_sha256 is None
            ):
                raise CopyLedgerError(
                    CopyLedgerCode.INVALID_REQUEST,
                    "reserved publish operation plan is incomplete",
                )
            if not hmac.compare_digest(
                plan.publish_transaction_reference_hmac_sha256,
                self._publish_transaction_reference_hmac(
                    _opaque_publish_transaction_id(publish_transaction_id)
                ),
            ):
                raise CopyLedgerError(
                    CopyLedgerCode.INVALID_REQUEST,
                    "publish operation transaction projection differs",
                )
            if plan.locator_mode is OperationLocatorMode.SAFE_RELATIVE:
                operation_source = canonical_source
                operation_target = canonical_target
            else:
                try:
                    operation_source = operation_ledger.locator_hmac(
                        canonical_source,
                        transaction_id=publish_transaction_id,
                        role=OperationLocatorRole.SOURCE,
                    )
                    operation_target = operation_ledger.locator_hmac(
                        canonical_target,
                        transaction_id=publish_transaction_id,
                        role=OperationLocatorRole.TARGET,
                    )
                except OperationLedgerError:
                    raise CopyLedgerError(
                        CopyLedgerCode.INVALID_REQUEST,
                        "publish operation locator plan cannot be authenticated",
                    ) from None
            expected_source = self._operation_plan_locator_hmac(
                operation_source,
                role=OperationLocatorRole.SOURCE,
                locator_mode=plan.locator_mode,
            )
            expected_target = self._operation_plan_locator_hmac(
                operation_target,
                role=OperationLocatorRole.TARGET,
                locator_mode=plan.locator_mode,
            )
            if (
                not hmac.compare_digest(
                    plan.source_locator_hmac_sha256,
                    expected_source,
                )
                or not hmac.compare_digest(
                    plan.target_locator_hmac_sha256,
                    expected_target,
                )
            ):
                raise CopyLedgerError(
                    CopyLedgerCode.INVALID_REQUEST,
                    "publish operation locators differ from the exact relative pair",
                )
        elif publish_transaction_id is not None:
            raise CopyLedgerError(
                CopyLedgerCode.INVALID_REQUEST,
                "unstarted publish operation cannot claim a transaction",
            )
        return self._publish_operation_binding_from_plan(
            plan=plan,
            transaction_binding_sha256=transaction_binding_sha256,
            copy_binding_sha256=copy_binding_sha256,
            source_anchor=source_anchor,
            copy_audit_ancestor_sha256=copy_audit_ancestor_sha256,
            target_locator=target_locator,
        )

    def _publish_operation_binding_from_plan(
        self,
        *,
        plan: CopyPublishOperationPlan,
        transaction_binding_sha256: str,
        copy_binding_sha256: str,
        source_anchor: CopySourceAnchor,
        copy_audit_ancestor_sha256: str,
        target_locator: CopyLocator,
    ) -> str:
        if (
            type(plan) is not CopyPublishOperationPlan
            or type(source_anchor) is not CopySourceAnchor
            or type(target_locator) is not CopyLocator
            or target_locator.mode is not CopyLocatorMode.HMAC_ONLY
        ):
            raise CopyLedgerError(
                CopyLedgerCode.INVALID_REQUEST,
                "publish operation binding values are not exact",
            )
        fields: dict[str, Any] = {
            "copy_binding_sha256": _require_sha256(
                copy_binding_sha256,
                "copy_binding_sha256",
                nonzero=True,
            ),
            "copy_audit_ancestor_sha256": _require_sha256(
                copy_audit_ancestor_sha256,
                "copy_audit_ancestor_sha256",
                nonzero=True,
            ),
            "operation_plan": plan.to_binding_json(),
            "source_anchor": source_anchor.to_json(),
            "target_locator_hmac_sha256": target_locator.value,
            "transaction_binding_sha256": _require_sha256(
                transaction_binding_sha256,
                "transaction_binding_sha256",
                nonzero=True,
            ),
        }
        return self._binding_hmac(
            b"COPY-PUBLISH-OPERATION-BINDING-V2",
            fields,
        )

    def _operation_reference_hmac(self, value: str) -> str:
        canonical = _safe_id(value, "operation_reference")
        return self._binding_hmac(
            b"COPY-EXPECTED-OPERATION-REFERENCE-V1",
            {"operation_reference": canonical},
        )

    def _publish_pair_reference_hmac(self, value: str) -> str:
        canonical = _safe_id(value, "publish_pair_reference")
        return self._binding_hmac(
            b"COPY-EXPECTED-PUBLISH-PAIR-V1",
            {"publish_pair_reference": canonical},
        )

    def _operation_plan_locator_hmac(
        self,
        value: str,
        *,
        role: OperationLocatorRole,
        locator_mode: OperationLocatorMode,
    ) -> str:
        if type(role) is not OperationLocatorRole or type(locator_mode) is not OperationLocatorMode:
            raise CopyLedgerError(
                CopyLedgerCode.INVALID_REQUEST,
                "operation plan locator projection requires exact typed semantics",
            )
        canonical = (
            _safe_relative(value, "operation_plan_safe_relative_locator")
            if locator_mode is OperationLocatorMode.SAFE_RELATIVE
            else _require_sha256(
                value,
                "operation_plan_operation_locator_hmac_sha256",
                nonzero=True,
            )
        )
        return self._binding_hmac(
            b"COPY-OPERATION-PLAN-LOCATOR-V1",
            {
                "locator_mode": locator_mode.value,
                "operation_locator": canonical,
                "role": role.value,
            },
        )

    def _project_publish_operation_plan(
        self,
        *,
        kind: CopyPublishPlanKind,
        operation_reference: str,
        context_binding_sha256: str,
        manifest_sha256: str,
        budget_sha256: str,
        classification: DataClassification,
        publish_transaction_id: str | None = None,
        pair_reference: str | None = None,
        locator_mode: OperationLocatorMode | None = None,
        source_locator: str | None = None,
        target_locator: str | None = None,
        source_evidence: OperationTreeEvidence | None = None,
        audit_ancestor_sha256: str | None = None,
    ) -> CopyPublishOperationPlan:
        """Project transient Operation facts into a Copy-keyed persisted plan."""

        if type(kind) is not CopyPublishPlanKind or type(classification) is not DataClassification:
            raise CopyLedgerError(
                CopyLedgerCode.INVALID_REQUEST,
                "publish operation projection types are not exact",
            )
        reserved = (
            publish_transaction_id,
            pair_reference,
            locator_mode,
            source_locator,
            target_locator,
            source_evidence,
            audit_ancestor_sha256,
        )
        if kind is CopyPublishPlanKind.UNSTARTED:
            if any(value is not None for value in reserved):
                raise CopyLedgerError(
                    CopyLedgerCode.INVALID_REQUEST,
                    "unstarted projection cannot include reservation facts",
                )
            transaction_hmac = None
            pair_hmac = None
            source_hmac = None
            target_hmac = None
        else:
            if (
                type(publish_transaction_id) is not str
                or type(pair_reference) is not str
                or type(locator_mode) is not OperationLocatorMode
                or type(source_locator) is not str
                or type(target_locator) is not str
                or type(source_evidence) is not OperationTreeEvidence
                or type(audit_ancestor_sha256) is not str
            ):
                raise CopyLedgerError(
                    CopyLedgerCode.INVALID_REQUEST,
                    "reserved projection requires every exact transient fact",
                )
            publish_transaction_id = _opaque_publish_transaction_id(
                publish_transaction_id
            )
            expected_mode = (
                OperationLocatorMode.HMAC_ONLY
                if classification is DataClassification.RESTRICTED
                else OperationLocatorMode.SAFE_RELATIVE
            )
            if locator_mode is not expected_mode:
                raise CopyLedgerError(
                    CopyLedgerCode.INVALID_REQUEST,
                    "projection classification and locator mode differ",
                )
            transaction_hmac = self._publish_transaction_reference_hmac(
                publish_transaction_id
            )
            pair_hmac = self._publish_pair_reference_hmac(pair_reference)
            source_hmac = self._operation_plan_locator_hmac(
                source_locator,
                role=OperationLocatorRole.SOURCE,
                locator_mode=locator_mode,
            )
            target_hmac = self._operation_plan_locator_hmac(
                target_locator,
                role=OperationLocatorRole.TARGET,
                locator_mode=locator_mode,
            )
        return CopyPublishOperationPlan(
            kind=kind,
            operation_reference_hmac_sha256=self._operation_reference_hmac(
                operation_reference
            ),
            context_binding_sha256=context_binding_sha256,
            manifest_sha256=manifest_sha256,
            budget_sha256=budget_sha256,
            classification=classification,
            publish_transaction_reference_hmac_sha256=transaction_hmac,
            pair_reference_hmac_sha256=pair_hmac,
            locator_mode=locator_mode,
            source_locator_hmac_sha256=source_hmac,
            target_locator_hmac_sha256=target_hmac,
            source_evidence=source_evidence,
            audit_ancestor_sha256=audit_ancestor_sha256,
        )

    def _project_operation_transition(
        self,
        transition: OperationTransition,
        *,
        audit_ancestor_sha256: str | None = None,
    ) -> CopyPublishOperationPlan:
        if type(transition) is not OperationTransition:
            raise CopyLedgerError(
                CopyLedgerCode.INVALID_REQUEST,
                "operation transition projection requires an exact fact",
            )
        return self._project_publish_operation_plan(
            kind=CopyPublishPlanKind.RESERVED,
            operation_reference=transition.operation_id,
            context_binding_sha256=transition.context_binding_sha256,
            manifest_sha256=transition.manifest_sha256,
            budget_sha256=transition.budget_sha256,
            classification=transition.classification,
            publish_transaction_id=transition.transaction_id,
            pair_reference=transition.pair_id,
            locator_mode=transition.locator_mode,
            source_locator=transition.source_locator,
            target_locator=transition.target_locator,
            source_evidence=transition.source_evidence,
            audit_ancestor_sha256=(
                transition.audit_ledger_head_sha256
                if audit_ancestor_sha256 is None
                else audit_ancestor_sha256
            ),
        )

    def _operation_epoch_reference_hmac(self, value: str) -> str:
        canonical = _safe_id(value, "operation_epoch_id")
        return self._binding_hmac(
            b"COPY-OPERATION-EPOCH-REFERENCE-V1",
            {"operation_epoch_id": canonical},
        )

    def _publish_transaction_reference_hmac(self, value: str) -> str:
        canonical = _safe_id(value, "publish_transaction_id")
        return self._binding_hmac(
            b"COPY-EXPECTED-PUBLISH-TRANSACTION-V1",
            {"publish_transaction_id": canonical},
        )

    def _absence_witness_authenticator(
        self,
        witness: CopyOperationAbsenceWitness,
        *,
        transaction_binding_sha256: str,
        copy_binding_sha256: str,
        publish_operation_binding_sha256: str,
    ) -> str:
        if type(witness) is not CopyOperationAbsenceWitness:
            raise CopyLedgerError(
                CopyLedgerCode.INVALID_REQUEST,
                "operation absence witness is not exact",
            )
        return self._binding_hmac(
            b"COPY-OPERATION-ABSENCE-WITNESS-V1",
            {
                "copy_binding_sha256": _require_sha256(
                    copy_binding_sha256,
                    "copy_binding_sha256",
                    nonzero=True,
                ),
                "publish_operation_binding_sha256": _require_sha256(
                    publish_operation_binding_sha256,
                    "publish_operation_binding_sha256",
                    nonzero=True,
                ),
                "transaction_binding_sha256": _require_sha256(
                    transaction_binding_sha256,
                    "transaction_binding_sha256",
                    nonzero=True,
                ),
                "witness": witness.unsigned_json(),
            },
        )

    def _issue_operation_absence_witness_under_existing_mutex(
        self,
        lease: RuntimeMutexLease,
        operation_ledger: DurableOperationLedger,
        *,
        plan: CopyPublishOperationPlan,
        operation_reference: str,
        publish_transaction_id: str | None,
        transaction_binding_sha256: str,
        copy_binding_sha256: str,
        source_anchor: CopySourceAnchor,
        copy_audit_ancestor_sha256: str,
        target_locator: CopyLocator,
        source_relative_locator: str,
        target_relative_locator: str,
        publish_operation_binding_sha256: str,
    ) -> CopyOperationAbsenceWitness:
        """Authenticate an exact operation-chain prefix before an abort append."""

        with self._lock:
            self._require_open()
            self._require_mutex(lease)
            if (
                type(operation_ledger) is not DurableOperationLedger
                or operation_ledger._storage is not self._storage
                or type(plan) is not CopyPublishOperationPlan
            ):
                raise CopyLedgerError(
                    CopyLedgerCode.INVALID_REQUEST,
                    "operation absence witness requires exact co-located ledgers",
                )
            expected_publish_binding = self.publish_operation_binding(
                plan=plan,
                operation_reference=operation_reference,
                publish_transaction_id=publish_transaction_id,
                transaction_binding_sha256=transaction_binding_sha256,
                copy_binding_sha256=copy_binding_sha256,
                source_anchor=source_anchor,
                copy_audit_ancestor_sha256=copy_audit_ancestor_sha256,
                target_locator=target_locator,
                source_relative_locator=source_relative_locator,
                target_relative_locator=target_relative_locator,
                operation_ledger=operation_ledger,
            )
            if not hmac.compare_digest(
                publish_operation_binding_sha256,
                expected_publish_binding,
            ):
                raise CopyLedgerError(
                    CopyLedgerCode.CROSS_REFERENCE_INVALID,
                    "operation absence witness publish plan differs",
                )
            try:
                operation_ledger._rescan_under_existing_mutex(lease)
                histories = operation_ledger._transaction_history
                if type(histories) is not dict:
                    raise ValueError("operation typed inventory is unavailable")
                for history in histories.values():
                    if type(history) not in {tuple, list} or not history:
                        raise ValueError("operation typed inventory is malformed")
                    first = history[0]
                    if type(first) is not OperationTransition:
                        raise ValueError("operation typed inventory is malformed")
                    if hmac.compare_digest(
                        plan.operation_reference_hmac_sha256,
                        self._operation_reference_hmac(first.operation_id),
                    ):
                        raise ValueError("expected operation is present")
                    expected_transaction_hmac = (
                        plan.publish_transaction_reference_hmac_sha256
                    )
                    if (
                        expected_transaction_hmac is not None
                        and hmac.compare_digest(
                            expected_transaction_hmac,
                            self._publish_transaction_reference_hmac(
                                first.transaction_id
                            ),
                        )
                    ):
                        raise ValueError("expected publish transaction is present")
                inventory = (
                    operation_ledger.authenticated_segment_sha256s_under_existing_mutex(
                        lease
                    )
                )
                head = operation_ledger.head
            except (OperationLedgerError, ValueError):
                raise CopyLedgerError(
                    CopyLedgerCode.CROSS_REFERENCE_INVALID,
                    "expected publish operation is not absent",
                ) from None
            if (
                not self._is_exact_ancestor_inventory(inventory)
                or len(inventory) != head.segment_count
                or inventory[-1] != head.last_segment_sha256
            ):
                raise CopyLedgerError(
                    CopyLedgerCode.CROSS_REFERENCE_INVALID,
                    "operation absence observation is not an exact authenticated head",
                )
            unsigned = CopyOperationAbsenceWitness(
                operation_epoch_reference_hmac_sha256=(
                    self._operation_epoch_reference_hmac(head.epoch_id)
                ),
                observation_head_sha256=head.last_segment_sha256,
                observation_segment_count=head.segment_count,
                expected_operation_reference_hmac_sha256=(
                    plan.operation_reference_hmac_sha256
                ),
                expected_publish_transaction_hmac_sha256=(
                    plan.publish_transaction_reference_hmac_sha256
                ),
                authenticator_sha256="1" * 64,
            )
            authenticator = self._absence_witness_authenticator(
                unsigned,
                transaction_binding_sha256=transaction_binding_sha256,
                copy_binding_sha256=copy_binding_sha256,
                publish_operation_binding_sha256=(
                    publish_operation_binding_sha256
                ),
            )
            return replace(unsigned, authenticator_sha256=authenticator)

    def _binding_hmac(self, domain: bytes, fields: dict[str, Any]) -> str:
        with self._lock:
            self._require_open()
            return hmac.new(
                self._copy_chain.auth_key,
                domain
                + b"\0"
                + self._epoch_id.encode("ascii")
                + b"\0"
                + self._run_scope_hmac_sha256.encode("ascii")
                + b"\0"
                + canonical_json_bytes(fields),
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
        self._scan_pair_under_mutex(startup_abandoned=lease.abandoned, allow_empty=initialize)
        if initialize:
            if self._source_chain.segments or self._copy_chain.segments:
                raise CopyLedgerError(CopyLedgerCode.INVALID_REQUEST, "copy ledger initialization requires two empty stores")
            created = _validate_utc_seconds(initialized_at_utc or _now_utc_seconds())
            self._publish_genesis(self._source_chain, created)
            self._publish_genesis(self._copy_chain, created)
            self._scan_pair_under_mutex(startup_abandoned=lease.abandoned, allow_empty=False)
        elif not self._source_chain.segments or not self._copy_chain.segments:
            raise CopyLedgerError(CopyLedgerCode.CHAIN_CORRUPT, "copy ledger pair is missing genesis")

    def _publish_genesis(self, chain: _CopyChain, created_at_utc: str) -> None:
        payload, segment_sha = chain.build_segment(
            sequence=0,
            previous=None,
            created_at_utc=created_at_utc,
            segment_kind="GENESIS",
            record=None,
        )
        chain.publish(0, segment_sha, payload)

    def _select_persisted_revision_under_mutex(self) -> None:
        selected: list[str] = []
        for config in (_CONFIGS[CopyLedgerKind.COPY_SOURCE], _CONFIGS[CopyLedgerKind.COPY_OPERATION]):
            try:
                snapshot = self._storage.read_flat_directory(
                    config.root / self._epoch_id,
                    maximum_entries=_MAX_SEGMENTS,
                    maximum_file_bytes=_MAX_SEGMENT_BYTES,
                    maximum_total_bytes=_MAX_LEDGER_BYTES,
                )
            except HandleWriterError as exc:
                raise CopyLedgerError(CopyLedgerCode.STORAGE_FAILURE, "copy genesis cannot be read for key selection") from exc
            genesis_payloads: list[bytes] = []
            for entry in snapshot.entries:
                match = _SEGMENT_FILE.fullmatch(entry.name)
                if match is None:
                    raise CopyLedgerError(CopyLedgerCode.UNKNOWN_ENTRY, "copy store contains an unknown or pending entry")
                if int(match.group("sequence")) == 0:
                    genesis_payloads.append(entry.payload)
            if len(genesis_payloads) != 1:
                raise CopyLedgerError(CopyLedgerCode.CHAIN_CORRUPT, "copy store requires exactly one genesis")
            try:
                value = parse_canonical_json_bytes(genesis_payloads[0], maximum_bytes=_MAX_SEGMENT_BYTES)
                revision_id = value["key_revision_id"]
                _safe_id(revision_id, "key_revision_id")
            except (KeyError, LedgerError, CopyLedgerError):
                raise CopyLedgerError(CopyLedgerCode.CHAIN_CORRUPT, "copy genesis cannot select a key") from None
            selected.append(revision_id)
        if len(set(selected)) != 1:
            raise CopyLedgerError(CopyLedgerCode.CROSS_REFERENCE_INVALID, "copy ledgers select different key revisions")
        revision = self._known_revisions.get(selected[0])
        if revision is None:
            raise CopyLedgerError(CopyLedgerCode.AUTHENTICATION_FAILED, "copy genesis key revision is unavailable")
        self._revision = revision
        self._append_enabled = revision.revision_id == self._requested_revision_id
        self._run_scope_hmac_sha256 = self._derive_run_scope_hmac(revision)
        self._configure_chains()

    def _rescan_under_existing_mutex(self, lease: RuntimeMutexLease) -> CopyLedgersHead:
        self._require_mutex(lease)
        with self._lock:
            self._require_open()
            try:
                self._scan_pair_under_mutex(startup_abandoned=lease.abandoned, allow_empty=False)
            except CopyLedgerError as exc:
                self._seal(exc.code)
                raise
            return self.head

    def _scan_pair_under_mutex(self, *, startup_abandoned: bool, allow_empty: bool) -> None:
        source_segments = self._source_chain.scan(allow_empty=allow_empty, startup_abandoned=startup_abandoned)
        copy_segments = self._copy_chain.scan(allow_empty=allow_empty, startup_abandoned=startup_abandoned)
        if bool(source_segments) != bool(copy_segments):
            raise CopyLedgerError(CopyLedgerCode.CROSS_REFERENCE_INVALID, "copy ledger genesis is asymmetric")
        source_records: dict[str, CopySourceRecord] = {}
        source_by_transaction: dict[str, CopySourceRecord] = {}
        source_receipts: dict[str, CopySourceReceipt] = {}
        for segment in source_segments[1:]:
            record = segment.record
            if type(record) is not CopySourceRecord or segment.record_sha256 is None:
                raise CopyLedgerError(CopyLedgerCode.CHAIN_CORRUPT, "source chain contains a non-source record")
            if record.record_id in source_records or record.transaction_binding_sha256 in source_by_transaction:
                raise CopyLedgerError(CopyLedgerCode.RECORD_CONFLICT, "source chain repeats a record or transaction binding")
            if any(existing.copy_binding_sha256 == record.copy_binding_sha256 for existing in source_records.values()):
                raise CopyLedgerError(CopyLedgerCode.RECORD_CONFLICT, "source chain repeats a copy binding")
            source_records[record.record_id] = record
            source_by_transaction[record.transaction_binding_sha256] = record
            source_receipts[record.record_id] = CopySourceReceipt(
                epoch_id=self._epoch_id,
                sequence=segment.sequence,
                segment_sha256=segment.segment_sha256,
                record_id=record.record_id,
                record_sha256=segment.record_sha256,
            )
        histories: dict[str, list[CopyTransition]] = {}
        transition_receipts: dict[str, CopyTransitionReceipt] = {}
        for segment in copy_segments[1:]:
            transition = segment.record
            if type(transition) is not CopyTransition or segment.record_sha256 is None:
                raise CopyLedgerError(CopyLedgerCode.CHAIN_CORRUPT, "copy chain contains a non-transition record")
            if transition.transition_id in transition_receipts:
                raise CopyLedgerError(CopyLedgerCode.TRANSITION_CONFLICT, "copy chain repeats a transition ID")
            self._validate_source_cross_reference(transition, source_records, source_receipts)
            history = histories.setdefault(transition.transaction_binding_sha256, [])
            self._validate_history_append(tuple(history), transition, histories)
            history.append(transition)
            transition_receipts[transition.transition_id] = CopyTransitionReceipt(
                epoch_id=self._epoch_id,
                sequence=segment.sequence,
                segment_sha256=segment.segment_sha256,
                transition_id=transition.transition_id,
                transition_sha256=segment.record_sha256,
                transaction_binding_sha256=transition.transaction_binding_sha256,
                state=transition.next_state,
            )
        self._source_records = source_records
        self._source_by_transaction = source_by_transaction
        self._source_receipts = source_receipts
        self._copy_histories = {key: tuple(value) for key, value in histories.items()}
        self._transition_receipts = transition_receipts
        self._require_copy_reservation_capacity()

    def _validate_source_cross_reference(
        self,
        transition: CopyTransition,
        records: dict[str, CopySourceRecord],
        receipts: dict[str, CopySourceReceipt],
    ) -> None:
        source = records.get(transition.source_anchor.record_id)
        receipt = receipts.get(transition.source_anchor.record_id)
        material: CopyProvenanceMaterial | None = None
        if source is not None and receipt is not None:
            try:
                material = build_copy_provenance_material(
                    source,
                    receipt,
                    manifest_id=_COPY_PROVENANCE_VALIDATION_MANIFEST_ID,
                )
            except CopyLedgerError:
                material = None
        if (
            source is None
            or receipt is None
            or material is None
            or receipt.anchor != transition.source_anchor
            or transition.transaction_binding_sha256 != source.transaction_binding_sha256
            or transition.copy_binding_sha256 != source.copy_binding_sha256
            or transition.audit_ancestor_sha256 != source.audit_ancestor_sha256
            or transition.classification is not source.classification
            or transition.provenance_metadata_sha256
            != material.provenance_sha256
            or transition.expected_manifest_sha256
            != material.publish_manifest.manifest_sha256
            or (
                transition.target_evidence is not None
                and (
                    transition.target_evidence.payload.size_bytes != source.source_evidence.size_bytes
                    or transition.target_evidence.payload.sha256 != source.source_evidence.sha256
                    or transition.target_evidence.provenance.size_bytes
                    != len(material.provenance_bytes)
                    or transition.target_evidence.provenance.sha256
                    != material.provenance_sha256
                )
            )
        ):
            raise CopyLedgerError(CopyLedgerCode.CROSS_REFERENCE_INVALID, "copy transition source ancestry is invalid")

    def _validate_history_append(
        self,
        history: tuple[CopyTransition, ...],
        transition: CopyTransition,
        all_histories: dict[str, list[CopyTransition]] | dict[str, tuple[CopyTransition, ...]],
    ) -> None:
        projected_transaction = (
            None
            if transition.publish_transaction_id is None
            else self._publish_transaction_reference_hmac(
                transition.publish_transaction_id
            )
        )
        if (
            transition.publish_operation_plan.publish_transaction_reference_hmac_sha256
            != projected_transaction
        ):
            raise CopyLedgerError(
                CopyLedgerCode.CROSS_REFERENCE_INVALID,
                "copy transition publish transaction projection differs",
            )
        if not history:
            if transition.previous_state is not None or transition.next_state not in {
                CopyState.PREPARED,
                CopyState.RECOVERED_ABORT,
            }:
                raise CopyLedgerError(
                    CopyLedgerCode.ILLEGAL_TRANSITION,
                    "copy transaction must begin at PREPARED or a proven source-only recovery abort",
                )
            if any(
                existing and existing[0].copy_binding_sha256 == transition.copy_binding_sha256
                for key, existing in all_histories.items()
                if key != transition.transaction_binding_sha256
            ):
                raise CopyLedgerError(CopyLedgerCode.TRANSITION_CONFLICT, "copy binding is already assigned")
            if any(
                existing and existing[0].target_locator == transition.target_locator
                for key, existing in all_histories.items()
                if key != transition.transaction_binding_sha256
            ):
                raise CopyLedgerError(CopyLedgerCode.TRANSITION_CONFLICT, "copy target locator is already assigned")
            return
        previous = history[-1]
        if previous.next_state in _TERMINAL_STATES:
            raise CopyLedgerError(CopyLedgerCode.ILLEGAL_TRANSITION, "terminal copy transaction cannot advance")
        stable = (
            "copy_binding_sha256", "source_anchor", "audit_ancestor_sha256",
            "classification", "target_locator", "expected_manifest_sha256",
            "provenance_metadata_sha256", "budget_sha256",
            "publish_operation_binding_sha256",
            "publish_operation_plan",
        )
        if transition.previous_state is not previous.next_state or any(
            getattr(transition, name) != getattr(previous, name) for name in stable
        ):
            raise CopyLedgerError(CopyLedgerCode.TRANSITION_CONFLICT, "copy transition changed immutable PREPARED bindings")
        if previous.mutation_attempted and not transition.mutation_attempted:
            raise CopyLedgerError(CopyLedgerCode.TRANSITION_CONFLICT, "copy transition reversed mutation evidence")
        if transition.publish_transaction_id != previous.publish_transaction_id:
            raise CopyLedgerError(
                CopyLedgerCode.TRANSITION_CONFLICT,
                "copy transition changed its exact publish transaction",
            )
        if previous.publish_terminal_segment_sha256 is not None and (
            transition.publish_terminal_segment_sha256 != previous.publish_terminal_segment_sha256
        ):
            raise CopyLedgerError(CopyLedgerCode.TRANSITION_CONFLICT, "copy transition changed publish ancestry")
        if previous.publish_terminal_state is not None and (
            transition.publish_terminal_state is not previous.publish_terminal_state
        ):
            raise CopyLedgerError(
                CopyLedgerCode.TRANSITION_CONFLICT,
                "copy transition changed typed publish terminal state",
            )
        if previous.publish_operation_absence_witness is not None and (
            transition.publish_operation_absence_witness
            != previous.publish_operation_absence_witness
        ):
            raise CopyLedgerError(
                CopyLedgerCode.TRANSITION_CONFLICT,
                "copy transition changed operation absence ancestry",
            )
        if previous.target_evidence is not None and transition.target_evidence != previous.target_evidence:
            raise CopyLedgerError(CopyLedgerCode.TRANSITION_CONFLICT, "copy transition changed target evidence")

    def _remaining_copy_segments(self, history: tuple[CopyTransition, ...] | None) -> int:
        if not history:
            return _COPY_LIFECYCLE_SEGMENTS
        state = history[-1].next_state
        return {
            CopyState.PREPARED: 4,
            CopyState.MUTATED: 3,
            CopyState.POSTCONDITION_VERIFIED: 2,
            CopyState.IN_DOUBT: 1,
        }.get(state, 0)

    def _pending_source_count(self) -> int:
        return sum(
            1
            for transaction in self._source_by_transaction
            if self._remaining_copy_segments(self._copy_histories.get(transaction)) > 0
        )

    def _require_copy_reservation_capacity(
        self,
        *,
        prospective_histories: dict[str, tuple[CopyTransition, ...]] | None = None,
        prospective_payload_bytes: int = 0,
        prospective_source: CopySourceRecord | None = None,
    ) -> None:
        histories = prospective_histories if prospective_histories is not None else self._copy_histories
        transactions = set(self._source_by_transaction)
        if prospective_source is not None:
            transactions.add(prospective_source.transaction_binding_sha256)
        remaining = sum(self._remaining_copy_segments(histories.get(item)) for item in transactions)
        if (
            len(self._copy_chain.segments) + (1 if prospective_payload_bytes else 0) + remaining > _MAX_SEGMENTS
            or self._copy_chain.total_bytes
            + prospective_payload_bytes
            + remaining * _MAX_COPY_TRANSITION_SEGMENT_BYTES
            > _MAX_LEDGER_BYTES
        ):
            raise CopyLedgerError(CopyLedgerCode.RESOURCE_LIMIT, "copy ledger lacks reserved capacity for every pending lifecycle")

    def _append_source_under_existing_mutex(
        self,
        lease: RuntimeMutexLease,
        record: CopySourceRecord,
        *,
        created_at_utc: str | None = None,
    ) -> CopySourceReceipt:
        self._require_mutex(lease)
        if type(record) is not CopySourceRecord:
            raise CopyLedgerError(CopyLedgerCode.INVALID_REQUEST, "source append requires an exact record")
        created = _validate_utc_seconds(created_at_utc or _now_utc_seconds())
        with self._lock:
            self._require_open()
            try:
                self._scan_pair_under_mutex(
                    startup_abandoned=False,
                    allow_empty=False,
                )
            except CopyLedgerError as exc:
                self._seal(exc.code)
                raise
            replay = self._source_receipts.get(record.record_id)
            if replay is not None:
                if self._source_records.get(record.record_id) != record:
                    self._seal(CopyLedgerCode.RECORD_CONFLICT)
                    raise CopyLedgerError(CopyLedgerCode.RECORD_CONFLICT, "source record replay differs")
                return replace(replay, replayed=True)
            self._require_append_revision_current(lease)
            if (
                record.transaction_binding_sha256 in self._source_by_transaction
                or any(item.copy_binding_sha256 == record.copy_binding_sha256 for item in self._source_records.values())
            ):
                raise CopyLedgerError(CopyLedgerCode.RECORD_CONFLICT, "source transaction or copy binding already exists")
            head = self._source_chain.head
            payload, segment_sha = self._source_chain.build_segment(
                sequence=head.last_sequence + 1,
                previous=head.last_segment_sha256,
                created_at_utc=created,
                segment_kind="SOURCE_OBSERVED",
                record=record,
            )
            if (
                len(payload) > _MAX_SOURCE_SEGMENT_BYTES
                or len(self._source_chain.segments) + 1 > _MAX_SEGMENTS
                or self._source_chain.total_bytes + len(payload) > _MAX_LEDGER_BYTES
            ):
                raise CopyLedgerError(CopyLedgerCode.RESOURCE_LIMIT, "source ledger lacks capacity")
            self._require_copy_reservation_capacity(prospective_source=record)
            try:
                self._source_chain.publish(head.last_sequence + 1, segment_sha, payload)
                self._scan_pair_under_mutex(startup_abandoned=False, allow_empty=False)
            except CopyLedgerError as exc:
                self._seal(exc.code)
                raise
            committed = self._source_receipts.get(record.record_id)
            if committed is None or committed.segment_sha256 != segment_sha:
                self._seal(CopyLedgerCode.STORAGE_FAILURE)
                raise CopyLedgerError(CopyLedgerCode.STORAGE_FAILURE, "published source record is absent after rescan")
            return committed

    def _append_transition_under_existing_mutex(
        self,
        lease: RuntimeMutexLease,
        transition: CopyTransition,
        *,
        created_at_utc: str | None = None,
    ) -> CopyTransitionReceipt:
        self._require_mutex(lease)
        if type(transition) is not CopyTransition:
            raise CopyLedgerError(CopyLedgerCode.INVALID_REQUEST, "copy append requires an exact transition")
        created = _validate_utc_seconds(created_at_utc or _now_utc_seconds())
        with self._lock:
            self._require_open()
            try:
                self._scan_pair_under_mutex(
                    startup_abandoned=False,
                    allow_empty=False,
                )
            except CopyLedgerError as exc:
                self._seal(exc.code)
                raise
            replay = self._transition_receipts.get(transition.transition_id)
            if replay is not None:
                existing = next(
                    (item for history in self._copy_histories.values() for item in history if item.transition_id == transition.transition_id),
                    None,
                )
                if existing != transition:
                    self._seal(CopyLedgerCode.TRANSITION_CONFLICT)
                    raise CopyLedgerError(CopyLedgerCode.TRANSITION_CONFLICT, "copy transition replay differs")
                return replace(replay, replayed=True)
            self._require_transition_append_allowed(lease, transition)
            self._validate_source_cross_reference(transition, self._source_records, self._source_receipts)
            history = self._copy_histories.get(transition.transaction_binding_sha256, ())
            self._validate_history_append(history, transition, self._copy_histories)
            head = self._copy_chain.head
            payload, segment_sha = self._copy_chain.build_segment(
                sequence=head.last_sequence + 1,
                previous=head.last_segment_sha256,
                created_at_utc=created,
                segment_kind="COPY_TRANSITION",
                record=transition,
            )
            if len(payload) > _MAX_COPY_TRANSITION_SEGMENT_BYTES:
                raise CopyLedgerError(CopyLedgerCode.RESOURCE_LIMIT, "copy transition exceeds its fixed byte limit")
            prospective = dict(self._copy_histories)
            prospective[transition.transaction_binding_sha256] = history + (transition,)
            self._require_copy_reservation_capacity(
                prospective_histories=prospective,
                prospective_payload_bytes=len(payload),
            )
            try:
                self._copy_chain.publish(head.last_sequence + 1, segment_sha, payload)
                self._scan_pair_under_mutex(startup_abandoned=False, allow_empty=False)
            except CopyLedgerError as exc:
                self._seal(exc.code)
                raise
            committed = self._transition_receipts.get(transition.transition_id)
            if committed is None or committed.segment_sha256 != segment_sha:
                self._seal(CopyLedgerCode.STORAGE_FAILURE)
                raise CopyLedgerError(CopyLedgerCode.STORAGE_FAILURE, "published copy transition is absent after rescan")
            return committed

    def source_result_under_existing_mutex(
        self,
        lease: RuntimeMutexLease,
        record_id: str,
    ) -> tuple[CopySourceRecord, CopySourceReceipt] | None:
        _require_sha256(record_id, "record_id", nonzero=True)
        self._rescan_under_existing_mutex(lease)
        record = self._source_records.get(record_id)
        receipt = self._source_receipts.get(record_id)
        return None if record is None or receipt is None else (record, receipt)

    def transaction_source_result_under_existing_mutex(
        self,
        lease: RuntimeMutexLease,
        transaction_binding_sha256: str,
    ) -> tuple[CopySourceRecord, CopySourceReceipt] | None:
        _require_sha256(
            transaction_binding_sha256,
            "transaction_binding_sha256",
            nonzero=True,
        )
        self._rescan_under_existing_mutex(lease)
        record = self._source_by_transaction.get(transaction_binding_sha256)
        if record is None:
            return None
        receipt = self._source_receipts.get(record.record_id)
        if receipt is None:
            self._seal(CopyLedgerCode.CHAIN_CORRUPT)
            raise CopyLedgerError(
                CopyLedgerCode.CHAIN_CORRUPT,
                "copy source receipt is missing",
            )
        return record, receipt

    def transaction_result_under_existing_mutex(
        self,
        lease: RuntimeMutexLease,
        transaction_binding_sha256: str,
    ) -> tuple[CopyTransition, CopyTransitionReceipt] | None:
        _require_sha256(transaction_binding_sha256, "transaction_binding_sha256", nonzero=True)
        self._rescan_under_existing_mutex(lease)
        history = self._copy_histories.get(transaction_binding_sha256)
        if not history:
            return None
        transition = history[-1]
        receipt = self._transition_receipts.get(transition.transition_id)
        if receipt is None:
            self._seal(CopyLedgerCode.CHAIN_CORRUPT)
            raise CopyLedgerError(CopyLedgerCode.CHAIN_CORRUPT, "copy transition receipt is missing")
        return transition, receipt

    def bound_audit_ancestors_under_existing_mutex(self, lease: RuntimeMutexLease) -> tuple[str, ...]:
        self._rescan_under_existing_mutex(lease)
        values = {item.audit_ancestor_sha256 for item in self._source_records.values()}
        values.update(
            item.publish_operation_plan.audit_ancestor_sha256
            for history in self._copy_histories.values()
            for item in history
            if item.publish_operation_plan.audit_ancestor_sha256 is not None
        )
        values.update(
            item.recovery_authority_head_sha256
            for history in self._copy_histories.values()
            for item in history
            if item.recovery_authority_head_sha256 is not None
        )
        return tuple(sorted(values))

    def bound_publish_terminals_under_existing_mutex(self, lease: RuntimeMutexLease) -> tuple[str, ...]:
        self._rescan_under_existing_mutex(lease)
        return tuple(
            sorted(
                {
                    item.publish_terminal_segment_sha256
                    for history in self._copy_histories.values()
                    for item in history
                    if item.publish_terminal_segment_sha256 is not None
                }
            )
        )

    def _persisted_publish_plan_audit_indexes(
        self,
        audit_inventory: tuple[str, ...],
        transition: CopyTransition,
    ) -> tuple[int, int | None]:
        if (
            not self._is_exact_ancestor_inventory(audit_inventory)
            or type(transition) is not CopyTransition
        ):
            raise ValueError("persisted publish plan audit inputs are invalid")
        try:
            source_audit_index = audit_inventory.index(
                transition.audit_ancestor_sha256
            )
        except ValueError:
            raise ValueError("copy source audit ancestor is absent") from None
        plan = transition.publish_operation_plan
        if plan.kind is CopyPublishPlanKind.UNSTARTED:
            return source_audit_index, None
        try:
            reservation_audit_index = audit_inventory.index(
                plan.audit_ancestor_sha256
            )
        except ValueError:
            raise ValueError("publish reservation audit ancestor is absent") from None
        if source_audit_index > reservation_audit_index:
            raise ValueError("publish reservation precedes its copy source")
        return source_audit_index, reservation_audit_index

    def _authenticate_persisted_publish_plan(
        self,
        audit_inventory: tuple[str, ...],
        transition: CopyTransition,
    ) -> tuple[
        CopySourceRecord,
        CopySourceReceipt,
        CopyProvenanceMaterial,
        int | None,
    ]:
        _, reservation_audit_index = self._persisted_publish_plan_audit_indexes(
            audit_inventory,
            transition,
        )
        source = self._source_by_transaction.get(
            transition.transaction_binding_sha256
        )
        source_receipt = (
            None if source is None else self._source_receipts.get(source.record_id)
        )
        if source is None or source_receipt is None:
            raise ValueError("copy source ancestry is absent")
        material = build_copy_provenance_material(
            source,
            source_receipt,
            manifest_id=_COPY_PROVENANCE_VALIDATION_MANIFEST_ID,
        )
        plan = transition.publish_operation_plan
        expected_binding = self._publish_operation_binding_from_plan(
            plan=plan,
            transaction_binding_sha256=transition.transaction_binding_sha256,
            copy_binding_sha256=transition.copy_binding_sha256,
            source_anchor=transition.source_anchor,
            copy_audit_ancestor_sha256=transition.audit_ancestor_sha256,
            target_locator=transition.target_locator,
        )
        plan_source = plan.source_evidence
        if (
            not hmac.compare_digest(
                transition.publish_operation_binding_sha256,
                expected_binding,
            )
            or transition.expected_manifest_sha256
            != material.publish_manifest.manifest_sha256
            or transition.provenance_metadata_sha256
            != material.provenance_sha256
            or (
                plan.kind is CopyPublishPlanKind.RESERVED
                and (
                    plan_source is None
                    or plan_source.entry_count != 2
                    or plan_source.total_bytes
                    != source.source_evidence.size_bytes
                    + len(material.provenance_bytes)
                )
            )
        ):
            raise ValueError("persisted publish plan authentication failed")
        return source, source_receipt, material, reservation_audit_index

    def _authenticated_publish_terminal_bindings_under_existing_mutex(
        self,
        lease: RuntimeMutexLease,
        operation_ledger: DurableOperationLedger,
        audit_inventory: tuple[str, ...],
    ) -> tuple[str, ...]:
        """Resolve terminal Copy facts against one exact operation epoch."""

        return self._authenticated_publish_terminal_bindings_for_epochs_under_existing_mutex(
            lease,
            (operation_ledger,),
            audit_inventory,
        )

    def _authenticated_publish_terminal_bindings_for_epochs_under_existing_mutex(
        self,
        lease: RuntimeMutexLease,
        operation_ledgers: tuple[DurableOperationLedger, ...],
        audit_inventory: tuple[str, ...],
    ) -> tuple[str, ...]:
        """Resolve every terminal Copy fact through one unique operation epoch."""

        self._require_mutex(lease)
        if (
            type(operation_ledgers) is not tuple
            or not operation_ledgers
            or any(
                type(item) is not DurableOperationLedger
                or item._storage is not self._storage
                for item in operation_ledgers
            )
            or not self._is_exact_ancestor_inventory(audit_inventory)
        ):
            raise CopyLedgerError(
                CopyLedgerCode.INVALID_REQUEST,
                "publish terminal authentication requires exact co-located operation epochs",
            )
        try:
            self._rescan_under_existing_mutex(lease)
            operation_epochs: dict[
                str,
                tuple[DurableOperationLedger, tuple[str, ...]],
            ] = {}
            segment_owners: dict[
                str,
                tuple[DurableOperationLedger, tuple[str, ...]],
            ] = {}
            epoch_reference_owners: dict[
                str,
                tuple[DurableOperationLedger, tuple[str, ...]],
            ] = {}
            for operation_ledger in operation_ledgers:
                operation_inventory = (
                    operation_ledger.authenticated_segment_sha256s_under_existing_mutex(
                        lease
                    )
                )
                operation_head = operation_ledger.head
                if (
                    not self._is_exact_ancestor_inventory(operation_inventory)
                    or operation_ledger.policy_digest != self._policy_digest
                    or operation_head.epoch_id in operation_epochs
                ):
                    raise ValueError("operation epoch inventory is not exact")
                owner = (operation_ledger, operation_inventory)
                operation_epochs[operation_head.epoch_id] = owner
                epoch_reference = self._operation_epoch_reference_hmac(
                    operation_head.epoch_id
                )
                if epoch_reference in epoch_reference_owners:
                    raise ValueError("operation epoch reference is ambiguous")
                epoch_reference_owners[epoch_reference] = owner
                for segment_sha256 in operation_inventory:
                    if segment_sha256 in segment_owners:
                        raise ValueError("operation segment belongs to multiple epochs")
                    segment_owners[segment_sha256] = owner
            terminal_bindings: list[str] = []
            for transaction_binding, history in sorted(self._copy_histories.items()):
                transition = history[-1]
                (
                    source,
                    _source_receipt,
                    material,
                    reservation_audit_index,
                ) = self._authenticate_persisted_publish_plan(
                    audit_inventory,
                    transition,
                )
                expected_manifest_sha256 = (
                    material.publish_manifest.manifest_sha256
                )
                terminal_sha256 = transition.publish_terminal_segment_sha256
                absence_witness = transition.publish_operation_absence_witness
                has_resolution = (
                    terminal_sha256 is not None or absence_witness is not None
                )
                if transition.next_state not in _TERMINAL_STATES and not has_resolution:
                    continue
                if terminal_sha256 is None:
                    if absence_witness is None:
                        raise ValueError("terminal Copy fact has no publish resolution")
                    owner = epoch_reference_owners.get(
                        absence_witness.operation_epoch_reference_hmac_sha256
                    )
                    if owner is None:
                        raise ValueError("operation absence epoch is missing")
                    operation_ledger, operation_inventory = owner
                    if (
                        operation_ledger.signing_revision_id
                        != self._revision.revision_id
                    ):
                        raise ValueError(
                            "operation absence epoch uses another signing revision"
                        )
                    terminal_bindings.append(
                        self._verify_operation_absence_witness_under_existing_mutex(
                            lease,
                            operation_ledger,
                            operation_inventory,
                            audit_inventory,
                            transition,
                            absence_witness,
                        )
                    )
                    continue
                owner = segment_owners.get(terminal_sha256)
                if owner is None:
                    raise ValueError("typed publish terminal epoch is missing")
                operation_ledger, operation_inventory = owner
                if (
                    operation_ledger.signing_revision_id
                    != self._revision.revision_id
                ):
                    raise ValueError(
                        "typed publish terminal epoch uses another signing revision"
                    )
                publish_transaction_id = transition.publish_transaction_id
                terminal_state = transition.publish_terminal_state
                if publish_transaction_id is None or terminal_state is None:
                    raise ValueError("terminal has no typed transaction")
                result = operation_ledger.transaction_result_under_existing_mutex(
                    lease,
                    publish_transaction_id,
                )
                if result is None:
                    raise ValueError("typed publish transaction is absent")
                operation, receipt = result
                if (
                    type(operation) is not OperationTransition
                    or type(receipt) is not OperationSegmentReceipt
                    or operation.next_state is not terminal_state
                    or operation.transaction_id != publish_transaction_id
                    or receipt.transaction_id != publish_transaction_id
                    or receipt.segment_sha256 != terminal_sha256
                    or receipt.transition_id != operation.transition_id
                    or receipt.transition_sha256 != operation.digest
                    or receipt.state is not operation.next_state
                ):
                    raise ValueError("typed publish terminal differs")
                stored_plan = transition.publish_operation_plan
                planned_operation = self._project_operation_transition(
                    operation,
                    audit_ancestor_sha256=stored_plan.audit_ancestor_sha256,
                )
                operation_source = operation.source_evidence
                operation_target = operation.target_evidence
                try:
                    operation_audit_index = audit_inventory.index(
                        operation.audit_ledger_head_sha256
                    )
                except ValueError:
                    raise ValueError("publish audit ancestor is absent") from None
                expected_operation_states = (
                    {OperationState.ABORTED, OperationState.RECOVERED_ABORT}
                    if transition.next_state
                    in {CopyState.ABORTED, CopyState.RECOVERED_ABORT}
                    else {OperationState.COMMITTED, OperationState.RECOVERED_COMMIT}
                )
                if (
                    terminal_state not in expected_operation_states
                    or stored_plan != planned_operation
                    or operation.manifest_sha256 != expected_manifest_sha256
                    or operation.budget_sha256 != transition.budget_sha256
                    or operation.classification is not transition.classification
                    or not hmac.compare_digest(
                        stored_plan.publish_transaction_reference_hmac_sha256,
                        self._publish_transaction_reference_hmac(
                            publish_transaction_id
                        ),
                    )
                    or reservation_audit_index is None
                    or reservation_audit_index > operation_audit_index
                    or (
                        operation.recovery_authority_head_sha256 is not None
                        and operation.recovery_authority_head_sha256
                        not in audit_inventory
                    )
                    or operation_source.manifest_sha256
                    != expected_manifest_sha256
                    or operation_source.entry_count != 2
                    or operation_source.total_bytes
                    != source.source_evidence.size_bytes
                    + len(material.provenance_bytes)
                ):
                    raise ValueError("typed publish semantics differ")
                committed_operation = terminal_state in {
                    OperationState.COMMITTED,
                    OperationState.RECOVERED_COMMIT,
                }
                if committed_operation != (
                    operation_target is not None
                    and operation_target == operation_source
                ):
                    raise ValueError("typed publish terminal tree semantics differ")
                if (
                    operation.locator_mode is OperationLocatorMode.SAFE_RELATIVE
                    and transition.target_locator
                    != self.target_locator(
                        operation.target_locator,
                        operation.classification,
                    )
                ):
                    raise ValueError("typed publish target locator differs")
                target = transition.target_evidence
                if target is not None and (
                    operation_target is None
                    or operation_target.manifest_sha256 != target.manifest_sha256
                    or operation_target.source_tree_sha256 != target.tree_sha256
                    or operation_target.topology_sha256 != target.topology_sha256
                    or operation_target.durable_identity_sha256
                    != target.tree_identity_hmac_sha256
                    or operation_target.entry_count != target.entry_count
                    or operation_target.total_bytes != target.total_bytes
                    or target.provenance.sha256 != material.provenance_sha256
                    or target.provenance.size_bytes != len(material.provenance_bytes)
                ):
                    raise ValueError("typed publish target evidence differs")
                terminal_bindings.append(
                    hashlib.sha256(
                        b"COPY-PUBLISH-TERMINAL-BINDING-V1\0"
                        + canonical_json_bytes(
                            {
                                "copy_transaction_binding_sha256": transaction_binding,
                                "copy_transition_sha256": transition.digest,
                                "operation_terminal_segment_sha256": receipt.segment_sha256,
                                "operation_terminal_state": operation.next_state.value,
                                "operation_transaction_id": operation.transaction_id,
                                "operation_transition_sha256": operation.digest,
                                "operation_tree_evidence_sha256": operation_source.digest,
                            }
                        )
                    ).hexdigest()
                )
            return tuple(terminal_bindings)
        except (CopyLedgerError, OperationLedgerError, ValueError):
            self._seal(CopyLedgerCode.CROSS_REFERENCE_INVALID)
            raise CopyLedgerError(
                CopyLedgerCode.CROSS_REFERENCE_INVALID,
                "copy publish terminal has no exact typed operation ancestor",
            ) from None

    def _verify_operation_absence_witness_under_existing_mutex(
        self,
        lease: RuntimeMutexLease,
        operation_ledger: DurableOperationLedger,
        operation_inventory: tuple[str, ...],
        audit_inventory: tuple[str, ...],
        transition: CopyTransition,
        witness: CopyOperationAbsenceWitness,
    ) -> str:
        self._require_mutex(lease)
        if (
            type(operation_ledger) is not DurableOperationLedger
            or operation_ledger._storage is not self._storage
            or not self._is_exact_ancestor_inventory(operation_inventory)
            or not self._is_exact_ancestor_inventory(audit_inventory)
            or type(transition) is not CopyTransition
            or type(witness) is not CopyOperationAbsenceWitness
            or transition.next_state
            not in {CopyState.ABORTED, CopyState.RECOVERED_ABORT}
        ):
            raise ValueError("operation absence witness inputs are invalid")
        self._persisted_publish_plan_audit_indexes(
            audit_inventory,
            transition,
        )
        expected_authenticator = self._absence_witness_authenticator(
            witness,
            transaction_binding_sha256=transition.transaction_binding_sha256,
            copy_binding_sha256=transition.copy_binding_sha256,
            publish_operation_binding_sha256=(
                transition.publish_operation_binding_sha256
            ),
        )
        expected_publish_binding = self._publish_operation_binding_from_plan(
            plan=transition.publish_operation_plan,
            transaction_binding_sha256=transition.transaction_binding_sha256,
            copy_binding_sha256=transition.copy_binding_sha256,
            source_anchor=transition.source_anchor,
            copy_audit_ancestor_sha256=transition.audit_ancestor_sha256,
            target_locator=transition.target_locator,
        )
        current_head = operation_ledger.head
        if (
            not hmac.compare_digest(
                witness.authenticator_sha256,
                expected_authenticator,
            )
            or not hmac.compare_digest(
                transition.publish_operation_binding_sha256,
                expected_publish_binding,
            )
            or not hmac.compare_digest(
                witness.operation_epoch_reference_hmac_sha256,
                self._operation_epoch_reference_hmac(current_head.epoch_id),
            )
            or witness.observation_segment_count > len(operation_inventory)
            or operation_inventory[witness.observation_segment_count - 1]
            != witness.observation_head_sha256
        ):
            raise ValueError("operation absence witness prefix differs")
        if not hmac.compare_digest(
            witness.expected_operation_reference_hmac_sha256,
            transition.publish_operation_plan.operation_reference_hmac_sha256,
        ):
            raise ValueError("operation absence reference differs from persisted plan")
        expected_transaction_hmac = (
            transition.publish_operation_plan
            .publish_transaction_reference_hmac_sha256
        )
        if (
            witness.expected_publish_transaction_hmac_sha256
            != expected_transaction_hmac
        ):
            raise ValueError("operation absence transaction binding differs")
        histories = operation_ledger._transaction_history
        if type(histories) is not dict:
            raise ValueError("operation typed inventory is unavailable")
        for history in histories.values():
            if type(history) not in {tuple, list} or not history:
                raise ValueError("operation typed inventory is malformed")
            first = history[0]
            if type(first) is not OperationTransition:
                raise ValueError("operation typed inventory is malformed")
            if hmac.compare_digest(
                witness.expected_operation_reference_hmac_sha256,
                self._operation_reference_hmac(first.operation_id),
            ):
                raise ValueError("expected absent operation is now present")
            if (
                expected_transaction_hmac is not None
                and hmac.compare_digest(
                    expected_transaction_hmac,
                    self._publish_transaction_reference_hmac(
                        first.transaction_id
                    ),
                )
            ):
                raise ValueError("expected absent transaction is now present")
        return hashlib.sha256(
            b"COPY-PUBLISH-ABSENCE-BINDING-V1\0"
            + canonical_json_bytes(
                {
                    "copy_transaction_binding_sha256": (
                        transition.transaction_binding_sha256
                    ),
                    "copy_transition_sha256": transition.digest,
                    "current_operation_head_sha256": (
                        operation_inventory[-1]
                    ),
                    "current_operation_segment_count": len(operation_inventory),
                    "operation_absence_witness": witness.to_json(),
                }
            )
        ).hexdigest()

    def _validate_full_dag_with_operation_epochs_under_existing_mutex(
        self,
        lease: RuntimeMutexLease,
        audit_ledger: DurableAuditLedger,
        operation_ledgers: tuple[DurableOperationLedger, ...],
    ) -> tuple[str, ...]:
        """Authenticate Audit -> operation epochs -> both Copy chains as one DAG."""

        self._require_mutex(lease)
        if (
            type(audit_ledger) is not DurableAuditLedger
            or audit_ledger._storage is not self._storage
            or type(operation_ledgers) is not tuple
            or not operation_ledgers
            or any(
                type(item) is not DurableOperationLedger
                or item._storage is not self._storage
                for item in operation_ledgers
            )
        ):
            raise CopyLedgerError(
                CopyLedgerCode.INVALID_REQUEST,
                "full Copy DAG validation requires exact co-located authorities",
            )
        try:
            audit_inventory = (
                audit_ledger.authenticated_segment_sha256s_under_existing_mutex(
                    lease
                )
            )
            if not self._is_exact_ancestor_inventory(audit_inventory):
                raise ValueError("audit inventory is not exact")
            audit_set = set(audit_inventory)
            operation_segment_set: set[str] = set()
            for operation_ledger in operation_ledgers:
                operation_inventory = (
                    operation_ledger.authenticated_segment_sha256s_under_existing_mutex(
                        lease
                    )
                )
                if not self._is_exact_ancestor_inventory(operation_inventory):
                    raise ValueError("operation inventory is not exact")
                if operation_segment_set.intersection(operation_inventory):
                    raise ValueError("operation epoch segment inventories overlap")
                operation_segment_set.update(operation_inventory)
                if not set(
                    operation_ledger.bound_audit_heads_under_existing_mutex(
                        lease
                    )
                ).issubset(audit_set):
                    raise ValueError("operation epoch audit ancestry is missing")
            terminal_bindings = (
                self._authenticated_publish_terminal_bindings_for_epochs_under_existing_mutex(
                    lease,
                    operation_ledgers,
                    audit_inventory,
                )
            )
            if (
                not self._is_exact_publish_terminal_binding_inventory(
                    terminal_bindings
                )
                or not set(
                    self.bound_audit_ancestors_under_existing_mutex(lease)
                ).issubset(audit_set)
                or not set(
                    self.bound_publish_terminals_under_existing_mutex(lease)
                ).issubset(operation_segment_set)
            ):
                raise ValueError("Copy DAG ancestry is incomplete")
            return terminal_bindings
        except (CopyLedgerError, LedgerError, OperationLedgerError, ValueError):
            self._seal(CopyLedgerCode.CROSS_REFERENCE_INVALID)
            raise CopyLedgerError(
                CopyLedgerCode.CROSS_REFERENCE_INVALID,
                "Copy history has no complete authenticated cross-ledger DAG",
            ) from None

    def _issue_authenticated_ancestors_under_existing_mutex(
        self,
        lease: RuntimeMutexLease,
        audit_ledger: DurableAuditLedger,
        operation_ledger: DurableOperationLedger,
    ) -> _AuthenticatedCopyAncestors:
        """Authenticate both ancestor chains and bind them to one live mutex lease."""

        with self._lock:
            self._require_open()
            self._require_mutex(lease)
            if (
                type(audit_ledger) is not DurableAuditLedger
                or type(operation_ledger) is not DurableOperationLedger
                or audit_ledger._storage is not self._storage
                or operation_ledger._storage is not self._storage
            ):
                raise CopyLedgerError(
                    CopyLedgerCode.INVALID_REQUEST,
                    "authenticated ancestors require the exact co-located ledgers",
                )
            try:
                audit_inventory = (
                    audit_ledger.authenticated_segment_sha256s_under_existing_mutex(
                        lease
                    )
                )
                publish_inventory = (
                    operation_ledger.authenticated_segment_sha256s_under_existing_mutex(
                        lease
                    )
                )
            except (LedgerError, OperationLedgerError):
                self._seal(CopyLedgerCode.CROSS_REFERENCE_INVALID)
                raise CopyLedgerError(
                    CopyLedgerCode.CROSS_REFERENCE_INVALID,
                    "an ancestor chain cannot be authenticated",
                ) from None
            if not self._is_exact_ancestor_inventory(audit_inventory) or not (
                self._is_exact_ancestor_inventory(publish_inventory)
            ):
                self._seal(CopyLedgerCode.CROSS_REFERENCE_INVALID)
                raise CopyLedgerError(
                    CopyLedgerCode.CROSS_REFERENCE_INVALID,
                    "an ancestor chain returned an invalid inventory",
                )
            publish_terminal_bindings = (
                self._authenticated_publish_terminal_bindings_under_existing_mutex(
                    lease,
                    operation_ledger,
                    audit_inventory,
                )
            )
            if not self._is_exact_publish_terminal_binding_inventory(
                publish_terminal_bindings
            ):
                self._seal(CopyLedgerCode.CROSS_REFERENCE_INVALID)
                raise CopyLedgerError(
                    CopyLedgerCode.CROSS_REFERENCE_INVALID,
                    "typed publish terminal inventory is invalid",
                )
            copy_cross_reference = self._copy_cross_reference_binding(
                publish_terminal_bindings
            )
            nonce = secrets.token_hex(32)
            owner_thread = threading.get_ident()
            binding = self._authenticated_ancestor_binding(
                lease=lease,
                audit_ledger=audit_ledger,
                operation_ledger=operation_ledger,
                audit_inventory=audit_inventory,
                publish_inventory=publish_inventory,
                publish_terminal_bindings=publish_terminal_bindings,
                copy_cross_reference=copy_cross_reference,
                nonce=nonce,
                owner_thread=owner_thread,
            )
            return _AuthenticatedCopyAncestors(
                self,
                self._storage,
                lease,
                audit_ledger,
                operation_ledger,
                audit_inventory,
                publish_inventory,
                publish_terminal_bindings,
                copy_cross_reference,
                nonce,
                binding,
                _constructor=_AUTHENTICATED_COPY_ANCESTORS_CONSTRUCTOR,
            )

    def _verify_external_ancestors_under_existing_mutex(
        self,
        lease: RuntimeMutexLease,
        capability: _AuthenticatedCopyAncestors,
    ) -> None:
        """Consume an exact proof, re-authenticate both chains, and verify ancestry."""

        with self._lock:
            self._require_open()
            self._require_mutex(lease)
            if type(capability) is not _AuthenticatedCopyAncestors:
                raise CopyLedgerError(
                    CopyLedgerCode.INVALID_REQUEST,
                    "authenticated ancestor capability is invalid",
                )
            valid = (
                capability._copy_ledgers is self
                and capability._storage is self._storage
                and capability._lease is lease
                and capability._owner_thread == threading.get_ident()
                and capability._state == "ISSUED"
                and type(capability._audit_ledger) is DurableAuditLedger
                and type(capability._operation_ledger) is DurableOperationLedger
                and capability._audit_ledger._storage is self._storage
                and capability._operation_ledger._storage is self._storage
                and self._is_exact_ancestor_inventory(
                    capability._audit_segment_sha256s
                )
                and self._is_exact_ancestor_inventory(
                    capability._publish_segment_sha256s
                )
                and self._is_exact_publish_terminal_binding_inventory(
                    capability._publish_terminal_binding_sha256s
                )
                and type(capability._copy_cross_reference_sha256) is str
                and _SHA256.fullmatch(
                    capability._copy_cross_reference_sha256
                ) is not None
                and type(capability._nonce) is str
                and _SHA256.fullmatch(capability._nonce) is not None
                and type(capability._binding_sha256) is str
                and _SHA256.fullmatch(capability._binding_sha256) is not None
            )
            if valid:
                expected_binding = self._authenticated_ancestor_binding(
                    lease=lease,
                    audit_ledger=capability._audit_ledger,
                    operation_ledger=capability._operation_ledger,
                    audit_inventory=capability._audit_segment_sha256s,
                    publish_inventory=capability._publish_segment_sha256s,
                    publish_terminal_bindings=(
                        capability._publish_terminal_binding_sha256s
                    ),
                    copy_cross_reference=capability._copy_cross_reference_sha256,
                    nonce=capability._nonce,
                    owner_thread=capability._owner_thread,
                )
                valid = hmac.compare_digest(
                    capability._binding_sha256,
                    expected_binding,
                )
            if not valid:
                raise CopyLedgerError(
                    CopyLedgerCode.INVALID_REQUEST,
                    "authenticated ancestor capability is consumed, foreign, or changed",
                )
            capability._state = "CONSUMED"
            try:
                authenticated_audit = (
                    capability._audit_ledger.authenticated_segment_sha256s_under_existing_mutex(
                        lease
                    )
                )
                authenticated_publish = (
                    capability._operation_ledger.authenticated_segment_sha256s_under_existing_mutex(
                        lease
                    )
                )
                authenticated_terminal_bindings = (
                    self._authenticated_publish_terminal_bindings_under_existing_mutex(
                        lease,
                        capability._operation_ledger,
                        authenticated_audit,
                    )
                )
            except (LedgerError, OperationLedgerError):
                self._seal(CopyLedgerCode.CROSS_REFERENCE_INVALID)
                raise CopyLedgerError(
                    CopyLedgerCode.CROSS_REFERENCE_INVALID,
                    "an ancestor chain changed during authentication",
                ) from None
            bound_audit = set(
                self.bound_audit_ancestors_under_existing_mutex(lease)
            )
            bound_publish = set(
                self.bound_publish_terminals_under_existing_mutex(lease)
            )
            authenticated_copy_cross_reference = self._copy_cross_reference_binding(
                authenticated_terminal_bindings
            )
            if (
                authenticated_audit != capability._audit_segment_sha256s
                or authenticated_publish != capability._publish_segment_sha256s
                or authenticated_terminal_bindings
                != capability._publish_terminal_binding_sha256s
                or not hmac.compare_digest(
                    authenticated_copy_cross_reference,
                    capability._copy_cross_reference_sha256,
                )
                or not bound_audit.issubset(set(authenticated_audit))
                or not bound_publish.issubset(set(authenticated_publish))
            ):
                self._seal(CopyLedgerCode.CROSS_REFERENCE_INVALID)
                raise CopyLedgerError(
                    CopyLedgerCode.CROSS_REFERENCE_INVALID,
                    "copy ledger ancestry differs from authenticated chains",
                )

    @staticmethod
    def _is_exact_ancestor_inventory(value: Any) -> bool:
        return (
            type(value) is tuple
            and len(value) > 0
            and all(type(item) is str and _SHA256.fullmatch(item) for item in value)
            and len(set(value)) == len(value)
        )

    @staticmethod
    def _is_exact_publish_terminal_binding_inventory(value: Any) -> bool:
        return (
            type(value) is tuple
            and all(
                type(item) is str
                and _SHA256.fullmatch(item) is not None
                and item != "0" * 64
                for item in value
            )
            and len(set(value)) == len(value)
        )

    def _copy_cross_reference_binding(
        self,
        publish_terminal_bindings: tuple[str, ...],
    ) -> str:
        if not self._is_exact_publish_terminal_binding_inventory(
            publish_terminal_bindings
        ):
            raise CopyLedgerError(
                CopyLedgerCode.INVALID_REQUEST,
                "copy cross-reference binding inventory is invalid",
            )
        payload = canonical_json_bytes(
            {
                "copy_head_sha256": self._copy_chain.head.last_segment_sha256,
                "publish_terminal_binding_sha256s": list(
                    publish_terminal_bindings
                ),
                "source_head_sha256": self._source_chain.head.last_segment_sha256,
            }
        )
        return hmac.new(
            self._copy_chain.auth_key,
            b"COPY-CROSS-REFERENCE-BINDING-V1\0" + payload,
            hashlib.sha256,
        ).hexdigest()

    def _authenticated_ancestor_binding(
        self,
        *,
        lease: RuntimeMutexLease,
        audit_ledger: DurableAuditLedger,
        operation_ledger: DurableOperationLedger,
        audit_inventory: tuple[str, ...],
        publish_inventory: tuple[str, ...],
        publish_terminal_bindings: tuple[str, ...],
        copy_cross_reference: str,
        nonce: str,
        owner_thread: int,
    ) -> str:
        payload = canonical_json_bytes(
            {
                "audit_inventory": list(audit_inventory),
                "audit_ledger_identity": id(audit_ledger),
                "copy_ledger_identity": id(self),
                "copy_cross_reference_sha256": copy_cross_reference,
                "epoch_id": self._epoch_id,
                "lease_identity": id(lease),
                "nonce": nonce,
                "operation_ledger_identity": id(operation_ledger),
                "owner_thread": owner_thread,
                "policy_digest": self._policy_digest,
                "publish_inventory": list(publish_inventory),
                "publish_terminal_binding_sha256s": list(
                    publish_terminal_bindings
                ),
                "run_scope_hmac_sha256": self._run_scope_hmac_sha256,
                "storage_identity": id(self._storage),
            }
        )
        return hmac.new(
            self._copy_chain.auth_key,
            b"COPY-AUTHENTICATED-ANCESTORS-V2\0" + payload,
            hashlib.sha256,
        ).hexdigest()

    def _require_mutex(self, lease: RuntimeMutexLease) -> None:
        if type(lease) is not RuntimeMutexLease or lease._writer is not self._storage:
            raise CopyLedgerError(CopyLedgerCode.MUTEX_INVALID, "copy ledgers require their exact storage mutex lease")
        try:
            lease._assert_live_owner(self._storage)
        except HandleWriterError:
            raise CopyLedgerError(CopyLedgerCode.MUTEX_INVALID, "copy ledger mutex is not live on its owner thread") from None

    def _seal(self, code: CopyLedgerCode) -> None:
        if self._sealed_code is None:
            self._sealed_code = code
        self._storage.seal_after_indeterminate_mutation()

    def _require_open(self) -> None:
        if self._sealed_code is not None:
            raise CopyLedgerError(CopyLedgerCode.LEDGER_SEALED, "copy ledgers are sealed after an unsafe or indeterminate state")

    def _append_revision_is_current_under_existing_mutex(
        self,
        lease: RuntimeMutexLease,
    ) -> bool:
        if not self._append_enabled:
            return False
        if self._audit_ledger is None:
            return True
        try:
            head = self._audit_ledger._rescan_under_existing_mutex(lease)
            activated = set(
                self._audit_ledger._activated_revision_ids_under_existing_mutex(
                    lease
                )
            )
        except LedgerError:
            self._seal(CopyLedgerCode.CROSS_REFERENCE_INVALID)
            raise CopyLedgerError(
                CopyLedgerCode.CROSS_REFERENCE_INVALID,
                "copy append cannot authenticate its audit revision",
            ) from None
        if (
            head.active_revision_id not in activated
            or self._revision.revision_id not in activated
        ):
            self._seal(CopyLedgerCode.CROSS_REFERENCE_INVALID)
            raise CopyLedgerError(
                CopyLedgerCode.CROSS_REFERENCE_INVALID,
                "copy append revision is absent from authenticated ancestry",
            )
        return self._revision.revision_id == head.active_revision_id

    def _require_append_revision_current(
        self,
        lease: RuntimeMutexLease,
    ) -> None:
        if not self._append_revision_is_current_under_existing_mutex(lease):
            raise CopyLedgerError(
                CopyLedgerCode.AUTHENTICATION_FAILED,
                "persisted copy ledgers are read-only under a prior key revision",
            )

    def _require_transition_append_allowed(
        self,
        lease: RuntimeMutexLease,
        transition: CopyTransition,
    ) -> None:
        if self._append_revision_is_current_under_existing_mutex(lease):
            return
        if transition.next_state not in {
            CopyState.RECOVERED_COMMIT,
            CopyState.RECOVERED_ABORT,
        }:
            raise CopyLedgerError(
                CopyLedgerCode.AUTHENTICATION_FAILED,
                "prior-revision copy epochs accept only replay or terminal recovery",
            )


__all__ = [
    "CopyFileEvidence",
    "CopyLedgerCode",
    "CopyLedgerError",
    "CopyLedgerHead",
    "CopyLedgerKind",
    "CopyLedgersHead",
    "CopyLocator",
    "CopyLocatorMode",
    "CopyOperationAbsenceWitness",
    "CopyPublishOperationPlan",
    "CopyPublishPlanKind",
    "CopySourceAnchor",
    "CopySourceReceipt",
    "CopySourceRecord",
    "CopyState",
    "CopyTargetEvidence",
    "CopyTransition",
    "CopyTransitionReceipt",
    "DurableCopyLedgers",
]
