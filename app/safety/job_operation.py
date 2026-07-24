from __future__ import annotations

import hashlib
import json
import secrets
import shutil
import threading
import time
import unicodedata
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol

from app.safety.context import (
    Caller,
    DataClassification,
    OperationContext,
    Purpose,
    ScopeKind,
    validate_safe_id,
)
from app.safety.segment_ledger import DurableAuditLedger, LedgerHead
from app.safety.operation_ledger import (
    DurableOperationLedger,
    OperationCompletionKind,
    OperationLocatorMode,
    OperationLocatorRole,
    OperationSegmentReceipt,
    OperationState,
    OperationTransition,
    OperationTreeEvidence,
    RECOVERY_GUARANTEE_SCOPE,
)
from app.safety.windows_handle_writer import (
    DirectoryPublishReceipt,
    DirectoryHandleLease,
    HandleWriterCode,
    HandleWriterError,
    TreeEntryKind,
    TreeScanBudget,
    _ObservedTreeLease,
    _DirectoryPublishJournalPermit,
    _ObservedHandle,
    _TreeLogicalRow,
    _TreeSnapshot,
    _ImmutableFileLease,
    _WindowsApi,
    _WindowsHandleWriter,
)


_JOB_RUNTIME_CONSTRUCTOR = object()
_OPERATION_LEASE_CONSTRUCTOR = object()
_STAGING_LEASE_CONSTRUCTOR = object()
_OBSERVED_JOB_TREE_CONSTRUCTOR = object()
_OBSERVED_QUARANTINE_TREE_CONSTRUCTOR = object()
_RETAINED_RESTORE_SOURCE_CONSTRUCTOR = object()
_PREPARED_RETAINED_RESTORE_CONSTRUCTOR = object()
_PUBLISH_JOURNAL_CONSTRUCTOR = object()


class JobOperationCode(StrEnum):
    INVALID_REQUEST = "INVALID_REQUEST"
    INVALID_CONTEXT = "INVALID_CONTEXT"
    INVALID_MANIFEST = "INVALID_MANIFEST"
    INVALID_LEASE = "INVALID_LEASE"
    OPERATION_BUSY = "OPERATION_BUSY"
    TARGET_CONFLICT = "TARGET_CONFLICT"
    RESOURCE_LIMIT = "RESOURCE_LIMIT"
    DEADLINE_EXCEEDED = "DEADLINE_EXCEEDED"
    DISK_BUDGET = "DISK_BUDGET"
    TREE_MISMATCH = "TREE_MISMATCH"
    LEDGER_CHANGED = "LEDGER_CHANGED"
    PUBLISH_UNAVAILABLE = "PUBLISH_UNAVAILABLE"
    PUBLISH_FAILED = "PUBLISH_FAILED"
    OPERATION_LEDGER_FAILED = "OPERATION_LEDGER_FAILED"
    OPERATION_FAILED = "OPERATION_FAILED"


class JobOperationError(RuntimeError):
    def __init__(self, code: JobOperationCode, message: str) -> None:
        self.code = code
        super().__init__(f"{code.value}: {message}")

    def __repr__(self) -> str:
        return f"JobOperationError(code='{self.code.value}', context='<redacted>')"


class _ContextAuthority(Protocol):
    @property
    def policy_digest(self) -> str: ...

    def _validate_job_operation_context(self, context: OperationContext) -> str: ...

    def _pin_job_operation_context(
        self,
        context: OperationContext,
        binding_sha256: str,
    ) -> Any: ...

    def _validate_job_operation_pin(
        self,
        context: OperationContext,
        pin: Any,
        binding_sha256: str,
    ) -> str: ...

    def _unpin_job_operation_context_after_failed_begin(
        self,
        context: OperationContext,
        pin: Any,
        binding_sha256: str,
    ) -> None: ...

    def _finish_job_operation_context(
        self,
        context: OperationContext,
        pin: Any,
        binding_sha256: str,
    ) -> None: ...

    def _issue_publish_pair_for_job(
        self,
        source_path: str | Path,
        target_path: str | Path,
        **kwargs: Any,
    ) -> Any: ...

    def _reserve_publish_pair_for_job(
        self,
        token: Any,
        **kwargs: Any,
    ) -> tuple[Any, Any]: ...

    def _issue_quarantine_pair_for_job(
        self,
        source_path: str | Path,
        **kwargs: Any,
    ) -> Any: ...

    def _reserve_quarantine_pair_for_job(
        self,
        token: Any,
        **kwargs: Any,
    ) -> tuple[Any, Any]: ...

    def _finish_reserved_pair_for_job(
        self,
        reservation: Any,
        **kwargs: Any,
    ) -> None: ...

    def _validate_reserved_pair_for_job(
        self,
        reservation: Any,
        **kwargs: Any,
    ) -> Any: ...

    def release_context(self, context: OperationContext) -> bool: ...


@dataclass(frozen=True, slots=True)
class JobResourceBudget:
    maximum_entries: int
    maximum_files: int
    maximum_directories: int
    maximum_depth: int
    maximum_file_bytes: int
    maximum_total_bytes: int
    maximum_path_utf8_bytes: int
    maximum_open_handles: int
    maximum_manifest_bytes: int
    maximum_elapsed_seconds: int
    minimum_free_bytes: int
    tree_budget: TreeScanBudget = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.maximum_elapsed_seconds) is not int
            or not 1 <= self.maximum_elapsed_seconds <= 300
            or type(self.minimum_free_bytes) is not int
            or not 0 <= self.minimum_free_bytes <= 64 * 1024 * 1024 * 1024
        ):
            raise JobOperationError(
                JobOperationCode.INVALID_REQUEST,
                "operation time or free-space budget is outside its fixed envelope",
            )
        try:
            tree_budget = TreeScanBudget(
                maximum_entries=self.maximum_entries,
                maximum_files=self.maximum_files,
                maximum_directories=self.maximum_directories,
                maximum_depth=self.maximum_depth,
                maximum_file_bytes=self.maximum_file_bytes,
                maximum_total_bytes=self.maximum_total_bytes,
                maximum_path_utf8_bytes=self.maximum_path_utf8_bytes,
                maximum_open_handles=self.maximum_open_handles,
                maximum_manifest_bytes=self.maximum_manifest_bytes,
            )
        except HandleWriterError as exc:
            raise JobOperationError(
                JobOperationCode.INVALID_REQUEST,
                "operation tree budget is outside its fixed envelope",
            ) from exc
        object.__setattr__(self, "tree_budget", tree_budget)

    @classmethod
    def conservative_test_default(cls) -> JobResourceBudget:
        del cls
        return JobResourceBudget(
            maximum_entries=128,
            maximum_files=96,
            maximum_directories=32,
            maximum_depth=8,
            maximum_file_bytes=4 * 1024 * 1024,
            maximum_total_bytes=16 * 1024 * 1024,
            maximum_path_utf8_bytes=1024,
            maximum_open_handles=256,
            maximum_manifest_bytes=512 * 1024,
            maximum_elapsed_seconds=60,
            minimum_free_bytes=64 * 1024 * 1024,
        )

    @property
    def digest(self) -> str:
        payload = _canonical_json_bytes(
            {
                "maximum_elapsed_seconds": self.maximum_elapsed_seconds,
                "minimum_free_bytes": self.minimum_free_bytes,
                "tree_budget_sha256": self.tree_budget.digest,
            }
        )
        return hashlib.sha256(b"M0-JOB-RESOURCE-BUDGET-V1\0" + payload).hexdigest()


@dataclass(frozen=True, slots=True)
class DeclaredTreeEntry:
    relative_path: str
    kind: TreeEntryKind
    size_bytes: int
    sha256: str | None

    def __post_init__(self) -> None:
        canonical = _validate_tree_relative_path(self.relative_path)
        if canonical != self.relative_path or type(self.kind) is not TreeEntryKind:
            raise JobOperationError(
                JobOperationCode.INVALID_MANIFEST,
                "declared tree entry path or kind is not canonical",
            )
        if self.kind is TreeEntryKind.DIRECTORY:
            if (
                type(self.size_bytes) is not int
                or self.size_bytes != 0
                or self.sha256 is not None
            ):
                raise JobOperationError(
                    JobOperationCode.INVALID_MANIFEST,
                    "declared directories require zero size and no content digest",
                )
        elif (
            type(self.size_bytes) is not int
            or self.size_bytes < 0
            or not _is_sha256(self.sha256)
        ):
            raise JobOperationError(
                JobOperationCode.INVALID_MANIFEST,
                "declared files require an exact size and lowercase SHA-256",
            )


@dataclass(frozen=True, slots=True)
class DeclaredTreeManifest:
    manifest_id: str
    classification: DataClassification
    entries: tuple[DeclaredTreeEntry, ...]
    manifest_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        try:
            validate_safe_id(self.manifest_id, field_name="manifest_id")
        except Exception:
            raise JobOperationError(
                JobOperationCode.INVALID_MANIFEST,
                "declared manifest identity is not canonical",
            ) from None
        if (
            type(self.classification) is not DataClassification
            or type(self.entries) is not tuple
            or not self.entries
            or len(self.entries) > 2048
            or any(type(entry) is not DeclaredTreeEntry for entry in self.entries)
        ):
            raise JobOperationError(
                JobOperationCode.INVALID_MANIFEST,
                "declared manifest has an invalid exact shape",
            )
        expected_order = tuple(
            sorted(self.entries, key=lambda entry: entry.relative_path.encode("utf-8"))
        )
        if self.entries != expected_order:
            raise JobOperationError(
                JobOperationCode.INVALID_MANIFEST,
                "declared manifest entries must use canonical UTF-8 path order",
            )
        by_path: dict[str, DeclaredTreeEntry] = {}
        folded: set[str] = set()
        for entry in self.entries:
            key = unicodedata.normalize("NFC", entry.relative_path).casefold()
            if key in folded or entry.relative_path in by_path:
                raise JobOperationError(
                    JobOperationCode.INVALID_MANIFEST,
                    "declared manifest contains a canonical path collision",
                )
            folded.add(key)
            parent, _, _name = entry.relative_path.rpartition("/")
            if parent:
                parent_entry = by_path.get(parent)
                if parent_entry is None or parent_entry.kind is not TreeEntryKind.DIRECTORY:
                    raise JobOperationError(
                        JobOperationCode.INVALID_MANIFEST,
                        "declared manifest requires every parent directory explicitly",
                    )
            by_path[entry.relative_path] = entry
        payload = _logical_manifest_bytes(self.entries)
        object.__setattr__(
            self,
            "manifest_sha256",
            hashlib.sha256(b"OBSERVED-TREE-MANIFEST-V1\0" + payload).hexdigest(),
        )

    def __reduce__(self) -> Any:
        raise TypeError("declared tree manifests cannot be serialized")


@dataclass(frozen=True, slots=True)
class ObservedTreeEvidence:
    manifest_sha256: str
    source_tree_sha256: str
    topology_sha256: str
    identity_digest: str
    budget_digest: str
    ledger_head_sha256: str
    entry_count: int
    file_count: int
    directory_count: int
    total_bytes: int
    maximum_depth_observed: int
    evidence_digest: str
    capability_state: str = "TEST_LOCAL_REVALIDATED_OBSERVATION"

    def __reduce__(self) -> Any:
        raise TypeError("observed tree evidence cannot be serialized")


@dataclass(frozen=True, slots=True)
class PublishOperationReceipt:
    transaction_id: str
    pair_id: str
    target_locator: str
    completion_kind: OperationCompletionKind
    native_directory_receipt_sha256: str | None
    recovery_observation_receipt_sha256: str | None
    recovery_guarantee_scope: str | None
    committed_segment_sha256: str
    committed_sequence: int
    target_identity_hmac_sha256: str
    locator_mode: OperationLocatorMode
    classification: DataClassification
    capability_state: str = "TEST_LOCAL_DURABLE_PAIR_PUBLISH"

    def __post_init__(self) -> None:
        if (
            type(self.locator_mode) is not OperationLocatorMode
            or type(self.classification) is not DataClassification
            or len(self.target_identity_hmac_sha256) != 64
            or any(
                character not in "0123456789abcdef"
                for character in self.target_identity_hmac_sha256
            )
            or (
                self.classification is DataClassification.RESTRICTED
                and (
                    self.locator_mode is not OperationLocatorMode.HMAC_ONLY
                    or len(self.target_locator) != 64
                    or any(character not in "0123456789abcdef" for character in self.target_locator)
                )
            )
            or (
                self.classification is DataClassification.INTERNAL
                and self.locator_mode is not OperationLocatorMode.SAFE_RELATIVE
            )
        ):
            raise TypeError("publish receipt locator classification is invalid")

    def __repr__(self) -> str:
        return (
            "PublishOperationReceipt(transaction_id='<redacted>', pair_id='<redacted>', "
            f"committed_sequence={self.committed_sequence}, target='<redacted>')"
        )

    def __reduce__(self) -> Any:
        raise TypeError("publish operation receipts cannot be serialized")


@dataclass(frozen=True, slots=True)
class QuarantineOperationReceipt:
    transaction_id: str
    pair_id: str
    quarantine_locator: str
    completion_kind: OperationCompletionKind
    native_directory_receipt_sha256: str | None
    recovery_observation_receipt_sha256: str | None
    recovery_guarantee_scope: str | None
    committed_segment_sha256: str
    committed_sequence: int
    quarantine_identity_hmac_sha256: str
    locator_mode: OperationLocatorMode
    classification: DataClassification
    capability_state: str = "TEST_LOCAL_DURABLE_QUARANTINE_MOVE"

    def __post_init__(self) -> None:
        if (
            type(self.locator_mode) is not OperationLocatorMode
            or type(self.classification) is not DataClassification
            or not _is_sha256(self.quarantine_identity_hmac_sha256)
            or (
                self.classification is DataClassification.RESTRICTED
                and (
                    self.locator_mode is not OperationLocatorMode.HMAC_ONLY
                    or not _is_sha256(self.quarantine_locator)
                )
            )
            or (
                self.classification is DataClassification.INTERNAL
                and self.locator_mode is not OperationLocatorMode.SAFE_RELATIVE
            )
        ):
            raise TypeError("quarantine receipt locator classification is invalid")

    def __repr__(self) -> str:
        return (
            "QuarantineOperationReceipt(transaction_id='<redacted>', "
            "pair_id='<redacted>', "
            f"committed_sequence={self.committed_sequence}, "
            "quarantine='<redacted>')"
        )

    def __reduce__(self) -> Any:
        raise TypeError("quarantine operation receipts cannot be serialized")


@dataclass(frozen=True, slots=True)
class RetainedRestoreOperationReceipt:
    publish_receipt: PublishOperationReceipt
    retained_source_locator: str
    retained_source_identity_hmac_sha256: str
    retained_source_manifest_sha256: str
    locator_mode: OperationLocatorMode
    classification: DataClassification
    capability_state: str = "TEST_LOCAL_RETAINED_RESTORE"

    def __post_init__(self) -> None:
        if (
            type(self.publish_receipt) is not PublishOperationReceipt
            or type(self.locator_mode) is not OperationLocatorMode
            or type(self.classification) is not DataClassification
            or not _is_sha256(self.retained_source_identity_hmac_sha256)
            or not _is_sha256(self.retained_source_manifest_sha256)
            or (
                self.classification is DataClassification.RESTRICTED
                and (
                    self.locator_mode is not OperationLocatorMode.HMAC_ONLY
                    or not _is_sha256(self.retained_source_locator)
                )
            )
            or (
                self.classification is DataClassification.INTERNAL
                and self.locator_mode is not OperationLocatorMode.SAFE_RELATIVE
            )
        ):
            raise TypeError("retained restore receipt binding is invalid")

    def __repr__(self) -> str:
        return (
            "RetainedRestoreOperationReceipt("
            "publish_receipt='<redacted>', retained_source='<redacted>')"
        )

    def __reduce__(self) -> Any:
        raise TypeError("retained restore receipts cannot be serialized")


def _receipt_from_authenticated_terminal(
    transition: OperationTransition,
    receipt: OperationSegmentReceipt,
) -> PublishOperationReceipt:
    """Build native and replay receipts from the same authenticated terminal."""

    if (
        type(transition) is not OperationTransition
        or type(receipt) is not OperationSegmentReceipt
        or receipt.transition_id != transition.transition_id
        or receipt.transaction_id != transition.transaction_id
        or receipt.state is not transition.next_state
        or transition.next_state
        not in {OperationState.COMMITTED, OperationState.RECOVERED_COMMIT}
        or transition.completion_kind
        not in {
            OperationCompletionKind.NATIVE_COMMIT,
            OperationCompletionKind.RECOVERED_COMMIT_WITH_NATIVE_MUTATION,
            OperationCompletionKind.RECOVERED_COMMIT_OBSERVATION_ONLY,
        }
        or transition.target_evidence is None
    ):
        raise JobOperationError(
            JobOperationCode.OPERATION_LEDGER_FAILED,
            "publish receipt requires an exact authenticated terminal",
        )
    return PublishOperationReceipt(
        transaction_id=transition.transaction_id,
        pair_id=transition.pair_id,
        target_locator=transition.target_locator,
        completion_kind=transition.completion_kind,
        native_directory_receipt_sha256=(
            transition.native_mutation_receipt_sha256
        ),
        recovery_observation_receipt_sha256=(
            transition.recovery_observation_receipt_sha256
        ),
        recovery_guarantee_scope=transition.recovery_guarantee_scope,
        committed_segment_sha256=receipt.segment_sha256,
        committed_sequence=receipt.sequence,
        target_identity_hmac_sha256=(
            transition.target_evidence.durable_identity_sha256
        ),
        locator_mode=transition.locator_mode,
        classification=transition.classification,
    )


def _quarantine_receipt_from_authenticated_terminal(
    transition: OperationTransition,
    receipt: OperationSegmentReceipt,
) -> QuarantineOperationReceipt:
    if (
        type(transition) is not OperationTransition
        or type(receipt) is not OperationSegmentReceipt
        or receipt.transition_id != transition.transition_id
        or receipt.transaction_id != transition.transaction_id
        or receipt.state is not transition.next_state
        or transition.next_state
        not in {OperationState.COMMITTED, OperationState.RECOVERED_COMMIT}
        or transition.completion_kind
        not in {
            OperationCompletionKind.NATIVE_COMMIT,
            OperationCompletionKind.RECOVERED_COMMIT_WITH_NATIVE_MUTATION,
            OperationCompletionKind.RECOVERED_COMMIT_OBSERVATION_ONLY,
        }
        or transition.target_evidence is None
    ):
        raise JobOperationError(
            JobOperationCode.OPERATION_LEDGER_FAILED,
            "quarantine receipt requires an exact authenticated terminal",
        )
    return QuarantineOperationReceipt(
        transaction_id=transition.transaction_id,
        pair_id=transition.pair_id,
        quarantine_locator=transition.target_locator,
        completion_kind=transition.completion_kind,
        native_directory_receipt_sha256=(
            transition.native_mutation_receipt_sha256
        ),
        recovery_observation_receipt_sha256=(
            transition.recovery_observation_receipt_sha256
        ),
        recovery_guarantee_scope=transition.recovery_guarantee_scope,
        committed_segment_sha256=receipt.segment_sha256,
        committed_sequence=receipt.sequence,
        quarantine_identity_hmac_sha256=(
            transition.target_evidence.durable_identity_sha256
        ),
        locator_mode=transition.locator_mode,
        classification=transition.classification,
    )


class _TestJobRuntime:
    __slots__ = (
        "_boundary",
        "_writer",
        "_ledger",
        "_operation_ledger",
        "_workspace_root",
        "_lock",
        "_active_operation_ids",
        "_spent_operation_ids",
    )

    def __init__(
        self,
        boundary: _ContextAuthority,
        writer: _WindowsHandleWriter,
        ledger: DurableAuditLedger,
        operation_ledger: DurableOperationLedger | None,
        workspace_root: Path,
        *,
        _constructor: object,
    ) -> None:
        if (
            _constructor is not _JOB_RUNTIME_CONSTRUCTOR
            or type(writer) is not _WindowsHandleWriter
            or type(ledger) is not DurableAuditLedger
            or (
                operation_ledger is not None
                and type(operation_ledger) is not DurableOperationLedger
            )
            or writer._workspace_root != workspace_root
        ):
            raise JobOperationError(
                JobOperationCode.INVALID_REQUEST,
                "job runtime requires the fixed durable Test-local authority",
            )
        self._boundary = boundary
        self._writer = writer
        self._ledger = ledger
        self._operation_ledger = operation_ledger
        self._workspace_root = workspace_root
        self._lock = threading.RLock()
        self._active_operation_ids: set[str] = set()
        self._spent_operation_ids: dict[str, None] = {}

    def replay_committed_publish(
        self,
        context: OperationContext,
        manifest: DeclaredTreeManifest,
        budget: JobResourceBudget,
    ) -> PublishOperationReceipt:
        """Return the durable terminal receipt without attempting another rename."""

        if self._operation_ledger is None:
            raise JobOperationError(
                JobOperationCode.PUBLISH_UNAVAILABLE,
                "publish replay requires the durable operation ledger",
            )
        binding = self._validate_context_and_manifest(context, manifest, budget)
        try:
            with self._writer.acquire_runtime_mutex() as lease:
                self._ledger._rescan_under_existing_mutex(lease)
                self._validate_operation_audit_bindings(lease)
                result = self._operation_ledger.operation_result_under_existing_mutex(
                    lease,
                    self._operation_ledger.operation_reference(
                        context.operation_id,
                        context.classification,
                    ),
                )
                if result is None:
                    raise JobOperationError(
                        JobOperationCode.PUBLISH_UNAVAILABLE,
                        "operation has no durable publish result",
                    )
                transition, receipt = result
                if (
                    transition.next_state
                    not in {OperationState.COMMITTED, OperationState.RECOVERED_COMMIT}
                    or context.purpose is Purpose.QUARANTINE
                    or transition.context_binding_sha256 != binding
                    or transition.manifest_sha256 != manifest.manifest_sha256
                    or transition.budget_sha256 != budget.digest
                    or transition.completion_kind
                    not in {
                        OperationCompletionKind.NATIVE_COMMIT,
                        OperationCompletionKind.RECOVERED_COMMIT_WITH_NATIVE_MUTATION,
                        OperationCompletionKind.RECOVERED_COMMIT_OBSERVATION_ONLY,
                    }
                ):
                    raise JobOperationError(
                        JobOperationCode.PUBLISH_UNAVAILABLE,
                        "operation is not an exact committed publish replay",
                    )
                return _receipt_from_authenticated_terminal(transition, receipt)
        except JobOperationError:
            raise
        except Exception:
            raise JobOperationError(
                JobOperationCode.OPERATION_LEDGER_FAILED,
                "durable publish replay failed safely",
            ) from None

    def replay_committed_quarantine(
        self,
        context: OperationContext,
        manifest: DeclaredTreeManifest,
        budget: JobResourceBudget,
    ) -> QuarantineOperationReceipt:
        """Return one durable quarantine terminal without attempting another move."""

        if self._operation_ledger is None:
            raise JobOperationError(
                JobOperationCode.PUBLISH_UNAVAILABLE,
                "quarantine replay requires the durable operation ledger",
            )
        binding = self._validate_context_and_manifest(context, manifest, budget)
        if context.purpose is not Purpose.QUARANTINE:
            raise JobOperationError(
                JobOperationCode.INVALID_CONTEXT,
                "quarantine replay requires an exact quarantine context",
            )
        try:
            with self._writer.acquire_runtime_mutex() as lease:
                self._ledger._rescan_under_existing_mutex(lease)
                self._validate_operation_audit_bindings(lease)
                result = self._operation_ledger.operation_result_under_existing_mutex(
                    lease,
                    self._operation_ledger.operation_reference(
                        context.operation_id,
                        context.classification,
                    ),
                )
                if result is None:
                    raise JobOperationError(
                        JobOperationCode.PUBLISH_UNAVAILABLE,
                        "operation has no durable quarantine result",
                    )
                transition, receipt = result
                if (
                    transition.next_state
                    not in {OperationState.COMMITTED, OperationState.RECOVERED_COMMIT}
                    or transition.context_binding_sha256 != binding
                    or transition.manifest_sha256 != manifest.manifest_sha256
                    or transition.budget_sha256 != budget.digest
                    or transition.completion_kind
                    not in {
                        OperationCompletionKind.NATIVE_COMMIT,
                        OperationCompletionKind.RECOVERED_COMMIT_WITH_NATIVE_MUTATION,
                        OperationCompletionKind.RECOVERED_COMMIT_OBSERVATION_ONLY,
                    }
                ):
                    raise JobOperationError(
                        JobOperationCode.PUBLISH_UNAVAILABLE,
                        "operation is not an exact committed quarantine replay",
                    )
                return _quarantine_receipt_from_authenticated_terminal(
                    transition,
                    receipt,
                )
        except JobOperationError:
            raise
        except Exception:
            raise JobOperationError(
                JobOperationCode.OPERATION_LEDGER_FAILED,
                "durable quarantine replay failed safely",
            ) from None

    def begin_operation(
        self,
        context: OperationContext,
        manifest: DeclaredTreeManifest,
        budget: JobResourceBudget,
    ) -> _OperationLease:
        if (
            type(context) is not OperationContext
            or type(manifest) is not DeclaredTreeManifest
            or type(budget) is not JobResourceBudget
        ):
            raise JobOperationError(
                JobOperationCode.INVALID_REQUEST,
                "job operation requires exact context, manifest, and budget objects",
            )
        context_binding = self._validate_context_and_manifest(context, manifest, budget)
        with self._lock:
            if (
                context.operation_id in self._active_operation_ids
                or context.operation_id in self._spent_operation_ids
            ):
                raise JobOperationError(
                    JobOperationCode.OPERATION_BUSY,
                    "job operation identity is active or already consumed",
                )
            self._active_operation_ids.add(context.operation_id)
        pin = None
        mutex = None
        try:
            pin = self._boundary._pin_job_operation_context(
                context,
                context_binding,
            )
            mutex = self._writer.acquire_runtime_mutex()
            head = self._ledger._rescan_under_existing_mutex(mutex)
            if self._operation_ledger is not None:
                operation_head = self._operation_ledger._rescan_under_existing_mutex(
                    mutex
                )
                self._validate_operation_audit_bindings(mutex)
                if self._operation_ledger.signing_revision_id != head.active_revision_id:
                    raise JobOperationError(
                        JobOperationCode.PUBLISH_UNAVAILABLE,
                        "retired operation epoch is read-only after audit key rotation",
                    )
                if operation_head.unresolved_transaction_ids:
                    raise JobOperationError(
                        JobOperationCode.PUBLISH_UNAVAILABLE,
                        "unresolved publish transactions require explicit reconciliation",
                    )
                if self._operation_ledger.operation_result_under_existing_mutex(
                    mutex,
                    self._operation_ledger.operation_reference(
                        context.operation_id,
                        context.classification,
                    ),
                ) is not None:
                    raise JobOperationError(
                        JobOperationCode.OPERATION_BUSY,
                        "operation identity already has a durable terminal or failed result",
                    )
            return _OperationLease(
                self,
                context,
                manifest,
                budget,
                mutex,
                head,
                context_binding,
                pin,
                _constructor=_OPERATION_LEASE_CONSTRUCTOR,
            )
        except BaseException:
            cleanup_error: BaseException | None = None
            if pin is not None:
                try:
                    self._boundary._unpin_job_operation_context_after_failed_begin(
                        context,
                        pin,
                        context_binding,
                    )
                except BaseException as exc:
                    cleanup_error = cleanup_error or exc
            if mutex is not None:
                try:
                    mutex.close()
                except BaseException as exc:
                    cleanup_error = cleanup_error or exc
            with self._lock:
                self._active_operation_ids.discard(context.operation_id)
            if cleanup_error is not None:
                self._writer.seal_after_indeterminate_mutation()
                raise cleanup_error from None
            raise

    def _validate_operation_audit_bindings(self, lease: Any) -> None:
        operation_ledger = self._operation_ledger
        if operation_ledger is None:
            return
        heads = operation_ledger.bound_audit_heads_under_existing_mutex(lease)
        if not self._ledger._contains_all_segment_sha256_under_existing_mutex(
            lease,
            heads,
        ):
            operation_ledger._seal_cross_ledger_contradiction()

    def _validate_context_and_manifest(
        self,
        context: OperationContext,
        manifest: DeclaredTreeManifest,
        budget: JobResourceBudget,
    ) -> str:
        try:
            validated_digest = self._boundary._validate_job_operation_context(context)
        except Exception:
            raise JobOperationError(
                JobOperationCode.INVALID_CONTEXT,
                "operation context is not live under this durable authority",
            ) from None
        required_scopes = {
            ScopeKind.RUN_ID: context.run_id,
            ScopeKind.JOB_ID: context.job_id,
            ScopeKind.OPERATION_ID: context.operation_id,
            ScopeKind.MANIFEST_ID: context.manifest_id,
            ScopeKind.CHECKPOINT_ID: context.scope_value(ScopeKind.CHECKPOINT_ID),
        }
        if (
            validated_digest != context.digest
            or context.manifest_id != manifest.manifest_id
            or context.classification is not manifest.classification
            or any(value is None for value in required_scopes.values())
            or any(context.scope_value(kind) != value for kind, value in required_scopes.items())
        ):
            raise JobOperationError(
                JobOperationCode.INVALID_CONTEXT,
                "operation context scopes do not exactly bind the job manifest",
            )
        internal_job_actors = {
            (Caller.TEST_LAB, Purpose.TEST),
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
        }
        quarantine_actors = {
            (Caller.DATABASE_SERVICE, Purpose.QUARANTINE),
            (Caller.IMPORT_SERVICE, Purpose.QUARANTINE),
            (Caller.ASSET_SERVICE, Purpose.QUARANTINE),
            (Caller.EXPORT_SERVICE, Purpose.QUARANTINE),
            (Caller.REPORT_SERVICE, Purpose.QUARANTINE),
            (Caller.BACKUP_SERVICE, Purpose.QUARANTINE),
            (Caller.TEST_LAB, Purpose.QUARANTINE),
        }
        allowed_actor = (
            context.classification is DataClassification.INTERNAL
            and (context.caller, context.purpose) in internal_job_actors
        ) or (
            context.caller is Caller.IMPORT_SERVICE
            and context.purpose is Purpose.COPY_SOURCE
            and context.classification is DataClassification.RESTRICTED
        ) or (
            (context.caller, context.purpose) in quarantine_actors
            and context.classification
            in {DataClassification.INTERNAL, DataClassification.RESTRICTED}
        )
        if not allowed_actor:
            raise JobOperationError(
                JobOperationCode.INVALID_CONTEXT,
                "Test-local job runtime rejects this actor and classification pair",
            )
        file_count = sum(entry.kind is TreeEntryKind.FILE for entry in manifest.entries)
        directory_count = len(manifest.entries) - file_count
        total_bytes = sum(entry.size_bytes for entry in manifest.entries)
        maximum_depth = max(entry.relative_path.count("/") + 1 for entry in manifest.entries)
        if (
            len(manifest.entries) > budget.maximum_entries
            or file_count > budget.maximum_files
            or directory_count > budget.maximum_directories
            or total_bytes > budget.maximum_total_bytes
            or maximum_depth > budget.maximum_depth
            or any(
                entry.size_bytes > budget.maximum_file_bytes
                or len(entry.relative_path.encode("utf-8"))
                > budget.maximum_path_utf8_bytes
                for entry in manifest.entries
            )
            or len(_logical_manifest_bytes(manifest.entries))
            > budget.maximum_manifest_bytes
        ):
            raise JobOperationError(
                JobOperationCode.RESOURCE_LIMIT,
                "declared manifest exceeds its immutable operation budget",
            )
        return hashlib.sha256(
            b"M0-JOB-CONTEXT-PIN-V1\0"
            + _canonical_json_bytes(
                {
                    "budget_sha256": budget.digest,
                    "context_sha256": context.digest,
                    "declared_manifest_sha256": manifest.manifest_sha256,
                    "policy_digest": self._boundary.policy_digest,
                }
            )
        ).hexdigest()

    def _finish(self, operation_id: str) -> None:
        with self._lock:
            if operation_id not in self._active_operation_ids:
                raise JobOperationError(
                    JobOperationCode.INVALID_LEASE,
                    "job operation runtime lost its live lease registry entry",
                )
            self._active_operation_ids.remove(operation_id)
            self._spent_operation_ids[operation_id] = None
            while len(self._spent_operation_ids) > 8192:
                self._spent_operation_ids.pop(next(iter(self._spent_operation_ids)))


class _OperationLease:
    __slots__ = (
        "_runtime",
        "_context",
        "_manifest",
        "_budget",
        "_mutex",
        "_ledger_head",
        "_context_binding",
        "_context_pin",
        "_owner_thread",
        "_started_at",
        "_staging",
        "_quarantine_source",
        "_retained_restore",
        "_reserved_pair",
        "_pair_token",
        "_pair_view",
        "_transaction_id",
        "_publish_receipt",
        "_quarantine_receipt",
        "_retained_restore_receipt",
        "_state",
        "_closed",
        "_close_had_secondary_error",
    )

    def __init__(
        self,
        runtime: _TestJobRuntime,
        context: OperationContext,
        manifest: DeclaredTreeManifest,
        budget: JobResourceBudget,
        mutex: Any,
        ledger_head: LedgerHead,
        context_binding: str,
        context_pin: Any,
        *,
        _constructor: object,
    ) -> None:
        if _constructor is not _OPERATION_LEASE_CONSTRUCTOR:
            raise TypeError("operation leases require the fixed job runtime")
        self._runtime = runtime
        self._context = context
        self._manifest = manifest
        self._budget = budget
        self._mutex = mutex
        self._ledger_head = ledger_head
        self._context_binding = context_binding
        self._context_pin = context_pin
        self._owner_thread = threading.get_ident()
        self._started_at = time.monotonic()
        self._staging: _JobStagingLease | None = None
        self._quarantine_source: _ObservedQuarantineTreeLease | None = None
        self._retained_restore: _PreparedRetainedRestore | None = None
        self._reserved_pair: Any | None = None
        self._pair_token: Any | None = None
        self._pair_view: Any | None = None
        self._transaction_id: str | None = None
        self._publish_receipt: PublishOperationReceipt | None = None
        self._quarantine_receipt: QuarantineOperationReceipt | None = None
        self._retained_restore_receipt: RetainedRestoreOperationReceipt | None = None
        self._state = "ACTIVE"
        self._closed = False
        self._close_had_secondary_error = False

    def create_fixed_staging(self) -> _JobStagingLease:
        self._assert_live()
        if self._staging is not None or self._state != "ACTIVE":
            raise JobOperationError(
                JobOperationCode.INVALID_LEASE,
                "fixed staging can be created exactly once",
            )
        self._check_runtime_budget()
        partition = self._context.classification.value
        job_root = Path("tmp") / "jobs" / partition / self._context.job_id
        publish_root = job_root / "publish"
        manifest_root = publish_root / (self._context.manifest_id or "")
        leases: list[DirectoryHandleLease] = []
        contract_lease: _ImmutableFileLease | None = None
        try:
            for relative in (job_root, publish_root, manifest_root):
                ticket = self._runtime._writer.authorize_create_directory(relative)
                leases.append(
                    self._runtime._writer.create_directory_lease(
                        ticket,
                        parent_lease=leases[-1] if leases else None,
                    )
                )
            contract = self._job_contract_bytes()
            if len(contract) > 64 * 1024:
                raise JobOperationError(
                    JobOperationCode.RESOURCE_LIMIT,
                    "immutable job contract exceeds its fixed size limit",
                )
            contract_ticket = self._runtime._writer.authorize_create_file(
                job_root / "job-contract.json"
            )
            contract_lease = self._runtime._writer.create_immutable_file_in_directory(
                leases[0],
                contract_ticket,
                contract,
                expected_sha256=hashlib.sha256(contract).hexdigest(),
            )
            self._check_runtime_budget()
            staging = _JobStagingLease(
                self,
                job_root,
                manifest_root,
                tuple(leases),
                contract_lease,
                _constructor=_STAGING_LEASE_CONSTRUCTOR,
            )
            leases = []
            contract_lease = None
            self._staging = staging
            self._state = "STAGING_READY"
            return staging
        except BaseException:
            self._state = "FAILED_SAFE_RESIDUE_RETAINED"
            cleanup_error: BaseException | None = None
            if contract_lease is not None:
                try:
                    contract_lease.close()
                except BaseException as exc:
                    cleanup_error = exc
            for lease in reversed(leases):
                try:
                    if not lease._closed:
                        lease.close()
                except BaseException as exc:
                    cleanup_error = cleanup_error or exc
            if cleanup_error is not None:
                self._runtime._writer.seal_after_indeterminate_mutation()
                raise cleanup_error from None
            raise

    def observe_quarantine_source(
        self,
        source_relative_path: str | Path,
    ) -> _ObservedQuarantineTreeLease:
        """Bind one existing business object tree to a live quarantine lease."""

        self._assert_live()
        if (
            self._runtime._operation_ledger is None
            or self._context.purpose is not Purpose.QUARANTINE
            or self._state != "ACTIVE"
            or self._staging is not None
            or self._quarantine_source is not None
        ):
            raise JobOperationError(
                JobOperationCode.INVALID_LEASE,
                "quarantine observation requires one fresh quarantine operation",
            )
        parent: DirectoryHandleLease | None = None
        root: DirectoryHandleLease | None = None
        low_level: _ObservedTreeLease | None = None
        try:
            parent, root, low_level = (
                self._runtime._writer._open_existing_tree_for_quarantine(
                    source_relative_path,
                    self._budget.tree_budget,
                )
            )
            snapshot = low_level.revalidate()
            _require_manifest_snapshot(self._manifest, snapshot)
            head = self._runtime._ledger._rescan_under_existing_mutex(self._mutex)
            if head != self._ledger_head:
                raise JobOperationError(
                    JobOperationCode.LEDGER_CHANGED,
                    "audit ledger changed during quarantine source observation",
                )
            self._check_runtime_budget()
            observed = _ObservedQuarantineTreeLease(
                self,
                Path(source_relative_path),
                parent,
                root,
                low_level,
                _evidence_from_snapshot(snapshot, self._budget, head),
                _constructor=_OBSERVED_QUARANTINE_TREE_CONSTRUCTOR,
            )
            parent = None
            root = None
            low_level = None
            self._quarantine_source = observed
            self._state = "QUARANTINE_TREE_OBSERVED"
            return observed
        except BaseException:
            self._state = "QUARANTINE_OBSERVATION_FAILED_NO_MUTATION"
            close_error: BaseException | None = None
            if low_level is not None and not low_level._closed:
                try:
                    low_level.close()
                except BaseException as exc:
                    close_error = exc
            if root is not None and not root._closed:
                try:
                    root.close()
                except BaseException as exc:
                    close_error = close_error or exc
            if parent is not None and not parent._closed:
                try:
                    parent.close()
                except BaseException as exc:
                    close_error = close_error or exc
            if close_error is not None:
                self._runtime._writer.seal_after_indeterminate_mutation()
                raise close_error from None
            raise

    def prepare_retained_restore(
        self,
        quarantine_relative_path: str | Path,
    ) -> _PreparedRetainedRestore:
        """Clone an immutable quarantine tree into staging while retaining it."""

        self._assert_live()
        canonical_source = _validate_internal_quarantine_object_path(
            quarantine_relative_path
        )
        if (
            self._runtime._operation_ledger is None
            or self._context.classification is not DataClassification.INTERNAL
            or self._context.caller is not Caller.BACKUP_SERVICE
            or self._context.purpose is not Purpose.RESTORE
            or self._state != "ACTIVE"
            or self._staging is not None
            or self._retained_restore is not None
        ):
            raise JobOperationError(
                JobOperationCode.INVALID_LEASE,
                "retained restore requires one fresh internal restore operation",
            )
        source_root: DirectoryHandleLease | None = None
        source_tree: _ObservedTreeLease | None = None
        source: _RetainedRestoreSourceLease | None = None
        try:
            source_root, source_tree = (
                self._runtime._writer._open_existing_tree_for_read(
                    canonical_source,
                    self._budget.tree_budget,
                )
            )
            snapshot, payload_rows = (
                self._runtime._writer._read_observed_tree_payloads(source_tree)
            )
            _require_manifest_snapshot(self._manifest, snapshot)
            head = self._runtime._ledger._rescan_under_existing_mutex(self._mutex)
            if head != self._ledger_head:
                raise JobOperationError(
                    JobOperationCode.LEDGER_CHANGED,
                    "audit ledger changed during retained restore observation",
                )
            source = _RetainedRestoreSourceLease(
                self,
                canonical_source,
                source_root,
                source_tree,
                snapshot,
                _constructor=_RETAINED_RESTORE_SOURCE_CONSTRUCTOR,
            )
            source_root = None
            source_tree = None
            staging = self.create_fixed_staging()
            payloads = dict(payload_rows)
            for entry in self._manifest.entries:
                if entry.kind is TreeEntryKind.DIRECTORY:
                    staging.create_declared_directory(entry.relative_path)
                else:
                    payload = payloads.get(entry.relative_path)
                    if payload is None:
                        raise JobOperationError(
                            JobOperationCode.TREE_MISMATCH,
                            "retained source lost a declared file payload",
                        )
                    staging.create_declared_file(entry.relative_path, payload)
            observed = staging.seal_and_observe()
            source.revalidate()
            prepared = _PreparedRetainedRestore(
                self,
                source,
                observed,
                _constructor=_PREPARED_RETAINED_RESTORE_CONSTRUCTOR,
            )
            self._retained_restore = prepared
            return prepared
        except BaseException:
            self._state = "RETAINED_RESTORE_PREPARE_FAILED_RESIDUE_RETAINED"
            close_error: BaseException | None = None
            if source is not None and not source._closed:
                try:
                    source.close()
                except BaseException as exc:
                    close_error = exc
            if source_tree is not None and not source_tree._closed:
                try:
                    source_tree.close()
                except BaseException as exc:
                    close_error = close_error or exc
            if source_root is not None and not source_root._closed:
                try:
                    source_root.close()
                except BaseException as exc:
                    close_error = close_error or exc
            if close_error is not None:
                self._runtime._writer.seal_after_indeterminate_mutation()
                raise close_error from None
            raise

    def authorize_publish(
        self,
        observed: _ObservedJobTreeLease,
        target_relative_path: str | Path,
        *,
        checkpoint_manifest_sha256: str,
    ) -> Any:
        """Issue and reserve exactly one publish pair under the live job mutex."""

        self._assert_live()
        if (
            self._runtime._operation_ledger is None
            or self._state != "TREE_OBSERVED"
            or self._staging is None
            or type(observed) is not _ObservedJobTreeLease
            or observed._staging is not self._staging
            or self._reserved_pair is not None
            or not _is_sha256(checkpoint_manifest_sha256)
        ):
            raise JobOperationError(
                JobOperationCode.PUBLISH_UNAVAILABLE,
                "publish authorization requires one exact observed tree and operation ledger",
            )
        evidence = observed.revalidate()
        checkpoint_id = self._context.scope_value(ScopeKind.CHECKPOINT_ID)
        if checkpoint_id is None:
            raise JobOperationError(
                JobOperationCode.INVALID_CONTEXT,
                "publish authorization requires the checkpoint scope",
            )
        token: Any | None = None
        reservation: Any | None = None
        try:
            token = self._runtime._boundary._issue_publish_pair_for_job(
                self._staging._manifest_root,
                target_relative_path,
                manifest_id=self._manifest.manifest_id,
                manifest_sha256=evidence.manifest_sha256,
                source_tree_sha256=evidence.source_tree_sha256,
                entry_count=evidence.entry_count,
                total_bytes=evidence.total_bytes,
                checkpoint_id=checkpoint_id,
                checkpoint_manifest_sha256=checkpoint_manifest_sha256,
                context=self._context,
                pin=self._context_pin,
                binding_sha256=self._context_binding,
                runtime_mutex_lease=self._mutex,
            )
            reservation, view = self._runtime._boundary._reserve_publish_pair_for_job(
                token,
                context=self._context,
                pin=self._context_pin,
                binding_sha256=self._context_binding,
                runtime_mutex_lease=self._mutex,
            )
            declared = view.evidence
            if (
                view.source_relative_path != self._staging._manifest_root
                or declared.manifest_sha256 != evidence.manifest_sha256
                or declared.source_tree_sha256 != evidence.source_tree_sha256
                or declared.entry_count != evidence.entry_count
                or declared.total_bytes != evidence.total_bytes
            ):
                raise JobOperationError(
                    JobOperationCode.TREE_MISMATCH,
                    "reserved pair declaration differs from the live observed tree",
                )
            previous_head = self._ledger_head
            new_head = self._runtime._ledger._rescan_under_existing_mutex(self._mutex)
            if (
                new_head.epoch_id != previous_head.epoch_id
                or new_head.active_revision_id != previous_head.active_revision_id
                or new_head.active_revision_sequence
                != previous_head.active_revision_sequence
                or new_head.last_sequence != previous_head.last_sequence + 2
                or new_head.segment_count != previous_head.segment_count + 2
            ):
                raise JobOperationError(
                    JobOperationCode.LEDGER_CHANGED,
                    "pair audit did not advance the exact expected ledger head",
                )
            observed._assert_local_live()
            snapshot = observed._low_level.revalidate()
            self._staging._compare_snapshot(snapshot)
            self._ledger_head = new_head
            observed._evidence = _evidence_from_snapshot(
                snapshot,
                self._budget,
                new_head,
            )
            transaction_digest = hashlib.sha256(
                b"M0-PUBLISH-TRANSACTION-ID-V1\0"
                + self._context.digest.encode("ascii")
                + view.pair_id.encode("ascii")
            ).hexdigest().upper()
            self._reserved_pair = reservation
            self._pair_token = token
            self._pair_view = view
            self._transaction_id = f"TXN-{transaction_digest[:32]}"
            self._state = "PAIR_RESERVED"
            return token
        except BaseException:
            if reservation is not None and not getattr(reservation, "_closed", True):
                try:
                    self._runtime._boundary._finish_reserved_pair_for_job(
                        reservation,
                        context=self._context,
                        pin=self._context_pin,
                        binding_sha256=self._context_binding,
                        lifecycle="FAILED",
                    )
                except BaseException:
                    self._runtime._writer.seal_after_indeterminate_mutation()
            self._state = "PAIR_AUTHORIZATION_FAILED_RESIDUE_RETAINED"
            raise

    def authorize_quarantine(
        self,
        observed: _ObservedQuarantineTreeLease,
        *,
        checkpoint_manifest_sha256: str,
    ) -> Any:
        """Issue and reserve one exact quarantine pair under the live mutex."""

        self._assert_live()
        if (
            self._runtime._operation_ledger is None
            or self._state != "QUARANTINE_TREE_OBSERVED"
            or type(observed) is not _ObservedQuarantineTreeLease
            or observed is not self._quarantine_source
            or self._reserved_pair is not None
            or not _is_sha256(checkpoint_manifest_sha256)
        ):
            raise JobOperationError(
                JobOperationCode.PUBLISH_UNAVAILABLE,
                "quarantine authorization requires one exact observed source",
            )
        evidence = observed.revalidate()
        checkpoint_id = self._context.scope_value(ScopeKind.CHECKPOINT_ID)
        if checkpoint_id is None:
            raise JobOperationError(
                JobOperationCode.INVALID_CONTEXT,
                "quarantine authorization requires the checkpoint scope",
            )
        token: Any | None = None
        reservation: Any | None = None
        try:
            token = self._runtime._boundary._issue_quarantine_pair_for_job(
                observed._source_relative_path,
                manifest_id=self._manifest.manifest_id,
                manifest_sha256=evidence.manifest_sha256,
                source_tree_sha256=evidence.source_tree_sha256,
                entry_count=evidence.entry_count,
                total_bytes=evidence.total_bytes,
                checkpoint_id=checkpoint_id,
                checkpoint_manifest_sha256=checkpoint_manifest_sha256,
                context=self._context,
                pin=self._context_pin,
                binding_sha256=self._context_binding,
                runtime_mutex_lease=self._mutex,
            )
            reservation, view = (
                self._runtime._boundary._reserve_quarantine_pair_for_job(
                    token,
                    context=self._context,
                    pin=self._context_pin,
                    binding_sha256=self._context_binding,
                    runtime_mutex_lease=self._mutex,
                )
            )
            declared = view.evidence
            if (
                view.source_relative_path != observed._source_relative_path
                or getattr(view.kind, "value", None) != "QUARANTINE"
                or declared.manifest_sha256 != evidence.manifest_sha256
                or declared.source_tree_sha256 != evidence.source_tree_sha256
                or declared.entry_count != evidence.entry_count
                or declared.total_bytes != evidence.total_bytes
            ):
                raise JobOperationError(
                    JobOperationCode.TREE_MISMATCH,
                    "reserved quarantine declaration differs from the live source",
                )
            previous_head = self._ledger_head
            new_head = self._runtime._ledger._rescan_under_existing_mutex(self._mutex)
            if (
                new_head.epoch_id != previous_head.epoch_id
                or new_head.active_revision_id != previous_head.active_revision_id
                or new_head.active_revision_sequence
                != previous_head.active_revision_sequence
                or new_head.last_sequence != previous_head.last_sequence + 2
                or new_head.segment_count != previous_head.segment_count + 2
            ):
                raise JobOperationError(
                    JobOperationCode.LEDGER_CHANGED,
                    "quarantine pair audit did not advance the expected ledger head",
                )
            observed._assert_local_live()
            snapshot = observed._low_level.revalidate()
            observed._compare_snapshot(snapshot)
            self._ledger_head = new_head
            observed._evidence = _evidence_from_snapshot(
                snapshot,
                self._budget,
                new_head,
            )
            transaction_digest = hashlib.sha256(
                b"M0-QUARANTINE-TRANSACTION-ID-V1\0"
                + self._context.digest.encode("ascii")
                + view.pair_id.encode("ascii")
            ).hexdigest().upper()
            self._reserved_pair = reservation
            self._pair_token = token
            self._pair_view = view
            self._transaction_id = f"TXN-{transaction_digest[:32]}"
            self._state = "QUARANTINE_PAIR_RESERVED"
            return token
        except BaseException:
            if reservation is not None and not getattr(reservation, "_closed", True):
                try:
                    self._runtime._boundary._finish_reserved_pair_for_job(
                        reservation,
                        context=self._context,
                        pin=self._context_pin,
                        binding_sha256=self._context_binding,
                        lifecycle="FAILED",
                    )
                except BaseException:
                    self._runtime._writer.seal_after_indeterminate_mutation()
            self._state = "QUARANTINE_AUTHORIZATION_FAILED_SOURCE_RETAINED"
            raise

    def authorize_retained_restore(
        self,
        prepared: _PreparedRetainedRestore,
        target_relative_path: str | Path,
        *,
        checkpoint_manifest_sha256: str,
    ) -> Any:
        self._assert_live()
        if (
            type(prepared) is not _PreparedRetainedRestore
            or prepared is not self._retained_restore
            or prepared._operation is not self
            or self._context.purpose is not Purpose.RESTORE
        ):
            raise JobOperationError(
                JobOperationCode.INVALID_LEASE,
                "retained restore authorization requires its exact prepared lease",
            )
        prepared._assert_live()
        return self.authorize_publish(
            prepared._observed,
            target_relative_path,
            checkpoint_manifest_sha256=checkpoint_manifest_sha256,
        )

    def execute_publish_pair(
        self,
        token: Any,
        observed: _ObservedJobTreeLease,
    ) -> PublishOperationReceipt:
        """The sole S3-E entry that may perform a directory-root mutation."""

        self._assert_live()
        if (
            self._runtime._operation_ledger is None
            or self._state != "PAIR_RESERVED"
            or token is not self._pair_token
            or type(observed) is not _ObservedJobTreeLease
            or self._staging is None
            or observed._staging is not self._staging
            or self._reserved_pair is None
            or self._pair_view is None
            or self._transaction_id is None
        ):
            raise JobOperationError(
                JobOperationCode.PUBLISH_UNAVAILABLE,
                "publish execution requires the exact reserved pair and observed lease",
            )
        observed.revalidate()
        previous_head = self._ledger_head
        validated_view = self._runtime._boundary._validate_reserved_pair_for_job(
            self._reserved_pair,
            context=self._context,
            pin=self._context_pin,
            binding_sha256=self._context_binding,
            runtime_mutex_lease=self._mutex,
        )
        if validated_view != self._pair_view:
            raise JobOperationError(
                JobOperationCode.PUBLISH_UNAVAILABLE,
                "reserved pair changed before the mutation boundary",
            )
        final_head = self._runtime._ledger._rescan_under_existing_mutex(self._mutex)
        if (
            final_head.epoch_id != previous_head.epoch_id
            or final_head.active_revision_id != previous_head.active_revision_id
            or final_head.active_revision_sequence
            != previous_head.active_revision_sequence
            or final_head.last_sequence != previous_head.last_sequence + 1
            or final_head.segment_count != previous_head.segment_count + 1
        ):
            raise JobOperationError(
                JobOperationCode.LEDGER_CHANGED,
                "final pair revalidation did not advance the exact audit head",
            )
        observed._assert_local_live()
        final_snapshot = observed._low_level.revalidate()
        self._staging._compare_snapshot(final_snapshot)
        self._ledger_head = final_head
        observed._evidence = _evidence_from_snapshot(
            final_snapshot,
            self._budget,
            final_head,
        )
        directory_publish_permit = (
            self._runtime._writer._issue_directory_publish_journal_permit(
                observed._low_level
            )
        )
        journal = _PublishOperationJournal(
            self,
            observed,
            directory_publish_permit=directory_publish_permit,
            _constructor=_PUBLISH_JOURNAL_CONSTRUCTOR,
        )
        directory_receipt: DirectoryPublishReceipt | None = None
        try:
            directory_receipt = self._runtime._writer._publish_observed_directory_no_replace(
                observed._low_level,
                self._pair_view.target_relative_path,
                journal,
            )
            committed = journal.committed_receipt
            if (
                type(directory_receipt) is not DirectoryPublishReceipt
                or committed is None
                or committed.state is not OperationState.COMMITTED
                or committed.transaction_id != self._transaction_id
            ):
                raise JobOperationError(
                    JobOperationCode.OPERATION_LEDGER_FAILED,
                    "directory publish returned without an exact committed ledger receipt",
                )
            terminal_result = (
                self._runtime._operation_ledger.transaction_result_under_existing_mutex(
                    self._mutex,
                    self._transaction_id,
                )
            )
            if terminal_result is None:
                raise JobOperationError(
                    JobOperationCode.OPERATION_LEDGER_FAILED,
                    "committed publish terminal is absent after authenticated rescan",
                )
            terminal, rescanned_receipt = terminal_result
            if (
                rescanned_receipt != committed
                or terminal.native_mutation_receipt_sha256
                != directory_receipt.receipt_sha256
            ):
                raise JobOperationError(
                    JobOperationCode.OPERATION_LEDGER_FAILED,
                    "committed publish terminal differs after authenticated rescan",
                )
            receipt = _receipt_from_authenticated_terminal(
                terminal,
                rescanned_receipt,
            )
            self._runtime._boundary._finish_reserved_pair_for_job(
                self._reserved_pair,
                context=self._context,
                pin=self._context_pin,
                binding_sha256=self._context_binding,
                lifecycle="CONSUMED",
            )
            # The source root has become the committed target.  Release the
            # staging/observed handles before returning so a caller can perform
            # an independent target reopen while this operation lease and its
            # mutex are still live.  Keeping the original write/delete-capable
            # root handle here would make an ordinary read-only reopen fail
            # Windows share checks and would turn valid post-publish evidence
            # into a false indeterminate result.
            self._staging._close_handles()
            self._publish_receipt = receipt
            self._state = "PUBLISH_COMMITTED"
            return receipt
        except BaseException as exc:
            terminal_already_committed = journal.committed_receipt is not None
            if not terminal_already_committed:
                try:
                    journal.record_failure(exc)
                except BaseException:
                    self._runtime._writer.seal_after_indeterminate_mutation()
            if (
                self._reserved_pair is not None
                and not getattr(self._reserved_pair, "_closed", True)
            ):
                try:
                    self._runtime._boundary._finish_reserved_pair_for_job(
                        self._reserved_pair,
                        context=self._context,
                        pin=self._context_pin,
                        binding_sha256=self._context_binding,
                        lifecycle=("CONSUMED" if terminal_already_committed else "FAILED"),
                    )
                except BaseException:
                    self._runtime._writer.seal_after_indeterminate_mutation()
            if terminal_already_committed or journal.mutation_may_have_occurred:
                self._runtime._writer.seal_after_indeterminate_mutation()
            self._state = (
                "PUBLISH_COMMITTED_CLEANUP_FAILED"
                if terminal_already_committed
                else "PUBLISH_FAILED_RESIDUE_RETAINED"
            )
            if isinstance(exc, JobOperationError):
                raise
            raise JobOperationError(
                JobOperationCode.PUBLISH_FAILED,
                "handle-bound publish failed; residue was retained for reconciliation",
            ) from None

    def execute_quarantine_pair(
        self,
        token: Any,
        observed: _ObservedQuarantineTreeLease,
    ) -> QuarantineOperationReceipt:
        """The sole S3-G entry that may move an observed tree into quarantine."""

        self._assert_live()
        if (
            self._runtime._operation_ledger is None
            or self._state != "QUARANTINE_PAIR_RESERVED"
            or token is not self._pair_token
            or type(observed) is not _ObservedQuarantineTreeLease
            or observed is not self._quarantine_source
            or self._reserved_pair is None
            or self._pair_view is None
            or getattr(self._pair_view.kind, "value", None) != "QUARANTINE"
            or self._transaction_id is None
        ):
            raise JobOperationError(
                JobOperationCode.PUBLISH_UNAVAILABLE,
                "quarantine execution requires its exact reserved pair and source",
            )
        observed.revalidate()
        previous_head = self._ledger_head
        validated_view = self._runtime._boundary._validate_reserved_pair_for_job(
            self._reserved_pair,
            context=self._context,
            pin=self._context_pin,
            binding_sha256=self._context_binding,
            runtime_mutex_lease=self._mutex,
        )
        if validated_view != self._pair_view:
            raise JobOperationError(
                JobOperationCode.PUBLISH_UNAVAILABLE,
                "reserved quarantine pair changed before the mutation boundary",
            )
        final_head = self._runtime._ledger._rescan_under_existing_mutex(self._mutex)
        if (
            final_head.epoch_id != previous_head.epoch_id
            or final_head.active_revision_id != previous_head.active_revision_id
            or final_head.active_revision_sequence
            != previous_head.active_revision_sequence
            or final_head.last_sequence != previous_head.last_sequence + 1
            or final_head.segment_count != previous_head.segment_count + 1
        ):
            raise JobOperationError(
                JobOperationCode.LEDGER_CHANGED,
                "final quarantine revalidation did not advance the expected audit head",
            )
        observed._assert_local_live()
        final_snapshot = observed._low_level.revalidate()
        observed._compare_snapshot(final_snapshot)
        self._ledger_head = final_head
        observed._evidence = _evidence_from_snapshot(
            final_snapshot,
            self._budget,
            final_head,
        )
        directory_publish_permit = (
            self._runtime._writer._issue_directory_publish_journal_permit(
                observed._low_level
            )
        )
        journal = _PublishOperationJournal(
            self,
            observed,
            directory_publish_permit=directory_publish_permit,
            _constructor=_PUBLISH_JOURNAL_CONSTRUCTOR,
        )
        try:
            directory_receipt = (
                self._runtime._writer._publish_observed_directory_no_replace(
                    observed._low_level,
                    self._pair_view.target_relative_path,
                    journal,
                    quarantine=True,
                )
            )
            committed = journal.committed_receipt
            if (
                type(directory_receipt) is not DirectoryPublishReceipt
                or committed is None
                or committed.state is not OperationState.COMMITTED
                or committed.transaction_id != self._transaction_id
            ):
                raise JobOperationError(
                    JobOperationCode.OPERATION_LEDGER_FAILED,
                    "quarantine move returned without an exact committed terminal",
                )
            terminal_result = (
                self._runtime._operation_ledger.transaction_result_under_existing_mutex(
                    self._mutex,
                    self._transaction_id,
                )
            )
            if terminal_result is None:
                raise JobOperationError(
                    JobOperationCode.OPERATION_LEDGER_FAILED,
                    "committed quarantine terminal is absent after authenticated rescan",
                )
            terminal, rescanned_receipt = terminal_result
            if (
                rescanned_receipt != committed
                or terminal.native_mutation_receipt_sha256
                != directory_receipt.receipt_sha256
            ):
                raise JobOperationError(
                    JobOperationCode.OPERATION_LEDGER_FAILED,
                    "committed quarantine terminal differs after authenticated rescan",
                )
            receipt = _quarantine_receipt_from_authenticated_terminal(
                terminal,
                rescanned_receipt,
            )
            self._runtime._boundary._finish_reserved_pair_for_job(
                self._reserved_pair,
                context=self._context,
                pin=self._context_pin,
                binding_sha256=self._context_binding,
                lifecycle="CONSUMED",
            )
            observed.close()
            self._quarantine_receipt = receipt
            self._state = "QUARANTINE_COMMITTED"
            return receipt
        except BaseException as exc:
            terminal_already_committed = journal.committed_receipt is not None
            if not terminal_already_committed:
                try:
                    journal.record_failure(exc)
                except BaseException:
                    self._runtime._writer.seal_after_indeterminate_mutation()
            if (
                self._reserved_pair is not None
                and not getattr(self._reserved_pair, "_closed", True)
            ):
                try:
                    self._runtime._boundary._finish_reserved_pair_for_job(
                        self._reserved_pair,
                        context=self._context,
                        pin=self._context_pin,
                        binding_sha256=self._context_binding,
                        lifecycle=("CONSUMED" if terminal_already_committed else "FAILED"),
                    )
                except BaseException:
                    self._runtime._writer.seal_after_indeterminate_mutation()
            if terminal_already_committed or journal.mutation_may_have_occurred:
                self._runtime._writer.seal_after_indeterminate_mutation()
            self._state = (
                "QUARANTINE_COMMITTED_CLEANUP_FAILED"
                if terminal_already_committed
                else "QUARANTINE_FAILED_SOURCE_OR_TARGET_RETAINED"
            )
            if isinstance(exc, JobOperationError):
                raise
            raise JobOperationError(
                JobOperationCode.PUBLISH_FAILED,
                "handle-bound quarantine failed; evidence was retained for reconciliation",
            ) from None

    def execute_retained_restore_pair(
        self,
        token: Any,
        prepared: _PreparedRetainedRestore,
    ) -> RetainedRestoreOperationReceipt:
        """Publish the cloned tree and prove the quarantine source stayed intact."""

        self._assert_live()
        if (
            type(prepared) is not _PreparedRetainedRestore
            or prepared is not self._retained_restore
            or prepared._operation is not self
            or self._context.purpose is not Purpose.RESTORE
        ):
            raise JobOperationError(
                JobOperationCode.INVALID_LEASE,
                "retained restore execution requires its exact prepared lease",
            )
        prepared._assert_live()
        publish_receipt = self.execute_publish_pair(token, prepared._observed)
        try:
            retained_evidence = prepared._source.operation_tree_evidence()
            prepared._source.close()
            receipt = RetainedRestoreOperationReceipt(
                publish_receipt=publish_receipt,
                retained_source_locator=(
                    prepared._source._source_relative_path.as_posix()
                ),
                retained_source_identity_hmac_sha256=(
                    retained_evidence.durable_identity_sha256
                ),
                retained_source_manifest_sha256=(
                    retained_evidence.manifest_sha256
                ),
                locator_mode=OperationLocatorMode.SAFE_RELATIVE,
                classification=DataClassification.INTERNAL,
            )
            self._retained_restore_receipt = receipt
            self._state = "RETAINED_RESTORE_COMMITTED"
            return receipt
        except BaseException:
            self._runtime._writer.seal_after_indeterminate_mutation()
            self._state = "RETAINED_RESTORE_COMMITTED_RETENTION_CHECK_FAILED"
            raise JobOperationError(
                JobOperationCode.OPERATION_FAILED,
                "restore target committed but retained-source verification failed",
            ) from None

    def _job_contract_bytes(self) -> bytes:
        head = self._ledger_head
        if head.last_segment_sha256 is None:
            raise JobOperationError(
                JobOperationCode.LEDGER_CHANGED,
                "initialized audit ledger has no immutable head",
            )
        public_ids: dict[str, str] | None
        if self._context.classification is DataClassification.INTERNAL:
            public_ids = {
                "checkpoint_id": self._context.scope_value(ScopeKind.CHECKPOINT_ID) or "",
                "job_id": self._context.job_id,
                "manifest_id": self._context.manifest_id or "",
                "operation_id": self._context.operation_id,
                "run_id": self._context.run_id,
            }
        else:
            public_ids = None
        payload = {
            "budget_sha256": self._budget.digest,
            "classification": self._context.classification.value,
            "context_sha256": self._context.digest,
            "declared_manifest_sha256": self._manifest.manifest_sha256,
            "id_binding_sha256": hashlib.sha256(
                b"M0-JOB-ID-BINDING-V1\0" + self._context.digest.encode("ascii")
            ).hexdigest(),
            "layout_version": "M0-JOB-STAGING-V1",
            "ledger": {
                "active_revision_id": head.active_revision_id,
                "epoch_id": head.epoch_id,
                "last_segment_sha256": head.last_segment_sha256,
                "sequence": head.last_sequence,
            },
            "policy_digest": self._runtime._boundary.policy_digest,
            "public_ids": public_ids,
            "schema_version": "1.0",
        }
        return _canonical_json_bytes(payload) + b"\n"

    def _assert_live(self) -> None:
        if (
            self._closed
            or self._owner_thread != threading.get_ident()
            or self._context.operation_id not in self._runtime._active_operation_ids
        ):
            raise JobOperationError(
                JobOperationCode.INVALID_LEASE,
                "operation lease is closed, foreign, replayed, or cross-thread",
            )
        try:
            validated = self._runtime._boundary._validate_job_operation_pin(
                self._context,
                self._context_pin,
                self._context_binding,
            )
        except Exception:
            raise JobOperationError(
                JobOperationCode.INVALID_CONTEXT,
                "operation context pin is no longer live and exact",
            ) from None
        if validated != self._context.digest:
            raise JobOperationError(
                JobOperationCode.INVALID_CONTEXT,
                "operation context pin returned a changed authority binding",
            )
        self._runtime._writer._require_unsealed()
        self._mutex._assert_live_owner(self._runtime._writer)
        if self._staging is not None and not self._staging._closed:
            self._staging._contract_lease._assert_live_owner(
                self._runtime._writer
            )

    def _check_runtime_budget(self) -> None:
        if time.monotonic() - self._started_at > self._budget.maximum_elapsed_seconds:
            raise JobOperationError(
                JobOperationCode.DEADLINE_EXCEEDED,
                "job operation exceeded its fixed elapsed-time limit",
            )
        try:
            free = shutil.disk_usage(self._runtime._workspace_root).free
        except OSError:
            raise JobOperationError(
                JobOperationCode.DISK_BUDGET,
                "job operation cannot verify current free space",
            ) from None
        required = self._budget.minimum_free_bytes + sum(
            entry.size_bytes for entry in self._manifest.entries
        )
        if free < required:
            raise JobOperationError(
                JobOperationCode.DISK_BUDGET,
                "job operation free-space reserve would be violated",
            )

    def close(self) -> None:
        if self._closed:
            return
        if self._owner_thread != threading.get_ident():
            raise JobOperationError(
                JobOperationCode.INVALID_LEASE,
                "operation lease must be closed by its owning thread",
            )
        close_error: BaseException | None = None
        self._close_had_secondary_error = False
        try:
            self._assert_live()
        except BaseException as exc:
            close_error = exc
            self._runtime._writer.seal_after_indeterminate_mutation()
        if self._staging is not None:
            try:
                self._staging._close_handles()
            except BaseException as exc:
                self._close_had_secondary_error = True
                close_error = exc
        if self._quarantine_source is not None and not self._quarantine_source._closed:
            try:
                self._quarantine_source.close()
            except BaseException as exc:
                self._close_had_secondary_error = True
                close_error = close_error or exc
        if (
            self._retained_restore is not None
            and not self._retained_restore._source._closed
        ):
            try:
                self._retained_restore._source.close()
            except BaseException as exc:
                self._close_had_secondary_error = True
                close_error = close_error or exc
        if (
            self._reserved_pair is not None
            and not getattr(self._reserved_pair, "_closed", True)
        ):
            try:
                self._runtime._boundary._finish_reserved_pair_for_job(
                    self._reserved_pair,
                    context=self._context,
                    pin=self._context_pin,
                    binding_sha256=self._context_binding,
                    lifecycle="FAILED",
                )
            except BaseException as exc:
                self._close_had_secondary_error = True
                if (
                    isinstance(close_error, HandleWriterError)
                    and close_error.code is HandleWriterCode.WRITER_SEALED
                ):
                    close_error = exc
                else:
                    close_error = close_error or exc
                self._runtime._writer.seal_after_indeterminate_mutation()
        try:
            self._runtime._boundary._finish_job_operation_context(
                self._context,
                self._context_pin,
                self._context_binding,
            )
        except BaseException as exc:
            self._close_had_secondary_error = True
            if (
                isinstance(close_error, HandleWriterError)
                and close_error.code is HandleWriterCode.WRITER_SEALED
            ):
                close_error = exc
            else:
                close_error = close_error or exc
            self._runtime._writer.seal_after_indeterminate_mutation()
        try:
            self._runtime._finish(self._context.operation_id)
        except BaseException as exc:
            self._close_had_secondary_error = True
            if (
                isinstance(close_error, HandleWriterError)
                and close_error.code is HandleWriterCode.WRITER_SEALED
            ):
                close_error = exc
            else:
                close_error = close_error or exc
        try:
            self._mutex.close()
        except BaseException as exc:
            self._close_had_secondary_error = True
            if (
                isinstance(close_error, HandleWriterError)
                and close_error.code is HandleWriterCode.WRITER_SEALED
            ):
                close_error = exc
            else:
                close_error = close_error or exc
        self._closed = True
        self._state = (
            "CLOSED_COMMITTED"
            if (
                self._publish_receipt is not None
                or self._quarantine_receipt is not None
                or self._retained_restore_receipt is not None
            )
            else "CLOSED_NO_COMMITTED_BUSINESS_MUTATION"
        )
        if close_error is not None:
            raise close_error

    def __enter__(self) -> _OperationLease:
        self._assert_live()
        return self

    def __exit__(self, _type: Any, value: Any, _traceback: Any) -> None:
        try:
            self.close()
        except HandleWriterError as close_error:
            # A publish failure can deliberately seal the writer before the
            # context manager performs its cleanup.  Keep the original
            # business exception in that one exact case; an explicit close()
            # still reports WRITER_SEALED, and every other cleanup failure
            # remains visible.
            if (
                value is not None
                and close_error.code is HandleWriterCode.WRITER_SEALED
                and not self._close_had_secondary_error
            ):
                return None
            raise
        return None

    def __repr__(self) -> str:
        return f"_OperationLease(state='{self._state}', context='<redacted>')"

    def __reduce__(self) -> Any:
        raise TypeError("operation leases cannot be serialized")


class _JobStagingLease:
    __slots__ = (
        "_operation",
        "_job_root",
        "_manifest_root",
        "_fixed_leases",
        "_contract_lease",
        "_directory_leases",
        "_created",
        "_observed",
        "_closed",
    )

    def __init__(
        self,
        operation: _OperationLease,
        job_root: Path,
        manifest_root: Path,
        fixed_leases: tuple[DirectoryHandleLease, ...],
        contract_lease: _ImmutableFileLease,
        *,
        _constructor: object,
    ) -> None:
        if (
            _constructor is not _STAGING_LEASE_CONSTRUCTOR
            or len(fixed_leases) != 3
            or type(contract_lease) is not _ImmutableFileLease
        ):
            raise TypeError("job staging leases require the fixed operation")
        self._operation = operation
        self._job_root = job_root
        self._manifest_root = manifest_root
        self._fixed_leases = fixed_leases
        self._contract_lease = contract_lease
        self._directory_leases: dict[str, DirectoryHandleLease] = {
            "": fixed_leases[-1]
        }
        self._created: set[str] = set()
        self._observed: _ObservedJobTreeLease | None = None
        self._closed = False

    def create_declared_directory(self, relative_path: str) -> None:
        self._assert_writable()
        entry = self._declared_entry(relative_path, TreeEntryKind.DIRECTORY)
        del entry
        parent, _, _name = relative_path.rpartition("/")
        if parent not in self._directory_leases:
            raise JobOperationError(
                JobOperationCode.INVALID_MANIFEST,
                "declared parent directory has not been created",
            )
        self._operation._check_runtime_budget()
        ticket = self._operation._runtime._writer.authorize_create_directory(
            self._manifest_root / Path(*relative_path.split("/"))
        )
        lease = self._operation._runtime._writer.create_directory_lease(
            ticket,
            parent_lease=self._directory_leases[parent],
        )
        self._directory_leases[relative_path] = lease
        self._created.add(relative_path)
        self._operation._check_runtime_budget()

    def create_declared_file(self, relative_path: str, payload: bytes) -> None:
        self._assert_writable()
        entry = self._declared_entry(relative_path, TreeEntryKind.FILE)
        if type(payload) is not bytes:
            raise JobOperationError(
                JobOperationCode.INVALID_MANIFEST,
                "declared file payload must be exact immutable bytes",
            )
        if (
            len(payload) != entry.size_bytes
            or len(payload) > self._operation._budget.maximum_file_bytes
        ):
            raise JobOperationError(
                JobOperationCode.TREE_MISMATCH,
                "declared file payload differs from its frozen manifest",
            )
        self._operation._check_runtime_budget()
        digest = hashlib.sha256(payload).hexdigest()
        if digest != entry.sha256:
            raise JobOperationError(
                JobOperationCode.TREE_MISMATCH,
                "declared file payload differs from its frozen manifest",
            )
        parent, _, _name = relative_path.rpartition("/")
        if parent not in self._directory_leases:
            raise JobOperationError(
                JobOperationCode.INVALID_MANIFEST,
                "declared file parent directory has not been created",
            )
        self._operation._check_runtime_budget()
        ticket = self._operation._runtime._writer.authorize_create_file(
            self._manifest_root / Path(*relative_path.split("/"))
        )
        self._operation._runtime._writer.create_file_in_directory(
            self._directory_leases[parent],
            ticket,
            payload,
            expected_sha256=digest,
        )
        self._created.add(relative_path)
        self._operation._check_runtime_budget()

    def seal_and_observe(self) -> _ObservedJobTreeLease:
        self._assert_writable()
        expected_paths = {entry.relative_path for entry in self._operation._manifest.entries}
        if self._created != expected_paths:
            raise JobOperationError(
                JobOperationCode.TREE_MISMATCH,
                "staging contents do not exactly cover the declared manifest",
            )
        self._operation._check_runtime_budget()
        for relative in sorted(
            (path for path in self._directory_leases if path),
            key=lambda value: (value.count("/"), value),
            reverse=True,
        ):
            self._directory_leases.pop(relative).close()
        self._operation._runtime._writer.seal_directory_lease_for_observation(
            self._fixed_leases[-1]
        )
        low_level = self._operation._runtime._writer.observe_tree(
            self._fixed_leases[-1],
            self._operation._budget.tree_budget,
        )
        try:
            snapshot = low_level.snapshot
            self._compare_snapshot(snapshot)
            head = self._operation._runtime._ledger._rescan_under_existing_mutex(
                self._operation._mutex
            )
            self._require_same_ledger_head(head)
            self._operation._check_runtime_budget()
            evidence = _evidence_from_snapshot(
                snapshot,
                self._operation._budget,
                head,
            )
            observed = _ObservedJobTreeLease(
                self,
                low_level,
                evidence,
                _constructor=_OBSERVED_JOB_TREE_CONSTRUCTOR,
            )
            low_level = None
            self._observed = observed
            self._operation._state = "TREE_OBSERVED"
            return observed
        finally:
            if low_level is not None:
                low_level.close()

    def _compare_snapshot(self, snapshot: _TreeSnapshot) -> None:
        expected = tuple(
            _TreeLogicalRow(
                relative_path=entry.relative_path,
                kind=entry.kind,
                size_bytes=entry.size_bytes,
                sha256=entry.sha256,
            )
            for entry in self._operation._manifest.entries
        )
        if snapshot.rows != expected or snapshot.manifest_sha256 != self._operation._manifest.manifest_sha256:
            raise JobOperationError(
                JobOperationCode.TREE_MISMATCH,
                "observed tree differs from the exact declared manifest",
            )

    def _require_same_ledger_head(self, head: LedgerHead) -> None:
        if head != self._operation._ledger_head:
            self._operation._runtime._writer.seal_after_indeterminate_mutation()
            raise JobOperationError(
                JobOperationCode.LEDGER_CHANGED,
                "audit ledger head changed during the operation lease",
            )

    def _declared_entry(
        self,
        relative_path: str,
        kind: TreeEntryKind,
    ) -> DeclaredTreeEntry:
        canonical = _validate_tree_relative_path(relative_path)
        if canonical in self._created:
            raise JobOperationError(
                JobOperationCode.TARGET_CONFLICT,
                "declared staging entry cannot be reused",
            )
        for entry in self._operation._manifest.entries:
            if entry.relative_path == canonical and entry.kind is kind:
                return entry
        raise JobOperationError(
            JobOperationCode.INVALID_MANIFEST,
            "requested staging entry is absent or has the wrong declared type",
        )

    def _assert_writable(self) -> None:
        self._operation._assert_live()
        if self._closed or self._observed is not None or self._operation._state != "STAGING_READY":
            raise JobOperationError(
                JobOperationCode.INVALID_LEASE,
                "job staging lease is closed or already observed",
            )

    def _close_handles(self) -> None:
        if self._closed:
            return
        close_error: BaseException | None = None
        if self._observed is not None:
            try:
                self._observed.close()
            except BaseException as exc:
                close_error = exc
        for relative in sorted(
            (path for path in self._directory_leases if path),
            key=lambda value: (value.count("/"), value),
            reverse=True,
        ):
            try:
                self._directory_leases.pop(relative).close()
            except BaseException as exc:
                close_error = close_error or exc
        try:
            if not self._contract_lease._closed:
                self._contract_lease.close()
        except BaseException as exc:
            close_error = close_error or exc
        for lease in reversed(self._fixed_leases):
            try:
                if not lease._closed:
                    lease.close()
            except BaseException as exc:
                close_error = close_error or exc
        self._closed = True
        if close_error is not None:
            raise close_error

    def __repr__(self) -> str:
        return "_JobStagingLease(paths='<redacted>', state='<redacted>')"

    def __reduce__(self) -> Any:
        raise TypeError("job staging leases cannot be serialized")


class _ObservedJobTreeLease:
    __slots__ = (
        "_staging",
        "_low_level",
        "_evidence",
        "_owner_thread",
        "_invalidated",
        "_closed",
    )

    def __init__(
        self,
        staging: _JobStagingLease,
        low_level: _ObservedTreeLease,
        evidence: ObservedTreeEvidence,
        *,
        _constructor: object,
    ) -> None:
        if _constructor is not _OBSERVED_JOB_TREE_CONSTRUCTOR:
            raise TypeError("observed job trees require the fixed staging lease")
        self._staging = staging
        self._low_level = low_level
        self._evidence = evidence
        self._owner_thread = threading.get_ident()
        self._invalidated = False
        self._closed = False

    @property
    def evidence(self) -> ObservedTreeEvidence:
        # Directory child namespaces cannot be frozen by a normal user-mode
        # Windows handle.  Never return authority-bearing evidence without a
        # fresh full-tree and ledger-head revalidation.
        return self.revalidate()

    def revalidate(self) -> ObservedTreeEvidence:
        self._assert_local_live()
        try:
            self._staging._operation._assert_live()
            snapshot = self._low_level.revalidate()
            self._staging._compare_snapshot(snapshot)
            head = self._staging._operation._runtime._ledger._rescan_under_existing_mutex(
                self._staging._operation._mutex
            )
            self._staging._require_same_ledger_head(head)
            current = _evidence_from_snapshot(
                snapshot,
                self._staging._operation._budget,
                head,
            )
            if current != self._evidence:
                raise JobOperationError(
                    JobOperationCode.TREE_MISMATCH,
                    "live observed evidence changed after it was frozen",
                )
            self._staging._operation._check_runtime_budget()
            return current
        except BaseException:
            self._invalidated = True
            self._staging._operation._state = "TREE_INVALIDATED_RESIDUE_RETAINED"
            raise

    def _assert_live(self) -> None:
        self._assert_local_live()
        self._staging._operation._assert_live()

    def _assert_local_live(self) -> None:
        if self._closed or self._invalidated or self._owner_thread != threading.get_ident():
            raise JobOperationError(
                JobOperationCode.INVALID_LEASE,
                "observed job tree lease is closed, foreign, or cross-thread",
            )

    def close(self) -> None:
        if self._closed:
            return
        if self._owner_thread != threading.get_ident():
            raise JobOperationError(
                JobOperationCode.INVALID_LEASE,
                "observed job tree lease must be closed by its owning thread",
            )
        self._low_level.close()
        self._closed = True

    def __repr__(self) -> str:
        state = "CLOSED" if self._closed else "INVALIDATED" if self._invalidated else "LIVE"
        return f"_ObservedJobTreeLease(state='{state}', evidence='<redacted>')"

    def __reduce__(self) -> Any:
        raise TypeError("observed job tree leases cannot be serialized")


class _ObservedQuarantineTreeLease:
    __slots__ = (
        "_operation",
        "_source_relative_path",
        "_parent",
        "_root",
        "_low_level",
        "_evidence",
        "_owner_thread",
        "_invalidated",
        "_closed",
    )

    def __init__(
        self,
        operation: _OperationLease,
        source_relative_path: Path,
        parent: DirectoryHandleLease,
        root: DirectoryHandleLease,
        low_level: _ObservedTreeLease,
        evidence: ObservedTreeEvidence,
        *,
        _constructor: object,
    ) -> None:
        if (
            _constructor is not _OBSERVED_QUARANTINE_TREE_CONSTRUCTOR
            or type(parent) is not DirectoryHandleLease
            or type(root) is not DirectoryHandleLease
            or type(low_level) is not _ObservedTreeLease
            or type(evidence) is not ObservedTreeEvidence
            or root._parent_lease is not parent
            or low_level._root is not root
        ):
            raise TypeError("quarantine tree leases require exact handle authority")
        self._operation = operation
        self._source_relative_path = source_relative_path
        self._parent = parent
        self._root = root
        self._low_level = low_level
        self._evidence = evidence
        self._owner_thread = threading.get_ident()
        self._invalidated = False
        self._closed = False

    @property
    def evidence(self) -> ObservedTreeEvidence:
        return self.revalidate()

    def _compare_snapshot(self, snapshot: _TreeSnapshot) -> None:
        _require_manifest_snapshot(self._operation._manifest, snapshot)

    def revalidate(self) -> ObservedTreeEvidence:
        self._assert_local_live()
        try:
            self._operation._assert_live()
            snapshot = self._low_level.revalidate()
            self._compare_snapshot(snapshot)
            head = self._operation._runtime._ledger._rescan_under_existing_mutex(
                self._operation._mutex
            )
            if head != self._operation._ledger_head:
                raise JobOperationError(
                    JobOperationCode.LEDGER_CHANGED,
                    "audit ledger changed during quarantine observation",
                )
            current = _evidence_from_snapshot(
                snapshot,
                self._operation._budget,
                head,
            )
            if current != self._evidence:
                raise JobOperationError(
                    JobOperationCode.TREE_MISMATCH,
                    "quarantine source evidence changed after observation",
                )
            self._operation._check_runtime_budget()
            return current
        except BaseException:
            self._invalidated = True
            self._operation._state = "QUARANTINE_TREE_INVALIDATED_SOURCE_RETAINED"
            raise

    def _assert_local_live(self) -> None:
        if self._closed or self._invalidated or self._owner_thread != threading.get_ident():
            raise JobOperationError(
                JobOperationCode.INVALID_LEASE,
                "quarantine tree lease is closed, invalidated, or cross-thread",
            )

    def close(self) -> None:
        if self._closed:
            return
        if self._owner_thread != threading.get_ident():
            raise JobOperationError(
                JobOperationCode.INVALID_LEASE,
                "quarantine tree lease must be closed by its owning thread",
            )
        close_error: BaseException | None = None
        if not self._low_level._closed:
            try:
                self._low_level.close()
            except BaseException as exc:
                close_error = exc
        if not self._root._closed:
            try:
                self._root.close()
            except BaseException as exc:
                close_error = close_error or exc
        if not self._parent._closed:
            try:
                self._parent.close()
            except BaseException as exc:
                close_error = close_error or exc
        self._closed = True
        if close_error is not None:
            raise close_error

    def __repr__(self) -> str:
        state = "CLOSED" if self._closed else "INVALIDATED" if self._invalidated else "LIVE"
        return f"_ObservedQuarantineTreeLease(state='{state}', source='<redacted>')"

    def __reduce__(self) -> Any:
        raise TypeError("quarantine tree leases cannot be serialized")


class _RetainedRestoreSourceLease:
    __slots__ = (
        "_operation",
        "_source_relative_path",
        "_root",
        "_low_level",
        "_snapshot",
        "_owner_thread",
        "_invalidated",
        "_closed",
    )

    def __init__(
        self,
        operation: _OperationLease,
        source_relative_path: Path,
        root: DirectoryHandleLease,
        low_level: _ObservedTreeLease,
        snapshot: _TreeSnapshot,
        *,
        _constructor: object,
    ) -> None:
        if (
            _constructor is not _RETAINED_RESTORE_SOURCE_CONSTRUCTOR
            or type(root) is not DirectoryHandleLease
            or type(low_level) is not _ObservedTreeLease
            or type(snapshot) is not _TreeSnapshot
            or low_level._root is not root
        ):
            raise TypeError("retained restore sources require exact read handles")
        self._operation = operation
        self._source_relative_path = source_relative_path
        self._root = root
        self._low_level = low_level
        self._snapshot = snapshot
        self._owner_thread = threading.get_ident()
        self._invalidated = False
        self._closed = False

    def revalidate(self) -> _TreeSnapshot:
        self._assert_local_live()
        try:
            self._operation._assert_live()
            snapshot = self._low_level.revalidate()
            _require_manifest_snapshot(self._operation._manifest, snapshot)
            if snapshot != self._snapshot:
                raise JobOperationError(
                    JobOperationCode.TREE_MISMATCH,
                    "retained quarantine source changed during restore",
                )
            return snapshot
        except BaseException:
            self._invalidated = True
            raise

    def operation_tree_evidence(self) -> OperationTreeEvidence:
        snapshot = self.revalidate()
        ledger = self._operation._runtime._operation_ledger
        if type(ledger) is not DurableOperationLedger:
            raise JobOperationError(
                JobOperationCode.OPERATION_LEDGER_FAILED,
                "retained source evidence requires the operation ledger",
            )
        root = self._operation._runtime._writer._observe_identity(
            self._root._handle
        )
        if not self._operation._runtime._writer._same_object(
            self._root._observed,
            root,
        ):
            raise JobOperationError(
                JobOperationCode.TREE_MISMATCH,
                "retained source root identity changed",
            )
        return OperationTreeEvidence(
            manifest_sha256=snapshot.manifest_sha256,
            source_tree_sha256=snapshot.source_tree_sha256,
            topology_sha256=snapshot.topology_sha256,
            durable_identity_sha256=(
                ledger.durable_tree_evidence_identity_digest(
                    root.volume_serial,
                    root.file_id,
                    snapshot.tree_identity_material,
                )
            ),
            entry_count=snapshot.entry_count,
            total_bytes=snapshot.total_bytes,
        )

    def _assert_local_live(self) -> None:
        if self._closed or self._invalidated or self._owner_thread != threading.get_ident():
            raise JobOperationError(
                JobOperationCode.INVALID_LEASE,
                "retained restore source is closed, invalidated, or cross-thread",
            )

    def close(self) -> None:
        if self._closed:
            return
        if self._owner_thread != threading.get_ident():
            raise JobOperationError(
                JobOperationCode.INVALID_LEASE,
                "retained restore source must be closed by its owning thread",
            )
        close_error: BaseException | None = None
        if not self._low_level._closed:
            try:
                self._low_level.close()
            except BaseException as exc:
                close_error = exc
        if not self._root._closed:
            try:
                self._root.close()
            except BaseException as exc:
                close_error = close_error or exc
        self._closed = True
        if close_error is not None:
            raise close_error

    def __repr__(self) -> str:
        state = "CLOSED" if self._closed else "INVALIDATED" if self._invalidated else "LIVE"
        return f"_RetainedRestoreSourceLease(state='{state}', source='<redacted>')"

    def __reduce__(self) -> Any:
        raise TypeError("retained restore source leases cannot be serialized")


class _PreparedRetainedRestore:
    __slots__ = ("_operation", "_source", "_observed", "_owner_thread")

    def __init__(
        self,
        operation: _OperationLease,
        source: _RetainedRestoreSourceLease,
        observed: _ObservedJobTreeLease,
        *,
        _constructor: object,
    ) -> None:
        if (
            _constructor is not _PREPARED_RETAINED_RESTORE_CONSTRUCTOR
            or type(source) is not _RetainedRestoreSourceLease
            or type(observed) is not _ObservedJobTreeLease
            or source._operation is not operation
            or observed._staging._operation is not operation
        ):
            raise TypeError("prepared retained restores require exact source and staging")
        self._operation = operation
        self._source = source
        self._observed = observed
        self._owner_thread = threading.get_ident()

    def _assert_live(self) -> None:
        if self._owner_thread != threading.get_ident():
            raise JobOperationError(
                JobOperationCode.INVALID_LEASE,
                "prepared retained restore cannot cross threads",
            )
        self._operation._assert_live()
        self._source.revalidate()
        self._observed._assert_local_live()

    def __repr__(self) -> str:
        return "_PreparedRetainedRestore(source='<redacted>', staging='<redacted>')"

    def __reduce__(self) -> Any:
        raise TypeError("prepared retained restores cannot be serialized")


class _PublishOperationJournal:
    __slots__ = (
        "_operation",
        "_observed",
        "_ledger",
        "_source_evidence",
        "_target_evidence",
        "_state",
        "_mutation_started",
        "_mutation_receipt_sha256",
        "_committed_receipt",
        "_owner_thread",
        "_directory_publish_permit",
    )

    def __init__(
        self,
        operation: _OperationLease,
        observed: _ObservedJobTreeLease | _ObservedQuarantineTreeLease,
        *,
        directory_publish_permit: _DirectoryPublishJournalPermit,
        _constructor: object,
    ) -> None:
        ledger = operation._runtime._operation_ledger
        if (
            _constructor is not _PUBLISH_JOURNAL_CONSTRUCTOR
            or type(ledger) is not DurableOperationLedger
            or type(observed)
            not in {_ObservedJobTreeLease, _ObservedQuarantineTreeLease}
            or (
                type(observed) is _ObservedJobTreeLease
                and observed._staging._operation is not operation
            )
            or (
                type(observed) is _ObservedQuarantineTreeLease
                and observed._operation is not operation
            )
            or type(directory_publish_permit) is not _DirectoryPublishJournalPermit
        ):
            raise TypeError("publish journals require the exact operation authority")
        self._operation = operation
        self._observed = observed
        self._ledger = ledger
        self._source_evidence: OperationTreeEvidence | None = None
        self._target_evidence: OperationTreeEvidence | None = None
        self._state: OperationState | None = None
        self._mutation_started = False
        self._mutation_receipt_sha256: str | None = None
        self._committed_receipt: OperationSegmentReceipt | None = None
        self._owner_thread = threading.get_ident()
        self._directory_publish_permit = directory_publish_permit
        directory_publish_permit._bind(
            operation._runtime._writer,
            observed._low_level,
            self,
        )

    @property
    def committed_receipt(self) -> OperationSegmentReceipt | None:
        self._assert_local_owner()
        return self._committed_receipt

    @property
    def mutation_may_have_occurred(self) -> bool:
        self._assert_local_owner()
        return self._mutation_started or self._state in {
            OperationState.MUTATED,
            OperationState.POSTCONDITION_VERIFIED,
            OperationState.COMMITTED,
            OperationState.IN_DOUBT,
        }

    def prepared(
        self,
        snapshot: _TreeSnapshot,
        root: _ObservedHandle,
    ) -> None:
        self._assert_live()
        if self._state is not None or type(snapshot) is not _TreeSnapshot or type(root) is not _ObservedHandle:
            raise JobOperationError(
                JobOperationCode.OPERATION_LEDGER_FAILED,
                "publish PREPARED journal state is invalid",
            )
        expected = self._observed._evidence
        if (
            snapshot.manifest_sha256 != expected.manifest_sha256
            or snapshot.source_tree_sha256 != expected.source_tree_sha256
            or snapshot.topology_sha256 != expected.topology_sha256
            or snapshot.entry_count != expected.entry_count
            or snapshot.total_bytes != expected.total_bytes
        ):
            raise JobOperationError(
                JobOperationCode.TREE_MISMATCH,
                "PREPARED snapshot differs from the reserved observed evidence",
            )
        self._source_evidence = self._operation_tree_evidence(snapshot, root)
        self._append(
            next_state=OperationState.PREPARED,
            mutation_attempted=False,
        )

    def mutation_started(self) -> None:
        self._assert_live()
        if self._state is not OperationState.PREPARED or self._mutation_started:
            raise JobOperationError(
                JobOperationCode.OPERATION_LEDGER_FAILED,
                "publish mutation boundary is not in PREPARED",
            )
        self._mutation_started = True

    def mutated(self, receipt: DirectoryPublishReceipt) -> None:
        self._assert_live()
        if (
            self._state is not OperationState.PREPARED
            or not self._mutation_started
            or type(receipt) is not DirectoryPublishReceipt
        ):
            raise JobOperationError(
                JobOperationCode.OPERATION_LEDGER_FAILED,
                "publish MUTATED journal state is invalid",
            )
        self._mutation_receipt_sha256 = receipt.receipt_sha256
        self._append(
            next_state=OperationState.MUTATED,
            mutation_attempted=True,
        )

    def postcondition_verified(
        self,
        snapshot: _TreeSnapshot,
        root: _ObservedHandle,
        receipt: DirectoryPublishReceipt,
    ) -> None:
        self._assert_live()
        if (
            self._state is not OperationState.MUTATED
            or type(snapshot) is not _TreeSnapshot
            or type(root) is not _ObservedHandle
            or type(receipt) is not DirectoryPublishReceipt
            or receipt.receipt_sha256 != self._mutation_receipt_sha256
            or self._source_evidence is None
        ):
            raise JobOperationError(
                JobOperationCode.OPERATION_LEDGER_FAILED,
                "publish postcondition journal state is invalid",
            )
        target = self._operation_tree_evidence(snapshot, root)
        if target != self._source_evidence:
            raise JobOperationError(
                JobOperationCode.TREE_MISMATCH,
                "durable target evidence differs from PREPARED source evidence",
            )
        self._target_evidence = target
        self._append(
            next_state=OperationState.POSTCONDITION_VERIFIED,
            mutation_attempted=True,
        )
        self._committed_receipt = self._append(
            next_state=OperationState.COMMITTED,
            mutation_attempted=True,
        )

    def record_failure(self, error: BaseException) -> None:
        self._assert_live()
        if (
            self._state is None
            or self._state in _TERMINAL_PUBLISH_STATES
            or self._state is OperationState.IN_DOUBT
        ):
            return
        deterministic_no_mutation = (
            isinstance(error, HandleWriterError)
            and error.code is HandleWriterCode.TARGET_CONFLICT
        )
        if self._state is OperationState.PREPARED and (
            not self._mutation_started or deterministic_no_mutation
        ):
            self._mutation_started = False
            self._append(
                next_state=OperationState.ABORTED,
                mutation_attempted=False,
                error_code=self._error_code(error),
            )
            return
        self._append(
            next_state=OperationState.IN_DOUBT,
            mutation_attempted=True,
            error_code=self._error_code(error),
        )

    def _append(
        self,
        *,
        next_state: OperationState,
        mutation_attempted: bool,
        error_code: str | None = None,
    ) -> OperationSegmentReceipt:
        operation = self._operation
        view = operation._pair_view
        source_evidence = self._source_evidence
        if view is None or source_evidence is None or operation._transaction_id is None:
            raise JobOperationError(
                JobOperationCode.OPERATION_LEDGER_FAILED,
                "publish journal lost its immutable transaction binding",
            )
        transition_key = (
            f"{operation._transaction_id}|"
            f"{'' if self._state is None else self._state.value}|{next_state.value}"
        ).encode("ascii")
        transition_id = "TRN-" + hashlib.sha256(
            b"M0-OPERATION-TRANSITION-ID-V1\0" + transition_key
        ).hexdigest().upper()[:32]
        if operation._context.classification is DataClassification.RESTRICTED:
            locator_mode = OperationLocatorMode.HMAC_ONLY
            source_locator = self._ledger.locator_hmac(
                view.source_relative_path.as_posix(),
                transaction_id=operation._transaction_id,
                role=OperationLocatorRole.SOURCE,
            )
            target_locator = self._ledger.locator_hmac(
                view.target_relative_path.as_posix(),
                transaction_id=operation._transaction_id,
                role=OperationLocatorRole.TARGET,
            )
        else:
            locator_mode = OperationLocatorMode.SAFE_RELATIVE
            source_locator = view.source_relative_path.as_posix()
            target_locator = view.target_relative_path.as_posix()
        transition = OperationTransition(
            transition_id=transition_id,
            transaction_id=operation._transaction_id,
            operation_id=self._ledger.operation_reference(
                operation._context.operation_id,
                operation._context.classification,
            ),
            pair_id=view.pair_id,
            previous_state=self._state,
            next_state=next_state,
            context_binding_sha256=operation._context_binding,
            manifest_sha256=operation._manifest.manifest_sha256,
            budget_sha256=operation._budget.digest,
            source_locator=source_locator,
            target_locator=target_locator,
            source_evidence=source_evidence,
            target_evidence=self._target_evidence,
            audit_ledger_head_sha256=operation._ledger_head.last_segment_sha256 or "",
            mutation_attempted=mutation_attempted,
            native_mutation_receipt_sha256=self._mutation_receipt_sha256,
            recovery_observation_receipt_sha256=None,
            completion_kind=(
                OperationCompletionKind.NATIVE_COMMIT
                if next_state is OperationState.COMMITTED
                else None
            ),
            error_code=error_code,
            locator_mode=locator_mode,
            classification=operation._context.classification,
        )
        receipt = self._ledger._append_transition_under_existing_mutex(
            operation._mutex,
            transition,
        )
        self._state = next_state
        return receipt

    def _operation_tree_evidence(
        self,
        snapshot: _TreeSnapshot,
        root: _ObservedHandle,
    ) -> OperationTreeEvidence:
        return OperationTreeEvidence(
            manifest_sha256=snapshot.manifest_sha256,
            source_tree_sha256=snapshot.source_tree_sha256,
            topology_sha256=snapshot.topology_sha256,
            durable_identity_sha256=(
                self._ledger.durable_tree_evidence_identity_digest(
                    root.volume_serial,
                    root.file_id,
                    snapshot.tree_identity_material,
                )
            ),
            entry_count=snapshot.entry_count,
            total_bytes=snapshot.total_bytes,
        )

    @staticmethod
    def _error_code(error: BaseException) -> str:
        if isinstance(error, HandleWriterError):
            return error.code.value
        if isinstance(error, JobOperationError):
            return error.code.value
        return "UNEXPECTED_FAILURE"

    def _assert_live(self) -> None:
        self._assert_local_owner()
        self._operation._assert_live()

    def _assert_local_owner(self) -> None:
        if self._owner_thread != threading.get_ident():
            raise JobOperationError(
                JobOperationCode.INVALID_LEASE,
                "publish journal cannot cross threads",
            )

    def __repr__(self) -> str:
        return "_PublishOperationJournal(state='<redacted>', transaction='<redacted>')"

    def __reduce__(self) -> Any:
        raise TypeError("publish operation journals cannot be serialized")


_TERMINAL_PUBLISH_STATES = frozenset(
    {
        OperationState.ABORTED,
        OperationState.COMMITTED,
        OperationState.RECOVERED_ABORT,
        OperationState.RECOVERED_COMMIT,
    }
)


def _build_test_job_runtime(
    boundary: _ContextAuthority,
    writer: _WindowsHandleWriter,
    ledger: DurableAuditLedger,
    workspace_root: Path,
    *,
    operation_ledger: DurableOperationLedger | None = None,
    _constructor: object,
) -> _TestJobRuntime:
    if _constructor is not _JOB_RUNTIME_CONSTRUCTOR:
        raise JobOperationError(
            JobOperationCode.INVALID_REQUEST,
            "job runtime factory authority is invalid",
        )
    return _TestJobRuntime(
        boundary,
        writer,
        ledger,
        operation_ledger,
        workspace_root,
        _constructor=_JOB_RUNTIME_CONSTRUCTOR,
    )


def _evidence_from_snapshot(
    snapshot: _TreeSnapshot,
    budget: JobResourceBudget,
    head: LedgerHead,
) -> ObservedTreeEvidence:
    if head.last_segment_sha256 is None:
        raise JobOperationError(
            JobOperationCode.LEDGER_CHANGED,
            "initialized audit ledger has no immutable head",
        )
    body = {
        "budget_digest": budget.digest,
        "directory_count": snapshot.directory_count,
        "entry_count": snapshot.entry_count,
        "file_count": snapshot.file_count,
        "identity_digest": snapshot.identity_digest,
        "ledger_head_sha256": head.last_segment_sha256,
        "manifest_sha256": snapshot.manifest_sha256,
        "maximum_depth_observed": snapshot.maximum_depth_observed,
        "source_tree_sha256": snapshot.source_tree_sha256,
        "topology_sha256": snapshot.topology_sha256,
        "total_bytes": snapshot.total_bytes,
    }
    digest = hashlib.sha256(
        b"OBSERVED-TREE-EVIDENCE-V1\0" + _canonical_json_bytes(body)
    ).hexdigest()
    return ObservedTreeEvidence(**body, evidence_digest=digest)


def _require_manifest_snapshot(
    manifest: DeclaredTreeManifest,
    snapshot: _TreeSnapshot,
) -> None:
    if type(manifest) is not DeclaredTreeManifest or type(snapshot) is not _TreeSnapshot:
        raise JobOperationError(
            JobOperationCode.TREE_MISMATCH,
            "tree comparison requires exact manifest and snapshot values",
        )
    expected = tuple(
        _TreeLogicalRow(
            relative_path=entry.relative_path,
            kind=entry.kind,
            size_bytes=entry.size_bytes,
            sha256=entry.sha256,
        )
        for entry in manifest.entries
    )
    if snapshot.rows != expected or snapshot.manifest_sha256 != manifest.manifest_sha256:
        raise JobOperationError(
            JobOperationCode.TREE_MISMATCH,
            "observed tree differs from the exact declared manifest",
        )


def _validate_internal_quarantine_object_path(
    value: str | Path,
) -> Path:
    try:
        path = Path(value)
    except (TypeError, ValueError):
        raise JobOperationError(
            JobOperationCode.INVALID_REQUEST,
            "retained restore source path is invalid",
        ) from None
    if (
        path.is_absolute()
        or len(path.parts) != 5
        or path.parts[:3] != ("data", "quarantine", "INTERNAL")
        or any(part in {"", ".", ".."} for part in path.parts)
        or len(path.parts[4]) != 32
        or path.parts[4] != path.parts[4].upper()
        or any(character not in "0123456789ABCDEF" for character in path.parts[4])
    ):
        raise JobOperationError(
            JobOperationCode.INVALID_REQUEST,
            "retained restore requires one exact internal quarantine object root",
        )
    try:
        parsed = time.strptime(path.parts[3], "%Y-%m-%d")
    except (TypeError, ValueError):
        raise JobOperationError(
            JobOperationCode.INVALID_REQUEST,
            "retained restore quarantine date is invalid",
        ) from None
    if time.strftime("%Y-%m-%d", parsed) != path.parts[3]:
        raise JobOperationError(
            JobOperationCode.INVALID_REQUEST,
            "retained restore quarantine date is non-canonical",
        )
    return path


def _logical_manifest_bytes(entries: tuple[DeclaredTreeEntry, ...]) -> bytes:
    value = {
        "entries": [
            {
                "kind": entry.kind.value,
                "path": entry.relative_path,
                "sha256": entry.sha256,
                "size_bytes": entry.size_bytes,
            }
            for entry in entries
        ],
        "schema_version": "1.0",
    }
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8") + b"\n"


def _canonical_json_bytes(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _validate_tree_relative_path(value: str) -> str:
    if type(value) is not str or not value or "\\" in value or value.startswith("/") or value.endswith("/"):
        raise JobOperationError(
            JobOperationCode.INVALID_MANIFEST,
            "tree paths must be non-empty canonical POSIX relative paths",
        )
    if unicodedata.normalize("NFC", value) != value:
        raise JobOperationError(
            JobOperationCode.INVALID_MANIFEST,
            "tree paths must already be NFC normalized",
        )
    components = value.split("/")
    try:
        for component in components:
            _WindowsApi._validated_relative_component(component)
    except (HandleWriterError, UnicodeError):
        raise JobOperationError(
            JobOperationCode.INVALID_MANIFEST,
            "tree path contains a forbidden Windows component",
        ) from None
    return "/".join(components)


def _is_sha256(value: str | None) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and value == value.casefold()
        and all(character in "0123456789abcdef" for character in value)
    )
