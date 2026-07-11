from __future__ import annotations

import hashlib
import json
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
from app.safety.windows_handle_writer import (
    DirectoryHandleLease,
    HandleWriterCode,
    HandleWriterError,
    TreeEntryKind,
    TreeScanBudget,
    _ObservedTreeLease,
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


class _TestJobRuntime:
    __slots__ = (
        "_boundary",
        "_writer",
        "_ledger",
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
        workspace_root: Path,
        *,
        _constructor: object,
    ) -> None:
        if (
            _constructor is not _JOB_RUNTIME_CONSTRUCTOR
            or type(writer) is not _WindowsHandleWriter
            or type(ledger) is not DurableAuditLedger
            or writer._workspace_root != workspace_root
        ):
            raise JobOperationError(
                JobOperationCode.INVALID_REQUEST,
                "job runtime requires the fixed durable Test-local authority",
            )
        self._boundary = boundary
        self._writer = writer
        self._ledger = ledger
        self._workspace_root = workspace_root
        self._lock = threading.RLock()
        self._active_operation_ids: set[str] = set()
        self._spent_operation_ids: dict[str, None] = {}

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
        allowed_actor = (
            context.caller is Caller.TEST_LAB
            and context.purpose is Purpose.TEST
            and context.classification is DataClassification.INTERNAL
        ) or (
            context.caller is Caller.IMPORT_SERVICE
            and context.purpose is Purpose.COPY_SOURCE
            and context.classification is DataClassification.RESTRICTED
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
        "_state",
        "_closed",
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
        self._state = "ACTIVE"
        self._closed = False

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
        try:
            self._assert_live()
        except BaseException as exc:
            close_error = exc
            self._runtime._writer.seal_after_indeterminate_mutation()
        if self._staging is not None:
            try:
                self._staging._close_handles()
            except BaseException as exc:
                close_error = exc
        try:
            self._runtime._boundary._finish_job_operation_context(
                self._context,
                self._context_pin,
                self._context_binding,
            )
        except BaseException as exc:
            close_error = close_error or exc
            self._runtime._writer.seal_after_indeterminate_mutation()
        try:
            self._runtime._finish(self._context.operation_id)
        except BaseException as exc:
            close_error = close_error or exc
        try:
            self._mutex.close()
        except BaseException as exc:
            close_error = close_error or exc
        self._closed = True
        self._state = "CLOSED_NO_BUSINESS_MUTATION"
        if close_error is not None:
            raise close_error

    def __enter__(self) -> _OperationLease:
        self._assert_live()
        return self

    def __exit__(self, _type: Any, _value: Any, _traceback: Any) -> None:
        self.close()

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


def _build_test_job_runtime(
    boundary: _ContextAuthority,
    writer: _WindowsHandleWriter,
    ledger: DurableAuditLedger,
    workspace_root: Path,
    *,
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
