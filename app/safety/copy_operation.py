from __future__ import annotations

import hashlib
import sys
import threading
import traceback
from contextlib import ExitStack
from dataclasses import dataclass, field, replace
from enum import StrEnum
from pathlib import Path
from types import CodeType, FunctionType
from typing import Any, Callable, NoReturn, ParamSpec, TypeVar

from app.safety.context import (
    Caller,
    DataClassification,
    OperationContext,
    Purpose,
    ScopeKind,
)
from app.safety.copy_ledger import (
    COPY_PROVENANCE_FILE_NAME,
    COPY_PROVENANCE_MAX_BYTES,
    CopyFileEvidence,
    CopyLedgerCode,
    CopyLedgerError,
    CopyLocator,
    CopyLocatorMode,
    CopyOperationAbsenceWitness,
    CopyProvenanceMaterial,
    CopyPublishOperationPlan,
    CopyPublishPlanKind,
    CopySourceAnchor,
    CopySourceReceipt,
    CopySourceRecord,
    CopyState,
    CopyTargetEvidence,
    CopyTransition,
    CopyTransitionReceipt,
    DurableCopyLedgers,
    build_copy_provenance_material,
)
from app.safety.external_source import (
    SYNTHETIC_REFERENCE_MAX_BYTES,
    SYNTHETIC_REFERENCE_PAYLOAD_NAME,
    ExternalSourceError,
    SyntheticReferenceReadPolicy,
    SyntheticSourceEvidence,
    SyntheticSourceMaterial,
    SyntheticSourceVerification,
    _CopyExecutionPermit,
    _SyntheticReferenceLease,
    _consume_copy_execution_permit,
    _issue_copy_execution_permit,
    _validate_copy_execution_permit,
)
from app.safety.job_operation import (
    DeclaredTreeEntry,
    DeclaredTreeManifest,
    JobOperationCode,
    JobOperationError,
    JobResourceBudget,
    PublishOperationReceipt,
    _OperationLease,
    _TestJobRuntime,
    _receipt_from_authenticated_terminal,
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
from app.safety.segment_ledger import LedgerError, canonical_json_bytes
from app.safety.windows_handle_writer import (
    HandleDirectorySnapshot,
    HandleWriterError,
    TreeEntryKind,
)


_COPY_OPERATION_CONSTRUCTOR = object()
_SHA256_HEX = frozenset("0123456789abcdef")
_P = ParamSpec("_P")
_T = TypeVar("_T")


class CopyOperationCode(StrEnum):
    INVALID_FACTORY = "INVALID_FACTORY"
    INVALID_REQUEST = "INVALID_REQUEST"
    INVALID_CONTEXT = "INVALID_CONTEXT"
    MANIFEST_MISMATCH = "MANIFEST_MISMATCH"
    SOURCE_FAILED = "SOURCE_FAILED"
    LEDGER_MISMATCH = "LEDGER_MISMATCH"
    RECOVERY_REQUIRED = "RECOVERY_REQUIRED"
    REPLAY_CONFLICT = "REPLAY_CONFLICT"
    STAGING_FAILED = "STAGING_FAILED"
    PUBLISH_FAILED = "PUBLISH_FAILED"
    TARGET_VERIFICATION_FAILED = "TARGET_VERIFICATION_FAILED"
    RECOVERY_CONTRADICTION = "RECOVERY_CONTRADICTION"
    INDETERMINATE = "INDETERMINATE"


class CopyOperationError(RuntimeError):
    def __init__(self, code: CopyOperationCode, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"{code.value}: {message}")

    def __repr__(self) -> str:
        return f"CopyOperationError(code='{self.code.value}', details='<redacted>')"

    def __reduce__(self) -> Any:
        del self
        raise TypeError("copy operation errors cannot be serialized")


def _raise_path_free(error: CopyOperationError) -> NoReturn:
    error.__traceback__ = None
    error.__context__ = None
    error.__cause__ = None
    error.__suppress_context__ = True
    try:
        raise error from None
    except CopyOperationError as exposed:
        # ``from None`` only suppresses display.  Bare re-raise after explicitly
        # scrubbing the new object also removes any exception active in a caller.
        exposed.__context__ = None
        exposed.__cause__ = None
        exposed.__suppress_context__ = True
        del error, exposed
        raise


@dataclass(frozen=True, slots=True)
class _CopyBoundarySuccess:
    value: Any = field(repr=False)


@dataclass(frozen=True, slots=True)
class _CopyBoundaryFailure:
    code: CopyOperationCode
    message: str


def _resolve_copy_boundary(
    outcome: _CopyBoundarySuccess | _CopyBoundaryFailure,
) -> Any:
    if type(outcome) is _CopyBoundarySuccess:
        value = outcome.value
        outcome = None  # type: ignore[assignment]
        del outcome
        return value
    if type(outcome) is _CopyBoundaryFailure:
        code = outcome.code
        message = outcome.message
        outcome = None  # type: ignore[assignment]
        del outcome
        _raise_path_free(CopyOperationError(code, message))
    _raise_path_free(
        CopyOperationError(
            CopyOperationCode.INDETERMINATE,
            "copy operation boundary failed safely",
        )
    )


_COPY_BOUNDARY_ALLOWED_QUALNAMES = (
    "_TestLocalCopyOperation.close",
    "_TestLocalCopyOperation.__enter__",
    "_TestLocalCopyOperation.__exit__",
    "_TestLocalCopyOperation.execute",
    "_TestLocalCopyOperation.reconcile",
)
_COPY_BOUNDARY_MAX = 5


def _copy_boundary_template(*arguments: Any, **keywords: Any) -> Any:
    outcome = _dispatch_copy_boundary(arguments, keywords)
    arguments = ()
    keywords = {}
    del arguments, keywords
    return _resolve_copy_boundary(outcome)


def _create_copy_boundary_runtime() -> tuple[
    Callable[[tuple[Any, ...], dict[str, Any]], _CopyBoundarySuccess | _CopyBoundaryFailure],
    Callable[[FunctionType], FunctionType],
    Callable[[], None],
]:
    """Build the fixed code-keyed vault before sealing the module surfaces."""

    if len(_COPY_BOUNDARY_ALLOWED_QUALNAMES) != _COPY_BOUNDARY_MAX:
        raise RuntimeError("copy boundary allowlist size is invalid")
    allowed = frozenset(_COPY_BOUNDARY_ALLOWED_QUALNAMES)
    if len(allowed) != _COPY_BOUNDARY_MAX:
        raise RuntimeError("copy boundary allowlist contains duplicates")
    vault: dict[CodeType, FunctionType] = {}
    registered: set[str] = set()
    sealed = False
    expected_module = __name__
    template_code = _copy_boundary_template.__code__
    template_globals = globals()

    def dispatch(
        arguments: tuple[Any, ...],
        keywords: dict[str, Any],
    ) -> _CopyBoundarySuccess | _CopyBoundaryFailure:
        try:
            caller_code = sys._getframe(1).f_code
        except BaseException:
            return _CopyBoundaryFailure(
                CopyOperationCode.INDETERMINATE,
                "copy operation boundary failed safely",
            )
        if (
            not sealed
            or type(arguments) is not tuple
            or type(keywords) is not dict
            or "__path_free_capture" in keywords
        ):
            return _CopyBoundaryFailure(
                CopyOperationCode.INDETERMINATE,
                "copy operation boundary failed safely",
            )

        function: FunctionType | None = None
        registered_code: CodeType | None = None
        registered_function: FunctionType | None = None
        for registered_code, registered_function in vault.items():
            if caller_code is registered_code:
                function = registered_function
                break
        if type(function) is not FunctionType:
            return _CopyBoundaryFailure(
                CopyOperationCode.INDETERMINATE,
                "copy operation boundary failed safely",
            )
        try:
            return _CopyBoundarySuccess(function(*arguments, **keywords))
        except BaseException as caught:
            if (
                type(caught) is CopyOperationError
                and type(caught.code) is CopyOperationCode
                and type(caught.message) is str
            ):
                failure_code = caught.code
                failure_message = caught.message
            else:
                failure_code = CopyOperationCode.INDETERMINATE
                failure_message = "copy operation boundary failed safely"
            caught_traceback = caught.__traceback__
            if caught_traceback is not None:
                traceback.clear_frames(caught_traceback)
            caught.__traceback__ = None
            caught.__context__ = None
            caught.__cause__ = None
            caught.__suppress_context__ = True
            result = _CopyBoundaryFailure(failure_code, failure_message)
            arguments = ()
            keywords = {}
            caller_code = None
            function = None
            registered_code = None
            registered_function = None
            del (
                arguments,
                keywords,
                caller_code,
                function,
                registered_code,
                registered_function,
                caught_traceback,
                caught,
            )
            return result

    def register(function: FunctionType) -> FunctionType:
        if (
            sealed
            or type(function) is not FunctionType
            or function.__module__ != expected_module
            or function.__qualname__ not in allowed
            or function.__qualname__ in registered
            or len(vault) >= _COPY_BOUNDARY_MAX
        ):
            raise RuntimeError("copy boundary registration is not allowed")
        index = _COPY_BOUNDARY_ALLOWED_QUALNAMES.index(function.__qualname__)
        boundary_code = template_code.replace(
            co_name=f"_copy_path_free_boundary_{index:02d}",
            co_qualname=f"_copy_path_free_boundary_{index:02d}",
        )
        if any(boundary_code is existing for existing in vault):
            raise RuntimeError("copy boundary code identity was reused")
        boundary = FunctionType(
            boundary_code,
            template_globals,
            function.__name__,
        )
        boundary.__qualname__ = function.__qualname__
        boundary.__module__ = function.__module__
        boundary.__doc__ = function.__doc__
        boundary.__annotations__ = dict(function.__annotations__)
        vault[boundary_code] = function
        registered.add(function.__qualname__)
        return boundary

    def seal() -> None:
        nonlocal sealed
        if (
            sealed
            or len(vault) != _COPY_BOUNDARY_MAX
            or registered != allowed
            or len({id(code) for code in vault}) != _COPY_BOUNDARY_MAX
        ):
            raise RuntimeError("copy boundary vault cannot be sealed")
        sealed = True

    return dispatch, register, seal


(
    _dispatch_copy_boundary,
    _register_copy_boundary,
    _seal_copy_boundaries,
) = _create_copy_boundary_runtime()


def _path_free_exception_boundary(
    function: Callable[_P, _T],
) -> Callable[_P, _T]:
    """Register one allowlisted surface during module initialization only."""

    if type(function) is not FunctionType:
        raise RuntimeError("copy boundary requires an exact function")
    return _register_copy_boundary(function)  # type: ignore[return-value]


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in _SHA256_HEX for character in value)
    )


def _digest(domain: bytes, *parts: bytes) -> str:
    value = hashlib.sha256(domain + b"\0")
    for part in parts:
        value.update(len(part).to_bytes(8, "big"))
        value.update(part)
    return value.hexdigest()


@dataclass(frozen=True, slots=True)
class CopyOperationReceipt:
    transaction_binding_sha256: str
    copy_binding_sha256: str
    source_record_segment_sha256: str
    copy_terminal_segment_sha256: str
    publish_terminal_segment_sha256: str
    source_verification_sha256: str
    classification: DataClassification
    size_bytes: int
    sha256: str
    replayed: bool = False
    capability_state: str = "TEST_LOCAL_AUTHENTICATED_SYNTHETIC_COPY"

    def __post_init__(self) -> None:
        digests = (
            self.transaction_binding_sha256,
            self.copy_binding_sha256,
            self.source_record_segment_sha256,
            self.copy_terminal_segment_sha256,
            self.publish_terminal_segment_sha256,
            self.source_verification_sha256,
            self.sha256,
        )
        if (
            any(not _is_sha256(value) for value in digests)
            or type(self.classification) is not DataClassification
            or type(self.size_bytes) is not int
            or not 0 <= self.size_bytes <= SYNTHETIC_REFERENCE_MAX_BYTES
            or type(self.replayed) is not bool
        ):
            raise TypeError("copy operation receipt has an invalid typed shape")

    def __repr__(self) -> str:
        return (
            "CopyOperationReceipt(classification='"
            f"{self.classification.value}', size_bytes={self.size_bytes}, "
            f"replayed={self.replayed}, references='<redacted>')"
        )

    def __reduce__(self) -> Any:
        del self
        raise TypeError("copy operation receipts cannot be serialized")


class _TestLocalCopyOperation:
    """One-shot S3-F orchestration; production has no construction factory."""

    __slots__ = (
        "_runtime",
        "_ledgers",
        "_source_policy",
        "_context",
        "_manifest",
        "_budget",
        "_copy_id",
        "_owner_thread",
        "_owner_thread_object",
        "_state",
    )

    def __init__(
        self,
        runtime: _TestJobRuntime,
        ledgers: DurableCopyLedgers,
        source_policy: SyntheticReferenceReadPolicy,
        context: OperationContext,
        manifest: DeclaredTreeManifest,
        budget: JobResourceBudget,
        *,
        _constructor: object | None = None,
    ) -> None:
        if (
            _constructor is not _COPY_OPERATION_CONSTRUCTOR
            or type(runtime) is not _TestJobRuntime
            or type(ledgers) is not DurableCopyLedgers
            or type(source_policy) is not SyntheticReferenceReadPolicy
            or type(context) is not OperationContext
            or type(manifest) is not DeclaredTreeManifest
            or type(budget) is not JobResourceBudget
            or type(runtime._operation_ledger) is not DurableOperationLedger
            or ledgers._storage is not runtime._writer
        ):
            raise CopyOperationError(
                CopyOperationCode.INVALID_FACTORY,
                "copy operation requires exact co-owned Test-local authorities",
            )
        copy_id = context.scope_value(ScopeKind.COPY_ID)
        copy_epoch_id = context.scope_value(ScopeKind.COPY_LEDGER_EPOCH_ID)
        if (
            copy_id is None
            or copy_epoch_id is None
            or copy_epoch_id != ledgers.storage_epoch_id
            or not ledgers.matches_run_scope(context.run_id)
        ):
            raise CopyOperationError(
                CopyOperationCode.INVALID_CONTEXT,
                "copy context has no exact Copy and ledger scopes",
            )
        self._validate_source_independent_preconditions(
            runtime,
            ledgers,
            context,
            manifest,
            budget,
        )
        source_scope_matches = False
        try:
            source_scope_matches = source_policy.matches_copy_scope(
                copy_id,
                context.classification,
            )
        except ExternalSourceError:
            source_scope_matches = False
        if (
            context.classification is not source_policy.classification
            or not source_scope_matches
        ):
            raise CopyOperationError(
                CopyOperationCode.INVALID_CONTEXT,
                "copy context, policy, classification, and manifest do not match",
            )
        self._runtime = runtime
        self._ledgers = ledgers
        self._source_policy = source_policy
        self._context = context
        self._manifest = manifest
        self._budget = budget
        self._copy_id = copy_id
        self._owner_thread = threading.get_ident()
        self._owner_thread_object = threading.current_thread()
        if self._owner_thread_object.ident != self._owner_thread:
            raise CopyOperationError(
                CopyOperationCode.INVALID_REQUEST,
                "copy operation thread identity is unstable",
            )
        self._state = "ISSUED"

    def __repr__(self) -> str:
        return "_TestLocalCopyOperation(state='<redacted>', authorities='<redacted>')"

    def __reduce__(self) -> Any:
        del self
        raise TypeError("copy operations cannot be serialized")

    @staticmethod
    def _validate_source_independent_preconditions(
        runtime: _TestJobRuntime,
        ledgers: DurableCopyLedgers,
        context: OperationContext,
        manifest: DeclaredTreeManifest,
        budget: JobResourceBudget,
    ) -> None:
        """Validate every remaining S3-F input before opening REFERENCE."""

        if (
            context.caller is not Caller.IMPORT_SERVICE
            or context.purpose is not Purpose.COPY_SOURCE
            or context.classification is not manifest.classification
            or context.manifest_id != manifest.manifest_id
        ):
            raise CopyOperationError(
                CopyOperationCode.INVALID_CONTEXT,
                "copy actor, classification, and manifest do not match",
            )
        if (
            len(manifest.entries) != 1
            or manifest.entries[0].relative_path
            != SYNTHETIC_REFERENCE_PAYLOAD_NAME
            or manifest.entries[0].kind is not TreeEntryKind.FILE
        ):
            raise CopyOperationError(
                CopyOperationCode.MANIFEST_MISMATCH,
                "S3-F manifest must contain only the immutable payload object",
            )
        operation_ledger = runtime._operation_ledger
        try:
            ledger_bindings_match = (
                type(operation_ledger) is DurableOperationLedger
                and ledgers.signing_revision_id
                == operation_ledger.signing_revision_id
                and ledgers._policy_digest == operation_ledger.policy_digest
                and operation_ledger.policy_digest == runtime._ledger.policy_digest
            )
        except (CopyLedgerError, OperationLedgerError, LedgerError) as error:
            raise CopyOperationError(
                CopyOperationCode.LEDGER_MISMATCH,
                f"copy ledger preflight failed safely ({error.code.value})",
            ) from None
        if not ledger_bindings_match:
            raise CopyOperationError(
                CopyOperationCode.LEDGER_MISMATCH,
                "copy, audit, and publish authorities do not share one policy ancestry",
            )
        try:
            runtime._validate_context_and_manifest(context, manifest, budget)
        except JobOperationError as error:
            mapped = (
                CopyOperationCode.INVALID_CONTEXT
                if error.code is JobOperationCode.INVALID_CONTEXT
                else CopyOperationCode.MANIFEST_MISMATCH
            )
            raise CopyOperationError(
                mapped,
                "copy preflight rejected context, manifest, or budget "
                f"({error.code.value})",
            ) from None

    @_path_free_exception_boundary
    def close(self) -> None:
        if self._state == "CLOSED":
            return
        if (
            self._owner_thread != threading.get_ident()
            or threading.current_thread() is not self._owner_thread_object
            or self._owner_thread_object.ident != self._owner_thread
        ):
            raise CopyOperationError(
                CopyOperationCode.INVALID_REQUEST,
                "copy operation must be closed by its issuing thread",
            )
        self._state = "CLOSED"
        try:
            self._source_policy.close()
        except ExternalSourceError as error:
            _raise_path_free(
                CopyOperationError(
                    CopyOperationCode.SOURCE_FAILED,
                    "synthetic source close failed safely "
                    f"({error.code.value})",
                )
            )

    @_path_free_exception_boundary
    def __enter__(self) -> _TestLocalCopyOperation:
        self._assert_issued()
        return self

    @_path_free_exception_boundary
    def __exit__(self, _type: Any, _value: Any, _traceback: Any) -> None:
        self.close()

    @_path_free_exception_boundary
    def execute(self, source_name: str) -> CopyOperationReceipt:
        self._assert_issued()
        self._state = "ACTIVE"
        result: CopyOperationReceipt | None = None
        try:
            # This gate is deliberately before ``open_reference``.  SOURCE_OBSERVED
            # is append-only, so every budget dimension needed by the immutable
            # two-file target must be proven before external material is opened.
            self._require_worst_case_publish_budget()
            with self._source_policy.open_reference(source_name) as source_lease:
                material = source_lease.read_once()
                self._validate_material_manifest(material)
                transaction_binding, copy_binding = self._stable_bindings(
                    material.evidence
                )
                target = self._target_relative_path()
                (
                    source_record,
                    source_receipt,
                    provenance,
                    source_created,
                ) = self._prepare_source_for_execute(
                    material.evidence,
                    transaction_binding,
                    copy_binding,
                )
                permit = self._issue_execution_permit(
                    source_lease,
                    material.evidence,
                    target,
                    provenance.publish_manifest,
                )
                replay = self._try_replay(
                    permit,
                    material,
                    source_lease,
                    source_record,
                    source_receipt,
                    provenance,
                    transaction_binding,
                    copy_binding,
                    target,
                )
                if replay is not None:
                    result = replay
                else:
                    if not source_created:
                        raise CopyOperationError(
                            CopyOperationCode.RECOVERY_REQUIRED,
                            "an existing source fact must be reconciled before new work",
                        )
                    result = self._execute_new(
                        permit,
                        material,
                        source_lease,
                        source_record,
                        source_receipt,
                        provenance,
                        transaction_binding,
                        copy_binding,
                        target,
                    )
            self._state = "COMMITTED"
            if result is None:
                raise AssertionError("copy operation completed without a receipt")
            return result
        except CopyOperationError as error:
            self._state = "FAILED"
            _raise_path_free(error)
        except ExternalSourceError as error:
            self._state = "FAILED"
            _raise_path_free(
                CopyOperationError(
                    CopyOperationCode.SOURCE_FAILED,
                    f"synthetic source authority rejected the request ({error.code.value})",
                )
            )
        except JobOperationError as error:
            self._state = "FAILED"
            _raise_path_free(
                CopyOperationError(
                    CopyOperationCode.PUBLISH_FAILED,
                    f"job publish authority failed safely ({error.code.value})",
                )
            )
        except CopyLedgerError as error:
            self._state = "FAILED"
            _raise_path_free(
                CopyOperationError(
                    CopyOperationCode.LEDGER_MISMATCH,
                    f"copy evidence ledger failed safely ({error.code.value})",
                )
            )
        except HandleWriterError as error:
            self._state = "FAILED"
            _raise_path_free(
                CopyOperationError(
                    CopyOperationCode.LEDGER_MISMATCH,
                    f"copy storage authority failed safely ({error.code.value})",
                )
            )
        except BaseException:
            self._state = "FAILED"
            _raise_path_free(
                CopyOperationError(
                    CopyOperationCode.INDETERMINATE,
                    "copy operation failed without a safely classifiable result",
                )
            )
        finally:
            self.close()

    @_path_free_exception_boundary
    def reconcile(
        self,
        source_name: str,
        *,
        restricted_locator_capability: object | None = None,
    ) -> CopyOperationReceipt | None:
        """Append one uniquely proven recovery fact without publishing again."""

        self._assert_issued()
        self._state = "RECONCILING"
        result: CopyOperationReceipt | None = None
        try:
            recovery_source: Path | None = None
            if self._context.classification is DataClassification.RESTRICTED:
                recovery_source, target = (
                    self._runtime._boundary._consume_restricted_copy_recovery_locator(
                        restricted_locator_capability,
                        self._context,
                    )
                )
            else:
                if restricted_locator_capability is not None:
                    self._raise_recovery_contradiction()
                target = self._target_relative_path()
            with self._source_policy.open_reference(source_name) as source_lease:
                material = source_lease.read_once()
                self._validate_material_manifest(material)
                transaction_binding, copy_binding = self._stable_bindings(
                    material.evidence
                )
                source_record, source_receipt, provenance = (
                    self._load_source_for_recovery(
                        material.evidence,
                        transaction_binding,
                        copy_binding,
                    )
                )
                permit = self._issue_execution_permit(
                    source_lease,
                    material.evidence,
                    target,
                    provenance.publish_manifest,
                    recovery_source=recovery_source,
                )
                self._consume_execution_permit(
                    permit,
                    source_lease,
                    material,
                    transaction_binding,
                    copy_binding,
                    target,
                    provenance.publish_manifest,
                    recovery_source=recovery_source,
                )
                result = self._reconcile_consumed_source(
                    material,
                    source_lease,
                    source_record,
                    source_receipt,
                    provenance,
                    transaction_binding,
                    copy_binding,
                    target,
                    recovery_source,
                )
            self._state = "COMMITTED" if result is not None else "RECOVERED_ABORT"
            return result
        except CopyOperationError as error:
            self._state = "FAILED"
            if error.code is CopyOperationCode.RECOVERY_CONTRADICTION:
                _raise_path_free(error)
            self._raise_recovery_contradiction()
        except (ExternalSourceError, JobOperationError, CopyLedgerError, HandleWriterError):
            self._state = "FAILED"
            self._raise_recovery_contradiction()
        except BaseException:
            self._state = "FAILED"
            self._raise_recovery_contradiction()
        finally:
            self.close()

    def _reconcile_consumed_source(
        self,
        material: SyntheticSourceMaterial,
        source_lease: _SyntheticReferenceLease,
        expected_source_record: CopySourceRecord,
        expected_source_receipt: CopySourceReceipt,
        provenance: CopyProvenanceMaterial,
        transaction_binding: str,
        copy_binding: str,
        target: Path,
        recovery_source: Path | None,
    ) -> CopyOperationReceipt | None:
        operation_ledger = self._runtime._operation_ledger
        if type(operation_ledger) is not DurableOperationLedger:
            self._raise_recovery_contradiction()
        with self._runtime._writer.acquire_runtime_mutex() as mutex:
            audit_head = self._runtime._ledger._rescan_under_existing_mutex(mutex)
            self._runtime._validate_operation_audit_bindings(mutex)
            self._ledgers._rescan_under_existing_mutex(mutex)
            if (
                self._ledgers.signing_revision_id
                != operation_ledger.signing_revision_id
                or not _is_sha256(audit_head.last_segment_sha256)
            ):
                self._raise_recovery_contradiction()

            copy_result = self._copy_recovery_result(
                self._copy_target_locator(target)
            )
            current: CopyTransition | None
            current_receipt: CopyTransitionReceipt | None
            if copy_result is None:
                current = None
                current_receipt = None
                source_result = (
                    self._ledgers.transaction_source_result_under_existing_mutex(
                        mutex,
                        transaction_binding,
                    )
                )
            else:
                current, current_receipt = copy_result
                source_result = self._ledgers.source_result_under_existing_mutex(
                    mutex,
                    current.source_anchor.record_id,
                )
            if source_result is None:
                self._raise_recovery_contradiction()
            source_record, source_receipt = source_result
            if (
                source_record != expected_source_record
                or source_receipt != expected_source_receipt
            ):
                self._raise_recovery_contradiction()
            if current is None:
                self._validate_source_only_recovery_binding(
                    material.evidence,
                    source_record,
                    source_receipt,
                    transaction_binding,
                    copy_binding,
                )
            else:
                self._validate_recovery_binding(
                    material.evidence,
                    source_record,
                    source_receipt,
                    provenance,
                    current,
                    transaction_binding,
                    copy_binding,
                    target,
                    recovery_source,
                )

            source_only_terminal = (
                current is not None
                and current.previous_state is None
                and current.next_state is CopyState.RECOVERED_ABORT
            )
            source_only_recovered_abort = (
                source_only_terminal
                and current.publish_transaction_id is None
                and current.publish_terminal_segment_sha256 is None
                and current.target_evidence is None
                and current.mutation_attempted is False
            )
            if source_only_terminal and not source_only_recovered_abort:
                self._raise_recovery_contradiction()
            if current is None or source_only_recovered_abort:
                publish_result = None
                unexpected_operation = (
                    operation_ledger.operation_result_under_existing_mutex(
                        mutex,
                        operation_ledger.operation_reference(
                            self._context.operation_id,
                            self._context.classification,
                        ),
                    )
                )
                if unexpected_operation is not None:
                    self._raise_recovery_contradiction()
            else:
                if current.publish_transaction_id is None:
                    self._raise_recovery_contradiction()
                publish_result = operation_ledger.transaction_result_under_existing_mutex(
                    mutex,
                    current.publish_transaction_id,
                )
            if publish_result is not None:
                # A source-only legacy recovery may intentionally carry a budget
                # that could never authorize the two-file publish.  Only a real
                # operation ancestor needs the current publish context pin.
                context_binding = self._runtime._validate_context_and_manifest(
                    self._context,
                    provenance.publish_manifest,
                    self._budget,
                )
                self._validate_recovery_publish_binding(
                    publish_result[0],
                    current,
                    context_binding,
                    target,
                    recovery_source,
                    provenance,
                )
            self._verify_all_ancestors(mutex)

            if current is None:
                return self._reconcile_source_only_abort(
                    mutex,
                    material,
                    source_lease,
                    source_record,
                    source_receipt,
                    provenance,
                    transaction_binding,
                    copy_binding,
                    target,
                    audit_head.last_segment_sha256,
                    recovery_source,
                )
            if current_receipt is None:
                self._raise_recovery_contradiction()

            if publish_result is not None and publish_result[0].next_state in {
                OperationState.COMMITTED,
                OperationState.RECOVERED_COMMIT,
            }:
                return self._reconcile_committed_publish(
                    mutex,
                    material,
                    source_lease,
                    source_receipt,
                    provenance,
                    current,
                    current_receipt,
                    publish_result,
                    target,
                    audit_head.last_segment_sha256,
                )
            if publish_result is None or publish_result[0].next_state in {
                OperationState.ABORTED,
                OperationState.RECOVERED_ABORT,
            }:
                return self._reconcile_absent_publish(
                    mutex,
                    material,
                    source_lease,
                    current,
                    provenance,
                    target,
                    audit_head.last_segment_sha256,
                    publish_result,
                    recovery_source,
                )
            self._raise_recovery_contradiction()

    def _copy_recovery_result(
        self,
        target_locator: CopyLocator,
    ) -> tuple[CopyTransition, CopyTransitionReceipt] | None:
        matches = tuple(
            history
            for history in self._ledgers._copy_histories.values()
            if history and history[0].target_locator == target_locator
        )
        if len(matches) > 1:
            self._raise_recovery_contradiction()
        if not matches:
            return None
        current = matches[0][-1]
        receipt = self._ledgers._transition_receipts.get(current.transition_id)
        if receipt is None:
            self._raise_recovery_contradiction()
        return current, receipt

    def _reconcile_source_only_abort(
        self,
        mutex: Any,
        material: SyntheticSourceMaterial,
        source_lease: _SyntheticReferenceLease,
        source_record: CopySourceRecord,
        source_receipt: CopySourceReceipt,
        provenance: CopyProvenanceMaterial,
        transaction_binding: str,
        copy_binding: str,
        target: Path,
        recovery_head: str,
        recovery_source: Path | None,
    ) -> None:
        """Close a crash window after SOURCE_OBSERVED but before PREPARED."""

        self._require_target_absent_twice(mutex, target)
        source_lease._checkpoint_unchanged(material.evidence)
        self._require_target_absent_twice(mutex, target)
        plan = self._unstarted_publish_plan(provenance)
        source_relative, target_relative = self._authoritative_publish_relative_paths(
            target,
            recovery_source,
        )
        target_locator = self._copy_target_locator(target)
        publish_binding = self._publish_operation_binding(
            plan,
            None,
            transaction_binding,
            copy_binding,
            source_receipt.anchor,
            source_record.audit_ancestor_sha256,
            target_locator,
            source_relative,
            target_relative,
        )
        absence_witness = self._issue_operation_absence_witness(
            mutex,
            plan,
            None,
            transaction_binding,
            copy_binding,
            source_receipt.anchor,
            source_record.audit_ancestor_sha256,
            target_locator,
            source_relative,
            target_relative,
            publish_binding,
        )
        recovered = self._source_only_recovered_abort_transition(
            source_record,
            source_receipt,
            provenance,
            transaction_binding,
            copy_binding,
            target,
            recovery_head,
            plan,
            publish_binding,
            absence_witness,
        )
        receipt = self._ledgers._append_transition_under_existing_mutex(
            mutex,
            recovered,
        )
        repeated = self._ledgers.transaction_result_under_existing_mutex(
            mutex,
            transaction_binding,
        )
        if repeated != (recovered, receipt):
            self._raise_recovery_contradiction()
        source_lease.verify_unchanged(material.evidence)
        self._require_target_absent_twice(mutex, target)
        self._verify_all_ancestors(mutex)
        return None

    def _reconcile_committed_publish(
        self,
        mutex: Any,
        material: SyntheticSourceMaterial,
        source_lease: _SyntheticReferenceLease,
        source_receipt: CopySourceReceipt,
        provenance: CopyProvenanceMaterial,
        current: CopyTransition,
        current_receipt: CopyTransitionReceipt,
        publish_result: tuple[Any, Any],
        target: Path,
        recovery_head: str,
    ) -> CopyOperationReceipt:
        publish_transition, publish_terminal_receipt = publish_result
        publish_receipt = _receipt_from_authenticated_terminal(
            publish_transition,
            publish_terminal_receipt,
        )
        self._validate_publish_receipt(
            publish_receipt,
            target,
            provenance.publish_manifest,
            expected_transaction_id=current.publish_transaction_id,
        )
        published_target = publish_transition.target_evidence
        if published_target is None:
            self._raise_recovery_contradiction()
        live_target = self._target_evidence(
            target,
            material,
            provenance,
            publish_tree_identity_sha256=(
                published_target.durable_identity_sha256
            ),
            manifest_sha256=published_target.manifest_sha256,
            tree_sha256=published_target.source_tree_sha256,
            topology_sha256=published_target.topology_sha256,
            expected_entry_count=published_target.entry_count,
            expected_total_bytes=published_target.total_bytes,
        )
        if (
            (current.target_evidence is not None and current.target_evidence != live_target)
            or (
                current.publish_terminal_segment_sha256 is not None
                and current.publish_terminal_segment_sha256
                != publish_receipt.committed_segment_sha256
            )
        ):
            self._raise_recovery_contradiction()
        verification = source_lease.verify_unchanged(material.evidence)

        if current.next_state in {CopyState.COMMITTED, CopyState.RECOVERED_COMMIT}:
            self._verify_all_ancestors(mutex)
            return self._receipt(
                material.evidence,
                source_receipt,
                current_receipt,
                publish_receipt,
                verification,
                current.copy_binding_sha256,
                replayed=True,
            )
        if current.next_state not in {
            CopyState.PREPARED,
            CopyState.MUTATED,
            CopyState.POSTCONDITION_VERIFIED,
            CopyState.IN_DOUBT,
        }:
            self._raise_recovery_contradiction()
        recovered = self._recovered_transition(
            current,
            CopyState.RECOVERED_COMMIT,
            recovery_head=recovery_head,
            publish_terminal=publish_receipt.committed_segment_sha256,
            publish_terminal_state=publish_transition.next_state,
            target_evidence=live_target,
        )
        recovered_receipt = self._ledgers._append_transition_under_existing_mutex(
            mutex,
            recovered,
        )
        repeated = self._ledgers.transaction_result_under_existing_mutex(
            mutex,
            recovered.transaction_binding_sha256,
        )
        if repeated != (recovered, recovered_receipt):
            self._raise_recovery_contradiction()
        self._verify_all_ancestors(mutex)
        return self._receipt(
            material.evidence,
            source_receipt,
            recovered_receipt,
            publish_receipt,
            verification,
            recovered.copy_binding_sha256,
            replayed=False,
        )

    def _reconcile_absent_publish(
        self,
        mutex: Any,
        material: SyntheticSourceMaterial,
        source_lease: _SyntheticReferenceLease,
        current: CopyTransition,
        provenance: CopyProvenanceMaterial,
        target: Path,
        recovery_head: str,
        publish_result: tuple[OperationTransition, OperationSegmentReceipt] | None,
        recovery_source: Path | None,
    ) -> None:
        if current.expected_manifest_sha256 != provenance.publish_manifest.manifest_sha256:
            self._raise_recovery_contradiction()
        self._require_target_absent_twice(mutex, target)
        source_lease._checkpoint_unchanged(material.evidence)
        self._require_target_absent_twice(mutex, target)
        if current.next_state in {CopyState.ABORTED, CopyState.RECOVERED_ABORT}:
            source_lease.verify_unchanged(material.evidence)
            self._require_target_absent_twice(mutex, target)
            self._verify_all_ancestors(mutex)
            return None
        if (
            current.next_state not in {CopyState.PREPARED, CopyState.IN_DOUBT}
            or current.target_evidence is not None
        ):
            self._raise_recovery_contradiction()
        publish_terminal: str | None = None
        publish_terminal_state: OperationState | None = None
        absence_witness: CopyOperationAbsenceWitness | None = None
        if publish_result is None:
            source_relative, target_relative = (
                self._authoritative_publish_relative_paths(
                    target,
                    recovery_source,
                )
            )
            publish_binding = self._publish_operation_binding(
                current.publish_operation_plan,
                current.publish_transaction_id,
                current.transaction_binding_sha256,
                current.copy_binding_sha256,
                current.source_anchor,
                current.audit_ancestor_sha256,
                current.target_locator,
                source_relative,
                target_relative,
            )
            if publish_binding != current.publish_operation_binding_sha256:
                self._raise_recovery_contradiction()
            absence_witness = self._issue_operation_absence_witness(
                mutex,
                current.publish_operation_plan,
                current.publish_transaction_id,
                current.transaction_binding_sha256,
                current.copy_binding_sha256,
                current.source_anchor,
                current.audit_ancestor_sha256,
                current.target_locator,
                source_relative,
                target_relative,
                publish_binding,
            )
        else:
            publish_transition, publish_receipt = publish_result
            if publish_transition.next_state not in {
                OperationState.ABORTED,
                OperationState.RECOVERED_ABORT,
            }:
                self._raise_recovery_contradiction()
            publish_terminal = publish_receipt.segment_sha256
            publish_terminal_state = publish_transition.next_state
        recovered = self._recovered_transition(
            current,
            CopyState.RECOVERED_ABORT,
            recovery_head=recovery_head,
            publish_terminal=publish_terminal,
            publish_terminal_state=publish_terminal_state,
            absence_witness=absence_witness,
        )
        receipt = self._ledgers._append_transition_under_existing_mutex(
            mutex,
            recovered,
        )
        repeated = self._ledgers.transaction_result_under_existing_mutex(
            mutex,
            recovered.transaction_binding_sha256,
        )
        if repeated != (recovered, receipt):
            self._raise_recovery_contradiction()
        source_lease.verify_unchanged(material.evidence)
        self._require_target_absent_twice(mutex, target)
        self._verify_all_ancestors(mutex)
        return None

    def _validate_recovery_binding(
        self,
        evidence: SyntheticSourceEvidence,
        source_record: CopySourceRecord,
        source_receipt: CopySourceReceipt,
        provenance: CopyProvenanceMaterial,
        transition: CopyTransition,
        transaction_binding: str,
        copy_binding: str,
        target: Path,
        recovery_source: Path | None,
    ) -> None:
        expected_source = self._source_record(
            evidence,
            transaction_binding,
            copy_binding,
            source_record.audit_ancestor_sha256,
        )
        source_relative, target_relative = self._authoritative_publish_relative_paths(
            target,
            recovery_source,
        )
        expected_publish_binding = self._publish_operation_binding(
            transition.publish_operation_plan,
            transition.publish_transaction_id,
            transaction_binding,
            copy_binding,
            transition.source_anchor,
            transition.audit_ancestor_sha256,
            transition.target_locator,
            source_relative,
            target_relative,
        )
        if (
            source_record != expected_source
            or source_receipt.anchor != transition.source_anchor
            or transition.transaction_binding_sha256 != transaction_binding
            or transition.copy_binding_sha256 != copy_binding
            or transition.audit_ancestor_sha256
            != source_record.audit_ancestor_sha256
            or transition.classification is not self._context.classification
            or transition.target_locator != self._copy_target_locator(target)
            or transition.expected_manifest_sha256
            != provenance.publish_manifest.manifest_sha256
            or transition.provenance_metadata_sha256
            != provenance.provenance_sha256
            or transition.budget_sha256 != self._budget.digest
            or transition.publish_operation_binding_sha256
            != expected_publish_binding
        ):
            self._raise_recovery_contradiction()

    def _validate_source_only_recovery_binding(
        self,
        evidence: SyntheticSourceEvidence,
        source_record: CopySourceRecord,
        source_receipt: CopySourceReceipt,
        transaction_binding: str,
        copy_binding: str,
    ) -> None:
        expected_source = self._source_record(
            evidence,
            transaction_binding,
            copy_binding,
            source_record.audit_ancestor_sha256,
        )
        if (
            source_record != expected_source
            or source_receipt.record_id != source_record.record_id
            or source_receipt.anchor.record_id != source_record.record_id
            or source_record.transaction_binding_sha256 != transaction_binding
            or source_record.copy_binding_sha256 != copy_binding
            or source_record.classification is not self._context.classification
        ):
            self._raise_recovery_contradiction()

    def _validate_recovery_publish_binding(
        self,
        transition: OperationTransition,
        copy_transition: CopyTransition,
        context_binding: str,
        target: Path,
        recovery_source: Path | None,
        provenance: CopyProvenanceMaterial,
    ) -> None:
        operation_ledger = self._runtime._operation_ledger
        if type(operation_ledger) is not DurableOperationLedger:
            self._raise_recovery_contradiction()
        operation_reference = operation_ledger.operation_reference(
            self._context.operation_id,
            self._context.classification,
        )
        if (
            type(transition) is not OperationTransition
            or type(copy_transition) is not CopyTransition
            or type(provenance) is not CopyProvenanceMaterial
            or type(target) is not type(Path())
            or not _is_sha256(context_binding)
            or transition.next_state
            not in {
                OperationState.ABORTED,
                OperationState.RECOVERED_ABORT,
                OperationState.COMMITTED,
                OperationState.RECOVERED_COMMIT,
            }
        ):
            self._raise_recovery_contradiction()
        source_relative, target_relative = self._authoritative_publish_relative_paths(
            target,
            recovery_source,
        )
        expected_source_locator = source_relative.as_posix()
        expected_target_locator = target_relative.as_posix()
        if self._context.classification is DataClassification.RESTRICTED:
            expected_source_locator = operation_ledger.locator_hmac(
                expected_source_locator,
                transaction_id=transition.transaction_id,
                role=OperationLocatorRole.SOURCE,
            )
            expected_target_locator = operation_ledger.locator_hmac(
                expected_target_locator,
                transaction_id=transition.transaction_id,
                role=OperationLocatorRole.TARGET,
            )
            expected_locator_mode = OperationLocatorMode.HMAC_ONLY
        else:
            expected_locator_mode = OperationLocatorMode.SAFE_RELATIVE
        plan = copy_transition.publish_operation_plan
        planned_operation = self._ledgers._project_operation_transition(
            transition,
            audit_ancestor_sha256=plan.audit_ancestor_sha256,
        )
        exact_copy_binding = (
            transition.transaction_id == copy_transition.publish_transaction_id
            and plan == planned_operation
            and copy_transition.publish_operation_binding_sha256
            == self._publish_operation_binding(
                plan,
                copy_transition.publish_transaction_id,
                copy_transition.transaction_binding_sha256,
                copy_transition.copy_binding_sha256,
                copy_transition.source_anchor,
                copy_transition.audit_ancestor_sha256,
                copy_transition.target_locator,
                source_relative,
                target_relative,
            )
        )
        committed = transition.next_state in {
            OperationState.COMMITTED,
            OperationState.RECOVERED_COMMIT,
        }
        source_tree = transition.source_evidence
        target_tree = transition.target_evidence
        exact_tree_semantics = (
            type(source_tree) is OperationTreeEvidence
            and source_tree.manifest_sha256
            == provenance.publish_manifest.manifest_sha256
            and source_tree.entry_count == 2
            and source_tree.total_bytes
            == self._manifest.entries[0].size_bytes
            + len(provenance.provenance_bytes)
            and (
                (committed and target_tree == source_tree)
                or (not committed and target_tree is None)
            )
        )
        if (
            transition.operation_id != operation_reference
            or not exact_copy_binding
            or transition.context_binding_sha256 != context_binding
            or transition.manifest_sha256
            != provenance.publish_manifest.manifest_sha256
            or transition.budget_sha256 != self._budget.digest
            or transition.classification is not self._context.classification
            or transition.locator_mode is not expected_locator_mode
            or transition.source_locator != expected_source_locator
            or transition.target_locator != expected_target_locator
            or not exact_tree_semantics
        ):
            self._raise_recovery_contradiction()
        if (
            copy_transition.target_evidence is not None
            and not self._operation_target_matches_copy(
                transition.target_evidence,
                copy_transition.target_evidence,
            )
        ):
            self._raise_recovery_contradiction()

    def _recovered_transition(
        self,
        previous: CopyTransition,
        state: CopyState,
        *,
        recovery_head: str,
        publish_terminal: str | None = None,
        publish_terminal_state: OperationState | None = None,
        absence_witness: CopyOperationAbsenceWitness | None = None,
        target_evidence: CopyTargetEvidence | None = None,
    ) -> CopyTransition:
        recovered_commit = state is CopyState.RECOVERED_COMMIT
        if state not in {CopyState.RECOVERED_COMMIT, CopyState.RECOVERED_ABORT}:
            self._raise_recovery_contradiction()
        return CopyTransition(
            transition_id=self._transition_id(
                previous.transaction_binding_sha256,
                previous.next_state,
                state,
            ),
            transaction_binding_sha256=previous.transaction_binding_sha256,
            copy_binding_sha256=previous.copy_binding_sha256,
            previous_state=previous.next_state,
            next_state=state,
            source_anchor=previous.source_anchor,
            audit_ancestor_sha256=previous.audit_ancestor_sha256,
            classification=previous.classification,
            target_locator=previous.target_locator,
            expected_manifest_sha256=previous.expected_manifest_sha256,
            provenance_metadata_sha256=previous.provenance_metadata_sha256,
            budget_sha256=previous.budget_sha256,
            publish_operation_binding_sha256=(
                previous.publish_operation_binding_sha256
            ),
            publish_operation_plan=previous.publish_operation_plan,
            mutation_attempted=(True if recovered_commit else previous.mutation_attempted),
            publish_transaction_id=previous.publish_transaction_id,
            publish_terminal_segment_sha256=publish_terminal,
            publish_terminal_state=publish_terminal_state,
            publish_operation_absence_witness=absence_witness,
            target_evidence=(target_evidence if recovered_commit else None),
            recovery_reason=(
                "PUBLISH_COMMITTED_TARGET_EXACT_SOURCE_EXACT"
                if recovered_commit
                else "PUBLISH_NOT_NATIVE_TARGET_ABSENT_SOURCE_EXACT"
            ),
            recovery_authority_head_sha256=recovery_head,
        )

    def _source_only_recovered_abort_transition(
        self,
        source_record: CopySourceRecord,
        source_receipt: CopySourceReceipt,
        provenance: CopyProvenanceMaterial,
        transaction_binding: str,
        copy_binding: str,
        target: Path,
        recovery_head: str,
        plan: CopyPublishOperationPlan,
        publish_binding: str,
        absence_witness: CopyOperationAbsenceWitness,
    ) -> CopyTransition:
        return CopyTransition(
            transition_id=self._transition_id(
                transaction_binding,
                None,
                CopyState.RECOVERED_ABORT,
            ),
            transaction_binding_sha256=transaction_binding,
            copy_binding_sha256=copy_binding,
            previous_state=None,
            next_state=CopyState.RECOVERED_ABORT,
            source_anchor=source_receipt.anchor,
            audit_ancestor_sha256=source_record.audit_ancestor_sha256,
            classification=self._context.classification,
            target_locator=self._copy_target_locator(target),
            expected_manifest_sha256=provenance.publish_manifest.manifest_sha256,
            provenance_metadata_sha256=provenance.provenance_sha256,
            budget_sha256=self._budget.digest,
            publish_operation_binding_sha256=publish_binding,
            publish_operation_plan=plan,
            mutation_attempted=False,
            publish_operation_absence_witness=absence_witness,
            recovery_reason="PUBLISH_NOT_NATIVE_TARGET_ABSENT_SOURCE_EXACT",
            recovery_authority_head_sha256=recovery_head,
        )

    def _require_target_absent_twice(self, mutex: Any, target: Path) -> None:
        if (
            type(target) is not type(Path())
            or target == Path()
            or target.is_absolute()
            or any(part in {"", ".", ".."} for part in target.parts)
        ):
            self._raise_recovery_contradiction()
        self._runtime._writer._require_directory_target_absent_under_existing_mutex(
            mutex,
            target,
        )

    def _raise_recovery_contradiction(self) -> NoReturn:
        try:
            self._ledgers._seal(CopyLedgerCode.CROSS_REFERENCE_INVALID)
        except BaseException:
            self._runtime._writer.seal_after_indeterminate_mutation()
        raise CopyOperationError(
            CopyOperationCode.RECOVERY_CONTRADICTION,
            "recovery evidence cannot uniquely prove one append-only truth",
        ) from None

    def _copy_provenance_material(
        self,
        source_record: CopySourceRecord,
        source_receipt: CopySourceReceipt,
    ) -> CopyProvenanceMaterial:
        provenance = build_copy_provenance_material(
            source_record,
            source_receipt,
            manifest_id=self._manifest.manifest_id,
        )
        if (
            provenance.payload_manifest_sha256 != self._manifest.manifest_sha256
            or provenance.publish_manifest.classification
            is not self._context.classification
        ):
            raise CopyOperationError(
                CopyOperationCode.MANIFEST_MISMATCH,
                "derived Copy provenance differs from the exact payload manifest",
            )
        return provenance

    def _require_exact_publish_budget(
        self,
        provenance: CopyProvenanceMaterial,
    ) -> None:
        if type(provenance) is not CopyProvenanceMaterial:
            raise CopyOperationError(
                CopyOperationCode.MANIFEST_MISMATCH,
                "copy publish budget requires exact provenance material",
            )
        try:
            self._runtime._validate_context_and_manifest(
                self._context,
                provenance.publish_manifest,
                self._budget,
            )
        except JobOperationError as error:
            raise CopyOperationError(
                CopyOperationCode.MANIFEST_MISMATCH,
                "derived Copy publish manifest exceeds its exact operation contract "
                f"({error.code.value})",
            ) from None

    def _require_worst_case_publish_budget(self) -> None:
        """Prove the fixed two-file envelope before opening external input."""

        payload_entry = self._manifest.entries[0]
        provenance_path_bytes = len(COPY_PROVENANCE_FILE_NAME.encode("utf-8"))
        payload_path_bytes = len(payload_entry.relative_path.encode("utf-8"))
        budget = self._budget
        if (
            budget.maximum_entries < 2
            or budget.maximum_files < 2
            or budget.maximum_depth < 1
            or budget.maximum_file_bytes
            < max(payload_entry.size_bytes, COPY_PROVENANCE_MAX_BYTES)
            or budget.maximum_total_bytes
            < payload_entry.size_bytes + COPY_PROVENANCE_MAX_BYTES
            or budget.maximum_path_utf8_bytes
            < max(payload_path_bytes, provenance_path_bytes)
            or budget.maximum_open_handles < 3
        ):
            raise CopyOperationError(
                CopyOperationCode.MANIFEST_MISMATCH,
                "copy budget cannot contain the immutable two-file envelope",
            )
        try:
            worst_case = DeclaredTreeManifest(
                manifest_id=self._manifest.manifest_id,
                classification=self._manifest.classification,
                entries=(
                    payload_entry,
                    DeclaredTreeEntry(
                        COPY_PROVENANCE_FILE_NAME,
                        TreeEntryKind.FILE,
                        COPY_PROVENANCE_MAX_BYTES,
                        "f" * 64,
                    ),
                ),
            )
            self._runtime._validate_context_and_manifest(
                self._context,
                worst_case,
                budget,
            )
        except JobOperationError as error:
            raise CopyOperationError(
                CopyOperationCode.MANIFEST_MISMATCH,
                "copy budget cannot contain the worst-case provenance manifest "
                f"({error.code.value})",
            ) from None

    def _prepare_source_for_execute(
        self,
        evidence: SyntheticSourceEvidence,
        transaction_binding: str,
        copy_binding: str,
    ) -> tuple[
        CopySourceRecord,
        CopySourceReceipt,
        CopyProvenanceMaterial,
        bool,
    ]:
        """Append SOURCE_OBSERVED once, before deriving the publish manifest."""

        operation_ledger = self._runtime._operation_ledger
        if type(operation_ledger) is not DurableOperationLedger:
            raise CopyOperationError(
                CopyOperationCode.LEDGER_MISMATCH,
                "copy publish ledger is unavailable",
            )
        with self._runtime._writer.acquire_runtime_mutex() as mutex:
            audit_head = self._runtime._ledger._rescan_under_existing_mutex(mutex)
            self._runtime._validate_operation_audit_bindings(mutex)
            head = self._ledgers._rescan_under_existing_mutex(mutex)
            if (
                self._ledgers.signing_revision_id
                != operation_ledger.signing_revision_id
                or not _is_sha256(audit_head.last_segment_sha256)
            ):
                raise CopyOperationError(
                    CopyOperationCode.LEDGER_MISMATCH,
                    "copy ledgers do not share one authenticated active revision",
                )
            existing = self._ledgers.transaction_source_result_under_existing_mutex(
                mutex,
                transaction_binding,
            )
            created = existing is None
            if existing is None:
                if head.pending_source_count:
                    raise CopyOperationError(
                        CopyOperationCode.RECOVERY_REQUIRED,
                        "an earlier Copy source fact requires reconciliation",
                    )
                source_record = self._source_record(
                    evidence,
                    transaction_binding,
                    copy_binding,
                    audit_head.last_segment_sha256,
                )
                source_receipt = self._ledgers._append_source_under_existing_mutex(
                    mutex,
                    source_record,
                )
            else:
                source_record, source_receipt = existing
                self._validate_source_only_recovery_binding(
                    evidence,
                    source_record,
                    source_receipt,
                    transaction_binding,
                    copy_binding,
                )
            provenance = self._copy_provenance_material(
                source_record,
                source_receipt,
            )
            # The conservative preflight ran before the source was opened.  This
            # exact check should therefore be infallible for an honest immutable
            # budget, but keeps the final manifest tied to its actual bytes.
            self._require_exact_publish_budget(provenance)
            self._verify_all_ancestors(mutex)
            return source_record, source_receipt, provenance, created

    def _load_source_for_recovery(
        self,
        evidence: SyntheticSourceEvidence,
        transaction_binding: str,
        copy_binding: str,
    ) -> tuple[CopySourceRecord, CopySourceReceipt, CopyProvenanceMaterial]:
        """Authenticate an existing source fact without appending recovery data."""

        with self._runtime._writer.acquire_runtime_mutex() as mutex:
            self._runtime._ledger._rescan_under_existing_mutex(mutex)
            self._runtime._validate_operation_audit_bindings(mutex)
            self._ledgers._rescan_under_existing_mutex(mutex)
            existing = self._ledgers.transaction_source_result_under_existing_mutex(
                mutex,
                transaction_binding,
            )
            if existing is None:
                self._raise_recovery_contradiction()
            source_record, source_receipt = existing
            self._validate_source_only_recovery_binding(
                evidence,
                source_record,
                source_receipt,
                transaction_binding,
                copy_binding,
            )
            provenance = self._copy_provenance_material(
                source_record,
                source_receipt,
            )
            self._verify_all_ancestors(mutex)
            return source_record, source_receipt, provenance

    def _execute_new(
        self,
        permit: _CopyExecutionPermit,
        material: SyntheticSourceMaterial,
        source_lease: _SyntheticReferenceLease,
        source_record: CopySourceRecord,
        source_receipt: CopySourceReceipt,
        provenance: CopyProvenanceMaterial,
        transaction_binding: str,
        copy_binding: str,
        target: Path,
    ) -> CopyOperationReceipt:
        self._require_exact_execution_envelope(
            permit,
            material,
            source_lease,
            source_record,
            source_receipt,
            provenance,
            transaction_binding,
            copy_binding,
            target,
        )
        self._consume_execution_permit(
            permit,
            source_lease,
            material,
            transaction_binding,
            copy_binding,
            target,
            provenance.publish_manifest,
        )
        operation = self._runtime.begin_operation(
            self._context,
            provenance.publish_manifest,
            self._budget,
        )
        current: CopyTransition | None = None
        native_boundary_entered = False
        verification: SyntheticSourceVerification | None = None
        receipt: CopyOperationReceipt | None = None
        seal_after_operation_close = [False]
        with ExitStack() as operation_scope:
            operation_scope.callback(
                self._seal_after_operation_close,
                seal_after_operation_close,
            )
            operation_scope.enter_context(operation)
            try:
                self._validate_ledgers_for_new_operation(
                    operation,
                    source_record,
                    source_receipt,
                )
                staging = operation.create_fixed_staging()
                staging.create_declared_file(
                    SYNTHETIC_REFERENCE_PAYLOAD_NAME,
                    material.payload,
                )
                staging.create_declared_file(
                    COPY_PROVENANCE_FILE_NAME,
                    provenance.provenance_bytes,
                )
                observed = staging.seal_and_observe()
                observed_evidence = observed.evidence
                token = operation.authorize_publish(
                    observed,
                    target,
                    checkpoint_manifest_sha256=self._checkpoint_digest(
                        provenance,
                        source_receipt,
                    ),
                )
                if operation._transaction_id is None:
                    raise CopyOperationError(
                        CopyOperationCode.PUBLISH_FAILED,
                        "publish reservation lost its exact transaction identity",
                    )
                (
                    publish_plan,
                    operation_source,
                    operation_target,
                ) = self._reserved_publish_plan(operation, observed, target)
                prepared = self._prepared_transition(
                    source_record,
                    source_receipt,
                    provenance,
                    transaction_binding,
                    copy_binding,
                    target,
                    publish_transaction_id=operation._transaction_id,
                    publish_plan=publish_plan,
                    operation_source=operation_source,
                    operation_target=operation_target,
                )
                self._ledgers._append_transition_under_existing_mutex(
                    operation._mutex,
                    prepared,
                )
                current = prepared
                native_boundary_entered = True
                publish_receipt = operation.execute_publish_pair(token, observed)
                self._validate_publish_receipt(
                    publish_receipt,
                    target,
                    provenance.publish_manifest,
                    expected_transaction_id=prepared.publish_transaction_id,
                )
                self._validate_authenticated_publish_result(
                    operation._mutex,
                    prepared,
                    publish_receipt,
                    provenance,
                )
                target_evidence = self._target_evidence(
                    target,
                    material,
                    provenance,
                    publish_tree_identity_sha256=(
                        publish_receipt.target_identity_hmac_sha256
                    ),
                    manifest_sha256=observed_evidence.manifest_sha256,
                    tree_sha256=observed_evidence.source_tree_sha256,
                    topology_sha256=observed_evidence.topology_sha256,
                    expected_entry_count=observed_evidence.entry_count,
                    expected_total_bytes=observed_evidence.total_bytes,
                )
                verification = source_lease.verify_unchanged(material.evidence)
                mutated = self._advance_transition(
                    current,
                    CopyState.MUTATED,
                    publish_terminal=publish_receipt.committed_segment_sha256,
                    publish_terminal_state=OperationState.COMMITTED,
                )
                self._ledgers._append_transition_under_existing_mutex(
                    operation._mutex,
                    mutated,
                )
                current = mutated
                verified = self._advance_transition(
                    current,
                    CopyState.POSTCONDITION_VERIFIED,
                    target_evidence=target_evidence,
                )
                self._ledgers._append_transition_under_existing_mutex(
                    operation._mutex,
                    verified,
                )
                current = verified
                committed = self._advance_transition(
                    current,
                    CopyState.COMMITTED,
                )
                terminal_receipt = (
                    self._ledgers._append_transition_under_existing_mutex(
                        operation._mutex,
                        committed,
                    )
                )
                current = committed
                self._verify_all_ancestors(operation._mutex)
                receipt = self._receipt(
                    material.evidence,
                    source_receipt,
                    terminal_receipt,
                    publish_receipt,
                    verification,
                    current.copy_binding_sha256,
                    replayed=False,
                )
            except BaseException as error:
                if current is not None and current.next_state not in {
                    CopyState.ABORTED,
                    CopyState.COMMITTED,
                    CopyState.RECOVERED_ABORT,
                    CopyState.RECOVERED_COMMIT,
                }:
                    try:
                        seal_after_operation_close[0] = self._append_failure_fact(
                            operation,
                            current,
                            error,
                            native_boundary_entered=native_boundary_entered,
                        )
                    except BaseException:
                        seal_after_operation_close[0] = True
                        raise
                raise
        if receipt is None or verification is None:
            raise CopyOperationError(
                CopyOperationCode.INDETERMINATE,
                "copy publish returned without complete terminal evidence",
            )
        return receipt

    def _try_replay(
        self,
        permit: _CopyExecutionPermit,
        material: SyntheticSourceMaterial,
        source_lease: _SyntheticReferenceLease,
        source_record: CopySourceRecord,
        source_receipt: CopySourceReceipt,
        provenance: CopyProvenanceMaterial,
        transaction_binding: str,
        copy_binding: str,
        target: Path,
    ) -> CopyOperationReceipt | None:
        self._require_exact_execution_envelope(
            permit,
            material,
            source_lease,
            source_record,
            source_receipt,
            provenance,
            transaction_binding,
            copy_binding,
            target,
        )
        self._validate_execution_permit(
            permit,
            source_lease,
            material,
            transaction_binding,
            copy_binding,
            target,
            provenance.publish_manifest,
        )
        with self._runtime._writer.acquire_runtime_mutex() as mutex:
            self._ledgers._rescan_under_existing_mutex(mutex)
            result = self._ledgers.transaction_result_under_existing_mutex(
                mutex,
                transaction_binding,
            )
            if result is None:
                return None
            transition, terminal_receipt = result
            if transition.next_state not in {
                CopyState.COMMITTED,
                CopyState.RECOVERED_COMMIT,
            }:
                raise CopyOperationError(
                    CopyOperationCode.RECOVERY_REQUIRED,
                    "existing copy transaction is not an exact terminal commit",
                )
            authenticated_source = self._ledgers.source_result_under_existing_mutex(
                mutex,
                transition.source_anchor.record_id,
            )
            if authenticated_source != (source_record, source_receipt):
                raise CopyOperationError(
                    CopyOperationCode.REPLAY_CONFLICT,
                    "committed copy lost its authenticated source record",
                )
            self._validate_replay_binding(
                material.evidence,
                source_record,
                source_receipt,
                provenance,
                transition,
                transaction_binding,
                copy_binding,
                target,
            )
            self._consume_execution_permit(
                permit,
                source_lease,
                material,
                transaction_binding,
                copy_binding,
                target,
                provenance.publish_manifest,
            )

        publish_receipt = self._runtime.replay_committed_publish(
            self._context,
            provenance.publish_manifest,
            self._budget,
        )
        if (
            publish_receipt.committed_segment_sha256
            != transition.publish_terminal_segment_sha256
        ):
            raise CopyOperationError(
                CopyOperationCode.REPLAY_CONFLICT,
                "publish replay differs from the Copy terminal ancestor",
            )
        with self._runtime._writer.acquire_runtime_mutex() as mutex:
            repeated = self._ledgers.transaction_result_under_existing_mutex(
                mutex,
                transaction_binding,
            )
            if repeated is None or repeated[0] != transition or repeated[1] != terminal_receipt:
                raise CopyOperationError(
                    CopyOperationCode.REPLAY_CONFLICT,
                    "copy terminal changed during replay",
                )
            self._validate_publish_receipt(
                publish_receipt,
                target,
                provenance.publish_manifest,
                expected_transaction_id=transition.publish_transaction_id,
            )
            self._validate_authenticated_publish_result(
                mutex,
                transition,
                publish_receipt,
                provenance,
            )
            live_target = self._target_evidence(
                target,
                material,
                provenance,
                publish_tree_identity_sha256=(
                    publish_receipt.target_identity_hmac_sha256
                ),
                manifest_sha256=transition.expected_manifest_sha256,
                tree_sha256=(
                    transition.target_evidence.tree_sha256
                    if transition.target_evidence is not None
                    else ""
                ),
                topology_sha256=(
                    transition.target_evidence.topology_sha256
                    if transition.target_evidence is not None
                    else ""
                ),
                expected_entry_count=(
                    transition.target_evidence.entry_count
                    if transition.target_evidence is not None
                    else -1
                ),
                expected_total_bytes=(
                    transition.target_evidence.total_bytes
                    if transition.target_evidence is not None
                    else -1
                ),
            )
            if live_target != transition.target_evidence:
                self._seal_cross_reference_failure()
            verification = source_lease.verify_unchanged(material.evidence)
            self._verify_all_ancestors(mutex)
        return self._receipt(
            material.evidence,
            source_receipt,
            terminal_receipt,
            publish_receipt,
            verification,
            transition.copy_binding_sha256,
            replayed=True,
        )

    def _validate_ledgers_for_new_operation(
        self,
        operation: _OperationLease,
        source_record: CopySourceRecord,
        source_receipt: CopySourceReceipt,
    ) -> None:
        head = self._ledgers._rescan_under_existing_mutex(operation._mutex)
        if (
            self._ledgers.signing_revision_id
            != operation._ledger_head.active_revision_id
            or self._runtime._operation_ledger is None
            or self._runtime._operation_ledger.signing_revision_id
            != operation._ledger_head.active_revision_id
        ):
            raise CopyOperationError(
                CopyOperationCode.LEDGER_MISMATCH,
                "copy, audit, and publish ledgers do not share one active revision",
            )
        self._verify_all_ancestors(operation._mutex)
        exact_source = self._ledgers.transaction_source_result_under_existing_mutex(
            operation._mutex,
            source_record.transaction_binding_sha256,
        )
        existing_copy = self._ledgers.transaction_result_under_existing_mutex(
            operation._mutex,
            source_record.transaction_binding_sha256,
        )
        if (
            head.pending_source_count != 1
            or exact_source != (source_record, source_receipt)
            or existing_copy is not None
        ):
            raise CopyOperationError(
                CopyOperationCode.RECOVERY_REQUIRED,
                "new Copy work requires exactly its own source-only pending fact",
            )

    def _verify_all_ancestors(self, mutex: Any) -> None:
        operation_ledger = self._runtime._operation_ledger
        if type(operation_ledger) is not DurableOperationLedger:
            raise CopyOperationError(
                CopyOperationCode.LEDGER_MISMATCH,
                "copy publish ledger is unavailable",
            )
        capability = (
            self._ledgers._issue_authenticated_ancestors_under_existing_mutex(
                mutex,
                self._runtime._ledger,
                operation_ledger,
            )
        )
        self._ledgers._verify_external_ancestors_under_existing_mutex(
            mutex,
            capability,
        )

    def _source_record(
        self,
        evidence: SyntheticSourceEvidence,
        transaction_binding: str,
        copy_binding: str,
        audit_head: str,
    ) -> CopySourceRecord:
        source_evidence = CopyFileEvidence(
            identity_hmac_sha256=evidence.source_identity_digest,
            size_bytes=evidence.size_bytes,
            sha256=evidence.sha256,
            change_evidence_sha256=evidence.stability_digest,
        )
        return CopySourceRecord(
            record_id=_digest(
                b"COPY-SOURCE-RECORD-ID-V1",
                transaction_binding.encode("ascii"),
                evidence.source_reference.encode("ascii"),
            ),
            transaction_binding_sha256=transaction_binding,
            copy_binding_sha256=copy_binding,
            reference_policy_digest=evidence.policy_digest,
            audit_ancestor_sha256=audit_head,
            classification=evidence.classification,
            source_locator=CopyLocator(
                CopyLocatorMode.HMAC_ONLY,
                evidence.locator_hmac,
            ),
            source_evidence=source_evidence,
        )

    def _prepared_transition(
        self,
        source_record: CopySourceRecord,
        source_receipt: CopySourceReceipt,
        provenance: CopyProvenanceMaterial,
        transaction_binding: str,
        copy_binding: str,
        target: Path,
        *,
        publish_transaction_id: str,
        publish_plan: CopyPublishOperationPlan,
        operation_source: Path,
        operation_target: Path,
    ) -> CopyTransition:
        target_locator = self._copy_target_locator(target)
        return CopyTransition(
            transition_id=self._transition_id(
                transaction_binding,
                None,
                CopyState.PREPARED,
            ),
            transaction_binding_sha256=transaction_binding,
            copy_binding_sha256=copy_binding,
            previous_state=None,
            next_state=CopyState.PREPARED,
            source_anchor=source_receipt.anchor,
            audit_ancestor_sha256=source_record.audit_ancestor_sha256,
            classification=self._context.classification,
            target_locator=target_locator,
            expected_manifest_sha256=provenance.publish_manifest.manifest_sha256,
            provenance_metadata_sha256=provenance.provenance_sha256,
            budget_sha256=self._budget.digest,
            publish_operation_binding_sha256=self._publish_operation_binding(
                publish_plan,
                publish_transaction_id,
                transaction_binding,
                copy_binding,
                source_receipt.anchor,
                source_record.audit_ancestor_sha256,
                target_locator,
                operation_source,
                operation_target,
            ),
            publish_operation_plan=publish_plan,
            mutation_attempted=False,
            publish_transaction_id=publish_transaction_id,
        )

    def _advance_transition(
        self,
        previous: CopyTransition,
        state: CopyState,
        *,
        publish_terminal: str | None = None,
        publish_terminal_state: OperationState | None = None,
        target_evidence: CopyTargetEvidence | None = None,
    ) -> CopyTransition:
        return CopyTransition(
            transition_id=self._transition_id(
                previous.transaction_binding_sha256,
                previous.next_state,
                state,
            ),
            transaction_binding_sha256=previous.transaction_binding_sha256,
            copy_binding_sha256=previous.copy_binding_sha256,
            previous_state=previous.next_state,
            next_state=state,
            source_anchor=previous.source_anchor,
            audit_ancestor_sha256=previous.audit_ancestor_sha256,
            classification=previous.classification,
            target_locator=previous.target_locator,
            expected_manifest_sha256=previous.expected_manifest_sha256,
            provenance_metadata_sha256=previous.provenance_metadata_sha256,
            budget_sha256=previous.budget_sha256,
            publish_operation_binding_sha256=(
                previous.publish_operation_binding_sha256
            ),
            publish_operation_plan=previous.publish_operation_plan,
            mutation_attempted=True,
            publish_transaction_id=previous.publish_transaction_id,
            publish_terminal_segment_sha256=(
                publish_terminal
                if publish_terminal is not None
                else previous.publish_terminal_segment_sha256
            ),
            publish_terminal_state=(
                publish_terminal_state
                if publish_terminal_state is not None
                else previous.publish_terminal_state
            ),
            publish_operation_absence_witness=(
                previous.publish_operation_absence_witness
            ),
            target_evidence=(
                target_evidence
                if target_evidence is not None
                else previous.target_evidence
            ),
        )

    def _append_failure_fact(
        self,
        operation: _OperationLease,
        previous: CopyTransition,
        error: BaseException,
        *,
        native_boundary_entered: bool,
    ) -> bool:
        mutation_possible = True
        publish_terminal = previous.publish_terminal_segment_sha256
        publish_terminal_state = previous.publish_terminal_state
        next_state = CopyState.IN_DOUBT
        operation_ledger = self._runtime._operation_ledger
        if (
            native_boundary_entered
            and type(operation_ledger) is DurableOperationLedger
            and previous.publish_transaction_id is not None
        ):
            try:
                durable = operation_ledger.transaction_result_under_existing_mutex(
                    operation._mutex,
                    previous.publish_transaction_id,
                )
                if durable is not None and durable[0].next_state in {
                    OperationState.ABORTED,
                    OperationState.RECOVERED_ABORT,
                }:
                    mutation_possible = False
                    next_state = CopyState.ABORTED
                    publish_terminal_state = durable[0].next_state
                    publish_terminal = durable[1].segment_sha256
                elif durable is not None and durable[0].next_state in {
                    OperationState.COMMITTED,
                    OperationState.RECOVERED_COMMIT,
                }:
                    publish_terminal_state = durable[0].next_state
                    publish_terminal = durable[1].segment_sha256
            except BaseException:
                mutation_possible = True
        try:
            failure = CopyTransition(
                transition_id=self._transition_id(
                    previous.transaction_binding_sha256,
                    previous.next_state,
                    next_state,
                ),
                transaction_binding_sha256=previous.transaction_binding_sha256,
                copy_binding_sha256=previous.copy_binding_sha256,
                previous_state=previous.next_state,
                next_state=next_state,
                source_anchor=previous.source_anchor,
                audit_ancestor_sha256=previous.audit_ancestor_sha256,
                classification=previous.classification,
                target_locator=previous.target_locator,
                expected_manifest_sha256=previous.expected_manifest_sha256,
                provenance_metadata_sha256=previous.provenance_metadata_sha256,
                budget_sha256=previous.budget_sha256,
                publish_operation_binding_sha256=(
                    previous.publish_operation_binding_sha256
                ),
                publish_operation_plan=previous.publish_operation_plan,
                mutation_attempted=mutation_possible,
                publish_transaction_id=previous.publish_transaction_id,
                publish_terminal_segment_sha256=publish_terminal,
                publish_terminal_state=publish_terminal_state,
                publish_operation_absence_witness=(
                    previous.publish_operation_absence_witness
                ),
                target_evidence=(
                    previous.target_evidence if mutation_possible else None
                ),
                error_code=self._error_code(error),
            )
            self._ledgers._append_transition_under_existing_mutex(
                operation._mutex,
                failure,
            )
        except BaseException:
            raise CopyOperationError(
                CopyOperationCode.INDETERMINATE,
                "copy failure could not persist its terminal safety fact",
            ) from None
        return mutation_possible

    def _seal_after_operation_close(self, required: list[bool]) -> None:
        if (
            type(required) is not list
            or len(required) != 1
            or type(required[0]) is not bool
        ):
            self._runtime._writer.seal_after_indeterminate_mutation()
            return
        if required[0]:
            self._runtime._writer.seal_after_indeterminate_mutation()

    def _target_evidence(
        self,
        target: Path,
        material: SyntheticSourceMaterial,
        provenance: CopyProvenanceMaterial,
        *,
        publish_tree_identity_sha256: str,
        manifest_sha256: str,
        tree_sha256: str,
        topology_sha256: str,
        expected_entry_count: int,
        expected_total_bytes: int,
    ) -> CopyTargetEvidence:
        if (
            type(material) is not SyntheticSourceMaterial
            or type(provenance) is not CopyProvenanceMaterial
            or manifest_sha256 != provenance.publish_manifest.manifest_sha256
            or expected_entry_count != 2
            or expected_total_bytes
            != material.evidence.size_bytes + len(provenance.provenance_bytes)
            or not all(
            _is_sha256(value)
            for value in (
                publish_tree_identity_sha256,
                manifest_sha256,
                tree_sha256,
                topology_sha256,
            )
            )
        ):
            raise CopyOperationError(
                CopyOperationCode.TARGET_VERIFICATION_FAILED,
                "target tree evidence is incomplete",
            )
        first = self._read_target(target, provenance)
        second = self._read_target(target, provenance)
        if first != second or len(first.entries) != 2:
            raise CopyOperationError(
                CopyOperationCode.TARGET_VERIFICATION_FAILED,
                "target changed during independent handle rescans",
            )
        first_entries = {entry.name: entry for entry in first.entries}
        second_entries = {entry.name: entry for entry in second.entries}
        if set(first_entries) != {
            SYNTHETIC_REFERENCE_PAYLOAD_NAME,
            COPY_PROVENANCE_FILE_NAME,
        } or set(second_entries) != set(first_entries):
            raise CopyOperationError(
                CopyOperationCode.TARGET_VERIFICATION_FAILED,
                "target does not contain the exact payload and provenance objects",
            )
        payload_entry = first_entries[SYNTHETIC_REFERENCE_PAYLOAD_NAME]
        provenance_entry = first_entries[COPY_PROVENANCE_FILE_NAME]
        second_payload = second_entries[SYNTHETIC_REFERENCE_PAYLOAD_NAME]
        second_provenance = second_entries[COPY_PROVENANCE_FILE_NAME]
        operation_ledger = self._runtime._operation_ledger
        if type(operation_ledger) is not DurableOperationLedger:
            raise CopyOperationError(
                CopyOperationCode.TARGET_VERIFICATION_FAILED,
                "target identity projection authority is unavailable",
            )
        try:
            first_identity = (
                operation_ledger.durable_object_identity_digest(
                    first.root_identity_material,
                ),
                operation_ledger.durable_object_identity_digest(
                    payload_entry.identity_material,
                ),
                operation_ledger.durable_object_identity_digest(
                    provenance_entry.identity_material,
                ),
                operation_ledger.durable_tree_identity_digest(
                    first.tree_identity_material,
                ),
            )
            second_identity = (
                operation_ledger.durable_object_identity_digest(
                    second.root_identity_material,
                ),
                operation_ledger.durable_object_identity_digest(
                    second_payload.identity_material,
                ),
                operation_ledger.durable_object_identity_digest(
                    second_provenance.identity_material,
                ),
                operation_ledger.durable_tree_identity_digest(
                    second.tree_identity_material,
                ),
            )
        except OperationLedgerError:
            raise CopyOperationError(
                CopyOperationCode.TARGET_VERIFICATION_FAILED,
                "target identity projection failed safely",
            ) from None
        if first_identity != second_identity:
            raise CopyOperationError(
                CopyOperationCode.TARGET_VERIFICATION_FAILED,
                "target identity changed during independent handle rescans",
            )
        (
            root_identity,
            payload_identity,
            provenance_identity,
            tree_identity,
        ) = first_identity
        if tree_identity != publish_tree_identity_sha256:
            raise CopyOperationError(
                CopyOperationCode.TARGET_VERIFICATION_FAILED,
                "target object identity differs from authenticated publish evidence",
            )
        if (
            payload_entry.payload != material.payload
            or payload_entry.size_bytes != material.evidence.size_bytes
            or payload_entry.sha256 != material.evidence.sha256
            or provenance_entry.payload != provenance.provenance_bytes
            or provenance_entry.size_bytes != len(provenance.provenance_bytes)
            or provenance_entry.sha256 != provenance.provenance_sha256
        ):
            raise CopyOperationError(
                CopyOperationCode.TARGET_VERIFICATION_FAILED,
                "target payload or provenance differs from the published manifest",
            )
        common_change_frame = (
            root_identity.encode("ascii"),
            payload_identity.encode("ascii"),
            provenance_identity.encode("ascii"),
            tree_identity.encode("ascii"),
        )
        payload_change_evidence = _digest(
            b"COPY-TARGET-PAYLOAD-DOUBLE-SCAN-V2",
            *common_change_frame,
            payload_entry.size_bytes.to_bytes(8, "big"),
            payload_entry.sha256.encode("ascii"),
        )
        provenance_change_evidence = _digest(
            b"COPY-TARGET-PROVENANCE-DOUBLE-SCAN-V2",
            *common_change_frame,
            provenance_entry.size_bytes.to_bytes(8, "big"),
            provenance_entry.sha256.encode("ascii"),
        )
        return CopyTargetEvidence(
            root_identity_hmac_sha256=root_identity,
            tree_identity_hmac_sha256=tree_identity,
            payload=CopyFileEvidence(
                identity_hmac_sha256=payload_identity,
                size_bytes=payload_entry.size_bytes,
                sha256=payload_entry.sha256,
                change_evidence_sha256=payload_change_evidence,
            ),
            provenance=CopyFileEvidence(
                identity_hmac_sha256=provenance_identity,
                size_bytes=provenance_entry.size_bytes,
                sha256=provenance_entry.sha256,
                change_evidence_sha256=provenance_change_evidence,
            ),
            manifest_sha256=manifest_sha256,
            tree_sha256=tree_sha256,
            topology_sha256=topology_sha256,
            entry_count=expected_entry_count,
            total_bytes=expected_total_bytes,
        )

    def _read_target(
        self,
        target: Path,
        provenance: CopyProvenanceMaterial,
    ) -> HandleDirectorySnapshot:
        if type(provenance) is not CopyProvenanceMaterial:
            raise CopyOperationError(
                CopyOperationCode.TARGET_VERIFICATION_FAILED,
                "target read requires exact provenance authority",
            )
        try:
            return self._runtime._writer.read_flat_directory(
                target,
                maximum_entries=4,
                maximum_file_bytes=SYNTHETIC_REFERENCE_MAX_BYTES,
                maximum_total_bytes=(
                    SYNTHETIC_REFERENCE_MAX_BYTES
                    + len(provenance.provenance_bytes)
                ),
            )
        except HandleWriterError:
            raise CopyOperationError(
                CopyOperationCode.TARGET_VERIFICATION_FAILED,
                "published Copy target cannot be independently rescanned",
            ) from None

    def _validate_replay_binding(
        self,
        evidence: SyntheticSourceEvidence,
        source_record: CopySourceRecord,
        source_receipt: CopySourceReceipt,
        provenance: CopyProvenanceMaterial,
        transition: CopyTransition,
        transaction_binding: str,
        copy_binding: str,
        target: Path,
    ) -> None:
        expected_source = self._source_record(
            evidence,
            transaction_binding,
            copy_binding,
            source_record.audit_ancestor_sha256,
        )
        operation_source, operation_target = (
            self._authoritative_publish_relative_paths(target, None)
        )
        expected_publish_binding = self._publish_operation_binding(
            transition.publish_operation_plan,
            transition.publish_transaction_id,
            transaction_binding,
            copy_binding,
            transition.source_anchor,
            transition.audit_ancestor_sha256,
            transition.target_locator,
            operation_source,
            operation_target,
        )
        if (
            type(provenance) is not CopyProvenanceMaterial
            or source_record != expected_source
            or source_receipt.anchor != transition.source_anchor
            or transition.transaction_binding_sha256 != transaction_binding
            or transition.copy_binding_sha256 != copy_binding
            or transition.classification is not self._context.classification
            or transition.target_locator != self._copy_target_locator(target)
            or transition.expected_manifest_sha256
            != provenance.publish_manifest.manifest_sha256
            or transition.provenance_metadata_sha256
            != provenance.provenance_sha256
            or transition.budget_sha256 != self._budget.digest
            or transition.publish_operation_binding_sha256
            != expected_publish_binding
            or transition.publish_transaction_id is None
            or transition.target_evidence is None
            or transition.publish_terminal_segment_sha256 is None
        ):
            raise CopyOperationError(
                CopyOperationCode.REPLAY_CONFLICT,
                "replay inputs differ from the committed Copy transaction",
            )

    def _validate_publish_receipt(
        self,
        receipt: PublishOperationReceipt,
        target: Path,
        publish_manifest: DeclaredTreeManifest,
        *,
        expected_transaction_id: str | None,
    ) -> None:
        if (
            type(receipt) is not PublishOperationReceipt
            or type(publish_manifest) is not DeclaredTreeManifest
            or expected_transaction_id is None
            or receipt.transaction_id != expected_transaction_id
            or receipt.classification is not self._context.classification
            or publish_manifest.classification is not self._context.classification
            or publish_manifest.manifest_id != self._context.manifest_id
            or len(publish_manifest.entries) != 2
            or publish_manifest.entries[0] != self._manifest.entries[0]
            or publish_manifest.entries[1].relative_path
            != COPY_PROVENANCE_FILE_NAME
            or not _is_sha256(receipt.committed_segment_sha256)
            or not _is_sha256(receipt.target_identity_hmac_sha256)
            or receipt.target_identity_hmac_sha256 == "0" * 64
        ):
            raise CopyOperationError(
                CopyOperationCode.PUBLISH_FAILED,
                "publish receipt lacks exact classified terminal evidence",
            )
        expected = target.as_posix()
        if self._context.classification is DataClassification.RESTRICTED:
            operation_ledger = self._runtime._operation_ledger
            if (
                type(operation_ledger) is not DurableOperationLedger
                or receipt.locator_mode is not OperationLocatorMode.HMAC_ONLY
                or receipt.target_locator
                != operation_ledger.locator_hmac(
                    expected,
                    transaction_id=receipt.transaction_id,
                    role=OperationLocatorRole.TARGET,
                )
            ):
                raise CopyOperationError(
                    CopyOperationCode.PUBLISH_FAILED,
                    "restricted publish receipt locator differs",
                )
        elif (
            receipt.locator_mode is not OperationLocatorMode.SAFE_RELATIVE
            or receipt.target_locator != expected
        ):
            raise CopyOperationError(
                CopyOperationCode.PUBLISH_FAILED,
                "internal publish receipt locator differs",
            )

    def _validate_material_manifest(self, material: SyntheticSourceMaterial) -> None:
        entry = self._manifest.entries[0]
        if (
            type(material) is not SyntheticSourceMaterial
            or material.evidence.classification is not self._context.classification
            or entry.size_bytes != material.evidence.size_bytes
            or entry.sha256 != material.evidence.sha256
            or material.evidence.size_bytes > self._budget.maximum_file_bytes
            or material.evidence.size_bytes > self._budget.maximum_total_bytes
        ):
            raise CopyOperationError(
                CopyOperationCode.MANIFEST_MISMATCH,
                "source material differs from the exact immutable manifest or budget",
            )

    def _issue_execution_permit(
        self,
        source_lease: _SyntheticReferenceLease,
        evidence: SyntheticSourceEvidence,
        target: Path,
        publish_manifest: DeclaredTreeManifest,
        *,
        recovery_source: Path | None = None,
    ) -> _CopyExecutionPermit:
        if (
            type(source_lease) is not _SyntheticReferenceLease
            or type(evidence) is not SyntheticSourceEvidence
            or not self._has_exact_path_authority(target, recovery_source)
            or not self._is_exact_publish_manifest(publish_manifest)
        ):
            raise CopyOperationError(
                CopyOperationCode.INVALID_FACTORY,
                "copy execution permit requires exact private source authorities",
            )
        return _issue_copy_execution_permit(
            self._source_policy,
            source_lease,
            evidence,
            operation_authority=self,
            operation_identity_sha256=self._execution_operation_identity_sha256(),
            context_sha256=self._context.digest,
            manifest_sha256=publish_manifest.manifest_sha256,
            budget_sha256=self._budget.digest,
            target_sha256=self._execution_path_authority_sha256(
                target,
                recovery_source,
            ),
            copy_id=self._copy_id,
            classification=self._context.classification,
        )

    def _validate_execution_permit(
        self,
        permit: _CopyExecutionPermit,
        source_lease: _SyntheticReferenceLease,
        material: SyntheticSourceMaterial,
        transaction_binding: str,
        copy_binding: str,
        target: Path,
        publish_manifest: DeclaredTreeManifest,
        *,
        recovery_source: Path | None = None,
    ) -> None:
        self._require_exact_execution_inputs(
            permit,
            source_lease,
            material,
            transaction_binding,
            copy_binding,
            target,
            publish_manifest,
            recovery_source=recovery_source,
        )
        _validate_copy_execution_permit(
            permit,
            self._source_policy,
            source_lease,
            material.evidence,
            operation_authority=self,
            operation_identity_sha256=self._execution_operation_identity_sha256(),
            context_sha256=self._context.digest,
            manifest_sha256=publish_manifest.manifest_sha256,
            budget_sha256=self._budget.digest,
            target_sha256=self._execution_path_authority_sha256(
                target,
                recovery_source,
            ),
            copy_id=self._copy_id,
            classification=self._context.classification,
        )

    def _consume_execution_permit(
        self,
        permit: _CopyExecutionPermit,
        source_lease: _SyntheticReferenceLease,
        material: SyntheticSourceMaterial,
        transaction_binding: str,
        copy_binding: str,
        target: Path,
        publish_manifest: DeclaredTreeManifest,
        *,
        recovery_source: Path | None = None,
    ) -> None:
        self._require_exact_execution_inputs(
            permit,
            source_lease,
            material,
            transaction_binding,
            copy_binding,
            target,
            publish_manifest,
            recovery_source=recovery_source,
        )
        _consume_copy_execution_permit(
            permit,
            self._source_policy,
            source_lease,
            material.evidence,
            operation_authority=self,
            operation_identity_sha256=self._execution_operation_identity_sha256(),
            context_sha256=self._context.digest,
            manifest_sha256=publish_manifest.manifest_sha256,
            budget_sha256=self._budget.digest,
            target_sha256=self._execution_path_authority_sha256(
                target,
                recovery_source,
            ),
            copy_id=self._copy_id,
            classification=self._context.classification,
        )

    def _require_exact_execution_inputs(
        self,
        permit: _CopyExecutionPermit,
        source_lease: _SyntheticReferenceLease,
        material: SyntheticSourceMaterial,
        transaction_binding: str,
        copy_binding: str,
        target: Path,
        publish_manifest: DeclaredTreeManifest,
        *,
        recovery_source: Path | None,
    ) -> None:
        if (
            type(permit) is not _CopyExecutionPermit
            or type(source_lease) is not _SyntheticReferenceLease
            or type(material) is not SyntheticSourceMaterial
            or type(material.evidence) is not SyntheticSourceEvidence
            or not self._has_exact_path_authority(target, recovery_source)
            or not self._is_exact_publish_manifest(publish_manifest)
            or not _is_sha256(transaction_binding)
            or not _is_sha256(copy_binding)
            or (transaction_binding, copy_binding)
            != self._stable_bindings(material.evidence)
        ):
            raise CopyOperationError(
                CopyOperationCode.INVALID_FACTORY,
                "private copy execution inputs lack one exact issued permit",
            )

    def _require_exact_execution_envelope(
        self,
        permit: object,
        material: object,
        source_lease: object,
        source_record: object,
        source_receipt: object,
        provenance: object,
        transaction_binding: object,
        copy_binding: object,
        target: object,
    ) -> None:
        """Reject direct helper forgery before dereferencing any input object."""

        if (
            type(permit) is not _CopyExecutionPermit
            or type(material) is not SyntheticSourceMaterial
            or type(source_lease) is not _SyntheticReferenceLease
            or type(source_record) is not CopySourceRecord
            or type(source_receipt) is not CopySourceReceipt
            or type(provenance) is not CopyProvenanceMaterial
            or type(transaction_binding) is not str
            or type(copy_binding) is not str
            or type(target) is not type(Path())
        ):
            raise CopyOperationError(
                CopyOperationCode.INVALID_FACTORY,
                "private copy execution helper inputs are not exact",
            )

    def _is_exact_publish_manifest(self, manifest: object) -> bool:
        return (
            type(manifest) is DeclaredTreeManifest
            and manifest.manifest_id == self._context.manifest_id
            and manifest.classification is self._context.classification
            and len(manifest.entries) == 2
            and manifest.entries[0] == self._manifest.entries[0]
            and manifest.entries[1].relative_path == COPY_PROVENANCE_FILE_NAME
            and manifest.entries[1].kind is TreeEntryKind.FILE
            and manifest.entries[1].size_bytes > 0
            and _is_sha256(manifest.entries[1].sha256)
        )

    def _execution_operation_identity_sha256(self) -> str:
        operation_ledger = self._runtime._operation_ledger
        if type(operation_ledger) is not DurableOperationLedger:
            raise CopyOperationError(
                CopyOperationCode.INVALID_FACTORY,
                "copy execution has no exact operation identity authority",
            )
        reference = operation_ledger.operation_reference(
            self._context.operation_id,
            self._context.classification,
        )
        return _digest(
            b"COPY-EXECUTION-OPERATION-IDENTITY-V1",
            reference.encode("ascii"),
        )

    def _execution_path_authority_sha256(
        self,
        target: Path,
        recovery_source: Path | None,
    ) -> str:
        if not self._has_exact_path_authority(target, recovery_source):
            raise CopyOperationError(
                CopyOperationCode.INVALID_FACTORY,
                "copy execution path authority is not exact",
            )
        source_frame = (
            b"NEW_EXECUTION"
            if recovery_source is None
            else recovery_source.as_posix().encode("utf-8")
        )
        return _digest(
            b"COPY-EXECUTION-PATH-AUTHORITY-V2",
            canonical_json_bytes(self._copy_target_locator(target).to_json()),
            source_frame,
        )

    def _has_exact_path_authority(
        self,
        target: object,
        recovery_source: object,
    ) -> bool:
        concrete_path_type = type(Path())
        if (
            type(target) is not concrete_path_type
            or target == Path()
            or target.is_absolute()
            or any(part in {"", ".", ".."} for part in target.parts)
        ):
            return False
        restricted_recovery = recovery_source is not None
        if restricted_recovery:
            return (
                self._context.classification is DataClassification.RESTRICTED
                and type(recovery_source) is concrete_path_type
                and recovery_source != Path()
                and not recovery_source.is_absolute()
                and all(
                    part not in {"", ".", ".."}
                    for part in recovery_source.parts
                )
            )
        return target == self._target_relative_path()

    def _stable_bindings(self, evidence: SyntheticSourceEvidence) -> tuple[str, str]:
        transaction = self._ledgers.transaction_binding(
            context_sha256=self._context.digest,
            manifest_sha256=self._manifest.manifest_sha256,
            budget_sha256=self._budget.digest,
            source_reference_sha256=evidence.source_reference,
            classification=evidence.classification,
        )
        copy_binding = self._ledgers.copy_object_binding(
            context_sha256=self._context.digest,
            copy_id=self._copy_id,
            source_reference_sha256=evidence.source_reference,
            classification=evidence.classification,
        )
        return transaction, copy_binding

    def _copy_target_locator(self, target: Path) -> CopyLocator:
        return self._ledgers.target_locator(
            target.as_posix(),
            self._context.classification,
        )

    def _target_relative_path(self) -> Path:
        partition = (
            "restricted"
            if self._context.classification is DataClassification.RESTRICTED
            else "source"
        )
        return Path("Copy") / partition / self._copy_id

    def _operation_source_relative_path(self) -> Path:
        return (
            Path("tmp")
            / "jobs"
            / self._context.classification.value
            / self._context.job_id
            / "publish"
            / (self._context.manifest_id or "")
        )

    def _authoritative_publish_relative_paths(
        self,
        target: Path,
        recovery_source: Path | None,
    ) -> tuple[Path, Path]:
        if not self._has_exact_path_authority(target, recovery_source):
            self._raise_recovery_contradiction()
        if recovery_source is not None:
            if self._context.classification is not DataClassification.RESTRICTED:
                self._raise_recovery_contradiction()
            return recovery_source, target
        return self._operation_source_relative_path(), target

    def _unstarted_publish_plan(
        self,
        provenance: CopyProvenanceMaterial,
    ) -> CopyPublishOperationPlan:
        operation_ledger = self._runtime._operation_ledger
        if (
            type(operation_ledger) is not DurableOperationLedger
            or type(provenance) is not CopyProvenanceMaterial
        ):
            self._raise_recovery_contradiction()
        return self._ledgers._project_publish_operation_plan(
            kind=CopyPublishPlanKind.UNSTARTED,
            operation_reference=operation_ledger.operation_reference(
                self._context.operation_id,
                self._context.classification,
            ),
            # Source-only recovery must remain possible for a legacy source fact
            # whose frozen budget cannot authorize today's two-file publish.
            context_binding_sha256=self._context.digest,
            manifest_sha256=provenance.publish_manifest.manifest_sha256,
            budget_sha256=self._budget.digest,
            classification=self._context.classification,
        )

    def _reserved_publish_plan(
        self,
        operation: _OperationLease,
        observed: Any,
        target: Path,
    ) -> tuple[CopyPublishOperationPlan, Path, Path]:
        operation_ledger = self._runtime._operation_ledger
        if (
            type(operation) is not _OperationLease
            or operation._runtime is not self._runtime
            or type(operation_ledger) is not DurableOperationLedger
            or operation._transaction_id is None
            or operation._pair_view is None
            or operation._ledger_head.last_segment_sha256 is None
        ):
            raise CopyOperationError(
                CopyOperationCode.PUBLISH_FAILED,
                "publish reservation lacks one exact typed plan",
            )
        view = operation._pair_view
        source_relative = view.source_relative_path
        target_relative = view.target_relative_path
        concrete_path_type = type(Path())
        if (
            type(source_relative) is not concrete_path_type
            or type(target_relative) is not concrete_path_type
            or target_relative != target
            or not self._has_exact_path_authority(target, None)
        ):
            raise CopyOperationError(
                CopyOperationCode.PUBLISH_FAILED,
                "publish reservation paths differ from the issued authority",
            )
        observed.revalidate()
        snapshot = observed._low_level.snapshot
        root = observed._low_level._root._observed
        source_evidence = OperationTreeEvidence(
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
        if self._context.classification is DataClassification.RESTRICTED:
            locator_mode = OperationLocatorMode.HMAC_ONLY
            source_locator = operation_ledger.locator_hmac(
                source_relative.as_posix(),
                transaction_id=operation._transaction_id,
                role=OperationLocatorRole.SOURCE,
            )
            target_locator = operation_ledger.locator_hmac(
                target_relative.as_posix(),
                transaction_id=operation._transaction_id,
                role=OperationLocatorRole.TARGET,
            )
        else:
            locator_mode = OperationLocatorMode.SAFE_RELATIVE
            source_locator = source_relative.as_posix()
            target_locator = target_relative.as_posix()
        return (
            self._ledgers._project_publish_operation_plan(
                kind=CopyPublishPlanKind.RESERVED,
                operation_reference=operation_ledger.operation_reference(
                    self._context.operation_id,
                    self._context.classification,
                ),
                context_binding_sha256=operation._context_binding,
                manifest_sha256=source_evidence.manifest_sha256,
                budget_sha256=self._budget.digest,
                classification=self._context.classification,
                publish_transaction_id=operation._transaction_id,
                pair_reference=view.pair_id,
                locator_mode=locator_mode,
                source_locator=source_locator,
                target_locator=target_locator,
                source_evidence=source_evidence,
                # This is the authenticated reservation head available before
                # entering the native publish boundary.  The Operation journal
                # may bind a later final-validation descendant.
                audit_ancestor_sha256=operation._ledger_head.last_segment_sha256,
            ),
            source_relative,
            target_relative,
        )

    def _publish_operation_binding(
        self,
        plan: CopyPublishOperationPlan,
        publish_transaction_id: str | None,
        transaction_binding: str,
        copy_binding: str,
        source_anchor: CopySourceAnchor,
        copy_audit_ancestor: str,
        target_locator: CopyLocator,
        source_relative: Path,
        target_relative: Path,
    ) -> str:
        operation_ledger = self._runtime._operation_ledger
        if type(operation_ledger) is not DurableOperationLedger:
            raise CopyOperationError(
                CopyOperationCode.LEDGER_MISMATCH,
                "copy publish ledger is unavailable",
            )
        return self._ledgers.publish_operation_binding(
            plan=plan,
            operation_reference=operation_ledger.operation_reference(
                self._context.operation_id,
                self._context.classification,
            ),
            publish_transaction_id=publish_transaction_id,
            transaction_binding_sha256=transaction_binding,
            copy_binding_sha256=copy_binding,
            source_anchor=source_anchor,
            copy_audit_ancestor_sha256=copy_audit_ancestor,
            target_locator=target_locator,
            source_relative_locator=source_relative.as_posix(),
            target_relative_locator=target_relative.as_posix(),
            operation_ledger=operation_ledger,
        )

    def _issue_operation_absence_witness(
        self,
        mutex: Any,
        plan: CopyPublishOperationPlan,
        publish_transaction_id: str | None,
        transaction_binding: str,
        copy_binding: str,
        source_anchor: CopySourceAnchor,
        copy_audit_ancestor: str,
        target_locator: CopyLocator,
        source_relative: Path,
        target_relative: Path,
        publish_binding: str,
    ) -> CopyOperationAbsenceWitness:
        operation_ledger = self._runtime._operation_ledger
        if type(operation_ledger) is not DurableOperationLedger:
            self._raise_recovery_contradiction()
        return self._ledgers._issue_operation_absence_witness_under_existing_mutex(
            mutex,
            operation_ledger,
            plan=plan,
            operation_reference=operation_ledger.operation_reference(
                self._context.operation_id,
                self._context.classification,
            ),
            publish_transaction_id=publish_transaction_id,
            transaction_binding_sha256=transaction_binding,
            copy_binding_sha256=copy_binding,
            source_anchor=source_anchor,
            copy_audit_ancestor_sha256=copy_audit_ancestor,
            target_locator=target_locator,
            source_relative_locator=source_relative.as_posix(),
            target_relative_locator=target_relative.as_posix(),
            publish_operation_binding_sha256=publish_binding,
        )

    @staticmethod
    def _operation_target_matches_copy(
        operation_target: OperationTreeEvidence | None,
        copy_target: CopyTargetEvidence,
    ) -> bool:
        return (
            type(operation_target) is OperationTreeEvidence
            and type(copy_target) is CopyTargetEvidence
            and operation_target.manifest_sha256 == copy_target.manifest_sha256
            and operation_target.source_tree_sha256 == copy_target.tree_sha256
            and operation_target.topology_sha256 == copy_target.topology_sha256
            and operation_target.durable_identity_sha256
            == copy_target.tree_identity_hmac_sha256
            and operation_target.entry_count == copy_target.entry_count
            and operation_target.total_bytes == copy_target.total_bytes
        )

    def _validate_authenticated_publish_result(
        self,
        mutex: Any,
        copy_transition: CopyTransition,
        publish_receipt: PublishOperationReceipt,
        provenance: CopyProvenanceMaterial,
    ) -> None:
        operation_ledger = self._runtime._operation_ledger
        try:
            if (
                type(operation_ledger) is not DurableOperationLedger
                or type(copy_transition) is not CopyTransition
                or copy_transition.publish_transaction_id is None
                or type(provenance) is not CopyProvenanceMaterial
            ):
                raise CopyOperationError(
                    CopyOperationCode.LEDGER_MISMATCH,
                    "authenticated publish validation requires exact typed ancestry",
                )
            result = operation_ledger.transaction_result_under_existing_mutex(
                mutex,
                copy_transition.publish_transaction_id,
            )
            if result is None:
                raise CopyOperationError(
                    CopyOperationCode.LEDGER_MISMATCH,
                    "authenticated publish transaction is absent",
                )
            terminal, terminal_receipt = result
            if (
                type(terminal) is not OperationTransition
                or type(terminal_receipt) is not OperationSegmentReceipt
                or terminal.next_state
                not in {OperationState.COMMITTED, OperationState.RECOVERED_COMMIT}
                or terminal_receipt.segment_sha256
                != publish_receipt.committed_segment_sha256
            ):
                raise CopyOperationError(
                    CopyOperationCode.LEDGER_MISMATCH,
                    "authenticated publish terminal differs from the supplied receipt",
                )
            context_binding = self._runtime._validate_context_and_manifest(
                self._context,
                provenance.publish_manifest,
                self._budget,
            )
            recovery_source = (
                self._operation_source_relative_path()
                if self._context.classification is DataClassification.RESTRICTED
                else None
            )
            self._validate_recovery_publish_binding(
                terminal,
                copy_transition,
                context_binding,
                self._target_relative_path(),
                recovery_source,
                provenance,
            )
            authenticated_receipt = _receipt_from_authenticated_terminal(
                terminal,
                terminal_receipt,
            )
            self._validate_publish_receipt(
                authenticated_receipt,
                self._target_relative_path(),
                provenance.publish_manifest,
                expected_transaction_id=copy_transition.publish_transaction_id,
            )
            if authenticated_receipt != publish_receipt:
                raise CopyOperationError(
                    CopyOperationCode.LEDGER_MISMATCH,
                    "authenticated publish receipt is not byte-for-byte stable",
                )
        except CopyOperationError as error:
            if error.code is CopyOperationCode.RECOVERY_CONTRADICTION:
                raise CopyOperationError(
                    CopyOperationCode.LEDGER_MISMATCH,
                    "copy ledger ancestry or live target contradicts authenticated evidence",
                ) from None
            self._seal_cross_reference_failure()
        except (JobOperationError, OperationLedgerError, CopyLedgerError):
            self._seal_cross_reference_failure()

    def _checkpoint_digest(
        self,
        provenance: CopyProvenanceMaterial,
        source_receipt: CopySourceReceipt,
    ) -> str:
        if (
            type(provenance) is not CopyProvenanceMaterial
            or type(source_receipt) is not CopySourceReceipt
        ):
            raise CopyOperationError(
                CopyOperationCode.INVALID_FACTORY,
                "copy checkpoint requires exact provenance ancestry",
            )
        return _digest(
            b"COPY-CHECKPOINT-MANIFEST-V2",
            self._context.digest.encode("ascii"),
            provenance.payload_manifest_sha256.encode("ascii"),
            provenance.publish_manifest.manifest_sha256.encode("ascii"),
            provenance.provenance_sha256.encode("ascii"),
            source_receipt.segment_sha256.encode("ascii"),
            source_receipt.record_sha256.encode("ascii"),
        )

    @staticmethod
    def _transition_id(
        transaction_binding: str,
        previous: CopyState | None,
        next_state: CopyState,
    ) -> str:
        return _digest(
            b"COPY-TRANSITION-ID-V1",
            transaction_binding.encode("ascii"),
            (b"NONE" if previous is None else previous.value.encode("ascii")),
            next_state.value.encode("ascii"),
        )

    @staticmethod
    def _error_code(error: BaseException) -> str:
        code = getattr(error, "code", None)
        value = getattr(code, "value", None)
        if (
            type(value) is str
            and value
            and len(value) <= 128
            and all(character.isupper() or character.isdigit() or character in "_-" for character in value)
        ):
            return value
        return "UNEXPECTED_FAILURE"

    @staticmethod
    def _receipt(
        evidence: SyntheticSourceEvidence,
        source_receipt: CopySourceReceipt,
        terminal_receipt: CopyTransitionReceipt,
        publish_receipt: PublishOperationReceipt,
        verification: SyntheticSourceVerification,
        copy_binding_sha256: str,
        *,
        replayed: bool,
    ) -> CopyOperationReceipt:
        return CopyOperationReceipt(
            transaction_binding_sha256=terminal_receipt.transaction_binding_sha256,
            copy_binding_sha256=copy_binding_sha256,
            source_record_segment_sha256=source_receipt.segment_sha256,
            copy_terminal_segment_sha256=terminal_receipt.segment_sha256,
            publish_terminal_segment_sha256=publish_receipt.committed_segment_sha256,
            source_verification_sha256=verification.verification_digest,
            classification=evidence.classification,
            size_bytes=evidence.size_bytes,
            sha256=evidence.sha256,
            replayed=replayed,
        )

    def _seal_cross_reference_failure(self) -> NoReturn:
        try:
            self._ledgers._seal(CopyLedgerCode.CROSS_REFERENCE_INVALID)
        finally:
            self._runtime._writer.seal_after_indeterminate_mutation()
        raise CopyOperationError(
            CopyOperationCode.LEDGER_MISMATCH,
            "copy ledger ancestry or live target contradicts authenticated evidence",
        ) from None

    def _assert_issued(self) -> None:
        if (
            self._owner_thread != threading.get_ident()
            or threading.current_thread() is not self._owner_thread_object
            or self._owner_thread_object.ident != self._owner_thread
            or self._state != "ISSUED"
        ):
            raise CopyOperationError(
                CopyOperationCode.INVALID_REQUEST,
                "copy operation is consumed, closed, or cross-thread",
            )


_seal_copy_boundaries()
del (
    _copy_boundary_template,
    _create_copy_boundary_runtime,
    _path_free_exception_boundary,
    _register_copy_boundary,
    _seal_copy_boundaries,
)


__all__ = [
    "CopyOperationCode",
    "CopyOperationError",
    "CopyOperationReceipt",
]
