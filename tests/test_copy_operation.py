from __future__ import annotations

import hashlib
import os
import pickle
import sys
import threading
from dataclasses import dataclass, replace
from pathlib import Path
from types import CodeType, FunctionType
from typing import Callable, Iterator, TypeVar

import pytest

import app.safety.copy_operation as copy_operation_module
import app.safety.production_guard as production_guard_module
from app.safety.context import (
    Caller,
    DataClassification,
    Purpose,
    ScopeId,
    ScopeKind,
)
from app.safety.copy_ledger import (
    COPY_PROVENANCE_FILE_NAME,
    COPY_PROVENANCE_MAX_BYTES,
    CopyLedgerCode,
    CopyLedgerError,
    CopyPublishPlanKind,
    CopyState,
    DurableCopyLedgers,
    _derive_copy_ledger_epoch_id,
    build_copy_provenance_material,
)
from app.safety.copy_operation import (
    CopyOperationCode,
    CopyOperationError,
    CopyOperationReceipt,
    _TestLocalCopyOperation,
)
from app.safety.external_source import (
    ExternalSourceCode,
    ExternalSourceError,
    SyntheticReferenceReadPolicy,
    _SyntheticReferenceLease,
)
from app.safety.job_operation import (
    DeclaredTreeEntry,
    DeclaredTreeManifest,
    JobResourceBudget,
    _logical_manifest_bytes,
)
from app.safety.operation_ledger import DurableOperationLedger, OperationState
from app.safety.production_guard import (
    BoundaryErrorCode,
    ProductionBoundaryError,
    _create_test_copy_ledgers,
    _create_test_copy_operation,
    _create_test_durable_boundary,
    _create_test_operation_ledger,
)
from app.safety.windows_handle_writer import TreeEntryKind, _WindowsHandleWriter
from tests.conftest import register_synthetic_source


_AUDIT_EPOCH = "RUN-S3F-COPY-AUDIT"
_KEY_ID = "KEYREV-S3F-COPY"
_KEY_TIME = "2026-07-13T01:00:00Z"
_MASTER_KEY = b"C" * 32
_ThreadResult = TypeVar("_ThreadResult")


def _module_traceback_locals(
    error: BaseException,
    module_name: str,
) -> tuple[dict[str, object], ...]:
    frames: list[dict[str, object]] = []
    current = error.__traceback__
    while current is not None:
        if current.tb_frame.f_globals.get("__name__") == module_name:
            frames.append(dict(current.tb_frame.f_locals))
        current = current.tb_next
    return tuple(frames)


def _copy_boundary_surfaces() -> tuple[FunctionType, ...]:
    return (
        _TestLocalCopyOperation.close,
        _TestLocalCopyOperation.__enter__,
        _TestLocalCopyOperation.__exit__,
        _TestLocalCopyOperation.execute,
        _TestLocalCopyOperation.reconcile,
    )


def _copy_boundary_vault() -> dict[CodeType, FunctionType]:
    candidates = []
    closure = copy_operation_module._dispatch_copy_boundary.__closure__ or ()
    assert len(closure) == 2
    assert any(type(cell.cell_contents) is bool and cell.cell_contents for cell in closure)
    for cell in closure:
        value = cell.cell_contents
        if (
            type(value) is dict
            and value
            and all(
                type(code) is CodeType and type(function) is FunctionType
                for code, function in value.items()
            )
        ):
            candidates.append(value)
    assert len(candidates) == 1
    return candidates[0]


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _run_in_fresh_thread(callback: Callable[[], _ThreadResult]) -> _ThreadResult:
    results: list[_ThreadResult] = []
    errors: list[BaseException] = []

    def run() -> None:
        try:
            results.append(callback())
        except BaseException as error:
            errors.append(error)

    worker = threading.Thread(target=run)
    worker.start()
    worker.join(timeout=30)
    assert not worker.is_alive()
    if errors:
        raise errors[0]
    assert len(results) == 1
    return results[0]


@dataclass(frozen=True)
class _Bootstrap:
    run_root: Path
    project: Path
    reference: Path


@dataclass(frozen=True)
class _CopyOperationLab:
    bootstrap: _Bootstrap
    bundle: object
    operation_ledger: object
    copy_ledgers: DurableCopyLedgers
    operation_epoch: str
    copy_epoch: str
    run_scope_id: str
    tag: str

    def source(self, name: str, payload: bytes) -> Path:
        path = self.bootstrap.reference / f"{self.tag}-{name}"
        if path.exists():
            assert path.read_bytes() == payload
        else:
            path.write_bytes(payload)
        register_synthetic_source(path)
        return path

    def context_and_manifest(
        self,
        payload: bytes,
        *,
        classification: DataClassification = DataClassification.INTERNAL,
    ):
        run_id = f"RUN-{self.tag}"
        job_id = f"JOB-{self.tag}"
        operation_id = f"OP-{self.tag}"
        manifest_id = f"MANIFEST-{self.tag}"
        copy_id = f"COPY-{self.tag}"
        checkpoint_id = f"CHECKPOINT-{self.tag}"
        context = self.bundle.boundary.issue_context(
            run_id=run_id,
            job_id=job_id,
            operation_id=operation_id,
            caller=Caller.IMPORT_SERVICE,
            purpose=Purpose.COPY_SOURCE,
            manifest_id=manifest_id,
            classification=classification,
            scopes=(
                ScopeId(ScopeKind.RUN_ID, run_id),
                ScopeId(
                    ScopeKind.COPY_LEDGER_EPOCH_ID,
                    self.copy_epoch,
                ),
                ScopeId(ScopeKind.JOB_ID, job_id),
                ScopeId(ScopeKind.OPERATION_ID, operation_id),
                ScopeId(ScopeKind.MANIFEST_ID, manifest_id),
                ScopeId(ScopeKind.COPY_ID, copy_id),
                ScopeId(ScopeKind.CHECKPOINT_ID, checkpoint_id),
            ),
        )
        manifest = DeclaredTreeManifest(
            manifest_id=manifest_id,
            classification=classification,
            entries=(
                DeclaredTreeEntry(
                    "payload.bin",
                    TreeEntryKind.FILE,
                    len(payload),
                    _sha(payload),
                ),
            ),
        )
        return context, manifest, copy_id

    def copy_operation(
        self,
        payload: bytes,
        *,
        classification: DataClassification = DataClassification.INTERNAL,
        budget: JobResourceBudget | None = None,
    ) -> tuple[_TestLocalCopyOperation, object, DeclaredTreeManifest, str]:
        context, manifest, copy_id = self.context_and_manifest(
            payload,
            classification=classification,
        )
        operation = _create_test_copy_operation(
            self.bundle,
            self.operation_ledger,
            self.copy_ledgers,
            context,
            manifest,
            (
                JobResourceBudget.conservative_test_default()
                if budget is None
                else budget
            ),
        )
        return operation, context, manifest, copy_id


@pytest.fixture(scope="module")
def copy_operation_bootstrap() -> Iterator[_Bootstrap]:
    run_root = Path(os.environ["M0_TEST_LAB_ROOT"])
    project = run_root / "project"
    reference = run_root / "external" / "REFERENCE"
    project.mkdir(exist_ok=True)
    reference.mkdir(parents=True, exist_ok=True)
    (project / "logs" / "audit" / "keys").mkdir(parents=True, exist_ok=True)
    (project / "logs" / "audit" / "segments" / _AUDIT_EPOCH).mkdir(
        parents=True,
        exist_ok=True,
    )
    (project / "tmp" / "jobs" / "INTERNAL").mkdir(parents=True, exist_ok=True)
    (project / "tmp" / "jobs" / "RESTRICTED").mkdir(parents=True, exist_ok=True)
    (project / "Copy" / "source").mkdir(parents=True, exist_ok=True)
    (project / "Copy" / "restricted").mkdir(parents=True, exist_ok=True)
    _create_test_durable_boundary(
        project,
        initialize=True,
        epoch_id=_AUDIT_EPOCH,
        initial_revision_sequence=1,
        initial_revision_id=_KEY_ID,
        master_key=_MASTER_KEY,
        key_created_at_utc=_KEY_TIME,
        ledger_initialized_at_utc="2026-07-13T01:00:01Z",
    )
    yield _Bootstrap(run_root=run_root, project=project, reference=reference)


@pytest.fixture
def copy_operation_lab(
    copy_operation_bootstrap: _Bootstrap,
    request: pytest.FixtureRequest,
) -> _CopyOperationLab:
    suffix = hashlib.sha256(request.node.name.encode("utf-8")).hexdigest()[:16].upper()
    tag = f"S3F-{suffix}"
    operation_epoch = f"OPLEDGER-{suffix}"
    run_scope_id = f"RUN-{tag}"
    project = copy_operation_bootstrap.project
    (project / "logs" / "operations" / "segments" / operation_epoch).mkdir(
        parents=True,
        exist_ok=True,
    )
    bundle = _create_test_durable_boundary(
        project,
        initialize=False,
        epoch_id=_AUDIT_EPOCH,
        initial_revision_sequence=1,
        initial_revision_id=_KEY_ID,
        master_key=_MASTER_KEY,
        key_created_at_utc=_KEY_TIME,
    )
    copy_epoch = _derive_copy_ledger_epoch_id(
        bundle.ledger._active_revision(),
        run_scope_id,
    )
    (project / "Copy" / "ledger" / "source" / "segments" / copy_epoch).mkdir(
        parents=True,
        exist_ok=True,
    )
    (project / "Copy" / "ledger" / "copy" / "segments" / copy_epoch).mkdir(
        parents=True,
        exist_ok=True,
    )
    operation_ledger = _create_test_operation_ledger(
        bundle,
        epoch_id=operation_epoch,
        initialize=True,
        initialized_at_utc="2026-07-13T01:00:02Z",
    )
    copy_ledgers = _create_test_copy_ledgers(
        bundle,
        operation_ledger,
        epoch_id=copy_epoch,
        run_scope_id=run_scope_id,
        initialize=True,
        initialized_at_utc="2026-07-13T01:00:03Z",
    )
    return _CopyOperationLab(
        bootstrap=copy_operation_bootstrap,
        bundle=bundle,
        operation_ledger=operation_ledger,
        copy_ledgers=copy_ledgers,
        operation_epoch=operation_epoch,
        copy_epoch=copy_epoch,
        run_scope_id=run_scope_id,
        tag=tag,
    )


def _reopen(lab: _CopyOperationLab) -> _CopyOperationLab:
    bundle = _create_test_durable_boundary(
        lab.bootstrap.project,
        initialize=False,
        epoch_id=_AUDIT_EPOCH,
        initial_revision_sequence=1,
        initial_revision_id=_KEY_ID,
        master_key=_MASTER_KEY,
        key_created_at_utc=_KEY_TIME,
    )
    operation_ledger = _create_test_operation_ledger(
        bundle,
        epoch_id=lab.operation_epoch,
        initialize=False,
    )
    copy_ledgers = _create_test_copy_ledgers(
        bundle,
        operation_ledger,
        epoch_id=lab.copy_epoch,
        run_scope_id=lab.run_scope_id,
        initialize=False,
    )
    return _CopyOperationLab(
        bootstrap=lab.bootstrap,
        bundle=bundle,
        operation_ledger=operation_ledger,
        copy_ledgers=copy_ledgers,
        operation_epoch=lab.operation_epoch,
        copy_epoch=lab.copy_epoch,
        run_scope_id=lab.run_scope_id,
        tag=lab.tag,
    )


def _copy_segment_bytes(lab: _CopyOperationLab) -> bytes:
    roots = (
        lab.bootstrap.project
        / "Copy"
        / "ledger"
        / "source"
        / "segments"
        / lab.copy_epoch,
        lab.bootstrap.project
        / "Copy"
        / "ledger"
        / "copy"
        / "segments"
        / lab.copy_epoch,
    )
    return b"".join(path.read_bytes() for root in roots for path in sorted(root.iterdir()))


def _operation_segment_bytes(lab: _CopyOperationLab) -> bytes:
    root = (
        lab.bootstrap.project
        / "logs"
        / "operations"
        / "segments"
        / lab.operation_epoch
    )
    return b"".join(path.read_bytes() for path in sorted(root.iterdir()))


def _replace_target_with_same_bytes(
    target: Path,
    payload: bytes,
    replacement_kind: str,
) -> None:
    payload_path = target / "payload.bin"
    provenance_path = target / COPY_PROVENANCE_FILE_NAME
    provenance = provenance_path.read_bytes()
    original_identity = (
        target.stat().st_ino,
        payload_path.stat().st_ino,
        provenance_path.stat().st_ino,
    )
    if replacement_kind == "root":
        displaced = target.with_name(target.name + "-displaced")
        target.rename(displaced)
        target.mkdir()
        payload_path.write_bytes(payload)
        provenance_path.write_bytes(provenance)
    elif replacement_kind == "payload":
        replacement = target / "replacement.bin"
        replacement.write_bytes(payload)
        os.replace(replacement, payload_path)
    else:
        raise AssertionError("replacement kind is not exact")
    replacement_identity = (
        target.stat().st_ino,
        payload_path.stat().st_ino,
        provenance_path.stat().st_ino,
    )
    assert payload_path.read_bytes() == payload
    assert provenance_path.read_bytes() == provenance
    assert replacement_identity != original_identity


def _two_file_budget_failure(
    manifest: DeclaredTreeManifest,
    dimension: str,
) -> JobResourceBudget:
    default = JobResourceBudget.conservative_test_default()
    payload_size = manifest.entries[0].size_bytes
    if dimension == "entries_and_open_handles":
        return replace(
            default,
            maximum_entries=1,
            maximum_files=1,
            maximum_directories=1,
            maximum_open_handles=2,
        )
    if dimension == "files":
        return replace(
            default,
            maximum_entries=2,
            maximum_files=1,
            maximum_directories=1,
            maximum_open_handles=3,
        )
    if dimension == "file_bytes":
        return replace(
            default,
            maximum_file_bytes=COPY_PROVENANCE_MAX_BYTES - 1,
        )
    if dimension == "total_bytes":
        return replace(
            default,
            maximum_file_bytes=max(payload_size, COPY_PROVENANCE_MAX_BYTES),
            maximum_total_bytes=(
                payload_size + COPY_PROVENANCE_MAX_BYTES - 1
            ),
        )
    if dimension == "path_bytes":
        return replace(
            default,
            maximum_path_utf8_bytes=(
                len(COPY_PROVENANCE_FILE_NAME.encode("utf-8")) - 1
            ),
        )
    if dimension == "manifest_bytes":
        return replace(
            default,
            maximum_manifest_bytes=len(_logical_manifest_bytes(manifest.entries)),
        )
    raise AssertionError("unknown two-file budget dimension")


def _exact_worst_case_two_file_budget(
    manifest: DeclaredTreeManifest,
) -> JobResourceBudget:
    payload_entry = manifest.entries[0]
    worst_case_manifest = DeclaredTreeManifest(
        manifest_id=manifest.manifest_id,
        classification=manifest.classification,
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
    default = JobResourceBudget.conservative_test_default()
    return JobResourceBudget(
        maximum_entries=2,
        maximum_files=2,
        maximum_directories=1,
        maximum_depth=1,
        maximum_file_bytes=max(
            payload_entry.size_bytes,
            COPY_PROVENANCE_MAX_BYTES,
        ),
        maximum_total_bytes=(
            payload_entry.size_bytes + COPY_PROVENANCE_MAX_BYTES
        ),
        maximum_path_utf8_bytes=max(
            len(payload_entry.relative_path.encode("utf-8")),
            len(COPY_PROVENANCE_FILE_NAME.encode("utf-8")),
        ),
        maximum_open_handles=3,
        maximum_manifest_bytes=len(
            _logical_manifest_bytes(worst_case_manifest.entries)
        ),
        maximum_elapsed_seconds=default.maximum_elapsed_seconds,
        minimum_free_bytes=default.minimum_free_bytes,
    )


def _leave_recovery_pending(
    lab: _CopyOperationLab,
    monkeypatch: pytest.MonkeyPatch,
    *,
    payload: bytes,
    source_name: str,
    pending_kind: str,
    classification: DataClassification = DataClassification.INTERNAL,
) -> tuple[Path, str]:
    source = lab.source(source_name, payload)
    operation, _context, _manifest, copy_id = lab.copy_operation(
        payload,
        classification=classification,
    )
    original_append = DurableCopyLedgers._append_transition_under_existing_mutex
    injected = False

    def stop_at_pending_window(
        self: DurableCopyLedgers,
        lease: object,
        transition: object,
    ):
        nonlocal injected
        if transition.next_state is CopyState.PREPARED and not injected:
            injected = True
            if pending_kind == "source_only":
                raise CopyOperationError(
                    CopyOperationCode.STAGING_FAILED,
                    "injected source-only recovery window",
                )
            if pending_kind == "prepared":
                original_append(self, lease, transition)
                raise CopyOperationError(
                    CopyOperationCode.STAGING_FAILED,
                    "injected durable PREPARED recovery window",
                )
            raise AssertionError("unknown pending recovery kind")
        return original_append(self, lease, transition)

    with monkeypatch.context() as fault:
        fault.setattr(
            DurableCopyLedgers,
            "_append_transition_under_existing_mutex",
            stop_at_pending_window,
        )
        with pytest.raises(CopyOperationError):
            operation.execute(source.name)
    assert injected
    target_partition = (
        "restricted"
        if classification is DataClassification.RESTRICTED
        else "source"
    )
    target = lab.bootstrap.project / "Copy" / target_partition / copy_id
    assert not target.exists()
    return source, copy_id


@pytest.mark.parametrize(
    "dimension",
    (
        "entries_and_open_handles",
        "files",
        "file_bytes",
        "total_bytes",
        "path_bytes",
        "manifest_bytes",
    ),
)
def test_two_file_budget_is_rejected_before_external_open_or_any_project_write(
    copy_operation_lab: _CopyOperationLab,
    monkeypatch: pytest.MonkeyPatch,
    dimension: str,
) -> None:
    payload = b"preflight must cover the provenance envelope"
    source = copy_operation_lab.source(f"budget-{dimension}.bin", payload)
    context, manifest, copy_id = copy_operation_lab.context_and_manifest(payload)
    budget = _two_file_budget_failure(manifest, dimension)
    operation = _create_test_copy_operation(
        copy_operation_lab.bundle,
        copy_operation_lab.operation_ledger,
        copy_operation_lab.copy_ledgers,
        context,
        manifest,
        budget,
    )
    source_open_count = 0
    original_open = SyntheticReferenceReadPolicy.open_reference

    def record_open(
        self: SyntheticReferenceReadPolicy,
        source_name: str,
    ):
        nonlocal source_open_count
        source_open_count += 1
        return original_open(self, source_name)

    monkeypatch.setattr(
        SyntheticReferenceReadPolicy,
        "open_reference",
        record_open,
    )
    before = (
        copy_operation_lab.copy_ledgers.head,
        copy_operation_lab.operation_ledger.head,
        _copy_segment_bytes(copy_operation_lab),
        _operation_segment_bytes(copy_operation_lab),
    )

    with pytest.raises(CopyOperationError) as rejected:
        operation.execute(source.name)

    assert rejected.value.code is CopyOperationCode.MANIFEST_MISMATCH
    assert source_open_count == 0
    assert copy_operation_lab.copy_ledgers.head == before[0]
    assert copy_operation_lab.operation_ledger.head == before[1]
    assert _copy_segment_bytes(copy_operation_lab) == before[2]
    assert _operation_segment_bytes(copy_operation_lab) == before[3]
    assert not (
        copy_operation_lab.bootstrap.project
        / "tmp"
        / "jobs"
        / "INTERNAL"
        / context.job_id
    ).exists()
    assert not (
        copy_operation_lab.bootstrap.project / "Copy" / "source" / copy_id
    ).exists()
    assert source.read_bytes() == payload


def test_exact_worst_case_two_file_budget_allows_real_publish(
    copy_operation_lab: _CopyOperationLab,
) -> None:
    payload = b"exact conservative envelope"
    source = copy_operation_lab.source("budget-exact.bin", payload)
    _context, manifest, _copy_id = copy_operation_lab.context_and_manifest(payload)
    budget = _exact_worst_case_two_file_budget(manifest)
    operation, _context, _manifest, copy_id = copy_operation_lab.copy_operation(
        payload,
        budget=budget,
    )

    receipt = operation.execute(source.name)

    target = copy_operation_lab.bootstrap.project / "Copy" / "source" / copy_id
    assert receipt.sha256 == _sha(payload)
    assert (target / "payload.bin").read_bytes() == payload
    assert (target / COPY_PROVENANCE_FILE_NAME).read_bytes()
    history = next(iter(copy_operation_lab.copy_ledgers._copy_histories.values()))
    terminal = history[-1]
    assert terminal.publish_operation_plan.kind is CopyPublishPlanKind.RESERVED
    assert terminal.publish_terminal_state is OperationState.COMMITTED
    assert terminal.publish_operation_absence_witness is None


def test_legacy_source_only_fact_with_too_small_publish_budget_can_abort_safely(
    copy_operation_lab: _CopyOperationLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b"legacy pending source needs an abort path"
    source = copy_operation_lab.source("legacy-budget.bin", payload)
    _context, manifest, copy_id = copy_operation_lab.context_and_manifest(payload)
    legacy_budget = _two_file_budget_failure(manifest, "files")
    operation, context, _manifest, _copy_id = copy_operation_lab.copy_operation(
        payload,
        budget=legacy_budget,
    )
    operation_before = (
        copy_operation_lab.operation_ledger.head,
        _operation_segment_bytes(copy_operation_lab),
    )
    original_preflight = (
        _TestLocalCopyOperation._require_worst_case_publish_budget
    )
    monkeypatch.setattr(
        _TestLocalCopyOperation,
        "_require_worst_case_publish_budget",
        lambda _self: None,
    )

    with pytest.raises(CopyOperationError) as legacy_failure:
        operation.execute(source.name)

    assert legacy_failure.value.code is CopyOperationCode.MANIFEST_MISMATCH
    assert copy_operation_lab.copy_ledgers.head.pending_source_count == 1
    assert copy_operation_lab.copy_ledgers._copy_histories == {}
    assert copy_operation_lab.operation_ledger.head == operation_before[0]
    assert _operation_segment_bytes(copy_operation_lab) == operation_before[1]
    assert not (
        copy_operation_lab.bootstrap.project
        / "tmp"
        / "jobs"
        / "INTERNAL"
        / context.job_id
    ).exists()
    target = copy_operation_lab.bootstrap.project / "Copy" / "source" / copy_id
    assert not target.exists()

    monkeypatch.setattr(
        _TestLocalCopyOperation,
        "_require_worst_case_publish_budget",
        original_preflight,
    )
    reopened = _reopen(copy_operation_lab)
    recovery, _context, _manifest, _copy_id = reopened.copy_operation(
        payload,
        budget=legacy_budget,
    )

    assert recovery.reconcile(source.name) is None
    history = next(iter(reopened.copy_ledgers._copy_histories.values()))
    assert tuple(item.next_state for item in history) == (
        CopyState.RECOVERED_ABORT,
    )
    assert history[-1].publish_operation_plan.kind is CopyPublishPlanKind.UNSTARTED
    assert history[-1].publish_operation_absence_witness is not None
    assert history[-1].publish_terminal_state is None
    assert reopened.copy_ledgers.head.pending_source_count == 0
    assert not target.exists()


@pytest.mark.parametrize("pending_kind", ("source_only", "prepared"))
def test_absent_recovery_orders_handle_proofs_around_each_source_verification(
    copy_operation_lab: _CopyOperationLab,
    monkeypatch: pytest.MonkeyPatch,
    pending_kind: str,
) -> None:
    payload = f"ordered-{pending_kind}-recovery".encode("ascii")
    source, _copy_id = _leave_recovery_pending(
        copy_operation_lab,
        monkeypatch,
        payload=payload,
        source_name=f"ordered-{pending_kind}.bin",
        pending_kind=pending_kind,
    )
    reopened = _reopen(copy_operation_lab)
    recovery, _context, _manifest, _copy_id = reopened.copy_operation(payload)
    events: list[str] = []
    original_absent = _TestLocalCopyOperation._require_target_absent_twice
    original_checkpoint = _SyntheticReferenceLease._checkpoint_unchanged
    original_verify = _SyntheticReferenceLease.verify_unchanged
    original_append = DurableCopyLedgers._append_transition_under_existing_mutex

    def record_absent(
        self: _TestLocalCopyOperation,
        mutex: object,
        target: Path,
    ) -> None:
        events.append("target_absent")
        original_absent(self, mutex, target)

    def record_checkpoint(
        self: _SyntheticReferenceLease,
        evidence: object,
    ):
        events.append("source_checkpoint")
        return original_checkpoint(self, evidence)

    def record_verify(
        self: _SyntheticReferenceLease,
        evidence: object,
    ):
        events.append("source_final_verify")
        return original_verify(self, evidence)

    def record_append(
        self: DurableCopyLedgers,
        mutex: object,
        transition: object,
    ):
        if transition.next_state is CopyState.RECOVERED_ABORT:
            events.append("copy_append")
        return original_append(self, mutex, transition)

    monkeypatch.setattr(
        _TestLocalCopyOperation,
        "_require_target_absent_twice",
        record_absent,
    )
    monkeypatch.setattr(
        _SyntheticReferenceLease,
        "_checkpoint_unchanged",
        record_checkpoint,
    )
    monkeypatch.setattr(
        _SyntheticReferenceLease,
        "verify_unchanged",
        record_verify,
    )
    monkeypatch.setattr(
        DurableCopyLedgers,
        "_append_transition_under_existing_mutex",
        record_append,
    )

    assert recovery.reconcile(source.name) is None
    assert events == [
        "target_absent",
        "source_checkpoint",
        "target_absent",
        "copy_append",
        "source_final_verify",
        "target_absent",
    ]
    history = next(iter(reopened.copy_ledgers._copy_histories.values()))
    terminal = history[-1]
    expected_kind = (
        CopyPublishPlanKind.UNSTARTED
        if pending_kind == "source_only"
        else CopyPublishPlanKind.RESERVED
    )
    assert terminal.publish_operation_plan.kind is expected_kind
    assert terminal.publish_operation_absence_witness is not None
    assert terminal.publish_terminal_state is None


@pytest.mark.parametrize("pending_kind", ("source_only", "prepared"))
def test_target_created_after_source_verify_seals_before_copy_append(
    copy_operation_lab: _CopyOperationLab,
    monkeypatch: pytest.MonkeyPatch,
    pending_kind: str,
) -> None:
    payload = f"verify-race-{pending_kind}".encode("ascii")
    source, copy_id = _leave_recovery_pending(
        copy_operation_lab,
        monkeypatch,
        payload=payload,
        source_name=f"verify-race-{pending_kind}.bin",
        pending_kind=pending_kind,
    )
    reopened = _reopen(copy_operation_lab)
    recovery, _context, _manifest, _copy_id = reopened.copy_operation(payload)
    target = reopened.bootstrap.project / "Copy" / "source" / copy_id
    before = _copy_segment_bytes(reopened)
    original_checkpoint = _SyntheticReferenceLease._checkpoint_unchanged
    injected = False

    def create_target_after_checkpoint(
        self: _SyntheticReferenceLease,
        evidence: object,
    ):
        nonlocal injected
        result = original_checkpoint(self, evidence)
        if not injected:
            injected = True
            target.mkdir()
            (target / "sentinel.bin").write_bytes(b"hostile target")
        return result

    monkeypatch.setattr(
        _SyntheticReferenceLease,
        "_checkpoint_unchanged",
        create_target_after_checkpoint,
    )

    with pytest.raises(CopyOperationError) as rejected:
        recovery.reconcile(source.name)

    assert rejected.value.code is CopyOperationCode.RECOVERY_CONTRADICTION
    assert injected
    assert _copy_segment_bytes(reopened) == before
    assert (target / "sentinel.bin").read_bytes() == b"hostile target"
    assert reopened.bundle.writer._poisoned is not None


def test_target_created_between_same_parent_handle_observations_seals_without_append(
    copy_operation_lab: _CopyOperationLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b"same-parent handle absence race"
    source, copy_id = _leave_recovery_pending(
        copy_operation_lab,
        monkeypatch,
        payload=payload,
        source_name="parent-handle-race.bin",
        pending_kind="source_only",
    )
    reopened = _reopen(copy_operation_lab)
    recovery, _context, _manifest, _copy_id = reopened.copy_operation(payload)
    target = reopened.bootstrap.project / "Copy" / "source" / copy_id
    before = _copy_segment_bytes(reopened)
    injected = False

    def create_during_parent_handle_scan(
        _writer: _WindowsHandleWriter,
        _guarded_target: object,
    ) -> None:
        nonlocal injected
        if not injected:
            injected = True
            target.mkdir()
            (target / "sentinel.bin").write_bytes(b"namespace race")

    monkeypatch.setattr(
        _WindowsHandleWriter,
        "_after_directory_target_absence_first_observation",
        create_during_parent_handle_scan,
    )

    with pytest.raises(CopyOperationError) as rejected:
        recovery.reconcile(source.name)

    assert rejected.value.code is CopyOperationCode.RECOVERY_CONTRADICTION
    assert injected
    assert _copy_segment_bytes(reopened) == before
    assert (target / "sentinel.bin").read_bytes() == b"namespace race"
    assert reopened.bundle.writer._poisoned is not None


@pytest.mark.parametrize("pending_kind", ("source_only", "prepared"))
@pytest.mark.parametrize("race_point", ("transition_built", "append_returned"))
def test_post_append_absence_race_never_returns_success_and_seals_ledger(
    copy_operation_lab: _CopyOperationLab,
    monkeypatch: pytest.MonkeyPatch,
    pending_kind: str,
    race_point: str,
) -> None:
    payload = f"post-append-{pending_kind}-{race_point}".encode("ascii")
    source, copy_id = _leave_recovery_pending(
        copy_operation_lab,
        monkeypatch,
        payload=payload,
        source_name=f"post-append-{pending_kind}-{race_point}.bin",
        pending_kind=pending_kind,
    )
    reopened = _reopen(copy_operation_lab)
    recovery, _context, _manifest, _copy_id = reopened.copy_operation(payload)
    target = reopened.bootstrap.project / "Copy" / "source" / copy_id
    before = _copy_segment_bytes(reopened)
    injected = False

    def create_target() -> None:
        nonlocal injected
        if not injected:
            injected = True
            target.mkdir()
            (target / "sentinel.bin").write_bytes(b"late namespace race")

    if race_point == "transition_built":
        method_name = (
            "_source_only_recovered_abort_transition"
            if pending_kind == "source_only"
            else "_recovered_transition"
        )
        original_transition = getattr(_TestLocalCopyOperation, method_name)

        def build_then_create(self: _TestLocalCopyOperation, *args: object, **kwargs: object):
            transition = original_transition(self, *args, **kwargs)
            create_target()
            return transition

        monkeypatch.setattr(
            _TestLocalCopyOperation,
            method_name,
            build_then_create,
        )
    else:
        original_append = DurableCopyLedgers._append_transition_under_existing_mutex

        def append_then_create(
            self: DurableCopyLedgers,
            mutex: object,
            transition: object,
        ):
            receipt = original_append(self, mutex, transition)
            if transition.next_state is CopyState.RECOVERED_ABORT:
                create_target()
            return receipt

        monkeypatch.setattr(
            DurableCopyLedgers,
            "_append_transition_under_existing_mutex",
            append_then_create,
        )

    with pytest.raises(CopyOperationError) as rejected:
        recovery.reconcile(source.name)

    assert rejected.value.code is CopyOperationCode.RECOVERY_CONTRADICTION
    assert injected
    assert _copy_segment_bytes(reopened) != before
    assert (target / "sentinel.bin").read_bytes() == b"late namespace race"
    assert reopened.bundle.writer._poisoned is not None


@pytest.mark.parametrize("pending_kind", ("source_only", "prepared"))
def test_restricted_abort_consumes_paths_before_open_and_never_rederives_them(
    copy_operation_lab: _CopyOperationLab,
    monkeypatch: pytest.MonkeyPatch,
    pending_kind: str,
) -> None:
    payload = f"restricted-abort-{pending_kind}".encode("ascii")
    source, copy_id = _leave_recovery_pending(
        copy_operation_lab,
        monkeypatch,
        payload=payload,
        source_name=f"restricted-abort-{pending_kind}.bin",
        pending_kind=pending_kind,
        classification=DataClassification.RESTRICTED,
    )
    reopened = _reopen(copy_operation_lab)
    recovery, context, _manifest, _copy_id = reopened.copy_operation(
        payload,
        classification=DataClassification.RESTRICTED,
    )
    boundary = reopened.bundle.boundary
    capability = boundary._issue_restricted_copy_recovery_locator(context)
    boundary_type = type(boundary)
    original_consume = boundary_type._consume_restricted_copy_recovery_locator
    original_open = SyntheticReferenceReadPolicy.open_reference
    events: list[str] = []
    consumed_paths: list[tuple[Path, Path]] = []

    def record_consume(
        self: object,
        supplied: object,
        supplied_context: object,
    ) -> tuple[Path, Path]:
        events.append("consume_locator")
        paths = original_consume(self, supplied, supplied_context)
        consumed_paths.append(paths)
        return paths

    def record_open(
        self: SyntheticReferenceReadPolicy,
        source_name: str,
    ):
        assert events == ["consume_locator"]
        events.append("open_external")
        return original_open(self, source_name)

    def forbid_path_derivation(_self: _TestLocalCopyOperation) -> Path:
        raise AssertionError("RESTRICTED recovery re-derived a locator")

    monkeypatch.setattr(
        boundary_type,
        "_consume_restricted_copy_recovery_locator",
        record_consume,
    )
    monkeypatch.setattr(
        SyntheticReferenceReadPolicy,
        "open_reference",
        record_open,
    )
    monkeypatch.setattr(
        _TestLocalCopyOperation,
        "_target_relative_path",
        forbid_path_derivation,
    )
    monkeypatch.setattr(
        _TestLocalCopyOperation,
        "_operation_source_relative_path",
        forbid_path_derivation,
    )

    assert recovery.reconcile(
        source.name,
        restricted_locator_capability=capability,
    ) is None

    assert events == ["consume_locator", "open_external"]
    assert len(consumed_paths) == 1
    recovery_source, recovery_target = consumed_paths[0]
    assert recovery_target == Path("Copy") / "restricted" / copy_id
    target = reopened.bootstrap.project / recovery_target
    assert not target.exists()
    history = next(iter(reopened.copy_ledgers._copy_histories.values()))
    expected_states = (
        (CopyState.RECOVERED_ABORT,)
        if pending_kind == "source_only"
        else (CopyState.PREPARED, CopyState.RECOVERED_ABORT)
    )
    assert tuple(item.next_state for item in history) == expected_states
    serialized = _copy_segment_bytes(reopened) + _operation_segment_bytes(reopened)
    for forbidden in (
        source.name,
        context.run_id,
        context.job_id,
        context.operation_id,
        copy_id,
        recovery_source.as_posix(),
        recovery_target.as_posix(),
    ):
        assert forbidden.encode("utf-8") not in serialized
        assert forbidden not in repr(capability)


def test_restricted_committed_recovery_and_replay_use_only_consumed_path_authority(
    copy_operation_lab: _CopyOperationLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b"restricted committed recovery and replay"
    source = copy_operation_lab.source("restricted-commit.bin", payload)
    operation, _context, _manifest, copy_id = copy_operation_lab.copy_operation(
        payload,
        classification=DataClassification.RESTRICTED,
    )
    original_append = DurableCopyLedgers._append_transition_under_existing_mutex
    injected = False

    def fail_first_mutated(
        self: DurableCopyLedgers,
        mutex: object,
        transition: object,
    ):
        nonlocal injected
        if transition.next_state is CopyState.MUTATED and not injected:
            injected = True
            raise CopyLedgerError(
                CopyLedgerCode.STORAGE_FAILURE,
                "injected restricted post-publish Copy gap",
            )
        return original_append(self, mutex, transition)

    with monkeypatch.context() as fault:
        fault.setattr(
            DurableCopyLedgers,
            "_append_transition_under_existing_mutex",
            fail_first_mutated,
        )
        with pytest.raises(CopyOperationError):
            operation.execute(source.name)
    assert injected
    target = (
        copy_operation_lab.bootstrap.project
        / "Copy"
        / "restricted"
        / copy_id
    )
    target_before = (
        target.stat().st_ino,
        (target / "payload.bin").stat().st_ino,
        (target / COPY_PROVENANCE_FILE_NAME).stat().st_ino,
    )

    reopened = _reopen(copy_operation_lab)
    recovery, context, _manifest, _copy_id = reopened.copy_operation(
        payload,
        classification=DataClassification.RESTRICTED,
    )
    capability = reopened.bundle.boundary._issue_restricted_copy_recovery_locator(
        context
    )

    def forbid_path_derivation(_self: _TestLocalCopyOperation) -> Path:
        raise AssertionError("RESTRICTED committed recovery re-derived a locator")

    monkeypatch.setattr(
        _TestLocalCopyOperation,
        "_target_relative_path",
        forbid_path_derivation,
    )
    monkeypatch.setattr(
        _TestLocalCopyOperation,
        "_operation_source_relative_path",
        forbid_path_derivation,
    )
    recovered = recovery.reconcile(
        source.name,
        restricted_locator_capability=capability,
    )
    assert type(recovered) is CopyOperationReceipt
    assert recovered.replayed is False
    assert next(iter(reopened.copy_ledgers._copy_histories.values()))[-1].next_state is (
        CopyState.RECOVERED_COMMIT
    )
    assert (
        target.stat().st_ino,
        (target / "payload.bin").stat().st_ino,
        (target / COPY_PROVENANCE_FILE_NAME).stat().st_ino,
    ) == target_before

    replayed = _reopen(reopened)
    replay, replay_context, _manifest, _copy_id = replayed.copy_operation(
        payload,
        classification=DataClassification.RESTRICTED,
    )
    replay_capability = (
        replayed.bundle.boundary._issue_restricted_copy_recovery_locator(
            replay_context
        )
    )
    before_replay = (
        _copy_segment_bytes(replayed),
        _operation_segment_bytes(replayed),
    )
    repeated = replay.reconcile(
        source.name,
        restricted_locator_capability=replay_capability,
    )
    assert type(repeated) is CopyOperationReceipt
    assert repeated.replayed is True
    assert _copy_segment_bytes(replayed) == before_replay[0]
    assert _operation_segment_bytes(replayed) == before_replay[1]
    assert (
        target.stat().st_ino,
        (target / "payload.bin").stat().st_ino,
        (target / COPY_PROVENANCE_FILE_NAME).stat().st_ino,
    ) == target_before


@pytest.mark.parametrize("misuse", ("missing", "foreign", "hmac", "cross_thread"))
def test_restricted_recovery_capability_misuse_fails_before_external_open(
    copy_operation_lab: _CopyOperationLab,
    monkeypatch: pytest.MonkeyPatch,
    misuse: str,
) -> None:
    payload = f"restricted-capability-{misuse}".encode("ascii")
    source, copy_id = _leave_recovery_pending(
        copy_operation_lab,
        monkeypatch,
        payload=payload,
        source_name=f"restricted-capability-{misuse}.bin",
        pending_kind="source_only",
        classification=DataClassification.RESTRICTED,
    )
    reopened = _reopen(copy_operation_lab)
    context, manifest, _copy_id = reopened.context_and_manifest(
        payload,
        classification=DataClassification.RESTRICTED,
    )
    boundary = reopened.bundle.boundary
    capability: object | None
    if misuse == "missing":
        capability = None
    elif misuse == "foreign":
        suffix = f"FOREIGN-{reopened.tag}"
        foreign_context = boundary.issue_context(
            run_id=f"RUN-{suffix}",
            job_id=f"JOB-{suffix}",
            operation_id=f"OP-{suffix}",
            caller=Caller.IMPORT_SERVICE,
            purpose=Purpose.COPY_SOURCE,
            manifest_id=f"MANIFEST-{suffix}",
            classification=DataClassification.RESTRICTED,
            scopes=(
                ScopeId(ScopeKind.RUN_ID, f"RUN-{suffix}"),
                ScopeId(
                    ScopeKind.COPY_LEDGER_EPOCH_ID,
                    reopened.copy_epoch,
                ),
                ScopeId(ScopeKind.JOB_ID, f"JOB-{suffix}"),
                ScopeId(ScopeKind.OPERATION_ID, f"OP-{suffix}"),
                ScopeId(ScopeKind.MANIFEST_ID, f"MANIFEST-{suffix}"),
                ScopeId(ScopeKind.COPY_ID, f"COPY-{suffix}"),
                ScopeId(ScopeKind.CHECKPOINT_ID, f"CHECKPOINT-{suffix}"),
            ),
        )
        capability = boundary._issue_restricted_copy_recovery_locator(
            foreign_context
        )
    else:
        capability = boundary._issue_restricted_copy_recovery_locator(context)
        if misuse == "hmac":
            object.__setattr__(
                capability,
                "_RestrictedRecoveryLocatorCapability__authenticator",
                "0" * 64,
            )
    source_open_count = 0
    original_open = SyntheticReferenceReadPolicy.open_reference

    def record_open(
        self: SyntheticReferenceReadPolicy,
        source_name: str,
    ):
        nonlocal source_open_count
        source_open_count += 1
        return original_open(self, source_name)

    monkeypatch.setattr(
        SyntheticReferenceReadPolicy,
        "open_reference",
        record_open,
    )
    before = (
        _copy_segment_bytes(reopened),
        _operation_segment_bytes(reopened),
    )
    default_budget = JobResourceBudget.conservative_test_default()

    def attempt_reconcile() -> CopyOperationError:
        recovery = _create_test_copy_operation(
            reopened.bundle,
            reopened.operation_ledger,
            reopened.copy_ledgers,
            context,
            manifest,
            default_budget,
        )
        try:
            recovery.reconcile(
                source.name,
                restricted_locator_capability=capability,
            )
        except CopyOperationError as error:
            return error
        raise AssertionError("restricted capability misuse returned success")

    error = (
        _run_in_fresh_thread(attempt_reconcile)
        if misuse == "cross_thread"
        else attempt_reconcile()
    )

    assert error.code is CopyOperationCode.RECOVERY_CONTRADICTION
    assert source_open_count == 0
    assert _copy_segment_bytes(reopened) == before[0]
    assert _operation_segment_bytes(reopened) == before[1]
    target = reopened.bootstrap.project / "Copy" / "restricted" / copy_id
    assert not target.exists()
    serialized_error = f"{error!r}\n{error}"
    for forbidden in (
        source.name,
        context.run_id,
        context.job_id,
        context.operation_id,
        copy_id,
        str(target),
    ):
        assert forbidden not in serialized_error


def test_restricted_recovery_capability_is_single_use_in_real_reconcile_flow(
    copy_operation_lab: _CopyOperationLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b"restricted capability single use"
    source, _copy_id = _leave_recovery_pending(
        copy_operation_lab,
        monkeypatch,
        payload=payload,
        source_name="restricted-capability-reused.bin",
        pending_kind="source_only",
        classification=DataClassification.RESTRICTED,
    )
    reopened = _reopen(copy_operation_lab)
    recovery, context, manifest, _copy_id = reopened.copy_operation(
        payload,
        classification=DataClassification.RESTRICTED,
    )
    capability = reopened.bundle.boundary._issue_restricted_copy_recovery_locator(
        context
    )
    assert recovery.reconcile(
        source.name,
        restricted_locator_capability=capability,
    ) is None
    before = (
        _copy_segment_bytes(reopened),
        _operation_segment_bytes(reopened),
    )
    second = _create_test_copy_operation(
        reopened.bundle,
        reopened.operation_ledger,
        reopened.copy_ledgers,
        context,
        manifest,
        JobResourceBudget.conservative_test_default(),
    )

    with pytest.raises(CopyOperationError) as rejected:
        second.reconcile(
            source.name,
            restricted_locator_capability=capability,
        )

    assert rejected.value.code is CopyOperationCode.RECOVERY_CONTRADICTION
    assert _copy_segment_bytes(reopened) == before[0]
    assert _operation_segment_bytes(reopened) == before[1]
    assert reopened.bundle.writer._poisoned is not None


def test_internal_copy_runs_source_to_dual_ledger_to_immutable_target(
    copy_operation_lab: _CopyOperationLab,
) -> None:
    payload = b"synthetic internal copy payload"
    source = copy_operation_lab.source("internal-source.bin", payload)
    operation, _context, _manifest, copy_id = copy_operation_lab.copy_operation(payload)

    receipt = operation.execute(source.name)

    target = copy_operation_lab.bootstrap.project / "Copy" / "source" / copy_id
    assert type(receipt) is CopyOperationReceipt
    assert receipt.classification is DataClassification.INTERNAL
    assert receipt.replayed is False
    assert receipt.sha256 == _sha(payload)
    assert (target / "payload.bin").read_bytes() == payload
    assert source.read_bytes() == payload
    assert copy_operation_lab.copy_ledgers.head.source.segment_count == 2
    assert copy_operation_lab.copy_ledgers.head.copy.segment_count == 5
    assert copy_operation_lab.copy_ledgers.head.pending_source_count == 0
    assert copy_operation_lab.operation_ledger.head.unresolved_transaction_ids == ()
    history = next(iter(copy_operation_lab.copy_ledgers._copy_histories.values()))
    prepared = history[0]
    with copy_operation_lab.bundle.writer.acquire_runtime_mutex() as mutex:
        source_result = (
            copy_operation_lab.copy_ledgers.source_result_under_existing_mutex(
                mutex,
                prepared.source_anchor.record_id,
            )
        )
    assert source_result is not None
    source_record, source_receipt = source_result
    provenance = build_copy_provenance_material(
        source_record,
        source_receipt,
        manifest_id=_manifest.manifest_id,
    )
    assert (target / COPY_PROVENANCE_FILE_NAME).read_bytes() == (
        provenance.provenance_bytes
    )
    assert prepared.source_anchor == source_receipt.anchor
    assert prepared.expected_manifest_sha256 == (
        provenance.publish_manifest.manifest_sha256
    )
    assert prepared.provenance_metadata_sha256 == provenance.provenance_sha256
    with pytest.raises(TypeError):
        pickle.dumps(receipt)


def test_restricted_copy_redacts_source_and_business_ids(
    copy_operation_lab: _CopyOperationLab,
) -> None:
    payload = b"synthetic restricted payload"
    source_name = "restricted-original-name.bin"
    source = copy_operation_lab.source(source_name, payload)
    operation, context, _manifest, copy_id = copy_operation_lab.copy_operation(
        payload,
        classification=DataClassification.RESTRICTED,
    )

    receipt = operation.execute(source.name)

    target = copy_operation_lab.bootstrap.project / "Copy" / "restricted" / copy_id
    assert (target / "payload.bin").read_bytes() == payload
    provenance_bytes = (target / COPY_PROVENANCE_FILE_NAME).read_bytes()
    assert provenance_bytes
    assert receipt.classification is DataClassification.RESTRICTED
    snapshot = copy_operation_lab.bundle.writer.read_flat_directory(
        Path("Copy") / "restricted" / copy_id,
        maximum_entries=4,
        maximum_file_bytes=1024 * 1024,
        maximum_total_bytes=1024 * 1024,
    )
    root_frame = object.__getattribute__(
        snapshot.root_identity_material,
        "_HandleObjectIdentityMaterial__frame",
    )
    entries = {entry.name: entry for entry in snapshot.entries}
    assert set(entries) == {"payload.bin", COPY_PROVENANCE_FILE_NAME}
    payload_frame = object.__getattribute__(
        entries["payload.bin"].identity_material,
        "_HandleObjectIdentityMaterial__frame",
    )
    provenance_frame = object.__getattribute__(
        entries[COPY_PROVENANCE_FILE_NAME].identity_material,
        "_HandleObjectIdentityMaterial__frame",
    )
    serialized = (
        _copy_segment_bytes(copy_operation_lab)
        + _operation_segment_bytes(copy_operation_lab)
        + provenance_bytes
    )
    for forbidden in (
        source_name,
        str(source),
        context.run_id,
        context.job_id,
        context.operation_id,
        copy_id,
    ):
        assert forbidden.encode("utf-8") not in serialized
        assert forbidden not in repr(receipt)
    for raw_identity in (
        root_frame[-24:],
        payload_frame[-24:],
        provenance_frame[-24:],
    ):
        assert raw_identity not in serialized
    with pytest.raises(TypeError):
        pickle.dumps(snapshot.root_identity_material)
    with pytest.raises(TypeError):
        pickle.dumps(snapshot.tree_identity_material)
    terminal = next(iter(copy_operation_lab.copy_ledgers._copy_histories.values()))[-1]
    assert terminal.target_locator.mode.value == "HMAC_ONLY"
    assert len(terminal.target_locator.value) == 64


def test_internal_copy_ledger_also_redacts_run_job_operation_and_copy_ids(
    copy_operation_lab: _CopyOperationLab,
) -> None:
    payload = b"synthetic internal redaction payload"
    source = copy_operation_lab.source("internal-redaction.bin", payload)
    operation, context, _manifest, copy_id = copy_operation_lab.copy_operation(payload)

    operation.execute(source.name)

    serialized = _copy_segment_bytes(copy_operation_lab)
    for forbidden in (
        source.name,
        context.run_id,
        context.job_id,
        context.operation_id,
        copy_id,
    ):
        assert forbidden.encode("utf-8") not in serialized
    terminal = next(iter(copy_operation_lab.copy_ledgers._copy_histories.values()))[-1]
    assert terminal.target_locator.mode.value == "HMAC_ONLY"
    plan = terminal.publish_operation_plan
    for projected in (
        plan.operation_reference_hmac_sha256,
        plan.publish_transaction_reference_hmac_sha256,
        plan.pair_reference_hmac_sha256,
        plan.source_locator_hmac_sha256,
        plan.target_locator_hmac_sha256,
    ):
        assert projected is not None and len(projected) == 64
    assert not {
        "operation_reference",
        "publish_transaction_id",
        "pair_reference",
        "source_locator",
        "target_locator",
    } & set(plan.to_json())
    assert copy_operation_lab.run_scope_id not in copy_operation_lab.copy_epoch


def test_cross_run_context_is_rejected_before_copy_or_publish_ledger_write(
    copy_operation_lab: _CopyOperationLab,
) -> None:
    payload = b"cross run must be rejected"
    context, manifest, _copy_id = copy_operation_lab.context_and_manifest(payload)
    wrong_run = copy_operation_lab.bundle.boundary.issue_context(
        run_id="RUN-S3F-CROSS-RUN",
        job_id=context.job_id,
        operation_id=context.operation_id,
        caller=context.caller,
        purpose=context.purpose,
        manifest_id=context.manifest_id,
        classification=context.classification,
        scopes=tuple(
            ScopeId(scope.kind, scope.value)
            for scope in context.scopes
            if scope.kind is not ScopeKind.RUN_ID
        )
        + (ScopeId(ScopeKind.RUN_ID, "RUN-S3F-CROSS-RUN"),),
    )
    before = (
        copy_operation_lab.copy_ledgers.head,
        copy_operation_lab.operation_ledger.head,
        _copy_segment_bytes(copy_operation_lab),
    )

    with pytest.raises(ProductionBoundaryError) as raised:
        _create_test_copy_operation(
            copy_operation_lab.bundle,
            copy_operation_lab.operation_ledger,
            copy_operation_lab.copy_ledgers,
            wrong_run,
            manifest,
            JobResourceBudget.conservative_test_default(),
        )

    assert raised.value.code is BoundaryErrorCode.INVALID_CONTEXT
    assert copy_operation_lab.copy_ledgers.head == before[0]
    assert copy_operation_lab.operation_ledger.head == before[1]
    assert _copy_segment_bytes(copy_operation_lab) == before[2]


def test_sqlite_name_fails_before_any_project_write(
    copy_operation_lab: _CopyOperationLab,
) -> None:
    payload = b"not a database"
    source = copy_operation_lab.source("blocked.sqlite3", payload)
    operation, context, _manifest, copy_id = copy_operation_lab.copy_operation(payload)
    before = (
        copy_operation_lab.copy_ledgers.head,
        copy_operation_lab.operation_ledger.head,
        _copy_segment_bytes(copy_operation_lab),
    )

    with pytest.raises(CopyOperationError) as raised:
        operation.execute(source.name)

    assert raised.value.code is CopyOperationCode.SOURCE_FAILED
    assert raised.value.__context__ is None
    assert raised.value.__cause__ is None
    surface = _TestLocalCopyOperation.execute
    assert not hasattr(surface, "__wrapped__")
    assert surface.__closure__ is None
    assert surface.__defaults__ is None
    assert surface.__kwdefaults__ is None
    traceback_frames = _module_traceback_locals(
        raised.value,
        "app.safety.copy_operation",
    )
    assert traceback_frames
    forbidden_keys = {
        "self",
        "arguments",
        "keywords",
        "caught",
        "caught_traceback",
        "function",
        "__path_free_capture",
        "source_name",
        "source_lease",
        "material",
        "source_handle",
        "handle",
        "payload",
    }
    for frame_locals in traceback_frames:
        assert forbidden_keys.isdisjoint(frame_locals)
        rendered = repr(frame_locals)
        assert source.name not in rendered
        assert str(source) not in rendered
        assert str(copy_operation_lab.bootstrap.reference) not in rendered
    assert copy_operation_lab.copy_ledgers.head == before[0]
    assert copy_operation_lab.operation_ledger.head == before[1]
    assert _copy_segment_bytes(copy_operation_lab) == before[2]
    assert not (
        copy_operation_lab.bootstrap.project
        / "tmp"
        / "jobs"
        / "INTERNAL"
        / context.job_id
    ).exists()
    assert not (
        copy_operation_lab.bootstrap.project / "Copy" / "source" / copy_id
    ).exists()


def test_copy_boundary_binder_failure_has_no_chain_and_does_not_consume(
    copy_operation_lab: _CopyOperationLab,
) -> None:
    payload = b"copy-boundary-binder-clean"
    source = copy_operation_lab.source("copy-binder-clean.bin", payload)
    operation, _context, _manifest, _copy_id = copy_operation_lab.copy_operation(
        payload
    )
    secret_keyword = r"D:\TRACE-CONTEXT-SECRET\copy-payload.bin"

    captured: CopyOperationError | None = None
    try:
        raise RuntimeError("outer-exception-must-not-become-context")
    except RuntimeError:
        try:
            operation.execute(source.name, **{secret_keyword: object()})
        except CopyOperationError as error:
            captured = error
            assert sys.exc_info()[1] is error
            assert error.code is CopyOperationCode.INDETERMINATE
            assert error.__context__ is None
            assert error.__cause__ is None
    assert captured is not None
    assert operation._state == "ISSUED"
    with pytest.raises(CopyOperationError) as cross_route:
        operation.execute(
            source.name,
            __path_free_capture=_TestLocalCopyOperation.reconcile.__code__,
        )
    assert cross_route.value.code is CopyOperationCode.INDETERMINATE
    assert cross_route.value.__context__ is None
    assert cross_route.value.__cause__ is None
    assert operation._state == "ISSUED"

    frames = _module_traceback_locals(captured, "app.safety.copy_operation")
    assert frames
    forbidden_keys = {
        "self",
        "arguments",
        "keywords",
        "function",
        "caught",
        "caught_traceback",
        "__path_free_capture",
        "source_name",
        "source_lease",
        "material",
        "source_handle",
        "handle",
        "payload",
    }
    for frame_locals in frames:
        assert forbidden_keys.isdisjoint(frame_locals)
        rendered = repr(frame_locals)
        assert secret_keyword not in rendered
        assert source.name not in rendered
        assert str(source) not in rendered

    surface = _TestLocalCopyOperation.execute
    assert not hasattr(surface, "__wrapped__")
    assert surface.__closure__ is None
    assert surface.__defaults__ is None
    assert surface.__kwdefaults__ is None
    surfaces = _copy_boundary_surfaces()
    assert len(surfaces) == copy_operation_module._COPY_BOUNDARY_MAX
    assert len({id(candidate.__code__) for candidate in surfaces}) == len(surfaces)
    assert all(candidate.__closure__ is None for candidate in surfaces)
    assert all(candidate.__defaults__ is None for candidate in surfaces)
    assert all(candidate.__kwdefaults__ is None for candidate in surfaces)
    for removed in (
        "_copy_boundary_template",
        "_create_copy_boundary_runtime",
        "_path_free_exception_boundary",
        "_register_copy_boundary",
        "_seal_copy_boundaries",
    ):
        assert not hasattr(copy_operation_module, removed)

    vault = _copy_boundary_vault()
    vault_size = len(vault)
    assert vault_size == copy_operation_module._COPY_BOUNDARY_MAX
    direct_result = copy_operation_module._dispatch_copy_boundary(
        (operation, source.name),
        {},
    )
    assert type(direct_result).__name__ == "_CopyBoundaryFailure"
    assert operation._state == "ISSUED"
    assert len(vault) == vault_size

    receipt = operation.execute(source.name)
    assert receipt.sha256 == hashlib.sha256(payload).hexdigest()


def test_copy_operation_rejects_reused_numeric_thread_ident(
    copy_operation_lab: _CopyOperationLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b"copy-operation-owner-object"
    source = copy_operation_lab.source("operation-ident-reuse.bin", payload)
    operation, _context, _manifest, _copy_id = copy_operation_lab.copy_operation(
        payload
    )
    replacement_thread = threading.Thread()
    replacement_thread._ident = operation._owner_thread

    with monkeypatch.context() as reused_identity:
        reused_identity.setattr(
            threading,
            "current_thread",
            lambda: replacement_thread,
        )
        with pytest.raises(CopyOperationError) as rejected:
            operation.execute(source.name)

    assert rejected.value.code is CopyOperationCode.INVALID_REQUEST
    assert operation._state == "ISSUED"
    receipt = operation.execute(source.name)
    assert receipt.sha256 == hashlib.sha256(payload).hexdigest()


def test_mismatched_source_policy_copy_scope_is_rejected_without_project_write(
    copy_operation_lab: _CopyOperationLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b"wrong source policy scope"
    context, manifest, copy_id = copy_operation_lab.context_and_manifest(payload)
    original_policy_factory = (
        production_guard_module._create_synthetic_reference_read_policy
    )
    issued_policies: list[object] = []

    def issue_wrong_scope(
        project_root: Path,
        *,
        copy_id: str,
        classification: DataClassification,
    ):
        policy = original_policy_factory(
            project_root,
            copy_id=f"{copy_id}-WRONG",
            classification=classification,
        )
        issued_policies.append(policy)
        return policy

    monkeypatch.setattr(
        production_guard_module,
        "_create_synthetic_reference_read_policy",
        issue_wrong_scope,
    )
    before = (
        copy_operation_lab.copy_ledgers.head,
        copy_operation_lab.operation_ledger.head,
        _copy_segment_bytes(copy_operation_lab),
    )

    with pytest.raises(CopyOperationError) as raised:
        _create_test_copy_operation(
            copy_operation_lab.bundle,
            copy_operation_lab.operation_ledger,
            copy_operation_lab.copy_ledgers,
            context,
            manifest,
            JobResourceBudget.conservative_test_default(),
        )

    assert raised.value.code is CopyOperationCode.INVALID_CONTEXT
    assert len(issued_policies) == 1
    assert issued_policies[0]._state == "CLOSED"
    assert issued_policies[0]._handles == []
    assert copy_operation_lab.copy_ledgers.head == before[0]
    assert copy_operation_lab.operation_ledger.head == before[1]
    assert _copy_segment_bytes(copy_operation_lab) == before[2]
    assert not (
        copy_operation_lab.bootstrap.project
        / "tmp"
        / "jobs"
        / "INTERNAL"
        / context.job_id
    ).exists()
    assert not (
        copy_operation_lab.bootstrap.project / "Copy" / "source" / copy_id
    ).exists()


def test_copy_preflight_rejects_manifest_before_source_policy_is_issued(
    copy_operation_lab: _CopyOperationLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b"preflight rejects before source handles"
    context, valid_manifest, _copy_id = copy_operation_lab.context_and_manifest(payload)
    invalid_manifest = DeclaredTreeManifest(
        manifest_id=valid_manifest.manifest_id,
        classification=valid_manifest.classification,
        entries=(
            DeclaredTreeEntry(
                "extra.bin",
                TreeEntryKind.FILE,
                1,
                _sha(b"x"),
            ),
            valid_manifest.entries[0],
        ),
    )
    source_policy_calls = 0

    def reject_source_policy_issue(*_args: object, **_kwargs: object) -> object:
        nonlocal source_policy_calls
        source_policy_calls += 1
        raise AssertionError("source policy must not be issued before preflight")

    monkeypatch.setattr(
        production_guard_module,
        "_create_synthetic_reference_read_policy",
        reject_source_policy_issue,
    )

    with pytest.raises(CopyOperationError) as raised:
        _create_test_copy_operation(
            copy_operation_lab.bundle,
            copy_operation_lab.operation_ledger,
            copy_operation_lab.copy_ledgers,
            context,
            invalid_manifest,
            JobResourceBudget.conservative_test_default(),
        )

    assert raised.value.code is CopyOperationCode.MANIFEST_MISMATCH
    assert source_policy_calls == 0


def test_unexecuted_copy_operation_close_is_idempotent_and_context_managed(
    copy_operation_lab: _CopyOperationLab,
) -> None:
    payload = b"unused copy operation closes source roots"
    operation, _context, _manifest, _copy_id = copy_operation_lab.copy_operation(payload)
    policy = operation._source_policy
    assert policy._state == "ISSUED"
    assert policy._handles

    with operation as entered:
        assert entered is operation
        operation.close()
        operation.close()

    assert operation._state == "CLOSED"
    assert policy._state == "CLOSED"
    assert policy._handles == []


@pytest.mark.parametrize("helper_name", ["_execute_new", "_try_replay"])
def test_private_execution_helpers_reject_forged_permit_before_project_write(
    copy_operation_lab: _CopyOperationLab,
    helper_name: str,
) -> None:
    payload = b"forged permit must never reach a writer"
    operation, context, _manifest, copy_id = copy_operation_lab.copy_operation(payload)
    target = Path("Copy") / "source" / copy_id
    before = (
        copy_operation_lab.copy_ledgers.head,
        copy_operation_lab.operation_ledger.head,
        _copy_segment_bytes(copy_operation_lab),
    )

    try:
        helper = getattr(operation, helper_name)
        with pytest.raises(CopyOperationError) as raised:
            helper(
                object(),
                object(),
                object(),
                object(),
                object(),
                object(),
                object(),
                object(),
                target,
            )
    finally:
        operation.close()

    assert raised.value.code is CopyOperationCode.INVALID_FACTORY
    assert copy_operation_lab.copy_ledgers.head == before[0]
    assert copy_operation_lab.operation_ledger.head == before[1]
    assert _copy_segment_bytes(copy_operation_lab) == before[2]
    assert not (
        copy_operation_lab.bootstrap.project
        / "tmp"
        / "jobs"
        / "INTERNAL"
        / context.job_id
    ).exists()
    assert not (
        copy_operation_lab.bootstrap.project / "Copy" / "source" / copy_id
    ).exists()


def test_existing_target_is_not_overwritten_and_source_only_fact_cannot_be_claimed(
    copy_operation_lab: _CopyOperationLab,
) -> None:
    payload = b"no replace copy payload"
    source = copy_operation_lab.source("target-conflict.bin", payload)
    operation, _context, _manifest, copy_id = copy_operation_lab.copy_operation(payload)
    target = copy_operation_lab.bootstrap.project / "Copy" / "source" / copy_id
    target.mkdir()
    sentinel = target / "sentinel.bin"
    sentinel.write_bytes(b"existing immutable object")

    with pytest.raises(CopyOperationError):
        operation.execute(source.name)

    assert sentinel.read_bytes() == b"existing immutable object"
    assert not (target / "payload.bin").exists()
    assert not (target / COPY_PROVENANCE_FILE_NAME).exists()
    assert copy_operation_lab.copy_ledgers._copy_histories == {}
    assert copy_operation_lab.copy_ledgers.head.pending_source_count == 1

    reopened = _reopen(copy_operation_lab)
    before_recovery = _copy_segment_bytes(reopened)
    recovery, _context, _manifest, _copy_id = reopened.copy_operation(payload)
    with pytest.raises(CopyOperationError) as raised:
        recovery.reconcile(source.name)

    assert raised.value.code is CopyOperationCode.RECOVERY_CONTRADICTION
    assert _copy_segment_bytes(reopened) == before_recovery
    assert reopened.copy_ledgers._copy_histories == {}
    with pytest.raises(CopyLedgerError) as sealed:
        _ = reopened.copy_ledgers.head
    assert sealed.value.code is CopyLedgerCode.LEDGER_SEALED
    assert sentinel.read_bytes() == b"existing immutable object"
    assert reopened.bundle.writer._poisoned is not None


def test_final_source_change_after_publish_is_durable_indoubt_without_cleanup(
    copy_operation_lab: _CopyOperationLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b"source stability payload"
    source = copy_operation_lab.source("source-change.bin", payload)
    operation, _context, _manifest, copy_id = copy_operation_lab.copy_operation(payload)
    target = copy_operation_lab.bootstrap.project / "Copy" / "source" / copy_id

    def reject_changed(
        _lease: _SyntheticReferenceLease,
        _evidence: object,
    ) -> object:
        assert (target / "payload.bin").read_bytes() == payload
        assert (target / COPY_PROVENANCE_FILE_NAME).read_bytes()
        raise ExternalSourceError(
            ExternalSourceCode.SOURCE_CHANGED,
            "synthetic source changed at the final stability gate",
        )

    monkeypatch.setattr(_SyntheticReferenceLease, "verify_unchanged", reject_changed)
    with pytest.raises(CopyOperationError) as raised:
        operation.execute(source.name)

    assert raised.value.code is CopyOperationCode.SOURCE_FAILED
    assert (target / "payload.bin").read_bytes() == payload
    assert (target / COPY_PROVENANCE_FILE_NAME).read_bytes()
    history = next(iter(copy_operation_lab.copy_ledgers._copy_histories.values()))
    assert history[-1].previous_state is CopyState.PREPARED
    assert history[-1].next_state is CopyState.IN_DOUBT
    assert source.read_bytes() == payload
    assert copy_operation_lab.bundle.writer._poisoned is not None


def test_source_stability_gate_follows_two_target_scans_and_precedes_mutated_fact(
    copy_operation_lab: _CopyOperationLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b"ordered source and target evidence"
    source = copy_operation_lab.source("ordered-evidence.bin", payload)
    operation, _context, _manifest, _copy_id = copy_operation_lab.copy_operation(payload)
    events: list[str] = []
    original_read_target = _TestLocalCopyOperation._read_target
    original_verify = _SyntheticReferenceLease.verify_unchanged
    original_append = DurableCopyLedgers._append_transition_under_existing_mutex

    def record_scan(
        self: _TestLocalCopyOperation,
        target: Path,
        provenance: object,
    ):
        events.append("target_scan")
        return original_read_target(self, target, provenance)

    def record_verify(self: _SyntheticReferenceLease, evidence: object):
        assert events == ["target_scan", "target_scan"]
        events.append("source_verify")
        return original_verify(self, evidence)

    def record_append(self: DurableCopyLedgers, lease: object, transition: object):
        if transition.next_state is CopyState.MUTATED:
            assert events == ["target_scan", "target_scan", "source_verify"]
            events.append("mutated_fact")
        return original_append(self, lease, transition)

    monkeypatch.setattr(_TestLocalCopyOperation, "_read_target", record_scan)
    monkeypatch.setattr(_SyntheticReferenceLease, "verify_unchanged", record_verify)
    monkeypatch.setattr(
        DurableCopyLedgers,
        "_append_transition_under_existing_mutex",
        record_append,
    )

    receipt = operation.execute(source.name)

    assert receipt.replayed is False
    assert events == [
        "target_scan",
        "target_scan",
        "source_verify",
        "mutated_fact",
    ]


def test_fresh_reconcile_prepared_without_publish_recovers_abort_once(
    copy_operation_lab: _CopyOperationLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b"prepared recovery abort payload"
    source = copy_operation_lab.source("prepared-recovery.bin", payload)
    operation, _context, _manifest, copy_id = copy_operation_lab.copy_operation(payload)
    original_append = DurableCopyLedgers._append_transition_under_existing_mutex
    injected = False

    def fail_after_prepared(
        self: DurableCopyLedgers,
        lease: object,
        transition: object,
    ):
        nonlocal injected
        receipt = original_append(self, lease, transition)
        if transition.next_state is CopyState.PREPARED and not injected:
            injected = True
            raise CopyOperationError(
                CopyOperationCode.STAGING_FAILED,
                "injected crash after durable Copy PREPARED",
            )
        return receipt

    monkeypatch.setattr(
        DurableCopyLedgers,
        "_append_transition_under_existing_mutex",
        fail_after_prepared,
    )
    with pytest.raises(CopyOperationError):
        operation.execute(source.name)

    target = copy_operation_lab.bootstrap.project / "Copy" / "source" / copy_id
    assert not target.exists()
    history = next(iter(copy_operation_lab.copy_ledgers._copy_histories.values()))
    assert [item.next_state for item in history] == [CopyState.PREPARED]

    reopened = _reopen(copy_operation_lab)
    before_copy = reopened.copy_ledgers.head.copy.segment_count
    before_publish = reopened.operation_ledger.head.segment_count
    recovery, _context, _manifest, _copy_id = reopened.copy_operation(payload)
    assert recovery.reconcile(source.name) is None
    assert reopened.copy_ledgers.head.copy.segment_count == before_copy + 1
    assert reopened.operation_ledger.head.segment_count == before_publish
    recovered_history = next(iter(reopened.copy_ledgers._copy_histories.values()))
    assert recovered_history[-1].next_state is CopyState.RECOVERED_ABORT
    assert not target.exists()

    replayed = _reopen(reopened)
    replay_count = replayed.copy_ledgers.head.copy.segment_count
    replay, _context, _manifest, _copy_id = replayed.copy_operation(payload)
    assert replay.reconcile(source.name) is None
    assert replayed.copy_ledgers.head.copy.segment_count == replay_count


def test_cross_thread_fresh_reconcile_source_record_without_prepared_recovers_abort_once(
    copy_operation_lab: _CopyOperationLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b"source-only recovery abort payload"
    source = copy_operation_lab.source("source-only-recovery.bin", payload)
    operation, _context, _manifest, copy_id = copy_operation_lab.copy_operation(payload)
    original_append = DurableCopyLedgers._append_transition_under_existing_mutex

    def crash_before_prepared(
        self: DurableCopyLedgers,
        lease: object,
        transition: object,
    ):
        if transition.next_state is CopyState.PREPARED:
            raise CopyOperationError(
                CopyOperationCode.STAGING_FAILED,
                "injected crash after source record and before Copy PREPARED",
            )
        return original_append(self, lease, transition)

    monkeypatch.setattr(
        DurableCopyLedgers,
        "_append_transition_under_existing_mutex",
        crash_before_prepared,
    )
    before_copy = copy_operation_lab.copy_ledgers.head.copy.segment_count
    before_source = copy_operation_lab.copy_ledgers.head.source.segment_count
    with pytest.raises(CopyOperationError):
        operation.execute(source.name)
    monkeypatch.setattr(
        DurableCopyLedgers,
        "_append_transition_under_existing_mutex",
        original_append,
    )

    assert copy_operation_lab.copy_ledgers.head.source.segment_count == before_source + 1
    assert copy_operation_lab.copy_ledgers.head.copy.segment_count == before_copy
    assert copy_operation_lab.copy_ledgers.head.pending_source_count == 1
    assert copy_operation_lab.copy_ledgers._copy_histories == {}
    target = copy_operation_lab.bootstrap.project / "Copy" / "source" / copy_id
    assert not target.exists()

    def recover_in_fresh_thread() -> tuple[object, tuple[CopyState, ...], int, str, str]:
        reopened = _reopen(copy_operation_lab)
        recovery, _context, _manifest, _copy_id = reopened.copy_operation(payload)
        result = recovery.reconcile(source.name)
        history = next(iter(reopened.copy_ledgers._copy_histories.values()))
        return (
            result,
            tuple(item.next_state for item in history),
            reopened.copy_ledgers.head.pending_source_count,
            recovery._state,
            recovery._source_policy._state,
        )

    result, states, pending, operation_state, policy_state = _run_in_fresh_thread(
        recover_in_fresh_thread
    )
    assert result is None
    assert states == (CopyState.RECOVERED_ABORT,)
    assert pending == 0
    assert operation_state == "CLOSED"
    assert policy_state == "CLOSED"

    replayed = _reopen(copy_operation_lab)
    replay_count = replayed.copy_ledgers.head.copy.segment_count
    checks = {
        "operation_result": 0,
        "target_absent_twice": 0,
        "source_checkpoint": 0,
        "source_final_verify": 0,
        "ancestors": 0,
    }
    original_operation_result = (
        DurableOperationLedger.operation_result_under_existing_mutex
    )
    original_target_absent = _TestLocalCopyOperation._require_target_absent_twice
    original_checkpoint_unchanged = _SyntheticReferenceLease._checkpoint_unchanged
    original_verify_unchanged = _SyntheticReferenceLease.verify_unchanged
    original_verify_ancestors = _TestLocalCopyOperation._verify_all_ancestors

    def record_operation_result(
        self: DurableOperationLedger,
        lease: object,
        operation_id: str,
    ):
        checks["operation_result"] += 1
        return original_operation_result(self, lease, operation_id)

    def record_target_absent(
        self: _TestLocalCopyOperation,
        mutex: object,
        observed_target: Path,
    ) -> None:
        checks["target_absent_twice"] += 1
        original_target_absent(self, mutex, observed_target)

    def record_source_checkpoint(
        self: _SyntheticReferenceLease,
        evidence: object,
    ):
        checks["source_checkpoint"] += 1
        return original_checkpoint_unchanged(self, evidence)

    def record_source_final_verify(
        self: _SyntheticReferenceLease,
        evidence: object,
    ):
        checks["source_final_verify"] += 1
        return original_verify_unchanged(self, evidence)

    def record_ancestors(
        self: _TestLocalCopyOperation,
        mutex: object,
    ) -> None:
        checks["ancestors"] += 1
        original_verify_ancestors(self, mutex)

    monkeypatch.setattr(
        DurableOperationLedger,
        "operation_result_under_existing_mutex",
        record_operation_result,
    )
    monkeypatch.setattr(
        _TestLocalCopyOperation,
        "_require_target_absent_twice",
        record_target_absent,
    )
    monkeypatch.setattr(
        _SyntheticReferenceLease,
        "_checkpoint_unchanged",
        record_source_checkpoint,
    )
    monkeypatch.setattr(
        _SyntheticReferenceLease,
        "verify_unchanged",
        record_source_final_verify,
    )
    monkeypatch.setattr(
        _TestLocalCopyOperation,
        "_verify_all_ancestors",
        record_ancestors,
    )
    replay, _context, _manifest, _copy_id = replayed.copy_operation(payload)
    assert replay.reconcile(source.name) is None
    assert replayed.copy_ledgers.head.copy.segment_count == replay_count
    assert checks["operation_result"] == 1
    assert checks["target_absent_twice"] == 3
    assert checks["source_checkpoint"] == 1
    assert checks["source_final_verify"] == 1
    assert checks["ancestors"] >= 1


def test_source_only_reconcile_target_presence_seals_without_recovery_append(
    copy_operation_lab: _CopyOperationLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b"source-only contradiction payload"
    source = copy_operation_lab.source("source-only-contradiction.bin", payload)
    operation, _context, _manifest, copy_id = copy_operation_lab.copy_operation(payload)
    original_append = DurableCopyLedgers._append_transition_under_existing_mutex

    def crash_before_prepared(
        self: DurableCopyLedgers,
        lease: object,
        transition: object,
    ):
        if transition.next_state is CopyState.PREPARED:
            raise CopyOperationError(
                CopyOperationCode.STAGING_FAILED,
                "injected source-only crash",
            )
        return original_append(self, lease, transition)

    monkeypatch.setattr(
        DurableCopyLedgers,
        "_append_transition_under_existing_mutex",
        crash_before_prepared,
    )
    with pytest.raises(CopyOperationError):
        operation.execute(source.name)

    target = copy_operation_lab.bootstrap.project / "Copy" / "source" / copy_id
    target.mkdir()
    (target / "payload.bin").write_bytes(b"unowned target")
    reopened = _reopen(copy_operation_lab)
    recovery, _context, _manifest, _copy_id = reopened.copy_operation(payload)
    before_copy = _copy_segment_bytes(reopened)

    with pytest.raises(CopyOperationError) as raised:
        recovery.reconcile(source.name)

    assert raised.value.code is CopyOperationCode.RECOVERY_CONTRADICTION
    assert _copy_segment_bytes(reopened) == before_copy
    assert reopened.bundle.writer._poisoned is not None


def test_failed_mutated_append_uses_last_persisted_prepared_state_for_indoubt(
    copy_operation_lab: _CopyOperationLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b"append fault after native publish"
    source = copy_operation_lab.source("append-fault.bin", payload)
    operation, _context, _manifest, copy_id = copy_operation_lab.copy_operation(payload)
    original_append = DurableCopyLedgers._append_transition_under_existing_mutex
    attempted_states: list[CopyState] = []
    injected = False

    def fail_first_mutated(
        self: DurableCopyLedgers,
        lease: object,
        transition: object,
    ):
        nonlocal injected
        attempted_states.append(transition.next_state)
        if transition.next_state is CopyState.MUTATED and not injected:
            injected = True
            raise CopyLedgerError(
                CopyLedgerCode.STORAGE_FAILURE,
                "injected transition append failure",
            )
        return original_append(self, lease, transition)

    monkeypatch.setattr(
        DurableCopyLedgers,
        "_append_transition_under_existing_mutex",
        fail_first_mutated,
    )

    with pytest.raises(CopyOperationError) as initial_failure:
        operation.execute(source.name)

    assert initial_failure.value.code is CopyOperationCode.LEDGER_MISMATCH
    assert copy_operation_lab.bundle.writer._poisoned is not None

    assert attempted_states == [
        CopyState.PREPARED,
        CopyState.MUTATED,
        CopyState.IN_DOUBT,
    ]
    history = next(iter(copy_operation_lab.copy_ledgers._copy_histories.values()))
    assert [item.next_state for item in history] == [
        CopyState.PREPARED,
        CopyState.IN_DOUBT,
    ]
    assert history[-1].previous_state is CopyState.PREPARED
    assert (
        copy_operation_lab.bootstrap.project
        / "Copy"
        / "source"
        / copy_id
        / "payload.bin"
    ).read_bytes() == payload
    assert (
        copy_operation_lab.bootstrap.project
        / "Copy"
        / "source"
        / copy_id
        / COPY_PROVENANCE_FILE_NAME
    ).read_bytes()

    target = (
        copy_operation_lab.bootstrap.project
        / "Copy"
        / "source"
        / copy_id
    )
    target_before = (
        target.stat().st_ino,
        (target / "payload.bin").stat().st_ino,
        (target / "payload.bin").read_bytes(),
        (target / COPY_PROVENANCE_FILE_NAME).stat().st_ino,
        (target / COPY_PROVENANCE_FILE_NAME).read_bytes(),
    )
    reopened = _reopen(copy_operation_lab)
    copy_count = reopened.copy_ledgers.head.copy.segment_count
    publish_count = reopened.operation_ledger.head.segment_count
    recovery, _context, _manifest, _copy_id = reopened.copy_operation(payload)
    recovered = recovery.reconcile(source.name)

    assert type(recovered) is CopyOperationReceipt
    assert recovered.replayed is False
    assert reopened.copy_ledgers.head.copy.segment_count == copy_count + 1
    assert reopened.operation_ledger.head.segment_count == publish_count
    assert next(iter(reopened.copy_ledgers._copy_histories.values()))[-1].next_state is (
        CopyState.RECOVERED_COMMIT
    )
    assert (
        target.stat().st_ino,
        (target / "payload.bin").stat().st_ino,
        (target / "payload.bin").read_bytes(),
        (target / COPY_PROVENANCE_FILE_NAME).stat().st_ino,
        (target / COPY_PROVENANCE_FILE_NAME).read_bytes(),
    ) == target_before

    replayed = _reopen(reopened)
    replay_count = replayed.copy_ledgers.head.copy.segment_count
    replay_publish_count = replayed.operation_ledger.head.segment_count
    replay, _context, _manifest, _copy_id = replayed.copy_operation(payload)
    repeated = replay.reconcile(source.name)
    assert type(repeated) is CopyOperationReceipt
    assert repeated.replayed is True
    assert replayed.copy_ledgers.head.copy.segment_count == replay_count
    assert replayed.operation_ledger.head.segment_count == replay_publish_count
    assert (target / "payload.bin").read_bytes() == payload
    assert (target / COPY_PROVENANCE_FILE_NAME).read_bytes()


@pytest.mark.parametrize(
    "contradiction",
    ("source_changed", "target_mismatch", "ancestor_mismatch"),
)
def test_reconcile_contradiction_seals_without_appending_recovery_fact(
    copy_operation_lab: _CopyOperationLab,
    monkeypatch: pytest.MonkeyPatch,
    contradiction: str,
) -> None:
    payload = b"recovery contradiction payload"
    source = copy_operation_lab.source("recovery-contradiction.bin", payload)
    operation, _context, _manifest, copy_id = copy_operation_lab.copy_operation(payload)
    original_append = DurableCopyLedgers._append_transition_under_existing_mutex
    injected = False

    def fail_first_mutated(
        self: DurableCopyLedgers,
        lease: object,
        transition: object,
    ):
        nonlocal injected
        if transition.next_state is CopyState.MUTATED and not injected:
            injected = True
            raise CopyLedgerError(
                CopyLedgerCode.STORAGE_FAILURE,
                "injected transition append failure",
            )
        return original_append(self, lease, transition)

    monkeypatch.setattr(
        DurableCopyLedgers,
        "_append_transition_under_existing_mutex",
        fail_first_mutated,
    )
    with pytest.raises(CopyOperationError):
        operation.execute(source.name)

    target = (
        copy_operation_lab.bootstrap.project
        / "Copy"
        / "source"
        / copy_id
        / "payload.bin"
    )
    source_original: Path | None = None
    source_changed_residue: Path | None = None
    try:
        if contradiction == "source_changed":
            source_original = source.with_name(source.name + "-original")
            source_changed_residue = source.with_name(source.name + "-changed-residue")
            source.rename(source_original)
            source.write_bytes(b"changed external source")
        elif contradiction == "target_mismatch":
            target.write_bytes(b"changed target")

        reopened = _reopen(copy_operation_lab)
        recovery, _context, _manifest, _copy_id = reopened.copy_operation(payload)
        if contradiction == "ancestor_mismatch":

            def reject_ancestors(self, lease, audit_ledger, operation_ledger):
                raise CopyLedgerError(
                    CopyLedgerCode.CROSS_REFERENCE_INVALID,
                    "injected authenticated ancestor mismatch",
                )

            monkeypatch.setattr(
                DurableCopyLedgers,
                "_issue_authenticated_ancestors_under_existing_mutex",
                reject_ancestors,
            )

        before_copy = _copy_segment_bytes(reopened)
        before_publish = _operation_segment_bytes(reopened)
        with pytest.raises(CopyOperationError) as raised:
            recovery.reconcile(source.name)

        assert raised.value.code is CopyOperationCode.RECOVERY_CONTRADICTION
        assert _copy_segment_bytes(reopened) == before_copy
        assert _operation_segment_bytes(reopened) == before_publish
        assert reopened.bundle.writer._poisoned is not None
    finally:
        if source_original is not None and source_changed_residue is not None:
            if source.exists():
                source.rename(source_changed_residue)
            if source_original.exists():
                source_original.rename(source)


def test_cross_thread_fresh_reopen_revalidates_ancestry_and_replays_without_write(
    copy_operation_lab: _CopyOperationLab,
) -> None:
    payload = b"fresh reopen replay payload"
    source = copy_operation_lab.source("reopen-replay.bin", payload)
    operation, _context, _manifest, copy_id = copy_operation_lab.copy_operation(payload)
    first = operation.execute(source.name)
    source_count = copy_operation_lab.copy_ledgers.head.source.segment_count
    copy_count = copy_operation_lab.copy_ledgers.head.copy.segment_count
    operation_count = copy_operation_lab.operation_ledger.head.segment_count

    def replay_in_fresh_thread() -> tuple[
        CopyOperationReceipt,
        str,
        int,
        int,
        int,
        str,
        str,
    ]:
        reopened = _reopen(copy_operation_lab)
        replay_operation, _new_context, _new_manifest, replay_copy_id = (
            reopened.copy_operation(payload)
        )
        replay = replay_operation.execute(source.name)
        return (
            replay,
            replay_copy_id,
            reopened.copy_ledgers.head.source.segment_count,
            reopened.copy_ledgers.head.copy.segment_count,
            reopened.operation_ledger.head.segment_count,
            replay_operation._state,
            replay_operation._source_policy._state,
        )

    (
        replay,
        replay_copy_id,
        replay_source_count,
        replay_copy_count,
        replay_operation_count,
        operation_state,
        policy_state,
    ) = _run_in_fresh_thread(replay_in_fresh_thread)

    assert replay_copy_id == copy_id
    assert replay.replayed is True
    assert replay.transaction_binding_sha256 == first.transaction_binding_sha256
    assert replay.copy_binding_sha256 == first.copy_binding_sha256
    assert replay.source_record_segment_sha256 == first.source_record_segment_sha256
    assert replay.copy_terminal_segment_sha256 == first.copy_terminal_segment_sha256
    assert replay.publish_terminal_segment_sha256 == first.publish_terminal_segment_sha256
    assert replay_source_count == source_count
    assert replay_copy_count == copy_count
    assert replay_operation_count == operation_count
    assert operation_state == "CLOSED"
    assert policy_state == "CLOSED"
    assert (
        copy_operation_lab.bootstrap.project
        / "Copy"
        / "source"
        / copy_id
        / "payload.bin"
    ).read_bytes() == payload
    assert (
        copy_operation_lab.bootstrap.project
        / "Copy"
        / "source"
        / copy_id
        / COPY_PROVENANCE_FILE_NAME
    ).read_bytes()


@pytest.mark.parametrize("replacement_kind", ("root", "payload"))
def test_fresh_reconcile_rejects_same_byte_replacement_after_copy_commit(
    copy_operation_lab: _CopyOperationLab,
    replacement_kind: str,
) -> None:
    payload = b"same bytes must not replace committed copy identity"
    source = copy_operation_lab.source(
        f"committed-{replacement_kind}-replacement.bin",
        payload,
    )
    operation, _context, _manifest, copy_id = copy_operation_lab.copy_operation(payload)
    operation.execute(source.name)
    target = copy_operation_lab.bootstrap.project / "Copy" / "source" / copy_id
    _replace_target_with_same_bytes(target, payload, replacement_kind)

    reopened = _reopen(copy_operation_lab)
    recovery, _context, _manifest, _copy_id = reopened.copy_operation(payload)
    before_copy = _copy_segment_bytes(reopened)
    before_publish = _operation_segment_bytes(reopened)

    with pytest.raises(CopyOperationError) as raised:
        recovery.reconcile(source.name)

    assert raised.value.code is CopyOperationCode.RECOVERY_CONTRADICTION
    assert _copy_segment_bytes(reopened) == before_copy
    assert _operation_segment_bytes(reopened) == before_publish
    assert reopened.bundle.writer._poisoned is not None


@pytest.mark.parametrize("replacement_kind", ("root", "payload"))
def test_fresh_reconcile_rejects_same_byte_replacement_in_publish_commit_window(
    copy_operation_lab: _CopyOperationLab,
    monkeypatch: pytest.MonkeyPatch,
    replacement_kind: str,
) -> None:
    payload = b"publish committed identity must bind copy crash recovery"
    source = copy_operation_lab.source(
        f"publish-window-{replacement_kind}.bin",
        payload,
    )
    operation, _context, _manifest, copy_id = copy_operation_lab.copy_operation(payload)
    original_append = DurableCopyLedgers._append_transition_under_existing_mutex

    def reject_post_publish_copy_facts(
        self: DurableCopyLedgers,
        lease: object,
        transition: object,
    ):
        if transition.next_state in {CopyState.MUTATED, CopyState.IN_DOUBT}:
            raise CopyLedgerError(
                CopyLedgerCode.STORAGE_FAILURE,
                "injected crash window after authenticated publish commit",
            )
        return original_append(self, lease, transition)

    monkeypatch.setattr(
        DurableCopyLedgers,
        "_append_transition_under_existing_mutex",
        reject_post_publish_copy_facts,
    )
    with pytest.raises(CopyOperationError) as initial:
        operation.execute(source.name)
    assert initial.value.code is CopyOperationCode.INDETERMINATE
    history = next(iter(copy_operation_lab.copy_ledgers._copy_histories.values()))
    assert history[-1].next_state is CopyState.PREPARED
    monkeypatch.setattr(
        DurableCopyLedgers,
        "_append_transition_under_existing_mutex",
        original_append,
    )

    target = copy_operation_lab.bootstrap.project / "Copy" / "source" / copy_id
    _replace_target_with_same_bytes(target, payload, replacement_kind)
    reopened = _reopen(copy_operation_lab)
    recovery, _context, _manifest, _copy_id = reopened.copy_operation(payload)
    before_copy = _copy_segment_bytes(reopened)
    before_publish = _operation_segment_bytes(reopened)

    with pytest.raises(CopyOperationError) as raised:
        recovery.reconcile(source.name)

    assert raised.value.code is CopyOperationCode.RECOVERY_CONTRADICTION
    assert _copy_segment_bytes(reopened) == before_copy
    assert _operation_segment_bytes(reopened) == before_publish
    assert reopened.bundle.writer._poisoned is not None


def test_audit_rotation_keeps_old_copy_epoch_recoverable_but_blocks_new_copy_work(
    copy_operation_lab: _CopyOperationLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b"rotation source-only recovery payload"
    source = copy_operation_lab.source("rotation-source-only.bin", payload)
    operation, _context, _manifest, _copy_id = copy_operation_lab.copy_operation(payload)
    original_append = DurableCopyLedgers._append_transition_under_existing_mutex

    def crash_before_prepared(
        self: DurableCopyLedgers,
        lease: object,
        transition: object,
    ):
        if transition.next_state is CopyState.PREPARED:
            raise CopyOperationError(
                CopyOperationCode.STAGING_FAILED,
                "injected crash before PREPARED and audit rotation",
            )
        return original_append(self, lease, transition)

    monkeypatch.setattr(
        DurableCopyLedgers,
        "_append_transition_under_existing_mutex",
        crash_before_prepared,
    )
    with pytest.raises(CopyOperationError):
        operation.execute(source.name)
    assert copy_operation_lab.copy_ledgers.head.pending_source_count == 1

    copy_operation_lab.bundle.key_store.create_revision(
        revision_sequence=2,
        revision_id="KEYREV-S3F-COPY-TWO",
        master_key=b"R" * 32,
        created_at_utc="2026-07-13T02:00:00Z",
    )
    copy_operation_lab.bundle.ledger.rotate_key(
        next_revision_id="KEYREV-S3F-COPY-TWO",
        rotation_id="ROTATE-S3F-COPY-ONE-TO-TWO",
        created_at_utc="2026-07-13T02:00:01Z",
    )

    reopened = _reopen(copy_operation_lab)
    assert reopened.copy_ledgers.signing_revision_id == _KEY_ID
    assert reopened.operation_ledger.signing_revision_id == _KEY_ID
    recovery, _context, _manifest, _copy_id = reopened.copy_operation(payload)
    assert recovery.reconcile(source.name) is None
    terminal = next(iter(reopened.copy_ledgers._copy_histories.values()))[-1]
    assert terminal.next_state is CopyState.RECOVERED_ABORT
    assert terminal.recovery_authority_head_sha256 == reopened.bundle.ledger.head.last_segment_sha256

    next_payload = b"new work must use a new Copy and operation epoch"
    next_source = reopened.source("rotation-new-work.bin", next_payload)
    next_job = f"JOB-{reopened.tag}-ROTATED"
    next_operation_id = f"OP-{reopened.tag}-ROTATED"
    next_manifest_id = f"MANIFEST-{reopened.tag}-ROTATED"
    next_copy_id = f"COPY-{reopened.tag}-ROTATED"
    next_checkpoint = f"CHECKPOINT-{reopened.tag}-ROTATED"
    next_context = reopened.bundle.boundary.issue_context(
        run_id=reopened.run_scope_id,
        job_id=next_job,
        operation_id=next_operation_id,
        caller=Caller.IMPORT_SERVICE,
        purpose=Purpose.COPY_SOURCE,
        manifest_id=next_manifest_id,
        classification=DataClassification.INTERNAL,
        scopes=(
            ScopeId(ScopeKind.RUN_ID, reopened.run_scope_id),
            ScopeId(ScopeKind.COPY_LEDGER_EPOCH_ID, reopened.copy_epoch),
            ScopeId(ScopeKind.JOB_ID, next_job),
            ScopeId(ScopeKind.OPERATION_ID, next_operation_id),
            ScopeId(ScopeKind.MANIFEST_ID, next_manifest_id),
            ScopeId(ScopeKind.COPY_ID, next_copy_id),
            ScopeId(ScopeKind.CHECKPOINT_ID, next_checkpoint),
        ),
    )
    next_manifest = DeclaredTreeManifest(
        manifest_id=next_manifest_id,
        classification=DataClassification.INTERNAL,
        entries=(
            DeclaredTreeEntry(
                "payload.bin",
                TreeEntryKind.FILE,
                len(next_payload),
                _sha(next_payload),
            ),
        ),
    )
    next_copy = _create_test_copy_operation(
        reopened.bundle,
        reopened.operation_ledger,
        reopened.copy_ledgers,
        next_context,
        next_manifest,
        JobResourceBudget.conservative_test_default(),
    )
    before_rejected = reopened.copy_ledgers.head
    with pytest.raises(CopyOperationError):
        next_copy.execute(next_source.name)
    assert reopened.copy_ledgers.head == before_rejected
