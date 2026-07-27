from __future__ import annotations

import hashlib
import hmac
import json
import os
import shutil
import subprocess
import sys
import threading
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Iterator

import pytest

import app.safety.operation_ledger as operation_ledger_module

from app.safety.context import (
    Caller,
    DataClassification,
    Purpose,
    ScopeId,
    ScopeKind,
)
from app.safety.job_operation import (
    DeclaredTreeEntry,
    DeclaredTreeManifest,
    JobOperationCode,
    JobOperationError,
    JobResourceBudget,
    PublishOperationReceipt,
)
from app.safety.operation_ledger import (
    OperationCompletionKind,
    OperationLedgerCode,
    OperationLedgerError,
    OperationLocatorMode,
    OperationState,
)
from app.safety.segment_ledger import canonical_json_bytes
from app.safety.production_guard import (
    _create_test_durable_boundary,
    _create_test_job_runtime,
    _create_test_operation_ledger,
    _reconcile_test_publish_operation,
)
from app.safety.windows_handle_writer import (
    HandleWriterCode,
    HandleWriterError,
    TreeEntryKind,
    _WindowsHandleWriter,
)


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True)
class _PublishLab:
    project: Path
    protected: Path
    sentinel: Path
    bundle: object
    operation_ledger: object
    runtime: object


S3H_CRASH_RACE_TRUTH_TABLE = (
    (
        "COOPERATIVE_WRITER_MUTEX",
        "MUTEX_BUSY_NO_MUTATION",
        "tests/test_job_operation.py::test_two_process_mutex_busy_rolls_back_pin_and_same_context_retries",
    ),
    (
        "HOSTILE_TARGET_CREATED_PRE_RENAME",
        "ABORTED_NO_OVERWRITE",
        "tests/test_publish_operation.py::test_target_race_after_prepared_aborts_without_overwrite",
    ),
    (
        "HOSTILE_SOURCE_NAMESPACE_DRIFT_PRE_BOUNDARY",
        "REJECTED_NO_MUTATION",
        "tests/test_windows_handle_writer.py::test_publish_source_share_blocks_external_path_rename_before_publish",
    ),
    (
        "HOSTILE_NAMESPACE_DRIFT_AFTER_NATIVE_BOUNDARY",
        "IN_DOUBT_AND_WRITER_SEALED",
        "tests/test_windows_handle_writer.py::test_publish_after_rename_failure_keeps_valid_final_and_seals",
    ),
    (
        "PROCESS_CRASH_BEFORE_RENAME",
        "RECOVERED_ABORT_ONCE",
        "tests/test_publish_operation.py::test_real_process_publish_crash_points_reconcile_once[BEFORE_RENAME-71-2-RECOVERED_ABORT]",
    ),
    (
        "PROCESS_CRASH_AFTER_RENAME",
        "RECOVERED_COMMIT_ONCE",
        "tests/test_publish_operation.py::test_real_process_publish_crash_points_reconcile_once[AFTER_RENAME-72-2-RECOVERED_COMMIT]",
    ),
    (
        "PROCESS_CRASH_BEFORE_TERMINAL_APPEND",
        "RECOVERED_COMMIT_ONCE",
        "tests/test_publish_operation.py::test_real_process_publish_crash_points_reconcile_once[BEFORE_TERMINAL_APPEND-73-4-RECOVERED_COMMIT]",
    ),
    (
        "PROCESS_CRASH_AFTER_TERMINAL_APPEND",
        "COMMITTED_REPLAY_NO_GROWTH",
        "tests/test_publish_operation.py::test_real_process_publish_crash_points_reconcile_once[AFTER_TERMINAL_APPEND-74-5-COMMITTED]",
    ),
    (
        "HOSTILE_EXTERNAL_WRITER_FREEZE",
        "NOT_GUARANTEED_DETECT_AND_SEAL",
        "RECOVERY_GUARANTEE_SCOPE=COOPERATIVE_APPLICATION_WRITERS_ONLY",
    ),
)


@pytest.fixture
def publish_lab(tmp_path: Path) -> Iterator[_PublishLab]:
    project = tmp_path / "project"
    protected = tmp_path / "protected"
    project.mkdir()
    protected.mkdir()
    sentinel = protected / "sentinel.bin"
    sentinel.write_bytes(b"publish-operation-protected-sentinel")
    (project / "logs" / "audit" / "keys").mkdir(parents=True)
    (project / "logs" / "audit" / "segments" / "RUN-S3E-AUDIT").mkdir(
        parents=True
    )
    (
        project
        / "logs"
        / "operations"
        / "segments"
        / "RUN-S3E-OPERATIONS"
    ).mkdir(parents=True)
    (project / "tmp" / "jobs" / "INTERNAL").mkdir(parents=True)
    (project / "tmp" / "jobs" / "RESTRICTED").mkdir(parents=True)
    (project / "data" / "exports").mkdir(parents=True)
    (project / "Copy" / "source").mkdir(parents=True)
    (project / "Copy" / "restricted").mkdir(parents=True)
    bundle = _create_test_durable_boundary(
        project,
        initialize=True,
        epoch_id="RUN-S3E-AUDIT",
        initial_revision_sequence=1,
        initial_revision_id="KEYREV-S3E-ONE",
        master_key=b"E" * 32,
        key_created_at_utc="2026-07-11T16:00:00Z",
        ledger_initialized_at_utc="2026-07-11T16:00:01Z",
    )
    operation_ledger = _create_test_operation_ledger(
        bundle,
        epoch_id="RUN-S3E-OPERATIONS",
        initialize=True,
        initialized_at_utc="2026-07-11T16:00:02Z",
    )
    yield _PublishLab(
        project=project,
        protected=protected,
        sentinel=sentinel,
        bundle=bundle,
        operation_ledger=operation_ledger,
        runtime=_create_test_job_runtime(
            bundle,
            operation_ledger=operation_ledger,
        ),
    )
    assert sentinel.read_bytes() == b"publish-operation-protected-sentinel"
    assert {path.name for path in protected.iterdir()} == {"sentinel.bin"}


def _manifest(
    manifest_id: str = "MANIFEST-S3E-ONE",
    payload: bytes = b"published-content",
    classification: DataClassification = DataClassification.INTERNAL,
) -> DeclaredTreeManifest:
    return DeclaredTreeManifest(
        manifest_id=manifest_id,
        classification=classification,
        entries=(
            DeclaredTreeEntry(
                "document.txt",
                TreeEntryKind.FILE,
                len(payload),
                _sha(payload),
            ),
        ),
    )


def _context(
    lab: _PublishLab,
    *,
    export_id: str = "EXPORT-S3E-ONE",
    operation_id: str = "OP-S3E-ONE",
    manifest_id: str = "MANIFEST-S3E-ONE",
):
    run_id = "RUN-S3E-PUBLISH"
    job_id = "JOB-S3E-PUBLISH"
    checkpoint_id = "CHECKPOINT-S3E-PUBLISH"
    return lab.bundle.boundary.issue_context(
        run_id=run_id,
        job_id=job_id,
        operation_id=operation_id,
        caller=Caller.EXPORT_SERVICE,
        purpose=Purpose.BUILD_EXPORT,
        manifest_id=manifest_id,
        scopes=(
            ScopeId(ScopeKind.RUN_ID, run_id),
            ScopeId(ScopeKind.JOB_ID, job_id),
            ScopeId(ScopeKind.OPERATION_ID, operation_id),
            ScopeId(ScopeKind.MANIFEST_ID, manifest_id),
            ScopeId(ScopeKind.CHECKPOINT_ID, checkpoint_id),
            ScopeId(ScopeKind.EXPORT_ID, export_id),
        ),
    )


def _prepare_publish(
    lab: _PublishLab,
    *,
    export_id: str = "EXPORT-S3E-ONE",
    operation_id: str = "OP-S3E-ONE",
):
    payload = b"published-content"
    manifest = _manifest()
    context = _context(
        lab,
        export_id=export_id,
        operation_id=operation_id,
    )
    operation = lab.runtime.begin_operation(
        context,
        manifest,
        JobResourceBudget.conservative_test_default(),
    )
    staging = operation.create_fixed_staging()
    staging.create_declared_file("document.txt", payload)
    observed = staging.seal_and_observe()
    token = operation.authorize_publish(
        observed,
        Path("data") / "exports" / export_id,
        checkpoint_manifest_sha256=_sha(b"checkpoint-manifest"),
    )
    return operation, observed, token, payload


def _run_real_publish_crash_child(
    lab: _PublishLab,
    *,
    crash_point: str,
    expected_exit_code: int,
    export_id: str,
    operation_id: str,
) -> subprocess.CompletedProcess[bytes]:
    child_code = r'''
import json
import os
import sys
from pathlib import Path

from app.safety.operation_ledger import DurableOperationLedger
from app.safety.production_guard import (
    _create_test_durable_boundary,
    _create_test_job_runtime,
    _create_test_operation_ledger,
)
from app.safety.windows_handle_writer import _WindowsHandleWriter
from tests.test_publish_operation import _PublishLab, _prepare_publish

project = Path(sys.argv[1])
crash_point = sys.argv[2]
expected_exit_code = int(sys.argv[3])
export_id = sys.argv[4]
operation_id = sys.argv[5]
bundle = _create_test_durable_boundary(
    project,
    initialize=False,
    epoch_id="RUN-S3E-AUDIT",
    initial_revision_sequence=1,
    initial_revision_id="KEYREV-S3E-ONE",
    master_key=b"E" * 32,
    key_created_at_utc="2026-07-11T16:00:00Z",
)
operation_ledger = _create_test_operation_ledger(
    bundle,
    epoch_id="RUN-S3E-OPERATIONS",
    initialize=False,
)
lab = _PublishLab(
    project=project,
    protected=project.parent / "protected",
    sentinel=project.parent / "protected" / "sentinel.bin",
    bundle=bundle,
    operation_ledger=operation_ledger,
    runtime=_create_test_job_runtime(
        bundle,
        operation_ledger=operation_ledger,
    ),
)
operation, observed, token, _payload = _prepare_publish(
    lab,
    export_id=export_id,
    operation_id=operation_id,
)

if crash_point in {"BEFORE_RENAME", "AFTER_RENAME"}:
    hook_name = (
        "_after_directory_publish_prepared"
        if crash_point == "BEFORE_RENAME"
        else "_after_directory_publish_renamed"
    )

    def crash_at_rename_boundary(
        _writer: object,
        _source: object,
        _target: object,
    ) -> None:
        os._exit(expected_exit_code)

    setattr(_WindowsHandleWriter, hook_name, crash_at_rename_boundary)
else:
    original_publish_segment = DurableOperationLedger._publish_segment

    def crash_at_terminal_append(
        self: DurableOperationLedger,
        sequence: int,
        segment_sha256: str,
        payload: bytes,
    ) -> None:
        value = json.loads(payload.decode("ascii", "strict"))
        transition = value.get("transition")
        is_committed = (
            type(transition) is dict
            and transition.get("next_state") == "COMMITTED"
        )
        if is_committed and crash_point == "BEFORE_TERMINAL_APPEND":
            os._exit(expected_exit_code)
        original_publish_segment(self, sequence, segment_sha256, payload)
        if is_committed and crash_point == "AFTER_TERMINAL_APPEND":
            os._exit(expected_exit_code)

    DurableOperationLedger._publish_segment = crash_at_terminal_append

operation.execute_publish_pair(token, observed)
raise AssertionError("configured real crash point did not terminate the child")
'''
    return subprocess.run(
        [
            sys.executable,
            "-B",
            "-c",
            child_code,
            str(lab.project),
            crash_point,
            str(expected_exit_code),
            export_id,
            operation_id,
        ],
        cwd=Path(__file__).parent.parent,
        env=os.environ.copy(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        check=False,
        timeout=40,
    )


def _restricted_copy_context(lab: _PublishLab):
    run_id = "RUN-S3F-RESTRICTED"
    job_id = "JOB-S3F-OPAQUE"
    operation_id = "OP-S3F-OPAQUE"
    manifest_id = "MANIFEST-S3F-OPAQUE"
    copy_id = "COPY-S3F-OPAQUE"
    checkpoint_id = "CHECKPOINT-S3F-OPAQUE"
    return lab.bundle.boundary.issue_context(
        run_id=run_id,
        job_id=job_id,
        operation_id=operation_id,
        caller=Caller.IMPORT_SERVICE,
        purpose=Purpose.COPY_SOURCE,
        manifest_id=manifest_id,
        classification=DataClassification.RESTRICTED,
        scopes=(
            ScopeId(ScopeKind.RUN_ID, run_id),
            ScopeId(ScopeKind.JOB_ID, job_id),
            ScopeId(ScopeKind.OPERATION_ID, operation_id),
            ScopeId(ScopeKind.MANIFEST_ID, manifest_id),
            ScopeId(ScopeKind.COPY_ID, copy_id),
            ScopeId(ScopeKind.CHECKPOINT_ID, checkpoint_id),
        ),
    )


def _reopen_publish_lab(lab: _PublishLab) -> _PublishLab:
    bundle = _create_test_durable_boundary(
        lab.project,
        initialize=False,
        epoch_id="RUN-S3E-AUDIT",
        initial_revision_sequence=1,
        initial_revision_id="KEYREV-S3E-ONE",
        master_key=b"E" * 32,
        key_created_at_utc="2026-07-11T16:00:00Z",
    )
    operation_ledger = _create_test_operation_ledger(
        bundle,
        epoch_id="RUN-S3E-OPERATIONS",
        initialize=False,
    )
    return _PublishLab(
        project=lab.project,
        protected=lab.protected,
        sentinel=lab.sentinel,
        bundle=bundle,
        operation_ledger=operation_ledger,
        runtime=_create_test_job_runtime(bundle, operation_ledger=operation_ledger),
    )


def _operation_segment_files(lab: _PublishLab) -> list[Path]:
    return sorted(
        (
            lab.project
            / "logs"
            / "operations"
            / "segments"
            / "RUN-S3E-OPERATIONS"
        ).glob("[0-9]*.json")
    )


def _resign_operation_segment(lab: _PublishLab, path: Path, value: dict) -> Path:
    transition = value["transition"]
    value["transition_sha256"] = (
        None
        if transition is None
        else hashlib.sha256(
            b"OPERATION-TRANSITION-V1\0" + canonical_json_bytes(transition)
        ).hexdigest()
    )
    body = dict(value)
    body.pop("segment_hmac_sha256")
    body.pop("segment_sha256")
    body_bytes = canonical_json_bytes(body)
    segment_sha256 = hashlib.sha256(
        b"OPERATION-SEGMENT-V1\0" + body_bytes
    ).hexdigest()
    value["segment_hmac_sha256"] = hmac.new(
        lab.operation_ledger._operation_key,
        b"OPERATION-SEGMENT-V1\0" + body_bytes,
        hashlib.sha256,
    ).hexdigest()
    value["segment_sha256"] = segment_sha256
    replacement = path.with_name(
        f"{value['sequence']:020d}-{segment_sha256}.json"
    )
    path.rename(replacement)
    replacement.write_bytes(canonical_json_bytes(value))
    return replacement


def _leave_prepared_operation_unresolved(
    lab: _PublishLab,
    *,
    export_id: str,
    operation_id: str,
) -> tuple[_PublishLab, str, Path, Path]:
    operation, observed, token, _payload = _prepare_publish(
        lab,
        export_id=export_id,
        operation_id=operation_id,
    )
    original = _WindowsHandleWriter._after_directory_publish_prepared

    def fail_before_rename(
        _writer: _WindowsHandleWriter,
        _source: object,
        _target: object,
    ) -> None:
        raise HandleWriterError(
            HandleWriterCode.RENAME_FAILED,
            "synthetic unresolved PREPARED operation",
        )

    _WindowsHandleWriter._after_directory_publish_prepared = fail_before_rename
    try:
        with pytest.raises(JobOperationError):
            operation.execute_publish_pair(token, observed)
    finally:
        _WindowsHandleWriter._after_directory_publish_prepared = original
        with pytest.raises(HandleWriterError):
            operation.close()
    reopened = _reopen_publish_lab(lab)
    transaction_id = reopened.operation_ledger.head.unresolved_transaction_ids[0]
    source = (
        lab.project
        / "tmp"
        / "jobs"
        / "INTERNAL"
        / "JOB-S3E-PUBLISH"
        / "publish"
        / "MANIFEST-S3E-ONE"
    )
    target = lab.project / "data" / "exports" / export_id
    return reopened, transaction_id, source, target


def test_handle_bound_directory_publish_commits_exact_target(
    publish_lab: _PublishLab,
) -> None:
    operation, observed, token, payload = _prepare_publish(publish_lab)
    source = (
        publish_lab.project
        / "tmp"
        / "jobs"
        / "INTERNAL"
        / "JOB-S3E-PUBLISH"
        / "publish"
        / "MANIFEST-S3E-ONE"
    )
    target = publish_lab.project / "data" / "exports" / "EXPORT-S3E-ONE"
    with operation:
        receipt = operation.execute_publish_pair(token, observed)
        assert type(receipt) is PublishOperationReceipt
        assert receipt.completion_kind is OperationCompletionKind.NATIVE_COMMIT
        assert receipt.native_directory_receipt_sha256 is not None
        assert receipt.recovery_observation_receipt_sha256 is None
        assert receipt.committed_sequence == 4
        assert not source.exists()
        assert target.is_dir()
        assert (target / "document.txt").read_bytes() == payload
        independent = publish_lab.bundle.writer.read_flat_directory(
            Path("data") / "exports" / "EXPORT-S3E-ONE",
            maximum_entries=4,
            maximum_file_bytes=1024,
            maximum_total_bytes=1024,
        )
        assert len(independent.entries) == 1
        assert independent.entries[0].payload == payload
        assert (
            publish_lab.operation_ledger.durable_tree_identity_digest(
                independent.tree_identity_material
            )
            == receipt.target_identity_hmac_sha256
        )
        assert publish_lab.operation_ledger.head.unresolved_transaction_ids == ()
        assert operation._state == "PUBLISH_COMMITTED"
        history = next(iter(publish_lab.operation_ledger._transaction_history.values()))
        assert (
            history[0].audit_ledger_head_sha256
            == publish_lab.bundle.ledger.head.last_segment_sha256
        )
    assert publish_lab.bundle.boundary.diagnostic_registry_counts["pair_live"] == 0
    assert (
        publish_lab.bundle.boundary.diagnostic_registry_counts[
            "pair_consumed_tombstones"
        ]
        == 1
    )


def test_restricted_copy_publish_uses_hmac_only_operation_locators(
    publish_lab: _PublishLab,
) -> None:
    payload = b"restricted-copy-payload"
    context = _restricted_copy_context(publish_lab)
    manifest = _manifest(
        "MANIFEST-S3F-OPAQUE",
        payload,
        DataClassification.RESTRICTED,
    )
    budget = JobResourceBudget.conservative_test_default()
    operation = publish_lab.runtime.begin_operation(context, manifest, budget)
    staging = operation.create_fixed_staging()
    staging.create_declared_file("document.txt", payload)
    observed = staging.seal_and_observe()
    token = operation.authorize_publish(
        observed,
        Path("Copy") / "restricted" / "COPY-S3F-OPAQUE",
        checkpoint_manifest_sha256=_sha(b"restricted-copy-checkpoint"),
    )
    with operation:
        receipt = operation.execute_publish_pair(token, observed)
    assert (
        publish_lab.project
        / "Copy"
        / "restricted"
        / "COPY-S3F-OPAQUE"
        / "document.txt"
    ).read_bytes() == payload
    transition = next(
        history[-1]
        for history in publish_lab.operation_ledger._transaction_history.values()
        if history[-1].classification is DataClassification.RESTRICTED
    )
    assert transition.locator_mode is OperationLocatorMode.HMAC_ONLY
    assert len(transition.source_locator) == 64
    assert len(transition.target_locator) == 64
    assert "COPY-S3F-OPAQUE" not in transition.source_locator
    assert "COPY-S3F-OPAQUE" not in transition.target_locator
    assert transition.operation_id != context.operation_id
    assert receipt.locator_mode is OperationLocatorMode.HMAC_ONLY
    assert receipt.classification is DataClassification.RESTRICTED
    assert receipt.target_locator == transition.target_locator
    assert "COPY-S3F-OPAQUE" not in receipt.target_locator
    assert "COPY-S3F-OPAQUE" not in repr(receipt)
    replay_context = _restricted_copy_context(publish_lab)
    replay = publish_lab.runtime.replay_committed_publish(
        replay_context,
        manifest,
        budget,
    )
    assert replay == receipt


def test_target_race_after_prepared_aborts_without_overwrite(
    publish_lab: _PublishLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    operation, observed, token, _payload = _prepare_publish(
        publish_lab,
        export_id="EXPORT-S3E-RACE",
        operation_id="OP-S3E-RACE",
    )
    target = publish_lab.project / "data" / "exports" / "EXPORT-S3E-RACE"

    def create_conflict(
        _writer: _WindowsHandleWriter,
        _source: object,
        _target: object,
    ) -> None:
        target.mkdir()
        (target / "sentinel.txt").write_bytes(b"do-not-overwrite")

    monkeypatch.setattr(
        _WindowsHandleWriter,
        "_after_directory_publish_prepared",
        create_conflict,
    )
    with operation:
        with pytest.raises(JobOperationError) as captured:
            operation.execute_publish_pair(token, observed)
        assert captured.value.code is JobOperationCode.PUBLISH_FAILED
        assert (target / "sentinel.txt").read_bytes() == b"do-not-overwrite"
        assert publish_lab.operation_ledger.head.unresolved_transaction_ids == ()
    assert (
        publish_lab.bundle.boundary.diagnostic_registry_counts[
            "pair_failed_tombstones"
        ]
        == 1
    )


def test_operation_ledger_unknown_pending_entry_seals_on_reopen(
    publish_lab: _PublishLab,
) -> None:
    pending = (
        publish_lab.project
        / "logs"
        / "operations"
        / "segments"
        / "RUN-S3E-OPERATIONS"
        / "PENDING-UNTRUSTED.json"
    )
    pending.write_bytes(b"{}\n")
    with pytest.raises(OperationLedgerError) as captured:
        _create_test_operation_ledger(
            publish_lab.bundle,
            epoch_id="RUN-S3E-OPERATIONS",
            initialize=False,
        )
    assert captured.value.code is OperationLedgerCode.UNKNOWN_ENTRY


def test_operation_ledger_runtime_rescan_seals_on_unknown_pending_entry(
    publish_lab: _PublishLab,
) -> None:
    pending = (
        publish_lab.project
        / "logs"
        / "operations"
        / "segments"
        / "RUN-S3E-OPERATIONS"
        / "PENDING-RUNTIME-UNTRUSTED.json"
    )
    pending.write_bytes(b"{}\n")
    with publish_lab.bundle.writer.acquire_runtime_mutex() as lease:
        with pytest.raises(OperationLedgerError) as captured:
            publish_lab.operation_ledger._rescan_under_existing_mutex(lease)
    assert captured.value.code is OperationLedgerCode.UNKNOWN_ENTRY
    with pytest.raises(OperationLedgerError) as sealed:
        _ = publish_lab.operation_ledger.head
    assert sealed.value.code is OperationLedgerCode.LEDGER_SEALED


def test_publish_requires_operation_ledger(publish_lab: _PublishLab) -> None:
    runtime = _create_test_job_runtime(publish_lab.bundle)
    manifest = _manifest("MANIFEST-S3E-NO-LEDGER")
    context = _context(
        publish_lab,
        export_id="EXPORT-S3E-NO-LEDGER",
        operation_id="OP-S3E-NO-LEDGER",
        manifest_id=manifest.manifest_id,
    )
    with runtime.begin_operation(
        context,
        manifest,
        JobResourceBudget.conservative_test_default(),
    ) as operation:
        staging = operation.create_fixed_staging()
        staging.create_declared_file("document.txt", b"published-content")
        observed = staging.seal_and_observe()
        with pytest.raises(JobOperationError) as captured:
            operation.authorize_publish(
                observed,
                Path("data") / "exports" / "EXPORT-S3E-NO-LEDGER",
                checkpoint_manifest_sha256=_sha(b"checkpoint-manifest"),
            )
        assert captured.value.code is JobOperationCode.PUBLISH_UNAVAILABLE


def test_directory_publish_receipt_and_pair_reservation_are_not_serializable(
    publish_lab: _PublishLab,
) -> None:
    operation, observed, token, _payload = _prepare_publish(
        publish_lab,
        export_id="EXPORT-S3E-OPAQUE",
        operation_id="OP-S3E-OPAQUE",
    )
    reservation = operation._reserved_pair
    with pytest.raises(TypeError):
        reservation.__reduce__()
    assert "redacted" in repr(reservation).casefold()
    with operation:
        receipt = operation.execute_publish_pair(token, observed)
        with pytest.raises(TypeError):
            receipt.__reduce__()
        assert "redacted" in repr(receipt).casefold()


def test_context_exit_preserves_publish_failure_when_writer_is_already_sealed(
    publish_lab: _PublishLab,
) -> None:
    operation, observed, token, _payload = _prepare_publish(
        publish_lab,
        export_id="EXPORT-S3E-PRIMARY-ERROR",
        operation_id="OP-S3E-PRIMARY-ERROR",
    )
    original = _WindowsHandleWriter._after_directory_publish_prepared

    def fail_after_prepared(
        _writer: _WindowsHandleWriter,
        _source: object,
        _target: object,
    ) -> None:
        raise HandleWriterError(
            HandleWriterCode.RENAME_FAILED,
            "synthetic pre-rename failure",
        )

    _WindowsHandleWriter._after_directory_publish_prepared = fail_after_prepared
    try:
        with pytest.raises(JobOperationError) as captured:
            with operation:
                operation.execute_publish_pair(token, observed)
    finally:
        _WindowsHandleWriter._after_directory_publish_prepared = original

    assert captured.value.code is JobOperationCode.PUBLISH_FAILED
    assert operation._closed is True


def test_context_exit_never_suppresses_secondary_cleanup_failure(
    publish_lab: _PublishLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    operation, observed, token, _payload = _prepare_publish(
        publish_lab,
        export_id="EXPORT-S3E-CLEANUP-ERROR",
        operation_id="OP-S3E-CLEANUP-ERROR",
    )
    writer_type = _WindowsHandleWriter
    boundary_type = type(publish_lab.bundle.boundary)

    def fail_after_prepared(
        _writer: _WindowsHandleWriter,
        _source: object,
        _target: object,
    ) -> None:
        raise HandleWriterError(
            HandleWriterCode.RENAME_FAILED,
            "synthetic pre-rename failure",
        )

    def fail_context_cleanup(
        _boundary: object,
        _context: object,
        _pin: object,
        _binding_sha256: str,
    ) -> None:
        raise RuntimeError("synthetic context cleanup failure")

    monkeypatch.setattr(
        writer_type,
        "_after_directory_publish_prepared",
        fail_after_prepared,
    )
    monkeypatch.setattr(
        boundary_type,
        "_finish_job_operation_context",
        fail_context_cleanup,
    )

    with pytest.raises(RuntimeError, match="synthetic context cleanup failure"):
        with operation:
            operation.execute_publish_pair(token, observed)

    assert operation._closed is True


def test_unresolved_operation_blocks_then_recovers_abort_without_mutation(
    publish_lab: _PublishLab,
) -> None:
    operation, observed, token, _payload = _prepare_publish(
        publish_lab,
        export_id="EXPORT-S3E-UNRESOLVED",
        operation_id="OP-S3E-UNRESOLVED",
    )
    journal = operation._runtime._writer
    del journal
    # Write PREPARED through the real publish path, then inject a deterministic
    # pre-rename crash surrogate that leaves recovery work instead of deleting.
    original = _WindowsHandleWriter._after_directory_publish_prepared

    def fail_after_prepared(
        _writer: _WindowsHandleWriter,
        _source: object,
        _target: object,
    ) -> None:
        raise HandleWriterError(
            HandleWriterCode.RENAME_FAILED,
            "synthetic pre-rename failure",
        )

    _WindowsHandleWriter._after_directory_publish_prepared = fail_after_prepared
    try:
        with pytest.raises(JobOperationError):
            operation.execute_publish_pair(token, observed)
    finally:
        _WindowsHandleWriter._after_directory_publish_prepared = original
        with pytest.raises(HandleWriterError) as close_failure:
            operation.close()
    assert close_failure.value.code is HandleWriterCode.WRITER_SEALED
    # The implementation conservatively records IN_DOUBT once the native
    # boundary is entered.  Reopen from immutable disk segments: the original
    # in-memory writer is deliberately sealed and cannot be trusted further.
    reopened_bundle = _create_test_durable_boundary(
        publish_lab.project,
        initialize=False,
        epoch_id="RUN-S3E-AUDIT",
        initial_revision_sequence=1,
        initial_revision_id="KEYREV-S3E-ONE",
        master_key=b"E" * 32,
        key_created_at_utc="2026-07-11T16:00:00Z",
    )
    reopened_operation_ledger = _create_test_operation_ledger(
        reopened_bundle,
        epoch_id="RUN-S3E-OPERATIONS",
        initialize=False,
    )
    assert reopened_operation_ledger.head.unresolved_transaction_ids
    transaction_id = reopened_operation_ledger.head.unresolved_transaction_ids[0]
    reopened_runtime = _create_test_job_runtime(
        reopened_bundle,
        operation_ledger=reopened_operation_ledger,
    )
    reopened_lab = _PublishLab(
        project=publish_lab.project,
        protected=publish_lab.protected,
        sentinel=publish_lab.sentinel,
        bundle=reopened_bundle,
        operation_ledger=reopened_operation_ledger,
        runtime=reopened_runtime,
    )
    manifest = _manifest("MANIFEST-S3E-BLOCKED")
    context = _context(
        reopened_lab,
        export_id="EXPORT-S3E-BLOCKED",
        operation_id="OP-S3E-BLOCKED",
        manifest_id=manifest.manifest_id,
    )
    with pytest.raises((JobOperationError, HandleWriterError)) as captured:
        reopened_runtime.begin_operation(
            context,
            manifest,
            JobResourceBudget.conservative_test_default(),
        )
    if isinstance(captured.value, JobOperationError):
        assert captured.value.code is JobOperationCode.PUBLISH_UNAVAILABLE
    reopened_bundle.key_store.create_revision(
        revision_sequence=2,
        revision_id="KEYREV-S3E-RECOVERY-TWO",
        master_key=b"R" * 32,
        created_at_utc="2026-07-11T16:20:00Z",
    )
    reopened_bundle.ledger.rotate_key(
        next_revision_id="KEYREV-S3E-RECOVERY-TWO",
        rotation_id="ROTATE-S3E-BEFORE-RECOVERY",
        created_at_utc="2026-07-11T16:20:01Z",
    )
    recovered = _reconcile_test_publish_operation(
        reopened_bundle,
        reopened_operation_ledger,
        transaction_id,
        JobResourceBudget.conservative_test_default(),
    )
    assert recovered.state is OperationState.RECOVERED_ABORT
    assert reopened_operation_ledger.head.unresolved_transaction_ids == ()
    post_recovery_context = _context(
        reopened_lab,
        export_id="EXPORT-S3E-POST-RECOVERY",
        operation_id="OP-S3E-POST-RECOVERY",
        manifest_id=manifest.manifest_id,
    )
    with pytest.raises(JobOperationError) as retired_epoch:
        reopened_runtime.begin_operation(
            post_recovery_context,
            manifest,
            JobResourceBudget.conservative_test_default(),
        )
    assert retired_epoch.value.code is JobOperationCode.PUBLISH_UNAVAILABLE
    (
        publish_lab.project
        / "logs"
        / "operations"
        / "segments"
        / "RUN-S3E-OPERATIONS-ROTATED"
    ).mkdir()
    rotated_operation_ledger = _create_test_operation_ledger(
        reopened_bundle,
        epoch_id="RUN-S3E-OPERATIONS-ROTATED",
        initialize=True,
        initialized_at_utc="2026-07-11T16:20:02Z",
    )
    rotated_runtime = _create_test_job_runtime(
        reopened_bundle,
        operation_ledger=rotated_operation_ledger,
    )
    with rotated_runtime.begin_operation(
        post_recovery_context,
        manifest,
        JobResourceBudget.conservative_test_default(),
    ):
        pass


def test_s3h_crash_race_truth_table_is_complete_and_unambiguous() -> None:
    cases = tuple(row[0] for row in S3H_CRASH_RACE_TRUTH_TABLE)
    outcomes = tuple(row[1] for row in S3H_CRASH_RACE_TRUTH_TABLE)

    assert len(S3H_CRASH_RACE_TRUTH_TABLE) == 9
    assert len(set(cases)) == len(cases)
    assert all(outcome and outcome == outcome.upper() for outcome in outcomes)
    assert S3H_CRASH_RACE_TRUTH_TABLE[-1] == (
        "HOSTILE_EXTERNAL_WRITER_FREEZE",
        "NOT_GUARANTEED_DETECT_AND_SEAL",
        "RECOVERY_GUARANTEE_SCOPE=COOPERATIVE_APPLICATION_WRITERS_ONLY",
    )


@pytest.mark.parametrize(
    (
        "crash_point",
        "exit_code",
        "segment_count_before",
        "expected_terminal_state",
    ),
    (
        ("BEFORE_RENAME", 71, 2, OperationState.RECOVERED_ABORT),
        ("AFTER_RENAME", 72, 2, OperationState.RECOVERED_COMMIT),
        (
            "BEFORE_TERMINAL_APPEND",
            73,
            4,
            OperationState.RECOVERED_COMMIT,
        ),
        ("AFTER_TERMINAL_APPEND", 74, 5, OperationState.COMMITTED),
    ),
    ids=(
        "BEFORE_RENAME-71-2-RECOVERED_ABORT",
        "AFTER_RENAME-72-2-RECOVERED_COMMIT",
        "BEFORE_TERMINAL_APPEND-73-4-RECOVERED_COMMIT",
        "AFTER_TERMINAL_APPEND-74-5-COMMITTED",
    ),
)
def test_real_process_publish_crash_points_reconcile_once(
    publish_lab: _PublishLab,
    crash_point: str,
    exit_code: int,
    segment_count_before: int,
    expected_terminal_state: OperationState,
) -> None:
    suffix = crash_point.replace("_", "-")
    export_id = f"EXPORT-S3H-{suffix}"
    operation_id = f"OP-S3H-{suffix}"
    completed = _run_real_publish_crash_child(
        publish_lab,
        crash_point=crash_point,
        expected_exit_code=exit_code,
        export_id=export_id,
        operation_id=operation_id,
    )
    assert completed.returncode == exit_code, (
        completed.stdout.decode("utf-8", "replace"),
        completed.stderr.decode("utf-8", "replace"),
    )
    assert publish_lab.sentinel.read_bytes() == (
        b"publish-operation-protected-sentinel"
    )
    reopened = _reopen_publish_lab(publish_lab)
    assert reopened.operation_ledger.head.segment_count == segment_count_before
    assert len(reopened.operation_ledger._transaction_history) == 1
    transaction_id, history = next(
        iter(reopened.operation_ledger._transaction_history.items())
    )
    previous_state = history[-1].next_state
    expected_previous_state = {
        "BEFORE_RENAME": OperationState.PREPARED,
        "AFTER_RENAME": OperationState.PREPARED,
        "BEFORE_TERMINAL_APPEND": OperationState.POSTCONDITION_VERIFIED,
        "AFTER_TERMINAL_APPEND": OperationState.COMMITTED,
    }[crash_point]
    assert previous_state is expected_previous_state
    if previous_state is OperationState.COMMITTED:
        assert reopened.operation_ledger.head.unresolved_transaction_ids == ()
    else:
        assert reopened.operation_ledger.head.unresolved_transaction_ids == (
            transaction_id,
        )

    source = (
        publish_lab.project
        / "tmp"
        / "jobs"
        / "INTERNAL"
        / "JOB-S3E-PUBLISH"
        / "publish"
        / "MANIFEST-S3E-ONE"
    )
    target = publish_lab.project / "data" / "exports" / export_id
    if crash_point == "BEFORE_RENAME":
        assert (source / "document.txt").read_bytes() == b"published-content"
        assert not target.exists()
    else:
        assert not source.exists()
        assert (target / "document.txt").read_bytes() == b"published-content"

    recovered = _reconcile_test_publish_operation(
        reopened.bundle,
        reopened.operation_ledger,
        transaction_id,
        JobResourceBudget.conservative_test_default(),
    )
    assert recovered.state is expected_terminal_state
    expected_segment_count = (
        segment_count_before
        if crash_point == "AFTER_TERMINAL_APPEND"
        else segment_count_before + 1
    )
    assert reopened.operation_ledger.head.segment_count == expected_segment_count
    assert reopened.operation_ledger.head.unresolved_transaction_ids == ()

    fresh = _reopen_publish_lab(reopened)
    before_replay = fresh.operation_ledger.head.segment_count
    replayed = _reconcile_test_publish_operation(
        fresh.bundle,
        fresh.operation_ledger,
        transaction_id,
        JobResourceBudget.conservative_test_default(),
    )
    assert replayed == recovered
    assert fresh.operation_ledger.head.segment_count == before_replay
    assert fresh.operation_ledger.head.unresolved_transaction_ids == ()
    assert publish_lab.sentinel.read_bytes() == (
        b"publish-operation-protected-sentinel"
    )


def test_rename_before_mutated_crash_recovers_commit_from_exact_target(
    publish_lab: _PublishLab,
) -> None:
    operation, observed, token, payload = _prepare_publish(
        publish_lab,
        export_id="EXPORT-S3E-CRASH-COMMIT",
        operation_id="OP-S3E-CRASH-COMMIT",
    )
    original = _WindowsHandleWriter._after_directory_publish_renamed

    def fail_after_rename(
        _writer: _WindowsHandleWriter,
        _source: object,
        _target: object,
    ) -> None:
        raise HandleWriterError(
            HandleWriterCode.RENAME_FAILED,
            "synthetic post-rename crash boundary",
        )

    _WindowsHandleWriter._after_directory_publish_renamed = fail_after_rename
    try:
        with pytest.raises(JobOperationError):
            operation.execute_publish_pair(token, observed)
    finally:
        _WindowsHandleWriter._after_directory_publish_renamed = original
        with pytest.raises(HandleWriterError):
            operation.close()
    target = (
        publish_lab.project
        / "data"
        / "exports"
        / "EXPORT-S3E-CRASH-COMMIT"
    )
    source = (
        publish_lab.project
        / "tmp"
        / "jobs"
        / "INTERNAL"
        / "JOB-S3E-PUBLISH"
        / "publish"
        / "MANIFEST-S3E-ONE"
    )
    assert not source.exists()
    assert (target / "document.txt").read_bytes() == payload
    reopened_bundle = _create_test_durable_boundary(
        publish_lab.project,
        initialize=False,
        epoch_id="RUN-S3E-AUDIT",
        initial_revision_sequence=1,
        initial_revision_id="KEYREV-S3E-ONE",
        master_key=b"E" * 32,
        key_created_at_utc="2026-07-11T16:00:00Z",
    )
    reopened_ledger = _create_test_operation_ledger(
        reopened_bundle,
        epoch_id="RUN-S3E-OPERATIONS",
        initialize=False,
    )
    transaction_id = reopened_ledger.head.unresolved_transaction_ids[0]
    recovered = _reconcile_test_publish_operation(
        reopened_bundle,
        reopened_ledger,
        transaction_id,
        JobResourceBudget.conservative_test_default(),
    )
    assert recovered.state is OperationState.RECOVERED_COMMIT
    assert reopened_ledger.head.unresolved_transaction_ids == ()
    assert (target / "document.txt").read_bytes() == payload
    segment_count = reopened_ledger.head.segment_count
    replayed_recovery = _reconcile_test_publish_operation(
        reopened_bundle,
        reopened_ledger,
        transaction_id,
        JobResourceBudget.conservative_test_default(),
    )
    assert replayed_recovery == recovered
    assert reopened_ledger.head.segment_count == segment_count
    reopened_lab = _PublishLab(
        project=publish_lab.project,
        protected=publish_lab.protected,
        sentinel=publish_lab.sentinel,
        bundle=reopened_bundle,
        operation_ledger=reopened_ledger,
        runtime=_create_test_job_runtime(
            reopened_bundle,
            operation_ledger=reopened_ledger,
        ),
    )
    replay = reopened_lab.runtime.replay_committed_publish(
        _context(
            reopened_lab,
            export_id="EXPORT-S3E-CRASH-COMMIT",
            operation_id="OP-S3E-CRASH-COMMIT",
        ),
        _manifest(),
        JobResourceBudget.conservative_test_default(),
    )
    assert (
        replay.completion_kind
        is OperationCompletionKind.RECOVERED_COMMIT_OBSERVATION_ONLY
    )
    assert replay.native_directory_receipt_sha256 is None
    assert replay.recovery_observation_receipt_sha256 is not None
    assert replay.recovery_guarantee_scope == "COOPERATIVE_APPLICATION_WRITERS_ONLY"
    assert reopened_ledger.head.segment_count == segment_count
    recovered_segment = _operation_segment_files(reopened_lab)[-1]
    recovered_value = json.loads(recovered_segment.read_text(encoding="ascii"))
    recovered_value["transition"]["recovery_observation_receipt_sha256"] = "0" * 64
    _resign_operation_segment(reopened_lab, recovered_segment, recovered_value)
    tampered_bundle = _create_test_durable_boundary(
        publish_lab.project,
        initialize=False,
        epoch_id="RUN-S3E-AUDIT",
        initial_revision_sequence=1,
        initial_revision_id="KEYREV-S3E-ONE",
        master_key=b"E" * 32,
        key_created_at_utc="2026-07-11T16:00:00Z",
    )
    with pytest.raises(OperationLedgerError) as tampered:
        _create_test_operation_ledger(
            tampered_bundle,
            epoch_id="RUN-S3E-OPERATIONS",
            initialize=False,
        )
    assert tampered.value.code is OperationLedgerCode.TRANSITION_CONFLICT


def test_restricted_publish_recovery_requires_exact_hmac_bound_storage_locators(
    publish_lab: _PublishLab,
) -> None:
    payload = b"restricted-copy-payload"
    context = _restricted_copy_context(publish_lab)
    manifest = _manifest(
        "MANIFEST-S3F-OPAQUE",
        payload,
        DataClassification.RESTRICTED,
    )
    budget = JobResourceBudget.conservative_test_default()
    operation = publish_lab.runtime.begin_operation(context, manifest, budget)
    staging = operation.create_fixed_staging()
    staging.create_declared_file("document.txt", payload)
    observed = staging.seal_and_observe()
    token = operation.authorize_publish(
        observed,
        Path("Copy") / "restricted" / "COPY-S3F-OPAQUE",
        checkpoint_manifest_sha256=_sha(b"restricted-copy-checkpoint"),
    )
    original = _WindowsHandleWriter._after_directory_publish_renamed

    def fail_after_restricted_rename(
        _writer: _WindowsHandleWriter,
        _source: object,
        _target: object,
    ) -> None:
        raise HandleWriterError(
            HandleWriterCode.RENAME_FAILED,
            "synthetic restricted post-rename crash boundary",
        )

    _WindowsHandleWriter._after_directory_publish_renamed = (
        fail_after_restricted_rename
    )
    try:
        with pytest.raises(JobOperationError):
            operation.execute_publish_pair(token, observed)
    finally:
        _WindowsHandleWriter._after_directory_publish_renamed = original
        with pytest.raises(HandleWriterError):
            operation.close()

    reopened = _reopen_publish_lab(publish_lab)
    transaction_id = reopened.operation_ledger.head.unresolved_transaction_ids[0]
    recovery_context = _restricted_copy_context(reopened)
    recovery_locator = (
        reopened.bundle.boundary._issue_restricted_recovery_locator(
            recovery_context,
            transaction_id,
        )
    )
    recovered = _reconcile_test_publish_operation(
        reopened.bundle,
        reopened.operation_ledger,
        transaction_id,
        budget,
        restricted_locator_capability=recovery_locator,
    )
    assert reopened.bundle.boundary.release_context(recovery_context)
    assert recovered.state is OperationState.RECOVERED_COMMIT
    terminal = reopened.operation_ledger._transaction_history[transaction_id][-1]
    assert terminal.locator_mode is OperationLocatorMode.HMAC_ONLY
    assert terminal.classification is DataClassification.RESTRICTED
    assert reopened.operation_ledger.head.unresolved_transaction_ids == ()
    assert (
        publish_lab.project
        / "Copy"
        / "restricted"
        / "COPY-S3F-OPAQUE"
        / "document.txt"
    ).read_bytes() == payload


def test_committed_publish_replay_is_idempotent_and_begin_rejects_reuse(
    publish_lab: _PublishLab,
) -> None:
    operation, observed, token, payload = _prepare_publish(
        publish_lab,
        export_id="EXPORT-S3E-REPLAY",
        operation_id="OP-S3E-REPLAY",
    )
    with operation:
        committed = operation.execute_publish_pair(token, observed)
    reopened = _reopen_publish_lab(publish_lab)
    target = reopened.project / "data" / "exports" / "EXPORT-S3E-REPLAY"
    before = reopened.operation_ledger.head.segment_count
    context = _context(
        reopened,
        export_id="EXPORT-S3E-REPLAY",
        operation_id="OP-S3E-REPLAY",
    )
    replay = reopened.runtime.replay_committed_publish(
        context,
        _manifest(),
        JobResourceBudget.conservative_test_default(),
    )
    assert replay.transaction_id == committed.transaction_id
    assert replay.pair_id == committed.pair_id
    assert replay.completion_kind is OperationCompletionKind.NATIVE_COMMIT
    assert replay.native_directory_receipt_sha256 == committed.native_directory_receipt_sha256
    assert replay.recovery_observation_receipt_sha256 is None
    assert reopened.operation_ledger.head.segment_count == before
    assert (target / "document.txt").read_bytes() == payload
    with pytest.raises(JobOperationError) as captured:
        reopened.runtime.begin_operation(
            context,
            _manifest(),
            JobResourceBudget.conservative_test_default(),
        )
    assert captured.value.code is JobOperationCode.OPERATION_BUSY


def test_operation_ledger_reopens_after_audit_key_rotation_with_stable_identity(
    publish_lab: _PublishLab,
) -> None:
    operation, observed, token, _payload = _prepare_publish(
        publish_lab,
        export_id="EXPORT-S3E-ROTATION",
        operation_id="OP-S3E-ROTATION",
    )
    with operation:
        operation.execute_publish_pair(token, observed)
    identity_before = publish_lab.operation_ledger.durable_identity_digest(
        42,
        b"\x11" * 16,
    )
    publish_lab.bundle.key_store.create_revision(
        revision_sequence=2,
        revision_id="KEYREV-S3E-TWO",
        master_key=b"F" * 32,
        created_at_utc="2026-07-11T16:10:00Z",
    )
    publish_lab.bundle.ledger.rotate_key(
        next_revision_id="KEYREV-S3E-TWO",
        rotation_id="ROTATE-S3E-ONE-TO-TWO",
        created_at_utc="2026-07-11T16:10:01Z",
    )
    reopened = _reopen_publish_lab(publish_lab)
    assert reopened.operation_ledger.head.segment_count == 5
    assert (
        reopened.operation_ledger.durable_identity_digest(42, b"\x11" * 16)
        == identity_before
    )
    replay = reopened.runtime.replay_committed_publish(
        _context(
            reopened,
            export_id="EXPORT-S3E-ROTATION",
            operation_id="OP-S3E-ROTATION",
        ),
        _manifest(),
        JobResourceBudget.conservative_test_default(),
    )
    assert replay.completion_kind is OperationCompletionKind.NATIVE_COMMIT
    new_manifest = _manifest("MANIFEST-S3E-AFTER-ROTATION")
    with pytest.raises(JobOperationError) as read_only_epoch:
        reopened.runtime.begin_operation(
            _context(
                reopened,
                export_id="EXPORT-S3E-AFTER-ROTATION",
                operation_id="OP-S3E-AFTER-ROTATION",
                manifest_id=new_manifest.manifest_id,
            ),
            new_manifest,
            JobResourceBudget.conservative_test_default(),
        )
    assert read_only_epoch.value.code is JobOperationCode.PUBLISH_UNAVAILABLE


def test_unactivated_audit_key_is_not_a_known_operation_epoch_authority(
    publish_lab: _PublishLab,
) -> None:
    publish_lab.bundle.key_store.create_revision(
        revision_sequence=2,
        revision_id="KEYREV-S3E-UNACTIVATED",
        master_key=b"U" * 32,
        created_at_utc="2026-07-11T16:15:00Z",
    )
    reopened = _reopen_publish_lab(publish_lab)
    assert set(reopened.operation_ledger._known_revisions) == {"KEYREV-S3E-ONE"}


def test_terminal_replay_and_reopen_reject_truncated_audit_ancestor(
    publish_lab: _PublishLab,
) -> None:
    operation, observed, token, _payload = _prepare_publish(
        publish_lab,
        export_id="EXPORT-S3E-AUDIT-TRUNCATION",
        operation_id="OP-S3E-AUDIT-TRUNCATION",
    )
    with operation:
        operation.execute_publish_pair(token, observed)
    audit_segments = sorted(
        (
            publish_lab.project
            / "logs"
            / "audit"
            / "segments"
            / "RUN-S3E-AUDIT"
        ).glob("[0-9]*.json")
    )
    assert len(audit_segments) >= 2
    audit_segments[-1].rename(
        publish_lab.project / "tmp" / "orphaned-audit-tail.json"
    )
    with pytest.raises(JobOperationError) as replay_failed:
        publish_lab.runtime.replay_committed_publish(
            _context(
                publish_lab,
                export_id="EXPORT-S3E-AUDIT-TRUNCATION",
                operation_id="OP-S3E-AUDIT-TRUNCATION",
            ),
            _manifest(),
            JobResourceBudget.conservative_test_default(),
        )
    assert replay_failed.value.code is JobOperationCode.OPERATION_LEDGER_FAILED
    reopened_bundle = _create_test_durable_boundary(
        publish_lab.project,
        initialize=False,
        epoch_id="RUN-S3E-AUDIT",
        initial_revision_sequence=1,
        initial_revision_id="KEYREV-S3E-ONE",
        master_key=b"E" * 32,
        key_created_at_utc="2026-07-11T16:00:00Z",
    )
    with pytest.raises(OperationLedgerError) as reopened_failed:
        _create_test_operation_ledger(
            reopened_bundle,
            epoch_id="RUN-S3E-OPERATIONS",
            initialize=False,
        )
    assert reopened_failed.value.code is OperationLedgerCode.CHAIN_CORRUPT


def test_prepared_reserves_complete_transaction_capacity_before_rename(
    publish_lab: _PublishLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(operation_ledger_module, "_MAX_SEGMENTS", 4)
    operation, observed, token, _payload = _prepare_publish(
        publish_lab,
        export_id="EXPORT-S3E-CAPACITY",
        operation_id="OP-S3E-CAPACITY",
    )
    source = (
        publish_lab.project
        / "tmp"
        / "jobs"
        / "INTERNAL"
        / "JOB-S3E-PUBLISH"
        / "publish"
        / "MANIFEST-S3E-ONE"
    )
    target = publish_lab.project / "data" / "exports" / "EXPORT-S3E-CAPACITY"
    with operation:
        with pytest.raises(JobOperationError) as captured:
            operation.execute_publish_pair(token, observed)
        assert captured.value.code is JobOperationCode.PUBLISH_FAILED
        assert source.is_dir()
        assert not target.exists()
        assert publish_lab.operation_ledger.head.segment_count == 1


def test_prepared_reserves_complete_transaction_byte_budget_before_rename(
    publish_lab: _PublishLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        operation_ledger_module,
        "_MAX_TRANSITION_SEGMENT_BYTES",
        128 * 1024,
    )
    monkeypatch.setattr(operation_ledger_module, "_MAX_LEDGER_BYTES", 512 * 1024)
    operation, observed, token, _payload = _prepare_publish(
        publish_lab,
        export_id="EXPORT-S3E-BYTE-CAPACITY",
        operation_id="OP-S3E-BYTE-CAPACITY",
    )
    target = (
        publish_lab.project / "data" / "exports" / "EXPORT-S3E-BYTE-CAPACITY"
    )
    with operation:
        with pytest.raises(JobOperationError) as captured:
            operation.execute_publish_pair(token, observed)
        assert captured.value.code is JobOperationCode.PUBLISH_FAILED
        assert not target.exists()
        assert publish_lab.operation_ledger.head.segment_count == 1


def test_pair_reservation_rejects_wrong_token_cross_thread_and_reuse(
    publish_lab: _PublishLab,
) -> None:
    operation, observed, token, _payload = _prepare_publish(
        publish_lab,
        export_id="EXPORT-S3E-PAIR-OWNER",
        operation_id="OP-S3E-PAIR-OWNER",
    )
    with pytest.raises(JobOperationError) as wrong_token:
        operation.execute_publish_pair(object(), observed)
    assert wrong_token.value.code is JobOperationCode.PUBLISH_UNAVAILABLE
    errors: list[BaseException] = []

    def cross_thread_attempt() -> None:
        try:
            operation.execute_publish_pair(token, observed)
        except BaseException as exc:
            errors.append(exc)

    worker = threading.Thread(target=cross_thread_attempt)
    worker.start()
    worker.join(timeout=10)
    assert not worker.is_alive()
    assert len(errors) == 1
    assert isinstance(errors[0], JobOperationError)
    assert errors[0].code is JobOperationCode.INVALID_LEASE
    with operation:
        operation.execute_publish_pair(token, observed)
        with pytest.raises(JobOperationError) as replay:
            operation.execute_publish_pair(token, observed)
        assert replay.value.code is JobOperationCode.PUBLISH_UNAVAILABLE


def test_registry_drift_is_detected_before_directory_mutation(
    publish_lab: _PublishLab,
) -> None:
    operation, observed, token, _payload = _prepare_publish(
        publish_lab,
        export_id="EXPORT-S3E-REGISTRY-DRIFT",
        operation_id="OP-S3E-REGISTRY-DRIFT",
    )
    reservation = operation._reserved_pair
    pair_id = reservation._pair.pair_id
    core = publish_lab.bundle.boundary._TestWorkspaceBoundary__core
    registry = core._BoundaryCore__pair_reservations
    original = registry[pair_id]
    registry[pair_id] = object()
    target = (
        publish_lab.project
        / "data"
        / "exports"
        / "EXPORT-S3E-REGISTRY-DRIFT"
    )
    try:
        with pytest.raises(Exception):
            operation.execute_publish_pair(token, observed)
        assert not target.exists()
        assert publish_lab.operation_ledger.head.segment_count == 1
    finally:
        registry[pair_id] = original
        operation.close()


@pytest.mark.parametrize(
    "tamper_mode",
    ("hmac", "schema", "policy", "key", "shape", "gap", "fork"),
)
def test_operation_ledger_tamper_gap_fork_and_envelope_changes_fail_closed(
    publish_lab: _PublishLab,
    tamper_mode: str,
) -> None:
    genesis = _operation_segment_files(publish_lab)[0]
    if tamper_mode == "gap":
        value = json.loads(genesis.read_text(encoding="ascii"))
        genesis.rename(
            genesis.with_name(f"{1:020d}-{value['segment_sha256']}.json")
        )
    elif tamper_mode == "fork":
        value = json.loads(genesis.read_text(encoding="ascii"))
        genesis.with_name(
            f"{1:020d}-{value['segment_sha256']}.json"
        ).write_bytes(genesis.read_bytes())
    else:
        value = json.loads(genesis.read_text(encoding="ascii"))
        if tamper_mode == "hmac":
            value["segment_hmac_sha256"] = "0" * 64
        elif tamper_mode == "schema":
            value["schema_version"] = "9.9"
        elif tamper_mode == "policy":
            value["policy_digest"] = "0" * 64
        elif tamper_mode == "key":
            value["key_revision_sha256"] = "0" * 64
        elif tamper_mode == "shape":
            value["unexpected"] = "FORBIDDEN"
        genesis.write_bytes(canonical_json_bytes(value))
    with pytest.raises(OperationLedgerError) as captured:
        _create_test_operation_ledger(
            publish_lab.bundle,
            epoch_id="RUN-S3E-OPERATIONS",
            initialize=False,
        )
    assert captured.value.code in {
        OperationLedgerCode.AUTHENTICATION_FAILED,
        OperationLedgerCode.CHAIN_CORRUPT,
    }


def test_operation_ledger_rejects_valid_hmac_illegal_transition(
    publish_lab: _PublishLab,
) -> None:
    operation, observed, token, _payload = _prepare_publish(
        publish_lab,
        export_id="EXPORT-S3E-ILLEGAL",
        operation_id="OP-S3E-ILLEGAL",
    )
    with operation:
        operation.execute_publish_pair(token, observed)
    committed = _operation_segment_files(publish_lab)[-1]
    value = json.loads(committed.read_text(encoding="ascii"))
    transition = value["transition"]
    transition["next_state"] = "ABORTED"
    transition["mutation_attempted"] = False
    transition["native_mutation_receipt_sha256"] = None
    transition["target_evidence"] = None
    transition["completion_kind"] = None
    transition["error_code"] = "SYNTHETIC_FAILURE"
    _resign_operation_segment(publish_lab, committed, value)
    with pytest.raises(OperationLedgerError) as captured:
        _create_test_operation_ledger(
            publish_lab.bundle,
            epoch_id="RUN-S3E-OPERATIONS",
            initialize=False,
        )
    assert captured.value.code is OperationLedgerCode.CHAIN_CORRUPT


def test_transition_id_replay_with_other_transaction_seals(
    publish_lab: _PublishLab,
) -> None:
    operation, observed, token, _payload = _prepare_publish(
        publish_lab,
        export_id="EXPORT-S3E-TRANSITION-CONFLICT",
        operation_id="OP-S3E-TRANSITION-CONFLICT",
    )
    with operation:
        operation.execute_publish_pair(token, observed)
    history = next(iter(publish_lab.operation_ledger._transaction_history.values()))
    conflicting = replace(
        history[0],
        transaction_id="TXN-S3E-CONFLICTING-REPLAY",
        operation_id="OP-S3E-CONFLICTING-REPLAY",
    )
    with publish_lab.bundle.writer.acquire_runtime_mutex() as lease:
        with pytest.raises(OperationLedgerError) as captured:
            publish_lab.operation_ledger._append_transition_under_existing_mutex(
                lease,
                conflicting,
            )
    assert captured.value.code is OperationLedgerCode.TRANSITION_CONFLICT


def test_nested_unicode_empty_and_zero_byte_tree_publishes_exactly(
    publish_lab: _PublishLab,
) -> None:
    nested_payload = "函数图像".encode("utf-8")
    manifest = DeclaredTreeManifest(
        manifest_id="MANIFEST-S3E-NESTED",
        classification=DataClassification.INTERNAL,
        entries=(
            DeclaredTreeEntry("zero.bin", TreeEntryKind.FILE, 0, _sha(b"")),
            DeclaredTreeEntry("图形", TreeEntryKind.DIRECTORY, 0, None),
            DeclaredTreeEntry(
                "图形/函数α.txt",
                TreeEntryKind.FILE,
                len(nested_payload),
                _sha(nested_payload),
            ),
            DeclaredTreeEntry("图形/空目录", TreeEntryKind.DIRECTORY, 0, None),
        ),
    )
    context = _context(
        publish_lab,
        export_id="EXPORT-S3E-NESTED",
        operation_id="OP-S3E-NESTED",
        manifest_id=manifest.manifest_id,
    )
    operation = publish_lab.runtime.begin_operation(
        context,
        manifest,
        JobResourceBudget.conservative_test_default(),
    )
    staging = operation.create_fixed_staging()
    staging.create_declared_directory("图形")
    staging.create_declared_directory("图形/空目录")
    staging.create_declared_file("图形/函数α.txt", nested_payload)
    staging.create_declared_file("zero.bin", b"")
    observed = staging.seal_and_observe()
    token = operation.authorize_publish(
        observed,
        Path("data") / "exports" / "EXPORT-S3E-NESTED",
        checkpoint_manifest_sha256=_sha(b"checkpoint-manifest"),
    )
    with operation:
        receipt = operation.execute_publish_pair(token, observed)
    target = publish_lab.project / "data" / "exports" / "EXPORT-S3E-NESTED"
    assert receipt.completion_kind is OperationCompletionKind.NATIVE_COMMIT
    assert (target / "图形" / "函数α.txt").read_bytes() == nested_payload
    assert (target / "图形" / "空目录").is_dir()
    assert (target / "zero.bin").read_bytes() == b""


@pytest.mark.parametrize(
    "contradiction",
    ("both_present", "both_absent", "wrong_target", "budget_mismatch"),
)
def test_recovery_contradiction_matrix_seals_without_claiming_success(
    publish_lab: _PublishLab,
    contradiction: str,
) -> None:
    identifier = contradiction.replace("_", "-").upper()
    reopened, transaction_id, source, target = _leave_prepared_operation_unresolved(
        publish_lab,
        export_id=f"EXPORT-S3E-{identifier}",
        operation_id=f"OP-S3E-{identifier}",
    )
    budget = JobResourceBudget.conservative_test_default()
    if contradiction == "both_present":
        shutil.copytree(source, target)
    elif contradiction == "both_absent":
        source.rename(publish_lab.project / "tmp" / "orphaned-source")
    elif contradiction == "wrong_target":
        source.rename(target)
        (target / "document.txt").write_bytes(b"changed-after-crash")
    else:
        budget = replace(
            budget,
            maximum_elapsed_seconds=budget.maximum_elapsed_seconds + 1,
        )
    with pytest.raises(OperationLedgerError) as captured:
        _reconcile_test_publish_operation(
            reopened.bundle,
            reopened.operation_ledger,
            transaction_id,
            budget,
        )
    assert captured.value.code is OperationLedgerCode.RECOVERY_CONTRADICTION
