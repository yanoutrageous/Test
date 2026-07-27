from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Iterator

import pytest

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
    QuarantineOperationReceipt,
    RetainedRestoreOperationReceipt,
)
from app.safety.operation_ledger import OperationLocatorMode, OperationState
from app.safety.production_guard import (
    ProductionBoundaryError,
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
class _S3GLab:
    project: Path
    protected: Path
    sentinel: Path
    bundle: object
    operation_ledger: object
    runtime: object
    quarantine_date: str


@pytest.fixture
def s3g_lab(tmp_path: Path) -> Iterator[_S3GLab]:
    project = tmp_path / "project"
    protected = tmp_path / "protected"
    project.mkdir()
    protected.mkdir()
    sentinel = protected / "sentinel.bin"
    sentinel.write_bytes(b"s3g-protected-sentinel")
    quarantine_date = datetime.now(UTC).date().isoformat()
    (project / "logs" / "audit" / "keys").mkdir(parents=True)
    (project / "logs" / "audit" / "segments" / "RUN-S3G-AUDIT").mkdir(
        parents=True
    )
    (
        project
        / "logs"
        / "operations"
        / "segments"
        / "RUN-S3G-OPERATIONS"
    ).mkdir(parents=True)
    (project / "tmp" / "jobs" / "INTERNAL").mkdir(parents=True)
    (project / "tmp" / "jobs" / "RESTRICTED").mkdir(parents=True)
    (project / "Copy" / "restricted").mkdir(parents=True)
    (project / "data" / "quarantine" / "INTERNAL").mkdir(parents=True)
    (project / "data" / "quarantine" / "RESTRICTED").mkdir(parents=True)
    (project / "data" / "snapshots").mkdir(parents=True)
    bundle = _create_test_durable_boundary(
        project,
        initialize=True,
        epoch_id="RUN-S3G-AUDIT",
        initial_revision_sequence=1,
        initial_revision_id="KEYREV-S3G-ONE",
        master_key=b"G" * 32,
        key_created_at_utc="2026-07-24T04:00:00Z",
        ledger_initialized_at_utc="2026-07-24T04:00:01Z",
    )
    operation_ledger = _create_test_operation_ledger(
        bundle,
        epoch_id="RUN-S3G-OPERATIONS",
        initialize=True,
        initialized_at_utc="2026-07-24T04:00:02Z",
    )
    yield _S3GLab(
        project=project,
        protected=protected,
        sentinel=sentinel,
        bundle=bundle,
        operation_ledger=operation_ledger,
        runtime=_create_test_job_runtime(
            bundle,
            operation_ledger=operation_ledger,
        ),
        quarantine_date=quarantine_date,
    )
    assert sentinel.read_bytes() == b"s3g-protected-sentinel"
    assert {path.name for path in protected.iterdir()} == {"sentinel.bin"}


def _manifest(
    *,
    manifest_id: str = "MANIFEST-S3G-ONE",
    payload: bytes = b"quarantine-content",
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


def _quarantine_context(
    lab: _S3GLab,
    *,
    run_id: str,
    job_id: str,
    operation_id: str,
    manifest_id: str,
    classification: DataClassification = DataClassification.INTERNAL,
    copy_id: str | None = None,
):
    scopes = [
        ScopeId(ScopeKind.RUN_ID, run_id),
        ScopeId(ScopeKind.JOB_ID, job_id),
        ScopeId(ScopeKind.OPERATION_ID, operation_id),
        ScopeId(ScopeKind.MANIFEST_ID, manifest_id),
        ScopeId(ScopeKind.CHECKPOINT_ID, f"CHECKPOINT-{operation_id}"),
    ]
    if copy_id is not None:
        scopes.append(ScopeId(ScopeKind.COPY_ID, copy_id))
    return lab.bundle.boundary.issue_context(
        run_id=run_id,
        job_id=job_id,
        operation_id=operation_id,
        caller=(
            Caller.IMPORT_SERVICE
            if classification is DataClassification.RESTRICTED
            else Caller.TEST_LAB
        ),
        purpose=Purpose.QUARANTINE,
        manifest_id=manifest_id,
        classification=classification,
        scopes=tuple(scopes),
    )


def _restore_context(
    lab: _S3GLab,
    *,
    run_id: str,
    job_id: str,
    operation_id: str,
    manifest_id: str,
    state_id: str,
):
    return lab.bundle.boundary.issue_context(
        run_id=run_id,
        job_id=job_id,
        operation_id=operation_id,
        caller=Caller.BACKUP_SERVICE,
        purpose=Purpose.RESTORE,
        manifest_id=manifest_id,
        scopes=(
            ScopeId(ScopeKind.RUN_ID, run_id),
            ScopeId(ScopeKind.JOB_ID, job_id),
            ScopeId(ScopeKind.OPERATION_ID, operation_id),
            ScopeId(ScopeKind.MANIFEST_ID, manifest_id),
            ScopeId(ScopeKind.CHECKPOINT_ID, f"CHECKPOINT-{operation_id}"),
            ScopeId(ScopeKind.STATE_ID, state_id),
        ),
    )


def _create_internal_source(
    lab: _S3GLab,
    *,
    job_id: str,
    manifest_id: str,
    payload: bytes,
) -> Path:
    relative = (
        Path("tmp")
        / "jobs"
        / "INTERNAL"
        / job_id
        / "publish"
        / manifest_id
    )
    absolute = lab.project / relative
    absolute.mkdir(parents=True)
    (absolute / "document.txt").write_bytes(payload)
    return relative


def _reopen_s3g_lab(lab: _S3GLab) -> _S3GLab:
    bundle = _create_test_durable_boundary(
        lab.project,
        initialize=False,
        epoch_id="RUN-S3G-AUDIT",
        initial_revision_sequence=1,
        initial_revision_id="KEYREV-S3G-ONE",
        master_key=b"G" * 32,
        key_created_at_utc="2026-07-24T04:00:00Z",
    )
    operation_ledger = _create_test_operation_ledger(
        bundle,
        epoch_id="RUN-S3G-OPERATIONS",
        initialize=False,
    )
    return _S3GLab(
        project=lab.project,
        protected=lab.protected,
        sentinel=lab.sentinel,
        bundle=bundle,
        operation_ledger=operation_ledger,
        runtime=_create_test_job_runtime(
            bundle,
            operation_ledger=operation_ledger,
        ),
        quarantine_date=lab.quarantine_date,
    )


def _prepare_internal_quarantine(
    lab: _S3GLab,
    *,
    run_id: str,
    job_id: str,
    operation_id: str,
    manifest_id: str = "MANIFEST-S3G-ONE",
    payload: bytes = b"quarantine-content",
):
    manifest = _manifest(manifest_id=manifest_id, payload=payload)
    source = _create_internal_source(
        lab,
        job_id=job_id,
        manifest_id=manifest.manifest_id,
        payload=payload,
    )
    context = _quarantine_context(
        lab,
        run_id=run_id,
        job_id=job_id,
        operation_id=operation_id,
        manifest_id=manifest.manifest_id,
    )
    operation = lab.runtime.begin_operation(
        context,
        manifest,
        JobResourceBudget.conservative_test_default(),
    )
    observed = operation.observe_quarantine_source(source)
    token = operation.authorize_quarantine(
        observed,
        checkpoint_manifest_sha256=_sha(
            f"checkpoint:{operation_id}".encode("ascii")
        ),
    )
    target = operation._pair_view.target_relative_path
    return operation, observed, token, source, target, manifest, payload


def _quarantine_internal_source(
    lab: _S3GLab,
    *,
    job_id: str = "JOB-S3G-QUARANTINE",
    operation_id: str = "OP-S3G-QUARANTINE",
) -> tuple[QuarantineOperationReceipt, DeclaredTreeManifest, bytes]:
    operation, observed, token, _source, _target, manifest, payload = (
        _prepare_internal_quarantine(
            lab,
            run_id="RUN-S3G-QUARANTINE",
            job_id=job_id,
            operation_id=operation_id,
        )
    )
    with operation:
        receipt = operation.execute_quarantine_pair(token, observed)
    return receipt, manifest, payload


def _create_restricted_source(
    lab: _S3GLab,
    *,
    copy_id: str,
    payload: bytes,
) -> Path:
    source = Path("Copy") / "restricted" / copy_id
    absolute = lab.project / source
    absolute.mkdir(parents=True)
    (absolute / "document.txt").write_bytes(payload)
    return source


def _prepare_restricted_quarantine(
    lab: _S3GLab,
    *,
    run_id: str,
    job_id: str,
    operation_id: str,
    manifest_id: str,
    copy_id: str,
    payload: bytes,
):
    manifest = _manifest(
        manifest_id=manifest_id,
        payload=payload,
        classification=DataClassification.RESTRICTED,
    )
    source = _create_restricted_source(
        lab,
        copy_id=copy_id,
        payload=payload,
    )
    context = _quarantine_context(
        lab,
        run_id=run_id,
        job_id=job_id,
        operation_id=operation_id,
        manifest_id=manifest.manifest_id,
        classification=DataClassification.RESTRICTED,
        copy_id=copy_id,
    )
    operation = lab.runtime.begin_operation(
        context,
        manifest,
        JobResourceBudget.conservative_test_default(),
    )
    observed = operation.observe_quarantine_source(source)
    token = operation.authorize_quarantine(
        observed,
        checkpoint_manifest_sha256=_sha(
            f"checkpoint:{operation_id}".encode("ascii")
        ),
    )
    target = operation._pair_view.target_relative_path
    return operation, observed, token, source, target, manifest


def test_handle_bound_quarantine_moves_exact_tree_and_replays(
    s3g_lab: _S3GLab,
) -> None:
    receipt, manifest, payload = _quarantine_internal_source(s3g_lab)
    quarantine = s3g_lab.project / Path(receipt.quarantine_locator)
    assert receipt.locator_mode is OperationLocatorMode.SAFE_RELATIVE
    assert receipt.classification is DataClassification.INTERNAL
    assert receipt.quarantine_locator.startswith(
        f"data/quarantine/INTERNAL/{s3g_lab.quarantine_date}/"
    )
    event_id = Path(receipt.quarantine_locator).name
    assert len(event_id) == 32
    assert event_id == event_id.upper()
    assert event_id.startswith(s3g_lab.quarantine_date.replace("-", ""))
    assert all(character in "0123456789ABCDEF" for character in event_id)
    assert not (
        s3g_lab.project
        / "tmp"
        / "jobs"
        / "INTERNAL"
        / "JOB-S3G-QUARANTINE"
        / "publish"
        / manifest.manifest_id
    ).exists()
    assert (quarantine / "document.txt").read_bytes() == payload

    replay_context = _quarantine_context(
        s3g_lab,
        run_id="RUN-S3G-QUARANTINE",
        job_id="JOB-S3G-QUARANTINE",
        operation_id="OP-S3G-QUARANTINE",
        manifest_id=manifest.manifest_id,
    )
    replay = s3g_lab.runtime.replay_committed_quarantine(
        replay_context,
        manifest,
        JobResourceBudget.conservative_test_default(),
    )
    assert replay == receipt


def test_restricted_quarantine_receipt_and_ledger_hide_locator(
    s3g_lab: _S3GLab,
) -> None:
    payload = b"restricted-quarantine-content"
    copy_id = "COPY-S3G-RESTRICTED"
    restricted_partition = (
        s3g_lab.project
        / "data"
        / "quarantine"
        / "RESTRICTED"
        / s3g_lab.quarantine_date
    )
    restricted_partition.mkdir()
    partition_identity = restricted_partition.stat().st_ino
    operation, observed, token, _source, _target, _manifest = (
        _prepare_restricted_quarantine(
            s3g_lab,
            run_id="RUN-S3G-RESTRICTED",
            job_id="JOB-S3G-RESTRICTED",
            operation_id="OP-S3G-RESTRICTED",
            manifest_id="MANIFEST-S3G-RESTRICTED",
            copy_id=copy_id,
            payload=payload,
        )
    )
    with operation:
        receipt = operation.execute_quarantine_pair(token, observed)

    assert receipt.locator_mode is OperationLocatorMode.HMAC_ONLY
    assert receipt.classification is DataClassification.RESTRICTED
    assert len(receipt.quarantine_locator) == 64
    assert copy_id not in receipt.quarantine_locator
    assert copy_id not in repr(receipt)
    assert restricted_partition.stat().st_ino == partition_identity
    targets = list(
        restricted_partition.iterdir()
    )
    assert len(targets) == 1
    assert (targets[0] / "document.txt").read_bytes() == payload
    rendered_segments = "".join(
        path.read_text(encoding="ascii")
        for path in (
            s3g_lab.project
            / "logs"
            / "operations"
            / "segments"
            / "RUN-S3G-OPERATIONS"
        ).glob("*.json")
    )
    assert copy_id not in rendered_segments


def test_quarantine_partition_lease_blocks_replacement_until_move_commits(
    s3g_lab: _S3GLab,
) -> None:
    (
        operation,
        observed,
        token,
        _source,
        target,
        _manifest,
        payload,
    ) = _prepare_internal_quarantine(
        s3g_lab,
        run_id="RUN-S3G-PARTITION-LEASE",
        job_id="JOB-S3G-PARTITION-LEASE",
        operation_id="OP-S3G-PARTITION-LEASE",
    )
    partition = s3g_lab.project / target.parent
    replacement = partition.with_name("partition-replaced")
    with operation:
        with pytest.raises(OSError):
            partition.rename(replacement)
        receipt = operation.execute_quarantine_pair(token, observed)

    assert Path(receipt.quarantine_locator) == target
    assert (s3g_lab.project / target / "document.txt").read_bytes() == payload
    assert not replacement.exists()


def test_quarantine_target_race_aborts_without_overwrite(
    s3g_lab: _S3GLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        operation,
        observed,
        token,
        source,
        target,
        _manifest,
        payload,
    ) = _prepare_internal_quarantine(
        s3g_lab,
        run_id="RUN-S3G-TARGET-RACE",
        job_id="JOB-S3G-TARGET-RACE",
        operation_id="OP-S3G-TARGET-RACE",
    )
    absolute_target = s3g_lab.project / target

    def create_conflict(
        _writer: _WindowsHandleWriter,
        _source: object,
        _target: object,
    ) -> None:
        absolute_target.mkdir()
        (absolute_target / "sentinel.txt").write_bytes(b"must-not-overwrite")

    monkeypatch.setattr(
        _WindowsHandleWriter,
        "_after_directory_publish_prepared",
        create_conflict,
    )
    with operation:
        with pytest.raises(JobOperationError) as captured:
            operation.execute_quarantine_pair(token, observed)

    assert captured.value.code is JobOperationCode.PUBLISH_FAILED
    assert (s3g_lab.project / source / "document.txt").read_bytes() == payload
    assert (
        absolute_target / "sentinel.txt"
    ).read_bytes() == b"must-not-overwrite"
    assert not (absolute_target / "document.txt").exists()
    assert s3g_lab.operation_ledger.head.unresolved_transaction_ids == ()


def test_quarantine_pre_rename_crash_recovers_abort_once(
    s3g_lab: _S3GLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id = "RUN-S3G-CRASH-ABORT"
    job_id = "JOB-S3G-CRASH-ABORT"
    operation_id = "OP-S3G-CRASH-ABORT"
    (
        operation,
        observed,
        token,
        source,
        target,
        manifest,
        payload,
    ) = _prepare_internal_quarantine(
        s3g_lab,
        run_id=run_id,
        job_id=job_id,
        operation_id=operation_id,
    )

    def fail_before_rename(
        _writer: _WindowsHandleWriter,
        _source: object,
        _target: object,
    ) -> None:
        raise HandleWriterError(
            HandleWriterCode.RENAME_FAILED,
            "synthetic quarantine pre-rename crash boundary",
        )

    monkeypatch.setattr(
        _WindowsHandleWriter,
        "_after_directory_publish_prepared",
        fail_before_rename,
    )
    with pytest.raises(JobOperationError) as captured:
        with operation:
            operation.execute_quarantine_pair(token, observed)

    assert captured.value.code is JobOperationCode.PUBLISH_FAILED
    assert (s3g_lab.project / source / "document.txt").read_bytes() == payload
    assert not (s3g_lab.project / target).exists()

    reopened = _reopen_s3g_lab(s3g_lab)
    transaction_id = reopened.operation_ledger.head.unresolved_transaction_ids[0]
    recovered = _reconcile_test_publish_operation(
        reopened.bundle,
        reopened.operation_ledger,
        transaction_id,
        JobResourceBudget.conservative_test_default(),
    )
    assert recovered.state is OperationState.RECOVERED_ABORT
    assert reopened.operation_ledger.head.unresolved_transaction_ids == ()
    segment_count = reopened.operation_ledger.head.segment_count
    repeated = _reconcile_test_publish_operation(
        reopened.bundle,
        reopened.operation_ledger,
        transaction_id,
        JobResourceBudget.conservative_test_default(),
    )
    assert repeated == recovered
    assert reopened.operation_ledger.head.segment_count == segment_count
    assert (s3g_lab.project / source / "document.txt").read_bytes() == payload
    assert not (s3g_lab.project / target).exists()

    replay_context = _quarantine_context(
        reopened,
        run_id=run_id,
        job_id=job_id,
        operation_id=operation_id,
        manifest_id=manifest.manifest_id,
    )
    with pytest.raises(JobOperationError) as replay_failure:
        reopened.runtime.replay_committed_quarantine(
            replay_context,
            manifest,
            JobResourceBudget.conservative_test_default(),
        )
    assert replay_failure.value.code is JobOperationCode.PUBLISH_UNAVAILABLE


def test_quarantine_post_rename_crash_recovers_commit_and_replays(
    s3g_lab: _S3GLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id = "RUN-S3G-CRASH-COMMIT"
    job_id = "JOB-S3G-CRASH-COMMIT"
    operation_id = "OP-S3G-CRASH-COMMIT"
    (
        operation,
        observed,
        token,
        source,
        target,
        manifest,
        payload,
    ) = _prepare_internal_quarantine(
        s3g_lab,
        run_id=run_id,
        job_id=job_id,
        operation_id=operation_id,
    )

    def fail_after_rename(
        _writer: _WindowsHandleWriter,
        _source: object,
        _target: object,
    ) -> None:
        raise HandleWriterError(
            HandleWriterCode.RENAME_FAILED,
            "synthetic quarantine post-rename crash boundary",
        )

    monkeypatch.setattr(
        _WindowsHandleWriter,
        "_after_directory_publish_renamed",
        fail_after_rename,
    )
    with pytest.raises(JobOperationError) as captured:
        with operation:
            operation.execute_quarantine_pair(token, observed)

    assert captured.value.code is JobOperationCode.PUBLISH_FAILED
    assert not (s3g_lab.project / source).exists()
    assert (s3g_lab.project / target / "document.txt").read_bytes() == payload

    reopened = _reopen_s3g_lab(s3g_lab)
    transaction_id = reopened.operation_ledger.head.unresolved_transaction_ids[0]
    recovered = _reconcile_test_publish_operation(
        reopened.bundle,
        reopened.operation_ledger,
        transaction_id,
        JobResourceBudget.conservative_test_default(),
    )
    assert recovered.state is OperationState.RECOVERED_COMMIT
    assert reopened.operation_ledger.head.unresolved_transaction_ids == ()
    replay_context = _quarantine_context(
        reopened,
        run_id=run_id,
        job_id=job_id,
        operation_id=operation_id,
        manifest_id=manifest.manifest_id,
    )
    replay = reopened.runtime.replay_committed_quarantine(
        replay_context,
        manifest,
        JobResourceBudget.conservative_test_default(),
    )
    assert Path(replay.quarantine_locator) == target
    assert replay.committed_sequence == recovered.sequence
    assert (s3g_lab.project / target / "document.txt").read_bytes() == payload


def test_restricted_quarantine_post_rename_recovery_uses_opaque_capability(
    s3g_lab: _S3GLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id = "RUN-S3G-RESTRICTED-RECOVERY"
    job_id = "JOB-S3G-RESTRICTED-RECOVERY"
    operation_id = "OP-S3G-RESTRICTED-RECOVERY"
    manifest_id = "MANIFEST-S3G-RESTRICTED-RECOVERY"
    copy_id = "COPY-S3G-RESTRICTED-RECOVERY"
    payload = b"restricted-recovery-payload"
    operation, observed, token, source, target, manifest = (
        _prepare_restricted_quarantine(
            s3g_lab,
            run_id=run_id,
            job_id=job_id,
            operation_id=operation_id,
            manifest_id=manifest_id,
            copy_id=copy_id,
            payload=payload,
        )
    )

    def fail_after_rename(
        _writer: _WindowsHandleWriter,
        _source: object,
        _target: object,
    ) -> None:
        raise HandleWriterError(
            HandleWriterCode.RENAME_FAILED,
            "synthetic restricted quarantine post-rename crash boundary",
        )

    monkeypatch.setattr(
        _WindowsHandleWriter,
        "_after_directory_publish_renamed",
        fail_after_rename,
    )
    with pytest.raises(JobOperationError):
        with operation:
            operation.execute_quarantine_pair(token, observed)

    assert not (s3g_lab.project / source).exists()
    assert (s3g_lab.project / target / "document.txt").read_bytes() == payload
    reopened = _reopen_s3g_lab(s3g_lab)
    transaction_id = reopened.operation_ledger.head.unresolved_transaction_ids[0]
    recovery_context = _quarantine_context(
        reopened,
        run_id=run_id,
        job_id=job_id,
        operation_id=operation_id,
        manifest_id=manifest.manifest_id,
        classification=DataClassification.RESTRICTED,
        copy_id=copy_id,
    )
    transition = reopened.operation_ledger._transaction_history[
        transaction_id
    ][-1]
    assert transition.pair_id == target.name
    with pytest.raises(ProductionBoundaryError):
        reopened.bundle.boundary._issue_restricted_recovery_locator(
            recovery_context,
            transaction_id,
            quarantine_pair_id="20260230" + "A" * 24,
        )
    locator = reopened.bundle.boundary._issue_restricted_recovery_locator(
        recovery_context,
        transaction_id,
        quarantine_pair_id=transition.pair_id,
    )
    recovered = _reconcile_test_publish_operation(
        reopened.bundle,
        reopened.operation_ledger,
        transaction_id,
        JobResourceBudget.conservative_test_default(),
        restricted_locator_capability=locator,
    )
    assert reopened.bundle.boundary.release_context(recovery_context)
    assert recovered.state is OperationState.RECOVERED_COMMIT
    assert reopened.operation_ledger.head.unresolved_transaction_ids == ()
    rendered_segments = "".join(
        path.read_text(encoding="ascii")
        for path in (
            s3g_lab.project
            / "logs"
            / "operations"
            / "segments"
            / "RUN-S3G-OPERATIONS"
        ).glob("*.json")
    )
    assert copy_id not in rendered_segments
    assert (s3g_lab.project / target / "document.txt").read_bytes() == payload


def test_retained_restore_keeps_quarantine_and_publishes_exact_clone(
    s3g_lab: _S3GLab,
) -> None:
    quarantine_receipt, manifest, payload = _quarantine_internal_source(s3g_lab)
    quarantine_relative = Path(quarantine_receipt.quarantine_locator)
    quarantine = s3g_lab.project / quarantine_relative
    state_id = "STATE-S3G-RESTORED"
    context = _restore_context(
        s3g_lab,
        run_id="RUN-S3G-RESTORE",
        job_id="JOB-S3G-RESTORE",
        operation_id="OP-S3G-RESTORE",
        manifest_id=manifest.manifest_id,
        state_id=state_id,
    )
    operation = s3g_lab.runtime.begin_operation(
        context,
        manifest,
        JobResourceBudget.conservative_test_default(),
    )
    with operation:
        prepared = operation.prepare_retained_restore(quarantine_relative)
        with pytest.raises(OSError):
            (quarantine / "document.txt").write_bytes(b"blocked-during-restore")
        token = operation.authorize_retained_restore(
            prepared,
            Path("data") / "snapshots" / state_id,
            checkpoint_manifest_sha256=_sha(b"s3g-restore-checkpoint"),
        )
        receipt = operation.execute_retained_restore_pair(token, prepared)

    assert type(receipt) is RetainedRestoreOperationReceipt
    assert receipt.retained_source_locator == quarantine_relative.as_posix()
    assert receipt.retained_source_manifest_sha256 == manifest.manifest_sha256
    assert (quarantine / "document.txt").read_bytes() == payload
    assert (
        s3g_lab.project
        / "data"
        / "snapshots"
        / state_id
        / "document.txt"
    ).read_bytes() == payload


def test_restore_conflict_never_overwrites_and_new_operation_can_recover(
    s3g_lab: _S3GLab,
) -> None:
    quarantine_receipt, manifest, payload = _quarantine_internal_source(s3g_lab)
    quarantine_relative = Path(quarantine_receipt.quarantine_locator)
    conflict_id = "STATE-S3G-CONFLICT"
    conflict = s3g_lab.project / "data" / "snapshots" / conflict_id
    conflict.mkdir()
    (conflict / "sentinel.txt").write_bytes(b"must-not-overwrite")

    context = _restore_context(
        s3g_lab,
        run_id="RUN-S3G-RESTORE-CONFLICT",
        job_id="JOB-S3G-RESTORE-CONFLICT",
        operation_id="OP-S3G-RESTORE-CONFLICT",
        manifest_id=manifest.manifest_id,
        state_id=conflict_id,
    )
    operation = s3g_lab.runtime.begin_operation(
        context,
        manifest,
        JobResourceBudget.conservative_test_default(),
    )
    with pytest.raises(ProductionBoundaryError):
        with operation:
            prepared = operation.prepare_retained_restore(quarantine_relative)
            operation.authorize_retained_restore(
                prepared,
                Path("data") / "snapshots" / conflict_id,
                checkpoint_manifest_sha256=_sha(b"s3g-conflict-checkpoint"),
            )
    assert (conflict / "sentinel.txt").read_bytes() == b"must-not-overwrite"
    assert not (conflict / "document.txt").exists()
    assert (
        s3g_lab.project / quarantine_relative / "document.txt"
    ).read_bytes() == payload

    recovered_id = "STATE-S3G-CONFLICT-RECOVERED"
    recovered_context = _restore_context(
        s3g_lab,
        run_id="RUN-S3G-RESTORE-RECOVERED",
        job_id="JOB-S3G-RESTORE-RECOVERED",
        operation_id="OP-S3G-RESTORE-RECOVERED",
        manifest_id=manifest.manifest_id,
        state_id=recovered_id,
    )
    recovered_operation = s3g_lab.runtime.begin_operation(
        recovered_context,
        manifest,
        JobResourceBudget.conservative_test_default(),
    )
    with recovered_operation:
        prepared = recovered_operation.prepare_retained_restore(
            quarantine_relative
        )
        token = recovered_operation.authorize_retained_restore(
            prepared,
            Path("data") / "snapshots" / recovered_id,
            checkpoint_manifest_sha256=_sha(b"s3g-recovered-checkpoint"),
        )
        recovered_operation.execute_retained_restore_pair(token, prepared)
    assert (
        s3g_lab.project
        / "data"
        / "snapshots"
        / recovered_id
        / "document.txt"
    ).read_bytes() == payload
    assert (
        s3g_lab.project / quarantine_relative / "document.txt"
    ).read_bytes() == payload


@pytest.mark.parametrize(
    ("case_id", "source"),
    (
        ("ABSOLUTE", "C:/outside/quarantine"),
        (
            "TRAVERSAL",
            "data/quarantine/INTERNAL/2026-07-24/../"
            + "A" * 32,
        ),
        (
            "RESTRICTED",
            "data/quarantine/RESTRICTED/2026-07-24/"
            + "A" * 32,
        ),
        (
            "BAD-DATE",
            "data/quarantine/INTERNAL/2026-7-24/"
            + "A" * 32,
        ),
        (
            "LOWERCASE-ID",
            "data/quarantine/INTERNAL/2026-07-24/"
            + "a" * 32,
        ),
        (
            "ADS",
            "data/quarantine/INTERNAL/2026-07-24/"
            + "A" * 32
            + ":stream",
        ),
        (
            "CHILD",
            "data/quarantine/INTERNAL/2026-07-24/"
            + "A" * 32
            + "/document.txt",
        ),
    ),
)
def test_retained_restore_rejects_noncanonical_quarantine_paths(
    s3g_lab: _S3GLab,
    case_id: str,
    source: str,
) -> None:
    manifest = _manifest(
        manifest_id=f"MANIFEST-S3G-PATH-{case_id}",
    )
    context = _restore_context(
        s3g_lab,
        run_id=f"RUN-S3G-PATH-{case_id}",
        job_id=f"JOB-S3G-PATH-{case_id}",
        operation_id=f"OP-S3G-PATH-{case_id}",
        manifest_id=manifest.manifest_id,
        state_id=f"STATE-S3G-PATH-{case_id}",
    )
    operation = s3g_lab.runtime.begin_operation(
        context,
        manifest,
        JobResourceBudget.conservative_test_default(),
    )
    with operation:
        with pytest.raises(JobOperationError) as captured:
            operation.prepare_retained_restore(source)
    assert captured.value.code is JobOperationCode.INVALID_REQUEST
