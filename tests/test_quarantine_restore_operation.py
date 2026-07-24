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
    JobResourceBudget,
    QuarantineOperationReceipt,
    RetainedRestoreOperationReceipt,
)
from app.safety.operation_ledger import OperationLocatorMode
from app.safety.production_guard import (
    ProductionBoundaryError,
    _create_test_durable_boundary,
    _create_test_job_runtime,
    _create_test_operation_ledger,
)
from app.safety.windows_handle_writer import TreeEntryKind


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
    (
        project
        / "data"
        / "quarantine"
        / "INTERNAL"
        / quarantine_date
    ).mkdir(parents=True)
    (
        project
        / "data"
        / "quarantine"
        / "RESTRICTED"
        / quarantine_date
    ).mkdir(parents=True)
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


def _quarantine_internal_source(
    lab: _S3GLab,
    *,
    job_id: str = "JOB-S3G-QUARANTINE",
    operation_id: str = "OP-S3G-QUARANTINE",
) -> tuple[QuarantineOperationReceipt, DeclaredTreeManifest, bytes]:
    payload = b"quarantine-content"
    manifest = _manifest(payload=payload)
    source = _create_internal_source(
        lab,
        job_id=job_id,
        manifest_id=manifest.manifest_id,
        payload=payload,
    )
    context = _quarantine_context(
        lab,
        run_id="RUN-S3G-QUARANTINE",
        job_id=job_id,
        operation_id=operation_id,
        manifest_id=manifest.manifest_id,
    )
    operation = lab.runtime.begin_operation(
        context,
        manifest,
        JobResourceBudget.conservative_test_default(),
    )
    with operation:
        observed = operation.observe_quarantine_source(source)
        token = operation.authorize_quarantine(
            observed,
            checkpoint_manifest_sha256=_sha(b"s3g-quarantine-checkpoint"),
        )
        receipt = operation.execute_quarantine_pair(token, observed)
    return receipt, manifest, payload


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
    manifest = _manifest(
        manifest_id="MANIFEST-S3G-RESTRICTED",
        payload=payload,
        classification=DataClassification.RESTRICTED,
    )
    copy_id = "COPY-S3G-RESTRICTED"
    source = Path("Copy") / "restricted" / copy_id
    absolute = s3g_lab.project / source
    absolute.mkdir(parents=True)
    (absolute / "document.txt").write_bytes(payload)
    context = _quarantine_context(
        s3g_lab,
        run_id="RUN-S3G-RESTRICTED",
        job_id="JOB-S3G-RESTRICTED",
        operation_id="OP-S3G-RESTRICTED",
        manifest_id=manifest.manifest_id,
        classification=DataClassification.RESTRICTED,
        copy_id=copy_id,
    )
    operation = s3g_lab.runtime.begin_operation(
        context,
        manifest,
        JobResourceBudget.conservative_test_default(),
    )
    with operation:
        observed = operation.observe_quarantine_source(source)
        token = operation.authorize_quarantine(
            observed,
            checkpoint_manifest_sha256=_sha(b"s3g-restricted-checkpoint"),
        )
        receipt = operation.execute_quarantine_pair(token, observed)

    assert receipt.locator_mode is OperationLocatorMode.HMAC_ONLY
    assert receipt.classification is DataClassification.RESTRICTED
    assert len(receipt.quarantine_locator) == 64
    assert copy_id not in receipt.quarantine_locator
    assert copy_id not in repr(receipt)
    targets = list(
        (
            s3g_lab.project
            / "data"
            / "quarantine"
            / "RESTRICTED"
            / s3g_lab.quarantine_date
        ).iterdir()
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
