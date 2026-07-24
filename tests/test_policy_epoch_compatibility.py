from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import replace
from pathlib import Path
from typing import Iterator

import pytest

import app.safety.operation_ledger as operation_ledger_module
import app.safety.segment_ledger as segment_ledger_module
from app.safety.audit_events import (
    AuditAction,
    AuditDecision,
    CapabilityKind,
    create_audit_event,
)
from app.safety.context import (
    Caller,
    DataClassification,
    OperationContext,
    Purpose,
    ScopeId,
    ScopeKind,
)
from app.safety.copy_ledger import (
    CopyFileEvidence,
    CopyLedgerCode,
    CopyLedgerError,
    CopyLocator,
    CopyLocatorMode,
    CopyPublishOperationPlan,
    CopyPublishPlanKind,
    CopySourceReceipt,
    CopySourceRecord,
    CopyState,
    CopyTransition,
    DurableCopyLedgers,
    build_copy_provenance_material,
    _derive_copy_ledger_epoch_id,
)
from app.safety.external_source import SYNTHETIC_REFERENCE_POLICY_DIGEST
from app.safety.namespace_policy import AuditPathMode, NamespaceId
from app.safety.operation_ledger import (
    RECOVERY_GUARANTEE_SCOPE,
    DurableOperationLedger,
    OperationLedgerCode,
    OperationLedgerError,
    OperationLocatorMode,
    OperationLocatorRole,
    OperationState,
    OperationTransition,
    OperationTreeEvidence,
)
from app.safety.production_guard import (
    BoundaryErrorCode,
    ProductionBoundaryError,
    _create_test_durable_boundary,
    _create_test_copy_ledgers,
    _create_test_handle_writer,
    _create_test_operation_ledger,
)
from app.safety.segment_ledger import (
    AuditKeyRevision,
    AuditKeyRevisionStore,
    DurableAuditLedger,
    LedgerCode,
    LedgerError,
    _LEDGER_CONSTRUCTOR,
    canonical_json_bytes,
)
from app.safety.windows_handle_writer import RuntimeMutexLease
from app.workspace_guard import ExpectedKind, PathIntent


_V7_POLICY_ID = "LOCAL-EXAM-BANK-WORKSPACE"
_V7_POLICY_VERSION = "M0-S3-V7"
_V7_POLICY_DIGEST = (
    "8df50ded63443c3310603614fd6d317234ce026c351870d0488a84dd1cfe4d88"
)
_V8_POLICY_VERSION = "M0-S3-V8"
_V8_POLICY_DIGEST = (
    "1d50da20075216ea7d3b20f68807ffe2cd108e9425a2c1c5ccc33292efe4d6cc"
)


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode("ascii", "strict")).hexdigest()


def _extended_test_host_path(path: Path) -> Path:
    """Return a test-lab-confined host path that can address long segments."""

    normalized = os.path.abspath(os.path.normpath(os.fspath(path)))
    run_root = os.path.abspath(
        os.path.normpath(os.environ["M0_TEST_LAB_ROOT"])
    )
    common = os.path.commonpath((run_root, normalized))
    assert normalized != run_root
    assert os.path.normcase(common) == os.path.normcase(run_root)
    if os.name != "nt":
        return Path(normalized)
    drive, tail = os.path.splitdrive(normalized)
    assert len(drive) == 2 and drive[1] == ":"
    assert tail.startswith("\\") and not tail.startswith("\\\\")
    assert not normalized.casefold().startswith(("\\\\?\\", "\\\\.\\", "\\??\\"))
    return Path("\\\\?\\" + normalized)


def _segment_entries(directory: Path) -> Iterator[Path]:
    for entry in _extended_test_host_path(directory).iterdir():
        yield directory / entry.name


def _write_segment(
    directory: Path,
    sequence: int,
    segment_sha256: str,
    payload: bytes,
) -> Path:
    target = directory / f"{sequence:020d}-{segment_sha256}.json"
    _extended_test_host_path(target).write_bytes(payload)
    return target


def _legacy_audit_event(revision: AuditKeyRevision, *, index: int):
    context = OperationContext(
        run_id="RUN-POLICY-COMPAT",
        job_id="JOB-POLICY-COMPAT",
        operation_id=f"OP-POLICY-COMPAT-{index:04d}",
        caller=Caller.AUDIT_SERVICE,
        purpose=Purpose.APPEND_AUDIT,
        classification=DataClassification.INTERNAL,
    )
    event = create_audit_event(
        decision=AuditDecision.CANDIDATE_ALLOW,
        action=AuditAction.ISSUE,
        capability_kind=CapabilityKind.SINGLE,
        error_code=None,
        context=context,
        effective_classification=DataClassification.INTERNAL,
        path_mode=AuditPathMode.RELATIVE,
        policy_digest=_V7_POLICY_DIGEST,
        boundary_instance_id="BOUNDARY-POLICY-COMPAT",
        ticket_id=f"TICKET-POLICY-COMPAT-{index:04d}",
        pair_id=None,
        pair_role=None,
        namespace=NamespaceId.AUDIT_LOG,
        intent=PathIntent.EXISTING_READ,
        expected_kind=ExpectedKind.FILE,
        relative_path=Path("safe") / f"record-{index:04d}.json",
        audit_hmac_key=revision.audit_hmac_key,
    )
    return replace(
        event,
        event_id=f"EVENT-POLICY-COMPAT-{index:04d}",
        occurred_at_utc=f"2026-07-13T00:01:{index:02d}Z",
        policy_id=_V7_POLICY_ID,
        policy_version=_V7_POLICY_VERSION,
        policy_digest=_V7_POLICY_DIGEST,
    )


def _operation_evidence(label: str) -> OperationTreeEvidence:
    return OperationTreeEvidence(
        manifest_sha256=_sha(f"{label}-manifest"),
        source_tree_sha256=_sha(f"{label}-tree"),
        topology_sha256=_sha(f"{label}-topology"),
        durable_identity_sha256=_sha(f"{label}-identity"),
        entry_count=1,
        total_bytes=17,
    )


def _prepared_transition(
    *,
    suffix: str,
    audit_head: str,
    classification: DataClassification = DataClassification.INTERNAL,
) -> OperationTransition:
    evidence = _operation_evidence(suffix)
    restricted = classification is DataClassification.RESTRICTED
    return OperationTransition(
        transition_id=f"TRANSITION-{suffix}-PREPARED",
        transaction_id=f"TRANSACTION-{suffix}",
        operation_id=f"OPERATION-{suffix}",
        pair_id=f"PAIR-{suffix}",
        previous_state=None,
        next_state=OperationState.PREPARED,
        context_binding_sha256=_sha(f"{suffix}-context"),
        manifest_sha256=evidence.manifest_sha256,
        budget_sha256=_sha(f"{suffix}-budget"),
        source_locator=(
            _sha(f"{suffix}-source-locator")
            if restricted
            else f"tmp/jobs/internal/{suffix.lower()}/publish"
        ),
        target_locator=(
            _sha(f"{suffix}-target-locator")
            if restricted
            else f"data/exports/{suffix.lower()}"
        ),
        source_evidence=evidence,
        target_evidence=None,
        audit_ledger_head_sha256=audit_head,
        mutation_attempted=False,
        locator_mode=(
            OperationLocatorMode.HMAC_ONLY
            if restricted
            else OperationLocatorMode.SAFE_RELATIVE
        ),
        classification=classification,
    )


def _operation_segment_bytes(
    *,
    revision: AuditKeyRevision,
    epoch_id: str,
    sequence: int,
    previous_segment_sha256: str | None,
    created_at_utc: str,
    policy_digest: str,
    schema_version: str,
    transition: OperationTransition | None,
) -> tuple[bytes, str]:
    operation_key = hmac.new(
        revision.segment_hmac_key,
        b"OPERATION-SEGMENT-AUTH-V1\0",
        hashlib.sha256,
    ).digest()
    operation_key_id = hashlib.sha256(
        b"OPERATION-KEY-ID-V1\0" + operation_key
    ).hexdigest()
    body = {
        "created_at_utc": created_at_utc,
        "epoch_id": epoch_id,
        "key_id": operation_key_id,
        "key_revision_id": revision.revision_id,
        "key_revision_sha256": revision.revision_sha256,
        "ledger_id": "OPERATION",
        "policy_digest": policy_digest,
        "previous_segment_sha256": previous_segment_sha256,
        "schema_id": "M0-OPERATION-SEGMENT",
        "schema_version": schema_version,
        "segment_kind": (
            "GENESIS" if transition is None else "OPERATION_TRANSITION"
        ),
        "sequence": sequence,
        "transition": None if transition is None else transition.to_json(),
        "transition_sha256": None if transition is None else transition.digest,
    }
    body_bytes = canonical_json_bytes(body)
    segment_sha256 = hashlib.sha256(
        b"OPERATION-SEGMENT-V1\0" + body_bytes
    ).hexdigest()
    envelope = dict(body)
    envelope["segment_hmac_sha256"] = hmac.new(
        operation_key,
        b"OPERATION-SEGMENT-V1\0" + body_bytes,
        hashlib.sha256,
    ).hexdigest()
    envelope["segment_sha256"] = segment_sha256
    return canonical_json_bytes(envelope), segment_sha256


def _copy_epoch_directories(
    project: Path,
    revision: AuditKeyRevision,
    run_scope_id: str,
) -> tuple[str, Path, Path]:
    epoch_id = _derive_copy_ledger_epoch_id(revision, run_scope_id)
    return (
        epoch_id,
        project / "Copy" / "ledger" / "source" / "segments" / epoch_id,
        project / "Copy" / "ledger" / "copy" / "segments" / epoch_id,
    )


def _create_copy_epoch_directories(
    project: Path,
    revision: AuditKeyRevision,
    run_scope_id: str,
) -> tuple[str, Path, Path]:
    epoch_id, source_directory, copy_directory = _copy_epoch_directories(
        project,
        revision,
        run_scope_id,
    )
    source_directory.mkdir(parents=True)
    copy_directory.mkdir(parents=True)
    return epoch_id, source_directory, copy_directory


def _copy_epoch_snapshot(
    project: Path,
    source_directory: Path,
    copy_directory: Path,
) -> tuple[tuple[Path, bytes], ...]:
    return tuple(
        sorted(
            (
                path.relative_to(project),
                _extended_test_host_path(path).read_bytes(),
            )
            for directory in (source_directory, copy_directory)
            for path in _segment_entries(directory)
        )
    )


def _initialize_operation_epoch(
    project: Path,
    bundle: object,
    epoch_id: str,
    created_at_utc: str,
):
    (project / "logs" / "operations" / "segments" / epoch_id).mkdir(
        parents=True
    )
    return _create_test_operation_ledger(
        bundle,
        epoch_id=epoch_id,
        initialize=True,
        initialized_at_utc=created_at_utc,
    )


def _copy_source_record(label: str, audit_head: str) -> CopySourceRecord:
    payload = f"copy-rotation-{label}".encode("ascii", "strict")
    return CopySourceRecord(
        record_id=_sha(f"{label}-record"),
        transaction_binding_sha256=_sha(f"{label}-transaction"),
        copy_binding_sha256=_sha(f"{label}-copy"),
        reference_policy_digest=SYNTHETIC_REFERENCE_POLICY_DIGEST,
        audit_ancestor_sha256=audit_head,
        classification=DataClassification.INTERNAL,
        source_locator=CopyLocator(
            CopyLocatorMode.HMAC_ONLY,
            _sha(f"{label}-source-locator"),
        ),
        source_evidence=CopyFileEvidence(
            identity_hmac_sha256=_sha(f"{label}-source-identity"),
            size_bytes=len(payload),
            sha256=hashlib.sha256(payload).hexdigest(),
            change_evidence_sha256=_sha(f"{label}-source-change"),
        ),
    )


def _copy_recovered_abort(
    label: str,
    copy_ledgers: DurableCopyLedgers,
    operation_ledger: DurableOperationLedger,
    lease: RuntimeMutexLease,
    source: CopySourceRecord,
    receipt: CopySourceReceipt,
    recovery_head: str,
) -> CopyTransition:
    manifest_id = f"MANIFEST-{label.upper()}-SOURCE-ONLY-RECOVERY"
    material = build_copy_provenance_material(
        source,
        receipt,
        manifest_id=manifest_id,
    )
    source_relative = f"tmp/jobs/internal/{label}/publish/{manifest_id}"
    target_relative = f"Copy/source/{label.upper()}"
    target_locator = copy_ledgers.target_locator(
        target_relative,
        source.classification,
    )
    operation_reference = operation_ledger.operation_reference(
        f"OPERATION-{label.upper()}-PUBLISH",
        source.classification,
    )
    plan = copy_ledgers._project_publish_operation_plan(
        kind=CopyPublishPlanKind.UNSTARTED,
        operation_reference=operation_reference,
        context_binding_sha256=_sha(f"{label}-publish-context"),
        manifest_sha256=material.publish_manifest.manifest_sha256,
        budget_sha256=_sha(f"{label}-budget"),
        classification=source.classification,
    )
    publish_binding = copy_ledgers.publish_operation_binding(
        plan=plan,
        operation_reference=operation_reference,
        publish_transaction_id=None,
        transaction_binding_sha256=source.transaction_binding_sha256,
        copy_binding_sha256=source.copy_binding_sha256,
        source_anchor=receipt.anchor,
        copy_audit_ancestor_sha256=source.audit_ancestor_sha256,
        target_locator=target_locator,
        source_relative_locator=source_relative,
        target_relative_locator=target_relative,
        operation_ledger=operation_ledger,
    )
    absence_witness = (
        copy_ledgers._issue_operation_absence_witness_under_existing_mutex(
            lease,
            operation_ledger,
            plan=plan,
            operation_reference=operation_reference,
            publish_transaction_id=None,
            transaction_binding_sha256=source.transaction_binding_sha256,
            copy_binding_sha256=source.copy_binding_sha256,
            source_anchor=receipt.anchor,
            copy_audit_ancestor_sha256=source.audit_ancestor_sha256,
            target_locator=target_locator,
            source_relative_locator=source_relative,
            target_relative_locator=target_relative,
            publish_operation_binding_sha256=publish_binding,
        )
    )
    return CopyTransition(
        transition_id=_sha(f"{label}-recovered-abort"),
        transaction_binding_sha256=source.transaction_binding_sha256,
        copy_binding_sha256=source.copy_binding_sha256,
        previous_state=None,
        next_state=CopyState.RECOVERED_ABORT,
        source_anchor=receipt.anchor,
        audit_ancestor_sha256=source.audit_ancestor_sha256,
        classification=source.classification,
        target_locator=target_locator,
        expected_manifest_sha256=material.publish_manifest.manifest_sha256,
        provenance_metadata_sha256=material.provenance_sha256,
        budget_sha256=plan.budget_sha256,
        publish_operation_binding_sha256=publish_binding,
        publish_operation_plan=plan,
        mutation_attempted=False,
        publish_transaction_id=None,
        publish_operation_absence_witness=absence_witness,
        recovery_reason="PUBLISH_NOT_NATIVE_TARGET_ABSENT_SOURCE_EXACT",
        recovery_authority_head_sha256=recovery_head,
    )


def _activate_next_revision(
    bundle: object,
    *,
    revision_id: str,
    rotation_id: str,
    master_key: bytes,
    created_at_utc: str,
    rotated_at_utc: str,
) -> AuditKeyRevision:
    current = bundle.ledger._active_revision()
    revision = bundle.key_store.create_revision(
        revision_sequence=current.revision_sequence + 1,
        revision_id=revision_id,
        master_key=master_key,
        created_at_utc=created_at_utc,
    )
    bundle.ledger.rotate_key(
        next_revision_id=revision.revision_id,
        rotation_id=rotation_id,
        created_at_utc=rotated_at_utc,
    )
    return revision


def _activate_second_revision(
    bundle: object,
    *,
    suffix: str,
    created_at_utc: str,
    rotated_at_utc: str,
) -> AuditKeyRevision:
    return _activate_next_revision(
        bundle,
        revision_id=f"KEYREV-{suffix}-TWO",
        rotation_id=f"ROTATION-{suffix}-ONE-TO-TWO",
        master_key=b"R" * 32,
        created_at_utc=created_at_utc,
        rotated_at_utc=rotated_at_utc,
    )


@pytest.fixture
def compat_project(request: pytest.FixtureRequest) -> Path:
    run_root = Path(os.environ["M0_TEST_LAB_ROOT"])
    workspace_id = hashlib.sha256(
        request.node.nodeid.encode("utf-8", "strict")
    ).hexdigest()[:8]
    project = run_root / f"p{workspace_id}" / "project"
    project.mkdir(parents=True)
    return project


def _create_boundary(project: Path, *, suffix: str):
    audit_epoch = f"RUN-{suffix}-AUDIT"
    (project / "logs" / "audit" / "keys").mkdir(parents=True)
    (project / "logs" / "audit" / "segments" / audit_epoch).mkdir(parents=True)
    bundle = _create_test_durable_boundary(
        project,
        initialize=True,
        epoch_id=audit_epoch,
        initial_revision_sequence=1,
        initial_revision_id=f"KEYREV-{suffix}",
        master_key=suffix.encode("ascii", "strict")[:1] * 32,
        key_created_at_utc="2026-07-13T00:00:00Z",
        ledger_initialized_at_utc="2026-07-13T00:00:01Z",
    )
    return project, bundle


def _create_v7_boundary(project: Path, *, suffix: str):
    audit_epoch = f"RUN-{suffix}-AUDIT-V7"
    segment_directory = project / "logs" / "audit" / "segments" / audit_epoch
    (project / "logs" / "audit" / "keys").mkdir(parents=True)
    segment_directory.mkdir(parents=True)
    writer = _create_test_handle_writer(project)
    key_store = AuditKeyRevisionStore(writer, _constructor=_LEDGER_CONSTRUCTOR)
    revision_id = f"KEYREV-{suffix}"
    master_key = suffix.encode("ascii", "strict")[:1] * 32
    revision = key_store.create_revision(
        revision_sequence=1,
        revision_id=revision_id,
        master_key=master_key,
        created_at_utc="2026-07-13T00:00:00Z",
    )
    genesis, genesis_sha, _batch, _records = (
        segment_ledger_module._build_genesis_segment_bytes(
            epoch_id=audit_epoch,
            created_at_utc="2026-07-13T00:00:01Z",
            revision=revision,
            _policy_binding=segment_ledger_module._AUDIT_V7_BINDING,
        )
    )
    event = _legacy_audit_event(revision, index=1)
    audit_batch, audit_sha, _audit_batch_sha, _event_ids = (
        segment_ledger_module.build_audit_segment_bytes(
            epoch_id=audit_epoch,
            sequence=1,
            previous_segment_sha256=genesis_sha,
            created_at_utc="2026-07-13T00:01:01Z",
            revision=revision,
            events=(event,),
            _policy_binding=segment_ledger_module._AUDIT_V7_BINDING,
        )
    )
    _write_segment(segment_directory, 0, genesis_sha, genesis)
    _write_segment(segment_directory, 1, audit_sha, audit_batch)
    bundle = _create_test_durable_boundary(
        project,
        initialize=False,
        epoch_id=audit_epoch,
        initial_revision_sequence=1,
        initial_revision_id=revision_id,
        master_key=master_key,
        key_created_at_utc="2026-07-13T00:00:00Z",
    )
    return project, bundle, revision


def test_reviewed_epoch_registry_matches_frozen_policy_goldens() -> None:
    audit_v7 = segment_ledger_module._AUDIT_V7_BINDING
    audit_v8 = segment_ledger_module._AUDIT_V8_BINDING
    operation_v7 = operation_ledger_module._OPERATION_V7_BINDING
    operation_v8 = operation_ledger_module._OPERATION_V8_BINDING

    assert (
        audit_v7.policy_id,
        audit_v7.policy_version,
        audit_v7.policy_digest,
        audit_v7.schema_version,
        audit_v7.writable,
    ) == (_V7_POLICY_ID, _V7_POLICY_VERSION, _V7_POLICY_DIGEST, "1.0", False)
    assert (
        audit_v8.policy_id,
        audit_v8.policy_version,
        audit_v8.policy_digest,
        audit_v8.schema_version,
        audit_v8.writable,
    ) == (_V7_POLICY_ID, _V8_POLICY_VERSION, _V8_POLICY_DIGEST, "1.0", True)
    assert (
        operation_v7.policy_digest,
        operation_v7.schema_version,
        operation_v7.allow_new_transactions,
        operation_v7.allow_recovery_append,
    ) == (_V7_POLICY_DIGEST, "1.0", False, True)
    assert (
        operation_v8.policy_digest,
        operation_v8.schema_version,
        operation_v8.allow_new_transactions,
    ) == (_V8_POLICY_DIGEST, "1.1", True)
    assert "COPY_SOURCE_LEDGER" not in audit_v7.namespace_values
    assert "COPY_OPERATION_LEDGER" not in audit_v7.namespace_values
    assert {
        "COPY_SOURCE_LEDGER",
        "COPY_OPERATION_LEDGER",
    } <= audit_v8.namespace_values
    assert operation_v7.classification_values == frozenset({"INTERNAL"})
    assert operation_v7.locator_mode_values == frozenset({"SAFE_RELATIVE"})
    assert operation_v8.classification_values == frozenset(
        {"INTERNAL", "RESTRICTED"}
    )
    assert tuple(role.value for role in OperationLocatorRole) == ("SOURCE", "TARGET")


def test_operation_schema_1_0_parser_is_internal_safe_relative_only() -> None:
    internal = _prepared_transition(suffix="V7-GOLDEN", audit_head="a" * 64)
    restricted = _prepared_transition(
        suffix="V8-GOLDEN",
        audit_head="b" * 64,
        classification=DataClassification.RESTRICTED,
    )

    assert operation_ledger_module._transition_from_json_v1_0(
        internal.to_json()
    ) == internal
    assert operation_ledger_module._transition_from_json_v1_1(
        restricted.to_json()
    ) == restricted
    with pytest.raises(OperationLedgerError) as captured:
        operation_ledger_module._transition_from_json_v1_0(restricted.to_json())
    assert captured.value.code is OperationLedgerCode.CHAIN_CORRUPT


def test_v7_audit_epoch_reopens_replays_queries_and_rejects_new_writes(
    compat_project: Path,
) -> None:
    project = compat_project
    epoch_id = "RUN-AUDIT-V7-COMPAT"
    segment_directory = project / "logs" / "audit" / "segments" / epoch_id
    (project / "logs" / "audit" / "keys").mkdir(parents=True)
    segment_directory.mkdir(parents=True)
    writer = _create_test_handle_writer(project)
    key_store = AuditKeyRevisionStore(writer, _constructor=_LEDGER_CONSTRUCTOR)
    revision = key_store.create_revision(
        revision_sequence=1,
        revision_id="KEYREV-AUDIT-V7",
        master_key=b"L" * 32,
        created_at_utc="2026-07-13T00:00:00Z",
    )
    genesis, genesis_sha, _batch, _records = (
        segment_ledger_module._build_genesis_segment_bytes(
            epoch_id=epoch_id,
            created_at_utc="2026-07-13T00:00:01Z",
            revision=revision,
            _policy_binding=segment_ledger_module._AUDIT_V7_BINDING,
        )
    )
    event = _legacy_audit_event(revision, index=1)
    batch, batch_sha, _audit_batch, _event_ids = (
        segment_ledger_module.build_audit_segment_bytes(
            epoch_id=epoch_id,
            sequence=1,
            previous_segment_sha256=genesis_sha,
            created_at_utc="2026-07-13T00:01:01Z",
            revision=revision,
            events=(event,),
            _policy_binding=segment_ledger_module._AUDIT_V7_BINDING,
        )
    )
    _write_segment(segment_directory, 0, genesis_sha, genesis)
    _write_segment(segment_directory, 1, batch_sha, batch)

    ledger = DurableAuditLedger(
        writer,
        key_store,
        epoch_id=epoch_id,
        initial_revision_id=revision.revision_id,
        _constructor=_LEDGER_CONSTRUCTOR,
    )
    before = tuple(sorted(path.name for path in _segment_entries(segment_directory)))
    assert ledger.policy_version == _V7_POLICY_VERSION
    assert ledger.is_read_only_epoch is True
    assert ledger.append_audit_batch((event,)).replayed is True
    with writer.acquire_runtime_mutex() as lease:
        assert ledger.authenticated_segment_sha256s_under_existing_mutex(lease) == (
            genesis_sha,
            batch_sha,
        )
    with pytest.raises(LedgerError) as append_error:
        ledger.append_audit_batch((_legacy_audit_event(revision, index=2),))
    assert append_error.value.code is LedgerCode.READ_ONLY_EPOCH

    key_store.create_revision(
        revision_sequence=2,
        revision_id="KEYREV-AUDIT-V7-TWO",
        master_key=b"M" * 32,
        created_at_utc="2026-07-13T00:02:00Z",
    )
    with pytest.raises(LedgerError) as rotation_error:
        ledger.rotate_key(
            next_revision_id="KEYREV-AUDIT-V7-TWO",
            rotation_id="ROTATION-AUDIT-V7-DENIED",
            created_at_utc="2026-07-13T00:02:01Z",
        )
    assert rotation_error.value.code is LedgerCode.READ_ONLY_EPOCH
    assert tuple(
        sorted(path.name for path in _segment_entries(segment_directory))
    ) == before


@pytest.mark.parametrize(
    ("namespace", "suffix"),
    (
        (NamespaceId.COPY_SOURCE_LEDGER, "V7-SOURCE-NS"),
        (NamespaceId.COPY_OPERATION_LEDGER, "V7-OPERATION-NS"),
    ),
)
def test_v7_audit_profile_rejects_v8_only_namespace_values(
    compat_project: Path,
    namespace: NamespaceId,
    suffix: str,
) -> None:
    _project, bundle, revision = _create_v7_boundary(compat_project, suffix=suffix)
    event = replace(
        _legacy_audit_event(revision, index=2),
        namespace=namespace,
    )

    with pytest.raises(LedgerError) as captured:
        segment_ledger_module.build_audit_segment_bytes(
            epoch_id=bundle.ledger.head.epoch_id,
            sequence=2,
            previous_segment_sha256=bundle.ledger.head.last_segment_sha256,
            created_at_utc="2026-07-13T00:02:02Z",
            revision=revision,
            events=(event,),
            _policy_binding=segment_ledger_module._AUDIT_V7_BINDING,
        )
    assert captured.value.code is LedgerCode.CHAIN_CORRUPT


def test_audit_epoch_rejects_authenticated_policy_mix(
    compat_project: Path,
) -> None:
    project = compat_project
    epoch_id = "RUN-AUDIT-MIXED"
    segment_directory = project / "logs" / "audit" / "segments" / epoch_id
    (project / "logs" / "audit" / "keys").mkdir(parents=True)
    segment_directory.mkdir(parents=True)
    writer = _create_test_handle_writer(project)
    key_store = AuditKeyRevisionStore(writer, _constructor=_LEDGER_CONSTRUCTOR)
    revision = key_store.create_revision(
        revision_sequence=1,
        revision_id="KEYREV-AUDIT-MIXED",
        master_key=b"N" * 32,
        created_at_utc="2026-07-13T00:00:00Z",
    )
    genesis, genesis_sha, _batch, _records = (
        segment_ledger_module._build_genesis_segment_bytes(
            epoch_id=epoch_id,
            created_at_utc="2026-07-13T00:00:01Z",
            revision=revision,
            _policy_binding=segment_ledger_module._AUDIT_V7_BINDING,
        )
    )
    v8_event = replace(
        _legacy_audit_event(revision, index=3),
        policy_version=_V8_POLICY_VERSION,
        policy_digest=_V8_POLICY_DIGEST,
    )
    mixed, mixed_sha, _mixed_batch, _mixed_records = (
        segment_ledger_module.build_audit_segment_bytes(
            epoch_id=epoch_id,
            sequence=1,
            previous_segment_sha256=genesis_sha,
            created_at_utc="2026-07-13T00:01:03Z",
            revision=revision,
            events=(v8_event,),
            _policy_binding=segment_ledger_module._AUDIT_V8_BINDING,
        )
    )
    _write_segment(segment_directory, 0, genesis_sha, genesis)
    _write_segment(segment_directory, 1, mixed_sha, mixed)

    with pytest.raises(LedgerError) as captured:
        DurableAuditLedger(
            writer,
            key_store,
            epoch_id=epoch_id,
            initial_revision_id=revision.revision_id,
            _constructor=_LEDGER_CONSTRUCTOR,
        )
    assert captured.value.code is LedgerCode.POLICY_MISMATCH


def test_v7_operation_epoch_reopens_replays_recovers_and_rejects_new_transaction(
    compat_project: Path,
) -> None:
    project, bundle, revision = _create_v7_boundary(
        compat_project,
        suffix="OPV7",
    )
    operation_epoch = "RUN-OPV7-OPERATIONS"
    segment_directory = (
        project / "logs" / "operations" / "segments" / operation_epoch
    )
    segment_directory.mkdir(parents=True)
    audit_head = bundle.ledger.head.last_segment_sha256
    prepared = _prepared_transition(suffix="OPV7", audit_head=audit_head)
    genesis, genesis_sha = _operation_segment_bytes(
        revision=revision,
        epoch_id=operation_epoch,
        sequence=0,
        previous_segment_sha256=None,
        created_at_utc="2026-07-13T00:00:02Z",
        policy_digest=_V7_POLICY_DIGEST,
        schema_version="1.0",
        transition=None,
    )
    prepared_payload, prepared_sha = _operation_segment_bytes(
        revision=revision,
        epoch_id=operation_epoch,
        sequence=1,
        previous_segment_sha256=genesis_sha,
        created_at_utc="2026-07-13T00:00:03Z",
        policy_digest=_V7_POLICY_DIGEST,
        schema_version="1.0",
        transition=prepared,
    )
    _write_segment(segment_directory, 0, genesis_sha, genesis)
    _write_segment(segment_directory, 1, prepared_sha, prepared_payload)

    ledger = _create_test_operation_ledger(bundle, epoch_id=operation_epoch)
    assert ledger.policy_digest == _V7_POLICY_DIGEST
    assert ledger.schema_version == "1.0"
    assert ledger.is_read_only_epoch is True
    legacy_volume = 42
    legacy_file_id = b"\x11" * 16
    assert ledger.durable_tree_evidence_identity_digest(
        legacy_volume,
        legacy_file_id,
        None,
    ) == ledger.durable_identity_digest(legacy_volume, legacy_file_id)
    with bundle.writer.acquire_runtime_mutex() as lease:
        assert ledger.authenticated_segment_sha256s_under_existing_mutex(lease) == (
            genesis_sha,
            prepared_sha,
        )
        assert ledger._append_transition_under_existing_mutex(
            lease,
            prepared,
        ).replayed is True
        with pytest.raises(OperationLedgerError) as new_transaction_error:
            ledger._append_transition_under_existing_mutex(
                lease,
                _prepared_transition(suffix="OPV7-NEW", audit_head=audit_head),
            )
        assert (
            new_transaction_error.value.code
            is OperationLedgerCode.READ_ONLY_EPOCH
        )
        recovered = replace(
            prepared,
            transition_id="TRANSITION-OPV7-RECOVERED",
            previous_state=OperationState.PREPARED,
            next_state=OperationState.RECOVERED_ABORT,
            recovery_guarantee_scope=RECOVERY_GUARANTEE_SCOPE,
            recovery_authority_head_sha256=audit_head,
            recovery_reason="SOURCE_EXACT_TARGET_ABSENT",
        )
        receipt = ledger._append_transition_under_existing_mutex(lease, recovered)
        assert receipt.state is OperationState.RECOVERED_ABORT
        result = ledger.transaction_result_under_existing_mutex(
            lease,
            prepared.transaction_id,
        )
        assert result is not None and result[0] == recovered

    reopened = _create_test_operation_ledger(bundle, epoch_id=operation_epoch)
    assert reopened.head.unresolved_transaction_ids == ()
    assert reopened.head.segment_count == 3


def test_v7_audit_epoch_rejects_v8_operation_initialization_before_write(
    compat_project: Path,
) -> None:
    project, bundle, _revision = _create_v7_boundary(
        compat_project,
        suffix="INIT-MIX",
    )
    segment_directory = (
        project / "logs" / "operations" / "segments" / "RUN-INIT-MIX-OPERATIONS"
    )

    with pytest.raises(ProductionBoundaryError) as captured:
        _create_test_operation_ledger(
            bundle,
            epoch_id="RUN-INIT-MIX-OPERATIONS",
            initialize=True,
            initialized_at_utc="2026-07-13T00:02:00Z",
        )
    assert captured.value.code is BoundaryErrorCode.INVALID_ARGUMENT
    assert not segment_directory.exists()


def test_operation_reopen_rejects_cross_policy_audit_epoch(
    compat_project: Path,
) -> None:
    project, bundle = _create_boundary(compat_project, suffix="CROSS-POLICY")
    operation_epoch = "RUN-CROSS-POLICY-OPERATIONS"
    segment_directory = (
        project / "logs" / "operations" / "segments" / operation_epoch
    )
    segment_directory.mkdir(parents=True)
    revision = bundle.key_store.load_all()["KEYREV-CROSS-POLICY"]
    genesis, genesis_sha = _operation_segment_bytes(
        revision=revision,
        epoch_id=operation_epoch,
        sequence=0,
        previous_segment_sha256=None,
        created_at_utc="2026-07-13T00:00:02Z",
        policy_digest=_V7_POLICY_DIGEST,
        schema_version="1.0",
        transition=None,
    )
    _write_segment(segment_directory, 0, genesis_sha, genesis)

    with pytest.raises(OperationLedgerError) as captured:
        _create_test_operation_ledger(bundle, epoch_id=operation_epoch)
    assert captured.value.code is OperationLedgerCode.CHAIN_CORRUPT


def test_new_v8_operation_epoch_writes_schema_1_1_and_restricted_locator(
    compat_project: Path,
) -> None:
    project, bundle = _create_boundary(compat_project, suffix="OPV8")
    operation_epoch = "RUN-OPV8-OPERATIONS"
    segment_directory = (
        project / "logs" / "operations" / "segments" / operation_epoch
    )
    segment_directory.mkdir(parents=True)
    ledger = _create_test_operation_ledger(
        bundle,
        epoch_id=operation_epoch,
        initialize=True,
        initialized_at_utc="2026-07-13T00:00:02Z",
    )
    genesis_path = next(_segment_entries(segment_directory))
    genesis = json.loads(
        _extended_test_host_path(genesis_path).read_text(encoding="ascii")
    )
    assert genesis["schema_version"] == "1.1"
    assert genesis["policy_digest"] == _V8_POLICY_DIGEST
    restricted = _prepared_transition(
        suffix="OPV8-RESTRICTED",
        audit_head=bundle.ledger.head.last_segment_sha256,
        classification=DataClassification.RESTRICTED,
    )
    source_locator = ledger.locator_hmac(
        "tmp/jobs/restricted/opv8-restricted/publish",
        transaction_id=restricted.transaction_id,
        role=OperationLocatorRole.SOURCE,
    )
    target_locator = ledger.locator_hmac(
        "copy/restricted/opv8-restricted",
        transaction_id=restricted.transaction_id,
        role=OperationLocatorRole.TARGET,
    )
    assert source_locator != target_locator
    assert source_locator != ledger.locator_hmac(
        "tmp/jobs/restricted/opv8-restricted/publish",
        transaction_id="TRANSACTION-OPV8-RESTRICTED-OTHER",
        role=OperationLocatorRole.SOURCE,
    )
    assert source_locator != ledger.locator_hmac(
        "tmp/jobs/restricted/opv8-restricted/publish",
        transaction_id=restricted.transaction_id,
        role=OperationLocatorRole.TARGET,
    )
    restricted = replace(
        restricted,
        source_locator=source_locator,
        target_locator=target_locator,
    )
    with pytest.raises(OperationLedgerError) as role_error:
        ledger.locator_hmac(
            "tmp/jobs/restricted/opv8-restricted/publish",
            transaction_id=restricted.transaction_id,
            role="SOURCE",  # type: ignore[arg-type]
        )
    assert role_error.value.code is OperationLedgerCode.INVALID_REQUEST
    with pytest.raises(OperationLedgerError) as transaction_error:
        ledger.locator_hmac(
            "tmp/jobs/restricted/opv8-restricted/publish",
            transaction_id="../not-canonical",
            role=OperationLocatorRole.SOURCE,
        )
    assert transaction_error.value.code is OperationLedgerCode.INVALID_REQUEST
    with bundle.writer.acquire_runtime_mutex() as lease:
        receipt = ledger._append_transition_under_existing_mutex(lease, restricted)
        assert receipt.state is OperationState.PREPARED
        assert len(ledger.authenticated_segment_sha256s_under_existing_mutex(lease)) == 2

    reopened = _create_test_operation_ledger(bundle, epoch_id=operation_epoch)
    assert reopened.schema_version == "1.1"
    assert reopened.is_read_only_epoch is False
    assert reopened._transaction_history[restricted.transaction_id][0] == restricted


@pytest.mark.parametrize(
    ("mixed_policy_digest", "mixed_schema_version"),
    (
        (_V8_POLICY_DIGEST, "1.0"),
        (_V7_POLICY_DIGEST, "1.1"),
    ),
)
def test_operation_epoch_rejects_authenticated_policy_or_schema_mix(
    compat_project: Path,
    mixed_policy_digest: str,
    mixed_schema_version: str,
) -> None:
    project, bundle = _create_boundary(compat_project, suffix="MIXED")
    operation_epoch = "RUN-MIXED-OPERATIONS"
    segment_directory = (
        project / "logs" / "operations" / "segments" / operation_epoch
    )
    segment_directory.mkdir(parents=True)
    ledger = _create_test_operation_ledger(
        bundle,
        epoch_id=operation_epoch,
        initialize=True,
        initialized_at_utc="2026-07-13T00:00:02Z",
    )
    revision = bundle.key_store.load_all()["KEYREV-MIXED"]
    transition = _prepared_transition(
        suffix="MIXED",
        audit_head=bundle.ledger.head.last_segment_sha256,
    )
    payload, segment_sha = _operation_segment_bytes(
        revision=revision,
        epoch_id=operation_epoch,
        sequence=1,
        previous_segment_sha256=ledger.head.last_segment_sha256,
        created_at_utc="2026-07-13T00:00:03Z",
        policy_digest=mixed_policy_digest,
        schema_version=mixed_schema_version,
        transition=transition,
    )
    _write_segment(segment_directory, 1, segment_sha, payload)

    with pytest.raises(OperationLedgerError) as captured:
        _create_test_operation_ledger(bundle, epoch_id=operation_epoch)
    assert captured.value.code is OperationLedgerCode.AUTHENTICATION_FAILED


def test_copy_epoch_factory_and_public_read_require_exact_activated_run_mapping(
    compat_project: Path,
) -> None:
    project, bundle = _create_boundary(compat_project, suffix="COPY-MAP")
    run_scope_id = "RUN-LOGICAL-COPY-MAP"
    active_revision = bundle.ledger._active_revision()
    operation_ledger = _initialize_operation_epoch(
        project,
        bundle,
        "RUN-COPY-MAP-OPERATIONS",
        "2026-07-13T03:00:00Z",
    )
    active_epoch, source_directory, copy_directory = (
        _create_copy_epoch_directories(
            project,
            active_revision,
            run_scope_id,
        )
    )
    unactivated_revision = bundle.key_store.create_revision(
        revision_sequence=2,
        revision_id="KEYREV-COPY-MAP-UNACTIVATED",
        master_key=b"U" * 32,
        created_at_utc="2026-07-13T03:00:01Z",
    )
    unactivated_epoch, unactivated_source, unactivated_copy = (
        _create_copy_epoch_directories(
            project,
            unactivated_revision,
            run_scope_id,
        )
    )
    wrong_epoch_id = "A" * 64
    assert wrong_epoch_id not in {active_epoch, unactivated_epoch}
    wrong_epoch_source = (
        project
        / "Copy"
        / "ledger"
        / "source"
        / "segments"
        / wrong_epoch_id
    )
    wrong_epoch_copy = (
        project
        / "Copy"
        / "ledger"
        / "copy"
        / "segments"
        / wrong_epoch_id
    )
    wrong_epoch_source.mkdir(parents=True)
    wrong_epoch_copy.mkdir(parents=True)

    with pytest.raises(CopyLedgerError) as wrong_revision:
        _create_test_copy_ledgers(
            bundle,
            operation_ledger,
            epoch_id=unactivated_epoch,
            run_scope_id=run_scope_id,
            initialize=True,
            initialized_at_utc="2026-07-13T03:00:02Z",
        )
    assert wrong_revision.value.code is CopyLedgerCode.INVALID_REQUEST
    with pytest.raises(CopyLedgerError) as wrong_epoch:
        _create_test_copy_ledgers(
            bundle,
            operation_ledger,
            epoch_id=wrong_epoch_id,
            run_scope_id=run_scope_id,
            initialize=True,
            initialized_at_utc="2026-07-13T03:00:03Z",
        )
    assert wrong_epoch.value.code is CopyLedgerCode.INVALID_REQUEST
    with pytest.raises(CopyLedgerError) as wrong_run:
        _create_test_copy_ledgers(
            bundle,
            operation_ledger,
            epoch_id=active_epoch,
            run_scope_id="RUN-LOGICAL-COPY-MAP-FORGED",
            initialize=True,
            initialized_at_utc="2026-07-13T03:00:04Z",
        )
    assert wrong_run.value.code is CopyLedgerCode.INVALID_REQUEST
    assert tuple(_segment_entries(unactivated_source)) == ()
    assert tuple(_segment_entries(unactivated_copy)) == ()
    assert tuple(_segment_entries(wrong_epoch_source)) == ()
    assert tuple(_segment_entries(wrong_epoch_copy)) == ()
    assert tuple(_segment_entries(source_directory)) == ()
    assert tuple(_segment_entries(copy_directory)) == ()

    copy_ledgers = _create_test_copy_ledgers(
        bundle,
        operation_ledger,
        epoch_id=active_epoch,
        run_scope_id=run_scope_id,
        initialize=True,
        initialized_at_utc="2026-07-13T03:00:05Z",
    )
    unactivated_probe = (
        unactivated_source
        / ("00000000000000000000-" + "e" * 64 + ".json")
    )
    _extended_test_host_path(unactivated_probe).write_bytes(
        b"synthetic-unactivated-copy-segment\n"
    )
    unactivated_context = bundle.boundary.issue_context(
        run_id=run_scope_id,
        job_id="JOB-COPY-MAP-UNACTIVATED",
        operation_id="OP-COPY-MAP-UNACTIVATED",
        caller=Caller.IMPORT_SERVICE,
        purpose=Purpose.COPY_SOURCE,
        scopes=(
            ScopeId(ScopeKind.RUN_ID, run_scope_id),
            ScopeId(
                ScopeKind.COPY_LEDGER_EPOCH_ID,
                unactivated_epoch,
            ),
        ),
    )
    with pytest.raises(ProductionBoundaryError) as unactivated_read:
        bundle.boundary.authorize(
            unactivated_probe.relative_to(project),
            intent=PathIntent.EXISTING_READ,
            expected_kind=ExpectedKind.FILE,
            context=unactivated_context,
        )
    assert unactivated_read.value.code is BoundaryErrorCode.POLICY_DENIED
    assert _extended_test_host_path(unactivated_probe).read_bytes() == (
        b"synthetic-unactivated-copy-segment\n"
    )
    source_genesis = next(_segment_entries(source_directory))
    source_relative = source_genesis.relative_to(project)
    correct_context = bundle.boundary.issue_context(
        run_id=run_scope_id,
        job_id="JOB-COPY-MAP-READ",
        operation_id="OP-COPY-MAP-READ",
        caller=Caller.IMPORT_SERVICE,
        purpose=Purpose.COPY_SOURCE,
        scopes=(
            ScopeId(ScopeKind.RUN_ID, run_scope_id),
            ScopeId(ScopeKind.COPY_LEDGER_EPOCH_ID, active_epoch),
        ),
    )
    before_head = copy_ledgers.head
    before_files = tuple(
        sorted(
            (
                path.relative_to(project),
                _extended_test_host_path(path).read_bytes(),
            )
            for directory in (source_directory, copy_directory)
            for path in _segment_entries(directory)
        )
    )
    ticket = bundle.boundary.authorize(
        source_relative,
        intent=PathIntent.EXISTING_READ,
        expected_kind=ExpectedKind.FILE,
        context=correct_context,
    )
    bundle.boundary.revalidate(ticket, context=correct_context)

    forged_run_id = "RUN-LOGICAL-COPY-MAP-FORGED"
    forged_context = bundle.boundary.issue_context(
        run_id=forged_run_id,
        job_id="JOB-COPY-MAP-FORGED",
        operation_id="OP-COPY-MAP-FORGED",
        caller=Caller.IMPORT_SERVICE,
        purpose=Purpose.COPY_SOURCE,
        scopes=(
            ScopeId(ScopeKind.RUN_ID, forged_run_id),
            ScopeId(ScopeKind.COPY_LEDGER_EPOCH_ID, active_epoch),
        ),
    )
    with pytest.raises(ProductionBoundaryError) as forged_read:
        bundle.boundary.authorize(
            source_relative,
            intent=PathIntent.EXISTING_READ,
            expected_kind=ExpectedKind.FILE,
            context=forged_context,
        )
    assert forged_read.value.code is BoundaryErrorCode.POLICY_DENIED

    with pytest.raises(ProductionBoundaryError) as generic_write:
        bundle.boundary.authorize(
            source_directory.relative_to(project)
            / ("00000000000000000009-" + "f" * 64 + ".json"),
            intent=PathIntent.NEW_WRITE,
            expected_kind=ExpectedKind.FILE,
            context=correct_context,
        )
    assert generic_write.value.code is BoundaryErrorCode.POLICY_DENIED
    after_files = tuple(
        sorted(
            (
                path.relative_to(project),
                _extended_test_host_path(path).read_bytes(),
            )
            for directory in (source_directory, copy_directory)
            for path in _segment_entries(directory)
        )
    )
    assert copy_ledgers.head == before_head
    assert after_files == before_files
    assert bundle.writer._poisoned is None
    serialized_audit = b"".join(
        _extended_test_host_path(path).read_bytes()
        for path in (
            project / "logs" / "audit" / "segments"
        ).rglob("*.json")
    )
    assert run_scope_id.encode("ascii") not in serialized_audit
    assert forged_run_id.encode("ascii") not in serialized_audit


def test_copy_rotation_blocks_pending_history_then_allows_after_terminal_recovery(
    compat_project: Path,
) -> None:
    project, bundle = _create_boundary(compat_project, suffix="COPY-ROTATE")
    run_scope_id = "RUN-COPY-ROTATE"
    old_revision = bundle.ledger._active_revision()
    old_operation = _initialize_operation_epoch(
        project,
        bundle,
        "RUN-COPY-ROTATE-OLD-OPERATIONS",
        "2026-07-13T03:10:00Z",
    )
    old_epoch, old_source_directory, old_copy_directory = (
        _create_copy_epoch_directories(project, old_revision, run_scope_id)
    )
    old_ledgers = _create_test_copy_ledgers(
        bundle,
        old_operation,
        epoch_id=old_epoch,
        run_scope_id=run_scope_id,
        initialize=True,
        initialized_at_utc="2026-07-13T03:10:01Z",
    )
    source = _copy_source_record(
        "copy-rotate",
        bundle.ledger.head.last_segment_sha256,
    )
    with bundle.writer.acquire_runtime_mutex() as lease:
        source_receipt = old_ledgers._append_source_under_existing_mutex(
            lease,
            source,
            created_at_utc="2026-07-13T03:10:02Z",
        )
    old_before_rotation = old_ledgers.head
    new_revision = _activate_second_revision(
        bundle,
        suffix="COPY-ROTATE",
        created_at_utc="2026-07-13T03:10:03Z",
        rotated_at_utc="2026-07-13T03:10:04Z",
    )
    new_operation = _initialize_operation_epoch(
        project,
        bundle,
        "RUN-COPY-ROTATE-NEW-OPERATIONS",
        "2026-07-13T03:10:05Z",
    )
    new_epoch, new_source_directory, new_copy_directory = (
        _create_copy_epoch_directories(project, new_revision, run_scope_id)
    )

    with bundle.writer.acquire_runtime_mutex() as lease:
        stale_before = old_ledgers.head
        with pytest.raises(CopyLedgerError) as stale_new_work:
            old_ledgers._append_source_under_existing_mutex(
                lease,
                _copy_source_record(
                    "copy-rotate-stale-new-work",
                    bundle.ledger.head.last_segment_sha256,
                ),
            )
        assert stale_new_work.value.code is CopyLedgerCode.AUTHENTICATION_FAILED
        assert old_ledgers.head == stale_before

    with pytest.raises(CopyLedgerError) as pending:
        _create_test_copy_ledgers(
            bundle,
            new_operation,
            epoch_id=new_epoch,
            run_scope_id=run_scope_id,
            initialize=True,
            initialized_at_utc="2026-07-13T03:10:06Z",
        )
    assert pending.value.code is CopyLedgerCode.ROTATION_BLOCKED
    assert tuple(_segment_entries(new_source_directory)) == ()
    assert tuple(_segment_entries(new_copy_directory)) == ()
    assert len(tuple(_segment_entries(old_source_directory))) == (
        old_before_rotation.source.segment_count
    )
    assert len(tuple(_segment_entries(old_copy_directory))) == (
        old_before_rotation.copy.segment_count
    )
    assert bundle.writer._poisoned is None

    reopened_old = _create_test_copy_ledgers(
        bundle,
        old_operation,
        epoch_id=old_epoch,
        run_scope_id=run_scope_id,
    )
    assert reopened_old.signing_revision_id == old_revision.revision_id
    with bundle.writer.acquire_runtime_mutex() as lease:
        before_new_work = reopened_old.head
        with pytest.raises(CopyLedgerError) as new_work:
            reopened_old._append_source_under_existing_mutex(
                lease,
                _copy_source_record(
                    "copy-rotate-new-work",
                    bundle.ledger.head.last_segment_sha256,
                ),
            )
        assert new_work.value.code is CopyLedgerCode.AUTHENTICATION_FAILED
        assert reopened_old.head == before_new_work
        recovered_abort = _copy_recovered_abort(
            "copy-rotate",
            reopened_old,
            old_operation,
            lease,
            source,
            source_receipt,
            bundle.ledger.head.last_segment_sha256,
        )
        recovered = reopened_old._append_transition_under_existing_mutex(
            lease,
            recovered_abort,
            created_at_utc="2026-07-13T03:10:07Z",
        )
        recovered_count = reopened_old.head.copy.segment_count
        replayed = reopened_old._append_transition_under_existing_mutex(
            lease,
            recovered_abort,
            created_at_utc="2026-07-13T03:10:08Z",
        )
        assert recovered.state is CopyState.RECOVERED_ABORT
        assert replayed.replayed is True
        assert reopened_old.head.copy.segment_count == recovered_count
        assert reopened_old.head.pending_source_count == 0

    old_files_after_recovery = (
        tuple(
            sorted(path.name for path in _segment_entries(old_source_directory))
        ),
        tuple(
            sorted(path.name for path in _segment_entries(old_copy_directory))
        ),
    )
    new_ledgers = _create_test_copy_ledgers(
        bundle,
        new_operation,
        epoch_id=new_epoch,
        run_scope_id=run_scope_id,
        initialize=True,
        initialized_at_utc="2026-07-13T03:10:09Z",
    )
    assert new_ledgers.signing_revision_id == new_revision.revision_id
    assert new_ledgers.head.source.segment_count == 1
    assert new_ledgers.head.copy.segment_count == 1
    assert old_files_after_recovery == (
        tuple(
            sorted(path.name for path in _segment_entries(old_source_directory))
        ),
        tuple(
            sorted(path.name for path in _segment_entries(old_copy_directory))
        ),
    )
    before_fresh_reopen = new_ledgers.head
    fresh_reopen = _create_test_copy_ledgers(
        bundle,
        new_operation,
        epoch_id=new_epoch,
        run_scope_id=run_scope_id,
    )
    assert fresh_reopen.head == before_fresh_reopen


@pytest.mark.parametrize("damage_mode", ("ASYMMETRIC", "CORRUPT"))
def test_copy_rotation_seals_on_historical_asymmetry_or_corruption_without_repair(
    compat_project: Path,
    damage_mode: str,
) -> None:
    project, bundle = _create_boundary(
        compat_project,
        suffix=f"COPY-{damage_mode}",
    )
    run_scope_id = f"RUN-COPY-{damage_mode}"
    old_revision = bundle.ledger._active_revision()
    old_epoch, old_source_directory, old_copy_directory = (
        _copy_epoch_directories(project, old_revision, run_scope_id)
    )
    if damage_mode == "ASYMMETRIC":
        old_source_directory.mkdir(parents=True)
        historical_snapshot = (True, False, ())
    else:
        old_operation = _initialize_operation_epoch(
            project,
            bundle,
            f"RUN-COPY-{damage_mode}-OLD-OPERATIONS",
            "2026-07-13T03:20:00Z",
        )
        old_source_directory.mkdir(parents=True)
        old_copy_directory.mkdir(parents=True)
        _create_test_copy_ledgers(
            bundle,
            old_operation,
            epoch_id=old_epoch,
            run_scope_id=run_scope_id,
            initialize=True,
            initialized_at_utc="2026-07-13T03:20:01Z",
        )
        source_genesis = next(_segment_entries(old_source_directory))
        _extended_test_host_path(source_genesis).write_bytes(
            b"corrupt-copy-genesis\n"
        )
        historical_snapshot = (
            True,
            True,
            tuple(
                sorted(
                    (
                        path.relative_to(project),
                        _extended_test_host_path(path).read_bytes(),
                    )
                    for directory in (old_source_directory, old_copy_directory)
                    for path in _segment_entries(directory)
                )
            ),
        )

    new_revision = _activate_second_revision(
        bundle,
        suffix=f"COPY-{damage_mode}",
        created_at_utc="2026-07-13T03:20:02Z",
        rotated_at_utc="2026-07-13T03:20:03Z",
    )
    new_operation = _initialize_operation_epoch(
        project,
        bundle,
        f"RUN-COPY-{damage_mode}-NEW-OPERATIONS",
        "2026-07-13T03:20:04Z",
    )
    new_epoch, new_source_directory, new_copy_directory = (
        _create_copy_epoch_directories(project, new_revision, run_scope_id)
    )
    with pytest.raises(CopyLedgerError) as rejected:
        _create_test_copy_ledgers(
            bundle,
            new_operation,
            epoch_id=new_epoch,
            run_scope_id=run_scope_id,
            initialize=True,
            initialized_at_utc="2026-07-13T03:20:05Z",
        )
    if damage_mode == "ASYMMETRIC":
        assert rejected.value.code is CopyLedgerCode.CROSS_REFERENCE_INVALID
        assert old_source_directory.exists()
        assert not old_copy_directory.exists()
        assert historical_snapshot == (True, False, ())
    else:
        assert rejected.value.code in {
            CopyLedgerCode.CHAIN_CORRUPT,
            CopyLedgerCode.AUTHENTICATION_FAILED,
        }
        assert historical_snapshot[2] == tuple(
            sorted(
                (
                    path.relative_to(project),
                    _extended_test_host_path(path).read_bytes(),
                )
                for directory in (old_source_directory, old_copy_directory)
                for path in _segment_entries(directory)
            )
        )
    assert tuple(_segment_entries(new_source_directory)) == ()
    assert tuple(_segment_entries(new_copy_directory)) == ()
    assert bundle.writer._poisoned is not None


def test_copy_three_rotations_preserve_historical_epochs_and_only_latest_accepts_new_work(
    compat_project: Path,
) -> None:
    project, bundle = _create_boundary(
        compat_project,
        suffix="COPY-THREE-ROTATIONS",
    )
    run_scope_id = "RUN-COPY-THREE-ROTATIONS"
    first_revision = bundle.ledger._active_revision()
    first_operation = _initialize_operation_epoch(
        project,
        bundle,
        "RUN-COPY-THREE-ROTATIONS-OPERATIONS-1",
        "2026-07-13T04:00:00Z",
    )
    first_epoch, first_source_directory, first_copy_directory = (
        _create_copy_epoch_directories(project, first_revision, run_scope_id)
    )
    first_ledgers = _create_test_copy_ledgers(
        bundle,
        first_operation,
        epoch_id=first_epoch,
        run_scope_id=run_scope_id,
        initialize=True,
        initialized_at_utc="2026-07-13T04:00:01Z",
    )
    first_source = _copy_source_record(
        "copy-three-rotations-first",
        bundle.ledger.head.last_segment_sha256,
    )
    with bundle.writer.acquire_runtime_mutex() as lease:
        first_receipt = first_ledgers._append_source_under_existing_mutex(
            lease,
            first_source,
            created_at_utc="2026-07-13T04:00:02Z",
        )
        first_terminal = first_ledgers._append_transition_under_existing_mutex(
            lease,
            _copy_recovered_abort(
                "copy-three-rotations-first",
                first_ledgers,
                first_operation,
                lease,
                first_source,
                first_receipt,
                bundle.ledger.head.last_segment_sha256,
            ),
            created_at_utc="2026-07-13T04:00:03Z",
        )
    assert first_terminal.state is CopyState.RECOVERED_ABORT
    assert first_ledgers.head.pending_source_count == 0

    epochs = [
        (
            first_revision,
            first_operation,
            first_epoch,
            first_source_directory,
            first_copy_directory,
            first_ledgers,
        )
    ]
    snapshots = {
        first_epoch: _copy_epoch_snapshot(
            project,
            first_source_directory,
            first_copy_directory,
        )
    }
    for ordinal in range(2, 5):
        revision = _activate_next_revision(
            bundle,
            revision_id=f"KEYREV-COPY-THREE-ROTATIONS-{ordinal}",
            rotation_id=(
                f"ROTATION-COPY-THREE-ROTATIONS-{ordinal - 1}-TO-{ordinal}"
            ),
            master_key=bytes([0x50 + ordinal]) * 32,
            created_at_utc=f"2026-07-13T04:{ordinal:02d}:00Z",
            rotated_at_utc=f"2026-07-13T04:{ordinal:02d}:01Z",
        )
        operation = _initialize_operation_epoch(
            project,
            bundle,
            f"RUN-COPY-THREE-ROTATIONS-OPERATIONS-{ordinal}",
            f"2026-07-13T04:{ordinal:02d}:02Z",
        )
        epoch, source_directory, copy_directory = (
            _create_copy_epoch_directories(project, revision, run_scope_id)
        )
        ledgers = _create_test_copy_ledgers(
            bundle,
            operation,
            epoch_id=epoch,
            run_scope_id=run_scope_id,
            initialize=True,
            initialized_at_utc=f"2026-07-13T04:{ordinal:02d}:03Z",
        )
        assert ledgers.signing_revision_id == revision.revision_id
        assert ledgers.head.source.segment_count == 1
        assert ledgers.head.copy.segment_count == 1
        epochs.append(
            (
                revision,
                operation,
                epoch,
                source_directory,
                copy_directory,
                ledgers,
            )
        )
        snapshots[epoch] = _copy_epoch_snapshot(
            project,
            source_directory,
            copy_directory,
        )

    epoch_ids = tuple(item[2] for item in epochs)
    assert len(set(epoch_ids)) == 4
    assert all(
        len(epoch_id) == 64
        and set(epoch_id).issubset(set("0123456789ABCDEF"))
        for epoch_id in epoch_ids
    )
    assert bundle.ledger._active_revision().revision_id == epochs[-1][0].revision_id
    for _revision, _operation, epoch, source_directory, copy_directory, _ledgers in epochs:
        assert _copy_epoch_snapshot(
            project,
            source_directory,
            copy_directory,
        ) == snapshots[epoch]

    historical_reopens = []
    for revision, operation, epoch, _source, _copy, ledgers in epochs[:-1]:
        reopened = _create_test_copy_ledgers(
            bundle,
            operation,
            epoch_id=epoch,
            run_scope_id=run_scope_id,
        )
        assert reopened.signing_revision_id == revision.revision_id
        assert reopened.head == ledgers.head
        assert reopened.matches_run_scope(run_scope_id) is True
        assert reopened.matches_run_scope(f"{run_scope_id}-FORGED") is False
        historical_reopens.append(reopened)

    with bundle.writer.acquire_runtime_mutex() as lease:
        for ordinal, reopened in enumerate(historical_reopens, start=1):
            before_rejected = reopened.head
            with pytest.raises(CopyLedgerError) as rejected:
                reopened._append_source_under_existing_mutex(
                    lease,
                    _copy_source_record(
                        f"copy-three-rotations-stale-{ordinal}",
                        bundle.ledger.head.last_segment_sha256,
                    ),
                )
            assert rejected.value.code is CopyLedgerCode.AUTHENTICATION_FAILED
            assert reopened.head == before_rejected

    for _revision, _operation, epoch, source_directory, copy_directory, _ledgers in epochs[:-1]:
        assert _copy_epoch_snapshot(
            project,
            source_directory,
            copy_directory,
        ) == snapshots[epoch]

    (
        active_revision,
        active_operation,
        active_epoch,
        _active_source_directory,
        _active_copy_directory,
        active_ledgers,
    ) = epochs[-1]
    active_source = _copy_source_record(
        "copy-three-rotations-active",
        bundle.ledger.head.last_segment_sha256,
    )
    with bundle.writer.acquire_runtime_mutex() as lease:
        active_receipt = active_ledgers._append_source_under_existing_mutex(
            lease,
            active_source,
            created_at_utc="2026-07-13T04:05:00Z",
        )
        active_terminal = active_ledgers._append_transition_under_existing_mutex(
            lease,
            _copy_recovered_abort(
                "copy-three-rotations-active",
                active_ledgers,
                active_operation,
                lease,
                active_source,
                active_receipt,
                bundle.ledger.head.last_segment_sha256,
            ),
            created_at_utc="2026-07-13T04:05:01Z",
        )
    assert active_terminal.state is CopyState.RECOVERED_ABORT
    assert active_ledgers.head.pending_source_count == 0
    active_head = active_ledgers.head
    active_reopen = _create_test_copy_ledgers(
        bundle,
        active_operation,
        epoch_id=active_epoch,
        run_scope_id=run_scope_id,
    )
    assert active_reopen.signing_revision_id == active_revision.revision_id
    assert active_reopen.head == active_head
    assert bundle.writer._poisoned is None


def test_public_copy_read_ticket_issued_before_three_rotations_revalidates_for_historical_epoch(
    compat_project: Path,
) -> None:
    project, bundle = _create_boundary(
        compat_project,
        suffix="COPY-PUBLIC-ROTATE",
    )
    run_scope_id = "RUN-COPY-PUBLIC-ROTATE"
    first_revision = bundle.ledger._active_revision()
    first_operation = _initialize_operation_epoch(
        project,
        bundle,
        "RUN-COPY-PUBLIC-ROTATE-OPERATIONS-1",
        "2026-07-13T05:00:00Z",
    )
    first_epoch, first_source_directory, first_copy_directory = (
        _create_copy_epoch_directories(project, first_revision, run_scope_id)
    )
    _create_test_copy_ledgers(
        bundle,
        first_operation,
        epoch_id=first_epoch,
        run_scope_id=run_scope_id,
        initialize=True,
        initialized_at_utc="2026-07-13T05:00:01Z",
    )
    source_genesis = next(_segment_entries(first_source_directory))
    source_relative = source_genesis.relative_to(project)
    historical_context = bundle.boundary.issue_context(
        run_id=run_scope_id,
        job_id="JOB-COPY-PUBLIC-ROTATE-HISTORICAL",
        operation_id="OP-COPY-PUBLIC-ROTATE-HISTORICAL",
        caller=Caller.IMPORT_SERVICE,
        purpose=Purpose.COPY_SOURCE,
        scopes=(
            ScopeId(ScopeKind.RUN_ID, run_scope_id),
            ScopeId(ScopeKind.COPY_LEDGER_EPOCH_ID, first_epoch),
        ),
    )
    historical_ticket = bundle.boundary.authorize(
        source_relative,
        intent=PathIntent.EXISTING_READ,
        expected_kind=ExpectedKind.FILE,
        context=historical_context,
    )
    epochs = [
        (
            first_epoch,
            first_source_directory,
            first_copy_directory,
        )
    ]
    snapshots = {
        first_epoch: _copy_epoch_snapshot(
            project,
            first_source_directory,
            first_copy_directory,
        )
    }

    for ordinal in range(2, 5):
        revision = _activate_next_revision(
            bundle,
            revision_id=f"KEYREV-COPY-PUBLIC-ROTATE-{ordinal}",
            rotation_id=(
                f"ROTATION-COPY-PUBLIC-ROTATE-{ordinal - 1}-TO-{ordinal}"
            ),
            master_key=bytes([0x60 + ordinal]) * 32,
            created_at_utc=f"2026-07-13T05:{ordinal:02d}:00Z",
            rotated_at_utc=f"2026-07-13T05:{ordinal:02d}:01Z",
        )
        operation = _initialize_operation_epoch(
            project,
            bundle,
            f"RUN-COPY-PUBLIC-ROTATE-OPERATIONS-{ordinal}",
            f"2026-07-13T05:{ordinal:02d}:02Z",
        )
        epoch, source_directory, copy_directory = (
            _create_copy_epoch_directories(project, revision, run_scope_id)
        )
        ledgers = _create_test_copy_ledgers(
            bundle,
            operation,
            epoch_id=epoch,
            run_scope_id=run_scope_id,
            initialize=True,
            initialized_at_utc=f"2026-07-13T05:{ordinal:02d}:03Z",
        )
        assert ledgers.signing_revision_id == revision.revision_id
        epochs.append((epoch, source_directory, copy_directory))
        snapshots[epoch] = _copy_epoch_snapshot(
            project,
            source_directory,
            copy_directory,
        )

    assert len({item[0] for item in epochs}) == 4
    bundle.boundary.revalidate(
        historical_ticket,
        context=historical_context,
    )
    assert bundle.ledger._active_revision().revision_id == (
        "KEYREV-COPY-PUBLIC-ROTATE-4"
    )

    forged_run_id = "RUN-COPY-PUBLIC-ROTATE-FORGED"
    forged_context = bundle.boundary.issue_context(
        run_id=forged_run_id,
        job_id="JOB-COPY-PUBLIC-ROTATE-FORGED",
        operation_id="OP-COPY-PUBLIC-ROTATE-FORGED",
        caller=Caller.IMPORT_SERVICE,
        purpose=Purpose.COPY_SOURCE,
        scopes=(
            ScopeId(ScopeKind.RUN_ID, forged_run_id),
            ScopeId(ScopeKind.COPY_LEDGER_EPOCH_ID, first_epoch),
        ),
    )
    with pytest.raises(ProductionBoundaryError) as forged_read:
        bundle.boundary.authorize(
            source_relative,
            intent=PathIntent.EXISTING_READ,
            expected_kind=ExpectedKind.FILE,
            context=forged_context,
        )
    assert forged_read.value.code is BoundaryErrorCode.POLICY_DENIED

    active_epoch, active_source_directory, _active_copy_directory = epochs[-1]
    active_genesis = next(_segment_entries(active_source_directory))
    active_context = bundle.boundary.issue_context(
        run_id=run_scope_id,
        job_id="JOB-COPY-PUBLIC-ROTATE-ACTIVE",
        operation_id="OP-COPY-PUBLIC-ROTATE-ACTIVE",
        caller=Caller.IMPORT_SERVICE,
        purpose=Purpose.COPY_SOURCE,
        scopes=(
            ScopeId(ScopeKind.RUN_ID, run_scope_id),
            ScopeId(ScopeKind.COPY_LEDGER_EPOCH_ID, active_epoch),
        ),
    )
    active_ticket = bundle.boundary.authorize(
        active_genesis.relative_to(project),
        intent=PathIntent.EXISTING_READ,
        expected_kind=ExpectedKind.FILE,
        context=active_context,
    )
    bundle.boundary.revalidate(active_ticket, context=active_context)

    for epoch, source_directory, copy_directory in epochs:
        assert _copy_epoch_snapshot(
            project,
            source_directory,
            copy_directory,
        ) == snapshots[epoch]
    assert bundle.writer._poisoned is None
