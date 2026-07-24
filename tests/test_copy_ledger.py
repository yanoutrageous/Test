from __future__ import annotations

import hashlib
import os
import pickle
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Iterator

import pytest

from app.workspace_guard import ExpectedKind, PathIntent
from app.safety import copy_ledger as copy_ledger_module
from app.safety.audit_events import (
    AuditAction,
    AuditDecision,
    AuditEvent,
    CapabilityKind,
    create_audit_event,
)
from app.safety.context import (
    Caller,
    DataClassification,
    OperationContext,
    Purpose,
)
from app.safety.copy_ledger import (
    COPY_PROVENANCE_FILE_NAME,
    CopyFileEvidence,
    CopyLedgerCode,
    CopyLedgerError,
    CopyLocator,
    CopyLocatorMode,
    CopyOperationAbsenceWitness,
    CopyPublishOperationPlan,
    CopyPublishPlanKind,
    CopySourceReceipt,
    CopySourceRecord,
    CopyState,
    CopyTargetEvidence,
    CopyTransition,
    DurableCopyLedgers,
    build_copy_provenance_material,
    _COPY_LEDGERS_CONSTRUCTOR,
    _derive_copy_ledger_epoch_id,
)
from app.safety.external_source import SYNTHETIC_REFERENCE_POLICY_DIGEST
from app.safety.namespace_policy import (
    AuditPathMode,
    NamespaceId,
    POLICY_DIGEST,
)
from app.safety.operation_ledger import (
    OperationCompletionKind,
    OperationLedgerCode,
    OperationLedgerError,
    OperationLocatorMode,
    OperationLocatorRole,
    OperationState,
    OperationTransition,
    OperationTreeEvidence,
)
from app.safety.production_guard import (
    _create_test_copy_ledgers,
    _create_test_durable_boundary,
    _create_test_handle_writer,
    _create_test_operation_ledger,
)
from app.safety.segment_ledger import (
    AuditKeyRevision,
    AuditKeyRevisionStore,
    canonical_json_bytes,
    parse_canonical_json_bytes,
    _LEDGER_CONSTRUCTOR,
)


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


@dataclass(frozen=True)
class _CopyLab:
    project: Path
    protected: Path
    sentinel: Path
    writer: object
    revision: AuditKeyRevision
    run_scope_id: str = "RUN-COPY-LEDGER-S3F"

    @property
    def epoch_id(self) -> str:
        return _derive_copy_ledger_epoch_id(self.revision, self.run_scope_id)


@dataclass(frozen=True)
class _TypedAncestorLab:
    project: Path
    bundle: object
    operation_ledger: object
    copy_ledgers: DurableCopyLedgers
    epoch_id: str
    run_scope_id: str


@pytest.fixture
def copy_lab(request: pytest.FixtureRequest) -> Iterator[_CopyLab]:
    run_root = Path(os.environ["M0_TEST_LAB_ROOT"])
    workspace_id = hashlib.sha256(
        request.node.nodeid.encode("utf-8", "strict")
    ).hexdigest()[:8]
    workspace = run_root / f"c{workspace_id}"
    project = workspace / "project"
    protected = workspace / "p"
    project.mkdir(parents=True)
    protected.mkdir()
    sentinel = protected / "sentinel.bin"
    sentinel.write_bytes(b"copy-ledger-protected")
    (project / "logs" / "audit" / "keys").mkdir(parents=True)
    writer = _create_test_handle_writer(project)
    revision = AuditKeyRevisionStore(
        writer,
        _constructor=_LEDGER_CONSTRUCTOR,
    ).create_revision(
        revision_sequence=1,
        revision_id="KEYREV-S3F-ONE",
        master_key=b"S" * 32,
        created_at_utc="2026-07-13T00:00:01Z",
    )
    epoch_id = _derive_copy_ledger_epoch_id(
        revision,
        "RUN-COPY-LEDGER-S3F",
    )
    (project / "Copy" / "ledger" / "source" / "segments" / epoch_id).mkdir(
        parents=True
    )
    (project / "Copy" / "ledger" / "copy" / "segments" / epoch_id).mkdir(
        parents=True
    )
    yield _CopyLab(
        project=project,
        protected=protected,
        sentinel=sentinel,
        writer=writer,
        revision=revision,
    )
    assert sentinel.read_bytes() == b"copy-ledger-protected"
    assert {item.name for item in protected.iterdir()} == {"sentinel.bin"}


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _opaque_txn(label: str) -> str:
    return f"TXN-{_digest(label).upper()[:32]}"


_RESTRICTED_RAW_OPERATION_EPOCH = "RUN-COPY-TYPED-OPERATIONS"
_RESTRICTED_RAW_RUN = "RUN-PRIVATE-STUDENT-2026"
_RESTRICTED_RAW_JOB = "JOB-PRIVATE-IMPORT-2026"
_RESTRICTED_RAW_OPERATION = "OPERATION-PRIVATE-COPY-2026"
_RESTRICTED_RAW_COPY = "COPY-PRIVATE-STUDENT-2026"


def _shape_only_absence(
    label: str,
    *,
    with_publish_transaction: bool = True,
) -> CopyOperationAbsenceWitness:
    """Syntactically exact witness for transition-only tests without an op ledger."""

    return CopyOperationAbsenceWitness(
        operation_epoch_reference_hmac_sha256=_digest(
            f"{label}-absence-epoch-reference"
        ),
        observation_head_sha256=_digest(f"{label}-absence-head"),
        observation_segment_count=1,
        expected_operation_reference_hmac_sha256=_digest(
            f"{label}-absence-operation"
        ),
        expected_publish_transaction_hmac_sha256=(
            _digest(f"{label}-absence-transaction")
            if with_publish_transaction
            else None
        ),
        authenticator_sha256=_digest(f"{label}-absence-authenticator"),
    )


def _ledgers(lab: _CopyLab, *, initialize: bool = True) -> DurableCopyLedgers:
    return DurableCopyLedgers(
        lab.writer,
        lab.revision,
        epoch_id=lab.epoch_id,
        run_scope_id=lab.run_scope_id,
        policy_digest=POLICY_DIGEST,
        initialize=initialize,
        initialized_at_utc="2026-07-13T00:00:02Z" if initialize else None,
        _constructor=_COPY_LEDGERS_CONSTRUCTOR,
    )


def _typed_ancestor_lab(lab: _CopyLab) -> _TypedAncestorLab:
    workspace = lab.project.parent
    project = workspace.parent / f"t{workspace.name[1:]}" / "project"
    project.mkdir(parents=True)
    (project / "logs" / "audit" / "keys").mkdir(parents=True)
    (project / "logs" / "audit" / "segments" / "RUN-COPY-TYPED-AUDIT").mkdir(
        parents=True
    )
    (
        project
        / "logs"
        / "operations"
        / "segments"
        / "RUN-COPY-TYPED-OPERATIONS"
    ).mkdir(parents=True)
    bundle = _create_test_durable_boundary(
        project,
        initialize=True,
        epoch_id="RUN-COPY-TYPED-AUDIT",
        initial_revision_sequence=1,
        initial_revision_id="KEYREV-COPY-TYPED-ONE",
        master_key=b"Y" * 32,
        key_created_at_utc="2026-07-13T05:00:00Z",
        ledger_initialized_at_utc="2026-07-13T05:00:01Z",
    )
    operation_ledger = _create_test_operation_ledger(
        bundle,
        epoch_id="RUN-COPY-TYPED-OPERATIONS",
        initialize=True,
        initialized_at_utc="2026-07-13T05:00:02Z",
    )
    run_scope_id = "RUN-COPY-TYPED-ANCESTOR"
    revision = bundle.ledger._active_revision()
    epoch_id = _derive_copy_ledger_epoch_id(revision, run_scope_id)
    (project / "Copy" / "ledger" / "source" / "segments" / epoch_id).mkdir(
        parents=True
    )
    (project / "Copy" / "ledger" / "copy" / "segments" / epoch_id).mkdir(
        parents=True
    )
    copy_ledgers = _create_test_copy_ledgers(
        bundle,
        operation_ledger,
        epoch_id=epoch_id,
        run_scope_id=run_scope_id,
        initialize=True,
        initialized_at_utc="2026-07-13T05:00:03Z",
    )
    return _TypedAncestorLab(
        project=project,
        bundle=bundle,
        operation_ledger=operation_ledger,
        copy_ledgers=copy_ledgers,
        epoch_id=epoch_id,
        run_scope_id=run_scope_id,
    )


def _append_typed_audit_marker(lab: _TypedAncestorLab) -> str:
    """Advance the exact audit chain across the reservation/finalization window."""

    context = OperationContext(
        run_id="RUN-COPY-TYPED-AUDIT",
        job_id="JOB-COPY-TYPED-AUDIT",
        operation_id="OPERATION-COPY-TYPED-AUDIT",
        caller=Caller.AUDIT_SERVICE,
        purpose=Purpose.APPEND_AUDIT,
        classification=DataClassification.INTERNAL,
    )

    def build(audit_hmac_key: bytes) -> tuple[AuditEvent, ...]:
        event = create_audit_event(
            decision=AuditDecision.CANDIDATE_ALLOW,
            action=AuditAction.ISSUE,
            capability_kind=CapabilityKind.SINGLE,
            error_code=None,
            context=context,
            effective_classification=DataClassification.INTERNAL,
            path_mode=AuditPathMode.RELATIVE,
            policy_digest=POLICY_DIGEST,
            boundary_instance_id="BOUNDARY-COPY-TYPED-AUDIT",
            ticket_id="TICKET-COPY-TYPED-AUDIT",
            pair_id=None,
            pair_role=None,
            namespace=NamespaceId.AUDIT_LOG,
            intent=PathIntent.EXISTING_READ,
            expected_kind=ExpectedKind.FILE,
            relative_path=Path("logs/audit/typed-marker.json"),
            audit_hmac_key=audit_hmac_key,
        )
        return (
            replace(
                event,
                event_id="EVENT-COPY-TYPED-AUDIT",
                occurred_at_utc="2026-07-13T05:00:03Z",
            ),
        )

    with lab.bundle.writer.acquire_runtime_mutex() as lease:
        _, receipt = (
            lab.bundle.ledger._append_built_audit_batch_under_existing_mutex(
                lease,
                build,
                created_at_utc="2026-07-13T05:00:03Z",
            )
        )
    return receipt.segment_sha256


def _file(label: str, *, payload: bytes = b"synthetic-copy-payload") -> CopyFileEvidence:
    return CopyFileEvidence(
        identity_hmac_sha256=_digest(f"identity-{label}"),
        size_bytes=len(payload),
        sha256=hashlib.sha256(payload).hexdigest(),
        change_evidence_sha256=_digest(f"change-{label}"),
    )


def _source(index: int = 1, *, restricted: bool = False) -> CopySourceRecord:
    return CopySourceRecord(
        record_id=_digest(f"source-record-{index}"),
        transaction_binding_sha256=_digest(f"transaction-{index}"),
        copy_binding_sha256=_digest(f"copy-{index}"),
        reference_policy_digest=SYNTHETIC_REFERENCE_POLICY_DIGEST,
        audit_ancestor_sha256=_digest(f"audit-{index}"),
        classification=(
            DataClassification.RESTRICTED
            if restricted
            else DataClassification.INTERNAL
        ),
        source_locator=CopyLocator(
            CopyLocatorMode.HMAC_ONLY,
            _digest(f"external-locator-{index}"),
        ),
        source_evidence=_file(f"source-{index}"),
    )


def _prepared(
    source: CopySourceRecord,
    receipt: CopySourceReceipt,
    *,
    ledgers: DurableCopyLedgers,
    index: int = 1,
) -> CopyTransition:
    locator = CopyLocator(
        CopyLocatorMode.HMAC_ONLY,
        _digest(f"opaque-target-{index}"),
    )
    provenance = build_copy_provenance_material(
        source,
        receipt,
        manifest_id=f"MANIFEST-COPY-{index}",
    )
    budget_sha256 = _digest(f"budget-{index}")
    restricted = source.classification is DataClassification.RESTRICTED
    operation_reference = (
        f"OPREF-{_digest(f'operation-reference-{index}').upper()[:32]}"
        if restricted
        else f"OPERATION-PUBLISH-{index}"
    )
    publish_transaction_id = _opaque_txn(f"publish-transaction-{index}")
    pair_reference = (
        _digest(f"publish-pair-{index}").upper()[:32]
        if restricted
        else f"PAIR-PUBLISH-{index}"
    )
    operation_source_evidence = OperationTreeEvidence(
        manifest_sha256=provenance.publish_manifest.manifest_sha256,
        source_tree_sha256=_digest(f"shape-operation-tree-{index}"),
        topology_sha256=_digest(f"shape-operation-topology-{index}"),
        durable_identity_sha256=_digest(f"shape-operation-identity-{index}"),
        entry_count=2,
        total_bytes=(
            source.source_evidence.size_bytes + len(provenance.provenance_bytes)
        ),
    )
    locator_mode = (
        OperationLocatorMode.HMAC_ONLY
        if restricted
        else OperationLocatorMode.SAFE_RELATIVE
    )
    source_locator = (
        _digest(f"shape-source-locator-{index}")
        if restricted
        else f"tmp/jobs/internal/copy-{index}/publish/MANIFEST"
    )
    target_operation_locator = (
        _digest(f"shape-target-locator-{index}")
        if restricted
        else f"Copy/source/COPY-{index}"
    )
    operation_plan = ledgers._project_publish_operation_plan(
        kind=CopyPublishPlanKind.RESERVED,
        operation_reference=operation_reference,
        context_binding_sha256=_digest(f"operation-context-{index}"),
        manifest_sha256=provenance.publish_manifest.manifest_sha256,
        budget_sha256=budget_sha256,
        classification=source.classification,
        publish_transaction_id=publish_transaction_id,
        pair_reference=pair_reference,
        locator_mode=locator_mode,
        source_locator=source_locator,
        target_locator=target_operation_locator,
        source_evidence=operation_source_evidence,
        audit_ancestor_sha256=source.audit_ancestor_sha256,
    )
    return CopyTransition(
        transition_id=_digest(f"transition-{index}-prepared"),
        transaction_binding_sha256=source.transaction_binding_sha256,
        copy_binding_sha256=source.copy_binding_sha256,
        previous_state=None,
        next_state=CopyState.PREPARED,
        source_anchor=receipt.anchor,
        audit_ancestor_sha256=source.audit_ancestor_sha256,
        classification=source.classification,
        target_locator=locator,
        expected_manifest_sha256=provenance.publish_manifest.manifest_sha256,
        provenance_metadata_sha256=provenance.provenance_sha256,
        budget_sha256=budget_sha256,
        publish_operation_binding_sha256=_digest(
            f"publish-operation-binding-{index}"
        ),
        publish_operation_plan=operation_plan,
        mutation_attempted=False,
        publish_transaction_id=publish_transaction_id,
    )


def _target(source: CopySourceRecord, prepared: CopyTransition) -> CopyTargetEvidence:
    receipt = CopySourceReceipt(
        epoch_id=prepared.source_anchor.epoch_id,
        sequence=prepared.source_anchor.sequence,
        segment_sha256=prepared.source_anchor.segment_sha256,
        record_id=prepared.source_anchor.record_id,
        record_sha256=prepared.source_anchor.record_sha256,
    )
    material = build_copy_provenance_material(
        source,
        receipt,
        manifest_id="MANIFEST-COPY-TARGET",
    )
    payload = CopyFileEvidence(
        identity_hmac_sha256=_digest("target-payload-identity"),
        size_bytes=source.source_evidence.size_bytes,
        sha256=source.source_evidence.sha256,
        change_evidence_sha256=_digest("target-payload-change"),
    )
    provenance = CopyFileEvidence(
        identity_hmac_sha256=_digest("target-provenance-identity"),
        size_bytes=len(material.provenance_bytes),
        sha256=material.provenance_sha256,
        change_evidence_sha256=_digest("target-provenance-change"),
    )
    return CopyTargetEvidence(
        root_identity_hmac_sha256=_digest("target-root"),
        tree_identity_hmac_sha256=_digest("target-tree-identity"),
        payload=payload,
        provenance=provenance,
        manifest_sha256=prepared.expected_manifest_sha256,
        tree_sha256=_digest("target-tree"),
        topology_sha256=_digest("target-topology"),
        entry_count=2,
        total_bytes=payload.size_bytes + provenance.size_bytes,
    )


def _append_committed_publish(
    lab: _TypedAncestorLab,
    *,
    manifest_sha256: str,
    budget_sha256: str,
    entry_count: int,
    total_bytes: int,
    mismatch: str | None = None,
) -> tuple[
    OperationTransition,
    object,
    CopyPublishOperationPlan,
    str,
    str,
]:
    reservation_audit_ancestor = (
        lab.bundle.ledger.head.last_segment_sha256
    )
    operation_audit_ancestor = _append_typed_audit_marker(lab)
    source_relative = "tmp/jobs/internal/copy-typed/publish/MANIFEST-COPY-TYPED"
    target_relative = "Copy/source/COPY-TYPED"
    transaction_id = _opaque_txn("copy-typed-publish")
    expected_evidence = OperationTreeEvidence(
        manifest_sha256=manifest_sha256,
        source_tree_sha256=_digest("typed-operation-tree"),
        topology_sha256=_digest("typed-operation-topology"),
        durable_identity_sha256=_digest("typed-operation-tree-identity"),
        entry_count=entry_count,
        total_bytes=total_bytes,
    )
    expected_plan = lab.copy_ledgers._project_publish_operation_plan(
        kind=CopyPublishPlanKind.RESERVED,
        operation_reference="OPERATION-COPY-TYPED-PUBLISH",
        context_binding_sha256=_digest("typed-operation-context"),
        manifest_sha256=manifest_sha256,
        budget_sha256=budget_sha256,
        classification=DataClassification.INTERNAL,
        publish_transaction_id=transaction_id,
        pair_reference="PAIR-COPY-TYPED-PUBLISH",
        locator_mode=OperationLocatorMode.SAFE_RELATIVE,
        source_locator=source_relative,
        target_locator=target_relative,
        source_evidence=expected_evidence,
        audit_ancestor_sha256=(
            operation_audit_ancestor
            if mismatch == "audit_order"
            else reservation_audit_ancestor
        ),
    )
    actual_manifest = (
        _digest("typed-operation-wrong-manifest")
        if mismatch == "manifest"
        else manifest_sha256
    )
    evidence = replace(
        expected_evidence,
        manifest_sha256=actual_manifest,
        source_tree_sha256=(
            _digest("typed-operation-wrong-observed-tree")
            if mismatch == "observed_tree"
            else expected_evidence.source_tree_sha256
        ),
        topology_sha256=(
            _digest("typed-operation-wrong-topology")
            if mismatch == "topology"
            else expected_evidence.topology_sha256
        ),
        durable_identity_sha256=(
            _digest("typed-operation-wrong-durable-identity")
            if mismatch == "durable_identity"
            else expected_evidence.durable_identity_sha256
        ),
        entry_count=(
            expected_evidence.entry_count + 1
            if mismatch == "entry_count"
            else expected_evidence.entry_count
        ),
        total_bytes=(
            expected_evidence.total_bytes + 1
            if mismatch == "total_bytes"
            else expected_evidence.total_bytes
        ),
    )
    actual_classification = (
        DataClassification.RESTRICTED
        if mismatch == "classification_locator_mode"
        else DataClassification.INTERNAL
    )
    actual_source_relative = (
        "tmp/jobs/internal/copy-other/publish/MANIFEST-COPY-TYPED"
        if mismatch == "source_locator"
        else source_relative
    )
    actual_target_relative = (
        "Copy/source/COPY-OTHER"
        if mismatch == "target_locator"
        else target_relative
    )
    if actual_classification is DataClassification.RESTRICTED:
        source_locator = lab.operation_ledger.locator_hmac(
            actual_source_relative,
            transaction_id=transaction_id,
            role=OperationLocatorRole.SOURCE,
        )
        target_locator = lab.operation_ledger.locator_hmac(
            actual_target_relative,
            transaction_id=transaction_id,
            role=OperationLocatorRole.TARGET,
        )
        locator_mode = OperationLocatorMode.HMAC_ONLY
    else:
        source_locator = actual_source_relative
        target_locator = actual_target_relative
        locator_mode = OperationLocatorMode.SAFE_RELATIVE
    prepared = OperationTransition(
        transition_id="TRANSITION-COPY-TYPED-PREPARED",
        transaction_id=transaction_id,
        operation_id=(
            "OPERATION-COPY-TYPED-WRONG"
            if mismatch == "operation_reference"
            else "OPERATION-COPY-TYPED-PUBLISH"
        ),
        pair_id=(
            "PAIR-COPY-TYPED-WRONG"
            if mismatch == "pair"
            else "PAIR-COPY-TYPED-PUBLISH"
        ),
        previous_state=None,
        next_state=OperationState.PREPARED,
        context_binding_sha256=(
            _digest("typed-operation-wrong-context")
            if mismatch == "context"
            else _digest("typed-operation-context")
        ),
        manifest_sha256=actual_manifest,
        budget_sha256=(
            _digest("typed-operation-wrong-budget")
            if mismatch == "budget"
            else budget_sha256
        ),
        source_locator=source_locator,
        target_locator=target_locator,
        source_evidence=evidence,
        target_evidence=None,
        audit_ledger_head_sha256=(
            _digest("typed-operation-wrong-audit-head")
            if mismatch == "audit_ancestry"
            else (
                reservation_audit_ancestor
                if mismatch == "audit_order"
                else operation_audit_ancestor
            )
        ),
        mutation_attempted=False,
        locator_mode=locator_mode,
        classification=actual_classification,
    )
    mutation_receipt = _digest("typed-native-mutation-receipt")
    mutated = replace(
        prepared,
        transition_id="TRANSITION-COPY-TYPED-MUTATED",
        previous_state=OperationState.PREPARED,
        next_state=OperationState.MUTATED,
        mutation_attempted=True,
        native_mutation_receipt_sha256=mutation_receipt,
    )
    postcondition = replace(
        mutated,
        transition_id="TRANSITION-COPY-TYPED-POSTCONDITION",
        previous_state=OperationState.MUTATED,
        next_state=OperationState.POSTCONDITION_VERIFIED,
        target_evidence=evidence,
    )
    committed = replace(
        postcondition,
        transition_id="TRANSITION-COPY-TYPED-COMMITTED",
        previous_state=OperationState.POSTCONDITION_VERIFIED,
        next_state=OperationState.COMMITTED,
        completion_kind=OperationCompletionKind.NATIVE_COMMIT,
    )
    with lab.bundle.writer.acquire_runtime_mutex() as lease:
        lab.operation_ledger._append_transition_under_existing_mutex(
            lease,
            prepared,
            created_at_utc="2026-07-13T05:00:04Z",
        )
        lab.operation_ledger._append_transition_under_existing_mutex(
            lease,
            mutated,
            created_at_utc="2026-07-13T05:00:05Z",
        )
        lab.operation_ledger._append_transition_under_existing_mutex(
            lease,
            postcondition,
            created_at_utc="2026-07-13T05:00:06Z",
        )
        terminal_receipt = (
            lab.operation_ledger._append_transition_under_existing_mutex(
                lease,
                committed,
                created_at_utc="2026-07-13T05:00:07Z",
            )
        )
    return (
        committed,
        terminal_receipt,
        expected_plan,
        source_relative,
        target_relative,
    )


def _append_typed_copy_commit(
    lab: _TypedAncestorLab,
    *,
    mismatch: str | None = None,
) -> CopyTransition:
    source = replace(
        _source(),
        audit_ancestor_sha256=lab.bundle.ledger.head.last_segment_sha256,
    )
    with lab.bundle.writer.acquire_runtime_mutex() as lease:
        source_receipt = lab.copy_ledgers._append_source_under_existing_mutex(
            lease,
            source,
            created_at_utc="2026-07-13T05:00:08Z",
        )
    material = build_copy_provenance_material(
        source,
        source_receipt,
        manifest_id="MANIFEST-COPY-TYPED-PUBLISH",
    )
    copy_budget_sha256 = _digest("typed-copy-budget")
    operation_mismatch = (
        mismatch
        if mismatch
        in {
            "operation_reference",
            "context",
            "pair",
            "source_locator",
            "target_locator",
            "manifest",
            "budget",
            "classification_locator_mode",
            "observed_tree",
            "topology",
            "durable_identity",
            "entry_count",
            "total_bytes",
            "audit_ancestry",
            "audit_order",
        }
        else None
    )
    (
        operation,
        terminal_receipt,
        expected_plan,
        source_relative,
        target_relative,
    ) = _append_committed_publish(
        lab,
        manifest_sha256=material.publish_manifest.manifest_sha256,
        budget_sha256=copy_budget_sha256,
        entry_count=2,
        total_bytes=(
            source.source_evidence.size_bytes + len(material.provenance_bytes)
        ),
        mismatch=operation_mismatch,
    )
    target_locator = lab.copy_ledgers.target_locator(
        target_relative,
        source.classification,
    )
    publish_binding = lab.copy_ledgers.publish_operation_binding(
        plan=expected_plan,
        operation_reference="OPERATION-COPY-TYPED-PUBLISH",
        publish_transaction_id=operation.transaction_id,
        transaction_binding_sha256=source.transaction_binding_sha256,
        copy_binding_sha256=source.copy_binding_sha256,
        source_anchor=source_receipt.anchor,
        copy_audit_ancestor_sha256=source.audit_ancestor_sha256,
        target_locator=target_locator,
        source_relative_locator=source_relative,
        target_relative_locator=target_relative,
        operation_ledger=lab.operation_ledger,
    )
    stored_plan = (
        replace(
            expected_plan,
            publish_transaction_reference_hmac_sha256=(
                lab.copy_ledgers._publish_transaction_reference_hmac(
                    _opaque_txn("copy-typed-missing")
                )
            ),
        )
        if mismatch == "transaction"
        else expected_plan
    )
    prepared = CopyTransition(
        transition_id=_digest("typed-copy-prepared"),
        transaction_binding_sha256=source.transaction_binding_sha256,
        copy_binding_sha256=source.copy_binding_sha256,
        previous_state=None,
        next_state=CopyState.PREPARED,
        source_anchor=source_receipt.anchor,
        audit_ancestor_sha256=source.audit_ancestor_sha256,
        classification=source.classification,
        target_locator=target_locator,
        expected_manifest_sha256=material.publish_manifest.manifest_sha256,
        provenance_metadata_sha256=material.provenance_sha256,
        budget_sha256=copy_budget_sha256,
        publish_operation_binding_sha256=(
            _digest("typed-copy-forged-operation-binding")
            if mismatch == "operation_binding"
            else publish_binding
        ),
        publish_operation_plan=stored_plan,
        mutation_attempted=False,
        publish_transaction_id=(
            _opaque_txn("copy-typed-missing")
            if mismatch == "transaction"
            else operation.transaction_id
        ),
    )
    mutated = replace(
        prepared,
        transition_id=_digest("typed-copy-mutated"),
        previous_state=CopyState.PREPARED,
        next_state=CopyState.MUTATED,
        mutation_attempted=True,
        publish_terminal_segment_sha256=(
            _digest("typed-copy-wrong-terminal-segment")
            if mismatch == "terminal_segment"
            else terminal_receipt.segment_sha256
        ),
        publish_terminal_state=(
            OperationState.RECOVERED_COMMIT
            if mismatch == "terminal_state"
            else operation.next_state
        ),
    )
    operation_target = operation.target_evidence
    assert operation_target is not None
    target = CopyTargetEvidence(
        root_identity_hmac_sha256=_digest("typed-copy-target-root"),
        tree_identity_hmac_sha256=operation_target.durable_identity_sha256,
        payload=CopyFileEvidence(
            identity_hmac_sha256=_digest("typed-copy-target-payload"),
            size_bytes=source.source_evidence.size_bytes,
            sha256=source.source_evidence.sha256,
            change_evidence_sha256=_digest("typed-copy-target-payload-change"),
        ),
        provenance=CopyFileEvidence(
            identity_hmac_sha256=_digest("typed-copy-target-provenance"),
            size_bytes=len(material.provenance_bytes),
            sha256=material.provenance_sha256,
            change_evidence_sha256=_digest(
                "typed-copy-target-provenance-change"
            ),
        ),
        manifest_sha256=material.publish_manifest.manifest_sha256,
        tree_sha256=(
            _digest("typed-copy-wrong-tree")
            if mismatch == "target_evidence"
            else operation_target.source_tree_sha256
        ),
        topology_sha256=operation_target.topology_sha256,
        entry_count=2,
        total_bytes=(
            source.source_evidence.size_bytes + len(material.provenance_bytes)
        ),
    )
    postcondition = replace(
        mutated,
        transition_id=_digest("typed-copy-postcondition"),
        previous_state=CopyState.MUTATED,
        next_state=CopyState.POSTCONDITION_VERIFIED,
        target_evidence=target,
    )
    committed = replace(
        postcondition,
        transition_id=_digest("typed-copy-committed"),
        previous_state=CopyState.POSTCONDITION_VERIFIED,
        next_state=CopyState.COMMITTED,
    )
    with lab.bundle.writer.acquire_runtime_mutex() as lease:
        for offset, transition in enumerate(
            (prepared, mutated, postcondition, committed),
            start=9,
        ):
            lab.copy_ledgers._append_transition_under_existing_mutex(
                lease,
                transition,
                created_at_utc=f"2026-07-13T05:00:{offset:02d}Z",
            )
    return committed


def _append_typed_copy_abort(
    lab: _TypedAncestorLab,
    *,
    recovered: bool,
) -> CopyTransition:
    source = replace(
        _source(index=41 if recovered else 40),
        audit_ancestor_sha256=lab.bundle.ledger.head.last_segment_sha256,
    )
    with lab.bundle.writer.acquire_runtime_mutex() as lease:
        source_receipt = lab.copy_ledgers._append_source_under_existing_mutex(
            lease,
            source,
            created_at_utc="2026-07-13T05:01:00Z",
        )
    material = build_copy_provenance_material(
        source,
        source_receipt,
        manifest_id="MANIFEST-COPY-TYPED-ABORT",
    )
    operation_evidence = OperationTreeEvidence(
        manifest_sha256=material.publish_manifest.manifest_sha256,
        source_tree_sha256=_digest("typed-abort-source-tree"),
        topology_sha256=_digest("typed-abort-topology"),
        durable_identity_sha256=_digest("typed-abort-identity"),
        entry_count=2,
        total_bytes=(
            source.source_evidence.size_bytes + len(material.provenance_bytes)
        ),
    )
    transaction_id = _opaque_txn(
        "copy-typed-recovered-abort" if recovered else "copy-typed-abort"
    )
    operation_id = (
        "OPERATION-COPY-TYPED-RECOVERED-ABORT"
        if recovered
        else "OPERATION-COPY-TYPED-ABORT"
    )
    pair_id = (
        "PAIR-COPY-TYPED-RECOVERED-ABORT"
        if recovered
        else "PAIR-COPY-TYPED-ABORT"
    )
    source_relative = (
        "tmp/jobs/internal/copy-typed-recovered-abort/publish/MANIFEST"
        if recovered
        else "tmp/jobs/internal/copy-typed-abort/publish/MANIFEST"
    )
    target_relative = (
        "Copy/source/COPY-TYPED-RECOVERED-ABORT"
        if recovered
        else "Copy/source/COPY-TYPED-ABORT"
    )
    operation_prepared = OperationTransition(
        transition_id=(
            "TRANSITION-COPY-TYPED-RECOVERED-ABORT-PREPARED"
            if recovered
            else "TRANSITION-COPY-TYPED-ABORT-PREPARED"
        ),
        transaction_id=transaction_id,
        operation_id=operation_id,
        pair_id=pair_id,
        previous_state=None,
        next_state=OperationState.PREPARED,
        context_binding_sha256=_digest("typed-abort-context"),
        manifest_sha256=material.publish_manifest.manifest_sha256,
        budget_sha256=_digest("typed-abort-budget"),
        source_locator=source_relative,
        target_locator=target_relative,
        source_evidence=operation_evidence,
        target_evidence=None,
        audit_ledger_head_sha256=source.audit_ancestor_sha256,
        mutation_attempted=False,
        classification=DataClassification.INTERNAL,
        locator_mode=OperationLocatorMode.SAFE_RELATIVE,
    )
    if recovered:
        operation_terminal = replace(
            operation_prepared,
            transition_id="TRANSITION-COPY-TYPED-RECOVERED-ABORT",
            previous_state=OperationState.PREPARED,
            next_state=OperationState.RECOVERED_ABORT,
            recovery_reason="SOURCE_EXACT_TARGET_ABSENT",
            recovery_guarantee_scope="COOPERATIVE_APPLICATION_WRITERS_ONLY",
            recovery_authority_head_sha256=source.audit_ancestor_sha256,
        )
    else:
        operation_terminal = replace(
            operation_prepared,
            transition_id="TRANSITION-COPY-TYPED-ABORT",
            previous_state=OperationState.PREPARED,
            next_state=OperationState.ABORTED,
            error_code="TEST_PRE_NATIVE_ABORT",
        )
    with lab.bundle.writer.acquire_runtime_mutex() as lease:
        lab.operation_ledger._append_transition_under_existing_mutex(
            lease,
            operation_prepared,
            created_at_utc="2026-07-13T05:01:01Z",
        )
        operation_receipt = (
            lab.operation_ledger._append_transition_under_existing_mutex(
                lease,
                operation_terminal,
                created_at_utc="2026-07-13T05:01:02Z",
            )
        )
    plan = lab.copy_ledgers._project_operation_transition(operation_terminal)
    copy_target_locator = lab.copy_ledgers.target_locator(
        target_relative,
        source.classification,
    )
    publish_binding = lab.copy_ledgers.publish_operation_binding(
        plan=plan,
        operation_reference=operation_id,
        publish_transaction_id=transaction_id,
        transaction_binding_sha256=source.transaction_binding_sha256,
        copy_binding_sha256=source.copy_binding_sha256,
        source_anchor=source_receipt.anchor,
        copy_audit_ancestor_sha256=source.audit_ancestor_sha256,
        target_locator=copy_target_locator,
        source_relative_locator=source_relative,
        target_relative_locator=target_relative,
        operation_ledger=lab.operation_ledger,
    )
    prepared = CopyTransition(
        transition_id=_digest(f"typed-copy-abort-prepared-{recovered}"),
        transaction_binding_sha256=source.transaction_binding_sha256,
        copy_binding_sha256=source.copy_binding_sha256,
        previous_state=None,
        next_state=CopyState.PREPARED,
        source_anchor=source_receipt.anchor,
        audit_ancestor_sha256=source.audit_ancestor_sha256,
        classification=source.classification,
        target_locator=copy_target_locator,
        expected_manifest_sha256=material.publish_manifest.manifest_sha256,
        provenance_metadata_sha256=material.provenance_sha256,
        budget_sha256=operation_terminal.budget_sha256,
        publish_operation_binding_sha256=publish_binding,
        publish_operation_plan=plan,
        mutation_attempted=False,
        publish_transaction_id=transaction_id,
    )
    terminal = replace(
        prepared,
        transition_id=_digest(f"typed-copy-abort-terminal-{recovered}"),
        previous_state=CopyState.PREPARED,
        next_state=(CopyState.RECOVERED_ABORT if recovered else CopyState.ABORTED),
        publish_terminal_segment_sha256=operation_receipt.segment_sha256,
        publish_terminal_state=operation_terminal.next_state,
        error_code=(None if recovered else "TEST_PRE_NATIVE_ABORT"),
        recovery_reason=(
            "PUBLISH_NOT_NATIVE_TARGET_ABSENT_SOURCE_EXACT"
            if recovered
            else None
        ),
        recovery_authority_head_sha256=(
            source.audit_ancestor_sha256 if recovered else None
        ),
    )
    with lab.bundle.writer.acquire_runtime_mutex() as lease:
        lab.copy_ledgers._append_transition_under_existing_mutex(
            lease,
            prepared,
            created_at_utc="2026-07-13T05:01:03Z",
        )
        lab.copy_ledgers._append_transition_under_existing_mutex(
            lease,
            terminal,
            created_at_utc="2026-07-13T05:01:04Z",
        )
    return terminal


def _append_source_only_absence_abort(
    lab: _TypedAncestorLab,
    *,
    index: int,
    witness_override: CopyOperationAbsenceWitness | None = None,
    restricted: bool = False,
) -> tuple[CopyTransition, CopyOperationAbsenceWitness, CopyPublishOperationPlan]:
    source = replace(
        _source(index=index, restricted=restricted),
        audit_ancestor_sha256=lab.bundle.ledger.head.last_segment_sha256,
    )
    with lab.bundle.writer.acquire_runtime_mutex() as lease:
        source_receipt = lab.copy_ledgers._append_source_under_existing_mutex(
            lease,
            source,
            created_at_utc="2026-07-13T05:02:00Z",
        )
    material = build_copy_provenance_material(
        source,
        source_receipt,
        manifest_id=f"MANIFEST-COPY-ABSENCE-{index}",
    )
    source_relative = (
        f"tmp/jobs/RESTRICTED/{_RESTRICTED_RAW_RUN}/"
        f"{_RESTRICTED_RAW_JOB}/publish/MANIFEST"
        if restricted
        else f"tmp/jobs/internal/copy-absence-{index}/publish/MANIFEST"
    )
    target_relative = (
        f"Copy/restricted/{_RESTRICTED_RAW_COPY}"
        if restricted
        else f"Copy/source/COPY-ABSENCE-{index}"
    )
    operation_reference = (
        lab.operation_ledger.operation_reference(
            _RESTRICTED_RAW_OPERATION,
            source.classification,
        )
        if restricted
        else f"OPERATION-COPY-ABSENCE-{index}"
    )
    plan = lab.copy_ledgers._project_publish_operation_plan(
        kind=CopyPublishPlanKind.UNSTARTED,
        operation_reference=operation_reference,
        context_binding_sha256=_digest(f"absence-context-{index}"),
        manifest_sha256=material.publish_manifest.manifest_sha256,
        budget_sha256=_digest(f"absence-budget-{index}"),
        classification=source.classification,
    )
    target_locator = lab.copy_ledgers.target_locator(
        target_relative,
        source.classification,
    )
    publish_binding = lab.copy_ledgers.publish_operation_binding(
        plan=plan,
        operation_reference=operation_reference,
        publish_transaction_id=None,
        transaction_binding_sha256=source.transaction_binding_sha256,
        copy_binding_sha256=source.copy_binding_sha256,
        source_anchor=source_receipt.anchor,
        copy_audit_ancestor_sha256=source.audit_ancestor_sha256,
        target_locator=target_locator,
        source_relative_locator=source_relative,
        target_relative_locator=target_relative,
        operation_ledger=lab.operation_ledger,
    )
    with lab.bundle.writer.acquire_runtime_mutex() as lease:
        witness = (
            lab.copy_ledgers._issue_operation_absence_witness_under_existing_mutex(
                lease,
                lab.operation_ledger,
                plan=plan,
                operation_reference=operation_reference,
                publish_transaction_id=None,
                transaction_binding_sha256=source.transaction_binding_sha256,
                copy_binding_sha256=source.copy_binding_sha256,
                source_anchor=source_receipt.anchor,
                copy_audit_ancestor_sha256=source.audit_ancestor_sha256,
                target_locator=target_locator,
                source_relative_locator=source_relative,
                target_relative_locator=target_relative,
                publish_operation_binding_sha256=publish_binding,
            )
        )
        terminal = CopyTransition(
            transition_id=_digest(f"source-only-absence-terminal-{index}"),
            transaction_binding_sha256=source.transaction_binding_sha256,
            copy_binding_sha256=source.copy_binding_sha256,
            previous_state=None,
            next_state=CopyState.RECOVERED_ABORT,
            source_anchor=source_receipt.anchor,
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
            publish_operation_absence_witness=(
                witness if witness_override is None else witness_override
            ),
            recovery_reason="PUBLISH_NOT_NATIVE_TARGET_ABSENT_SOURCE_EXACT",
            recovery_authority_head_sha256=source.audit_ancestor_sha256,
        )
        lab.copy_ledgers._append_transition_under_existing_mutex(
            lease,
            terminal,
            created_at_utc="2026-07-13T05:02:01Z",
        )
    return terminal, witness, plan


def _append_prepared_absence_abort(
    lab: _TypedAncestorLab,
    *,
    recovered: bool,
) -> CopyTransition:
    index = 56 if recovered else 55
    source = replace(
        _source(index=index),
        audit_ancestor_sha256=lab.bundle.ledger.head.last_segment_sha256,
    )
    with lab.bundle.writer.acquire_runtime_mutex() as lease:
        source_receipt = lab.copy_ledgers._append_source_under_existing_mutex(
            lease,
            source,
            created_at_utc="2026-07-13T05:02:10Z",
        )
    material = build_copy_provenance_material(
        source,
        source_receipt,
        manifest_id=f"MANIFEST-COPY-PREPARED-ABSENCE-{index}",
    )
    source_relative = f"tmp/jobs/internal/prepared-absence-{index}/publish/MANIFEST"
    target_relative = f"Copy/source/PREPARED-ABSENCE-{index}"
    publish_transaction_id = _opaque_txn(f"prepared-absence-{index}")
    source_evidence = OperationTreeEvidence(
        manifest_sha256=material.publish_manifest.manifest_sha256,
        source_tree_sha256=_digest(f"prepared-absence-tree-{index}"),
        topology_sha256=_digest(f"prepared-absence-topology-{index}"),
        durable_identity_sha256=_digest(f"prepared-absence-identity-{index}"),
        entry_count=2,
        total_bytes=(
            source.source_evidence.size_bytes + len(material.provenance_bytes)
        ),
    )
    operation_reference = f"OPERATION-PREPARED-ABSENCE-{index}"
    plan = lab.copy_ledgers._project_publish_operation_plan(
        kind=CopyPublishPlanKind.RESERVED,
        operation_reference=operation_reference,
        context_binding_sha256=_digest(f"prepared-absence-context-{index}"),
        manifest_sha256=material.publish_manifest.manifest_sha256,
        budget_sha256=_digest(f"prepared-absence-budget-{index}"),
        classification=source.classification,
        publish_transaction_id=publish_transaction_id,
        pair_reference=f"PAIR-PREPARED-ABSENCE-{index}",
        locator_mode=OperationLocatorMode.SAFE_RELATIVE,
        source_locator=source_relative,
        target_locator=target_relative,
        source_evidence=source_evidence,
        audit_ancestor_sha256=source.audit_ancestor_sha256,
    )
    target_locator = lab.copy_ledgers.target_locator(
        target_relative,
        source.classification,
    )
    publish_binding = lab.copy_ledgers.publish_operation_binding(
        plan=plan,
        operation_reference=operation_reference,
        publish_transaction_id=publish_transaction_id,
        transaction_binding_sha256=source.transaction_binding_sha256,
        copy_binding_sha256=source.copy_binding_sha256,
        source_anchor=source_receipt.anchor,
        copy_audit_ancestor_sha256=source.audit_ancestor_sha256,
        target_locator=target_locator,
        source_relative_locator=source_relative,
        target_relative_locator=target_relative,
        operation_ledger=lab.operation_ledger,
    )
    prepared = CopyTransition(
        transition_id=_digest(f"prepared-absence-prepared-{index}"),
        transaction_binding_sha256=source.transaction_binding_sha256,
        copy_binding_sha256=source.copy_binding_sha256,
        previous_state=None,
        next_state=CopyState.PREPARED,
        source_anchor=source_receipt.anchor,
        audit_ancestor_sha256=source.audit_ancestor_sha256,
        classification=source.classification,
        target_locator=target_locator,
        expected_manifest_sha256=material.publish_manifest.manifest_sha256,
        provenance_metadata_sha256=material.provenance_sha256,
        budget_sha256=plan.budget_sha256,
        publish_operation_binding_sha256=publish_binding,
        publish_operation_plan=plan,
        mutation_attempted=False,
        publish_transaction_id=publish_transaction_id,
    )
    with lab.bundle.writer.acquire_runtime_mutex() as lease:
        lab.copy_ledgers._append_transition_under_existing_mutex(
            lease,
            prepared,
            created_at_utc="2026-07-13T05:02:11Z",
        )

    reopened_operation_ledger = _create_test_operation_ledger(
        lab.bundle,
        epoch_id="RUN-COPY-TYPED-OPERATIONS",
    )
    reopened_copy_ledgers = _create_test_copy_ledgers(
        lab.bundle,
        reopened_operation_ledger,
        epoch_id=lab.epoch_id,
        run_scope_id=lab.run_scope_id,
    )
    with lab.bundle.writer.acquire_runtime_mutex() as lease:
        durable = reopened_copy_ledgers.transaction_result_under_existing_mutex(
            lease,
            prepared.transaction_binding_sha256,
        )
        assert durable is not None
        durable_prepared = durable[0]
        assert durable_prepared.publish_operation_plan == plan
        witness = (
            reopened_copy_ledgers._issue_operation_absence_witness_under_existing_mutex(
                lease,
                reopened_operation_ledger,
                plan=durable_prepared.publish_operation_plan,
                operation_reference=operation_reference,
                publish_transaction_id=publish_transaction_id,
                transaction_binding_sha256=source.transaction_binding_sha256,
                copy_binding_sha256=source.copy_binding_sha256,
                source_anchor=source_receipt.anchor,
                copy_audit_ancestor_sha256=source.audit_ancestor_sha256,
                target_locator=target_locator,
                source_relative_locator=source_relative,
                target_relative_locator=target_relative,
                publish_operation_binding_sha256=publish_binding,
            )
        )
        terminal = replace(
            durable_prepared,
            transition_id=_digest(f"prepared-absence-terminal-{index}"),
            previous_state=CopyState.PREPARED,
            next_state=(
                CopyState.RECOVERED_ABORT if recovered else CopyState.ABORTED
            ),
            publish_operation_absence_witness=witness,
            error_code=(None if recovered else "TEST_PREPARED_ABSENCE"),
            recovery_reason=(
                "PUBLISH_NOT_NATIVE_TARGET_ABSENT_SOURCE_EXACT"
                if recovered
                else None
            ),
            recovery_authority_head_sha256=(
                source.audit_ancestor_sha256 if recovered else None
            ),
        )
        reopened_copy_ledgers._append_transition_under_existing_mutex(
            lease,
            terminal,
            created_at_utc="2026-07-13T05:02:12Z",
        )
    return terminal


def _append_invalid_pending_or_absence_plan(
    lab: _TypedAncestorLab,
    *,
    index: int,
    reservation_mode: str,
    with_absence: bool,
) -> CopyTransition:
    if reservation_mode not in {"missing", "out_of_order", "forged_binding"}:
        raise AssertionError("unsupported synthetic reservation mode")
    earlier_audit_head = lab.bundle.ledger.head.last_segment_sha256
    if reservation_mode == "out_of_order":
        source_audit_head = _append_typed_audit_marker(lab)
        reservation_audit_head = earlier_audit_head
    else:
        source_audit_head = earlier_audit_head
        reservation_audit_head = (
            _digest(f"missing-reservation-audit-{index}")
            if reservation_mode == "missing"
            else earlier_audit_head
        )
    source = replace(
        _source(index=index),
        audit_ancestor_sha256=source_audit_head,
    )
    with lab.bundle.writer.acquire_runtime_mutex() as lease:
        source_receipt = lab.copy_ledgers._append_source_under_existing_mutex(
            lease,
            source,
            created_at_utc="2026-07-13T05:03:00Z",
        )
    material = build_copy_provenance_material(
        source,
        source_receipt,
        manifest_id=f"MANIFEST-COPY-PENDING-AUDIT-{index}",
    )
    source_relative = f"tmp/jobs/internal/pending-audit-{index}/publish/MANIFEST"
    target_relative = f"Copy/source/PENDING-AUDIT-{index}"
    publish_transaction_id = _opaque_txn(f"pending-audit-{index}")
    operation_reference = f"OPERATION-PENDING-AUDIT-{index}"
    plan = lab.copy_ledgers._project_publish_operation_plan(
        kind=CopyPublishPlanKind.RESERVED,
        operation_reference=operation_reference,
        context_binding_sha256=_digest(f"pending-audit-context-{index}"),
        manifest_sha256=material.publish_manifest.manifest_sha256,
        budget_sha256=_digest(f"pending-audit-budget-{index}"),
        classification=source.classification,
        publish_transaction_id=publish_transaction_id,
        pair_reference=f"PAIR-PENDING-AUDIT-{index}",
        locator_mode=OperationLocatorMode.SAFE_RELATIVE,
        source_locator=source_relative,
        target_locator=target_relative,
        source_evidence=OperationTreeEvidence(
            manifest_sha256=material.publish_manifest.manifest_sha256,
            source_tree_sha256=_digest(f"pending-audit-tree-{index}"),
            topology_sha256=_digest(f"pending-audit-topology-{index}"),
            durable_identity_sha256=_digest(f"pending-audit-identity-{index}"),
            entry_count=2,
            total_bytes=(
                source.source_evidence.size_bytes
                + len(material.provenance_bytes)
            ),
        ),
        audit_ancestor_sha256=reservation_audit_head,
    )
    target_locator = lab.copy_ledgers.target_locator(
        target_relative,
        source.classification,
    )
    publish_binding = lab.copy_ledgers.publish_operation_binding(
        plan=plan,
        operation_reference=operation_reference,
        publish_transaction_id=publish_transaction_id,
        transaction_binding_sha256=source.transaction_binding_sha256,
        copy_binding_sha256=source.copy_binding_sha256,
        source_anchor=source_receipt.anchor,
        copy_audit_ancestor_sha256=source.audit_ancestor_sha256,
        target_locator=target_locator,
        source_relative_locator=source_relative,
        target_relative_locator=target_relative,
        operation_ledger=lab.operation_ledger,
    )
    prepared = CopyTransition(
        transition_id=_digest(f"pending-audit-prepared-{index}"),
        transaction_binding_sha256=source.transaction_binding_sha256,
        copy_binding_sha256=source.copy_binding_sha256,
        previous_state=None,
        next_state=CopyState.PREPARED,
        source_anchor=source_receipt.anchor,
        audit_ancestor_sha256=source.audit_ancestor_sha256,
        classification=source.classification,
        target_locator=target_locator,
        expected_manifest_sha256=material.publish_manifest.manifest_sha256,
        provenance_metadata_sha256=material.provenance_sha256,
        budget_sha256=plan.budget_sha256,
        publish_operation_binding_sha256=(
            _digest(f"forged-pending-binding-{index}")
            if reservation_mode == "forged_binding"
            else publish_binding
        ),
        publish_operation_plan=plan,
        mutation_attempted=False,
        publish_transaction_id=publish_transaction_id,
    )
    with lab.bundle.writer.acquire_runtime_mutex() as lease:
        lab.copy_ledgers._append_transition_under_existing_mutex(
            lease,
            prepared,
            created_at_utc="2026-07-13T05:03:01Z",
        )
        if not with_absence:
            return prepared
        witness = (
            lab.copy_ledgers._issue_operation_absence_witness_under_existing_mutex(
                lease,
                lab.operation_ledger,
                plan=plan,
                operation_reference=operation_reference,
                publish_transaction_id=publish_transaction_id,
                transaction_binding_sha256=source.transaction_binding_sha256,
                copy_binding_sha256=source.copy_binding_sha256,
                source_anchor=source_receipt.anchor,
                copy_audit_ancestor_sha256=source.audit_ancestor_sha256,
                target_locator=target_locator,
                source_relative_locator=source_relative,
                target_relative_locator=target_relative,
                publish_operation_binding_sha256=publish_binding,
            )
        )
        terminal = replace(
            prepared,
            transition_id=_digest(f"pending-audit-aborted-{index}"),
            previous_state=CopyState.PREPARED,
            next_state=CopyState.ABORTED,
            publish_operation_binding_sha256=publish_binding,
            publish_operation_absence_witness=witness,
            error_code="TEST_PENDING_OPERATION_ABSENT",
        )
        lab.copy_ledgers._append_transition_under_existing_mutex(
            lease,
            terminal,
            created_at_utc="2026-07-13T05:03:02Z",
        )
    return terminal


def _append_unrelated_aborted_operation(
    lab: _TypedAncestorLab,
    *,
    suffix: str,
    operation_id: str | None = None,
    transaction_id: str | None = None,
) -> None:
    evidence = OperationTreeEvidence(
        manifest_sha256=_digest(f"unrelated-manifest-{suffix}"),
        source_tree_sha256=_digest(f"unrelated-tree-{suffix}"),
        topology_sha256=_digest(f"unrelated-topology-{suffix}"),
        durable_identity_sha256=_digest(f"unrelated-identity-{suffix}"),
        entry_count=1,
        total_bytes=1,
    )
    prepared = OperationTransition(
        transition_id=f"TRANSITION-UNRELATED-{suffix}-PREPARED",
        transaction_id=(transaction_id or _opaque_txn(f"unrelated-{suffix}")),
        operation_id=(operation_id or f"OPERATION-UNRELATED-{suffix}"),
        pair_id=f"PAIR-UNRELATED-{suffix}",
        previous_state=None,
        next_state=OperationState.PREPARED,
        context_binding_sha256=_digest(f"unrelated-context-{suffix}"),
        manifest_sha256=evidence.manifest_sha256,
        budget_sha256=_digest(f"unrelated-budget-{suffix}"),
        source_locator=f"tmp/jobs/internal/unrelated-{suffix}/publish/MANIFEST",
        target_locator=f"Copy/source/UNRELATED-{suffix}",
        source_evidence=evidence,
        target_evidence=None,
        audit_ledger_head_sha256=lab.bundle.ledger.head.last_segment_sha256,
        mutation_attempted=False,
    )
    aborted = replace(
        prepared,
        transition_id=f"TRANSITION-UNRELATED-{suffix}-ABORTED",
        previous_state=OperationState.PREPARED,
        next_state=OperationState.ABORTED,
        error_code="TEST_UNRELATED_ABORT",
    )
    with lab.bundle.writer.acquire_runtime_mutex() as lease:
        lab.operation_ledger._append_transition_under_existing_mutex(
            lease,
            prepared,
            created_at_utc="2026-07-13T05:03:00Z",
        )
        lab.operation_ledger._append_transition_under_existing_mutex(
            lease,
            aborted,
            created_at_utc="2026-07-13T05:03:01Z",
        )


def _commit_lifecycle(
    ledgers: DurableCopyLedgers,
    lab: _CopyLab,
    source: CopySourceRecord,
    receipt: CopySourceReceipt,
) -> tuple[CopyTransition, str]:
    prepared = _prepared(source, receipt, ledgers=ledgers)
    terminal = _digest("publish-terminal")
    mutated = replace(
        prepared,
        transition_id=_digest("transition-1-mutated"),
        previous_state=CopyState.PREPARED,
        next_state=CopyState.MUTATED,
        mutation_attempted=True,
        publish_terminal_segment_sha256=terminal,
        publish_terminal_state=OperationState.COMMITTED,
    )
    post = replace(
        mutated,
        transition_id=_digest("transition-1-post"),
        previous_state=CopyState.MUTATED,
        next_state=CopyState.POSTCONDITION_VERIFIED,
        target_evidence=_target(source, prepared),
    )
    committed = replace(
        post,
        transition_id=_digest("transition-1-committed"),
        previous_state=CopyState.POSTCONDITION_VERIFIED,
        next_state=CopyState.COMMITTED,
    )
    with lab.writer.acquire_runtime_mutex() as lease:
        ledgers._append_transition_under_existing_mutex(lease, prepared)
        ledgers._append_transition_under_existing_mutex(lease, mutated)
        ledgers._append_transition_under_existing_mutex(lease, post)
        ledgers._append_transition_under_existing_mutex(lease, committed)
    return committed, terminal


def test_dual_genesis_uses_independent_store_domain_and_key(copy_lab: _CopyLab) -> None:
    ledgers = _ledgers(copy_lab)
    head = ledgers.head
    assert head.source.segment_count == 1
    assert head.copy.segment_count == 1
    assert head.source.key_id != head.copy.key_id
    source_files = list(
        _segment_entries(
            copy_lab.project
            / "Copy"
            / "ledger"
            / "source"
            / "segments"
            / copy_lab.epoch_id
        )
    )
    copy_files = list(
        _segment_entries(
            copy_lab.project
            / "Copy"
            / "ledger"
            / "copy"
            / "segments"
            / copy_lab.epoch_id
        )
    )
    assert len(source_files) == len(copy_files) == 1
    assert source_files[0].name != copy_files[0].name
    assert _extended_test_host_path(source_files[0]).read_bytes() != (
        _extended_test_host_path(copy_files[0]).read_bytes()
    )
    source_genesis = parse_canonical_json_bytes(
        _extended_test_host_path(source_files[0]).read_bytes(),
        maximum_bytes=512 * 1024,
    )
    copy_genesis = parse_canonical_json_bytes(
        _extended_test_host_path(copy_files[0]).read_bytes(),
        maximum_bytes=512 * 1024,
    )
    assert source_genesis["schema_version"] == "1.0"
    assert copy_genesis["schema_version"] == "1.3"
    assert source_genesis["key_id"] != copy_genesis["key_id"]


def test_persisted_publish_plan_parser_rejects_legacy_raw_or_dual_shape(
    copy_lab: _CopyLab,
) -> None:
    ledgers = _ledgers(copy_lab)
    plan = ledgers._project_publish_operation_plan(
        kind=CopyPublishPlanKind.UNSTARTED,
        operation_reference="OPERATION-STRICT-PARSER",
        context_binding_sha256=_digest("strict-parser-context"),
        manifest_sha256=_digest("strict-parser-manifest"),
        budget_sha256=_digest("strict-parser-budget"),
        classification=DataClassification.INTERNAL,
    )
    projected = plan.to_json()
    dual = {**projected, "operation_reference": "OPERATION-RAW-DUAL"}
    legacy = dict(projected)
    legacy.pop("operation_reference_hmac_sha256")
    legacy["operation_reference"] = "OPERATION-RAW-LEGACY"
    for raw_name, projected_name in (
        ("publish_transaction_id", "publish_transaction_reference_hmac_sha256"),
        ("pair_reference", "pair_reference_hmac_sha256"),
        ("source_locator", "source_locator_hmac_sha256"),
        ("target_locator", "target_locator_hmac_sha256"),
    ):
        legacy[raw_name] = legacy.pop(projected_name)

    for rejected in (dual, legacy):
        with pytest.raises(CopyLedgerError) as raised:
            copy_ledger_module._publish_operation_plan_from_json(rejected)
        assert raised.value.code is CopyLedgerCode.CHAIN_CORRUPT


def test_copy_plan_projection_hides_raw_facts_and_separates_locator_roles(
    copy_lab: _CopyLab,
) -> None:
    ledgers = _ledgers(copy_lab)
    raw_operation = "OPERATION-PROJECTION-CANARY"
    raw_transaction = _opaque_txn("projection-canary")
    raw_pair = "PAIR-PROJECTION-CANARY"
    raw_locator = "tmp/jobs/internal/projection-canary"
    evidence = OperationTreeEvidence(
        manifest_sha256=_digest("projection-manifest"),
        source_tree_sha256=_digest("projection-tree"),
        topology_sha256=_digest("projection-topology"),
        durable_identity_sha256=_digest("projection-identity"),
        entry_count=1,
        total_bytes=1,
    )
    plan = ledgers._project_publish_operation_plan(
        kind=CopyPublishPlanKind.RESERVED,
        operation_reference=raw_operation,
        context_binding_sha256=_digest("projection-context"),
        manifest_sha256=evidence.manifest_sha256,
        budget_sha256=_digest("projection-budget"),
        classification=DataClassification.INTERNAL,
        publish_transaction_id=raw_transaction,
        pair_reference=raw_pair,
        locator_mode=OperationLocatorMode.SAFE_RELATIVE,
        source_locator=raw_locator,
        target_locator=raw_locator,
        source_evidence=evidence,
        audit_ancestor_sha256=_digest("projection-audit"),
    )
    serialized = canonical_json_bytes(plan.to_json())
    for raw in (raw_operation, raw_transaction, raw_pair, raw_locator):
        assert raw.encode("ascii") not in serialized
    assert plan.source_locator_hmac_sha256 != plan.target_locator_hmac_sha256
    assert set(plan.to_json()) == {
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


def test_storage_epoch_and_segments_do_not_persist_plaintext_business_ids(
    copy_lab: _CopyLab,
) -> None:
    ledgers = _ledgers(copy_lab)
    source = _source()
    with copy_lab.writer.acquire_runtime_mutex() as lease:
        receipt = ledgers._append_source_under_existing_mutex(lease, source)
        ledgers._append_transition_under_existing_mutex(
            lease,
            _prepared(source, receipt, ledgers=ledgers),
        )

    assert ledgers.matches_run_scope(copy_lab.run_scope_id)
    assert not ledgers.matches_run_scope("RUN-COPY-LEDGER-OTHER")
    assert len(copy_lab.epoch_id) == 64
    assert copy_lab.run_scope_id not in copy_lab.epoch_id
    persisted_paths = tuple(
        path
        for kind in ("source", "copy")
        for path in _segment_entries(
            copy_lab.project
            / "Copy"
            / "ledger"
            / kind
            / "segments"
            / copy_lab.epoch_id
        )
    )
    serialized = b"".join(
        _extended_test_host_path(path).read_bytes()
        for path in persisted_paths
    )
    for forbidden in (
        copy_lab.run_scope_id,
        "JOB-COPY-LEDGER-S3F",
        "OP-COPY-LEDGER-S3F",
        "COPY-0001",
    ):
        assert forbidden not in "\n".join(str(path) for path in persisted_paths)
        assert forbidden.encode("ascii") not in serialized


@pytest.mark.parametrize("restricted", [False, True])
@pytest.mark.parametrize(
    "raw_business_id",
    [
        "JOB-PRIVATE-PUBLISH-2026",
        "TRANSACTION-PRIVATE-PUBLISH-2026",
        "COPY-PRIVATE-PUBLISH-2026",
    ],
)
def test_copy_transition_rejects_business_id_as_publish_transaction(
    copy_lab: _CopyLab,
    restricted: bool,
    raw_business_id: str,
) -> None:
    ledgers = _ledgers(copy_lab)
    source = _source(index=81, restricted=restricted)
    with copy_lab.writer.acquire_runtime_mutex() as lease:
        receipt = ledgers._append_source_under_existing_mutex(lease, source)
    prepared = _prepared(source, receipt, ledgers=ledgers, index=81)

    with pytest.raises(CopyLedgerError) as raised:
        replace(prepared, publish_transaction_id=raw_business_id)
    assert raised.value.code is CopyLedgerCode.INVALID_REQUEST
    persisted = prepared.to_json()
    persisted["publish_transaction_id"] = raw_business_id
    with pytest.raises(CopyLedgerError) as parsed:
        copy_ledger_module._transition_from_json(persisted)
    assert parsed.value.code is CopyLedgerCode.CHAIN_CORRUPT


@pytest.mark.parametrize("restricted", [False, True])
def test_all_copy_segments_keep_business_ids_outside_opaque_transaction_channel(
    copy_lab: _CopyLab,
    restricted: bool,
) -> None:
    ledgers = _ledgers(copy_lab)
    source = _source(index=82, restricted=restricted)
    with copy_lab.writer.acquire_runtime_mutex() as lease:
        receipt = ledgers._append_source_under_existing_mutex(lease, source)
        prepared = _prepared(source, receipt, ledgers=ledgers, index=82)
        ledgers._append_transition_under_existing_mutex(lease, prepared)

    assert prepared.publish_transaction_id is not None
    assert copy_ledger_module._OPAQUE_PUBLISH_TRANSACTION_REFERENCE.fullmatch(
        prepared.publish_transaction_id
    )
    serialized = b"".join(
        _extended_test_host_path(path).read_bytes()
        for kind in ("source", "copy")
        for path in _segment_entries(
            copy_lab.project
            / "Copy"
            / "ledger"
            / kind
            / "segments"
            / copy_lab.epoch_id
        )
    )
    assert prepared.publish_transaction_id.encode("ascii") in serialized
    for forbidden in (
        "JOB-PRIVATE-PUBLISH-2026",
        "TRANSACTION-PRIVATE-PUBLISH-2026",
        "COPY-PRIVATE-PUBLISH-2026",
        "OPERATION-PUBLISH-82",
        "tmp/jobs/internal/copy-82/publish/MANIFEST",
        "Copy/source/COPY-82",
    ):
        assert forbidden.encode("ascii") not in serialized


def test_source_genesis_cannot_be_interchanged_with_copy_store(copy_lab: _CopyLab) -> None:
    _ledgers(copy_lab)
    source_dir = (
        copy_lab.project
        / "Copy"
        / "ledger"
        / "source"
        / "segments"
        / copy_lab.epoch_id
    )
    copy_dir = (
        copy_lab.project
        / "Copy"
        / "ledger"
        / "copy"
        / "segments"
        / copy_lab.epoch_id
    )
    source_genesis = next(_segment_entries(source_dir))
    copy_genesis = next(_segment_entries(copy_dir))
    interchanged = copy_dir / source_genesis.name
    _extended_test_host_path(copy_genesis).rename(
        _extended_test_host_path(interchanged)
    )
    _extended_test_host_path(interchanged).write_bytes(
        _extended_test_host_path(source_genesis).read_bytes()
    )

    with pytest.raises(CopyLedgerError) as raised:
        _ledgers(copy_lab, initialize=False)
    assert raised.value.code in {
        CopyLedgerCode.AUTHENTICATION_FAILED,
        CopyLedgerCode.CHAIN_CORRUPT,
    }


def test_epoch_must_authenticate_exact_run_scope(copy_lab: _CopyLab) -> None:
    copy_root = copy_lab.project / "Copy" / "ledger"
    before_files = tuple(sorted(path.relative_to(copy_root) for path in copy_root.rglob("*") if path.is_file()))
    wrong_epoch = _derive_copy_ledger_epoch_id(
        copy_lab.revision,
        "RUN-COPY-LEDGER-OTHER",
    )
    with pytest.raises(CopyLedgerError) as raised:
        DurableCopyLedgers(
            copy_lab.writer,
            copy_lab.revision,
            epoch_id=wrong_epoch,
            run_scope_id=copy_lab.run_scope_id,
            policy_digest=POLICY_DIGEST,
            initialize=True,
            initialized_at_utc="2026-07-13T00:00:02Z",
            _constructor=_COPY_LEDGERS_CONSTRUCTOR,
        )
    assert raised.value.code is CopyLedgerCode.INVALID_REQUEST

    with pytest.raises(CopyLedgerError) as wrong_run:
        DurableCopyLedgers(
            copy_lab.writer,
            copy_lab.revision,
            epoch_id=copy_lab.epoch_id,
            run_scope_id="RUN-COPY-LEDGER-OTHER",
            policy_digest=POLICY_DIGEST,
            initialize=True,
            initialized_at_utc="2026-07-13T00:00:02Z",
            _constructor=_COPY_LEDGERS_CONSTRUCTOR,
        )
    assert wrong_run.value.code is CopyLedgerCode.INVALID_REQUEST

    wrong_revision = AuditKeyRevisionStore(
        copy_lab.writer,
        _constructor=_LEDGER_CONSTRUCTOR,
    ).create_revision(
        revision_sequence=2,
        revision_id="KEYREV-S3F-UNACTIVATED",
        master_key=b"U" * 32,
        created_at_utc="2026-07-13T00:00:03Z",
    )
    with pytest.raises(CopyLedgerError) as wrong_revision_error:
        DurableCopyLedgers(
            copy_lab.writer,
            copy_lab.revision,
            epoch_id=_derive_copy_ledger_epoch_id(
                wrong_revision,
                copy_lab.run_scope_id,
            ),
            run_scope_id=copy_lab.run_scope_id,
            policy_digest=POLICY_DIGEST,
            known_revisions=(wrong_revision,),
            initialize=True,
            initialized_at_utc="2026-07-13T00:00:04Z",
            _constructor=_COPY_LEDGERS_CONSTRUCTOR,
        )
    assert wrong_revision_error.value.code is CopyLedgerCode.INVALID_REQUEST
    after_files = tuple(sorted(path.relative_to(copy_root) for path in copy_root.rglob("*") if path.is_file()))
    assert after_files == before_files == ()


def test_source_copy_commit_reopen_and_untrusted_ancestor_tuple_rejected(
    copy_lab: _CopyLab,
) -> None:
    ledgers = _ledgers(copy_lab)
    source = _source()
    with copy_lab.writer.acquire_runtime_mutex() as lease:
        source_receipt = ledgers._append_source_under_existing_mutex(lease, source)
    committed, terminal = _commit_lifecycle(ledgers, copy_lab, source, source_receipt)
    assert committed.next_state is CopyState.COMMITTED
    assert ledgers.head.pending_source_count == 0

    reopened = _ledgers(copy_lab, initialize=False)
    with copy_lab.writer.acquire_runtime_mutex() as lease:
        result = reopened.transaction_result_under_existing_mutex(
            lease,
            source.transaction_binding_sha256,
        )
        assert result is not None and result[0] == committed
        with pytest.raises(CopyLedgerError) as raised:
            reopened._verify_external_ancestors_under_existing_mutex(
                lease,
                (source.audit_ancestor_sha256, terminal),  # type: ignore[arg-type]
            )
        assert raised.value.code is CopyLedgerCode.INVALID_REQUEST


def test_typed_publish_terminal_survives_capability_check_and_fresh_reopen(
    copy_lab: _CopyLab,
) -> None:
    typed = _typed_ancestor_lab(copy_lab)
    committed = _append_typed_copy_commit(typed)
    with typed.bundle.writer.acquire_runtime_mutex() as lease:
        operation_result = (
            typed.operation_ledger.transaction_result_under_existing_mutex(
                lease,
                committed.publish_transaction_id,
            )
        )
        assert operation_result is not None
        operation_terminal = operation_result[0]
        audit_inventory = (
            typed.bundle.ledger.authenticated_segment_sha256s_under_existing_mutex(
                lease
            )
        )
        assert audit_inventory.index(
            committed.publish_operation_plan.audit_ancestor_sha256
        ) < audit_inventory.index(operation_terminal.audit_ledger_head_sha256)
        capability = (
            typed.copy_ledgers._issue_authenticated_ancestors_under_existing_mutex(
                lease,
                typed.bundle.ledger,
                typed.operation_ledger,
            )
        )
        assert len(capability._publish_terminal_binding_sha256s) == 1
        typed.copy_ledgers._verify_external_ancestors_under_existing_mutex(
            lease,
            capability,
        )

    reopened_operation_ledger = _create_test_operation_ledger(
        typed.bundle,
        epoch_id="RUN-COPY-TYPED-OPERATIONS",
    )
    reopened = _create_test_copy_ledgers(
        typed.bundle,
        reopened_operation_ledger,
        epoch_id=typed.epoch_id,
        run_scope_id=typed.run_scope_id,
    )
    with typed.bundle.writer.acquire_runtime_mutex() as lease:
        result = reopened.transaction_result_under_existing_mutex(
            lease,
            committed.transaction_binding_sha256,
        )
    assert result is not None and result[0] == committed


@pytest.mark.parametrize(
    "mismatch",
    [
        "transaction",
        "operation_binding",
        "operation_reference",
        "context",
        "pair",
        "source_locator",
        "target_locator",
        "manifest",
        "budget",
        "classification_locator_mode",
        "observed_tree",
        "topology",
        "durable_identity",
        "entry_count",
        "total_bytes",
        "audit_ancestry",
        "audit_order",
        "terminal_segment",
        "terminal_state",
        "target_evidence",
    ],
)
def test_fresh_reopen_rejects_semantically_wrong_typed_publish_terminal(
    copy_lab: _CopyLab,
    mismatch: str,
) -> None:
    typed = _typed_ancestor_lab(copy_lab)
    _append_typed_copy_commit(typed, mismatch=mismatch)
    if mismatch == "audit_ancestry":
        with pytest.raises(OperationLedgerError) as operation_error:
            _create_test_operation_ledger(
                typed.bundle,
                epoch_id="RUN-COPY-TYPED-OPERATIONS",
            )
        assert operation_error.value.code is OperationLedgerCode.CHAIN_CORRUPT
        return
    reopened_operation_ledger = _create_test_operation_ledger(
        typed.bundle,
        epoch_id="RUN-COPY-TYPED-OPERATIONS",
    )

    with pytest.raises(CopyLedgerError) as raised:
        _create_test_copy_ledgers(
            typed.bundle,
            reopened_operation_ledger,
            epoch_id=typed.epoch_id,
            run_scope_id=typed.run_scope_id,
        )
    assert raised.value.code is CopyLedgerCode.CROSS_REFERENCE_INVALID


@pytest.mark.parametrize("reservation_mode", ["missing", "out_of_order"])
@pytest.mark.parametrize("with_absence", [False, True])
def test_pending_and_absence_plans_require_ordered_authenticated_audit_ancestry(
    copy_lab: _CopyLab,
    reservation_mode: str,
    with_absence: bool,
) -> None:
    typed = _typed_ancestor_lab(copy_lab)
    _append_invalid_pending_or_absence_plan(
        typed,
        index=(71 if reservation_mode == "missing" else 72),
        reservation_mode=reservation_mode,
        with_absence=with_absence,
    )
    reopened_operation_ledger = _create_test_operation_ledger(
        typed.bundle,
        epoch_id="RUN-COPY-TYPED-OPERATIONS",
    )
    with pytest.raises(CopyLedgerError) as raised:
        _create_test_copy_ledgers(
            typed.bundle,
            reopened_operation_ledger,
            epoch_id=typed.epoch_id,
            run_scope_id=typed.run_scope_id,
        )
    assert raised.value.code is CopyLedgerCode.CROSS_REFERENCE_INVALID


def test_pending_plan_binding_is_reauthenticated_on_fresh_reopen(
    copy_lab: _CopyLab,
) -> None:
    typed = _typed_ancestor_lab(copy_lab)
    _append_invalid_pending_or_absence_plan(
        typed,
        index=73,
        reservation_mode="forged_binding",
        with_absence=False,
    )
    reopened_operation_ledger = _create_test_operation_ledger(
        typed.bundle,
        epoch_id="RUN-COPY-TYPED-OPERATIONS",
    )
    with pytest.raises(CopyLedgerError) as raised:
        _create_test_copy_ledgers(
            typed.bundle,
            reopened_operation_ledger,
            epoch_id=typed.epoch_id,
            run_scope_id=typed.run_scope_id,
        )
    assert raised.value.code is CopyLedgerCode.CROSS_REFERENCE_INVALID


@pytest.mark.parametrize("recovered", [False, True])
def test_abort_terminal_is_typed_and_survives_fresh_reopen(
    copy_lab: _CopyLab,
    recovered: bool,
) -> None:
    typed = _typed_ancestor_lab(copy_lab)
    terminal = _append_typed_copy_abort(typed, recovered=recovered)
    reopened_operation_ledger = _create_test_operation_ledger(
        typed.bundle,
        epoch_id="RUN-COPY-TYPED-OPERATIONS",
    )
    reopened = _create_test_copy_ledgers(
        typed.bundle,
        reopened_operation_ledger,
        epoch_id=typed.epoch_id,
        run_scope_id=typed.run_scope_id,
    )
    with typed.bundle.writer.acquire_runtime_mutex() as lease:
        result = reopened.transaction_result_under_existing_mutex(
            lease,
            terminal.transaction_binding_sha256,
        )
    assert result is not None and result[0] == terminal
    assert terminal.publish_terminal_state is (
        OperationState.RECOVERED_ABORT if recovered else OperationState.ABORTED
    )


def test_abort_terminal_rollback_is_rejected_on_fresh_reopen(
    copy_lab: _CopyLab,
) -> None:
    typed = _typed_ancestor_lab(copy_lab)
    _append_typed_copy_abort(typed, recovered=False)
    operation_dir = (
        typed.project
        / "logs"
        / "operations"
        / "segments"
        / "RUN-COPY-TYPED-OPERATIONS"
    )
    terminal_segment = sorted(_segment_entries(operation_dir))[-1]
    _extended_test_host_path(terminal_segment).rename(
        typed.project / "rolled-back-operation-terminal.json"
    )
    reopened_operation_ledger = _create_test_operation_ledger(
        typed.bundle,
        epoch_id="RUN-COPY-TYPED-OPERATIONS",
    )
    with pytest.raises(CopyLedgerError) as raised:
        _create_test_copy_ledgers(
            typed.bundle,
            reopened_operation_ledger,
            epoch_id=typed.epoch_id,
            run_scope_id=typed.run_scope_id,
        )
    assert raised.value.code is CopyLedgerCode.CROSS_REFERENCE_INVALID


def test_absence_witness_accepts_authenticated_chain_extension(
    copy_lab: _CopyLab,
) -> None:
    typed = _typed_ancestor_lab(copy_lab)
    terminal, witness, _ = _append_source_only_absence_abort(typed, index=50)
    observed_count = witness.observation_segment_count
    _append_unrelated_aborted_operation(typed, suffix="EXTENSION")
    reopened_operation_ledger = _create_test_operation_ledger(
        typed.bundle,
        epoch_id="RUN-COPY-TYPED-OPERATIONS",
    )
    reopened = _create_test_copy_ledgers(
        typed.bundle,
        reopened_operation_ledger,
        epoch_id=typed.epoch_id,
        run_scope_id=typed.run_scope_id,
    )
    assert reopened_operation_ledger.head.segment_count > observed_count
    with typed.bundle.writer.acquire_runtime_mutex() as lease:
        result = reopened.transaction_result_under_existing_mutex(
            lease,
            terminal.transaction_binding_sha256,
        )
    assert result is not None and result[0] == terminal


@pytest.mark.parametrize("recovered", [False, True])
def test_prepared_abort_without_operation_fact_requires_valid_absence_witness(
    copy_lab: _CopyLab,
    recovered: bool,
) -> None:
    typed = _typed_ancestor_lab(copy_lab)
    terminal = _append_prepared_absence_abort(typed, recovered=recovered)
    reopened_operation_ledger = _create_test_operation_ledger(
        typed.bundle,
        epoch_id="RUN-COPY-TYPED-OPERATIONS",
    )
    reopened = _create_test_copy_ledgers(
        typed.bundle,
        reopened_operation_ledger,
        epoch_id=typed.epoch_id,
        run_scope_id=typed.run_scope_id,
    )
    with typed.bundle.writer.acquire_runtime_mutex() as lease:
        result = reopened.transaction_result_under_existing_mutex(
            lease,
            terminal.transaction_binding_sha256,
        )
    assert result is not None and result[0] == terminal
    assert terminal.publish_operation_absence_witness is not None
    assert terminal.publish_terminal_segment_sha256 is None


def test_absence_witness_rejects_authenticated_prefix_rollback(
    copy_lab: _CopyLab,
) -> None:
    typed = _typed_ancestor_lab(copy_lab)
    _append_unrelated_aborted_operation(typed, suffix="PREFIX")
    _append_source_only_absence_abort(typed, index=51)
    operation_dir = (
        typed.project
        / "logs"
        / "operations"
        / "segments"
        / "RUN-COPY-TYPED-OPERATIONS"
    )
    observed_head = sorted(_segment_entries(operation_dir))[-1]
    _extended_test_host_path(observed_head).rename(
        typed.project / "rolled-back-absence-head.json"
    )
    reopened_operation_ledger = _create_test_operation_ledger(
        typed.bundle,
        epoch_id="RUN-COPY-TYPED-OPERATIONS",
    )
    with pytest.raises(CopyLedgerError) as raised:
        _create_test_copy_ledgers(
            typed.bundle,
            reopened_operation_ledger,
            epoch_id=typed.epoch_id,
            run_scope_id=typed.run_scope_id,
        )
    assert raised.value.code is CopyLedgerCode.CROSS_REFERENCE_INVALID


def test_absence_witness_rejects_expected_operation_in_later_extension(
    copy_lab: _CopyLab,
) -> None:
    typed = _typed_ancestor_lab(copy_lab)
    _append_source_only_absence_abort(typed, index=52)
    _append_unrelated_aborted_operation(
        typed,
        suffix="EXPECTED",
        operation_id="OPERATION-COPY-ABSENCE-52",
    )
    reopened_operation_ledger = _create_test_operation_ledger(
        typed.bundle,
        epoch_id="RUN-COPY-TYPED-OPERATIONS",
    )
    with pytest.raises(CopyLedgerError) as raised:
        _create_test_copy_ledgers(
            typed.bundle,
            reopened_operation_ledger,
            epoch_id=typed.epoch_id,
            run_scope_id=typed.run_scope_id,
        )
    assert raised.value.code is CopyLedgerCode.CROSS_REFERENCE_INVALID


def test_absence_witness_rejects_expected_transaction_in_later_extension(
    copy_lab: _CopyLab,
) -> None:
    typed = _typed_ancestor_lab(copy_lab)
    _append_prepared_absence_abort(typed, recovered=False)
    _append_unrelated_aborted_operation(
        typed,
        suffix="EXPECTED-TRANSACTION",
        transaction_id=_opaque_txn("prepared-absence-55"),
    )
    reopened_operation_ledger = _create_test_operation_ledger(
        typed.bundle,
        epoch_id="RUN-COPY-TYPED-OPERATIONS",
    )
    with pytest.raises(CopyLedgerError) as raised:
        _create_test_copy_ledgers(
            typed.bundle,
            reopened_operation_ledger,
            epoch_id=typed.epoch_id,
            run_scope_id=typed.run_scope_id,
        )
    assert raised.value.code is CopyLedgerCode.CROSS_REFERENCE_INVALID


def test_absence_witness_replay_across_copy_transaction_is_rejected(
    copy_lab: _CopyLab,
) -> None:
    typed = _typed_ancestor_lab(copy_lab)
    _, first_witness, _ = _append_source_only_absence_abort(typed, index=53)
    _append_source_only_absence_abort(
        typed,
        index=54,
        witness_override=first_witness,
    )
    reopened_operation_ledger = _create_test_operation_ledger(
        typed.bundle,
        epoch_id="RUN-COPY-TYPED-OPERATIONS",
    )
    with pytest.raises(CopyLedgerError) as raised:
        _create_test_copy_ledgers(
            typed.bundle,
            reopened_operation_ledger,
            epoch_id=typed.epoch_id,
            run_scope_id=typed.run_scope_id,
        )
    assert raised.value.code is CopyLedgerCode.CROSS_REFERENCE_INVALID


def test_replay_returns_typed_receipt_without_advancing_chain(copy_lab: _CopyLab) -> None:
    ledgers = _ledgers(copy_lab)
    source = _source()
    with copy_lab.writer.acquire_runtime_mutex() as lease:
        first = ledgers._append_source_under_existing_mutex(lease, source)
        source_count = ledgers.head.source.segment_count
        replay = ledgers._append_source_under_existing_mutex(lease, source)
        assert replay.replayed is True
        assert replay.segment_sha256 == first.segment_sha256
        assert ledgers.head.source.segment_count == source_count
        prepared = _prepared(source, first, ledgers=ledgers)
        original = ledgers._append_transition_under_existing_mutex(lease, prepared)
        copy_count = ledgers.head.copy.segment_count
        repeated = ledgers._append_transition_under_existing_mutex(lease, prepared)
        assert repeated.replayed is True
        assert repeated.segment_sha256 == original.segment_sha256
        assert ledgers.head.copy.segment_count == copy_count


@pytest.mark.parametrize("name", ["PENDING-crash.json", "unknown.bin", "00000000000000000001.json"])
def test_unknown_or_pending_entry_fails_closed(copy_lab: _CopyLab, name: str) -> None:
    _ledgers(copy_lab)
    source_dir = copy_lab.project / "Copy" / "ledger" / "source" / "segments" / copy_lab.epoch_id
    _extended_test_host_path(source_dir / name).write_bytes(b"synthetic-unknown")
    with pytest.raises(CopyLedgerError) as raised:
        _ledgers(copy_lab, initialize=False)
    assert raised.value.code is CopyLedgerCode.UNKNOWN_ENTRY


def test_tamper_and_noncanonical_segment_fail_closed(copy_lab: _CopyLab) -> None:
    ledgers = _ledgers(copy_lab)
    source = _source()
    with copy_lab.writer.acquire_runtime_mutex() as lease:
        ledgers._append_source_under_existing_mutex(lease, source)
    source_dir = copy_lab.project / "Copy" / "ledger" / "source" / "segments" / copy_lab.epoch_id
    segment = sorted(_segment_entries(source_dir))[1]
    payload = _extended_test_host_path(segment).read_bytes()
    _extended_test_host_path(segment).write_bytes(
        payload.replace(
            b'"classification":"INTERNAL"',
            b'"classification": "INTERNAL"',
        )
    )
    with pytest.raises(CopyLedgerError) as raised:
        _ledgers(copy_lab, initialize=False)
    assert raised.value.code in {
        CopyLedgerCode.CHAIN_CORRUPT,
        CopyLedgerCode.AUTHENTICATION_FAILED,
    }


def test_gap_or_fork_filename_fails_closed(copy_lab: _CopyLab) -> None:
    ledgers = _ledgers(copy_lab)
    source = _source()
    with copy_lab.writer.acquire_runtime_mutex() as lease:
        ledgers._append_source_under_existing_mutex(lease, source)
    source_dir = copy_lab.project / "Copy" / "ledger" / "source" / "segments" / copy_lab.epoch_id
    record_segment = sorted(_segment_entries(source_dir))[1]
    gap_name = "00000000000000000002" + record_segment.name[20:]
    _extended_test_host_path(record_segment).rename(
        _extended_test_host_path(source_dir / gap_name)
    )
    with pytest.raises(CopyLedgerError) as raised:
        _ledgers(copy_lab, initialize=False)
    assert raised.value.code is CopyLedgerCode.CHAIN_CORRUPT


def test_source_policy_is_frozen_to_synthetic_reference_contract() -> None:
    with pytest.raises(CopyLedgerError) as raised:
        replace(
            _source(),
            reference_policy_digest=_digest("different-reference-policy"),
        )
    assert raised.value.code is CopyLedgerCode.INVALID_REQUEST


def test_target_evidence_is_exactly_payload_plus_provenance(
    copy_lab: _CopyLab,
) -> None:
    ledgers = _ledgers(copy_lab)
    source = _source()
    receipt = CopySourceReceipt(
        epoch_id="A" * 64,
        sequence=1,
        segment_sha256=_digest("source-segment"),
        record_id=source.record_id,
        record_sha256=source.digest,
        replayed=False,
    )
    target = _target(source, _prepared(source, receipt, ledgers=ledgers))

    with pytest.raises(CopyLedgerError) as entry_error:
        replace(target, entry_count=1)
    assert entry_error.value.code is CopyLedgerCode.INVALID_REQUEST

    with pytest.raises(CopyLedgerError) as bytes_error:
        replace(target, total_bytes=target.total_bytes + 1)
    assert bytes_error.value.code is CopyLedgerCode.INVALID_REQUEST


def test_provenance_bytes_bind_exact_source_anchor_and_derive_two_file_manifest() -> None:
    source = _source()
    receipt = CopySourceReceipt(
        epoch_id="A" * 64,
        sequence=7,
        segment_sha256=_digest("exact-source-segment"),
        record_id=source.record_id,
        record_sha256=source.digest,
    )
    material = build_copy_provenance_material(
        source,
        receipt,
        manifest_id="MANIFEST-COPY-PROVENANCE-TEST",
    )
    expected = canonical_json_bytes(
        {
            "payload_manifest_sha256": material.payload_manifest_sha256,
            "schema_id": "M0-COPY-PROVENANCE",
            "schema_version": "1.0",
            "source_anchor": receipt.anchor.to_json(),
            "source_record": source.to_json(),
        }
    )

    assert material.provenance_bytes == expected
    assert material.provenance_sha256 == hashlib.sha256(expected).hexdigest()
    assert material.publish_manifest.manifest_sha256 != (
        material.payload_manifest_sha256
    )
    assert tuple(
        entry.relative_path for entry in material.publish_manifest.entries
    ) == ("payload.bin", COPY_PROVENANCE_FILE_NAME)
    assert material.publish_manifest.entries[1].size_bytes == len(expected)
    assert material.publish_manifest.entries[1].sha256 == material.provenance_sha256


def test_publish_transaction_is_present_from_prepared_and_terminal_is_later(
    copy_lab: _CopyLab,
) -> None:
    ledgers = _ledgers(copy_lab)
    source = _source()
    receipt = CopySourceReceipt(
        epoch_id="A" * 64,
        sequence=1,
        segment_sha256=_digest("source-segment-for-publish-transaction"),
        record_id=source.record_id,
        record_sha256=source.digest,
    )
    prepared = _prepared(source, receipt, ledgers=ledgers)

    with pytest.raises(CopyLedgerError) as missing_transaction:
        replace(prepared, publish_transaction_id=None)
    assert missing_transaction.value.code is CopyLedgerCode.INVALID_REQUEST

    with pytest.raises(CopyLedgerError) as early_terminal:
        replace(
            prepared,
            publish_terminal_segment_sha256=_digest("early-terminal"),
        )
    assert early_terminal.value.code is CopyLedgerCode.INVALID_REQUEST

    in_doubt = replace(
        prepared,
        transition_id=_digest("prepared-in-doubt"),
        previous_state=CopyState.PREPARED,
        next_state=CopyState.IN_DOUBT,
        mutation_attempted=True,
        error_code="PUBLISH_RESULT_UNKNOWN",
    )
    assert in_doubt.publish_transaction_id == prepared.publish_transaction_id
    assert in_doubt.publish_terminal_segment_sha256 is None

    source_only_recovered_abort = replace(
        prepared,
        transition_id=_digest("source-only-recovered-abort-no-publish-transaction"),
        previous_state=None,
        next_state=CopyState.RECOVERED_ABORT,
        publish_transaction_id=None,
        publish_operation_plan=replace(
            prepared.publish_operation_plan,
            kind=CopyPublishPlanKind.UNSTARTED,
            publish_transaction_reference_hmac_sha256=None,
            pair_reference_hmac_sha256=None,
            locator_mode=None,
            source_locator_hmac_sha256=None,
            target_locator_hmac_sha256=None,
            source_evidence=None,
            audit_ancestor_sha256=None,
        ),
        publish_operation_absence_witness=_shape_only_absence(
            "source-only",
            with_publish_transaction=False,
        ),
        recovery_reason="PUBLISH_NOT_NATIVE_TARGET_ABSENT_SOURCE_EXACT",
        recovery_authority_head_sha256=_digest("source-only-authority"),
    )
    assert source_only_recovered_abort.publish_transaction_id is None


def test_ledger_recomputes_prepared_provenance(copy_lab: _CopyLab) -> None:
    ledgers = _ledgers(copy_lab)
    source = _source()
    with copy_lab.writer.acquire_runtime_mutex() as lease:
        receipt = ledgers._append_source_under_existing_mutex(lease, source)
        copy_count = ledgers.head.copy.segment_count
        with pytest.raises(CopyLedgerError) as raised:
            ledgers._append_transition_under_existing_mutex(
                lease,
                replace(
                    _prepared(source, receipt, ledgers=ledgers),
                    provenance_metadata_sha256=_digest("forged-provenance"),
                ),
            )
        assert ledgers.head.copy.segment_count == copy_count
        with pytest.raises(CopyLedgerError) as manifest_error:
            prepared = _prepared(source, receipt, ledgers=ledgers)
            forged_manifest = _digest("forged-one-file-manifest")
            ledgers._append_transition_under_existing_mutex(
                lease,
                replace(
                    prepared,
                    expected_manifest_sha256=forged_manifest,
                    publish_operation_plan=replace(
                        prepared.publish_operation_plan,
                        manifest_sha256=forged_manifest,
                        source_evidence=replace(
                            prepared.publish_operation_plan.source_evidence,
                            manifest_sha256=forged_manifest,
                        ),
                    ),
                ),
            )
        assert ledgers.head.copy.segment_count == copy_count
    assert raised.value.code is CopyLedgerCode.CROSS_REFERENCE_INVALID
    assert manifest_error.value.code is CopyLedgerCode.CROSS_REFERENCE_INVALID


def test_cross_reference_and_classification_downgrade_are_rejected(
    copy_lab: _CopyLab,
) -> None:
    ledgers = _ledgers(copy_lab)
    restricted = _source(restricted=True)
    with copy_lab.writer.acquire_runtime_mutex() as lease:
        receipt = ledgers._append_source_under_existing_mutex(lease, restricted)
        with pytest.raises(CopyLedgerError) as locator_error:
            replace(
                _prepared(restricted, receipt, ledgers=ledgers),
                target_locator=CopyLocator(
                    CopyLocatorMode.SAFE_RELATIVE,
                    "Copy/source/DOWNGRADE",
                ),
            )
        assert locator_error.value.code is CopyLedgerCode.INVALID_REQUEST

        other = _source(index=2, restricted=True)
        with pytest.raises(CopyLedgerError) as ancestry_error:
            ledgers._append_transition_under_existing_mutex(
                lease,
                replace(
                    _prepared(restricted, receipt, ledgers=ledgers),
                    transaction_binding_sha256=other.transaction_binding_sha256,
                ),
            )
        assert ancestry_error.value.code is CopyLedgerCode.CROSS_REFERENCE_INVALID


def test_prepared_target_locator_is_unique_across_transactions(
    copy_lab: _CopyLab,
) -> None:
    ledgers = _ledgers(copy_lab)
    first_source = _source(index=1)
    second_source = _source(index=2)
    with copy_lab.writer.acquire_runtime_mutex() as lease:
        first_receipt = ledgers._append_source_under_existing_mutex(lease, first_source)
        second_receipt = ledgers._append_source_under_existing_mutex(lease, second_source)
        first_prepared = _prepared(
            first_source,
            first_receipt,
            ledgers=ledgers,
            index=1,
        )
        ledgers._append_transition_under_existing_mutex(lease, first_prepared)
        with pytest.raises(CopyLedgerError) as raised:
            ledgers._append_transition_under_existing_mutex(
                lease,
                replace(
                    _prepared(
                        second_source,
                        second_receipt,
                        ledgers=ledgers,
                        index=2,
                    ),
                    target_locator=first_prepared.target_locator,
                ),
            )
    assert raised.value.code is CopyLedgerCode.TRANSITION_CONFLICT


def test_recovered_abort_rejects_mutated_and_postcondition_edges(
    copy_lab: _CopyLab,
) -> None:
    ledgers = _ledgers(copy_lab)
    source = _source()
    terminal = _digest("recovery-publish-terminal")
    authority = _digest("recovery-authority")
    with copy_lab.writer.acquire_runtime_mutex() as lease:
        receipt = ledgers._append_source_under_existing_mutex(lease, source)
        prepared = _prepared(source, receipt, ledgers=ledgers)
        mutated = replace(
            prepared,
            transition_id=_digest("recovery-mutated"),
            previous_state=CopyState.PREPARED,
            next_state=CopyState.MUTATED,
            mutation_attempted=True,
            publish_terminal_segment_sha256=terminal,
            publish_terminal_state=OperationState.COMMITTED,
        )
        post = replace(
            mutated,
            transition_id=_digest("recovery-postcondition"),
            previous_state=CopyState.MUTATED,
            next_state=CopyState.POSTCONDITION_VERIFIED,
            target_evidence=_target(source, prepared),
        )
        for index, transition in enumerate((mutated, post), start=1):
            with pytest.raises(CopyLedgerError) as raised:
                replace(
                    transition,
                    transition_id=_digest(f"illegal-recovered-abort-{index}"),
                    previous_state=transition.next_state,
                    next_state=CopyState.RECOVERED_ABORT,
                    recovery_reason="PUBLISH_NOT_NATIVE_TARGET_ABSENT_SOURCE_EXACT",
                    recovery_authority_head_sha256=authority,
                )
            assert raised.value.code is CopyLedgerCode.ILLEGAL_TRANSITION

        recovered_abort = replace(
            prepared,
            transition_id=_digest("prepared-recovered-abort"),
            previous_state=CopyState.PREPARED,
            next_state=CopyState.RECOVERED_ABORT,
            publish_operation_absence_witness=_shape_only_absence(
                "prepared-recovery"
            ),
            recovery_reason="PUBLISH_NOT_NATIVE_TARGET_ABSENT_SOURCE_EXACT",
            recovery_authority_head_sha256=authority,
        )
        ledgers._append_transition_under_existing_mutex(lease, prepared)
        ledgers._append_transition_under_existing_mutex(lease, recovered_abort)
    assert ledgers.head.pending_source_count == 0


def test_pending_source_reserves_complete_copy_lifecycle(
    copy_lab: _CopyLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(copy_ledger_module, "_MAX_SEGMENTS", 6)
    ledgers = _ledgers(copy_lab)
    with copy_lab.writer.acquire_runtime_mutex() as lease:
        ledgers._append_source_under_existing_mutex(lease, _source(1))
        with pytest.raises(CopyLedgerError) as raised:
            ledgers._append_source_under_existing_mutex(lease, _source(2))
    assert raised.value.code is CopyLedgerCode.RESOURCE_LIMIT
    assert ledgers.head.source.segment_count == 2
    assert ledgers.head.copy.segment_count == 1


def test_prior_revision_epoch_allows_replay_and_recovery_but_rejects_new_work(
    copy_lab: _CopyLab,
) -> None:
    ledgers = _ledgers(copy_lab)
    source = _source(index=1)
    with copy_lab.writer.acquire_runtime_mutex() as lease:
        receipt = ledgers._append_source_under_existing_mutex(lease, source)

    current_revision = AuditKeyRevisionStore(
        copy_lab.writer,
        _constructor=_LEDGER_CONSTRUCTOR,
    ).create_revision(
        revision_sequence=2,
        revision_id="KEYREV-S3F-TWO",
        master_key=b"T" * 32,
        created_at_utc="2026-07-13T00:00:03Z",
    )
    reopened = DurableCopyLedgers(
        copy_lab.writer,
        current_revision,
        epoch_id=copy_lab.epoch_id,
        run_scope_id=copy_lab.run_scope_id,
        policy_digest=POLICY_DIGEST,
        known_revisions=(copy_lab.revision,),
        initialize=False,
        _constructor=_COPY_LEDGERS_CONSTRUCTOR,
    )
    assert reopened.signing_revision_id == copy_lab.revision.revision_id

    with copy_lab.writer.acquire_runtime_mutex() as lease:
        result = reopened.source_result_under_existing_mutex(lease, source.record_id)
        assert result == (source, receipt)
        prepared = _prepared(source, receipt, ledgers=reopened)
        recovered_abort = replace(
            prepared,
            transition_id=_digest("old-revision-source-only-recovered-abort"),
            previous_state=None,
            next_state=CopyState.RECOVERED_ABORT,
            publish_transaction_id=None,
            publish_operation_plan=replace(
                prepared.publish_operation_plan,
                kind=CopyPublishPlanKind.UNSTARTED,
                publish_transaction_reference_hmac_sha256=None,
                pair_reference_hmac_sha256=None,
                locator_mode=None,
                source_locator_hmac_sha256=None,
                target_locator_hmac_sha256=None,
                source_evidence=None,
                audit_ancestor_sha256=None,
            ),
            publish_operation_absence_witness=_shape_only_absence(
                "old-revision-source-only",
                with_publish_transaction=False,
            ),
            recovery_reason="PUBLISH_NOT_NATIVE_TARGET_ABSENT_SOURCE_EXACT",
            recovery_authority_head_sha256=_digest("current-audit-recovery-head"),
        )
        recovery_receipt = reopened._append_transition_under_existing_mutex(
            lease,
            recovered_abort,
        )
        assert recovery_receipt.state is CopyState.RECOVERED_ABORT
        replay = reopened._append_transition_under_existing_mutex(
            lease,
            recovered_abort,
        )
        assert replay.replayed is True
        before_rejected_work = reopened.head
        with pytest.raises(CopyLedgerError) as source_error:
            reopened._append_source_under_existing_mutex(lease, _source(index=2))
        assert source_error.value.code is CopyLedgerCode.AUTHENTICATION_FAILED
        with pytest.raises(CopyLedgerError) as transition_error:
            reopened._append_transition_under_existing_mutex(
                lease,
                prepared,
            )
        assert transition_error.value.code is CopyLedgerCode.AUTHENTICATION_FAILED
        assert reopened.head == before_rejected_work


def test_receipts_records_errors_and_ledger_do_not_expose_or_serialize(
    copy_lab: _CopyLab,
) -> None:
    ledgers = _ledgers(copy_lab)
    source = _source(restricted=True)
    raw_path = r"D:\private\original-name.sqlite3"
    with copy_lab.writer.acquire_runtime_mutex() as lease:
        receipt = ledgers._append_source_under_existing_mutex(lease, source)
    prepared = _prepared(source, receipt, ledgers=ledgers)
    witness = _shape_only_absence("restricted-redaction")
    for value in (
        ledgers,
        source,
        source.source_locator,
        source.source_evidence,
        receipt,
        prepared,
        prepared.publish_operation_plan,
        witness,
    ):
        assert raw_path not in repr(value)
        with pytest.raises(TypeError):
            pickle.dumps(value)
    serialized_plan = canonical_json_bytes(
        prepared.publish_operation_plan.to_json()
    )
    assert raw_path.encode("utf-8") not in serialized_plan
    assert b"original-name" not in serialized_plan
    error = CopyLedgerError(CopyLedgerCode.CHAIN_CORRUPT, raw_path)
    assert raw_path not in str(error)
    assert raw_path not in repr(error)
    assert raw_path not in " ".join(str(item) for item in error.args)


def test_restricted_absence_segments_persist_only_opaque_identifiers(
    copy_lab: _CopyLab,
) -> None:
    typed = _typed_ancestor_lab(copy_lab)
    terminal, witness, plan = _append_source_only_absence_abort(
        typed,
        index=74,
        restricted=True,
    )
    reopened_operation_ledger = _create_test_operation_ledger(
        typed.bundle,
        epoch_id=_RESTRICTED_RAW_OPERATION_EPOCH,
    )
    reopened = _create_test_copy_ledgers(
        typed.bundle,
        reopened_operation_ledger,
        epoch_id=typed.epoch_id,
        run_scope_id=typed.run_scope_id,
    )
    assert terminal.classification is DataClassification.RESTRICTED
    assert reopened.head.pending_source_count == 0
    assert plan.operation_reference_hmac_sha256 == (
        typed.copy_ledgers._operation_reference_hmac(
            typed.operation_ledger.operation_reference(
                _RESTRICTED_RAW_OPERATION,
                DataClassification.RESTRICTED,
            )
        )
    )
    assert witness.operation_epoch_reference_hmac_sha256 == (
        typed.copy_ledgers._operation_epoch_reference_hmac(
            _RESTRICTED_RAW_OPERATION_EPOCH
        )
    )
    persisted = b"".join(
        _extended_test_host_path(segment).read_bytes()
        for root in (
            typed.project
            / "Copy"
            / "ledger"
            / "source"
            / "segments"
            / typed.epoch_id,
            typed.project
            / "Copy"
            / "ledger"
            / "copy"
            / "segments"
            / typed.epoch_id,
        )
        for segment in _segment_entries(root)
    )
    for raw_identifier in (
        _RESTRICTED_RAW_RUN,
        _RESTRICTED_RAW_JOB,
        _RESTRICTED_RAW_OPERATION,
        _RESTRICTED_RAW_COPY,
        _RESTRICTED_RAW_OPERATION_EPOCH,
    ):
        assert raw_identifier.encode("ascii") not in persisted
    assert b'"operation_epoch_id":' not in persisted
    assert witness.operation_epoch_reference_hmac_sha256.encode("ascii") in (
        persisted
    )


def test_closed_or_foreign_mutex_is_rejected(copy_lab: _CopyLab) -> None:
    ledgers = _ledgers(copy_lab)
    closed = copy_lab.writer.acquire_runtime_mutex()
    closed.close()
    with pytest.raises(CopyLedgerError) as closed_error:
        ledgers._rescan_under_existing_mutex(closed)
    assert closed_error.value.code is CopyLedgerCode.MUTEX_INVALID

    foreign = _create_test_handle_writer(copy_lab.project)
    with foreign.acquire_runtime_mutex() as lease:
        with pytest.raises(CopyLedgerError) as foreign_error:
            ledgers._rescan_under_existing_mutex(lease)
    assert foreign_error.value.code is CopyLedgerCode.MUTEX_INVALID
