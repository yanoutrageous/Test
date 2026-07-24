from __future__ import annotations

import ctypes
import hashlib
import hmac
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Iterator

import pytest

from app.safety import segment_ledger as segment_ledger_module
from app.safety.audit_events import (
    AuditAction,
    AuditDecision,
    AuditEvent,
    CapabilityKind,
    PairRole,
    create_audit_event,
)
from app.safety.context import Caller, DataClassification, OperationContext, Purpose
from app.safety.namespace_policy import (
    POLICY_DIGEST,
    AuditPathMode,
    NamespaceId,
)
from app.safety.production_guard import (
    ProductionBoundaryError,
    _AuditAuthority,
    _create_test_durable_boundary,
    _create_test_handle_writer,
)
from app.safety.segment_ledger import (
    AuditKeyRevision,
    AuditKeyRevisionStore,
    DurableAuditLedger,
    DurableAuditSink,
    LedgerCode,
    LedgerError,
    _LEDGER_CONSTRUCTOR,
    build_audit_segment_bytes,
    build_key_revision_bytes,
    canonical_json_bytes,
    parse_canonical_json_bytes,
)
from app.workspace_guard import ExpectedKind, PathIntent
from app.safety.windows_handle_writer import HandleWriterCode, HandleWriterError


@dataclass(frozen=True)
class _LedgerLab:
    project: Path
    protected: Path
    sentinel: Path
    epoch_id: str
    writer: object
    key_store: AuditKeyRevisionStore


@pytest.fixture
def ledger_lab(tmp_path: Path) -> Iterator[_LedgerLab]:
    project = tmp_path / "project"
    protected = tmp_path / "protected"
    project.mkdir()
    protected.mkdir()
    sentinel = protected / "sentinel.bin"
    sentinel.write_bytes(b"segment-ledger-protected-sentinel")
    epoch_id = "RUN-S3C-LEDGER"
    (project / "logs" / "audit" / "keys").mkdir(parents=True)
    (project / "logs" / "audit" / "segments" / epoch_id).mkdir(parents=True)
    writer = _create_test_handle_writer(project)
    yield _LedgerLab(
        project=project,
        protected=protected,
        sentinel=sentinel,
        epoch_id=epoch_id,
        writer=writer,
        key_store=AuditKeyRevisionStore(
            writer,
            _constructor=_LEDGER_CONSTRUCTOR,
        ),
    )
    assert sentinel.read_bytes() == b"segment-ledger-protected-sentinel"
    assert {path.name for path in protected.iterdir()} == {"sentinel.bin"}


def _create_revision(
    lab: _LedgerLab,
    *,
    sequence: int = 1,
    revision_id: str = "KEYREV-ONE",
    key_byte: bytes = b"K",
) -> AuditKeyRevision:
    return lab.key_store.create_revision(
        revision_sequence=sequence,
        revision_id=revision_id,
        master_key=key_byte * 32,
        created_at_utc=f"2026-07-11T00:00:0{sequence}Z",
    )


def _event(
    revision: AuditKeyRevision,
    *,
    index: int,
    restricted: bool = False,
    decision: AuditDecision = AuditDecision.CANDIDATE_ALLOW,
    action: AuditAction = AuditAction.ISSUE,
    capability_kind: CapabilityKind = CapabilityKind.SINGLE,
    error_code: str | None = None,
    pair_id: str | None = None,
    pair_role: PairRole | None = None,
    path_mode: AuditPathMode | None = None,
    context_present: bool = True,
) -> AuditEvent:
    classification = (
        DataClassification.RESTRICTED if restricted else DataClassification.INTERNAL
    )
    context = (
        OperationContext(
            run_id="RUN-S3C-EVENT",
            job_id="JOB-S3C-EVENT",
            operation_id=f"OP-S3C-{index:04d}",
            caller=Caller.AUDIT_SERVICE,
            purpose=Purpose.APPEND_AUDIT,
            classification=classification,
        )
        if context_present
        else None
    )
    event = create_audit_event(
        decision=decision,
        action=action,
        capability_kind=capability_kind,
        error_code=error_code,
        context=context,
        effective_classification=classification,
        path_mode=(
            path_mode
            if path_mode is not None
            else (
                AuditPathMode.HMAC_ONLY
                if restricted
                else AuditPathMode.RELATIVE
            )
        ),
        policy_digest=POLICY_DIGEST,
        boundary_instance_id="BOUNDARY-S3C",
        ticket_id=f"TICKET-S3C-{index:04d}",
        pair_id=pair_id,
        pair_role=pair_role,
        namespace=NamespaceId.AUDIT_LOG,
        intent=PathIntent.EXISTING_READ,
        expected_kind=ExpectedKind.FILE,
        relative_path=Path("safe") / f"item-{index:04d}.json",
        audit_hmac_key=revision.audit_hmac_key,
    )
    return replace(
        event,
        event_id=f"EVENT-S3C-{index:04d}",
        occurred_at_utc=f"2026-07-11T00:10:{index:02d}Z",
    )


def _semantic_event(
    revision: AuditKeyRevision,
    *,
    index: int,
    variant: str,
) -> AuditEvent:
    if variant == "allow-issue":
        return _event(revision, index=index)
    if variant == "allow-revalidate":
        return _event(
            revision,
            index=index,
            action=AuditAction.REVALIDATE,
        )
    if variant == "deny":
        return _event(
            revision,
            index=index,
            decision=AuditDecision.DENY,
            action=AuditAction.DENY,
            error_code="SYNTHETIC_DENIAL",
        )
    if variant == "pair":
        return _event(
            revision,
            index=index,
            capability_kind=CapabilityKind.PUBLISH_PAIR,
            pair_id="PAIR-S3C-SEMANTIC",
            pair_role=PairRole.SOURCE,
        )
    if variant == "context-hmac":
        return _event(
            revision,
            index=index,
            context_present=False,
        )
    if variant == "path-hmac":
        return _event(
            revision,
            index=index,
            path_mode=AuditPathMode.HMAC_ONLY,
        )
    if variant == "restricted":
        return _event(
            revision,
            index=index,
            restricted=True,
        )
    raise AssertionError(f"unsupported semantic event variant: {variant}")


def _ledger(lab: _LedgerLab, revision_id: str = "KEYREV-ONE") -> DurableAuditLedger:
    return DurableAuditLedger(
        lab.writer,
        lab.key_store,
        epoch_id=lab.epoch_id,
        initial_revision_id=revision_id,
        initialize=True,
        initialized_at_utc="2026-07-11T00:00:10Z",
        _constructor=_LEDGER_CONSTRUCTOR,
    )


def test_ledger_rescan_reuses_exact_live_mutex_without_nested_acquire(
    ledger_lab: _LedgerLab,
) -> None:
    _create_revision(ledger_lab)
    ledger = _ledger(ledger_lab)
    before = _ledger_entry_snapshot(ledger_lab)
    with ledger_lab.writer.acquire_runtime_mutex() as lease:
        head = ledger._rescan_under_existing_mutex(lease)
        assert head == ledger.head
        assert head.last_sequence == 0
    assert _ledger_entry_snapshot(ledger_lab) == before


def test_ledger_rescan_rejects_closed_foreign_and_cross_thread_mutex(
    ledger_lab: _LedgerLab,
) -> None:
    _create_revision(ledger_lab)
    ledger = _ledger(ledger_lab)
    before = _ledger_entry_snapshot(ledger_lab)
    closed = ledger_lab.writer.acquire_runtime_mutex()
    closed.close()
    with pytest.raises(LedgerError) as closed_error:
        ledger._rescan_under_existing_mutex(closed)
    assert closed_error.value.code is LedgerCode.INVALID_REQUEST

    foreign_writer = _create_test_handle_writer(ledger_lab.project)
    with foreign_writer.acquire_runtime_mutex() as foreign:
        with pytest.raises(LedgerError) as foreign_error:
            ledger._rescan_under_existing_mutex(foreign)
        assert foreign_error.value.code is LedgerCode.INVALID_REQUEST

    with ledger_lab.writer.acquire_runtime_mutex() as live:
        errors: list[BaseException] = []

        def cross_thread() -> None:
            try:
                ledger._rescan_under_existing_mutex(live)
            except BaseException as exc:
                errors.append(exc)

        thread = __import__("threading").Thread(target=cross_thread)
        thread.start()
        thread.join(timeout=5)
        assert len(errors) == 1
        assert isinstance(errors[0], LedgerError)
        assert errors[0].code is LedgerCode.INVALID_REQUEST
        assert ledger._rescan_under_existing_mutex(live) == ledger.head
    assert _ledger_entry_snapshot(ledger_lab) == before


def test_under_mutex_rescan_tamper_seals_without_append_or_repair(
    ledger_lab: _LedgerLab,
) -> None:
    _create_revision(ledger_lab)
    ledger = _ledger(ledger_lab)
    segment = _segment_files(ledger_lab)[0]
    payload = bytearray(segment.read_bytes())
    payload[len(payload) // 2] ^= 1
    tampered = bytes(payload)
    names_before = tuple(path.name for path in _segment_files(ledger_lab))
    segment.write_bytes(tampered)
    with ledger_lab.writer.acquire_runtime_mutex() as lease:
        with pytest.raises(LedgerError) as captured:
            ledger._rescan_under_existing_mutex(lease)
        assert captured.value.code in {
            LedgerCode.CHAIN_CORRUPT,
            LedgerCode.POLICY_MISMATCH,
            LedgerCode.STORAGE_FAILURE,
        }
    assert tuple(path.name for path in _segment_files(ledger_lab)) == names_before
    assert segment.read_bytes() == tampered
    with pytest.raises(LedgerError) as sealed_ledger:
        _ = ledger.head
    assert sealed_ledger.value.code is LedgerCode.LEDGER_SEALED
    with pytest.raises(HandleWriterError) as sealed_writer:
        ledger_lab.writer.acquire_runtime_mutex()
    assert sealed_writer.value.code is HandleWriterCode.WRITER_SEALED


def _segment_files(lab: _LedgerLab) -> list[Path]:
    root = lab.project / "logs" / "audit" / "segments" / lab.epoch_id
    return sorted(root.iterdir(), key=lambda path: path.name)


def _key_files(lab: _LedgerLab) -> list[Path]:
    root = lab.project / "logs" / "audit" / "keys"
    return sorted(root.iterdir(), key=lambda path: path.name)


def _ledger_entry_snapshot(lab: _LedgerLab) -> dict[str, tuple[tuple[str, bytes], ...]]:
    key_root = lab.project / "logs" / "audit" / "keys"
    segment_root = lab.project / "logs" / "audit" / "segments" / lab.epoch_id
    return {
        "keys": tuple(
            (path.name, path.read_bytes())
            for path in sorted(key_root.iterdir(), key=lambda item: item.name)
        ),
        "segments": tuple(
            (path.name, path.read_bytes())
            for path in sorted(segment_root.iterdir(), key=lambda item: item.name)
        ),
    }


def _assert_error_is_path_and_key_free(error: LedgerError, lab: _LedgerLab) -> None:
    surface = str(error) + repr(error) + repr(error.args) + repr(error.__dict__)
    assert error.__cause__ is None
    assert error.__context__ is None
    assert str(lab.project) not in surface
    assert "PENDING" not in surface
    assert (b"K" * 32).hex() not in surface


def _run_crash_child(
    lab: _LedgerLab,
    *,
    hook_name: str,
    event_index: int,
) -> subprocess.CompletedProcess[bytes]:
    environment = os.environ.copy()
    environment.update(
        {
            "M0_LEDGER_CHILD_PROJECT": str(lab.project),
            "M0_LEDGER_CHILD_EPOCH": lab.epoch_id,
            "M0_LEDGER_CHILD_HOOK": hook_name,
            "M0_LEDGER_CHILD_EVENT_INDEX": str(event_index),
        }
    )
    child_code = """
import os
from pathlib import Path
from app.safety.production_guard import _create_test_handle_writer
from app.safety.segment_ledger import (
    AuditKeyRevisionStore,
    DurableAuditLedger,
    _LEDGER_CONSTRUCTOR,
)
from tests.test_segment_ledger import _event

project = Path(os.environ["M0_LEDGER_CHILD_PROJECT"])
epoch = os.environ["M0_LEDGER_CHILD_EPOCH"]
hook_name = os.environ["M0_LEDGER_CHILD_HOOK"]
index = int(os.environ["M0_LEDGER_CHILD_EVENT_INDEX"])
writer = _create_test_handle_writer(project)
key_store = AuditKeyRevisionStore(writer, _constructor=_LEDGER_CONSTRUCTOR)
revision = key_store.load_all()["KEYREV-ONE"]
ledger = DurableAuditLedger(
    writer,
    key_store,
    epoch_id=epoch,
    initial_revision_id="KEYREV-ONE",
    _constructor=_LEDGER_CONSTRUCTOR,
)
setattr(writer, hook_name, lambda _staging, _target: os._exit(73))
ledger.append_audit_batch(
    (_event(revision, index=index),),
    created_at_utc=f"2026-07-11T09:00:{index:02d}Z",
)
raise AssertionError("crash hook did not terminate the process")
"""
    return subprocess.run(
        [sys.executable, "-B", "-c", child_code],
        cwd=Path(__file__).parent.parent,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        check=False,
        timeout=20,
    )


def test_key_revision_canonical_bytes_and_store_round_trip(ledger_lab: _LedgerLab) -> None:
    payload, expected = build_key_revision_bytes(
        revision_sequence=1,
        revision_id="KEYREV-ONE",
        created_at_utc="2026-07-11T00:00:01Z",
        master_key=b"K" * 32,
    )
    decoded = parse_canonical_json_bytes(payload, maximum_bytes=16 * 1024)

    assert payload == canonical_json_bytes(decoded)
    assert b"\r" not in payload
    assert payload.endswith(b"\n") and not payload.endswith(b"\n\n")
    created = _create_revision(ledger_lab)
    loaded = ledger_lab.key_store.load_all()
    assert created.revision_sha256 == expected.revision_sha256
    assert loaded["KEYREV-ONE"].master_key_sha256 == expected.master_key_sha256
    assert b"K" * 32 not in repr(created).encode("utf-8")


def test_durable_components_reject_missing_or_wrong_constructor_authority(
    ledger_lab: _LedgerLab,
) -> None:
    with pytest.raises(TypeError):
        AuditKeyRevisionStore(ledger_lab.writer)
    store = AuditKeyRevisionStore(
        ledger_lab.writer,
        _constructor=_LEDGER_CONSTRUCTOR,
    )
    _create_revision(ledger_lab)
    with pytest.raises(TypeError):
        DurableAuditLedger(
            ledger_lab.writer,
            store,
            epoch_id=ledger_lab.epoch_id,
            initial_revision_id="KEYREV-ONE",
        )
    ledger = _ledger(ledger_lab)
    with pytest.raises(LedgerError) as missing_sink_token:
        DurableAuditSink(ledger)
    assert missing_sink_token.value.code is LedgerCode.INVALID_REQUEST
    sink = DurableAuditSink(
        ledger,
        _constructor=_LEDGER_CONSTRUCTOR,
    )
    with pytest.raises(TypeError):
        _AuditAuthority(sink=sink, _constructor=object())


def test_genesis_append_reopen_and_idempotent_batch(ledger_lab: _LedgerLab) -> None:
    revision = _create_revision(ledger_lab)
    ledger = _ledger(ledger_lab)
    event = _event(revision, index=1)

    first = ledger.append_audit_batch(
        (event,),
        created_at_utc="2026-07-11T01:00:00Z",
    )
    replay = ledger.append_audit_batch(
        (event,),
        created_at_utc="2026-07-11T01:00:01Z",
    )
    reopened_writer = _create_test_handle_writer(ledger_lab.project)
    reopened = DurableAuditLedger(
        reopened_writer,
        AuditKeyRevisionStore(
            reopened_writer,
            _constructor=_LEDGER_CONSTRUCTOR,
        ),
        epoch_id=ledger_lab.epoch_id,
        initial_revision_id="KEYREV-ONE",
        _constructor=_LEDGER_CONSTRUCTOR,
    )

    assert first.sequence == 1
    assert replay.sequence == 1 and replay.replayed is True
    assert len(_segment_files(ledger_lab)) == 2
    assert reopened.head.last_sequence == 1
    assert reopened.head.last_segment_sha256 == first.segment_sha256
    assert reopened.head.active_revision_id == "KEYREV-ONE"


def test_mutex_busy_is_retryable_and_does_not_seal_the_ledger(
    ledger_lab: _LedgerLab,
) -> None:
    revision = _create_revision(ledger_lab)
    ledger = _ledger(ledger_lab)
    event = _event(revision, index=12)
    lease = ledger_lab.writer.acquire_runtime_mutex()
    try:
        with pytest.raises(LedgerError) as captured:
            ledger.append_audit_batch(
                (event,),
                created_at_utc="2026-07-11T01:30:00Z",
            )
    finally:
        lease.close()

    assert captured.value.code is LedgerCode.MUTEX_BUSY
    _assert_error_is_path_and_key_free(captured.value, ledger_lab)
    committed = ledger.append_audit_batch(
        (event,),
        created_at_utc="2026-07-11T01:30:01Z",
    )
    assert committed.sequence == 1
    assert ledger.head.segment_count == 2


def test_closed_mutex_lease_cannot_bypass_ledger_initialization_lock(
    ledger_lab: _LedgerLab,
) -> None:
    _create_revision(ledger_lab)
    stale = ledger_lab.writer.acquire_runtime_mutex()
    stale.close()

    with pytest.raises(HandleWriterError) as captured:
        DurableAuditLedger(
            ledger_lab.writer,
            ledger_lab.key_store,
            epoch_id=ledger_lab.epoch_id,
            initial_revision_id="KEYREV-ONE",
            initialize=True,
            initialized_at_utc="2026-07-11T01:45:00Z",
            _runtime_mutex_lease=stale,
            _constructor=_LEDGER_CONSTRUCTOR,
        )

    assert captured.value.code is HandleWriterCode.MUTEX_FAILED
    initialized = _ledger(ledger_lab)
    assert initialized.head.segment_count == 1


def test_three_segments_form_a_contiguous_restart_chain(ledger_lab: _LedgerLab) -> None:
    revision = _create_revision(ledger_lab)
    ledger = _ledger(ledger_lab)
    receipts = [
        ledger.append_audit_batch(
            (_event(revision, index=index),),
            created_at_utc=f"2026-07-11T02:00:0{index}Z",
        )
        for index in range(1, 4)
    ]
    reopened_writer = _create_test_handle_writer(ledger_lab.project)
    reopened = DurableAuditLedger(
        reopened_writer,
        AuditKeyRevisionStore(
            reopened_writer,
            _constructor=_LEDGER_CONSTRUCTOR,
        ),
        epoch_id=ledger_lab.epoch_id,
        initial_revision_id="KEYREV-ONE",
        _constructor=_LEDGER_CONSTRUCTOR,
    )

    assert [receipt.sequence for receipt in receipts] == [1, 2, 3]
    assert reopened.head.last_sequence == 3
    assert reopened.head.last_segment_sha256 == receipts[-1].segment_sha256
    assert [path.name[:20] for path in _segment_files(ledger_lab)] == [
        "00000000000000000000",
        "00000000000000000001",
        "00000000000000000002",
        "00000000000000000003",
    ]


def test_restricted_segment_contains_only_hmac_context(ledger_lab: _LedgerLab) -> None:
    revision = _create_revision(ledger_lab)
    ledger = _ledger(ledger_lab)
    event = _event(revision, index=4, restricted=True)

    ledger.append_audit_batch(
        (event,),
        created_at_utc="2026-07-11T03:00:00Z",
    )
    payload = _segment_files(ledger_lab)[-1].read_bytes()
    decoded = parse_canonical_json_bytes(payload, maximum_bytes=2 * 1024 * 1024)
    record = decoded["body"]["records"][0]

    assert record["classification"] == "RESTRICTED"
    assert record["redaction_mode"] == "HMAC_ONLY"
    assert record["safe_relative_path"] is None
    assert record["run_id"] is None
    assert record["operation_id"] is None
    assert record["path_hmac_sha256"]
    assert b"item-0004" not in payload


def test_key_rotation_is_old_key_authenticated_and_survives_restart(
    ledger_lab: _LedgerLab,
) -> None:
    first = _create_revision(ledger_lab)
    ledger = _ledger(ledger_lab)
    second = _create_revision(
        ledger_lab,
        sequence=2,
        revision_id="KEYREV-TWO",
        key_byte=b"L",
    )
    first_event = _event(first, index=5)
    first_receipt = ledger.append_audit_batch(
        (first_event,),
        created_at_utc="2026-07-11T04:00:00Z",
    )
    rotation = ledger.rotate_key(
        next_revision_id="KEYREV-TWO",
        rotation_id="ROTATION-S3C-0001",
        created_at_utc="2026-07-11T04:00:01Z",
    )
    rotation_replay = ledger.rotate_key(
        next_revision_id="KEYREV-TWO",
        rotation_id="ROTATION-S3C-0001",
        created_at_utc="2026-07-11T04:00:05Z",
    )
    old_batch_replay = ledger.append_audit_batch(
        (first_event,),
        created_at_utc="2026-07-11T04:00:06Z",
    )
    after_rotation = ledger.append_audit_batch(
        (_event(second, index=6),),
        created_at_utc="2026-07-11T04:00:07Z",
    )
    reopened_writer = _create_test_handle_writer(ledger_lab.project)
    reopened = DurableAuditLedger(
        reopened_writer,
        AuditKeyRevisionStore(
            reopened_writer,
            _constructor=_LEDGER_CONSTRUCTOR,
        ),
        epoch_id=ledger_lab.epoch_id,
        initial_revision_id="KEYREV-ONE",
        _constructor=_LEDGER_CONSTRUCTOR,
    )

    assert rotation.sequence == 2
    assert rotation_replay.sequence == 2 and rotation_replay.replayed is True
    assert old_batch_replay.sequence == first_receipt.sequence
    assert old_batch_replay.replayed is True
    assert after_rotation.sequence == 3
    assert reopened.head.active_revision_id == "KEYREV-TWO"
    assert reopened.audit_hmac_key_id == second.audit_hmac_key_id


def test_open_rejects_deleted_genesis_and_old_key_cannot_reinitialize(
    ledger_lab: _LedgerLab,
) -> None:
    _create_revision(ledger_lab)
    initialized = _ledger(ledger_lab)
    assert initialized.head.segment_count == 1
    genesis = _segment_files(ledger_lab)[0]
    genesis.unlink()
    assert _segment_files(ledger_lab) == []

    fresh_writer = _create_test_handle_writer(ledger_lab.project)
    fresh_store = AuditKeyRevisionStore(
        fresh_writer,
        _constructor=_LEDGER_CONSTRUCTOR,
    )
    with pytest.raises(LedgerError) as opened:
        DurableAuditLedger(
            fresh_writer,
            fresh_store,
            epoch_id=ledger_lab.epoch_id,
            initial_revision_id="KEYREV-ONE",
            _constructor=_LEDGER_CONSTRUCTOR,
        )
    assert opened.value.code is LedgerCode.CHAIN_CORRUPT

    retry_writer = _create_test_handle_writer(ledger_lab.project)
    retry_store = AuditKeyRevisionStore(
        retry_writer,
        _constructor=_LEDGER_CONSTRUCTOR,
    )
    with pytest.raises(LedgerError) as retried:
        DurableAuditLedger(
            retry_writer,
            retry_store,
            epoch_id=ledger_lab.epoch_id,
            initial_revision_id="KEYREV-ONE",
            initialize=True,
            initialized_at_utc="2026-07-11T04:30:00Z",
            _constructor=_LEDGER_CONSTRUCTOR,
        )
    assert retried.value.code is LedgerCode.INVALID_REQUEST
    assert _segment_files(ledger_lab) == []


def test_rotation_history_rejects_same_length_old_key_tamper(
    ledger_lab: _LedgerLab,
) -> None:
    _create_revision(ledger_lab)
    ledger = _ledger(ledger_lab)
    _create_revision(
        ledger_lab,
        sequence=2,
        revision_id="KEYREV-TWO",
        key_byte=b"L",
    )
    ledger.rotate_key(
        next_revision_id="KEYREV-TWO",
        rotation_id="ROTATION-S3C-TAMPER",
        created_at_utc="2026-07-11T04:40:00Z",
    )
    old_key = _key_files(ledger_lab)[0]
    original = old_key.read_bytes()
    marker = b"S0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0s="
    replacement = b"R0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0s="
    assert marker in original and len(marker) == len(replacement)
    old_key.write_bytes(original.replace(marker, replacement, 1))

    fresh_writer = _create_test_handle_writer(ledger_lab.project)
    with pytest.raises(LedgerError) as captured:
        DurableAuditLedger(
            fresh_writer,
            AuditKeyRevisionStore(
                fresh_writer,
                _constructor=_LEDGER_CONSTRUCTOR,
            ),
            epoch_id=ledger_lab.epoch_id,
            initial_revision_id="KEYREV-ONE",
            _constructor=_LEDGER_CONSTRUCTOR,
        )
    assert captured.value.code in {
        LedgerCode.KEY_STORE_CORRUPT,
        LedgerCode.CHAIN_CORRUPT,
    }
    assert old_key.read_bytes() != original


def test_self_consistent_unknown_key_schema_is_rejected_and_retained(
    ledger_lab: _LedgerLab,
) -> None:
    _create_revision(ledger_lab)
    original = _key_files(ledger_lab)[0]
    decoded = parse_canonical_json_bytes(
        original.read_bytes(),
        maximum_bytes=16 * 1024,
    )
    body = decoded["body"]
    body["schema_version"] = "9.9"
    revision_sha256 = hashlib.sha256(
        b"AUDIT-KEY-REVISION-V1\0" + canonical_json_bytes(body)[:-1]
    ).hexdigest()
    payload = canonical_json_bytes(
        {
            "body": body,
            "integrity": {"revision_sha256": revision_sha256},
        }
    )
    tampered = original.with_name(
        f"{body['revision_sequence']:08d}-{body['revision_id']}-"
        f"{revision_sha256}.json"
    )
    original.rename(tampered)
    tampered.write_bytes(payload)
    fresh_writer = _create_test_handle_writer(ledger_lab.project)
    fresh_store = AuditKeyRevisionStore(
        fresh_writer,
        _constructor=_LEDGER_CONSTRUCTOR,
    )

    with pytest.raises(LedgerError) as captured:
        fresh_store.load_all()

    assert captured.value.code is LedgerCode.KEY_STORE_CORRUPT
    assert tampered.read_bytes() == payload
    assert {path.name for path in _key_files(ledger_lab)} == {tampered.name}
    with pytest.raises(HandleWriterError) as sealed:
        fresh_writer.acquire_runtime_mutex()
    assert sealed.value.code is HandleWriterCode.WRITER_SEALED


def test_unknown_pending_file_seals_startup_without_cleanup(ledger_lab: _LedgerLab) -> None:
    _create_revision(ledger_lab)
    segment_root = ledger_lab.project / "logs" / "audit" / "segments" / ledger_lab.epoch_id
    pending = segment_root / "PENDING-00000000000000000000-AAAAAAAA-BBBBBBBB.json"
    pending.write_bytes(b"partial")
    fresh_writer = _create_test_handle_writer(ledger_lab.project)

    with pytest.raises(LedgerError) as captured:
        DurableAuditLedger(
            fresh_writer,
            AuditKeyRevisionStore(
                fresh_writer,
                _constructor=_LEDGER_CONSTRUCTOR,
            ),
            epoch_id=ledger_lab.epoch_id,
            initial_revision_id="KEYREV-ONE",
            _constructor=_LEDGER_CONSTRUCTOR,
        )

    assert captured.value.code is LedgerCode.UNKNOWN_ENTRY
    assert pending.read_bytes() == b"partial"
    _assert_error_is_path_and_key_free(captured.value, ledger_lab)


@pytest.mark.parametrize("entry_kind", ["file", "directory"])
def test_startup_rejects_nonsegment_file_and_child_directory(
    ledger_lab: _LedgerLab,
    entry_kind: str,
) -> None:
    _create_revision(ledger_lab)
    _ledger(ledger_lab)
    segment_root = ledger_lab.project / "logs" / "audit" / "segments" / ledger_lab.epoch_id
    unknown = segment_root / (
        "desktop.ini" if entry_kind == "file" else "unexpected-child"
    )
    if entry_kind == "file":
        unknown.write_bytes(b"unknown")
    else:
        unknown.mkdir()

    fresh_writer = _create_test_handle_writer(ledger_lab.project)
    with pytest.raises(LedgerError) as captured:
        DurableAuditLedger(
            fresh_writer,
            AuditKeyRevisionStore(
                fresh_writer,
                _constructor=_LEDGER_CONSTRUCTOR,
            ),
            epoch_id=ledger_lab.epoch_id,
            initial_revision_id="KEYREV-ONE",
            _constructor=_LEDGER_CONSTRUCTOR,
        )

    assert captured.value.code in {
        LedgerCode.UNKNOWN_ENTRY,
        LedgerCode.STORAGE_FAILURE,
    }
    assert unknown.exists()
    with pytest.raises(HandleWriterError) as sealed:
        fresh_writer.acquire_runtime_mutex()
    assert sealed.value.code is HandleWriterCode.WRITER_SEALED


def test_same_length_segment_tamper_seals_full_chain(ledger_lab: _LedgerLab) -> None:
    revision = _create_revision(ledger_lab)
    ledger = _ledger(ledger_lab)
    ledger.append_audit_batch(
        (_event(revision, index=7),),
        created_at_utc="2026-07-11T05:00:00Z",
    )
    segment = _segment_files(ledger_lab)[-1]
    original = segment.read_bytes()
    marker = b"EVENT-S3C-0007"
    assert marker in original
    segment.write_bytes(original.replace(marker, b"EVENT-S3C-9007", 1))
    fresh_writer = _create_test_handle_writer(ledger_lab.project)

    with pytest.raises(LedgerError) as captured:
        DurableAuditLedger(
            fresh_writer,
            AuditKeyRevisionStore(
                fresh_writer,
                _constructor=_LEDGER_CONSTRUCTOR,
            ),
            epoch_id=ledger_lab.epoch_id,
            initial_revision_id="KEYREV-ONE",
            _constructor=_LEDGER_CONSTRUCTOR,
        )

    assert captured.value.code is LedgerCode.CHAIN_CORRUPT
    assert segment.read_bytes() != original


def test_self_consistent_unknown_segment_schema_is_rejected_and_retained(
    ledger_lab: _LedgerLab,
) -> None:
    revision = _create_revision(ledger_lab)
    _ledger(ledger_lab)
    original = _segment_files(ledger_lab)[0]
    decoded = parse_canonical_json_bytes(
        original.read_bytes(),
        maximum_bytes=2 * 1024 * 1024,
    )
    body = decoded["body"]
    body["schema_version"] = "9.9"
    segment_sha256 = hashlib.sha256(
        b"LEDGER-SEGMENT-V1\0" + canonical_json_bytes(body)[:-1]
    ).hexdigest()
    segment_hmac_sha256 = hmac.new(
        revision.segment_hmac_key,
        b"LEDGER-SEGMENT-AUTH-V1\0" + bytes.fromhex(segment_sha256),
        hashlib.sha256,
    ).hexdigest()
    payload = canonical_json_bytes(
        {
            "body": body,
            "integrity": {
                "segment_sha256": segment_sha256,
                "segment_hmac_sha256": segment_hmac_sha256,
            },
        }
    )
    tampered = original.with_name(
        f"{body['sequence']:020d}-{segment_sha256}.json"
    )
    original.rename(tampered)
    tampered.write_bytes(payload)
    fresh_writer = _create_test_handle_writer(ledger_lab.project)

    with pytest.raises(LedgerError) as captured:
        DurableAuditLedger(
            fresh_writer,
            AuditKeyRevisionStore(
                fresh_writer,
                _constructor=_LEDGER_CONSTRUCTOR,
            ),
            epoch_id=ledger_lab.epoch_id,
            initial_revision_id="KEYREV-ONE",
            _constructor=_LEDGER_CONSTRUCTOR,
        )

    assert captured.value.code is LedgerCode.POLICY_MISMATCH
    assert tampered.read_bytes() == payload
    assert {path.name for path in _segment_files(ledger_lab)} == {tampered.name}
    with pytest.raises(HandleWriterError) as sealed:
        fresh_writer.acquire_runtime_mutex()
    assert sealed.value.code is HandleWriterCode.WRITER_SEALED
    _assert_error_is_path_and_key_free(captured.value, ledger_lab)


def test_startup_rejects_sequence_gap_without_renaming_it_back(
    ledger_lab: _LedgerLab,
) -> None:
    revision = _create_revision(ledger_lab)
    ledger = _ledger(ledger_lab)
    ledger.append_audit_batch(
        (_event(revision, index=16),),
        created_at_utc="2026-07-11T05:10:00Z",
    )
    source = _segment_files(ledger_lab)[-1]
    digest = source.name.split("-", 1)[1]
    gap = source.with_name("00000000000000000002-" + digest)
    source.rename(gap)

    fresh_writer = _create_test_handle_writer(ledger_lab.project)
    with pytest.raises(LedgerError) as captured:
        DurableAuditLedger(
            fresh_writer,
            AuditKeyRevisionStore(
                fresh_writer,
                _constructor=_LEDGER_CONSTRUCTOR,
            ),
            epoch_id=ledger_lab.epoch_id,
            initial_revision_id="KEYREV-ONE",
            _constructor=_LEDGER_CONSTRUCTOR,
        )
    assert captured.value.code is LedgerCode.CHAIN_CORRUPT
    assert gap.exists() and not source.exists()


def test_startup_rejects_two_individually_valid_same_sequence_forks(
    ledger_lab: _LedgerLab,
) -> None:
    revision = _create_revision(ledger_lab)
    ledger = _ledger(ledger_lab)
    genesis = ledger.head.last_segment_sha256
    assert genesis is not None
    first_payload, first_sha, _first_batch, _first_ids = build_audit_segment_bytes(
        epoch_id=ledger_lab.epoch_id,
        sequence=1,
        previous_segment_sha256=genesis,
        created_at_utc="2026-07-11T05:20:00Z",
        revision=revision,
        events=(_event(revision, index=17),),
    )
    second_payload, second_sha, _second_batch, _second_ids = build_audit_segment_bytes(
        epoch_id=ledger_lab.epoch_id,
        sequence=1,
        previous_segment_sha256=genesis,
        created_at_utc="2026-07-11T05:20:01Z",
        revision=revision,
        events=(_event(revision, index=18),),
    )
    segment_root = ledger_lab.project / "logs" / "audit" / "segments" / ledger_lab.epoch_id
    first = segment_root / f"{1:020d}-{first_sha}.json"
    second = segment_root / f"{1:020d}-{second_sha}.json"
    first.write_bytes(first_payload)
    second.write_bytes(second_payload)

    fresh_writer = _create_test_handle_writer(ledger_lab.project)
    with pytest.raises(LedgerError) as captured:
        DurableAuditLedger(
            fresh_writer,
            AuditKeyRevisionStore(
                fresh_writer,
                _constructor=_LEDGER_CONSTRUCTOR,
            ),
            epoch_id=ledger_lab.epoch_id,
            initial_revision_id="KEYREV-ONE",
            _constructor=_LEDGER_CONSTRUCTOR,
        )
    assert captured.value.code is LedgerCode.CHAIN_CORRUPT
    assert first.read_bytes() == first_payload
    assert second.read_bytes() == second_payload


def test_valid_final_after_post_rename_failure_is_recovered_by_restart_scan(
    ledger_lab: _LedgerLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    revision = _create_revision(ledger_lab)
    ledger = _ledger(ledger_lab)
    event = _event(revision, index=8)

    def fail_after_publish(_staging: object, _target: object) -> None:
        raise HandleWriterError(
            HandleWriterCode.POSTCONDITION_FAILED,
            "injected crash-equivalent after rename",
        )

    monkeypatch.setattr(ledger_lab.writer, "_after_publish", fail_after_publish)
    with pytest.raises(LedgerError) as captured:
        ledger.append_audit_batch(
            (event,),
            created_at_utc="2026-07-11T06:00:00Z",
        )
    assert captured.value.code is LedgerCode.STORAGE_FAILURE
    assert len(_segment_files(ledger_lab)) == 2

    monkeypatch.undo()
    fresh_writer = _create_test_handle_writer(ledger_lab.project)
    recovered = DurableAuditLedger(
        fresh_writer,
        AuditKeyRevisionStore(
            fresh_writer,
            _constructor=_LEDGER_CONSTRUCTOR,
        ),
        epoch_id=ledger_lab.epoch_id,
        initial_revision_id="KEYREV-ONE",
        _constructor=_LEDGER_CONSTRUCTOR,
    )
    assert recovered.head.last_sequence == 1


def test_real_process_crash_after_rename_recovers_the_published_final(
    ledger_lab: _LedgerLab,
) -> None:
    revision = _create_revision(ledger_lab)
    _ledger(ledger_lab)

    completed = _run_crash_child(
        ledger_lab,
        hook_name="_after_publish",
        event_index=13,
    )

    assert completed.returncode == 73, (completed.stdout, completed.stderr)
    entries = _segment_files(ledger_lab)
    assert len(entries) == 2
    assert entries[-1].name.startswith("00000000000000000001-")
    assert not any(path.name.startswith("PENDING-") for path in entries)
    fresh_writer = _create_test_handle_writer(ledger_lab.project)
    recovered = DurableAuditLedger(
        fresh_writer,
        AuditKeyRevisionStore(
            fresh_writer,
            _constructor=_LEDGER_CONSTRUCTOR,
        ),
        epoch_id=ledger_lab.epoch_id,
        initial_revision_id="KEYREV-ONE",
        _constructor=_LEDGER_CONSTRUCTOR,
    )
    assert recovered.head.last_sequence == 1
    assert recovered.head.segment_count == 2
    replay = recovered.append_audit_batch(
        (_event(revision, index=13),),
        created_at_utc="2026-07-11T09:00:59Z",
    )
    assert replay.replayed is True
    assert len(_segment_files(ledger_lab)) == 2


def test_real_process_crash_before_rename_retains_pending_and_seals_restart(
    ledger_lab: _LedgerLab,
) -> None:
    _create_revision(ledger_lab)
    _ledger(ledger_lab)

    completed = _run_crash_child(
        ledger_lab,
        hook_name="_after_stage_verified",
        event_index=14,
    )

    assert completed.returncode == 73, (completed.stdout, completed.stderr)
    entries = _segment_files(ledger_lab)
    assert len(entries) == 2
    pending = next(path for path in entries if path.name.startswith("PENDING-"))
    assert pending.name.startswith("PENDING-")
    original = pending.read_bytes()
    fresh_writer = _create_test_handle_writer(ledger_lab.project)
    with pytest.raises(LedgerError) as captured:
        DurableAuditLedger(
            fresh_writer,
            AuditKeyRevisionStore(
                fresh_writer,
                _constructor=_LEDGER_CONSTRUCTOR,
            ),
            epoch_id=ledger_lab.epoch_id,
            initial_revision_id="KEYREV-ONE",
            _constructor=_LEDGER_CONSTRUCTOR,
        )
    assert captured.value.code is LedgerCode.UNKNOWN_ENTRY
    assert pending.read_bytes() == original
    _assert_error_is_path_and_key_free(captured.value, ledger_lab)
    with pytest.raises(HandleWriterError) as writer_error:
        fresh_writer.acquire_runtime_mutex()
    assert writer_error.value.code is HandleWriterCode.WRITER_SEALED


def test_cross_process_mutex_allows_one_writer_and_then_releases(
    ledger_lab: _LedgerLab,
) -> None:
    ready = ledger_lab.project / "mutex-child-ready.marker"
    release = ledger_lab.project / "mutex-child-release.marker"
    environment = os.environ.copy()
    environment.update(
        {
            "M0_MUTEX_CHILD_PROJECT": str(ledger_lab.project),
            "M0_MUTEX_CHILD_READY": str(ready),
            "M0_MUTEX_CHILD_RELEASE": str(release),
        }
    )
    child_code = """
import os
import time
from pathlib import Path
from app.safety.production_guard import _create_test_handle_writer

project = Path(os.environ["M0_MUTEX_CHILD_PROJECT"])
ready = Path(os.environ["M0_MUTEX_CHILD_READY"])
release = Path(os.environ["M0_MUTEX_CHILD_RELEASE"])
writer = _create_test_handle_writer(project)
with writer.acquire_runtime_mutex():
    ready.write_bytes(b"ready\\n")
    deadline = time.monotonic() + 15
    while not release.is_file():
        if time.monotonic() >= deadline:
            raise TimeoutError("parent did not release mutex child")
        time.sleep(0.01)
"""
    child = subprocess.Popen(
        [sys.executable, "-B", "-c", child_code],
        cwd=Path(__file__).parent.parent,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
    )
    try:
        deadline = time.monotonic() + 10
        while not ready.is_file() and child.poll() is None:
            if time.monotonic() >= deadline:
                break
            time.sleep(0.01)
        assert ready.is_file(), child.communicate(timeout=5)
        assert ready.read_bytes() == b"ready\n"
        with pytest.raises(HandleWriterError) as captured:
            ledger_lab.writer.acquire_runtime_mutex()
        assert captured.value.code is HandleWriterCode.MUTEX_BUSY
    finally:
        if not release.exists():
            release.write_bytes(b"release\n")
        stdout, stderr = child.communicate(timeout=20)
    assert child.returncode == 0, (stdout, stderr)
    with ledger_lab.writer.acquire_runtime_mutex() as lease:
        assert lease.abandoned is False


def test_abandoned_mutex_is_observed_without_claiming_a_new_final_recovery(
    ledger_lab: _LedgerLab,
) -> None:
    revision = _create_revision(ledger_lab)
    ledger = _ledger(ledger_lab)
    ledger.append_audit_batch(
        (_event(revision, index=15),),
        created_at_utc="2026-07-11T09:15:00Z",
    )
    segment = _segment_files(ledger_lab)[0]
    original_sha256 = hashlib.sha256(segment.read_bytes()).hexdigest()
    ready = ledger_lab.project / "abandoned-child-ready.marker"
    crash = ledger_lab.project / "abandoned-child-crash.marker"
    environment = os.environ.copy()
    environment.update(
        {
            "M0_ABANDONED_PROJECT": str(ledger_lab.project),
            "M0_ABANDONED_READY": str(ready),
            "M0_ABANDONED_CRASH": str(crash),
        }
    )
    child_code = """
import os
import time
from pathlib import Path
from app.safety.production_guard import _create_test_handle_writer

project = Path(os.environ["M0_ABANDONED_PROJECT"])
ready = Path(os.environ["M0_ABANDONED_READY"])
crash = Path(os.environ["M0_ABANDONED_CRASH"])
writer = _create_test_handle_writer(project)
with writer.acquire_runtime_mutex():
    ready.write_bytes(b"ready\\n")
    deadline = time.monotonic() + 15
    while not crash.is_file():
        if time.monotonic() >= deadline:
            raise TimeoutError("parent did not trigger abandoned mutex")
        time.sleep(0.01)
    os._exit(74)
"""
    child = subprocess.Popen(
        [sys.executable, "-B", "-c", child_code],
        cwd=Path(__file__).parent.parent,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
    )
    observer_handle = 0
    try:
        deadline = time.monotonic() + 10
        while not ready.is_file() and child.poll() is None:
            if time.monotonic() >= deadline:
                break
            time.sleep(0.01)
        assert ready.is_file(), child.communicate(timeout=5)
        observer_handle = int(
            ledger_lab.writer._api.kernel32.CreateMutexW(
                None,
                False,
                ledger_lab.writer._mutex_name,
            )
        )
        assert ctypes.c_void_p(observer_handle).value not in {
            None,
            ledger_lab.writer._api.invalid_handle,
        }
        crash.write_bytes(b"crash\n")
        stdout, stderr = child.communicate(timeout=20)
        assert child.returncode == 74, (stdout, stderr)
        fresh_writer = _create_test_handle_writer(ledger_lab.project)
        recovered = DurableAuditLedger(
            fresh_writer,
            AuditKeyRevisionStore(
                fresh_writer,
                _constructor=_LEDGER_CONSTRUCTOR,
            ),
            epoch_id=ledger_lab.epoch_id,
            initial_revision_id="KEYREV-ONE",
            _constructor=_LEDGER_CONSTRUCTOR,
        )
    finally:
        if child.poll() is None:
            if not crash.exists():
                crash.write_bytes(b"crash\n")
            child.communicate(timeout=20)
        if observer_handle:
            ledger_lab.writer._api.close(observer_handle)

    assert recovered.head.startup_observed_abandoned_mutex is True
    assert recovered.head.segment_count == 2
    assert hashlib.sha256(segment.read_bytes()).hexdigest() == original_sha256


def test_durable_sink_returns_exact_audit_receipt(ledger_lab: _LedgerLab) -> None:
    revision = _create_revision(ledger_lab)
    ledger = _ledger(ledger_lab)
    sink = DurableAuditSink(
        ledger,
        _constructor=_LEDGER_CONSTRUCTOR,
    )
    events = (_event(revision, index=9), _event(revision, index=10))

    receipt = sink.record_batch(events)

    assert receipt.event_ids == tuple(event.event_id for event in events)
    assert receipt.batch_sha256 == hashlib.sha256(
        b"AUDIT-BATCH-V1\0"
        + __import__("json").dumps(
            [event.to_dict() for event in events],
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    ).hexdigest()
    assert ledger.head.segment_count == 2


def test_durable_sink_wraps_malformed_exact_event_without_writing(
    ledger_lab: _LedgerLab,
) -> None:
    revision = _create_revision(ledger_lab)
    ledger = _ledger(ledger_lab)
    sink = DurableAuditSink(
        ledger,
        _constructor=_LEDGER_CONSTRUCTOR,
    )
    malformed = replace(
        _event(revision, index=11),
        action="ISSUE",  # type: ignore[arg-type]
    )

    with pytest.raises(LedgerError) as captured:
        sink.record_batch((malformed,))

    assert captured.value.code is LedgerCode.INVALID_REQUEST
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    assert ledger.head.segment_count == 1


def test_durable_sink_seals_if_post_commit_receipt_recomputation_fails(
    ledger_lab: _LedgerLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    revision = _create_revision(ledger_lab)
    ledger = _ledger(ledger_lab)
    sink = DurableAuditSink(
        ledger,
        _constructor=_LEDGER_CONSTRUCTOR,
    )
    original_receipt = segment_ledger_module.audit_receipt
    receipt_calls = 0

    def fail_only_after_commit(events: tuple[AuditEvent, ...]) -> object:
        nonlocal receipt_calls
        receipt_calls += 1
        if receipt_calls == 3:
            raise AttributeError("injected post-commit receipt failure")
        return original_receipt(events)

    monkeypatch.setattr(
        segment_ledger_module,
        "audit_receipt",
        fail_only_after_commit,
    )

    with pytest.raises(LedgerError) as captured:
        sink.record_factory(lambda _key: (_event(revision, index=13),))

    assert receipt_calls == 3
    assert captured.value.code is LedgerCode.STORAGE_FAILURE
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    assert len(_segment_files(ledger_lab)) == 2
    with pytest.raises(LedgerError) as sealed:
        _ = ledger.head
    assert sealed.value.code is LedgerCode.LEDGER_SEALED


@pytest.mark.parametrize(
    ("changes", "expected_code"),
    (
        (
            {
                "action": AuditAction.DENY,
                "error_code": "INCONSISTENT",
            },
            LedgerCode.CHAIN_CORRUPT,
        ),
        (
            {
                "decision": AuditDecision.DENY,
                "action": AuditAction.ISSUE,
                "error_code": None,
            },
            LedgerCode.CHAIN_CORRUPT,
        ),
        (
            {"safe_relative_path": "C:item.json", "path_depth": 1},
            LedgerCode.REDACTION_FAILURE,
        ),
        (
            {"safe_relative_path": "safe/item.json", "path_depth": 99},
            LedgerCode.REDACTION_FAILURE,
        ),
        (
            {"safe_relative_path": "SAFE/item.json", "path_depth": 2},
            LedgerCode.REDACTION_FAILURE,
        ),
    ),
)
def test_audit_event_semantic_truth_table_and_canonical_path_are_frozen(
    ledger_lab: _LedgerLab,
    changes: dict[str, object],
    expected_code: LedgerCode,
) -> None:
    revision = _create_revision(ledger_lab)
    ledger = _ledger(ledger_lab)
    invalid = replace(_event(revision, index=14), **changes)
    before = _ledger_entry_snapshot(ledger_lab)

    with pytest.raises(LedgerError) as captured:
        ledger.append_audit_batch(
            (invalid,),
            created_at_utc="2026-07-11T06:59:59Z",
        )

    assert captured.value.code is expected_code
    assert _ledger_entry_snapshot(ledger_lab) == before


@pytest.mark.parametrize(
    "variant",
    (
        "allow-issue",
        "allow-revalidate",
        "deny",
        "pair",
        "context-hmac",
        "path-hmac",
        "restricted",
    ),
)
def test_each_valid_audit_semantic_row_commits_exactly_once(
    ledger_lab: _LedgerLab,
    variant: str,
) -> None:
    revision = _create_revision(ledger_lab)
    ledger = _ledger(ledger_lab)
    event = _semantic_event(
        revision,
        index=15,
        variant=variant,
    )

    receipt = ledger.append_audit_batch(
        (event,),
        created_at_utc="2026-07-11T06:58:00Z",
    )

    assert receipt.sequence == 1
    assert receipt.record_ids == (event.event_id,)
    assert ledger.head.segment_count == 2
    decoded = parse_canonical_json_bytes(
        _segment_files(ledger_lab)[-1].read_bytes(),
        maximum_bytes=2 * 1024 * 1024,
    )
    record = decoded["body"]["records"][0]
    if variant == "allow-issue":
        assert (record["decision"], record["action"], record["error_code"]) == (
            "CANDIDATE_ALLOW",
            "ISSUE",
            None,
        )
    elif variant == "allow-revalidate":
        assert (record["decision"], record["action"], record["error_code"]) == (
            "CANDIDATE_ALLOW",
            "REVALIDATE",
            None,
        )
    elif variant == "deny":
        assert (record["decision"], record["action"], record["error_code"]) == (
            "DENY",
            "DENY",
            "SYNTHETIC_DENIAL",
        )
    elif variant == "pair":
        assert (record["capability_kind"], record["pair_id"], record["pair_role"]) == (
            "PUBLISH_PAIR",
            "PAIR-S3C-SEMANTIC",
            "SOURCE",
        )
    elif variant == "context-hmac":
        assert record["context_hmac_sha256"] is not None
        assert record["context_digest"] is None
        assert record["run_id"] is None
    elif variant == "path-hmac":
        assert record["redaction_mode"] == "HMAC_ONLY"
        assert record["safe_relative_path"] is None
        assert record["path_hmac_sha256"] is not None
        assert record["path_depth"] == 2
    elif variant == "restricted":
        assert record["classification"] == "RESTRICTED"
        assert record["redaction_mode"] == "HMAC_ONLY"
        assert record["context_hmac_sha256"] is not None
        assert record["safe_relative_path"] is None
        assert record["path_depth"] is None


@pytest.mark.parametrize(
    ("base_variant", "field", "value", "expected_code"),
    (
        ("allow-issue", "action", AuditAction.DENY, LedgerCode.CHAIN_CORRUPT),
        ("allow-issue", "error_code", "UNEXPECTED", LedgerCode.CHAIN_CORRUPT),
        ("deny", "error_code", None, LedgerCode.CHAIN_CORRUPT),
        ("deny", "action", AuditAction.ISSUE, LedgerCode.CHAIN_CORRUPT),
        ("deny", "action", AuditAction.REVALIDATE, LedgerCode.CHAIN_CORRUPT),
        ("allow-issue", "pair_id", "PAIR-EXTRA", LedgerCode.CHAIN_CORRUPT),
        ("allow-issue", "pair_role", PairRole.SOURCE, LedgerCode.CHAIN_CORRUPT),
        ("pair", "pair_id", None, LedgerCode.CHAIN_CORRUPT),
        ("pair", "pair_role", None, LedgerCode.CHAIN_CORRUPT),
        ("deny", "pair_role", PairRole.SOURCE, LedgerCode.CHAIN_CORRUPT),
        (
            "allow-issue",
            "context_hmac_sha256",
            "0" * 64,
            LedgerCode.REDACTION_FAILURE,
        ),
        (
            "context-hmac",
            "context_digest",
            "0" * 64,
            LedgerCode.REDACTION_FAILURE,
        ),
        (
            "context-hmac",
            "run_id",
            "RUN-CONTEXT-POLLUTION",
            LedgerCode.REDACTION_FAILURE,
        ),
        (
            "allow-issue",
            "path_hmac_sha256",
            "0" * 64,
            LedgerCode.REDACTION_FAILURE,
        ),
        (
            "allow-issue",
            "safe_relative_path",
            "C:item.json",
            LedgerCode.REDACTION_FAILURE,
        ),
        (
            "allow-issue",
            "safe_relative_path",
            "../item.json",
            LedgerCode.REDACTION_FAILURE,
        ),
        (
            "allow-issue",
            "safe_relative_path",
            "SAFE/item.json",
            LedgerCode.REDACTION_FAILURE,
        ),
        ("allow-issue", "path_depth", 99, LedgerCode.REDACTION_FAILURE),
        (
            "path-hmac",
            "safe_relative_path",
            "safe/item.json",
            LedgerCode.REDACTION_FAILURE,
        ),
        (
            "path-hmac",
            "path_hmac_sha256",
            "g" * 64,
            LedgerCode.REDACTION_FAILURE,
        ),
        ("path-hmac", "path_depth", 0, LedgerCode.REDACTION_FAILURE),
        ("restricted", "path_depth", 2, LedgerCode.REDACTION_FAILURE),
        (
            "restricted",
            "safe_relative_path",
            "safe/item.json",
            LedgerCode.REDACTION_FAILURE,
        ),
    ),
)
def test_each_invalid_audit_semantic_cell_is_zero_write(
    ledger_lab: _LedgerLab,
    base_variant: str,
    field: str,
    value: object,
    expected_code: LedgerCode,
) -> None:
    revision = _create_revision(ledger_lab)
    ledger = _ledger(ledger_lab)
    valid = _semantic_event(
        revision,
        index=16,
        variant=base_variant,
    )
    invalid = replace(valid, **{field: value})
    before = _ledger_entry_snapshot(ledger_lab)

    with pytest.raises(LedgerError) as captured:
        ledger.append_audit_batch(
            (invalid,),
            created_at_utc="2026-07-11T06:58:01Z",
        )

    assert captured.value.code is expected_code
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    assert _ledger_entry_snapshot(ledger_lab) == before


def test_private_durable_boundary_persists_real_candidate_audit_across_restart(
    ledger_lab: _LedgerLab,
) -> None:
    base = ledger_lab.project / "Base"
    base.mkdir()
    reference = base / "reference.txt"
    reference.write_text("synthetic reference", encoding="utf-8")
    master_key = b"D" * 32
    first = _create_test_durable_boundary(
        ledger_lab.project,
        initialize=True,
        epoch_id=ledger_lab.epoch_id,
        initial_revision_sequence=1,
        initial_revision_id="KEYREV-DURABLE",
        master_key=master_key,
        key_created_at_utc="2026-07-11T07:00:00Z",
        ledger_initialized_at_utc="2026-07-11T07:00:01Z",
    )
    context = first.boundary.issue_context(
        run_id=ledger_lab.epoch_id,
        job_id="JOB-DURABLE-0001",
        operation_id="OP-DURABLE-0001",
        caller=Caller.IMPORT_SERVICE,
        purpose=Purpose.READ_REFERENCE,
    )

    ticket = first.boundary.authorize(
        Path("Base") / reference.name,
        intent=PathIntent.EXISTING_READ,
        expected_kind=ExpectedKind.FILE,
        context=context,
    )

    assert ticket is not None
    assert first.boundary.writer_available is False
    assert first.ledger.head.last_sequence == 1
    restarted = _create_test_durable_boundary(
        ledger_lab.project,
        epoch_id=ledger_lab.epoch_id,
        initial_revision_sequence=1,
        initial_revision_id="KEYREV-DURABLE",
        master_key=master_key,
        key_created_at_utc="2026-07-11T07:00:00Z",
    )
    assert restarted.ledger.head.last_sequence == 1
    assert restarted.ledger.audit_hmac_key_id == first.ledger.audit_hmac_key_id


def test_durable_factory_default_timestamps_survive_a_later_open(
    ledger_lab: _LedgerLab,
) -> None:
    first = _create_test_durable_boundary(
        ledger_lab.project,
        initialize=True,
        epoch_id=ledger_lab.epoch_id,
        initial_revision_sequence=1,
        initial_revision_id="KEYREV-DEFAULT-TIME",
        master_key=b"T" * 32,
    )

    reopened = _create_test_durable_boundary(
        ledger_lab.project,
        epoch_id=ledger_lab.epoch_id,
        initial_revision_sequence=1,
        initial_revision_id="KEYREV-DEFAULT-TIME",
        master_key=b"T" * 32,
    )

    assert first.ledger.head.segment_count == 1
    assert reopened.ledger.head.last_segment_sha256 == first.ledger.head.last_segment_sha256


def test_invalid_initialize_mode_is_rejected_before_key_or_genesis_write(
    ledger_lab: _LedgerLab,
) -> None:
    with pytest.raises(LedgerError) as captured:
        _create_test_durable_boundary(
            ledger_lab.project,
            initialize="yes",  # type: ignore[arg-type]
            epoch_id=ledger_lab.epoch_id,
            initial_revision_sequence=1,
            initial_revision_id="KEYREV-INVALID-MODE",
            master_key=b"I" * 32,
        )

    assert captured.value.code is LedgerCode.INVALID_REQUEST
    assert _key_files(ledger_lab) == []
    assert _segment_files(ledger_lab) == []


@pytest.mark.parametrize(
    "existing_state",
    ("healthy", "key-only", "key-and-pending"),
)
def test_fixed_durable_factory_rejects_reset_with_zero_byte_change(
    ledger_lab: _LedgerLab,
    existing_state: str,
) -> None:
    if existing_state == "healthy":
        _create_test_durable_boundary(
            ledger_lab.project,
            initialize=True,
            epoch_id=ledger_lab.epoch_id,
            initial_revision_sequence=1,
            initial_revision_id="KEYREV-ONE",
            master_key=b"K" * 32,
            key_created_at_utc="2026-07-11T00:00:01Z",
            ledger_initialized_at_utc="2026-07-11T00:00:10Z",
        )
    else:
        _create_revision(ledger_lab)
        if existing_state == "key-and-pending":
            pending = (
                ledger_lab.project
                / "logs"
                / "audit"
                / "segments"
                / ledger_lab.epoch_id
                / "PENDING-00000000000000000000-RESET-PROBE.json"
            )
            pending.write_bytes(b"synthetic interrupted initialization")
    before = _ledger_entry_snapshot(ledger_lab)

    with pytest.raises(LedgerError) as captured:
        _create_test_durable_boundary(
            ledger_lab.project,
            initialize=True,
            epoch_id=ledger_lab.epoch_id,
            initial_revision_sequence=1,
            initial_revision_id="KEYREV-ONE",
            master_key=b"K" * 32,
            key_created_at_utc="2026-07-11T00:00:01Z",
            ledger_initialized_at_utc="2026-07-11T00:00:10Z",
        )

    assert captured.value.code is LedgerCode.INVALID_REQUEST
    assert _ledger_entry_snapshot(ledger_lab) == before


def test_durable_boundary_builds_post_rotation_events_with_the_active_key(
    ledger_lab: _LedgerLab,
) -> None:
    base = ledger_lab.project / "Base"
    base.mkdir()
    reference = base / "rotated-reference.txt"
    reference.write_text("rotated synthetic reference", encoding="utf-8")
    bundle = _create_test_durable_boundary(
        ledger_lab.project,
        initialize=True,
        epoch_id=ledger_lab.epoch_id,
        initial_revision_sequence=1,
        initial_revision_id="KEYREV-DURABLE",
        master_key=b"D" * 32,
        key_created_at_utc="2026-07-11T07:10:00Z",
        ledger_initialized_at_utc="2026-07-11T07:10:01Z",
    )
    second = bundle.key_store.create_revision(
        revision_sequence=2,
        revision_id="KEYREV-DURABLE-TWO",
        master_key=b"E" * 32,
        created_at_utc="2026-07-11T07:10:02Z",
    )
    bundle.ledger.rotate_key(
        next_revision_id=second.revision_id,
        rotation_id="ROTATION-DURABLE-0001",
        created_at_utc="2026-07-11T07:10:03Z",
    )
    context = bundle.boundary.issue_context(
        run_id=ledger_lab.epoch_id,
        job_id="JOB-DURABLE-ROTATED",
        operation_id="OP-DURABLE-ROTATED",
        caller=Caller.IMPORT_SERVICE,
        purpose=Purpose.READ_REFERENCE,
    )

    ticket = bundle.boundary.authorize(
        Path("Base") / reference.name,
        intent=PathIntent.EXISTING_READ,
        expected_kind=ExpectedKind.FILE,
        context=context,
    )

    assert ticket is not None
    assert bundle.ledger.head.active_revision_id == second.revision_id
    assert bundle.ledger.head.last_sequence == 2
    decoded = parse_canonical_json_bytes(
        _segment_files(ledger_lab)[-1].read_bytes(),
        maximum_bytes=2 * 1024 * 1024,
    )
    assert decoded["body"]["records"][0]["hmac_key_id"] == second.audit_hmac_key_id


def test_restricted_denial_without_a_path_uses_a_sentinel_hmac(
    ledger_lab: _LedgerLab,
) -> None:
    bundle = _create_test_durable_boundary(
        ledger_lab.project,
        initialize=True,
        epoch_id=ledger_lab.epoch_id,
        initial_revision_sequence=1,
        initial_revision_id="KEYREV-DENIAL",
        master_key=b"F" * 32,
        key_created_at_utc="2026-07-11T07:20:00Z",
        ledger_initialized_at_utc="2026-07-11T07:20:01Z",
    )
    context = bundle.boundary.issue_context(
        run_id=ledger_lab.epoch_id,
        job_id="JOB-DURABLE-DENIAL",
        operation_id="OP-DURABLE-DENIAL",
        caller=Caller.IMPORT_SERVICE,
        purpose=Purpose.READ_REFERENCE,
        classification=DataClassification.RESTRICTED,
    )

    with pytest.raises(ProductionBoundaryError):
        bundle.boundary.authorize(
            Path("..") / "forbidden.txt",
            intent=PathIntent.EXISTING_READ,
            expected_kind=ExpectedKind.FILE,
            context=context,
        )

    assert bundle.ledger.head.last_sequence == 1
    decoded = parse_canonical_json_bytes(
        _segment_files(ledger_lab)[-1].read_bytes(),
        maximum_bytes=2 * 1024 * 1024,
    )
    record = decoded["body"]["records"][0]
    assert record["decision"] == "DENY"
    assert record["classification"] == "RESTRICTED"
    assert record["safe_relative_path"] is None
    assert len(record["path_hmac_sha256"]) == 64


def test_canonical_parser_rejects_duplicate_keys_float_crlf_and_noncanonical_order() -> None:
    bad_payloads = (
        b'{"a":1,"a":2}\n',
        b'{"a":1.0}\n',
        b'{"a":1}\r\n',
        b'{"b":1,"a":2}\n',
        b'\xef\xbb\xbf{"a":1}\n',
    )

    for payload in bad_payloads:
        with pytest.raises(LedgerError) as captured:
            parse_canonical_json_bytes(payload, maximum_bytes=1024)
        assert captured.value.code is LedgerCode.CHAIN_CORRUPT


@pytest.mark.parametrize(
    "payload",
    [
        b'{"a":' + b"[" * 2000 + b"0" + b"]" * 2000 + b"}\n",
        b'{"a":' + b"9" * 5000 + b"}\n",
    ],
)
def test_canonical_parser_maps_depth_and_integer_limits_to_ledger_errors(
    payload: bytes,
) -> None:
    with pytest.raises(LedgerError) as captured:
        parse_canonical_json_bytes(payload, maximum_bytes=16 * 1024)
    assert captured.value.code is LedgerCode.CHAIN_CORRUPT
    assert captured.value.__cause__ is None


def test_build_segment_rejects_event_signed_by_different_revision(
    ledger_lab: _LedgerLab,
) -> None:
    first = _create_revision(ledger_lab)
    second_payload, second = build_key_revision_bytes(
        revision_sequence=2,
        revision_id="KEYREV-TWO",
        created_at_utc="2026-07-11T00:00:02Z",
        master_key=b"L" * 32,
    )
    assert second_payload

    with pytest.raises(LedgerError) as captured:
        build_audit_segment_bytes(
            epoch_id=ledger_lab.epoch_id,
            sequence=1,
            previous_segment_sha256="0" * 64,
            created_at_utc="2026-07-11T08:00:00Z",
            revision=second,
            events=(_event(first, index=11),),
        )

    assert captured.value.code is LedgerCode.REDACTION_FAILURE
