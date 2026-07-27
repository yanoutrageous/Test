from __future__ import annotations

import ctypes
import hashlib
import json
import os
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
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
    _logical_manifest_bytes,
)
from app.safety.production_guard import (
    BoundaryErrorCode,
    ProductionBoundaryError,
    _create_test_durable_boundary,
    _create_test_job_runtime,
)
from app.safety.windows_handle_writer import (
    HandleWriterCode,
    HandleWriterError,
    TreeEntryKind,
    _IoStatusBlock,
    _ObjectAttributes,
    _UnicodeString,
    _WindowsApi,
)


@dataclass(frozen=True)
class _JobLab:
    project: Path
    protected: Path
    sentinel: Path
    bundle: object
    runtime: object


@pytest.fixture
def job_lab(tmp_path: Path) -> Iterator[_JobLab]:
    project = tmp_path / "project"
    protected = tmp_path / "protected"
    project.mkdir()
    protected.mkdir()
    sentinel = protected / "sentinel.bin"
    sentinel.write_bytes(b"job-operation-protected-sentinel")
    (project / "logs" / "audit" / "keys").mkdir(parents=True)
    (project / "logs" / "audit" / "segments" / "RUN-S3D-LEDGER").mkdir(
        parents=True
    )
    (project / "tmp" / "jobs" / "INTERNAL").mkdir(parents=True)
    (project / "tmp" / "jobs" / "RESTRICTED").mkdir(parents=True)
    bundle = _create_test_durable_boundary(
        project,
        initialize=True,
        epoch_id="RUN-S3D-LEDGER",
        initial_revision_sequence=1,
        initial_revision_id="KEYREV-S3D-ONE",
        master_key=b"J" * 32,
        key_created_at_utc="2026-07-11T01:00:00Z",
        ledger_initialized_at_utc="2026-07-11T01:00:01Z",
    )
    yield _JobLab(
        project=project,
        protected=protected,
        sentinel=sentinel,
        bundle=bundle,
        runtime=_create_test_job_runtime(bundle),
    )
    assert sentinel.read_bytes() == b"job-operation-protected-sentinel"
    assert {path.name for path in protected.iterdir()} == {"sentinel.bin"}


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _entries(*entries: DeclaredTreeEntry) -> tuple[DeclaredTreeEntry, ...]:
    return tuple(sorted(entries, key=lambda entry: entry.relative_path.encode("utf-8")))


def _manifest(
    manifest_id: str = "MANIFEST-S3D",
    *,
    classification: DataClassification = DataClassification.INTERNAL,
    payload: bytes = b"alpha",
) -> DeclaredTreeManifest:
    return DeclaredTreeManifest(
        manifest_id=manifest_id,
        classification=classification,
        entries=_entries(
            DeclaredTreeEntry("empty", TreeEntryKind.DIRECTORY, 0, None),
            DeclaredTreeEntry("中文", TreeEntryKind.DIRECTORY, 0, None),
            DeclaredTreeEntry("中文/data.txt", TreeEntryKind.FILE, len(payload), _sha(payload)),
            DeclaredTreeEntry("zero.bin", TreeEntryKind.FILE, 0, _sha(b"")),
        ),
    )


def _context(
    lab: _JobLab,
    *,
    run_id: str = "RUN-S3D-JOB",
    job_id: str = "JOB-S3D-ONE",
    operation_id: str = "OP-S3D-ONE",
    manifest_id: str = "MANIFEST-S3D",
    checkpoint_id: str = "CHECKPOINT-S3D",
    classification: DataClassification = DataClassification.INTERNAL,
    caller: Caller = Caller.TEST_LAB,
    purpose: Purpose = Purpose.TEST,
):
    return lab.bundle.boundary.issue_context(
        run_id=run_id,
        job_id=job_id,
        operation_id=operation_id,
        caller=caller,
        purpose=purpose,
        manifest_id=manifest_id,
        classification=classification,
        scopes=(
            ScopeId(ScopeKind.RUN_ID, run_id),
            ScopeId(ScopeKind.JOB_ID, job_id),
            ScopeId(ScopeKind.OPERATION_ID, operation_id),
            ScopeId(ScopeKind.MANIFEST_ID, manifest_id),
            ScopeId(ScopeKind.CHECKPOINT_ID, checkpoint_id),
        ),
    )


def _build_normal_tree(staging: object, payload: bytes = b"alpha") -> None:
    staging.create_declared_directory("empty")
    staging.create_declared_file("zero.bin", b"")
    staging.create_declared_directory("中文")
    staging.create_declared_file("中文/data.txt", payload)


def _manifest_metrics(manifest: DeclaredTreeManifest) -> dict[str, int]:
    files = tuple(entry for entry in manifest.entries if entry.kind is TreeEntryKind.FILE)
    directories = tuple(
        entry for entry in manifest.entries if entry.kind is TreeEntryKind.DIRECTORY
    )
    return {
        "maximum_entries": len(manifest.entries),
        "maximum_files": len(files),
        "maximum_directories": len(directories),
        "maximum_depth": max(entry.relative_path.count("/") + 1 for entry in manifest.entries),
        "maximum_file_bytes": max((entry.size_bytes for entry in files), default=0),
        "maximum_total_bytes": sum(entry.size_bytes for entry in files),
        "maximum_path_utf8_bytes": max(
            len(entry.relative_path.encode("utf-8")) for entry in manifest.entries
        ),
        "maximum_manifest_bytes": len(_logical_manifest_bytes(manifest.entries)),
    }


def _boundary_budget(
    exact: DeclaredTreeManifest,
    overflow: DeclaredTreeManifest,
    target: str,
) -> JobResourceBudget:
    exact_metrics = _manifest_metrics(exact)
    overflow_metrics = _manifest_metrics(overflow)
    limits = {
        key: max(1, exact_metrics[key], overflow_metrics[key])
        for key in exact_metrics
    }
    limits[target] = max(1, exact_metrics[target])
    limits["maximum_total_bytes"] = max(
        limits["maximum_total_bytes"], limits["maximum_file_bytes"]
    )
    limits["maximum_open_handles"] = max(
        exact_metrics["maximum_entries"], overflow_metrics["maximum_entries"]
    ) + 1
    return JobResourceBudget(
        **limits,
        maximum_elapsed_seconds=60,
        minimum_free_bytes=0,
    )


def test_nt_structures_match_64_bit_windows_abi() -> None:
    assert ctypes.sizeof(ctypes.c_void_p) == 8
    assert ctypes.sizeof(_UnicodeString) == 16
    assert _UnicodeString.buffer.offset == 8
    assert ctypes.sizeof(_ObjectAttributes) == 48
    assert _ObjectAttributes.root_directory.offset == 8
    assert _ObjectAttributes.object_name.offset == 16
    assert ctypes.sizeof(_IoStatusBlock) == 16
    assert _IoStatusBlock.information.offset == 8


@pytest.mark.parametrize(
    "name",
    ["", ".", "..", "a/b", "a\\b", "x:y", "NUL.txt", "bad.", "bad ", "e\u0301"],
)
def test_relative_nt_component_rejects_noncanonical_names(name: str) -> None:
    with pytest.raises(HandleWriterError) as captured:
        _WindowsApi._validated_relative_component(name)
    assert captured.value.code is HandleWriterCode.INVALID_REQUEST


def test_relative_nt_component_accepts_canonical_chinese() -> None:
    assert _WindowsApi._validated_relative_component("函数与几何") == "函数与几何"


def test_relative_parent_create_returns_live_directory_handle(job_lab: _JobLab) -> None:
    writer = job_lab.bundle.writer
    ticket = writer.authorize_create_directory(Path("tmp") / "jobs" / "INTERNAL" / "JOB-NT-ONE")
    lease = writer.create_directory_lease(ticket)
    try:
        target = job_lab.project / "tmp" / "jobs" / "INTERNAL" / "JOB-NT-ONE"
        assert target.is_dir()
        assert list(target.iterdir()) == []
        with pytest.raises(OSError):
            os.rename(target, target.with_name("JOB-NT-MOVED"))
        lease._assert_live_owner(writer)
    finally:
        lease.close()


def test_relative_parent_create_never_adopts_existing_directory(job_lab: _JobLab) -> None:
    writer = job_lab.bundle.writer
    existing = job_lab.project / "tmp" / "jobs" / "INTERNAL" / "JOB-CONFLICT"
    existing.mkdir()
    with pytest.raises(HandleWriterError) as captured:
        writer.authorize_create_directory(
            Path("tmp") / "jobs" / "INTERNAL" / "JOB-CONFLICT"
        )
    assert captured.value.code is HandleWriterCode.GUARD_REJECTED
    assert list(existing.iterdir()) == []


def test_relative_directory_create_race_never_adopts_competing_final(
    job_lab: _JobLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    writer = job_lab.bundle.writer
    target = job_lab.project / "tmp" / "jobs" / "INTERNAL" / "JOB-RACE-FINAL"
    sentinel = target / "competitor.bin"
    ticket = writer.authorize_create_directory(
        Path("tmp") / "jobs" / "INTERNAL" / "JOB-RACE-FINAL"
    )

    original_create = writer._api.create_relative_directory

    def insert_competitor(parent_handle: int, name: str) -> int:
        target.mkdir()
        sentinel.write_bytes(b"competitor-owned")
        return original_create(parent_handle, name)

    monkeypatch.setattr(writer._api, "create_relative_directory", insert_competitor)
    with pytest.raises(HandleWriterError) as captured:
        writer.create_directory_lease(ticket)
    assert captured.value.code is HandleWriterCode.TARGET_CONFLICT
    assert sentinel.read_bytes() == b"competitor-owned"
    assert writer._poisoned == HandleWriterCode.MUTATION_IN_DOUBT.value


def test_directory_native_success_in_doubt_seals_even_if_final_moved(
    job_lab: _JobLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    writer = job_lab.bundle.writer
    target = job_lab.project / "tmp/jobs/INTERNAL/JOB-POST-SUCCESS"
    moved = target.with_name("JOB-POST-SUCCESS-RESIDUE")
    original_create = writer._api.create_relative_directory

    def create_move_and_lose_receipt(parent_handle: int, name: str) -> int:
        handle = original_create(parent_handle, name)
        writer._api.close(handle)
        os.rename(target, moved)
        raise HandleWriterError(
            HandleWriterCode.MUTATION_IN_DOUBT,
            "injected directory native success without a valid receipt",
        )

    monkeypatch.setattr(
        writer._api,
        "create_relative_directory",
        create_move_and_lose_receipt,
    )
    ticket = writer.authorize_create_directory(
        Path("tmp/jobs/INTERNAL/JOB-POST-SUCCESS")
    )
    with pytest.raises(HandleWriterError) as captured:
        writer.create_directory_lease(ticket)
    assert captured.value.code is HandleWriterCode.MUTATION_IN_DOUBT
    assert not target.exists()
    assert moved.is_dir()
    assert writer._poisoned == HandleWriterCode.MUTATION_IN_DOUBT.value


def test_full_job_staging_and_live_tree_evidence(job_lab: _JobLab) -> None:
    manifest = _manifest()
    context = _context(job_lab)
    budget = JobResourceBudget.conservative_test_default()
    with job_lab.runtime.begin_operation(context, manifest, budget) as operation:
        staging = operation.create_fixed_staging()
        _build_normal_tree(staging)
        observed = staging.seal_and_observe()
        evidence = observed.evidence
        assert evidence.manifest_sha256 == manifest.manifest_sha256
        assert evidence.entry_count == 4
        assert evidence.file_count == 2
        assert evidence.directory_count == 2
        assert evidence.total_bytes == len(b"alpha")
        assert evidence.maximum_depth_observed == 2
        assert evidence.capability_state == "TEST_LOCAL_REVALIDATED_OBSERVATION"
        assert observed.revalidate() == evidence
        surface = repr(observed) + repr(operation) + repr(evidence)
        assert str(job_lab.project) not in surface
        assert context.job_id not in surface
    contract = (
        job_lab.project
        / "tmp"
        / "jobs"
        / "INTERNAL"
        / context.job_id
        / "job-contract.json"
    )
    decoded = json.loads(contract.read_text(encoding="ascii"))
    assert decoded["declared_manifest_sha256"] == manifest.manifest_sha256
    assert decoded["budget_sha256"] == budget.digest
    assert decoded["ledger"]["sequence"] == 0


def test_live_job_contract_rejects_same_length_overwrite(job_lab: _JobLab) -> None:
    manifest = _manifest()
    context = _context(job_lab)
    with job_lab.runtime.begin_operation(
        context,
        manifest,
        JobResourceBudget.conservative_test_default(),
    ) as operation:
        expected = operation._job_contract_bytes()
        staging = operation.create_fixed_staging()
        contract = (
            job_lab.project
            / "tmp"
            / "jobs"
            / "INTERNAL"
            / context.job_id
            / "job-contract.json"
        )
        before_identity = os.lstat(contract)
        replacement = bytes(byte ^ 1 for byte in expected)
        with pytest.raises(OSError):
            contract.write_bytes(replacement)
        after_identity = os.lstat(contract)
        assert (after_identity.st_dev, after_identity.st_ino) == (
            before_identity.st_dev,
            before_identity.st_ino,
        )
        _build_normal_tree(staging)
        staging.seal_and_observe().revalidate()
    assert contract.read_bytes() == expected


def test_immutable_contract_final_revalidation_failure_closes_every_handle(
    job_lab: _JobLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _manifest()
    context = _context(job_lab)
    operation = job_lab.runtime.begin_operation(
        context,
        manifest,
        JobResourceBudget.conservative_test_default(),
    )

    def fail_final_revalidation(_lease: object) -> None:
        raise HandleWriterError(
            HandleWriterCode.POSTCONDITION_FAILED,
            "injected immutable contract final revalidation failure",
        )

    monkeypatch.setattr(
        job_lab.bundle.writer,
        "_revalidate_immutable_file_lease",
        fail_final_revalidation,
    )
    with pytest.raises(HandleWriterError) as captured:
        operation.create_fixed_staging()
    assert captured.value.code is HandleWriterCode.POSTCONDITION_FAILED
    assert job_lab.bundle.writer._poisoned == HandleWriterCode.MUTATION_IN_DOUBT.value
    job_root = job_lab.project / "tmp/jobs/INTERNAL/JOB-S3D-ONE"
    contract = job_root / "job-contract.json"
    api = job_lab.bundle.writer._api
    contract_handle = api.open_handle(
        contract,
        access=api.GENERIC_READ,
        share=api.FILE_SHARE_READ | api.FILE_SHARE_WRITE | api.FILE_SHARE_DELETE,
        disposition=api.OPEN_EXISTING,
        flags=api.FILE_FLAG_OPEN_REPARSE_POINT,
    )
    api.close(contract_handle)
    root_handle = api.open_handle(
        job_root,
        access=api.FILE_ADD_FILE | api.FILE_ADD_SUBDIRECTORY | api.FILE_READ_ATTRIBUTES,
        share=api.FILE_SHARE_READ | api.FILE_SHARE_WRITE | api.FILE_SHARE_DELETE,
        disposition=api.OPEN_EXISTING,
        flags=api.FILE_FLAG_OPEN_REPARSE_POINT | api.FILE_FLAG_BACKUP_SEMANTICS,
    )
    api.close(root_handle)
    with pytest.raises(HandleWriterError) as close_failure:
        operation.close()
    assert close_failure.value.code is HandleWriterCode.WRITER_SEALED
    counts = job_lab.bundle.boundary.diagnostic_registry_counts
    assert counts["context_live"] == 0
    assert counts["job_context_pins"] == 0


def test_native_success_without_valid_create_receipt_seals_writer(
    job_lab: _JobLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    operation = job_lab.runtime.begin_operation(
        _context(job_lab),
        _manifest(),
        JobResourceBudget.conservative_test_default(),
    )
    api = job_lab.bundle.writer._api
    original_create = api.create_relative_file

    def create_then_lose_receipt(parent_handle: int, name: str) -> int:
        handle = original_create(parent_handle, name)
        api.close(handle)
        raise HandleWriterError(
            HandleWriterCode.MUTATION_IN_DOUBT,
            "injected native success without a valid create receipt",
        )

    monkeypatch.setattr(api, "create_relative_file", create_then_lose_receipt)
    with pytest.raises(HandleWriterError) as captured:
        operation.create_fixed_staging()
    assert captured.value.code is HandleWriterCode.MUTATION_IN_DOUBT
    assert job_lab.bundle.writer._poisoned == HandleWriterCode.MUTATION_IN_DOUBT.value
    assert (
        job_lab.project / "tmp/jobs/INTERNAL/JOB-S3D-ONE/job-contract.json"
    ).is_file()
    with pytest.raises(HandleWriterError) as close_failure:
        operation.close()
    assert close_failure.value.code is HandleWriterCode.WRITER_SEALED
    counts = job_lab.bundle.boundary.diagnostic_registry_counts
    assert counts["context_live"] == 0
    assert counts["job_context_pins"] == 0


def test_live_operation_context_is_pinned_until_atomic_close(job_lab: _JobLab) -> None:
    manifest = _manifest()
    context = _context(job_lab)
    operation = job_lab.runtime.begin_operation(
        context,
        manifest,
        JobResourceBudget.conservative_test_default(),
    )
    with pytest.raises(ProductionBoundaryError) as captured:
        job_lab.bundle.boundary.release_context(context)
    assert captured.value.code is BoundaryErrorCode.INVALID_CONTEXT
    staging = operation.create_fixed_staging()
    _build_normal_tree(staging)
    staging.seal_and_observe().revalidate()
    operation.close()
    assert job_lab.bundle.boundary.release_context(context) is False
    with pytest.raises(JobOperationError) as replayed:
        job_lab.runtime.begin_operation(
            context,
            manifest,
            JobResourceBudget.conservative_test_default(),
        )
    assert replayed.value.code is JobOperationCode.INVALID_CONTEXT


def test_restricted_import_job_contract_and_surfaces_are_redacted(job_lab: _JobLab) -> None:
    identifiers = {
        "run": "RUN-RESTRICTED-S3D",
        "job": "JOB-RESTRICTED-S3D",
        "operation": "OP-RESTRICTED-S3D",
        "manifest": "MANIFEST-RESTRICTED-S3D",
        "checkpoint": "CHECKPOINT-RESTRICTED-S3D",
    }
    payload = b"restricted-payload-marker"
    manifest = _manifest(
        identifiers["manifest"],
        classification=DataClassification.RESTRICTED,
        payload=payload,
    )
    context = _context(
        job_lab,
        run_id=identifiers["run"],
        job_id=identifiers["job"],
        operation_id=identifiers["operation"],
        manifest_id=identifiers["manifest"],
        checkpoint_id=identifiers["checkpoint"],
        classification=DataClassification.RESTRICTED,
        caller=Caller.IMPORT_SERVICE,
        purpose=Purpose.COPY_SOURCE,
    )
    with job_lab.runtime.begin_operation(
        context,
        manifest,
        JobResourceBudget.conservative_test_default(),
    ) as operation:
        staging = operation.create_fixed_staging()
        with pytest.raises(JobOperationError) as failure:
            staging.create_declared_file("not-declared.bin", payload)
        _build_normal_tree(staging, payload)
        observed = staging.seal_and_observe()
        surface = "\n".join(
            (repr(operation), repr(staging), repr(observed), repr(observed.evidence), str(failure.value))
        )
        for secret in (*identifiers.values(), str(job_lab.project), payload.decode("ascii")):
            assert secret not in surface
        observed.revalidate()
    restricted_root = (
        job_lab.project / "tmp" / "jobs" / "RESTRICTED" / identifiers["job"]
    )
    assert restricted_root.is_dir()
    assert not (job_lab.project / "tmp" / "jobs" / "INTERNAL" / identifiers["job"]).exists()
    contract_bytes = (restricted_root / "job-contract.json").read_bytes()
    decoded = json.loads(contract_bytes)
    assert decoded["public_ids"] is None
    for secret in (*identifiers.values(), str(job_lab.project), payload.decode("ascii")):
        assert secret.encode("utf-8") not in contract_bytes


def test_same_job_root_is_never_reused(job_lab: _JobLab) -> None:
    first_manifest = _manifest("MANIFEST-FIRST")
    with job_lab.runtime.begin_operation(
        _context(job_lab, operation_id="OP-FIRST", manifest_id="MANIFEST-FIRST"),
        first_manifest,
        JobResourceBudget.conservative_test_default(),
    ) as operation:
        operation.create_fixed_staging()
    second_context = _context(
        job_lab,
        operation_id="OP-SECOND",
        manifest_id="MANIFEST-SECOND",
    )
    second_manifest = _manifest("MANIFEST-SECOND")
    with job_lab.runtime.begin_operation(
        second_context,
        second_manifest,
        JobResourceBudget.conservative_test_default(),
    ) as operation:
        with pytest.raises(HandleWriterError) as captured:
            operation.create_fixed_staging()
        assert captured.value.code is HandleWriterCode.GUARD_REJECTED


def test_payload_mismatch_is_rejected_before_file_creation(job_lab: _JobLab) -> None:
    manifest = _manifest()
    with job_lab.runtime.begin_operation(
        _context(job_lab), manifest, JobResourceBudget.conservative_test_default()
    ) as operation:
        staging = operation.create_fixed_staging()
        staging.create_declared_directory("中文")
        with pytest.raises(JobOperationError) as captured:
            staging.create_declared_file("中文/data.txt", b"wrong")
        assert captured.value.code is JobOperationCode.TREE_MISMATCH
        target = (
            job_lab.project
            / "tmp/jobs/INTERNAL/JOB-S3D-ONE/publish/MANIFEST-S3D/中文/data.txt"
        )
        assert not target.exists()


def test_missing_declared_entry_cannot_form_evidence(job_lab: _JobLab) -> None:
    manifest = _manifest()
    with job_lab.runtime.begin_operation(
        _context(job_lab), manifest, JobResourceBudget.conservative_test_default()
    ) as operation:
        staging = operation.create_fixed_staging()
        staging.create_declared_directory("empty")
        with pytest.raises(JobOperationError) as captured:
            staging.seal_and_observe()
        assert captured.value.code is JobOperationCode.TREE_MISMATCH


def test_extra_output_is_observed_and_rejected(job_lab: _JobLab) -> None:
    manifest = _manifest()
    with job_lab.runtime.begin_operation(
        _context(job_lab), manifest, JobResourceBudget.conservative_test_default()
    ) as operation:
        staging = operation.create_fixed_staging()
        _build_normal_tree(staging)
        extra = (
            job_lab.project
            / "tmp/jobs/INTERNAL/JOB-S3D-ONE/publish/MANIFEST-S3D/extra.bin"
        )
        extra.write_bytes(b"extra")
        with pytest.raises(JobOperationError) as captured:
            staging.seal_and_observe()
        assert captured.value.code is JobOperationCode.TREE_MISMATCH


def test_live_root_directory_handle_blocks_hardlink_alias_creation(job_lab: _JobLab) -> None:
    manifest = _manifest()
    with job_lab.runtime.begin_operation(
        _context(job_lab), manifest, JobResourceBudget.conservative_test_default()
    ) as operation:
        staging = operation.create_fixed_staging()
        _build_normal_tree(staging)
        root = job_lab.project / "tmp/jobs/INTERNAL/JOB-S3D-ONE/publish/MANIFEST-S3D"
        source = root / "zero.bin"
        alias = root / "zero-alias.bin"
        with pytest.raises(OSError):
            os.link(source, alias)
        assert not alias.exists()
        assert staging.seal_and_observe().evidence.manifest_sha256 == manifest.manifest_sha256


def test_ads_tree_is_rejected_without_reading_the_stream(job_lab: _JobLab) -> None:
    manifest = _manifest()
    with job_lab.runtime.begin_operation(
        _context(job_lab), manifest, JobResourceBudget.conservative_test_default()
    ) as operation:
        staging = operation.create_fixed_staging()
        _build_normal_tree(staging)
        root = job_lab.project / "tmp/jobs/INTERNAL/JOB-S3D-ONE/publish/MANIFEST-S3D"
        target = root / "zero.bin"
        stream = f"{target}:forbidden"
        with open(stream, "wb") as handle:
            handle.write(b"secret-stream")
        try:
            with pytest.raises(HandleWriterError) as captured:
                staging.seal_and_observe()
            assert captured.value.code is HandleWriterCode.HANDLE_IDENTITY_MISMATCH
            assert ":forbidden" not in str(captured.value)
            assert str(target) not in str(captured.value)
        finally:
            os.remove(stream)
            (root.parent / "ads-cleanup.json").write_text(
                json.dumps(
                    {"action": "remove-exact-synthetic-ads", "base": target.name},
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
                newline="\n",
            )


def test_directory_ads_on_tree_root_is_rejected(job_lab: _JobLab) -> None:
    manifest = _manifest()
    root = job_lab.project / "tmp/jobs/INTERNAL/JOB-S3D-ONE/publish/MANIFEST-S3D"
    stream = f"{root}:directory-hidden"
    operation = job_lab.runtime.begin_operation(
        _context(job_lab), manifest, JobResourceBudget.conservative_test_default()
    )
    try:
        staging = operation.create_fixed_staging()
        _build_normal_tree(staging)
        writer = job_lab.bundle.writer
        stream_handle = writer._api.open_handle(
            Path(stream),
            access=writer._api.GENERIC_WRITE,
            share=(
                writer._api.FILE_SHARE_READ
                | writer._api.FILE_SHARE_WRITE
                | writer._api.FILE_SHARE_DELETE
            ),
            disposition=writer._api.CREATE_NEW,
            flags=(
                writer._api.FILE_FLAG_OPEN_REPARSE_POINT
                | writer._api.FILE_FLAG_BACKUP_SEMANTICS
            ),
        )
        try:
            writer._write_all(stream_handle, b"directory-ads")
            writer._flush(stream_handle)
        finally:
            writer._api.close(stream_handle)
        with pytest.raises(HandleWriterError) as captured:
            staging.seal_and_observe()
        assert captured.value.code is HandleWriterCode.HANDLE_IDENTITY_MISMATCH
        with pytest.raises(HandleWriterError) as close_failure:
            operation.close()
        assert close_failure.value.code is HandleWriterCode.WRITER_SEALED
    finally:
        if root.exists():
            (root.parent / "directory-ads-cleanup.json").write_text(
                json.dumps(
                    {"action": "remove-exact-synthetic-directory-ads"},
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
                newline="\n",
            )
            try:
                os.remove(stream)
            except FileNotFoundError:
                pass


def test_case_collision_is_rejected_before_child_open(
    job_lab: _JobLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = DeclaredTreeManifest(
        "MANIFEST-S3D",
        DataClassification.INTERNAL,
        _entries(DeclaredTreeEntry("A.txt", TreeEntryKind.FILE, 1, _sha(b"a"))),
    )
    with job_lab.runtime.begin_operation(
        _context(job_lab), manifest, JobResourceBudget.conservative_test_default()
    ) as operation:
        staging = operation.create_fixed_staging()
        staging.create_declared_file("A.txt", b"a")
        original = job_lab.bundle.writer._api.enumerate_directory_handle

        def colliding(handle: int, *, maximum_entries: int):
            rows = original(handle, maximum_entries=maximum_entries)
            if rows and rows[0][0] == "A.txt":
                return rows + (("a.TXT", rows[0][1], rows[0][2]),)
            return rows

        monkeypatch.setattr(job_lab.bundle.writer._api, "enumerate_directory_handle", colliding)
        with pytest.raises(HandleWriterError) as captured:
            staging.seal_and_observe()
        assert captured.value.code is HandleWriterCode.DIRECTORY_SCAN_FAILED


def test_live_tree_handles_block_same_size_rewrite(job_lab: _JobLab) -> None:
    manifest = _manifest()
    with job_lab.runtime.begin_operation(
        _context(job_lab), manifest, JobResourceBudget.conservative_test_default()
    ) as operation:
        staging = operation.create_fixed_staging()
        _build_normal_tree(staging)
        observed = staging.seal_and_observe()
        target = (
            job_lab.project
            / "tmp/jobs/INTERNAL/JOB-S3D-ONE/publish/MANIFEST-S3D/中文/data.txt"
        )
        with pytest.raises(OSError):
            target.write_bytes(b"bravo")
        assert target.read_bytes() == b"alpha"
        observed.revalidate()


def test_external_root_addition_invalidates_live_tree_evidence(job_lab: _JobLab) -> None:
    manifest = _manifest()
    with job_lab.runtime.begin_operation(
        _context(job_lab), manifest, JobResourceBudget.conservative_test_default()
    ) as operation:
        staging = operation.create_fixed_staging()
        _build_normal_tree(staging)
        observed = staging.seal_and_observe()
        extra = (
            job_lab.project
            / "tmp/jobs/INTERNAL/JOB-S3D-ONE/publish/MANIFEST-S3D/external-extra.bin"
        )
        extra.write_bytes(b"external-drift")
        with pytest.raises(HandleWriterError) as captured:
            observed.revalidate()
        assert captured.value.code is HandleWriterCode.DIRECTORY_CHANGED
        with pytest.raises(JobOperationError) as permanently_invalid:
            _ = observed.evidence
        assert permanently_invalid.value.code is JobOperationCode.INVALID_LEASE


def test_addition_after_first_revalidation_enumeration_is_caught_by_post_pass(
    job_lab: _JobLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _manifest()
    with job_lab.runtime.begin_operation(
        _context(job_lab), manifest, JobResourceBudget.conservative_test_default()
    ) as operation:
        staging = operation.create_fixed_staging()
        _build_normal_tree(staging)
        observed = staging.seal_and_observe()
        root = job_lab.project / "tmp/jobs/INTERNAL/JOB-S3D-ONE/publish/MANIFEST-S3D"
        extra = root / "post-enumeration-extra.bin"
        original = job_lab.bundle.writer._api.enumerate_directory_handle
        injected = False

        def enumerate_then_race(handle: int, *, maximum_entries: int):
            nonlocal injected
            rows = original(handle, maximum_entries=maximum_entries)
            if not injected:
                injected = True
                extra.write_bytes(b"raced-after-pre-enumeration")
            return rows

        monkeypatch.setattr(
            job_lab.bundle.writer._api,
            "enumerate_directory_handle",
            enumerate_then_race,
        )
        with pytest.raises(HandleWriterError) as captured:
            observed.revalidate()
        assert captured.value.code is HandleWriterCode.DIRECTORY_CHANGED
        assert injected


def test_observation_seal_revokes_all_trusted_relative_writes(job_lab: _JobLab) -> None:
    manifest = _manifest()
    with job_lab.runtime.begin_operation(
        _context(job_lab), manifest, JobResourceBudget.conservative_test_default()
    ) as operation:
        staging = operation.create_fixed_staging()
        _build_normal_tree(staging)
        observed = staging.seal_and_observe()
        root_lease = staging._fixed_leases[-1]
        writer = job_lab.bundle.writer
        file_ticket = writer.authorize_create_file(
            Path("tmp/jobs/INTERNAL/JOB-S3D-ONE/publish/MANIFEST-S3D/trusted-extra.bin")
        )
        with pytest.raises(HandleWriterError) as file_failure:
            writer.create_file_in_directory(
                root_lease,
                file_ticket,
                b"x",
                expected_sha256=_sha(b"x"),
            )
        assert file_failure.value.code is HandleWriterCode.INVALID_TICKET
        directory_ticket = writer.authorize_create_directory(
            Path("tmp/jobs/INTERNAL/JOB-S3D-ONE/publish/MANIFEST-S3D/trusted-extra")
        )
        with pytest.raises(HandleWriterError) as directory_failure:
            writer.create_directory_lease(
                directory_ticket,
                parent_lease=root_lease,
            )
        assert directory_failure.value.code is HandleWriterCode.INVALID_TICKET
        observed.revalidate()


def test_writer_seal_permanently_revokes_live_tree_evidence(job_lab: _JobLab) -> None:
    manifest = _manifest()
    operation = job_lab.runtime.begin_operation(
        _context(job_lab), manifest, JobResourceBudget.conservative_test_default()
    )
    staging = operation.create_fixed_staging()
    _build_normal_tree(staging)
    observed = staging.seal_and_observe()
    job_lab.bundle.writer.seal_after_indeterminate_mutation()
    with pytest.raises(HandleWriterError) as sealed:
        _ = observed.evidence
    assert sealed.value.code is HandleWriterCode.WRITER_SEALED
    with pytest.raises(JobOperationError) as invalidated:
        observed.revalidate()
    assert invalidated.value.code is JobOperationCode.INVALID_LEASE
    with pytest.raises(HandleWriterError) as close_failure:
        operation.close()
    assert close_failure.value.code is HandleWriterCode.WRITER_SEALED
    counts = job_lab.bundle.boundary.diagnostic_registry_counts
    assert counts["context_live"] == 0
    assert counts["job_context_pins"] == 0


def test_closed_observed_lease_cannot_be_replayed(job_lab: _JobLab) -> None:
    manifest = _manifest()
    context = _context(job_lab)
    with job_lab.runtime.begin_operation(
        context, manifest, JobResourceBudget.conservative_test_default()
    ) as operation:
        staging = operation.create_fixed_staging()
        _build_normal_tree(staging)
        observed = staging.seal_and_observe()
        observed.close()
        with pytest.raises(JobOperationError) as captured:
            observed.revalidate()
        assert captured.value.code is JobOperationCode.INVALID_LEASE


def test_cross_thread_observed_lease_is_rejected(job_lab: _JobLab) -> None:
    manifest = _manifest()
    with job_lab.runtime.begin_operation(
        _context(job_lab), manifest, JobResourceBudget.conservative_test_default()
    ) as operation:
        staging = operation.create_fixed_staging()
        _build_normal_tree(staging)
        observed = staging.seal_and_observe()
        errors: list[BaseException] = []

        def use_foreign_lease() -> None:
            try:
                observed.revalidate()
            except BaseException as exc:
                errors.append(exc)

        thread = threading.Thread(target=use_foreign_lease)
        thread.start()
        thread.join(timeout=5)
        assert not thread.is_alive()
        assert len(errors) == 1
        assert isinstance(errors[0], JobOperationError)
        observed.revalidate()


def test_real_child_crash_retains_staging_and_same_job_is_never_adopted(
    job_lab: _JobLab,
) -> None:
    writer = job_lab.bundle.writer
    observer = writer._api.kernel32.CreateMutexW(None, False, writer._mutex_name)
    assert observer not in {0, None, writer._api.invalid_handle}
    child_code = r'''
import hashlib
import os
import sys
from pathlib import Path
from app.safety.context import Caller, DataClassification, Purpose, ScopeId, ScopeKind
from app.safety.job_operation import DeclaredTreeEntry, DeclaredTreeManifest, JobResourceBudget
from app.safety.production_guard import _create_test_durable_boundary, _create_test_job_runtime
from app.safety.windows_handle_writer import TreeEntryKind

project = Path(sys.argv[1])
bundle = _create_test_durable_boundary(
    project,
    initialize=False,
    epoch_id="RUN-S3D-LEDGER",
    initial_revision_sequence=1,
    initial_revision_id="KEYREV-S3D-ONE",
    master_key=b"J" * 32,
    key_created_at_utc="2026-07-11T01:00:00Z",
)
manifest = DeclaredTreeManifest(
    "MANIFEST-CRASH",
    DataClassification.INTERNAL,
    (DeclaredTreeEntry("payload.bin", TreeEntryKind.FILE, 1, hashlib.sha256(b"x").hexdigest()),),
)
context = bundle.boundary.issue_context(
    run_id="RUN-S3D-CRASH",
    job_id="JOB-S3D-CRASH",
    operation_id="OP-S3D-CRASH",
    caller=Caller.TEST_LAB,
    purpose=Purpose.TEST,
    manifest_id="MANIFEST-CRASH",
    scopes=(
        ScopeId(ScopeKind.RUN_ID, "RUN-S3D-CRASH"),
        ScopeId(ScopeKind.JOB_ID, "JOB-S3D-CRASH"),
        ScopeId(ScopeKind.OPERATION_ID, "OP-S3D-CRASH"),
        ScopeId(ScopeKind.MANIFEST_ID, "MANIFEST-CRASH"),
        ScopeId(ScopeKind.CHECKPOINT_ID, "CHECKPOINT-S3D-CRASH"),
    ),
)
operation = _create_test_job_runtime(bundle).begin_operation(
    context,
    manifest,
    JobResourceBudget.conservative_test_default(),
)
operation.create_fixed_staging()
os._exit(73)
'''
    try:
        completed = subprocess.run(
            [sys.executable, "-B", "-c", child_code, str(job_lab.project)],
            cwd=Path(__file__).parent.parent,
            env=os.environ.copy(),
            shell=False,
            check=False,
            timeout=30,
        )
        assert completed.returncode == 73
        residue = job_lab.project / "tmp/jobs/INTERNAL/JOB-S3D-CRASH"
        assert residue.is_dir()
        assert (residue / "job-contract.json").is_file()
        reopened = _create_test_durable_boundary(
            job_lab.project,
            initialize=False,
            epoch_id="RUN-S3D-LEDGER",
            initial_revision_sequence=1,
            initial_revision_id="KEYREV-S3D-ONE",
            master_key=b"J" * 32,
            key_created_at_utc="2026-07-11T01:00:00Z",
        )
        assert reopened.ledger.head.startup_observed_abandoned_mutex
        manifest = DeclaredTreeManifest(
            "MANIFEST-RETRY",
            DataClassification.INTERNAL,
            (DeclaredTreeEntry("x.bin", TreeEntryKind.FILE, 1, _sha(b"x")),),
        )
        retry_context = reopened.boundary.issue_context(
            run_id="RUN-S3D-RETRY",
            job_id="JOB-S3D-CRASH",
            operation_id="OP-S3D-RETRY",
            caller=Caller.TEST_LAB,
            purpose=Purpose.TEST,
            manifest_id="MANIFEST-RETRY",
            scopes=(
                ScopeId(ScopeKind.RUN_ID, "RUN-S3D-RETRY"),
                ScopeId(ScopeKind.JOB_ID, "JOB-S3D-CRASH"),
                ScopeId(ScopeKind.OPERATION_ID, "OP-S3D-RETRY"),
                ScopeId(ScopeKind.MANIFEST_ID, "MANIFEST-RETRY"),
                ScopeId(ScopeKind.CHECKPOINT_ID, "CHECKPOINT-S3D-RETRY"),
            ),
        )
        with _create_test_job_runtime(reopened).begin_operation(
            retry_context,
            manifest,
            JobResourceBudget.conservative_test_default(),
        ) as retry:
            with pytest.raises(HandleWriterError) as captured:
                retry.create_fixed_staging()
            assert captured.value.code is HandleWriterCode.GUARD_REJECTED
    finally:
        writer._api.close(int(observer))


def test_two_process_mutex_busy_rolls_back_pin_and_same_context_retries(
    job_lab: _JobLab,
) -> None:
    ready = job_lab.project / "tmp" / "s3d-child-ready.txt"
    release = job_lab.project / "tmp" / "s3d-child-release.txt"
    child_code = r'''
import hashlib
import sys
import time
from pathlib import Path
from app.safety.context import Caller, DataClassification, Purpose, ScopeId, ScopeKind
from app.safety.job_operation import DeclaredTreeEntry, DeclaredTreeManifest, JobResourceBudget
from app.safety.production_guard import _create_test_durable_boundary, _create_test_job_runtime
from app.safety.windows_handle_writer import TreeEntryKind

project, ready, release = map(Path, sys.argv[1:4])
bundle = _create_test_durable_boundary(
    project,
    initialize=False,
    epoch_id="RUN-S3D-LEDGER",
    initial_revision_sequence=1,
    initial_revision_id="KEYREV-S3D-ONE",
    master_key=b"J" * 32,
    key_created_at_utc="2026-07-11T01:00:00Z",
)
manifest = DeclaredTreeManifest(
    "MANIFEST-CHILD-MUTEX",
    DataClassification.INTERNAL,
    (DeclaredTreeEntry("x.bin", TreeEntryKind.FILE, 1, hashlib.sha256(b"x").hexdigest()),),
)
context = bundle.boundary.issue_context(
    run_id="RUN-S3D-CHILD-MUTEX",
    job_id="JOB-S3D-CHILD-MUTEX",
    operation_id="OP-S3D-CHILD-MUTEX",
    caller=Caller.TEST_LAB,
    purpose=Purpose.TEST,
    manifest_id=manifest.manifest_id,
    scopes=(
        ScopeId(ScopeKind.RUN_ID, "RUN-S3D-CHILD-MUTEX"),
        ScopeId(ScopeKind.JOB_ID, "JOB-S3D-CHILD-MUTEX"),
        ScopeId(ScopeKind.OPERATION_ID, "OP-S3D-CHILD-MUTEX"),
        ScopeId(ScopeKind.MANIFEST_ID, manifest.manifest_id),
        ScopeId(ScopeKind.CHECKPOINT_ID, "CHECKPOINT-S3D-CHILD-MUTEX"),
    ),
)
operation = _create_test_job_runtime(bundle).begin_operation(
    context,
    manifest,
    JobResourceBudget.conservative_test_default(),
)
ready.write_text("ready", encoding="ascii")
deadline = time.monotonic() + 20
while not release.exists() and time.monotonic() < deadline:
    time.sleep(0.02)
if not release.exists():
    raise SystemExit(74)
operation.close()
'''
    child = subprocess.Popen(
        [
            sys.executable,
            "-B",
            "-c",
            child_code,
            str(job_lab.project),
            str(ready),
            str(release),
        ],
        cwd=Path(__file__).parent.parent,
        env=os.environ.copy(),
        shell=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + 15
        while not ready.exists() and child.poll() is None and time.monotonic() < deadline:
            time.sleep(0.02)
        assert ready.is_file()
        manifest = DeclaredTreeManifest(
            "MANIFEST-PARENT-RETRY",
            DataClassification.INTERNAL,
            (DeclaredTreeEntry("x.bin", TreeEntryKind.FILE, 1, _sha(b"x")),),
        )
        context = _context(
            job_lab,
            job_id="JOB-PARENT-RETRY",
            operation_id="OP-PARENT-RETRY",
            manifest_id=manifest.manifest_id,
        )
        with pytest.raises(HandleWriterError) as busy:
            job_lab.runtime.begin_operation(
                context,
                manifest,
                JobResourceBudget.conservative_test_default(),
            )
        assert busy.value.code is HandleWriterCode.MUTEX_BUSY
        assert job_lab.bundle.boundary.diagnostic_registry_counts["job_context_pins"] == 0
        release.write_text("release", encoding="ascii")
        stdout, stderr = child.communicate(timeout=20)
        assert child.returncode == 0, (stdout, stderr)
        with job_lab.runtime.begin_operation(
            context,
            manifest,
            JobResourceBudget.conservative_test_default(),
        ):
            pass
    finally:
        if child.poll() is None:
            child.kill()
            child.communicate(timeout=10)


def test_context_missing_checkpoint_scope_is_rejected_before_mutex(job_lab: _JobLab) -> None:
    context = job_lab.bundle.boundary.issue_context(
        run_id="RUN-S3D-JOB",
        job_id="JOB-S3D-ONE",
        operation_id="OP-S3D-ONE",
        caller=Caller.TEST_LAB,
        purpose=Purpose.TEST,
        manifest_id="MANIFEST-S3D",
        scopes=(
            ScopeId(ScopeKind.RUN_ID, "RUN-S3D-JOB"),
            ScopeId(ScopeKind.JOB_ID, "JOB-S3D-ONE"),
            ScopeId(ScopeKind.OPERATION_ID, "OP-S3D-ONE"),
            ScopeId(ScopeKind.MANIFEST_ID, "MANIFEST-S3D"),
        ),
    )
    try:
        with pytest.raises(JobOperationError) as captured:
            job_lab.runtime.begin_operation(
                context,
                _manifest(),
                JobResourceBudget.conservative_test_default(),
            )
        assert captured.value.code is JobOperationCode.INVALID_CONTEXT
    finally:
        assert job_lab.bundle.boundary.release_context(context)


def test_restricted_context_requires_exact_import_actor(job_lab: _JobLab) -> None:
    context = _context(
        job_lab,
        classification=DataClassification.RESTRICTED,
        caller=Caller.TEST_LAB,
        purpose=Purpose.TEST,
    )
    try:
        with pytest.raises(JobOperationError) as captured:
            job_lab.runtime.begin_operation(
                context,
                _manifest(classification=DataClassification.RESTRICTED),
                JobResourceBudget.conservative_test_default(),
            )
        assert captured.value.code is JobOperationCode.INVALID_CONTEXT
    finally:
        assert job_lab.bundle.boundary.release_context(context)


@pytest.mark.parametrize(
    "path",
    ["../x", "/x", "x\\y", "x:y", "NUL.txt", "tail.", "e\u0301.txt", "\ud800"],
)
def test_declared_manifest_rejects_windows_path_attacks(path: str) -> None:
    with pytest.raises(JobOperationError) as captured:
        DeclaredTreeEntry(path, TreeEntryKind.FILE, 0, _sha(b""))
    assert captured.value.code is JobOperationCode.INVALID_MANIFEST


def test_declared_manifest_requires_explicit_parent_directory() -> None:
    with pytest.raises(JobOperationError) as captured:
        DeclaredTreeManifest(
            "MANIFEST-S3D",
            DataClassification.INTERNAL,
            (DeclaredTreeEntry("parent/file.bin", TreeEntryKind.FILE, 0, _sha(b"")),),
        )
    assert captured.value.code is JobOperationCode.INVALID_MANIFEST


def test_declared_directory_rejects_boolean_size() -> None:
    with pytest.raises(JobOperationError) as captured:
        DeclaredTreeEntry("d", TreeEntryKind.DIRECTORY, False, None)
    assert captured.value.code is JobOperationCode.INVALID_MANIFEST


def test_budget_rejects_bool_negative_and_fixed_cap_overflow() -> None:
    valid = JobResourceBudget.conservative_test_default()
    with pytest.raises(JobOperationError):
        JobResourceBudget(
            maximum_entries=True,
            maximum_files=valid.maximum_files,
            maximum_directories=valid.maximum_directories,
            maximum_depth=valid.maximum_depth,
            maximum_file_bytes=valid.maximum_file_bytes,
            maximum_total_bytes=valid.maximum_total_bytes,
            maximum_path_utf8_bytes=valid.maximum_path_utf8_bytes,
            maximum_open_handles=valid.maximum_open_handles,
            maximum_manifest_bytes=valid.maximum_manifest_bytes,
            maximum_elapsed_seconds=valid.maximum_elapsed_seconds,
            minimum_free_bytes=valid.minimum_free_bytes,
        )


def test_exact_small_budget_passes_and_file_limit_plus_one_fails(job_lab: _JobLab) -> None:
    payload = b"x"
    manifest = DeclaredTreeManifest(
        "MANIFEST-EXACT",
        DataClassification.INTERNAL,
        (DeclaredTreeEntry("x.bin", TreeEntryKind.FILE, 1, _sha(payload)),),
    )
    exact = JobResourceBudget(
        maximum_entries=1,
        maximum_files=1,
        maximum_directories=1,
        maximum_depth=1,
        maximum_file_bytes=1,
        maximum_total_bytes=1,
        maximum_path_utf8_bytes=len("x.bin"),
        maximum_open_handles=2,
        maximum_manifest_bytes=512,
        maximum_elapsed_seconds=60,
        minimum_free_bytes=0,
    )
    with job_lab.runtime.begin_operation(
        _context(
            job_lab,
            job_id="JOB-S3D-EXACT",
            operation_id="OP-S3D-EXACT",
            manifest_id="MANIFEST-EXACT",
        ),
        manifest,
        exact,
    ) as operation:
        staging = operation.create_fixed_staging()
        staging.create_declared_file("x.bin", payload)
        assert staging.seal_and_observe().evidence.total_bytes == 1

    oversized = DeclaredTreeManifest(
        "MANIFEST-TOO-LARGE",
        DataClassification.INTERNAL,
        (DeclaredTreeEntry("x.bin", TreeEntryKind.FILE, 2, _sha(b"xx")),),
    )
    context = _context(
        job_lab,
        job_id="JOB-S3D-TOO-LARGE",
        operation_id="OP-S3D-TOO-LARGE",
        manifest_id="MANIFEST-TOO-LARGE",
    )
    try:
        with pytest.raises(JobOperationError) as captured:
            job_lab.runtime.begin_operation(context, oversized, exact)
        assert captured.value.code is JobOperationCode.RESOURCE_LIMIT
    finally:
        assert job_lab.bundle.boundary.release_context(context)
    with pytest.raises(JobOperationError):
        JobResourceBudget(
            maximum_entries=2049,
            maximum_files=2048,
            maximum_directories=512,
            maximum_depth=16,
            maximum_file_bytes=64 * 1024 * 1024,
            maximum_total_bytes=256 * 1024 * 1024,
            maximum_path_utf8_bytes=4096,
            maximum_open_handles=4096,
            maximum_manifest_bytes=8 * 1024 * 1024,
            maximum_elapsed_seconds=300,
            minimum_free_bytes=0,
        )


@pytest.mark.parametrize(
    "target",
    [
        "maximum_entries",
        "maximum_files",
        "maximum_directories",
        "maximum_depth",
        "maximum_file_bytes",
        "maximum_total_bytes",
        "maximum_path_utf8_bytes",
        "maximum_manifest_bytes",
    ],
)
def test_declared_budget_exact_limit_passes_and_plus_one_fails_before_mutation(
    job_lab: _JobLab,
    target: str,
) -> None:
    if target in {"maximum_entries", "maximum_files", "maximum_manifest_bytes"}:
        exact_entries = _entries(
            DeclaredTreeEntry("x.bin", TreeEntryKind.FILE, 1, _sha(b"x"))
        )
        overflow_entries = _entries(
            *exact_entries,
            DeclaredTreeEntry("y.bin", TreeEntryKind.FILE, 1, _sha(b"y")),
        )
    elif target == "maximum_directories":
        exact_entries = _entries(
            DeclaredTreeEntry("d", TreeEntryKind.DIRECTORY, 0, None)
        )
        overflow_entries = _entries(
            *exact_entries,
            DeclaredTreeEntry("e", TreeEntryKind.DIRECTORY, 0, None),
        )
    elif target == "maximum_depth":
        exact_entries = _entries(
            DeclaredTreeEntry("d", TreeEntryKind.DIRECTORY, 0, None),
            DeclaredTreeEntry("d/x.bin", TreeEntryKind.FILE, 1, _sha(b"x")),
        )
        overflow_entries = _entries(
            DeclaredTreeEntry("d", TreeEntryKind.DIRECTORY, 0, None),
            DeclaredTreeEntry("d/e", TreeEntryKind.DIRECTORY, 0, None),
            DeclaredTreeEntry("d/e/x.bin", TreeEntryKind.FILE, 1, _sha(b"x")),
        )
    elif target == "maximum_file_bytes":
        exact_entries = _entries(
            DeclaredTreeEntry("x.bin", TreeEntryKind.FILE, 1, _sha(b"x"))
        )
        overflow_entries = _entries(
            DeclaredTreeEntry("x.bin", TreeEntryKind.FILE, 2, _sha(b"xx"))
        )
    elif target == "maximum_total_bytes":
        exact_entries = _entries(
            DeclaredTreeEntry("x.bin", TreeEntryKind.FILE, 1, _sha(b"x")),
            DeclaredTreeEntry("y.bin", TreeEntryKind.FILE, 1, _sha(b"y")),
        )
        overflow_entries = _entries(
            *exact_entries,
            DeclaredTreeEntry("z.bin", TreeEntryKind.FILE, 1, _sha(b"z")),
        )
    else:
        exact_entries = _entries(
            DeclaredTreeEntry("x.bin", TreeEntryKind.FILE, 1, _sha(b"x"))
        )
        overflow_entries = _entries(
            DeclaredTreeEntry("xx.bin", TreeEntryKind.FILE, 1, _sha(b"x"))
        )
    suffix = target.removeprefix("maximum_").replace("_", "-").upper()
    exact_manifest = DeclaredTreeManifest(
        f"MANIFEST-EXACT-{suffix}",
        DataClassification.INTERNAL,
        exact_entries,
    )
    overflow_manifest = DeclaredTreeManifest(
        f"MANIFEST-OVER-{suffix}",
        DataClassification.INTERNAL,
        overflow_entries,
    )
    budget = _boundary_budget(exact_manifest, overflow_manifest, target)
    with job_lab.runtime.begin_operation(
        _context(
            job_lab,
            job_id=f"JOB-EXACT-{suffix}",
            operation_id=f"OP-EXACT-{suffix}",
            manifest_id=exact_manifest.manifest_id,
        ),
        exact_manifest,
        budget,
    ):
        pass
    overflow_context = _context(
        job_lab,
        job_id=f"JOB-OVER-{suffix}",
        operation_id=f"OP-OVER-{suffix}",
        manifest_id=overflow_manifest.manifest_id,
    )
    try:
        with pytest.raises(JobOperationError) as captured:
            job_lab.runtime.begin_operation(
                overflow_context,
                overflow_manifest,
                budget,
            )
        assert captured.value.code is JobOperationCode.RESOURCE_LIMIT
    finally:
        assert job_lab.bundle.boundary.release_context(overflow_context)
    assert not (job_lab.project / "tmp" / "jobs" / "INTERNAL" / f"JOB-OVER-{suffix}").exists()


def test_open_handle_budget_requires_exact_entry_count_plus_root() -> None:
    valid = JobResourceBudget(
        maximum_entries=2,
        maximum_files=2,
        maximum_directories=1,
        maximum_depth=1,
        maximum_file_bytes=1,
        maximum_total_bytes=2,
        maximum_path_utf8_bytes=16,
        maximum_open_handles=3,
        maximum_manifest_bytes=512,
        maximum_elapsed_seconds=60,
        minimum_free_bytes=0,
    )
    assert valid.maximum_open_handles == valid.maximum_entries + 1
    with pytest.raises(JobOperationError) as captured:
        JobResourceBudget(
            maximum_entries=2,
            maximum_files=2,
            maximum_directories=1,
            maximum_depth=1,
            maximum_file_bytes=1,
            maximum_total_bytes=2,
            maximum_path_utf8_bytes=16,
            maximum_open_handles=2,
            maximum_manifest_bytes=512,
            maximum_elapsed_seconds=60,
            minimum_free_bytes=0,
        )
    assert captured.value.code is JobOperationCode.INVALID_REQUEST


def test_elapsed_and_disk_reserves_fail_before_job_root_creation(
    job_lab: _JobLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = DeclaredTreeManifest(
        "MANIFEST-RUNTIME-BUDGET",
        DataClassification.INTERNAL,
        (DeclaredTreeEntry("x.bin", TreeEntryKind.FILE, 1, _sha(b"x")),),
    )
    base = _boundary_budget(manifest, manifest, "maximum_entries")
    timeout_budget = JobResourceBudget(
        maximum_entries=base.maximum_entries,
        maximum_files=base.maximum_files,
        maximum_directories=base.maximum_directories,
        maximum_depth=base.maximum_depth,
        maximum_file_bytes=base.maximum_file_bytes,
        maximum_total_bytes=base.maximum_total_bytes,
        maximum_path_utf8_bytes=base.maximum_path_utf8_bytes,
        maximum_open_handles=base.maximum_open_handles,
        maximum_manifest_bytes=base.maximum_manifest_bytes,
        maximum_elapsed_seconds=1,
        minimum_free_bytes=0,
    )
    timeout_context = _context(
        job_lab,
        job_id="JOB-RUNTIME-TIMEOUT",
        operation_id="OP-RUNTIME-TIMEOUT",
        manifest_id=manifest.manifest_id,
    )
    with job_lab.runtime.begin_operation(
        timeout_context,
        manifest,
        timeout_budget,
    ) as operation:
        monkeypatch.setattr(
            "app.safety.job_operation.time.monotonic",
            lambda: operation._started_at + 2,
        )
        with pytest.raises(JobOperationError) as timeout_failure:
            operation.create_fixed_staging()
        assert timeout_failure.value.code is JobOperationCode.DEADLINE_EXCEEDED
    assert not (job_lab.project / "tmp/jobs/INTERNAL/JOB-RUNTIME-TIMEOUT").exists()

    monkeypatch.undo()
    disk_context = _context(
        job_lab,
        job_id="JOB-RUNTIME-DISK",
        operation_id="OP-RUNTIME-DISK",
        manifest_id=manifest.manifest_id,
    )
    disk_budget = JobResourceBudget(
        maximum_entries=base.maximum_entries,
        maximum_files=base.maximum_files,
        maximum_directories=base.maximum_directories,
        maximum_depth=base.maximum_depth,
        maximum_file_bytes=base.maximum_file_bytes,
        maximum_total_bytes=base.maximum_total_bytes,
        maximum_path_utf8_bytes=base.maximum_path_utf8_bytes,
        maximum_open_handles=base.maximum_open_handles,
        maximum_manifest_bytes=base.maximum_manifest_bytes,
        maximum_elapsed_seconds=60,
        minimum_free_bytes=1024,
    )
    required = disk_budget.minimum_free_bytes + 1
    with job_lab.runtime.begin_operation(disk_context, manifest, disk_budget) as operation:
        monkeypatch.setattr(
            "app.safety.job_operation.shutil.disk_usage",
            lambda _path: SimpleNamespace(free=required - 1),
        )
        with pytest.raises(JobOperationError) as disk_failure:
            operation.create_fixed_staging()
        assert disk_failure.value.code is JobOperationCode.DISK_BUDGET
    assert not (job_lab.project / "tmp/jobs/INTERNAL/JOB-RUNTIME-DISK").exists()


def test_observed_extra_entry_exceeding_budget_fails_closed(job_lab: _JobLab) -> None:
    payload = b"x"
    manifest = DeclaredTreeManifest(
        "MANIFEST-OBSERVED-BUDGET",
        DataClassification.INTERNAL,
        (DeclaredTreeEntry("x.bin", TreeEntryKind.FILE, 1, _sha(payload)),),
    )
    budget = JobResourceBudget(
        maximum_entries=1,
        maximum_files=1,
        maximum_directories=1,
        maximum_depth=1,
        maximum_file_bytes=1,
        maximum_total_bytes=1,
        maximum_path_utf8_bytes=64,
        maximum_open_handles=2,
        maximum_manifest_bytes=512,
        maximum_elapsed_seconds=60,
        minimum_free_bytes=0,
    )
    with job_lab.runtime.begin_operation(
        _context(
            job_lab,
            job_id="JOB-OBSERVED-BUDGET",
            operation_id="OP-OBSERVED-BUDGET",
            manifest_id=manifest.manifest_id,
        ),
        manifest,
        budget,
    ) as operation:
        staging = operation.create_fixed_staging()
        staging.create_declared_file("x.bin", payload)
        root = job_lab.project / "tmp/jobs/INTERNAL/JOB-OBSERVED-BUDGET/publish/MANIFEST-OBSERVED-BUDGET"
        (root / "extra.bin").write_bytes(b"y")
        with pytest.raises(HandleWriterError) as captured:
            staging.seal_and_observe()
        assert captured.value.code is HandleWriterCode.RESOURCE_LIMIT


def test_production_boundary_still_has_no_job_writer_surface(job_lab: _JobLab) -> None:
    from app.safety.production_guard import get_production_boundary

    production = get_production_boundary()
    assert production.writer_available is False
    assert not hasattr(production, "begin_operation")
    assert not hasattr(production, "create_fixed_staging")
    assert job_lab.bundle.boundary.writer_available is False
