from __future__ import annotations

import hashlib
import os
import pickle
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from types import CodeType, FunctionType

import pytest

import app.safety.external_source as external_source_module
from app.safety.context import DataClassification
from app.safety.external_source import (
    SYNTHETIC_REFERENCE_MAX_BYTES,
    SYNTHETIC_REFERENCE_PAYLOAD_NAME,
    SYNTHETIC_REFERENCE_POLICY_DIGEST,
    ExternalSourceCode,
    ExternalSourceError,
    RegisteredSourceEvidence,
    RegisteredSourceMaterial,
    RegisteredSourceVerification,
    SyntheticReferenceReadPolicy,
    SyntheticSourceEvidence,
    SyntheticSourceMaterial,
    SyntheticSourceVerification,
    _CopyExecutionPermit,
    _ReferenceReadApi,
    _consume_copy_execution_permit,
    _create_synthetic_reference_read_policy,
    _issue_copy_execution_permit,
    _validate_copy_execution_permit,
    open_registered_external_source,
)
from app.workspace_guard import PathIntent
from tests.conftest import register_synthetic_source
from tests.test_workspace_guard import (
    _controlled_mklink_junction,
    _remove_expected_reparse,
)


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


def _external_boundary_surfaces() -> tuple[FunctionType, ...]:
    return (
        SyntheticReferenceReadPolicy.matches_copy_scope,
        SyntheticReferenceReadPolicy.open_reference,
        SyntheticReferenceReadPolicy.close,
        SyntheticReferenceReadPolicy.__enter__,
        SyntheticReferenceReadPolicy.__exit__,
        external_source_module._SyntheticReferenceLease.read_once,
        external_source_module._SyntheticReferenceLease._checkpoint_unchanged,
        external_source_module._SyntheticReferenceLease.verify_unchanged,
        external_source_module._SyntheticReferenceLease.close,
        external_source_module._SyntheticReferenceLease.__enter__,
        external_source_module._SyntheticReferenceLease.__exit__,
        _issue_copy_execution_permit,
        _validate_copy_execution_permit,
        _consume_copy_execution_permit,
        _create_synthetic_reference_read_policy,
        external_source_module._RegisteredExternalReadLease.read_once,
        external_source_module._RegisteredExternalReadLease.verify_unchanged,
        external_source_module._RegisteredExternalReadLease.close,
        external_source_module._RegisteredExternalReadLease.__enter__,
        external_source_module._RegisteredExternalReadLease.__exit__,
        open_registered_external_source,
    )


def _external_boundary_vault() -> dict[CodeType, FunctionType]:
    candidates = []
    closure = external_source_module._dispatch_external_boundary.__closure__ or ()
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


@dataclass(frozen=True)
class _ExternalLab:
    run_root: Path
    project: Path
    reference: Path

    def write_unregistered(self, name: str, payload: bytes) -> Path:
        digest = hashlib.sha256(
            name.encode("utf-8", "strict") + b"\0" + payload
        ).hexdigest()[:12].upper()
        target = self.reference / f"EXT-{digest}-{name}"
        if target.exists():
            assert target.read_bytes() == payload
        else:
            target.write_bytes(payload)
        return target

    def write(self, name: str, payload: bytes) -> Path:
        target = self.write_unregistered(name, payload)
        register_synthetic_source(target)
        return target

    def policy(
        self,
        copy_id: str,
        classification: DataClassification = DataClassification.INTERNAL,
    ) -> SyntheticReferenceReadPolicy:
        return _create_synthetic_reference_read_policy(
            self.project,
            copy_id=copy_id,
            classification=classification,
        )


@pytest.fixture(scope="module")
def external_lab() -> _ExternalLab:
    run_root = Path(os.environ["M0_TEST_LAB_ROOT"])
    project = run_root / "project"
    external = run_root / "external"
    reference = external / "REFERENCE"
    project.mkdir(exist_ok=True)
    external.mkdir(exist_ok=True)
    reference.mkdir(exist_ok=True)
    return _ExternalLab(run_root=run_root, project=project, reference=reference)


def _surface(value: object) -> str:
    dictionary = getattr(value, "__dict__", {})
    arguments = getattr(value, "args", ())
    return repr(value) + str(value) + repr(dictionary) + repr(arguments)


def test_internal_source_read_and_final_reverification_are_handle_bound(
    external_lab: _ExternalLab,
) -> None:
    payload = "函数、几何与统计\n".encode("utf-8")
    source = external_lab.write("normal-internal.bin", payload)

    policy = external_lab.policy("COPY-S3F-NORMAL-INTERNAL")
    assert policy.intent is PathIntent.EXISTING_READ
    assert policy.classification is DataClassification.INTERNAL
    assert policy.policy_digest == SYNTHETIC_REFERENCE_POLICY_DIGEST
    with policy.open_reference(source.name) as lease:
        material = lease.read_once()
        verification = lease.verify_unchanged(material.evidence)

    assert type(material) is SyntheticSourceMaterial
    assert type(material.evidence) is SyntheticSourceEvidence
    assert type(verification) is SyntheticSourceVerification
    assert material.payload == payload
    assert material.evidence.size_bytes == len(payload)
    assert material.evidence.sha256 == hashlib.sha256(payload).hexdigest()
    assert material.evidence.destination_name == SYNTHETIC_REFERENCE_PAYLOAD_NAME
    assert verification.evidence is material.evidence
    assert source.read_bytes() == payload


def test_registered_source_public_lease_is_handle_bound_and_path_redacted(
    external_lab: _ExternalLab,
) -> None:
    payload = b"registered external source"
    source = external_lab.write("registered-public-source.svg", payload)

    with open_registered_external_source(
        source,
        logical_id="REF-UNIT-REGISTERED-SOURCE",
        classification=DataClassification.INTERNAL,
    ) as lease:
        material = lease.read_once()
        verification = lease.verify_unchanged(material.evidence)

    assert type(material) is RegisteredSourceMaterial
    assert type(material.evidence) is RegisteredSourceEvidence
    assert type(verification) is RegisteredSourceVerification
    assert material.payload == payload
    assert material.evidence.logical_id == "REF-UNIT-REGISTERED-SOURCE"
    assert material.evidence.sha256 == hashlib.sha256(payload).hexdigest()
    assert verification.evidence is material.evidence
    exposed = repr(lease) + repr(material) + repr(verification)
    assert source.name not in exposed
    assert str(source) not in exposed


def test_registered_source_rejects_other_project_local_files_without_path_leak(
    external_lab: _ExternalLab,
) -> None:
    project_file = Path(__file__).parent.parent / "README.md"
    with pytest.raises(ExternalSourceError) as captured:
        open_registered_external_source(
            project_file,
            logical_id="REF-UNIT-REJECT-PROJECT",
            classification=DataClassification.INTERNAL,
        )

    assert captured.value.code is ExternalSourceCode.PATH_REJECTED
    surface = repr(captured.value) + str(captured.value)
    assert project_file.name not in surface
    assert str(project_file) not in surface


def test_restricted_record_is_hmac_only_and_contains_no_source_or_ids(
    external_lab: _ExternalLab,
) -> None:
    copy_id = "COPY-S3F-RESTRICTED-SECRET"
    source = external_lab.write("restricted-original-name.bin", b"restricted-source")
    source_name = source.name

    with external_lab.policy(copy_id, DataClassification.RESTRICTED).open_reference(
        source.name
    ) as lease:
        material = lease.read_once()
        lease.verify_unchanged(material.evidence)

    record = material.evidence.to_source_record_fields()
    serialized = repr(record)
    assert record["classification"] == "RESTRICTED"
    assert record["locator"]["mode"] == "HMAC_ONLY"
    assert len(record["locator"]["digest"]) == 64
    for forbidden in (
        source_name,
        str(source),
        str(external_lab.run_root),
        copy_id,
    ):
        assert forbidden not in serialized


def test_factory_requires_the_exact_direct_run_project(
    external_lab: _ExternalLab,
    tmp_path: Path,
) -> None:
    nested_project = tmp_path / "project"
    nested_project.mkdir()

    with pytest.raises(ExternalSourceError) as captured:
        _create_synthetic_reference_read_policy(
            nested_project,
            copy_id="COPY-S3F-WRONG-PROJECT",
            classification=DataClassification.INTERNAL,
        )

    assert captured.value.code is ExternalSourceCode.INVALID_LABORATORY


def test_factory_requires_the_active_launcher_token(
    external_lab: _ExternalLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("M0_TEST_LAB_TOKEN")

    with pytest.raises(ExternalSourceError) as captured:
        external_lab.policy("COPY-S3F-NO-TOKEN")

    assert captured.value.code is ExternalSourceCode.INVALID_FACTORY


def test_factory_rejects_string_pseudo_classification(external_lab: _ExternalLab) -> None:
    with pytest.raises(ExternalSourceError) as captured:
        _create_synthetic_reference_read_policy(
            external_lab.project,
            copy_id="COPY-S3F-PSEUDO-CLASS",
            classification="INTERNAL",  # type: ignore[arg-type]
        )

    assert captured.value.code is ExternalSourceCode.INVALID_REQUEST


def test_factory_rejects_path_syntax_in_copy_id(external_lab: _ExternalLab) -> None:
    with pytest.raises(ExternalSourceError) as captured:
        external_lab.policy("../COPY-S3F-ESCAPE")

    assert captured.value.code is ExternalSourceCode.INVALID_REQUEST


@pytest.mark.parametrize("name", ["../source.bin", "source:stream", "source.bin "])
def test_source_request_rejects_non_component_syntax(
    external_lab: _ExternalLab,
    name: str,
) -> None:
    policy = external_lab.policy(
        "COPY-S3F-BAD-NAME-" + hashlib.sha256(name.encode()).hexdigest()[:12].upper()
    )
    with pytest.raises(ExternalSourceError) as captured:
        policy.open_reference(name)
    policy.close()

    assert captured.value.code is ExternalSourceCode.INVALID_REQUEST


@pytest.mark.parametrize(
    "name",
    [
        "blocked.DB",
        "blocked.DB3",
        "blocked.SQLite",
        "blocked.SQLITE3",
        "blocked-source-WAL",
        "blocked-source.SHM",
        "blocked-source-journal",
    ],
)
def test_sqlite_names_are_rejected_before_a_source_lease_is_returned(
    external_lab: _ExternalLab,
    name: str,
) -> None:
    source = external_lab.write(name, b"not-even-a-database")
    policy = external_lab.policy(
        "COPY-S3F-SQLNAME-" + hashlib.sha256(name.encode()).hexdigest()[:12].upper()
    )

    with pytest.raises(ExternalSourceError) as captured:
        policy.open_reference(source.name)

    assert captured.value.code is ExternalSourceCode.SQLITE_REJECTED
    assert source.name not in _surface(captured.value)
    assert str(source) not in _surface(captured.value)


def test_sqlite_header_is_rejected_under_a_disguised_name(
    external_lab: _ExternalLab,
) -> None:
    source = external_lab.write(
        "disguised-database.bin",
        b"SQLite format 3\0" + b"\0" * 64,
    )
    policy = external_lab.policy("COPY-S3F-SQLITE-HEADER")

    with pytest.raises(ExternalSourceError) as captured:
        policy.open_reference(source.name)

    assert captured.value.code is ExternalSourceCode.SQLITE_REJECTED
    assert source.name not in _surface(captured.value)


def test_sparse_source_over_64_mib_is_rejected_before_payload_return(
    external_lab: _ExternalLab,
) -> None:
    source = external_lab.reference / "over-limit.bin"
    with source.open("xb") as stream:
        stream.truncate(SYNTHETIC_REFERENCE_MAX_BYTES + 1)
    register_synthetic_source(source)
    policy = external_lab.policy("COPY-S3F-OVER-LIMIT")

    with pytest.raises(ExternalSourceError) as captured:
        policy.open_reference(source.name)

    assert captured.value.code is ExternalSourceCode.RESOURCE_LIMIT


def test_hardlinked_source_is_rejected(external_lab: _ExternalLab) -> None:
    source = external_lab.write_unregistered(
        "hardlink-source.bin",
        b"hardlink-source",
    )
    alias = source.with_name(source.stem + "-alias" + source.suffix)
    os.link(source, alias)
    policy = external_lab.policy("COPY-S3F-HARDLINK")

    try:
        with pytest.raises(ExternalSourceError) as captured:
            policy.open_reference(source.name)

        assert captured.value.code is ExternalSourceCode.HARDLINK_REJECTED
    finally:
        alias.unlink(missing_ok=True)

    assert source.read_bytes() == b"hardlink-source"
    assert source.stat().st_nlink == 1
    register_synthetic_source(source)
    with external_lab.policy("COPY-S3F-HARDLINK-CLEAN").open_reference(
        source.name
    ) as lease:
        material = lease.read_once()
        lease.verify_unchanged(material.evidence)
    assert material.payload == b"hardlink-source"


def test_alternate_data_stream_is_rejected(external_lab: _ExternalLab) -> None:
    source = external_lab.write_unregistered("ads-source.bin", b"default-stream")
    private_stream = Path(f"{source}:private")
    private_stream.write_bytes(b"alternate-stream")
    policy = external_lab.policy("COPY-S3F-ADS")

    try:
        with pytest.raises(ExternalSourceError) as captured:
            policy.open_reference(source.name)

        assert captured.value.code is ExternalSourceCode.ALTERNATE_STREAM_REJECTED
    finally:
        private_stream.unlink(missing_ok=True)

    assert source.read_bytes() == b"default-stream"
    assert source.stat().st_nlink == 1
    register_synthetic_source(source)
    with external_lab.policy("COPY-S3F-ADS-CLEAN").open_reference(
        source.name
    ) as lease:
        material = lease.read_once()
        lease.verify_unchanged(material.evidence)
    assert material.payload == b"default-stream"


def test_directory_source_is_rejected_as_non_regular(
    external_lab: _ExternalLab,
) -> None:
    source = external_lab.reference / "directory-source"
    source.mkdir()
    policy = external_lab.policy("COPY-S3F-DIRECTORY-SOURCE")

    with pytest.raises(ExternalSourceError) as captured:
        policy.open_reference(source.name)

    assert captured.value.code is ExternalSourceCode.TYPE_MISMATCH
    assert source.is_dir()


def test_reference_root_junction_is_rejected_before_project_write(
    external_lab: _ExternalLab,
) -> None:
    original = external_lab.run_root / "REFERENCE-original"
    junction_target = external_lab.run_root / "REFERENCE-junction-target"
    junction_target.mkdir()
    sentinel = external_lab.reference / "junction-root-sentinel.bin"
    sentinel.write_bytes(b"reference-root-must-be-preserved")
    register_synthetic_source(sentinel)
    project_before = tuple(
        sorted(
            (
                path.relative_to(external_lab.project).as_posix(),
                path.is_dir(),
                None if path.is_dir() else path.read_bytes(),
            )
            for path in external_lab.project.rglob("*")
        )
    )
    reference_renamed = False
    junction_created = False
    try:
        os.rename(external_lab.reference, original)
        reference_renamed = True
        _controlled_mklink_junction(
            external_lab.reference,
            junction_target,
            external_lab.run_root,
        )
        junction_created = True
        with pytest.raises(ExternalSourceError) as captured:
            external_lab.policy("COPY-S3F-REFERENCE-JUNCTION")

        assert captured.value.code is ExternalSourceCode.REPARSE_POINT
        project_after = tuple(
            sorted(
                (
                    path.relative_to(external_lab.project).as_posix(),
                    path.is_dir(),
                    None if path.is_dir() else path.read_bytes(),
                )
                for path in external_lab.project.rglob("*")
            )
        )
        assert project_after == project_before
    finally:
        if junction_created:
            _remove_expected_reparse(
                external_lab.reference,
                external_lab.run_root,
                reason="s3f-reference-root-junction",
            )
        if reference_renamed:
            os.rename(original, external_lab.reference)

    assert sentinel.read_bytes() == b"reference-root-must-be-preserved"


def test_source_junction_is_rejected_as_reparse(
    external_lab: _ExternalLab,
) -> None:
    source = external_lab.reference / "junction-source"
    junction_target = external_lab.run_root / "source-junction-target"
    junction_target.mkdir()
    _controlled_mklink_junction(source, junction_target, external_lab.run_root)
    policy = external_lab.policy("COPY-S3F-SOURCE-JUNCTION")
    try:
        with pytest.raises(ExternalSourceError) as captured:
            policy.open_reference(source.name)

        assert captured.value.code is ExternalSourceCode.REPARSE_POINT
    finally:
        _remove_expected_reparse(
            source,
            external_lab.run_root,
            reason="s3f-source-junction",
        )


def test_open_source_lease_blocks_write_and_rename_sharing(
    external_lab: _ExternalLab,
) -> None:
    payload = b"immutable-while-lease-live"
    source = external_lab.write("share-fence-source.bin", payload)
    policy = external_lab.policy("COPY-S3F-SHARE-FENCE")
    with policy.open_reference(source.name) as lease:
        with pytest.raises(OSError):
            source.open("r+b")
        with pytest.raises(OSError):
            os.rename(source, external_lab.reference / "share-fence-renamed.bin")
        material = lease.read_once()
        lease.verify_unchanged(material.evidence)

    assert source.read_bytes() == payload


def test_source_lease_is_single_read_and_single_final_verification(
    external_lab: _ExternalLab,
) -> None:
    source = external_lab.write("one-shot-source.bin", b"one-shot")
    with external_lab.policy("COPY-S3F-ONE-SHOT").open_reference(source.name) as lease:
        material = lease.read_once()
        with pytest.raises(ExternalSourceError) as second_read:
            lease.read_once()
        assert second_read.value.code is ExternalSourceCode.CAPABILITY_ALREADY_USED
        lease.verify_unchanged(material.evidence)
        with pytest.raises(ExternalSourceError) as second_verify:
            lease.verify_unchanged(material.evidence)
        assert second_verify.value.code is ExternalSourceCode.CAPABILITY_ALREADY_USED


def test_source_lease_recovery_checkpoint_is_repeatable_but_not_final(
    external_lab: _ExternalLab,
) -> None:
    source = external_lab.write("checkpoint-source.bin", b"checkpoint")
    with external_lab.policy("COPY-S3F-CHECKPOINT").open_reference(source.name) as lease:
        material = lease.read_once()
        with pytest.raises(ExternalSourceError) as cross_route:
            lease._checkpoint_unchanged(
                material.evidence,
                __path_free_capture=lease.verify_unchanged.__code__,
            )
        assert cross_route.value.code is ExternalSourceCode.INTERNAL_FAILURE
        assert lease._state == "READ"
        assert lease._checkpoint_unchanged(material.evidence) is None
        assert lease._checkpoint_unchanged(material.evidence) is None
        lease.verify_unchanged(material.evidence)
        with pytest.raises(ExternalSourceError) as after_final:
            lease._checkpoint_unchanged(material.evidence)
        assert after_final.value.code is ExternalSourceCode.CAPABILITY_ALREADY_USED


def test_policy_cannot_issue_a_second_source(
    external_lab: _ExternalLab,
) -> None:
    first = external_lab.write("policy-once-first.bin", b"first")
    second = external_lab.write("policy-once-second.bin", b"second")
    policy = external_lab.policy("COPY-S3F-POLICY-ONCE")
    with policy.open_reference(first.name) as lease:
        material = lease.read_once()
        lease.verify_unchanged(material.evidence)

    with pytest.raises(ExternalSourceError) as captured:
        policy.open_reference(second.name)

    assert captured.value.code is ExternalSourceCode.CAPABILITY_ALREADY_USED


def test_policy_close_closes_its_consumed_lease_and_is_idempotent(
    external_lab: _ExternalLab,
) -> None:
    source = external_lab.write("policy-close-consumed.bin", b"close-consumed")
    policy = external_lab.policy("COPY-S3F-CLOSE-CONSUMED")
    lease = policy.open_reference(source.name)
    lease.read_once()

    policy.close()
    policy.close()
    lease.close()

    assert policy._state == "CLOSED"
    assert lease._state == "CLOSED"
    assert policy._handles == []
    assert lease._handles == []
    with source.open("r+b") as writable:
        assert writable.read() == b"close-consumed"


def test_policy_is_bound_to_its_issuing_thread(external_lab: _ExternalLab) -> None:
    source = external_lab.write("cross-thread-source.bin", b"thread-bound")
    policy = external_lab.policy("COPY-S3F-CROSS-THREAD")
    errors: list[ExternalSourceError] = []

    def foreign_open() -> None:
        try:
            policy.open_reference(source.name)
        except ExternalSourceError as error:
            errors.append(error)

    thread = threading.Thread(target=foreign_open)
    thread.start()
    thread.join(timeout=10)
    assert not thread.is_alive()
    assert [error.code for error in errors] == [ExternalSourceCode.CAPABILITY_CROSS_THREAD]
    policy.close()


def test_policy_rejects_reused_numeric_thread_ident(
    external_lab: _ExternalLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = external_lab.write("policy-ident-reuse.bin", b"policy-ident-reuse")
    policy = external_lab.policy("COPY-S3F-POLICY-IDENT-REUSE")
    replacement_thread = threading.Thread()
    replacement_thread._ident = policy._owner_thread

    with monkeypatch.context() as reused_identity:
        reused_identity.setattr(
            threading,
            "current_thread",
            lambda: replacement_thread,
        )
        with pytest.raises(ExternalSourceError) as rejected:
            policy.open_reference(source.name)
    assert rejected.value.code is ExternalSourceCode.CAPABILITY_CROSS_THREAD
    assert policy._state == "ISSUED"

    with policy.open_reference(source.name) as lease:
        material = lease.read_once()
        lease.verify_unchanged(material.evidence)


def test_source_lease_rejects_reused_numeric_thread_ident(
    external_lab: _ExternalLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = external_lab.write("lease-ident-reuse.bin", b"lease-ident-reuse")
    policy = external_lab.policy("COPY-S3F-LEASE-IDENT-REUSE")
    with policy.open_reference(source.name) as lease:
        replacement_thread = threading.Thread()
        replacement_thread._ident = lease._owner_thread
        with monkeypatch.context() as reused_identity:
            reused_identity.setattr(
                threading,
                "current_thread",
                lambda: replacement_thread,
            )
            with pytest.raises(ExternalSourceError) as rejected:
                lease.read_once()
        assert rejected.value.code is ExternalSourceCode.CAPABILITY_CROSS_THREAD
        assert lease._state == "OPEN"

        material = lease.read_once()
        lease.verify_unchanged(material.evidence)


def test_repr_and_errors_redact_path_name_ids_and_handle_values(
    external_lab: _ExternalLab,
) -> None:
    source_name = "repr-secret-source.bin"
    copy_id = "COPY-S3F-REPR-SECRET"
    source = external_lab.write(source_name, b"repr-secret")
    policy = external_lab.policy(copy_id, DataClassification.RESTRICTED)
    policy_surface = repr(policy)
    with policy.open_reference(source.name) as lease:
        lease_surface = repr(lease)
        material = lease.read_once()
        material_surface = repr(material) + repr(material.evidence)
        lease.verify_unchanged(material.evidence)

    combined = policy_surface + lease_surface + material_surface
    for forbidden in (
        source_name,
        copy_id,
        str(source),
        str(external_lab.run_root),
    ):
        assert forbidden not in combined
    assert "handle=" not in combined.casefold()


def test_external_error_traceback_has_no_sensitive_library_locals(
    external_lab: _ExternalLab,
) -> None:
    source = external_lab.write(
        "traceback-secret.sqlite",
        b"not actually sqlite",
    )
    policy = external_lab.policy("COPY-S3F-TRACEBACK-REDACTION")

    with pytest.raises(ExternalSourceError) as captured:
        policy.open_reference(source.name)

    assert captured.value.code is ExternalSourceCode.SQLITE_REJECTED
    assert captured.value.__context__ is None
    assert captured.value.__cause__ is None
    surface = SyntheticReferenceReadPolicy.open_reference
    assert not hasattr(surface, "__wrapped__")
    assert surface.__closure__ is None
    assert surface.__defaults__ is None
    assert surface.__kwdefaults__ is None
    frames = _module_traceback_locals(
        captured.value,
        "app.safety.external_source",
    )
    assert frames
    forbidden_keys = {
        "self",
        "arguments",
        "keywords",
        "caught",
        "caught_traceback",
        "function",
        "__path_free_capture",
        "canonical_name",
        "actual_name",
        "source_name",
        "source_path",
        "source_handle",
        "handle",
        "payload",
    }
    for frame_locals in frames:
        assert forbidden_keys.isdisjoint(frame_locals)
        rendered = repr(frame_locals)
        assert source.name not in rendered
        assert str(source) not in rendered
        assert str(external_lab.reference) not in rendered


def test_external_boundary_binder_failure_has_no_chain_and_does_not_consume(
    external_lab: _ExternalLab,
) -> None:
    source = external_lab.write("binder-clean-source.bin", b"binder-clean")
    policy = external_lab.policy("COPY-S3F-BINDER-CLEAN")
    secret_keyword = r"D:\TRACE-CONTEXT-SECRET\payload.bin"

    captured: ExternalSourceError | None = None
    try:
        raise RuntimeError("outer-exception-must-not-become-context")
    except RuntimeError:
        try:
            policy.open_reference(source.name, **{secret_keyword: object()})
        except ExternalSourceError as error:
            captured = error
            assert sys.exc_info()[1] is error
            assert error.code is ExternalSourceCode.INTERNAL_FAILURE
            assert error.__context__ is None
            assert error.__cause__ is None
    assert captured is not None
    assert policy._state == "ISSUED"
    with pytest.raises(ExternalSourceError) as cross_route:
        policy.open_reference(
            source.name,
            __path_free_capture=SyntheticReferenceReadPolicy.close.__code__,
        )
    assert cross_route.value.code is ExternalSourceCode.INTERNAL_FAILURE
    assert cross_route.value.__context__ is None
    assert cross_route.value.__cause__ is None
    assert policy._state == "ISSUED"

    frames = _module_traceback_locals(captured, "app.safety.external_source")
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
        "source_path",
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

    surface = SyntheticReferenceReadPolicy.open_reference
    assert not hasattr(surface, "__wrapped__")
    assert surface.__closure__ is None
    assert surface.__defaults__ is None
    assert surface.__kwdefaults__ is None
    surfaces = _external_boundary_surfaces()
    assert len(surfaces) == external_source_module._EXTERNAL_BOUNDARY_MAX
    assert len({id(candidate.__code__) for candidate in surfaces}) == len(surfaces)
    assert all(candidate.__closure__ is None for candidate in surfaces)
    assert all(candidate.__defaults__ is None for candidate in surfaces)
    assert all(candidate.__kwdefaults__ is None for candidate in surfaces)
    for removed in (
        "_create_external_boundary_runtime",
        "_external_boundary_template",
        "_path_free_exception_boundary",
        "_register_external_boundary",
        "_seal_external_boundaries",
    ):
        assert not hasattr(external_source_module, removed)

    vault = _external_boundary_vault()
    vault_size = len(vault)
    assert vault_size == external_source_module._EXTERNAL_BOUNDARY_MAX
    direct_result = external_source_module._dispatch_external_boundary(
        (policy, source.name),
        {},
    )
    assert type(direct_result).__name__ == "_ExternalBoundaryFailure"
    assert policy._state == "ISSUED"
    assert len(vault) == vault_size

    with policy.open_reference(source.name) as lease:
        material = lease.read_once()
        lease.verify_unchanged(material.evidence)


def test_authority_and_returned_objects_cannot_be_pickled(
    external_lab: _ExternalLab,
) -> None:
    source = external_lab.write("pickle-source.bin", b"pickle")
    policy = external_lab.policy("COPY-S3F-PICKLE")
    with pytest.raises(TypeError):
        pickle.dumps(policy)
    with policy.open_reference(source.name) as lease:
        with pytest.raises(TypeError):
            pickle.dumps(lease)
        material = lease.read_once()
        verification = lease.verify_unchanged(material.evidence)
    for value in (material, material.evidence, verification):
        with pytest.raises(TypeError):
            pickle.dumps(value)


def test_copy_id_and_classification_are_bound_without_plaintext_disclosure(
    external_lab: _ExternalLab,
) -> None:
    source = external_lab.write("binding-source.bin", b"binding")
    evidence: list[SyntheticSourceEvidence] = []
    for copy_id, classification in (
        ("COPY-S3F-BIND-A", DataClassification.INTERNAL),
        ("COPY-S3F-BIND-B", DataClassification.INTERNAL),
        ("COPY-S3F-BIND-A", DataClassification.RESTRICTED),
    ):
        with external_lab.policy(copy_id, classification).open_reference(
            source.name
        ) as lease:
            material = lease.read_once()
            lease.verify_unchanged(material.evidence)
            evidence.append(material.evidence)

    assert len({item.locator_hmac for item in evidence}) == 3
    assert len({item.capability_binding_digest for item in evidence}) == 3


def test_copy_execution_permit_is_exact_bound_thread_local_and_one_shot(
    external_lab: _ExternalLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    copy_id = "COPY-S3F-EXECUTION-PERMIT"
    source = external_lab.write("execution-permit.bin", b"permit-bound-source")
    policy = external_lab.policy(copy_id)
    operation_authority = object()
    bindings = {
        "operation_authority": operation_authority,
        "operation_identity_sha256": hashlib.sha256(b"operation").hexdigest(),
        "context_sha256": hashlib.sha256(b"context").hexdigest(),
        "manifest_sha256": hashlib.sha256(b"manifest").hexdigest(),
        "budget_sha256": hashlib.sha256(b"budget").hexdigest(),
        "target_sha256": hashlib.sha256(b"target").hexdigest(),
        "copy_id": copy_id,
        "classification": DataClassification.INTERNAL,
    }
    with policy.open_reference(source.name) as lease:
        material = lease.read_once()
        permit = _issue_copy_execution_permit(
            policy,
            lease,
            material.evidence,
            **bindings,
        )

        assert type(permit) is _CopyExecutionPermit
        assert copy_id not in repr(permit)
        with pytest.raises(TypeError):
            pickle.dumps(permit)
        _validate_copy_execution_permit(
            permit,
            policy,
            lease,
            material.evidence,
            **bindings,
        )

        binder_bindings = dict(bindings)
        binder_bindings["__path_free_capture"] = (
            _consume_copy_execution_permit.__code__
        )
        with pytest.raises(ExternalSourceError) as binder_rejected:
            _validate_copy_execution_permit(
                permit,
                policy,
                lease,
                material.evidence,
                **binder_bindings,
            )
        assert binder_rejected.value.code is ExternalSourceCode.INTERNAL_FAILURE
        assert binder_rejected.value.__context__ is None
        assert binder_rejected.value.__cause__ is None
        assert permit._state == "ISSUED"

        for field in (
            "operation_identity_sha256",
            "context_sha256",
            "manifest_sha256",
            "budget_sha256",
            "target_sha256",
        ):
            mismatched = dict(bindings)
            mismatched[field] = hashlib.sha256(
                f"wrong-{field}".encode("ascii")
            ).hexdigest()
            with pytest.raises(ExternalSourceError) as rejected:
                _validate_copy_execution_permit(
                    permit,
                    policy,
                    lease,
                    material.evidence,
                    **mismatched,
                )
            assert rejected.value.code is ExternalSourceCode.INVALID_REQUEST

        thread_errors: list[ExternalSourceError] = []

        def cross_thread_validate() -> None:
            try:
                _validate_copy_execution_permit(
                    permit,
                    policy,
                    lease,
                    material.evidence,
                    **bindings,
                )
            except ExternalSourceError as error:
                thread_errors.append(error)

        worker = threading.Thread(target=cross_thread_validate)
        worker.start()
        worker.join()
        assert [error.code for error in thread_errors] == [
            ExternalSourceCode.CAPABILITY_CROSS_THREAD
        ]

        original_owner_object = permit._owner_thread_object
        assert policy._owner_thread_object is original_owner_object
        assert lease._owner_thread_object is original_owner_object
        replacement_thread = threading.Thread()
        replacement_thread._ident = permit._owner_thread
        with monkeypatch.context() as reused_identity:
            reused_identity.setattr(
                threading,
                "current_thread",
                lambda: replacement_thread,
            )
            with pytest.raises(ExternalSourceError) as reused:
                _validate_copy_execution_permit(
                    permit,
                    policy,
                    lease,
                    material.evidence,
                    **bindings,
                )
        assert reused.value.code is ExternalSourceCode.CAPABILITY_CROSS_THREAD
        assert permit._state == "ISSUED"

        policy._owner_thread_object = replacement_thread
        lease._owner_thread_object = replacement_thread
        permit._owner_thread_object = replacement_thread
        try:
            with monkeypatch.context() as rebound_identity:
                rebound_identity.setattr(
                    threading,
                    "current_thread",
                    lambda: replacement_thread,
                )
                with pytest.raises(ExternalSourceError) as rebound:
                    _validate_copy_execution_permit(
                        permit,
                        policy,
                        lease,
                        material.evidence,
                        **bindings,
                    )
            assert rebound.value.code is ExternalSourceCode.INVALID_REQUEST
            assert permit._state == "ISSUED"
        finally:
            policy._owner_thread_object = original_owner_object
            lease._owner_thread_object = original_owner_object
            permit._owner_thread_object = original_owner_object

        _consume_copy_execution_permit(
            permit,
            policy,
            lease,
            material.evidence,
            **bindings,
        )
        with pytest.raises(ExternalSourceError) as reused:
            _consume_copy_execution_permit(
                permit,
                policy,
                lease,
                material.evidence,
                **bindings,
            )
        assert reused.value.code is ExternalSourceCode.CAPABILITY_ALREADY_USED
        lease.verify_unchanged(material.evidence)


def test_copy_execution_permit_rejects_nonlease_exactly(
    external_lab: _ExternalLab,
) -> None:
    copy_id = "COPY-S3F-EXECUTION-FAKE-LEASE"
    source = external_lab.write("execution-fake-lease.bin", b"exact-lease-required")
    policy = external_lab.policy(copy_id)
    with policy.open_reference(source.name) as lease:
        material = lease.read_once()
        with pytest.raises(ExternalSourceError) as rejected:
            _issue_copy_execution_permit(
                policy,
                object(),  # type: ignore[arg-type]
                material.evidence,
                operation_authority=object(),
                operation_identity_sha256=hashlib.sha256(b"operation").hexdigest(),
                context_sha256=hashlib.sha256(b"context").hexdigest(),
                manifest_sha256=hashlib.sha256(b"manifest").hexdigest(),
                budget_sha256=hashlib.sha256(b"budget").hexdigest(),
                target_sha256=hashlib.sha256(b"target").hexdigest(),
                copy_id=copy_id,
                classification=DataClassification.INTERNAL,
            )
        assert rejected.value.code is ExternalSourceCode.INVALID_FACTORY
        lease.verify_unchanged(material.evidence)


def test_read_api_has_no_writer_or_mutation_surface() -> None:
    forbidden = {
        "append",
        "create_relative_directory",
        "create_relative_file",
        "publish",
        "rename_by_handle_no_replace",
        "replace",
        "write",
    }
    assert forbidden.isdisjoint(set(dir(_ReferenceReadApi)))
    with pytest.raises(TypeError):
        _ReferenceReadApi(_constructor=object())


def test_direct_policy_construction_is_forbidden() -> None:
    with pytest.raises(TypeError):
        SyntheticReferenceReadPolicy(  # type: ignore[call-arg]
            api=object(),
            handles=[],
            reference_root=Path("."),
            run_id="RUN-FORGED",
            copy_id="COPY-FORGED",
            classification=DataClassification.INTERNAL,
            locator_key=b"x" * 32,
            marker_digest="0" * 64,
            _constructor=object(),
        )
