from __future__ import annotations

import gzip
import hashlib
import json
import os
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest
import scripts.run_safe_pytest as launcher_module

from scripts.run_safe_pytest import (
    RUN_ID_PATTERN,
    RUN_RESULT_SCHEMA_VERSION,
    PROTECTED_TREE_SNAPSHOT_FORMAT,
    SOURCE_WITNESS_FILE_NAME,
    SOURCE_WITNESS_SCHEMA_VERSION,
    SOURCE_WITNESS_SCOPE,
    SOURCE_WITNESS_SOURCE_MAX_BYTES,
    SOURCE_REGISTRATION_REQUIRED_MODES,
    SafetyStop,
    _WindowsJob,
    _WindowsProtectedTreeFence,
    _WindowsProtectedTreeWatcher,
    _build_command,
    _canonical_json_bytes,
    _effective_exit_code,
    _junit_evidence,
    _protected_tree_snapshot,
    _registered_source_count_gate,
    _regular_file_evidence,
    _relative_parts,
    _run_test_process,
    _sign_source_witness_payload,
    _snapshot_changes,
    _source_witness_evidence,
    _source_witness_locator_id,
    _validate_source_witness_bytes,
    _verify_run_tree_no_reparse,
    _windows_extended_path,
    _write_gzip_json_exclusive,
    _write_json_exclusive,
    main,
)
from tests.conftest import register_synthetic_source


def _pid_is_running(pid: int) -> bool:
    if os.name != "nt":
        try:
            os.kill(pid, 0)
        except OSError:
            return False
        return True
    import ctypes

    synchronize = 0x00100000
    wait_timeout = 0x00000102
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
    kernel32.WaitForSingleObject.restype = ctypes.c_ulong
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int
    handle = kernel32.OpenProcess(synchronize, False, pid)
    if not handle:
        return False
    try:
        return int(kernel32.WaitForSingleObject(handle, 0)) == wait_timeout
    finally:
        kernel32.CloseHandle(handle)


def _wait_until_pid_stops(pid: int, timeout_seconds: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while _pid_is_running(pid):
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.05)
    return True


def _source_witness_test_document(
    *,
    run_id: str,
    launch_token: str,
    locator_input: str,
    source_payload: bytes,
    changed: bool = False,
) -> dict[str, Any]:
    parent = {
        "device": 1,
        "inode": 100,
        "mode": stat.S_IFDIR | 0o755,
        "file_attributes": 0,
        "reparse_tag": 0,
    }
    source_before = {
        "device": 1,
        "inode": 200,
        "mode": stat.S_IFREG | 0o600,
        "file_attributes": 0,
        "reparse_tag": 0,
        "nlink": 1,
        "size": len(source_payload),
        "mtime_ns": 123_456_789,
        "sha256": hashlib.sha256(source_payload).hexdigest(),
        "default_stream_only": True,
    }
    source_after = dict(source_before)
    if changed:
        source_after["mtime_ns"] += 1
        source_after["sha256"] = hashlib.sha256(
            source_payload + b"-changed"
        ).hexdigest()
        source_after["size"] += len(b"-changed")
    entry = {
        "source_id": _source_witness_locator_id(locator_input, launch_token),
        "parent_before": parent,
        "source_before": source_before,
        "parent_after": dict(parent),
        "source_after": source_after,
        "final_state_matches_registration": not changed,
    }
    unsigned = {
        "schema_version": SOURCE_WITNESS_SCHEMA_VERSION,
        "run_id": run_id,
        "launch_token_sha256": hashlib.sha256(
            launch_token.encode("utf-8")
        ).hexdigest(),
        "source_count": 1,
        "matching_final_state_count": 0 if changed else 1,
        "mismatched_final_state_count": 1 if changed else 0,
        "witness_scope": SOURCE_WITNESS_SCOPE,
        "registered_source_final_state_matches": not changed,
        "sources": [entry],
    }
    return _sign_source_witness_payload(unsigned, launch_token)


def _source_witness_test_bytes(document: dict[str, Any]) -> bytes:
    return _canonical_json_bytes(document) + b"\n"


@pytest.mark.parametrize(
    "run_id",
    [
        r"RUN-..\BASE",
        "RUN-../BASE",
        r"D:\RUN-ESCAPE",
        "RUN-WITH SPACE",
        "not-a-run",
        "",
    ],
)
def test_launcher_rejects_path_syntax_in_run_id_without_writing(run_id: str) -> None:
    with pytest.raises(SafetyStop):
        main(["--run-id", run_id, "--mode", "full"])


def test_run_id_contract_accepts_a_unique_safe_identifier() -> None:
    assert RUN_ID_PATTERN.fullmatch("RUN-20260711-M0-S1-UNIT-001")


def test_launcher_root_authority_is_bound_before_runtime_monkeypatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = launcher_module._verified_launcher_root()
    monkeypatch.setattr(
        launcher_module,
        "VERIFIED_PROJECT_ROOT",
        expected.parent,
    )

    assert launcher_module._verified_launcher_root() == expected


def test_evidence_json_round_trips_an_unpaired_utf16_code_unit(
    tmp_path: Path,
) -> None:
    evidence = tmp_path / "evidence.json"
    value = "malformed-\udedf-name"

    _write_json_exclusive(evidence, {"value": value})

    raw = evidence.read_bytes()
    assert b"\\udedf" in raw
    assert json.loads(raw)["value"] == value


def test_protected_snapshot_is_deterministic_compressed_and_exclusive(
    tmp_path: Path,
) -> None:
    first = tmp_path / "first.json.gz"
    second = tmp_path / "second.json.gz"
    payload = {
        "schema_version": "1.0",
        "entry_count": 1,
        "entries": {"F:中文.txt": {"kind": "file", "sha256": "a" * 64}},
    }

    _write_gzip_json_exclusive(first, payload)
    _write_gzip_json_exclusive(second, payload)

    assert PROTECTED_TREE_SNAPSHOT_FORMAT == "gzip-canonical-json-v1"
    assert first.read_bytes() == second.read_bytes()
    assert json.loads(gzip.decompress(first.read_bytes())) == payload
    with pytest.raises(FileExistsError):
        _write_gzip_json_exclusive(first, payload)


def test_source_witness_is_canonical_authenticated_and_path_redacted() -> None:
    run_id = "RUN-SOURCE-WITNESS-UNIT-001"
    launch_token = "source-witness-unit-token"
    source_path = r"D:\AAA命题\Test\tmp\test_lab\RUN-X\external\REFERENCE\secret.bin"
    source_name = "secret.bin"
    source_payload = b"private synthetic source payload"
    document = _source_witness_test_document(
        run_id=run_id,
        launch_token=launch_token,
        locator_input=source_path.casefold(),
        source_payload=source_payload,
    )
    raw = _source_witness_test_bytes(document)

    details = _validate_source_witness_bytes(
        raw,
        run_id=run_id,
        launch_token=launch_token,
    )

    assert details["source_count"] == 1
    assert details["matching_final_state_count"] == 1
    assert details["mismatched_final_state_count"] == 0
    assert details["witness_scope"] == SOURCE_WITNESS_SCOPE
    assert details["registered_source_final_state_matches"] is True
    assert details["mismatched_source_ids"] == []
    assert raw == _canonical_json_bytes(json.loads(raw)) + b"\n"
    for forbidden in (
        source_path.encode("utf-8"),
        source_name.encode("utf-8"),
        source_payload,
        launch_token.encode("utf-8"),
    ):
        assert forbidden not in raw

    changed_document = _source_witness_test_document(
        run_id=run_id,
        launch_token=launch_token,
        locator_input=source_path.casefold(),
        source_payload=source_payload,
        changed=True,
    )
    changed_details = _validate_source_witness_bytes(
        _source_witness_test_bytes(changed_document),
        run_id=run_id,
        launch_token=launch_token,
    )
    assert changed_details["registered_source_final_state_matches"] is False
    assert changed_details["mismatched_final_state_count"] == 1
    assert changed_details["mismatched_source_ids"] == [
        changed_document["sources"][0]["source_id"]
    ]

    zero_source_document = _sign_source_witness_payload(
        {
            "schema_version": SOURCE_WITNESS_SCHEMA_VERSION,
            "run_id": run_id,
            "launch_token_sha256": hashlib.sha256(
                launch_token.encode("utf-8")
            ).hexdigest(),
            "source_count": 0,
            "matching_final_state_count": 0,
            "mismatched_final_state_count": 0,
            "witness_scope": SOURCE_WITNESS_SCOPE,
            "registered_source_final_state_matches": True,
            "sources": [],
        },
        launch_token,
    )
    zero_source_details = _validate_source_witness_bytes(
        _source_witness_test_bytes(zero_source_document),
        run_id=run_id,
        launch_token=launch_token,
    )
    assert zero_source_details["source_count"] == 0
    assert zero_source_details["registered_source_final_state_matches"] is True


def test_source_witness_rejects_tamper_and_authenticated_inconsistency() -> None:
    run_id = "RUN-SOURCE-WITNESS-UNIT-002"
    launch_token = "source-witness-structure-token"
    document = _source_witness_test_document(
        run_id=run_id,
        launch_token=launch_token,
        locator_input="opaque-locator-input",
        source_payload=b"source-bytes",
    )

    tampered = json.loads(json.dumps(document))
    tampered["source_count"] = 2
    with pytest.raises(SafetyStop, match="HMAC authentication"):
        _validate_source_witness_bytes(
            _source_witness_test_bytes(tampered),
            run_id=run_id,
            launch_token=launch_token,
        )

    with pytest.raises(SafetyStop, match="launch token"):
        _validate_source_witness_bytes(
            _source_witness_test_bytes(document),
            run_id=run_id,
            launch_token="different-token",
        )

    with pytest.raises(SafetyStop, match="run ID"):
        _validate_source_witness_bytes(
            _source_witness_test_bytes(document),
            run_id="RUN-SOURCE-WITNESS-DIFFERENT",
            launch_token=launch_token,
        )

    noncanonical = json.dumps(document, sort_keys=True).encode("ascii") + b"\n"
    with pytest.raises(SafetyStop, match="not canonical"):
        _validate_source_witness_bytes(
            noncanonical,
            run_id=run_id,
            launch_token=launch_token,
        )

    def resign(mutated: dict[str, Any]) -> dict[str, Any]:
        unsigned = {
            key: value for key, value in mutated.items() if key != "hmac_sha256"
        }
        return _sign_source_witness_payload(unsigned, launch_token)

    wrong_schema = json.loads(json.dumps(document))
    wrong_schema["schema_version"] = "2.0"
    with pytest.raises(SafetyStop, match="schema version"):
        _validate_source_witness_bytes(
            _source_witness_test_bytes(resign(wrong_schema)),
            run_id=run_id,
            launch_token=launch_token,
        )

    wrong_count = json.loads(json.dumps(document))
    wrong_count["source_count"] = 2
    with pytest.raises(SafetyStop, match="source count is inconsistent"):
        _validate_source_witness_bytes(
            _source_witness_test_bytes(resign(wrong_count)),
            run_id=run_id,
            launch_token=launch_token,
        )

    wrong_state = json.loads(json.dumps(document))
    wrong_state["sources"][0]["final_state_matches_registration"] = False
    with pytest.raises(SafetyStop, match="entry final-match state is inconsistent"):
        _validate_source_witness_bytes(
            _source_witness_test_bytes(resign(wrong_state)),
            run_id=run_id,
            launch_token=launch_token,
        )

    wrong_scope = json.loads(json.dumps(document))
    wrong_scope["witness_scope"] = "CONTINUOUS_RUNTIME_IMMUTABILITY"
    with pytest.raises(SafetyStop, match="guarantee scope"):
        _validate_source_witness_bytes(
            _source_witness_test_bytes(resign(wrong_scope)),
            run_id=run_id,
            launch_token=launch_token,
        )

    wrong_stream = json.loads(json.dumps(document))
    wrong_stream["sources"][0]["source_before"]["default_stream_only"] = False
    wrong_stream["sources"][0]["source_after"]["default_stream_only"] = False
    with pytest.raises(SafetyStop, match="eligible source file"):
        _validate_source_witness_bytes(
            _source_witness_test_bytes(resign(wrong_stream)),
            run_id=run_id,
            launch_token=launch_token,
        )

    plaintext_extension = json.loads(json.dumps(document))
    plaintext_extension["sources"][0]["path"] = r"D:\forbidden\source.bin"
    with pytest.raises(SafetyStop, match="invalid field set"):
        _validate_source_witness_bytes(
            _source_witness_test_bytes(resign(plaintext_extension)),
            run_id=run_id,
            launch_token=launch_token,
        )


def test_source_witness_file_gate_requires_present_single_link_default_stream(
    tmp_path: Path,
) -> None:
    run_id = "RUN-SOURCE-WITNESS-FILE-001"
    launch_token = "source-witness-file-token"
    run_root = tmp_path / run_id
    run_root.mkdir()
    witness = run_root / SOURCE_WITNESS_FILE_NAME
    document = _source_witness_test_document(
        run_id=run_id,
        launch_token=launch_token,
        locator_input="file-gate-locator",
        source_payload=b"file-gate-source",
    )

    with pytest.raises(SafetyStop):
        _source_witness_evidence(
            run_root,
            run_id=run_id,
            launch_token=launch_token,
        )

    witness.write_bytes(_source_witness_test_bytes(document))
    details = _source_witness_evidence(
        run_root,
        run_id=run_id,
        launch_token=launch_token,
    )
    assert details["registered_source_final_state_matches"] is True

    alias = run_root / "witness-alias.json"
    os.link(witness, alias)
    try:
        with pytest.raises(SafetyStop, match="exactly one hard link"):
            _source_witness_evidence(
                run_root,
                run_id=run_id,
                launch_token=launch_token,
            )
    finally:
        alias.unlink()

    alternate_stream = f"{witness}:forged"
    with open(alternate_stream, "wb") as handle:
        handle.write(b"not-default-stream")
    try:
        with pytest.raises(SafetyStop, match="alternate data stream"):
            _source_witness_evidence(
                run_root,
                run_id=run_id,
                launch_token=launch_token,
            )
    finally:
        os.remove(alternate_stream)


def test_source_witness_registration_rejects_ads_and_supports_over_64_mib() -> None:
    assert SOURCE_WITNESS_SOURCE_MAX_BYTES >= 64 * 1024 * 1024 + 1
    run_root = Path(os.environ["M0_TEST_LAB_ROOT"])
    source_root = run_root / "external" / "witness-api-unit"
    source_root.mkdir(parents=True, exist_ok=True)
    source = source_root / "registered-source.bin"
    source.write_bytes(b"registered source remains unchanged")
    alternate_stream = f"{source}:forged"
    with open(alternate_stream, "wb") as handle:
        handle.write(b"alternate stream must not be witnessed as safe")
    try:
        with pytest.raises(pytest.UsageError, match="stable single-link"):
            register_synthetic_source(source)
    finally:
        os.remove(alternate_stream)

    source_id = register_synthetic_source(source)
    assert len(source_id) == 64
    assert register_synthetic_source(source) == source_id
    assert source.name not in source_id
    assert str(source) not in source_id


def test_source_witness_registration_does_not_retain_a_share_fence() -> None:
    run_root = Path(os.environ["M0_TEST_LAB_ROOT"])
    source_root = run_root / "external" / "witness-share-unit"
    source_root.mkdir(parents=True, exist_ok=True)
    source = source_root / "share-source.bin"
    alias = source_root / "share-alias.bin"
    renamed = source_root / "share-renamed.bin"
    source.write_bytes(b"registration must release every observation handle")
    register_synthetic_source(source)

    os.link(source, alias)
    alias.unlink()
    source.rename(renamed)
    renamed.rename(source)

    assert source.read_bytes() == b"registration must release every observation handle"
    assert source.stat().st_nlink == 1


def test_component_containment_rejects_test2_prefix(tmp_path: Path) -> None:
    allowed = tmp_path / "Test"
    sibling = tmp_path / "Test2" / "RUN-SAFE-001"
    candidate = allowed / "RUN-SAFE-001"

    assert _relative_parts(candidate, allowed) == ("RUN-SAFE-001",)
    assert _relative_parts(sibling, allowed) is None


def test_launcher_builds_fixed_test_local_outputs(tmp_path: Path) -> None:
    run_root = tmp_path / "RUN-SAFE-001"
    run_root.mkdir()

    command, basetemp, junit = _build_command(
        tmp_path,
        run_root,
        mode="guard",
        exclude_symlink=True,
    )

    assert basetemp == run_root / "pytest-basetemp"
    assert junit == run_root / "junit.xml"
    assert "tests/test_workspace_guard.py" in command
    assert "--basetemp" in command
    assert "--junitxml" in command
    assert "no:cacheprovider" in command
    assert "not test_real_directory_symlink_is_rejected" in command


def test_writer_mode_has_a_fixed_non_injectable_regression_selection(
    tmp_path: Path,
) -> None:
    run_root = tmp_path / "RUN-WRITER-MODE"
    run_root.mkdir()

    command, basetemp, junit = _build_command(
        tmp_path,
        run_root,
        mode="writer",
        exclude_symlink=True,
    )

    assert basetemp == run_root / "pytest-basetemp"
    assert junit == run_root / "junit.xml"
    assert command == [
        sys.executable,
        "-m",
        "pytest",
        "tests/test_windows_handle_writer.py",
        "tests/test_segment_ledger.py",
        "tests/test_job_operation.py",
        "tests/test_workspace_guard.py",
        "tests/test_workspace_policy.py",
        "tests/test_write_entry_inventory.py",
        "tests/test_safe_pytest_launcher.py",
        "-q",
        "-p",
        "no:cacheprovider",
        "-k",
        "not test_real_directory_symlink_is_rejected",
        "--basetemp",
        str(basetemp),
        "--junitxml",
        str(junit),
    ]


def test_s3d_mode_has_a_fixed_non_injectable_selection(tmp_path: Path) -> None:
    run_root = tmp_path / "RUN-S3D-MODE"
    run_root.mkdir()
    command, _basetemp, _junit = _build_command(
        tmp_path,
        run_root,
        mode="s3d",
        exclude_symlink=True,
    )
    assert command[3:6] == [
        "tests/test_job_operation.py",
        "tests/test_windows_handle_writer.py",
        "tests/test_segment_ledger.py",
    ]


@pytest.mark.parametrize(
    ("mode", "selection"),
    (
        ("s3e_core", ["tests/test_publish_operation.py"]),
        (
            "s3e",
            [
                "tests/test_publish_operation.py",
                "tests/test_job_operation.py",
                "tests/test_windows_handle_writer.py",
                "tests/test_segment_ledger.py",
                "tests/test_workspace_policy.py",
                "tests/test_write_entry_inventory.py",
            ],
        ),
        (
            "s3f_core",
            [
                "tests/test_copy_operation.py",
                "tests/test_copy_ledger.py",
                "tests/test_policy_epoch_compatibility.py",
                "tests/test_external_source.py",
            ],
        ),
        (
            "s3f",
            [
                "tests/test_copy_operation.py",
                "tests/test_copy_ledger.py",
                "tests/test_policy_epoch_compatibility.py",
                "tests/test_external_source.py",
                "tests/test_publish_operation.py",
                "tests/test_job_operation.py",
                "tests/test_windows_handle_writer.py",
                "tests/test_segment_ledger.py",
                "tests/test_workspace_policy.py",
                "tests/test_write_entry_inventory.py",
            ],
        ),
        ("s3g_core", ["tests/test_quarantine_restore_operation.py"]),
        (
            "s3g",
            [
                "tests/test_quarantine_restore_operation.py",
                "tests/test_publish_operation.py",
                "tests/test_job_operation.py",
                "tests/test_windows_handle_writer.py",
                "tests/test_segment_ledger.py",
                "tests/test_workspace_policy.py",
                "tests/test_write_entry_inventory.py",
            ],
        ),
        (
            "s3h_core",
            [
                "tests/test_publish_operation.py::test_s3h_crash_race_truth_table_is_complete_and_unambiguous",
                "tests/test_publish_operation.py::test_real_process_publish_crash_points_reconcile_once",
                "tests/test_publish_operation.py::test_target_race_after_prepared_aborts_without_overwrite",
                "tests/test_policy_epoch_compatibility.py",
                "tests/test_job_operation.py::test_two_process_mutex_busy_rolls_back_pin_and_same_context_retries",
                "tests/test_windows_handle_writer.py::test_publish_source_share_blocks_external_path_rename_before_publish",
                "tests/test_windows_handle_writer.py::test_publish_after_rename_failure_keeps_valid_final_and_seals",
                "tests/test_write_entry_inventory.py::test_tracked_inventory_matches_full_current_scanner_and_source_manifest",
                "tests/test_write_entry_inventory.py::test_source_manifest_is_checkout_independent_utf8_lf",
                "tests/test_write_entry_inventory.py::test_inventory_counts_and_policy_metadata_are_internally_consistent",
                "tests/test_write_entry_inventory.py::test_full_digests_cover_policy_metadata_and_are_key_order_stable",
                "tests/test_write_entry_inventory.py::test_no_current_production_module_bypasses_fixed_boundary",
            ],
        ),
        (
            "s3h",
            [
                "tests/test_publish_operation.py",
                "tests/test_policy_epoch_compatibility.py",
                "tests/test_copy_operation.py",
                "tests/test_copy_ledger.py",
                "tests/test_external_source.py",
                "tests/test_quarantine_restore_operation.py",
                "tests/test_job_operation.py",
                "tests/test_windows_handle_writer.py",
                "tests/test_segment_ledger.py",
                "tests/test_workspace_policy.py",
                "tests/test_write_entry_inventory.py",
            ],
        ),
        (
            "s4_core",
            [
                "tests/test_database_migrations.py",
                "tests/test_database_backup.py",
                "tests/test_database.py",
                "tests/test_import_batches.py",
                "tests/test_structured_ai.py",
                "tests/test_web.py",
            ],
        ),
        (
            "s4",
            [
                "tests/test_database_migrations.py",
                "tests/test_database_backup.py",
                "tests/test_database.py",
                "tests/test_import_batches.py",
                "tests/test_structured_ai.py",
                "tests/test_web.py",
                "tests/test_workspace_policy.py",
                "tests/test_write_entry_inventory.py",
                "tests/test_safe_pytest_launcher.py",
            ],
        ),
        (
            "s5_core",
            [
                "tests/test_domain_models.py",
                "tests/test_ir_contracts.py",
                "tests/test_gold_registry.py",
            ],
        ),
        (
            "s5",
            [
                "tests/test_domain_models.py",
                "tests/test_ir_contracts.py",
                "tests/test_gold_registry.py",
                "tests/test_workspace_policy.py",
                "tests/test_write_entry_inventory.py",
                "tests/test_safe_pytest_launcher.py",
            ],
        ),
        (
            "s6_core",
            [
                "tests/test_workspace_io.py",
                "tests/test_source_copy.py",
                "tests/test_database.py",
                "tests/test_database_migrations.py",
                "tests/test_database_backup.py",
                "tests/test_codex_structure.py",
                "tests/test_pdf_import.py",
                "tests/test_pdf_scan.py",
                "tests/test_stage7_quality.py",
                "tests/test_stage9_report.py",
                "tests/test_stage10.py",
                "tests/test_stage11.py",
                "tests/test_stage12.py",
                "tests/test_stage13.py",
                "tests/test_stage14.py",
                "tests/test_web.py",
            ],
        ),
        (
            "s6",
            [
                "tests/test_workspace_io.py",
                "tests/test_source_copy.py",
                "tests/test_database.py",
                "tests/test_database_migrations.py",
                "tests/test_database_backup.py",
                "tests/test_copy_operation.py",
                "tests/test_copy_ledger.py",
                "tests/test_external_source.py",
                "tests/test_gold_registry.py",
                "tests/test_workspace_policy.py",
                "tests/test_write_entry_inventory.py",
                "tests/test_safe_pytest_launcher.py",
            ],
        ),
        (
            "m1_core",
            [
                "tests/test_m1_pipeline.py",
                "tests/test_question_split.py",
                "tests/test_pdf_scan.py",
                "tests/test_pdf_import.py",
                "tests/test_ir_contracts.py",
                "tests/test_database.py",
                "tests/test_web.py",
            ],
        ),
        (
            "m1",
            [
                "tests/test_m1_pipeline.py",
                "tests/test_question_split.py",
                "tests/test_pdf_scan.py",
                "tests/test_pdf_import.py",
                "tests/test_ir_contracts.py",
                "tests/test_database.py",
                "tests/test_web.py",
                "tests/test_workspace_io.py",
                "tests/test_workspace_policy.py",
                "tests/test_write_entry_inventory.py",
                "tests/test_safe_pytest_launcher.py",
            ],
        ),
        (
            "m2_core",
            [
                "tests/test_m2_pipeline.py",
                "tests/test_domain_models.py",
                "tests/test_ir_contracts.py",
                "tests/test_database.py",
                "tests/test_web.py",
            ],
        ),
        (
            "m2",
            [
                "tests/test_m2_pipeline.py",
                "tests/test_m1_pipeline.py",
                "tests/test_domain_models.py",
                "tests/test_ir_contracts.py",
                "tests/test_database.py",
                "tests/test_web.py",
                "tests/test_workspace_io.py",
                "tests/test_workspace_policy.py",
                "tests/test_write_entry_inventory.py",
                "tests/test_safe_pytest_launcher.py",
            ],
        ),
        (
            "m3_core",
            [
                "tests/test_m3_pipeline.py",
                "tests/test_domain_models.py",
                "tests/test_ir_contracts.py",
                "tests/test_database.py",
                "tests/test_web.py",
            ],
        ),
        (
            "m3",
            [
                "tests/test_m3_pipeline.py",
                "tests/test_m2_pipeline.py",
                "tests/test_m1_pipeline.py",
                "tests/test_domain_models.py",
                "tests/test_ir_contracts.py",
                "tests/test_database.py",
                "tests/test_web.py",
                "tests/test_workspace_io.py",
                "tests/test_workspace_policy.py",
                "tests/test_write_entry_inventory.py",
                "tests/test_safe_pytest_launcher.py",
            ],
        ),
        (
            "m4_core",
            [
                "tests/test_m4_backup.py",
                "tests/test_m3_pipeline.py",
                "tests/test_m2_pipeline.py",
                "tests/test_m1_pipeline.py",
                "tests/test_database_backup.py",
                "tests/test_database_migrations.py",
                "tests/test_domain_models.py",
                "tests/test_ir_contracts.py",
                "tests/test_database.py",
                "tests/test_web.py",
            ],
        ),
        (
            "m4",
            [
                "tests/test_m4_backup.py",
                "tests/test_m3_pipeline.py",
                "tests/test_m2_pipeline.py",
                "tests/test_m1_pipeline.py",
                "tests/test_database_backup.py",
                "tests/test_database_migrations.py",
                "tests/test_domain_models.py",
                "tests/test_ir_contracts.py",
                "tests/test_database.py",
                "tests/test_web.py",
                "tests/test_workspace_io.py",
                "tests/test_workspace_policy.py",
                "tests/test_write_entry_inventory.py",
                "tests/test_safe_pytest_launcher.py",
            ],
        ),
    ),
)
def test_s3e_through_s6_modes_have_exact_non_injectable_selections(
    tmp_path: Path,
    mode: str,
    selection: list[str],
) -> None:
    run_root = tmp_path / f"RUN-{mode.upper()}-MODE"
    run_root.mkdir()
    command, basetemp, junit = _build_command(
        tmp_path,
        run_root,
        mode=mode,
        exclude_symlink=False,
    )
    assert command == [
        sys.executable,
        "-m",
        "pytest",
        *selection,
        "-q",
        "-p",
        "no:cacheprovider",
        "--basetemp",
        str(basetemp),
        "--junitxml",
        str(junit),
    ]


def test_launcher_refuses_to_reuse_existing_basetemp(tmp_path: Path) -> None:
    run_root = tmp_path / "RUN-SAFE-002"
    run_root.mkdir()
    (run_root / "pytest-basetemp").mkdir()

    with pytest.raises(SafetyStop, match="must not exist"):
        _build_command(
            tmp_path,
            run_root,
            mode="full",
            exclude_symlink=False,
        )


def test_symlink_mode_cannot_hide_its_only_gate(tmp_path: Path) -> None:
    run_root = tmp_path / "RUN-SAFE-003"
    run_root.mkdir()

    with pytest.raises(SafetyStop, match="cannot exclude"):
        _build_command(
            tmp_path,
            run_root,
            mode="symlink",
            exclude_symlink=True,
        )


def test_protected_tree_snapshot_detects_new_source_and_sqlite_sidecar(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    run_root = project / "tmp" / "test_lab" / "RUN-SAFE-004"
    run_root.mkdir(parents=True)
    database = project / "data" / "db" / "question_bank.sqlite3"
    database.parent.mkdir(parents=True)
    database.write_bytes(b"main")
    app_file = project / "app" / "module.py"
    app_file.parent.mkdir()
    app_file.write_text("VALUE = 1\n", encoding="utf-8")

    before = _protected_tree_snapshot(project, excluded_root=run_root)
    (database.parent / "question_bank.sqlite3-wal").write_bytes(b"wal")
    (app_file.parent / "new_module.py").write_text("VALUE = 2\n", encoding="utf-8")
    after = _protected_tree_snapshot(project, excluded_root=run_root)

    changed = _snapshot_changes(before, after)
    assert "F:data/db/question_bank.sqlite3-wal" in changed
    assert "F:app/new_module.py" in changed


def test_protected_tree_snapshot_ignores_only_the_current_run_root(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    current_run = project / "tmp" / "test_lab" / "RUN-SAFE-005"
    previous_run = project / "tmp" / "test_lab" / "RUN-SAFE-OLD"
    current_run.mkdir(parents=True)
    previous_run.mkdir(parents=True)
    (current_run / "live.txt").write_text("before", encoding="utf-8")
    previous_file = previous_run / "evidence.txt"
    previous_file.write_text("before", encoding="utf-8")

    before = _protected_tree_snapshot(project, excluded_root=current_run)
    (current_run / "live.txt").write_text("after", encoding="utf-8")
    previous_file.write_text("after", encoding="utf-8")
    after = _protected_tree_snapshot(project, excluded_root=current_run)

    changed = _snapshot_changes(before, after)
    assert all("RUN-SAFE-005" not in item for item in changed)
    assert "F:tmp/test_lab/RUN-SAFE-OLD/evidence.txt" in changed


def test_cold_archive_exclusion_skips_only_verified_archive_root(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    current_run = project / "tmp" / "test_lab" / "RUN-SAFE-CURRENT"
    previous_run = project / "tmp" / "test_lab" / "RUN-SAFE-PREVIOUS"
    cold_archives = project / "tmp" / "test_lab_archives"
    current_run.mkdir(parents=True)
    previous_run.mkdir(parents=True)
    cold_archives.mkdir(parents=True)
    current_file = current_run / "current.txt"
    previous_file = previous_run / "previous.txt"
    archive_file = cold_archives / "history.tar.gz"
    current_file.write_text("before", encoding="utf-8")
    previous_file.write_text("before", encoding="utf-8")
    archive_file.write_bytes(b"verified-cold-archive")

    before = _protected_tree_snapshot(
        project,
        excluded_root=current_run,
        additional_excluded_roots=(cold_archives,),
    )
    current_file.write_text("after", encoding="utf-8")
    archive_file.write_bytes(b"checked-at-stage-freeze")
    previous_file.write_text("after", encoding="utf-8")
    after = _protected_tree_snapshot(
        project,
        excluded_root=current_run,
        additional_excluded_roots=(cold_archives,),
    )

    changed = _snapshot_changes(before, after)
    assert all("RUN-SAFE-CURRENT" not in item for item in changed)
    assert all("test_lab_archives" not in item for item in changed)
    assert "F:tmp/test_lab/RUN-SAFE-PREVIOUS/previous.txt" in changed


def test_windows_extended_path_canonicalizes_drive_and_unc_namespaces() -> None:
    drive_path = r"D:\AAA命题\Test\tmp\history\evidence.bin"
    extended_drive = r"\\?\D:\AAA命题\Test\tmp\history\evidence.bin"
    unc_path = r"\\server\share\history\evidence.bin"
    extended_unc = r"\\?\UNC\server\share\history\evidence.bin"

    assert _windows_extended_path(drive_path) == extended_drive
    assert _windows_extended_path(extended_drive) == extended_drive
    assert _windows_extended_path(unc_path) == extended_unc
    assert _windows_extended_path(extended_unc) == extended_unc
    assert _windows_extended_path(r"\\server\share") == "\\\\?\\UNC\\server\\share\\"
    assert str(launcher_module._absolute_lexical(extended_drive)) == drive_path
    assert str(launcher_module._absolute_lexical(extended_unc)) == unc_path


def test_protected_snapshot_hash_walk_and_fence_cover_historical_long_path(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    excluded = project / "tmp" / "test_lab" / "RUN-SAFE-CURRENT"
    history = project / "tmp" / "test_lab" / "RUN-SAFE-HISTORY"
    os.makedirs(_windows_extended_path(excluded))
    os.makedirs(_windows_extended_path(history))
    long_directories: list[Path] = []
    long_parent = history
    evidence_payload = b'{"retained":true,"long_path":true}\n'
    fence: _WindowsProtectedTreeFence | None = None
    evidence_path: Path | None = None
    extended_evidence_path: str | None = None
    evidence_created = False
    try:
        while len(str(long_parent)) <= 275:
            long_parent = long_parent / ("historical-evidence-segment-" + "d" * 64)
            os.mkdir(_windows_extended_path(long_parent))
            long_directories.append(long_parent)
        evidence_path = long_parent / "retained-evidence.json"
        extended_evidence_path = _windows_extended_path(evidence_path)
        with open(extended_evidence_path, "xb") as handle:
            evidence_created = True
            handle.write(evidence_payload)

        assert len(str(long_parent)) > 260
        assert evidence_path is not None and extended_evidence_path is not None
        snapshot = _protected_tree_snapshot(project, excluded_root=excluded)
        evidence_key = "F:" + evidence_path.relative_to(project).as_posix()
        assert evidence_key in snapshot
        assert snapshot[evidence_key]["sha256"] == hashlib.sha256(
            evidence_payload
        ).hexdigest()
        assert all("\\\\?\\" not in key for key in snapshot)

        fence = _WindowsProtectedTreeFence(
            project,
            excluded_root=excluded,
            snapshot=snapshot,
        )
        with pytest.raises(OSError):
            with open(extended_evidence_path, "r+b") as handle:
                handle.write(b"tampered")
        with open(extended_evidence_path, "rb") as handle:
            assert handle.read() == evidence_payload
    finally:
        finish_result: tuple[int, str | None] | None = None
        if fence is not None:
            finish_result = fence.finish()
        if evidence_created and extended_evidence_path is not None:
            os.remove(extended_evidence_path)
        for directory in reversed(long_directories):
            os.rmdir(_windows_extended_path(directory))
        if finish_result is not None:
            count, error = finish_result
            assert error is None
            assert count > 0


def test_protected_snapshot_accepts_only_fully_internal_hardlink_groups(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    excluded = project / "current-run"
    excluded.mkdir(parents=True)
    original = project / "original.bin"
    original.write_bytes(b"same-inode")
    internal_link = project / "internal-link.bin"
    os.link(original, internal_link)
    try:
        snapshot = _protected_tree_snapshot(project, excluded_root=excluded)
        assert "F:original.bin" in snapshot
        assert "F:internal-link.bin" in snapshot
    finally:
        internal_link.unlink()

    excluded_link = excluded / "excluded-link.bin"
    os.link(original, excluded_link)
    try:
        with pytest.raises(SafetyStop, match="not wholly contained"):
            _protected_tree_snapshot(project, excluded_root=excluded)
    finally:
        excluded_link.unlink()
    assert os.stat(original).st_nlink == 1


def test_protected_snapshot_detects_directory_metadata_change(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    excluded = project / "excluded"
    excluded.mkdir(parents=True)
    before = _protected_tree_snapshot(project, excluded_root=excluded)
    identity = project.stat()
    os.utime(
        project,
        ns=(identity.st_atime_ns, identity.st_mtime_ns + 10_000_000),
    )
    after = _protected_tree_snapshot(project, excluded_root=excluded)
    assert "D:." in _snapshot_changes(before, after)


def test_runtime_watcher_detects_transient_create_delete(tmp_path: Path) -> None:
    project = tmp_path / "project"
    excluded = project / "excluded"
    excluded.mkdir(parents=True)
    watcher = _WindowsProtectedTreeWatcher(project, excluded_root=excluded)
    transient = project / "transient"
    transient.mkdir()
    transient.rmdir()
    changes, error = watcher.finish()
    assert error is None
    assert any(change.endswith(":transient") for change in changes)


def test_runtime_watcher_ignores_only_its_excluded_root(tmp_path: Path) -> None:
    project = tmp_path / "project"
    excluded = project / "excluded"
    excluded.mkdir(parents=True)
    watcher = _WindowsProtectedTreeWatcher(project, excluded_root=excluded)
    (excluded / "allowed.txt").write_text("inside exclusion", encoding="utf-8")
    changes, error = watcher.finish()
    assert error is None
    assert changes == ()


def test_runtime_watcher_ignores_current_run_and_cold_archives_only(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    excluded = project / "current-run"
    cold_archives = project / "tmp" / "test_lab_archives"
    excluded.mkdir(parents=True)
    cold_archives.mkdir(parents=True)
    watcher = _WindowsProtectedTreeWatcher(
        project,
        excluded_root=excluded,
        additional_excluded_roots=(cold_archives,),
    )
    (excluded / "current.txt").write_text("current", encoding="utf-8")
    (cold_archives / "cold.tar.gz").write_bytes(b"cold")
    protected = project / "must-be-observed.txt"
    protected.write_text("protected", encoding="utf-8")
    changes, error = watcher.finish()
    assert error is None
    assert any(change.endswith(":must-be-observed.txt") for change in changes)
    assert all("current-run" not in change for change in changes)
    assert all("test_lab_archives" not in change for change in changes)


def test_runtime_watcher_cannot_be_stopped_by_an_early_drain_marker(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    excluded = project / "excluded"
    excluded.mkdir(parents=True)
    watcher = _WindowsProtectedTreeWatcher(project, excluded_root=excluded)
    early_drain = object.__getattribute__(watcher, "_drain_path")
    early_drain.write_text("forged early drain", encoding="utf-8")
    early_drain.unlink()
    transient = project / "must-be-observed"
    transient.mkdir()
    transient.rmdir()
    changes, error = watcher.finish()
    assert error is None
    assert any(change.endswith(":must-be-observed") for change in changes)


def test_runtime_watcher_fails_closed_on_unexpected_io_cancellation(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    excluded = project / "excluded"
    excluded.mkdir(parents=True)
    watcher = _WindowsProtectedTreeWatcher(project, excluded_root=excluded)
    kernel32 = object.__getattribute__(watcher, "_kernel32")
    handle = object.__getattribute__(watcher, "_handle")
    cancelled = bool(kernel32.CancelIoEx(handle, None))
    thread = object.__getattribute__(watcher, "_thread")
    thread.join(timeout=5)
    _changes, error = watcher.finish()
    assert cancelled
    assert error is not None
    assert "monitor" in error


def test_protected_tree_fence_blocks_direct_protected_file_write(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    excluded = project / "excluded"
    excluded.mkdir(parents=True)
    protected = project / "protected.bin"
    protected.write_bytes(b"immutable")
    snapshot = _protected_tree_snapshot(project, excluded_root=excluded)
    fence = _WindowsProtectedTreeFence(
        project,
        excluded_root=excluded,
        snapshot=snapshot,
    )
    alias = excluded / "alias.bin"
    alias_created = False
    try:
        with pytest.raises(OSError):
            protected.write_bytes(b"tampered")
        assert protected.read_bytes() == b"immutable"
        try:
            os.link(protected, alias)
            alias_created = True
        except OSError:
            pass
        if alias_created:
            with pytest.raises(OSError):
                alias.write_bytes(b"tampered-through-alias")
            assert protected.read_bytes() == b"immutable"
    finally:
        _count, error = fence.finish()
        assert error is None
        if alias_created:
            alias.unlink()
    assert protected.read_bytes() == b"immutable"
    assert protected.stat().st_nlink == 1


def test_protected_tree_fence_does_not_open_cold_archive_files(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    excluded = project / "current-run"
    cold_archives = project / "tmp" / "test_lab_archives"
    excluded.mkdir(parents=True)
    cold_archives.mkdir(parents=True)
    protected = project / "protected.bin"
    archive = cold_archives / "history.tar.gz"
    protected.write_bytes(b"protected")
    archive.write_bytes(b"cold")
    snapshot = _protected_tree_snapshot(
        project,
        excluded_root=excluded,
        additional_excluded_roots=(cold_archives,),
    )
    assert all("test_lab_archives" not in key for key in snapshot)
    fence = _WindowsProtectedTreeFence(
        project,
        excluded_root=excluded,
        additional_excluded_roots=(cold_archives,),
        snapshot=snapshot,
    )
    try:
        archive.write_bytes(b"stage-freeze-validation-is-separate")
        with pytest.raises(OSError):
            protected.write_bytes(b"tampered")
    finally:
        _count, error = fence.finish()
    assert error is None
    assert protected.read_bytes() == b"protected"


def test_test_lab_hardlink_guard_rejects_source_outside_current_run(
    tmp_path: Path,
) -> None:
    outside_source = Path(__file__).resolve()
    destination = tmp_path / "forbidden-alias.py"
    with pytest.raises(PermissionError, match="SAFE_TEST_HARDLINK_DENIED"):
        os.link(outside_source, destination)
    assert not destination.exists()


def test_test_lab_hardlink_guard_rejects_nt_link_outside_current_run(
    tmp_path: Path,
) -> None:
    outside_source = Path(__file__).resolve()
    destination = tmp_path / "forbidden-nt-alias.py"
    nt_module = __import__("nt")
    with pytest.raises(PermissionError, match="SAFE_TEST_HARDLINK_DENIED"):
        nt_module.link(outside_source, destination)
    assert not destination.exists()


def test_python_child_inherits_cross_boundary_hardlink_guard(
    tmp_path: Path,
) -> None:
    outside_source = Path(__file__).resolve()
    destination = tmp_path / "forbidden-child-alias.py"
    completed = subprocess.run(
        [
            sys.executable,
            "-B",
            "-c",
            (
                "import os; "
                f"os.link({str(outside_source)!r}, {str(destination)!r})"
            ),
        ],
        cwd=Path(__file__).parent.parent,
        env=os.environ.copy(),
        text=True,
        capture_output=True,
        check=False,
        timeout=10,
    )
    assert completed.returncode != 0
    assert "SAFE_TEST_HARDLINK_DENIED" in completed.stderr
    assert not destination.exists()


def test_python_child_script_argument_is_not_misread_as_interpreter_flag() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-B",
            "-c",
            "import sys; assert sys.argv[1] == '-SESSION'",
            "-SESSION",
        ],
        cwd=Path(__file__).parent.parent,
        env=os.environ.copy(),
        check=False,
        timeout=10,
    )
    assert completed.returncode == 0


@pytest.mark.parametrize(
    ("case", "interpreter_arguments"),
    [
        ("separate-s", ("-S", "-c")),
        ("separate-e", ("-E", "-c")),
        ("separate-i", ("-I", "-c")),
        ("combined-ic", ("-Ic",)),
        ("combined-sc", ("-Sc",)),
        ("combined-ec", ("-Ec",)),
        ("warning-then-i", ("-W", "ignore", "-I", "-c")),
        ("xoption-then-s", ("-X", "dev", "-S", "-c")),
        ("combined-i-warning", ("-IWignore", "-c")),
        ("combined-i-xoption", ("-IXdev", "-c")),
    ],
)
def test_python_child_cannot_disable_bootstrap_with_isolation_flag(
    tmp_path: Path,
    case: str,
    interpreter_arguments: tuple[str, ...],
) -> None:
    sentinel = tmp_path / f"child-{case}.ran"
    with pytest.raises(PermissionError, match="SAFE_TEST_PROCESS_DENIED"):
        subprocess.run(
            [
                sys.executable,
                *interpreter_arguments,
                f"from pathlib import Path; Path({str(sentinel)!r}).write_text('ran')",
            ],
            cwd=Path(__file__).parent.parent,
            env=os.environ.copy(),
            check=False,
            timeout=10,
        )
    assert not sentinel.exists()


@pytest.mark.parametrize(
    "removed_name",
    ["M0_TEST_LAB_ROOT", "M0_TEST_HARDLINK_GUARD_REQUIRED", "PYTHONPATH"],
)
def test_python_child_cannot_strip_required_guard_environment(
    tmp_path: Path,
    removed_name: str,
) -> None:
    sentinel = tmp_path / f"child-without-{removed_name}.ran"
    environment = os.environ.copy()
    environment.pop(removed_name, None)
    with pytest.raises(PermissionError, match="SAFE_TEST_PROCESS_DENIED"):
        subprocess.run(
            [
                sys.executable,
                "-B",
                "-c",
                f"from pathlib import Path; Path({str(sentinel)!r}).write_text('ran')",
            ],
            cwd=Path(__file__).parent.parent,
            env=environment,
            check=False,
            timeout=10,
        )
    assert not sentinel.exists()


def test_ctypes_cannot_resolve_native_hardlink_api() -> None:
    import ctypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    with pytest.raises(PermissionError, match="SAFE_TEST_PROCESS_DENIED"):
        getattr(kernel32, "CreateHardLinkW")


def test_ctypes_cannot_resolve_native_process_api() -> None:
    import ctypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    with pytest.raises(PermissionError, match="SAFE_TEST_PROCESS_DENIED"):
        getattr(kernel32, "CreateProcessW")


@pytest.mark.parametrize(
    "event",
    [
        "os.system",
        "os.startfile",
        "os.startfile/2",
        "os.exec",
        "os.spawn",
        "os.posix_spawn",
    ],
)
def test_alternate_process_audit_events_fail_closed(event: str) -> None:
    import sitecustomize

    audit_hook = getattr(sitecustomize, "_INSTALLED_AUDIT_HOOK")
    with pytest.raises(PermissionError, match="SAFE_TEST_PROCESS_DENIED"):
        audit_hook(event, ())


@pytest.mark.parametrize(
    "command",
    [
        ["fsutil", "hardlink", "list", "never-run"],
        ["cmd.exe", "/d", "/c", "mklink", "/H", "never", "run"],
        ["powershell.exe", "-NoProfile", "New-Item", "-ItemType", "HardLink"],
    ],
)
def test_native_hardlink_commands_are_rejected_before_process_creation(
    command: list[str],
) -> None:
    with pytest.raises(PermissionError, match="SAFE_TEST_PROCESS_DENIED"):
        subprocess.run(command, check=False, timeout=10)


def test_cmd_trampoline_cannot_launch_isolated_python(tmp_path: Path) -> None:
    sentinel = tmp_path / "cmd-trampoline.ran"
    cmd = Path(os.environ["SystemRoot"]) / "System32" / "cmd.exe"
    with pytest.raises(PermissionError, match="SAFE_TEST_PROCESS_DENIED"):
        subprocess.run(
            [
                str(cmd),
                "/d",
                "/q",
                "/c",
                sys.executable,
                "-I",
                "-c",
                f"from pathlib import Path; Path({str(sentinel)!r}).write_text('ran')",
            ],
            cwd=tmp_path,
            env=os.environ.copy(),
            check=False,
            timeout=10,
        )
    assert not sentinel.exists()


def test_fake_direct_pytest_canary_cannot_bypass_child_guard(tmp_path: Path) -> None:
    sentinel = tmp_path / "fake-canary.ran"
    environment = os.environ.copy()
    for name in (
        "M0_TEST_LAB_ROOT",
        "M0_TEST_LAB_TOKEN",
        "M0_TEST_HARDLINK_GUARD_ACTIVE",
        "M0_TEST_HARDLINK_GUARD_REQUIRED",
        "PYTHONPATH",
    ):
        environment.pop(name, None)
    environment["M0_TEST_DIRECT_PYTEST_CANARY"] = "1"
    with pytest.raises(PermissionError, match="SAFE_TEST_PROCESS_DENIED"):
        subprocess.run(
            [
                sys.executable,
                "-c",
                f"from pathlib import Path; Path({str(sentinel)!r}).write_text('ran')",
                "tests/test_safe_pytest_launcher.py",
                "--collect-only",
                "--basetemp",
                str(tmp_path),
            ],
            cwd=Path(__file__).parent.parent,
            env=environment,
            check=False,
            timeout=10,
        )
    assert not sentinel.exists()


def test_immutable_run_evidence_detects_content_and_identity_change(
    tmp_path: Path,
) -> None:
    evidence = tmp_path / "run-manifest.json"
    evidence.write_text('{"safe": true}\n', encoding="utf-8")
    before = _regular_file_evidence(evidence)
    evidence.write_text('{"safe": false}\n', encoding="utf-8")
    after = _regular_file_evidence(evidence)
    assert before != after


def test_junit_evidence_requires_regular_valid_zero_or_nonzero_counts(
    tmp_path: Path,
) -> None:
    junit = tmp_path / "junit.xml"
    junit.write_text(
        '<testsuites><testsuite tests="2" failures="0" errors="0" skipped="1">'
        '<testcase name="ok"/><testcase name="skip"><skipped/></testcase>'
        '</testsuite></testsuites>',
        encoding="utf-8",
    )
    evidence = _junit_evidence(junit)
    assert evidence["tests"] == 2
    assert evidence["failures"] == 0
    assert evidence["errors"] == 0
    junit.write_text("<testsuites>", encoding="utf-8")
    with pytest.raises(SafetyStop, match="JUnit XML is invalid"):
        _junit_evidence(junit)


def test_junit_evidence_rejects_hardlinked_output(tmp_path: Path) -> None:
    original = tmp_path / "original.xml"
    original.write_text(
        '<testsuite tests="1" failures="0" errors="0" skipped="0" />',
        encoding="utf-8",
    )
    linked = tmp_path / "junit.xml"
    os.link(original, linked)
    try:
        with pytest.raises(SafetyStop, match="exactly one hard link"):
            _junit_evidence(linked)
    finally:
        linked.unlink()
    assert os.stat(original).st_nlink == 1


def test_junit_evidence_rejects_aggregate_and_status_tree_mismatch(
    tmp_path: Path,
) -> None:
    junit = tmp_path / "junit.xml"
    junit.write_text(
        '<testsuite tests="1" failures="0" errors="0" skipped="0">'
        '<testcase name="hidden"><failure/></testcase></testsuite>',
        encoding="utf-8",
    )
    with pytest.raises(SafetyStop, match="aggregate counts"):
        _junit_evidence(junit)

    junit.write_text(
        '<testsuite tests="0" failures="1" errors="0" skipped="0">'
        '<failure/></testsuite>',
        encoding="utf-8",
    )
    with pytest.raises(SafetyStop, match="direct testcase children"):
        _junit_evidence(junit)


def test_run_tree_verifier_accepts_a_regular_isolated_tree(tmp_path: Path) -> None:
    run_root = tmp_path / "RUN-SAFE-VERIFY"
    run_root.mkdir()
    (run_root / "regular.txt").write_text("safe", encoding="utf-8")
    _verify_run_tree_no_reparse(run_root)
    nested = run_root / "nested"
    nested.mkdir()
    _verify_run_tree_no_reparse(run_root)


def test_run_tree_depth_counts_file_component_at_exact_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(launcher_module, "RUN_TREE_MAX_DEPTH", 2)
    run_root = tmp_path / "RUN-SAFE-DEPTH"
    nested = run_root / "a"
    nested.mkdir(parents=True)
    (nested / "exact.bin").write_bytes(b"x")
    metrics = _verify_run_tree_no_reparse(run_root)
    assert metrics["maximum_depth"] == 2
    deeper = nested / "b"
    deeper.mkdir()
    (deeper / "overflow.bin").write_bytes(b"x")
    with pytest.raises(SafetyStop, match="file depth"):
        _verify_run_tree_no_reparse(run_root)


def test_run_tree_verifier_rejects_hardlinks_without_leaving_them(
    tmp_path: Path,
) -> None:
    run_root = tmp_path / "RUN-SAFE-HARDLINK"
    run_root.mkdir()
    original = run_root / "original.bin"
    linked = run_root / "linked.bin"
    original.write_bytes(b"hardlink")
    os.link(original, linked)
    try:
        with pytest.raises(SafetyStop, match="multiple hard links"):
            _verify_run_tree_no_reparse(run_root)
    finally:
        linked.unlink()
    _verify_run_tree_no_reparse(run_root)


def test_run_tree_verifier_reports_fixed_metrics_and_rejects_ads(
    tmp_path: Path,
) -> None:
    run_root = tmp_path / "RUN-SAFE-ADS"
    run_root.mkdir()
    target = run_root / "regular.bin"
    target.write_bytes(b"safe")
    metrics = _verify_run_tree_no_reparse(run_root)
    assert metrics["file_count"] == 1
    assert metrics["total_bytes"] == 4
    stream = f"{target}:synthetic"
    with open(stream, "wb") as handle:
        handle.write(b"ads")
    try:
        with pytest.raises(SafetyStop, match="alternate data stream"):
            _verify_run_tree_no_reparse(run_root)
    finally:
        os.remove(stream)
    _verify_run_tree_no_reparse(run_root)
    directory_stream = f"{run_root}:synthetic-directory"
    from app.safety.windows_handle_writer import _WindowsApi

    api = _WindowsApi()
    directory_stream_handle = api.open_handle(
        Path(directory_stream),
        access=api.GENERIC_WRITE,
        share=api.FILE_SHARE_READ | api.FILE_SHARE_WRITE | api.FILE_SHARE_DELETE,
        disposition=api.CREATE_NEW,
        flags=api.FILE_FLAG_OPEN_REPARSE_POINT | api.FILE_FLAG_BACKUP_SEMANTICS,
    )
    api.close(directory_stream_handle)
    try:
        with pytest.raises(SafetyStop, match="alternate data stream"):
            _verify_run_tree_no_reparse(run_root)
    finally:
        os.remove(directory_stream)
    _verify_run_tree_no_reparse(run_root)


def test_process_job_reports_and_kills_an_unexpected_background_child(
    tmp_path: Path,
) -> None:
    child_pid = tmp_path / "background-child.pid"
    child_code = (
        "import pathlib,subprocess,sys; "
        "child=subprocess.Popen([sys.executable, '-B', '-c', "
        "'import time; time.sleep(30)']); "
        f"pathlib.Path({str(child_pid)!r}).write_text(str(child.pid), encoding='ascii')"
    )
    exit_code, timed_out, tree_terminated, budget_error, _budget_peak = _run_test_process(
        [sys.executable, "-B", "-c", child_code],
        project_root=Path(__file__).parent.parent,
        run_root=tmp_path,
        environment=os.environ.copy(),
        timeout_seconds=10,
    )
    assert exit_code == 0
    assert not timed_out
    assert not tree_terminated
    assert budget_error is None
    pid = int(child_pid.read_text(encoding="ascii"))
    assert _wait_until_pid_stops(pid)


def test_process_output_is_captured_inside_the_run_root(tmp_path: Path) -> None:
    code = (
        "import sys; "
        "print('captured stdout', flush=True); "
        "print('captured stderr', file=sys.stderr, flush=True)"
    )
    exit_code, timed_out, tree_terminated, budget_error, _budget_peak = (
        _run_test_process(
            [sys.executable, "-B", "-c", code],
            project_root=Path(__file__).parent.parent,
            run_root=tmp_path,
            environment=os.environ.copy(),
            timeout_seconds=10,
        )
    )
    assert exit_code == 0
    assert not timed_out
    assert tree_terminated
    assert budget_error is None
    assert (tmp_path / "pytest-stdout.log").read_text(
        encoding="utf-8"
    ) == "captured stdout\n"
    assert (tmp_path / "pytest-stderr.log").read_text(
        encoding="utf-8"
    ) == "captured stderr\n"


def test_process_output_capture_refuses_existing_log_targets(tmp_path: Path) -> None:
    (tmp_path / "pytest-stdout.log").write_bytes(b"existing")
    with pytest.raises(SafetyStop, match="output logs must not exist"):
        _run_test_process(
            [sys.executable, "-B", "-c", "pass"],
            project_root=Path(__file__).parent.parent,
            run_root=tmp_path,
            environment=os.environ.copy(),
            timeout_seconds=10,
        )


def test_process_job_terminates_the_full_tree_on_timeout(tmp_path: Path) -> None:
    child_pid = tmp_path / "timeout-child.pid"
    parent_code = (
        "import pathlib,subprocess,sys,time; "
        "child=subprocess.Popen([sys.executable, '-B', '-c', "
        "'import time; time.sleep(30)']); "
        f"pathlib.Path({str(child_pid)!r}).write_text(str(child.pid), encoding='ascii'); "
        "time.sleep(30)"
    )
    exit_code, timed_out, tree_terminated, budget_error, _budget_peak = _run_test_process(
        [sys.executable, "-B", "-c", parent_code],
        project_root=Path(__file__).parent.parent,
        run_root=tmp_path,
        environment=os.environ.copy(),
        timeout_seconds=10,
    )
    assert exit_code == 124
    assert timed_out
    assert tree_terminated
    assert budget_error is None
    pid = int(child_pid.read_text(encoding="ascii"))
    assert not _pid_is_running(pid)


def test_process_job_terminates_when_runtime_run_budget_is_exceeded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(launcher_module, "RUN_TREE_MAX_TOTAL_BYTES", 32)
    payload = tmp_path / "oversize.bin"
    code = (
        "from pathlib import Path; import time; "
        f"Path({str(payload)!r}).write_bytes(b'x' * 4096); time.sleep(30)"
    )
    exit_code, timed_out, tree_terminated, budget_error, budget_peak = _run_test_process(
        [sys.executable, "-B", "-c", code],
        project_root=Path(__file__).parent.parent,
        run_root=tmp_path,
        environment=os.environ.copy(),
        timeout_seconds=10,
    )
    assert exit_code == 94
    assert not timed_out
    assert tree_terminated
    assert budget_error is not None
    assert budget_peak["total_bytes"] <= 32


def test_process_job_terminates_when_runtime_file_depth_exceeds_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(launcher_module, "RUN_TREE_MAX_DEPTH", 1)
    nested = tmp_path / "nested"
    code = (
        "from pathlib import Path; import time; "
        f"p=Path({str(nested)!r}); p.mkdir(); (p/'overflow.bin').write_bytes(b'x'); "
        "time.sleep(30)"
    )
    exit_code, timed_out, tree_terminated, budget_error, _budget_peak = _run_test_process(
        [sys.executable, "-B", "-c", code],
        project_root=Path(__file__).parent.parent,
        run_root=tmp_path,
        environment=os.environ.copy(),
        timeout_seconds=10,
    )
    assert exit_code == 94
    assert not timed_out
    assert tree_terminated
    assert budget_error is not None


@pytest.mark.skipif(os.name != "nt", reason="Windows suspended-process contract")
@pytest.mark.parametrize("failure_method", ["assign", "resume_process"])
def test_job_setup_failure_never_runs_suspended_child(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_method: str,
) -> None:
    sentinel = tmp_path / f"{failure_method}.ran"

    def fail(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError(f"forced {failure_method} failure")

    monkeypatch.setattr(_WindowsJob, failure_method, fail)
    with pytest.raises(RuntimeError, match=failure_method):
        _run_test_process(
            [
                sys.executable,
                "-B",
                "-c",
                f"from pathlib import Path; Path({str(sentinel)!r}).write_text('ran')",
            ],
            project_root=Path(__file__).parent.parent,
            run_root=tmp_path,
            environment=os.environ.copy(),
            timeout_seconds=5,
        )
    assert not sentinel.exists()


def test_effective_exit_code_records_protected_state_gate_and_skips() -> None:
    base = {
        "pytest_exit_code": 0,
        "junit_valid": True,
        "junit_details": {"tests": 1, "failures": 0, "errors": 0, "skipped": 0},
        "process_tree_terminated": True,
        "run_tree_safe": True,
        "immutable_evidence_unchanged": True,
        "database_unchanged": True,
        "protected_tree_unchanged": True,
        "protected_runtime_monitor_valid": True,
        "protected_runtime_unchanged": True,
        "protected_handle_fence_valid": True,
        "source_witness_valid": True,
        "registered_source_final_state_matches": True,
        "registered_source_count_requirement_met": True,
    }
    assert _effective_exit_code(**base) == 0
    assert _effective_exit_code(**{**base, "pytest_exit_code": 1}) == 1
    assert _effective_exit_code(**{**base, "process_tree_terminated": False}) != 0
    assert _effective_exit_code(**{**base, "run_tree_safe": False}) != 0
    assert _effective_exit_code(**{**base, "immutable_evidence_unchanged": False}) != 0
    assert _effective_exit_code(**{**base, "database_unchanged": False}) == 97
    assert _effective_exit_code(**{**base, "protected_tree_unchanged": False}) == 97
    assert _effective_exit_code(
        **{**base, "protected_runtime_monitor_valid": False}
    ) == 97
    assert _effective_exit_code(
        **{**base, "protected_runtime_unchanged": False}
    ) == 97
    assert _effective_exit_code(
        **{**base, "protected_handle_fence_valid": False}
    ) == 97
    assert _effective_exit_code(**{**base, "source_witness_valid": False}) == 97
    assert _effective_exit_code(
        **{**base, "registered_source_final_state_matches": False}
    ) == 97
    assert _effective_exit_code(
        **{**base, "registered_source_count_requirement_met": False}
    ) == 97
    assert _effective_exit_code(
        **{
            **base,
            "junit_details": {
                "tests": 1,
                "failures": 0,
                "errors": 0,
                "skipped": 1,
            },
        }
    ) == 98
    for field in ("failures", "errors"):
        details = {"tests": 1, "failures": 0, "errors": 0, "skipped": 0}
        details[field] = 1
        assert _effective_exit_code(**{**base, "junit_details": details}) == 98
    assert _effective_exit_code(
        **{
            **base,
            "junit_details": {
                "tests": 0,
                "failures": 0,
                "errors": 0,
                "skipped": 0,
            },
        }
    ) == 98


def test_only_copy_bearing_modes_require_a_registered_source_witness() -> None:
    assert RUN_RESULT_SCHEMA_VERSION == "1.2"
    assert SOURCE_REGISTRATION_REQUIRED_MODES == frozenset(
        {"full", "s3f", "s3f_core", "s3h", "s6"}
    )
    assert {
        "guard",
        "writer",
        "s3d",
        "s3e",
        "s3e_core",
        "s3g",
        "s3g_core",
        "s3h_core",
        "s4",
        "s4_core",
        "s5",
        "s5_core",
        "s6_core",
        "m1",
        "m1_core",
        "m2",
        "m2_core",
        "m3",
        "m3_core",
        "m4",
        "m4_core",
        "launcher",
        "symlink",
    }.isdisjoint(SOURCE_REGISTRATION_REQUIRED_MODES)
    for mode in SOURCE_REGISTRATION_REQUIRED_MODES:
        assert _registered_source_count_gate(
            mode,
            source_witness_valid=True,
            source_count=0,
        ) == {
            "registered_source_count": 0,
            "registered_source_count_minimum_required": 1,
            "registered_source_count_requirement_met": False,
        }
        assert _registered_source_count_gate(
            mode,
            source_witness_valid=True,
            source_count=1,
        )["registered_source_count_requirement_met"] is True
        assert _registered_source_count_gate(
            mode,
            source_witness_valid=False,
            source_count=1,
        )["registered_source_count_requirement_met"] is False
    for mode in {
        "guard",
        "writer",
        "s3d",
        "s3e",
        "s3e_core",
        "s3g",
        "s3g_core",
        "s3h_core",
        "s4",
        "s4_core",
        "s5",
        "s5_core",
        "s6_core",
        "m1",
        "m1_core",
        "m2",
        "m2_core",
        "m3",
        "m3_core",
        "m4",
        "m4_core",
        "launcher",
        "symlink",
    }:
        assert _registered_source_count_gate(
            mode,
            source_witness_valid=True,
            source_count=0,
        )["registered_source_count_requirement_met"] is True


def test_direct_pytest_canary_rejects_injected_plugin_environment(
    tmp_path: Path,
) -> None:
    basetemp = tmp_path / "injected-plugin-basetemp"
    basetemp.mkdir()
    environment = os.environ.copy()
    for name in (
        "M0_TEST_LAB_ROOT",
        "M0_TEST_LAB_TOKEN",
        "M0_TEST_HARDLINK_GUARD_ACTIVE",
        "M0_TEST_HARDLINK_GUARD_REQUIRED",
        "PYTHONPATH",
        "PYTEST_ADDOPTS",
        "PYTEST_PLUGINS",
    ):
        environment.pop(name, None)
    environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    environment["M0_TEST_DIRECT_PYTEST_CANARY"] = "1"
    environment["PYTEST_PLUGINS"] = "injected_plugin_must_not_load"
    with pytest.raises(PermissionError, match="SAFE_TEST_PROCESS_DENIED"):
        subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "tests/test_safe_pytest_launcher.py",
                "--collect-only",
                "-q",
                "-p",
                "no:cacheprovider",
                "--basetemp",
                str(basetemp),
            ],
            cwd=Path(__file__).parent.parent,
            env=environment,
            check=False,
            timeout=10,
        )


def test_direct_pytest_is_rejected_before_existing_basetemp_is_touched(
    tmp_path: Path,
) -> None:
    protected_basetemp = tmp_path / "protected-basetemp"
    protected_basetemp.mkdir()
    sentinel = protected_basetemp / "sentinel.bin"
    sentinel.write_bytes(b"direct-pytest-must-not-delete-this")
    sentinel_before = hashlib.sha256(sentinel.read_bytes()).hexdigest()

    environment = os.environ.copy()
    environment.pop("M0_TEST_LAB_ROOT", None)
    environment.pop("M0_TEST_LAB_TOKEN", None)
    environment.pop("M0_TEST_HARDLINK_GUARD_ACTIVE", None)
    environment.pop("M0_TEST_HARDLINK_GUARD_REQUIRED", None)
    environment.pop("PYTHONPATH", None)
    environment.pop("PYTEST_ADDOPTS", None)
    environment.pop("PYTEST_PLUGINS", None)
    environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    environment["M0_TEST_DIRECT_PYTEST_CANARY"] = "1"
    project_root = Path(__file__).parent.parent
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "tests/test_safe_pytest_launcher.py",
            "--collect-only",
            "-q",
            "-p",
            "no:cacheprovider",
            "--basetemp",
            str(protected_basetemp),
        ],
        cwd=project_root,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        check=False,
        timeout=30,
    )

    assert completed.returncode != 0
    combined_output = completed.stdout + completed.stderr
    assert b"SAFE_TEST_LAB_REQUIRED" in combined_output
    assert sentinel.is_file()
    assert hashlib.sha256(sentinel.read_bytes()).hexdigest() == sentinel_before
