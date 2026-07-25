from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

import app.m4_backup as m4
from app.cli import main as cli_main
from app.m3_pipeline import M3PipelineConfig, M3PipelineError
from app.project_root import PROJECT_ROOT


FULL_BACKUP_ID = "BACKUP-M4-YANYAN-FULL-20260726-R2"
INCREMENTAL_BACKUP_ID = "BACKUP-M4-YANYAN-INCREMENTAL-20260726-R2"
RESTORED_STATE_ID = "STATE-M4-YANYAN-RESTORED-20260726-R2"
LEGACY_ACTIVITY_SHA256 = (
    "1505bf05bd8e385eada30642110596363c"
    "561c330da02a40a497072064ad1c94"
)


def _service() -> m4.M4BackupService:
    return m4.M4BackupService()


def _full_manifest() -> dict[str, object]:
    return json.loads(
        (
            PROJECT_ROOT / "backups" / FULL_BACKUP_ID / "manifest.json"
        ).read_text(encoding="utf-8")
    )


@pytest.mark.parametrize(
    "value",
    (
        "../escape",
        "data/../escape",
        "E:/outside",
        "/absolute",
        r"data\backslash",
        "data/file.txt:stream",
        "data/CON/payload",
        "data/trailing./payload",
        "data/trailing /payload",
    ),
)
def test_backup_paths_reject_traversal_absolute_ads_and_devices(
    value: str,
) -> None:
    with pytest.raises(m4.M4Error) as captured:
        m4._safe_relative_path(value, field_name="probe")

    assert captured.value.code is m4.M4Code.INVALID_PATH


def test_formal_full_and_incremental_backups_are_valid_and_deduplicated() -> None:
    service = _service()
    full = service.validate_backup(FULL_BACKUP_ID)
    incremental = service.validate_backup(INCREMENTAL_BACKUP_ID)

    assert full.validation_status == "VALID"
    assert full.backup_kind == "full"
    assert full.file_count == 156
    assert full.logical_bytes == 14_118_572
    assert full.stored_blob_count == 129
    assert 0 < full.stored_bytes < full.logical_bytes
    assert incremental.validation_status == "VALID"
    assert incremental.backup_kind == "incremental"
    assert incremental.parent_backup_id == FULL_BACKUP_ID
    assert incremental.file_count == full.file_count
    assert incremental.logical_bytes == full.logical_bytes
    assert incremental.reused_file_count == incremental.file_count
    assert incremental.stored_blob_count == 0
    assert incremental.stored_bytes == 0


def test_formal_restored_state_replays_search_question_basket_and_export() -> None:
    service = _service()
    verification = service.verify_state(RESTORED_STATE_ID)

    assert verification["status"] == "PASS"
    assert verification["database"] == {
        "approved_question_count": 19,
        "foreign_key_violations": 0,
        "integrity_check": "ok",
        "question_count": 19,
        "schema_version": 1,
        "source_paper_count": 1,
    }
    assert verification["m1"]["question_count"] == 19
    assert verification["m2"]["document_count"] == 5
    assert verification["m3"]["semantic_index_question_count"] == 19
    assert verification["journey"]["journey_count"] == 6
    assert verification["journey"]["status"] == "PASS"
    assert verification["activation_gate_sha256"] == (
        "e2f1268db3c6b46562fa22ac5adf42dd"
        "e90cea9d384e1ca319be8645b6112dd2"
    )


def test_active_pointer_selects_restored_state_without_overwriting_legacy_db() -> None:
    service = _service()
    active = service.current_runtime()
    pointer_payload = service.active_pointer_path.read_bytes()
    legacy_payload = (
        PROJECT_ROOT / "data" / "db" / "question_bank.sqlite3"
    ).read_bytes()

    assert active.active_state_id == RESTORED_STATE_ID
    assert active.source_root_relative == (
        f"data/snapshots/{RESTORED_STATE_ID}/files"
    )
    assert active.generation >= 1
    assert hashlib.sha256(legacy_payload).hexdigest() == LEGACY_ACTIVITY_SHA256
    assert b"E:" not in pointer_payload
    assert b"C:" not in pointer_payload
    assert b"\\\\" not in pointer_payload


def test_m4_ui_exposes_backup_scope_status_and_recovered_runtime() -> None:
    service = _service()
    app = m4.create_m4_app(service)

    with app.test_client() as client:
        maintenance = client.get("/maintenance")
        status = client.get("/maintenance/status")
        detail = client.get(f"/maintenance/backups/{FULL_BACKUP_ID}")
        search = client.get(
            "/search",
            query_string={"q": "函数", "limit": 3},
        )
        export = client.get("/runtime/bundles/student")

    assert maintenance.status_code == 200
    assert "同一产品根所在卷".encode() in maintenance.data
    assert status.status_code == 200
    assert status.get_json()["active_state_id"] == RESTORED_STATE_ID
    assert status.get_json()["same_volume_disaster_protection"] is False
    assert FULL_BACKUP_ID in status.get_json()["selectable_backup_ids"]
    assert detail.status_code == 200
    assert detail.get_json()["validation_status"] == "VALID"
    assert search.status_code == 200
    assert search.get_json()["results"]
    assert export.status_code == 200
    assert export.data.startswith(b"%PDF-")


def test_cli_lists_and_validates_the_same_public_backup_service(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert cli_main(["backup-validate", "--backup-id", FULL_BACKUP_ID]) == 0
    validate_payload = json.loads(capsys.readouterr().out)
    assert validate_payload["status"] == "ok"
    assert validate_payload["result"]["validation_status"] == "VALID"

    assert cli_main(["backup-list"]) == 0
    list_payload = json.loads(capsys.readouterr().out)
    assert FULL_BACKUP_ID in list_payload["result"]["selectable_backup_ids"]


def test_space_preflight_fails_before_creating_any_target() -> None:
    service = _service()
    missing = PROJECT_ROOT / "backups" / "BACKUP-M4-UNIT-LOW-SPACE"
    assert not missing.exists()

    with pytest.raises(m4.M4Error) as captured:
        service._space_preflight(
            required_bytes=1,
            reserve_bytes=1,
            available_bytes_override=0,
        )

    assert captured.value.code is m4.M4Code.INSUFFICIENT_SPACE
    assert not missing.exists()


def test_manifest_shape_rejects_old_schema_and_self_parent() -> None:
    service = _service()
    old = copy.deepcopy(_full_manifest())
    old["manifest_schema_version"] = "0.9"
    with pytest.raises(m4.M4Error, match="identity or shape"):
        service._validate_manifest_shape(old, backup_id=FULL_BACKUP_ID)

    self_parent = copy.deepcopy(_full_manifest())
    self_parent["backup_kind"] = "incremental"
    self_parent["parent_backup_id"] = FULL_BACKUP_ID
    with pytest.raises(m4.M4Error, match="itself"):
        service._validate_manifest_shape(
            self_parent,
            backup_id=FULL_BACKUP_ID,
        )


def test_manifest_validation_rejects_extra_and_traversal_content(
    tmp_path: Path,
) -> None:
    service = _service()
    backup_id = "BACKUP-M4-UNIT-INHERITED"
    manifest = copy.deepcopy(_full_manifest())
    manifest["backup_id"] = backup_id
    manifest["backup_kind"] = "incremental"
    manifest["parent_backup_id"] = FULL_BACKUP_ID
    for row in manifest["files"]:
        row["blob"]["backup_id"] = FULL_BACKUP_ID
    manifest["deduplication"]["reused_file_count"] = len(manifest["files"])
    manifest["storage"] = {
        "logical_bytes": manifest["storage"]["logical_bytes"],
        "stored_blob_count": 0,
        "stored_bytes": 0,
    }
    candidate = tmp_path / backup_id
    candidate.mkdir()
    (candidate / "manifest.json").write_bytes(
        m4._canonical_json_bytes(manifest)
    )

    valid = service.validate_backup(
        backup_id,
        root_override=candidate,
    )
    assert valid.stored_bytes == 0

    (candidate / "undeclared.bin").write_bytes(b"unexpected")
    with pytest.raises(m4.M4Error, match="undeclared"):
        service.validate_backup(
            backup_id,
            root_override=candidate,
        )

    traversal = copy.deepcopy(manifest)
    traversal["files"][0]["logical_path"] = "../escape"
    (candidate / "manifest.json").write_bytes(
        m4._canonical_json_bytes(traversal)
    )
    with pytest.raises(m4.M4Error) as captured:
        service.validate_backup(
            backup_id,
            root_override=candidate,
        )
    assert captured.value.code is m4.M4Code.INVALID_PATH


def test_catalog_never_marks_rejected_or_legacy_candidates_selectable() -> None:
    catalog = _service().list_backups()
    selectable = set(catalog["selectable_backup_ids"])

    assert FULL_BACKUP_ID in selectable
    assert INCREMENTAL_BACKUP_ID in selectable
    assert all(
        row["candidate_id"] not in selectable
        for row in catalog["invalid_candidates"]
    )
    assert catalog["invalid_candidate_count"] >= 1


def test_restored_m3_database_root_is_relative_and_constrained() -> None:
    active = _service().current_runtime()
    config = M3PipelineConfig(
        data_source_root_relative=active.source_root_relative
    )

    assert config.m1_database_path.is_file()
    assert config.m1_database_path.relative_to(PROJECT_ROOT)
    with pytest.raises(M3PipelineError, match="data source root"):
        M3PipelineConfig(data_source_root_relative="../outside")


def test_state_manifest_and_gate_contain_no_machine_absolute_paths() -> None:
    state_root = (
        PROJECT_ROOT / "data" / "snapshots" / RESTORED_STATE_ID
    )
    for name in ("state-manifest.json", "activation-gate.json"):
        payload = (state_root / name).read_bytes()
        assert b"E:" not in payload
        assert b"C:" not in payload
        assert b"file://" not in payload
        assert b"\\\\" not in payload
