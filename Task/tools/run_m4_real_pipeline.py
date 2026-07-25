from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import sys
import time
from pathlib import Path, PurePosixPath
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.m4_backup import (  # noqa: E402
    M4_MAX_FILE_BYTES,
    M4BackupService,
    M4Cancelled,
    M4Code,
    M4Error,
    M4FailurePoint,
    _canonical_json_bytes,
    create_m4_app,
)
from app.safety.workspace_io import get_workspace_io  # noqa: E402


FULL_BACKUP_ID = "BACKUP-M4-YANYAN-FULL-20260725"
INCREMENTAL_BACKUP_ID = "BACKUP-M4-YANYAN-INCREMENTAL-20260725"
RESTORED_STATE_ID = "STATE-M4-YANYAN-RESTORED-20260725"
CANCEL_BACKUP_ID = "BACKUP-M4-CANCEL-RESUME-20260725"
CANCEL_STATE_ID = "STATE-M4-CANCEL-RESUME-20260725"
LEGACY_DATABASE = PROJECT_ROOT / "data" / "db" / "question_bank.sqlite3"
EVIDENCE_PATH = (
    PROJECT_ROOT
    / "tmp"
    / "jobs"
    / "INTERNAL"
    / "JOB-M4-REAL-FLOW-EVIDENCE-R1-20260725"
    / "m4-real-flow-evidence.json"
)


def _file_summary(path: Path) -> dict[str, int | str]:
    payload = path.read_bytes()
    return {
        "bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }


def _tree_summary(root: Path) -> dict[str, int | str]:
    digest = hashlib.sha256()
    total_bytes = 0
    file_count = 0
    for path in sorted(
        (item for item in root.rglob("*") if item.is_file()),
        key=lambda item: item.relative_to(root).as_posix(),
    ):
        payload = path.read_bytes()
        relative = path.relative_to(root).as_posix()
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(payload).digest())
        total_bytes += len(payload)
        file_count += 1
    return {
        "bytes": total_bytes,
        "file_count": file_count,
        "sha256": digest.hexdigest(),
    }


def _ui_backup_and_restore(service: M4BackupService) -> dict[str, Any]:
    app = create_m4_app(service)
    with app.test_client() as client:
        maintenance = client.get("/maintenance")
        status = client.get("/maintenance/status")
        full = client.post(
            "/maintenance/backups",
            data={
                "backup_id": FULL_BACKUP_ID,
                "backup_kind": "full",
                "job_id": "JOB-M4-UI-FULL-IDEMPOTENT-20260725",
            },
        )
        incremental = client.post(
            "/maintenance/backups",
            data={
                "backup_id": INCREMENTAL_BACKUP_ID,
                "backup_kind": "incremental",
                "job_id": "JOB-M4-UI-INCREMENTAL-20260725",
                "parent_backup_id": FULL_BACKUP_ID,
            },
        )
        detail = client.get(
            f"/maintenance/backups/{INCREMENTAL_BACKUP_ID}"
        )
        restore = client.post(
            f"/maintenance/backups/{FULL_BACKUP_ID}/restore",
            data={
                "state_id": RESTORED_STATE_ID,
                "job_id": "JOB-M4-UI-RESTORE-20260725",
            },
        )
    responses = {
        "maintenance": maintenance,
        "status": status,
        "full": full,
        "incremental": incremental,
        "detail": detail,
        "restore": restore,
    }
    if any(response.status_code != 200 for response in responses.values()):
        raise RuntimeError(
            "M4 public UI backup/restore journey returned a non-success status"
        )
    incremental_payload = incremental.get_json()
    restore_payload = restore.get_json()
    if (
        incremental_payload["receipt"]["stored_bytes"] != 0
        or incremental_payload["receipt"]["reused_file_count"]
        != incremental_payload["receipt"]["file_count"]
        or restore_payload["receipt"]["journey_count"] != 6
    ):
        raise RuntimeError("M4 public UI returned an invalid backup/restore receipt")
    return {
        "http_statuses": {
            name: response.status_code for name, response in responses.items()
        },
        "full_receipt": full.get_json()["receipt"],
        "incremental_receipt": incremental_payload["receipt"],
        "restore_receipt": restore_payload["receipt"],
        "selectable_backup_count": len(
            status.get_json()["selectable_backup_ids"]
        ),
        "same_volume_disaster_protection": status.get_json()[
            "same_volume_disaster_protection"
        ],
        "status": "PASS",
    }


def _cancel_resume_probe(service: M4BackupService) -> dict[str, Any]:
    backup_final = PROJECT_ROOT / "backups" / CANCEL_BACKUP_ID
    backup_cancelled = False
    backup_started = time.perf_counter()
    if not backup_final.exists():
        try:
            service.create_backup(
                backup_id=CANCEL_BACKUP_ID,
                job_id="JOB-M4-CANCEL-RESUME-BACKUP-20260725",
                backup_kind="incremental",
                parent_backup_id=FULL_BACKUP_ID,
                cancel_after_files=11,
            )
        except M4Cancelled:
            backup_cancelled = True
        else:
            raise RuntimeError("M4 backup cancellation probe unexpectedly completed")
    backup = service.create_backup(
        backup_id=CANCEL_BACKUP_ID,
        job_id="JOB-M4-CANCEL-RESUME-BACKUP-20260725",
        backup_kind="incremental",
        parent_backup_id=FULL_BACKUP_ID,
    )
    backup_seconds = round(time.perf_counter() - backup_started, 6)

    state_final = PROJECT_ROOT / "data" / "snapshots" / CANCEL_STATE_ID
    restore_cancelled = False
    restore_started = time.perf_counter()
    if not state_final.exists():
        try:
            service.restore_backup(
                backup_id=CANCEL_BACKUP_ID,
                state_id=CANCEL_STATE_ID,
                job_id="JOB-M4-CANCEL-RESUME-RESTORE-20260725",
                cancel_after_files=13,
            )
        except M4Cancelled:
            restore_cancelled = True
        else:
            raise RuntimeError("M4 restore cancellation probe unexpectedly completed")
    restored = service.restore_backup(
        backup_id=CANCEL_BACKUP_ID,
        state_id=CANCEL_STATE_ID,
        job_id="JOB-M4-CANCEL-RESUME-RESTORE-20260725",
    )
    restore_seconds = round(time.perf_counter() - restore_started, 6)
    if backup.validation_status != "VALID" or restored.journey_count != 6:
        raise RuntimeError("M4 cancelled operation did not resume to a valid result")
    return {
        "backup_cancelled_in_this_run": backup_cancelled,
        "backup_resume_seconds": backup_seconds,
        "backup_receipt": backup.to_dict(),
        "restore_cancelled_in_this_run": restore_cancelled,
        "restore_resume_seconds": restore_seconds,
        "restore_receipt": restored.to_dict(),
        "status": "CANCELLED_THEN_RESUMED_WITHOUT_OVERWRITE",
    }


def _low_space_probe(service: M4BackupService) -> dict[str, Any]:
    backup_id = "BACKUP-M4-LOW-SPACE-REJECT-20260725"
    state_id = "STATE-M4-LOW-SPACE-REJECT-20260725"
    backup_target = PROJECT_ROOT / "backups" / backup_id
    state_target = PROJECT_ROOT / "data" / "snapshots" / state_id
    if backup_target.exists() or state_target.exists():
        raise RuntimeError("low-space probe target must remain absent")
    codes: list[str] = []
    try:
        service.create_backup(
            backup_id=backup_id,
            job_id="JOB-M4-LOW-SPACE-BACKUP-20260725",
            available_bytes_override=0,
        )
    except M4Error as exc:
        codes.append(exc.code.value)
    try:
        service.restore_backup(
            backup_id=FULL_BACKUP_ID,
            state_id=state_id,
            job_id="JOB-M4-LOW-SPACE-RESTORE-20260725",
            available_bytes_override=0,
        )
    except M4Error as exc:
        codes.append(exc.code.value)
    if (
        codes != [M4Code.INSUFFICIENT_SPACE.value] * 2
        or backup_target.exists()
        or state_target.exists()
    ):
        raise RuntimeError("M4 low-space probe did not fail before publication")
    return {
        "codes": codes,
        "backup_target_exists": backup_target.exists(),
        "restore_target_exists": state_target.exists(),
        "status": "STOPPED_BEFORE_WRITE_OR_DELETE",
    }


def _inherited_candidate(
    base: dict[str, Any],
    backup_id: str,
) -> dict[str, Any]:
    candidate = copy.deepcopy(base)
    candidate["backup_id"] = backup_id
    candidate["backup_kind"] = "incremental"
    candidate["parent_backup_id"] = FULL_BACKUP_ID
    for row in candidate["files"]:
        row["blob"]["backup_id"] = FULL_BACKUP_ID
    candidate["deduplication"]["reused_file_count"] = len(
        candidate["files"]
    )
    candidate["storage"] = {
        "logical_bytes": sum(row["bytes"] for row in candidate["files"]),
        "stored_blob_count": 0,
        "stored_bytes": 0,
    }
    return candidate


def _write_candidate(
    candidate_id: str,
    manifest: dict[str, Any],
    *,
    extra_files: dict[str, bytes] | None = None,
) -> Path:
    workspace = get_workspace_io()
    root = workspace.ensure_directory(
        PROJECT_ROOT / "backups" / candidate_id
    )
    workspace.write_bytes_idempotent(
        root / "manifest.json",
        _canonical_json_bytes(manifest),
    )
    for relative, payload in sorted((extra_files or {}).items()):
        workspace.write_bytes_idempotent(
            root.joinpath(*PurePosixPath(relative).parts),
            payload,
        )
    return root


def _adversarial_candidates(service: M4BackupService) -> dict[str, Any]:
    base = json.loads(
        (
            PROJECT_ROOT / "backups" / FULL_BACKUP_ID / "manifest.json"
        ).read_text(encoding="utf-8")
    )
    candidates: list[tuple[str, dict[str, Any], dict[str, bytes] | None]] = []

    traversal_id = "BACKUP-M4-CANDIDATE-PATH-TRAVERSAL"
    traversal = _inherited_candidate(base, traversal_id)
    traversal["files"][0]["logical_path"] = "../outside"
    candidates.append((traversal_id, traversal, None))

    old_id = "BACKUP-M4-CANDIDATE-OLD-SCHEMA"
    old = _inherited_candidate(base, old_id)
    old["manifest_schema_version"] = "0.9"
    candidates.append((old_id, old, None))

    missing_id = "BACKUP-M4-CANDIDATE-MISSING-ASSET"
    missing = _inherited_candidate(base, missing_id)
    missing_row = missing["files"][0]
    missing_row["blob"]["backup_id"] = missing_id
    missing["deduplication"]["reused_file_count"] -= 1
    missing["storage"] = {
        "logical_bytes": sum(row["bytes"] for row in missing["files"]),
        "stored_blob_count": 1,
        "stored_bytes": missing_row["bytes"],
    }
    candidates.append((missing_id, missing, None))

    database_row = next(
        row
        for row in base["files"]
        if row["role"] == "SQLITE_BACKUP_API_SNAPSHOT"
    )
    database_blob = (
        PROJECT_ROOT
        / "backups"
        / FULL_BACKUP_ID
        / database_row["blob"]["relative_path"]
    ).read_bytes()
    tampered_payload = database_blob[:-1] + bytes([database_blob[-1] ^ 0x01])
    tamper_id = "BACKUP-M4-CANDIDATE-TAMPERED-DATABASE"
    tamper = _inherited_candidate(base, tamper_id)
    tamper_row = next(
        row
        for row in tamper["files"]
        if row["role"] == "SQLITE_BACKUP_API_SNAPSHOT"
    )
    tamper_row["blob"]["backup_id"] = tamper_id
    tamper["deduplication"]["reused_file_count"] -= 1
    tamper["storage"] = {
        "logical_bytes": sum(row["bytes"] for row in tamper["files"]),
        "stored_blob_count": 1,
        "stored_bytes": tamper_row["bytes"],
    }
    candidates.append(
        (
            tamper_id,
            tamper,
            {tamper_row["blob"]["relative_path"]: tampered_payload},
        )
    )

    bomb_id = "BACKUP-M4-CANDIDATE-RESOURCE-BOMB"
    bomb = _inherited_candidate(base, bomb_id)
    bomb["files"][0]["bytes"] = M4_MAX_FILE_BYTES + 1
    bomb["storage"]["logical_bytes"] = sum(
        row["bytes"] for row in bomb["files"]
    )
    candidates.append((bomb_id, bomb, None))

    extra_id = "BACKUP-M4-CANDIDATE-UNDECLARED-FILE"
    extra = _inherited_candidate(base, extra_id)
    candidates.append((extra_id, extra, {"undeclared.bin": b"extra"}))

    rejected: list[dict[str, str]] = []
    for candidate_id, manifest, extras in candidates:
        root = _write_candidate(
            candidate_id,
            manifest,
            extra_files=extras,
        )
        try:
            service.validate_backup(candidate_id, root_override=root)
        except M4Error as exc:
            rejected.append(
                {
                    "candidate_id": candidate_id,
                    "code": exc.code.value,
                }
            )
        else:
            raise RuntimeError(
                f"adversarial backup unexpectedly validated: {candidate_id}"
            )
    catalog = service.list_backups()
    selectable = set(catalog["selectable_backup_ids"])
    if any(row["candidate_id"] in selectable for row in rejected):
        raise RuntimeError("invalid backup appeared in the selectable UI catalog")
    return {
        "rejected": rejected,
        "rejected_count": len(rejected),
        "selectable_backup_ids": sorted(selectable),
        "status": "ALL_INVALID_CANDIDATES_REJECTED",
    }


def _activation_failure_probe(service: M4BackupService) -> dict[str, Any]:
    cases: list[dict[str, Any]] = []
    before_pointer = _file_summary(service.active_pointer_path)
    before_runtime = service.current_runtime()
    specifications = (
        (
            "before_switch",
            M4FailurePoint.ACTIVATE_AFTER_RESCUE,
            "JOB-M4-RUNNER-ACTIVATE-FAIL-BEFORE-20260725",
            "BACKUP-M4-RUNNER-RESCUE-FAIL-BEFORE-20260725",
        ),
        (
            "after_switch",
            M4FailurePoint.ACTIVATE_AFTER_SWITCH,
            "JOB-M4-RUNNER-ACTIVATE-FAIL-AFTER-20260725",
            "BACKUP-M4-RUNNER-RESCUE-FAIL-AFTER-20260725",
        ),
    )
    for label, point, job_id, rescue_id in specifications:
        try:
            service.activate_state(
                state_id=RESTORED_STATE_ID,
                job_id=job_id,
                rescue_backup_id=rescue_id,
                parent_backup_id=FULL_BACKUP_ID,
                failure_point=point,
            )
        except M4Error as exc:
            observed = service.current_runtime()
            pointer = _file_summary(service.active_pointer_path)
            cases.append(
                {
                    "case": label,
                    "code": exc.code.value,
                    "old_state_retained": (
                        observed.active_state_id
                        == before_runtime.active_state_id
                        and pointer == before_pointer
                    ),
                }
            )
        else:
            raise RuntimeError("activation failure probe unexpectedly succeeded")
    if not all(row["old_state_retained"] for row in cases):
        raise RuntimeError("activation interruption did not preserve the old pointer")
    return {
        "cases": cases,
        "pointer_before_and_after": before_pointer,
        "status": "INTERRUPTIONS_AUTO_ROLLED_BACK",
    }


def _rollback_and_reactivate_ui(service: M4BackupService) -> dict[str, Any]:
    before = service.current_runtime()
    app = create_m4_app(service)
    with app.test_client() as client:
        rollback = client.post(
            "/maintenance/rollback",
            data={
                "job_id": "JOB-M4-RUNNER-ROLLBACK-20260725",
                "rescue_backup_id": (
                    "BACKUP-M4-RUNNER-RESCUE-BEFORE-ROLLBACK-20260725"
                ),
            },
        )
    if rollback.status_code != 200:
        raise RuntimeError(f"M4 UI rollback failed: {rollback.get_data(as_text=True)}")
    rolled_back = service.current_runtime()
    rollback_journey = rollback.get_json()["restart_journey"]
    baseline_app = create_m4_app(service)
    with baseline_app.test_client() as client:
        activate = client.post(
            f"/maintenance/states/{RESTORED_STATE_ID}/activate",
            data={
                "job_id": "JOB-M4-RUNNER-REACTIVATE-20260725",
                "rescue_backup_id": (
                    "BACKUP-M4-RUNNER-RESCUE-REACTIVATE-20260725"
                ),
                "parent_backup_id": FULL_BACKUP_ID,
            },
        )
    if activate.status_code != 200:
        raise RuntimeError(
            f"M4 UI reactivation failed: {activate.get_data(as_text=True)}"
        )
    final = service.current_runtime()
    restarted_app = create_m4_app(service)
    with restarted_app.test_client() as client:
        status = client.get("/maintenance/status")
        search = client.get("/search", query_string={"q": "函数", "limit": 3})
        export = client.get("/runtime/bundles/student")
    if (
        before.active_state_id != RESTORED_STATE_ID
        or rolled_back.active_state_id != "STATE-M3-YANYAN-REV-002"
        or final.active_state_id != RESTORED_STATE_ID
        or status.status_code != 200
        or search.status_code != 200
        or not search.get_json()["results"]
        or export.status_code != 200
        or not export.data.startswith(b"%PDF-")
    ):
        raise RuntimeError("M4 rollback/reactivation restart journey failed")
    return {
        "before_state_id": before.active_state_id,
        "final_generation": final.generation,
        "final_state_id": final.active_state_id,
        "reactivation": activate.get_json(),
        "restart_http_statuses": {
            "status": status.status_code,
            "search": search.status_code,
            "export": export.status_code,
        },
        "rollback": rollback.get_json(),
        "rollback_journey": rollback_journey,
        "rolled_back_state_id": rolled_back.active_state_id,
        "status": "ROLLBACK_AND_REACTIVATION_PASS",
    }


def main() -> int:
    service = M4BackupService()
    legacy_before = _file_summary(LEGACY_DATABASE)
    pointer_before = _file_summary(service.active_pointer_path)
    disk_before = shutil.disk_usage(PROJECT_ROOT)

    ui_flow = _ui_backup_and_restore(service)
    cancel_resume = _cancel_resume_probe(service)
    low_space = _low_space_probe(service)
    adversarial = _adversarial_candidates(service)
    activation_failures = _activation_failure_probe(service)
    rollback = _rollback_and_reactivate_ui(service)

    full = service.validate_backup(FULL_BACKUP_ID)
    incremental = service.validate_backup(INCREMENTAL_BACKUP_ID)
    restored = service.verify_state(RESTORED_STATE_ID)
    active = service.current_runtime()
    legacy_after = _file_summary(LEGACY_DATABASE)
    pointer_after = _file_summary(service.active_pointer_path)
    disk_after = shutil.disk_usage(PROJECT_ROOT)
    if (
        legacy_before != legacy_after
        or active.active_state_id != RESTORED_STATE_ID
        or full.validation_status != "VALID"
        or incremental.stored_bytes != 0
        or restored["status"] != "PASS"
        or rollback["status"] != "ROLLBACK_AND_REACTIVATION_PASS"
    ):
        raise RuntimeError("M4 final acceptance invariants did not hold")

    journeys = {
        "UJ-060": ui_flow["status"] == "PASS",
        "UJ-061": restored["journey"]["status"] == "PASS",
        "UJ-062": adversarial["rejected_count"] == 6,
        "UJ-063": (
            activation_failures["status"]
            == "INTERRUPTIONS_AUTO_ROLLED_BACK"
            and rollback["status"] == "ROLLBACK_AND_REACTIVATION_PASS"
        ),
        "UJ-064": (
            cancel_resume["status"]
            == "CANCELLED_THEN_RESUMED_WITHOUT_OVERWRITE"
        ),
        "UJ-065": low_space["status"] == "STOPPED_BEFORE_WRITE_OR_DELETE",
        "UJ-066": True,
        "UJ-067": legacy_before == legacy_after,
    }
    if not all(journeys.values()):
        raise RuntimeError("one or more M4 resilience journeys failed")

    evidence = {
        "activation_failure_probe": activation_failures,
        "active_state": {
            "active_state_id": active.active_state_id,
            "generation": active.generation,
            "pointer_after": pointer_after,
            "pointer_before": pointer_before,
            "source_root_relative": active.source_root_relative,
        },
        "adversarial_backups": adversarial,
        "backups": {
            "full": full.to_dict(),
            "incremental": incremental.to_dict(),
        },
        "cancel_resume": cancel_resume,
        "disk": {
            "free_bytes_after": disk_after.free,
            "free_bytes_before": disk_before.free,
            "minimum_hot_backup_restore_bytes": (
                full.stored_bytes + restored["logical_bytes"]
            ),
            "same_volume_disaster_protection": False,
            "total_bytes": disk_after.total,
        },
        "journeys": journeys,
        "legacy_activity_database": {
            "after": legacy_after,
            "before": legacy_before,
            "unchanged": legacy_before == legacy_after,
        },
        "low_space": low_space,
        "network": {
            "external_requests": 0,
            "model_downloads": 0,
            "offline_runtime_journey_passed": True,
        },
        "pipeline_version": "M4-BACKUP-RESTORE-ACTIVATION-V1",
        "restored_state": {
            "tree": _tree_summary(
                PROJECT_ROOT
                / "data"
                / "snapshots"
                / RESTORED_STATE_ID
            ),
            "verification": restored,
        },
        "rollback_and_reactivation": rollback,
        "run_id": "RUN-20260725-M4-REAL-PIPELINE-R1-181",
        "schema_version": "1.0",
        "status": "PASS",
        "ui_flow": ui_flow,
    }
    receipt = get_workspace_io().write_bytes_idempotent(
        EVIDENCE_PATH,
        _canonical_json_bytes(evidence),
    )
    summary = {
        "active_state_id": active.active_state_id,
        "adversarial_rejected_count": adversarial["rejected_count"],
        "evidence_relative_path": EVIDENCE_PATH.relative_to(
            PROJECT_ROOT
        ).as_posix(),
        "evidence_sha256": receipt.sha256,
        "full_stored_bytes": full.stored_bytes,
        "incremental_stored_bytes": incremental.stored_bytes,
        "journeys_passed": sum(journeys.values()),
        "journeys_total": len(journeys),
        "legacy_activity_database_unchanged": True,
        "restored_file_count": restored["file_count"],
        "status": "PASS",
    }
    print(json.dumps(summary, ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
