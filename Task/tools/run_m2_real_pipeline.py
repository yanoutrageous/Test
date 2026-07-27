from __future__ import annotations

import hashlib
import json
import shutil
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.m2_pipeline import (  # noqa: E402
    M2InjectedFailure,
    M2PipelineConfig,
    M2PipelineError,
    build_bundle_staging,
    full_blueprint_spec,
    load_candidate_pool,
    publish_bundle,
    run_blueprint_ui_flow,
    run_m2_real_pipeline,
    solve_blueprint,
)
from app.safety.workspace_io import get_workspace_io  # noqa: E402


MAX_EVIDENCE_FILE_BYTES = 64 * 1024 * 1024


def _file_summary(path: Path) -> dict[str, int | str]:
    payload = get_workspace_io().read_bytes(
        path,
        maximum_bytes=MAX_EVIDENCE_FILE_BYTES,
    )
    return {
        "bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }


def _tree_summary(root: Path) -> dict[str, int | str]:
    digest = hashlib.sha256()
    total_bytes = 0
    file_count = 0
    if not root.exists():
        return {
            "bytes": 0,
            "file_count": 0,
            "sha256": hashlib.sha256(b"ABSENT").hexdigest(),
        }
    files = sorted(
        (path for path in root.rglob("*") if path.is_file()),
        key=lambda path: path.relative_to(root).as_posix(),
    )
    for path in files:
        payload = get_workspace_io().read_bytes(
            path,
            maximum_bytes=MAX_EVIDENCE_FILE_BYTES,
        )
        relative_path = path.relative_to(root).as_posix()
        digest.update(relative_path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(payload).digest())
        total_bytes += len(payload)
        file_count += 1
    return {
        "bytes": total_bytes,
        "file_count": file_count,
        "sha256": digest.hexdigest(),
    }


def _atomic_failure_probe() -> dict[str, object]:
    config = M2PipelineConfig(
        job_id="JOB-M2-ATOMIC-FAILURE-R4-20260726",
        export_object_id="EXPORT-M2-ATOMIC-FAILURE-R4",
        export_id="EXPORT-M2-ATOMIC-FAILURE-R4-20260726",
    )
    if config.bundle_target_root.exists():
        raise RuntimeError("the failure-probe target must never exist")

    candidates = load_candidate_pool(config)
    full_result = solve_blueprint(candidates, full_blueprint_spec())
    ui_flow = run_blueprint_ui_flow(candidates, config=config)
    injected = False
    if not config.bundle_staging_root.exists():
        try:
            build_bundle_staging(
                config,
                candidates=candidates,
                full_result=full_result,
                blueprint_ui_flow=ui_flow,
                inject_failure_role="detailed_solution",
            )
        except M2InjectedFailure:
            injected = True
        else:
            raise RuntimeError("M2 failure injection unexpectedly succeeded")

    publish_blocked = False
    publish_error = ""
    try:
        publish_bundle(config)
    except M2PipelineError as exc:
        publish_blocked = True
        publish_error = str(exc)
    if (
        not publish_blocked
        or config.bundle_target_root.exists()
        or not config.bundle_staging_root.is_dir()
    ):
        raise RuntimeError("partial M2 bundle was not fail-closed")
    return {
        "injected_in_this_run": injected,
        "publish_blocked": publish_blocked,
        "publish_error": publish_error,
        "formal_target_exists": config.bundle_target_root.exists(),
        "partial_staging_exists": config.bundle_staging_root.is_dir(),
        "partial_staging": _tree_summary(config.bundle_staging_root),
        "status": "PARTIAL_STAGING_NOT_PUBLISHED",
    }


def main() -> int:
    config = M2PipelineConfig()
    activity_database = (
        PROJECT_ROOT / "data" / "db" / "question_bank.sqlite3"
    )
    activity_before = _file_summary(activity_database)
    failure_probe = _atomic_failure_probe()
    activity_after_failure = _file_summary(activity_database)
    if activity_after_failure != activity_before:
        raise RuntimeError("M2 failure probe changed the activity database")

    result = run_m2_real_pipeline(config)
    activity_after = _file_summary(activity_database)
    if activity_after != activity_before:
        raise RuntimeError("M2 real pipeline changed the activity database")
    if not result.get("repeat_stable"):
        raise RuntimeError("M2 repeat verification was not stable")

    verification = result.get(
        "verification",
        result.get("first_verification", {}),
    )
    if (
        verification.get("question_count") != 19
        or verification.get("declared_total_points") != 150
        or verification.get("document_page_counts")
        != {
            "answer": 11,
            "answer_sheet": 6,
            "detailed_solution": 63,
            "student": 4,
            "teacher": 15,
        }
        or verification.get("student_answer_leak_count") != 0
        or verification.get("answer_sheet_mapped_question_count") != 19
        or any(
            status != 200
            for status in verification.get(
                "ui_download_statuses",
                {},
            ).values()
        )
    ):
        raise RuntimeError("M2 published bundle failed acceptance checks")

    disk = shutil.disk_usage(PROJECT_ROOT)
    evidence = {
        "schema_version": "1.0",
        "run_id": "RUN-20260726-M2-REAL-PIPELINE-R4-203",
        "pipeline_result": result,
        "atomic_failure_probe": failure_probe,
        "activity_database": {
            "before": activity_before,
            "after_failure_probe": activity_after_failure,
            "after": activity_after,
            "unchanged": activity_before == activity_after,
        },
        "published_bundle": _tree_summary(config.bundle_target_root),
        "disk": {
            "free_bytes_after": disk.free,
            "total_bytes": disk.total,
        },
        "status": "PASS",
    }
    evidence_path = (
        PROJECT_ROOT
        / "tmp"
        / "jobs"
        / "INTERNAL"
        / "JOB-M2-REAL-FLOW-EVIDENCE-R4-20260726"
        / "m2-real-flow-evidence.json"
    )
    payload = (
        json.dumps(
            evidence,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            indent=2,
        )
        + "\n"
    ).encode("utf-8")
    receipt = get_workspace_io().write_bytes_idempotent(
        evidence_path,
        payload,
    )
    summary = {
        "activity_database_unchanged": (
            evidence["activity_database"]["unchanged"]
        ),
        "atomic_failure_status": failure_probe["status"],
        "bundle_bytes": evidence["published_bundle"]["bytes"],
        "bundle_manifest_sha256": verification.get(
            "bundle_manifest_sha256"
        ),
        "evidence_path": evidence_path.relative_to(PROJECT_ROOT).as_posix(),
        "evidence_sha256": receipt.sha256,
        "free_bytes_after": disk.free,
        "question_count": verification.get("question_count"),
        "status": "PASS",
    }
    print(json.dumps(summary, ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
