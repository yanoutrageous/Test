from __future__ import annotations

import hashlib
import json
import shutil
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.m1_pipeline import (  # noqa: E402
    M1PipelineConfig,
    classify_pdf_bytes,
    run_m1_real_pipeline,
)
from app.safety.workspace_io import get_workspace_io  # noqa: E402


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    if not root.exists():
        digest.update(b"ABSENT")
        return digest.hexdigest()
    for path in sorted(
        (item for item in root.rglob("*") if item.is_file()),
        key=lambda item: item.relative_to(root).as_posix(),
    ):
        relative = path.relative_to(root).as_posix()
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def _no_text_pdf() -> bytes:
    import fitz

    document = fitz.open()
    try:
        page = document.new_page(width=300, height=400)
        page.draw_rect(fitz.Rect(40, 60, 260, 320), color=(0, 0, 0))
        return document.tobytes(no_new_id=True)
    finally:
        document.close()


def main() -> int:
    config = M1PipelineConfig()
    activity_database = PROJECT_ROOT / "data" / "db" / "question_bank.sqlite3"
    activity_before = {
        "bytes": activity_database.stat().st_size,
        "sha256": _sha256(activity_database),
    }

    protected_before = _tree_digest(PROJECT_ROOT / "data" / "derived")
    failure_classification = classify_pdf_bytes(_no_text_pdf())
    protected_after_failure = _tree_digest(PROJECT_ROOT / "data" / "derived")
    activity_after_failure = {
        "bytes": activity_database.stat().st_size,
        "sha256": _sha256(activity_database),
    }
    if (
        not failure_classification.review_required
        or protected_before != protected_after_failure
        or activity_before != activity_after_failure
    ):
        raise RuntimeError("M1 failure-routing probe polluted protected state")

    result = run_m1_real_pipeline(config)
    activity_after = {
        "bytes": activity_database.stat().st_size,
        "sha256": _sha256(activity_database),
    }
    if activity_after != activity_before:
        raise RuntimeError("M1 real pipeline changed the activity database")
    if not result.get("repeat_stable"):
        raise RuntimeError("M1 repeat verification was not stable")

    disk = shutil.disk_usage(PROJECT_ROOT)
    evidence = {
        "schema_version": "1.0",
        "run_id": "RUN-20260725-M1-REAL-PIPELINE-R2-153",
        "pipeline_result": result,
        "failure_routing": {
            "classification": failure_classification.to_dict(),
            "activity_database_unchanged": activity_before == activity_after_failure,
            "formal_asset_tree_unchanged": protected_before == protected_after_failure,
            "status": "REVIEW_REQUIRED_NO_POLLUTION",
        },
        "activity_database": {
            "before": activity_before,
            "after": activity_after,
            "unchanged": activity_before == activity_after,
        },
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
        / "JOB-M1-REAL-FLOW-EVIDENCE-R2-20260725"
        / "m1-real-flow-evidence.json"
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
    receipt = get_workspace_io().write_bytes_idempotent(evidence_path, payload)
    summary = {
        "activity_database_unchanged": evidence["activity_database"]["unchanged"],
        "evidence_path": evidence_path.relative_to(PROJECT_ROOT).as_posix(),
        "evidence_sha256": receipt.sha256,
        "failure_routing_status": evidence["failure_routing"]["status"],
        "free_bytes_after": disk.free,
        "formal_pdf_sha256": result.get("verification", result.get("first_verification", {})).get(
            "formal_pdf_sha256"
        ),
        "question_count": result.get("question_count", result.get("first_verification", {}).get("question_count")),
        "status": "PASS",
    }
    print(json.dumps(summary, ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
