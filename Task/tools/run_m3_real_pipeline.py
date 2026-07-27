from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.m1_pipeline import load_copy_payload  # noqa: E402
from app.m3_pipeline import (  # noqa: E402
    M3InjectedFailure,
    M3PipelineConfig,
    M3PipelineError,
    build_m3_staging,
    publish_m3_state,
    rebuild_published_semantic_index,
    run_m3_real_pipeline,
)
from app.safety.context import DataClassification  # noqa: E402
from app.safety.external_source import (  # noqa: E402
    open_registered_external_source,
)
from app.safety.workspace_io import get_workspace_io  # noqa: E402
from app.source_copy import copy_registered_external_file  # noqa: E402


MAX_SOURCE_BYTES = 64 * 1024 * 1024
M3_COPY_JOB_ID = "JOB-M3-SOURCE-COPY-20260725"
M3_COPY_PURPOSE = "M3-REAL-PIPELINE"


def _canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            indent=2,
        )
        + "\n"
    ).encode("utf-8")


def _file_summary(path: Path) -> dict[str, int | str]:
    payload = get_workspace_io().read_bytes(
        path,
        maximum_bytes=MAX_SOURCE_BYTES,
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
    for path in sorted(
        (item for item in root.rglob("*") if item.is_file()),
        key=lambda item: item.relative_to(root).as_posix(),
    ):
        payload = get_workspace_io().read_bytes(
            path,
            maximum_bytes=MAX_SOURCE_BYTES,
        )
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


def _private_map() -> dict[str, dict[str, Any]]:
    path = PROJECT_ROOT / "Task" / "local" / "GOLD_SOURCE_MAP.local.json"
    payload = get_workspace_io().read_bytes(
        path,
        maximum_bytes=512 * 1024,
    )
    try:
        document = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("private source map is invalid") from exc
    if (
        document.get("schema_id")
        != "LOCAL_EXAM_BANK_PRIVATE_GOLD_SOURCE_MAP"
        or document.get("schema_version") != "1.0"
    ):
        raise RuntimeError("private source map identity is invalid")
    return {
        str(item["logical_id"]): item["selector"]
        for item in document["entries"]
    }


def _load_m3_copy(copy_id: str) -> tuple[bytes, dict[str, Any]]:
    root = PROJECT_ROOT / "Copy" / "source" / copy_id
    payload = get_workspace_io().read_bytes(
        root / "payload.bin",
        maximum_bytes=MAX_SOURCE_BYTES,
    )
    provenance_payload = get_workspace_io().read_bytes(
        root / "provenance.json",
        maximum_bytes=128 * 1024,
    )
    try:
        provenance = json.loads(provenance_payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("M3 Copy provenance is invalid") from exc
    expected = provenance.get("payload")
    digest = hashlib.sha256(payload).hexdigest()
    if (
        provenance.get("schema_version") != "1.0"
        or provenance.get("copy_id") != copy_id
        or provenance.get("classification") != "INTERNAL"
        or provenance.get("purpose") != M3_COPY_PURPOSE
        or not isinstance(expected, dict)
        or expected.get("path") != "payload.bin"
        or expected.get("bytes") != len(payload)
        or expected.get("sha256") != digest
    ):
        raise RuntimeError("M3 Copy does not match immutable provenance")
    return payload, {
        "copy_id": copy_id,
        "bytes": len(payload),
        "sha256": digest,
        "relative_path": (
            f"Copy/source/{copy_id}/payload.bin"
        ),
    }


def _copy_or_verify(
    source_path: str,
    *,
    logical_source_id: str,
    copy_id: str,
) -> tuple[bytes, dict[str, Any]]:
    root = PROJECT_ROOT / "Copy" / "source" / copy_id
    if root.exists():
        payload, summary = _load_m3_copy(copy_id)
        with open_registered_external_source(
            source_path,
            logical_id=logical_source_id,
            classification=DataClassification.INTERNAL,
        ) as lease:
            material = lease.read_once()
            lease.verify_unchanged(material.evidence)
        if material.payload != payload:
            raise RuntimeError(
                "registered source changed after immutable M3 Copy publication"
            )
        summary["operation"] = "VERIFIED_EXISTING_COPY"
        return payload, summary
    receipt = copy_registered_external_file(
        source_path,
        logical_source_id=logical_source_id,
        copy_id=copy_id,
        job_id=M3_COPY_JOB_ID,
        purpose=M3_COPY_PURPOSE,
        classification=DataClassification.INTERNAL,
    )
    payload, summary = _load_m3_copy(copy_id)
    if (
        summary["sha256"] != receipt.payload_sha256
        or summary["bytes"] != receipt.payload_bytes
    ):
        raise RuntimeError("new M3 Copy receipt does not match published bytes")
    summary["operation"] = "PUBLISHED_COPY"
    return payload, summary


def _source_materials() -> tuple[
    dict[str, dict[str, Any]],
    bytes,
    bytes,
    list[dict[str, Any]],
]:
    entries = _private_map()
    geometry_paths = entries["REF-FIG-GEOMETRY-SET"].get("paths")
    solution_paths = entries["REF-FIG-SOLUTION-SET"].get("paths")
    statistics_paths = entries["REF-FIG-STAT-SET"].get("paths")
    broken_path = entries["REF-FIG-BROKEN-SVG"].get("path")
    if (
        not isinstance(geometry_paths, list)
        or len(geometry_paths) != 3
        or not isinstance(solution_paths, list)
        or len(solution_paths) < 1
        or not isinstance(statistics_paths, list)
        or len(statistics_paths) < 1
        or not isinstance(broken_path, str)
    ):
        raise RuntimeError("M3 source selectors are incomplete")
    specifications = (
        (
            "geometry-original",
            geometry_paths[0],
            "REF-M3-FIG-GEOMETRY-ORIGINAL",
            "COPY-M3-FIG-GEOMETRY-ORIGINAL-20260725",
        ),
        (
            "geometry-auxiliary",
            geometry_paths[1],
            "REF-M3-FIG-GEOMETRY-AUXILIARY",
            "COPY-M3-FIG-GEOMETRY-AUXILIARY-20260725",
        ),
        (
            "geometry-coordinate",
            geometry_paths[2],
            "REF-M3-FIG-GEOMETRY-COORDINATE",
            "COPY-M3-FIG-GEOMETRY-COORDINATE-20260725",
        ),
        (
            "function-original",
            solution_paths[0],
            "REF-M3-FIG-FUNCTION-ORIGINAL",
            "COPY-M3-FIG-FUNCTION-ORIGINAL-20260725",
        ),
        (
            "statistics-original",
            statistics_paths[0],
            "REF-M3-FIG-STATISTICS-ORIGINAL",
            "COPY-M3-FIG-STATISTICS-ORIGINAL-20260725",
        ),
        (
            "broken",
            broken_path,
            "REF-M3-FIG-BROKEN",
            "COPY-M3-FIG-BROKEN-20260725",
        ),
    )
    payloads: dict[str, bytes] = {}
    summaries: list[dict[str, Any]] = []
    for role, path, logical_id, copy_id in specifications:
        payload, summary = _copy_or_verify(
            str(path),
            logical_source_id=logical_id,
            copy_id=copy_id,
        )
        payloads[role] = payload
        summary["role"] = role
        summaries.append(summary)
    figure_sources = {
        "geometry": {
            "source_file_revision_id": (
                "SOURCE-M3-GEOMETRY-COPY-REV-001"
            ),
            "original_payload": payloads["geometry-original"],
            "auxiliary_payload": payloads["geometry-auxiliary"],
            "coordinate_payload": payloads["geometry-coordinate"],
        },
        "function": {
            "source_file_revision_id": (
                "SOURCE-M3-FUNCTION-COPY-REV-001"
            ),
            "original_payload": payloads["function-original"],
        },
        "statistics": {
            "source_file_revision_id": (
                "SOURCE-M3-STATISTICS-COPY-REV-001"
            ),
            "original_payload": payloads["statistics-original"],
        },
    }
    font_source = load_copy_payload(
        "COPY-M1-YANYAN-PAPER-A4-20260725"
    ).payload
    return figure_sources, payloads["broken"], font_source, summaries


def _atomic_failure_probe(
    figure_sources: dict[str, dict[str, Any]],
    broken_svg_payload: bytes,
    font_source_payload: bytes,
) -> dict[str, Any]:
    config = M3PipelineConfig(
        job_id="JOB-M3-ATOMIC-FAILURE-R3-20260726",
        state_id="STATE-M3-ATOMIC-FAILURE-R3",
    )
    if config.target_root.exists():
        raise RuntimeError("M3 failure-probe target must never exist")
    injected = False
    if not config.staging_root.exists():
        try:
            build_m3_staging(
                config,
                figure_sources=figure_sources,
                broken_svg_payload=broken_svg_payload,
                font_source_payload=font_source_payload,
                inject_failure_after="figures",
            )
        except M3InjectedFailure:
            injected = True
        else:
            raise RuntimeError("M3 failure injection unexpectedly succeeded")
    blocked = False
    error = ""
    try:
        publish_m3_state(config)
    except M3PipelineError as exc:
        blocked = True
        error = str(exc)
    if (
        not blocked
        or config.target_root.exists()
        or not config.staging_root.is_dir()
    ):
        raise RuntimeError("partial M3 staging did not fail closed")
    return {
        "injected_in_this_run": injected,
        "publish_blocked": blocked,
        "publish_error": error,
        "formal_target_exists": config.target_root.exists(),
        "partial_staging_exists": config.staging_root.is_dir(),
        "partial_staging": _tree_summary(config.staging_root),
        "status": "PARTIAL_STAGING_NOT_PUBLISHED",
    }


def _run_rebuild() -> int:
    result = rebuild_published_semantic_index(M3PipelineConfig())
    evidence_path = (
        PROJECT_ROOT
        / "tmp"
        / "jobs"
        / "INTERNAL"
        / "JOB-M3-INDEX-REBUILD-EVIDENCE-R3-20260726"
        / "m3-index-rebuild-evidence.json"
    )
    receipt = get_workspace_io().write_bytes_idempotent(
        evidence_path,
        _canonical_json_bytes(result),
    )
    print(
        json.dumps(
            {
                **result,
                "evidence_relative_path": (
                    evidence_path.relative_to(PROJECT_ROOT).as_posix()
                ),
                "evidence_sha256": receipt.sha256,
            },
            ensure_ascii=True,
            sort_keys=True,
        )
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the M3 local figure/search/template acceptance flow."
    )
    parser.add_argument("--rebuild-index", action="store_true")
    args = parser.parse_args()
    if args.rebuild_index:
        return _run_rebuild()

    activity_database = (
        PROJECT_ROOT / "data" / "db" / "question_bank.sqlite3"
    )
    activity_before = _file_summary(activity_database)
    (
        figure_sources,
        broken_svg,
        font_source,
        copy_summaries,
    ) = _source_materials()
    activity_after_copy = _file_summary(activity_database)
    if activity_after_copy != activity_before:
        raise RuntimeError("M3 source Copy flow changed the activity database")
    failure_probe = _atomic_failure_probe(
        figure_sources,
        broken_svg,
        font_source,
    )
    activity_after_failure = _file_summary(activity_database)
    if activity_after_failure != activity_before:
        raise RuntimeError("M3 failure probe changed the activity database")

    config = M3PipelineConfig()
    result = run_m3_real_pipeline(
        config,
        figure_sources=figure_sources,
        broken_svg_payload=broken_svg,
        font_source_payload=font_source,
    )
    activity_after = _file_summary(activity_database)
    if activity_after != activity_before:
        raise RuntimeError("M3 real pipeline changed the activity database")
    if not result.get("repeat_stable"):
        raise RuntimeError("M3 repeated verification was not stable")
    verification = result["verification"]
    if (
        verification.get("status") != "PASS"
        or verification.get("figure_kind_count") != 3
        or verification.get("semantic_index_question_count") != 19
        or verification.get("search_hit_at_3") != 1.0
        or float(verification.get("search_mrr", 0)) < 0.8
        or verification.get("active_template_revision_id")
        != "TEMPLATE-M3-EDITABLE-B5-REV-002"
    ):
        raise RuntimeError("M3 published state failed acceptance checks")
    rebuild = rebuild_published_semantic_index(config)
    disk = shutil.disk_usage(PROJECT_ROOT)
    evidence = {
        "schema_version": "1.0",
        "run_id": "RUN-20260726-M3-REAL-PIPELINE-R3-204",
        "pipeline_result": result,
        "semantic_index_rebuild": rebuild,
        "atomic_failure_probe": failure_probe,
        "source_copies": copy_summaries,
        "activity_database": {
            "before": activity_before,
            "after_copy": activity_after_copy,
            "after_failure_probe": activity_after_failure,
            "after": activity_after,
            "unchanged": activity_before == activity_after,
        },
        "published_state": _tree_summary(config.target_root),
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
        / "JOB-M3-REAL-FLOW-EVIDENCE-R3-20260726"
        / "m3-real-flow-evidence.json"
    )
    receipt = get_workspace_io().write_bytes_idempotent(
        evidence_path,
        _canonical_json_bytes(evidence),
    )
    summary = {
        "activity_database_unchanged": True,
        "artifact_count": verification["artifact_count"],
        "atomic_failure_status": failure_probe["status"],
        "evidence_relative_path": (
            evidence_path.relative_to(PROJECT_ROOT).as_posix()
        ),
        "evidence_sha256": receipt.sha256,
        "free_bytes_after": disk.free,
        "manifest_sha256": verification["manifest_sha256"],
        "repeat_stable": result["repeat_stable"],
        "search_hit_at_3": verification["search_hit_at_3"],
        "search_mrr": verification["search_mrr"],
        "state_id": verification["state_id"],
        "status": "PASS",
    }
    print(json.dumps(summary, ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
