from __future__ import annotations

import copy
import json

import pytest

from app.domain_models import (
    DOMAIN_OBJECT_TYPES,
    DomainContractError,
    DomainRevision,
    create_domain_revision,
    validate_domain_revision,
)


SHA = "a" * 64


def _payloads() -> dict[str, dict[str, object]]:
    return {
        "source_file_revision": {
            "logical_source_id": "SOURCE-001",
            "source_sha256": SHA,
            "bytes": 12,
            "media_type": "application/pdf",
            "project_relative_path": "Copy/sources/source.pdf",
            "license_status": "user-owned",
            "pii_classification": "none",
        },
        "source_page": {
            "source_file_revision_id": "SOURCE-REV-001",
            "page_no": 1,
            "width_mm": 210,
            "height_mm": 297,
            "rotation_degrees": 0,
        },
        "source_region": {
            "source_page_id": "SOURCE-PAGE-001",
            "coordinate_space": "pdf_points_top_left",
            "bbox": [0, 0, 100, 200],
            "transform_chain_id": "TRANSFORM-001",
        },
        "question_revision": {
            "question_ir_revision_id": "QUESTION-IR-REV-001",
            "solution_revision_ids": ["SOLUTION-REV-001"],
            "figure_revision_ids": ["FIGURE-REV-001"],
        },
        "solution_revision": {
            "question_revision_id": "QUESTION-REV-001",
            "solution_ir_revision_id": "SOLUTION-IR-REV-001",
            "scoring_point_revision_ids": ["SCORING-REV-001"],
        },
        "scoring_point_revision": {
            "solution_revision_id": "SOLUTION-REV-001",
            "points": 4,
            "criteria_blocks": [{"kind": "text", "text": "criterion"}],
        },
        "taxonomy_release": {
            "taxonomy_id": "TAXONOMY-001",
            "release_version": "1.0.0",
            "terms_sha256": SHA,
        },
        "tag_assertion": {
            "question_revision_id": "QUESTION-REV-001",
            "taxonomy_release_id": "TAXONOMY-REL-001",
            "tag_id": "TAG-001",
            "evidence_revision_ids": ["EVIDENCE-REV-001"],
            "review_status": "candidate",
        },
        "figure_revision": {
            "figure_ir_revision_id": "FIGURE-IR-REV-001",
            "fallback_asset_ref": "assets/figures/fallback.svg",
            "derived_asset_refs": ["assets/figures/render.png"],
        },
        "template_revision": {
            "template_family_id": "TEMPLATE-NEW9-B5-182X257",
            "token_contract_sha256": SHA,
            "font_manifest_revision_id": "FONT-MANIFEST-REV-001",
        },
        "font_manifest": {
            "fonts": [
                {
                    "font_id": "FONT-001",
                    "family": "Test Serif",
                    "version": "1.0",
                    "sha256": SHA,
                    "glyph_coverage": ["latin", "cjk"],
                    "license_status": "redistributable",
                    "redistributable": True,
                    "fallback_font_id": None,
                }
            ],
            "fallback_policy": "fail-on-silent-substitution",
        },
        "blueprint_revision": {
            "taxonomy_release_id": "TAXONOMY-REL-001",
            "constraints": [{"kind": "hard", "field": "points", "value": 150}],
        },
        "candidate_pool_snapshot": {
            "question_revision_ids": ["QUESTION-REV-001"],
            "query_contract_sha256": SHA,
        },
        "paper_revision": {
            "paper_ir_revision_id": "PAPER-IR-REV-001",
            "blueprint_revision_id": "BLUEPRINT-REV-001",
            "candidate_pool_snapshot_id": "POOL-SNAPSHOT-001",
        },
        "export_bundle": {
            "paper_revision_id": "PAPER-REV-001",
            "artifact_refs": ["exports/paper.pdf", "exports/manifest.json"],
            "manifest_sha256": SHA,
        },
        "backup_set": {
            "state_id": "ACTIVE-STATE-001",
            "database_backup_id": "DATABASE-BACKUP-001",
            "asset_manifest_sha256": SHA,
        },
        "active_state": {
            "pointers": {
                "paper_revision": "PAPER-REV-001",
                "taxonomy_release": "TAXONOMY-REL-001",
            },
        },
        "review_event": {
            "subject_revision_id": "QUESTION-REV-001",
            "decision": "approve",
            "actor_ref": "ACTOR-001",
            "evidence_revision_ids": ["EVIDENCE-REV-001"],
        },
        "audit_event": {
            "action": "publish",
            "subject_revision_id": "PAPER-REV-001",
            "result": "success",
            "evidence_sha256": SHA,
        },
    }


def _revision(object_type: str) -> DomainRevision:
    return create_domain_revision(
        object_type=object_type,
        object_id=f"{object_type.upper().replace('_', '-')}-001",
        revision_id=f"{object_type.upper().replace('_', '-')}-REV-001",
        revision_no=1,
        state="candidate",
        created_at="2026-07-25T00:00:00Z",
        predecessor_revision_id=None,
        payload=_payloads()[object_type],
    )


@pytest.mark.parametrize("object_type", sorted(DOMAIN_OBJECT_TYPES))
def test_all_versioned_domain_object_contracts_round_trip(object_type: str) -> None:
    revision = _revision(object_type)

    restored = DomainRevision.from_json_bytes(revision.to_json_bytes())

    assert restored.document == revision.document
    assert restored.content_sha256 == revision.content_sha256
    assert restored.to_json_bytes() == revision.to_json_bytes()


def test_domain_object_set_is_frozen_to_m0_scope() -> None:
    assert DOMAIN_OBJECT_TYPES == set(_payloads())


def test_domain_revision_rejects_content_tampering() -> None:
    document = _revision("paper_revision").document
    document["state"] = "approved"

    with pytest.raises(DomainContractError, match="content_sha256"):
        validate_domain_revision(document)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value.__setitem__("unknown", True), "unknown fields"),
        (
            lambda value: value["payload"].__setitem__("unknown", True),
            "unknown fields",
        ),
        (
            lambda value: value.__setitem__("extensions", {"future": True}),
            "x-\\*",
        ),
        (
            lambda value: value["payload"].__setitem__(
                "project_relative_path", "E:\\private\\source.pdf"
            ),
            "project-relative",
        ),
    ],
)
def test_domain_revision_rejects_ambiguous_or_nonportable_fields(
    mutation,
    message: str,
) -> None:
    document = _revision("source_file_revision").document
    mutation(document)

    with pytest.raises(DomainContractError, match=message):
        validate_domain_revision(document)


def test_domain_revision_accepts_namespaced_extensions_when_rehashed() -> None:
    base = _payloads()["source_page"]
    base["extensions"] = {"x-test-note": {"value": 1}}
    revision = create_domain_revision(
        object_type="source_page",
        object_id="SOURCE-PAGE-001",
        revision_id="SOURCE-PAGE-REV-001",
        revision_no=2,
        state="reviewed",
        created_at="2026-07-25T00:00:00Z",
        predecessor_revision_id="SOURCE-PAGE-REV-000",
        payload=base,
        extensions={"x-test-owner": "reviewer"},
    )

    assert revision.document["extensions"]["x-test-owner"] == "reviewer"
    assert revision.document["payload"]["extensions"]["x-test-note"]["value"] == 1


def test_revision_chain_requires_explicit_predecessor() -> None:
    with pytest.raises(DomainContractError, match="predecessor"):
        create_domain_revision(
            object_type="paper_revision",
            object_id="PAPER-001",
            revision_id="PAPER-REV-002",
            revision_no=2,
            state="candidate",
            created_at="2026-07-25T00:00:00Z",
            predecessor_revision_id=None,
            payload=_payloads()["paper_revision"],
        )


def test_domain_revision_rejects_impossible_calendar_timestamp() -> None:
    with pytest.raises(DomainContractError, match="real UTC calendar"):
        create_domain_revision(
            object_type="paper_revision",
            object_id="PAPER-001",
            revision_id="PAPER-REV-001",
            revision_no=1,
            state="candidate",
            created_at="2026-13-40T25:61:61Z",
            predecessor_revision_id=None,
            payload=_payloads()["paper_revision"],
        )


def test_active_state_requires_exact_revision_pointers() -> None:
    payload = copy.deepcopy(_payloads()["active_state"])
    payload["pointers"]["paper_revision"] = "latest"

    with pytest.raises(DomainContractError, match="contracted identifier"):
        create_domain_revision(
            object_type="active_state",
            object_id="ACTIVE-STATE-001",
            revision_id="ACTIVE-STATE-REV-001",
            revision_no=1,
            state="candidate",
            created_at="2026-07-25T00:00:00Z",
            predecessor_revision_id=None,
            payload=payload,
        )


def test_duplicate_json_keys_are_rejected_before_validation() -> None:
    payload = json.dumps(_revision("paper_revision").document)
    duplicate = payload.replace(
        '"schema_id": "LOCAL_EXAM_BANK_DOMAIN_REVISION"',
        '"schema_id": "LOCAL_EXAM_BANK_DOMAIN_REVISION", '
        '"schema_id": "LOCAL_EXAM_BANK_DOMAIN_REVISION"',
        1,
    ).encode("utf-8")

    with pytest.raises(DomainContractError, match="duplicate JSON key"):
        DomainRevision.from_json_bytes(duplicate)
