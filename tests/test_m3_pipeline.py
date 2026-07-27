from __future__ import annotations

import copy

import pytest

import app.m3_pipeline as m3
from app.m1_pipeline import load_copy_payload


_SAFE_SVG = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">'
    '<rect width="100" height="100" fill="#ffffff"/>'
    '<line x1="10" y1="90" x2="90" y2="10" stroke="#000000"/>'
    "</svg>"
).encode("utf-8")
_BROKEN_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" '
    'xmlns="http://www.w3.org/2000/svg"></svg>'
).encode("utf-8")


def _figure_sources() -> dict[str, dict[str, object]]:
    return {
        "geometry": {
            "source_file_revision_id": "SOURCE-M3-TEST-GEOMETRY-REV-001",
            "original_payload": _SAFE_SVG,
            "auxiliary_payload": _SAFE_SVG,
            "coordinate_payload": _SAFE_SVG,
        },
        "function": {
            "source_file_revision_id": "SOURCE-M3-TEST-FUNCTION-REV-001",
            "original_payload": _SAFE_SVG,
        },
        "statistics": {
            "source_file_revision_id": "SOURCE-M3-TEST-STATISTICS-REV-001",
            "original_payload": _SAFE_SVG,
        },
    }


def _font_source() -> bytes:
    return load_copy_payload(
        "COPY-M1-YANYAN-PAPER-A4-20260725"
    ).payload


def test_taxonomy_alias_deprecation_and_domain_release_are_explicit() -> None:
    taxonomy = m3.build_taxonomy_release()

    assert taxonomy["status"] == "approved"
    assert taxonomy["domain_revision"]["object_type"] == "taxonomy_release"
    assert (
        m3.resolve_taxonomy_term(taxonomy, "解析法")
        == "METHOD-COORDINATE"
    )
    assert (
        m3.resolve_taxonomy_term(taxonomy, "METHOD-OLD-ANALYTIC")
        == "METHOD-COORDINATE"
    )
    assert m3.resolve_taxonomy_term(taxonomy, "不存在的标签") is None
    assert taxonomy["migration_from"]["TAXONOMY-M2-STRUCTURAL-V1"] == {
        "METHOD-OLD-ANALYTIC": "METHOD-COORDINATE"
    }


def test_tags_require_evidence_and_solution_change_stales_dependencies() -> None:
    config = m3.M3PipelineConfig()
    documents = m3.load_search_documents(config)
    taxonomy = m3.build_taxonomy_release()
    assertions = m3.build_tag_assertion_candidates(documents, taxonomy)
    state = m3.M3WorkbenchState(
        figures={},
        taxonomy=taxonomy,
        assertions=assertions,
        documents=documents,
        semantic_index=m3.build_semantic_index(
            documents,
            taxonomy,
            assertions,
        ),
        templates={},
        active_template_revision_id="TEMPLATE-M3-TEST-REV-001",
    )

    with pytest.raises(m3.M3PipelineError, match="requires concrete"):
        m3.review_tag_assertion(
            state,
            "TAG-M3-INVALID-NO-EVIDENCE",
            decision="approve",
            reason="must fail closed",
        )
    approved = m3.review_tag_assertion(
        state,
        "TAG-M3-003",
        decision="approve",
        reason="evidence checked",
    )
    state.semantic_index = m3.build_semantic_index(
        documents,
        taxonomy,
        assertions,
    )
    event = m3.mark_solution_changed(
        state,
        approved["solution_revision_id"],
        "f" * 64,
    )

    assert state.assertions["TAG-M3-003"]["status"] == "stale"
    assert event["stale_assertion_ids"] == ["TAG-M3-003"]
    assert event["stale_embedding_qids"]
    assert any(
        row["status"] == "stale"
        for row in state.semantic_index["documents"]
        if row["solution_revision_id"] == approved["solution_revision_id"]
    )


def test_svg_and_tikz_boundaries_reject_active_or_malformed_content() -> None:
    report = m3.validate_and_sanitize_svg(_SAFE_SVG)

    assert report["monochrome"] is True
    assert report["active_content_count"] == 0
    with pytest.raises(m3.M3PipelineError, match="malformed"):
        m3.validate_and_sanitize_svg(_BROKEN_SVG)
    with pytest.raises(m3.M3PipelineError, match="forbidden"):
        m3.validate_and_sanitize_svg(
            (
                '<svg xmlns="http://www.w3.org/2000/svg">'
                '<script>alert(1)</script></svg>'
            ).encode("utf-8")
        )
    with pytest.raises(m3.M3PipelineError, match="unsafe"):
        m3.validate_safe_tikz(
            b"\\begin{tikzpicture}\\input{outside}\\end{tikzpicture}"
        )


def test_figure_ir_renderers_share_semantics_and_rejection_keeps_preferred() -> None:
    config = m3.M3PipelineConfig()
    figures, assets = m3.build_figure_tracks(
        config,
        _figure_sources(),
        broken_svg_payload=_BROKEN_SVG,
    )
    state = m3.M3WorkbenchState(
        figures=figures,
        taxonomy={},
        assertions={},
        documents={},
        semantic_index={"manifest": {}, "documents": []},
        templates={},
        active_template_revision_id="TEMPLATE-M3-TEST-REV-001",
    )

    assert set(figures) == {"geometry", "function", "statistics"}
    assert all(
        figures[kind]["ir"]["figure_kind"] == kind for kind in figures
    )
    assert all(
        figures[kind]["revisions"][
            f"FIGURE-M3-{kind.upper()}-SVG-REV-002"
        ]["validation"]["passed"]
        for kind in figures
    )
    assert m3.validate_and_sanitize_svg(
        assets["figures/statistics/generated.svg"]
    )["monochrome"]
    preferred = figures["statistics"]["preferred_revision_id"]
    with pytest.raises(m3.M3PipelineError, match="cannot be approved"):
        m3.review_figure_revision(
            state,
            "statistics",
            "FIGURE-M3-STATISTICS-BROKEN-REV-004",
            decision="approve",
        )
    assert figures["statistics"]["preferred_revision_id"] == preferred
    rejected = m3.review_figure_revision(
        state,
        "statistics",
        "FIGURE-M3-STATISTICS-BROKEN-REV-004",
        decision="reject",
    )
    assert rejected["status"] == "rejected"
    assert figures["statistics"]["preferred_revision_id"] == preferred


def test_template_tokens_font_and_visual_regression_fail_closed() -> None:
    templates, active, _assets, font_manifest = m3.build_template_tracks(
        _font_source()
    )

    assert active == m3.M3_TEMPLATE_BASE_ID
    assert templates[m3.M3_TEMPLATE_PASS_ID]["regression"]["passed"] is True
    assert templates[m3.M3_TEMPLATE_FAIL_ID]["regression"]["passed"] is False
    assert (
        templates[m3.M3_TEMPLATE_FAIL_ID]["regression"][
            "maximum_anchor_delta_mm"
        ]
        > 1.0
    )
    assert font_manifest["silent_font_substitution_count"] == 0
    unsafe = dict(
        templates[m3.M3_TEMPLATE_BASE_ID]["tokens"],
        footer="\\input{outside}",
    )
    with pytest.raises(m3.M3PipelineError, match="uncontrolled"):
        m3.validate_template_tokens(unsafe)
    with pytest.raises(m3.M3PipelineError, match="MISSING_REQUIRED_FONT"):
        m3.render_template_preview(
            templates[m3.M3_TEMPLATE_BASE_ID]["tokens"],
            font_payload=None,
            revision_id="TEMPLATE-M3-MISSING-FONT-TEST",
        )

    state = m3.M3WorkbenchState(
        figures={},
        taxonomy={},
        assertions={},
        documents={},
        semantic_index={"manifest": {}, "documents": []},
        templates=copy.deepcopy(templates),
        active_template_revision_id=active,
    )
    with pytest.raises(m3.M3PipelineError, match="activation is blocked"):
        m3.review_template_revision(
            state,
            m3.M3_TEMPLATE_FAIL_ID,
            decision="approve",
        )
    m3.review_template_revision(
        state,
        m3.M3_TEMPLATE_PASS_ID,
        decision="approve",
    )
    assert state.active_template_revision_id == m3.M3_TEMPLATE_PASS_ID
    assert m3.baseline_update_request()["status"] == 403


def test_public_ui_flow_covers_required_journeys_and_search_quality() -> None:
    config = m3.M3PipelineConfig()
    state, _assets, _font_manifest = m3.create_m3_workbench(
        config,
        figure_sources=_figure_sources(),
        broken_svg_payload=_BROKEN_SVG,
        font_source_payload=_font_source(),
    )

    flow = m3.run_m3_ui_flow(state, config=config)
    quality = m3.evaluate_m3_search(config, state)

    assert flow["status"] == "PASS"
    assert set(flow["required_journeys"]).issubset(
        flow["journey_counts"]
    )
    assert flow["basket"]
    assert state.active_template_revision_id == m3.M3_TEMPLATE_PASS_ID
    assert quality["passed"] is True
    assert quality["hit_at_3"] == 1.0
    assert quality["mrr"] >= 0.8
    assert all(
        result["match_reasons"]
        for query in ("直方图", "极值点偏移")
        for result in m3.hybrid_search(
            config,
            state,
            query=query,
            limit=3,
        )["results"]
    )


def test_published_m3_state_and_index_rebuild_are_repeat_stable() -> None:
    config = m3.M3PipelineConfig()

    first = m3.verify_m3_state(config)
    second = m3.verify_m3_state(config)
    rebuilt = m3.rebuild_published_semantic_index(config)

    assert first == second
    assert first["status"] == "PASS"
    assert first["artifact_count"] == 38
    assert first["semantic_index_question_count"] == 19
    assert rebuilt["stable"] is True
    assert rebuilt["index_payload_sha256"]
