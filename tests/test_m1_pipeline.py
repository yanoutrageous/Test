from __future__ import annotations

from pathlib import Path

from app.database import initialize_database
from app.m1_pipeline import (
    M1_RENDERER_VERSION,
    M1PipelineConfig,
    PdfClassification,
    QuestionSlice,
    SolutionSlice,
    SourceLine,
    SourceRegion,
    _analysis_question_boundaries,
    _marker_parts,
    _normalize_extracted_text,
    build_paper_ir,
    build_question_ir,
    classify_pdf_bytes,
    inspect_formal_pdf,
    render_formal_pdf,
    split_complete_paper,
)
from app.web import create_app


def _pdf_bytes(*, with_text: bool, page_count: int = 1) -> bytes:
    import fitz

    document = fitz.open()
    try:
        for _ in range(page_count):
            page = document.new_page(width=300, height=400)
            if with_text:
                page.insert_text((40, 80), "synthetic born digital question text")
                page.insert_text(
                    (40, 110),
                    "enough searchable text for classification",
                )
            else:
                page.draw_rect(fitz.Rect(40, 60, 260, 320), color=(0, 0, 0))
        return document.tobytes(no_new_id=True)
    finally:
        document.close()


def _line(
    index: int,
    text: str,
    *,
    page_no: int = 1,
    x0: float = 60,
) -> SourceLine:
    y0 = 50 + index * 14
    return SourceLine(
        page_no=page_no,
        line_index=index,
        page_width=595,
        page_height=842,
        bbox=(x0, y0, 520, y0 + 11),
        text=text,
    )


def _complete_lines() -> tuple[SourceLine, ...]:
    lines: list[SourceLine] = []
    index = 0
    sections = (
        ("一、选择题", range(1, 9)),
        ("二、选择题：有多项符合要求", range(9, 12)),
        ("三、填空题", range(12, 15)),
        ("四、解答题", range(15, 20)),
    )
    for title, numbers in sections:
        lines.append(_line(index, title))
        index += 1
        for number in numbers:
            lines.append(
                _line(
                    index,
                    f"{number}．synthetic question {number} with enough body text",
                )
            )
            index += 1
            if number <= 11:
                lines.append(_line(index, "A．one B．two C．three D．four"))
                index += 1
    return tuple(lines)


def _question_slice(number: int = 1) -> QuestionSlice:
    line = _line(1, f"{number}．Choose one A．one B．two C．three D．four")
    region = SourceRegion(
        page_no=1,
        page_width=595,
        page_height=842,
        bbox=line.bbox,
    )
    return QuestionSlice(
        question_no=number,
        question_type="单项选择题",
        lines=(line,),
        regions=(region,),
        stem_text=line.text,
    )


def test_input_classifier_routes_no_text_without_claiming_success() -> None:
    born_digital = classify_pdf_bytes(_pdf_bytes(with_text=True))
    no_text = classify_pdf_bytes(_pdf_bytes(with_text=False))

    assert isinstance(born_digital, PdfClassification)
    assert born_digital.kind == "born_digital_text"
    assert born_digital.review_required is False
    assert no_text.kind == "pdf_without_usable_text"
    assert no_text.review_required is True
    assert "manual_review_required" in no_text.reasons


def test_private_use_math_glyphs_are_normalized_or_removed() -> None:
    assert _normalize_extracted_text(
        "x\uf0a2=1, \uf061\uf03e0, \uf075\uf075\uf072"
    ) == "x′=1, α>0, "


def test_complete_paper_split_uses_sections_and_exact_sequence() -> None:
    questions = split_complete_paper(_complete_lines())

    assert [question.question_no for question in questions] == list(range(1, 20))
    assert [question.question_type for question in questions[:8]] == [
        "单项选择题"
    ] * 8
    assert [question.question_type for question in questions[8:11]] == [
        "多项选择题"
    ] * 3
    assert sum(
        {
            **{number: 5 for number in range(1, 9)},
            **{number: 6 for number in range(9, 12)},
            **{number: 5 for number in range(12, 15)},
            15: 13,
            16: 15,
            17: 15,
            18: 17,
            19: 17,
        }[question.question_no]
        for question in questions
    ) == 150


def test_analysis_boundaries_ignore_indented_notes_and_markers_split() -> None:
    lines: list[SourceLine] = []
    index = 0
    for number in range(1, 20):
        lines.append(_line(index, f"{number}．question {number}", x0=68))
        index += 1
        lines.append(_line(index, f"{number}. note reference", x0=84))
        index += 1
    boundaries = _analysis_question_boundaries(tuple(lines))

    assert boundaries[1] == (0, 2)
    assert boundaries[19] == (36, 38)
    assert _marker_parts("题面\n【答案】A\n【解析】because") == ("A", "because")
    assert _marker_parts("题面\n【解析】full solution") == ("", "full solution")


def test_question_and_paper_ir_keep_design_and_observed_metrics_distinct() -> None:
    question = _question_slice()
    solution = SolutionSlice(
        question_no=1,
        answer_text="A",
        analysis_text="Because option A is correct.",
        analysis_pages=(1,),
    )
    question_ir = build_question_ir(question, solution)
    complete_questions = split_complete_paper(_complete_lines())
    paper_ir = build_paper_ir(complete_questions)

    assert question_ir["design_difficulty"] == 1
    assert question_ir["observed_p"] is None
    assert question_ir["expected_time_seconds"] == 120
    assert len(question_ir["options"]) == 4
    assert paper_ir["declared_total_points"] == 150
    assert sum(
        len(section["question_entries"]) for section in paper_ir["sections"]
    ) == 19


def test_formal_source_page_composition_is_byte_and_pixel_stable() -> None:
    source = _pdf_bytes(with_text=True, page_count=4)
    paper_ir = build_paper_ir(split_complete_paper(_complete_lines()))

    first = render_formal_pdf(source, paper_ir)
    second = render_formal_pdf(source, paper_ir)
    quality = inspect_formal_pdf(source, first)

    assert first == source
    assert second == first
    assert quality["renderer_version"] == M1_RENDERER_VERSION
    assert quality["differing_channel_samples"] == 0
    assert quality["crop_count"] == 0
    assert quality["overflow_count"] == 0
    assert quality["silent_font_substitution_count"] == 0


def test_web_serves_only_an_explicit_versioned_asset_root(tmp_path: Path) -> None:
    db_path = tmp_path / "candidate.sqlite3"
    asset_root = tmp_path / "derived"
    asset_root.mkdir()
    allowed = asset_root / "preview.png"
    allowed.write_bytes(b"local-preview")
    outside = tmp_path / "outside.txt"
    outside.write_text("blocked", encoding="utf-8")
    initialize_database(db_path)
    app = create_app(
        db_path=db_path,
        project_root=Path.cwd(),
        asset_roots=[asset_root],
    )
    app.config["TESTING"] = True
    client = app.test_client()

    allowed_path = allowed.relative_to(Path.cwd()).as_posix()
    outside_path = outside.relative_to(Path.cwd()).as_posix()
    assert client.get("/assets/" + allowed_path).status_code == 200
    assert client.get("/assets/" + outside_path).status_code == 404


def test_m1_config_paths_are_portable_and_project_relative() -> None:
    config = M1PipelineConfig()

    for path in (
        config.database_staging_path,
        config.database_target_path,
        config.derived_staging_root,
        config.derived_target_root,
        config.template_target_root,
    ):
        assert path.is_relative_to(Path.cwd())
