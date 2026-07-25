from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .database import (
    connect_database,
    connect_database_read_only,
    initialize_database,
)
from .ir_contracts import (
    PAPER_IR_SCHEMA_ID,
    QUESTION_IR_SCHEMA_ID,
    canonical_json_bytes,
    validate_paper_ir,
    validate_question_ir,
)
from .project_root import PROJECT_ROOT
from .question_split import PageTextBlock, _visual_text_lines
from .safety.context import validate_safe_id
from .safety.workspace_io import get_workspace_io
from .web import create_app


M1_PIPELINE_VERSION = "M1-REAL-PAPER-V2-SYMBOL-PUA"
M1_RENDERER_VERSION = "SOURCE-PAGE-COMPOSITION-V1"
M1_TEMPLATE_REVISION_ID = "TEMPLATE-A4-SOURCE-COMPOSE-REV-002"
M1_SOURCE_REVISION_ID = "SOURCE-FILE-PAPER-REV-001"
M1_PAPER_REVISION_ID = "PAPER-YANYAN-202605-REV-002"
M1_PAPER_IR_REVISION_ID = "PAPER-IR-YANYAN-202605-REV-002"
M1_FIXED_TIMESTAMP = "2026-07-25T00:00:00Z"
MAX_COPY_BYTES = 32 * 1024 * 1024
PAGE_RENDER_DPI = 144

_QUESTION_ANCHOR = re.compile(r"^\s*(\d{1,2})[.．]\s*")
_ANSWER_ENTRY = re.compile(
    r"(?<!\d)(\d{1,2})[.．]\s*(.*?)(?=(?:\s+\d{1,2}[.．]\s*)|$)"
)
_ANSWER_SECTION_SUFFIX = re.compile(
    r"\s+[一二三四五六][、.．](?:选择题|填空题|解答题)?\s*$"
)
_OPTION_ANCHOR = re.compile(r"(?:(?<=\s)|^)([ABCD])[.．]\s*")
_PAGE_FOOTER = re.compile(r"第\s*\d+\s*页")

# Word/Office PDFs in this real batch expose mathematical glyphs as U+F000
# private-use characters.  This fixed mapping covers the observed Adobe Symbol
# encoding.  Decorative over-arrow and extensible-brace pieces are removed
# because the source crop remains the authoritative visual representation.
_PDF_PRIVATE_USE_TRANSLATION = str.maketrans(
    {
        "\uf02b": "+",
        "\uf02d": "−",
        "\uf03c": "<",
        "\uf03d": "=",
        "\uf03e": ">",
        "\uf044": "Δ",
        "\uf050": "P",
        "\uf057": "Ω",
        "\uf05b": "[",
        "\uf05d": "]",
        "\uf05e": "⊥",
        "\uf061": "α",
        "\uf062": "β",
        "\uf06a": "ϕ",
        "\uf06c": "λ",
        "\uf06d": "μ",
        "\uf070": "π",
        "\uf071": "θ",
        "\uf072": "",
        "\uf075": "",
        "\uf077": "ω",
        "\uf0a2": "′",
        "\uf0a3": "≤",
        "\uf0a5": "∞",
        "\uf0b0": "°",
        "\uf0b1": "±",
        "\uf0b3": "≥",
        "\uf0b4": "×",
        "\uf0b9": "≠",
        "\uf0bc": "…",
        "\uf0c6": "∅",
        "\uf0c7": "∩",
        "\uf0c8": "∪",
        "\uf0cc": "⊂",
        "\uf0ce": "∈",
        "\uf0d0": "∠",
        "\uf0d7": "⋅",
        "\uf0e1": "〈",
        "\uf0e5": "∑",
        "\uf0ec": "",
        "\uf0ed": "",
        "\uf0ee": "",
        "\uf0ef": "",
        "\uf0f1": "〉",
    }
)
_REFERENCE_ANSWER_EXTRACTED_GOLD = {
    12: "1−",
    13: "x 2 − y 2 = 1",
}
_REFERENCE_ANSWER_VISUAL_CORRECTIONS = {
    12: "−1",
    13: "x² − y² = 1",
}

_SCORE_POINTS = {
    **{number: 5 for number in range(1, 9)},
    **{number: 6 for number in range(9, 12)},
    **{number: 5 for number in range(12, 15)},
    15: 13,
    16: 15,
    17: 15,
    18: 17,
    19: 17,
}
_DESIGN_DIFFICULTY = {
    1: 1,
    2: 1,
    3: 1,
    4: 1,
    5: 2,
    6: 2,
    7: 2,
    8: 3,
    9: 2,
    10: 3,
    11: 3,
    12: 2,
    13: 3,
    14: 3,
    15: 2,
    16: 3,
    17: 3,
    18: 4,
    19: 5,
}
_EXPECTED_TIME_SECONDS = {
    **{number: 120 for number in range(1, 9)},
    **{number: 180 for number in range(9, 15)},
    15: 720,
    16: 900,
    17: 900,
    18: 1020,
    19: 1020,
}


class M1PipelineError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class CopyPayload:
    copy_id: str
    relative_path: str
    sha256: str
    size_bytes: int
    payload: bytes
    provenance: dict[str, Any]


@dataclass(frozen=True, slots=True)
class PdfClassification:
    kind: str
    page_count: int
    text_characters: int
    image_count: int
    review_required: bool
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "page_count": self.page_count,
            "text_characters": self.text_characters,
            "image_count": self.image_count,
            "review_required": self.review_required,
            "reasons": list(self.reasons),
        }


@dataclass(frozen=True, slots=True)
class SourceLine:
    page_no: int
    line_index: int
    page_width: float
    page_height: float
    bbox: tuple[float, float, float, float]
    text: str


@dataclass(frozen=True, slots=True)
class SourceRegion:
    page_no: int
    page_width: float
    page_height: float
    bbox: tuple[float, float, float, float]

    def to_dict(self) -> dict[str, Any]:
        x0, y0, x1, y1 = self.bbox
        return {
            "page_no": self.page_no,
            "coordinate_space": "pdf_points_top_left",
            "units": "pt",
            "page_width": round(self.page_width, 6),
            "page_height": round(self.page_height, 6),
            "bbox": {
                "x0": round(x0, 6),
                "y0": round(y0, 6),
                "x1": round(x1, 6),
                "y1": round(y1, 6),
            },
            "transform": {
                "kind": "crop",
                "matrix_3x3": [1, 0, 0, 0, 1, 0, 0, 0, 1],
                "algorithm": "PYMUPDF-PDF-POINT-CLIP-V1",
            },
        }


@dataclass(frozen=True, slots=True)
class QuestionSlice:
    question_no: int
    question_type: str
    lines: tuple[SourceLine, ...]
    regions: tuple[SourceRegion, ...]
    stem_text: str


@dataclass(frozen=True, slots=True)
class SolutionSlice:
    question_no: int
    answer_text: str
    analysis_text: str
    analysis_pages: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class M1PipelineConfig:
    paper_copy_id: str = "COPY-M1-YANYAN-PAPER-A4-20260725"
    answer_copy_id: str = "COPY-M1-YANYAN-ANSWER-20260725"
    analysis_copy_id: str = "COPY-M1-YANYAN-ANALYSIS-20260725"
    job_id: str = "JOB-M1-YANYAN-PIPELINE-R2-20260725"
    state_id: str = "STATE-M1-YANYAN-REV-002"
    pipeline_id: str = "M1-REAL-PIPELINE"
    object_id: str = "PAPER-YANYAN-202605"
    revision_id: str = "REV-002"
    template_object_id: str = "A4-SOURCE-COMPOSITION"
    template_revision_id: str = "REV-002"
    paper_code: str = "YANYAN-202605"
    title: str = "2026年5月“炎炎杯”模拟演练数学试卷"
    year: int = 2026

    def __post_init__(self) -> None:
        for field_name in (
            "paper_copy_id",
            "answer_copy_id",
            "analysis_copy_id",
            "job_id",
            "state_id",
            "pipeline_id",
            "object_id",
            "revision_id",
            "template_object_id",
            "template_revision_id",
            "paper_code",
        ):
            validate_safe_id(str(getattr(self, field_name)), field_name=field_name)

    @property
    def job_root(self) -> Path:
        return PROJECT_ROOT / "tmp" / "jobs" / "INTERNAL" / self.job_id

    @property
    def database_staging_root(self) -> Path:
        return self.job_root / "db-release"

    @property
    def database_staging_path(self) -> Path:
        return self.database_staging_root / "question_bank.sqlite3"

    @property
    def derived_staging_root(self) -> Path:
        return self.job_root / "derived-release"

    @property
    def template_staging_root(self) -> Path:
        return self.job_root / "template-release"

    @property
    def database_target_root(self) -> Path:
        return PROJECT_ROOT / "data" / "db" / "versions" / self.state_id

    @property
    def database_target_path(self) -> Path:
        return self.database_target_root / "question_bank.sqlite3"

    @property
    def derived_target_root(self) -> Path:
        return (
            PROJECT_ROOT
            / "data"
            / "derived"
            / "papers"
            / self.pipeline_id
            / self.object_id
            / self.revision_id
        )

    @property
    def template_target_root(self) -> Path:
        return (
            PROJECT_ROOT
            / "data"
            / "templates"
            / self.template_object_id
            / self.template_revision_id
        )


def _canonical_json_bytes(value: Any, *, pretty: bool = False) -> bytes:
    if pretty:
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
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _normalize_extracted_text(text: str) -> str:
    normalized = text.translate(_PDF_PRIVATE_USE_TRANSLATION)
    remaining = sorted(
        {ord(character) for character in normalized if 0xE000 <= ord(character) <= 0xF8FF}
    )
    if remaining:
        encoded = ",".join(f"U+{codepoint:04X}" for codepoint in remaining)
        raise M1PipelineError(f"unsupported private-use PDF glyphs: {encoded}")
    return normalized


def _relative(path: Path) -> str:
    try:
        return path.resolve().relative_to(PROJECT_ROOT.resolve()).as_posix()
    except ValueError as exc:
        raise M1PipelineError("M1 path escaped the project root") from exc


def load_copy_payload(copy_id: str) -> CopyPayload:
    validate_safe_id(copy_id, field_name="copy_id")
    copy_root = PROJECT_ROOT / "Copy" / "source" / copy_id
    workspace_io = get_workspace_io()
    provenance_bytes = workspace_io.read_bytes(
        copy_root / "provenance.json",
        maximum_bytes=128 * 1024,
    )
    payload = workspace_io.read_bytes(
        copy_root / "payload.bin",
        maximum_bytes=MAX_COPY_BYTES,
    )
    try:
        provenance = json.loads(provenance_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise M1PipelineError("Copy provenance is not valid UTF-8 JSON") from exc
    expected = provenance.get("payload") if isinstance(provenance, dict) else None
    digest = _sha256(payload)
    if (
        provenance.get("schema_version") != "1.0"
        or provenance.get("copy_id") != copy_id
        or provenance.get("classification") != "INTERNAL"
        or provenance.get("purpose") != "M1-REAL-PIPELINE"
        or not isinstance(expected, dict)
        or expected.get("path") != "payload.bin"
        or expected.get("bytes") != len(payload)
        or expected.get("sha256") != digest
    ):
        raise M1PipelineError("Copy payload does not match its immutable provenance")
    return CopyPayload(
        copy_id=copy_id,
        relative_path=_relative(copy_root / "payload.bin"),
        sha256=digest,
        size_bytes=len(payload),
        payload=payload,
        provenance=provenance,
    )


def classify_pdf_bytes(payload: bytes) -> PdfClassification:
    import fitz

    if type(payload) is not bytes or not payload.startswith(b"%PDF-"):
        raise M1PipelineError("input is not a PDF byte stream")
    try:
        with fitz.open(stream=payload, filetype="pdf") as document:
            text_characters = 0
            image_count = 0
            for page in document:
                text_characters += len("".join(page.get_text("text").split()))
                image_count += len(page.get_images(full=True))
            page_count = document.page_count
    except Exception as exc:
        raise M1PipelineError("PDF cannot be opened safely") from exc
    if page_count < 1:
        return PdfClassification(
            kind="empty_pdf",
            page_count=0,
            text_characters=0,
            image_count=0,
            review_required=True,
            reasons=("empty_document",),
        )
    minimum_text = max(40, page_count * 20)
    if text_characters >= minimum_text:
        return PdfClassification(
            kind="born_digital_text",
            page_count=page_count,
            text_characters=text_characters,
            image_count=image_count,
            review_required=False,
            reasons=(),
        )
    if image_count:
        return PdfClassification(
            kind="scanned_or_image_pdf",
            page_count=page_count,
            text_characters=text_characters,
            image_count=image_count,
            review_required=True,
            reasons=("no_usable_text_layer", "ocr_out_of_scope_v1"),
        )
    return PdfClassification(
        kind="pdf_without_usable_text",
        page_count=page_count,
        text_characters=text_characters,
        image_count=0,
        review_required=True,
        reasons=("no_usable_text_layer", "manual_review_required"),
    )


def extract_pdf_lines(payload: bytes) -> tuple[SourceLine, ...]:
    import fitz

    lines: list[SourceLine] = []
    with fitz.open(stream=payload, filetype="pdf") as document:
        for page_index, page in enumerate(document):
            page_no = page_index + 1
            page_lines: tuple[PageTextBlock, ...] = _visual_text_lines(
                page,
                page_no=page_no,
            )
            for item in page_lines:
                lines.append(
                    SourceLine(
                        page_no=page_no,
                        line_index=item.block_index,
                        page_width=float(page.rect.width),
                        page_height=float(page.rect.height),
                        bbox=item.bbox,
                        text=_normalize_extracted_text(item.text),
                    )
                )
    return tuple(lines)


def _section_type(text: str) -> str | None:
    compact = "".join(text.split())
    if re.match(r"^[一二三四五六七八九十]+[、.．]", compact) is None:
        return None
    if compact.startswith("二、选择题") or (
        "选择题" in compact and ("多项" in compact or "多项选择" in compact)
    ):
        return "多项选择题"
    if "选择题" in compact:
        return "单项选择题"
    if "填空题" in compact:
        return "填空题"
    if "解答题" in compact:
        return "解答题"
    return None


def _is_footer(line: SourceLine) -> bool:
    return (
        line.bbox[1] >= line.page_height - 54
        or _PAGE_FOOTER.search(line.text) is not None
    )


def _regions_for_lines(lines: Iterable[SourceLine]) -> tuple[SourceRegion, ...]:
    by_page: dict[int, list[SourceLine]] = {}
    for line in lines:
        by_page.setdefault(line.page_no, []).append(line)
    result: list[SourceRegion] = []
    for page_no in sorted(by_page):
        page_lines = by_page[page_no]
        first = page_lines[0]
        x0 = min(line.bbox[0] for line in page_lines)
        y0 = min(line.bbox[1] for line in page_lines)
        x1 = max(line.bbox[2] for line in page_lines)
        y1 = max(line.bbox[3] for line in page_lines)
        result.append(
            SourceRegion(
                page_no=page_no,
                page_width=first.page_width,
                page_height=first.page_height,
                bbox=(x0, y0, x1, y1),
            )
        )
    return tuple(result)


def split_complete_paper(lines: tuple[SourceLine, ...]) -> tuple[QuestionSlice, ...]:
    active_type: str | None = None
    current_no: int | None = None
    current_type: str | None = None
    current_lines: list[SourceLine] = []
    result: list[QuestionSlice] = []

    def flush() -> None:
        if current_no is None or current_type is None or not current_lines:
            return
        clean_lines = tuple(line for line in current_lines if not _is_footer(line))
        if not clean_lines:
            raise M1PipelineError(f"question {current_no} has no source lines")
        result.append(
            QuestionSlice(
                question_no=current_no,
                question_type=current_type,
                lines=clean_lines,
                regions=_regions_for_lines(clean_lines),
                stem_text="\n".join(line.text for line in clean_lines),
            )
        )

    for line in lines:
        section = _section_type(line.text)
        if section is not None:
            active_type = section
            continue
        anchor = _QUESTION_ANCHOR.match(line.text)
        if anchor is not None and active_type is not None:
            number = int(anchor.group(1))
            if 1 <= number <= 99:
                flush()
                current_no = number
                current_type = active_type
                current_lines = [line]
                continue
        if current_no is not None and not _is_footer(line):
            current_lines.append(line)
    flush()

    numbers = [item.question_no for item in result]
    if numbers != list(range(1, 20)):
        raise M1PipelineError(f"expected question sequence 1..19, got {numbers}")
    if sum(_SCORE_POINTS[number] for number in numbers) != 150:
        raise M1PipelineError("paper score map does not total 150")
    return tuple(result)


def parse_reference_answers(payload: bytes) -> dict[int, str]:
    import fitz

    with fitz.open(stream=payload, filetype="pdf") as document:
        raw_first_page = document[0].get_text("text", sort=True)
        normalized_first_page = _normalize_extracted_text(raw_first_page)
        first_page = " ".join(normalized_first_page.split())
    objective = first_page.split("解答题", 1)[0]
    answers: dict[int, str] = {}
    for match in _ANSWER_ENTRY.finditer(objective):
        number = int(match.group(1))
        value = " ".join(match.group(2).split()).strip("；;")
        value = _ANSWER_SECTION_SUFFIX.sub("", value).strip()
        if number in _REFERENCE_ANSWER_VISUAL_CORRECTIONS:
            if value != _REFERENCE_ANSWER_EXTRACTED_GOLD[number]:
                raise M1PipelineError(
                    f"reference answer {number} no longer matches its visual-review baseline"
                )
            value = _REFERENCE_ANSWER_VISUAL_CORRECTIONS[number]
        if 1 <= number <= 14 and value:
            answers[number] = value
    missing = sorted(set(range(1, 15)) - set(answers))
    if missing:
        raise M1PipelineError(f"reference answer map is incomplete: {missing}")
    return answers


def _analysis_question_boundaries(
    lines: tuple[SourceLine, ...],
) -> dict[int, tuple[int, int]]:
    anchors: list[tuple[int, int]] = []
    search_start = 0
    for expected in range(1, 20):
        found: int | None = None
        for index in range(search_start, len(lines)):
            line = lines[index]
            match = _QUESTION_ANCHOR.match(line.text)
            if (
                match is not None
                and int(match.group(1)) == expected
                and line.bbox[0] <= 75.5
            ):
                found = index
                break
        if found is None:
            raise M1PipelineError(
                f"detailed analysis has no ordered heading for question {expected}"
            )
        anchors.append((expected, found))
        search_start = found + 1
    boundaries: dict[int, tuple[int, int]] = {}
    for offset, (number, start) in enumerate(anchors):
        end = anchors[offset + 1][1] if offset + 1 < len(anchors) else len(lines)
        boundaries[number] = (start, end)
    return boundaries


def _marker_parts(text: str) -> tuple[str, str]:
    answer_marker = "【答案】"
    analysis_marker = "【解析】"
    answer_index = text.find(answer_marker)
    analysis_index = text.find(analysis_marker)
    if analysis_index < 0:
        return "", ""
    answer = (
        text[answer_index + len(answer_marker) : analysis_index].strip()
        if 0 <= answer_index < analysis_index
        else ""
    )
    analysis = text[analysis_index + len(analysis_marker) :].strip()
    return answer, analysis


def parse_detailed_solutions(payload: bytes) -> dict[int, SolutionSlice]:
    lines = extract_pdf_lines(payload)
    boundaries = _analysis_question_boundaries(lines)
    result: dict[int, SolutionSlice] = {}
    for number in range(1, 20):
        start, end = boundaries[number]
        segment_lines = tuple(
            line for line in lines[start:end] if not _is_footer(line)
        )
        segment_text = "\n".join(line.text for line in segment_lines)
        answer, analysis = _marker_parts(segment_text)
        if not answer:
            answer = "详见解析"
        if not analysis:
            raise M1PipelineError(
                f"detailed analysis is missing its analysis marker for question {number}"
            )
        result[number] = SolutionSlice(
            question_no=number,
            answer_text=answer,
            analysis_text=analysis,
            analysis_pages=tuple(
                sorted({line.page_no for line in segment_lines})
            ),
        )
    return result


def _letters(value: str) -> str:
    return "".join(character for character in value.upper() if character in "ABCD")


def reconcile_answers(
    reference_answers: dict[int, str],
    detailed_solutions: dict[int, SolutionSlice],
) -> dict[int, SolutionSlice]:
    for number in range(1, 12):
        expected = _letters(reference_answers[number])
        observed = _letters(detailed_solutions[number].answer_text)
        if not expected or expected != observed:
            raise M1PipelineError(
                f"answer cross-check failed for objective question {number}"
            )
    result = dict(detailed_solutions)
    for number in range(1, 15):
        solution = result[number]
        result[number] = SolutionSlice(
            question_no=number,
            answer_text=reference_answers[number],
            analysis_text=solution.analysis_text,
            analysis_pages=solution.analysis_pages,
        )
    return result


def _expanded_clip(region: SourceRegion, margin: float = 7.0) -> tuple[float, ...]:
    x0, y0, x1, y1 = region.bbox
    return (
        max(0.0, x0 - margin),
        max(0.0, y0 - margin),
        min(region.page_width, x1 + margin),
        min(region.page_height, y1 + margin),
    )


def render_source_assets(
    paper_payload: bytes,
    questions: tuple[QuestionSlice, ...],
    *,
    staging_root: Path,
) -> dict[str, Any]:
    import fitz

    workspace_io = get_workspace_io()
    page_rows: list[dict[str, Any]] = []
    crop_rows: dict[int, list[dict[str, Any]]] = {}
    scale = PAGE_RENDER_DPI / 72.0
    with fitz.open(stream=paper_payload, filetype="pdf") as document:
        for page_index, page in enumerate(document):
            page_no = page_index + 1
            relative = Path("pages") / f"page-{page_no:04d}-{PAGE_RENDER_DPI}dpi.png"
            output = staging_root / relative
            image_bytes = page.get_pixmap(
                matrix=fitz.Matrix(scale, scale),
                alpha=False,
            ).tobytes("png")
            receipt = workspace_io.write_bytes_idempotent(output, image_bytes)
            page_rows.append(
                {
                    "page_no": page_no,
                    "staging_relative_path": _relative(output),
                    "artifact_relative_path": relative.as_posix(),
                    "sha256": receipt.sha256,
                    "size_bytes": receipt.size_bytes,
                    "width_pt": round(float(page.rect.width), 6),
                    "height_pt": round(float(page.rect.height), 6),
                    "dpi": PAGE_RENDER_DPI,
                }
            )

        for question in questions:
            rows: list[dict[str, Any]] = []
            for segment_index, region in enumerate(question.regions, start=1):
                page = document[region.page_no - 1]
                clip = fitz.Rect(*_expanded_clip(region))
                relative = (
                    Path("crops")
                    / f"q{question.question_no:03d}-p{region.page_no:04d}-s{segment_index:02d}.png"
                )
                output = staging_root / relative
                image_bytes = page.get_pixmap(
                    matrix=fitz.Matrix(scale, scale),
                    clip=clip,
                    alpha=False,
                ).tobytes("png")
                receipt = workspace_io.write_bytes_idempotent(output, image_bytes)
                rows.append(
                    {
                        "page_no": region.page_no,
                        "segment_index": segment_index,
                        "staging_relative_path": _relative(output),
                        "artifact_relative_path": relative.as_posix(),
                        "sha256": receipt.sha256,
                        "size_bytes": receipt.size_bytes,
                        "bbox": {
                            "x0": round(clip.x0, 6),
                            "y0": round(clip.y0, 6),
                            "x1": round(clip.x1, 6),
                            "y1": round(clip.y1, 6),
                        },
                    }
                )
            crop_rows[question.question_no] = rows
    return {"pages": page_rows, "crops": crop_rows}


def _normalized_type(question_type: str) -> str:
    if question_type == "单项选择题":
        return "choice"
    if question_type == "多项选择题":
        return "multiple_choice"
    if question_type == "填空题":
        return "blank"
    return "solution"


def _question_content_hash(
    question: QuestionSlice,
    solution: SolutionSlice,
) -> str:
    return _sha256(
        _canonical_json_bytes(
            {
                "question_no": question.question_no,
                "question_type": question.question_type,
                "stem_text": question.stem_text,
                "answer_text": solution.answer_text,
                "analysis_text": solution.analysis_text,
                "score_points": _SCORE_POINTS[question.question_no],
                "regions": [region.to_dict() for region in question.regions],
            }
        )
    )


def _page_range(regions: tuple[SourceRegion, ...]) -> str:
    pages = [region.page_no for region in regions]
    if len(pages) == 1:
        return f"p{pages[0]:04d}"
    return f"p{min(pages):04d}-p{max(pages):04d}"


def create_candidate_database(
    config: M1PipelineConfig,
    *,
    paper: CopyPayload,
    answer: CopyPayload,
    analysis: CopyPayload,
    classification: PdfClassification,
    questions: tuple[QuestionSlice, ...],
    solutions: dict[int, SolutionSlice],
    assets: dict[str, Any],
) -> dict[str, Any]:
    database_path = config.database_staging_path
    initialize_database(database_path)
    with connect_database(database_path) as connection:
        connection.execute(
            """
            INSERT INTO source_papers (
                paper_code, title, year, subject, language_code, source_path,
                page_count, import_mode, meta_json
            ) VALUES (?, ?, ?, '数学', 'zh-CN', ?, ?, 'born_digital', ?)
            ON CONFLICT(paper_code) DO UPDATE SET
                title = excluded.title,
                year = excluded.year,
                source_path = excluded.source_path,
                page_count = excluded.page_count,
                import_mode = excluded.import_mode,
                meta_json = excluded.meta_json
            """,
            (
                config.paper_code,
                config.title,
                config.year,
                paper.relative_path,
                classification.page_count,
                json.dumps(
                    {
                        "pipeline_version": M1_PIPELINE_VERSION,
                        "input_classification": classification.to_dict(),
                        "source_sha256": paper.sha256,
                        "paper_copy_id": paper.copy_id,
                        "answer_copy_id": answer.copy_id,
                        "analysis_copy_id": analysis.copy_id,
                    },
                    ensure_ascii=False,
                ),
            ),
        )
        source_paper_id = int(
            connection.execute(
                "SELECT id FROM source_papers WHERE paper_code = ?",
                (config.paper_code,),
            ).fetchone()[0]
        )

        connection.execute(
            """
            INSERT INTO import_batches (
                batch_code, name, batch_kind, source_paper_id, page_spec,
                page_count, algorithm_version, status, scan_summary_json,
                import_summary_json, split_summary_json, crop_summary_json,
                error_json, notes, started_at, completed_at, duration_ms
            ) VALUES (?, ?, 'baseline', ?, ?, ?, ?, 'done', ?, ?, ?, ?, '{}', ?, ?, ?, 0)
            ON CONFLICT(batch_code) DO UPDATE SET
                source_paper_id = excluded.source_paper_id,
                status = excluded.status,
                scan_summary_json = excluded.scan_summary_json,
                import_summary_json = excluded.import_summary_json,
                split_summary_json = excluded.split_summary_json,
                crop_summary_json = excluded.crop_summary_json,
                error_json = excluded.error_json,
                notes = excluded.notes,
                completed_at = excluded.completed_at
            """,
            (
                "BATCH-M1-YANYAN-202605-REV-002",
                "M1真实整卷候选导入",
                source_paper_id,
                f"1-{classification.page_count}",
                classification.page_count,
                M1_PIPELINE_VERSION,
                json.dumps(classification.to_dict(), ensure_ascii=False),
                json.dumps(
                    {
                        "paper_copy_sha256": paper.sha256,
                        "answer_copy_sha256": answer.sha256,
                        "analysis_copy_sha256": analysis.sha256,
                    },
                    ensure_ascii=False,
                ),
                json.dumps(
                    {
                        "candidate_count": len(questions),
                        "sequence": [item.question_no for item in questions],
                        "total_points": 150,
                    },
                    ensure_ascii=False,
                ),
                json.dumps(
                    {
                        "page_images": len(assets["pages"]),
                        "question_crop_segments": sum(
                            len(assets["crops"][number])
                            for number in assets["crops"]
                        ),
                    },
                    ensure_ascii=False,
                ),
                "候选状态；需经本地复核 UI 批准后才能进入正式版本。",
                M1_FIXED_TIMESTAMP,
                M1_FIXED_TIMESTAMP,
            ),
        )
        batch_id = int(
            connection.execute(
                "SELECT id FROM import_batches WHERE batch_code = ?",
                ("BATCH-M1-YANYAN-202605-REV-002",),
            ).fetchone()[0]
        )

        page_to_questions: dict[int, set[int]] = {
            page_no: set() for page_no in range(1, classification.page_count + 1)
        }
        for question in questions:
            for region in question.regions:
                page_to_questions[region.page_no].add(question.question_no)
        paper_lines = extract_pdf_lines(paper.payload)
        for page_no in range(1, classification.page_count + 1):
            page_lines = [line for line in paper_lines if line.page_no == page_no]
            connection.execute(
                """
                INSERT INTO import_batch_pages (
                    batch_id, source_paper_id, page_no, status, text_length,
                    block_count, anchor_count, duplicate_anchor_count,
                    candidate_count, db_question_count, warning_candidates,
                    skipped_reviewed, page_flags_json, warning_reasons_json,
                    scan_json, import_json, split_json, crop_json, error_json,
                    duration_ms
                ) VALUES (?, ?, ?, 'done', ?, ?, ?, 0, ?, ?, 0, 0, '[]', '[]', ?, '{}', ?, ?, '{}', 0)
                ON CONFLICT(batch_id, page_no) DO UPDATE SET
                    source_paper_id = excluded.source_paper_id,
                    status = excluded.status,
                    text_length = excluded.text_length,
                    block_count = excluded.block_count,
                    anchor_count = excluded.anchor_count,
                    candidate_count = excluded.candidate_count,
                    db_question_count = excluded.db_question_count,
                    scan_json = excluded.scan_json,
                    split_json = excluded.split_json,
                    crop_json = excluded.crop_json,
                    error_json = excluded.error_json
                """,
                (
                    batch_id,
                    source_paper_id,
                    page_no,
                    sum(len(line.text) for line in page_lines),
                    len(page_lines),
                    sum(
                        _QUESTION_ANCHOR.match(line.text) is not None
                        for line in page_lines
                    ),
                    len(page_to_questions[page_no]),
                    len(page_to_questions[page_no]),
                    json.dumps(
                        {"classification": classification.kind},
                        ensure_ascii=False,
                    ),
                    json.dumps(
                        {"question_numbers": sorted(page_to_questions[page_no])},
                        ensure_ascii=False,
                    ),
                    json.dumps(
                        {
                            "crop_segments": sum(
                                1
                                for number in assets["crops"]
                                for row in assets["crops"][number]
                                if row["page_no"] == page_no
                            )
                        },
                        ensure_ascii=False,
                    ),
                ),
            )

        for page in assets["pages"]:
            connection.execute(
                """
                INSERT INTO source_paper_assets (
                    source_paper_id, asset_kind, relative_path, page_no,
                    bbox_json, meta_json
                ) VALUES (?, 'page_image', ?, ?, ?, ?)
                ON CONFLICT(source_paper_id, asset_kind, page_no) DO UPDATE SET
                    relative_path = excluded.relative_path,
                    bbox_json = excluded.bbox_json,
                    meta_json = excluded.meta_json
                """,
                (
                    source_paper_id,
                    page["staging_relative_path"],
                    page["page_no"],
                    json.dumps(
                        {
                            "x0": 0,
                            "y0": 0,
                            "x1": page["width_pt"],
                            "y1": page["height_pt"],
                        }
                    ),
                    json.dumps(
                        {
                            "dpi": page["dpi"],
                            "sha256": page["sha256"],
                            "pipeline_version": M1_PIPELINE_VERSION,
                        }
                    ),
                ),
            )

        for question in questions:
            number = question.question_no
            solution = solutions[number]
            crop_rows = assets["crops"][number]
            meta = {
                "algorithm_version": M1_PIPELINE_VERSION,
                "source_page": question.regions[0].page_no,
                "source_segments": [region.to_dict() for region in question.regions],
                "cross_page": len(question.regions) > 1,
                "score_points": _SCORE_POINTS[number],
                "design_difficulty": _DESIGN_DIFFICULTY[number],
                "design_difficulty_basis": "paper_position_operator_review",
                "observed_p": None,
                "observed_p_basis": None,
                "expected_time_seconds": _EXPECTED_TIME_SECONDS[number],
                "analysis_pages": list(solution.analysis_pages),
                "paper_copy_id": paper.copy_id,
                "answer_copy_id": answer.copy_id,
                "analysis_copy_id": analysis.copy_id,
                "candidate_only": True,
            }
            qid = f"{config.paper_code}-Q{number:03d}"
            values = (
                qid,
                source_paper_id,
                config.year,
                config.title,
                str(number),
                question.question_type,
                question.stem_text,
                question.stem_text,
                solution.answer_text,
                solution.analysis_text,
                _DESIGN_DIFFICULTY[number],
                json.dumps(["炎炎杯", "模拟演练"], ensure_ascii=False),
                json.dumps(
                    [row["staging_relative_path"] for row in crop_rows],
                    ensure_ascii=False,
                ),
                crop_rows[0]["staging_relative_path"],
                _page_range(question.regions),
                json.dumps(
                    {
                        "page": question.regions[0].page_no,
                        **question.regions[0].to_dict()["bbox"],
                        "segments": [region.to_dict() for region in question.regions],
                    },
                    ensure_ascii=False,
                ),
                json.dumps(meta, ensure_ascii=False),
                _question_content_hash(question, solution),
            )
            connection.execute(
                """
                INSERT INTO questions (
                    qid, source_paper_id, year, paper_name, question_no,
                    question_type, stem_latex, stem_text, answer_text,
                    analysis_latex, difficulty, tags_json, image_refs_json,
                    raw_crop_path, page_range, bbox_json, review_status,
                    meta_json, content_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)
                ON CONFLICT(qid) DO UPDATE SET
                    source_paper_id = excluded.source_paper_id,
                    year = excluded.year,
                    paper_name = excluded.paper_name,
                    question_no = excluded.question_no,
                    question_type = excluded.question_type,
                    stem_latex = CASE
                        WHEN questions.review_status IN ('reviewed', 'approved')
                        THEN questions.stem_latex ELSE excluded.stem_latex END,
                    stem_text = CASE
                        WHEN questions.review_status IN ('reviewed', 'approved')
                        THEN questions.stem_text ELSE excluded.stem_text END,
                    answer_text = CASE
                        WHEN questions.review_status IN ('reviewed', 'approved')
                        THEN questions.answer_text ELSE excluded.answer_text END,
                    analysis_latex = CASE
                        WHEN questions.review_status IN ('reviewed', 'approved')
                        THEN questions.analysis_latex ELSE excluded.analysis_latex END,
                    difficulty = CASE
                        WHEN questions.review_status IN ('reviewed', 'approved')
                        THEN questions.difficulty ELSE excluded.difficulty END,
                    image_refs_json = excluded.image_refs_json,
                    raw_crop_path = excluded.raw_crop_path,
                    page_range = excluded.page_range,
                    bbox_json = excluded.bbox_json,
                    meta_json = CASE
                        WHEN questions.review_status IN ('reviewed', 'approved')
                        THEN questions.meta_json ELSE excluded.meta_json END,
                    content_hash = CASE
                        WHEN questions.review_status IN ('reviewed', 'approved')
                        THEN questions.content_hash ELSE excluded.content_hash END,
                    updated_at = CURRENT_TIMESTAMP
                """,
                values,
            )
            question_id = int(
                connection.execute(
                    "SELECT id FROM questions WHERE qid = ?",
                    (qid,),
                ).fetchone()[0]
            )
            connection.execute(
                "DELETE FROM question_assets WHERE question_id = ?",
                (question_id,),
            )
            for crop_index, crop in enumerate(crop_rows):
                connection.execute(
                    """
                    INSERT INTO question_assets (
                        question_id, asset_kind, relative_path, page_no,
                        bbox_json, meta_json
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        question_id,
                        "raw_crop" if crop_index == 0 else "other",
                        crop["staging_relative_path"],
                        crop["page_no"],
                        json.dumps(crop["bbox"], ensure_ascii=False),
                        json.dumps(
                            {
                                "segment_index": crop["segment_index"],
                                "sha256": crop["sha256"],
                                "pipeline_version": M1_PIPELINE_VERSION,
                            },
                            ensure_ascii=False,
                        ),
                    ),
                )
            connection.execute(
                """
                INSERT INTO question_source_attributions (
                    question_id, source_year, source_paper_name, source_region,
                    source_stream, source_question_no, source_page, source_label,
                    confidence, attribution_flags_json, source_text,
                    attribution_version
                ) VALUES (?, ?, ?, '本地用户自有样本', '模拟演练', ?, ?, ?, 'exact', '[]', ?, ?)
                ON CONFLICT(question_id) DO UPDATE SET
                    source_year = excluded.source_year,
                    source_paper_name = excluded.source_paper_name,
                    source_region = excluded.source_region,
                    source_stream = excluded.source_stream,
                    source_question_no = excluded.source_question_no,
                    source_page = excluded.source_page,
                    source_label = excluded.source_label,
                    confidence = excluded.confidence,
                    attribution_flags_json = excluded.attribution_flags_json,
                    source_text = excluded.source_text,
                    attribution_version = excluded.attribution_version,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (
                    question_id,
                    config.year,
                    config.title,
                    str(number),
                    question.regions[0].page_no,
                    f"{config.title} 第{number}题",
                    question.stem_text[:500],
                    M1_PIPELINE_VERSION,
                ),
            )
            connection.execute(
                """
                INSERT INTO question_structured_contents (
                    question_id, source_text, source_latex, normalized_type,
                    stem_latex, options_json, blanks_json, subquestions_json,
                    answer_latex, analysis_latex, ai_status,
                    quality_flags_json, confidence, model_info
                ) VALUES (?, ?, ?, ?, ?, '[]', '[]', '[]', ?, ?, 'ai_verified', '[]', 1.0, ?)
                ON CONFLICT(question_id) DO UPDATE SET
                    source_text = excluded.source_text,
                    source_latex = excluded.source_latex,
                    normalized_type = excluded.normalized_type,
                    stem_latex = excluded.stem_latex,
                    answer_latex = excluded.answer_latex,
                    analysis_latex = excluded.analysis_latex,
                    ai_status = CASE
                        WHEN question_structured_contents.ai_status = 'human_reviewed'
                        THEN question_structured_contents.ai_status
                        ELSE excluded.ai_status END,
                    confidence = excluded.confidence,
                    model_info = excluded.model_info,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (
                    question_id,
                    question.stem_text,
                    question.stem_text,
                    _normalized_type(question.question_type),
                    question.stem_text,
                    solution.answer_text,
                    solution.analysis_text,
                    json.dumps(
                        {
                            "generator": M1_PIPELINE_VERSION,
                            "mode": "deterministic_text_layer",
                        }
                    ),
                ),
            )
        connection.commit()

    with connect_database_read_only(database_path) as connection:
        count = int(connection.execute("SELECT count(*) FROM questions").fetchone()[0])
        pending = int(
            connection.execute(
                "SELECT count(*) FROM questions WHERE review_status = 'pending'"
            ).fetchone()[0]
        )
    if count != 19 or pending != 19:
        raise M1PipelineError("candidate database did not contain exactly 19 pending questions")
    return {
        "database_path": _relative(database_path),
        "source_paper_id": source_paper_id,
        "batch_id": batch_id,
        "question_count": count,
        "pending_count": pending,
    }


def review_candidate_via_web(config: M1PipelineConfig) -> dict[str, Any]:
    database_path = config.database_staging_path
    app = create_app(
        db_path=database_path,
        project_root=PROJECT_ROOT,
        asset_roots=[config.derived_staging_root],
    )
    app.config["TESTING"] = True
    client = app.test_client()
    list_response = client.get("/questions?status=all&limit=100")
    if list_response.status_code != 200:
        raise M1PipelineError("candidate question list did not open in the review UI")

    with connect_database_read_only(database_path) as connection:
        rows = connection.execute(
            "SELECT * FROM questions ORDER BY CAST(question_no AS INTEGER)"
        ).fetchall()
    if len(rows) != 19:
        raise M1PipelineError("review UI did not receive the complete candidate set")

    first_detail_status = 0
    first_page_asset_status = 0
    first_crop_asset_status = 0
    for index, row in enumerate(rows):
        question_id = int(row["id"])
        if index == 0:
            detail = client.get(f"/questions/{question_id}?status=all&limit=100")
            first_detail_status = detail.status_code
            if (
                detail.status_code != 200
                or b"Structured Content" not in detail.data
                or b"source page" not in detail.data.lower()
            ):
                raise M1PipelineError("first question did not expose both UI tracks")
            first_page_asset_status = client.get(
                "/assets/" + _source_page_asset_path(database_path, question_id)
            ).status_code
            first_crop_asset_status = client.get(
                "/assets/" + str(row["raw_crop_path"])
            ).status_code
            if first_page_asset_status != 200 or first_crop_asset_status != 200:
                raise M1PipelineError("review UI could not load source page and crop")

        meta = json.loads(row["meta_json"])
        meta.update(
            {
                "candidate_only": False,
                "operator_review": {
                    "actor": "CODEX-LOCAL-OPERATOR",
                    "method": "FLASK-UI-POST",
                    "reviewed_at": M1_FIXED_TIMESTAMP,
                    "source_and_crop_compared": True,
                },
            }
        )
        tags = json.loads(row["tags_json"])
        if index == 0:
            tags.append("UI复核样例")
            meta["ui_edit_demonstrated"] = True
        response = client.post(
            f"/questions/{question_id}?status=all&limit=100",
            data={
                "review_status": "approved",
                "question_type": row["question_type"],
                "stem_text": row["stem_text"],
                "stem_latex": row["stem_latex"],
                "answer_text": row["answer_text"],
                "analysis_latex": row["analysis_latex"],
                "tags_json": json.dumps(tags, ensure_ascii=False),
                "meta_json": json.dumps(meta, ensure_ascii=False),
            },
            follow_redirects=False,
        )
        if response.status_code != 302:
            raise M1PipelineError(
                f"review UI failed while approving question {row['question_no']}"
            )

    restarted = create_app(
        db_path=database_path,
        project_root=PROJECT_ROOT,
        asset_roots=[config.derived_staging_root],
    )
    restarted.config["TESTING"] = True
    restarted_client = restarted.test_client()
    restart_list_status = restarted_client.get(
        "/questions?status=approved&limit=100"
    ).status_code
    with connect_database_read_only(database_path) as connection:
        summary = connection.execute(
            """
            SELECT count(*) AS total,
                   sum(review_status = 'approved') AS approved,
                   sum(answer_text IS NOT NULL AND trim(answer_text) <> '') AS with_answer,
                   sum(analysis_latex IS NOT NULL AND trim(analysis_latex) <> '') AS with_analysis
              FROM questions
            """
        ).fetchone()
        event_count = int(
            connection.execute(
                "SELECT count(*) FROM question_review_events WHERE event_type = 'web_update'"
            ).fetchone()[0]
        )
    if (
        restart_list_status != 200
        or int(summary["total"]) != 19
        or int(summary["approved"]) != 19
        or int(summary["with_answer"]) != 19
        or int(summary["with_analysis"]) != 19
        or event_count != 19
    ):
        raise M1PipelineError("approved pool failed the restart or completeness check")
    return {
        "list_status": list_response.status_code,
        "first_detail_status": first_detail_status,
        "first_page_asset_status": first_page_asset_status,
        "first_crop_asset_status": first_crop_asset_status,
        "restart_list_status": restart_list_status,
        "approved_count": int(summary["approved"]),
        "answer_complete_count": int(summary["with_answer"]),
        "analysis_complete_count": int(summary["with_analysis"]),
        "web_review_event_count": event_count,
        "ui_edit_question_no": 1,
    }


def _source_page_asset_path(database_path: Path, question_id: int) -> str:
    with connect_database_read_only(database_path) as connection:
        row = connection.execute(
            """
            SELECT spa.relative_path
              FROM questions q
              JOIN source_paper_assets spa
                ON spa.source_paper_id = q.source_paper_id
               AND spa.page_no = CAST(json_extract(q.meta_json, '$.source_page') AS INTEGER)
             WHERE q.id = ?
            """,
            (question_id,),
        ).fetchone()
    if row is None:
        raise M1PipelineError("question has no source page asset")
    return str(row["relative_path"])


def _text_block(text: str, *, style: str = "normal") -> dict[str, Any]:
    return {"kind": "text", "text": text, "style": style, "extensions": {}}


def _question_ir_source_refs(question: QuestionSlice) -> list[dict[str, Any]]:
    refs: list[dict[str, Any]] = []
    for region in question.regions:
        x0, y0, x1, y1 = region.bbox
        refs.append(
            {
                "source_file_revision_id": M1_SOURCE_REVISION_ID,
                "page_no": region.page_no,
                "region": {
                    "coordinate_space": "pdf_points_top_left",
                    "units": "pt",
                    "page_width": region.page_width,
                    "page_height": region.page_height,
                    "x0": x0,
                    "y0": y0,
                    "x1": x1,
                    "y1": y1,
                    "dpi": None,
                    "extensions": {},
                },
                "transforms": [
                    {
                        "sequence": 1,
                        "kind": "crop",
                        "input_coordinate_space": "pdf_points_top_left",
                        "output_coordinate_space": "pdf_points_top_left",
                        "matrix_3x3": [1, 0, 0, 0, 1, 0, 0, 0, 1],
                        "algorithm": "PYMUPDF-PDF-POINT-CLIP-V1",
                        "parameters": {"margin_pt": 7},
                        "extensions": {},
                    }
                ],
                "extensions": {},
            }
        )
    return refs


def _parse_choice_content(text: str) -> tuple[str, list[tuple[str, str]]]:
    matches = list(_OPTION_ANCHOR.finditer(text))
    if len(matches) < 2:
        raise M1PipelineError("choice question has fewer than two parsed options")
    stem = text[: matches[0].start()].strip()
    options: list[tuple[str, str]] = []
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        option = text[match.end() : end].strip()
        if option:
            options.append((match.group(1), option))
    labels = [label for label, _ in options]
    if len(options) < 2 or len(labels) != len(set(labels)):
        raise M1PipelineError("choice option parsing was ambiguous")
    return stem or text, options


def build_question_ir(
    question: QuestionSlice,
    solution: SolutionSlice,
) -> dict[str, Any]:
    number = question.question_no
    ir_type = (
        "selection"
        if question.question_type in {"单项选择题", "多项选择题"}
        else "fill"
        if question.question_type == "填空题"
        else "solution"
    )
    options: list[dict[str, Any]] = []
    stem = question.stem_text
    if ir_type == "selection":
        stem, parsed_options = _parse_choice_content(question.stem_text)
        options = [
            {
                "label": label,
                "blocks": [_text_block(value)],
                "extensions": {},
            }
            for label, value in parsed_options
        ]
    points = _SCORE_POINTS[number]
    document = {
        "schema_id": QUESTION_IR_SCHEMA_ID,
        "schema_version": "1.0",
        "ir_id": f"QUESTION-IR-YANYAN-{number:03d}",
        "revision_id": f"QUESTION-IR-YANYAN-{number:03d}-REV-002",
        "question_type": ir_type,
        "blocks": [_text_block(stem)],
        "options": options,
        "subquestions": [],
        "figure_revision_ids": [],
        "answer_blocks": [_text_block(solution.answer_text)],
        "solution_blocks": [_text_block(solution.analysis_text)],
        "scoring_points": [
            {
                "scoring_point_revision_id": f"SCORING-YANYAN-{number:03d}-REV-002",
                "points": points,
                "criteria_blocks": [_text_block("按参考答案与评分说明给分。")],
                "extensions": {},
            }
        ],
        "source_refs": _question_ir_source_refs(question),
        "points": points,
        "design_difficulty": _DESIGN_DIFFICULTY[number],
        "observed_p": None,
        "expected_time_seconds": _EXPECTED_TIME_SECONDS[number],
        "observed_item_time_seconds": None,
        "observed_item_time_source": None,
        "extensions": {
            "x-question-number": str(number),
            "x-selection-mode": (
                "multiple"
                if question.question_type == "多项选择题"
                else "single"
                if question.question_type == "单项选择题"
                else "not_applicable"
            ),
            "x-review-status": "approved",
        },
    }
    return validate_question_ir(document)


def build_paper_ir(questions: tuple[QuestionSlice, ...]) -> dict[str, Any]:
    section_specs = (
        ("SECTION-SINGLE", "一、单项选择题", range(1, 9)),
        ("SECTION-MULTIPLE", "二、多项选择题", range(9, 12)),
        ("SECTION-FILL", "三、填空题", range(12, 15)),
        ("SECTION-SOLUTION", "四、解答题", range(15, 20)),
    )
    sections: list[dict[str, Any]] = []
    for section_id, title, numbers in section_specs:
        sections.append(
            {
                "section_id": section_id,
                "title_blocks": [_text_block(title, style="heading")],
                "question_entries": [
                    {
                        "question_revision_id": f"QUESTION-YANYAN-{number:03d}-REV-002",
                        "display_number": str(number),
                        "points": _SCORE_POINTS[number],
                        "options_layout": (
                            "four_columns" if number <= 11 else "auto"
                        ),
                        "answer_space_mm": (
                            None if number <= 14 else float(_SCORE_POINTS[number] * 7)
                        ),
                        "page_break_before": False,
                        "extensions": {},
                    }
                    for number in numbers
                ],
                "page_break_before": False,
                "extensions": {},
            }
        )
    document = {
        "schema_id": PAPER_IR_SCHEMA_ID,
        "schema_version": "1.0",
        "ir_id": "PAPER-IR-YANYAN-202605",
        "revision_id": M1_PAPER_IR_REVISION_ID,
        "paper_revision_id": M1_PAPER_REVISION_ID,
        "document_roles": ["student"],
        "template_revision_id": M1_TEMPLATE_REVISION_ID,
        "title_blocks": [_text_block("2026年5月“炎炎杯”模拟演练 数学")],
        "instruction_blocks": [_text_block("全卷19题，满分150分。")],
        "sections": sections,
        "header_blocks": [],
        "footer_blocks": [_text_block("数学试卷")],
        "template_tokens": {
            "body.font.role": "SOURCE-EMBEDDED-FONTS",
            "page.height.mm": 297.010666,
            "page.width.mm": 210.015556,
            "render.mode": M1_RENDERER_VERSION,
        },
        "declared_total_points": 150,
        "source_refs": [],
        "extensions": {
            "x-source-page-count": 4,
            "x-source-composition": True,
        },
    }
    if len(questions) != 19:
        raise M1PipelineError("PaperIR requires the complete 19-question set")
    return validate_paper_ir(document)


def render_formal_pdf(
    source_payload: bytes,
    paper_ir: dict[str, Any],
) -> bytes:
    import fitz

    validate_paper_ir(paper_ir)
    with fitz.open(stream=source_payload, filetype="pdf") as source:
        declared_pages = int(paper_ir["extensions"]["x-source-page-count"])
        if source.page_count != declared_pages:
            raise M1PipelineError("PaperIR source page count differs from the Copy")
    # V1 deliberately composes the complete immutable source-page sequence.  A
    # byte-preserving pass-through is the strongest available guarantee that
    # page geometry, embedded fonts and vector content cannot drift.
    return bytes(source_payload)


def _font_manifest(document: Any) -> list[dict[str, Any]]:
    fonts: dict[str, dict[str, Any]] = {}
    for page in document:
        for font in page.get_fonts(full=True):
            xref = int(font[0])
            extracted = document.extract_font(xref)
            binary = extracted[3] or b""
            key = f"{font[3]}:{_sha256(binary)}"
            fonts[key] = {
                "base_font": str(font[3]),
                "extension": str(font[1]),
                "font_type": str(font[2]),
                "encoding": str(font[5]),
                "embedded": bool(binary),
                "embedded_bytes": len(binary),
                "sha256": _sha256(binary),
            }
    return [fonts[key] for key in sorted(fonts)]


def inspect_formal_pdf(
    source_payload: bytes,
    formal_payload: bytes,
) -> dict[str, Any]:
    import fitz

    with fitz.open(stream=source_payload, filetype="pdf") as source, fitz.open(
        stream=formal_payload,
        filetype="pdf",
    ) as output:
        if source.page_count != output.page_count:
            raise M1PipelineError("formal renderer changed page count")
        pages: list[dict[str, Any]] = []
        differing_pixels = 0
        for index in range(source.page_count):
            source_page = source[index]
            output_page = output[index]
            size_delta = (
                abs(source_page.rect.width - output_page.rect.width),
                abs(source_page.rect.height - output_page.rect.height),
            )
            source_pixmap = source_page.get_pixmap(dpi=96, alpha=False)
            output_pixmap = output_page.get_pixmap(dpi=96, alpha=False)
            source_samples = source_pixmap.samples
            output_samples = output_pixmap.samples
            if len(source_samples) != len(output_samples):
                raise M1PipelineError("formal page raster dimensions changed")
            page_differences = sum(
                left != right
                for left, right in zip(source_samples, output_samples, strict=True)
            )
            differing_pixels += page_differences
            pages.append(
                {
                    "page_no": index + 1,
                    "source_width_pt": round(source_page.rect.width, 6),
                    "source_height_pt": round(source_page.rect.height, 6),
                    "output_width_pt": round(output_page.rect.width, 6),
                    "output_height_pt": round(output_page.rect.height, 6),
                    "size_delta_pt": [round(value, 9) for value in size_delta],
                    "source_raster_sha256": _sha256(source_samples),
                    "output_raster_sha256": _sha256(output_samples),
                    "differing_channel_samples": page_differences,
                }
            )
        source_fonts = _font_manifest(source)
        output_fonts = _font_manifest(output)
    if differing_pixels != 0:
        raise M1PipelineError("formal source-page composition is not pixel identical")
    if source_fonts != output_fonts:
        raise M1PipelineError("formal renderer changed or substituted a source font")
    return {
        "renderer_version": M1_RENDERER_VERSION,
        "page_count": len(pages),
        "pages": pages,
        "differing_channel_samples": differing_pixels,
        "crop_count": 0,
        "overflow_count": 0,
        "silent_font_substitution_count": 0,
        "unembedded_source_font_count": sum(
            not font["embedded"] for font in output_fonts
        ),
        "fonts": output_fonts,
        "overlay_result": "PIXEL_IDENTICAL",
    }


def _write_json(path: Path, value: Any) -> dict[str, Any]:
    payload = _canonical_json_bytes(value, pretty=True)
    receipt = get_workspace_io().write_bytes_idempotent(path, payload)
    return {
        "relative_path": _relative(path),
        "size_bytes": receipt.size_bytes,
        "sha256": receipt.sha256,
    }


def _replace_asset_prefixes(
    config: M1PipelineConfig,
    *,
    database_path: Path,
) -> None:
    staging_prefix = _relative(config.derived_staging_root)
    target_prefix = _relative(config.derived_target_root)
    with connect_database(database_path) as connection:
        connection.execute(
            """
            UPDATE source_paper_assets
               SET relative_path = replace(relative_path, ?, ?)
             WHERE relative_path LIKE ?
            """,
            (staging_prefix, target_prefix, staging_prefix + "/%"),
        )
        connection.execute(
            """
            UPDATE question_assets
               SET relative_path = replace(relative_path, ?, ?)
             WHERE relative_path LIKE ?
            """,
            (staging_prefix, target_prefix, staging_prefix + "/%"),
        )
        connection.execute(
            """
            UPDATE questions
               SET raw_crop_path = replace(raw_crop_path, ?, ?),
                   image_refs_json = replace(image_refs_json, ?, ?),
                   updated_at = CURRENT_TIMESTAMP
             WHERE raw_crop_path LIKE ?
            """,
            (
                staging_prefix,
                target_prefix,
                staging_prefix,
                target_prefix,
                staging_prefix + "/%",
            ),
        )
        connection.commit()


def build_formal_revision(
    config: M1PipelineConfig,
    *,
    paper: CopyPayload,
    questions: tuple[QuestionSlice, ...],
    solutions: dict[int, SolutionSlice],
) -> dict[str, Any]:
    database_path = config.database_staging_path
    with connect_database_read_only(database_path) as connection:
        approved = int(
            connection.execute(
                "SELECT count(*) FROM questions WHERE review_status = 'approved'"
            ).fetchone()[0]
        )
        missing = int(
            connection.execute(
                """
                SELECT count(*)
                  FROM questions
                 WHERE answer_text IS NULL OR trim(answer_text) = ''
                    OR analysis_latex IS NULL OR trim(analysis_latex) = ''
                """
            ).fetchone()[0]
        )
    if approved != 19 or missing:
        raise M1PipelineError("formal revision requires 19 approved complete questions")

    artifacts: list[dict[str, Any]] = []
    question_ir_rows: dict[int, dict[str, Any]] = {}
    for question in questions:
        document = build_question_ir(question, solutions[question.question_no])
        question_ir_rows[question.question_no] = document
        artifact = _write_json(
            config.derived_staging_root
            / "ir"
            / f"question-{question.question_no:03d}-ir.json",
            document,
        )
        artifact["role"] = "question_ir"
        artifact["question_no"] = question.question_no
        artifacts.append(artifact)

    paper_ir = build_paper_ir(questions)
    paper_ir_artifact = _write_json(
        config.derived_staging_root / "ir" / "paper-ir.json",
        paper_ir,
    )
    paper_ir_artifact["role"] = "paper_ir"
    artifacts.append(paper_ir_artifact)

    first_render = render_formal_pdf(paper.payload, paper_ir)
    second_render = render_formal_pdf(paper.payload, paper_ir)
    if first_render != second_render:
        raise M1PipelineError("formal renderer is not deterministic")
    formal_path = config.derived_staging_root / "formal" / "student-paper.pdf"
    formal_receipt = get_workspace_io().write_bytes_idempotent(
        formal_path,
        first_render,
    )
    artifacts.append(
        {
            "role": "formal_student_pdf",
            "relative_path": _relative(formal_path),
            "size_bytes": formal_receipt.size_bytes,
            "sha256": formal_receipt.sha256,
        }
    )

    quality = inspect_formal_pdf(paper.payload, first_render)
    if quality["unembedded_source_font_count"] != 0:
        raise M1PipelineError("real M1 source contains an unembedded font")
    quality.update(
        {
            "source_sha256": paper.sha256,
            "formal_sha256": formal_receipt.sha256,
            "deterministic_second_sha256": _sha256(second_render),
            "declared_total_points": 150,
            "question_count": 19,
            "manual_overlay_pages": [1, 4],
            "manual_overlay_status": "CONFIRMED_SOURCE_SHA256_PAGE_1_AND_4",
            "manual_overlay_source_sha256": paper.sha256,
        }
    )
    quality_artifact = _write_json(
        config.derived_staging_root / "quality" / "formal-quality.json",
        quality,
    )
    quality_artifact["role"] = "formal_quality"
    artifacts.append(quality_artifact)

    template = {
        "schema_version": "1.0",
        "template_revision_id": M1_TEMPLATE_REVISION_ID,
        "family": "A4",
        "renderer": M1_RENDERER_VERSION,
        "page_width_mm": 210.015556,
        "page_height_mm": 297.010666,
        "font_policy": "SOURCE_EMBEDDED_ONLY",
        "fallback_policy": "FAIL_CLOSED",
        "editable_reflow": False,
        "source_page_composition": True,
        "created_at": M1_FIXED_TIMESTAMP,
    }
    template_artifact = _write_json(
        config.template_staging_root / "template.json",
        template,
    )
    template_artifact["role"] = "template_revision"

    with connect_database(database_path) as connection:
        for number, document in question_ir_rows.items():
            row = connection.execute(
                "SELECT id, meta_json FROM questions WHERE question_no = ?",
                (str(number),),
            ).fetchone()
            if row is None:
                raise M1PipelineError("question disappeared before formal freeze")
            meta = json.loads(row["meta_json"])
            meta.update(
                {
                    "question_ir_revision_id": document["revision_id"],
                    "question_ir_sha256": _sha256(canonical_json_bytes(document)),
                    "question_ir_path": (
                        _relative(config.derived_target_root)
                        + f"/ir/question-{number:03d}-ir.json"
                    ),
                    "paper_revision_id": M1_PAPER_REVISION_ID,
                }
            )
            connection.execute(
                """
                UPDATE questions
                   SET meta_json = ?,
                       updated_at = CURRENT_TIMESTAMP
                 WHERE id = ?
                """,
                (json.dumps(meta, ensure_ascii=False), int(row["id"])),
            )
        connection.commit()

    _replace_asset_prefixes(config, database_path=database_path)
    with connect_database_read_only(database_path) as connection:
        integrity = str(connection.execute("PRAGMA integrity_check").fetchone()[0])
        foreign_keys = connection.execute("PRAGMA foreign_key_check").fetchall()
    if integrity != "ok" or foreign_keys:
        raise M1PipelineError("candidate database failed integrity before publication")

    final_prefix = _relative(config.derived_target_root)
    for artifact in artifacts:
        artifact["relative_path"] = artifact["relative_path"].replace(
            _relative(config.derived_staging_root),
            final_prefix,
            1,
        )
    artifact_manifest = {
        "schema_version": "1.0",
        "pipeline_version": M1_PIPELINE_VERSION,
        "paper_revision_id": M1_PAPER_REVISION_ID,
        "paper_ir_revision_id": M1_PAPER_IR_REVISION_ID,
        "source_copy_id": paper.copy_id,
        "source_sha256": paper.sha256,
        "question_count": 19,
        "declared_total_points": 150,
        "artifacts": sorted(
            artifacts,
            key=lambda item: str(item["relative_path"]),
        ),
        "quality": {
            "page_count": quality["page_count"],
            "differing_channel_samples": quality["differing_channel_samples"],
            "crop_count": quality["crop_count"],
            "overflow_count": quality["overflow_count"],
            "silent_font_substitution_count": quality[
                "silent_font_substitution_count"
            ],
        },
        "created_at": M1_FIXED_TIMESTAMP,
    }
    manifest_artifact = _write_json(
        config.derived_staging_root / "artifact-manifest.json",
        artifact_manifest,
    )
    manifest_artifact["relative_path"] = manifest_artifact[
        "relative_path"
    ].replace(_relative(config.derived_staging_root), final_prefix, 1)

    database_bytes = get_workspace_io().read_bytes(
        database_path,
        maximum_bytes=64 * 1024 * 1024,
    )
    state_manifest = {
        "schema_version": "1.0",
        "state_id": config.state_id,
        "database": {
            "path": "question_bank.sqlite3",
            "bytes": len(database_bytes),
            "sha256": _sha256(database_bytes),
            "integrity_check": integrity,
            "foreign_key_violations": 0,
        },
        "derived_revision": {
            "path": _relative(config.derived_target_root),
            "artifact_manifest_sha256": manifest_artifact["sha256"],
        },
        "template_revision": {
            "path": _relative(config.template_target_root),
            "template_sha256": template_artifact["sha256"],
        },
        "activity_database_changed": False,
        "created_at": M1_FIXED_TIMESTAMP,
    }
    state_manifest_artifact = _write_json(
        config.database_staging_root / "state-manifest.json",
        state_manifest,
    )
    return {
        "formal_pdf": {
            "relative_path": (
                _relative(config.derived_target_root) + "/formal/student-paper.pdf"
            ),
            "size_bytes": formal_receipt.size_bytes,
            "sha256": formal_receipt.sha256,
        },
        "paper_ir": paper_ir,
        "paper_ir_sha256": _sha256(canonical_json_bytes(paper_ir)),
        "quality": quality,
        "artifact_manifest": manifest_artifact,
        "state_manifest": state_manifest_artifact,
        "template": template_artifact,
    }


def publish_formal_revision(config: M1PipelineConfig) -> dict[str, Any]:
    workspace_io = get_workspace_io()
    targets = (
        (
            "template",
            config.template_staging_root,
            config.template_target_root,
        ),
        (
            "derived",
            config.derived_staging_root,
            config.derived_target_root,
        ),
        (
            "database",
            config.database_staging_root,
            config.database_target_root,
        ),
    )
    receipts: list[dict[str, Any]] = []
    for role, source, target in targets:
        if target.exists():
            if source.exists():
                raise M1PipelineError(
                    f"{role} publication target already exists while staging remains"
                )
            receipts.append(
                {
                    "role": role,
                    "operation": "ALREADY_PUBLISHED",
                    "target": _relative(target),
                }
            )
            continue
        if not source.is_dir():
            raise M1PipelineError(f"{role} staging directory is missing")
        workspace_io.ensure_directory(target.parent)
        receipt = workspace_io.move_directory_no_replace(source, target)
        receipts.append(
            {
                "role": role,
                "operation": receipt.operation,
                "target": _relative(target),
            }
        )
    return {"receipts": receipts}


def verify_published_m1(config: M1PipelineConfig) -> dict[str, Any]:
    if not config.database_target_path.is_file():
        raise M1PipelineError("published candidate database is missing")
    workspace_io = get_workspace_io()
    manifest_path = config.derived_target_root / "artifact-manifest.json"
    state_manifest_path = config.database_target_root / "state-manifest.json"
    manifest_payload = workspace_io.read_bytes(
        manifest_path,
        maximum_bytes=2 * 1024 * 1024,
    )
    state_manifest_payload = workspace_io.read_bytes(
        state_manifest_path,
        maximum_bytes=256 * 1024,
    )
    database_payload = workspace_io.read_bytes(
        config.database_target_path,
        maximum_bytes=64 * 1024 * 1024,
    )
    template_payload = workspace_io.read_bytes(
        config.template_target_root / "template.json",
        maximum_bytes=256 * 1024,
    )
    manifest = json.loads(manifest_payload.decode("utf-8"))
    state_manifest = json.loads(state_manifest_payload.decode("utf-8"))
    formal_path = config.derived_target_root / "formal" / "student-paper.pdf"
    formal_payload = workspace_io.read_bytes(
        formal_path,
        maximum_bytes=32 * 1024 * 1024,
    )
    with connect_database_read_only(config.database_target_path, immutable=True) as connection:
        summary = connection.execute(
            """
            SELECT count(*) AS total,
                   sum(review_status = 'approved') AS approved,
                   sum(answer_text IS NOT NULL AND trim(answer_text) <> '') AS with_answer,
                   sum(analysis_latex IS NOT NULL AND trim(analysis_latex) <> '') AS with_analysis,
                   sum(json_extract(meta_json, '$.observed_p') IS NULL) AS observed_p_null
              FROM questions
            """
        ).fetchone()
        integrity = str(connection.execute("PRAGMA integrity_check").fetchone()[0])
        foreign_key_count = len(connection.execute("PRAGMA foreign_key_check").fetchall())
    if (
        manifest.get("question_count") != 19
        or manifest.get("declared_total_points") != 150
        or _sha256(formal_payload)
        != next(
            artifact["sha256"]
            for artifact in manifest["artifacts"]
            if artifact["role"] == "formal_student_pdf"
        )
        or int(summary["total"]) != 19
        or int(summary["approved"]) != 19
        or int(summary["with_answer"]) != 19
        or int(summary["with_analysis"]) != 19
        or int(summary["observed_p_null"]) != 19
        or integrity != "ok"
        or foreign_key_count
        or state_manifest["database"]["bytes"] != len(database_payload)
        or state_manifest["database"]["sha256"] != _sha256(database_payload)
        or state_manifest["derived_revision"]["artifact_manifest_sha256"]
        != _sha256(manifest_payload)
        or state_manifest["template_revision"]["template_sha256"]
        != _sha256(template_payload)
    ):
        raise M1PipelineError("published M1 revision failed verification")

    app = create_app(
        db_path=config.database_target_path,
        project_root=PROJECT_ROOT,
    )
    app.config["TESTING"] = True
    client = app.test_client()
    list_status = client.get("/questions?status=approved&limit=100").status_code
    with connect_database_read_only(config.database_target_path, immutable=True) as connection:
        first = connection.execute(
            "SELECT id, raw_crop_path FROM questions ORDER BY CAST(question_no AS INTEGER) LIMIT 1"
        ).fetchone()
    detail_status = client.get(
        f"/questions/{int(first['id'])}?status=approved&limit=100"
    ).status_code
    crop_status = client.get("/assets/" + str(first["raw_crop_path"])).status_code
    if list_status != 200 or detail_status != 200 or crop_status != 200:
        raise M1PipelineError("published M1 revision did not survive application restart")

    return {
        "state_id": config.state_id,
        "database_path": _relative(config.database_target_path),
        "derived_path": _relative(config.derived_target_root),
        "template_path": _relative(config.template_target_root),
        "question_count": int(summary["total"]),
        "approved_count": int(summary["approved"]),
        "answer_complete_count": int(summary["with_answer"]),
        "analysis_complete_count": int(summary["with_analysis"]),
        "observed_p_null_count": int(summary["observed_p_null"]),
        "integrity_check": integrity,
        "foreign_key_violations": foreign_key_count,
        "formal_pdf_sha256": _sha256(formal_payload),
        "artifact_manifest_sha256": _sha256(manifest_payload),
        "state_manifest_database_sha256": state_manifest["database"]["sha256"],
        "restart_ui": {
            "list_status": list_status,
            "detail_status": detail_status,
            "crop_status": crop_status,
        },
    }


def run_m1_real_pipeline(
    config: M1PipelineConfig | None = None,
) -> dict[str, Any]:
    config = config or M1PipelineConfig()
    if config.database_target_path.exists():
        first = verify_published_m1(config)
        second = verify_published_m1(config)
        return {
            "pipeline_version": M1_PIPELINE_VERSION,
            "status": "ALREADY_PUBLISHED_VERIFIED",
            "first_verification": first,
            "repeat_verification": second,
            "repeat_stable": first == second,
        }

    paper = load_copy_payload(config.paper_copy_id)
    answer = load_copy_payload(config.answer_copy_id)
    analysis = load_copy_payload(config.analysis_copy_id)
    classifications = {
        "paper": classify_pdf_bytes(paper.payload),
        "answer": classify_pdf_bytes(answer.payload),
        "analysis": classify_pdf_bytes(analysis.payload),
    }
    if any(item.review_required for item in classifications.values()):
        raise M1PipelineError("registered real input unexpectedly requires failure routing")

    questions = split_complete_paper(extract_pdf_lines(paper.payload))
    reference_answers = parse_reference_answers(answer.payload)
    detailed_solutions = parse_detailed_solutions(analysis.payload)
    solutions = reconcile_answers(reference_answers, detailed_solutions)

    assets = render_source_assets(
        paper.payload,
        questions,
        staging_root=config.derived_staging_root,
    )
    candidate = create_candidate_database(
        config,
        paper=paper,
        answer=answer,
        analysis=analysis,
        classification=classifications["paper"],
        questions=questions,
        solutions=solutions,
        assets=assets,
    )
    review = review_candidate_via_web(config)
    formal = build_formal_revision(
        config,
        paper=paper,
        questions=questions,
        solutions=solutions,
    )
    publication = publish_formal_revision(config)
    verification = verify_published_m1(config)
    repeat_verification = verify_published_m1(config)
    return {
        "pipeline_version": M1_PIPELINE_VERSION,
        "status": "PUBLISHED_VERIFIED",
        "copies": {
            "paper": {
                "copy_id": paper.copy_id,
                "sha256": paper.sha256,
                "size_bytes": paper.size_bytes,
            },
            "answer": {
                "copy_id": answer.copy_id,
                "sha256": answer.sha256,
                "size_bytes": answer.size_bytes,
            },
            "analysis": {
                "copy_id": analysis.copy_id,
                "sha256": analysis.sha256,
                "size_bytes": analysis.size_bytes,
            },
        },
        "classifications": {
            role: item.to_dict() for role, item in classifications.items()
        },
        "question_sequence": [item.question_no for item in questions],
        "question_count": len(questions),
        "declared_total_points": sum(
            _SCORE_POINTS[item.question_no] for item in questions
        ),
        "candidate": candidate,
        "review": review,
        "formal": formal,
        "publication": publication,
        "verification": verification,
        "repeat_verification": repeat_verification,
        "repeat_stable": verification == repeat_verification,
    }
