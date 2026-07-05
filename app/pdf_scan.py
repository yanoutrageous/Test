from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from .config import PROJECT_ROOT, get_project_paths
from .pdf_import import PdfImportError, read_pdf_page_count, validate_pages
from .question_split import (
    detect_question_anchor,
    extract_page_text_blocks,
    split_blocks_into_candidates,
)


ANSWER_TERMS = ("\u7b54\u6848", "\u53c2\u8003\u7b54\u6848", "\u89e3\u6790")
TOC_TERMS = ("\u76ee\u5f55", "\u7d22\u5f15", "contents")
INSTRUCTION_TERMS = ("\u8bf4\u660e", "\u6ce8\u610f\u4e8b\u9879", "\u672c\u8bd5\u5377")


def scan_pdf_pages(
    *,
    pages: tuple[int, ...],
    pdf_path: Path | None = None,
    project_root: Path = PROJECT_ROOT,
) -> dict[str, Any]:
    paths = get_project_paths(project_root, require_target_pdf=pdf_path is None)
    target_pdf = pdf_path or paths.target_pdf
    if target_pdf is None:
        raise PdfImportError("Target PDF is required for page scanning")
    page_count = read_pdf_page_count(target_pdf)
    validate_pages(pages, page_count)

    page_results: list[dict[str, Any]] = []
    for page_no in pages:
        blocks = extract_page_text_blocks(target_pdf, page_no)
        text = "\n".join(block.text for block in blocks)
        anchors = [
            anchor
            for anchor in (detect_question_anchor(block.text) for block in blocks)
            if anchor is not None
        ]
        duplicate_anchor_count = sum(
            count - 1 for count in Counter(anchors).values() if count > 1
        )
        candidates = split_blocks_into_candidates(
            blocks,
            source_paper_id=0,
            paper_code="SCAN",
            paper_title=target_pdf.stem,
            page_no=page_no,
        )
        warning_candidates = sum(1 for candidate in candidates if candidate.split_warnings)
        warning_reasons = sorted(
            {
                warning
                for candidate in candidates
                for warning in candidate.split_warnings
            }
        )
        flags = _page_flags(
            text=text,
            text_length=len(text),
            anchor_count=len(anchors),
            candidate_count=len(candidates),
            warning_candidates=warning_candidates,
            warning_reasons=warning_reasons,
            duplicate_anchor_count=duplicate_anchor_count,
        )
        page_results.append(
            {
                "page_no": page_no,
                "text_length": len(text),
                "block_count": len(blocks),
                "anchor_count": len(anchors),
                "first_anchors": anchors[:8],
                "duplicate_anchor_count": duplicate_anchor_count,
                "candidate_count": len(candidates),
                "warning_candidates": warning_candidates,
                "warning_reasons": warning_reasons,
                "page_flags": flags,
            }
        )

    return {
        "paper": {
            "source_path": str(target_pdf),
            "page_count": page_count,
        },
        "pages": page_results,
        "summary": _summary(page_results),
    }


def _page_flags(
    *,
    text: str,
    text_length: int,
    anchor_count: int,
    candidate_count: int,
    warning_candidates: int,
    warning_reasons: list[str],
    duplicate_anchor_count: int,
) -> list[str]:
    flags: list[str] = []
    if text_length == 0:
        flags.append("empty_text")
    elif text_length < 80:
        flags.append("short_text")

    if anchor_count == 0:
        flags.append("no_anchors")
    elif anchor_count < 2:
        flags.append("few_anchors")

    if candidate_count == 0:
        flags.append("no_candidates")
    if warning_candidates:
        flags.append("warning_candidates")
    if duplicate_anchor_count:
        flags.append("duplicate_anchors")
    if "question_number_non_contiguous" in warning_reasons:
        flags.append("question_number_non_contiguous")
    if "stem_too_short" in warning_reasons:
        flags.append("short_candidate_text")

    lowered = text.lower()
    if any(term in text for term in ANSWER_TERMS):
        flags.append("possible_answer_page")
    if any(term in text or term in lowered for term in TOC_TERMS):
        flags.append("possible_toc_page")
    if any(term in text for term in INSTRUCTION_TERMS):
        flags.append("possible_instruction_page")

    return flags


def _summary(page_results: list[dict[str, Any]]) -> dict[str, Any]:
    flagged_pages = [
        {"page_no": page["page_no"], "page_flags": page["page_flags"]}
        for page in page_results
        if page["page_flags"]
    ]
    return {
        "page_count": len(page_results),
        "total_candidates": sum(page["candidate_count"] for page in page_results),
        "total_warning_candidates": sum(page["warning_candidates"] for page in page_results),
        "flagged_pages": flagged_pages,
    }
