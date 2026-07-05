from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import PROJECT_ROOT, get_project_paths
from .database import connect_database, initialize_database
from .pdf_import import PdfImportError, parse_pages as parse_import_pages, relative_path, validate_pages


ALGORITHM_VERSION = "stage4_page_anchor_v1"
DEFAULT_SPLIT_PAGES = (1090,)
QUESTION_ANCHOR_RE = re.compile(r"^\s*(\d{1,3})[.．]\s*")
MIN_STEM_TEXT_LENGTH = 20


class QuestionSplitError(RuntimeError):
    """Raised when page-level question splitting cannot continue."""


@dataclass(frozen=True)
class PageTextBlock:
    page_no: int
    block_index: int
    bbox: tuple[float, float, float, float]
    text: str


@dataclass(frozen=True)
class QuestionCandidate:
    source_paper_id: int
    paper_code: str
    paper_title: str
    page_no: int
    question_no: str
    question_type: str | None
    blocks: tuple[PageTextBlock, ...]
    stem_text: str
    bbox: tuple[float, float, float, float]
    split_warnings: tuple[str, ...]
    qid: str
    content_hash: str


def parse_split_pages(value: str | None) -> tuple[int, ...]:
    if value is None or not value.strip():
        return DEFAULT_SPLIT_PAGES
    try:
        return parse_import_pages(value)
    except PdfImportError as exc:
        raise QuestionSplitError(str(exc)) from exc


def normalize_block_text(text: str) -> str:
    return " ".join((text or "").split())


def detect_question_anchor(text: str) -> int | None:
    match = QUESTION_ANCHOR_RE.match(text)
    if not match:
        return None
    return int(match.group(1))


def _section_question_type(text: str) -> str | None:
    normalized = normalize_block_text(text)
    if "选择题" in normalized:
        return "选择题"
    if "填空题" in normalized:
        return "填空题"
    if "解答题" in normalized:
        return "解答题"
    return None


def extract_page_text_blocks(pdf_path: Path, page_no: int) -> tuple[PageTextBlock, ...]:
    import fitz

    with fitz.open(pdf_path) as doc:
        validate_pages((page_no,), doc.page_count)
        page = doc[page_no - 1]
        blocks: list[PageTextBlock] = []
        for block_index, block in enumerate(page.get_text("blocks")):
            x0, y0, x1, y1, text, *_ = block
            clean = normalize_block_text(text)
            if clean:
                blocks.append(
                    PageTextBlock(
                        page_no=page_no,
                        block_index=block_index,
                        bbox=(float(x0), float(y0), float(x1), float(y1)),
                        text=clean,
                    )
                )
        return tuple(blocks)


def _union_bbox(blocks: tuple[PageTextBlock, ...]) -> tuple[float, float, float, float]:
    return (
        min(block.bbox[0] for block in blocks),
        min(block.bbox[1] for block in blocks),
        max(block.bbox[2] for block in blocks),
        max(block.bbox[3] for block in blocks),
    )


def _content_hash(*parts: str) -> str:
    digest = hashlib.sha256()
    for part in parts:
        digest.update((part or "").encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


def _stable_qid(paper_code: str, page_no: int, question_no: str) -> str:
    try:
        normalized_no = f"{int(question_no):03d}"
    except ValueError:
        normalized_no = question_no
    return f"{paper_code}-P{page_no:04d}-Q{normalized_no}"


def _build_candidate(
    *,
    source_paper_id: int,
    paper_code: str,
    paper_title: str,
    page_no: int,
    question_no: int,
    question_type: str | None,
    blocks: tuple[PageTextBlock, ...],
    previous_question_no: int | None,
) -> QuestionCandidate:
    question_no_text = str(question_no)
    stem_text = "\n".join(block.text for block in blocks)
    warnings: list[str] = []
    if len(stem_text) < MIN_STEM_TEXT_LENGTH:
        warnings.append("stem_too_short")
    if previous_question_no is not None and question_no != previous_question_no + 1:
        warnings.append("question_number_non_contiguous")

    qid = _stable_qid(paper_code, page_no, question_no_text)
    content_hash = _content_hash(paper_code, str(page_no), question_no_text, stem_text)
    return QuestionCandidate(
        source_paper_id=source_paper_id,
        paper_code=paper_code,
        paper_title=paper_title,
        page_no=page_no,
        question_no=question_no_text,
        question_type=question_type,
        blocks=blocks,
        stem_text=stem_text,
        bbox=_union_bbox(blocks),
        split_warnings=tuple(warnings),
        qid=qid,
        content_hash=content_hash,
    )


def split_blocks_into_candidates(
    blocks: tuple[PageTextBlock, ...],
    *,
    source_paper_id: int,
    paper_code: str,
    paper_title: str,
    page_no: int,
) -> tuple[QuestionCandidate, ...]:
    candidates: list[QuestionCandidate] = []
    current_blocks: list[PageTextBlock] = []
    current_question_no: int | None = None
    current_question_type: str | None = None
    active_question_type: str | None = None
    previous_question_no: int | None = None

    def flush_current() -> None:
        nonlocal previous_question_no
        if current_question_no is None or not current_blocks:
            return
        candidate = _build_candidate(
            source_paper_id=source_paper_id,
            paper_code=paper_code,
            paper_title=paper_title,
            page_no=page_no,
            question_no=current_question_no,
            question_type=current_question_type,
            blocks=tuple(current_blocks),
            previous_question_no=previous_question_no,
        )
        candidates.append(candidate)
        previous_question_no = current_question_no

    for block in blocks:
        section_type = _section_question_type(block.text)
        if section_type:
            active_question_type = section_type
            continue

        anchor_no = detect_question_anchor(block.text)
        if anchor_no is not None:
            flush_current()
            current_question_no = anchor_no
            current_question_type = active_question_type
            current_blocks = [block]
            continue

        if current_question_no is not None:
            current_blocks.append(block)

    flush_current()
    return tuple(candidates)


def _load_source_paper_for_pdf(
    pdf_path: Path,
    *,
    db_path: Path | None = None,
    project_root: Path = PROJECT_ROOT,
) -> dict[str, Any]:
    source_path = relative_path(pdf_path, project_root)
    with connect_database(db_path) as conn:
        row = conn.execute(
            """
            SELECT id, paper_code, title, source_path, page_count
              FROM source_papers
             WHERE source_path = ?
            """,
            (source_path,),
        ).fetchone()
    if row is None:
        raise QuestionSplitError(
            "Source paper is not registered. Run `python -m app.cli import-pdf` first."
        )
    return dict(row)


def extract_candidates_from_pdf_page(
    pdf_path: Path,
    page_no: int,
    *,
    db_path: Path | None = None,
    project_root: Path = PROJECT_ROOT,
) -> tuple[QuestionCandidate, ...]:
    paper = _load_source_paper_for_pdf(pdf_path, db_path=db_path, project_root=project_root)
    blocks = extract_page_text_blocks(pdf_path, page_no)
    return split_blocks_into_candidates(
        blocks,
        source_paper_id=int(paper["id"]),
        paper_code=paper["paper_code"],
        paper_title=paper["title"],
        page_no=page_no,
    )


def _candidate_meta(candidate: QuestionCandidate) -> str:
    return json.dumps(
        {
            "algorithm_version": ALGORITHM_VERSION,
            "source_page": candidate.page_no,
            "split_warnings": list(candidate.split_warnings),
            "source_blocks": [block.block_index for block in candidate.blocks],
        },
        ensure_ascii=False,
    )


def _candidate_bbox(candidate: QuestionCandidate) -> str:
    x0, y0, x1, y1 = candidate.bbox
    return json.dumps(
        {
            "page": candidate.page_no,
            "x0": x0,
            "y0": y0,
            "x1": x1,
            "y1": y1,
        },
        ensure_ascii=False,
    )


def write_question_candidates(
    candidates: tuple[QuestionCandidate, ...],
    *,
    db_path: Path | None = None,
) -> dict[str, Any]:
    inserted = 0
    updated = 0
    skipped_reviewed = 0
    pending = 0
    page_writes: dict[int, dict[str, int]] = {}

    def page_stats(candidate: QuestionCandidate) -> dict[str, int]:
        stats = page_writes.setdefault(
            candidate.page_no,
            {
                "page_no": candidate.page_no,
                "candidates": 0,
                "inserted": 0,
                "updated": 0,
                "skipped_reviewed": 0,
                "warning_candidates": 0,
            },
        )
        stats["candidates"] += 1
        if candidate.split_warnings:
            stats["warning_candidates"] += 1
        return stats

    with connect_database(db_path) as conn:
        for candidate in candidates:
            stats = page_stats(candidate)
            existing = conn.execute(
                "SELECT id, review_status FROM questions WHERE qid = ?",
                (candidate.qid,),
            ).fetchone()

            values = {
                "qid": candidate.qid,
                "source_paper_id": candidate.source_paper_id,
                "paper_name": candidate.paper_title,
                "question_no": candidate.question_no,
                "question_type": candidate.question_type,
                "stem_latex": candidate.stem_text,
                "stem_text": candidate.stem_text,
                "tags_json": "[]",
                "image_refs_json": "[]",
                "page_range": f"p{candidate.page_no:04d}",
                "bbox_json": _candidate_bbox(candidate),
                "review_status": "pending",
                "meta_json": _candidate_meta(candidate),
                "content_hash": candidate.content_hash,
            }

            if existing is None:
                conn.execute(
                    """
                    INSERT INTO questions (
                        qid,
                        source_paper_id,
                        paper_name,
                        question_no,
                        question_type,
                        stem_latex,
                        stem_text,
                        tags_json,
                        image_refs_json,
                        page_range,
                        bbox_json,
                        review_status,
                        meta_json,
                        content_hash
                    ) VALUES (
                        :qid,
                        :source_paper_id,
                        :paper_name,
                        :question_no,
                        :question_type,
                        :stem_latex,
                        :stem_text,
                        :tags_json,
                        :image_refs_json,
                        :page_range,
                        :bbox_json,
                        :review_status,
                        :meta_json,
                        :content_hash
                    )
                    """,
                    values,
                )
                inserted += 1
                stats["inserted"] += 1
            else:
                if existing["review_status"] in ("reviewed", "approved"):
                    skipped_reviewed += 1
                    stats["skipped_reviewed"] += 1
                    continue

                conn.execute(
                    """
                    UPDATE questions
                       SET source_paper_id = :source_paper_id,
                           paper_name = :paper_name,
                           question_no = :question_no,
                           question_type = :question_type,
                           stem_latex = :stem_latex,
                           stem_text = :stem_text,
                           tags_json = :tags_json,
                           image_refs_json = :image_refs_json,
                           page_range = :page_range,
                           bbox_json = :bbox_json,
                           review_status = :review_status,
                           meta_json = :meta_json,
                           content_hash = :content_hash,
                           updated_at = CURRENT_TIMESTAMP
                     WHERE qid = :qid
                    """,
                    values,
                )
                updated += 1
                stats["updated"] += 1

        conn.commit()

        pending = conn.execute(
            """
            SELECT count(*)
              FROM questions
             WHERE review_status = 'pending'
               AND meta_json ->> '$.algorithm_version' = ?
            """,
            (ALGORITHM_VERSION,),
        ).fetchone()[0]

    return {
        "candidates": len(candidates),
        "inserted": inserted,
        "updated": updated,
        "skipped_reviewed": skipped_reviewed,
        "pending_stage4": pending,
        "warning_candidates": sum(1 for candidate in candidates if candidate.split_warnings),
        "page_writes": [page_writes[key] for key in sorted(page_writes)],
    }


def split_questions(
    *,
    pages: tuple[int, ...] = DEFAULT_SPLIT_PAGES,
    db_path: Path | None = None,
    project_root: Path = PROJECT_ROOT,
) -> dict[str, Any]:
    paths = get_project_paths(project_root)
    initialize_database(db_path or paths.db_path)
    paper = _load_source_paper_for_pdf(
        paths.target_pdf,
        db_path=db_path or paths.db_path,
        project_root=project_root,
    )
    validate_pages(pages, int(paper["page_count"]))

    page_results: list[dict[str, Any]] = []
    all_candidates: list[QuestionCandidate] = []
    for page_no in pages:
        candidates = extract_candidates_from_pdf_page(
            paths.target_pdf,
            page_no,
            db_path=db_path or paths.db_path,
            project_root=project_root,
        )
        all_candidates.extend(candidates)
        page_results.append(
            {
                "page_no": page_no,
                "candidate_count": len(candidates),
                "warning_candidates": sum(1 for candidate in candidates if candidate.split_warnings),
            }
        )

    write_result = write_question_candidates(
        tuple(all_candidates),
        db_path=db_path or paths.db_path,
    )

    writes_by_page = {
        item["page_no"]: item for item in write_result.get("page_writes", [])
    }
    for page_result in page_results:
        page_result["write"] = writes_by_page.get(
            page_result["page_no"],
            {
                "page_no": page_result["page_no"],
                "candidates": page_result["candidate_count"],
                "inserted": 0,
                "updated": 0,
                "skipped_reviewed": 0,
                "warning_candidates": page_result["warning_candidates"],
            },
        )

    return {
        "paper": {
            "id": paper["id"],
            "paper_code": paper["paper_code"],
            "source_path": paper["source_path"],
            "page_count": paper["page_count"],
        },
        "pages": page_results,
        "write": write_result,
        "db_path": str(db_path or paths.db_path),
    }
