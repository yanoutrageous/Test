from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import PROJECT_ROOT, ensure_storage_directories, get_project_paths
from .database import connect_database, initialize_database
from .page_ranges import PageRangeError, parse_page_numbers
from .safety.workspace_io import WorkspaceIOError, get_workspace_io


DEFAULT_IMPORT_PAGES = (1, 603, 1090, 1207)
DEFAULT_RENDER_DPI = 144


class PdfImportError(RuntimeError):
    """Raised when a PDF cannot be registered or rendered for this slice."""


@dataclass(frozen=True)
class RegisteredPaper:
    id: int
    paper_code: str
    title: str
    source_path: str
    page_count: int
    sha256: str


def parse_pages(value: str | None) -> tuple[int, ...]:
    try:
        return parse_page_numbers(value, default=DEFAULT_IMPORT_PAGES)
    except PageRangeError as exc:
        raise PdfImportError(str(exc)) from exc


def compute_file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_paper_code(sha256: str) -> str:
    return f"PDF-{sha256[:16].upper()}"


def relative_path(path: Path, root: Path = PROJECT_ROOT) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError as exc:
        raise PdfImportError(f"Path is outside project root: {path}") from exc


def read_pdf_page_count(pdf_path: Path) -> int:
    import fitz

    with fitz.open(pdf_path) as doc:
        return doc.page_count


def validate_pages(page_numbers: tuple[int, ...], page_count: int) -> None:
    invalid = [page_no for page_no in page_numbers if page_no < 1 or page_no > page_count]
    if invalid:
        raise PdfImportError(
            f"Page out of range: {invalid}; valid range is 1-{page_count}"
        )


def register_source_pdf(
    pdf_path: Path,
    *,
    db_path: Path | None = None,
    project_root: Path = PROJECT_ROOT,
) -> RegisteredPaper:
    if not pdf_path.exists():
        raise PdfImportError(f"PDF not found: {pdf_path}")
    if pdf_path.suffix.lower() != ".pdf":
        raise PdfImportError(f"Expected a PDF file: {pdf_path}")
    try:
        pdf_path = get_workspace_io().validate_read_file_path(pdf_path)
    except WorkspaceIOError as exc:
        raise PdfImportError(
            "PDF must be a handle-verified file inside the project workspace"
        ) from exc

    sha256 = compute_file_sha256(pdf_path)
    paper_code = build_paper_code(sha256)
    page_count = read_pdf_page_count(pdf_path)
    source_path = relative_path(pdf_path, project_root)
    title = pdf_path.stem
    meta_json = json.dumps(
        {
            "sha256": sha256,
            "registered_by": "stage3_import_pdf",
        },
        ensure_ascii=False,
    )

    initialize_database(db_path)
    with connect_database(db_path) as conn:
        conn.execute(
            """
            INSERT INTO source_papers (
                paper_code,
                title,
                source_path,
                page_count,
                import_mode,
                meta_json
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(paper_code) DO UPDATE SET
                title = excluded.title,
                source_path = excluded.source_path,
                page_count = excluded.page_count,
                import_mode = excluded.import_mode,
                meta_json = excluded.meta_json
            """,
            (paper_code, title, source_path, page_count, "born_digital", meta_json),
        )
        row = conn.execute(
            """
            SELECT id, paper_code, title, source_path, page_count, meta_json
              FROM source_papers
             WHERE paper_code = ?
            """,
            (paper_code,),
        ).fetchone()
        conn.commit()

    return RegisteredPaper(
        id=int(row["id"]),
        paper_code=row["paper_code"],
        title=row["title"],
        source_path=row["source_path"],
        page_count=int(row["page_count"]),
        sha256=sha256,
    )


def render_pdf_pages(
    pdf_path: Path,
    paper: RegisteredPaper,
    page_numbers: tuple[int, ...],
    *,
    dpi: int = DEFAULT_RENDER_DPI,
    db_path: Path | None = None,
    project_root: Path = PROJECT_ROOT,
    paper_pages_dir: Path | None = None,
) -> list[dict[str, Any]]:
    if dpi <= 0:
        raise PdfImportError(f"DPI must be positive: {dpi}")
    try:
        pdf_path = get_workspace_io().validate_read_file_path(pdf_path)
    except WorkspaceIOError as exc:
        raise PdfImportError(
            "PDF must be a handle-verified file inside the project workspace"
        ) from exc

    validate_pages(page_numbers, paper.page_count)

    import fitz

    paths = ensure_storage_directories()
    pages_root = paper_pages_dir or paths.paper_pages_dir
    output_dir = pages_root / paper.paper_code
    workspace_io = get_workspace_io()
    workspace_io.ensure_directory(output_dir)

    rendered: list[dict[str, Any]] = []
    database_rows: list[tuple[int, str, int, str, str]] = []
    with fitz.open(pdf_path) as doc:
        for page_no in page_numbers:
            page = doc[page_no - 1]
            output_path = output_dir / f"page_{page_no:04d}_{dpi}dpi.png"
            pixmap = page.get_pixmap(dpi=dpi)
            receipt = workspace_io.write_bytes_idempotent(
                output_path,
                pixmap.tobytes("png"),
            )

            rel_path = relative_path(output_path, project_root)
            bbox_json = json.dumps(
                {
                    "page_width": page.rect.width,
                    "page_height": page.rect.height,
                },
                ensure_ascii=False,
            )
            meta_json = json.dumps(
                {
                    "dpi": dpi,
                    "paper_code": paper.paper_code,
                },
                ensure_ascii=False,
            )
            database_rows.append(
                (paper.id, rel_path, page_no, bbox_json, meta_json)
            )
            rendered.append(
                {
                    "page_no": page_no,
                    "relative_path": rel_path,
                    "path": str(output_path),
                    "size_bytes": receipt.size_bytes,
                }
            )

    # The database lease deliberately owns the writer's single mutation
    # reservation.  Finish immutable page publication before opening it.
    with connect_database(db_path) as conn:
        for source_paper_id, rel_path, page_no, bbox_json, meta_json in database_rows:
            conn.execute(
                """
                INSERT INTO source_paper_assets (
                    source_paper_id,
                    asset_kind,
                    relative_path,
                    page_no,
                    bbox_json,
                    meta_json
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(source_paper_id, asset_kind, page_no) DO UPDATE SET
                    relative_path = excluded.relative_path,
                    bbox_json = excluded.bbox_json,
                    meta_json = excluded.meta_json
                """,
                (
                    source_paper_id,
                    "page_image",
                    rel_path,
                    page_no,
                    bbox_json,
                    meta_json,
                ),
            )
        conn.commit()

    return rendered


def import_pdf(
    *,
    pdf_path: Path | None = None,
    pages: tuple[int, ...] = DEFAULT_IMPORT_PAGES,
    dpi: int = DEFAULT_RENDER_DPI,
    db_path: Path | None = None,
    project_root: Path = PROJECT_ROOT,
) -> dict[str, Any]:
    paths = get_project_paths(project_root)
    target_pdf = pdf_path or paths.target_pdf
    resolved_db_path = db_path or paths.db_path

    paper = register_source_pdf(
        target_pdf,
        db_path=resolved_db_path,
        project_root=project_root,
    )
    rendered_pages = render_pdf_pages(
        target_pdf,
        paper,
        pages,
        dpi=dpi,
        db_path=resolved_db_path,
        project_root=project_root,
        paper_pages_dir=paths.paper_pages_dir,
    )

    return {
        "paper": {
            "id": paper.id,
            "paper_code": paper.paper_code,
            "title": paper.title,
            "source_path": paper.source_path,
            "page_count": paper.page_count,
            "sha256": paper.sha256,
        },
        "pages": rendered_pages,
        "db_path": str(resolved_db_path),
    }
