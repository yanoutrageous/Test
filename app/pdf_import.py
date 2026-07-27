from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import PROJECT_ROOT, ensure_storage_directories, get_project_paths
from .database import connect_database, initialize_database
from .page_ranges import PageRangeError, parse_page_numbers
from .safety.context import ContextError, DataClassification, validate_safe_id
from .safety.workspace_io import WorkspaceIOError, get_workspace_io
from .source_copy import (
    COPY_PAYLOAD_NAME,
    COPY_PROVENANCE_NAME,
    SourceCopyError,
    copy_registered_external_file,
)


DEFAULT_IMPORT_PAGES = (1, 603, 1090, 1207)
DEFAULT_RENDER_DPI = 144
MAX_TITLE_LENGTH = 240
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


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


def _safe_import_id(value: str) -> str:
    try:
        return validate_safe_id(value, field_name="import_id")
    except ContextError as exc:
        raise PdfImportError("import_id is not a canonical safe identifier") from exc


def _clean_title(value: str | None, *, fallback: str) -> str:
    title = (value or fallback).strip()
    if (
        not title
        or len(title) > MAX_TITLE_LENGTH
        or any(ord(character) < 32 for character in title)
    ):
        raise PdfImportError(
            f"title must contain 1-{MAX_TITLE_LENGTH} printable characters"
        )
    return title


def _verified_copy_payload(
    pdf_path: Path,
    *,
    project_root: Path,
) -> dict[str, Any]:
    try:
        relative = pdf_path.resolve().relative_to(project_root.resolve())
    except ValueError as exc:
        raise PdfImportError("Copy payload is outside the product root") from exc
    if (
        len(relative.parts) != 4
        or relative.parts[:2] != ("Copy", "source")
        or relative.name != COPY_PAYLOAD_NAME
    ):
        raise PdfImportError("non-PDF paths must be verified Copy/source payloads")
    copy_id = relative.parts[2]
    try:
        validate_safe_id(copy_id, field_name="copy_id")
        workspace = get_workspace_io()
        allowed_target_relative_paths = {
            relative.parent.as_posix(),
            pdf_path.parent.resolve()
            .relative_to(workspace.project_root.resolve())
            .as_posix(),
        }
        payload = workspace.read_bytes(
            pdf_path,
            maximum_bytes=64 * 1024 * 1024,
        )
        provenance_payload = workspace.read_bytes(
            pdf_path.parent / COPY_PROVENANCE_NAME,
            maximum_bytes=256 * 1024,
        )
        provenance = json.loads(provenance_payload.decode("ascii"))
    except (
        ContextError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
        WorkspaceIOError,
    ) as exc:
        raise PdfImportError("Copy/source provenance is unreadable") from exc
    expected = provenance.get("payload") if type(provenance) is dict else None
    digest = hashlib.sha256(payload).hexdigest()
    if (
        type(provenance) is not dict
        or provenance.get("schema_version") != "1.0"
        or provenance.get("copy_id") != copy_id
        or provenance.get("classification") != "INTERNAL"
        or provenance.get("target_relative_path")
        not in allowed_target_relative_paths
        or type(expected) is not dict
        or expected.get("path") != COPY_PAYLOAD_NAME
        or expected.get("bytes") != len(payload)
        or expected.get("sha256") != digest
        or not SHA256_RE.fullmatch(digest)
    ):
        raise PdfImportError("Copy/source payload does not match its provenance")
    return {
        "bytes": len(payload),
        "copy_id": copy_id,
        "logical_source_id": provenance.get("source", {}).get(
            "logical_id"
        ),
        "sha256": digest,
    }


def _copy_or_verify_external_pdf(
    source_path: str | os.PathLike[str],
    *,
    import_id: str,
    project_root: Path,
) -> tuple[Path, dict[str, Any]]:
    canonical_import_id = _safe_import_id(import_id)
    source_name = Path(os.fspath(source_path)).name
    if Path(source_name).suffix.lower() != ".pdf":
        raise PdfImportError("external import currently supports PDF files only")
    copy_id = f"COPY-USER-PDF-{canonical_import_id}"
    logical_source_id = f"REF-USER-PDF-{canonical_import_id}"
    job_id = f"JOB-USER-PDF-{canonical_import_id}"
    try:
        validate_safe_id(copy_id, field_name="copy_id")
        validate_safe_id(logical_source_id, field_name="logical_source_id")
        validate_safe_id(job_id, field_name="job_id")
    except ContextError as exc:
        raise PdfImportError(
            "import_id is too long for the controlled Copy identifiers"
        ) from exc
    copy_root = project_root / "Copy" / "source" / copy_id
    payload_path = copy_root / COPY_PAYLOAD_NAME
    if os.path.lexists(copy_root):
        summary = _verified_copy_payload(
            payload_path,
            project_root=project_root,
        )
        try:
            verification = copy_registered_external_file(
                source_path,
                logical_source_id=logical_source_id,
                copy_id=copy_id,
                job_id=job_id,
                purpose="USER-PDF-IMPORT",
                classification=DataClassification.INTERNAL,
                verify_only=True,
            )
        except SourceCopyError as exc:
            raise PdfImportError(
                "external PDF did not pass the read-only verification boundary"
            ) from exc
        if (
            verification.payload_sha256 != summary["sha256"]
            or verification.payload_bytes != summary["bytes"]
        ):
            raise PdfImportError(
                "external PDF differs from the existing immutable import copy"
            )
        return payload_path, {
            **summary,
            "operation": "VERIFIED_EXISTING_COPY",
        }
    try:
        receipt = copy_registered_external_file(
            source_path,
            logical_source_id=logical_source_id,
            copy_id=copy_id,
            job_id=job_id,
            purpose="USER-PDF-IMPORT",
            classification=DataClassification.INTERNAL,
        )
    except SourceCopyError as exc:
        raise PdfImportError(
            "external PDF could not be published into the immutable Copy ledger"
        ) from exc
    summary = _verified_copy_payload(
        payload_path,
        project_root=project_root,
    )
    if (
        summary["sha256"] != receipt.payload_sha256
        or summary["bytes"] != receipt.payload_bytes
    ):
        raise PdfImportError("new Copy receipt does not match the published PDF")
    return payload_path, {
        **summary,
        "operation": "PUBLISHED_COPY",
    }


def register_source_pdf(
    pdf_path: Path,
    *,
    db_path: Path | None = None,
    project_root: Path = PROJECT_ROOT,
    title: str | None = None,
    import_id: str | None = None,
) -> RegisteredPaper:
    if not pdf_path.exists():
        raise PdfImportError(f"PDF not found: {pdf_path}")
    try:
        pdf_path = get_workspace_io().validate_read_file_path(pdf_path)
    except WorkspaceIOError as exc:
        raise PdfImportError(
            "PDF must be a handle-verified file inside the project workspace"
        ) from exc

    copy_summary: dict[str, Any] | None = None
    if pdf_path.suffix.lower() != ".pdf":
        copy_summary = _verified_copy_payload(
            pdf_path,
            project_root=project_root,
        )
    sha256 = compute_file_sha256(pdf_path)
    paper_code = build_paper_code(sha256)
    page_count = read_pdf_page_count(pdf_path)
    source_path = relative_path(pdf_path, project_root)
    resolved_title = _clean_title(
        title,
        fallback=(
            f"Imported PDF {sha256.upper()[:12]}"
            if copy_summary is not None
            else pdf_path.stem
        ),
    )
    meta_json = json.dumps(
        {
            "sha256": sha256,
            "registered_by": "stage3_import_pdf",
            "import_id": import_id,
            "copy_id": (
                copy_summary["copy_id"]
                if copy_summary is not None
                else None
            ),
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
            (
                paper_code,
                resolved_title,
                source_path,
                page_count,
                "born_digital",
                meta_json,
            ),
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


def import_external_pdf(
    source_path: str | os.PathLike[str],
    *,
    import_id: str,
    pages: tuple[int, ...],
    column_count: int = 1,
    dpi: int = 120,
    title: str | None = None,
    year: int | None = None,
    db_path: Path | None = None,
    project_root: Path = PROJECT_ROOT,
) -> dict[str, Any]:
    """Copy, register, render and split one user-selected born-digital PDF."""

    from .question_split import MAX_COLUMN_COUNT, split_questions

    canonical_import_id = _safe_import_id(import_id)
    if not pages:
        raise PdfImportError("at least one source page is required")
    if type(column_count) is not int or not 1 <= column_count <= MAX_COLUMN_COUNT:
        raise PdfImportError(
            f"column_count must be between 1 and {MAX_COLUMN_COUNT}"
        )
    if type(dpi) is not int or not 72 <= dpi <= 300:
        raise PdfImportError("dpi must be between 72 and 300")
    if year is not None and (type(year) is not int or not 1900 <= year <= 2200):
        raise PdfImportError("year must be between 1900 and 2200")

    paths = get_project_paths(project_root, require_target_pdf=False)
    resolved_db_path = db_path or paths.db_path
    payload_path, copy_summary = _copy_or_verify_external_pdf(
        source_path,
        import_id=canonical_import_id,
        project_root=project_root,
    )
    paper = register_source_pdf(
        payload_path,
        db_path=resolved_db_path,
        project_root=project_root,
        title=title,
        import_id=canonical_import_id,
    )
    validate_pages(pages, paper.page_count)
    import_root = project_root / "data" / "imports" / canonical_import_id
    rendered_pages = render_pdf_pages(
        payload_path,
        paper,
        pages,
        dpi=dpi,
        db_path=resolved_db_path,
        project_root=project_root,
        paper_pages_dir=import_root / "pages",
    )
    split = split_questions(
        pages=pages,
        db_path=resolved_db_path,
        project_root=project_root,
        pdf_path=payload_path,
        column_count=column_count,
        year=year,
    )
    return {
        "column_count": column_count,
        "copy": copy_summary,
        "database_relative_path": relative_path(
            resolved_db_path,
            project_root,
        ),
        "dpi": dpi,
        "import_id": canonical_import_id,
        "pages": [
            {
                "page_no": row["page_no"],
                "relative_path": row["relative_path"],
                "size_bytes": row["size_bytes"],
            }
            for row in rendered_pages
        ],
        "paper": {
            "id": paper.id,
            "paper_code": paper.paper_code,
            "title": paper.title,
            "source_path": paper.source_path,
            "page_count": paper.page_count,
            "sha256": paper.sha256,
        },
        "split": {
            "column_count": split["column_count"],
            "pages": split["pages"],
            "write": split["write"],
        },
        "status": "IMPORTED_PENDING_REVIEW",
        "year": year,
    }
