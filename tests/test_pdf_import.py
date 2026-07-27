from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from app.database import connect_database, initialize_database
from app.pdf_import import (
    DEFAULT_IMPORT_PAGES,
    PdfImportError,
    import_pdf,
    import_external_pdf,
    parse_pages,
    register_source_pdf,
)
from tests.conftest import register_synthetic_source


def _create_pdf(path: Path, page_count: int = 4) -> None:
    import fitz

    path.parent.mkdir(parents=True, exist_ok=True)
    doc = fitz.open()
    for index in range(page_count):
        page = doc.new_page(width=180, height=240)
        page.insert_text((36, 72), f"sample page {index + 1}")
    doc.save(path)
    doc.close()


def _prepare_project(tmp_path: Path) -> tuple[Path, Path]:
    pdf_path = tmp_path / "Base" / "sample.pdf"
    db_path = tmp_path / "data" / "db" / "question_bank.sqlite3"
    _create_pdf(pdf_path)
    initialize_database(db_path)
    return pdf_path, db_path


def test_parse_pages_uses_default_and_deduplicates() -> None:
    assert parse_pages(None) == DEFAULT_IMPORT_PAGES
    assert parse_pages("1, 2,2; 3") == (1, 2, 3)
    assert parse_pages("1-3,2,5") == (1, 2, 3, 5)
    assert parse_pages("3-3") == (3,)


def test_parse_pages_rejects_invalid_ranges() -> None:
    for value in ("0", "3-1", "1-", "a-b"):
        with pytest.raises(PdfImportError):
            parse_pages(value)


def test_register_source_pdf_is_idempotent(tmp_path: Path) -> None:
    pdf_path, db_path = _prepare_project(tmp_path)

    first = register_source_pdf(pdf_path, db_path=db_path, project_root=tmp_path)
    second = register_source_pdf(pdf_path, db_path=db_path, project_root=tmp_path)

    assert first.id == second.id
    assert first.paper_code == second.paper_code
    assert first.source_path == "Base/sample.pdf"
    assert first.page_count == 4

    with connect_database(db_path) as conn:
        assert conn.execute("SELECT count(*) FROM source_papers").fetchone()[0] == 1


def test_register_source_pdf_accepts_only_provenance_verified_copy_payload(
    tmp_path: Path,
) -> None:
    copy_id = "COPY-USER-PDF-UNIT-001"
    copy_root = tmp_path / "Copy" / "source" / copy_id
    payload_path = copy_root / "payload.bin"
    db_path = tmp_path / "data" / "db" / "question_bank.sqlite3"
    _create_pdf(payload_path, page_count=2)
    payload = payload_path.read_bytes()
    (copy_root / "provenance.json").write_text(
        json.dumps(
            {
                "classification": "INTERNAL",
                "copy_id": copy_id,
                "payload": {
                    "bytes": len(payload),
                    "path": "payload.bin",
                    "sha256": hashlib.sha256(payload).hexdigest(),
                },
                "schema_version": "1.0",
                "source": {"logical_source_id": "USER-PDF-UNIT-001"},
                "target_relative_path": f"Copy/source/{copy_id}",
            }
        ),
        encoding="ascii",
    )

    paper = register_source_pdf(
        payload_path,
        db_path=db_path,
        project_root=tmp_path,
        title="Verified Copy Paper",
        import_id="UNIT-001",
    )

    assert paper.title == "Verified Copy Paper"
    assert paper.page_count == 2
    assert paper.source_path == f"Copy/source/{copy_id}/payload.bin"


def test_import_external_pdf_uses_registered_reference_identity() -> None:
    run_root = Path(os.environ["M0_TEST_LAB_ROOT"])
    project_root = run_root / "project"
    source = run_root / "external" / "REFERENCE" / "external-paper.pdf"
    database = project_root / "data" / "db" / "question_bank.sqlite3"
    _create_pdf(source, page_count=1)
    register_synthetic_source(source)
    initialize_database(database)

    result = import_external_pdf(
        source,
        import_id="UNIT-EXTERNAL-001",
        pages=(1,),
        db_path=database,
        project_root=project_root,
    )

    provenance_path = (
        project_root
        / "Copy"
        / "source"
        / "COPY-USER-PDF-UNIT-EXTERNAL-001"
        / "provenance.json"
    )
    provenance = json.loads(provenance_path.read_text(encoding="ascii"))
    assert result["copy"]["operation"] == "PUBLISHED_COPY"
    assert result["copy"]["logical_source_id"] == (
        "REF-USER-PDF-UNIT-EXTERNAL-001"
    )
    assert provenance["source"]["logical_id"] == (
        "REF-USER-PDF-UNIT-EXTERNAL-001"
    )


def test_import_pdf_renders_relative_page_assets_idempotently(tmp_path: Path) -> None:
    pdf_path, db_path = _prepare_project(tmp_path)

    first = import_pdf(
        pdf_path=pdf_path,
        pages=(1, 3),
        dpi=72,
        db_path=db_path,
        project_root=tmp_path,
    )
    second = import_pdf(
        pdf_path=pdf_path,
        pages=(1, 3),
        dpi=72,
        db_path=db_path,
        project_root=tmp_path,
    )

    assert first["paper"]["paper_code"] == second["paper"]["paper_code"]
    assert len(first["pages"]) == 2
    assert len(second["pages"]) == 2

    with connect_database(db_path) as conn:
        assert conn.execute("SELECT count(*) FROM source_papers").fetchone()[0] == 1
        assert conn.execute("SELECT count(*) FROM source_paper_assets").fetchone()[0] == 2
        rows = conn.execute(
            """
            SELECT relative_path, page_no
              FROM source_paper_assets
             ORDER BY page_no
            """
        ).fetchall()

    assert [row["page_no"] for row in rows] == [1, 3]
    for row in rows:
        relative_path = row["relative_path"]
        assert ":" not in relative_path
        assert not relative_path.startswith("/")
        assert relative_path.endswith(".png")
        output_path = tmp_path / relative_path
        assert output_path.exists()
        assert output_path.stat().st_size > 0


def test_import_pdf_rejects_out_of_range_pages(tmp_path: Path) -> None:
    pdf_path, db_path = _prepare_project(tmp_path)

    with pytest.raises(PdfImportError, match="Page out of range"):
        import_pdf(
            pdf_path=pdf_path,
            pages=(5,),
            dpi=72,
            db_path=db_path,
            project_root=tmp_path,
        )
