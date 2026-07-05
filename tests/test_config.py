from pathlib import Path

import pytest

from app.config import (
    BASE_DIR,
    DATA_DIR,
    PROJECT_ROOT,
    TARGET_PDF_ENV,
    ConfigurationError,
    find_unique_target_pdf,
    get_project_paths,
    list_base_pdfs,
    resolve_target_pdf,
)


def test_project_paths_resolve_expected_directories() -> None:
    expected_root = Path(__file__).resolve().parents[1]

    assert PROJECT_ROOT == expected_root
    assert BASE_DIR == PROJECT_ROOT / "Base"
    assert DATA_DIR == PROJECT_ROOT / "data"

    paths = get_project_paths(require_target_pdf=False)
    assert paths.project_root == PROJECT_ROOT
    assert paths.base_dir == BASE_DIR
    assert paths.data_dir == DATA_DIR
    assert paths.db_dir == DATA_DIR / "db"
    assert paths.db_path == paths.db_dir / "question_bank.sqlite3"
    assert paths.db_backups_dir == paths.db_dir / "backups"
    assert paths.assets_dir == DATA_DIR / "assets"
    assert paths.question_images_dir == paths.assets_dir / "question_images"
    assert paths.paper_pages_dir == paths.assets_dir / "paper_pages"
    assert paths.exports_dir == DATA_DIR / "exports"
    assert paths.target_pdf is None


def test_base_pdf_discovery_finds_single_pdf(tmp_path: Path) -> None:
    (tmp_path / "sample.pdf").touch()
    (tmp_path / "notes.txt").touch()
    pdfs = list_base_pdfs(tmp_path)

    assert len(pdfs) == 1
    assert find_unique_target_pdf(tmp_path) == pdfs[0]


def test_find_unique_target_pdf_rejects_missing_pdf(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="Expected exactly one PDF"):
        find_unique_target_pdf(tmp_path)


def test_find_unique_target_pdf_rejects_multiple_pdfs(tmp_path: Path) -> None:
    (tmp_path / "a.pdf").touch()
    (tmp_path / "b.PDF").touch()

    with pytest.raises(ConfigurationError, match="found 2"):
        find_unique_target_pdf(tmp_path)


def test_find_unique_target_pdf_accepts_explicit_relative_target(tmp_path: Path) -> None:
    first = tmp_path / "a.pdf"
    second = tmp_path / "b.pdf"
    first.touch()
    second.touch()

    assert find_unique_target_pdf(tmp_path, target_pdf="b.pdf") == second.resolve()


def test_resolve_target_pdf_rejects_non_pdf(tmp_path: Path) -> None:
    target = tmp_path / "sample.txt"
    target.touch()

    with pytest.raises(ConfigurationError, match="Expected a PDF"):
        resolve_target_pdf(tmp_path, target)


def test_get_project_paths_uses_env_target_pdf(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project_root = tmp_path / "project"
    base_dir = project_root / "Base"
    base_dir.mkdir(parents=True)
    first = base_dir / "a.pdf"
    second = base_dir / "b.pdf"
    first.touch()
    second.touch()
    monkeypatch.setenv(TARGET_PDF_ENV, "b.pdf")

    paths = get_project_paths(project_root)

    assert paths.target_pdf == second.resolve()
