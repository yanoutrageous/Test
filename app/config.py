from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


class ConfigurationError(RuntimeError):
    """Raised when required local project paths cannot be resolved."""


PROJECT_ROOT = Path(__file__).resolve().parents[1]
BASE_DIR = PROJECT_ROOT / "Base"
DATA_DIR = PROJECT_ROOT / "data"
TARGET_PDF_ENV = "EXAM_BANK_TARGET_PDF"


@dataclass(frozen=True)
class ProjectPaths:
    project_root: Path
    base_dir: Path
    data_dir: Path
    db_dir: Path
    db_path: Path
    db_backups_dir: Path
    assets_dir: Path
    question_images_dir: Path
    paper_pages_dir: Path
    exports_dir: Path
    target_pdf: Path | None


def list_base_pdfs(base_dir: Path = BASE_DIR) -> tuple[Path, ...]:
    if not base_dir.exists():
        return ()

    return tuple(
        sorted(
            path
            for path in base_dir.iterdir()
            if path.is_file() and path.suffix.lower() == ".pdf"
        )
    )


def resolve_target_pdf(base_dir: Path, target_pdf: str | Path) -> Path:
    candidate = Path(target_pdf).expanduser()
    if not candidate.is_absolute():
        candidate = base_dir / candidate

    resolved = candidate.resolve()
    if resolved.suffix.lower() != ".pdf":
        raise ConfigurationError(f"Expected a PDF file for target PDF: {candidate}")
    if not resolved.exists():
        raise ConfigurationError(f"Target PDF not found: {candidate}")
    if not resolved.is_file():
        raise ConfigurationError(f"Target PDF is not a file: {candidate}")

    return resolved


def find_unique_target_pdf(
    base_dir: Path = BASE_DIR,
    *,
    target_pdf: str | Path | None = None,
) -> Path:
    if target_pdf is not None:
        return resolve_target_pdf(base_dir, target_pdf)

    pdfs = list_base_pdfs(base_dir)

    if len(pdfs) != 1:
        names = ", ".join(path.name for path in pdfs) or "none"
        raise ConfigurationError(
            f"Expected exactly one PDF in {base_dir}, found {len(pdfs)}: {names}"
        )

    return pdfs[0].resolve()


def get_project_paths(
    project_root: Path = PROJECT_ROOT,
    *,
    require_target_pdf: bool = True,
    target_pdf: str | Path | None = None,
) -> ProjectPaths:
    base_dir = project_root / "Base"
    data_dir = project_root / "data"
    db_dir = data_dir / "db"
    assets_dir = data_dir / "assets"
    exports_dir = data_dir / "exports"
    configured_target_pdf = (
        target_pdf if target_pdf is not None else os.environ.get(TARGET_PDF_ENV)
    )
    return ProjectPaths(
        project_root=project_root,
        base_dir=base_dir,
        data_dir=data_dir,
        db_dir=db_dir,
        db_path=db_dir / "question_bank.sqlite3",
        db_backups_dir=db_dir / "backups",
        assets_dir=assets_dir,
        question_images_dir=assets_dir / "question_images",
        paper_pages_dir=assets_dir / "paper_pages",
        exports_dir=exports_dir,
        target_pdf=(
            find_unique_target_pdf(base_dir, target_pdf=configured_target_pdf)
            if require_target_pdf
            else None
        ),
    )


def ensure_storage_directories(
    paths: ProjectPaths | None = None,
    *,
    require_target_pdf: bool = False,
    target_pdf: str | Path | None = None,
) -> ProjectPaths:
    resolved = paths or get_project_paths(
        require_target_pdf=require_target_pdf,
        target_pdf=target_pdf,
    )
    for directory in (
        resolved.data_dir,
        resolved.db_dir,
        resolved.db_backups_dir,
        resolved.assets_dir,
        resolved.question_images_dir,
        resolved.paper_pages_dir,
        resolved.exports_dir,
    ):
        directory.mkdir(parents=True, exist_ok=True)

    return resolved
