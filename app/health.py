from __future__ import annotations

from importlib import metadata
import sqlite3
from pathlib import Path
from typing import Any

from .config import PROJECT_ROOT, ConfigurationError, get_project_paths, list_base_pdfs


def check_dependency(module_name: str, distribution_name: str | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"module": module_name, "ok": False}
    distribution = distribution_name or module_name

    try:
        if module_name == "flask":
            import flask  # noqa: F401
        elif module_name == "fitz":
            import fitz  # noqa: F401
        else:
            raise ValueError("dependency is not in the local health allowlist")
        result["ok"] = True
    except Exception as exc:  # pragma: no cover - exercised only in broken envs
        result["error"] = f"{type(exc).__name__}: {exc}"

    try:
        result["version"] = metadata.version(distribution)
    except metadata.PackageNotFoundError:
        result["version"] = None

    return result


def check_sqlite() -> dict[str, Any]:
    result: dict[str, Any] = {
        "ok": False,
        "module": "sqlite3",
        "sqlite_version": sqlite3.sqlite_version,
        "connect": False,
        "fts5": False,
        "json": False,
        "errors": [],
    }

    try:
        with sqlite3.connect(":memory:") as conn:
            result["connect"] = True

            conn.execute("CREATE VIRTUAL TABLE fts_test USING fts5(content)")
            conn.execute("INSERT INTO fts_test(content) VALUES (?)", ("alpha beta",))
            fts_count = conn.execute(
                "SELECT count(*) FROM fts_test WHERE fts_test MATCH ?",
                ("alpha",),
            ).fetchone()[0]
            result["fts5"] = fts_count == 1

            json_value = conn.execute(
                "SELECT json_extract('{\"a\":1}', '$.a')"
            ).fetchone()[0]
            result["json"] = json_value == 1
    except Exception as exc:  # pragma: no cover - exercised only in broken envs
        result["errors"].append(f"{type(exc).__name__}: {exc}")

    result["ok"] = result["connect"] and result["fts5"] and result["json"]
    return result


def get_pdf_info(pdf_path: Path) -> dict[str, Any]:
    info: dict[str, Any] = {
        "exists": pdf_path.exists(),
        "name": pdf_path.name,
        "path": str(pdf_path),
        "size_bytes": pdf_path.stat().st_size if pdf_path.exists() else None,
        "page_count": None,
        "encrypted": None,
        "readable": False,
    }

    try:
        import fitz

        with fitz.open(pdf_path) as doc:
            info["page_count"] = doc.page_count
            info["encrypted"] = doc.is_encrypted
            info["readable"] = True
    except Exception as exc:  # pragma: no cover - exercised only in broken envs
        info["error"] = f"{type(exc).__name__}: {exc}"

    return info


def build_health_report(project_root: Path = PROJECT_ROOT) -> dict[str, Any]:
    dependencies = {
        "flask": check_dependency("flask", "Flask"),
        "pymupdf": check_dependency("fitz", "PyMuPDF"),
        "sqlite3": {
            "module": "sqlite3",
            "ok": True,
            "version": sqlite3.sqlite_version,
        },
    }
    sqlite_info = check_sqlite()
    errors: list[str] = []
    warnings: list[str] = []

    try:
        paths = get_project_paths(project_root, require_target_pdf=False)
        project_info: dict[str, Any] = {
            "project_root": str(paths.project_root),
            "base_dir": str(paths.base_dir),
            "data_dir": str(paths.data_dir),
            "db_path": str(paths.db_path),
            "assets_dir": str(paths.assets_dir),
            "question_images_dir": str(paths.question_images_dir),
            "paper_pages_dir": str(paths.paper_pages_dir),
        }
    except ConfigurationError as exc:
        project_info = {}
        errors.append(str(exc))

    try:
        target_paths = get_project_paths(project_root, require_target_pdf=True)
        target_pdf = get_pdf_info(target_paths.target_pdf)
        target_pdf["resolved"] = True
    except ConfigurationError as exc:
        base_dir = project_root / "Base"
        target_pdf = {"exists": False, "readable": False}
        target_pdf["resolved"] = False
        target_pdf["error"] = str(exc)
        target_pdf["candidates"] = [path.name for path in list_base_pdfs(base_dir)]
        target_pdf["required_for"] = [
            "import-pdf",
            "scan-pdf-pages",
            "split-questions",
            "batch-run",
        ]
        warnings.append(str(exc))

    dependency_ok = all(item.get("ok") for item in dependencies.values())
    ok = dependency_ok and sqlite_info["ok"] and not errors

    return {
        "status": "ok" if ok else "error",
        "project": project_info,
        "dependencies": dependencies,
        "sqlite": sqlite_info,
        "target_pdf": target_pdf,
        "errors": errors,
        "warnings": warnings,
    }
