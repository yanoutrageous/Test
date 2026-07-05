from __future__ import annotations

import json
import re
import shutil
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from .config import PROJECT_ROOT, get_project_paths
from .database import connect_database, initialize_database
from .page_ranges import PageRangeError, format_page_spec, parse_page_numbers
from .pdf_import import DEFAULT_RENDER_DPI, import_pdf, relative_path
from .pdf_scan import scan_pdf_pages
from .question_assets import crop_question_assets
from .question_split import ALGORITHM_VERSION, split_questions


class ImportBatchError(RuntimeError):
    """Raised when a staged import batch cannot continue."""


SAFE_CODE_RE = re.compile(r"[^A-Za-z0-9_.-]+")


def _safe_code(value: str) -> str:
    cleaned = SAFE_CODE_RE.sub("-", value.strip()).strip(".-").upper()
    return cleaned or "BATCH"


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False)


def _now_label() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def parse_batch_pages(value: str | None) -> tuple[int, ...]:
    try:
        return parse_page_numbers(value)
    except PageRangeError as exc:
        raise ImportBatchError(str(exc)) from exc


def _batch_code(name: str) -> str:
    return f"BATCH-{_safe_code(name)}"


def _load_batch(
    conn,
    *,
    batch_id: int | None = None,
    name: str | None = None,
) -> dict[str, Any] | None:
    if batch_id is not None:
        row = conn.execute(
            "SELECT * FROM import_batches WHERE id = ?",
            (batch_id,),
        ).fetchone()
    elif name is not None:
        row = conn.execute(
            "SELECT * FROM import_batches WHERE name = ?",
            (name,),
        ).fetchone()
    else:
        row = None
    return dict(row) if row is not None else None


def _load_source_paper_id(conn, project_root: Path) -> int | None:
    paths = get_project_paths(project_root)
    source_path = relative_path(paths.target_pdf, project_root)
    row = conn.execute(
        "SELECT id FROM source_papers WHERE source_path = ? ORDER BY id LIMIT 1",
        (source_path,),
    ).fetchone()
    return int(row["id"]) if row is not None else None


def create_import_batch(
    *,
    name: str,
    pages: tuple[int, ...],
    db_path: Path | None = None,
    project_root: Path = PROJECT_ROOT,
    batch_kind: str = "expansion",
    status: str = "planned",
    algorithm_version: str = ALGORITHM_VERSION,
    notes: str | None = None,
) -> dict[str, Any]:
    if batch_kind not in ("baseline", "expansion"):
        raise ImportBatchError(f"Unsupported batch_kind: {batch_kind}")
    if status not in ("planned", "running", "done", "failed"):
        raise ImportBatchError(f"Unsupported batch status: {status}")
    if not pages:
        raise ImportBatchError("Batch pages cannot be empty.")

    initialize_database(db_path)
    page_spec = format_page_spec(pages)
    with connect_database(db_path) as conn:
        source_paper_id = _load_source_paper_id(conn, project_root)
        conn.execute(
            """
            INSERT INTO import_batches (
                batch_code,
                name,
                batch_kind,
                source_paper_id,
                page_spec,
                page_count,
                algorithm_version,
                status,
                notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(name) DO UPDATE SET
                batch_kind = excluded.batch_kind,
                source_paper_id = COALESCE(excluded.source_paper_id, import_batches.source_paper_id),
                page_spec = excluded.page_spec,
                page_count = excluded.page_count,
                algorithm_version = excluded.algorithm_version,
                status = excluded.status,
                notes = excluded.notes,
                updated_at = CURRENT_TIMESTAMP
            """,
            (
                _batch_code(name),
                name,
                batch_kind,
                source_paper_id,
                page_spec,
                len(pages),
                algorithm_version,
                status,
                notes,
            ),
        )
        batch = _load_batch(conn, name=name)
        assert batch is not None
        for page_no in pages:
            conn.execute(
                """
                INSERT INTO import_batch_pages (
                    batch_id,
                    source_paper_id,
                    page_no,
                    status
                ) VALUES (?, ?, ?, ?)
                ON CONFLICT(batch_id, page_no) DO UPDATE SET
                    source_paper_id = COALESCE(excluded.source_paper_id, import_batch_pages.source_paper_id),
                    status = excluded.status,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (batch["id"], source_paper_id, page_no, "planned"),
            )
        conn.commit()
        return get_import_batch(batch_id=int(batch["id"]), db_path=db_path)


def list_import_batches(*, db_path: Path | None = None) -> list[dict[str, Any]]:
    initialize_database(db_path)
    with connect_database(db_path) as conn:
        rows = conn.execute(
            """
            SELECT b.*,
                   count(p.id) AS page_rows,
                   sum(CASE WHEN p.status = 'failed' THEN 1 ELSE 0 END) AS failed_pages,
                   sum(CASE WHEN p.warning_candidates > 0 OR p.duplicate_anchor_count > 0 THEN 1 ELSE 0 END) AS warning_pages
              FROM import_batches b
              LEFT JOIN import_batch_pages p ON p.batch_id = b.id
             GROUP BY b.id
             ORDER BY b.id
            """
        ).fetchall()
    return [dict(row) for row in rows]


def get_import_batch(
    *,
    batch_id: int | None = None,
    name: str | None = None,
    db_path: Path | None = None,
) -> dict[str, Any]:
    initialize_database(db_path)
    with connect_database(db_path) as conn:
        batch = _load_batch(conn, batch_id=batch_id, name=name)
        if batch is None:
            raise ImportBatchError("Import batch not found.")
        pages = conn.execute(
            """
            SELECT *
              FROM import_batch_pages
             WHERE batch_id = ?
             ORDER BY page_no
            """,
            (batch["id"],),
        ).fetchall()
    batch["pages"] = [dict(row) for row in pages]
    return batch


def _copy_database_backup(
    *,
    db_path: Path,
    project_root: Path,
    batch_code: str,
) -> str:
    paths = get_project_paths(project_root)
    paths.db_backups_dir.mkdir(parents=True, exist_ok=True)
    output_path = paths.db_backups_dir / f"before-{_safe_code(batch_code).lower()}-{_now_label()}.sqlite3"
    shutil.copy2(db_path, output_path)
    return output_path.resolve().relative_to(project_root.resolve()).as_posix()


def _question_count_for_page(conn, *, source_paper_id: int | None, page_no: int) -> int:
    params: list[Any] = [page_no]
    source_sql = ""
    if source_paper_id is not None:
        source_sql = "AND source_paper_id = ?"
        params.append(source_paper_id)
    return int(
        conn.execute(
            f"""
            SELECT count(*)
              FROM questions
             WHERE CAST(json_extract(meta_json, '$.source_page') AS INTEGER) = ?
               {source_sql}
            """,
            params,
        ).fetchone()[0]
    )


def _question_ids_for_pages(
    conn,
    *,
    source_paper_id: int | None,
    pages: tuple[int, ...],
) -> tuple[int, ...]:
    if not pages:
        return ()
    placeholders = ", ".join("?" for _ in pages)
    params: list[Any] = list(pages)
    source_sql = ""
    if source_paper_id is not None:
        source_sql = "AND source_paper_id = ?"
        params.append(source_paper_id)
    rows = conn.execute(
        f"""
        SELECT id
          FROM questions
         WHERE CAST(json_extract(meta_json, '$.source_page') AS INTEGER) IN ({placeholders})
           {source_sql}
         ORDER BY id
        """,
        params,
    ).fetchall()
    return tuple(int(row["id"]) for row in rows)


def _raw_crop_count_for_page(conn, *, source_paper_id: int | None, page_no: int) -> int:
    params: list[Any] = [page_no]
    source_sql = ""
    if source_paper_id is not None:
        source_sql = "AND q.source_paper_id = ?"
        params.append(source_paper_id)
    return int(
        conn.execute(
            f"""
            SELECT count(*)
              FROM question_assets qa
              JOIN questions q ON q.id = qa.question_id
             WHERE qa.asset_kind = 'raw_crop'
               AND CAST(json_extract(q.meta_json, '$.source_page') AS INTEGER) = ?
               {source_sql}
            """,
            params,
        ).fetchone()[0]
    )


def _update_batch_status(
    conn,
    *,
    batch_id: int,
    status: str,
    error: dict[str, Any] | None = None,
    started: bool = False,
    completed: bool = False,
    duration_ms: int | None = None,
) -> None:
    conn.execute(
        """
        UPDATE import_batches
           SET status = ?,
               error_json = ?,
               started_at = CASE WHEN ? THEN CURRENT_TIMESTAMP ELSE started_at END,
               completed_at = CASE WHEN ? THEN CURRENT_TIMESTAMP ELSE completed_at END,
               duration_ms = COALESCE(?, duration_ms),
               updated_at = CURRENT_TIMESTAMP
         WHERE id = ?
        """,
        (
            status,
            _json(error or {}),
            1 if started else 0,
            1 if completed else 0,
            duration_ms,
            batch_id,
        ),
    )


def _record_scan_pages(
    conn,
    *,
    batch_id: int,
    source_paper_id: int | None,
    scan_pages: list[dict[str, Any]],
) -> None:
    for page in scan_pages:
        conn.execute(
            """
            UPDATE import_batch_pages
               SET source_paper_id = COALESCE(?, source_paper_id),
                   text_length = ?,
                   block_count = ?,
                   anchor_count = ?,
                   duplicate_anchor_count = ?,
                   candidate_count = ?,
                   warning_candidates = ?,
                   page_flags_json = ?,
                   warning_reasons_json = ?,
                   scan_json = ?,
                   status = 'done',
                   updated_at = CURRENT_TIMESTAMP
             WHERE batch_id = ?
               AND page_no = ?
            """,
            (
                source_paper_id,
                page["text_length"],
                page["block_count"],
                page["anchor_count"],
                page["duplicate_anchor_count"],
                page["candidate_count"],
                page["warning_candidates"],
                _json(page["page_flags"]),
                _json(page["warning_reasons"]),
                _json(page),
                batch_id,
                page["page_no"],
            ),
        )


def _record_import_pages(
    conn,
    *,
    batch_id: int,
    source_paper_id: int,
    import_pages: list[dict[str, Any]],
) -> None:
    for page in import_pages:
        conn.execute(
            """
            UPDATE import_batch_pages
               SET source_paper_id = ?,
                   import_json = ?,
                   updated_at = CURRENT_TIMESTAMP
             WHERE batch_id = ?
               AND page_no = ?
            """,
            (source_paper_id, _json(page), batch_id, page["page_no"]),
        )


def _record_split_pages(
    conn,
    *,
    batch_id: int,
    source_paper_id: int | None,
    split_pages: list[dict[str, Any]],
) -> None:
    for page in split_pages:
        write = page.get("write", {})
        db_question_count = _question_count_for_page(
            conn,
            source_paper_id=source_paper_id,
            page_no=page["page_no"],
        )
        conn.execute(
            """
            UPDATE import_batch_pages
               SET candidate_count = ?,
                   warning_candidates = ?,
                   skipped_reviewed = ?,
                   db_question_count = ?,
                   split_json = ?,
                   updated_at = CURRENT_TIMESTAMP
             WHERE batch_id = ?
               AND page_no = ?
            """,
            (
                page["candidate_count"],
                page["warning_candidates"],
                int(write.get("skipped_reviewed", 0)),
                db_question_count,
                _json(page),
                batch_id,
                page["page_no"],
            ),
        )


def _record_crop_pages(
    conn,
    *,
    batch_id: int,
    source_paper_id: int | None,
    pages: tuple[int, ...],
) -> None:
    for page_no in pages:
        raw_crop_count = _raw_crop_count_for_page(
            conn,
            source_paper_id=source_paper_id,
            page_no=page_no,
        )
        conn.execute(
            """
            UPDATE import_batch_pages
               SET crop_json = ?,
                   updated_at = CURRENT_TIMESTAMP
             WHERE batch_id = ?
               AND page_no = ?
            """,
            (_json({"raw_crop_count": raw_crop_count}), batch_id, page_no),
        )


def register_baseline_batch(
    *,
    name: str = "stage8-baseline-1090-1099",
    pages: tuple[int, ...],
    db_path: Path | None = None,
    project_root: Path = PROJECT_ROOT,
) -> dict[str, Any]:
    batch = create_import_batch(
        name=name,
        pages=pages,
        db_path=db_path,
        project_root=project_root,
        batch_kind="baseline",
        status="planned",
        notes="Stage 8 baseline registered from already imported stage 7 sample pages.",
    )
    scan = scan_pdf_pages(pages=pages, project_root=project_root)

    with connect_database(db_path) as conn:
        source_paper_id = _load_source_paper_id(conn, project_root)
        _update_batch_status(conn, batch_id=int(batch["id"]), status="running", started=True)
        _record_scan_pages(
            conn,
            batch_id=int(batch["id"]),
            source_paper_id=source_paper_id,
            scan_pages=scan["pages"],
        )
        for page_no in pages:
            db_question_count = _question_count_for_page(
                conn,
                source_paper_id=source_paper_id,
                page_no=page_no,
            )
            raw_crop_count = _raw_crop_count_for_page(
                conn,
                source_paper_id=source_paper_id,
                page_no=page_no,
            )
            conn.execute(
                """
                UPDATE import_batch_pages
                   SET db_question_count = ?,
                       crop_json = ?,
                       updated_at = CURRENT_TIMESTAMP
                 WHERE batch_id = ?
                   AND page_no = ?
                """,
                (
                    db_question_count,
                    _json({"raw_crop_count": raw_crop_count}),
                    batch["id"],
                    page_no,
                ),
            )
        conn.execute(
            """
            UPDATE import_batches
               SET source_paper_id = COALESCE(?, source_paper_id),
                   status = 'done',
                   scan_summary_json = ?,
                   completed_at = CURRENT_TIMESTAMP,
                   updated_at = CURRENT_TIMESTAMP
             WHERE id = ?
            """,
            (source_paper_id, _json(scan["summary"]), batch["id"]),
        )
        conn.commit()

    return get_import_batch(batch_id=int(batch["id"]), db_path=db_path)


def run_import_batch(
    *,
    name: str,
    pages: tuple[int, ...],
    db_path: Path | None = None,
    project_root: Path = PROJECT_ROOT,
    dpi: int = DEFAULT_RENDER_DPI,
    create_backup: bool = True,
) -> dict[str, Any]:
    paths = get_project_paths(project_root)
    resolved_db_path = db_path or paths.db_path
    batch = create_import_batch(
        name=name,
        pages=pages,
        db_path=resolved_db_path,
        project_root=project_root,
        batch_kind="expansion",
        status="planned",
    )
    batch_id = int(batch["id"])
    started_at = time.perf_counter()
    backup_path: str | None = None

    try:
        if create_backup:
            backup_path = _copy_database_backup(
                db_path=resolved_db_path,
                project_root=project_root,
                batch_code=batch["batch_code"],
            )

        with connect_database(resolved_db_path) as conn:
            _update_batch_status(conn, batch_id=batch_id, status="running", started=True)
            if backup_path:
                conn.execute(
                    """
                    UPDATE import_batches
                       SET backup_path = ?,
                           updated_at = CURRENT_TIMESTAMP
                     WHERE id = ?
                    """,
                    (backup_path, batch_id),
                )
            conn.commit()

        scan = scan_pdf_pages(pages=pages, project_root=project_root)
        with connect_database(resolved_db_path) as conn:
            source_paper_id = _load_source_paper_id(conn, project_root)
            _record_scan_pages(
                conn,
                batch_id=batch_id,
                source_paper_id=source_paper_id,
                scan_pages=scan["pages"],
            )
            conn.execute(
                """
                UPDATE import_batches
                   SET scan_summary_json = ?,
                       updated_at = CURRENT_TIMESTAMP
                 WHERE id = ?
                """,
                (_json(scan["summary"]), batch_id),
            )
            conn.commit()

        imported = import_pdf(
            pages=pages,
            dpi=dpi,
            db_path=resolved_db_path,
            project_root=project_root,
        )
        source_paper_id = int(imported["paper"]["id"])
        with connect_database(resolved_db_path) as conn:
            _record_import_pages(
                conn,
                batch_id=batch_id,
                source_paper_id=source_paper_id,
                import_pages=imported["pages"],
            )
            conn.execute(
                """
                UPDATE import_batches
                   SET source_paper_id = ?,
                       import_summary_json = ?,
                       updated_at = CURRENT_TIMESTAMP
                 WHERE id = ?
                """,
                (
                    source_paper_id,
                    _json(
                        {
                            "page_count": len(imported["pages"]),
                            "paper": imported["paper"],
                        }
                    ),
                    batch_id,
                ),
            )
            conn.commit()

        split = split_questions(
            pages=pages,
            db_path=resolved_db_path,
            project_root=project_root,
        )
        with connect_database(resolved_db_path) as conn:
            _record_split_pages(
                conn,
                batch_id=batch_id,
                source_paper_id=source_paper_id,
                split_pages=split["pages"],
            )
            question_ids = _question_ids_for_pages(
                conn,
                source_paper_id=source_paper_id,
                pages=pages,
            )
            conn.execute(
                """
                UPDATE import_batches
                   SET split_summary_json = ?,
                       updated_at = CURRENT_TIMESTAMP
                 WHERE id = ?
                """,
                (
                    _json(
                        {
                            "page_count": len(split["pages"]),
                            "write": split["write"],
                        }
                    ),
                    batch_id,
                ),
            )
            conn.commit()

        crop = crop_question_assets(
            db_path=resolved_db_path,
            project_root=project_root,
            question_ids=question_ids,
        )
        duration_ms = int((time.perf_counter() - started_at) * 1000)
        with connect_database(resolved_db_path) as conn:
            _record_crop_pages(
                conn,
                batch_id=batch_id,
                source_paper_id=source_paper_id,
                pages=pages,
            )
            conn.execute(
                """
                UPDATE import_batches
                   SET crop_summary_json = ?,
                       status = 'done',
                       completed_at = CURRENT_TIMESTAMP,
                       duration_ms = ?,
                       error_json = '{}',
                       updated_at = CURRENT_TIMESTAMP
                 WHERE id = ?
                """,
                (_json(crop), duration_ms, batch_id),
            )
            conn.commit()
    except Exception as exc:
        duration_ms = int((time.perf_counter() - started_at) * 1000)
        with connect_database(resolved_db_path) as conn:
            _update_batch_status(
                conn,
                batch_id=batch_id,
                status="failed",
                error={"type": type(exc).__name__, "message": str(exc)},
                completed=True,
                duration_ms=duration_ms,
            )
            conn.execute(
                """
                UPDATE import_batch_pages
                   SET status = CASE WHEN status = 'planned' THEN 'failed' ELSE status END,
                       error_json = CASE WHEN status = 'planned' THEN ? ELSE error_json END,
                       updated_at = CURRENT_TIMESTAMP
                 WHERE batch_id = ?
                """,
                (_json({"type": type(exc).__name__, "message": str(exc)}), batch_id),
            )
            conn.commit()
        raise ImportBatchError(str(exc)) from exc

    return get_import_batch(batch_id=batch_id, db_path=resolved_db_path)
