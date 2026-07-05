from __future__ import annotations

import json
import math
import re
from pathlib import Path
from typing import Any

from .config import PROJECT_ROOT, get_project_paths
from .database import connect_database, initialize_database


class QuestionAssetError(RuntimeError):
    """Raised when question-level asset generation cannot continue."""


SAFE_FILENAME_RE = re.compile(r"[^A-Za-z0-9_.-]+")


def _safe_filename(value: str) -> str:
    return SAFE_FILENAME_RE.sub("_", value).strip("._") or "question"


def _relative_to_project(path: Path, project_root: Path) -> str:
    return path.resolve().relative_to(project_root.resolve()).as_posix()


def _load_crop_rows(conn, question_ids: tuple[int, ...] | None) -> list[dict[str, Any]]:
    filter_sql = ""
    params: list[Any] = []
    if question_ids:
        placeholders = ", ".join("?" for _ in question_ids)
        filter_sql = f"AND q.id IN ({placeholders})"
        params.extend(question_ids)

    rows = conn.execute(
        f"""
        SELECT q.id,
               q.qid,
               q.bbox_json,
               CAST(json_extract(q.meta_json, '$.source_page') AS INTEGER) AS source_page,
               sp.paper_code,
               spa.relative_path AS page_image_path,
               spa.bbox_json AS page_bbox_json,
               spa.meta_json AS page_meta_json
          FROM questions q
          JOIN source_papers sp ON sp.id = q.source_paper_id
          LEFT JOIN source_paper_assets spa
            ON spa.source_paper_id = q.source_paper_id
           AND spa.asset_kind = 'page_image'
           AND spa.page_no = CAST(json_extract(q.meta_json, '$.source_page') AS INTEGER)
         WHERE 1 = 1
           {filter_sql}
         ORDER BY q.id
        """,
        params,
    ).fetchall()
    return [dict(row) for row in rows]


def crop_question_assets(
    *,
    db_path: Path | None = None,
    project_root: Path = PROJECT_ROOT,
    question_ids: tuple[int, ...] | None = None,
    overwrite: bool = False,
    padding_px: int = 8,
) -> dict[str, Any]:
    initialize_database(db_path)
    paths = get_project_paths(project_root)
    paths.question_images_dir.mkdir(parents=True, exist_ok=True)

    generated = 0
    reused = 0
    updated_records = 0
    skipped: list[dict[str, Any]] = []

    import fitz

    with connect_database(db_path or paths.db_path) as conn:
        rows = _load_crop_rows(conn, question_ids)
        for row in rows:
            if not row["page_image_path"]:
                skipped.append({"question_id": row["id"], "reason": "missing_page_image"})
                continue

            page_image_path = (project_root / row["page_image_path"]).resolve()
            try:
                page_image_path.relative_to(paths.assets_dir.resolve())
            except ValueError:
                skipped.append({"question_id": row["id"], "reason": "page_image_outside_assets"})
                continue
            if not page_image_path.exists():
                skipped.append({"question_id": row["id"], "reason": "page_image_missing_file"})
                continue

            try:
                bbox = json.loads(row["bbox_json"] or "{}")
                page_box = json.loads(row["page_bbox_json"] or "{}")
            except json.JSONDecodeError:
                skipped.append({"question_id": row["id"], "reason": "invalid_bbox_json"})
                continue

            page_width = float(page_box.get("page_width") or 0)
            page_height = float(page_box.get("page_height") or 0)
            if page_width <= 0 or page_height <= 0:
                skipped.append({"question_id": row["id"], "reason": "missing_page_dimensions"})
                continue

            with fitz.open(page_image_path) as image_doc:
                image_page = image_doc[0]
                image_width = float(image_page.rect.width)
                image_height = float(image_page.rect.height)
                scale_x = image_width / page_width
                scale_y = image_height / page_height
                x0 = max(0, math.floor(float(bbox["x0"]) * scale_x) - padding_px)
                y0 = max(0, math.floor(float(bbox["y0"]) * scale_y) - padding_px)
                x1 = min(image_width, math.ceil(float(bbox["x1"]) * scale_x) + padding_px)
                y1 = min(image_height, math.ceil(float(bbox["y1"]) * scale_y) + padding_px)
                if x1 <= x0 or y1 <= y0:
                    skipped.append({"question_id": row["id"], "reason": "invalid_crop_rect"})
                    continue

                output_dir = paths.question_images_dir / row["paper_code"]
                output_dir.mkdir(parents=True, exist_ok=True)
                output_path = output_dir / f"{_safe_filename(row['qid'])}.png"
                if overwrite or not output_path.exists():
                    pixmap = image_page.get_pixmap(clip=fitz.Rect(x0, y0, x1, y1))
                    pixmap.save(output_path)
                    generated += 1
                else:
                    reused += 1

            relative_output = _relative_to_project(output_path, project_root)
            crop_bbox_json = json.dumps(
                {
                    "page": row["source_page"],
                    "x0": x0,
                    "y0": y0,
                    "x1": x1,
                    "y1": y1,
                },
                ensure_ascii=False,
            )
            meta_json = json.dumps(
                {
                    "source_page_image": row["page_image_path"],
                    "crop_algorithm": "stage7_bbox_page_png_v1",
                    "padding_px": padding_px,
                },
                ensure_ascii=False,
            )
            existing = conn.execute(
                """
                SELECT id
                  FROM question_assets
                 WHERE question_id = ?
                   AND asset_kind = 'raw_crop'
                 ORDER BY id DESC
                 LIMIT 1
                """,
                (row["id"],),
            ).fetchone()
            if existing is None:
                conn.execute(
                    """
                    INSERT INTO question_assets (
                        question_id,
                        asset_kind,
                        relative_path,
                        page_no,
                        bbox_json,
                        meta_json
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        row["id"],
                        "raw_crop",
                        relative_output,
                        row["source_page"],
                        crop_bbox_json,
                        meta_json,
                    ),
                )
            else:
                conn.execute(
                    """
                    UPDATE question_assets
                       SET relative_path = ?,
                           page_no = ?,
                           bbox_json = ?,
                           meta_json = ?
                     WHERE id = ?
                    """,
                    (
                        relative_output,
                        row["source_page"],
                        crop_bbox_json,
                        meta_json,
                        existing["id"],
                    ),
                )
            updated_records += 1

        conn.commit()
        asset_count = conn.execute(
            "SELECT count(*) FROM question_assets WHERE asset_kind = 'raw_crop'"
        ).fetchone()[0]

    return {
        "questions_considered": len(rows),
        "generated_files": generated,
        "reused_files": reused,
        "updated_records": updated_records,
        "raw_crop_assets": asset_count,
        "skipped": skipped,
    }

