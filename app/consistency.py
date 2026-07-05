from __future__ import annotations

from pathlib import Path
from typing import Any

from .config import PROJECT_ROOT
from .database import connect_database, initialize_database


def _is_relative_database_path(value: str | None) -> bool:
    if not value:
        return True
    return ":" not in value and not value.startswith("/") and not value.startswith("\\")


def check_consistency(
    *,
    db_path: Path | None = None,
    project_root: Path = PROJECT_ROOT,
) -> dict[str, Any]:
    initialize_database(db_path)
    errors: list[dict[str, Any]] = []

    with connect_database(db_path) as conn:
        question_count = conn.execute("SELECT count(*) FROM questions").fetchone()[0]
        search_count = conn.execute(
            "SELECT count(*) FROM question_search_content"
        ).fetchone()[0]
        fts_count = conn.execute("SELECT count(*) FROM question_fts").fetchone()[0]
        if not (question_count == search_count == fts_count):
            errors.append(
                {
                    "check": "fts_counts",
                    "questions": question_count,
                    "question_search_content": search_count,
                    "question_fts": fts_count,
                }
            )

        missing_search_rows = conn.execute(
            """
            SELECT q.id, q.qid
              FROM questions q
              LEFT JOIN question_search_content s ON s.question_id = q.id
             WHERE s.question_id IS NULL
             ORDER BY q.id
            """
        ).fetchall()
        if missing_search_rows:
            errors.append(
                {
                    "check": "missing_search_rows",
                    "rows": [dict(row) for row in missing_search_rows],
                }
            )

        missing_structured_rows = conn.execute(
            """
            SELECT q.id, q.qid
              FROM questions q
              LEFT JOIN question_structured_contents sc ON sc.question_id = q.id
             WHERE sc.question_id IS NULL
             ORDER BY q.id
            """
        ).fetchall()
        if missing_structured_rows:
            errors.append(
                {
                    "check": "missing_structured_content_rows",
                    "rows": [dict(row) for row in missing_structured_rows],
                }
            )

        usability_count = conn.execute(
            "SELECT count(*) FROM question_usability_states"
        ).fetchone()[0]
        if usability_count:
            missing_usability_rows = conn.execute(
                """
                SELECT q.id, q.qid
                  FROM questions q
                  LEFT JOIN question_usability_states us ON us.question_id = q.id
                 WHERE us.question_id IS NULL
                 ORDER BY q.id
                """
            ).fetchall()
            if missing_usability_rows:
                errors.append(
                    {
                        "check": "missing_usability_state_rows",
                        "rows": [dict(row) for row in missing_usability_rows],
                    }
                )

        export_quality_count = conn.execute(
            "SELECT count(*) FROM question_export_quality"
        ).fetchone()[0]
        if export_quality_count:
            missing_export_quality_rows = conn.execute(
                """
                SELECT q.id, q.qid
                  FROM questions q
                  LEFT JOIN question_export_quality eq ON eq.question_id = q.id
                 WHERE eq.question_id IS NULL
                 ORDER BY q.id
                """
            ).fetchall()
            if missing_export_quality_rows:
                errors.append(
                    {
                        "check": "missing_export_quality_rows",
                        "rows": [dict(row) for row in missing_export_quality_rows],
                    }
                )

        source_attribution_count = conn.execute(
            "SELECT count(*) FROM question_source_attributions"
        ).fetchone()[0]
        missing_source_attribution_rows = conn.execute(
            """
            SELECT q.id, q.qid
              FROM questions q
              LEFT JOIN question_source_attributions sa ON sa.question_id = q.id
             WHERE sa.question_id IS NULL
             ORDER BY q.id
            """
        ).fetchall()
        if missing_source_attribution_rows:
            errors.append(
                {
                    "check": "missing_source_attribution_rows",
                    "rows": [dict(row) for row in missing_source_attribution_rows],
                }
            )

        stage14_queue_count = conn.execute(
            "SELECT count(*) FROM stage14_quality_queue"
        ).fetchone()[0]
        if stage14_queue_count:
            missing_stage14_queue_rows = conn.execute(
                """
                SELECT q.id, q.qid
                  FROM questions q
                  LEFT JOIN stage14_quality_queue s14 ON s14.question_id = q.id
                 WHERE s14.question_id IS NULL
                 ORDER BY q.id
                """
            ).fetchall()
            if missing_stage14_queue_rows:
                errors.append(
                    {
                        "check": "missing_stage14_quality_queue_rows",
                        "rows": [dict(row) for row in missing_stage14_queue_rows],
                    }
                )

        relative_checks = {
            "source_papers.source_path": conn.execute(
                "SELECT id, source_path AS path FROM source_papers"
            ).fetchall(),
            "import_batches.backup_path": conn.execute(
                "SELECT id, backup_path AS path FROM import_batches WHERE backup_path IS NOT NULL"
            ).fetchall(),
            "questions.raw_crop_path": conn.execute(
                "SELECT id, raw_crop_path AS path FROM questions WHERE raw_crop_path IS NOT NULL"
            ).fetchall(),
            "question_assets.relative_path": conn.execute(
                "SELECT id, relative_path AS path FROM question_assets"
            ).fetchall(),
            "source_paper_assets.relative_path": conn.execute(
                "SELECT id, relative_path AS path FROM source_paper_assets"
            ).fetchall(),
            "stage14_visual_repair_candidates.candidate_relative_path": conn.execute(
                """
                SELECT id, candidate_relative_path AS path
                  FROM stage14_visual_repair_candidates
                 WHERE candidate_relative_path IS NOT NULL
                """
            ).fetchall(),
        }
        for check_name, rows in relative_checks.items():
            bad_rows = [dict(row) for row in rows if not _is_relative_database_path(row["path"])]
            if bad_rows:
                errors.append({"check": check_name, "rows": bad_rows})

        asset_rows = []
        asset_rows.extend(
            (
                "question_assets",
                row["id"],
                row["relative_path"],
            )
            for row in conn.execute(
                "SELECT id, relative_path FROM question_assets"
            ).fetchall()
        )
        asset_rows.extend(
            (
                "source_paper_assets",
                row["id"],
                row["relative_path"],
            )
            for row in conn.execute(
                "SELECT id, relative_path FROM source_paper_assets"
            ).fetchall()
        )
        asset_rows.extend(
            (
                "stage14_visual_repair_candidates",
                row["id"],
                row["candidate_relative_path"],
            )
            for row in conn.execute(
                """
                SELECT id, candidate_relative_path
                  FROM stage14_visual_repair_candidates
                 WHERE candidate_relative_path IS NOT NULL
                """
            ).fetchall()
        )
        missing_assets = []
        for table, row_id, relative_path in asset_rows:
            path = project_root / relative_path
            if not path.is_file() or path.stat().st_size <= 0:
                missing_assets.append(
                    {"table": table, "id": row_id, "relative_path": relative_path}
                )
        if missing_assets:
            errors.append({"check": "asset_files", "rows": missing_assets})

        duplicate_raw_crops = conn.execute(
            """
            SELECT question_id, count(*) AS count
              FROM question_assets
             WHERE asset_kind = 'raw_crop'
             GROUP BY question_id
            HAVING count(*) > 1
             ORDER BY question_id
            """
        ).fetchall()
        if duplicate_raw_crops:
            errors.append(
                {
                    "check": "duplicate_raw_crop_assets",
                    "rows": [dict(row) for row in duplicate_raw_crops],
                }
            )

        orphan_checks = {
            "question_assets": conn.execute(
                """
                SELECT qa.id
                  FROM question_assets qa
                  LEFT JOIN questions q ON q.id = qa.question_id
                 WHERE q.id IS NULL
                """
            ).fetchall(),
            "source_paper_assets": conn.execute(
                """
                SELECT spa.id
                  FROM source_paper_assets spa
                  LEFT JOIN source_papers sp ON sp.id = spa.source_paper_id
                 WHERE sp.id IS NULL
                """
            ).fetchall(),
            "question_search_content": conn.execute(
                """
                SELECT s.question_id
                  FROM question_search_content s
                  LEFT JOIN questions q ON q.id = s.question_id
                 WHERE q.id IS NULL
                """
            ).fetchall(),
            "question_review_events": conn.execute(
                """
                SELECT e.id
                  FROM question_review_events e
                  LEFT JOIN questions q ON q.id = e.question_id
                 WHERE q.id IS NULL
                """
            ).fetchall(),
            "question_ai_suggestions": conn.execute(
                """
                SELECT s.id
                  FROM question_ai_suggestions s
                  LEFT JOIN questions q ON q.id = s.question_id
                 WHERE q.id IS NULL
                """
            ).fetchall(),
            "question_structured_contents": conn.execute(
                """
                SELECT sc.id
                  FROM question_structured_contents sc
                  LEFT JOIN questions q ON q.id = sc.question_id
                 WHERE q.id IS NULL
                """
            ).fetchall(),
            "question_usability_states": conn.execute(
                """
                SELECT us.id
                  FROM question_usability_states us
                  LEFT JOIN questions q ON q.id = us.question_id
                 WHERE q.id IS NULL
                """
            ).fetchall(),
            "question_export_quality": conn.execute(
                """
                SELECT eq.id
                  FROM question_export_quality eq
                  LEFT JOIN questions q ON q.id = eq.question_id
                 WHERE q.id IS NULL
                """
            ).fetchall(),
            "question_source_attributions": conn.execute(
                """
                SELECT sa.id
                  FROM question_source_attributions sa
                  LEFT JOIN questions q ON q.id = sa.question_id
                 WHERE q.id IS NULL
                """
            ).fetchall(),
            "stage14_quality_queue": conn.execute(
                """
                SELECT s14.id
                  FROM stage14_quality_queue s14
                  LEFT JOIN questions q ON q.id = s14.question_id
                 WHERE q.id IS NULL
                """
            ).fetchall(),
            "stage14_visual_repair_candidates": conn.execute(
                """
                SELECT v14.id
                  FROM stage14_visual_repair_candidates v14
                  LEFT JOIN questions q ON q.id = v14.question_id
                 WHERE q.id IS NULL
                """
            ).fetchall(),
            "stage14_source_audits": conn.execute(
                """
                SELECT a14.id
                  FROM stage14_source_audits a14
                  LEFT JOIN questions q ON q.id = a14.question_id
                 WHERE q.id IS NULL
                """
            ).fetchall(),
            "stage14_page_recut_audits": conn.execute(
                """
                SELECT r14.id
                  FROM stage14_page_recut_audits r14
                  LEFT JOIN source_papers sp ON sp.id = r14.source_paper_id
                 WHERE r14.source_paper_id IS NOT NULL
                   AND sp.id IS NULL
                """
            ).fetchall(),
            "import_batch_pages": conn.execute(
                """
                SELECT p.id
                  FROM import_batch_pages p
                  LEFT JOIN import_batches b ON b.id = p.batch_id
                 WHERE b.id IS NULL
                """
            ).fetchall(),
        }
        for table, rows in orphan_checks.items():
            if rows:
                errors.append({"check": f"orphan_{table}", "rows": [dict(row) for row in rows]})

        status_distribution = {
            row["review_status"]: row["count"]
            for row in conn.execute(
                """
                SELECT review_status, count(*) AS count
                  FROM questions
                 GROUP BY review_status
                 ORDER BY review_status
                """
            ).fetchall()
        }

        counts = {
            "source_papers": conn.execute("SELECT count(*) FROM source_papers").fetchone()[0],
            "source_paper_assets": conn.execute(
                "SELECT count(*) FROM source_paper_assets"
            ).fetchone()[0],
            "questions": question_count,
            "question_assets": conn.execute("SELECT count(*) FROM question_assets").fetchone()[0],
            "question_search_content": search_count,
            "question_fts": fts_count,
            "question_review_events": conn.execute(
                "SELECT count(*) FROM question_review_events"
            ).fetchone()[0],
            "question_ai_suggestions": conn.execute(
                "SELECT count(*) FROM question_ai_suggestions"
            ).fetchone()[0],
            "question_structured_contents": conn.execute(
                "SELECT count(*) FROM question_structured_contents"
            ).fetchone()[0],
            "question_usability_states": usability_count,
            "question_export_quality": export_quality_count,
            "question_source_attributions": source_attribution_count,
            "stage14_quality_queue": stage14_queue_count,
            "stage14_page_recut_audits": conn.execute(
                "SELECT count(*) FROM stage14_page_recut_audits"
            ).fetchone()[0],
            "stage14_visual_repair_candidates": conn.execute(
                "SELECT count(*) FROM stage14_visual_repair_candidates"
            ).fetchone()[0],
            "stage14_source_audits": conn.execute(
                "SELECT count(*) FROM stage14_source_audits"
            ).fetchone()[0],
            "import_batches": conn.execute(
                "SELECT count(*) FROM import_batches"
            ).fetchone()[0],
            "import_batch_pages": conn.execute(
                "SELECT count(*) FROM import_batch_pages"
            ).fetchone()[0],
        }

    return {
        "ok": not errors,
        "counts": counts,
        "status_distribution": status_distribution,
        "errors": errors,
    }
