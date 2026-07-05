from __future__ import annotations

from pathlib import Path
from typing import Any

from .database import connect_database, initialize_database


def rebuild_search_index(*, db_path: Path | None = None) -> dict[str, Any]:
    initialize_database(db_path)

    with connect_database(db_path) as conn:
        question_count = conn.execute("SELECT count(*) FROM questions").fetchone()[0]

        conn.execute("DELETE FROM question_search_content")
        conn.execute(
            """
            INSERT INTO question_search_content (
                question_id,
                qid,
                year_text,
                paper_name,
                question_type,
                tags_text,
                stem_text,
                answer_text,
                analysis_text
            )
            SELECT id,
                   qid,
                   COALESCE(CAST(year AS TEXT), ''),
                   COALESCE(paper_name, ''),
                   COALESCE(question_type, ''),
                   COALESCE(tags_json, '[]'),
                   COALESCE(stem_text, ''),
                   COALESCE(answer_text, ''),
                   COALESCE(analysis_latex, '')
              FROM questions
             ORDER BY id
            """
        )
        conn.execute("INSERT INTO question_fts(question_fts) VALUES ('rebuild')")
        conn.commit()

        search_content_count = conn.execute(
            "SELECT count(*) FROM question_search_content"
        ).fetchone()[0]
        fts_count = conn.execute("SELECT count(*) FROM question_fts").fetchone()[0]

    return {
        "questions": question_count,
        "question_search_content": search_content_count,
        "question_fts": fts_count,
        "synced": question_count == search_content_count == fts_count,
    }

