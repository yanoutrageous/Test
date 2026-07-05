from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from .ai_suggestions import AiSuggestionError, generate_ai_suggestions
from .consistency import check_consistency
from .codex_structure import (
    CodexStructureError,
    apply_codex_structure_jsonl,
    export_codex_structure_batch,
    run_codex_structure_batch,
)
from .config import PROJECT_ROOT
from .database import initialize_database
from .export_quality import (
    classify_export_quality_states,
    summarize_export_quality,
    write_stage12_export_quality_report,
)
from .export_selection import save_stage11_export_sample, save_stage12_export_sample
from .health import build_health_report
from .import_batches import (
    ImportBatchError,
    create_import_batch,
    get_import_batch,
    list_import_batches,
    parse_batch_pages,
    register_baseline_batch,
    run_import_batch,
)
from .page_ranges import PageRangeError, parse_page_numbers
from .pdf_import import PdfImportError, import_pdf, parse_pages
from .pdf_scan import scan_pdf_pages
from .question_assets import QuestionAssetError, crop_question_assets
from .question_split import QuestionSplitError, parse_split_pages, split_questions
from .search_index import rebuild_search_index
from .stage8_report import write_stage8_quality_report
from .stage9_report import write_stage9_quality_report
from .stage10 import (
    Stage10Error,
    register_stage10_baseline,
    run_stage10_structure_batch,
    save_stage10_export_sample,
    write_stage10_quality_report,
)
from .stage11 import (
    classify_usability_states,
    summarize_usability_states,
    write_stage11_quality_report,
)
from .stage14 import (
    classify_stage14_quality_queue,
    generate_stage14_visual_repair_candidates,
    save_stage14_export_sample,
    summarize_stage14_quality,
    write_stage14_quality_report,
)
from .source_attribution import (
    rebuild_source_attributions,
    summarize_source_attributions,
    write_stage13_source_attribution_report,
)
from .structured_ai import (
    StructuredAiError,
    get_structured_ai_provider_status,
    run_structured_ai_corrections,
)
from .structured_content import (
    initialize_structured_contents,
    summarize_structured_contents,
)
from .structured_validation import (
    StructuredValidationError,
    validate_structured_contents,
)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli")
    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser("health", help="Run local environment and project health checks.")
    init_db_parser = subparsers.add_parser("init-db", help="Initialize the local SQLite database.")
    init_db_parser.add_argument(
        "--db-path",
        type=Path,
        default=None,
        help="Optional SQLite database path. Defaults to data/db/question_bank.sqlite3.",
    )
    init_structured_parser = subparsers.add_parser(
        "init-structured-content",
        help="Create missing stage 9 structured content rows from questions.",
    )
    init_structured_parser.add_argument(
        "--db-path",
        type=Path,
        default=None,
        help="Optional SQLite database path. Defaults to data/db/question_bank.sqlite3.",
    )
    init_structured_parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Optional maximum number of missing rows to initialize.",
    )
    structured_status_parser = subparsers.add_parser(
        "structured-status",
        help="Show stage 9 structured content coverage and status distribution.",
    )
    structured_status_parser.add_argument(
        "--db-path",
        type=Path,
        default=None,
        help="Optional SQLite database path. Defaults to data/db/question_bank.sqlite3.",
    )
    import_pdf_parser = subparsers.add_parser(
        "import-pdf",
        help="Register the unique Base PDF and render selected source page images.",
    )
    import_pdf_parser.add_argument(
        "--pages",
        default=None,
        help="Comma-separated 1-based page numbers. Defaults to 1,603,1090,1207.",
    )
    import_pdf_parser.add_argument(
        "--dpi",
        type=int,
        default=144,
        help="PNG render DPI. Defaults to 144.",
    )
    import_pdf_parser.add_argument(
        "--db-path",
        type=Path,
        default=None,
        help="Optional SQLite database path. Defaults to data/db/question_bank.sqlite3.",
    )
    split_parser = subparsers.add_parser(
        "split-questions",
        help="Split selected born-digital PDF pages into pending question candidates.",
    )
    split_parser.add_argument(
        "--pages",
        default=None,
        help="Comma-separated 1-based page numbers. Defaults to 1090 for this slice.",
    )
    split_parser.add_argument(
        "--db-path",
        type=Path,
        default=None,
        help="Optional SQLite database path. Defaults to data/db/question_bank.sqlite3.",
    )
    scan_parser = subparsers.add_parser(
        "scan-pdf-pages",
        help="Read selected born-digital PDF pages and report text/anchor/candidate quality stats.",
    )
    scan_parser.add_argument(
        "--pages",
        required=True,
        help="Page numbers or ranges, for example 1090-1099,1105. This command is read-only.",
    )
    ai_parser = subparsers.add_parser(
        "ai-suggest",
        help="Create pending AI suggestions. Without --mock, reports skipped when AI is not configured.",
    )
    ai_parser.add_argument(
        "--question-id",
        type=int,
        action="append",
        default=None,
        help="Question id to suggest for. Can be provided multiple times.",
    )
    ai_parser.add_argument(
        "--mock",
        action="store_true",
        help="Insert a local simulated suggestion without calling an AI service.",
    )
    ai_parser.add_argument(
        "--limit",
        type=int,
        default=1,
        help="Maximum suggestions to create when --question-id is omitted. Defaults to 1.",
    )
    ai_parser.add_argument(
        "--db-path",
        type=Path,
        default=None,
        help="Optional SQLite database path. Defaults to data/db/question_bank.sqlite3.",
    )
    ai_structure_parser = subparsers.add_parser(
        "ai-structure",
        help="Queue or run stage 9 structured AI correction. Without --mock, records provider unavailable.",
    )
    ai_structure_parser.add_argument(
        "--question-id",
        type=int,
        action="append",
        default=None,
        help="Question id to process. Can be provided multiple times.",
    )
    ai_structure_parser.add_argument(
        "--mock",
        action="store_true",
        help="Use the local structured mock provider. Requires --db-path and cannot target the real DB.",
    )
    ai_structure_parser.add_argument(
        "--limit",
        type=int,
        default=25,
        help="Maximum questions to consider when --question-id is omitted. Defaults to 25.",
    )
    ai_structure_parser.add_argument(
        "--db-path",
        type=Path,
        default=None,
        help="Optional SQLite database path. Defaults to data/db/question_bank.sqlite3.",
    )
    subparsers.add_parser(
        "ai-structure-config",
        help="Show stage 9 structured AI provider configuration without sending data.",
    )
    validate_structured_parser = subparsers.add_parser(
        "validate-structured-content",
        help="Validate stage 9 structured AI drafts and update ai_status.",
    )
    validate_structured_parser.add_argument(
        "--question-id",
        type=int,
        action="append",
        default=None,
        help="Question id to validate. Can be provided multiple times.",
    )
    validate_structured_parser.add_argument(
        "--status",
        action="append",
        default=None,
        help="Input ai_status to validate when --question-id is omitted. Defaults to ai_draft.",
    )
    validate_structured_parser.add_argument(
        "--limit",
        type=int,
        default=100,
        help="Maximum structured rows to validate. Defaults to 100.",
    )
    validate_structured_parser.add_argument(
        "--db-path",
        type=Path,
        default=None,
        help="Optional SQLite database path. Defaults to data/db/question_bank.sqlite3.",
    )
    codex_export_parser = subparsers.add_parser(
        "codex-structure-export",
        help="Export a deterministic Stage 9 Codex-agent correction JSONL package.",
    )
    codex_export_parser.add_argument(
        "--sample-size",
        type=int,
        default=120,
        help="Deterministic sample size. Defaults to 120.",
    )
    codex_export_parser.add_argument(
        "--batch-name",
        default="stage9-codex-agent",
        help="Batch name recorded in the JSONL records.",
    )
    codex_export_parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Output JSONL path. Prefer data/exports/*.jsonl.",
    )
    codex_export_parser.add_argument(
        "--db-path",
        type=Path,
        default=None,
        help="Optional SQLite database path. Defaults to data/db/question_bank.sqlite3.",
    )
    codex_apply_parser = subparsers.add_parser(
        "codex-structure-apply",
        help="Validate and apply a Codex-agent structured correction JSONL package.",
    )
    codex_apply_parser.add_argument("--input", type=Path, required=True, help="Input JSONL path.")
    codex_apply_parser.add_argument(
        "--batch-name",
        default=None,
        help="Optional batch name override recorded in model_info.",
    )
    codex_apply_parser.add_argument(
        "--no-validate",
        action="store_true",
        help="Apply as ai_draft without immediately validating.",
    )
    codex_apply_parser.add_argument(
        "--db-path",
        type=Path,
        default=None,
        help="Optional SQLite database path. Defaults to data/db/question_bank.sqlite3.",
    )
    codex_batch_parser = subparsers.add_parser(
        "codex-structure-batch",
        help="Export, apply and validate a deterministic Stage 9 Codex-agent sample batch.",
    )
    codex_batch_parser.add_argument(
        "--sample-size",
        type=int,
        default=120,
        help="Deterministic sample size. Defaults to 120.",
    )
    codex_batch_parser.add_argument(
        "--batch-name",
        default="stage9-codex-agent",
        help="Batch name recorded in JSONL and model_info.",
    )
    codex_batch_parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional output JSONL path. Defaults to data/exports/<batch>_<size>.jsonl.",
    )
    codex_batch_parser.add_argument(
        "--db-path",
        type=Path,
        default=None,
        help="Optional SQLite database path. Defaults to data/db/question_bank.sqlite3.",
    )
    rebuild_parser = subparsers.add_parser(
        "rebuild-search-index",
        help="Rebuild question_search_content and question_fts from questions.",
    )
    rebuild_parser.add_argument(
        "--db-path",
        type=Path,
        default=None,
        help="Optional SQLite database path. Defaults to data/db/question_bank.sqlite3.",
    )
    crop_parser = subparsers.add_parser(
        "crop-question-assets",
        help="Generate question-level raw crop PNG assets from page PNGs and question bbox_json.",
    )
    crop_parser.add_argument(
        "--db-path",
        type=Path,
        default=None,
        help="Optional SQLite database path. Defaults to data/db/question_bank.sqlite3.",
    )
    crop_parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Regenerate crop PNG files even when the target file already exists.",
    )
    consistency_parser = subparsers.add_parser(
        "check-consistency",
        help="Check search index, relative paths, assets, orphans, and review status distribution.",
    )
    consistency_parser.add_argument(
        "--db-path",
        type=Path,
        default=None,
        help="Optional SQLite database path. Defaults to data/db/question_bank.sqlite3.",
    )
    batch_create_parser = subparsers.add_parser(
        "batch-create",
        help="Create or update an import batch without running scan/import/split/crop.",
    )
    batch_create_parser.add_argument("--name", required=True, help="Batch name.")
    batch_create_parser.add_argument("--pages", required=True, help="Page numbers or ranges.")
    batch_create_parser.add_argument(
        "--kind",
        choices=("baseline", "expansion"),
        default="expansion",
        help="Batch kind. Defaults to expansion.",
    )
    batch_create_parser.add_argument(
        "--db-path",
        type=Path,
        default=None,
        help="Optional SQLite database path. Defaults to data/db/question_bank.sqlite3.",
    )
    batch_baseline_parser = subparsers.add_parser(
        "batch-baseline",
        help="Register already imported baseline pages as a completed batch.",
    )
    batch_baseline_parser.add_argument(
        "--name",
        default="stage8-baseline-1090-1099",
        help="Baseline batch name.",
    )
    batch_baseline_parser.add_argument("--pages", required=True, help="Baseline page range.")
    batch_baseline_parser.add_argument(
        "--db-path",
        type=Path,
        default=None,
        help="Optional SQLite database path. Defaults to data/db/question_bank.sqlite3.",
    )
    batch_run_parser = subparsers.add_parser(
        "batch-run",
        help="Run scan -> import-pdf -> split-questions -> crop-question-assets for a batch.",
    )
    batch_run_parser.add_argument("--name", required=True, help="Batch name.")
    batch_run_parser.add_argument("--pages", required=True, help="Page numbers or ranges.")
    batch_run_parser.add_argument(
        "--dpi",
        type=int,
        default=144,
        help="PNG render DPI. Defaults to 144.",
    )
    batch_run_parser.add_argument(
        "--no-backup",
        action="store_true",
        help="Skip the pre-run SQLite file backup.",
    )
    batch_run_parser.add_argument(
        "--db-path",
        type=Path,
        default=None,
        help="Optional SQLite database path. Defaults to data/db/question_bank.sqlite3.",
    )
    batch_list_parser = subparsers.add_parser(
        "batch-list",
        help="List import batches.",
    )
    batch_list_parser.add_argument(
        "--db-path",
        type=Path,
        default=None,
        help="Optional SQLite database path. Defaults to data/db/question_bank.sqlite3.",
    )
    batch_show_parser = subparsers.add_parser(
        "batch-show",
        help="Show one import batch and its pages.",
    )
    batch_show_parser.add_argument("--name", required=True, help="Batch name.")
    batch_show_parser.add_argument(
        "--db-path",
        type=Path,
        default=None,
        help="Optional SQLite database path. Defaults to data/db/question_bank.sqlite3.",
    )
    report_parser = subparsers.add_parser(
        "stage8-report",
        help="Write docs/stage8_quality_report.md from batch and database statistics.",
    )
    report_parser.add_argument(
        "--db-path",
        type=Path,
        default=None,
        help="Optional SQLite database path. Defaults to data/db/question_bank.sqlite3.",
    )
    stage9_report_parser = subparsers.add_parser(
        "stage9-report",
        help="Write docs/stage9_quality_report.md from structured content and sample statistics.",
    )
    stage9_report_parser.add_argument(
        "--db-path",
        type=Path,
        default=None,
        help="Optional SQLite database path. Defaults to data/db/question_bank.sqlite3.",
    )
    stage9_report_parser.add_argument(
        "--sample-size",
        type=int,
        default=120,
        help="Representative sample size. Defaults to 120.",
    )
    stage9_report_parser.add_argument(
        "--no-queue",
        action="store_true",
        help="Only write the report; do not mark sample rows with provider unavailable.",
    )
    stage10_baseline_parser = subparsers.add_parser(
        "stage10-baseline",
        help="Register the Stage 10 baseline question set without touching questions.",
    )
    stage10_baseline_parser.add_argument(
        "--db-path",
        type=Path,
        default=None,
        help="Optional SQLite database path. Defaults to data/db/question_bank.sqlite3.",
    )
    stage10_baseline_parser.add_argument(
        "--sample-size",
        type=int,
        default=160,
        help="Baseline sample size. Defaults to 160 and never below 100.",
    )
    stage10_structure_parser = subparsers.add_parser(
        "stage10-structure-batch",
        help="Run Stage 10 local rule structuring and validation on low-risk candidates.",
    )
    stage10_structure_parser.add_argument(
        "--db-path",
        type=Path,
        default=None,
        help="Optional SQLite database path. Defaults to data/db/question_bank.sqlite3.",
    )
    stage10_structure_parser.add_argument(
        "--target-verified",
        type=int,
        default=100,
        help="Target total ai_verified count. Defaults to 100.",
    )
    stage10_structure_parser.add_argument(
        "--max-questions",
        type=int,
        default=350,
        help="Maximum writable structured rows to process. Defaults to 350.",
    )
    stage10_structure_parser.add_argument(
        "--sample-size",
        type=int,
        default=160,
        help="Baseline sample size. Defaults to 160.",
    )
    stage10_report_parser = subparsers.add_parser(
        "stage10-report",
        help="Write docs/stage10_quality_report.md from Stage 10 statistics.",
    )
    stage10_report_parser.add_argument(
        "--db-path",
        type=Path,
        default=None,
        help="Optional SQLite database path. Defaults to data/db/question_bank.sqlite3.",
    )
    stage10_report_parser.add_argument(
        "--sample-size",
        type=int,
        default=160,
        help="Baseline sample size. Defaults to 160.",
    )
    stage10_export_parser = subparsers.add_parser(
        "stage10-export-sample",
        help="Save a Stage 10 printable HTML sample into data/exports.",
    )
    stage10_export_parser.add_argument(
        "--db-path",
        type=Path,
        default=None,
        help="Optional SQLite database path. Defaults to data/db/question_bank.sqlite3.",
    )
    stage10_export_parser.add_argument(
        "--limit",
        type=int,
        default=14,
        help="Maximum verified questions in the sample. Defaults to 14.",
    )
    stage11_classify_parser = subparsers.add_parser(
        "stage11-classify-usability",
        help="Classify every question into Stage 11 usability lanes without touching questions.",
    )
    stage11_classify_parser.add_argument(
        "--db-path",
        type=Path,
        default=None,
        help="Optional SQLite database path. Defaults to data/db/question_bank.sqlite3.",
    )
    stage11_classify_parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Optional maximum rows to classify. Omit for the full database.",
    )
    usability_status_parser = subparsers.add_parser(
        "usability-status",
        help="Show Stage 11 usability status distribution.",
    )
    usability_status_parser.add_argument(
        "--db-path",
        type=Path,
        default=None,
        help="Optional SQLite database path. Defaults to data/db/question_bank.sqlite3.",
    )
    stage11_report_parser = subparsers.add_parser(
        "stage11-report",
        help="Write docs/stage11_quality_report.md from Stage 11 usability states.",
    )
    stage11_report_parser.add_argument(
        "--db-path",
        type=Path,
        default=None,
        help="Optional SQLite database path. Defaults to data/db/question_bank.sqlite3.",
    )
    stage11_export_parser = subparsers.add_parser(
        "stage11-export-sample",
        help="Save a formal Stage 11 HTML sample using only strict_structured and visual_fallback.",
    )
    stage11_export_parser.add_argument(
        "--db-path",
        type=Path,
        default=None,
        help="Optional SQLite database path. Defaults to data/db/question_bank.sqlite3.",
    )
    stage11_export_parser.add_argument(
        "--limit",
        type=int,
        default=24,
        help="Maximum export-usable questions in the sample. Defaults to 24.",
    )
    stage12_classify_parser = subparsers.add_parser(
        "stage12-classify-export-quality",
        help="Classify every question into Stage 12 export quality lanes without touching questions.",
    )
    stage12_classify_parser.add_argument(
        "--db-path",
        type=Path,
        default=None,
        help="Optional SQLite database path. Defaults to data/db/question_bank.sqlite3.",
    )
    stage12_classify_parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Optional maximum rows to classify. Omit for the full database.",
    )
    export_quality_status_parser = subparsers.add_parser(
        "export-quality-status",
        help="Show Stage 12 export quality status distribution.",
    )
    export_quality_status_parser.add_argument(
        "--db-path",
        type=Path,
        default=None,
        help="Optional SQLite database path. Defaults to data/db/question_bank.sqlite3.",
    )
    source_attribution_parser = subparsers.add_parser(
        "rebuild-source-attributions",
        help="Rebuild per-question source labels from source page headers and existing metadata.",
    )
    source_attribution_parser.add_argument(
        "--db-path",
        type=Path,
        default=None,
        help="Optional SQLite database path. Defaults to data/db/question_bank.sqlite3.",
    )
    source_attribution_parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Optional maximum number of questions to rebuild.",
    )
    source_attribution_status_parser = subparsers.add_parser(
        "source-attribution-status",
        help="Show per-question source attribution coverage and confidence distribution.",
    )
    source_attribution_status_parser.add_argument(
        "--db-path",
        type=Path,
        default=None,
        help="Optional SQLite database path. Defaults to data/db/question_bank.sqlite3.",
    )
    stage13_report_parser = subparsers.add_parser(
        "stage13-report",
        help="Write docs/stage13_source_attribution_report.md from source attributions.",
    )
    stage13_report_parser.add_argument(
        "--db-path",
        type=Path,
        default=None,
        help="Optional SQLite database path. Defaults to data/db/question_bank.sqlite3.",
    )
    stage12_report_parser = subparsers.add_parser(
        "stage12-report",
        help="Write docs/stage12_export_quality_report.md from Stage 12 quality states.",
    )
    stage12_report_parser.add_argument(
        "--db-path",
        type=Path,
        default=None,
        help="Optional SQLite database path. Defaults to data/db/question_bank.sqlite3.",
    )
    stage12_export_parser = subparsers.add_parser(
        "stage12-export-sample",
        help="Save a formal Stage 12 HTML sample using only export_ready_* questions.",
    )
    stage12_export_parser.add_argument(
        "--db-path",
        type=Path,
        default=None,
        help="Optional SQLite database path. Defaults to data/db/question_bank.sqlite3.",
    )
    stage12_export_parser.add_argument(
        "--limit",
        type=int,
        default=24,
        help="Maximum export-ready questions in the sample. Defaults to 24.",
    )
    stage14_classify_parser = subparsers.add_parser(
        "stage14-classify-quality",
        help="Build the Stage 14 quality queue without touching questions.",
    )
    stage14_classify_parser.add_argument(
        "--db-path",
        type=Path,
        default=None,
        help="Optional SQLite database path. Defaults to data/db/question_bank.sqlite3.",
    )
    stage14_classify_parser.add_argument(
        "--no-recut-audit",
        action="store_true",
        help="Skip high-risk duplicate-anchor page scan audit.",
    )
    stage14_classify_parser.add_argument(
        "--no-source-audit",
        action="store_true",
        help="Skip inferred source audit sampling.",
    )
    stage14_classify_parser.add_argument(
        "--source-audit-limit",
        type=int,
        default=40,
        help="Maximum inferred source rows to audit. Use 0 to skip.",
    )
    stage14_classify_parser.add_argument(
        "--write-report",
        action="store_true",
        help="Also write docs/stage14_quality_report.md.",
    )
    stage14_repair_parser = subparsers.add_parser(
        "stage14-visual-repair",
        help="Generate versioned Stage 14 visual repair candidates.",
    )
    stage14_repair_parser.add_argument(
        "--db-path",
        type=Path,
        default=None,
        help="Optional SQLite database path. Defaults to data/db/question_bank.sqlite3.",
    )
    stage14_repair_parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Optional maximum visual repair candidates to process.",
    )
    stage14_repair_parser.add_argument(
        "--write-report",
        action="store_true",
        help="Also write docs/stage14_quality_report.md.",
    )
    stage14_status_parser = subparsers.add_parser(
        "stage14-status",
        help="Show Stage 14 queue, repair, source audit, and asset statistics.",
    )
    stage14_status_parser.add_argument(
        "--db-path",
        type=Path,
        default=None,
        help="Optional SQLite database path. Defaults to data/db/question_bank.sqlite3.",
    )
    stage14_report_parser = subparsers.add_parser(
        "stage14-report",
        help="Write docs/stage14_quality_report.md.",
    )
    stage14_report_parser.add_argument(
        "--db-path",
        type=Path,
        default=None,
        help="Optional SQLite database path. Defaults to data/db/question_bank.sqlite3.",
    )
    stage14_export_parser = subparsers.add_parser(
        "stage14-export-sample",
        help="Save a formal Stage 14 HTML sample using only export-ready questions.",
    )
    stage14_export_parser.add_argument(
        "--db-path",
        type=Path,
        default=None,
        help="Optional SQLite database path. Defaults to data/db/question_bank.sqlite3.",
    )
    stage14_export_parser.add_argument(
        "--limit",
        type=int,
        default=24,
        help="Maximum export-ready questions in the sample. Defaults to 24.",
    )

    args = parser.parse_args(argv)

    if args.command == "init-db":
        result = initialize_database(args.db_path)
        print(json.dumps({"status": "ok", **result}, ensure_ascii=False, indent=2))
        return 0

    if args.command == "init-structured-content":
        result = initialize_structured_contents(db_path=args.db_path, limit=args.limit)
        print(json.dumps({"status": "ok", **result}, ensure_ascii=False, indent=2))
        return 0

    if args.command == "structured-status":
        result = summarize_structured_contents(db_path=args.db_path)
        print(json.dumps({"status": "ok", **result}, ensure_ascii=False, indent=2))
        return 0

    if args.command == "split-questions":
        try:
            pages = parse_split_pages(args.pages)
            result = split_questions(pages=pages, db_path=args.db_path)
        except QuestionSplitError as exc:
            print(
                json.dumps(
                    {"status": "error", "error": str(exc)},
                    ensure_ascii=False,
                    indent=2,
                ),
                file=sys.stderr,
            )
            return 1

        print(json.dumps({"status": "ok", **result}, ensure_ascii=False, indent=2))
        return 0

    if args.command == "scan-pdf-pages":
        try:
            pages = parse_page_numbers(args.pages)
            result = scan_pdf_pages(pages=pages)
        except (PdfImportError, PageRangeError) as exc:
            print(
                json.dumps(
                    {"status": "error", "error": str(exc)},
                    ensure_ascii=False,
                    indent=2,
                ),
                file=sys.stderr,
            )
            return 1

        print(json.dumps({"status": "ok", **result}, ensure_ascii=False, indent=2))
        return 0

    if args.command == "ai-suggest":
        try:
            question_ids = tuple(args.question_id) if args.question_id else None
            result = generate_ai_suggestions(
                db_path=args.db_path,
                question_ids=question_ids,
                mock=args.mock,
                limit=args.limit,
            )
        except AiSuggestionError as exc:
            print(
                json.dumps(
                    {"status": "error", "error": str(exc)},
                    ensure_ascii=False,
                    indent=2,
                ),
                file=sys.stderr,
            )
            return 1
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    if args.command == "ai-structure":
        try:
            question_ids = tuple(args.question_id) if args.question_id else None
            result = run_structured_ai_corrections(
                db_path=args.db_path,
                question_ids=question_ids,
                mock=args.mock,
                limit=args.limit,
            )
        except StructuredAiError as exc:
            print(
                json.dumps(
                    {"status": "error", "error": str(exc)},
                    ensure_ascii=False,
                    indent=2,
                ),
                file=sys.stderr,
            )
            return 1
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    if args.command == "ai-structure-config":
        result = get_structured_ai_provider_status()
        print(json.dumps({"status": "ok", **result}, ensure_ascii=False, indent=2))
        return 0

    if args.command == "validate-structured-content":
        try:
            question_ids = tuple(args.question_id) if args.question_id else None
            statuses = tuple(args.status) if args.status else ("ai_draft",)
            result = validate_structured_contents(
                db_path=args.db_path,
                question_ids=question_ids,
                limit=args.limit,
                statuses=statuses,
            )
        except StructuredValidationError as exc:
            print(
                json.dumps(
                    {"status": "error", "error": str(exc)},
                    ensure_ascii=False,
                    indent=2,
                ),
                file=sys.stderr,
            )
            return 1
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    if args.command == "codex-structure-export":
        try:
            result = export_codex_structure_batch(
                db_path=args.db_path,
                output_path=args.output,
                sample_size=args.sample_size,
                batch_name=args.batch_name,
            )
        except CodexStructureError as exc:
            print(
                json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=False, indent=2),
                file=sys.stderr,
            )
            return 1
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    if args.command == "codex-structure-apply":
        try:
            result = apply_codex_structure_jsonl(
                db_path=args.db_path,
                input_path=args.input,
                batch_name=args.batch_name,
                validate_after=not args.no_validate,
            )
        except CodexStructureError as exc:
            print(
                json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=False, indent=2),
                file=sys.stderr,
            )
            return 1
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    if args.command == "codex-structure-batch":
        try:
            result = run_codex_structure_batch(
                db_path=args.db_path,
                sample_size=args.sample_size,
                batch_name=args.batch_name,
                output_path=args.output,
            )
        except CodexStructureError as exc:
            print(
                json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=False, indent=2),
                file=sys.stderr,
            )
            return 1
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    if args.command == "rebuild-search-index":
        result = rebuild_search_index(db_path=args.db_path)
        print(json.dumps({"status": "ok", **result}, ensure_ascii=False, indent=2))
        return 0

    if args.command == "crop-question-assets":
        try:
            result = crop_question_assets(db_path=args.db_path, overwrite=args.overwrite)
        except QuestionAssetError as exc:
            print(
                json.dumps(
                    {"status": "error", "error": str(exc)},
                    ensure_ascii=False,
                    indent=2,
                ),
                file=sys.stderr,
            )
            return 1
        print(json.dumps({"status": "ok", **result}, ensure_ascii=False, indent=2))
        return 0

    if args.command == "check-consistency":
        result = check_consistency(db_path=args.db_path)
        status = "ok" if result["ok"] else "error"
        print(json.dumps({"status": status, **result}, ensure_ascii=False, indent=2))
        return 0 if result["ok"] else 1

    if args.command == "batch-create":
        try:
            pages = parse_batch_pages(args.pages)
            result = create_import_batch(
                name=args.name,
                pages=pages,
                batch_kind=args.kind,
                db_path=args.db_path,
            )
        except ImportBatchError as exc:
            print(
                json.dumps(
                    {"status": "error", "error": str(exc)},
                    ensure_ascii=False,
                    indent=2,
                ),
                file=sys.stderr,
            )
            return 1
        print(json.dumps({"status": "ok", "batch": result}, ensure_ascii=False, indent=2))
        return 0

    if args.command == "batch-baseline":
        try:
            pages = parse_batch_pages(args.pages)
            result = register_baseline_batch(
                name=args.name,
                pages=pages,
                db_path=args.db_path,
            )
        except (ImportBatchError, PdfImportError, PageRangeError) as exc:
            print(
                json.dumps(
                    {"status": "error", "error": str(exc)},
                    ensure_ascii=False,
                    indent=2,
                ),
                file=sys.stderr,
            )
            return 1
        print(json.dumps({"status": "ok", "batch": result}, ensure_ascii=False, indent=2))
        return 0

    if args.command == "batch-run":
        try:
            pages = parse_batch_pages(args.pages)
            result = run_import_batch(
                name=args.name,
                pages=pages,
                dpi=args.dpi,
                db_path=args.db_path,
                create_backup=not args.no_backup,
            )
        except (ImportBatchError, PdfImportError, QuestionSplitError, QuestionAssetError) as exc:
            print(
                json.dumps(
                    {"status": "error", "error": str(exc)},
                    ensure_ascii=False,
                    indent=2,
                ),
                file=sys.stderr,
            )
            return 1
        print(json.dumps({"status": "ok", "batch": result}, ensure_ascii=False, indent=2))
        return 0

    if args.command == "batch-list":
        print(
            json.dumps(
                {"status": "ok", "batches": list_import_batches(db_path=args.db_path)},
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0

    if args.command == "batch-show":
        try:
            result = get_import_batch(name=args.name, db_path=args.db_path)
        except ImportBatchError as exc:
            print(
                json.dumps(
                    {"status": "error", "error": str(exc)},
                    ensure_ascii=False,
                    indent=2,
                ),
                file=sys.stderr,
            )
            return 1
        print(json.dumps({"status": "ok", "batch": result}, ensure_ascii=False, indent=2))
        return 0

    if args.command == "stage8-report":
        result = write_stage8_quality_report(db_path=args.db_path)
        print(json.dumps({"status": "ok", **result}, ensure_ascii=False, indent=2))
        return 0

    if args.command == "stage9-report":
        result = write_stage9_quality_report(
            db_path=args.db_path,
            project_root=_report_project_root(args.db_path),
            sample_size=args.sample_size,
            run_queue=not args.no_queue,
        )
        print(json.dumps({"status": "ok", **result}, ensure_ascii=False, indent=2))
        return 0

    if args.command == "stage10-baseline":
        try:
            result = register_stage10_baseline(
                db_path=args.db_path,
                sample_size=args.sample_size,
            )
        except Stage10Error as exc:
            print(
                json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=False, indent=2),
                file=sys.stderr,
            )
            return 1
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    if args.command == "stage10-structure-batch":
        try:
            result = run_stage10_structure_batch(
                db_path=args.db_path,
                target_verified=args.target_verified,
                max_questions=args.max_questions,
                sample_size=args.sample_size,
            )
        except Stage10Error as exc:
            print(
                json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=False, indent=2),
                file=sys.stderr,
            )
            return 1
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    if args.command == "stage10-report":
        result = write_stage10_quality_report(
            db_path=args.db_path,
            project_root=_report_project_root(args.db_path),
            sample_size=args.sample_size,
        )
        print(json.dumps({"status": "ok", **result}, ensure_ascii=False, indent=2))
        return 0

    if args.command == "stage10-export-sample":
        result = save_stage10_export_sample(
            db_path=args.db_path,
            project_root=_report_project_root(args.db_path),
            limit=args.limit,
        )
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    if args.command == "stage11-classify-usability":
        result = classify_usability_states(
            db_path=args.db_path,
            project_root=_report_project_root(args.db_path),
            limit=args.limit,
        )
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    if args.command == "usability-status":
        result = summarize_usability_states(
            db_path=args.db_path,
            project_root=_report_project_root(args.db_path),
        )
        print(json.dumps({"status": "ok", **result}, ensure_ascii=False, indent=2))
        return 0

    if args.command == "stage11-report":
        result = write_stage11_quality_report(
            db_path=args.db_path,
            project_root=_report_project_root(args.db_path),
        )
        print(json.dumps({"status": "ok", **result}, ensure_ascii=False, indent=2))
        return 0

    if args.command == "stage11-export-sample":
        result = save_stage11_export_sample(
            db_path=args.db_path,
            project_root=_report_project_root(args.db_path),
            limit=args.limit,
        )
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    if args.command == "stage12-classify-export-quality":
        result = classify_export_quality_states(
            db_path=args.db_path,
            project_root=_report_project_root(args.db_path),
            limit=args.limit,
        )
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    if args.command == "export-quality-status":
        result = summarize_export_quality(
            db_path=args.db_path,
            project_root=_report_project_root(args.db_path),
        )
        print(json.dumps({"status": "ok", **result}, ensure_ascii=False, indent=2))
        return 0

    if args.command == "rebuild-source-attributions":
        result = rebuild_source_attributions(
            db_path=args.db_path,
            project_root=_report_project_root(args.db_path),
            limit=args.limit,
        )
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    if args.command == "source-attribution-status":
        result = summarize_source_attributions(db_path=args.db_path)
        print(json.dumps({"status": "ok", **result}, ensure_ascii=False, indent=2))
        return 0

    if args.command == "stage13-report":
        result = write_stage13_source_attribution_report(
            db_path=args.db_path,
            project_root=_report_project_root(args.db_path),
        )
        print(json.dumps({"status": "ok", **result}, ensure_ascii=False, indent=2))
        return 0

    if args.command == "stage12-report":
        result = write_stage12_export_quality_report(
            db_path=args.db_path,
            project_root=_report_project_root(args.db_path),
        )
        print(json.dumps({"status": "ok", **result}, ensure_ascii=False, indent=2))
        return 0

    if args.command == "stage12-export-sample":
        result = save_stage12_export_sample(
            db_path=args.db_path,
            project_root=_report_project_root(args.db_path),
            limit=args.limit,
        )
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    if args.command == "stage14-classify-quality":
        result = classify_stage14_quality_queue(
            db_path=args.db_path,
            project_root=_report_project_root(args.db_path),
            audit_recuts=not args.no_recut_audit,
            audit_sources=not args.no_source_audit,
            source_audit_limit=args.source_audit_limit,
            write_report=args.write_report,
        )
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    if args.command == "stage14-visual-repair":
        result = generate_stage14_visual_repair_candidates(
            db_path=args.db_path,
            project_root=_report_project_root(args.db_path),
            limit=args.limit,
            write_report=args.write_report,
        )
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    if args.command == "stage14-status":
        result = summarize_stage14_quality(
            db_path=args.db_path,
            project_root=_report_project_root(args.db_path),
        )
        print(json.dumps({"status": "ok", **result}, ensure_ascii=False, indent=2))
        return 0

    if args.command == "stage14-report":
        result = write_stage14_quality_report(
            db_path=args.db_path,
            project_root=_report_project_root(args.db_path),
        )
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    if args.command == "stage14-export-sample":
        result = save_stage14_export_sample(
            db_path=args.db_path,
            project_root=_report_project_root(args.db_path),
            limit=args.limit,
        )
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    if args.command == "import-pdf":
        try:
            pages = parse_pages(args.pages)
            result = import_pdf(pages=pages, dpi=args.dpi, db_path=args.db_path)
        except PdfImportError as exc:
            print(
                json.dumps(
                    {"status": "error", "error": str(exc)},
                    ensure_ascii=False,
                    indent=2,
                ),
                file=sys.stderr,
            )
            return 1

        print(json.dumps({"status": "ok", **result}, ensure_ascii=False, indent=2))
        return 0

    if args.command in (None, "health"):
        report = build_health_report()
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0 if report["status"] == "ok" else 1

    parser.error(f"unknown command: {args.command}")
    return 2


def _report_project_root(db_path: Path | None) -> Path:
    if db_path is None:
        return PROJECT_ROOT
    resolved = db_path.resolve()
    if resolved.parent.name == "db" and resolved.parent.parent.name == "data":
        return resolved.parent.parent.parent
    return PROJECT_ROOT


if __name__ == "__main__":
    sys.exit(main())
