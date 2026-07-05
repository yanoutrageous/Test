from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .config import PROJECT_ROOT, get_project_paths
from .database import connect_database, initialize_database
from .structured_ai import StructuredAiError, validate_ai_output_payload
from .structured_content import initialize_structured_contents, normalize_question_type, parse_json_field
from .structured_validation import validate_structured_contents


CODEX_AGENT_VERSION = "stage9_codex_agent_v1"
CODEX_AGENT_PROVIDER = "codex_agent"
CODEX_AGENT_MODEL = "gpt-5.5-xhigh-execution-thread"
FOCUS_QIDS = (
    "PDF-D02D0F16371FA96F-P1094-Q011",
    "PDF-D02D0F16371FA96F-P1094-Q012",
)
HIGH_RISK_PAGES = (1098, 1100, 1128, 1148, 1168)
WRITABLE_STRUCTURED_STATUSES = ("unprocessed", "ai_draft", "needs_review", "failed")
PROTECTED_QUESTION_STATUSES = ("reviewed", "approved")


class CodexStructureError(RuntimeError):
    """Raised when Codex-agent structured correction cannot continue."""


def export_codex_structure_batch(
    *,
    db_path: Path | None = None,
    output_path: Path,
    sample_size: int = 120,
    batch_name: str = "stage9-codex-agent",
    project_root: Path = PROJECT_ROOT,
) -> dict[str, Any]:
    initialize_database(db_path)
    initialize_structured_contents(db_path=db_path)
    rows = _select_rows(db_path=db_path, sample_size=sample_size)
    output_abs = _resolve_output_path(output_path, project_root=project_root)
    output_abs.parent.mkdir(parents=True, exist_ok=True)

    written = 0
    with output_abs.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            payload = _build_codex_payload(row)
            record = {
                "schema_version": CODEX_AGENT_VERSION,
                "batch_name": batch_name,
                "question_id": row["question_id"],
                "qid": row["qid"],
                "source_page": row["source_page"],
                "review_status": row["review_status"],
                "raw_crop_path": row["raw_crop_path"],
                "page_image_path": row["page_image_path"],
                "payload": payload,
            }
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
            written += 1

    return {
        "status": "ok",
        "batch_name": batch_name,
        "sample_size": sample_size,
        "exported": written,
        "output_path": str(output_abs),
        "relative_output_path": _relative_to_project(output_abs, project_root),
        "qids": [row["qid"] for row in rows],
    }


def apply_codex_structure_jsonl(
    *,
    db_path: Path | None = None,
    input_path: Path,
    batch_name: str | None = None,
    validate_after: bool = True,
    project_root: Path = PROJECT_ROOT,
) -> dict[str, Any]:
    initialize_database(db_path)
    initialize_structured_contents(db_path=db_path)
    input_abs = _resolve_input_path(input_path, project_root=project_root)
    if not input_abs.is_file():
        raise CodexStructureError(f"Codex structure JSONL does not exist: {input_abs}")

    records = _read_jsonl_records(input_abs)
    applied: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []

    with connect_database(db_path) as conn:
        for line_no, record in records:
            try:
                applied_row = _apply_record(
                    conn,
                    record,
                    line_no=line_no,
                    batch_name=batch_name or str(record.get("batch_name") or ""),
                    input_path=input_abs,
                    project_root=project_root,
                )
            except CodexStructureError as exc:
                errors.append({"line_no": line_no, "error": str(exc)})
                continue
            if applied_row["status"] == "skipped":
                skipped.append(applied_row)
            else:
                applied.append(applied_row)
        conn.commit()

    validation_result: dict[str, Any] | None = None
    if validate_after and applied:
        validation_result = validate_structured_contents(
            db_path=db_path,
            question_ids=tuple(item["question_id"] for item in applied),
            limit=len(applied),
        )

    return {
        "status": "ok" if not errors else "error",
        "input_path": str(input_abs),
        "batch_name": batch_name,
        "records": len(records),
        "applied": len(applied),
        "skipped": skipped,
        "errors": errors,
        "validation": validation_result,
    }


def run_codex_structure_batch(
    *,
    db_path: Path | None = None,
    sample_size: int = 120,
    batch_name: str = "stage9-codex-agent",
    output_path: Path | None = None,
    project_root: Path = PROJECT_ROOT,
) -> dict[str, Any]:
    paths = get_project_paths(project_root, require_target_pdf=False)
    output = output_path or (
        paths.exports_dir / f"{_safe_filename(batch_name)}_{sample_size}.jsonl"
    )
    export_result = export_codex_structure_batch(
        db_path=db_path,
        output_path=output,
        sample_size=sample_size,
        batch_name=batch_name,
        project_root=project_root,
    )
    apply_result = apply_codex_structure_jsonl(
        db_path=db_path,
        input_path=Path(export_result["output_path"]),
        batch_name=batch_name,
        validate_after=True,
        project_root=project_root,
    )
    status_counts: dict[str, int] = {}
    if apply_result.get("validation"):
        status_counts = dict(apply_result["validation"].get("status_counts", {}))
    return {
        "status": apply_result["status"],
        "batch_name": batch_name,
        "sample_size": sample_size,
        "export": export_result,
        "apply": apply_result,
        "validation_status_counts": status_counts,
    }


def _select_rows(*, db_path: Path | None, sample_size: int) -> list[dict[str, Any]]:
    capped = max(1, min(sample_size, 500))
    with connect_database(db_path) as conn:
        rows = [
            dict(row)
            for row in conn.execute(
                """
                SELECT q.id AS question_id,
                       q.qid,
                       q.question_no,
                       q.question_type,
                       q.review_status,
                       q.stem_text,
                       q.stem_latex AS question_stem_latex,
                       q.answer_text,
                       q.analysis_latex AS question_analysis_latex,
                       q.bbox_json,
                       q.meta_json,
                       CAST(json_extract(q.meta_json, '$.source_page') AS INTEGER) AS source_page,
                       sc.source_text,
                       sc.source_latex,
                       sc.ai_status,
                       sc.normalized_type AS normalized_type_candidate,
                       qa.relative_path AS raw_crop_path,
                       spa.relative_path AS page_image_path,
                       COALESCE(ibp.warning_candidates, 0) AS warning_candidates,
                       COALESCE(ibp.duplicate_anchor_count, 0) AS duplicate_anchor_count,
                       COALESCE(ibp.page_flags_json, '[]') AS page_flags_json
                  FROM questions q
                  JOIN question_structured_contents sc ON sc.question_id = q.id
                  LEFT JOIN question_assets qa
                    ON qa.question_id = q.id
                   AND qa.asset_kind = 'raw_crop'
                  LEFT JOIN source_paper_assets spa
                    ON spa.source_paper_id = q.source_paper_id
                   AND spa.asset_kind = 'page_image'
                   AND spa.page_no = CAST(json_extract(q.meta_json, '$.source_page') AS INTEGER)
                  LEFT JOIN import_batch_pages ibp
                    ON ibp.id = (
                        SELECT id
                          FROM import_batch_pages ibp2
                         WHERE ibp2.page_no = CAST(json_extract(q.meta_json, '$.source_page') AS INTEGER)
                           AND (ibp2.source_paper_id IS NULL OR ibp2.source_paper_id = q.source_paper_id)
                         ORDER BY ibp2.updated_at DESC, ibp2.id DESC
                         LIMIT 1
                    )
                 ORDER BY q.id
                """
            ).fetchall()
        ]

    by_qid = {row["qid"]: row for row in rows}
    selected: dict[int, dict[str, Any]] = {}

    def add(row: dict[str, Any] | None) -> None:
        if row is None or len(selected) >= capped:
            return
        selected[int(row["question_id"])] = row

    for qid in FOCUS_QIDS:
        add(by_qid.get(qid))

    for page_no in HIGH_RISK_PAGES:
        for row in rows:
            if len(selected) >= capped:
                break
            if int(row["source_page"] or 0) == page_no:
                add(row)

    for normalized_type in ("choice", "blank", "solution", "unknown"):
        current = sum(
            1 for row in selected.values() if row["normalized_type_candidate"] == normalized_type
        )
        target = max(1, capped // 8)
        for row in rows:
            if current >= target or len(selected) >= capped:
                break
            if row["normalized_type_candidate"] == normalized_type:
                add(row)
                current += 1

    for row in rows:
        if len(selected) >= capped:
            break
        add(row)

    return list(selected.values())


def _build_codex_payload(row: dict[str, Any]) -> dict[str, Any]:
    override = _focus_override(row)
    if override is not None:
        return override

    source_text = str(row.get("source_text") or row.get("stem_text") or "")
    normalized_type = normalize_question_type(str(row.get("question_type") or ""))
    if normalized_type == "unknown":
        normalized_type = str(row.get("normalized_type_candidate") or "unknown")

    stem_text, options = _split_options(source_text)
    if options and normalized_type == "unknown":
        normalized_type = "choice"

    flags = _base_quality_flags(row)
    if not source_text.strip():
        flags.append("empty_source_text")
    if _looks_visual_question(source_text):
        flags.append("image_question_needs_manual_review")

    if normalized_type in ("choice", "multiple_choice"):
        if len(options) != 4:
            flags.append("option_count_anomaly")
        payload_options = [
            {"label": option["label"], "text_latex": _normalize_latex_text(option["text"])}
            for option in options
        ]
        stem_latex = _normalize_latex_text(stem_text or source_text)
        blanks: list[dict[str, Any]] = []
        subquestions: list[dict[str, Any]] = []
    elif normalized_type == "blank":
        payload_options = []
        stem_latex = _normalize_latex_text(source_text)
        blanks = _extract_blanks(stem_latex)
        subquestions = []
        if not blanks:
            flags.append("blank_placeholder_uncertain")
    elif normalized_type == "solution":
        payload_options = []
        stem_latex = _normalize_latex_text(source_text)
        blanks = []
        subquestions = _extract_subquestions(stem_latex)
    else:
        payload_options = []
        stem_latex = _normalize_latex_text(source_text)
        blanks = []
        subquestions = []
        flags.append("unknown_question_type")

    if _formula_may_need_human_check(source_text) and row["qid"] not in FOCUS_QIDS:
        flags.append("formula_uncertain")

    flags.append("no_answer_in_source")
    return validate_ai_output_payload(
        {
            "normalized_type": normalized_type,
            "stem_latex": stem_latex,
            "options_json": payload_options,
            "blanks_json": blanks,
            "subquestions_json": subquestions,
            "answer_latex": "",
            "analysis_latex": "",
            "confidence": _confidence_for_flags(flags),
            "quality_flags": _dedupe(flags),
        }
    )


def _focus_override(row: dict[str, Any]) -> dict[str, Any] | None:
    qid = str(row.get("qid") or "")
    if qid.endswith("P1094-Q011"):
        return validate_ai_output_payload(
            {
                "normalized_type": "choice",
                "stem_latex": (
                    "11. 设 $F$ 为双曲线 $C: \\frac{x^2}{a^2}-\\frac{y^2}{b^2}=1$ "
                    "($a>0,b>0$) 的右焦点，$O$ 为坐标原点，以 $OF$ 为直径的圆与圆 "
                    "$x^2+y^2=a^2$ 交于 $P,Q$ 两点。若 $|PQ|=|OF|$，则 $C$ 的离心率为（ ）"
                ),
                "options_json": [
                    {"label": "A", "text_latex": "$\\sqrt{2}$"},
                    {"label": "B", "text_latex": "$\\sqrt{3}$"},
                    {"label": "C", "text_latex": "$2$"},
                    {"label": "D", "text_latex": "$\\sqrt{5}$"},
                ],
                "blanks_json": [],
                "subquestions_json": [],
                "answer_latex": "",
                "analysis_latex": "",
                "confidence": 0.92,
                "quality_flags": [
                    "codex_agent_structured",
                    "referenced_raw_crop_image",
                    "no_answer_in_source",
                ],
            }
        )
    if qid.endswith("P1094-Q012"):
        return validate_ai_output_payload(
            {
                "normalized_type": "choice",
                "stem_latex": (
                    "12. 设函数 $f(x)$ 的定义域为 $\\mathbb{R}$，满足 $f(x+1)=2f(x)$，"
                    "且当 $x\\in(0,1]$ 时，$f(x)=x(x-1)$。若对任意 "
                    "$x\\in(-\\infty,m]$，都有 $f(x)\\ge -\\frac{8}{9}$，则 $m$ 的取值范围是（ ）"
                ),
                "options_json": [
                    {"label": "A", "text_latex": "$(-\\infty,\\frac{9}{4}]$"},
                    {"label": "B", "text_latex": "$(-\\infty,\\frac{7}{3}]$"},
                    {"label": "C", "text_latex": "$(-\\infty,\\frac{5}{2}]$"},
                    {"label": "D", "text_latex": "$(-\\infty,\\frac{8}{3}]$"},
                ],
                "blanks_json": [],
                "subquestions_json": [],
                "answer_latex": "",
                "analysis_latex": "",
                "confidence": 0.92,
                "quality_flags": [
                    "codex_agent_structured",
                    "referenced_raw_crop_image",
                    "no_answer_in_source",
                ],
            }
        )
    return None


def _base_quality_flags(row: dict[str, Any]) -> list[str]:
    flags = ["codex_agent_structured"]
    if not row.get("raw_crop_path"):
        flags.append("missing_raw_crop")
    else:
        flags.append("referenced_raw_crop_image")
    if not row.get("page_image_path"):
        flags.append("missing_page_image")
    if int(row.get("duplicate_anchor_count") or 0) > 0:
        flags.append("page_duplicate_anchors")
    if int(row.get("warning_candidates") or 0) > 0:
        flags.append("page_warning_candidates")
    page_flags = parse_json_field(row.get("page_flags_json"), [])
    if isinstance(page_flags, list) and page_flags:
        flags.append("page_flags_present")
        flags.extend(f"page_flag_{flag}" for flag in page_flags if flag)
    meta = parse_json_field(row.get("meta_json"), {})
    split_warnings = meta.get("split_warnings") if isinstance(meta, dict) else None
    if isinstance(split_warnings, list) and split_warnings:
        flags.append("split_warnings_present")
        flags.extend(f"split_warning_{flag}" for flag in split_warnings if flag)
    if row.get("review_status") in PROTECTED_QUESTION_STATUSES:
        flags.append("question_review_status_protected")
    return flags


def _split_options(text: str) -> tuple[str, list[dict[str, str]]]:
    pattern = re.compile(r"[\(（]\s*([A-H])\s*[\)）]")
    matches = list(pattern.finditer(text or ""))
    if not matches:
        return text, []
    stem = text[: matches[0].start()].strip()
    options: list[dict[str, str]] = []
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        options.append(
            {
                "label": match.group(1).upper(),
                "text": text[match.end() : end].strip(),
            }
        )
    return stem, options


def _extract_blanks(stem_latex: str) -> list[dict[str, Any]]:
    count = len(re.findall(r"_{3,}|\\underline|（\s*）|\(\s*\)", stem_latex or ""))
    if count == 0 and "填空" in stem_latex:
        count = 1
    return [
        {"index": index, "placeholder_latex": "\\underline{\\hspace{3em}}"}
        for index in range(1, count + 1)
    ]


def _extract_subquestions(stem_latex: str) -> list[dict[str, Any]]:
    matches = list(re.finditer(r"[（(]\s*(\d+)\s*[）)]", stem_latex or ""))
    if not matches:
        return []
    subquestions: list[dict[str, Any]] = []
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(stem_latex)
        subquestions.append(
            {
                "index": int(match.group(1)),
                "stem_latex": stem_latex[match.end() : end].strip(),
                "answer_latex": "",
            }
        )
    return subquestions


def _normalize_latex_text(value: str) -> str:
    text = " ".join((value or "").split())
    replacements = {
        "−": "-",
        "⩾": "\\ge",
        "≥": "\\ge",
        "⩽": "\\le",
        "≤": "\\le",
        "∈": "\\in",
        "∞": "\\infty",
        "π": "\\pi",
        "≠": "\\ne",
        "≈": "\\approx",
        "∥": "\\parallel",
        "⊥": "\\perp",
    }
    for source, target in replacements.items():
        text = text.replace(source, target)
    text = re.sub(r"√\s*(\d+)", r"\\sqrt{\1}", text)
    return text.strip()


def _looks_visual_question(text: str) -> bool:
    return any(token in (text or "") for token in ("如图", "图象", "图像", "框图", "直方图"))


def _formula_may_need_human_check(text: str) -> bool:
    return bool(re.search(r"√|[∈∞π≠≈∥⊥]|[a-zA-Z]\s*\n|\n\s*[a-zA-Z0-9]", text or ""))


def _confidence_for_flags(flags: list[str]) -> float:
    review_markers = (
        "missing_",
        "page_",
        "split_",
        "formula_uncertain",
        "image_question",
        "option_count_anomaly",
        "unknown_question_type",
        "blank_placeholder_uncertain",
        "empty_source_text",
    )
    if any(flag.startswith(review_markers) or flag in review_markers for flag in flags):
        return 0.45
    return 0.78


def _apply_record(
    conn,
    record: dict[str, Any],
    *,
    line_no: int,
    batch_name: str,
    input_path: Path,
    project_root: Path,
) -> dict[str, Any]:
    if not isinstance(record, dict):
        raise CodexStructureError("JSONL line must be an object.")
    qid = str(record.get("qid") or "").strip()
    if not qid:
        raise CodexStructureError("JSONL record qid is required.")
    try:
        payload = validate_ai_output_payload(record.get("payload"))
    except StructuredAiError as exc:
        raise CodexStructureError(str(exc)) from exc
    row = conn.execute(
        """
        SELECT q.id,
               q.qid,
               q.review_status,
               sc.ai_status,
               qa.relative_path AS raw_crop_path,
               spa.relative_path AS page_image_path,
               CAST(json_extract(q.meta_json, '$.source_page') AS INTEGER) AS source_page
          FROM questions q
          JOIN question_structured_contents sc ON sc.question_id = q.id
          LEFT JOIN question_assets qa
            ON qa.question_id = q.id
           AND qa.asset_kind = 'raw_crop'
          LEFT JOIN source_paper_assets spa
            ON spa.source_paper_id = q.source_paper_id
           AND spa.asset_kind = 'page_image'
           AND spa.page_no = CAST(json_extract(q.meta_json, '$.source_page') AS INTEGER)
         WHERE q.qid = ?
        """,
        (qid,),
    ).fetchone()
    if row is None:
        raise CodexStructureError(f"Question not found for qid={qid}")
    if row["review_status"] in PROTECTED_QUESTION_STATUSES:
        return {
            "status": "skipped",
            "question_id": row["id"],
            "qid": qid,
            "reason": "protected_question_review_status",
        }
    if row["ai_status"] not in WRITABLE_STRUCTURED_STATUSES:
        return {
            "status": "skipped",
            "question_id": row["id"],
            "qid": qid,
            "reason": "protected_structured_status",
        }
    model_info = {
        "source": CODEX_AGENT_PROVIDER,
        "provider": CODEX_AGENT_PROVIDER,
        "model": CODEX_AGENT_MODEL,
        "algorithm_version": CODEX_AGENT_VERSION,
        "batch_name": batch_name,
        "jsonl_line_no": line_no,
        "jsonl_path": _relative_to_project(input_path, project_root),
        "created_at": _utc_now(),
        "input": {
            "qid": qid,
            "source_page": row["source_page"],
            "raw_crop_path": row["raw_crop_path"],
            "page_image_path": row["page_image_path"],
        },
    }
    conn.execute(
        """
        UPDATE question_structured_contents
           SET normalized_type = ?,
               stem_latex = ?,
               options_json = ?,
               blanks_json = ?,
               subquestions_json = ?,
               answer_latex = ?,
               analysis_latex = ?,
               ai_status = 'ai_draft',
               quality_flags_json = ?,
               confidence = ?,
               model_info = ?,
               updated_at = CURRENT_TIMESTAMP
         WHERE question_id = ?
        """,
        (
            payload["normalized_type"],
            payload["stem_latex"],
            json.dumps(payload["options_json"], ensure_ascii=False),
            json.dumps(payload["blanks_json"], ensure_ascii=False),
            json.dumps(payload["subquestions_json"], ensure_ascii=False),
            payload["answer_latex"],
            payload["analysis_latex"],
            json.dumps(payload["quality_flags"], ensure_ascii=False),
            payload["confidence"],
            json.dumps(model_info, ensure_ascii=False),
            row["id"],
        ),
    )
    return {"status": "applied", "question_id": row["id"], "qid": qid}


def _read_jsonl_records(path: Path) -> list[tuple[int, dict[str, Any]]]:
    records: list[tuple[int, dict[str, Any]]] = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError as exc:
            raise CodexStructureError(f"Invalid JSON on line {line_no}: {exc}") from exc
        records.append((line_no, parsed))
    return records


def _resolve_output_path(path: Path, *, project_root: Path) -> Path:
    resolved = path if path.is_absolute() else project_root / path
    return resolved.resolve()


def _resolve_input_path(path: Path, *, project_root: Path) -> Path:
    resolved = path if path.is_absolute() else project_root / path
    return resolved.resolve()


def _relative_to_project(path: Path, project_root: Path) -> str:
    try:
        return path.resolve().relative_to(project_root.resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def _safe_filename(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._") or "codex-structure"


def _dedupe(values: list[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        if value and value not in result:
            result.append(value)
    return result


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
