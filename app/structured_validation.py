from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .database import connect_database, initialize_database
from .structured_content import NORMALIZED_TYPES, initialize_structured_contents, parse_json_field


VALIDATION_VERSION = "stage10_validation_v2"
VALIDATION_INPUT_STATUSES = ("ai_draft",)
PROTECTED_STATUSES = ("human_reviewed",)
REVIEW_REQUIRED_QUALITY_FLAGS = {
    "empty_source_text",
    "formula_uncertain",
    "image_question_needs_manual_review",
    "missing_page_image",
    "missing_raw_crop",
    "option_count_anomaly",
    "page_duplicate_anchors",
    "page_flags_present",
    "page_warning_candidates",
    "question_review_status_protected",
    "split_warnings_present",
    "unknown_question_type",
    "latex_ambiguous_decimal_or_log",
    "latex_fraction_after_variable_suspicious",
    "latex_garbled_geometry_symbol",
    "latex_garbled_piecewise_or_symbol",
    "latex_implicit_exponent_unconverted",
    "latex_pi_trailing_number_suspicious",
    "latex_private_use_piecewise_symbol",
    "latex_sqrt_fraction_split_suspicious",
    "latex_sqrt_trailing_number_suspicious",
    "latex_unconverted_degree_symbol",
    "latex_unconverted_overline_symbol",
    "latex_unicode_math_symbol_unconverted",
    "latex_zero_denominator_suspicious",
    "blank_placeholder_inferred",
}
REVIEW_REQUIRED_QUALITY_PREFIXES = ("page_flag_", "split_warning_")


class StructuredValidationError(RuntimeError):
    """Raised when structured validation cannot run."""


def validate_structured_contents(
    *,
    db_path: Path | None = None,
    question_ids: tuple[int, ...] | None = None,
    limit: int = 100,
    statuses: tuple[str, ...] = VALIDATION_INPUT_STATUSES,
) -> dict[str, Any]:
    initialize_database(db_path)
    initialize_structured_contents(db_path=db_path)
    _validate_requested_statuses(statuses)

    with connect_database(db_path) as conn:
        rows = _load_validation_rows(
            conn,
            question_ids=question_ids,
            limit=limit,
            statuses=statuses,
        )
        results: list[dict[str, Any]] = []
        skipped: list[dict[str, Any]] = []
        for row in rows:
            if row["ai_status"] in PROTECTED_STATUSES:
                skipped.append({"question_id": row["question_id"], "reason": "protected_ai_status"})
                continue
            result = validate_structured_row(dict(row))
            _write_validation_result(conn, dict(row), result)
            results.append(
                {
                    "question_id": row["question_id"],
                    "qid": row["qid"],
                    "status": result["status"],
                    "flags": result["flags"],
                }
            )
        conn.commit()

    status_counts: dict[str, int] = {}
    for result in results:
        status_counts[result["status"]] = status_counts.get(result["status"], 0) + 1
    return {
        "status": "ok",
        "validated": len(results),
        "status_counts": status_counts,
        "skipped": skipped,
        "results": results,
        "validation_version": VALIDATION_VERSION,
    }


def validate_structured_row(row: dict[str, Any]) -> dict[str, Any]:
    flags: list[str] = []
    fatal_flags: list[str] = []
    existing_quality_flags = parse_json_field(row.get("quality_flags_json"), [])
    if not isinstance(existing_quality_flags, list):
        existing_quality_flags = []
    for quality_flag in existing_quality_flags:
        normalized_flag = str(quality_flag)
        if _quality_flag_requires_review(normalized_flag):
            flags.append(normalized_flag)

    normalized_type = str(row.get("normalized_type") or "unknown")
    if normalized_type not in NORMALIZED_TYPES:
        fatal_flags.append("unsupported_normalized_type")

    source_text = str(row.get("source_text") or "")
    stem_latex = str(row.get("stem_latex") or "")
    source_latex = str(row.get("source_latex") or "")
    if len(_compact_text(source_text)) < 10:
        flags.append("short_source_text")
    if len(_compact_text(stem_latex)) < 10:
        fatal_flags.append("empty_or_short_stem_latex")

    if not _latex_has_balanced_delimiters(stem_latex):
        fatal_flags.append("latex_unbalanced_delimiters")
    if source_latex and not _latex_has_balanced_delimiters(source_latex):
        flags.append("source_latex_unbalanced_delimiters")

    question_no_flag = _question_number_consistency_flag(row)
    if question_no_flag:
        flags.append(question_no_flag)
    if _anchor_count(source_text) > 1 or _anchor_count(stem_latex) > 1:
        flags.append("possible_cross_question_pollution")

    options = _json_list(row.get("options_json"), "options_json", fatal_flags)
    blanks = _json_list(row.get("blanks_json"), "blanks_json", fatal_flags)
    subquestions = _json_list(row.get("subquestions_json"), "subquestions_json", fatal_flags)

    if normalized_type in ("choice", "multiple_choice"):
        _validate_options(options, flags, fatal_flags)
    elif normalized_type == "blank":
        _validate_blanks(blanks, stem_latex, flags, fatal_flags)
    elif normalized_type == "solution":
        _validate_subquestions(subquestions, source_text, flags, fatal_flags)
    elif normalized_type == "unknown":
        flags.append("unknown_question_type")

    comparable_latex = _combined_structured_latex(
        stem_latex=stem_latex,
        options=options,
        blanks=blanks,
        subquestions=subquestions,
        answer_latex=str(row.get("answer_latex") or ""),
        analysis_latex=str(row.get("analysis_latex") or ""),
    )
    if _numbers_missing_from_stem(source_text, comparable_latex, str(row.get("question_no") or "")):
        flags.append("numbers_or_symbols_may_be_missing")
    elif _symbols_missing_from_stem(source_text, comparable_latex):
        flags.append("numbers_or_symbols_may_be_missing")
    flags.extend(_latex_quality_risk_flags(comparable_latex))

    flags = _dedupe(flags)
    fatal_flags = _dedupe(fatal_flags)
    if fatal_flags:
        status = "failed"
    elif flags:
        status = "needs_review"
    else:
        status = "ai_verified"
    return {
        "status": status,
        "flags": flags,
        "fatal_flags": fatal_flags,
    }


def latex_basic_renderable(text: str | None) -> bool:
    return _latex_has_balanced_delimiters(text or "")


def _load_validation_rows(
    conn,
    *,
    question_ids: tuple[int, ...] | None,
    limit: int,
    statuses: tuple[str, ...],
) -> list[dict[str, Any]]:
    params: list[Any] = []
    if question_ids:
        placeholders = ", ".join("?" for _ in question_ids)
        where_sql = f"WHERE q.id IN ({placeholders})"
        params.extend(question_ids)
    else:
        placeholders = ", ".join("?" for _ in statuses)
        where_sql = f"WHERE sc.ai_status IN ({placeholders})"
        params.extend(statuses)
    params.append(max(1, min(limit, 1000)))

    rows = conn.execute(
        f"""
        SELECT sc.*,
               q.qid,
               q.question_no,
               q.question_type
          FROM question_structured_contents sc
          JOIN questions q ON q.id = sc.question_id
         {where_sql}
         ORDER BY q.id
         LIMIT ?
        """,
        params,
    ).fetchall()
    return [dict(row) for row in rows]


def _write_validation_result(conn, row: dict[str, Any], result: dict[str, Any]) -> None:
    existing_flags = parse_json_field(row.get("quality_flags_json"), [])
    if not isinstance(existing_flags, list):
        existing_flags = []
    combined_flags = _dedupe(
        [str(flag) for flag in existing_flags]
        + result["flags"]
        + result["fatal_flags"]
    )
    model_info = parse_json_field(row.get("model_info"), {})
    if not isinstance(model_info, dict):
        model_info = {}
    model_info["last_validation"] = {
        "validation_version": VALIDATION_VERSION,
        "status": result["status"],
        "flags": result["flags"],
        "fatal_flags": result["fatal_flags"],
        "created_at": _utc_now(),
    }
    conn.execute(
        """
        UPDATE question_structured_contents
           SET ai_status = ?,
               quality_flags_json = ?,
               model_info = ?,
               updated_at = CURRENT_TIMESTAMP
         WHERE question_id = ?
        """,
        (
            result["status"],
            json.dumps(combined_flags, ensure_ascii=False),
            json.dumps(model_info, ensure_ascii=False),
            row["question_id"],
        ),
    )


def _validate_requested_statuses(statuses: tuple[str, ...]) -> None:
    if not statuses:
        raise StructuredValidationError("At least one input status is required.")
    allowed = {
        "unprocessed",
        "ai_draft",
        "ai_verified",
        "needs_review",
        "failed",
        "human_reviewed",
    }
    invalid = [status for status in statuses if status not in allowed]
    if invalid:
        raise StructuredValidationError(f"Unsupported validation status filter: {invalid}")


def _json_list(value: str | None, field_name: str, fatal_flags: list[str]) -> list[Any]:
    parsed = parse_json_field(value, None)
    if not isinstance(parsed, list):
        fatal_flags.append(f"{field_name}_not_list")
        return []
    return parsed


def _validate_options(
    options: list[Any],
    flags: list[str],
    fatal_flags: list[str],
) -> None:
    if len(options) < 2:
        flags.append("choice_options_incomplete")
        return
    labels: list[str] = []
    for option in options:
        if not isinstance(option, dict):
            fatal_flags.append("choice_option_not_object")
            continue
        label = str(option.get("label") or "").strip()
        text = str(option.get("text_latex") or option.get("text") or "").strip()
        if not label or not text:
            flags.append("choice_option_missing_label_or_text")
        labels.append(label.upper())
    if len(labels) != len(set(labels)):
        flags.append("choice_option_duplicate_labels")
    if len(options) < 4:
        flags.append("choice_options_less_than_four")


def _validate_blanks(
    blanks: list[Any],
    stem_latex: str,
    flags: list[str],
    fatal_flags: list[str],
) -> None:
    if not blanks and not re.search(r"_{3,}|\\underline|\\blank", stem_latex):
        flags.append("blank_missing_placeholder")
    for blank in blanks:
        if not isinstance(blank, dict):
            fatal_flags.append("blank_not_object")
            continue
        if "index" not in blank:
            flags.append("blank_missing_index")


def _validate_subquestions(
    subquestions: list[Any],
    source_text: str,
    flags: list[str],
    fatal_flags: list[str],
) -> None:
    source_has_subquestions = bool(re.search(r"[（(]\s*\d+\s*[）)]", source_text))
    if source_has_subquestions and not subquestions:
        flags.append("subquestions_missing")
    for subquestion in subquestions:
        if not isinstance(subquestion, dict):
            fatal_flags.append("subquestion_not_object")
            continue
        if not str(subquestion.get("stem_latex") or "").strip():
            flags.append("subquestion_missing_stem")


def _combined_structured_latex(
    *,
    stem_latex: str,
    options: list[Any],
    blanks: list[Any],
    subquestions: list[Any],
    answer_latex: str,
    analysis_latex: str,
) -> str:
    parts = [stem_latex, answer_latex, analysis_latex]
    for option in options:
        if isinstance(option, dict):
            parts.append(str(option.get("text_latex") or option.get("text") or ""))
    for blank in blanks:
        if isinstance(blank, dict):
            parts.append(str(blank.get("placeholder_latex") or ""))
    for subquestion in subquestions:
        if isinstance(subquestion, dict):
            parts.append(str(subquestion.get("stem_latex") or ""))
            parts.append(str(subquestion.get("answer_latex") or ""))
    return "\n".join(parts)


def _quality_flag_requires_review(flag: str) -> bool:
    return flag in REVIEW_REQUIRED_QUALITY_FLAGS or flag.startswith(
        REVIEW_REQUIRED_QUALITY_PREFIXES
    )


def _question_number_consistency_flag(row: dict[str, Any]) -> str | None:
    source_text = str(row.get("source_text") or "")
    question_no = str(row.get("question_no") or "").strip()
    if not question_no:
        return "question_no_missing"
    match = re.search(r"(?m)^\s*(\d{1,3})\s*[\.\．、]", source_text)
    if match and match.group(1) != question_no:
        return "question_no_mismatch"
    return None


def _anchor_count(text: str) -> int:
    return len(re.findall(r"(?m)^\s*\d{1,3}\s*[\.\．、]", text or ""))


def _latex_has_balanced_delimiters(text: str) -> bool:
    braces = 0
    index = 0
    while index < len(text):
        char = text[index]
        escaped = index > 0 and text[index - 1] == "\\"
        if char == "{" and not escaped:
            braces += 1
        elif char == "}" and not escaped:
            braces -= 1
            if braces < 0:
                return False
        index += 1
    if braces != 0:
        return False
    unescaped_dollars = len(re.findall(r"(?<!\\)\$", text))
    if unescaped_dollars % 2 != 0:
        return False
    if text.count("\\left") != text.count("\\right"):
        return False
    return True


def _numbers_missing_from_stem(source_text: str, stem_latex: str, question_no: str) -> bool:
    source_numbers = set(re.findall(r"\d+(?:\.\d+)?", source_text or ""))
    stem_numbers = set(re.findall(r"\d+(?:\.\d+)?", stem_latex or ""))
    source_numbers.discard(question_no)
    return bool(source_numbers - stem_numbers)


def _symbols_missing_from_stem(source_text: str, stem_latex: str) -> bool:
    latex_equivalents = {
        "π": "\\pi",
        "√": "\\sqrt",
        "∠": "\\angle",
        "⊥": "\\perp",
        "∥": "\\parallel",
        "≤": "\\le",
        "⩽": "\\le",
        "≥": "\\ge",
        "⩾": "\\ge",
        "≈": "\\approx",
        "≠": "\\ne",
        "∞": "\\infty",
    }
    target = stem_latex or ""
    for symbol in set(source_text or "") & set(latex_equivalents):
        if symbol not in target and latex_equivalents[symbol] not in target:
            return True
    return False


def _latex_quality_risk_flags(value: str) -> list[str]:
    flags: list[str] = []
    text = value or ""
    compact = re.sub(r"\s+", "", value or "")
    if not compact:
        return flags
    if re.search(r"(?<!\\)[A-Za-z]\s*\\frac\{2\}\{[^{}]+\}", text):
        flags.append("latex_fraction_after_variable_suspicious")
    if re.search(r"\\pi\s*\d", text):
        flags.append("latex_pi_trailing_number_suspicious")
    if re.search(r"\\sqrt\{[^{}]+\}\s*\d", text):
        flags.append("latex_sqrt_trailing_number_suspicious")
    if re.search(r"\\sqrt\{[A-Za-z]\}\s*\\frac\{\d+\}\{\d+\}", text):
        flags.append("latex_sqrt_fraction_split_suspicious")
    if re.search(r"\\frac\{[^{}]+\}\{0+\}", text):
        flags.append("latex_zero_denominator_suspicious")
    if any("\uf8f1" <= char <= "\uf8f4" for char in text):
        flags.append("latex_private_use_piecewise_symbol")
    if "¯" in compact:
        flags.append("latex_unconverted_overline_symbol")
    if "◦" in compact:
        flags.append("latex_unconverted_degree_symbol")
    if re.search(r"#\s*»|#\s*&raquo;", text):
        flags.append("latex_garbled_geometry_symbol")
    if any(token in text for token in ("�", "锛?", "鈥")):
        flags.append("latex_garbled_piecewise_or_symbol")
    if re.search(r"(?:^|[^A-Za-z])(?:x|y|z|a|b|c|m|n|r|t)\s*\d", text):
        flags.append("latex_implicit_exponent_unconverted")
    if re.search(r"\)\s*\d", text):
        flags.append("latex_implicit_exponent_unconverted")
    if re.search(r"\blog\s*\d+(?:\.\d+)?", text) or re.search(r"\d+\.\d+\.\d+", compact):
        flags.append("latex_ambiguous_decimal_or_log")
    unicode_math_symbols = set("∁∪∩∅∑∫∂∆Δ∧∨∈∉√⊥∥≤≥≈≠∞π∠⊂⊆")
    if set(compact) & unicode_math_symbols:
        flags.append("latex_unicode_math_symbol_unconverted")
    return _dedupe(flags)


def _compact_text(value: str) -> str:
    return re.sub(r"\s+", "", value or "")


def _dedupe(values: list[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        if value and value not in result:
            result.append(value)
    return result


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
