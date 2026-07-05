from __future__ import annotations

import json
import re
from html import escape
from typing import Any

from .structured_content import normalize_question_type, parse_json_field


VERIFIED_STRUCTURED_STATUSES = ("ai_verified", "human_reviewed")
EXPORT_USABLE_USABILITY_STATUSES = ("strict_structured", "visual_fallback")
EXPORT_READY_QUALITY_STATUSES = ("export_ready_structured", "export_ready_visual")
PAPER_SECTION_ORDER = ("choice", "multiple_choice", "blank", "solution", "unknown")
PAPER_SECTION_TITLES = {
    "choice": "一、单项选择题",
    "multiple_choice": "二、多项选择题",
    "blank": "三、填空题",
    "solution": "四、解答题",
    "unknown": "五、其他题型",
}
MATH_RENDERER_HEAD_HTML = r"""
<style id="local-math-renderer-style">
  .math-rendered { display: inline-flex; align-items: center; gap: 0.08em; vertical-align: baseline; font-family: "Cambria Math", "Times New Roman", serif; }
  .math-frac { display: inline-grid; grid-template-rows: auto auto; align-items: center; justify-items: center; vertical-align: middle; margin: 0 0.12em; line-height: 1.05; }
  .math-frac-num { border-bottom: 1px solid currentColor; padding: 0 0.18em 0.08em; }
  .math-frac-den { padding: 0.08em 0.18em 0; }
  .math-sqrt { display: inline-flex; align-items: stretch; margin: 0 0.08em; }
  .math-sqrt-radicand { border-top: 1px solid currentColor; padding: 0 0.12em; }
  .math-rendered sup, .math-rendered sub { font-size: 0.72em; line-height: 0; }
</style>
<script id="local-math-renderer">
(function () {
  function escapeHtml(value) {
    return String(value || "").replace(/[&<>"']/g, function (ch) {
      return {"&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;"}[ch];
    });
  }
  function renderMath(latex) {
    var html = escapeHtml(latex)
      .replace(/\\mathbb\{R\}/g, "ℝ")
      .replace(/\\infty/g, "∞")
      .replace(/\\ge/g, "≥")
      .replace(/\\le/g, "≤")
      .replace(/\\ne/g, "≠")
      .replace(/\\approx/g, "≈")
      .replace(/\\in/g, "∈")
      .replace(/\\pi/g, "π");
    html = html.replace(/\\frac\{([^{}]+)\}\{([^{}]+)\}/g, '<span class="math-frac"><span class="math-frac-num">$1</span><span class="math-frac-den">$2</span></span>');
    html = html.replace(/\\sqrt\{([^{}]+)\}/g, '<span class="math-sqrt">√<span class="math-sqrt-radicand">$1</span></span>');
    html = html.replace(/([A-Za-z0-9)\]])\^\{([^{}]+)\}/g, "$1<sup>$2</sup>");
    html = html.replace(/([A-Za-z0-9)\]])\^(-?\d+|[A-Za-z])/g, "$1<sup>$2</sup>");
    html = html.replace(/([A-Za-z0-9)\]])_\{([^{}]+)\}/g, "$1<sub>$2</sub>");
    html = html.replace(/([A-Za-z0-9)\]])_(-?\d+|[A-Za-z])/g, "$1<sub>$2</sub>");
    return html;
  }
  document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll("[data-local-math]").forEach(function (node) {
      node.innerHTML = renderMath(node.getAttribute("data-latex") || node.textContent || "");
      node.classList.add("math-rendered-js");
    });
  });
})();
</script>
"""


def attach_structured_contents(
    questions: list[dict[str, Any]],
    structured_by_question_id: dict[int, dict[str, Any]],
) -> list[dict[str, Any]]:
    for question in questions:
        question["structured_content"] = structured_by_question_id.get(int(question["id"]))
    return questions


def structured_content_json_text(structured: dict[str, Any] | None) -> str:
    if not structured:
        return "{}"
    payload = {
        "normalized_type": structured.get("normalized_type"),
        "stem_latex": structured.get("stem_latex"),
        "options_json": parse_json_field(structured.get("options_json"), []),
        "blanks_json": parse_json_field(structured.get("blanks_json"), []),
        "subquestions_json": parse_json_field(structured.get("subquestions_json"), []),
        "answer_latex": structured.get("answer_latex"),
        "analysis_latex": structured.get("analysis_latex"),
        "ai_status": structured.get("ai_status"),
        "quality_flags_json": parse_json_field(structured.get("quality_flags_json"), []),
        "confidence": structured.get("confidence"),
        "model_info": parse_json_field(structured.get("model_info"), {}),
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def math_renderer_head_html() -> str:
    return MATH_RENDERER_HEAD_HTML


def paper_type_key(question: dict[str, Any]) -> str:
    structured = question.get("structured_content")
    if structured and structured.get("normalized_type") in PAPER_SECTION_ORDER:
        return str(structured.get("normalized_type"))
    normalized = normalize_question_type(str(question.get("question_type") or ""))
    return normalized if normalized in PAPER_SECTION_ORDER else "unknown"


def build_paper_sections(questions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {key: [] for key in PAPER_SECTION_ORDER}
    for question in questions:
        grouped[paper_type_key(question)].append(question)

    sections: list[dict[str, Any]] = []
    number = 1
    for section_key in PAPER_SECTION_ORDER:
        items = []
        for question in grouped[section_key]:
            items.append({"number": number, "question": question})
            number += 1
        if items:
            sections.append(
                {
                    "key": section_key,
                    "title": PAPER_SECTION_TITLES[section_key],
                    "items": items,
                }
            )
    return sections


def render_printable_paper_html(
    questions: list[dict[str, Any]],
    *,
    rejected: list[dict[str, Any]] | None = None,
    export: bool = True,
    title: str = "可打印试卷",
    basket_url: str = "/paper-basket",
    export_url: str = "/paper-export",
    save_url: str = "/paper-export/save",
    asset_url_mode: str = "flask",
) -> str:
    sections = build_paper_sections(questions)
    rejected_html = _render_rejected_summary(rejected or [])
    toolbar = ""
    if not export:
        toolbar = f"""
    <div class="toolbar">
      <a href="{escape(basket_url, quote=True)}">返回组卷篮</a>
      <a href="{escape(export_url, quote=True)}">导出 HTML</a>
      <form method="post" action="{escape(save_url, quote=True)}">
        <button type="submit">保存 HTML</button>
      </form>
      <a href="javascript:window.print()">打印</a>
    </div>
"""
    if not questions:
        body_html = '<div class="empty">组卷篮为空。</div>'
    else:
        rendered_sections = []
        for section in sections:
            rendered_items = "".join(
                render_question_for_print_html(
                    item["question"],
                    item["number"],
                    asset_url_mode=asset_url_mode,
                )
                for item in section["items"]
            )
            rendered_sections.append(
                f'<section class="paper-section paper-section-{escape(section["key"])}">'
                f'<h2>{escape(section["title"])}</h2>{rendered_items}</section>'
            )
        body_html = "".join(rendered_sections)

    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{escape(title)}</title>
  <style>
    :root {{ color-scheme: light; font-family: "Segoe UI", Arial, sans-serif; }}
    body {{ margin: 0; background: #ffffff; color: #111827; }}
    main {{ max-width: 820px; margin: 0 auto; padding: 28px; }}
    .toolbar {{ display: flex; gap: 12px; margin-bottom: 20px; }}
    .toolbar form {{ display: inline; }}
    a {{ color: #1d4ed8; }}
    h1 {{ text-align: center; font-size: 26px; margin: 8px 0 24px; }}
    h2 {{ font-size: 19px; margin: 28px 0 8px; padding-bottom: 6px; border-bottom: 2px solid #111827; }}
    article {{ break-inside: avoid; padding: 16px 0; border-top: 1px solid #d1d5db; }}
    h2 + article {{ border-top: 0; }}
    .meta {{ color: #4b5563; font-size: 14px; margin-bottom: 10px; }}
    .stem {{ white-space: pre-wrap; line-height: 1.65; font-size: 16px; }}
    .status-badge, .source-note {{ display: inline-block; margin: 4px 0 10px; border: 1px solid #cbd5e1; border-radius: 6px; padding: 3px 7px; font-size: 12px; color: #475569; background: #f8fafc; }}
    .options {{ list-style: none; padding: 0; margin: 12px 0; display: grid; gap: 8px 18px; }}
    .options-4 {{ grid-template-columns: repeat(4, minmax(0, 1fr)); }}
    .options-2 {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
    .options-1 {{ grid-template-columns: 1fr; }}
    .option-label {{ font-weight: 600; }}
    .blank-line {{ display: inline-block; min-width: 140px; border-bottom: 1px solid #111827; height: 1em; }}
    .subquestions {{ padding-left: 24px; line-height: 1.65; }}
    .answer, .analysis {{ margin-top: 12px; }}
    .answer-space {{ min-height: 96px; border: 1px dashed #9ca3af; margin-top: 14px; }}
    .answer-space-solution {{ min-height: 180px; }}
    .visual-fallback-image {{ display: block; max-width: 100%; height: auto; border: 1px solid #d1d5db; background: white; margin-top: 8px; }}
    .empty {{ border: 1px solid #e5e7eb; padding: 18px; }}
    @media print {{
      .toolbar {{ display: none; }}
      main {{ max-width: none; padding: 0; }}
      body {{ margin: 12mm; }}
      article {{ page-break-inside: avoid; }}
    }}
  </style>
  {math_renderer_head_html()}
</head>
<body>
<main>
  {toolbar}
  <h1>{escape(title)}</h1>
  {rejected_html}
  {body_html}
</main>
</body>
</html>
"""


def render_structured_preview_html(
    question: dict[str, Any],
    structured: dict[str, Any] | None,
) -> str:
    return render_question_for_print_html(
        {**question, "structured_content": structured},
        index=None,
        include_source=False,
    )


def render_question_for_print_html(
    question: dict[str, Any],
    index: int | None = None,
    *,
    include_source: bool = True,
    asset_url_mode: str = "flask",
) -> str:
    structured = question.get("structured_content")
    usability = question.get("usability_state")
    export_quality = question.get("export_quality_state")
    usability_status = usability.get("usability_status") if usability else None
    export_quality_status = (
        export_quality.get("export_quality_status") if export_quality else None
    )
    status = structured.get("ai_status") if structured else "missing"
    prefix = f"{index}. " if index is not None else ""
    source_text = (
        question.get("source_label")
        or question.get("paper_name")
        or question.get("source_title")
        or ""
    )
    source_confidence = question.get("source_confidence")
    source_suffix = f" / source:{source_confidence}" if source_confidence else ""
    meta = (
        f"{prefix}{escape(str(question.get('question_type') or '题目'))}"
        f" / {escape(str(source_text))}"
        f" / {escape(str(question.get('page_range') or ''))}"
        f" / {escape(str(question.get('qid') or ''))}"
        f"{escape(source_suffix)}"
    )
    if export_quality_status == "export_ready_visual":
        return _render_visual_fallback_question(
            question,
            meta=meta,
            include_source=include_source,
            asset_url_mode=asset_url_mode,
            source_label="export_ready_visual",
        )

    if export_quality_status and export_quality_status not in EXPORT_READY_QUALITY_STATUSES:
        body = _render_candidate_body(question, status)
        return (
            f'<article class="question export-quality-status-{escape(str(export_quality_status))}">'
            f'<div class="meta">{meta}</div>'
            f'<div class="status-badge">excluded:{escape(str(export_quality_status))}</div>'
            f"{body}</article>"
        )

    if not export_quality_status and usability_status == "visual_fallback":
        return _render_visual_fallback_question(
            question,
            meta=meta,
            include_source=include_source,
            asset_url_mode=asset_url_mode,
            source_label="visual_fallback",
        )

    if usability_status and usability_status not in EXPORT_USABLE_USABILITY_STATUSES:
        body = _render_candidate_body(question, status)
        return (
            f'<article class="question usability-status-{escape(str(usability_status))}">'
            f'<div class="meta">{meta}</div>'
            f'<div class="status-badge">excluded:{escape(str(usability_status))}</div>'
            f"{body}</article>"
        )

    if not structured or status not in VERIFIED_STRUCTURED_STATUSES:
        body = _render_candidate_body(question, status)
        return f'<article class="question structured-status-{escape(str(status))}"><div class="meta">{meta}</div>{body}</article>'

    normalized_type = structured.get("normalized_type") or "unknown"
    stem_latex = structured.get("stem_latex") or question.get("stem_text") or ""
    parts = [
        f'<article class="question structured-status-{escape(str(status))} structured-type-{escape(str(normalized_type))}">',
        f'<div class="meta">{meta} / structured:{escape(str(status))}</div>',
        f'<div class="stem latex-block">{_render_latex_lines(stem_latex)}</div>',
    ]
    if normalized_type in ("choice", "multiple_choice"):
        parts.append(_render_options(parse_json_field(structured.get("options_json"), [])))
    elif normalized_type == "blank":
        parts.append(_render_blanks(parse_json_field(structured.get("blanks_json"), [])))
    elif normalized_type == "solution":
        parts.append(_render_subquestions(parse_json_field(structured.get("subquestions_json"), [])))
        parts.append('<div class="answer-space answer-space-solution"></div>')

    answer_latex = structured.get("answer_latex")
    analysis_latex = structured.get("analysis_latex")
    if answer_latex:
        parts.append(f'<div class="answer"><strong>答案</strong><div>{_render_latex_lines(answer_latex)}</div></div>')
    if analysis_latex:
        parts.append(f'<div class="analysis"><strong>解析</strong><div>{_render_latex_lines(analysis_latex)}</div></div>')
    if include_source:
        if export_quality_status == "export_ready_structured":
            source_label = "export_ready_structured"
        elif usability_status == "strict_structured":
            source_label = "strict_structured"
        else:
            source_label = f"structured:{status}"
        parts.append(f'<div class="source-note">source:{escape(str(source_label))}</div>')
    parts.append("</article>")
    return "".join(parts)


def _render_visual_fallback_question(
    question: dict[str, Any],
    *,
    meta: str,
    include_source: bool,
    asset_url_mode: str,
    source_label: str,
) -> str:
    image_src = _asset_src(str(question.get("raw_crop_path") or ""), asset_url_mode)
    alt = escape(str(question.get("qid") or "visual fallback question"), quote=True)
    parts = [
        f'<article class="question source-{escape(source_label)}">',
        f'<div class="meta">{meta} / {escape(source_label)}</div>',
        f'<div class="status-badge">source:{escape(source_label)}</div>',
    ]
    if image_src:
        parts.append(
            f'<img class="visual-fallback-image" src="{escape(image_src, quote=True)}" alt="{alt}">'
        )
    else:
        parts.append(_render_candidate_body(question, "visual_fallback_missing_image"))
    question_type = paper_type_key(question)
    if question_type == "blank":
        parts.append('<div class="blank-line"></div>')
    elif question_type == "solution":
        parts.append('<div class="answer-space answer-space-solution"></div>')
    if include_source:
        parts.append(f'<div class="source-note">source:{escape(source_label)}</div>')
    parts.append("</article>")
    return "".join(parts)


def _render_rejected_summary(rejected: list[dict[str, Any]]) -> str:
    if not rejected:
        return ""
    items = []
    for row in rejected:
        qid = row.get("qid") or row.get("question_id") or ""
        status = row.get("export_quality_status") or row.get("usability_status") or "unclassified"
        reasons = row.get("blocking_reasons") or row.get("quality_flags") or []
        if isinstance(reasons, list):
            reason_text = ", ".join(str(reason) for reason in reasons if reason)
        else:
            reason_text = str(reasons)
        items.append(
            "<li>"
            f"{escape(str(qid))}: {escape(str(status))}"
            f"{' / ' + escape(reason_text) if reason_text else ''}"
            "</li>"
        )
    return (
        '<section class="export-rejections">'
        '<h2>已排除题目</h2>'
        '<ul>'
        + "".join(items)
        + "</ul></section>"
    )


def _render_candidate_body(question: dict[str, Any], status: str) -> str:
    stem = question.get("stem_text") or ""
    answer_space = ""
    question_type = paper_type_key(question)
    if question_type == "blank":
        answer_space = '<div class="blank-line"></div>'
    elif question_type == "solution":
        answer_space = '<div class="answer-space answer-space-solution"></div>'
    return (
        f'<div class="status-badge">candidate:{escape(str(status))}</div>'
        f'<div class="stem candidate-stem">{_escaped_linebreaks(stem)}</div>'
        f"{answer_space}"
    )


def _render_options(options: Any) -> str:
    if not isinstance(options, list) or not options:
        return '<div class="status-badge">options:missing</div>'
    option_lengths = [
        len(str(option.get("text_latex") or option.get("text") or ""))
        for option in options
        if isinstance(option, dict)
    ]
    max_len = max(option_lengths) if option_lengths else 0
    columns = 4 if max_len <= 12 else 2 if max_len <= 32 else 1
    items = []
    for option in options:
        if not isinstance(option, dict):
            continue
        label = escape(str(option.get("label") or ""))
        text = _render_latex_lines(str(option.get("text_latex") or option.get("text") or ""))
        items.append(f'<li><span class="option-label">{label}.</span> {text}</li>')
    return f'<ol class="options options-{columns}">{"".join(items)}</ol>'


def _render_blanks(blanks: Any) -> str:
    if not isinstance(blanks, list) or not blanks:
        return '<div class="blank-line"></div>'
    items = []
    for blank in blanks:
        label = ""
        if isinstance(blank, dict) and blank.get("index") is not None:
            label = f'{escape(str(blank.get("index")))}. '
        items.append(f'<li>{label}<span class="blank-line"></span></li>')
    return f'<ol class="blanks">{"".join(items)}</ol>'


def _render_subquestions(subquestions: Any) -> str:
    if not isinstance(subquestions, list) or not subquestions:
        return ""
    items = []
    for subquestion in subquestions:
        if not isinstance(subquestion, dict):
            continue
        index = escape(str(subquestion.get("index") or ""))
        stem = _render_latex_lines(str(subquestion.get("stem_latex") or ""))
        answer = str(subquestion.get("answer_latex") or "")
        answer_html = f'<div class="sub-answer">{_render_latex_lines(answer)}</div>' if answer else ""
        items.append(f'<li><strong>({index})</strong> <span>{stem}</span>{answer_html}</li>')
    return f'<ol class="subquestions">{"".join(items)}</ol>'


def _render_latex_lines(value: str) -> str:
    return "<br>".join(_render_latex_inline(line) for line in str(value).splitlines())


def _render_latex_inline(value: str) -> str:
    text = str(value)
    matches = list(re.finditer(r"\$(.+?)\$", text))
    if not matches and re.search(r"\\(?:frac|sqrt|infty|in|ge|le|ne|approx|pi|mathbb)", text):
        return _math_span(text)
    parts: list[str] = []
    cursor = 0
    for match in matches:
        parts.append(escape(text[cursor : match.start()]))
        parts.append(_math_span(match.group(1)))
        cursor = match.end()
    parts.append(escape(text[cursor:]))
    return "".join(parts)


def _math_span(latex: str) -> str:
    rendered = _render_math_segment(latex)
    return (
        '<span class="math-rendered" data-local-math="1" '
        f'data-latex="{escape(latex, quote=True)}">{rendered}</span>'
    )


def _render_math_segment(latex: str) -> str:
    html = escape(latex)
    while True:
        next_html = re.sub(
            r"\\frac\{([^{}]+)\}\{([^{}]+)\}",
            lambda match: (
                '<span class="math-frac">'
                f'<span class="math-frac-num">{_render_math_segment(match.group(1))}</span>'
                f'<span class="math-frac-den">{_render_math_segment(match.group(2))}</span>'
                "</span>"
            ),
            html,
        )
        if next_html == html:
            break
        html = next_html
    html = re.sub(
        r"\\sqrt\{([^{}]+)\}",
        lambda match: (
            '<span class="math-sqrt">√'
            f'<span class="math-sqrt-radicand">{_render_math_segment(match.group(1))}</span>'
            "</span>"
        ),
        html,
    )
    replacements = {
        r"\mathbb{R}": "ℝ",
        r"\infty": "∞",
        r"\ge": "≥",
        r"\le": "≤",
        r"\ne": "≠",
        r"\approx": "≈",
        r"\in": "∈",
        r"\pi": "π",
        r"\parallel": "∥",
        r"\perp": "⊥",
    }
    for source, target in replacements.items():
        html = html.replace(source, target)
    html = re.sub(r"([A-Za-z0-9)\]])\^\{([^{}]+)\}", r"\1<sup>\2</sup>", html)
    html = re.sub(r"([A-Za-z0-9)\]])\^(-?\d+|[A-Za-z])", r"\1<sup>\2</sup>", html)
    html = re.sub(r"([A-Za-z0-9)\]])_\{([^{}]+)\}", r"\1<sub>\2</sub>", html)
    html = re.sub(r"([A-Za-z0-9)\]])_(-?\d+|[A-Za-z])", r"\1<sub>\2</sub>", html)
    return html


def _escaped_linebreaks(value: str) -> str:
    return "<br>".join(escape(str(value)).splitlines())


def _asset_src(relative_path: str, mode: str) -> str:
    cleaned = str(relative_path or "").replace("\\", "/").lstrip("/")
    if not cleaned:
        return ""
    if mode == "export_relative":
        if cleaned.startswith("data/"):
            cleaned = cleaned[len("data/") :]
        return "../" + cleaned
    if mode == "project_relative":
        return cleaned
    return "/assets/" + cleaned
