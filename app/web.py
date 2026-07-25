from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path

from flask import (
    Flask,
    Response,
    abort,
    jsonify,
    redirect,
    render_template_string,
    request,
    send_file,
    session,
    url_for,
)

from .ai_suggestions import (
    AiSuggestionError,
    accept_ai_suggestion,
    list_ai_suggestions,
    reject_ai_suggestion,
)
from .config import get_project_paths
from .exports import save_html_export
from .export_selection import ExportSelectionService
from .export_quality import (
    attach_export_quality_states,
    classify_export_quality_states,
    get_export_quality_by_question_ids,
)
from .health import build_health_report
from .import_batches import ImportBatchError, get_import_batch, list_import_batches
from .question_repository import (
    EDIT_STATUSES,
    LIST_STATUSES,
    STAGE14_QUEUE_FILTERS,
    get_question_detail,
    get_questions_by_ids,
    list_question_ids,
    list_questions,
    update_question_from_form,
)
from .paper_render import PaperRenderService
from .stage10 import (
    Stage10Error,
    list_structured_review_items,
    update_structured_review_status,
)
from .stage11 import (
    attach_usability_states,
    classify_usability_states,
    get_usability_states_by_question_ids,
)
from .structured_content import (
    get_structured_content,
    get_structured_contents_by_question_ids,
)
from .structured_render import (
    attach_structured_contents,
    math_renderer_head_html,
    render_question_for_print_html,
    render_structured_preview_html,
    structured_content_json_text,
)
from .safety.workspace_io import WorkspaceIOError, get_workspace_io


BASKET_SESSION_KEY = "paper_basket_question_ids"


def _basket_ids() -> list[int]:
    ids: list[int] = []
    for value in session.get(BASKET_SESSION_KEY, []):
        try:
            question_id = int(value)
        except (TypeError, ValueError):
            continue
        if question_id > 0 and question_id not in ids:
            ids.append(question_id)
    return ids


def _save_basket_ids(question_ids: list[int]) -> None:
    session[BASKET_SESSION_KEY] = question_ids
    session.modified = True


def _safe_next_url(value: str | None, fallback: str) -> str:
    if value and value.startswith("/") and not value.startswith("//"):
        return value
    return fallback


def _basket_questions(db_path: Path) -> list[dict]:
    ids = _basket_ids()
    questions = get_questions_by_ids(ids, db_path=db_path)
    structured = get_structured_contents_by_question_ids(ids, db_path=db_path)
    attach_structured_contents(questions, structured)
    usability = get_usability_states_by_question_ids(ids, db_path=db_path)
    attach_usability_states(questions, usability)
    export_quality = get_export_quality_by_question_ids(ids, db_path=db_path)
    attach_export_quality_states(questions, export_quality)
    existing_ids = [int(question["id"]) for question in questions]
    if existing_ids != ids:
        _save_basket_ids(existing_ids)
    return questions


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def _optional_positive_int(value: str | None, *, field_name: str) -> int | None:
    cleaned = (value or "").strip()
    if not cleaned:
        return None
    try:
        parsed = int(cleaned)
    except ValueError as exc:
        raise ValueError(f"{field_name} must be an integer") from exc
    if parsed <= 0:
        raise ValueError(f"{field_name} must be positive")
    return parsed


def _question_context(source) -> dict:
    limit_value = str(source.get("limit", "100") or "100")
    try:
        limit = int(limit_value)
    except ValueError as exc:
        raise ValueError("limit must be an integer") from exc
    batch_id = _optional_positive_int(str(source.get("batch_id", "")), field_name="batch_id")
    return {
        "status": str(source.get("status", "pending") or "pending"),
        "question_type": str(source.get("question_type", "") or ""),
        "page_range": str(source.get("page_range", "") or ""),
        "q": str(source.get("q", "") or ""),
        "limit": max(1, min(limit, 5000)),
        "limit_text": limit_value,
        "batch_id": batch_id,
        "batch_id_text": "" if batch_id is None else str(batch_id),
        "issue_only": _truthy(str(source.get("issue_only", ""))),
        "stage14_queue": str(source.get("stage14_queue", "all") or "all"),
    }


def _structured_review_context(source) -> dict:
    limit_value = str(source.get("limit", "100") or "100")
    try:
        limit = int(limit_value)
    except ValueError as exc:
        raise ValueError("limit must be an integer") from exc
    page = _optional_positive_int(str(source.get("page", "")), field_name="page")
    return {
        "ai_status": str(source.get("ai_status", "needs_review") or "needs_review"),
        "quality_flag": str(source.get("quality_flag", "") or ""),
        "normalized_type": str(source.get("normalized_type", "all") or "all"),
        "page": page,
        "page_text": "" if page is None else str(page),
        "high_risk": _truthy(str(source.get("high_risk", ""))),
        "usability_status": str(source.get("usability_status", "all") or "all"),
        "risk_type": str(source.get("risk_type", "") or ""),
        "render_mode": str(source.get("render_mode", "all") or "all"),
        "stage14_queue": str(source.get("stage14_queue", "all") or "all"),
        "stage14_reason": str(source.get("stage14_reason", "") or ""),
        "limit": max(1, min(limit, 500)),
        "limit_text": limit_value,
    }


def _structured_review_query_args(context: dict) -> dict[str, str]:
    args = {
        "ai_status": context["ai_status"],
        "normalized_type": context["normalized_type"],
        "limit": str(context["limit"]),
    }
    if context["quality_flag"]:
        args["quality_flag"] = context["quality_flag"]
    if context["page"] is not None:
        args["page"] = str(context["page"])
    if context["high_risk"]:
        args["high_risk"] = "1"
    if context["usability_status"] != "all":
        args["usability_status"] = context["usability_status"]
    if context["risk_type"]:
        args["risk_type"] = context["risk_type"]
    if context["render_mode"] != "all":
        args["render_mode"] = context["render_mode"]
    if context["stage14_queue"] != "all":
        args["stage14_queue"] = context["stage14_queue"]
    if context["stage14_reason"]:
        args["stage14_reason"] = context["stage14_reason"]
    return args


def _context_query_args(context: dict) -> dict[str, str]:
    args: dict[str, str] = {"status": context["status"], "limit": str(context["limit"])}
    for key in ("question_type", "page_range", "q"):
        if context[key]:
            args[key] = context[key]
    if context["batch_id"] is not None:
        args["batch_id"] = str(context["batch_id"])
    if context["issue_only"]:
        args["issue_only"] = "1"
    if context.get("stage14_queue") and context["stage14_queue"] != "all":
        args["stage14_queue"] = context["stage14_queue"]
    return args


def _issue_tags_text(meta_json: str | None) -> str:
    try:
        meta = json.loads(meta_json or "{}")
    except json.JSONDecodeError:
        return ""
    tags = meta.get("issue_tags", [])
    if isinstance(tags, list):
        return ", ".join(str(tag) for tag in tags)
    if tags:
        return str(tags)
    return ""


LIST_TEMPLATE = """
<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>题目复核队列</title>
  <style>
    :root { color-scheme: light; font-family: "Segoe UI", Arial, sans-serif; }
    body { margin: 0; background: #f6f7f9; color: #1f2937; }
    main { max-width: 1180px; margin: 0 auto; padding: 24px; }
    h1 { font-size: 24px; margin: 0 0 18px; }
    form.filters { display: grid; grid-template-columns: repeat(8, minmax(0, 1fr)) auto; gap: 10px; align-items: end; margin-bottom: 16px; }
    label { display: grid; gap: 5px; font-size: 13px; color: #4b5563; }
    input, select, textarea { border: 1px solid #cbd5e1; border-radius: 6px; padding: 8px 10px; background: white; color: #111827; font: inherit; }
    button, .button { border: 1px solid #1f2937; border-radius: 6px; padding: 8px 12px; background: #1f2937; color: white; text-decoration: none; font: inherit; cursor: pointer; }
    nav { display: flex; gap: 12px; margin-bottom: 16px; }
    form.inline { display: inline; }
    form.inline button { padding: 5px 8px; margin-top: 6px; }
    .count { margin: 8px 0 12px; color: #4b5563; }
    table { width: 100%; border-collapse: collapse; background: white; border: 1px solid #e5e7eb; }
    th, td { border-bottom: 1px solid #e5e7eb; padding: 10px; text-align: left; vertical-align: top; }
    th { background: #eef2f7; font-size: 13px; color: #374151; }
    td.preview { max-width: 460px; white-space: pre-wrap; }
    .status { font-weight: 600; }
    @media (max-width: 900px) {
      main { padding: 16px; }
      form.filters { grid-template-columns: 1fr 1fr; }
      table { font-size: 14px; }
    }
  </style>
</head>
<body>
<main>
  <h1>题目复核队列</h1>
  <nav>
    <a href="{{ url_for('questions') }}">题目列表</a>
    <a href="{{ url_for('batches') }}">批次</a>
    <a href="{{ url_for('structured_review') }}">Structured Review</a>
    <a href="{{ url_for('paper_basket') }}">组卷篮（{{ basket_count }}）</a>
  </nav>
  <form class="filters" method="get" action="{{ url_for('questions') }}">
    <label>状态
      <select name="status">
        <option value="pending" {% if filters.status == 'pending' %}selected{% endif %}>pending</option>
        <option value="reviewed" {% if filters.status == 'reviewed' %}selected{% endif %}>reviewed</option>
        <option value="rejected" {% if filters.status == 'rejected' %}selected{% endif %}>rejected</option>
        <option value="approved" {% if filters.status == 'approved' %}selected{% endif %}>approved</option>
        <option value="all" {% if filters.status == 'all' %}selected{% endif %}>all</option>
      </select>
    </label>
    <label>题型
      <input name="question_type" value="{{ filters.question_type }}" placeholder="选择题">
    </label>
    <label>页码
      <input name="page_range" value="{{ filters.page_range }}" placeholder="p1090">
    </label>
    <label>关键词
      <input name="q" value="{{ filters.q }}" placeholder="函数">
    </label>
    <label>批次
      <select name="batch_id">
        <option value="" {% if not filters.batch_id_text %}selected{% endif %}>all</option>
        {% for batch in batches %}
          <option value="{{ batch.id }}" {% if filters.batch_id_text == batch.id|string %}selected{% endif %}>{{ batch.name }}</option>
        {% endfor %}
      </select>
    </label>
    <label>异常
      <select name="issue_only">
        <option value="" {% if not filters.issue_only %}selected{% endif %}>all</option>
        <option value="1" {% if filters.issue_only %}selected{% endif %}>flagged</option>
      </select>
    </label>
    <label>Stage14
      <select name="stage14_queue">
        <option value="all" {% if filters.stage14_queue == 'all' %}selected{% endif %}>all</option>
        {% for queue in stage14_queues %}
          <option value="{{ queue }}" {% if filters.stage14_queue == queue %}selected{% endif %}>{{ queue }}</option>
        {% endfor %}
      </select>
    </label>
    <label>数量
      <input name="limit" value="{{ filters.limit_text }}" inputmode="numeric">
    </label>
    <button type="submit">筛选</button>
  </form>

  <div class="count">共 {{ questions|length }} 条</div>
  <table>
    <thead>
      <tr>
        <th>ID</th>
        <th>题号</th>
        <th>题型</th>
        <th>状态</th>
        <th>页码</th>
        <th>源页</th>
        <th>来源</th>
        <th>Stage14</th>
        <th>题干预览</th>
        <th>操作</th>
      </tr>
    </thead>
    <tbody>
    {% for question in questions %}
      <tr>
        <td>{{ question.qid }}</td>
        <td>{{ question.question_no }}</td>
        <td>{{ question.question_type or '' }}</td>
        <td class="status">{{ question.review_status }}</td>
        <td>{{ question.page_range or '' }}</td>
        <td>{{ question.source_page or '' }}</td>
        <td>{{ question.source_label or question.paper_name or '' }}{% if question.source_confidence %}<br><small>{{ question.source_confidence }}</small>{% endif %}</td>
        <td>{{ question.stage14_queue_name or 'unclassified' }}{% if question.stage14_primary_reason %}<br><small>{{ question.stage14_primary_reason }}</small>{% endif %}</td>
        <td class="preview">{{ question.stem_preview }}</td>
        <td>
          <a href="{{ detail_url(question.id) }}">查看</a>
          <form class="inline" method="post" action="{{ url_for('add_to_basket', question_id=question.id) }}">
            <input type="hidden" name="next" value="{{ request.full_path }}">
            <button type="submit">加入组卷</button>
          </form>
        </td>
      </tr>
    {% endfor %}
    </tbody>
  </table>
</main>
</body>
</html>
"""


DETAIL_TEMPLATE = """
<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{ question.qid }}</title>
  <style>
    :root { color-scheme: light; font-family: "Segoe UI", Arial, sans-serif; }
    body { margin: 0; background: #f6f7f9; color: #1f2937; }
    main { max-width: 1240px; margin: 0 auto; padding: 24px; }
    header { display: flex; justify-content: space-between; gap: 16px; align-items: center; margin-bottom: 16px; }
    h1 { font-size: 22px; margin: 0; }
    a { color: #1d4ed8; }
    .saved { color: #166534; font-weight: 600; }
    .layout { display: grid; grid-template-columns: minmax(360px, 0.95fr) minmax(420px, 1.05fr); gap: 18px; align-items: start; }
    .panel { background: white; border: 1px solid #e5e7eb; border-radius: 8px; padding: 16px; }
    .meta { display: grid; grid-template-columns: 110px 1fr; gap: 6px 10px; margin-bottom: 14px; font-size: 14px; }
    .page-image { width: 100%; height: auto; border: 1px solid #d1d5db; background: #fff; }
    pre { white-space: pre-wrap; overflow-wrap: anywhere; background: #f3f4f6; border: 1px solid #e5e7eb; border-radius: 6px; padding: 10px; font-size: 13px; }
    form { display: grid; gap: 12px; }
    label { display: grid; gap: 5px; font-size: 13px; color: #4b5563; }
    input, select, textarea { border: 1px solid #cbd5e1; border-radius: 6px; padding: 8px 10px; background: white; color: #111827; font: inherit; }
    textarea { min-height: 96px; resize: vertical; }
    textarea.large { min-height: 160px; }
    button { border: 1px solid #1f2937; border-radius: 6px; padding: 9px 13px; background: #1f2937; color: white; font: inherit; cursor: pointer; width: fit-content; }
    nav { display: flex; gap: 12px; margin-bottom: 14px; }
    .actions { display: flex; flex-wrap: wrap; gap: 10px; }
    .mini-table { width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 13px; }
    .mini-table th, .mini-table td { border: 1px solid #e5e7eb; padding: 6px; text-align: left; }
    .status-badge, .source-note { display: inline-block; margin: 6px 0; border: 1px solid #cbd5e1; border-radius: 6px; padding: 3px 7px; font-size: 12px; color: #475569; background: #f8fafc; }
    .structured-preview { border: 1px solid #e5e7eb; border-radius: 6px; padding: 10px; margin-top: 8px; }
    .latex-block, .candidate-stem { white-space: pre-wrap; line-height: 1.6; }
    .options { list-style: none; padding: 0; margin: 12px 0; display: grid; gap: 8px 18px; }
    .options-4 { grid-template-columns: repeat(4, minmax(0, 1fr)); }
    .options-2 { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .options-1 { grid-template-columns: 1fr; }
    .blank-line { display: inline-block; min-width: 140px; border-bottom: 1px solid #111827; height: 1em; }
    .subquestions { padding-left: 22px; }
    @media (max-width: 960px) {
      main { padding: 16px; }
      .layout { grid-template-columns: 1fr; }
      .options-4, .options-2 { grid-template-columns: 1fr; }
    }
  </style>
  {{ math_renderer_head_html|safe }}
</head>
<body>
<main>
  <header>
    <div>
      <h1>{{ question.qid }}</h1>
      <div>{{ question.source_label or (question.paper_name or question.source_title) }}{% if question.source_confidence %} / {{ question.source_confidence }}{% endif %}</div>
    </div>
    <nav>
      <a href="{{ list_url }}">返回列表</a>
      {% if prev_question_id %}<a href="{{ detail_url(prev_question_id) }}">上一题</a>{% endif %}
      {% if next_question_id %}<a href="{{ detail_url(next_question_id) }}">下一题</a>{% endif %}
      <a href="{{ url_for('paper_basket') }}">组卷篮（{{ basket_count }}）</a>
    </nav>
  </header>
  {% if saved %}<p class="saved">已保存</p>{% endif %}
  {% if error %}<p>{{ error }}</p>{% endif %}

  <div class="layout">
    <section class="panel">
      <div class="meta">
        <strong>状态</strong><span>{{ question.review_status }}</span>
        <strong>题型</strong><span>{{ question.question_type or '' }}</span>
        <strong>页码</strong><span>{{ question.page_range or '' }}</span>
        <strong>来源</strong><span>{{ question.source_label or question.paper_code }}</span>
        <strong>来源置信</strong><span>{{ question.source_confidence or 'unclassified' }}</span>
        <strong>来源页眉</strong><span>{{ question.source_attribution_text or '' }}</span>
      </div>
      {% if question.page_image_path %}
        <img class="page-image" src="{{ url_for('asset_file', relative_path=question.page_image_path) }}" alt="source page {{ question.source_page }}">
      {% else %}
        <p>未找到页面级原貌图。</p>
      {% endif %}
      <h2>题级裁切图</h2>
      {% if question.raw_crop_path %}
        <img class="page-image" src="{{ url_for('asset_file', relative_path=question.raw_crop_path) }}" alt="question crop {{ question.question_no }}">
        <pre>{{ question.raw_crop_bbox_json or '{}' }}</pre>
      {% else %}
        <p>未找到题级裁切图。</p>
      {% endif %}
      <h2>BBox</h2>
      <pre>{{ question.bbox_json }}</pre>
      <h2>页面资产</h2>
      <pre>{{ question.page_image_bbox_json or '{}' }}</pre>
      <h2>批次页状态</h2>
      {% if question.batch_pages %}
        <table class="mini-table">
          <thead>
            <tr>
              <th>批次</th>
              <th>候选</th>
              <th>入库</th>
              <th>warning</th>
              <th>重复锚点</th>
            </tr>
          </thead>
          <tbody>
            {% for batch_page in question.batch_pages %}
              <tr>
                <td><a href="{{ url_for('batch_detail', batch_id=batch_page.batch_id) }}">{{ batch_page.batch_name }}</a></td>
                <td>{{ batch_page.candidate_count }}</td>
                <td>{{ batch_page.db_question_count }}</td>
                <td>{{ batch_page.warning_candidates }}</td>
                <td>{{ batch_page.duplicate_anchor_count }}</td>
              </tr>
            {% endfor %}
          </tbody>
        </table>
      {% else %}
        <p>未关联批次页记录。</p>
      {% endif %}
      <h2>可用性状态</h2>
      {% if question.usability_status %}
        <div class="meta">
          <strong>usability</strong><span>{{ question.usability_status }}</span>
          <strong>render_mode</strong><span>{{ question.usability_render_mode }}</span>
          <strong>export</strong><span>{{ question.usability_export_eligible }}</span>
          <strong>primary_issue</strong><span>{{ question.usability_primary_issue }}</span>
        </div>
        <pre>{{ question.usability_issue_flags_json or '[]' }}</pre>
      {% else %}
        <p>未生成可用性分流状态。</p>
      {% endif %}
      <h2>导出质量状态</h2>
      {% if question.export_quality_status %}
        <div class="meta">
          <strong>quality</strong><span>{{ question.export_quality_status }}</span>
          <strong>render_mode</strong><span>{{ question.export_quality_render_mode }}</span>
          <strong>export</strong><span>{{ question.export_quality_export_eligible }}</span>
          <strong>source usability</strong><span>{{ question.export_quality_source_usability_status }}</span>
        </div>
        <pre>{{ question.export_quality_blocking_reasons_json or '[]' }}</pre>
        <pre>{{ question.export_quality_flags_json or '[]' }}</pre>
      {% else %}
        <p>未生成导出质量状态。</p>
      {% endif %}
      <h2>Stage14 质量队列</h2>
      {% if question.stage14_queue_name %}
        <div class="meta">
          <strong>queue</strong><span>{{ question.stage14_queue_name }}</span>
          <strong>severity</strong><span>{{ question.stage14_severity }}</span>
          <strong>reason</strong><span>{{ question.stage14_primary_reason }}</span>
          <strong>action</strong><span>{{ question.stage14_suggested_action }}</span>
        </div>
        <pre>{{ question.stage14_queue_tags_json or '[]' }}</pre>
        <pre>{{ question.stage14_flags_json or '[]' }}</pre>
      {% else %}
        <p>未生成 Stage14 队列。</p>
      {% endif %}
      {% if question.stage14_visual_repair_status %}
        <h2>Stage14 视觉修复候选</h2>
        <div class="meta">
          <strong>status</strong><span>{{ question.stage14_visual_repair_status }}</span>
          <strong>candidate</strong><span>{{ question.stage14_visual_candidate_path or '' }}</span>
        </div>
        {% if question.stage14_visual_candidate_path %}
          <img class="page-image" src="{{ url_for('asset_file', relative_path=question.stage14_visual_candidate_path) }}" alt="stage14 visual candidate">
        {% endif %}
        <pre>{{ question.stage14_visual_error_json or '{}' }}</pre>
      {% endif %}
    </section>

    <section class="panel">
      <form method="post" action="{{ detail_url(question.id) }}">
        {% for key, value in context_args.items() %}
          <input type="hidden" name="{{ key }}" value="{{ value }}">
        {% endfor %}
        <label>review_status
          <select name="review_status">
            {% for status in edit_statuses %}
              <option value="{{ status }}" {% if question.review_status == status %}selected{% endif %}>{{ status }}</option>
            {% endfor %}
          </select>
        </label>
        <label>question_type
          <input name="question_type" value="{{ question.question_type or '' }}">
        </label>
        <label>stem_text
          <textarea class="large" name="stem_text" required>{{ question.stem_text }}</textarea>
        </label>
        <label>stem_latex
          <textarea class="large" name="stem_latex" required>{{ question.stem_latex }}</textarea>
        </label>
        <label>answer_text
          <textarea name="answer_text">{{ question.answer_text or '' }}</textarea>
        </label>
        <label>analysis_latex
          <textarea name="analysis_latex">{{ question.analysis_latex or '' }}</textarea>
        </label>
        <label>tags_json
          <textarea name="tags_json">{{ question.tags_json }}</textarea>
        </label>
        <label>issue_tags
          <input name="issue_tags" value="{{ issue_tags_text }}" placeholder="切分异常, 缺图">
        </label>
        <label>meta_json
          <textarea class="large" name="meta_json">{{ question.meta_json }}</textarea>
        </label>
        <div class="actions">
          <button type="submit">保存</button>
          {% if next_question_id %}
            <button type="submit" name="save_next" value="1">保存并下一题</button>
          {% endif %}
        </div>
      </form>
      <h2>Structured Content</h2>
      {% if structured_content %}
        <div class="meta">
          <strong>ai_status</strong><span>{{ structured_content.ai_status }}</span>
          <strong>normalized_type</strong><span>{{ structured_content.normalized_type }}</span>
          <strong>confidence</strong><span>{{ structured_content.confidence if structured_content.confidence is not none else '' }}</span>
        </div>
        <h3>source_text</h3>
        <pre>{{ structured_content.source_text }}</pre>
        <h3>JSON / LaTeX</h3>
        <pre>{{ structured_json_text }}</pre>
        <h3>Preview</h3>
        <div class="structured-preview">{{ structured_preview_html|safe }}</div>
        <div class="actions">
          <form method="post" action="{{ url_for('structured_status_route', question_id=question.id) }}">
            <input type="hidden" name="action" value="accept">
            <input type="hidden" name="next" value="{{ request.full_path }}">
            <button type="submit">Accept structured</button>
          </form>
          <form method="post" action="{{ url_for('structured_status_route', question_id=question.id) }}">
            <input type="hidden" name="action" value="downgrade">
            <input type="hidden" name="next" value="{{ request.full_path }}">
            <button type="submit">Downgrade</button>
          </form>
          <form method="post" action="{{ url_for('structured_status_route', question_id=question.id) }}">
            <input type="hidden" name="action" value="needs_review">
            <input type="hidden" name="next" value="{{ request.full_path }}">
            <button type="submit">Mark needs_review</button>
          </form>
        </div>
      {% else %}
        <p>No structured content.</p>
      {% endif %}
      <h2>AI Suggestions</h2>
      {% if ai_suggestions %}
        {% for suggestion in ai_suggestions %}
          <section class="panel">
            <div class="meta">
              <strong>ID</strong><span>{{ suggestion.id }}</span>
              <strong>type</strong><span>{{ suggestion.suggestion_type }}</span>
              <strong>status</strong><span>{{ suggestion.status }}</span>
              <strong>model</strong><span>{{ suggestion.model_name }}</span>
            </div>
            <pre>{{ suggestion.suggestion_json }}</pre>
            {% if suggestion.status == 'pending' %}
              <form method="post" action="{{ url_for('accept_ai_suggestion_route', question_id=question.id, suggestion_id=suggestion.id) }}">
                <button type="submit">Accept</button>
              </form>
              <form method="post" action="{{ url_for('reject_ai_suggestion_route', question_id=question.id, suggestion_id=suggestion.id) }}">
                <button type="submit">Reject</button>
              </form>
            {% endif %}
          </section>
        {% endfor %}
      {% else %}
        <p>No AI suggestions.</p>
      {% endif %}
    </section>
  </div>
</main>
</body>
</html>
"""


STRUCTURED_REVIEW_TEMPLATE = """
<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Stage 10 Structured Review</title>
  <style>
    :root { color-scheme: light; font-family: "Segoe UI", Arial, sans-serif; }
    body { margin: 0; background: #f6f7f9; color: #1f2937; }
    main { max-width: 1240px; margin: 0 auto; padding: 24px; }
    h1 { font-size: 24px; margin: 0 0 18px; }
    nav { display: flex; gap: 12px; margin-bottom: 16px; }
    form.filters { display: grid; grid-template-columns: repeat(11, minmax(0, 1fr)) auto; gap: 10px; align-items: end; margin-bottom: 16px; }
    label { display: grid; gap: 5px; font-size: 13px; color: #4b5563; }
    input, select { border: 1px solid #cbd5e1; border-radius: 6px; padding: 8px 10px; background: white; color: #111827; font: inherit; }
    button, .button { border: 1px solid #1f2937; border-radius: 6px; padding: 8px 12px; background: #1f2937; color: white; text-decoration: none; font: inherit; cursor: pointer; }
    table { width: 100%; border-collapse: collapse; background: white; border: 1px solid #e5e7eb; }
    th, td { border-bottom: 1px solid #e5e7eb; padding: 10px; text-align: left; vertical-align: top; }
    th { background: #eef2f7; font-size: 13px; color: #374151; }
    td.preview { max-width: 360px; white-space: pre-wrap; }
    .flags { max-width: 280px; overflow-wrap: anywhere; }
    .thumbs { display: flex; gap: 8px; }
    .thumbs img { max-width: 92px; max-height: 120px; border: 1px solid #d1d5db; background: white; object-fit: contain; }
    form.inline { display: inline; }
    form.inline button { padding: 5px 8px; margin: 2px 0; }
    .count { margin: 8px 0 12px; color: #4b5563; }
    @media (max-width: 980px) {
      main { padding: 16px; }
      form.filters { grid-template-columns: 1fr 1fr; }
      table { font-size: 14px; }
    }
  </style>
</head>
<body>
<main>
  <h1>Stage 10 Structured Review</h1>
  <nav>
    <a href="{{ url_for('questions') }}">Questions</a>
    <a href="{{ url_for('batches') }}">Batches</a>
    <a href="{{ url_for('paper_basket') }}">Basket ({{ basket_count }})</a>
  </nav>
  {% if error %}<p>{{ error }}</p>{% endif %}
  <form class="filters" method="get" action="{{ url_for('structured_review') }}">
    <label>ai_status
      <select name="ai_status">
        {% for status in ['needs_review', 'failed', 'unprocessed', 'ai_draft', 'ai_verified', 'human_reviewed', 'all'] %}
          <option value="{{ status }}" {% if filters.ai_status == status %}selected{% endif %}>{{ status }}</option>
        {% endfor %}
      </select>
    </label>
    <label>flag
      <input name="quality_flag" value="{{ filters.quality_flag }}" placeholder="duplicate_anchor">
    </label>
    <label>type
      <select name="normalized_type">
        {% for type_value in ['all', 'choice', 'multiple_choice', 'blank', 'solution', 'unknown'] %}
          <option value="{{ type_value }}" {% if filters.normalized_type == type_value %}selected{% endif %}>{{ type_value }}</option>
        {% endfor %}
      </select>
    </label>
    <label>page
      <input name="page" value="{{ filters.page_text }}" inputmode="numeric" placeholder="1098">
    </label>
    <label>high risk
      <select name="high_risk">
        <option value="" {% if not filters.high_risk %}selected{% endif %}>all</option>
        <option value="1" {% if filters.high_risk %}selected{% endif %}>1098/1100/1128/1148/1168</option>
      </select>
    </label>
    <label>usability
      <select name="usability_status">
        {% for status in ['all', 'strict_structured', 'visual_fallback', 'needs_formula_repair', 'needs_blank_repair', 'needs_type_review', 'needs_recut', 'failed', 'protected'] %}
          <option value="{{ status }}" {% if filters.usability_status == status %}selected{% endif %}>{{ status }}</option>
        {% endfor %}
      </select>
    </label>
    <label>risk type
      <input name="risk_type" value="{{ filters.risk_type }}" placeholder="formula">
    </label>
    <label>render
      <select name="render_mode">
        {% for mode in ['all', 'structured_html', 'raw_crop_image', 'candidate_preview', 'none'] %}
          <option value="{{ mode }}" {% if filters.render_mode == mode %}selected{% endif %}>{{ mode }}</option>
        {% endfor %}
      </select>
    </label>
    <label>Stage14
      <select name="stage14_queue">
        <option value="all" {% if filters.stage14_queue == 'all' %}selected{% endif %}>all</option>
        {% for queue in stage14_queues %}
          <option value="{{ queue }}" {% if filters.stage14_queue == queue %}selected{% endif %}>{{ queue }}</option>
        {% endfor %}
      </select>
    </label>
    <label>reason
      <input name="stage14_reason" value="{{ filters.stage14_reason }}" placeholder="visual_image">
    </label>
    <label>limit
      <input name="limit" value="{{ filters.limit_text }}" inputmode="numeric">
    </label>
    <button type="submit">Filter</button>
  </form>
  <div class="count">Rows: {{ rows|length }}</div>
  <table>
    <thead>
      <tr>
        <th>QID</th>
        <th>Status</th>
        <th>Usability</th>
        <th>Export Quality</th>
        <th>Stage14</th>
        <th>Type</th>
        <th>Page</th>
        <th>Source</th>
        <th>Preview</th>
        <th>Images</th>
        <th>Flags</th>
        <th>Actions</th>
      </tr>
    </thead>
    <tbody>
      {% for row in rows %}
        <tr>
          <td><a href="{{ url_for('question_detail', question_id=row.question_id, status='all', page_range=row.page_range or '', limit=5000) }}">{{ row.qid }}</a></td>
          <td>{{ row.ai_status }}</td>
          <td>{{ row.usability_status or 'unclassified' }}<br>{{ row.render_mode or '' }}<br>{{ row.primary_issue or '' }}</td>
          <td>
            {{ row.export_quality_status or 'unclassified' }}<br>{{ row.export_quality_render_mode or '' }}
            {% if row.export_quality_blocking_reasons %}
              <br>{{ row.export_quality_blocking_reasons|join(', ') }}
            {% endif %}
          </td>
          <td>{{ row.stage14_queue_name or 'unclassified' }}<br>{{ row.stage14_primary_reason or '' }}</td>
          <td>{{ row.normalized_type }}</td>
          <td>{{ row.source_page }}{% if row.high_risk %} high-risk{% endif %}</td>
          <td>{{ row.source_label or '' }}{% if row.source_confidence %}<br>{{ row.source_confidence }}{% endif %}</td>
          <td class="preview">{{ row.stem_preview }}</td>
          <td>
            <div class="thumbs">
              {% if row.page_image_path %}<img src="{{ url_for('asset_file', relative_path=row.page_image_path) }}" alt="page">{% endif %}
              {% if row.raw_crop_path %}<img src="{{ url_for('asset_file', relative_path=row.raw_crop_path) }}" alt="crop">{% endif %}
            </div>
          </td>
          <td class="flags">{{ row.quality_flags|join(', ') }}{% if row.usability_flags %}<br>usability: {{ row.usability_flags|join(', ') }}{% endif %}{% if row.export_quality_flags %}<br>export: {{ row.export_quality_flags|join(', ') }}{% endif %}</td>
          <td>
            <form class="inline" method="post" action="{{ url_for('structured_status_route', question_id=row.question_id) }}">
              <input type="hidden" name="action" value="accept">
              <input type="hidden" name="next" value="{{ request.full_path }}">
              <button type="submit">Accept</button>
            </form>
            <form class="inline" method="post" action="{{ url_for('structured_status_route', question_id=row.question_id) }}">
              <input type="hidden" name="action" value="downgrade">
              <input type="hidden" name="next" value="{{ request.full_path }}">
              <button type="submit">Downgrade</button>
            </form>
            <form class="inline" method="post" action="{{ url_for('structured_status_route', question_id=row.question_id) }}">
              <input type="hidden" name="action" value="needs_review">
              <input type="hidden" name="next" value="{{ request.full_path }}">
              <button type="submit">Needs review</button>
            </form>
          </td>
        </tr>
      {% endfor %}
    </tbody>
  </table>
</main>
</body>
</html>
"""


BASKET_TEMPLATE = """
<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>组卷篮</title>
  <style>
    :root { color-scheme: light; font-family: "Segoe UI", Arial, sans-serif; }
    body { margin: 0; background: #f6f7f9; color: #1f2937; }
    main { max-width: 1180px; margin: 0 auto; padding: 24px; }
    h1 { font-size: 24px; margin: 0 0 14px; }
    nav, .toolbar { display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 16px; align-items: center; }
    a { color: #1d4ed8; }
    table { width: 100%; border-collapse: collapse; background: white; border: 1px solid #e5e7eb; }
    th, td { border-bottom: 1px solid #e5e7eb; padding: 10px; text-align: left; vertical-align: top; }
    th { background: #eef2f7; font-size: 13px; color: #374151; }
    td.preview { max-width: 420px; white-space: pre-wrap; }
    form.inline { display: inline; }
    button, .button { border: 1px solid #1f2937; border-radius: 6px; padding: 7px 10px; background: #1f2937; color: white; text-decoration: none; font: inherit; cursor: pointer; }
    button.secondary, .button.secondary { background: white; color: #1f2937; }
    button:disabled { opacity: 0.45; cursor: default; }
    .empty { background: white; border: 1px solid #e5e7eb; padding: 18px; border-radius: 8px; }
  </style>
</head>
<body>
<main>
  <h1>组卷篮</h1>
  <nav>
    <a href="{{ url_for('questions') }}">题目列表</a>
    <a href="{{ url_for('paper_preview') }}">预览</a>
    <a href="{{ url_for('paper_export') }}">导出 HTML</a>
    <form method="post" action="{{ url_for('paper_export_save') }}">
      <button class="secondary" type="submit" {% if not questions %}disabled{% endif %}>保存 HTML</button>
    </form>
  </nav>
  <div class="toolbar">
    <span>已选 {{ questions|length }} 题</span>
    <form method="post" action="{{ url_for('clear_basket') }}">
      <button class="secondary" type="submit" {% if not questions %}disabled{% endif %}>清空</button>
    </form>
  </div>

  {% if not questions %}
    <div class="empty">组卷篮为空。</div>
  {% else %}
    <table>
      <thead>
        <tr>
          <th>顺序</th>
          <th>题号</th>
          <th>题型</th>
          <th>状态</th>
          <th>可用性</th>
          <th>导出质量</th>
          <th>来源</th>
          <th>Stage14</th>
          <th>题干预览</th>
          <th>操作</th>
        </tr>
      </thead>
      <tbody>
      {% for question in questions %}
        <tr>
          <td>{{ loop.index }}</td>
          <td><a href="{{ url_for('question_detail', question_id=question.id) }}">{{ question.qid }}</a></td>
          <td>{{ question.question_type or '' }}</td>
          <td>{{ question.review_status }}</td>
          <td>
            {% if question.usability_state %}
              {{ question.usability_state.usability_status }}<br>{{ question.usability_state.render_mode }}
            {% else %}
              unclassified
            {% endif %}
          </td>
          <td>
            {% if question.export_quality_state %}
              {{ question.export_quality_state.export_quality_status }}<br>{{ question.export_quality_state.render_mode }}
              {% if question.export_quality_state.blocking_reasons %}
                <br>{{ question.export_quality_state.blocking_reasons|join(', ') }}
              {% endif %}
            {% else %}
              unclassified
            {% endif %}
          </td>
          <td>{{ question.source_label or question.paper_name or question.source_title }}{% if question.source_confidence %}<br>{{ question.source_confidence }}{% endif %}</td>
          <td>{{ question.stage14_queue_name or 'unclassified' }}{% if question.stage14_primary_reason %}<br><small>{{ question.stage14_primary_reason }}</small>{% endif %}</td>
          <td class="preview">{{ question.stem_text[:160] }}</td>
          <td>
            <form class="inline" method="post" action="{{ url_for('move_basket_item', question_id=question.id, direction='up') }}">
              <button class="secondary" type="submit" {% if loop.first %}disabled{% endif %}>上移</button>
            </form>
            <form class="inline" method="post" action="{{ url_for('move_basket_item', question_id=question.id, direction='down') }}">
              <button class="secondary" type="submit" {% if loop.last %}disabled{% endif %}>下移</button>
            </form>
            <form class="inline" method="post" action="{{ url_for('remove_from_basket', question_id=question.id) }}">
              <button type="submit">删除</button>
            </form>
          </td>
        </tr>
      {% endfor %}
      </tbody>
    </table>
  {% endif %}
</main>
</body>
</html>
"""


PAPER_TEMPLATE = """
<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>可打印试卷</title>
  <style>
    :root { color-scheme: light; font-family: "Segoe UI", Arial, sans-serif; }
    body { margin: 0; background: #ffffff; color: #111827; }
    main { max-width: 820px; margin: 0 auto; padding: 28px; }
    .toolbar { display: flex; gap: 12px; margin-bottom: 20px; }
    a { color: #1d4ed8; }
    h1 { text-align: center; font-size: 26px; margin: 8px 0 24px; }
    article { break-inside: avoid; padding: 16px 0; border-top: 1px solid #d1d5db; }
    article:first-of-type { border-top: 0; }
    .meta { color: #4b5563; font-size: 14px; margin-bottom: 10px; }
    .stem { white-space: pre-wrap; line-height: 1.65; font-size: 16px; }
    .status-badge, .source-note { display: inline-block; margin: 4px 0 10px; border: 1px solid #cbd5e1; border-radius: 6px; padding: 3px 7px; font-size: 12px; color: #475569; background: #f8fafc; }
    .options { list-style: none; padding: 0; margin: 12px 0; display: grid; gap: 8px 18px; }
    .options-4 { grid-template-columns: repeat(4, minmax(0, 1fr)); }
    .options-2 { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .options-1 { grid-template-columns: 1fr; }
    .option-label { font-weight: 600; }
    .blank-line { display: inline-block; min-width: 140px; border-bottom: 1px solid #111827; height: 1em; }
    .subquestions { padding-left: 24px; line-height: 1.65; }
    .answer, .analysis { margin-top: 12px; }
    .empty { border: 1px solid #e5e7eb; padding: 18px; }
    @media print {
      .toolbar { display: none; }
      main { max-width: none; padding: 0; }
      body { margin: 12mm; }
      article { page-break-inside: avoid; }
    }
  </style>
  {{ math_renderer_head_html|safe }}
</head>
<body>
<main>
  {% if not export %}
    <div class="toolbar">
      <a href="{{ url_for('paper_basket') }}">返回组卷篮</a>
      <a href="{{ url_for('paper_export') }}">导出 HTML</a>
      <form method="post" action="{{ url_for('paper_export_save') }}">
        <button type="submit">保存 HTML</button>
      </form>
      <a href="javascript:window.print()">打印</a>
    </div>
  {% endif %}
  <h1>可打印试卷</h1>
  {% if not questions %}
    <div class="empty">组卷篮为空。</div>
  {% else %}
    {% for question in questions %}
      {{ render_question_html(question, loop.index)|safe }}
    {% endfor %}
  {% endif %}
</main>
</body>
</html>
"""


EXPORT_SAVED_TEMPLATE = """
<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>导出已保存</title>
  <style>
    :root { color-scheme: light; font-family: "Segoe UI", Arial, sans-serif; }
    body { margin: 0; background: #f6f7f9; color: #1f2937; }
    main { max-width: 820px; margin: 0 auto; padding: 28px; }
    .panel { background: white; border: 1px solid #e5e7eb; border-radius: 8px; padding: 18px; }
    code { overflow-wrap: anywhere; }
    nav { display: flex; gap: 12px; margin-top: 16px; }
  </style>
</head>
<body>
<main>
  <section class="panel">
    <h1>导出已保存</h1>
    <p><code>{{ result.relative_path }}</code></p>
    <p>{{ result.size_bytes }} bytes</p>
    <nav>
      <a href="{{ url_for('paper_basket') }}">返回组卷篮</a>
      <a href="{{ url_for('paper_preview') }}">预览</a>
    </nav>
  </section>
</main>
</body>
</html>
"""


BATCH_LIST_TEMPLATE = """
<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>导入批次</title>
  <style>
    :root { color-scheme: light; font-family: "Segoe UI", Arial, sans-serif; }
    body { margin: 0; background: #f6f7f9; color: #1f2937; }
    main { max-width: 1180px; margin: 0 auto; padding: 24px; }
    nav { display: flex; gap: 12px; margin-bottom: 16px; }
    table { width: 100%; border-collapse: collapse; background: white; border: 1px solid #e5e7eb; }
    th, td { border-bottom: 1px solid #e5e7eb; padding: 10px; text-align: left; vertical-align: top; }
    th { background: #eef2f7; font-size: 13px; color: #374151; }
    a { color: #1d4ed8; }
  </style>
</head>
<body>
<main>
  <h1>导入批次</h1>
  <nav>
    <a href="{{ url_for('questions') }}">题目列表</a>
    <a href="{{ url_for('paper_basket') }}">组卷篮（{{ basket_count }}）</a>
  </nav>
  <table>
    <thead>
      <tr>
        <th>ID</th>
        <th>名称</th>
        <th>页码</th>
        <th>状态</th>
        <th>页数</th>
        <th>异常页</th>
        <th>失败页</th>
        <th>操作</th>
      </tr>
    </thead>
    <tbody>
      {% for batch in batches %}
        <tr>
          <td>{{ batch.id }}</td>
          <td><a href="{{ url_for('batch_detail', batch_id=batch.id) }}">{{ batch.name }}</a></td>
          <td>{{ batch.page_spec }}</td>
          <td>{{ batch.status }}</td>
          <td>{{ batch.page_rows }}</td>
          <td>{{ batch.warning_pages }}</td>
          <td>{{ batch.failed_pages }}</td>
          <td>
            <a href="{{ url_for('questions', status='all', batch_id=batch.id, limit=5000) }}">查看题目</a>
            <a href="{{ url_for('questions', status='all', batch_id=batch.id, issue_only=1, limit=5000) }}">异常优先</a>
          </td>
        </tr>
      {% endfor %}
    </tbody>
  </table>
</main>
</body>
</html>
"""


BATCH_DETAIL_TEMPLATE = """
<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{ batch.name }}</title>
  <style>
    :root { color-scheme: light; font-family: "Segoe UI", Arial, sans-serif; }
    body { margin: 0; background: #f6f7f9; color: #1f2937; }
    main { max-width: 1180px; margin: 0 auto; padding: 24px; }
    nav { display: flex; gap: 12px; margin-bottom: 16px; }
    table { width: 100%; border-collapse: collapse; background: white; border: 1px solid #e5e7eb; }
    th, td { border-bottom: 1px solid #e5e7eb; padding: 10px; text-align: left; vertical-align: top; }
    th { background: #eef2f7; font-size: 13px; color: #374151; }
    pre { white-space: pre-wrap; overflow-wrap: anywhere; background: #fff; border: 1px solid #e5e7eb; padding: 10px; }
    a { color: #1d4ed8; }
  </style>
</head>
<body>
<main>
  <h1>{{ batch.name }}</h1>
  <nav>
    <a href="{{ url_for('batches') }}">批次列表</a>
    <a href="{{ url_for('questions', status='all', batch_id=batch.id, limit=5000) }}">本批题目</a>
    <a href="{{ url_for('questions', status='all', batch_id=batch.id, issue_only=1, limit=5000) }}">异常优先</a>
  </nav>
  <p>状态：{{ batch.status }} / 页码：{{ batch.page_spec }} / 算法：{{ batch.algorithm_version }}</p>
  {% if batch.error_json and batch.error_json != '{}' %}
    <h2>错误</h2>
    <pre>{{ batch.error_json }}</pre>
  {% endif %}
  <table>
    <thead>
      <tr>
        <th>页</th>
        <th>状态</th>
        <th>候选</th>
        <th>入库</th>
        <th>warning</th>
        <th>重复锚点</th>
        <th>skipped reviewed</th>
        <th>flags</th>
      </tr>
    </thead>
    <tbody>
      {% for page in batch.pages %}
        <tr>
          <td><a href="{{ url_for('questions', status='all', batch_id=batch.id, page_range='p%04d' % page.page_no, limit=5000) }}">{{ page.page_no }}</a></td>
          <td>{{ page.status }}</td>
          <td>{{ page.candidate_count }}</td>
          <td>{{ page.db_question_count }}</td>
          <td>{{ page.warning_candidates }}</td>
          <td>{{ page.duplicate_anchor_count }}</td>
          <td>{{ page.skipped_reviewed }}</td>
          <td>{{ page.page_flags_json }}</td>
        </tr>
      {% endfor %}
    </tbody>
  </table>
</main>
</body>
</html>
"""


def create_app(
    *,
    db_path: str | Path | None = None,
    project_root: str | Path | None = None,
    asset_roots: Iterable[str | Path] | None = None,
) -> Flask:
    app = Flask(__name__)
    paths = (
        get_project_paths(Path(project_root), require_target_pdf=False)
        if project_root is not None
        else get_project_paths(require_target_pdf=False)
    )
    app.config["SECRET_KEY"] = "local-exam-bank-session"
    app.config["DB_PATH"] = Path(db_path) if db_path is not None else paths.db_path
    app.config["PROJECT_ROOT"] = paths.project_root
    app.config["ASSETS_DIR"] = paths.assets_dir
    configured_asset_roots = (
        [Path(value) for value in asset_roots]
        if asset_roots is not None
        else [paths.assets_dir, paths.project_root / "data" / "derived"]
    )
    project_root_path = paths.project_root.resolve()
    validated_asset_roots: list[Path] = []
    for configured_root in configured_asset_roots:
        candidate = (
            configured_root
            if configured_root.is_absolute()
            else paths.project_root / configured_root
        ).resolve()
        try:
            candidate.relative_to(project_root_path)
        except ValueError as exc:
            raise ValueError("asset roots must stay inside the project root") from exc
        if candidate.exists():
            candidate = get_workspace_io().validate_directory_path(candidate)
        if candidate not in validated_asset_roots:
            validated_asset_roots.append(candidate)
    app.config["ASSET_ROOTS"] = tuple(validated_asset_roots)

    @app.get("/health")
    def health():
        report = build_health_report(Path(app.config["PROJECT_ROOT"]))
        status_code = 200 if report["status"] == "ok" else 503
        return jsonify(report), status_code

    @app.get("/batches")
    def batches():
        rows = list_import_batches(db_path=app.config["DB_PATH"])
        return render_template_string(
            BATCH_LIST_TEMPLATE,
            batches=rows,
            basket_count=len(_basket_ids()),
        )

    @app.get("/batches/<int:batch_id>")
    def batch_detail(batch_id: int):
        try:
            batch = get_import_batch(batch_id=batch_id, db_path=app.config["DB_PATH"])
        except ImportBatchError:
            abort(404)
        return render_template_string(BATCH_DETAIL_TEMPLATE, batch=batch)

    @app.get("/questions")
    def questions():
        try:
            context = _question_context(request.args)
            rows = list_questions(
                db_path=app.config["DB_PATH"],
                status=context["status"],
                question_type=context["question_type"],
                page_range=context["page_range"],
                keyword=context["q"],
                limit=context["limit"],
                batch_id=context["batch_id"],
                issue_only=context["issue_only"],
                stage14_queue=context["stage14_queue"],
            )
            batches_rows = list_import_batches(db_path=app.config["DB_PATH"])
        except ValueError as exc:
            abort(400, str(exc))

        context_args = _context_query_args(context)

        def detail_url(question_id: int) -> str:
            return url_for("question_detail", question_id=question_id, **context_args)

        return render_template_string(
            LIST_TEMPLATE,
            questions=rows,
            statuses=LIST_STATUSES,
            basket_count=len(_basket_ids()),
            filters=context,
            batches=batches_rows,
            stage14_queues=STAGE14_QUEUE_FILTERS,
            detail_url=detail_url,
        )

    @app.get("/structured-review")
    def structured_review():
        error = request.args.get("error")
        try:
            context = _structured_review_context(request.args)
            rows = list_structured_review_items(
                db_path=app.config["DB_PATH"],
                ai_status=context["ai_status"],
                quality_flag=context["quality_flag"],
                normalized_type=context["normalized_type"],
                page=context["page"],
                high_risk=context["high_risk"],
                usability_status=context["usability_status"],
                risk_type=context["risk_type"],
                render_mode=context["render_mode"],
                stage14_queue=context["stage14_queue"],
                stage14_reason=context["stage14_reason"],
                limit=context["limit"],
            )
        except ValueError as exc:
            abort(400, str(exc))
        return render_template_string(
            STRUCTURED_REVIEW_TEMPLATE,
            rows=rows,
            filters=context,
            basket_count=len(_basket_ids()),
            stage14_queues=STAGE14_QUEUE_FILTERS,
            error=error,
        )

    @app.post("/structured-review/<int:question_id>/status")
    def structured_status_route(question_id: int):
        action = str(request.form.get("action") or "")
        next_url = _safe_next_url(request.form.get("next"), url_for("structured_review"))
        try:
            update_structured_review_status(
                question_id,
                action=action,
                db_path=app.config["DB_PATH"],
            )
            classify_usability_states(
                db_path=app.config["DB_PATH"],
                project_root=app.config["PROJECT_ROOT"],
            )
            classify_export_quality_states(
                db_path=app.config["DB_PATH"],
                project_root=app.config["PROJECT_ROOT"],
            )
        except Stage10Error as exc:
            return redirect(url_for("structured_review", error=str(exc)))
        return redirect(next_url)

    @app.route("/questions/<int:question_id>", methods=["GET", "POST"])
    def question_detail(question_id: int):
        error = request.args.get("ai_error")
        try:
            context = _question_context(request.values if request.method == "POST" else request.args)
            question_ids = list_question_ids(
                db_path=app.config["DB_PATH"],
                status=context["status"],
                question_type=context["question_type"],
                page_range=context["page_range"],
                keyword=context["q"],
                batch_id=context["batch_id"],
                issue_only=context["issue_only"],
                stage14_queue=context["stage14_queue"],
                limit=context["limit"],
            )
        except ValueError as exc:
            abort(400, str(exc))
        context_args = _context_query_args(context)
        current_index = question_ids.index(question_id) if question_id in question_ids else -1
        prev_question_id = question_ids[current_index - 1] if current_index > 0 else None
        next_question_id = (
            question_ids[current_index + 1]
            if current_index >= 0 and current_index + 1 < len(question_ids)
            else None
        )

        def detail_url(target_question_id: int) -> str:
            return url_for("question_detail", question_id=target_question_id, **context_args)

        list_url = url_for("questions", **context_args)
        if request.method == "POST":
            try:
                update_question_from_form(
                    question_id,
                    request.form,
                    db_path=app.config["DB_PATH"],
                )
            except LookupError:
                abort(404)
            except ValueError as exc:
                error = str(exc)
            else:
                target_question_id = (
                    next_question_id
                    if request.form.get("save_next") and next_question_id is not None
                    else question_id
                )
                return redirect(
                    url_for(
                        "question_detail",
                        question_id=target_question_id,
                        saved="1",
                        **context_args,
                    )
                )

        question = get_question_detail(question_id, db_path=app.config["DB_PATH"])
        if question is None:
            abort(404)
        structured_content = get_structured_content(question_id, db_path=app.config["DB_PATH"])
        return render_template_string(
            DETAIL_TEMPLATE,
            question=question,
            structured_content=structured_content,
            structured_json_text=structured_content_json_text(structured_content),
            structured_preview_html=render_structured_preview_html(
                question, structured_content
            ),
            ai_suggestions=list_ai_suggestions(question_id, db_path=app.config["DB_PATH"]),
            edit_statuses=EDIT_STATUSES,
            basket_count=len(_basket_ids()),
            saved=request.args.get("saved") == "1",
            error=error,
            context_args=context_args,
            list_url=list_url,
            detail_url=detail_url,
            prev_question_id=prev_question_id,
            next_question_id=next_question_id,
            issue_tags_text=_issue_tags_text(question.get("meta_json")),
            math_renderer_head_html=math_renderer_head_html(),
        )

    @app.post("/questions/<int:question_id>/ai-suggestions/<int:suggestion_id>/accept")
    def accept_ai_suggestion_route(question_id: int, suggestion_id: int):
        try:
            result = accept_ai_suggestion(
                suggestion_id,
                db_path=app.config["DB_PATH"],
                expected_question_id=question_id,
            )
        except AiSuggestionError as exc:
            return redirect(
                url_for("question_detail", question_id=question_id, ai_error=str(exc))
            )
        if int(result["question_id"]) != question_id:
            abort(404)
        return redirect(url_for("question_detail", question_id=question_id, saved="1"))

    @app.post("/questions/<int:question_id>/ai-suggestions/<int:suggestion_id>/reject")
    def reject_ai_suggestion_route(question_id: int, suggestion_id: int):
        try:
            result = reject_ai_suggestion(
                suggestion_id,
                db_path=app.config["DB_PATH"],
                expected_question_id=question_id,
            )
        except AiSuggestionError as exc:
            return redirect(
                url_for("question_detail", question_id=question_id, ai_error=str(exc))
            )
        if int(result["question_id"]) != question_id:
            abort(404)
        return redirect(url_for("question_detail", question_id=question_id, saved="1"))

    @app.post("/paper-basket/add/<int:question_id>")
    def add_to_basket(question_id: int):
        if not get_questions_by_ids([question_id], db_path=app.config["DB_PATH"]):
            abort(404)
        ids = _basket_ids()
        if question_id not in ids:
            ids.append(question_id)
            _save_basket_ids(ids)
        next_url = _safe_next_url(request.form.get("next"), url_for("paper_basket"))
        return redirect(next_url)

    @app.post("/paper-basket/remove/<int:question_id>")
    def remove_from_basket(question_id: int):
        _save_basket_ids([value for value in _basket_ids() if value != question_id])
        return redirect(url_for("paper_basket"))

    @app.post("/paper-basket/move/<int:question_id>/<direction>")
    def move_basket_item(question_id: int, direction: str):
        ids = _basket_ids()
        if question_id not in ids:
            return redirect(url_for("paper_basket"))

        index = ids.index(question_id)
        if direction == "up" and index > 0:
            ids[index - 1], ids[index] = ids[index], ids[index - 1]
        elif direction == "down" and index < len(ids) - 1:
            ids[index + 1], ids[index] = ids[index], ids[index + 1]
        elif direction not in ("up", "down"):
            abort(404)

        _save_basket_ids(ids)
        return redirect(url_for("paper_basket"))

    @app.post("/paper-basket/clear")
    def clear_basket():
        _save_basket_ids([])
        return redirect(url_for("paper_basket"))

    @app.get("/paper-basket")
    def paper_basket():
        questions = _basket_questions(app.config["DB_PATH"])
        return render_template_string(BASKET_TEMPLATE, questions=questions)

    @app.get("/paper-preview")
    def paper_preview():
        selection = ExportSelectionService(
            db_path=app.config["DB_PATH"],
            project_root=app.config["PROJECT_ROOT"],
        ).select_for_question_ids(_basket_ids())
        return PaperRenderService().render_printable(
            selection["questions"],
            rejected=selection["rejected"],
            export=False,
            basket_url=url_for("paper_basket"),
            export_url=url_for("paper_export"),
            save_url=url_for("paper_export_save"),
            asset_url_mode="flask",
        )

    @app.get("/paper-export")
    def paper_export():
        selection = ExportSelectionService(
            db_path=app.config["DB_PATH"],
            project_root=app.config["PROJECT_ROOT"],
        ).select_for_question_ids(_basket_ids())
        html = PaperRenderService().render_printable(
            selection["questions"],
            rejected=selection["rejected"],
            export=True,
            asset_url_mode="flask",
        )
        return Response(
            html,
            content_type="text/html; charset=utf-8",
            headers={"Content-Disposition": "attachment; filename=exam-paper.html"},
        )

    @app.post("/paper-export/save")
    def paper_export_save():
        selection = ExportSelectionService(
            db_path=app.config["DB_PATH"],
            project_root=app.config["PROJECT_ROOT"],
        ).select_for_question_ids(_basket_ids())
        html = PaperRenderService().render_printable(
            selection["questions"],
            rejected=selection["rejected"],
            export=True,
            asset_url_mode="export_relative",
        )
        result = save_html_export(html, project_root=app.config["PROJECT_ROOT"])
        return render_template_string(EXPORT_SAVED_TEMPLATE, result=result)

    @app.get("/assets/<path:relative_path>")
    def asset_file(relative_path: str):
        project_root_path = Path(app.config["PROJECT_ROOT"]).resolve()
        target = (project_root_path / relative_path).resolve()
        if not any(
            _is_path_below(target, Path(root))
            for root in app.config["ASSET_ROOTS"]
        ):
            abort(404)
        if not target.is_file():
            abort(404)
        try:
            target = get_workspace_io().validate_read_file_path(target)
        except WorkspaceIOError:
            abort(404)
        return send_file(target)

    return app


def _is_path_below(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root.resolve())
    except ValueError:
        return False
    return True
