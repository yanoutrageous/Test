from __future__ import annotations

from html import escape
from typing import Any

from .structured_render import render_printable_paper_html


class PaperRenderService:
    """Render formal paper HTML from already-selected export-ready questions."""

    def render_printable(
        self,
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
        return render_printable_paper_html(
            questions,
            rejected=rejected or [],
            export=export,
            title=title,
            basket_url=basket_url,
            export_url=export_url,
            save_url=save_url,
            asset_url_mode=asset_url_mode,
        )


def render_export_quality_audit_html(
    rows_by_status: dict[str, list[dict[str, Any]]],
    *,
    title: str = "阶段 12 导出质量抽样验收",
) -> str:
    sections = []
    for status, rows in rows_by_status.items():
        body = "".join(_audit_row(row) for row in rows) or "<tr><td colspan=\"5\">none</td></tr>"
        sections.append(
            f"""
            <section>
              <h2>{escape(status)}</h2>
              <table>
                <thead>
                  <tr><th>QID</th><th>Page</th><th>Usability</th><th>Render</th><th>Reasons / Flags</th></tr>
                </thead>
                <tbody>{body}</tbody>
              </table>
            </section>
            """
        )
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{escape(title)}</title>
  <style>
    :root {{ color-scheme: light; font-family: "Segoe UI", Arial, sans-serif; }}
    body {{ margin: 0; background: #f6f7f9; color: #111827; }}
    main {{ max-width: 1100px; margin: 0 auto; padding: 28px; }}
    h1 {{ font-size: 24px; margin: 0 0 18px; }}
    h2 {{ font-size: 18px; margin: 24px 0 8px; }}
    table {{ width: 100%; border-collapse: collapse; background: white; border: 1px solid #e5e7eb; }}
    th, td {{ border-bottom: 1px solid #e5e7eb; padding: 8px; text-align: left; vertical-align: top; }}
    th {{ background: #eef2f7; }}
    td:last-child {{ overflow-wrap: anywhere; }}
  </style>
</head>
<body>
<main>
  <h1>{escape(title)}</h1>
  {''.join(sections)}
</main>
</body>
</html>
"""


def _audit_row(row: dict[str, Any]) -> str:
    reasons = row.get("blocking_reasons") or []
    flags = row.get("quality_flags") or []
    reason_text = ", ".join(str(item) for item in reasons)
    flag_text = ", ".join(str(item) for item in flags)
    combined = escape(reason_text)
    if flag_text:
        combined = f"{combined}<br>flags: {escape(flag_text)}" if combined else f"flags: {escape(flag_text)}"
    return (
        "<tr>"
        f"<td>{escape(str(row.get('qid') or ''))}</td>"
        f"<td>{escape(str(row.get('source_page') or ''))}</td>"
        f"<td>{escape(str(row.get('source_usability_status') or ''))}</td>"
        f"<td>{escape(str(row.get('render_mode') or ''))}</td>"
        f"<td>{combined}</td>"
        "</tr>"
    )
