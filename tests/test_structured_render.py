from __future__ import annotations

from app.structured_render import _render_math_segment, math_renderer_head_html


def test_math_renderer_keeps_adjacent_unbraced_superscripts_separate() -> None:
    html = _render_math_segment("x^2+y^2")

    assert "x<sup>2</sup>+y<sup>2</sup>" in html
    assert "<sup>2+y</sup>" not in html


def test_browser_math_renderer_keeps_adjacent_unbraced_superscripts_separate() -> None:
    head_html = math_renderer_head_html()

    assert r"\^(-?\d+|[A-Za-z])" in head_html
    assert r"\^\{?([A-Za-z0-9+\-]+)\}?" not in head_html
