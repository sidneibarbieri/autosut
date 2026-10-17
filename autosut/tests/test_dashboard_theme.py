"""Keep the dashboard's theme state explicit and optional storage failures narrow."""

import importlib
from pathlib import Path


def _theme_page(monkeypatch):
    root = Path(__file__).resolve().parents[1]
    monkeypatch.syspath_prepend(str(root / "scripts"))
    dashboard = importlib.import_module("build_reviewer_dashboard")
    for name in dir(dashboard):
        if name.startswith("render_") and name != "render_html":
            monkeypatch.setattr(dashboard, name, lambda *args, **kwargs: "")
    return dashboard.render_html({}, "", None, {})


def test_rendered_theme_toggle_exposes_effective_state(monkeypatch):
    html = _theme_page(monkeypatch)
    assert "aria-label='Toggle color theme' aria-pressed='false'" in html
    assert "var current = effectiveTheme();" in html
    assert "window.matchMedia('(prefers-color-scheme: dark)').matches" in html
    assert "String(effectiveTheme() === 'dark')" in html
    assert "addEventListener('change', syncThemeToggle)" in html


def test_storage_only_accepts_known_themes_and_expected_denials(monkeypatch):
    html = _theme_page(monkeypatch)
    assert "stored === 'light' || stored === 'dark'" in html
    assert "if (err.name !== 'SecurityError') throw err;" in html
    assert "err.name !== 'SecurityError' && err.name !== 'QuotaExceededError'" in html
    assert "catch (err) {}" not in html


def test_long_inline_evidence_tokens_are_mobile_bounded(monkeypatch):
    root = Path(__file__).resolve().parents[1]
    monkeypatch.syspath_prepend(str(root / "scripts"))
    dashboard = importlib.import_module("build_reviewer_dashboard")
    assert ".value-key { display: inline-block; max-width: 100%;" in dashboard.STYLE
    assert ".kbd { display: inline-block; max-width: 100%;" in dashboard.STYLE
    assert dashboard.STYLE.count("white-space: normal; overflow-wrap: anywhere;") >= 2
