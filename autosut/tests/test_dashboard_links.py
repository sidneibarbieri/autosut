from pathlib import Path

import pytest

from scripts.validate_dashboard_links import audit_links


def _page(root: Path, content: str) -> Path:
    page = root / "release/dashboard/index.html"
    page.parent.mkdir(parents=True, exist_ok=True)
    page.write_text(content, encoding="utf-8")
    return page


def test_artifact_root_retains_parent_evidence_links(tmp_path):
    evidence = tmp_path / "measurement/result.json"
    evidence.parent.mkdir()
    evidence.write_text("{}")
    page = _page(tmp_path, '<a href="../../measurement/result.json">Evidence</a>')
    assert audit_links(page, tmp_path) == []
    assert audit_links(page, page.parent)[0].reason == "outside_artifact"


@pytest.mark.parametrize(
    "reference,reason",
    [
        ("data/missing.csv", "missing_file"),
        ("#missing", "missing_anchor"),
        ("../../../outside", "outside_artifact"),
        ("%2e%2e/%2e%2e/%2e%2e/outside", "outside_artifact"),
        ("file:///private/file", "unsupported_scheme"),
    ],
)
def test_broken_or_escaping_links_are_reported(tmp_path, reference, reason):
    page = _page(tmp_path, f'<a href="{reference}">Evidence</a>')
    issue = audit_links(page, tmp_path)[0]
    assert issue.reference == reference
    assert issue.reason == reason


def test_local_assets_queries_and_anchors(tmp_path):
    page = _page(
        tmp_path,
        '<main id="evidence"></main><a href="#evidence">Jump</a>'
        '<link href="style.css?v=2"><script src="app.js"></script>'
        '<img src="icon.svg"><a href="https://example.test/">External</a>',
    )
    for name in ("style.css", "app.js", "icon.svg"):
        (page.parent / name).write_text("")
    assert audit_links(page, tmp_path) == []


def test_symlink_cannot_expose_external_file(tmp_path):
    root = tmp_path / "artifact"
    outside = tmp_path / "external.json"
    outside.write_text("{}")
    page = _page(root, '<a href="data.json">Evidence</a>')
    (page.parent / "data.json").symlink_to(outside)
    assert audit_links(page, root)[0].reason == "outside_artifact"
