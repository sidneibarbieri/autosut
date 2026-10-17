"""Check explicit keyboard access to dashboard table regions."""

import importlib
from html.parser import HTMLParser
from pathlib import Path


class TableRegions(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.regions = []

    def handle_starttag(self, tag, attributes) -> None:
        values = dict(attributes)
        if tag == "div" and "table-wrap" in values.get("class", "").split():
            self.regions.append(values)


def test_rendered_table_has_a_named_focusable_region(monkeypatch) -> None:
    root = Path(__file__).resolve().parents[1]
    monkeypatch.syspath_prepend(str(root / "scripts"))
    dashboard = importlib.import_module("build_reviewer_dashboard")
    parser = TableRegions()
    parser.feed(dashboard.render_table(["Campaign", "Evidence"], [["C0010", "record"]]))
    assert len(parser.regions) == 1
    region = parser.regions[0]
    assert region.get("tabindex") == "0"
    assert region.get("role") == "region"
    assert region.get("aria-label") == "Data table: Campaign, Evidence"


def test_region_label_is_escaped_and_wide_layout_is_preserved(monkeypatch) -> None:
    root = Path(__file__).resolve().parents[1]
    monkeypatch.syspath_prepend(str(root / "scripts"))
    dashboard = importlib.import_module("build_reviewer_dashboard")
    parser = TableRegions()
    parser.feed(dashboard.wrap_table_region("<table></table>", "Evidence 'A' <B>", wide=True))
    region = parser.regions[0]
    assert region["aria-label"] == "Evidence 'A' <B>"
    assert region["class"] == "table-wrap wide"
    assert "tabindex='0'" in dashboard.wrap_table_region("<table></table>", "Evidence")
