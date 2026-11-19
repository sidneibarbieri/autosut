"""Every asset the workbench page loads must be served from 'self', which its CSP requires."""

import re
from pathlib import Path

from planning.environment_workbench_http import STATIC_FILES

WEB_ROOT = Path(__file__).resolve().parents[1] / "web" / "environment-workbench"
LOCAL_REFERENCE = re.compile(r"""\b(?:href|src)=["']([^"'#]+)["']""")


def test_page_references_only_served_files():
    html = (WEB_ROOT / "index.html").read_text()
    references = LOCAL_REFERENCE.findall(html)
    assert references, "the page should load its own assets"
    for reference in references:
        assert not reference.startswith("data:"), f"blocked by default-src 'self': {reference[:40]}"
        if reference.startswith(("http://", "https://")):
            continue
        assert reference in STATIC_FILES, f"{reference} is referenced but not served"
        assert (WEB_ROOT / STATIC_FILES[reference][0]).is_file()
