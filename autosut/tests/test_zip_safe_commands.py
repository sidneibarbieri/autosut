"""Reviewer-facing commands must work from the anonymous ZIP, which drops executable bits."""

import re
from pathlib import Path

import pytest

AUTOSUT_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_ROOT = AUTOSUT_ROOT.parent
DOT_SLASH_SCRIPT = re.compile(r"(^|[^\w./])\./[\w-]+\.sh\b")
REVIEWER_FACING = (
    PACKAGE_ROOT / "run.sh",
    PACKAGE_ROOT / "README.md",
    AUTOSUT_ROOT / "run.sh",
)


@pytest.mark.parametrize("path", REVIEWER_FACING, ids=lambda path: path.relative_to(PACKAGE_ROOT).as_posix())
def test_reviewer_facing_text_never_relies_on_an_executable_bit(path):
    lines = path.read_text().splitlines()
    offending = [f"{number}: {line.strip()}" for number, line in enumerate(lines, 1)
                 if DOT_SLASH_SCRIPT.search(line)]
    assert not offending, "use 'bash script.sh' instead:\n" + "\n".join(offending)
