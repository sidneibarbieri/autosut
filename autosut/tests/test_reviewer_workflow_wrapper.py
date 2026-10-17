from __future__ import annotations

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent


def test_reviewer_workflow_wrapper_uses_the_pinned_reviewer_environment():
    wrapper = PROJECT_ROOT / "scripts" / "run_reviewer_workflow.sh"
    source = wrapper.read_text(encoding="utf-8")

    assert "set -euo pipefail" in source
    assert "requirements-reviewer.txt" in source
    assert "autosut_resolve_python" in source
    assert "run_reviewer_workflow.py" in source
