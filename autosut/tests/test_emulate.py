from __future__ import annotations

import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
C0045_PLAN = PROJECT_ROOT / "release" / "inputs" / "sticks" / "c0045-v1" / "C0045.procedural-plan.json"


def _emulate(plan: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "scripts/emulate.py", str(plan)],
        cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=120,
    )


def test_reports_platform_coverage_without_implying_a_provisioned_host():
    result = _emulate(C0045_PLAN)
    assert result.returncode == 0, result.stderr
    assert "Declared platform requirements are covered by the Linux backend" in result.stdout
    assert "Operational status: not_run" in result.stdout
    assert "service readiness and target effects are not verified" in result.stdout
    assert "The procedure needs a System Under Test" in result.stdout


def test_rejects_a_missing_plan():
    result = _emulate(Path("does-not-exist.json"))
    assert result.returncode != 0
    assert "procedural plan not found" in result.stderr
