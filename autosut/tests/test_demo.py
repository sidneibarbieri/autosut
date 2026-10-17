from __future__ import annotations

import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _run_demo() -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "scripts/demo.py"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )


def test_demo_runs_offline_and_shows_the_gap():
    # This is the first command a reviewer runs, so a break here is as serious as a failing claim.
    result = _run_demo()
    assert result.returncode == 0, result.stderr
    assert "WHAT PUBLIC THREAT INTELLIGENCE ANSWERS" in result.stdout
    assert "Structured intelligence narrows the candidate environment" in result.stdout


def test_demo_reports_generated_values_not_literals():
    result = _run_demo()
    # Platform coverage and system-requirement coverage are the two ends of the measured gradient.
    assert "697 techniques" in result.stdout
    assert "100.0%" in result.stdout
    assert "0.0%" in result.stdout


def test_demo_defaults_to_a_value_file_inside_the_artifact():
    source = (PROJECT_ROOT / "scripts" / "demo.py").read_text(encoding="utf-8")
    assert 'PROJECT_ROOT / "release" / "study_values.tex"' in source
    assert 'parent / "paper"' not in source
