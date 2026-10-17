from __future__ import annotations

import subprocess
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_artifact_run_help_has_no_docker_side_effects() -> None:
    result = subprocess.run(
        ["bash", str(PROJECT_ROOT / "artifact" / "run.sh"), "--help"],
        cwd=PROJECT_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )

    assert "without contacting Docker" in result.stdout
    assert "Docker daemon:" not in result.stdout
    assert "pulling target image" not in result.stdout
