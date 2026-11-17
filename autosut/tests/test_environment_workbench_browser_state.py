"""Check asynchronous UI invalidation without a browser dependency."""

import shutil
import subprocess
import sys
from pathlib import Path
import pytest


def test_changed_input_and_failed_requests_cannot_export_stale_results():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required for the browser-state regression")
    result = subprocess.run(
        [node, str(Path(__file__).with_name("environment_workbench_state.cjs"))],
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    )
    assert "environment workbench state: PASS" in result.stdout


def test_environment_map_groups_every_step_and_requirement(tmp_path: Path) -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is required for the environment-map test")
    root = Path(__file__).resolve().parents[1]
    output = tmp_path / "C0045.planning.json"
    subprocess.run(
        [sys.executable, "scripts/emulate.py",
         "release/inputs/sticks/c0045-v1/C0045.procedural-plan.json", "--output", str(output)],
        cwd=root, check=True, capture_output=True, text=True,
    )
    completed = subprocess.run(
        [node, str(Path(__file__).with_name("environment_map.cjs")), str(output)],
        capture_output=True, text=True, check=True,
    )
    assert completed.stdout.startswith("zones attacker,boundary,target")
