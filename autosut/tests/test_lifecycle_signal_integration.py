"""A SIGTERM mid-run tears the real environment down and seals an interrupted_clean bundle.

This is the automated form of a leak observed once by hand: an externally-killed run used to leave
a container behind. It is a real Docker integration test, opt-in via AUTOSUT_DOCKER_INTEGRATION=1
so the fast unit suite stays fast and signal-timing flakiness stays out of it.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
pytestmark = pytest.mark.skipif(
    os.environ.get("AUTOSUT_DOCKER_INTEGRATION") != "1",
    reason="opt-in Docker integration test; set AUTOSUT_DOCKER_INTEGRATION=1 to run",
)


def _autosut_containers() -> set[str]:
    listing = subprocess.run(
        ["docker", "ps", "-a", "--filter", "name=autosut-", "--format", "{{.Names}}"],
        capture_output=True, text=True, check=False, timeout=30,
    )
    return {name for name in listing.stdout.split() if name and "caldera" not in name}


def test_sigterm_midrun_reaches_interrupted_clean_with_no_residual(tmp_path):
    baseline = _autosut_containers()
    evidence_root = tmp_path / "evidence"
    process = subprocess.Popen(
        [
            sys.executable, "scripts/run_lifecycle.py", "0.c0010", "--label", "sigterm_auto",
            "--evidence-root", str(evidence_root),
        ],
        cwd=PROJECT_ROOT,
    )
    time.sleep(10)  # let materialization start so the signal lands mid-run
    process.send_signal(signal.SIGTERM)
    process.wait(timeout=120)

    assert _autosut_containers() - baseline == set(), "SIGTERM left a residual container"

    bundle = max(evidence_root.glob("0.c0010_sigterm_auto_*"), key=lambda path: path.stat().st_mtime)
    result = json.loads((bundle / "lifecycle-result.json").read_text(encoding="utf-8"))
    assert result["final_state"] == "interrupted_clean"
