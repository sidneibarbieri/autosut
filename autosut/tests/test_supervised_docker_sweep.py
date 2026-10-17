"""The namespace sweep removes real autosut Docker resources, and the supervisor does so after a kill.

These are opt-in integration tests: they create and destroy real containers, so they run only when
AUTOSUT_DOCKER_INTEGRATION=1 and a docker daemon is reachable. The first proves the sweep in isolation;
the second proves the whole supervised path -- a hung run that created a container is terminated by the
process group and its container is swept -- which is the guarantee the canonical entrypoint relies on.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from infrastructure.docker_namespace import NamespaceSweep, autosut_resources  # noqa: E402
from infrastructure.process_supervisor import supervise  # noqa: E402

_DOCKER_OPT_IN = os.environ.get("AUTOSUT_DOCKER_INTEGRATION") == "1"


def _docker_available() -> bool:
    probe = subprocess.run(
        ["docker", "version", "--format", "{{.Server.Version}}"],
        capture_output=True, text=True, check=False, timeout=15,
    )
    return probe.returncode == 0


pytestmark = pytest.mark.skipif(
    not (_DOCKER_OPT_IN and _docker_available()),
    reason="set AUTOSUT_DOCKER_INTEGRATION=1 with a reachable docker daemon to run",
)


def _remove(name: str) -> None:
    subprocess.run(["docker", "rm", "-f", name], capture_output=True, text=True,
                   check=False, timeout=60)


def test_sweep_removes_a_real_autosut_container():
    name = "autosut-sweeptest-probe"
    _remove(name)
    baseline = NamespaceSweep.capture()
    subprocess.run(
        ["docker", "run", "-d", "--name", name, "alpine", "sleep", "300"],
        capture_output=True, text=True, check=True, timeout=60,
    )
    try:
        assert f"container:{name}" in autosut_resources()
        residual = baseline.sweep()
        assert residual == []
        assert f"container:{name}" not in autosut_resources()
    finally:
        _remove(name)


def test_supervisor_terminates_and_sweeps_a_hung_run_that_created_a_container():
    name = "autosut-suphang-probe"
    _remove(name)
    create_then_hang = (
        "import subprocess, time; "
        f"subprocess.run(['docker','run','-d','--name','{name}','alpine','sleep','600'], check=True); "
        "time.sleep(600)"
    )
    baseline = NamespaceSweep.capture()
    try:
        outcome = supervise(
            [sys.executable, "-c", create_then_hang],
            deadline_seconds=8, grace_seconds=3, sweep=baseline.sweep,
        )
        assert outcome.completed_naturally is False
        assert outcome.escalation in (["SIGTERM"], ["SIGTERM", "SIGKILL"])
        assert outcome.terminated_clean is True
        assert outcome.residual_after_termination == []
        assert f"container:{name}" not in autosut_resources()
    finally:
        _remove(name)
