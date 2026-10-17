"""The process supervisor genuinely terminates a wedged run, not merely stops waiting for it.

A child that exits on its own is reported as such. A child that overruns the deadline is stopped
with SIGTERM within the grace window. A child that TRAPS SIGTERM is still terminated, by SIGKILL,
which cannot be trapped -- this is the property a worker thread cannot provide. Because the child is
a process-group leader, the kill reaches a grandchild it spawned too, so no descendant survives.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from infrastructure.process_supervisor import supervise  # noqa: E402
from infrastructure.docker_namespace import (  # noqa: E402
    DockerInventoryDiagnostic,
    DockerInventoryError,
    DockerInventoryFailureKind,
)


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


def _no_residual() -> list[str]:
    return []


def test_natural_exit_is_reported_with_its_code():
    outcome = supervise(
        [sys.executable, "-c", "pass"],
        deadline_seconds=10,
        grace_seconds=2,
        sweep=_no_residual,
    )
    assert outcome.completed_naturally is True
    assert outcome.exit_code == 0
    assert outcome.escalation == []
    assert outcome.terminated_clean is True


def test_non_zero_exit_is_preserved():
    outcome = supervise(
        [sys.executable, "-c", "import sys; sys.exit(3)"],
        deadline_seconds=10,
        grace_seconds=2,
        sweep=_no_residual,
    )
    assert outcome.completed_naturally is True
    assert outcome.exit_code == 3


def test_deadline_overrun_is_stopped_with_sigterm_within_grace():
    outcome = supervise(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        deadline_seconds=0.5,
        grace_seconds=3,
        sweep=_no_residual,
    )
    assert outcome.completed_naturally is False
    assert outcome.escalation == ["SIGTERM"]
    assert outcome.grace_deadline_exceeded is False
    assert _pid_alive(outcome.pid) is False


def test_child_that_traps_sigterm_is_still_killed():
    """The decisive property: SIGKILL terminates a process that refuses to honour SIGTERM."""
    ignore_sigterm = (
        "import signal, time; " "signal.signal(signal.SIGTERM, signal.SIG_IGN); " "time.sleep(120)"
    )
    outcome = supervise(
        [sys.executable, "-c", ignore_sigterm],
        deadline_seconds=0.5,
        grace_seconds=1,
        sweep=_no_residual,
    )
    assert outcome.completed_naturally is False
    assert outcome.escalation == ["SIGTERM", "SIGKILL"]
    assert outcome.grace_deadline_exceeded is True
    assert _pid_alive(outcome.pid) is False


def test_kill_reaches_a_grandchild_in_the_group(tmp_path):
    """A process-group kill reaches a descendant the child spawned, so nothing is orphaned."""
    grandchild_pid_file = tmp_path / "grandchild.pid"
    spawn_grandchild = (
        "import subprocess, sys, time, pathlib; "
        f"gc = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)']); "
        f"pathlib.Path(r'{grandchild_pid_file}').write_text(str(gc.pid)); "
        "time.sleep(120)"
    )
    outcome = supervise(
        [sys.executable, "-c", spawn_grandchild],
        deadline_seconds=1.0,
        grace_seconds=1,
        sweep=_no_residual,
    )
    assert outcome.completed_naturally is False

    deadline = time.monotonic() + 5
    while not grandchild_pid_file.is_file() and time.monotonic() < deadline:
        time.sleep(0.05)
    grandchild_pid = int(grandchild_pid_file.read_text())

    # Give the OS a moment to finish tearing down the killed group before asserting absence.
    for _ in range(50):
        if not _pid_alive(outcome.pid) and not _pid_alive(grandchild_pid):
            break
        time.sleep(0.1)
    assert _pid_alive(outcome.pid) is False
    assert _pid_alive(grandchild_pid) is False


def test_residual_left_by_the_run_is_reported_after_termination():
    outcome = supervise(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        deadline_seconds=0.5,
        grace_seconds=1,
        sweep=lambda: ["autosut-abc123-sut"],
    )
    assert outcome.terminated_clean is False
    assert outcome.residual_after_termination == ["autosut-abc123-sut"]


def test_uninspectable_cleanup_is_not_reported_as_clean():
    diagnostic = DockerInventoryDiagnostic(
        resource_kind="container",
        command=["docker", "ps", "-a"],
        return_code=1,
        stderr="Cannot connect to Docker",
        failure_kind=DockerInventoryFailureKind.NONZERO_EXIT,
    )

    def unavailable_inventory() -> list[str]:
        raise DockerInventoryError(diagnostic)

    outcome = supervise(
        [sys.executable, "-c", "pass"],
        deadline_seconds=10,
        grace_seconds=2,
        sweep=unavailable_inventory,
    )

    assert outcome.completed_naturally is True
    assert outcome.cleanup_completed is False
    assert outcome.terminated_clean is False
    assert outcome.residual_after_termination == []
    assert outcome.cleanup_error == diagnostic.model_dump(mode="json")


def test_deadline_can_be_armed_by_an_observed_stage_boundary():
    armed = False

    def arm_after_boundary() -> bool:
        return armed

    def mark_boundary() -> None:
        nonlocal armed
        time.sleep(0.25)
        armed = True

    import threading

    thread = threading.Thread(target=mark_boundary)
    thread.start()
    started = time.monotonic()
    outcome = supervise(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        deadline_seconds=0.2,
        grace_seconds=1,
        setup_deadline_seconds=2,
        sweep=_no_residual,
        arm_deadline=arm_after_boundary,
    )
    thread.join()

    assert outcome.completed_naturally is False
    assert outcome.escalation == ["SIGTERM"]
    # The deadline starts when the boundary is observed, not when the child is launched.
    assert time.monotonic() - started >= 0.4


def test_missing_stage_boundary_is_not_reported_as_natural_completion():
    outcome = supervise(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        deadline_seconds=1,
        grace_seconds=1,
        setup_deadline_seconds=0.2,
        sweep=_no_residual,
        arm_deadline=lambda: False,
    )

    assert outcome.completed_naturally is False
    assert outcome.escalation == ["SIGTERM"]


def test_interrupting_the_supervisor_still_terminates_its_child_group():
    """A SIGTERM to the wrapper must not orphan a child in its separate process session."""
    import signal
    import threading

    interrupter = threading.Timer(0.2, lambda: os.kill(os.getpid(), signal.SIGTERM))
    interrupter.start()
    try:
        outcome = supervise(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            deadline_seconds=10,
            grace_seconds=1,
            sweep=_no_residual,
        )
    finally:
        interrupter.cancel()

    assert outcome.completed_naturally is False
    assert outcome.supervisor_interruption == "SIGTERM"
    assert outcome.escalation == ["SIGTERM"]
    assert _pid_alive(outcome.pid) is False
