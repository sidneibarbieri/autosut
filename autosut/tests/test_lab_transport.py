"""A Vagrant machine that never booted must not be reported as having run a command.

Regression test: `vagrant ssh -c` can exit 0 for some multi-machine Vagrantfiles even when
the named machine was never created, printing a state warning instead of executing the
remote script. An executor trusting that exit code alone previously reported a fabricated
success for T1190 against a target that was never reachable.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from executors.lab_transport import (  # noqa: E402
    VagrantInstanceUnavailableError,
    run_command_in_vm,
)


def _completed_process(stdout: str, returncode: int = 0) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(
        args=["vagrant", "ssh", "-c", "echo hi"], returncode=returncode, stdout=stdout, stderr=""
    )


def test_a_zero_exit_with_the_not_created_marker_raises_instead_of_succeeding():
    fake_result = _completed_process(
        "==> target-linux-1: Instance is not created. Please run `vagrant up` first.",
        returncode=0,
    )
    with patch("executors.lab_transport.Path.exists", return_value=True), patch(
        "executors.lab_transport.subprocess.run", return_value=fake_result
    ):
        try:
            run_command_in_vm("target-linux-1", "echo hi")
        except VagrantInstanceUnavailableError:
            return
    raise AssertionError("a not-created machine must not be reported as having run the command")


def test_a_genuine_successful_transcript_is_returned_normally():
    fake_result = _completed_process("hello from the vm", returncode=0)
    with patch("executors.lab_transport.Path.exists", return_value=True), patch(
        "executors.lab_transport.subprocess.run", return_value=fake_result
    ):
        result = run_command_in_vm("target-linux-1", "echo hi")
    assert result.returncode == 0
    assert result.stdout == "hello from the vm"
