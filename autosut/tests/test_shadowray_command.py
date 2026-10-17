from __future__ import annotations

import base64
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from run_shadowray_via_caldera import _ray_job_submission_command  # noqa: E402


def test_shadowray_command_uses_stdlib_and_run_specific_marker() -> None:
    command = _ray_job_submission_command(
        "192.0.2.10",
        marker_file="/tmp/effect-123",
        marker_value="expected-456",
    )
    encoded = command.split()[2]
    script = base64.b64decode(encoded).decode()

    compile(script, "ray_probe.py", "exec")
    assert "urllib.request" in script
    assert "requests" not in script
    assert "pip install" not in command
    assert "/tmp/effect-123" in script
    assert "expected-456" in script
