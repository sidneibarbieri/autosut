"""A failed real-service attempt must remain auditable after fallback."""

import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from orchestrator.injector import (
    inject_ray_2_6_3,
    inject_ray_dashboard_surrogate,
    rebind_ray_after_isolation,
)


class RecordingEnvironment:
    def __init__(self):
        self.logs = []

    def run_shell(self, command, *, log_name, timeout):
        self.logs.append(log_name)
        return SimpleNamespace(ok=False)


def test_ray_fallback_keeps_failed_real_attempt_log():
    environment = RecordingEnvironment()
    real = inject_ray_2_6_3(environment)
    surrogate = inject_ray_dashboard_surrogate(environment)

    assert real.log_path != surrogate.log_path
    assert environment.logs == [real.log_path, surrogate.log_path]


def test_ray_rebind_checks_jobs_api_after_network_change():
    class ReadyEnvironment:
        def run_shell(self, command, *, log_name, timeout):
            assert "ray stop --force" in command
            assert "ray start --head" in command
            assert "ray_job_preflight=ok" in command
            assert log_name == "sut/ray_rebind_after_isolation.log"
            return SimpleNamespace(ok=True)

    rebind_ray_after_isolation(ReadyEnvironment())
