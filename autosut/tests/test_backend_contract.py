"""The backend contract self-qualifies and rejects unknown backends honestly.

A backend that does not implement check() is reported not-ready rather than assumed ready; the
factory raises on an unknown backend instead of importing a module that does not exist; and each
concrete backend's check() names itself and returns a real readiness verdict.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from orchestrator.environment import DockerEnvironment  # noqa: E402
from orchestrator.environment_base import (  # noqa: E402
    BackendReadiness,
    EnvironmentBackend,
    select_backend,
)
from orchestrator.qemu_environment import QEMUEnvironment  # noqa: E402
from orchestrator.windows_qemu_environment import WindowsQemuEnvironment  # noqa: E402


class _BackendWithoutCheck(EnvironmentBackend):
    backend_name = "unchecked"

    @classmethod
    def bring_up(cls, sut, run_dir):  # pragma: no cover - not exercised
        raise NotImplementedError

    @property
    def host_id(self):  # pragma: no cover - not exercised
        return "none"

    def run_shell(self, command, log_name=None, timeout=600):  # pragma: no cover
        raise NotImplementedError

    def teardown(self):  # pragma: no cover - not exercised
        return True


class _SUT:
    def __init__(self, backend):
        self.backend = backend


def test_a_backend_without_a_check_is_reported_not_ready():
    readiness = _BackendWithoutCheck.check()
    assert readiness.ready is False
    assert readiness.gaps


def test_select_backend_raises_on_an_unknown_backend():
    with pytest.raises(ValueError):
        select_backend(_SUT("tart"))


def test_select_backend_routes_docker_qemu_and_windows():
    assert select_backend(_SUT(None)) is DockerEnvironment
    assert select_backend(_SUT("docker")) is DockerEnvironment
    assert select_backend(_SUT("qemu")) is QEMUEnvironment
    assert select_backend(_SUT("windows-qemu")) is WindowsQemuEnvironment


def test_each_concrete_check_names_itself_and_returns_readiness():
    for backend in (DockerEnvironment, QEMUEnvironment, WindowsQemuEnvironment):
        readiness = backend.check()
        assert isinstance(readiness, BackendReadiness)
        assert readiness.backend_name == backend.backend_name
        assert isinstance(readiness.ready, bool)


def test_windows_backend_satisfies_the_contract_surface():
    assert issubclass(WindowsQemuEnvironment, EnvironmentBackend)
    assert WindowsQemuEnvironment.backend_name == "windows-qemu"
    # check() is a dependency preflight that runs without materializing anything.
    readiness = WindowsQemuEnvironment.check()
    assert readiness.backend_name == "windows-qemu"
