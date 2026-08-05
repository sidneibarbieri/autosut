"""Unit tests for the EnvironmentBackend abstraction.

These tests verify the substrate-selection contract without booting any
real VM. The end-to-end VM smoke is a separate, opt-in script
(``scripts/qemu_backend_smoke.py``) because cold-start box downloads can
take minutes.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Make the orchestrator package importable from tests/.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from orchestrator.environment_base import (  # noqa: E402
    CommandResult,
    EnvironmentBackend,
    select_backend,
)
from orchestrator.environment import DockerEnvironment  # noqa: E402
from orchestrator.qemu_environment import QEMUEnvironment  # noqa: E402
from orchestrator.models import SUTProfile  # noqa: E402


def _profile(backend: str | None = None) -> SUTProfile:
    return SUTProfile(
        sut_id="test", base_image="python:3.11-slim",
        services=[], memory_mb=512, smp=1, backend=backend,
    )


def test_docker_is_subclass_of_environment_backend():
    assert issubclass(DockerEnvironment, EnvironmentBackend)
    assert DockerEnvironment.backend_name == "docker"


def test_qemu_is_subclass_of_environment_backend():
    assert issubclass(QEMUEnvironment, EnvironmentBackend)
    assert QEMUEnvironment.backend_name == "qemu"


def test_default_backend_is_docker():
    assert select_backend(_profile()) is DockerEnvironment
    assert select_backend(_profile("docker")) is DockerEnvironment


def test_qemu_backend_selected_when_declared():
    assert select_backend(_profile("qemu")) is QEMUEnvironment


def test_unknown_backend_falls_back_to_docker():
    # Defensive: an unrecognised string should not crash the orchestrator.
    # Today it falls through to Docker; if we change that policy in the
    # future this test should be updated.
    assert select_backend(_profile("nonsense")) is DockerEnvironment


def test_command_result_ok_property():
    assert CommandResult("ls", 0, "", "").ok is True
    assert CommandResult("ls", 1, "", "err").ok is False


def test_environment_backend_is_abstract():
    with pytest.raises(TypeError):
        EnvironmentBackend()  # type: ignore[abstract]
