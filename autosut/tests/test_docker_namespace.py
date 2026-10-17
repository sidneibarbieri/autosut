"""Docker namespace inventory is fail-closed: an unavailable daemon is not an empty namespace."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from infrastructure import docker_namespace  # noqa: E402


@pytest.mark.parametrize("resource", [
    "container:production", "network:other-autosut-network", "volume:--help",
    "container:autosut-", "image:autosut-test", "autosut-test",
])
def test_removal_refuses_resources_outside_owned_namespace(monkeypatch, resource):
    def forbidden_call(*args, **kwargs):
        pytest.fail("invalid resource must be rejected before invoking Docker")

    monkeypatch.setattr(docker_namespace.subprocess, "run", forbidden_call)
    with pytest.raises(ValueError, match="outside the autosut namespace"):
        docker_namespace.force_remove(resource)


def test_inventory_rejects_filter_substring_false_positives(monkeypatch):
    def listing(command, **_kwargs):
        if "network" in command:
            kind = "network"
        elif "volume" in command:
            kind = "volume"
        else:
            kind = "container"
        return subprocess.CompletedProcess(
            command,
            returncode=0,
            stdout=f"autosut-{kind}\nother-autosut-{kind}\n",
            stderr="",
        )

    monkeypatch.setattr(docker_namespace.subprocess, "run", listing)

    assert docker_namespace.autosut_resources() == {
        "container:autosut-container",
        "network:autosut-network",
        "volume:autosut-volume",
    }


def test_nonzero_inventory_is_structured_and_not_treated_as_empty(monkeypatch):
    def unavailable(command, **_kwargs):
        return subprocess.CompletedProcess(
            command,
            returncode=1,
            stdout="",
            stderr=(
                "Cannot connect to Docker: api_key=must-not-be-persisted\n"
                "Authorization: Bearer must-not-be-persisted-either"
            ),
        )

    monkeypatch.setattr(docker_namespace.subprocess, "run", unavailable)

    with pytest.raises(docker_namespace.DockerInventoryError) as raised:
        docker_namespace.autosut_resources()

    diagnostic = raised.value.diagnostic
    assert diagnostic.resource_kind == "container"
    assert diagnostic.command == [
        "docker",
        "ps",
        "-a",
        "--filter",
        "name=autosut-",
        "--format",
        "{{.Names}}",
    ]
    assert diagnostic.return_code == 1
    assert diagnostic.failure_kind is docker_namespace.DockerInventoryFailureKind.NONZERO_EXIT
    assert "must-not-be-persisted" not in diagnostic.stderr
    assert "api_key=<redacted>" in diagnostic.stderr
    assert "Authorization: <redacted>" in diagnostic.stderr


def test_missing_docker_cli_is_not_treated_as_empty_namespace(monkeypatch):
    def missing_cli(_command, **_kwargs):
        raise FileNotFoundError(2, "No such file or directory", "docker")

    monkeypatch.setattr(docker_namespace.subprocess, "run", missing_cli)

    with pytest.raises(docker_namespace.DockerInventoryError) as raised:
        docker_namespace.NamespaceSweep.capture()

    diagnostic = raised.value.diagnostic
    assert diagnostic.return_code is None
    assert diagnostic.failure_kind is docker_namespace.DockerInventoryFailureKind.COMMAND_NOT_FOUND
