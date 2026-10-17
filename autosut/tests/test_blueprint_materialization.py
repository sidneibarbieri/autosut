"""The blueprint -> SUTProfile materializer must produce a profile the canonical backend can bring up."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
for root in (PROJECT_ROOT / "src", PROJECT_ROOT / "scripts"):
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))

from planning.blueprint_materialization import sut_profile_from_blueprint  # noqa: E402
from planning.sut_blueprint import BackendRecipe, BlueprintHost, SUTBlueprint  # noqa: E402


def _docker_host(host_id: str, role: str = "target") -> BlueprintHost:
    return BlueprintHost(
        host_id=host_id, role=role, platform="Linux",
        recipe=BackendRecipe(backend="docker", base_image="python:3.11-slim", memory_mb=2048, cpu_count=2),
    )


def _blueprint(campaign_id: str, hosts: list[BlueprintHost]) -> SUTBlueprint:
    return SUTBlueprint(
        campaign_id=campaign_id, source_constraint_sha256="0" * 64,
        hosts=hosts, concretized_requirements=[],
    )


def test_single_host_blueprint_fills_scalar_fields():
    profile = sut_profile_from_blueprint(_blueprint("C0010", [_docker_host("target-1")]))
    assert profile.sut_id == "C0010-sut"
    assert profile.backend == "docker"
    assert profile.base_image == "python:3.11-slim"
    assert profile.smp == 2
    assert not profile.is_multi_host


def test_multi_host_blueprint_fills_hosts():
    profile = sut_profile_from_blueprint(_blueprint(
        "C0026", [_docker_host("attacker-1", role="attacker"), _docker_host("target-1")]))
    assert profile.is_multi_host
    assert [host.name for host in profile.hosts] == ["attacker-1", "target-1"]


def test_unsupported_backend_is_rejected():
    host = BlueprintHost(
        host_id="h", role="target", platform="Solaris",
        recipe=BackendRecipe(backend="zones", base_image="x", memory_mb=1, cpu_count=1))
    with pytest.raises(ValueError, match="unsupported materialization backend"):
        sut_profile_from_blueprint(_blueprint("Cx", [host]))


@pytest.mark.parametrize("backend", ["qemu", "windows-qemu"])
def test_vm_fleet_cannot_be_materialized_as_a_docker_fleet(backend):
    hosts = [
        _docker_host(host_id).model_copy(update={
            "recipe": BackendRecipe(backend=backend, base_image="guest.qcow2", memory_mb=2048, cpu_count=2),
        })
        for host_id in ("target-1", "target-2")
    ]

    with pytest.raises(ValueError, match="multi-host backend"):
        sut_profile_from_blueprint(_blueprint("C0045", hosts))
