"""The ingress probe requires isolation and independent transfer evidence."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from planning.ingress_probe_runtime import (
    container_command,
    verify_http_service_observations,
    verify_ingress_observations,
    verify_local_resource_observations,
    verify_resolver_observations,
)


def test_container_starts_on_private_network_without_host_mounts() -> None:
    command = container_command("probe-actor", "probe-net", "python:3.11-slim", "actor.test")

    assert command[:3] == ["docker", "run", "-d"]
    assert command[command.index("--network") + 1] == "probe-net"
    assert "--read-only" in command
    assert command[command.index("--cap-drop") + 1] == "ALL"
    assert "--privileged" not in command
    assert "-v" not in command and "--mount" not in command


def test_ingress_needs_hash_server_log_and_gateway_denial() -> None:
    digest = "a" * 64
    assert verify_ingress_observations(digest, digest, "GET /fixture ", "blocked_observed")
    with pytest.raises(ValueError, match="destination hash"):
        verify_ingress_observations(digest, "b" * 64, "GET /fixture ", "blocked_observed")
    with pytest.raises(ValueError, match="source request"):
        verify_ingress_observations(digest, digest, "", "blocked_observed")
    with pytest.raises(ValueError, match="host gateway"):
        verify_ingress_observations(digest, digest, "GET /fixture ", "not_certified")


def test_http_service_requires_target_observation() -> None:
    digest = "a" * 64
    assert verify_http_service_observations(digest, digest, "GET /index.html ", "blocked_observed")
    with pytest.raises(ValueError, match="actor hash"):
        verify_http_service_observations(digest, "b" * 64, "GET /index.html ", "blocked_observed")


def test_resolver_requires_declared_actor_address() -> None:
    assert verify_resolver_observations("172.20.0.2", "172.20.0.2", "blocked_observed")
    with pytest.raises(ValueError, match="undeclared address"):
        verify_resolver_observations("172.20.0.3", "172.20.0.2", "blocked_observed")


def test_local_resource_requires_independent_matching_digest() -> None:
    assert verify_local_resource_observations("decoy-data", "a" * 64, "a" * 64)
    with pytest.raises(ValueError, match="decoy-data digest"):
        verify_local_resource_observations("decoy-data", "a" * 64, "b" * 64)
