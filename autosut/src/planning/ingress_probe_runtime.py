"""Fixed Docker command and observation policy for a private ingress witness."""

from __future__ import annotations


def container_command(name: str, network: str, image: str, alias: str) -> list[str]:
    """Start one bounded actor on an already-created internal Docker network."""
    return [
        "docker",
        "run",
        "-d",
        "--rm",
        "--name",
        name,
        "--network",
        network,
        "--network-alias",
        alias,
        "--read-only",
        "--tmpfs",
        "/tmp:rw,nosuid,noexec,size=16m",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "128",
        "--memory",
        "512m",
        "--cpus",
        "1",
        image,
        "sleep",
        "infinity",
    ]


def verify_ingress_observations(
    source_sha256: str,
    destination_sha256: str,
    server_log: str,
    gateway_access: str,
) -> bool:
    if source_sha256 != destination_sha256:
        raise ValueError("destination hash differs from staged source")
    if "GET /fixture " not in server_log:
        raise ValueError("source request was not observed")
    if gateway_access != "blocked_observed":
        raise ValueError("host gateway denial was not observed")
    return True


def verify_http_service_observations(
    target_sha256: str, actor_sha256: str, server_log: str, gateway_access: str
) -> bool:
    if actor_sha256 != target_sha256:
        raise ValueError("actor hash differs from target service content")
    if "GET /index.html " not in server_log:
        raise ValueError("target service request was not observed")
    if gateway_access != "blocked_observed":
        raise ValueError("host gateway denial was not observed")
    return True


def verify_resolver_observations(
    resolved_address: str, declared_address: str, gateway_access: str
) -> bool:
    if resolved_address != declared_address:
        raise ValueError("resolver returned an undeclared address")
    if gateway_access != "blocked_observed":
        raise ValueError("host gateway denial was not observed")
    return True


def verify_local_resource_observations(
    resource: str, expected_sha256: str, observed_sha256: str
) -> bool:
    if observed_sha256 != expected_sha256:
        raise ValueError(f"{resource} digest differs from the reviewed fixture")
    return True
