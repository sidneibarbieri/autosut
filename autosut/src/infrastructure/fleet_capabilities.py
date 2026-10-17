"""Declare the execution substrates supported by the current host fleet."""

from __future__ import annotations


def require_docker_fleet_backend(backend: str | None) -> None:
    if backend not in (None, "docker"):
        raise ValueError(
            f"multi-host backend {backend!r} is not supported by the Docker fleet; "
            "a separately qualified VM fleet is required"
        )
