"""Verified teardown primitives for Docker-backed campaign resources."""

from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass


@dataclass(frozen=True)
class DockerTeardownReceipt:
    """Removal request and independent postcondition for one Docker resource."""

    command: tuple[str, ...]
    return_code: int
    stdout: str
    stderr: str
    absent: bool
    verification_error: str = ""

    @property
    def clean(self) -> bool:
        return self.absent and not self.verification_error

    def as_log(self) -> str:
        return (
            f"{' '.join(self.command)}\n"
            f"exit_code: {self.return_code}\n"
            f"stdout: {self.stdout}\n"
            f"stderr: {self.stderr}\n"
            f"verified_absent: {str(self.absent).lower()}\n"
            f"verification_error: {self.verification_error or '(none)'}\n"
        )


def stop_container(
    container_name: str,
    *,
    grace_seconds: float = 30.0,
    interval_seconds: float = 0.5,
) -> DockerTeardownReceipt:
    """Stop an auto-removing container and wait until Docker confirms absence."""
    return _remove_and_confirm(
        command=("docker", "stop", container_name),
        inspect_command=("docker", "container", "inspect", container_name),
        missing_messages=(
            f"error: no such container: {container_name}".lower(),
            f"error: no such object: {container_name}".lower(),
            f"error response from daemon: no such container: {container_name}".lower(),
        ),
        grace_seconds=grace_seconds,
        interval_seconds=interval_seconds,
    )


def remove_network(
    network_name: str,
    *,
    grace_seconds: float = 30.0,
    interval_seconds: float = 0.5,
) -> DockerTeardownReceipt:
    """Remove a network and wait until Docker confirms absence."""
    return _remove_and_confirm(
        command=("docker", "network", "rm", network_name),
        inspect_command=("docker", "network", "inspect", network_name),
        missing_messages=(
            f"error: no such network: {network_name}".lower(),
            f"error: no such object: {network_name}".lower(),
            f"error response from daemon: network {network_name} not found".lower(),
        ),
        grace_seconds=grace_seconds,
        interval_seconds=interval_seconds,
    )


def _remove_and_confirm(
    *,
    command: tuple[str, ...],
    inspect_command: tuple[str, ...],
    missing_messages: tuple[str, ...],
    grace_seconds: float,
    interval_seconds: float,
) -> DockerTeardownReceipt:
    removal = subprocess.run(
        list(command),
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    deadline = time.monotonic() + grace_seconds
    verification_error = ""
    while True:
        inspection = subprocess.run(
            list(inspect_command),
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        if inspection.returncode != 0:
            detail = (inspection.stderr or inspection.stdout).strip()
            if detail.lower() in missing_messages:
                return DockerTeardownReceipt(
                    command=command,
                    return_code=removal.returncode,
                    stdout=removal.stdout,
                    stderr=removal.stderr,
                    absent=True,
                )
            verification_error = (
                f"Docker inspection failed with exit {inspection.returncode}: "
                f"{detail or 'no diagnostic'}"
            )
        else:
            verification_error = ""
        if time.monotonic() >= deadline:
            return DockerTeardownReceipt(
                command=command,
                return_code=removal.returncode,
                stdout=removal.stdout,
                stderr=removal.stderr,
                absent=False,
                verification_error=verification_error,
            )
        time.sleep(interval_seconds)
