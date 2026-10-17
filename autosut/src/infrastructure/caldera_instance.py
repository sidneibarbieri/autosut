"""A Caldera server owned by one run: materialized, made ready, and destroyed inside the run.

A persistent, shared Caldera cannot back a clean-rerun claim: it is not cold-started, not isolated,
and never torn down by the run. This materializes a fresh Caldera container named for the run on
its own port, waits until its API answers, exposes its randomized red API key, and force-removes it
on teardown with confirmed absence. Nothing here reuses an existing instance.
"""

from __future__ import annotations

import socket
import subprocess
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass

# Pinned by digest, not a moving tag, so every run materializes the identical Caldera build.
CALDERA_IMAGE = (
    "ghcr.io/mitre/caldera@sha256:"
    "97a8f9fd052aaabdee76e8367d1ec985b3e44e6add0b27a28d8fee9cafe426c7"
)
_GUEST_PORT = 8888
_API_KEY_FIELD = "api_key_red:"


class CalderaNotReadyError(RuntimeError):
    """The materialized Caldera did not answer its API within the readiness timeout."""


class CalderaResidualError(RuntimeError):
    """The Caldera container was still present after force-removal."""


def _free_tcp_port() -> int:
    """Ask the OS for an unused TCP port, so two runs never collide on Caldera's port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


@dataclass
class CalderaInstance:
    """One isolated Caldera server, addressed by its own container name and host port."""

    container_name: str
    host_port: int

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.host_port}"

    @staticmethod
    def prepare_image() -> tuple[bool, float]:
        """Ensure the pinned image exists and report cache status and elapsed time."""
        started = time.monotonic()
        inspection = subprocess.run(
            ["docker", "image", "inspect", CALDERA_IMAGE],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        cache_hit = inspection.returncode == 0
        if not cache_hit:
            subprocess.run(
                ["docker", "pull", "--platform", "linux/amd64", CALDERA_IMAGE],
                capture_output=True,
                text=True,
                check=True,
                timeout=900,
            )
        return cache_hit, round(time.monotonic() - started, 3)

    @classmethod
    def materialize(cls, container_name: str) -> CalderaInstance:
        """Start a fresh Caldera container on a free port. Raises if docker refuses to start it."""
        host_port = _free_tcp_port()
        subprocess.run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                container_name,
                "--platform",
                "linux/amd64",
                "-p",
                f"127.0.0.1:{host_port}:{_GUEST_PORT}",
                CALDERA_IMAGE,
            ],
            capture_output=True,
            text=True,
            check=True,
            timeout=120,
        )
        return cls(container_name=container_name, host_port=host_port)

    def wait_until_ready(
        self,
        timeout_seconds: int = 300,
        on_probe_started: Callable[[], None] | None = None,
    ) -> float:
        """Poll the landing page until it answers, returning the seconds waited.

        ``on_probe_started`` fires exactly once immediately before the first real readiness
        request.  It is used only for interruption-protocol instrumentation; it does not alter
        readiness semantics or turn a planned probe into a successful readiness claim.
        """
        started = time.monotonic()
        deadline = started + timeout_seconds
        probe_notified = False
        while time.monotonic() < deadline:
            if not probe_notified and on_probe_started is not None:
                on_probe_started()
                probe_notified = True
            if self._landing_answers():
                return round(time.monotonic() - started, 1)
            time.sleep(3)
        raise CalderaNotReadyError(
            f"{self.container_name} did not answer {self.base_url} within {timeout_seconds}s"
        )

    def _landing_answers(self) -> bool:
        """True when the Caldera landing page returns HTTP 200; connection refused is not ready."""
        try:
            with urllib.request.urlopen(self.base_url, timeout=5) as response:
                return response.status == 200
        except urllib.error.HTTPError as answered:
            return answered.code < 500
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            return False

    def read_red_api_key(self) -> str:
        """Read the container's randomized red API key. Raises if the field is absent."""
        local_yml = subprocess.run(
            ["docker", "exec", self.container_name, "cat", "/usr/src/app/conf/local.yml"],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        for line in local_yml.stdout.splitlines():
            if line.startswith(_API_KEY_FIELD):
                return line.split(":", 1)[1].strip()
        raise RuntimeError(f"{_API_KEY_FIELD} not found in {self.container_name} local.yml")

    def destroy(self) -> None:
        """Force-remove the container and confirm it is gone. Raises if it survives."""
        subprocess.run(
            ["docker", "rm", "-f", self.container_name],
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
        if self._still_present():
            raise CalderaResidualError(f"{self.container_name} survived force-removal")

    def _still_present(self) -> bool:
        listing = subprocess.run(
            [
                "docker",
                "ps",
                "-a",
                "--filter",
                f"name={self.container_name}",
                "--format",
                "{{.Names}}",
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        if listing.returncode:
            raise RuntimeError(
                f"Caldera container inventory failed: exit {listing.returncode}"
            )
        return self.container_name in listing.stdout.split()
