"""Docker-backed isolated environment for one campaign run.

Each invocation creates a fresh container based on the SUT profile, returns a
handle that supports running shell commands and copying files, and tears the
container down on context exit. No state is shared between runs.

Threat model note: every shell command executed inside the container comes
from the orchestrator's own catalog (catalog.py and the per-campaign
injectors). No external user input flows into these calls. The bash shell is
exercised in the container, not on the host.
"""

from __future__ import annotations

import os
import subprocess
import uuid
from pathlib import Path

# Backwards-compat: CommandResult was originally defined here; keep the
# import so external callers continue to work, but the canonical home is
# now ``environment_base``.
from .environment_base import CommandResult, EnvironmentBackend  # noqa: F401
from .models import SUTProfile


class DockerEnvironment(EnvironmentBackend):
    """One container instantiated for the duration of a single campaign run.

    Canonical reviewer-facing execution substrate: portable, fast cold
    start, every host can run it.
    """

    backend_name = "docker"

    def __init__(self, container_name: str, sut: SUTProfile, run_dir: Path):
        self.container_name = container_name
        self.sut = sut
        self.run_dir = run_dir

    @property
    def host_id(self) -> str:
        return self.container_name

    @classmethod
    def bring_up(cls, sut: SUTProfile, run_dir: Path) -> "DockerEnvironment":
        container_name = f"autosut-{uuid.uuid4().hex[:10]}"
        run_dir.mkdir(parents=True, exist_ok=True)

        platform = os.environ.get("AUTOSUT_DOCKER_PLATFORM", "").strip()
        platform_args = ["--platform", platform] if platform else []
        subprocess.run(
            ["docker", "pull", *platform_args, sut.base_image],
            capture_output=True, text=True, check=False,
        )
        proc = subprocess.run(
            [
                "docker", "run", "-d",
                *platform_args,
                "--name", container_name,
                "--rm",
                "--memory", f"{sut.memory_mb}m",
                "--cpus", str(sut.smp),
                "--shm-size", "1024m",  # ray needs /dev/shm for plasma store
                sut.base_image,
                "sleep", "infinity",
            ],
            capture_output=True, text=True, check=True,
        )
        log_path = run_dir / "sut" / "setup.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(
            f"# container bring-up\nimage: {sut.base_image}\nname: {container_name}\n"
            f"platform: {platform or 'default'}\n"
            f"container_id: {proc.stdout.strip()}\n",
            encoding="utf-8",
        )
        return cls(container_name, sut, run_dir)

    def __enter__(self) -> "DockerEnvironment":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.teardown()

    def run_shell(self, command: str, log_name: str | None = None,
                  timeout: int = 600) -> CommandResult:
        """Execute a shell command inside the container.

        The host-side call uses subprocess with a list argv; bash runs only
        inside the container. The argument `command` is trusted (orchestrator-
        owned recipes), never reviewer-supplied.
        """
        # ``sh -c`` rather than ``bash -c`` so the contract works on both
        # Debian/Ubuntu (where /bin/sh is dash, bash optional) and Alpine
        # (where bash isn't installed by default but /bin/sh always is).
        # Recipes that genuinely need bash can still call ``bash -c`` from
        # within the command string.
        proc = subprocess.run(
            ["docker", "exec", self.container_name, "sh", "-c", command],
            capture_output=True, text=True, timeout=timeout,
        )
        result = CommandResult(
            cmd=command, exit_code=proc.returncode,
            stdout=proc.stdout, stderr=proc.stderr,
        )
        if log_name:
            log_path = self.run_dir / log_name
            log_path.parent.mkdir(parents=True, exist_ok=True)
            log_path.write_text(
                f"$ {command}\n"
                f"exit_code: {result.exit_code}\n"
                f"--- stdout ---\n{result.stdout}\n"
                f"--- stderr ---\n{result.stderr}\n",
                encoding="utf-8",
            )
        return result

    def teardown(self) -> bool:
        proc = subprocess.run(
            ["docker", "stop", self.container_name],
            capture_output=True, text=True, check=False, timeout=60,
        )
        log_path = self.run_dir / "sut" / "teardown.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(
            f"docker stop {self.container_name}\nexit_code: {proc.returncode}\n"
            f"stdout: {proc.stdout}\nstderr: {proc.stderr}\n",
            encoding="utf-8",
        )
        return proc.returncode == 0


def select_backend() -> type[DockerEnvironment]:
    """Legacy single-backend factory. Retained for backwards compatibility.

    New code should call :func:`environment_base.select_backend` with the
    SUT profile so per-campaign backend selection ("docker" / "qemu" /
    "tart") is respected.
    """
    return DockerEnvironment
