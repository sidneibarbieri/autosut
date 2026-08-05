"""Abstract execution-substrate backend for one campaign run.

AutoSUT separates **orchestration semantics** (tuple, manifest, fidelity
rubric, Caldera dispatch) from **execution substrate** (container, VM,
hypervisor). The orchestrator only requires the contract defined here, so
the same campaign can be executed on:

- :class:`DockerEnvironment` — canonical, portable, reviewer-friendly.
- :class:`QEMUEnvironment` — extended realism, real kernel boundary, full
  ARM64 Linux VM via Vagrant + QEMU (parity with the frozen
  ``sticks/Vagrantfile``).
- :class:`TartEnvironment` *(optional, experimental)* — Apple Silicon
  fast-path via Virtualization.framework. Never the canonical
  recommendation per artifact-evaluation guidance (avoid the
  "Apple-only artifact" critique).

This module defines the abstract contract. Each concrete backend is in its
own module so reviewers can audit them independently.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path

from .models import SUTProfile


@dataclass
class CommandResult:
    """Outcome of running one shell command inside an environment."""

    cmd: str
    exit_code: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.exit_code == 0


class EnvironmentBackend(ABC):
    """The contract an execution-substrate must satisfy.

    Concrete implementations are responsible for bringing up an isolated SUT
    (Docker container, Vagrant VM, etc.), accepting shell commands, and
    tearing the substrate down. The orchestrator never reaches into backend
    internals; it only uses these methods.
    """

    # The reviewer-facing label for this substrate (e.g. "docker", "qemu",
    # "tart"). Recorded in manifests for transparency.
    backend_name: str = "abstract"

    @classmethod
    @abstractmethod
    def bring_up(cls, sut: SUTProfile, run_dir: Path) -> "EnvironmentBackend":
        """Provision an isolated SUT environment ready to accept commands."""

    @property
    @abstractmethod
    def host_id(self) -> str:
        """A stable identifier for the running host (container name, VM
        name, paw, etc.). Recorded in evidence for cross-referencing."""

    @abstractmethod
    def run_shell(self, command: str, log_name: str | None = None,
                  timeout: int = 600) -> CommandResult:
        """Execute a shell command inside the environment."""

    @abstractmethod
    def teardown(self) -> bool:
        """Tear the environment down. Returns True on clean teardown."""

    def __enter__(self) -> "EnvironmentBackend":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.teardown()


def select_backend(sut: SUTProfile) -> type[EnvironmentBackend]:
    """Pick the backend implementation for a SUT profile.

    Default policy:

    1. If the profile sets ``backend == "qemu"``, use the QEMU VM backend.
    2. If the profile sets ``backend == "tart"``, use the experimental Tart
       backend (Apple Silicon only).
    3. Otherwise, use the canonical Docker backend.

    The selection is intentionally explicit (declared by the SUT profile)
    rather than implicit (host detection): a artifact evaluator running the
    canonical Docker path must get the canonical Docker path regardless of
    what hypervisors are available locally.
    """
    declared = getattr(sut, "backend", None)
    if declared == "qemu":
        from .qemu_environment import QEMUEnvironment
        return QEMUEnvironment
    if declared == "tart":
        from .tart_environment import TartEnvironment  # noqa: F401
        return TartEnvironment
    from .environment import DockerEnvironment
    return DockerEnvironment
