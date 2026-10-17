"""One shared view of the autosut Docker namespace: what exists, and force-removing it.

Every resource a run creates is named ``autosut-<token>-<role>``. Listing those resources and removing
them lives here so the experiment lifecycle and the out-of-process supervisor share exactly one
implementation of "what belongs to autosut" and "remove it", instead of each carrying its own copy.
"""

from __future__ import annotations

import re
import subprocess
from enum import Enum

from pydantic import BaseModel, ConfigDict

_PREFIX = "autosut-"

_LIST_COMMAND = {
    "container": ["docker", "ps", "-a", "--filter", f"name={_PREFIX}", "--format", "{{.Names}}"],
    "network": ["docker", "network", "ls", "--filter", f"name={_PREFIX}", "--format", "{{.Name}}"],
    "volume": ["docker", "volume", "ls", "--filter", f"name={_PREFIX}", "--format", "{{.Name}}"],
}

_REMOVE_COMMAND = {
    "container": lambda name: ["docker", "rm", "-f", name],
    "network": lambda name: ["docker", "network", "rm", name],
    "volume": lambda name: ["docker", "volume", "rm", "-f", name],
}


class DockerInventoryFailureKind(str, Enum):
    """The observable reason an autosut namespace inventory could not complete."""

    COMMAND_NOT_FOUND = "command_not_found"
    COMMAND_UNAVAILABLE = "command_unavailable"
    COMMAND_TIMEOUT = "command_timeout"
    NONZERO_EXIT = "nonzero_exit"


class DockerInventoryDiagnostic(BaseModel):
    """A redacted record of an inventory failure that prevents a clean verdict."""

    model_config = ConfigDict(extra="forbid")

    resource_kind: str
    command: list[str]
    return_code: int | None
    stderr: str
    failure_kind: DockerInventoryFailureKind


class DockerInventoryError(RuntimeError):
    """Raised when Docker cannot authoritatively enumerate the autosut namespace."""

    def __init__(self, diagnostic: DockerInventoryDiagnostic):
        self.diagnostic = diagnostic
        return_code = (
            "unavailable" if diagnostic.return_code is None else str(diagnostic.return_code)
        )
        super().__init__(
            "Docker namespace inventory failed for "
            f"{diagnostic.resource_kind} (return_code={return_code}; "
            f"failure_kind={diagnostic.failure_kind.value})"
        )


_SENSITIVE_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passwd|token|api[_-]?key|secret|authorization)\b" r"\s*([=:])\s*([^\s,;]+)"
)
_AUTHORIZATION_HEADER = re.compile(r"(?im)^\s*authorization\s*:\s*[^\r\n]+")
_CREDENTIAL_URL = re.compile(r"(?i)(://[^\s/@:]+:)([^\s/@]+)(@)")
_MAX_STDERR_CHARACTERS = 4096


def _redact_stderr(stderr: str | bytes | None) -> str:
    """Bound diagnostic stderr while stripping common inline credentials before persistence."""
    if stderr is None:
        return ""
    if isinstance(stderr, bytes):
        stderr = stderr.decode("utf-8", errors="replace")
    redacted = _SENSITIVE_ASSIGNMENT.sub(r"\1\2<redacted>", stderr)
    redacted = _AUTHORIZATION_HEADER.sub("Authorization: <redacted>", redacted)
    redacted = _CREDENTIAL_URL.sub(r"\1<redacted>\3", redacted)
    if len(redacted) > _MAX_STDERR_CHARACTERS:
        return redacted[:_MAX_STDERR_CHARACTERS] + "\n[truncated]"
    return redacted


def _inventory_failure(
    kind: str,
    command: list[str],
    return_code: int | None,
    stderr: str | bytes | None,
    failure_kind: DockerInventoryFailureKind,
) -> DockerInventoryError:
    return DockerInventoryError(
        DockerInventoryDiagnostic(
            resource_kind=kind,
            command=command,
            return_code=return_code,
            stderr=_redact_stderr(stderr),
            failure_kind=failure_kind,
        )
    )


def _names(kind: str) -> set[str]:
    command = _LIST_COMMAND[kind]
    try:
        listing = subprocess.run(command, capture_output=True, text=True, check=False, timeout=30)
    except FileNotFoundError as error:
        raise _inventory_failure(
            kind,
            command,
            return_code=None,
            stderr=str(error),
            failure_kind=DockerInventoryFailureKind.COMMAND_NOT_FOUND,
        ) from error
    except subprocess.TimeoutExpired as error:
        raise _inventory_failure(
            kind,
            command,
            return_code=None,
            stderr=error.stderr,
            failure_kind=DockerInventoryFailureKind.COMMAND_TIMEOUT,
        ) from error
    except OSError as error:
        raise _inventory_failure(
            kind,
            command,
            return_code=None,
            stderr=str(error),
            failure_kind=DockerInventoryFailureKind.COMMAND_UNAVAILABLE,
        ) from error
    if listing.returncode != 0:
        raise _inventory_failure(
            kind,
            command,
            return_code=listing.returncode,
            stderr=listing.stderr,
            failure_kind=DockerInventoryFailureKind.NONZERO_EXIT,
        )
    return {
        name
        for name in listing.stdout.split()
        if name.startswith(_PREFIX)
    }


def autosut_resources() -> set[str]:
    """Every autosut-prefixed Docker resource, or a typed error when inventory is unavailable.

    An unavailable Docker CLI or daemon is not an empty namespace.  Callers must surface the
    resulting ``DockerInventoryError`` as an incomplete cleanup rather than certify a clean run.
    """
    return {f"{kind}:{name}" for kind in _LIST_COMMAND for name in _names(kind)}


def force_remove(resource: str) -> None:
    """Force-remove one ``kind:name`` resource. A resource already gone is the goal, so it is ignored."""
    kind, separator, name = resource.partition(":")
    if (
        not separator
        or kind not in _REMOVE_COMMAND
        or re.fullmatch(r"autosut-[A-Za-z0-9][A-Za-z0-9_.-]*", name) is None
    ):
        raise ValueError("refusing to remove a resource outside the autosut namespace")
    subprocess.run(
        _REMOVE_COMMAND[kind](name), capture_output=True, text=True, check=False, timeout=60
    )


class NamespaceSweep(BaseModel):
    """Force-removes every autosut resource that appeared since a baseline; reports what remains.

    Baseline-diff is safe because the single-experiment execution lock serialises runs: while one run
    holds infrastructure, any autosut resource not in the baseline was created by that run. This makes
    the sweep a precise namespace cleanup even though it does not thread the run_id into the parent.
    """

    model_config = ConfigDict(extra="forbid")

    baseline: list[str]

    @classmethod
    def capture(cls) -> "NamespaceSweep":
        """Snapshot the autosut resources present before a supervised run starts."""
        return cls(baseline=sorted(autosut_resources()))

    def sweep(self) -> list[str]:
        """Remove what the run created; raise if Docker cannot verify the post-sweep inventory."""
        created = autosut_resources() - set(self.baseline)
        for resource in sorted(created):
            force_remove(resource)
        return sorted(autosut_resources() - set(self.baseline))
