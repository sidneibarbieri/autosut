"""Per-run identity, isolation, and evidence for one experiment execution.

Every experiment runs under a unique run_id that namespaces each resource it creates (containers,
networks, VMs, agents), so two runs cannot collide and teardown can prove a run left nothing
behind. A single-experiment lock serialises materialization and Caldera use: only one run may hold
infrastructure at a time. The run directory is sealed at the end with a SHA-256 manifest, so its
evidence is auditable and tamper-evident.
"""

from __future__ import annotations

import fcntl
import hashlib
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel, ConfigDict

_RESOURCE_PREFIX = "autosut"


class ExecutionLockHeld(RuntimeError):
    """Another experiment already holds the single-experiment execution lock."""


class ManifestEntry(BaseModel):
    """One file in a sealed run, with its content hash."""

    model_config = ConfigDict(extra="forbid")

    path: str
    sha256: str
    bytes: int


class RunManifest(BaseModel):
    """The tamper-evident seal over everything a run produced."""

    model_config = ConfigDict(extra="forbid")

    run_id: str
    created_at: str
    sealed_at: str
    file_count: int
    total_bytes: int
    files: list[ManifestEntry]


def _new_run_id() -> str:
    """A sortable, unique run identifier: UTC timestamp plus a short token."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{stamp}-{uuid.uuid4().hex[:8]}"


def _sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def seal_directory(run_dir: Path, run_id: str, created_at: str) -> RunManifest:
    """Hash every file under a run directory and write the manifest that seals it.

    Free-standing so any run directory can be sealed, including one produced by the existing
    orchestrator, not only a directory a RunContext created.
    """
    manifest_path = run_dir / "manifest.json"
    entries: list[ManifestEntry] = []
    total_bytes = 0
    for file_path in sorted(run_dir.rglob("*")):
        if not file_path.is_file() or file_path == manifest_path:
            continue
        size = file_path.stat().st_size
        total_bytes += size
        entries.append(
            ManifestEntry(
                path=str(file_path.relative_to(run_dir)),
                sha256=_sha256_of(file_path),
                bytes=size,
            )
        )
    manifest = RunManifest(
        run_id=run_id,
        created_at=created_at,
        sealed_at=datetime.now(timezone.utc).isoformat(),
        file_count=len(entries),
        total_bytes=total_bytes,
        files=entries,
    )
    manifest_path.write_text(manifest.model_dump_json(indent=2) + "\n", encoding="utf-8")
    return manifest


class RunContext:
    """The identity, directory, and resource namespace of one experiment run."""

    def __init__(self, run_id: str, run_dir: Path, created_at: str):
        self.run_id = run_id
        self.run_dir = run_dir
        self.created_at = created_at

    @classmethod
    def create(cls, evidence_root: Path, label: str = "") -> "RunContext":
        """Allocate a fresh run_id and its directory under the evidence root.

        An optional label prefixes the run_id so a bundle directory reads as, for example,
        ``0.c0010_run1_20260806T...``; the unique token is always the final segment, so resource
        namespacing is unaffected by the label.
        """
        run_id = f"{label}_{_new_run_id()}" if label else _new_run_id()
        run_dir = evidence_root / run_id
        run_dir.mkdir(parents=True, exist_ok=False)
        return cls(run_id, run_dir, datetime.now(timezone.utc).isoformat())

    @property
    def resource_prefix(self) -> str:
        """A name-safe prefix every materialized resource must carry."""
        token = self.run_id.rsplit("-", 1)[-1]
        return f"{_RESOURCE_PREFIX}-{token}"

    def namespaced(self, resource: str) -> str:
        """Namespace one resource (container, network, VM, agent) to this run."""
        return f"{self.resource_prefix}-{resource}"

    def path(self, *parts: str) -> Path:
        """A path inside the run directory, with its parent created."""
        target = self.run_dir.joinpath(*parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        return target

    def seal(self) -> RunManifest:
        """Hash every file in the run and write the manifest that seals it."""
        return seal_directory(self.run_dir, self.run_id, self.created_at)


class ExecutionLock:
    """A single-experiment lock: only one run may materialize infrastructure at a time.

    Backed by an OS advisory lock, so a crashed experiment releases it automatically instead of
    wedging the next run. Acquiring a held lock raises ExecutionLockHeld naming the holder, rather
    than blocking or silently proceeding.
    """

    def __init__(self, lock_path: Path):
        self.lock_path = lock_path
        self._handle = None

    def __enter__(self) -> "ExecutionLock":
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        self._handle = self.lock_path.open("a+", encoding="utf-8")
        try:
            fcntl.flock(self._handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as already_held:
            self._handle.seek(0)
            holder = self._handle.read().strip() or "unknown"
            self._handle.close()
            self._handle = None
            raise ExecutionLockHeld(
                f"another experiment holds {self.lock_path} (holder pid: {holder})"
            ) from already_held
        self._handle.seek(0)
        self._handle.truncate()
        self._handle.write(str(os.getpid()))
        self._handle.flush()
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        if self._handle is None:
            return
        fcntl.flock(self._handle, fcntl.LOCK_UN)
        self._handle.close()
        self._handle = None
