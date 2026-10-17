"""Dispose of explicitly identified Windows overlays after an interrupted run."""

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class RemovedOverlay(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str
    bytes: int = Field(ge=0)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class PreparationLink(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["windows-preparation-link/v1"] = "windows-preparation-link/v1"
    run_id: str
    credential_directory: str
    prepared_overlay_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class CrashRecoveryReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["windows-crash-recovery/v1"] = "windows-crash-recovery/v1"
    run_id: str
    credential_directory: str
    preparation_link_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    removed_overlays: list[RemovedOverlay] = Field(min_length=1)
    sealed_run: Literal[False] = False


def _validate_child(root: Path, name: str) -> Path:
    if not name or Path(name).name != name or name in {".", ".."}:
        raise ValueError("recovery target must be one child name")
    child = root / name
    if child.is_symlink() or not child.is_dir():
        raise ValueError(f"recovery directory is missing or symlinked: {name}")
    return child


def _assert_no_process_uses(overlays: list[Path], root: Path) -> None:
    for process_name in ("qemu-system-aarch64", "swtpm", "qemu-img"):
        probe = subprocess.run(
            ["pgrep", "-x", process_name], capture_output=True, text=True, check=False,
        )
        if probe.returncode == 0:
            raise RuntimeError(f"{process_name} is active; recovery refused")
        if probe.returncode != 1:
            raise RuntimeError(f"could not inspect {process_name}")
    for overlay in overlays:
        probe = subprocess.run(
            ["lsof", str(overlay)], capture_output=True, text=True, check=False,
        )
        if probe.returncode == 0:
            raise RuntimeError(f"overlay is open; recovery refused: {overlay.name}")
        if probe.returncode != 1:
            raise RuntimeError(f"could not inspect overlay: {overlay.name}")
    containers = subprocess.run(
        ["docker", "ps", "-q"], capture_output=True, text=True, check=False,
    )
    if containers.returncode != 0:
        raise RuntimeError("Docker inventory is unavailable; recovery refused")
    for container_id in containers.stdout.splitlines():
        mounts = subprocess.run(
            ["docker", "inspect", "--format", "{{json .Mounts}}", container_id],
            capture_output=True, text=True, check=False,
        )
        if mounts.returncode != 0:
            raise RuntimeError("Docker mount inventory is incomplete; recovery refused")
        for mount in json.loads(mounts.stdout):
            source = mount.get("Source")
            if source and (root.is_relative_to(Path(source).resolve())
                           or Path(source).resolve().is_relative_to(root)):
                raise RuntimeError("an active Docker container mounts the evidence root")


def _fingerprint(path: Path, root: Path) -> RemovedOverlay:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return RemovedOverlay(
        path=path.relative_to(root).as_posix(), bytes=path.stat().st_size,
        sha256=digest.hexdigest(),
    )


def recover_interrupted_run(
    evidence_root: Path, run_id: str, credential_directory: str, *, dispose: bool,
) -> CrashRecoveryReceipt:
    """Inspect two run-owned disks; delete them only when explicitly requested."""
    if evidence_root.is_symlink() or not evidence_root.is_dir():
        raise ValueError("evidence root is missing or symlinked")
    root = evidence_root.resolve(strict=True)
    run = _validate_child(root, run_id)
    credentials = _validate_child(root, credential_directory)
    if not credential_directory.startswith("windows-credential-"):
        raise ValueError("credential directory has an unexpected name")
    if not (run / "stage-starts.jsonl").is_file() or (run / "manifest.json").exists():
        raise ValueError("run is not an unsealed, started Windows run")
    link_path = run / "preparation-link.json"
    if link_path.is_symlink() or not link_path.is_file():
        raise ValueError("run preparation link is missing or symlinked")
    link_bytes = link_path.read_bytes()
    link = PreparationLink.model_validate_json(link_bytes)
    if link.run_id != run_id or link.credential_directory != credential_directory:
        raise ValueError("credential directory is not bound to this run")
    workdir = run / "windows-qemu"
    if workdir.is_symlink() or not workdir.is_dir():
        raise ValueError("Windows QEMU workdir is missing or symlinked")
    paths = [credentials / "prepared.qcow2", workdir / "guest.qcow2"]
    overlays = [path for path in paths if path.exists() or path.is_symlink()]
    if not overlays:
        raise FileNotFoundError("no abandoned Windows overlay found")
    if any(path.is_symlink() or not path.is_file() for path in overlays):
        raise ValueError("recovery overlay is not a regular file")
    _assert_no_process_uses(overlays, root)
    fingerprints = [_fingerprint(path, root) for path in overlays]
    prepared = next((item for item in fingerprints if item.path.endswith("/prepared.qcow2")), None)
    if prepared is not None and prepared.sha256 != link.prepared_overlay_sha256:
        raise ValueError("prepared overlay differs from the run preparation link")
    receipt = CrashRecoveryReceipt(
        run_id=run_id, credential_directory=credential_directory,
        preparation_link_sha256=hashlib.sha256(link_bytes).hexdigest(),
        removed_overlays=fingerprints,
    )
    if not dispose:
        return receipt

    receipt_path = root / f"{run_id}.crash-recovery.json"
    if receipt_path.exists() or receipt_path.is_symlink():
        raise FileExistsError("crash recovery receipt already exists")
    _assert_no_process_uses(overlays, root)
    for path in overlays:
        path.unlink()
    if any(path.exists() or path.is_symlink() for path in overlays):
        raise RuntimeError("Windows overlay disposal was incomplete")
    with receipt_path.open("x", encoding="utf-8") as output:
        output.write(receipt.model_dump_json(indent=2) + "\n")
    return receipt
