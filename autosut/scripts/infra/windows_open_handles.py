"""Detect deleted provisioning files still held open by host processes."""

from __future__ import annotations

import subprocess
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field


class OpenProvisioningHandle(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    pid: int = Field(gt=0)
    descriptor: str = Field(min_length=1)
    path: Path


def _provisioning_path(name: str, base_directory: Path) -> Path | None:
    path = Path(name.removesuffix(" (deleted)"))
    if (
        not path.is_absolute()
        or path.name not in {"answer.xml", "prepared.qcow2"}
        or not path.parent.name.startswith("guestfish-overlay-")
        or path.parent.parent.resolve(strict=False) != base_directory
    ):
        return None
    return path


def list_open_deleted_provisioning_files(base_directory: Path) -> list[OpenProvisioningHandle]:
    """Report run-created answer/overlay inodes whose path was removed."""
    base_directory = base_directory.resolve(strict=True)
    result = subprocess.run(
        ["lsof", "-nP", "+L1", "-F", "pfn"],
        capture_output=True, text=True, check=False, timeout=30,
    )
    if result.returncode not in {0, 1} or result.stderr.strip():
        raise RuntimeError("open-file inventory did not complete")
    process_id: int | None = None
    descriptor: str | None = None
    handles = []
    for line in result.stdout.splitlines():
        if line.startswith("p"):
            process_id = int(line[1:])
            descriptor = None
        elif line.startswith("f"):
            descriptor = line[1:]
        elif line.startswith("n"):
            path = _provisioning_path(line[1:], base_directory)
            if path is not None:
                if process_id is None or not descriptor:
                    raise RuntimeError("open-file inventory omitted process identity")
                handles.append(OpenProvisioningHandle(
                    pid=process_id, descriptor=descriptor, path=path,
                ))
    return handles


def require_closed_provisioning_files(base_directory: Path) -> None:
    base_directory = base_directory.resolve(strict=True)
    retained_directories = list(base_directory.glob("guestfish-overlay-*"))
    if retained_directories:
        raise RuntimeError(
            f"{len(retained_directories)} provisioning directories remain on disk"
        )
    handles = list_open_deleted_provisioning_files(base_directory)
    if handles:
        raise RuntimeError(
            f"{len(handles)} unlinked provisioning files remain open; "
            "Windows credential clearance cannot be qualified while their "
            "host process holds those inodes"
        )
