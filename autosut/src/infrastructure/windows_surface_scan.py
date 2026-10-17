"""Inventory and verify retained credential-scan inputs."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from .revision import SOURCE_PATHSPEC, included_source_path


class ScannedFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str = Field(min_length=1)
    size: int = Field(ge=0)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class SurfaceScan(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    schema_version: str = Field(alias="schema")
    surface: str
    run_id: str
    input_root: str
    scanner_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    files: list[ScannedFile]
    inventory_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    files_scanned: int = Field(ge=0)
    completed: bool
    leak_found: bool


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _raise_walk_error(error: OSError) -> None:
    raise error


def inventory(root: Path) -> list[ScannedFile]:
    """Hash every regular file, rejecting symlinks and unreadable entries."""
    if root.is_symlink():
        raise RuntimeError("scan input root is a symlink")
    if root.is_file():
        paths = [(root.name, root)]
    elif root.is_dir():
        paths = []
        for directory, names, filenames in os.walk(root, onerror=_raise_walk_error):
            for name in (*names, *filenames):
                path = Path(directory) / name
                if path.is_symlink():
                    raise RuntimeError("scan input contains a symlink")
                if path.is_dir():
                    continue
                if not path.is_file():
                    raise RuntimeError("scan input contains a nonregular file")
                paths.append((path.relative_to(root).as_posix(), path))
    else:
        raise FileNotFoundError(f"scan input is missing or nonregular: {root}")
    return [
        ScannedFile(path=relative, size=path.stat().st_size, sha256=sha256_file(path))
        for relative, path in sorted(paths)
    ]


def source_tree_inventory(root: Path) -> list[ScannedFile]:
    """Inventory the implementation paths used by the revision stamp."""
    if root.is_symlink() or not root.is_dir():
        raise ValueError("source tree root must be a regular directory")
    paths = []
    for directory_name in SOURCE_PATHSPEC:
        directory = root / directory_name
        if directory.is_symlink():
            raise RuntimeError("source tree contains a symlink")
        if not directory.is_dir():
            continue
        for path in sorted(directory.rglob("*")):
            relative = path.relative_to(root)
            if not included_source_path(relative):
                continue
            if path.is_symlink():
                raise RuntimeError("source tree contains a symlink")
            if path.is_dir():
                continue
            if not path.is_file():
                raise RuntimeError("source tree contains a nonregular file")
            paths.append((relative.as_posix(), path))
    if not paths:
        raise ValueError("source tree has no implementation files")
    return [
        ScannedFile(path=relative, size=path.stat().st_size, sha256=sha256_file(path))
        for relative, path in paths
    ]


def inventory_digest(files: list[ScannedFile]) -> str:
    payload = [file.model_dump() for file in files]
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def verify_scan(
    receipt_path: Path, *, expected_root: Path, run_id: str, surface: str,
    scanner_source: Path | None = None,
) -> SurfaceScan:
    scan = SurfaceScan.model_validate_json(receipt_path.read_text(encoding="utf-8"))
    root = expected_root.resolve(strict=True)
    if scan.schema_version != "windows-surface-scan/v2":
        raise ValueError("unsupported Windows surface scan schema")
    if scan.run_id != run_id or scan.surface != surface or scan.input_root != str(root):
        raise ValueError("Windows surface scan identity mismatch")
    if not scan.completed or scan.leak_found or scan.files_scanned == 0:
        raise ValueError("Windows surface scan incomplete or positive")
    if scan.files_scanned != len(scan.files):
        raise ValueError("Windows surface scan count mismatch")
    if scanner_source is not None and scan.scanner_sha256 != sha256_file(scanner_source):
        raise ValueError("Windows surface scanner source mismatch")
    current_files = (
        source_tree_inventory(expected_root)
        if surface == "source_tree" else inventory(expected_root)
    )
    if current_files != scan.files or inventory_digest(current_files) != scan.inventory_sha256:
        raise ValueError("Windows surface input inventory changed")
    return scan
