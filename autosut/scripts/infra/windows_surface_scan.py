"""Produce a retained credential-surface scan receipt from actual input bytes."""

from __future__ import annotations

from pathlib import Path

from infrastructure.windows_surface_scan import (
    SurfaceScan, inventory, inventory_digest, sha256_file, source_tree_inventory,
)

from .windows_secret_audit import (
    SecretResidueDetected, assert_no_secret, contains_secret_file,
)


def produce_scan(
    *, surface: str, run_id: str, input_root: Path, receipt_path: Path, secret: str,
) -> SurfaceScan:
    """Scan a stable input and write its receipt outside that input."""
    if not secret or not run_id or not surface:
        raise ValueError("surface scan requires a secret, run identity, and surface")
    if input_root.is_symlink():
        raise RuntimeError("scan input root is a symlink")
    root = input_root.resolve(strict=True)
    if secret in root.as_posix():
        raise SecretResidueDetected("credential residue detected in scan input path")
    output = receipt_path.resolve(strict=False)
    if output == root or output.is_relative_to(root):
        raise ValueError("scan receipt must be outside the input root")
    before = source_tree_inventory(root) if surface == "source_tree" else inventory(root)
    if surface == "source_tree":
        for file in before:
            if secret in file.path or contains_secret_file(root / file.path, secret):
                raise SecretResidueDetected("credential residue detected in source tree")
        scanned = len(before)
    elif root.is_dir():
        scanned = assert_no_secret(root, secret)
    else:
        if contains_secret_file(root, secret):
            raise SecretResidueDetected("credential residue detected in scanned input")
        scanned = 1
    after = source_tree_inventory(root) if surface == "source_tree" else inventory(root)
    if before != after or scanned != len(after):
        raise RuntimeError("scan input changed during credential audit")
    scan = SurfaceScan(
        schema_version="windows-surface-scan/v2", surface=surface, run_id=run_id,
        input_root=str(root), scanner_sha256=sha256_file(
            Path(__file__).with_name("windows_secret_audit.py")
        ),
        files=after, inventory_sha256=inventory_digest(after),
        files_scanned=scanned, completed=True, leak_found=False,
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8") as destination:
        destination.write(scan.model_dump_json(indent=2, by_alias=True) + "\n")
    return scan
