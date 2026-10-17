"""Verify logical disposal of the credential-bearing prepared Windows overlay."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .evidence_bundle import EvidenceBundle
from .windows_surface_scan import sha256_file


class PreparedOverlayDisposal(BaseModel):
    """Evidence for one removed overlay path, not secure physical erasure."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["prepared-overlay-disposal/v1"] = "prepared-overlay-disposal/v1"
    scope: Literal["prepared-overlay-only"] = "prepared-overlay-only"
    run_id: str = Field(min_length=1)
    overlay_path: str = Field(min_length=1)
    overlay_sha256_before: str = Field(pattern=r"^[0-9a-f]{64}$")
    manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    removed: bool


def verify_overlay_disposal(run_dir: Path, receipt_path: Path) -> PreparedOverlayDisposal:
    """Check a disposal statement after the caller verifies the run seal."""
    if receipt_path.is_symlink():
        raise ValueError("overlay disposal receipt is a symlink")
    if receipt_path.resolve(strict=True).is_relative_to(run_dir.resolve(strict=True)):
        raise ValueError("overlay disposal receipt is inside the sealed run")
    receipt = PreparedOverlayDisposal.model_validate_json(receipt_path.read_text(encoding="utf-8"))
    if receipt.run_id != run_dir.name:
        raise ValueError("overlay disposal run identity mismatch")
    if not receipt.removed:
        raise ValueError("prepared overlay was not reported removed")
    if receipt.manifest_sha256 != sha256_file(run_dir / "manifest.json"):
        raise ValueError("overlay disposal manifest digest mismatch")
    bundle = EvidenceBundle.model_validate_json((run_dir / "bundle.json").read_text(encoding="utf-8"))
    if bundle.identity.run_id != run_dir.name:
        raise ValueError("sealed bundle run identity mismatch")
    if receipt.overlay_sha256_before != bundle.provenance.base_image_sha256:
        raise ValueError("disposed overlay digest differs from executed image")
    evidence_root = run_dir.parent.resolve(strict=True)
    overlay_path = Path(receipt.overlay_path)
    if not overlay_path.is_absolute() or not overlay_path.resolve().is_relative_to(evidence_root):
        raise ValueError("overlay disposal path escaped the run evidence root")
    if overlay_path.exists() or overlay_path.is_symlink():
        raise ValueError("prepared overlay path still exists")
    return receipt
