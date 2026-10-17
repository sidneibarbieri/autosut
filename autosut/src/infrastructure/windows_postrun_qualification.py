"""Assess Windows evidence collected after an immutable run was sealed."""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ConfigDict

from .evidence_bundle import (
    EvidenceBundle,
    SecretAuditEvidence,
    SecretSurfaceReceipt,
    validate_bundle,
)
from .run_context import RunManifest
from .revision import revision_from_stamp
from .windows_surface_scan import inventory, sha256_file


class PostRunQualification(BaseModel):
    """Decision bound to the original sealed bytes, without changing them."""

    model_config = ConfigDict(extra="forbid")

    run_id: str
    manifest_sha256: str
    bundle_sha256: str
    admissible: bool
    violations: list[str]


def _verified_seal(run_dir: Path) -> RunManifest:
    manifest_path = run_dir / "manifest.json"
    manifest = RunManifest.model_validate_json(manifest_path.read_text(encoding="utf-8"))
    if manifest.run_id != run_dir.name:
        raise ValueError("sealed manifest run identity mismatch")
    actual = {entry.path: entry for entry in inventory(run_dir)}
    if "manifest.json" not in actual:
        raise ValueError("sealed manifest is missing")
    del actual["manifest.json"]
    expected = {entry.path: entry for entry in manifest.files}
    if len(expected) != len(manifest.files) or set(actual) != set(expected):
        raise ValueError("sealed manifest file inventory mismatch")
    if manifest.file_count != len(actual) or manifest.total_bytes != sum(
        entry.size for entry in actual.values()
    ):
        raise ValueError("sealed manifest totals mismatch")
    for path, entry in actual.items():
        listed = expected[path]
        if entry.size != listed.bytes or entry.sha256 != listed.sha256:
            raise ValueError(f"sealed manifest digest mismatch for {path}")
    return manifest


def _receipt_location_violations(
    run_dir: Path, receipt_root: Path, reports: list[SecretSurfaceReceipt],
) -> list[str]:
    sealed_root = run_dir.resolve(strict=True)
    receipt_base = receipt_root.resolve(strict=True)
    violations = []
    for report in reports:
        receipt = receipt_base / report.receipt_path
        if receipt.is_relative_to(sealed_root):
            violations.append(f"post-run receipt is inside the sealed run: {report.surface.value}")
    return violations


def _surface_binding_violations(
    run_dir: Path, bundle: EvidenceBundle, surface_roots: dict[str, Path],
) -> list[str]:
    violations = []
    base_image = surface_roots.get("base_image")
    expected_digest = bundle.provenance.image_digests.get("immutable_base_sha256")
    if base_image is None or not base_image.is_file() or not expected_digest:
        violations.append("base_image is not bound to a sealed image digest")
    elif sha256_file(base_image) != expected_digest:
        violations.append("base_image input does not match the sealed image digest")

    required_roots = {
        "evidence_bundle": run_dir / "bundle.json",
        "run_logs": run_dir,
        "guest_panther": run_dir / "windows-qemu" / "panther-acquisition",
    }
    for surface, expected in required_roots.items():
        supplied = surface_roots.get(surface)
        if supplied is None or not supplied.exists() or not expected.exists() or (
            supplied.resolve(strict=True) != expected.resolve(strict=True)
        ):
            violations.append(f"{surface} input is not the sealed run's source")
    source_tree = surface_roots.get("source_tree")
    if (
        source_tree is None
        or source_tree.is_symlink()
        or not source_tree.is_dir()
        or not (source_tree / "IMPLEMENTATION_REVISION.json").is_file()
        or revision_from_stamp(source_tree) != bundle.provenance.git_revision
    ):
        violations.append("source_tree input producer provenance is not bound to the sealed revision")
    for surface in ("provisioning_media", "host_temporary", "controller_state"):
        violations.append(f"{surface} input producer provenance is not yet bound to the sealed run")
    return violations


def assess_sealed_windows_run(
    run_dir: Path, *, receipt_root: Path, surface_roots: dict[str, Path],
    reports: list[SecretSurfaceReceipt],
) -> PostRunQualification:
    """Validate the seal, then assess later scan evidence as a separate decision."""
    _verified_seal(run_dir)
    bundle_path = run_dir / "bundle.json"
    bundle = EvidenceBundle.model_validate_json(bundle_path.read_text(encoding="utf-8"))
    if bundle.identity.run_id != run_dir.name:
        raise ValueError("sealed bundle run identity mismatch")

    projected = bundle.model_copy(deep=True)
    projected.classification.claim_eligible = True
    projected.secret_audit = SecretAuditEvidence(
        performed=bool(reports),
        scan_completed=bool(reports) and all(report.completed for report in reports),
        scanned_locations=[str(root) for root in surface_roots.values()],
        scanned_surfaces=[report.surface for report in reports],
        surface_receipts=reports,
        leak_found=any(report.leak_found for report in reports),
    )
    result = validate_bundle(
        projected, evidence_root=receipt_root, surface_roots=surface_roots,
    )
    violations = (
        result.violations
        + _receipt_location_violations(run_dir, receipt_root, reports)
        + _surface_binding_violations(run_dir, bundle, surface_roots)
    )
    if bundle.classification.claim_eligible:
        violations.append("sealed bundle asserted claim eligibility before post-run audit")
    return PostRunQualification(
        run_id=run_dir.name,
        manifest_sha256=sha256_file(run_dir / "manifest.json"),
        bundle_sha256=sha256_file(bundle_path),
        admissible=not violations,
        violations=violations,
    )
