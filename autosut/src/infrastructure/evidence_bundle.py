"""Canonical evidence schema every backend and experiment must produce, with a fail-closed validator.

One schema, one validator, one sealing helper. Backends and experiments compose these small DTOs rather
than each inventing bundle fields, so the claim ledger consumes every run uniformly and a bundle that
omits a required guarantee is rejected rather than assumed sound.
"""

from __future__ import annotations

import hashlib
from enum import StrEnum
from pathlib import Path, PurePosixPath

from pydantic import BaseModel, ConfigDict, Field

from .run_context import RunManifest, seal_directory
from .windows_surface_scan import verify_scan

SCHEMA_VERSION = "1.1.0"
_SUPPORTED_SCHEMA_VERSIONS = ("1.0.0", SCHEMA_VERSION)

_EVIDENCE_ROLES = ("development", "integration", "qualification")


class RunIdentity(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: str
    label: str
    created_at: str
    backend: str
    sut_id: str
    host_id: str


class ArtifactProvenance(BaseModel):
    model_config = ConfigDict(extra="forbid")

    git_revision: str
    revision_dirty: bool
    base_image_sha256: str | None = None
    agent_sha256: str | None = None
    image_digests: dict[str, str] = {}
    input_hashes: dict[str, str] = {}


class ProcedureEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    technique_id: str
    technique_name: str
    tactic: str
    source_procedure_id: str | None = None
    negative_control_absent_before: bool
    dispatched: bool
    operation_reached_terminal_state: bool


class OracleEvidence(BaseModel):
    """The effect observed by a probe that does not consult the executor (Caldera is never its own oracle)."""

    model_config = ConfigDict(extra="forbid")

    independent_of_executor: bool
    observed: str
    expected: str
    matches: bool


class LifecycleEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    total_seconds: float
    forward_completed: bool
    final_state: str
    guest_exited_naturally: bool
    forced_termination_used: bool
    stage_names: list[str]


class ResidualEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scope: str
    inventory_completed: bool
    residual_resources: list[str]


class SecretAuditSurface(StrEnum):
    """Credential persistence surfaces required by Windows qualification."""

    BASE_IMAGE = "base_image"
    SOURCE_TREE = "source_tree"
    EVIDENCE_BUNDLE = "evidence_bundle"
    RUN_LOGS = "run_logs"
    GUEST_PANTHER = "guest_panther"
    PROVISIONING_MEDIA = "provisioning_media"
    HOST_TEMPORARY = "host_temporary"
    CONTROLLER_STATE = "controller_state"


class SecretSurfaceReceipt(BaseModel):
    """One surface's completed scan, bound to a retained receipt digest."""

    model_config = ConfigDict(extra="forbid")

    surface: SecretAuditSurface
    receipt_path: str = Field(min_length=1)
    receipt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    files_scanned: int = Field(ge=0)
    completed: bool
    leak_found: bool


class SecretAuditEvidence(BaseModel):
    """Post-run sentinel scan for the ephemeral credential (G2 item 2). Fail-closed: an incomplete scan is a leak."""

    model_config = ConfigDict(extra="forbid")

    performed: bool
    scan_completed: bool
    scanned_locations: list[str]
    scanned_surfaces: list[SecretAuditSurface] = []
    surface_receipts: list[SecretSurfaceReceipt] = []
    leak_found: bool


class EvidenceClassification(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_role: str
    frozen_revision: bool
    clean_room: bool
    supervised: bool
    claim_eligible: bool


class EvidenceBundle(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = SCHEMA_VERSION
    experiment_id: str
    identity: RunIdentity
    provenance: ArtifactProvenance
    classification: EvidenceClassification
    procedure: ProcedureEvidence
    oracle: OracleEvidence
    lifecycle: LifecycleEvidence
    residual: ResidualEvidence
    secret_audit: SecretAuditEvidence
    manifest_sha256: str | None = None


class BundleValidation(BaseModel):
    """Why a bundle is or is not admissible. ``admissible`` is true only when no violation is found."""

    model_config = ConfigDict(extra="forbid")

    admissible: bool
    violations: list[str]


def validate_bundle(
    bundle: EvidenceBundle, *, evidence_root: Path | None = None,
    surface_roots: dict[str, Path] | None = None,
) -> BundleValidation:
    """Reject any bundle that does not carry every guarantee a claim depends on. Fail-closed."""
    violations = _execution_violations(bundle)

    if bundle.schema_version not in _SUPPORTED_SCHEMA_VERSIONS:
        violations.append(f"unsupported schema_version {bundle.schema_version}")
    if bundle.classification.evidence_role not in _EVIDENCE_ROLES:
        violations.append(f"unknown evidence_role {bundle.classification.evidence_role!r}")
    if not bundle.residual.inventory_completed:
        violations.append("residual inventory did not complete (cannot prove clean)")
    if bundle.residual.residual_resources:
        violations.append(f"residual resources remain: {bundle.residual.residual_resources}")
    if bundle.lifecycle.forced_termination_used:
        violations.append("teardown required forced termination")
    if not bundle.lifecycle.guest_exited_naturally:
        violations.append("guest did not exit naturally")
    if not bundle.oracle.independent_of_executor:
        violations.append("effect oracle is not independent of the executor")
    if bundle.secret_audit.performed and not bundle.secret_audit.scan_completed:
        violations.append("secret residue scan did not complete (treated as leak)")
    if bundle.secret_audit.leak_found:
        violations.append("secret residue detected")
    if bundle.classification.claim_eligible and not bundle.secret_audit.performed:
        violations.append("claim-eligible evidence requires a secret residue scan")
    if bundle.classification.claim_eligible and not bundle.secret_audit.scanned_locations:
        violations.append("claim-eligible evidence requires declared secret scan locations")
    violations.extend(_windows_secret_coverage_violations(bundle, evidence_root, surface_roots))
    if not bundle.provenance.git_revision.strip():
        violations.append("provenance is missing the executed git revision")
    if bundle.classification.claim_eligible and not _claim_eligible(bundle.classification):
        violations.append("claim_eligible set without a frozen-revision clean-room qualification role")
    if bundle.classification.claim_eligible and not bundle.classification.supervised:
        violations.append("claim-eligible evidence requires supervised execution")
    if bundle.classification.claim_eligible and bundle.provenance.revision_dirty:
        violations.append("claim-eligible evidence requires an unmodified frozen revision")

    return BundleValidation(admissible=not violations, violations=violations)


def _windows_secret_coverage_violations(
    bundle: EvidenceBundle, evidence_root: Path | None,
    surface_roots: dict[str, Path] | None,
) -> list[str]:
    if not bundle.classification.claim_eligible or bundle.identity.backend != "windows-qemu":
        return []
    missing = set(SecretAuditSurface) - set(bundle.secret_audit.scanned_surfaces)
    violations = []
    if missing:
        names = ", ".join(sorted(surface.value for surface in missing))
        violations.append(f"Windows qualification requires all credential audit surfaces; missing: {names}")

    reports = bundle.secret_audit.surface_receipts
    reported = [report.surface for report in reports]
    missing_reports = set(SecretAuditSurface) - set(reported)
    if missing_reports:
        names = ", ".join(sorted(surface.value for surface in missing_reports))
        violations.append(f"Windows qualification requires scan receipts; missing: {names}")
    if len(reported) != len(set(reported)):
        violations.append("Windows qualification has duplicate scan receipts")
    for report in reports:
        if not report.completed or report.leak_found:
            violations.append(f"Windows credential scan failed for {report.surface.value}")
    if evidence_root is None:
        violations.append("Windows qualification requires a receipt verification root")
    else:
        violations.extend(_surface_receipt_file_violations(
            reports, evidence_root, bundle.identity.run_id, surface_roots,
        ))
    return violations


def _surface_receipt_file_violations(
    reports: list[SecretSurfaceReceipt], evidence_root: Path,
    run_id: str, surface_roots: dict[str, Path] | None,
) -> list[str]:
    root = evidence_root.resolve(strict=True)
    violations = []
    if surface_roots is None:
        violations.append("Windows qualification requires independently supplied surface roots")
    for report in reports:
        relative = PurePosixPath(report.receipt_path)
        if relative.is_absolute() or ".." in relative.parts or "." in relative.parts:
            violations.append(f"unsafe Windows scan receipt path for {report.surface.value}")
            continue
        candidate = root.joinpath(*relative.parts)
        if any(parent.is_symlink() for parent in (candidate, *candidate.parents) if parent != root):
            violations.append(f"symlinked Windows scan receipt for {report.surface.value}")
            continue
        if not candidate.is_file():
            violations.append(f"missing Windows scan receipt for {report.surface.value}")
            continue
        content = candidate.read_bytes()
        if hashlib.sha256(content).hexdigest() != report.receipt_sha256:
            violations.append(f"Windows scan receipt digest mismatch for {report.surface.value}")
            continue
        input_root = None if surface_roots is None else surface_roots.get(report.surface.value)
        if input_root is None:
            violations.append(f"missing independent scan root for {report.surface.value}")
            continue
        scanner_source = Path(__file__).resolve().parents[2] / "scripts/infra/windows_secret_audit.py"
        try:
            scan = verify_scan(
                candidate, expected_root=input_root, run_id=run_id,
                surface=report.surface.value, scanner_source=scanner_source,
            )
        except (ValueError, OSError) as error:
            violations.append(f"Windows scan receipt unverifiable for {report.surface.value}: {error}")
            continue
        if (
            scan.files_scanned != report.files_scanned
            or scan.completed != report.completed
            or scan.leak_found != report.leak_found
        ):
            violations.append(f"Windows scan receipt content mismatch for {report.surface.value}")
    return violations


def _execution_violations(bundle: EvidenceBundle) -> list[str]:
    guarantees = (
        (bundle.procedure.negative_control_absent_before, "negative control was not absent before execution"),
        (bundle.procedure.dispatched, "procedure was not dispatched"),
        (bundle.procedure.operation_reached_terminal_state, "operation did not reach a terminal state"),
        (bundle.oracle.matches, "observed effect did not match the expected effect"),
        (bundle.lifecycle.forward_completed, "forward lifecycle did not complete"),
        (bundle.lifecycle.final_state == "clean", "lifecycle did not finish in the clean state"),
    )
    return [message for satisfied, message in guarantees if not satisfied]


def _claim_eligible(classification: EvidenceClassification) -> bool:
    return (
        classification.evidence_role == "qualification"
        and classification.frozen_revision
        and classification.clean_room
    )


def seal_bundle(bundle: EvidenceBundle, run_dir: Path, run_id: str, created_at: str) -> RunManifest:
    """Write the final bundle once, then bind it in the run manifest."""
    if bundle.manifest_sha256 is not None:
        raise ValueError("record the manifest digest outside its own listed files")
    (run_dir / "bundle.json").write_text(bundle.model_dump_json(indent=2) + "\n", encoding="utf-8")
    return seal_directory(run_dir, run_id, created_at)
