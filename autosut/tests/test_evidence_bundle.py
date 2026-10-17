"""The canonical bundle validator must reject every bundle that drops a guarantee a claim depends on."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from scripts.infra.windows_surface_scan import produce_scan  # noqa: E402

from infrastructure.evidence_bundle import (  # noqa: E402
    ArtifactProvenance,
    EvidenceBundle,
    EvidenceClassification,
    LifecycleEvidence,
    OracleEvidence,
    ProcedureEvidence,
    ResidualEvidence,
    RunIdentity,
    SecretAuditEvidence,
    SecretSurfaceReceipt,
    seal_bundle,
    validate_bundle,
)
from infrastructure.revision import write_revision_stamp  # noqa: E402
from infrastructure.windows_postrun_qualification import (  # noqa: E402
    _surface_binding_violations,
    assess_sealed_windows_run,
)
from infrastructure.windows_overlay_disposal import (  # noqa: E402
    PreparedOverlayDisposal,
    verify_overlay_disposal,
)

WINDOWS_SURFACES = (
    "base_image", "source_tree", "evidence_bundle", "run_logs",
    "guest_panther", "provisioning_media", "host_temporary", "controller_state",
)


def _surface_receipts(root: Path) -> list[SecretSurfaceReceipt]:
    receipts = []
    for surface in WINDOWS_SURFACES:
        path = root / "audits" / f"{surface}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "surface": surface, "files_scanned": 1,
            "completed": True, "leak_found": False,
        }
        path.write_text(json.dumps(payload), encoding="utf-8")
        receipts.append(SecretSurfaceReceipt(
            surface=surface, receipt_path=f"audits/{surface}.json",
            receipt_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
            files_scanned=1, completed=True, leak_found=False,
        ))
    return receipts


def _actual_surface_receipts(root: Path, run_id: str, run_dir: Path | None = None):
    receipts = []
    input_roots = {}
    for surface in WINDOWS_SURFACES:
        if run_dir is not None and surface == "evidence_bundle":
            input_root = run_dir / "bundle.json"
        elif run_dir is not None and surface == "run_logs":
            input_root = run_dir
        elif run_dir is not None and surface == "guest_panther":
            input_root = run_dir / "windows-qemu" / "panther-acquisition"
        elif run_dir is not None and surface == "base_image":
            input_root = root / "inputs" / "base-image.img"
            input_root.parent.mkdir(parents=True, exist_ok=True)
            input_root.write_text("safe fixture", encoding="utf-8")
        elif surface == "source_tree":
            input_root = root / "inputs" / surface
            (input_root / "src").mkdir(parents=True)
            (input_root / "src" / "observed.txt").write_text(
                "safe fixture", encoding="utf-8",
            )
        else:
            input_root = root / "inputs" / surface
            input_root.mkdir(parents=True)
            (input_root / "observed.txt").write_text("safe fixture", encoding="utf-8")
        receipt_path = root / "audits" / f"{surface}.json"
        scan = produce_scan(
            surface=surface, run_id=run_id, input_root=input_root,
            receipt_path=receipt_path, secret="Ephemeral-Secret-123!",
        )
        input_roots[surface] = input_root
        receipts.append(SecretSurfaceReceipt(
            surface=surface, receipt_path=f"audits/{surface}.json",
            receipt_sha256=hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
            files_scanned=scan.files_scanned, completed=True, leak_found=False,
        ))
    return receipts, input_roots


def _clean_bundle(**classification_overrides) -> EvidenceBundle:
    classification = {
        "evidence_role": "integration",
        "frozen_revision": False,
        "clean_room": False,
        "supervised": False,
        "claim_eligible": False,
    }
    classification.update(classification_overrides)
    return EvidenceBundle(
        experiment_id="windows-cyber",
        identity=RunIdentity(run_id="r1", label="run", created_at="t", backend="windows-qemu",
                             sut_id="windows-cyber", host_id="h@windows-qemu:1"),
        provenance=ArtifactProvenance(git_revision="abc123", revision_dirty=False),
        classification=EvidenceClassification(**classification),
        procedure=ProcedureEvidence(technique_id="T1112", technique_name="Modify Registry",
                                    tactic="defense-evasion", negative_control_absent_before=True,
                                    dispatched=True, operation_reached_terminal_state=True),
        oracle=OracleEvidence(independent_of_executor=True, observed="present:nonce",
                              expected="present:nonce", matches=True),
        lifecycle=LifecycleEvidence(total_seconds=180.0, forward_completed=True, final_state="clean",
                                    guest_exited_naturally=True, forced_termination_used=False,
                                    stage_names=["materialize", "collect_evidence"]),
        residual=ResidualEvidence(scope="windows-qemu", inventory_completed=True,
                                  residual_resources=[]),
        secret_audit=SecretAuditEvidence(performed=False, scan_completed=False, scanned_locations=[],
                                         leak_found=False),
    )


def test_clean_bundle_is_admissible():
    assert validate_bundle(_clean_bundle()).admissible


def test_windows_qualification_rejects_retained_files_only_secret_scan():
    bundle = _clean_bundle(
        evidence_role="qualification", frozen_revision=True, clean_room=True,
        supervised=True, claim_eligible=True,
    )
    bundle.secret_audit = SecretAuditEvidence(
        performed=True, scan_completed=True,
        scanned_locations=["retained-run-evidence"], leak_found=False,
    )

    result = validate_bundle(bundle)

    assert not result.admissible
    assert any("surfaces" in violation for violation in result.violations)


@pytest.mark.parametrize(
    ("section_name", "field_name", "invalid_value"),
    [
        ("procedure", "negative_control_absent_before", False),
        ("procedure", "dispatched", False),
        ("procedure", "operation_reached_terminal_state", False),
        ("oracle", "matches", False),
        ("lifecycle", "forward_completed", False),
        ("lifecycle", "final_state", "failed_clean"),
    ],
)
def test_failed_scientific_execution_is_not_admissible(
    section_name, field_name, invalid_value
):
    bundle = _clean_bundle()
    setattr(getattr(bundle, section_name), field_name, invalid_value)

    result = validate_bundle(bundle)

    assert not result.admissible
    assert result.violations


@pytest.mark.parametrize(
    ("section_name", "field_name", "invalid_value"),
    [
        ("classification", "supervised", False),
        ("provenance", "revision_dirty", True),
        ("provenance", "git_revision", "   "),
    ],
)
def test_claim_eligibility_rejects_unqualified_provenance(
    section_name, field_name, invalid_value
):
    bundle = _clean_bundle(
        evidence_role="qualification", frozen_revision=True, clean_room=True,
        supervised=True, claim_eligible=True,
    )
    bundle.secret_audit = SecretAuditEvidence(
        performed=True, scan_completed=True,
        scanned_locations=["retained-run-evidence"], leak_found=False,
    )
    setattr(getattr(bundle, section_name), field_name, invalid_value)

    result = validate_bundle(bundle)

    assert not result.admissible
    assert result.violations


def test_sealed_bundle_matches_manifest_after_return(tmp_path):
    bundle = _clean_bundle()
    manifest = seal_bundle(bundle, tmp_path, "r1", "t")
    entry = next(item for item in manifest.files if item.path == "bundle.json")
    payload = (tmp_path / "bundle.json").read_bytes()
    assert len(payload) == entry.bytes
    assert hashlib.sha256(payload).hexdigest() == entry.sha256


def test_sealing_rejects_a_bundle_containing_its_own_manifest_digest(tmp_path):
    bundle = _clean_bundle()
    bundle.manifest_sha256 = "a" * 64
    with pytest.raises(ValueError):
        seal_bundle(bundle, tmp_path, "r1", "t")
    assert not (tmp_path / "manifest.json").exists()


def test_incomplete_inventory_is_rejected():
    bundle = _clean_bundle()
    bundle.residual.inventory_completed = False
    result = validate_bundle(bundle)
    assert not result.admissible
    assert any("inventory" in v for v in result.violations)


def test_residual_resource_is_rejected():
    bundle = _clean_bundle()
    bundle.residual.residual_resources = ["qemu-process-alive"]
    assert not validate_bundle(bundle).admissible


def test_forced_termination_is_rejected():
    bundle = _clean_bundle()
    bundle.lifecycle.forced_termination_used = True
    assert not validate_bundle(bundle).admissible


def test_non_natural_exit_is_rejected():
    bundle = _clean_bundle()
    bundle.lifecycle.guest_exited_naturally = False
    assert not validate_bundle(bundle).admissible


def test_non_independent_oracle_is_rejected():
    bundle = _clean_bundle()
    bundle.oracle.independent_of_executor = False
    assert not validate_bundle(bundle).admissible


def test_incomplete_secret_scan_is_rejected():
    bundle = _clean_bundle()
    bundle.secret_audit.performed = True
    bundle.secret_audit.scan_completed = False
    assert not validate_bundle(bundle).admissible


def test_secret_leak_is_rejected():
    bundle = _clean_bundle()
    bundle.secret_audit.leak_found = True
    assert not validate_bundle(bundle).admissible


def test_missing_revision_is_rejected():
    bundle = _clean_bundle()
    bundle.provenance.git_revision = ""
    assert not validate_bundle(bundle).admissible


def test_claim_eligible_requires_frozen_cleanroom_qualification(tmp_path):
    integration_claiming = _clean_bundle(claim_eligible=True)
    assert not validate_bundle(integration_claiming).admissible

    qualified = _clean_bundle(evidence_role="qualification", frozen_revision=True, clean_room=True,
                              supervised=True, claim_eligible=True)
    assert not validate_bundle(qualified).admissible
    qualified.secret_audit.performed = True
    qualified.secret_audit.scan_completed = True
    assert not validate_bundle(qualified).admissible
    qualified.secret_audit = SecretAuditEvidence(
        performed=True,
        scan_completed=True,
        scanned_locations=["retained-run-evidence"],
        scanned_surfaces=[
            "base_image", "source_tree", "evidence_bundle", "run_logs",
            "guest_panther", "provisioning_media", "host_temporary", "controller_state",
        ],
        surface_receipts=_surface_receipts(tmp_path),
        leak_found=False,
    )
    assert not validate_bundle(qualified).admissible
    assert not validate_bundle(qualified, evidence_root=tmp_path).admissible


def test_windows_qualification_requires_actual_scan_inventory(tmp_path):
    qualified = _clean_bundle(
        evidence_role="qualification", frozen_revision=True, clean_room=True,
        supervised=True, claim_eligible=True,
    )
    receipts, roots = _actual_surface_receipts(tmp_path, qualified.identity.run_id)
    qualified.secret_audit = SecretAuditEvidence(
        performed=True, scan_completed=True,
        scanned_locations=[str(root) for root in roots.values()],
        scanned_surfaces=list(WINDOWS_SURFACES), surface_receipts=receipts,
        leak_found=False,
    )

    assert not validate_bundle(qualified, evidence_root=tmp_path).admissible
    assert validate_bundle(
        qualified, evidence_root=tmp_path, surface_roots=roots,
    ).admissible
    (roots["guest_panther"] / "observed.txt").write_text("changed", encoding="utf-8")
    assert not validate_bundle(
        qualified, evidence_root=tmp_path, surface_roots=roots,
    ).admissible


def test_windows_qualification_rejects_surface_names_without_receipts():
    bundle = _clean_bundle(
        evidence_role="qualification", frozen_revision=True, clean_room=True,
        supervised=True, claim_eligible=True,
    )
    bundle.secret_audit = SecretAuditEvidence(
        performed=True, scan_completed=True, scanned_locations=["audit-report.json"],
        scanned_surfaces=list(WINDOWS_SURFACES), leak_found=False,
    )

    result = validate_bundle(bundle)

    assert not result.admissible
    assert any("scan receipts" in violation for violation in result.violations)


@pytest.mark.parametrize("failure", ["missing", "duplicate", "incomplete", "leak"])
def test_windows_qualification_rejects_invalid_surface_receipts(failure, tmp_path):
    bundle = _clean_bundle(
        evidence_role="qualification", frozen_revision=True, clean_room=True,
        supervised=True, claim_eligible=True,
    )
    receipts = _surface_receipts(tmp_path)
    if failure == "missing":
        receipts.pop()
    elif failure == "duplicate":
        receipts.append(receipts[0].model_copy())
    elif failure == "incomplete":
        receipts[0].completed = False
    else:
        receipts[0].leak_found = True
    bundle.secret_audit = SecretAuditEvidence(
        performed=True, scan_completed=True, scanned_locations=["audit-report.json"],
        scanned_surfaces=list(WINDOWS_SURFACES),
        surface_receipts=receipts, leak_found=False,
    )

    assert not validate_bundle(bundle, evidence_root=tmp_path).admissible


@pytest.mark.parametrize("failure", ["missing", "changed", "traversal", "symlink"])
def test_windows_qualification_rejects_unverifiable_receipt_file(failure, tmp_path):
    bundle = _clean_bundle(
        evidence_role="qualification", frozen_revision=True, clean_room=True,
        supervised=True, claim_eligible=True,
    )
    receipts = _surface_receipts(tmp_path)
    target = tmp_path / receipts[0].receipt_path
    if failure == "missing":
        target.unlink()
    elif failure == "changed":
        target.write_text("{}", encoding="utf-8")
    elif failure == "traversal":
        receipts[0].receipt_path = "../outside.json"
    else:
        original = target.read_bytes()
        target.unlink()
        alternate = tmp_path / "alternate.json"
        alternate.write_bytes(original)
        target.symlink_to(alternate)
    bundle.secret_audit = SecretAuditEvidence(
        performed=True, scan_completed=True, scanned_locations=["audit-report.json"],
        scanned_surfaces=list(WINDOWS_SURFACES),
        surface_receipts=receipts, leak_found=False,
    )

    assert not validate_bundle(bundle, evidence_root=tmp_path).admissible


@pytest.mark.parametrize("omitted", [
    "base_image", "source_tree", "evidence_bundle", "run_logs",
    "guest_panther", "provisioning_media", "host_temporary", "controller_state",
])
def test_windows_qualification_requires_each_credential_surface(omitted):
    bundle = _clean_bundle(
        evidence_role="qualification", frozen_revision=True, clean_room=True,
        supervised=True, claim_eligible=True,
    )
    surfaces = [
        "base_image", "source_tree", "evidence_bundle", "run_logs",
        "guest_panther", "provisioning_media", "host_temporary", "controller_state",
    ]
    bundle.secret_audit = SecretAuditEvidence(
        performed=True, scan_completed=True, scanned_locations=["audit-report.json"],
        scanned_surfaces=[surface for surface in surfaces if surface != omitted],
        leak_found=False,
    )

    result = validate_bundle(bundle)

    assert not result.admissible
    assert any(omitted in violation for violation in result.violations)


def test_legacy_integration_bundle_stays_admissible_without_forensic_coverage():
    bundle = _clean_bundle()
    payload = bundle.model_dump()
    payload["schema_version"] = "1.0.0"
    payload["secret_audit"].pop("scanned_surfaces")

    assert validate_bundle(EvidenceBundle.model_validate(payload)).admissible


def test_unknown_credential_surface_is_rejected():
    with pytest.raises(ValidationError):
        SecretAuditEvidence(
            performed=True, scan_completed=True, scanned_locations=["audit.json"],
            scanned_surfaces=["all-files"], leak_found=False,
        )


def test_non_windows_claim_does_not_require_windows_specific_surfaces():
    bundle = _clean_bundle(
        evidence_role="qualification", frozen_revision=True, clean_room=True,
        supervised=True, claim_eligible=True,
    )
    bundle.identity.backend = "docker"
    bundle.secret_audit = SecretAuditEvidence(
        performed=True, scan_completed=True,
        scanned_locations=["retained-run-evidence"], leak_found=False,
    )

    assert validate_bundle(bundle).admissible


def test_unsupported_schema_version_is_rejected():
    bundle = _clean_bundle()
    bundle.schema_version = "unknown"

    assert not validate_bundle(bundle).admissible


def test_postrun_qualification_keeps_seal_but_rejects_unbound_inputs(tmp_path):
    bundle = _clean_bundle(
        evidence_role="qualification", frozen_revision=True, clean_room=True,
        supervised=True,
    )
    bundle.provenance.image_digests["immutable_base_sha256"] = hashlib.sha256(
        b"safe fixture"
    ).hexdigest()
    run_dir = tmp_path / bundle.identity.run_id
    run_dir.mkdir()
    panther = run_dir / "windows-qemu" / "panther-acquisition"
    panther.mkdir(parents=True)
    (panther / "observed.txt").write_text("safe fixture", encoding="utf-8")
    seal_bundle(bundle, run_dir, bundle.identity.run_id, "created")
    sealed_bundle = (run_dir / "bundle.json").read_bytes()
    sealed_manifest = (run_dir / "manifest.json").read_bytes()
    reports, roots = _actual_surface_receipts(tmp_path, bundle.identity.run_id, run_dir)

    decision = assess_sealed_windows_run(
        run_dir, receipt_root=tmp_path, surface_roots=roots, reports=reports,
    )

    assert not decision.admissible
    assert any("source_tree input producer" in item for item in decision.violations)
    assert (run_dir / "bundle.json").read_bytes() == sealed_bundle
    assert (run_dir / "manifest.json").read_bytes() == sealed_manifest
    assert not EvidenceBundle.model_validate_json(sealed_bundle).classification.claim_eligible


def test_postrun_qualification_rejects_integration_role(tmp_path):
    bundle = _clean_bundle()
    run_dir = tmp_path / bundle.identity.run_id
    run_dir.mkdir()
    seal_bundle(bundle, run_dir, bundle.identity.run_id, "created")
    reports, roots = _actual_surface_receipts(tmp_path, bundle.identity.run_id)

    decision = assess_sealed_windows_run(
        run_dir, receipt_root=tmp_path, surface_roots=roots, reports=reports,
    )

    assert not decision.admissible
    assert any("qualification role" in violation for violation in decision.violations)


def test_source_tree_binding_requires_stamped_source_bytes(tmp_path):
    package_root = tmp_path / "package"
    source_dir = package_root / "src"
    source_dir.mkdir(parents=True)
    source_file = source_dir / "runner.py"
    source_file.write_text("pass\n", encoding="utf-8")
    revision = "a" * 40
    write_revision_stamp(package_root, revision)
    bundle = _clean_bundle()
    bundle.provenance.git_revision = revision
    roots = {"source_tree": package_root}

    before = _surface_binding_violations(tmp_path / "run", bundle, roots)
    assert not any("source_tree input producer" in item for item in before)

    source_file.write_text("raise RuntimeError()\n", encoding="utf-8")
    after = _surface_binding_violations(tmp_path / "run", bundle, roots)
    assert any("source_tree input producer" in item for item in after)


def test_postrun_qualification_rejects_missing_surface(tmp_path):
    bundle = _clean_bundle(
        evidence_role="qualification", frozen_revision=True, clean_room=True,
        supervised=True,
    )
    run_dir = tmp_path / bundle.identity.run_id
    run_dir.mkdir()
    seal_bundle(bundle, run_dir, bundle.identity.run_id, "created")
    reports, roots = _actual_surface_receipts(tmp_path, bundle.identity.run_id)

    decision = assess_sealed_windows_run(
        run_dir, receipt_root=tmp_path, surface_roots=roots, reports=reports[:-1],
    )

    assert not decision.admissible
    assert any("controller_state" in violation for violation in decision.violations)


def test_postrun_qualification_rejects_changed_sealed_bytes(tmp_path):
    bundle = _clean_bundle()
    run_dir = tmp_path / bundle.identity.run_id
    run_dir.mkdir()
    seal_bundle(bundle, run_dir, bundle.identity.run_id, "created")
    (run_dir / "bundle.json").write_text("{}", encoding="utf-8")

    with pytest.raises(ValueError, match="manifest"):
        assess_sealed_windows_run(
            run_dir, receipt_root=tmp_path, surface_roots={}, reports=[],
        )


def test_postrun_qualification_rejects_receipt_inside_seal(tmp_path):
    bundle = _clean_bundle(
        evidence_role="qualification", frozen_revision=True, clean_room=True,
        supervised=True,
    )
    run_dir = tmp_path / bundle.identity.run_id
    run_dir.mkdir()
    reports, roots = _actual_surface_receipts(tmp_path, bundle.identity.run_id)
    receipt = tmp_path / reports[0].receipt_path
    embedded = run_dir / "embedded-receipt.json"
    embedded.write_bytes(receipt.read_bytes())
    reports[0].receipt_path = f"{run_dir.name}/{embedded.name}"
    seal_bundle(bundle, run_dir, bundle.identity.run_id, "created")

    decision = assess_sealed_windows_run(
        run_dir, receipt_root=tmp_path, surface_roots=roots, reports=reports,
    )

    assert not decision.admissible
    assert any("inside the sealed run" in violation for violation in decision.violations)


def test_postrun_qualification_rejects_premature_claim(tmp_path):
    bundle = _clean_bundle(
        evidence_role="qualification", frozen_revision=True, clean_room=True,
        supervised=True, claim_eligible=True,
    )
    run_dir = tmp_path / bundle.identity.run_id
    run_dir.mkdir()
    seal_bundle(bundle, run_dir, bundle.identity.run_id, "created")
    reports, roots = _actual_surface_receipts(tmp_path, bundle.identity.run_id)

    decision = assess_sealed_windows_run(
        run_dir, receipt_root=tmp_path, surface_roots=roots, reports=reports,
    )

    assert not decision.admissible
    assert any("before post-run audit" in violation for violation in decision.violations)


def test_postrun_qualification_rejects_unbound_surface_inputs(tmp_path):
    bundle = _clean_bundle(
        evidence_role="qualification", frozen_revision=True, clean_room=True,
        supervised=True,
    )
    run_dir = tmp_path / bundle.identity.run_id
    run_dir.mkdir()
    seal_bundle(bundle, run_dir, bundle.identity.run_id, "created")
    reports, roots = _actual_surface_receipts(tmp_path, bundle.identity.run_id)

    decision = assess_sealed_windows_run(
        run_dir, receipt_root=tmp_path, surface_roots=roots, reports=reports,
    )

    assert not decision.admissible
    assert any("base_image" in violation for violation in decision.violations)
    assert any("evidence_bundle" in violation for violation in decision.violations)
    assert any("run_logs" in violation for violation in decision.violations)


def test_postrun_qualification_rejects_wrong_base_digest(tmp_path):
    bundle = _clean_bundle(
        evidence_role="qualification", frozen_revision=True, clean_room=True,
        supervised=True,
    )
    bundle.provenance.image_digests["immutable_base_sha256"] = "0" * 64
    run_dir = tmp_path / bundle.identity.run_id
    run_dir.mkdir()
    panther = run_dir / "windows-qemu" / "panther-acquisition"
    panther.mkdir(parents=True)
    (panther / "observed.txt").write_text("safe fixture", encoding="utf-8")
    seal_bundle(bundle, run_dir, bundle.identity.run_id, "created")
    reports, roots = _actual_surface_receipts(tmp_path, bundle.identity.run_id, run_dir)

    decision = assess_sealed_windows_run(
        run_dir, receipt_root=tmp_path, surface_roots=roots, reports=reports,
    )

    assert not decision.admissible
    assert any("sealed image digest" in violation for violation in decision.violations)


def test_overlay_disposal_receipt_binds_executed_overlay_and_seal(tmp_path):
    bundle = _clean_bundle()
    bundle.provenance.base_image_sha256 = hashlib.sha256(b"prepared image").hexdigest()
    run_dir = tmp_path / bundle.identity.run_id
    run_dir.mkdir()
    seal_bundle(bundle, run_dir, bundle.identity.run_id, "created")
    overlay = tmp_path / "windows-credential-test" / "prepared.qcow2"
    receipt_path = tmp_path / "r1.overlay-disposal.json"
    receipt = PreparedOverlayDisposal(
        run_id=run_dir.name, overlay_path=str(overlay),
        overlay_sha256_before=bundle.provenance.base_image_sha256,
        manifest_sha256=hashlib.sha256((run_dir / "manifest.json").read_bytes()).hexdigest(),
        removed=True,
    )
    receipt_path.write_text(receipt.model_dump_json(), encoding="utf-8")

    assert verify_overlay_disposal(run_dir, receipt_path) == receipt

    overlay.parent.mkdir()
    overlay.write_bytes(b"residual")
    with pytest.raises(ValueError, match="still exists"):
        verify_overlay_disposal(run_dir, receipt_path)

    embedded = run_dir / "embedded-disposal.json"
    embedded.write_text(receipt.model_dump_json(), encoding="utf-8")
    with pytest.raises(ValueError, match="inside the sealed run"):
        verify_overlay_disposal(run_dir, embedded)


def test_overlay_disposal_rejects_digest_from_different_run(tmp_path):
    bundle = _clean_bundle()
    bundle.provenance.base_image_sha256 = "a" * 64
    run_dir = tmp_path / bundle.identity.run_id
    run_dir.mkdir()
    seal_bundle(bundle, run_dir, bundle.identity.run_id, "created")
    receipt = PreparedOverlayDisposal(
        run_id=run_dir.name,
        overlay_path=str(tmp_path / "windows-credential-test" / "prepared.qcow2"),
        overlay_sha256_before="b" * 64,
        manifest_sha256=hashlib.sha256((run_dir / "manifest.json").read_bytes()).hexdigest(),
        removed=True,
    )
    receipt_path = tmp_path / "r1.overlay-disposal.json"
    receipt_path.write_text(receipt.model_dump_json(), encoding="utf-8")

    with pytest.raises(ValueError, match="executed image"):
        verify_overlay_disposal(run_dir, receipt_path)

    (run_dir / "manifest.json").write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="manifest digest"):
        verify_overlay_disposal(run_dir, receipt_path)
