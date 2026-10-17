"""S32 subdetermination - unit, property, determinism, and guarded integration."""

from __future__ import annotations

import inspect
import json
import os
import random
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from orchestrator import catalog, models, provenance, subdetermination  # noqa: E402
from orchestrator import orchestrator as orchestrator_mod  # noqa: E402


def test_every_exposure_has_purpose():
    # After the S32 parity fix, NetworkExposure carries `purpose` like the
    # other three composition models, so no exposure element may be blank.
    for campaign_id in catalog.implemented_campaigns():
        _, sut, cves = catalog.resolve(campaign_id)
        summary = provenance.summarize_profile(sut, campaign_id, cves)
        for element in summary.elements:
            if element.dimension == "exposures":
                assert element.purpose, (
                    f"{campaign_id}: {element.identifier} has empty purpose")


def _cve_summary():
    _, sut, cves = catalog.resolve("0.cve_2021_41773")
    return provenance.summarize_profile(sut, "0.cve_2021_41773", cves)


def test_partition_splits_strictly_by_tag():
    invariant, free = subdetermination.partition(_cve_summary())
    assert all(e.source in (
        models.ProvenanceSource.corpus_supported,
        models.ProvenanceSource.external_reference,
    ) for e in invariant)
    assert all(e.source in (models.ProvenanceSource.analyst_authored,
                            models.ProvenanceSource.autosut_concretized)
               for e in free)
    ids_invariant = {e.identifier for e in invariant}
    ids_free = {e.identifier for e in free}
    assert ids_invariant.isdisjoint(ids_free)


def test_partition_invariant_equals_fixed_evidence_tags():
    summary = _cve_summary()
    invariant, _ = subdetermination.partition(summary)
    expected = [
        element for element in summary.elements
        if element.source in (
            models.ProvenanceSource.corpus_supported,
            models.ProvenanceSource.external_reference,
        )
    ]
    assert invariant == expected


def test_fingerprint_is_stable():
    _, sut, cves = catalog.resolve("0.cve_2021_41773")
    a = provenance.summarize_profile(sut, "0.cve_2021_41773", cves)
    b = provenance.summarize_profile(sut, "0.cve_2021_41773", cves)
    assert (subdetermination.invariant_fingerprint(a)
            == subdetermination.invariant_fingerprint(b))


def test_compatible_variant_roundtrips():
    _, sut, _ = catalog.resolve("0.cve_2021_41773")
    variant = subdetermination.CompatibleVariant(
        variant_id="0.cve_2021_41773#canonical", seed=0,
        sut_profile=sut, free_elements_changed=[], free_fraction=20.0,
    )
    restored = subdetermination.CompatibleVariant.model_validate(
        variant.model_dump())
    assert restored.sut_profile.sut_id == sut.sut_id
    assert restored.free_fraction == 20.0


def test_relocate_decoy_changes_only_artifact():
    _, sut, cves = catalog.resolve("0.cve_2021_41773")
    summary = provenance.summarize_profile(sut, "0.cve_2021_41773", cves)
    _, free = subdetermination.partition(summary)
    decoy = next(e for e in free if e.dimension == "artifacts")
    strategy = subdetermination.RelocateDecoyArtifact()
    assert strategy.applies_to(decoy)
    variant = strategy.perturb(sut, decoy, random.Random(1))
    variant_summary = provenance.summarize_profile(
        variant, "0.cve_2021_41773", cves)
    # The corpus fingerprint is preserved; the artifact identifier changed.
    assert (subdetermination.invariant_fingerprint(variant_summary)
            == subdetermination.invariant_fingerprint(summary))
    assert {e.identifier for e in variant_summary.elements} != {
        e.identifier for e in summary.elements}


def test_rotate_credential_applies_to_free_cred():
    _, sut, cves = catalog.resolve("0.apt41_dust")
    summary = provenance.summarize_profile(sut, "0.apt41_dust", cves)
    _, free = subdetermination.partition(summary)
    cred = next(e for e in free if e.dimension == "credentials")
    strategy = subdetermination.RotateCredentialLiteral()
    assert strategy.applies_to(cred)


def test_substitute_service_is_material_and_preserves_invariant():
    _, sut, cves = catalog.resolve("0.apt41_dust")
    summary = provenance.summarize_profile(sut, "0.apt41_dust", cves)
    _, free = subdetermination.partition(summary)
    ssh_app = next(e for e in free
                   if e.dimension == "software" and "openssh" in e.value)
    strategy = subdetermination.SubstituteEquivalentService()
    assert strategy.applies_to(ssh_app)
    variant = strategy.perturb(sut, ssh_app, random.Random(1))
    variant_summary = provenance.summarize_profile(variant, "0.apt41_dust", cves)
    # Different product now present; corpus fingerprint unchanged.
    values = {e.value for e in variant_summary.elements}
    assert any(v.startswith("dropbear@") for v in values)
    assert (subdetermination.invariant_fingerprint(variant_summary)
            == subdetermination.invariant_fingerprint(summary))


def test_substitute_service_skips_corpus_software():
    # Apache in cve_2021_41773 is externally anchored - never substitutable.
    _, sut, cves = catalog.resolve("0.cve_2021_41773")
    summary = provenance.summarize_profile(sut, "0.cve_2021_41773", cves)
    apache = next(e for e in summary.elements
                  if e.dimension == "software" and "apache" in e.value)
    assert not subdetermination.SubstituteEquivalentService().applies_to(apache)


class _CorpusBreaker:
    """Test double: applies to the free decoy but corrupts the corpus apache
    version - must trip the generator's fingerprint guard."""

    def applies_to(self, element):
        return element.dimension == "artifacts"

    def perturb(self, profile, element, rng):
        variant = profile.model_copy(deep=True)
        for host in variant.hosts or []:
            if host.composition:
                for app in host.composition.applications:
                    app.version = "9.9.9-broken"
        return variant


def test_generator_preserves_invariant_and_changes_free():
    generator = subdetermination.VariantGenerator()
    variant = generator.generate("0.cve_2021_41773", seed=7)
    _, sut, cves = catalog.resolve("0.cve_2021_41773")
    canonical = provenance.summarize_profile(sut, "0.cve_2021_41773", cves)
    variant_summary = provenance.summarize_profile(
        variant.sut_profile, "0.cve_2021_41773", cves)
    assert (subdetermination.invariant_fingerprint(variant_summary)
            == subdetermination.invariant_fingerprint(canonical))
    assert variant.free_elements_changed  # genuinely distinct


def test_generator_is_deterministic():
    g = subdetermination.VariantGenerator()
    a = g.generate("0.apt41_dust", seed=7)
    b = g.generate("0.apt41_dust", seed=7)
    assert a.sut_profile.model_dump() == b.sut_profile.model_dump()


def test_generator_raises_if_strategy_touches_invariant():
    generator = subdetermination.VariantGenerator(strategies=[_CorpusBreaker()])
    with pytest.raises(subdetermination.SubdeterminationError):
        generator.generate("0.cve_2021_41773", seed=1)


def test_run_campaign_exposes_backward_compatible_seam():
    sig = inspect.signature(
        orchestrator_mod.CampaignOrchestrator.run_campaign)
    assert sig.parameters["sut_override"].default is None
    assert sig.parameters["run_label"].default == ""
    # Pre-existing params keep their defaults (backward compatible).
    assert (sig.parameters["fidelity_preference"].default
            == "real_then_surrogate")


def test_proof_structure_cve_minimal():
    proof = subdetermination.prove_subdetermination(
        "0.cve_2021_41773", n_variants=2)
    assert proof.invariant_count == 2
    assert proof.free_count == 3
    assert proof.free_fraction == 60.0
    assert len(proof.variants) == 2
    assert proof.executable is False
    assert proof.execution_runs == []
    for variant in proof.variants:
        summary = provenance.summarize_profile(
            variant.sut_profile, proof.campaign_id, None)
        assert (subdetermination.invariant_fingerprint(summary)
                == proof.invariant_fingerprint)


def test_proof_structure_apt41_material():
    proof = subdetermination.prove_subdetermination(
        "0.apt41_dust", n_variants=2)
    assert proof.invariant_count == 0
    assert proof.free_count == 11
    assert proof.free_fraction == 100.0
    # at least one variant materially substituted a service product
    assert any(cid.startswith("software.")
               for variant in proof.variants
               for cid in variant.free_elements_changed)


def test_cli_emits_structural_proof():
    proc = subprocess.run(
        [sys.executable, "scripts/prove_subdetermination.py",
         "0.cve_2021_41773", "--variants", "2"],
        cwd=str(PROJECT_ROOT), capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["campaign_id"] == "0.cve_2021_41773"
    assert payload["invariant_count"] == 2
    assert len(payload["variants"]) == 2
    assert payload["executable"] is False


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    return subprocess.run(["docker", "info"],
                          capture_output=True).returncode == 0


def _docker_execution_tests_enabled() -> bool:
    return os.environ.get("AUTOSUT_RUN_DOCKER_TESTS") == "1" and _docker_available()


@pytest.mark.skipif(not _docker_execution_tests_enabled(),
                    reason="set AUTOSUT_RUN_DOCKER_TESTS=1 with Docker running")
def test_cve_variants_execute_for_real():
    # The executable existence proof: two compatible variants of the rigorous
    # target both run real_controlled with declared_mode == executed_mode.
    proof = subdetermination.prove_subdetermination(
        "0.cve_2021_41773", n_variants=2, execute=True)
    assert proof.executable is True
    assert len(proof.variants) == 2
    assert len(proof.execution_runs) == 3
    assert all(record.manifest_sha256 for record in proof.execution_runs)
    assert all(record.summary_sha256 for record in proof.execution_runs)


def test_build_subdetermination_artifact_structural():
    import build_subdetermination_artifact as bsa
    artifact = bsa.build_artifact(execute=False)
    proofs = artifact["proofs"]
    assert proofs["0.cve_2021_41773"]["invariant_count"] == 2
    assert proofs["0.cve_2021_41773"]["free_count"] == 3
    # Coincident witness: present in the artifact, partition stable without
    # Docker (executable is only asserted when Docker drives a live run).
    assert proofs["0.pivot_demo"]["invariant_count"] == 0
    assert proofs["0.pivot_demo"]["free_count"] == 9
    # Second coincident witness (edge HTTP service class: Apache <-> Nginx).
    assert proofs["0.web_demo"]["invariant_count"] == 0
    assert proofs["0.web_demo"]["free_count"] == 4
    assert proofs["0.apt41_dust"]["invariant_count"] == 0
    assert proofs["0.apt41_dust"]["free_count"] == 11
    assert "generated_at" in artifact
