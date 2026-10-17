"""Tests for the public claim-to-evidence ledger."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = PROJECT_ROOT / "scripts" / "generate_claim_evidence_ledger.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("claim_evidence_ledger", SCRIPT_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load claim-evidence ledger generator")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_caldera_dispatch_claim_uses_the_canonical_public_witness() -> None:
    module = _load_module()
    claim = module._caldera_dispatch_claim()

    assert claim["status"] == "supported_bounded"
    assert claim["evidence_artifacts"]
    assert claim["measured_value"]["campaign_id"] == "0.shadowray"
    assert claim["measured_value"]["source_campaign_id"] == "C0045"
    assert all(path.startswith("release/experiments/") for path in claim["evidence_artifacts"])
    assert "release/evidence/shadowray_caldera/milestone.json" not in claim["evidence_artifacts"]


def test_every_generated_claim_uses_the_declared_status_vocabulary() -> None:
    module = _load_module()
    ledger = module.build_ledger()

    declared = set(ledger["status_vocabulary"])
    observed = {claim["status"] for claim in ledger["claims"]}
    assert observed <= declared


def test_ledger_dimensions_are_independent_of_manuscript_questions() -> None:
    claims = {claim["claim_id"]: claim for claim in _load_module().build_ledger()["claims"]}
    expected = {
        "RQ1-MEASUREMENT": "cti_environment_evidence",
        "RQ2-OPERATIONALIZATION": "compatibility_policy",
        "RQ3-SPECIFICITY": "profile_distinctiveness",
        "RQ2-CONFIGURATION-01": "sut_configuration",
        "RQ1-NVD-ENRICHMENT-01": "vulnerability_enrichment",
        "CALDERA-DISPATCH-01": "caldera_dispatch",
        "RQ4-CONSTRUCTIVE-01": "environment_non_identification",
        "C0045-CASE-01": "controlled_sut_contrast",
    }
    assert {identity: claim["evidence_dimension"] for identity, claim in claims.items()} == expected
    assert all("research_question" not in claim for claim in claims.values())
