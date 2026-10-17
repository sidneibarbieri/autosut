"""Keep recorded execution separate from each reference case's scientific role."""

import importlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.fixture
def dashboard(monkeypatch, tmp_path):
    root = Path(__file__).resolve().parents[1]
    monkeypatch.syspath_prepend(str(root / "scripts"))
    module = importlib.import_module("build_reviewer_dashboard")
    monkeypatch.setattr(module, "PROJECT_ROOT", tmp_path)
    (tmp_path / "release").mkdir()
    return module


def render_cases(dashboard, cases):
    proofs = {
        case_id: {
            "executable": executable,
            "invariant_fingerprint": "0123456789abcdef" * 4,
            "variants": [{}, {}],
            "invariant_count": 7,
            "free_count": 3,
        }
        for case_id, executable in cases.items()
    }
    artifact = dashboard.PROJECT_ROOT / "release" / "subdetermination_proof.json"
    artifact.write_text(json.dumps({"proofs": proofs}), encoding="utf-8")
    return dashboard.render_subdetermination_section()


def test_cve_decoy_variants_are_a_harness_check(dashboard):
    html = render_cases(dashboard, {"0.cve_2021_41773": True})
    assert "Harness sanity check" in html
    assert "decoy-only" in html
    assert "not a material service-substitution witness" in html
    assert "Executable witness:" not in html
    assert "<th>Reference case</th>" in html
    assert "<th>Fixed elements</th>" in html
    assert "same corpus fingerprint" not in html
    assert "0123456789abcdef" in html
    assert "<td>2</td>" in html
    assert "<td>7</td><td>3</td>" in html


@pytest.mark.parametrize(
    ("executed_case", "structural_case", "included", "excluded"),
    [
        ("0.pivot_demo", "0.web_demo", "OpenSSH and Dropbear", "Apache and Nginx"),
        ("0.web_demo", "0.pivot_demo", "Apache and Nginx", "OpenSSH and Dropbear"),
    ],
)
def test_execution_details_are_specific_to_the_recorded_case(
    dashboard, executed_case, structural_case, included, excluded
):
    html = render_cases(dashboard, {executed_case: True, structural_case: False})
    assert included in html
    assert excluded not in html
    assert "Internal service-substitution demonstration" in html
    assert "Execution not recorded" in html
    assert "two informative service" not in html


def test_structural_case_does_not_imply_deployment(dashboard):
    html = render_cases(dashboard, {"0.apt41_dust": False})
    assert "Structural compatibility illustration" in html
    assert "Execution not recorded" in html
    assert "not deployment evidence" in html
    assert "successfully execute" not in html


def test_unknown_reference_cannot_inherit_a_witness_role(dashboard):
    html = render_cases(dashboard, {"unclassified_reference": True})
    assert "Unclassified reference" in html
    assert "not a classified witness" in html


def test_malformed_evidence_is_not_hidden(dashboard):
    artifact = dashboard.PROJECT_ROOT / "release" / "subdetermination_proof.json"
    artifact.write_text("invalid JSON", encoding="utf-8")
    with pytest.raises(json.JSONDecodeError):
        dashboard.render_subdetermination_section()


def test_overview_does_not_promote_the_cve_harness(dashboard):
    merged = SimpleNamespace(
        total_elements=0,
        percentages={source: 0 for source in (
            "corpus_supported", "external_reference", "autosut_concretized",
            "analyst_authored",
        )},
    )
    html = dashboard.render_audit_overview(merged, {"claims": []})
    assert "not a material" in html
    assert "decoy-variation harness check" in html
    assert "Non-uniqueness witness</strong>" not in html
    assert "same corpus fingerprint" not in html


@pytest.mark.parametrize("claims", [None, {}, "invalid", 3, False])
def test_invalid_claims_preserve_document_validation_error(dashboard, claims):
    artifact = dashboard.PROJECT_ROOT / "release" / dashboard.CLAIM_LEDGER_FILE
    artifact.write_text(json.dumps({"claims": claims}), encoding="utf-8")
    assert issubclass(dashboard.ClaimLedgerError, ValueError)
    with pytest.raises(dashboard.ClaimLedgerError, match="claim ledger must contain a claims list"):
        dashboard.load_claim_ledger()


def test_empty_claim_list_remains_valid(dashboard):
    artifact = dashboard.PROJECT_ROOT / "release" / dashboard.CLAIM_LEDGER_FILE
    artifact.write_text(json.dumps({"claims": []}), encoding="utf-8")
    assert dashboard.load_claim_ledger() == {"claims": []}
