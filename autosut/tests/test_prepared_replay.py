"""Prepared replay must refuse altered inputs before provisioning."""

import hashlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT / "src", ROOT / "scripts"):
    sys.path.insert(0, str(path))

from planning.prepared_replay import load_prepared_pair
from orchestrator import campaign_state


def test_external_identity_reuses_only_an_exact_reviewed_procedure():
    from planning.execution_admission import resolve_template_adapter

    _, _, contract = load_prepared_pair(ROOT / "release/prepared-pairs/0.c0010")
    external = contract.model_copy(deep=True, update={"campaign_id": "external-linux-study"})
    assert resolve_template_adapter(external) == "0.c0010"
    external.transitions[0].bindings = {"actor": "unreviewed.external.actor"}
    with pytest.raises(ValueError, match="binding mismatch"):
        resolve_template_adapter(external)


def test_external_identity_cannot_admit_an_incomplete_procedure():
    from planning.execution_admission import resolve_template_adapter

    _, _, contract = load_prepared_pair(ROOT / "release/prepared-pairs/0.c0026")
    external = contract.model_copy(deep=True, update={"campaign_id": "external-linux-study"})
    external.transitions.pop()
    with pytest.raises(ValueError, match="no reviewed execution adapter"):
        resolve_template_adapter(external)


def test_external_specification_scope_is_restored_after_failure(tmp_path):
    spec = tmp_path / "campaign.json"
    spec.write_text(json.dumps({"campaign_id": "external-linux-study"}))
    with pytest.raises(RuntimeError):
        with campaign_state.use_verified_contract(tmp_path / "contract.json", spec):
            assert campaign_state._campaign_spec("external-linux-study")["campaign_id"] == "external-linux-study"
            raise RuntimeError("fixture failure")
    assert campaign_state._active_campaign_spec.get() is None


def test_blocked_pair_cannot_be_materialized(tmp_path):
    (tmp_path / "pair.json").write_text(json.dumps({"campaign_id": "blocked", "reasons": ["unsupported_platform_requirements"]}))
    with pytest.raises(ValueError, match="pair is blocked"):
        load_prepared_pair(tmp_path)


def test_manifest_must_cover_execution_inputs(tmp_path):
    (tmp_path / "pair.json").write_text(json.dumps({"campaign_id": "fixture", "status": "prepared"}))
    with pytest.raises(ValueError, match="omits required"):
        load_prepared_pair(tmp_path)


def test_changed_execution_input_is_rejected(tmp_path):
    names = ["sut-blueprint.json", "executable-contract.json", "campaign-source.json", "campaign.json"]
    for name in names:
        (tmp_path / name).write_text("{}")
    digest = hashlib.sha256(b"{}").hexdigest()
    (tmp_path / "pair.json").write_text(json.dumps({"campaign_id": "fixture", "status": "prepared", "files": dict.fromkeys(names, digest)}))
    (tmp_path / "campaign.json").write_text('{"changed": true}')
    with pytest.raises(ValueError, match="hash mismatch: campaign.json"):
        load_prepared_pair(tmp_path)


def test_contract_scope_is_restored_after_failure(tmp_path):
    assert campaign_state._active_contract.get() is None
    with pytest.raises(RuntimeError):
        with campaign_state.use_verified_contract(tmp_path / "contract.json"):
            assert campaign_state._active_contract.get() == tmp_path / "contract.json"
            raise RuntimeError("fixture failure")
    assert campaign_state._active_contract.get() is None


def test_unreviewed_template_cannot_reuse_shadowray_executor():
    from planning.prepared_replay import validate_template_adapters
    from planning.executable_contract import ExecutableCampaignContract, BoundTransition
    contract = ExecutableCampaignContract(campaign_id="0.shadowray", source_campaign_id="C0045",
        source_plan_sha256="fixture", scope="test", initial_facts=["ready"],
        transitions=[BoundTransition(technique_id="T1105", template_id="unreviewed-alternative", produces=["payload"])])
    with pytest.raises(ValueError, match="no reviewed execution adapter"):
        validate_template_adapters(contract)


def test_shadowray_partial_sequence_cannot_reuse_reviewed_adapter():
    from planning.execution_admission import SHADOWRAY_TEMPLATE_ADAPTERS
    from planning.prepared_replay import validate_template_adapters
    from planning.executable_contract import BoundTransition, ExecutableCampaignContract

    technique_id, template_id = next(iter(SHADOWRAY_TEMPLATE_ADAPTERS.items()))
    contract = ExecutableCampaignContract(
        campaign_id="0.shadowray",
        source_campaign_id="C0045",
        source_plan_sha256="synthetic",
        scope="synthetic test",
        initial_facts=["ready"],
        transitions=[BoundTransition(
            technique_id=technique_id,
            template_id=template_id,
            produces=["staged"],
        )],
    )
    with pytest.raises(ValueError, match="no reviewed execution adapter"):
        validate_template_adapters(contract)


def test_shadowray_faithful_claim_is_rejected():
    from planning.execution_admission import SHADOWRAY_TEMPLATE_ADAPTERS
    from planning.prepared_replay import validate_template_adapters
    from planning.executable_contract import BoundTransition, ExecutableCampaignContract

    contract = ExecutableCampaignContract(
        campaign_id="0.shadowray", source_campaign_id="C0045",
        source_plan_sha256="synthetic", scope="synthetic test", initial_facts=["ready"],
        transitions=[BoundTransition(
            technique_id=technique_id, template_id=template_id, produces=["effect"],
            fidelity_ceiling="faithful" if technique_id == "T1190" else (
                "inspired" if technique_id == "T1068" else "adapted"
            ),
        ) for technique_id, template_id in SHADOWRAY_TEMPLATE_ADAPTERS.items()],
    )

    with pytest.raises(ValueError, match="fidelity ceiling exceeds reviewed adapter"):
        validate_template_adapters(contract)


def test_unregistered_template_is_rejected_for_c0010():
    from planning.prepared_replay import validate_template_adapters
    from planning.executable_contract import ExecutableCampaignContract, BoundTransition
    contract = ExecutableCampaignContract(campaign_id="0.c0010", source_campaign_id="C0010", source_plan_sha256="fixture", scope="lab", initial_facts=["ready"], transitions=[BoundTransition(technique_id="T1189", template_id="unregistered", produces=["access"])])
    with pytest.raises(ValueError, match="no reviewed execution adapter"):
        validate_template_adapters(contract)


def test_bounded_adapter_cannot_promote_inspired_template():
    from planning.bounded_templates import (
        CAMPAIGN_TEMPLATES, TEMPLATE_BINDINGS, TEMPLATE_PREDICATES,
    )
    from planning.prepared_replay import validate_template_adapters
    from planning.executable_contract import BoundTransition, ExecutableCampaignContract

    contract = ExecutableCampaignContract(
        campaign_id="0.c0010", source_campaign_id="C0010",
        source_plan_sha256="synthetic", scope="synthetic test", initial_facts=["ready"],
        transitions=[BoundTransition(
            technique_id=technique_id, template_id=template_id, produces=["effect"],
            bindings=TEMPLATE_BINDINGS[template_id],
            evidence_predicates=TEMPLATE_PREDICATES[template_id],
            fidelity_ceiling="adapted",
        ) for technique_id, template_id in CAMPAIGN_TEMPLATES["0.c0010"].items()],
    )

    with pytest.raises(ValueError, match="fidelity ceiling exceeds reviewed adapter"):
        validate_template_adapters(contract)


def test_unknown_campaign_cannot_bypass_adapter_admission():
    from planning.prepared_replay import validate_template_adapters
    from planning.executable_contract import BoundTransition, ExecutableCampaignContract

    contract = ExecutableCampaignContract(
        campaign_id="0.unknown",
        source_campaign_id="C9999",
        source_plan_sha256="synthetic",
        scope="synthetic test",
        initial_facts=["ready"],
        transitions=[BoundTransition(
            technique_id="T1105",
            template_id="transfer-staged-benign-tool",
            produces=["payload"],
        )],
    )
    with pytest.raises(ValueError, match="no reviewed execution adapter for campaign"):
        validate_template_adapters(contract)


def test_external_evidence_directory_is_portable(tmp_path):
    from orchestrator.orchestrator import portable_evidence_directory

    assert portable_evidence_directory(tmp_path) == "."
