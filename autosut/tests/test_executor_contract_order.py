import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from orchestrator.executor import _order_techniques_for_contract


def test_contract_order_controls_campaign_execution() -> None:
    techniques = [
        {"technique_id": "T2", "name": "second"},
        {"technique_id": "T1", "name": "first"},
    ]

    ordered = _order_techniques_for_contract(techniques, ["T1", "T2"], "demo")

    assert [step["technique_id"] for step in ordered] == ["T1", "T2"]


def test_contract_order_rejects_a_different_technique_set() -> None:
    with pytest.raises(ValueError, match="source and execution contract differ"):
        _order_techniques_for_contract(
            [{"technique_id": "T1", "name": "first"}],
            ["T1", "T2"],
            "demo",
        )


def test_marker_cannot_admit_a_dependent_execution():
    from orchestrator.campaign_state import ExecutionContract, TransitionContract, StateFact, FactSource
    from orchestrator.models import TechniqueOutcome, FidelityLevel, ExecutionMode, Realization
    from orchestrator.executor import _missing_causal_requirements
    fact = StateFact(fact_id="access", subject="target", predicate="access", value="observed", source=FactSource.execution)
    contract = ExecutionContract(scope="test", initial_facts=["ready"], techniques=[
        TransitionContract(technique_id="T1", requires=["ready"], produces=[fact]),
        TransitionContract(technique_id="T2", requires=["access"]),
    ])
    marker = TechniqueOutcome(technique_id="T1", declared_fidelity=FidelityLevel.inspired,
        executed_fidelity=FidelityLevel.inspired, declared_mode=ExecutionMode.naive_simulated,
        executed_mode=ExecutionMode.naive_simulated, realization=Realization.generic_primitive,
        status="success", evidence_files=["marker.log"])
    assert _missing_causal_requirements(contract, [marker], "T2") == ["access"]
    observed = marker.model_copy(update={"executed_mode": ExecutionMode.real_controlled})
    assert _missing_causal_requirements(contract, [observed], "T2") == []


def test_causal_abstention_never_invokes_a_recipe(tmp_path):
    from orchestrator.executor import _causal_abstention
    from orchestrator.models import Realization
    outcome = _causal_abstention("T2", ["access"], tmp_path, Realization.generic_primitive)
    assert outcome.status == "skipped"
    assert "abstained_before_dispatch" in (tmp_path / outcome.evidence_files[0]).read_text()
