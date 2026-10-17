"""Declared resources and observed preconditions must agree before execution."""

import hashlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from planning.binding_catalog import BindingCatalog, BindingValue  # noqa: E402
from planning.executable_contract import BoundTransition, ExecutableCampaignContract  # noqa: E402
from planning.scenario_admission import (  # noqa: E402
    ObservationEvidence,
    ObservedBinding,
    ScenarioObservation,
    admit_scenario,
)


@pytest.fixture
def scenario(tmp_path):
    evidence = tmp_path / "probe.json"
    evidence.write_text('{"service_present":true}')
    catalog = BindingCatalog(
        sut_id="fixture",
        source_sha256="a" * 64,
        initial_facts=["service.ready"],
        goal_facts=["effect.observed"],
        bindings=[
            BindingValue(
                binding_id="service", kind="endpoint", value="lab://target/service", source="sut"
            )
        ],
    )
    catalog.finalize_hash()
    contract = ExecutableCampaignContract(
        campaign_id="fixture",
        source_campaign_id="C0000",
        source_plan_sha256="b" * 64,
        binding_catalog_sha256=catalog.content_sha256,
        scope="fixture",
        initial_facts=["service.ready"],
        transitions=[
            BoundTransition(
                technique_id="T0000",
                bindings={"endpoint": "service"},
                requires=["service.ready"],
                produces=["effect.observed"],
            )
        ],
    )
    contract.finalize_hash()
    observation = ScenarioObservation(
        run_id="run-1",
        contract_sha256=contract.content_sha256,
        bindings=(
            ObservedBinding(
                binding_id="service", kind="endpoint", value="lab://target/service", present=True
            ),
        ),
        observed_facts=("service.ready",),
        absent_facts=("effect.observed",),
        evidence=(
            ObservationEvidence(
                path="probe.json", sha256=hashlib.sha256(evidence.read_bytes()).hexdigest()
            ),
        ),
    )
    return contract, catalog, observation


def check(scenario, root):
    admit_scenario(*scenario, run_id="run-1", goal_facts=("effect.observed",), evidence_root=root)


def test_matching_scenario_is_admitted(scenario, tmp_path):
    check(scenario, tmp_path)


@pytest.mark.parametrize(
    "change,message",
    [
        ({"bindings": ()}, "binding is absent"),
        ({"observed_facts": ()}, "preconditions were not observed"),
        ({"observed_facts": ("service.ready", "effect.observed")}, "already satisfied"),
        ({"absent_facts": ()}, "absence was not established"),
        ({"run_id": "other-run"}, "another run"),
    ],
)
def test_observation_mismatch_is_rejected(scenario, tmp_path, change, message):
    contract, catalog, observation = scenario
    with pytest.raises(ValueError, match=message):
        check((contract, catalog, observation.model_copy(update=change)), tmp_path)


def test_binding_value_mismatch_is_rejected(scenario, tmp_path):
    contract, catalog, observation = scenario
    binding = observation.bindings[0].model_copy(update={"value": "lab://wrong/service"})
    with pytest.raises(ValueError, match="differs"):
        check(
            (contract, catalog, observation.model_copy(update={"bindings": (binding,)})), tmp_path
        )


def test_modified_evidence_is_rejected(scenario, tmp_path):
    (tmp_path / "probe.json").write_text("changed")
    with pytest.raises(ValueError, match="hash mismatch"):
        check(scenario, tmp_path)


def test_missing_causal_predecessor_is_rejected(scenario, tmp_path):
    contract, catalog, observation = scenario
    contract.transitions[0].requires = ["missing.predecessor"]
    contract.finalize_hash()
    observation = observation.model_copy(update={"contract_sha256": contract.content_sha256})
    with pytest.raises(ValueError, match="causal predecessor"):
        check((contract, catalog, observation), tmp_path)
