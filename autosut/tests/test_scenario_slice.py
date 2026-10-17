from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from planning.binding_catalog import BindingCatalog
from planning.executable_contract import ExecutableCampaignContract
from planning.scenario_slice import derive_scenario_slice

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _inputs() -> tuple[ExecutableCampaignContract, BindingCatalog]:
    contract = ExecutableCampaignContract.model_validate_json(
        (PROJECT_ROOT / "release/plans/C0045.verified-executable-contract.json").read_text()
    )
    catalog = BindingCatalog.model_validate_json(
        (PROJECT_ROOT / "release/plans/C0045.binding-catalog.json").read_text()
    )
    return contract, catalog


def test_slice_rehashes_contract_and_catalog_for_exact_goal() -> None:
    contract, catalog = _inputs()

    sliced_contract, sliced_catalog = derive_scenario_slice(contract, catalog, ("T1190",))

    assert [step.technique_id for step in sliced_contract.transitions] == ["T1190"]
    assert sliced_catalog.goal_facts == ["access.target.shell", "access:initial"]
    assert [binding.binding_id for binding in sliced_catalog.bindings] == [
        "actor.primary",
        "target.primary",
        "endpoint.public_service",
    ]
    assert sliced_contract.binding_catalog_sha256 == sliced_catalog.content_sha256
    assert sliced_contract.content_sha256 != contract.content_sha256


def test_slice_rejects_missing_causal_predecessor() -> None:
    contract, catalog = _inputs()

    with pytest.raises(ValueError, match="not causally closed"):
        derive_scenario_slice(contract, catalog, ("T1059.006",))


def test_slice_requires_contract_order() -> None:
    contract, catalog = _inputs()

    with pytest.raises(ValueError, match="preserve contract order"):
        derive_scenario_slice(contract, catalog, ("T1190", "T1588.002"))


@pytest.mark.parametrize("source_kind", ["contract", "catalog"])
def test_slice_rejects_tampered_source(source_kind: str) -> None:
    contract, catalog = _inputs()
    if source_kind == "contract":
        contract.scope = "altered"
    else:
        catalog.bindings[0].value = "lab://different-actor"

    with pytest.raises(ValueError, match=f"source {source_kind} hash mismatch"):
        derive_scenario_slice(contract, catalog, ("T1190",))


def test_slice_rejects_different_sut_even_with_valid_hashes() -> None:
    contract, catalog = _inputs()
    catalog.sut_id = "different-sut"
    catalog.finalize_hash()
    contract.binding_catalog_sha256 = catalog.content_sha256
    contract.finalize_hash()

    with pytest.raises(ValueError, match="identity mismatch"):
        derive_scenario_slice(contract, catalog, ("T1190",))
