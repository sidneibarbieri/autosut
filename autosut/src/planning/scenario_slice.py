"""Derive a hash-bound executable slice from a larger campaign contract."""

from __future__ import annotations

from collections.abc import Iterable

from .binding_catalog import BindingCatalog
from .executable_contract import ExecutableCampaignContract


def derive_scenario_slice(
    contract: ExecutableCampaignContract,
    catalog: BindingCatalog,
    technique_ids: Iterable[str],
) -> tuple[ExecutableCampaignContract, BindingCatalog]:
    """Return a causally closed contract and catalog for the selected techniques."""

    selected_ids = tuple(technique_ids)
    if not selected_ids or len(set(selected_ids)) != len(selected_ids):
        raise ValueError("scenario slice requires unique technique ids")
    for label, source in (("contract", contract), ("catalog", catalog)):
        verified = source.model_copy(deep=True)
        verified.finalize_hash()
        if verified.content_sha256 != source.content_sha256:
            raise ValueError(f"source {label} hash mismatch")
    if contract.binding_catalog_sha256 != catalog.content_sha256:
        raise ValueError("source contract/catalog mismatch")
    if contract.campaign_id != catalog.sut_id:
        raise ValueError("source campaign/SUT identity mismatch")

    transitions_by_id = {transition.technique_id: transition for transition in contract.transitions}
    missing_ids = sorted(set(selected_ids) - transitions_by_id.keys())
    if missing_ids:
        raise ValueError("unknown technique ids: " + ", ".join(missing_ids))

    selected = [
        transition for transition in contract.transitions if transition.technique_id in selected_ids
    ]
    if [transition.technique_id for transition in selected] != list(selected_ids):
        raise ValueError("scenario slice must preserve contract order")

    reachable = set(contract.initial_facts)
    for transition in selected:
        missing_facts = sorted(set(transition.requires) - reachable)
        if missing_facts:
            raise ValueError(
                f"{transition.technique_id} is not causally closed: " + ", ".join(missing_facts)
            )
        reachable.update(transition.produces)

    goal_facts = list(selected[-1].produces)
    required_binding_ids = {
        binding_id for transition in selected for binding_id in transition.bindings.values()
    }
    sliced_catalog = catalog.model_copy(
        deep=True,
        update={
            "goal_facts": goal_facts,
            "bindings": [
                binding
                for binding in catalog.bindings
                if binding.binding_id in required_binding_ids
            ],
            "content_sha256": "",
        },
    )
    sliced_catalog.finalize_hash()
    sliced_contract = contract.model_copy(
        deep=True,
        update={
            "transitions": selected,
            "binding_catalog_sha256": sliced_catalog.content_sha256,
            "scope": f"{contract.scope}:technique-slice",
            "content_sha256": "",
        },
    )
    sliced_contract.finalize_hash()
    return sliced_contract, sliced_catalog
