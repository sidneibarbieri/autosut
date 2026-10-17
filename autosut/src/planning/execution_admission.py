"""Admit only contracts with reviewed, bounded execution adapters."""

from .executable_contract import ExecutableCampaignContract


SHADOWRAY_TEMPLATE_ADAPTERS = {
    "T1588.002": "stage-benign-toolkit",
    "T1190": "probe-declared-public-service",
    "T1059.006": "run-benign-python",
    "T1546.004": "write-lab-shell-config",
    "T1068": "assess-privilege-boundary",
    "T1027.013": "encode-benign-artifact",
    "T1003.008": "read-declared-credential-fixture",
    "T1016": "inspect-declared-network",
    "T1105": "transfer-benign-payload",
    "T1496.001": "run-bounded-compute-workload",
}
REVIEWED_CAMPAIGNS = frozenset({"0.c0010", "0.c0026", "0.shadowray"})


def resolve_template_adapter(contract: ExecutableCampaignContract) -> str:
    """Reject unknown campaigns or changes to their reviewed operation sequence."""
    if contract.campaign_id != "0.shadowray":
        from .bounded_templates import bounded_recipe_id, validate_bound_template

        validate_bound_template(contract)
        return bounded_recipe_id(contract)
    if contract.campaign_id == "0.shadowray":
        actual = [(step.technique_id, step.template_id) for step in contract.transitions]
        expected = list(SHADOWRAY_TEMPLATE_ADAPTERS.items())
        if actual != expected:
            raise ValueError("no reviewed execution adapter for ShadowRay sequence")
        for step in contract.transitions:
            expected_fidelity = "inspired" if step.technique_id == "T1068" else "adapted"
            if step.fidelity_ceiling != expected_fidelity:
                raise ValueError(f"fidelity ceiling exceeds reviewed adapter for {step.technique_id}")
        return "0.shadowray"
    raise ValueError(f"no reviewed execution adapter for campaign {contract.campaign_id}")


def has_reviewed_sequence(contract: ExecutableCampaignContract) -> bool:
    from .bounded_templates import CAMPAIGN_TEMPLATES

    actual = [(step.technique_id, step.template_id) for step in contract.transitions]
    if contract.campaign_id == "0.shadowray":
        return actual == list(SHADOWRAY_TEMPLATE_ADAPTERS.items())
    if contract.campaign_id in CAMPAIGN_TEMPLATES:
        return actual == list(CAMPAIGN_TEMPLATES[contract.campaign_id].items())
    return any(actual == list(templates.items()) for templates in CAMPAIGN_TEMPLATES.values())


def validate_template_adapters(contract: ExecutableCampaignContract) -> None:
    resolve_template_adapter(contract)
