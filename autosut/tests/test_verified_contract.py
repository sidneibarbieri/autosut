from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from planning.concretized_plan import ConcretizedPlanInput
from planning.executable_contract import compile_verified_contract


def test_verified_contract_preserves_bindings_and_causal_state(
    tmp_path: Path,
) -> None:
    plan = ConcretizedPlanInput(
        schema_version="1",
        campaign_id="C9999",
        source_plan_sha256="source-plan",
        binding_catalog_sha256="bindings",
        action_catalog_sha256="actions",
        steps=[
            {
                "sequence": 1,
                "technique_id": "T1190",
                "template_id": "probe",
                "bindings": {"endpoint": "endpoint.primary"},
                "requires": ["sut.service.reachable"],
                "produces": ["access.target.shell"],
                "evidence_predicates": ["request_logged"],
                "fidelity_ceiling": "adapted",
                "proposal_source": "finite_domain_solver",
                "assumption_count": 0,
            }
        ],
        planning_certificate={
            "valid": True,
            "unresolved_goals": [],
            "content_sha256": "certificate",
        },
        execution_semantic_sha256="execution-semantics",
        content_sha256="concretized",
    )
    campaign = tmp_path / "campaign.json"
    campaign.write_text(
        json.dumps(
            {
                "campaign_id": "local.fixture",
                "source_campaign_id": "C9999",
                "execution_contract": {
                    "scope": "controlled",
                    "initial_facts": ["sut.service.reachable"],
                    "techniques": [
                        {
                            "technique_id": "T1190",
                            "requires": ["sut.service.reachable"],
                            "produces": ["access.target.shell"],
                        }
                    ],
                },
            }
        ),
        encoding="utf-8",
    )
    contract = compile_verified_contract(plan, campaign)
    assert contract.transitions[0].bindings == {"endpoint": "endpoint.primary"}
    assert contract.transitions[0].evidence_predicates == ["request_logged"]
    assert contract.planning_certificate_sha256 == "certificate"
    assert contract.content_sha256
