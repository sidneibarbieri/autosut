#!/usr/bin/env python3
"""Compare raw-plan and enriched-plan readiness without executing a campaign.

This is an ablation manifest, not a claim of attack success. It makes the
reviewer-visible difference between a source STIX list and the executable
contract explicit before any sandbox is started.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from src.planning.procedural_plan import load_procedural_plan
from src.planning.sut_constraints import SUTConstraintSet


def build_comparison(plan_path: Path, constraints_path: Path) -> dict:
    plan = load_procedural_plan(plan_path)
    constraints = SUTConstraintSet.model_validate_json(
        constraints_path.read_text(encoding="utf-8")
    )
    raw_steps = plan.steps
    enriched_steps = [step for step in raw_steps if step.execution_domain != "attacker"]
    return {
        "schema_version": "1",
        "campaign_id": plan.campaign_id,
        "raw_stix_arm": {
            "steps": len(raw_steps),
            "target_boundary_known": False,
            "ordering_policy": "source-links-without-total-order",
            "sut_ready": False,
            "reason": "STIX procedure links alone do not specify a materialized SUT.",
        },
        "enriched_autosut_arm": {
            "steps": len(enriched_steps),
            "attacker_steps_excluded": len(raw_steps) - len(enriched_steps),
            "selected_platforms": constraints.platform_resolution.selected_platforms,
            "uncovered_techniques": constraints.platform_resolution.uncovered_technique_ids,
            "sut_ready": constraints.platform_resolution.complete,
            "constraint_count": len(constraints.requirements),
        },
        "interpretation": "The arms are compared on readiness and coverage; execution evidence is produced only by the enriched arm.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("plan", type=Path)
    parser.add_argument("constraints", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    comparison = build_comparison(args.plan, args.constraints)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(comparison, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(comparison, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
