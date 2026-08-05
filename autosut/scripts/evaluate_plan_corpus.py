#!/usr/bin/env python3
"""Evaluate compiled procedural plans against declared AutoSUT backends."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.planning.procedural_plan import load_procedural_plan
from src.planning.sut_blueprint import synthesize_blueprint
from src.planning.sut_constraints import (
    RequirementSource,
    resolve_sut_constraints,
)


def evaluate_corpus(
    plans_dir: Path,
    materializable_platforms: set[str],
    constraints_dir: Path,
) -> dict:
    constraints_dir.mkdir(parents=True, exist_ok=True)
    rows: list[dict] = []
    for plan_path in sorted(plans_dir.glob("C*.procedural-plan.json")):
        plan = load_procedural_plan(plan_path)
        constraints = resolve_sut_constraints(
            plan,
            materializable_platforms=materializable_platforms,
        )
        constraint_path = constraints_dir / f"{plan.campaign_id}.sut-constraints.json"
        constraint_path.write_text(
            constraints.model_dump_json(indent=2) + "\n",
            encoding="utf-8",
        )
        blueprint_skeleton_available = False
        if constraints.platform_resolution.complete:
            synthesize_blueprint(constraints)
            blueprint_skeleton_available = True
        rows.append(
            {
                "campaign_id": plan.campaign_id,
                "campaign_name": plan.campaign_name,
                "step_count": len(plan.steps),
                "target_or_boundary_steps": sum(
                    step.execution_domain != "attacker" for step in plan.steps
                ),
                "selected_platforms": constraints.platform_resolution.selected_platforms,
                "unsupported_platforms": constraints.platform_resolution.unsupported_platforms,
                "uncovered_technique_count": len(
                    constraints.platform_resolution.uncovered_technique_ids
                ),
                "platform_constraint_complete": constraints.platform_resolution.complete,
                "blueprint_skeleton_available": blueprint_skeleton_available,
                "stix_requirement_count": sum(
                    requirement.source == RequirementSource.stix_field
                    for requirement in constraints.requirements
                ),
                "curated_requirement_count": sum(
                    requirement.source == RequirementSource.curated_rule
                    for requirement in constraints.requirements
                ),
                "constraint_sha256": constraints.content_sha256,
                "constraint_path": str(constraint_path.relative_to(PROJECT_ROOT)),
            }
        )
    return {
        "schema_version": "1",
        "evaluation_claim": (
            "platform_constraint_and_blueprint_skeleton_coverage_"
            "not_replay_ready_sut_or_campaign_execution"
        ),
        "materializable_platforms": sorted(materializable_platforms),
        "plan_count": len(rows),
        "platform_constraint_complete_count": sum(
            row["platform_constraint_complete"] for row in rows
        ),
        "blueprint_skeleton_available_count": sum(
            row["blueprint_skeleton_available"] for row in rows
        ),
        "rows": rows,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plans-dir", type=Path, required=True)
    parser.add_argument(
        "--materializable-platform",
        action="append",
        dest="platforms",
        default=[],
    )
    parser.add_argument(
        "--constraints-dir",
        type=Path,
        default=PROJECT_ROOT / "release" / "plans" / "enterprise",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=PROJECT_ROOT / "release" / "experiments" / "enterprise_constraint_coverage.json",
    )
    args = parser.parse_args()
    platforms = set(args.platforms or ["Linux"])
    report = evaluate_corpus(args.plans_dir, platforms, args.constraints_dir)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"[plan-corpus] plans: {report['plan_count']}")
    print(
        "[plan-corpus] platform-complete constraints: "
        f"{report['platform_constraint_complete_count']}"
    )
    print(
        "[plan-corpus] blueprint skeletons available: "
        f"{report['blueprint_skeleton_available_count']}"
    )
    print(f"[plan-corpus] output: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
