#!/usr/bin/env python3
"""Propose a materializable SUT composition for a STIX-derived procedural plan.

STICKS compiles a STIX bundle into a procedural plan. This command derives a supported platform,
asks a model to propose a composition for the plan's on-host steps, and checks only whether the
proposal is materializable by the local recipe set. It writes a planning record with
``operational_status: not_run``. It does not stand up the proposal, execute commands, or establish
that the generated composition is historically grounded or semantically sufficient.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from orchestrator.sut_applications import RECIPES  # noqa: E402
from planning.model_provider import ProviderConfig, build_completion, recording_completion  # noqa: E402
from planning.procedural_plan import load_procedural_plan  # noqa: E402
from planning.sut_constraints import resolve_sut_constraints  # noqa: E402
from planning.sut_synthesizer import synthesize_composition  # noqa: E402

MATERIALIZABLE_PLATFORMS = {"Linux"}
RULE = "-" * 78


def on_host_steps(plan) -> list:
    return [step for step in plan.steps
            if step.execution_domain != "attacker" and (set(step.platforms) - {"PRE"})]


def brief_dicts(steps) -> list[dict]:
    return [{"technique_id": s.technique_id, "name": s.name,
             "procedure": " ".join(s.procedure_descriptions)[:200]} for s in steps]


def run(plan_path: Path, config_path: Path, record_path: Path | None):
    plan = load_procedural_plan(plan_path)
    constraints = resolve_sut_constraints(plan, materializable_platforms=MATERIALIZABLE_PLATFORMS)
    materializable = constraints.platform_resolution.materializable_platforms
    if not materializable:
        raise SystemExit(f"plan {plan.campaign_id} needs "
                         f"{constraints.platform_resolution.selected_platforms}, none materializable here")
    platform = materializable[0]
    steps = on_host_steps(plan)

    complete = build_completion(ProviderConfig.from_file(config_path))
    if record_path is not None:
        record_path.parent.mkdir(parents=True, exist_ok=True)
        complete = recording_completion(complete, record_path)

    composition, verdict = synthesize_composition(
        platform, brief_dicts(steps), complete,
        materializable_platforms=MATERIALIZABLE_PLATFORMS, known_recipes=set(RECIPES),
    )
    print(RULE)
    print(f"PLAN {plan.campaign_id}   platform: {platform}   on-host techniques: {len(steps)}")
    print(f"synthesized SUT: {len(composition.credentials)} credentials, "
          f"{len(composition.artifacts)} artifacts, {len(composition.applications)} applications")
    if not verdict.materializable:
        print("SUT proposal is not materializable:")
        for issue in verdict.issues:
            print(f"  - {issue}")
        print(RULE)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir = PROJECT_ROOT / "release" / "runs" / "synth-planning" / f"{plan.campaign_id}-{stamp}"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "synthesized_composition.json").write_text(
        json.dumps(composition.model_dump(), indent=2), encoding="utf-8")
    (out_dir / "synthesis_verdict.json").write_text(json.dumps({
        "campaign_id": plan.campaign_id,
        "platform": platform,
        "on_host_technique_count": len(steps),
        "materializable": verdict.materializable,
        "issues": verdict.issues,
        "operational_status": "not_run",
    }, indent=2), encoding="utf-8")
    print(RULE)
    print(f"  materializable {verdict.materializable}   operational status: not_run")
    print(f"  wrote {out_dir}")
    print(RULE)
    return composition, verdict


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("plan", help="a STICKS procedural plan, e.g. C0045.procedural-plan.json")
    parser.add_argument("--config", required=True, help="model provider config")
    parser.add_argument("--record", help="write the planning transcript here for offline inspection")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    run(Path(args.plan), Path(args.config), Path(args.record) if args.record else None)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
