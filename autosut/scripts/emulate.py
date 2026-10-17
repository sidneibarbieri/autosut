#!/usr/bin/env python3
"""Show what environment a campaign needs, and whether this artifact can build it.

The recorded experiments report the environment semantics gap across the corpus. This applies the
same resolution to one campaign the reader chooses and prints, in order: what the procedure requires
from a System Under Test, which of those requirements a laboratory can materialize today, and where
the requirement outruns what public intelligence justifies.

The input is a procedural plan, the typed form of a campaign that the companion STICKS artifact
compiles from a STIX bundle. Given that plan, this resolves the minimal environment its steps need,
reports the platforms a materializable backend covers, and names the techniques left uncovered. It
does not stand up infrastructure; it decides whether infrastructure could be stood up and says so.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from planning.procedural_plan import load_procedural_plan  # noqa: E402
from planning.sut_constraints import resolve_sut_constraints  # noqa: E402

# The backends a laboratory can materialize today. Linux is provisioned; the others are declared
# where a real backend exists, so this set is the honest statement of current reach.
MATERIALIZABLE_PLATFORMS = {"Linux"}
RULE = "-" * 78


def summarize(plan_path: Path) -> None:
    plan = load_procedural_plan(plan_path)
    constraints = resolve_sut_constraints(plan, materializable_platforms=MATERIALIZABLE_PLATFORMS)
    resolution = constraints.platform_resolution

    print(RULE)
    print(f"CAMPAIGN {plan.campaign_id}   steps: {len(plan.steps)}")
    print(RULE)

    print("The procedure needs a System Under Test that provides:")
    for requirement in constraints.requirements:
        if requirement.kind == "platform":
            techniques = ", ".join(requirement.technique_ids)
            print(f"  {techniques:<16} platform in {{{', '.join(requirement.acceptable_values)}}}")

    print("\nWhat a laboratory can materialize today:")
    print(f"  selected platforms:      {', '.join(resolution.selected_platforms) or 'none'}")
    print(f"  materializable here:     {', '.join(resolution.materializable_platforms)}")
    if resolution.unsupported_platforms:
        print(f"  not materializable:      {', '.join(resolution.unsupported_platforms)}")
    if resolution.uncovered_technique_ids:
        print(f"  techniques left uncovered: {', '.join(resolution.uncovered_technique_ids)}")

    print()
    if resolution.complete:
        print("  This environment is materializable end to end from the measured requirements.")
    else:
        print("  This environment is not materializable here: the requirement outruns what a")
        print("  Linux laboratory covers. The gap is reported per technique rather than filled in,")
        print("  which is what the environment semantics gap means for this campaign.")
    print(RULE)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("plan", help="procedural plan compiled from a campaign, e.g. C0045.procedural-plan.json")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    plan_path = Path(args.plan)
    if not plan_path.is_file():
        raise FileNotFoundError(f"procedural plan not found: {plan_path}")
    summarize(plan_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
