#!/usr/bin/env python3
"""Resolve a STICKS procedural plan into an AutoSUT constraint set."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from planning.procedural_plan import load_procedural_plan
from planning.sut_constraints import resolve_sut_constraints


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("plan", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--materializable-platform",
        action="append",
        dest="platforms",
        default=["Linux"],
        help="Platform supported by the current AutoSUT backend; repeat as needed.",
    )
    args = parser.parse_args()

    plan = load_procedural_plan(args.plan)
    constraints = resolve_sut_constraints(
        plan, materializable_platforms=set(args.platforms)
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(constraints.model_dump_json(indent=2), encoding="utf-8")
    print(f"[sut-constraints] campaign: {constraints.campaign_id}")
    print(
        "[sut-constraints] selected platforms: "
        + ", ".join(constraints.platform_resolution.selected_platforms)
    )
    print(f"[sut-constraints] complete: {constraints.platform_resolution.complete}")
    print(f"[sut-constraints] output: {args.output}")
    return 0 if constraints.platform_resolution.complete else 2


if __name__ == "__main__":
    raise SystemExit(main())
