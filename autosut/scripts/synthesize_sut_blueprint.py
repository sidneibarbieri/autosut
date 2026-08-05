#!/usr/bin/env python3
"""Synthesize an isolated SUT blueprint from resolved constraints."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from planning.sut_blueprint import synthesize_blueprint
from planning.sut_constraints import SUTConstraintSet


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("constraints", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    constraints = SUTConstraintSet.model_validate_json(
        args.constraints.read_text(encoding="utf-8")
    )
    blueprint = synthesize_blueprint(constraints)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(blueprint.model_dump_json(indent=2), encoding="utf-8")
    print(f"[sut-blueprint] campaign: {blueprint.campaign_id}")
    print(f"[sut-blueprint] hosts: {len(blueprint.hosts)}")
    print(f"[sut-blueprint] output: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
