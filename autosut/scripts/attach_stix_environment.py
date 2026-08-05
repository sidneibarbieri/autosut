#!/usr/bin/env python3
"""Attach AutoSUT environment semantics to a STICKS-enriched STIX bundle."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
for import_root in (PROJECT_ROOT, SRC_ROOT):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))

from planning.binding_catalog import BindingCatalog  # noqa: E402
from planning.concretized_plan import load_concretized_plan  # noqa: E402
from planning.procedural_plan import load_procedural_plan  # noqa: E402
from planning.stix_environment_extension import (  # noqa: E402
    attach_environment_semantics,
)
from planning.sut_blueprint import SUTBlueprint  # noqa: E402
from planning.sut_constraints import SUTConstraintSet  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sticks-bundle", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--concretized-plan", type=Path, required=True)
    parser.add_argument("--constraints", type=Path, required=True)
    parser.add_argument("--blueprint", type=Path, required=True)
    parser.add_argument("--bindings", type=Path, required=True)
    parser.add_argument(
        "--cve-rules",
        type=Path,
        default=PROJECT_ROOT / "data/cve_resolution_rules.yml",
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    output = attach_environment_semantics(
        sticks_bundle=json.loads(args.sticks_bundle.read_text(encoding="utf-8")),
        procedural_plan=load_procedural_plan(args.plan),
        concretized_plan=load_concretized_plan(args.concretized_plan),
        constraints=SUTConstraintSet.model_validate_json(
            args.constraints.read_text(encoding="utf-8")
        ),
        blueprint=SUTBlueprint.model_validate_json(
            args.blueprint.read_text(encoding="utf-8")
        ),
        binding_catalog=BindingCatalog.model_validate_json(
            args.bindings.read_text(encoding="utf-8")
        ),
        cve_rules_path=args.cve_rules,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
    print(f"[environment-extension] campaign: {output['x_autosut_export']['campaign_id']}")
    print(f"[environment-extension] output: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

