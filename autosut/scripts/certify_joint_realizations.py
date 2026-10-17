#!/usr/bin/env python3
"""Certify STICKS realization graphs against an AutoSUT blueprint and bindings."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.planning.binding_catalog import BindingCatalog  # noqa: E402
from src.planning.joint_realization import (  # noqa: E402
    certify_joint_realizations,
    load_realization_space,
)
from src.planning.sut_blueprint import SUTBlueprint  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--realizations", type=Path, required=True)
    parser.add_argument("--blueprint", type=Path, required=True)
    parser.add_argument("--bindings", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--require-compatible", action="store_true")
    args = parser.parse_args()

    space = load_realization_space(args.realizations)
    blueprint = SUTBlueprint.model_validate_json(args.blueprint.read_text(encoding="utf-8"))
    catalog = BindingCatalog.model_validate_json(args.bindings.read_text(encoding="utf-8"))
    result = certify_joint_realizations(space, blueprint, catalog)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(result.model_dump_json(indent=2) + "\n", encoding="utf-8")
    print(f"[joint] campaign: {result.campaign_id}")
    print(f"[joint] SUT: {result.sut_id}")
    print(f"[joint] compatible: {result.compatible_realization_count}")
    print(f"[joint] operational status: {result.operational_status}")
    print(f"[joint] hash: {result.content_sha256}")
    print(f"[joint] output: {args.output}")
    if args.require_compatible and result.compatible_realization_count == 0:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
