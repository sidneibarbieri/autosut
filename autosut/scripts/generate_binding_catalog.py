#!/usr/bin/env python3
"""Generate a secret-free binding catalog from an AutoSUT blueprint."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.planning.binding_catalog import (  # noqa: E402
    build_binding_catalog,
    build_reference_catalog,
)
from src.planning.sut_blueprint import SUTBlueprint  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--blueprint", type=Path, required=True)
    parser.add_argument("--campaign", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--reference-output", type=Path)
    args = parser.parse_args()
    blueprint = SUTBlueprint.model_validate_json(
        args.blueprint.read_text(encoding="utf-8")
    )
    catalog = build_binding_catalog(blueprint, args.campaign)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        catalog.model_dump_json(indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"[bindings] SUT: {catalog.sut_id}")
    print(f"[bindings] values: {len(catalog.bindings)}")
    print(f"[bindings] semantic hash: {catalog.content_sha256}")
    print(f"[bindings] output: {args.output}")
    if args.reference_output:
        reference = build_reference_catalog(catalog)
        args.reference_output.parent.mkdir(parents=True, exist_ok=True)
        args.reference_output.write_text(
            reference.model_dump_json(indent=2) + "\n",
            encoding="utf-8",
        )
        print(f"[bindings] reference values: {len(reference.bindings)}")
        print(
            "[bindings] reference semantic hash: "
            f"{reference.content_sha256}"
        )
        print(f"[bindings] reference output: {args.reference_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
