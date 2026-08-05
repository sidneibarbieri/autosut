#!/usr/bin/env python3
"""Bind one STICKS procedural plan to an AutoSUT execution contract."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.planning.executable_contract import compile_executable_contract
from src.planning.procedural_plan import load_procedural_plan


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("plan", type=Path)
    parser.add_argument("campaign_spec", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    plan = load_procedural_plan(args.plan)
    contract = compile_executable_contract(plan, args.campaign_spec)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        contract.model_dump_json(indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"[executable-contract] campaign: {contract.campaign_id}")
    print(f"[executable-contract] transitions: {len(contract.transitions)}")
    print(f"[executable-contract] hash: {contract.content_sha256}")
    print(f"[executable-contract] output: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
