#!/usr/bin/env python3
"""Compile a verified STICKS plan into an AutoSUT execution contract."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.planning.concretized_plan import load_concretized_plan  # noqa: E402
from src.planning.executable_contract import compile_verified_contract  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--campaign", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    plan = load_concretized_plan(args.plan)
    contract = compile_verified_contract(plan, args.campaign)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        contract.model_dump_json(indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"[contract] campaign: {contract.campaign_id}")
    print(f"[contract] transitions: {len(contract.transitions)}")
    print(f"[contract] semantic hash: {contract.content_sha256}")
    print(f"[contract] output: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
