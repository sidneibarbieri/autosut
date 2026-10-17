#!/usr/bin/env python3
"""Qualify the bounded supply-chain sequence without provider calls."""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


def main() -> None:
    from planning.supply_chain_qualification import qualify_supply_chain

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--image", default="python:3.11-slim")
    args = parser.parse_args()
    receipt = qualify_supply_chain(args.plan.resolve(), args.evidence.resolve(), args.image)
    print(receipt.model_dump_json(indent=2))


if __name__ == "__main__":
    main()
