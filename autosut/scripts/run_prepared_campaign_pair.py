#!/usr/bin/env python3
"""Materialize a prepared STICKS/AutoSUT pair and verify its causal execution."""

import argparse
import os
import sys
from pathlib import Path

os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
sys.dont_write_bytecode = True

PROJECT_ROOT = Path(__file__).resolve().parents[1]
for root in (PROJECT_ROOT / "src", PROJECT_ROOT / "scripts"):
    sys.path.insert(0, str(root))

from planning.prepared_replay import replay_prepared_pair


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pair", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    args = parser.parse_args()
    receipt = replay_prepared_pair(args.pair.resolve(), args.evidence.resolve())
    print(receipt.model_dump_json(indent=2))
    return 0 if receipt.execution_complete else 2


if __name__ == "__main__":
    raise SystemExit(main())
