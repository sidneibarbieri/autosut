#!/usr/bin/env python3
"""CLI: construct and report a subdetermination proof for one campaign.

Usage:
    python3 scripts/prove_subdetermination.py <campaign_id> [--variants N]
                                              [--seed S] [--execute]

Without --execute the proof is structural (no Docker). With --execute every
variant is run through the orchestrator and `executable` reflects whether each
ran with declared_mode == executed_mode and a clean teardown.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from orchestrator import subdetermination  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="subdetermination proof")
    parser.add_argument("campaign_id")
    parser.add_argument("--variants", type=int, default=2)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()

    proof = subdetermination.prove_subdetermination(
        args.campaign_id, n_variants=args.variants,
        seed=args.seed, execute=args.execute,
    )
    print(json.dumps(proof.model_dump(mode="json"), indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
