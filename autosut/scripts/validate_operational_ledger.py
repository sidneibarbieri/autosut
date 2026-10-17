#!/usr/bin/env python3
"""Validate an operational ledger and emit its frozen per-environment metrics."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from evaluation.operational_metrics import OperationalLedger, calculate_metrics  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("ledger", type=Path)
    parser.add_argument(
        "--evidence-root",
        type=Path,
        help="verify every hash-bound evidence reference below this directory",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    ledger = OperationalLedger.model_validate_json(args.ledger.read_text(encoding="utf-8"))
    if args.evidence_root is not None:
        ledger.verify_evidence(args.evidence_root)
    metrics = [metric.model_dump(mode="json") for metric in calculate_metrics(ledger)]
    print(json.dumps(metrics, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
