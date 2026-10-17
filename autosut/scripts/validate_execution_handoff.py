#!/usr/bin/env python3
"""Validate a generic execution handoff against the current AutoSUT revision."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from infrastructure.execution_handoff import ExecutionHandoff  # noqa: E402
from infrastructure.revision import current_revision  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("handoff", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    handoff = ExecutionHandoff.model_validate_json(args.handoff.read_text(encoding="utf-8"))
    handoff.validate_for_consumer(
        consumer="autosut",
        revision=current_revision(PROJECT_ROOT),
    )
    print(
        f"[execution-handoff] accepted {handoff.campaign_id} seed={handoff.seed} "
        f"from {handoff.producer}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
