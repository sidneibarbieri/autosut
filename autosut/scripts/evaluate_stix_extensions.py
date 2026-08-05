#!/usr/bin/env python3
"""Evaluate STIX, STICKS, and AutoSUT semantic closure with ablations."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
for import_root in (PROJECT_ROOT, SRC_ROOT):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))

from evaluation.extension_effectiveness import (  # noqa: E402
    build_extension_effectiveness_report,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--csv-output", type=Path, required=True)
    args = parser.parse_args()

    report = build_extension_effectiveness_report(
        json.loads(args.bundle.read_text(encoding="utf-8"))
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report.model_dump_json(indent=2) + "\n", encoding="utf-8")
    with args.csv_output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "arm_id",
                "treatment",
                "applicable_cells",
                "resolved_cells",
                "unresolved_cells",
                "closure_rate",
            ],
        )
        writer.writeheader()
        for arm in report.arms:
            writer.writerow(
                {
                    field: getattr(arm, field)
                    for field in writer.fieldnames or []
                }
            )
    print(f"[extension-eval] campaign: {report.campaign_id}")
    for arm in report.arms:
        print(
            f"[extension-eval] {arm.arm_id}: "
            f"{arm.resolved_cells}/{arm.applicable_cells} "
            f"({arm.closure_rate:.3f})"
        )
    print(f"[extension-eval] unresolved full-arm cells: {len(report.unresolved_full_arm_cells)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

