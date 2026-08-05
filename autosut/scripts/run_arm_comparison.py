#!/usr/bin/env python3
"""Validate and render the self-contained C0045 bounded experiment."""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
for import_root in (PROJECT_ROOT, SRC_ROOT):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))

from evaluation.arm_comparison import (  # noqa: E402
    build_report,
    load_comparison_report,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input-manifest",
        type=Path,
        default=(
            PROJECT_ROOT
            / "release/inputs/sticks/c0045-v1/manifest.json"
        ),
    )
    parser.add_argument(
        "--execution-validity",
        type=Path,
        default=PROJECT_ROOT / "release/experiments/execution_validity.json",
    )
    parser.add_argument("--local-campaign-id", default="0.shadowray")
    parser.add_argument(
        "--output",
        type=Path,
        default=(
            PROJECT_ROOT / "release/experiments/arm_comparison/C0045.json"
        ),
    )
    parser.add_argument(
        "--csv-output",
        type=Path,
        default=(
            PROJECT_ROOT / "release/experiments/arm_comparison/C0045.csv"
        ),
    )
    args = parser.parse_args()
    report = build_report(
        input_manifest_path=args.input_manifest,
        execution_validity_path=args.execution_validity,
        local_campaign_id=args.local_campaign_id,
        project_root=PROJECT_ROOT,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        report.model_dump_json(indent=2) + "\n",
        encoding="utf-8",
    )
    verified_report = load_comparison_report(args.output)
    with args.csv_output.open("w", encoding="utf-8", newline="") as handle:
        fieldnames = [
            "arm_id",
            "treatment",
            "technique_count",
            "verified_procedure_count",
            "precondition_resolved_count",
            "executable_step_count",
            "executed_with_evidence_count",
            "resolver_output_verified",
            "execution_attempted",
            "campaign_completed",
            "assumption_count",
            "assumption_bearing_step_count",
            "execution_semantic_sha256",
        ]
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for arm in verified_report.arms:
            row = arm.model_dump()
            writer.writerow({field: row.get(field) for field in fieldnames})
    print(f"[c0045] input set: {verified_report.input_audit.input_set_id}")
    print(f"[c0045] report: {args.output}")
    print(f"[c0045] CSV: {args.csv_output}")
    print(
        "[c0045] plan synthesis gate: "
        f"{verified_report.plan_synthesis_gate_passed}"
    )
    print(
        "[c0045] arm-C execution gate: "
        f"{verified_report.execution_evidence_gate_passed}"
    )
    print(
        "[c0045] three-arm execution supported: "
        f"{verified_report.three_arm_execution_comparison_supported}"
    )
    for arm in verified_report.arms:
        print(
            f"[c0045] {arm.arm_id}: planned={arm.executable_step_count}/"
            f"{arm.technique_count}, execution_evidence="
            f"{arm.executed_with_evidence_count}"
        )
    return 0 if verified_report.primary_gate_passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
