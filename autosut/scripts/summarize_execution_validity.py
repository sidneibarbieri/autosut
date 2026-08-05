#!/usr/bin/env python3
"""Build an honest execution-validity table from latest campaign evidence."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts.orchestrator.campaign_state import (
    CampaignStateLedger,
    validate_ledger,
)
from scripts.orchestrator.models import RunResult


DEFAULT_CAMPAIGNS = (
    "0.shadowray",
    "0.pivot_demo",
    "0.dmz_segmentation_demo",
    "0.salesforce_data_exfiltration",
)


def _latest_manifest(campaign_id: str) -> Path:
    evidence_root = PROJECT_ROOT / "release" / "evidence"
    candidates = list(evidence_root.glob(f"{campaign_id}_*/manifest.json"))
    candidates.extend(
        (evidence_root / "_reviewer_runs").glob(
            f"{campaign_id}_*/manifest.json"
        )
    )
    if not candidates:
        raise FileNotFoundError(f"no evidence found for {campaign_id}")
    return max(candidates, key=lambda path: path.stat().st_mtime)


def build_rows(campaigns: tuple[str, ...]) -> list[dict]:
    rows: list[dict] = []
    for campaign_id in campaigns:
        manifest_path = _latest_manifest(campaign_id)
        result = RunResult.model_validate_json(
            manifest_path.read_text(encoding="utf-8")
        )
        spec = json.loads(
            (PROJECT_ROOT / "campaigns" / f"{campaign_id}.json").read_text(
                encoding="utf-8"
            )
        )
        ledger_path = manifest_path.parent / "campaign_state.json"
        ledger = (
            CampaignStateLedger.model_validate_json(
                ledger_path.read_text(encoding="utf-8")
            )
            if ledger_path.exists()
            else None
        )
        contract_declared = (
            ledger.contract_coverage == "declared" if ledger is not None else False
        )
        contract_valid = (
            not validate_ledger(ledger)
            if ledger is not None and ledger.contract_coverage == "declared"
            else None
        )
        context_observations = (
            len(ledger.context_observations) if ledger is not None else 0
        )
        rows.append(
            {
                "campaign_id": campaign_id,
                "source_kind": (
                    "stix_campaign"
                    if spec.get("source_campaign_id")
                    or not str(spec.get("plan_origin", "")).startswith("autosut_internal")
                    else "engineering_witness"
                ),
                "source_campaign_id": spec.get("source_campaign_id", ""),
                "run_id": result.run_id,
                "total_steps": result.total_techniques,
                "status_success": result.successful,
                "evidence_backed_success": result.evidence_backed_successful,
                "adapted_success": result.adapted_successful,
                "marker_only": result.marker_only_successful,
                "contract_declared": contract_declared,
                "contract_valid": contract_valid,
                "context_observations": context_observations,
                "teardown_clean": result.teardown_clean,
                "evidence_path": str(manifest_path.relative_to(PROJECT_ROOT)),
            }
        )
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign", action="append", dest="campaigns")
    parser.add_argument(
        "--json-output",
        type=Path,
        default=PROJECT_ROOT / "release" / "experiments" / "execution_validity.json",
    )
    parser.add_argument(
        "--csv-output",
        type=Path,
        default=PROJECT_ROOT / "release" / "experiments" / "execution_validity.csv",
    )
    args = parser.parse_args()
    rows = build_rows(tuple(args.campaigns or DEFAULT_CAMPAIGNS))
    args.json_output.parent.mkdir(parents=True, exist_ok=True)
    args.json_output.write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
    with args.csv_output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    print(f"[execution-validity] rows: {len(rows)}")
    print(f"[execution-validity] JSON: {args.json_output}")
    print(f"[execution-validity] CSV: {args.csv_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
