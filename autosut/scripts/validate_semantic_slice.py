#!/usr/bin/env python3
"""Validate the latest controlled execution slice and its state ledger."""

from __future__ import annotations

import json
from pathlib import Path

from orchestrator.campaign_state import CampaignStateLedger, validate_ledger


PROJECT_ROOT = Path(__file__).resolve().parent.parent
EVIDENCE_ROOT = PROJECT_ROOT / "release" / "evidence"
CAMPAIGN_ID = "0.shadowray"
EXPECTED_TECHNIQUES = (
    "T1588.002",
    "T1190",
    "T1059.006",
    "T1546.004",
    "T1068",
    "T1027.013",
    "T1003.008",
    "T1016",
    "T1105",
    "T1496.001",
)


def latest_run_dir() -> Path:
    candidates = [
        path
        for path in EVIDENCE_ROOT.glob(f"{CAMPAIGN_ID}_*")
        if all(
            (path / filename).is_file()
            for filename in ("manifest.json", "summary.json", "campaign_state.json", "fidelity_report.json")
        )
    ]
    if not candidates:
        raise SystemExit(f"missing evidence directory for {CAMPAIGN_ID}")
    return max(candidates, key=lambda path: path.name)


def main() -> None:
    run_dir = latest_run_dir()
    manifest_path = run_dir / "manifest.json"
    ledger_path = run_dir / "campaign_state.json"
    if not manifest_path.is_file() or not ledger_path.is_file():
        raise SystemExit("controlled slice is missing manifest or state ledger")

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    ledger = CampaignStateLedger.model_validate_json(ledger_path.read_text(encoding="utf-8"))
    observed = tuple(item["technique_id"] for item in manifest["techniques"])
    if observed != EXPECTED_TECHNIQUES:
        raise SystemExit(f"unexpected controlled technique sequence: {observed}")
    if any(item["status"] != "success" for item in manifest["techniques"]):
        raise SystemExit("controlled technique sequence did not complete")
    if ledger.contract_coverage != "declared":
        raise SystemExit("controlled technique sequence has no declared state contract")
    violations = validate_ledger(ledger)
    if violations:
        raise SystemExit(f"state-contract violations: {violations}")

    print(f"[semantic-slice] evidence: {run_dir}")
    print("[semantic-slice] controlled state contract OK")


if __name__ == "__main__":
    main()
