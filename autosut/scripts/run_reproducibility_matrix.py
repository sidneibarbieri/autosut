#!/usr/bin/env python3
"""Run representative campaigns sequentially and compare semantic outcomes."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from orchestrator import build_default
from orchestrator.campaign_state import CampaignStateLedger, validate_ledger


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CAMPAIGNS = (
    "0.shadowray",
    "0.pivot_demo",
    "0.dmz_segmentation_demo",
)


def semantic_projection(ledger: CampaignStateLedger) -> dict:
    """Return the stable campaign semantics, excluding run-local identifiers."""

    return {
        "campaign_id": ledger.campaign_id,
        "contract_coverage": ledger.contract_coverage,
        "declared_technique_ids": ledger.declared_technique_ids,
        "executed_technique_ids": ledger.executed_technique_ids,
        "transitions": [
            {
                "technique_id": transition.technique_id,
                "status": transition.status,
                "missing_requirements": transition.missing_requirements,
                "produced_fact_ids": transition.produced_fact_ids,
            }
            for transition in ledger.transitions
        ],
        "fact_ids": [fact.fact_id for fact in ledger.facts],
        "context": [
            {
                "activity_id": observation.activity_id,
                "source_host": observation.source_host,
                "destination_host": observation.destination_host,
                "protocol": observation.protocol,
                "port": observation.port,
                "status": observation.status,
            }
            for observation in ledger.context_observations
        ],
    }


def semantic_hash(ledger: CampaignStateLedger) -> str:
    encoded = json.dumps(
        semantic_projection(ledger),
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _relative(path: Path) -> str:
    return str(path.resolve().relative_to(PROJECT_ROOT))


def run_matrix(campaigns: tuple[str, ...], repetitions: int) -> dict:
    orchestrator = build_default()
    rows: list[dict] = []
    for campaign_id in campaigns:
        for repetition in range(1, repetitions + 1):
            fidelity = "surrogate" if campaign_id == "0.shadowray" else "real_then_surrogate"
            result = orchestrator.run_campaign(
                campaign_id,
                fidelity_preference=fidelity,
                run_label=f"_rep{repetition:02d}",
            )
            ledger_path = Path(result.campaign_state_path)
            ledger = CampaignStateLedger.model_validate_json(
                ledger_path.read_text(encoding="utf-8")
            )
            violations = validate_ledger(ledger)
            evidence_missing = [
                evidence_path
                for transition in ledger.transitions
                for evidence_path in transition.evidence_files
                if not (ledger_path.parent / evidence_path).is_file()
            ]
            rows.append(
                {
                    "campaign_id": campaign_id,
                    "repetition": repetition,
                    "run_id": result.run_id,
                    "successful": result.successful,
                    "evidence_backed_successful": result.evidence_backed_successful,
                    "adapted_successful": result.adapted_successful,
                    "marker_only_successful": result.marker_only_successful,
                    "total_techniques": result.total_techniques,
                    "teardown_clean": result.teardown_clean,
                    "semantic_sha256": semantic_hash(ledger),
                    "ledger": _relative(ledger_path),
                    "violations": violations,
                    "missing_evidence": sorted(set(evidence_missing)),
                }
            )

    campaigns_summary: dict[str, dict] = {}
    for campaign_id in campaigns:
        campaign_rows = [row for row in rows if row["campaign_id"] == campaign_id]
        hashes = sorted({row["semantic_sha256"] for row in campaign_rows})
        campaigns_summary[campaign_id] = {
            "repetitions": len(campaign_rows),
            "semantic_hashes": hashes,
            "semantically_identical": len(hashes) == 1,
            "all_steps_successful": all(
                row["evidence_backed_successful"] == row["total_techniques"]
                for row in campaign_rows
            ),
            "all_teardowns_clean": all(
                row["teardown_clean"] for row in campaign_rows
            ),
            "all_ledgers_valid": all(
                not row["violations"] and not row["missing_evidence"]
                for row in campaign_rows
            ),
        }

    return {
        "schema_version": "1",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "campaigns": campaigns_summary,
        "runs": rows,
        "pass": all(
            summary["semantically_identical"]
            and summary["all_steps_successful"]
            and summary["all_teardowns_clean"]
            and summary["all_ledgers_valid"]
            for summary in campaigns_summary.values()
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--campaign",
        action="append",
        dest="campaigns",
        help="Campaign ID; repeat the option to select several.",
    )
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument(
        "--output",
        type=Path,
        default=PROJECT_ROOT / "release" / "experiments" / "reproducibility_matrix.json",
    )
    args = parser.parse_args()
    if args.repetitions < 2:
        parser.error("--repetitions must be at least 2")
    campaigns = tuple(args.campaigns or DEFAULT_CAMPAIGNS)
    report = run_matrix(campaigns, args.repetitions)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"[reproducibility] output: {args.output}")
    print(f"[reproducibility] pass: {report['pass']}")
    for campaign_id, summary in report["campaigns"].items():
        print(
            f"[reproducibility] {campaign_id}: "
            f"{summary['repetitions']} runs, "
            f"{len(summary['semantic_hashes'])} semantic hash(es)"
        )
    return 0 if report["pass"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
