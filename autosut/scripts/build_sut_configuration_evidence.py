#!/usr/bin/env python3
"""Measure the provenance and variability of proposed SUT configurations.

Reads the frozen proposals, assigns provenance to every value by comparing it against the
constraints AutoSUT measured from the bundle, and reports how much of a deployable
configuration the intelligence supports. Deterministic and offline: only the collection of
proposals needs local models.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
for import_root in (PROJECT_ROOT, SRC_ROOT):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))

from planning.sut_configuration import (  # noqa: E402
    ConfiguredService,
    SutConfigurationProposal,
    classify_proposal,
    partition_requirements,
)
from planning.sut_constraints import EnvironmentRequirement  # noqa: E402

PLANS_DIR = PROJECT_ROOT / "release" / "plans"
EXPERIMENT_DIR = PROJECT_ROOT / "release" / "experiments" / "sut_configuration"
PROPOSALS_DIR = EXPERIMENT_DIR / "proposals"
DEFAULT_OUTPUT = EXPERIMENT_DIR / "corpus.json"

QUESTION = (
    "How much of a deployable SUT configuration do the measured CTI constraints support, and "
    "how much must a proposer introduce?"
)
METHOD = (
    "Each campaign's measured environment constraints are given to two local model families, "
    "sampled three times each, which return a concrete configuration. Every value is then "
    "classified by comparing it against those constraints and a versioned deployment catalog. "
    "Provenance is assigned by this check, not declared by the proposer."
)
NOTE = (
    "Satisfaction is reported only for platform requirements, whose values a configuration "
    "states in the same vocabulary. The remaining measured requirements name the role a "
    "component plays in the declared laboratory rather than a deployable product, so the step "
    "from role to product is exactly what a proposer must supply and what the intelligence "
    "does not decide. "
    "A satisfied configuration is consistent with the measured constraints of the campaign. It "
    "is not the environment the campaign historically ran against. Values classified as "
    "proposer-introduced are deployment choices without support in the evaluated fields; they "
    "are not necessarily wrong, but nothing in the intelligence determines them."
)


def _requirements(campaign_id: str) -> list[EnvironmentRequirement]:
    payload = json.loads(
        (PLANS_DIR / f"{campaign_id}.sut-constraints.json").read_text(encoding="utf-8")
    )
    return [EnvironmentRequirement.model_validate(item) for item in payload["requirements"]]


def _deployment_catalog() -> set[str]:
    """Products the measured constraints name anywhere, which a laboratory could stock."""
    catalog: set[str] = set()
    for path in sorted(PLANS_DIR.glob("*.sut-constraints.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        for requirement in payload["requirements"]:
            if requirement["kind"] != "platform":
                catalog.update(requirement["acceptable_values"])
    return catalog


def _proposal(record: dict) -> SutConfigurationProposal:
    services = [
        ConfiguredService(
            host_role=str(service.get("host_role", "")),
            product=str(service.get("product", "")),
            version=str(service.get("version", "")),
            port=str(service.get("port", "")),
            exposure=str(service.get("exposure", "")),
        )
        for service in record.get("services", [])
        if isinstance(service, dict)
    ]
    return SutConfigurationProposal(
        campaign_id=record["campaign_id"],
        proposer=f"{record['model']}.{record['sample']}",
        platform=str(record.get("platform", "")),
        services=services,
    )


def _distinct_service_stacks(verdict_records: list[dict]) -> dict[str, int]:
    """Distinct product sets proposed per campaign, as a coarse variability measure."""
    stacks: dict[str, set[str]] = {}
    for record in verdict_records:
        signature = "|".join(
            sorted(
                str(service.get("product", "")).strip().lower()
                for service in record.get("services", [])
                if str(service.get("product", "")).strip()
            )
        )
        stacks.setdefault(record["campaign_id"], set()).add(signature)
    return {campaign: len(values) for campaign, values in stacks.items()}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    records = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in sorted(PROPOSALS_DIR.glob("*.json"))
    ]
    if not records:
        raise FileNotFoundError(f"no frozen proposals under {PROPOSALS_DIR}")

    catalog = _deployment_catalog()
    requirements_by_campaign = {
        campaign: _requirements(campaign)
        for campaign in sorted({record["campaign_id"] for record in records})
    }

    totals: Counter[str] = Counter()
    satisfying = 0
    per_proposal = []
    for record in records:
        comparable, role_level = partition_requirements(
            requirements_by_campaign[record["campaign_id"]]
        )
        verdict = classify_proposal(_proposal(record), comparable, catalog)
        counts = verdict.provenance_counts()
        totals.update(counts)
        satisfying += 1 if verdict.satisfies_all_requirements else 0
        per_proposal.append(
            {
                "campaign_id": verdict.campaign_id,
                "role_level_requirements": len(role_level),
                "proposer": verdict.proposer,
                "services": verdict.services,
                "provenance_counts": counts,
                "satisfies_all_requirements": verdict.satisfies_all_requirements,
            }
        )

    occurrences = sum(totals.values())
    corpus = {
        "question": QUESTION,
        "method": METHOD,
        "campaigns": len(requirements_by_campaign),
        "proposals": len(records),
        "total_value_occurrences": occurrences,
        "provenance_occurrence_counts": dict(totals),
        "proposer_introduced_rate": totals["proposer_introduced"] / occurrences,
        "cti_evidenced_rate": totals["cti_evidenced"] / occurrences,
        "proposals_satisfying_all_platform_requirements": satisfying,
        "role_level_requirements_per_campaign": {
            campaign: len(partition_requirements(requirements)[1])
            for campaign, requirements in requirements_by_campaign.items()
        },
        "distinct_service_stacks_per_campaign": _distinct_service_stacks(records),
        "note": NOTE,
        "per_proposal": per_proposal,
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(corpus, indent=2) + "\n", encoding="utf-8")
    print(
        f"[sut-configuration] {corpus['proposals']} proposals, "
        f"{occurrences} value occurrences: "
        f"{corpus['cti_evidenced_rate'] * 100:.1f}% CTI-evidenced, "
        f"{corpus['proposer_introduced_rate'] * 100:.1f}% proposer-introduced; "
        f"distinct stacks per campaign {corpus['distinct_service_stacks_per_campaign']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
