#!/usr/bin/env python3
"""Measure platform reach separately from SUT realization and execution."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path


PLATFORM_SCENARIOS = {
    "current_docker": frozenset({"Linux"}),
    "docker_plus_windows": frozenset({"Linux", "Windows"}),
}
PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _platform_requirements(constraints: dict) -> list[dict]:
    return [item for item in constraints["requirements"] if item["kind"] == "platform"]


def _uncovered(requirements: list[dict], platforms: frozenset[str]) -> list[str]:
    return [
        item["requirement_id"]
        for item in requirements
        if not platforms.intersection(item["acceptable_values"])
    ]


def _declared_contracts(campaign_specs: Path) -> set[str]:
    if not campaign_specs.is_dir():
        raise ValueError(f"campaign specification directory missing: {campaign_specs}")
    source_ids = set()
    for path in sorted(campaign_specs.glob("*.json")):
        spec = json.loads(path.read_text())
        if spec.get("source_campaign_id") and spec.get("execution_contract"):
            source_ids.add(spec["source_campaign_id"])
    return source_ids


def audit_corpus(corpus: Path, campaign_specs: Path = PROJECT_ROOT / "campaigns") -> dict:
    manifest_path = corpus / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    declared_contracts = _declared_contracts(campaign_specs)
    records = []
    summary = Counter()
    seen_campaigns: set[str] = set()
    for entry in manifest["records"]:
        campaign_id = entry["campaign_id"]
        if not re.fullmatch(r"C\d{4}", campaign_id) or campaign_id in seen_campaigns:
            raise ValueError(f"invalid or duplicate campaign ID: {campaign_id}")
        seen_campaigns.add(campaign_id)
        constraints = json.loads((corpus / campaign_id / "constraints.json").read_text())
        if constraints["campaign_id"] != campaign_id:
            raise ValueError(f"constraint identity mismatch for {campaign_id}")
        expected_hash = constraints["content_sha256"]
        content = {key: value for key, value in constraints.items() if key != "content_sha256"}
        encoded = json.dumps(content, sort_keys=True, separators=(",", ":")).encode()
        if hashlib.sha256(encoded).hexdigest() != expected_hash:
            raise ValueError(f"constraint hash mismatch for {campaign_id}")
        if constraints["source_plan_sha256"] != entry["source_plan_sha256"]:
            raise ValueError(f"source plan mismatch for {campaign_id}")
        requirements = _platform_requirements(constraints)
        scenarios = {
            name: _uncovered(requirements, platforms)
            for name, platforms in PLATFORM_SCENARIOS.items()
        }
        nonplatform = [item for item in constraints["requirements"] if item["kind"] != "platform"]
        for name, missing in scenarios.items():
            summary[f"{name}_covered_campaigns"] += not missing
            summary[f"{name}_uncovered_requirements"] += len(missing)
            summary[f"{name}_without_nonplatform_requirements"] += not missing and not nonplatform
        summary["campaigns"] += 1
        summary["blueprints_generated"] += entry["status"] == "blueprint_generated"
        summary["materialized_in_corpus_batch"] += bool(entry["materialized"])
        summary["executed_in_corpus_batch"] += bool(entry["executed"])
        summary["campaigns_with_unverified_nonplatform_requirements"] += bool(nonplatform)
        summary["campaigns_with_declared_execution_contracts"] += campaign_id in declared_contracts
        records.append({
            "campaign_id": campaign_id,
            "current_docker_uncovered": scenarios["current_docker"],
            "docker_plus_windows_uncovered": scenarios["docker_plus_windows"],
            "nonplatform_requirement_ids": [item["requirement_id"] for item in nonplatform],
            "declared_execution_contract": campaign_id in declared_contracts,
            "materialized_in_corpus_batch": bool(entry["materialized"]),
            "executed_in_corpus_batch": bool(entry["executed"]),
        })
    if summary["campaigns"] != manifest["campaigns"]:
        raise ValueError("manifest campaign count mismatch")
    return {
        "schema_version": "autosut-readiness-audit/v1",
        "source_manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        "scope": (
            "Windows is a counterfactual platform availability scenario. Platform reach does "
            "not establish resource provisioning, procedure admission, execution, or effect."
        ),
        "summary": dict(summary),
        "records": records,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", type=Path)
    parser.add_argument("--campaign-specs", type=Path, default=PROJECT_ROOT / "campaigns")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = audit_corpus(args.corpus, args.campaign_specs)
    encoded = json.dumps(report, indent=2) + "\n"
    if args.output:
        if args.output.exists():
            raise ValueError("readiness report already exists; preserve prior evidence")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded)
    else:
        print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
