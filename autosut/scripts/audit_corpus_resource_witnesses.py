#!/usr/bin/env python3
"""Audit base-host and resource receipts against a frozen SUT corpus."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_FIXTURE_SHA256 = hashlib.sha256(b"AUTOSUT SYNTHETIC DECOY RECORD\n").hexdigest()
HTTP_RESOURCES = frozenset({"private-lab-http-target", "public-facing-application"})


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _digest(value: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-f]{64}", value))


def _matching_transfer(observation: dict, source_key: str, target_key: str, path: str) -> None:
    source = observation[source_key]
    target = observation[target_key]
    _require(_digest(source) and source == target, "resource transfer digest mismatch")
    _require(f"GET /{path} " in observation["server_log"], "resource request log missing")
    _require(observation["request_observed"] is True, "resource request flag missing")


def audit_network_receipt(receipt: dict, required: tuple[str, ...]) -> None:
    """Recompute each reported resource predicate from retained observations."""
    _require(receipt["campaign_executed"] is False, "resource receipt claims campaign execution")
    _require(receipt["network_internal"] is True, "resource network was not internal")
    _require(receipt["teardown_clean"] is True, "resource lab teardown incomplete")
    _require(receipt["resource_witnessed"] is True, "resource probe did not pass")
    gateway = receipt["gateway"]
    _require(gateway["host_gateway_access"] == "blocked_observed", "gateway denial absent")
    _require(gateway["positive_before_rule"] is True, "gateway positive control absent")
    _require(gateway["listener_live_after_rule"] is True, "gateway listener control absent")
    _require(gateway["dropped_packets"] >= 2, "gateway drop counter insufficient")
    observations = receipt["observations"]
    _require(set(receipt["required_resources"]) == set(required), "resource declaration mismatch")
    _require(set(observations) == set(required), "resource observations incomplete")
    for resource in required:
        observed = observations[resource]
        if resource == "controlled-ingress-channel":
            _matching_transfer(observed, "source_sha256", "destination_sha256", "fixture")
        elif resource in HTTP_RESOURCES:
            _matching_transfer(observed, "target_sha256", "actor_sha256", "index.html")
        elif resource == "private-lab-resolver":
            _require(
                observed["resolved_address"] == observed["declared_address"],
                "resolver address mismatch",
            )
        elif resource == "declared-decoy-data":
            _require(
                observed["fixture_sha256"] == DATA_FIXTURE_SHA256, "decoy fixture digest mismatch"
            )
        elif resource == "local-archive-utility":
            _require(_digest(observed["archive_sha256"]), "archive digest invalid")
        elif resource == "bounded-local-chunk-store":
            _require(_digest(observed["sha256"]), "chunk digest invalid")
            _require(
                observed["chunk_count"] > 0 and 0 < observed["maximum_bytes"] <= 1024,
                "chunk bound invalid",
            )
            if "local-archive-utility" in observations:
                _require(
                    observed["sha256"] == observations["local-archive-utility"]["archive_sha256"],
                    "chunk reconstruction differs from archive",
                )
        else:
            raise ValueError(f"unknown resource witness: {resource}")


def _source_hashes_match(receipt: dict) -> None:
    sources = {
        "probe": PROJECT_ROOT / "scripts/probe_corpus_network_resources.py",
        "admission": PROJECT_ROOT / "src/planning/corpus_probe_admission.py",
        "runtime": PROJECT_ROOT / "src/planning/ingress_probe_runtime.py",
        "gateway_guard": PROJECT_ROOT / "src/planning/gateway_guard.py",
    }
    declared = receipt["implementation_sha256"]
    _require(set(declared) == set(sources), "implementation source list mismatch")
    for name, path in sources.items():
        _require(
            hashlib.sha256(path.read_bytes()).hexdigest() == declared[name],
            f"implementation source drift: {name}",
        )


def audit_corpus(corpus: Path, base_receipts: Path, network_receipts: Path) -> dict:
    manifest_path = corpus / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    records = []
    for entry in manifest["records"]:
        if entry["status"] != "blueprint_generated":
            continue
        campaign_id = entry["campaign_id"]
        blueprint_path = corpus / campaign_id / "sut-blueprint.json"
        constraints = json.loads((corpus / campaign_id / "constraints.json").read_text())
        required = tuple(
            sorted(
                {
                    value
                    for item in constraints["requirements"]
                    if item["kind"] != "platform"
                    for value in item["acceptable_values"]
                }
            )
        )
        receipt_path = (network_receipts if required else base_receipts) / f"{campaign_id}.json"
        receipt = json.loads(receipt_path.read_text())
        _require(receipt["campaign_id"] == campaign_id, "receipt campaign identity mismatch")
        _require(
            receipt["blueprint_file_sha256"]
            == hashlib.sha256(blueprint_path.read_bytes()).hexdigest(),
            "receipt blueprint file mismatch",
        )
        _require(
            receipt["blueprint_content_sha256"] == entry["blueprint_sha256"],
            "receipt blueprint content mismatch",
        )
        if required:
            _require(
                receipt["schema_version"] == "autosut-network-resource-probe/v1",
                "wrong network receipt schema",
            )
            audit_network_receipt(receipt, required)
            _source_hashes_match(receipt)
            status = "resources_witnessed"
        else:
            _require(
                receipt["schema_version"] == "autosut-base-host-probe/v1",
                "wrong base-host receipt schema",
            )
            _require(
                receipt["base_host_materialized"] is True and receipt["teardown_clean"] is True,
                "base host did not pass",
            )
            _require(receipt["observed"]["default_route"] is False, "base host has a default route")
            _require(
                receipt["campaign_executed"] is False, "base-host receipt claims campaign execution"
            )
            status = "base_host_materialized"
        records.append({"campaign_id": campaign_id, "status": status, "resources": required})
    _require(len(records) == manifest["blueprints_generated"], "incomplete blueprint receipts")
    return {
        "schema_version": "autosut-corpus-resource-audit/v1",
        "corpus_manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        "campaigns": manifest["campaigns"],
        "blueprints_generated": manifest["blueprints_generated"],
        "base_hosts_materialized": sum(
            item["status"] == "base_host_materialized" for item in records
        ),
        "resource_witnesses": sum(item["status"] == "resources_witnessed" for item in records),
        "campaigns_executed_by_these_probes": 0,
        "records": records,
        "scope": "Host and synthetic resource witnesses; no campaign technique effect or Windows qualification.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", required=True, type=Path)
    parser.add_argument("--base-receipts", required=True, type=Path)
    parser.add_argument("--network-receipts", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError("audit output already exists")
    report = audit_corpus(args.corpus, args.base_receipts, args.network_receipts)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(
        json.dumps(
            {
                key: report[key]
                for key in (
                    "campaigns",
                    "blueprints_generated",
                    "base_hosts_materialized",
                    "resource_witnesses",
                    "campaigns_executed_by_these_probes",
                )
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
