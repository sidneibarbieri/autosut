#!/usr/bin/env python3
"""Check the recorded identity, evidence paths, and isolation of a paired replay."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from pydantic import BaseModel, ConfigDict

PROJECT_ROOT = Path(__file__).resolve().parents[1]
for source_root in (PROJECT_ROOT / "src", PROJECT_ROOT / "scripts"):
    sys.path.insert(0, str(source_root))

from orchestrator.campaign_state import (
    CampaignStateLedger,
    validate_ledger,
)
from planning.executable_contract import ExecutableCampaignContract
from planning.prepared_replay import (
    JointReplayReceipt,
    load_prepared_pair,
)
from planning.replay_integrity import MANIFEST_NAME, verify_replay_evidence


class ReplayAudit(BaseModel):
    """Static checks over a finished, separately collected replay record."""

    model_config = ConfigDict(extra="forbid")

    campaign_id: str
    total_steps: int
    evidence_files_checked: int
    host_gateway_access: str
    teardown_clean: bool
    integrity_verified: bool = False
    run_id: str | None = None
    limitations: str = (
        "Input hashes, recorded transitions, fidelity counts, evidence paths, and gateway "
        "records are checked. This static audit does not rerun effect observers or "
        "independently establish historical technique fidelity."
        " Retained file digests are checked only when integrity_verified is true."
    )


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _evidence_paths(evidence_dir: Path, techniques: list[dict]) -> int:
    checked = 0
    for technique in techniques:
        _require(technique.get("status") == "success", "a recorded technique did not succeed")
        paths = technique.get("evidence_files", [])
        _require(bool(paths), "a successful technique has no evidence file")
        for relative in paths:
            path = (evidence_dir / relative).resolve()
            _require(
                path.is_relative_to(evidence_dir) and path.is_file(),
                f"technique evidence is missing or escapes the replay: {relative}",
            )
            checked += 1
    return checked


def _audit_transition_records(
    techniques: list[dict],
    state: CampaignStateLedger,
    contract: ExecutableCampaignContract,
) -> None:
    expected_ids = [transition.technique_id for transition in contract.transitions]
    _require(
        [technique.get("technique_id") for technique in techniques]
        == [transition.technique_id for transition in state.transitions]
        == expected_ids,
        "technique sequence differs across contract, manifest, and state",
    )
    for sequence, (technique, transition, declared) in enumerate(
        zip(techniques, state.transitions, contract.transitions, strict=True), start=1
    ):
        _require(transition.sequence == sequence, "recorded transition sequence is not contiguous")
        _require(transition.status == "success", "a recorded transition did not succeed")
        _require(
            technique.get("evidence_files") == transition.evidence_files,
            "evidence paths differ between manifest and transition",
        )
        _require(
            set(declared.produces).issubset(transition.produced_fact_ids),
            "recorded transition omits a contracted produced fact",
        )


def _audit_fidelity_records(
    techniques: list[dict],
    contract: ExecutableCampaignContract,
    receipt: JointReplayReceipt,
) -> None:
    fidelity_rank = {"inspired": 0, "adapted": 1, "faithful": 2}
    counts = {"adapted": 0, "inspired": 0}
    for technique, declared in zip(techniques, contract.transitions, strict=True):
        executed = technique.get("executed_fidelity")
        ceiling = declared.fidelity_ceiling
        _require(executed in fidelity_rank, "unsupported executed fidelity")
        _require(ceiling in fidelity_rank, "contract lacks a supported fidelity ceiling")
        _require(
            technique.get("declared_fidelity") == ceiling
            and fidelity_rank[executed] <= fidelity_rank[ceiling],
            "manifest exceeds or changes the contracted fidelity ceiling",
        )
        _require(executed in counts, "receipt schema cannot account for executed fidelity")
        counts[executed] += 1
    _require(
        receipt.adapted_steps == counts["adapted"] and receipt.inspired_steps == counts["inspired"],
        "receipt fidelity counts differ from the recorded techniques",
    )


def audit_replay(pair_dir: Path, evidence_dir: Path, *, require_integrity: bool = False) -> ReplayAudit:
    """Reject a record whose declared identity or observed boundary has drifted."""
    pair_dir = pair_dir.resolve()
    evidence_dir = evidence_dir.resolve()
    pair, blueprint, contract = load_prepared_pair(pair_dir)
    receipt = JointReplayReceipt.model_validate_json(
        (evidence_dir / "joint-replay-receipt.json").read_text(encoding="utf-8")
    )
    manifest = _read_json(evidence_dir / "manifest.json")
    gateway = _read_json(evidence_dir / "gateway-isolation.json")
    state = CampaignStateLedger.model_validate_json(
        (evidence_dir / "campaign_state.json").read_text(encoding="utf-8")
    )
    integrity_required = (require_integrity or receipt.schema_version == "autosut-joint-replay/v2"
                          or (evidence_dir / MANIFEST_NAME).exists()
                          or receipt.run_id is not None
                          or receipt.evidence_manifest_sha256 is not None)
    if integrity_required:
        _require(receipt.schema_version == "autosut-joint-replay/v2"
                 and receipt.run_id is not None and receipt.evidence_manifest_sha256 is not None,
                 "replay integrity binding required")
        sealed = verify_replay_evidence(evidence_dir, receipt.evidence_manifest_sha256, receipt.run_id)
        _require(sealed.campaign_id == receipt.campaign_id
                 and sealed.run_label == state.run_id == manifest["run_id"],
                 "replay run identity differs from campaign records")

    _require(
        receipt.campaign_id == pair.campaign_id == manifest["campaign_id"] == state.campaign_id,
        "campaign identity differs across pair and replay",
    )
    _require(
        receipt.source_campaign_id == pair.source_campaign_id,
        "source campaign identity differs from the prepared pair",
    )
    _require(
        receipt.pair_manifest_sha256
        == hashlib.sha256((pair_dir / "pair.json").read_bytes()).hexdigest(),
        "prepared-pair manifest hash differs from the receipt",
    )
    _require(
        receipt.blueprint_sha256 == blueprint.content_sha256,
        "blueprint hash differs from the receipt",
    )
    _require(
        receipt.contract_sha256 == contract.content_sha256 == state.executable_contract_sha256,
        "executed contract hash differs from the prepared pair",
    )
    _require(
        state.source_plan_sha256 == contract.source_plan_sha256,
        "executed source plan differs from the prepared contract",
    )
    if pair.source_plan_sha256 is not None:
        _require(
            state.source_plan_sha256 == pair.source_plan_sha256,
            "executed source plan differs from the prepared pair",
        )
    _require(not validate_ledger(state), "campaign state ledger violates its causal contract")

    techniques = manifest["techniques"]
    _require(
        len(techniques)
        == receipt.total_steps
        == len(state.transitions)
        == len(contract.transitions),
        "technique count differs across contract, manifest, state, and receipt",
    )
    _audit_transition_records(techniques, state, contract)
    _audit_fidelity_records(techniques, contract, receipt)
    checked = _evidence_paths(evidence_dir, techniques)
    _require(
        receipt.evidence_backed_steps == receipt.total_steps and receipt.marker_only_steps == 0,
        "receipt does not certify effect-backed completion for every step",
    )
    _require(
        receipt.adapted_steps + receipt.inspired_steps == receipt.total_steps,
        "executed fidelity counts do not cover every step",
    )
    _require(
        receipt.revision_stable and not receipt.causal_violations,
        "implementation or causal ledger changed during replay",
    )
    _require(
        receipt.teardown_clean and manifest["teardown_clean"] and receipt.execution_complete,
        "replay did not finish with clean teardown",
    )
    _require(
        receipt.host_gateway_access == gateway["host_gateway_access"] == "blocked_observed",
        "host gateway denial was not observed",
    )
    _require(
        gateway["positive_before_rule"]
        and gateway["listener_live_after_rule"]
        and gateway["dropped_packets"] > 0,
        "gateway certificate lacks positive reachability or a counted denial",
    )
    return ReplayAudit(
        integrity_verified=integrity_required,
        run_id=receipt.run_id,
        campaign_id=receipt.campaign_id,
        total_steps=receipt.total_steps,
        evidence_files_checked=checked,
        host_gateway_access=receipt.host_gateway_access,
        teardown_clean=receipt.teardown_clean,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pair", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--require-integrity", action="store_true")
    args = parser.parse_args()
    print(audit_replay(args.pair, args.evidence, require_integrity=args.require_integrity).model_dump_json(indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
