#!/usr/bin/env python3
"""Build the canonical claim-to-evidence ledger for the public artifact.

The measurement pipeline already emits a detailed RQ1--RQ3 map.  This script
adds the system witnesses used for RQ4 and the bounded C0045 case study, while
making unsupported interpretations explicit.  It never upgrades a claim from
the existence of a file alone: each system claim has a small, executable gate
over the recorded evidence.
"""

from __future__ import annotations

import csv
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
MEASUREMENT_MAP = (
    PROJECT_ROOT
    / "measurement"
    / "sut"
    / "scripts"
    / "results"
    / "claim_evidence_map.csv"
)
RELEASE_DIR = PROJECT_ROOT / "release"

JSON_OUTPUTS = (
    RELEASE_DIR / "claim_evidence_traceability.json",
    RELEASE_DIR / "claims_evidence_matrix.json",
)
MARKDOWN_OUTPUTS = (
    RELEASE_DIR / "CLAIM_EVIDENCE_TRACEABILITY.md",
    RELEASE_DIR / "CLAIMS_EVIDENCE_MATRIX.md",
)


def _load_json(relative_path: str, default: Any) -> Any:
    path = PROJECT_ROOT / relative_path
    if not path.is_file():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def _generated_at() -> str:
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "1784332800"))
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


def _measurement_rows() -> list[dict[str, str]]:
    if not MEASUREMENT_MAP.is_file():
        return []
    with MEASUREMENT_MAP.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def _all_paths_exist(paths: list[str]) -> bool:
    return all((PROJECT_ROOT / path).is_file() for path in paths)


def _measurement_claim(
    *,
    claim_id: str,
    row_prefix: str,
    claim: str,
    scope: str,
    caveat: str,
) -> dict[str, Any]:
    rows = [row for row in _measurement_rows() if row["claim_id"].startswith(row_prefix)]
    evidence = sorted(
        {
            path.strip()
            for row in rows
            for path in row["evidence_artifacts"].split(",")
            if path.strip()
        }
    )
    # Paths in the measurement map are relative to measurement/sut/scripts.
    normalized = []
    for path in evidence:
        if path.startswith("figures/"):
            normalized.append(
                "measurement/sut/scripts/results/rendered_figures/"
                + Path(path).name
            )
        elif path.startswith("results/"):
            normalized.append(f"measurement/sut/scripts/{path}")
        else:
            normalized.append(path)
    supported = bool(rows) and _all_paths_exist(normalized)
    return {
        "claim_id": claim_id,
        "research_question": row_prefix.rstrip("-"),
        "claim": claim,
        "status": "supported" if supported else "blocked_missing_evidence",
        "scope": scope,
        "measured_value": f"{len(rows)} generated claim rows",
        "evidence_artifacts": normalized,
        "reproduction_command": "bash run_review_check.sh",
        "caveat": caveat,
    }


def _execution_record_is_complete(record: dict[str, Any]) -> bool:
    total = record.get("techniques_total")
    if not isinstance(total, int) or total <= 0:
        return False
    return (
        record.get("techniques_success") == total
        and record.get("evidence_backed_successful") == total
        and record.get("mode_status_consistent") is True
        and record.get("teardown_clean") is True
        and bool(record.get("manifest_sha256"))
        and bool(record.get("summary_sha256"))
        and bool(record.get("evidence_sha256"))
    )


def _rq4_claim() -> dict[str, Any]:
    proof = _load_json("release/subdetermination_proof.json", {}).get("proofs", {})
    expected_runs = {
        "0.cve_2021_41773": 3,
        "0.pivot_demo": 2,
        "0.web_demo": 2,
    }
    witness_status: dict[str, dict[str, Any]] = {}
    for campaign_id, expected_count in expected_runs.items():
        campaign = proof.get(campaign_id, {})
        records = campaign.get("execution_runs", [])
        witness_status[campaign_id] = {
            "variant_count": len(campaign.get("variants", [])),
            "execution_count": len(records),
            "expected_execution_count": expected_count,
            "executable": campaign.get("executable") is True,
            "records_complete": (
                len(records) == expected_count
                and all(_execution_record_is_complete(record) for record in records)
            ),
            "invariant_count": campaign.get("invariant_count"),
            "free_count": campaign.get("free_count"),
        }
    supported = bool(witness_status) and all(
        witness["executable"] and witness["records_complete"]
        for witness in witness_status.values()
    )
    return {
        "claim_id": "RQ4-CONSTRUCTIVE-01",
        "research_question": "RQ4",
        "claim": (
            "A declared campaign contract can admit more than one controlled SUT "
            "realization while preserving the checked technique sequence and oracle."
        ),
        "status": "supported_bounded" if supported else "blocked_execution_gate",
        "scope": (
            "Three engineering witnesses: a CVE mechanism, a two-hop SSH path, "
            "and an authenticated HTTP path."
        ),
        "measured_value": witness_status,
        "evidence_artifacts": ["release/subdetermination_proof.json"],
        "reproduction_command": "python3 scripts/build_subdetermination_artifact.py",
        "caveat": (
            "This is an existence result over controlled witnesses, not a population "
            "estimate, historical reconstruction result, or proof that arbitrary "
            "ATT&CK campaigns admit equivalent realizations."
        ),
    }


def _c0045_claim() -> dict[str, Any]:
    comparison = _load_json("release/experiments/arm_comparison/C0045.json", {})
    validity = _load_json("release/experiments/execution_validity.json", [])
    arms = {arm.get("arm_id"): arm for arm in comparison.get("arms", [])}
    shadowray = next(
        (
            row
            for row in validity
            if row.get("source_campaign_id") == "C0045"
            and row.get("campaign_id") == "0.shadowray"
        ),
        {},
    )
    arm_a = arms.get("A", {})
    arm_b = arms.get("B", {})
    arm_c = arms.get("C", {})
    supported = (
        comparison.get("primary_gate_passed") is True
        and comparison.get("plan_synthesis_gate_passed") is True
        and comparison.get("execution_evidence_gate_passed") is True
        and comparison.get("three_arm_execution_comparison_supported") is False
        and arm_a.get("executable_step_count") == 0
        and arm_a.get("execution_attempted") is False
        and arm_b.get("executable_step_count") == 1
        and arm_b.get("execution_attempted") is False
        and arm_c.get("executable_step_count") == 10
        and arm_c.get("execution_attempted") is True
        and arm_c.get("executed_with_evidence_count") == 10
        and arm_c.get("execution_fidelity_distribution")
        == {"adapted": 9, "inspired": 1}
        and arm_c.get("realization_distribution") == {"surrogate": 10}
        and shadowray.get("status_success") == 10
        and shadowray.get("evidence_backed_success") == 10
        and shadowray.get("contract_valid") is True
        and shadowray.get("teardown_clean") is True
        and comparison.get("execution_audit", {}).get(
            "fidelity_overclaim_count"
        ) == 0
    )
    measured_value = {
        "raw_stix_executable_steps": arm_a.get("executable_step_count"),
        "fixed_reference_sut_executable_steps": arm_b.get("executable_step_count"),
        "autosut_witness_executable_steps": arm_c.get("executable_step_count"),
        "autosut_witness_evidence_backed_steps": arm_c.get(
            "executed_with_evidence_count"
        ),
        "plan_fidelity_ceiling_distribution": arm_c.get(
            "plan_fidelity_ceiling_distribution",
            arm_c.get("fidelity_ceiling_distribution"),
        ),
        "execution_fidelity_distribution": arm_c.get(
            "execution_fidelity_distribution"
        ),
        "realization_distribution": arm_c.get("realization_distribution"),
        "assumption_count": arm_c.get("assumption_count"),
        "semantic_plan_hash_repeated": comparison.get(
            "semantically_identical_across_repetitions"
        ),
    }
    return {
        "claim_id": "C0045-CASE-01",
        "research_question": "C0045 case study",
        "claim": (
            "For the bounded ten-step C0045-derived laboratory case, the fixed "
            "resolver produced 0/10 admitted steps from raw STIX, 1/10 on the "
            "fixed reference SUT, and 10/10 on the synthesized witness. Only the "
            "witness arm was executed; it emitted evidence for all ten steps."
        ),
        "status": "supported_bounded" if supported else "blocked_execution_gate",
        "scope": (
            "One campaign-derived, controlled surrogate case under the released "
            "action catalog, verifier, evidence policy, and safety boundary."
        ),
        "measured_value": measured_value,
        "evidence_artifacts": [
            "release/experiments/arm_comparison/C0045.json",
            "release/experiments/execution_validity.json",
            "release/experiments/extension_effectiveness/C0045.json",
            "release/inputs/sticks/c0045-v1/manifest.json",
        ],
        "reproduction_command": "bash run_review_check.sh",
        "caveat": (
            "The result uses a surrogate, not a deployed historical Ray victim. "
            "Nine steps have an adapted ceiling and one is inspired. It does not "
            "constitute a three-arm execution comparison and does not establish "
            "historical equivalence, external validity across campaigns, or a "
            "reduction in analyst effort."
        ),
    }


def _blocked_claims() -> list[dict[str, str]]:
    return [
        {
            "claim": "faithful or historically equivalent campaign replay",
            "reason": "No ground-truth historical environment or trace equivalence study.",
        },
        {
            "claim": "automatic reconstruction for arbitrary ATT&CK campaigns",
            "reason": "The executable action catalog and evaluated campaign slice are bounded.",
        },
        {
            "claim": "measured analyst-effort reduction",
            "reason": "No controlled human-subject or time-on-task experiment.",
        },
        {
            "claim": "scalability or minimal-overhead result",
            "reason": "No scaling curve, resource study, or comparative overhead experiment.",
        },
        {
            "claim": "validated accuracy of CF/VMR/ID routing labels",
            "reason": "The released manual adjudication packet remains unlabeled.",
        },
    ]


def build_ledger() -> dict[str, Any]:
    claims = [
        _measurement_claim(
            claim_id="RQ1-MEASUREMENT",
            row_prefix="RQ1-",
            claim=(
                "The evaluated CTI snapshots provide broad platform labels but "
                "substantially less software, version, and campaign-linked CVE detail."
            ),
            scope="Pinned ATT&CK Enterprise, Mobile, ICS, CAPEC, and FiGHT snapshots.",
            caveat="Coverage is snapshot- and parser-dependent; it is not a timeless CTI property.",
        ),
        _measurement_claim(
            claim_id="RQ2-OPERATIONALIZATION",
            row_prefix="RQ2-",
            claim=(
                "Bounded enrichment and the declared routing policy expose "
                "operationalization headroom without turning fallback labels into ground truth."
            ),
            scope="Deterministic enrichment and CF/VMR/ID policy over the pinned snapshots.",
            caveat="Routing labels are policy outputs; the manual accuracy study is not complete.",
        ),
        _measurement_claim(
            claim_id="RQ3-SPECIFICITY",
            row_prefix="RQ3-",
            claim=(
                "Profile distinctiveness and its threshold sensitivity can be "
                "recomputed under the declared similarity and null models."
            ),
            scope="Campaign profiles derived from the pinned Enterprise snapshot.",
            caveat="Profile distinctiveness is not executable sufficiency or historical fidelity.",
        ),
        _rq4_claim(),
        _c0045_claim(),
    ]
    return {
        "schema_version": "2",
        "generated_at": _generated_at(),
        "status_vocabulary": {
            "supported": "all deterministic evidence files required by the claim are present",
            "supported_bounded": "the executable gate passes only for the stated witness scope",
            "blocked_missing_evidence": "a required deterministic output is absent",
            "blocked_execution_gate": "the required live-evidence gate does not pass",
        },
        "claims": claims,
        "blocked_interpretations": _blocked_claims(),
        "measurement_detail": _measurement_rows(),
    }


def _format_value(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _markdown(ledger: dict[str, Any]) -> str:
    lines = [
        "# Canonical Claim-to-Evidence Ledger",
        "",
        "This file is generated by `python3 scripts/generate_claim_evidence_ledger.py`.",
        "A `supported` label is bounded by the scope and caveat in the same row; it",
        "is not permission to restate the result as historical or universal.",
        "",
        "| Claim ID | Status | Claim | Scope | Measured value | Evidence | Caveat |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for claim in ledger["claims"]:
        evidence = "; ".join(f"`{path}`" for path in claim["evidence_artifacts"])
        value = _format_value(claim["measured_value"]).replace("|", "\\|")
        lines.append(
            f"| {claim['claim_id']} | `{claim['status']}` | {claim['claim']} | "
            f"{claim['scope']} | `{value}` | {evidence} | {claim['caveat']} |"
        )

    lines.extend(["", "## Claim Boundaries", ""])
    for blocked in ledger["blocked_interpretations"]:
        lines.append(f"- **Not claimed:** {blocked['claim']}. {blocked['reason']}")

    lines.extend(
        [
            "",
            "## Reproduction",
            "",
            "```bash",
            "bash run_review_check.sh",
            "```",
            "",
            "The machine-readable version is `release/claim_evidence_traceability.json`.",
            "The detailed RQ1--RQ3 rows remain in",
            "`measurement/sut/scripts/results/claim_evidence_map.csv`.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    ledger = build_ledger()
    RELEASE_DIR.mkdir(parents=True, exist_ok=True)
    json_text = json.dumps(ledger, indent=2, sort_keys=True) + "\n"
    markdown_text = _markdown(ledger)
    for path in JSON_OUTPUTS:
        path.write_text(json_text, encoding="utf-8")
    for path in MARKDOWN_OUTPUTS:
        path.write_text(markdown_text, encoding="utf-8")
    statuses = ", ".join(
        f"{claim['claim_id']}={claim['status']}" for claim in ledger["claims"]
    )
    print(f"[claim-ledger] {statuses}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
