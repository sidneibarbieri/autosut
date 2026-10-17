#!/usr/bin/env python3
"""Build the canonical claim-to-evidence ledger for the public artifact.

The measurement pipeline retains historical row identifiers. This script maps
its claim groups and bounded witnesses to stable evidence dimensions, while
making unsupported interpretations explicit.  It never upgrades a claim from
the existence of a file alone: each system claim has a small, executable gate
over the recorded evidence.
"""

from __future__ import annotations

import csv
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MEASUREMENT_MAP = (
    PROJECT_ROOT / "measurement" / "sut" / "scripts" / "results" / "claim_evidence_map.csv"
)
RELEASE_DIR = PROJECT_ROOT / "release"
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from evaluation.canonical_operational_witness import (  # noqa: E402
    assess_caldera_dispatch_witness,
)

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
    evidence_dimension: str,
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
            normalized.append("measurement/sut/scripts/results/rendered_figures/" + Path(path).name)
        elif path.startswith("results/"):
            normalized.append(f"measurement/sut/scripts/{path}")
        else:
            normalized.append(path)
    supported = bool(rows) and _all_paths_exist(normalized)
    return {
        "claim_id": claim_id,
        "evidence_dimension": evidence_dimension,
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


def _caldera_dispatch_claim() -> dict[str, Any]:
    """Report only the static, public, hash-bound dispatch witness."""
    assessment = assess_caldera_dispatch_witness(PROJECT_ROOT)
    witness = assessment.witness
    return {
        "claim_id": "CALDERA-DISPATCH-01",
        "evidence_dimension": "caldera_dispatch",
        "claim": (
            "One frozen, isolated witness records a Caldera-dispatched ability whose effect "
            "was independently confirmed on an automatically materialized surrogate SUT."
        ),
        "status": assessment.status,
        "scope": (
            "One serial, one-seed C0045-derived T1190 surrogate cell in the released "
            "operational collection, with a fresh control plane for the cell."
        ),
        "measured_value": (
            {
                "collection": witness.collection_relative_path,
                "implementation_revision": witness.implementation_revision,
                "campaign_id": witness.campaign_id,
                "source_campaign_id": witness.source_campaign_id,
                "operation_link_count": witness.operation_link_count,
                "realization": witness.realization,
            }
            if witness is not None
            else {"validation_failure": assessment.failure_reason}
        ),
        "evidence_artifacts": list(assessment.evidence_artifacts),
        "reproduction_command": "bash run_review_check.sh",
        "caveat": (
            "The static audit verifies a sealed recorded observation, not a live rerun. It is "
            "one ability on one surrogate host and does not establish complete C0045 execution, "
            "campaign-wide reliability, historical equivalence, or a reduction in human effort."
        ),
    }


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
        witness["executable"] and witness["records_complete"] for witness in witness_status.values()
    )
    return {
        "claim_id": "RQ4-CONSTRUCTIVE-01",
        "evidence_dimension": "environment_non_identification",
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


def _sut_configuration_claim() -> dict[str, Any]:
    """How much of a deployable configuration the measured constraints support."""
    corpus = _load_json("release/experiments/sut_configuration/corpus.json", {})
    if not corpus:
        return {
            "claim_id": "RQ2-CONFIGURATION-01",
            "evidence_dimension": "sut_configuration",
            "claim": "Measured constraints do not determine a deployable SUT configuration.",
            "status": "blocked_missing_evidence",
            "scope": "Requires release/experiments/sut_configuration/corpus.json.",
            "measured_value": {},
            "evidence_artifacts": ["release/experiments/sut_configuration/corpus.json"],
            "reproduction_command": "python3 scripts/build_sut_configuration_evidence.py",
            "caveat": "Evidence record absent; the claim carries no support.",
        }
    return {
        "claim_id": "RQ2-CONFIGURATION-01",
        "evidence_dimension": "sut_configuration",
        "claim": (
            "Baseline B0, platform-only input: when a proposer receives only the platform "
            "constraints, it satisfies them yet supplies most of a deployable configuration "
            "itself and selects products unrelated to the campaign."
        ),
        "status": "supported_baseline",
        "scope": (
            f"{corpus['proposals']} candidate configurations for {corpus['campaigns']} "
            "campaigns from two local model families sampled three times each."
        ),
        "measured_value": {
            "value_occurrences": corpus["total_value_occurrences"],
            "cti_evidenced_rate": corpus["cti_evidenced_rate"],
            "proposer_introduced_rate": corpus["proposer_introduced_rate"],
            "satisfying_all_platform_requirements": corpus[
                "proposals_satisfying_all_platform_requirements"
            ],
            "distinct_service_stacks_per_campaign": corpus["distinct_service_stacks_per_campaign"],
        },
        "evidence_artifacts": ["release/experiments/sut_configuration/corpus.json"],
        "reproduction_command": "python3 scripts/build_sut_configuration_evidence.py",
        "caveat": (
            "This arm withholds evidence the artifact already resolves: for ShadowRay, "
            "release/cve_resolution_candidates.json binds CVE-2023-48022 to the pip package "
            "ray with explicit candidate versions. The result therefore measures what a "
            "proposer does without consolidated evidence, and must not be read as a limit of "
            "structured CTI. Provenance is assigned by comparison against the evaluated "
            "fields; satisfaction is reported only for platform requirements."
        ),
    }


def _nvd_enrichment_claim() -> dict[str, Any]:
    """What joining NVD adds to the deployment dimensions structured CTI fixes."""
    path = "measurement/sut/scripts/results/nvd_enrichment.json"
    report = _load_json(path, {})
    if not report:
        return {
            "claim_id": "RQ1-NVD-ENRICHMENT-01",
            "evidence_dimension": "vulnerability_enrichment",
            "claim": "Joining NVD narrows but does not identify a CVE's deployment.",
            "status": "blocked_missing_evidence",
            "scope": f"Requires {path}.",
            "measured_value": {},
            "evidence_artifacts": [path],
            "reproduction_command": "python3 measurement/sut/scripts/nvd_enrichment.py",
            "caveat": "Evidence record absent; the claim carries no support.",
        }
    counts = {row["dimension"]: row for row in report["dimensions"]}
    return {
        "claim_id": "RQ1-NVD-ENRICHMENT-01",
        "evidence_dimension": "vulnerability_enrichment",
        "claim": (
            "Joining the pinned NVD record names the vulnerable product, version bounds, "
            "exposure, and exploit privilege that structured CTI leaves open, but leaves no "
            "CVE with a unique deployment and no topology or trust boundary."
        ),
        "status": "supported",
        "scope": f"All {report['cves']} CVEs the measurement extracts from Enterprise CTI.",
        "measured_value": {
            dimension: {"structured_cti": row["structured_cti"], "cti_plus_nvd": row["cti_plus_nvd"]}
            for dimension, row in counts.items()
        } | {"unique_deployment_after_nvd": report["unique_deployment_after_nvd"]},
        "evidence_artifacts": [path, "measurement/sut/scripts/data/nvd_snapshot_manifest.json"],
        "reproduction_command": "python3 measurement/sut/scripts/nvd_enrichment.py",
        "caveat": (
            "NVD describes vulnerable configurations, not deployments, and its records change; "
            "the snapshot is pinned with retrieval times. Topology is unresolved by schema in "
            "both sources."
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
            if row.get("source_campaign_id") == "C0045" and row.get("campaign_id") == "0.shadowray"
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
        and arm_c.get("execution_fidelity_distribution") == {"adapted": 9, "inspired": 1}
        and arm_c.get("realization_distribution") == {"surrogate": 10}
        and shadowray.get("status_success") == 10
        and shadowray.get("evidence_backed_success") == 10
        and shadowray.get("contract_valid") is True
        and shadowray.get("teardown_clean") is True
        and comparison.get("execution_audit", {}).get("fidelity_overclaim_count") == 0
    )
    measured_value = {
        "raw_stix_executable_steps": arm_a.get("executable_step_count"),
        "fixed_reference_sut_executable_steps": arm_b.get("executable_step_count"),
        "autosut_witness_executable_steps": arm_c.get("executable_step_count"),
        "autosut_witness_evidence_backed_steps": arm_c.get("executed_with_evidence_count"),
        "plan_fidelity_ceiling_distribution": arm_c.get(
            "plan_fidelity_ceiling_distribution",
            arm_c.get("fidelity_ceiling_distribution"),
        ),
        "execution_fidelity_distribution": arm_c.get("execution_fidelity_distribution"),
        "realization_distribution": arm_c.get("realization_distribution"),
        "assumption_count": arm_c.get("assumption_count"),
        "semantic_plan_hash_repeated": comparison.get("semantically_identical_across_repetitions"),
    }
    return {
        "claim_id": "C0045-CASE-01",
        "evidence_dimension": "controlled_sut_contrast",
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
            evidence_dimension="cti_environment_evidence",
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
            evidence_dimension="compatibility_policy",
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
            evidence_dimension="profile_distinctiveness",
            claim=(
                "Profile distinctiveness and its threshold sensitivity can be "
                "recomputed under the declared similarity and null models."
            ),
            scope="Campaign profiles derived from the pinned Enterprise snapshot.",
            caveat="Profile distinctiveness is not executable sufficiency or historical fidelity.",
        ),
        _sut_configuration_claim(),
        _nvd_enrichment_claim(),
        _caldera_dispatch_claim(),
        _rq4_claim(),
        _c0045_claim(),
    ]
    return {
        "schema_version": "3",
        "generated_at": _generated_at(),
        "status_vocabulary": {
            "supported": "all deterministic evidence files required by the claim are present",
            "supported_baseline": "a declared baseline is reproducible within its stated scope",
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
            "Claim identifiers and measurement-row prefixes are stable historical keys,",
            "not manuscript question numbers. The `evidence_dimension` field groups",
            "results by scientific subject independently of manuscript organization.",
            "Engineering witnesses support only their stated scope; they do not",
            "replace controlled consequence experiments.",
            "",
            "The detailed historical rows remain in",
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
    statuses = ", ".join(f"{claim['claim_id']}={claim['status']}" for claim in ledger["claims"])
    print(f"[claim-ledger] {statuses}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
