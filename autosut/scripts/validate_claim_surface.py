#!/usr/bin/env python3
"""Validate the canonical public claim ledger and dashboard surface."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from pydantic import AliasChoices, BaseModel, ConfigDict, Field


class ClaimRecord(BaseModel):
    """One evidence-bound public research claim."""

    model_config = ConfigDict(extra="forbid")

    claim_id: str = Field(min_length=1)
    evidence_dimension: str = Field(
        min_length=1,
        validation_alias=AliasChoices("evidence_dimension", "research_question"),
    )
    claim: str = Field(min_length=1)
    status: str = Field(min_length=1)
    scope: str = Field(min_length=1)
    measured_value: Any
    evidence_artifacts: list[str] = Field(min_length=1)
    reproduction_command: str = Field(min_length=1)
    caveat: str = Field(min_length=1)


class BlockedInterpretation(BaseModel):
    """An interpretation deliberately excluded by the released evidence."""

    model_config = ConfigDict(extra="forbid")

    claim: str = Field(min_length=1)
    reason: str = Field(min_length=1)


class ClaimLedger(BaseModel):
    """The only current public claim surface."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = Field(min_length=1)
    generated_at: str = Field(min_length=1)
    measurement_detail: list[dict[str, Any]] = Field(min_length=1)
    status_vocabulary: dict[str, str] = Field(min_length=1)
    claims: list[ClaimRecord] = Field(min_length=1)
    blocked_interpretations: list[BlockedInterpretation] = Field(min_length=1)


REQUIRED_CLAIMS = frozenset(
    {
        "RQ1-MEASUREMENT",
        "RQ2-OPERATIONALIZATION",
        "RQ3-SPECIFICITY",
        "CALDERA-DISPATCH-01",
        "RQ4-CONSTRUCTIVE-01",
        "C0045-CASE-01",
    }
)
LEGACY_DASHBOARD_MARKERS = (
    "golden_runs.json",
    "canonical_runs.json",
    "data/evidence/",
    "Audited Complete Runs",
)


def _safe_path(root: Path, relative: str) -> Path:
    path = Path(relative)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"claim evidence path is unsafe: {relative}")
    candidate = (root / path).resolve()
    if not candidate.is_relative_to(root.resolve()):
        raise ValueError(f"claim evidence path escapes the artifact root: {relative}")
    if not candidate.is_file():
        raise FileNotFoundError(f"claim evidence path is missing: {relative}")
    return candidate


def _dashboard_href(relative: str) -> str:
    path = Path(relative)
    if path.parts[0] == "release":
        return (Path("..") / Path(*path.parts[1:])).as_posix()
    return (Path("..") / ".." / path).as_posix()


def _read_ledger(root: Path) -> ClaimLedger:
    ledger_path = root / "release" / "claim_evidence_traceability.json"
    markdown_path = root / "release" / "CLAIM_EVIDENCE_TRACEABILITY.md"
    payload = json.loads(ledger_path.read_text(encoding="utf-8"))
    ledger = ClaimLedger.model_validate(payload)
    json_alias = root / "release" / "claims_evidence_matrix.json"
    markdown_alias = root / "release" / "CLAIMS_EVIDENCE_MATRIX.md"
    if json_alias.read_bytes() != ledger_path.read_bytes():
        raise ValueError("claims_evidence_matrix.json differs from the canonical ledger")
    if markdown_alias.read_bytes() != markdown_path.read_bytes():
        raise ValueError("CLAIMS_EVIDENCE_MATRIX.md differs from the canonical ledger")
    return ledger


def _validate_claims(root: Path, ledger: ClaimLedger) -> None:
    claim_ids = [claim.claim_id for claim in ledger.claims]
    if len(set(claim_ids)) != len(claim_ids):
        raise ValueError("canonical claim ledger contains duplicate claim identifiers")
    missing = sorted(REQUIRED_CLAIMS - set(claim_ids))
    if missing:
        raise ValueError("canonical claim ledger lacks required claims: " + ", ".join(missing))
    unknown_statuses = {
        claim.status
        for claim in ledger.claims
        if claim.status not in ledger.status_vocabulary
    }
    if unknown_statuses:
        raise ValueError(
            "canonical claim ledger uses undeclared statuses: "
            + ", ".join(sorted(unknown_statuses))
        )
    unsupported = [
        claim.claim_id
        for claim in ledger.claims
        if claim.claim_id in REQUIRED_CLAIMS and not claim.status.startswith("supported")
    ]
    if unsupported:
        raise ValueError("required claims are unsupported: " + ", ".join(sorted(unsupported)))
    for claim in ledger.claims:
        for evidence_path in claim.evidence_artifacts:
            _safe_path(root, evidence_path)


def _validate_dashboard(root: Path, ledger: ClaimLedger) -> None:
    dashboard_path = root / "release" / "dashboard" / "index.html"
    dashboard = dashboard_path.read_text(encoding="utf-8")
    legacy_markers = [
        marker for marker in LEGACY_DASHBOARD_MARKERS if marker in dashboard
    ]
    if legacy_markers:
        raise ValueError(
            "dashboard contains legacy claim-surface markers: "
            + ", ".join(legacy_markers)
        )
    for claim in ledger.claims:
        if claim.claim_id not in dashboard:
            raise ValueError(f"dashboard omits canonical claim: {claim.claim_id}")
        for evidence_path in claim.evidence_artifacts:
            href = _dashboard_href(evidence_path)
            if f"href='{href}'" not in dashboard:
                raise ValueError(
                    f"dashboard omits canonical evidence link for {claim.claim_id}: {evidence_path}"
                )


def validate(root: Path) -> ClaimLedger:
    """Fail if the rendered public surface diverges from the canonical ledger."""
    artifact_root = root.resolve()
    ledger = _read_ledger(artifact_root)
    _validate_claims(artifact_root, ledger)
    _validate_dashboard(artifact_root, ledger)
    return ledger


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    ledger = validate(args.root)
    print(f"[claim-surface] PASS: {len(ledger.claims)} canonical claims are evidence-bound")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
