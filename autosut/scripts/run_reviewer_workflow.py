#!/usr/bin/env python3
"""Execute the published AutoSUT reviewer workflow and record its verdict.

This is deliberately an evaluator, not a second source of truth.  It invokes
the same public gates a reviewer is asked to use and writes a schema-validated
report describing exactly what was attempted, what passed, what was blocked by
the host, and which claim records were inspected.  A blocked optional backend
is not silently converted into a pass.

``kick-the-tires`` performs only host-safe checks.  ``full-reproduction`` also
executes the published claim gate.  Live Docker/VM replays remain explicit
follow-on protocols because their availability is host-dependent.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from infrastructure.preflight import PreflightReport, run_preflight  # noqa: E402


class StepStatus(str, Enum):
    """Terminal status of one independently observable reviewer step."""

    PASSED = "passed"
    FAILED = "failed"
    BLOCKED = "blocked"
    SKIPPED = "skipped"


class ReviewStep(BaseModel):
    """A command or inspection executed by the reviewer workflow."""

    model_config = ConfigDict(extra="forbid")

    name: str
    status: StepStatus
    command: list[str] = Field(default_factory=list)
    duration_seconds: float = 0.0
    detail: str = ""


class ClaimInspection(BaseModel):
    """The public claim boundary inspected before the execution gates run."""

    model_config = ConfigDict(extra="forbid")

    claim_id: str
    status: str
    evidence_artifacts: list[str]
    reproduction_command: str


class ReviewerReport(BaseModel):
    """Machine-readable report for an AEC-style review pass."""

    model_config = ConfigDict(extra="forbid")

    schema_version: int = 1
    generated_at: str
    mode: str
    artifact_root: str
    preflight: PreflightReport
    claims: list[ClaimInspection]
    steps: list[ReviewStep]
    final_result: StepStatus
    failed_requirements: list[str]
    blocked_requirements: list[str]
    manual_interventions: list[str]


_REQUIRED_DOCS = ("README.md", "REVIEWER_GUIDE.md", "REPRODUCIBILITY.md")
_REQUIRED_CLAIMS = {
    "RQ1-MEASUREMENT",
    "RQ2-OPERATIONALIZATION",
    "RQ3-SPECIFICITY",
    "CALDERA-DISPATCH-01",
    "RQ4-CONSTRUCTIVE-01",
    "C0045-CASE-01",
}


def _run(name: str, command: list[str], *, timeout_seconds: int = 3600) -> ReviewStep:
    """Run one public command and preserve a compact, useful outcome."""
    started = time.monotonic()
    try:
        completed = subprocess.run(
            command,
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        return ReviewStep(
            name=name,
            status=StepStatus.FAILED,
            command=command,
            duration_seconds=round(time.monotonic() - started, 3),
            detail=f"timed out after {exc.timeout} seconds",
        )

    output = (completed.stdout + completed.stderr).strip()
    return ReviewStep(
        name=name,
        status=StepStatus.PASSED if completed.returncode == 0 else StepStatus.FAILED,
        command=command,
        duration_seconds=round(time.monotonic() - started, 3),
        detail=output[-4000:],
    )


def _inspect_docs() -> ReviewStep:
    """Require the three documents needed for an external reviewer to start."""
    missing = [name for name in _REQUIRED_DOCS if not (PROJECT_ROOT / name).is_file()]
    return ReviewStep(
        name="reviewer-documentation",
        status=StepStatus.PASSED if not missing else StepStatus.FAILED,
        detail="all required reviewer documents are present" if not missing else ", ".join(missing),
    )


def _inspect_claims() -> tuple[ReviewStep, list[ClaimInspection]]:
    """Check that the public ledger names evidence and a reproduction command."""
    ledger_path = PROJECT_ROOT / "release" / "claim_evidence_traceability.json"
    if not ledger_path.is_file():
        return (
            ReviewStep(
                name="claim-evidence-ledger",
                status=StepStatus.FAILED,
                detail=f"missing {ledger_path.relative_to(PROJECT_ROOT)}",
            ),
            [],
        )
    try:
        payload = json.loads(ledger_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return (
            ReviewStep(name="claim-evidence-ledger", status=StepStatus.FAILED, detail=str(exc)),
            [],
        )

    records = {entry.get("claim_id"): entry for entry in payload.get("claims", [])}
    missing = sorted(_REQUIRED_CLAIMS - set(records))
    unsupported = sorted(
        claim_id
        for claim_id in _REQUIRED_CLAIMS & set(records)
        if not str(records[claim_id].get("status", "")).startswith("supported")
    )
    incomplete = sorted(
        claim_id
        for claim_id in _REQUIRED_CLAIMS & set(records)
        if not records[claim_id].get("evidence_artifacts")
        or not records[claim_id].get("reproduction_command")
    )
    detail_parts = []
    if missing:
        detail_parts.append(f"missing: {', '.join(missing)}")
    if unsupported:
        detail_parts.append(f"not supported: {', '.join(unsupported)}")
    if incomplete:
        detail_parts.append(f"incomplete: {', '.join(incomplete)}")
    inspections = [
        ClaimInspection(
            claim_id=claim_id,
            status=str(records[claim_id]["status"]),
            evidence_artifacts=list(records[claim_id]["evidence_artifacts"]),
            reproduction_command=str(records[claim_id]["reproduction_command"]),
        )
        for claim_id in sorted(_REQUIRED_CLAIMS & set(records))
    ]
    return (
        ReviewStep(
            name="claim-evidence-ledger",
            status=StepStatus.PASSED if not detail_parts else StepStatus.FAILED,
            detail=(
                "all required claims are evidence-bound"
                if not detail_parts
                else "; ".join(detail_parts)
            ),
        ),
        inspections,
    )


def _preflight_step(report: PreflightReport) -> ReviewStep:
    """Record optional-backend limits without confusing them with a failed core gate.

    The released artifact's host-only claim gate does not require Docker, QEMU,
    or native Windows. Docker is required only by the separately documented
    live replay, and native Windows is outside the released Linux-only scope.
    The report preserves those limits while allowing a reviewer to distinguish
    an unavailable optional backend from a failed reproducibility contract.
    """
    blocked = [backend.backend for backend in report.backends if backend.status.value == "blocked"]
    return ReviewStep(
        name="host-preflight",
        status=StepStatus.PASSED,
        detail=(
            "host-only claim gate requires no live backend; unavailable optional backends: "
            + ", ".join(blocked)
            if blocked
            else "all declared backends are available for qualification"
        ),
    )


def _final_status(steps: list[ReviewStep]) -> StepStatus:
    if any(step.status is StepStatus.FAILED for step in steps):
        return StepStatus.FAILED
    if any(step.status is StepStatus.BLOCKED for step in steps):
        return StepStatus.BLOCKED
    return StepStatus.PASSED


def run_workflow(mode: str) -> ReviewerReport:
    """Execute one of the two documented reviewer personas."""
    preflight = run_preflight()
    claim_step, claims = _inspect_claims()
    steps = [_inspect_docs(), _preflight_step(preflight), claim_step]
    steps.append(
        _run(
            "public-surface",
            [sys.executable, "scripts/check_public_surface.py"],
            timeout_seconds=120,
        )
    )

    if mode == "full-reproduction":
        steps.append(
            _run(
                "claim-reproduction",
                ["bash", "run_review_check.sh"],
                timeout_seconds=7200,
            )
        )
    else:
        steps.append(
            ReviewStep(
                name="claim-reproduction",
                status=StepStatus.SKIPPED,
                detail="kick-the-tires stops before the long claim-reproduction gate",
            )
        )

    failed = [step.name for step in steps if step.status is StepStatus.FAILED]
    blocked = [step.name for step in steps if step.status is StepStatus.BLOCKED]
    return ReviewerReport(
        generated_at=datetime.now(timezone.utc).isoformat(),
        mode=mode,
        artifact_root=str(PROJECT_ROOT),
        preflight=preflight,
        claims=claims,
        steps=steps,
        final_result=_final_status(steps),
        failed_requirements=failed,
        blocked_requirements=blocked,
        manual_interventions=[],
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--mode",
        choices=("kick-the-tires", "full-reproduction"),
        default="kick-the-tires",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=PROJECT_ROOT
        / "results"
        / "reviewer_runtime"
        / "review-report.json",
    )
    args = parser.parse_args(argv)

    report = run_workflow(args.mode)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report.model_dump_json(indent=2) + "\n", encoding="utf-8")
    print(f"[reviewer-workflow] {report.final_result.value}: {args.output}")
    for step in report.steps:
        print(f"[reviewer-workflow] {step.status.value}: {step.name}")
    return 0 if report.final_result is StepStatus.PASSED else 1


if __name__ == "__main__":
    raise SystemExit(main())
