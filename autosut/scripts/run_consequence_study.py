#!/usr/bin/env python3
"""Run the pre-registered environment-consequence study for one campaign.

Two SUT arms satisfy the same CTI-derived constraints and differ only in the
free dimension the CTI leaves open: whether the service's job-submission API
accepts an unauthenticated request. Each arm runs the same campaign chain in
the disposable, networkless laboratory. The outcome vectors defined in
PRE_REGISTRATION.md are recorded per arm, and the primary comparison is the
executed-with-evidence step delta between the arms.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
sys.dont_write_bytecode = True

PROJECT_ROOT = Path(__file__).resolve().parents[1]
for root in (PROJECT_ROOT / "src", PROJECT_ROOT / "scripts"):
    sys.path.insert(0, str(root))

from pydantic import BaseModel, ConfigDict, Field  # noqa: E402

from planning.blueprint_materialization import sut_profile_from_blueprint  # noqa: E402
from planning.campaign_pair import PairPreparation  # noqa: E402
from planning.replay_network import ReplayNetwork  # noqa: E402
from planning.sut_blueprint import SUTBlueprint  # noqa: E402
from orchestrator.models import (  # noqa: E402
    CVEInjection,
    FidelityLevel,
    ProvenanceSource,
    Realization,
    RunResult,
)
from orchestrator.orchestrator import CampaignOrchestrator  # noqa: E402

CONSEQUENCE_ROOT = PROJECT_ROOT / "release" / "experiments" / "consequence_study"
VULNERABILITY_DEPENDENT_STEP = "T1190"


class ConsequenceRunRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    pair: Path
    run_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]*$", max_length=128)
    repetitions: int = Field(gt=0)


def create_run_directory(request: ConsequenceRunRequest) -> Path:
    runs_root = CONSEQUENCE_ROOT / "runs"
    if runs_root.is_symlink():
        raise ValueError("the runs directory must not be a symlink")
    run_root = runs_root / request.run_id
    run_root.mkdir(parents=True)
    return run_root


def _reachable_injection() -> CVEInjection:
    return CVEInjection(
        cve_id="CVE-2023-48022",
        target_software="ray (surrogate)",
        target_version="surrogate-1.0",
        fidelity=FidelityLevel.adapted,
        realization=Realization.surrogate,
        install_recipe="ray_dashboard_surrogate",
        source=ProvenanceSource.external_reference,
        reason="Arm RAY-REACHABLE: the job-submission API accepts an "
               "unauthenticated request, as the advisory describes.",
    )


def _guarded_injection() -> CVEInjection:
    return CVEInjection(
        cve_id="CVE-2023-48022",
        target_software="ray (guarded surrogate)",
        target_version="surrogate-guarded-1.0",
        fidelity=FidelityLevel.adapted,
        realization=Realization.surrogate,
        install_recipe="ray_dashboard_guarded",
        source=ProvenanceSource.external_reference,
        reason="Arm RAY-GUARDED: the job-submission API requires a token, an "
               "equally CTI-consistent choice because the CTI names no software.",
    )


ARMS = {
    "ray_reachable": _reachable_injection,
    "ray_guarded": _guarded_injection,
}


class StepOutcome(BaseModel):
    model_config = ConfigDict(frozen=True)

    step_index: int
    technique_id: str
    executed_with_evidence: bool
    status: str


class ArmOutcome(BaseModel):
    model_config = ConfigDict(frozen=True)

    arm: str
    repetition: int
    environment_build_success: bool
    procedure_started: bool
    executed_with_evidence_count: int
    total_steps: int
    procedure_completed: bool
    failure_step_index: int | None
    failure_technique_id: str | None
    teardown_clean: bool
    steps: list[StepOutcome]
    execution_semantic_sha256: str


def _execution_semantic_hash(result: RunResult) -> str:
    semantic = [
        {"technique_id": outcome.technique_id, "status": outcome.status}
        for outcome in result.techniques
    ]
    payload = json.dumps(semantic, sort_keys=True).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def summarize_arm(arm: str, repetition: int, result: RunResult) -> ArmOutcome:
    steps = [
        StepOutcome(
            step_index=index,
            technique_id=outcome.technique_id,
            executed_with_evidence=outcome.status == "success" and bool(outcome.evidence_files),
            status=outcome.status,
        )
        for index, outcome in enumerate(result.techniques)
    ]
    first_failure = next((step for step in steps if not step.executed_with_evidence), None)
    executed = sum(step.executed_with_evidence for step in steps)
    return ArmOutcome(
        arm=arm,
        repetition=repetition,
        environment_build_success=bool(result.techniques),
        procedure_started=bool(steps) and steps[0].status != "skipped",
        executed_with_evidence_count=executed,
        total_steps=len(steps),
        procedure_completed=bool(steps) and executed == len(steps),
        failure_step_index=first_failure.step_index if first_failure else None,
        failure_technique_id=first_failure.technique_id if first_failure else None,
        teardown_clean=result.teardown_clean,
        steps=steps,
        execution_semantic_sha256=_execution_semantic_hash(result),
    )


def run_arm(pair_dir: Path, arm: str, repetition: int, run_root: Path) -> ArmOutcome:
    pair = PairPreparation.model_validate_json((pair_dir / "pair.json").read_text())
    blueprint = SUTBlueprint.model_validate_json((pair_dir / "sut-blueprint.json").read_text())
    profile = sut_profile_from_blueprint(blueprint)
    if profile.backend != "docker" or profile.is_multi_host:
        raise ValueError("the consequence study requires a single Docker target")
    run_dir = run_root / f"{arm}-rep{repetition}"
    if run_dir.exists():
        raise ValueError(f"run directory already exists: {run_dir}")
    run_dir.mkdir(parents=True)

    with ReplayNetwork() as network:
        def isolate_only(target, attacker, evidence_dir, realization):
            # Both arms are surrogates, so the real-Ray rebind never applies;
            # this only isolates the target from the host gateway.
            return network.isolate(target, attacker, evidence_dir)

        result = CampaignOrchestrator().run_campaign(
            pair.campaign_id,
            fidelity_preference="surrogate",
            sut_override=profile,
            run_dir=run_dir,
            before_execution=isolate_only,
            cve_override=[ARMS[arm]()],
        )
    outcome = summarize_arm(arm, repetition, result)
    (run_dir / "arm-outcome.json").write_text(outcome.model_dump_json(indent=2) + "\n")
    return outcome


def primary_comparison(reachable: list[ArmOutcome], guarded: list[ArmOutcome]) -> dict:
    reachable_steps = reachable[0].executed_with_evidence_count
    guarded_steps = guarded[0].executed_with_evidence_count
    return {
        "experimental_unit": "C0045",
        "reachable_executed_steps": reachable_steps,
        "guarded_executed_steps": guarded_steps,
        "executed_step_delta": reachable_steps - guarded_steps,
        "guarded_failure_technique_id": guarded[0].failure_technique_id,
        "guarded_stops_at_vulnerability_dependent_step": (
            guarded[0].failure_technique_id == VULNERABILITY_DEPENDENT_STEP
        ),
        "reachable_repetitions_agree": len({arm.execution_semantic_sha256 for arm in reachable}) == 1,
        "guarded_repetitions_agree": len({arm.execution_semantic_sha256 for arm in guarded}) == 1,
        "consequence_observed": reachable_steps != guarded_steps,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pair", type=Path, default=PROJECT_ROOT / "release" / "prepared-pairs" / "0.shadowray")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--repetitions", type=int, default=2)
    args = parser.parse_args()

    request = ConsequenceRunRequest(pair=args.pair, run_id=args.run_id, repetitions=args.repetitions)
    run_root = create_run_directory(request)

    outcomes = {arm: [] for arm in ARMS}
    for repetition in range(1, request.repetitions + 1):
        for arm in ARMS:
            outcome = run_arm(request.pair.resolve(), arm, repetition, run_root)
            outcomes[arm].append(outcome)
            print(f"[{arm} rep{repetition}] executed {outcome.executed_with_evidence_count}"
                  f"/{outcome.total_steps}, stops at {outcome.failure_technique_id}")

    comparison = primary_comparison(outcomes["ray_reachable"], outcomes["ray_guarded"])
    (run_root / "comparison.json").write_text(json.dumps(comparison, indent=2, sort_keys=True) + "\n")
    print(json.dumps(comparison, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
