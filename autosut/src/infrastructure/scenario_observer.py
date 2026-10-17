"""Collect command-backed observations used by pre-execution scenario admission."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from planning.binding_catalog import BindingCatalog
from planning.executable_contract import ExecutableCampaignContract
from planning.scenario_admission import (
    ObservationEvidence,
    ObservedBinding,
    ScenarioObservation,
)


class ProbeSpec(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    subject_id: str = Field(min_length=1)
    argv: tuple[str, ...] = Field(min_length=1)
    timeout_seconds: int = Field(default=15, ge=1, le=120)
    expected_stdout: str | None = None


class ProbeResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    subject_id: str
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    expected_stdout: str | None = None

    @property
    def observed(self) -> bool:
        return self.returncode == 0 and (
            self.expected_stdout is None or self.stdout.strip() == self.expected_stdout
        )


def run_probe(probe: ProbeSpec) -> ProbeResult:
    completed = subprocess.run(
        list(probe.argv),
        capture_output=True,
        text=True,
        check=False,
        timeout=probe.timeout_seconds,
    )
    return ProbeResult(
        subject_id=probe.subject_id,
        argv=probe.argv,
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
        expected_stdout=probe.expected_stdout,
    )


def collect_scenario_observation(
    *,
    contract: ExecutableCampaignContract,
    catalog: BindingCatalog,
    run_id: str,
    binding_probes: tuple[ProbeSpec, ...],
    fact_probes: tuple[ProbeSpec, ...],
    goal_absence_probes: tuple[ProbeSpec, ...],
    evidence_root: Path,
    report_path: Path = Path("scenario/probes.json"),
) -> ScenarioObservation:
    """Execute probes and return an observation bound to their persisted output."""

    if report_path.is_absolute() or ".." in report_path.parts:
        raise ValueError("probe report path must stay within its evidence root")
    resolved_root = evidence_root.resolve()
    target = (resolved_root / report_path).resolve()
    if not target.is_relative_to(resolved_root):
        raise ValueError("probe report path must stay within its evidence root")
    if target.exists():
        raise FileExistsError("refusing to overwrite an existing probe report")
    binding_ids = {binding.binding_id for binding in catalog.bindings}
    required_binding_ids = {
        binding_id
        for transition in contract.transitions
        for binding_id in transition.bindings.values()
    }
    observed_binding_ids = [probe.subject_id for probe in binding_probes]
    if len(set(observed_binding_ids)) != len(observed_binding_ids):
        raise ValueError("duplicate binding probe")
    if set(observed_binding_ids) != required_binding_ids:
        raise ValueError("binding probes must exactly cover the executable slice")
    if not required_binding_ids.issubset(binding_ids):
        raise ValueError("contract references an undeclared binding")

    fact_ids = [probe.subject_id for probe in fact_probes]
    if len(set(fact_ids)) != len(fact_ids):
        raise ValueError("duplicate fact probe")
    if set(fact_ids) != set(contract.initial_facts):
        raise ValueError("fact probes must exactly cover initial facts")

    goal_ids = [probe.subject_id for probe in goal_absence_probes]
    if len(set(goal_ids)) != len(goal_ids):
        raise ValueError("duplicate goal-absence probe")
    if set(goal_ids) != set(catalog.goal_facts):
        raise ValueError("goal-absence probes must exactly cover campaign goals")

    binding_results = tuple(run_probe(probe) for probe in binding_probes)
    fact_results = tuple(run_probe(probe) for probe in fact_probes)
    goal_absence_results = tuple(run_probe(probe) for probe in goal_absence_probes)
    report = {
        "schema_version": "autosut-scenario-probes/v1",
        "run_id": run_id,
        "contract_sha256": contract.content_sha256,
        "binding_results": [result.model_dump(mode="json") for result in binding_results],
        "fact_results": [result.model_dump(mode="json") for result in fact_results],
        "goal_absence_results": [result.model_dump(mode="json") for result in goal_absence_results],
    }
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("x", encoding="utf-8") as report_file:
        report_file.write(json.dumps(report, indent=2) + "\n")
    report_sha256 = hashlib.sha256(target.read_bytes()).hexdigest()

    declared = {binding.binding_id: binding for binding in catalog.bindings}
    return ScenarioObservation(
        run_id=run_id,
        contract_sha256=contract.content_sha256,
        bindings=tuple(
            ObservedBinding(
                binding_id=result.subject_id,
                kind=declared[result.subject_id].kind,
                value=declared[result.subject_id].value,
                present=result.observed,
            )
            for result in binding_results
        ),
        observed_facts=tuple(result.subject_id for result in fact_results if result.observed),
        absent_facts=tuple(result.subject_id for result in goal_absence_results if result.observed),
        evidence=(ObservationEvidence(path=report_path.as_posix(), sha256=report_sha256),),
    )
