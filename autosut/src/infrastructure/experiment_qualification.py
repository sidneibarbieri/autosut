"""Derive full-experiment qualifications under an explicit evidence-eligibility policy.

The experiment summary keeps every candidate bundle, including historical and direct executions.
Only bundles eligible for the declared policy contribute to a level.  This prevents a final
supervised protocol from silently borrowing evidence from an older direct protocol while preserving
the older evidence and its actual observations for audit.
"""

from __future__ import annotations

import hashlib
import json
import statistics
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from .capability import CapabilityLevel
from .qualification import (
    EvidenceEligibility,
    EvidenceEligibilityPolicy,
    evaluate_evidence_eligibility,
    historical_audit_policy,
)

_MIN_CLEAN_RUNS_FOR_REPRODUCIBLE = 5


class ExperimentRunRecord(BaseModel):
    """One full-experiment observation and its eligibility for the summary policy."""

    model_config = ConfigDict(extra="forbid")

    label: str
    run_id: str
    final_state: str
    total_seconds: float
    realization: str
    topology: str | None = None
    operation_state: str | None
    effect_confirmed: bool | None
    stages_all_passed: bool
    implementation_revision: str | None
    bundle_manifest_sha256: str
    eligibility: EvidenceEligibility = Field(
        default_factory=lambda: EvidenceEligibility(
            policy_name="legacy-unscoped",
            eligible=False,
            metadata_status="legacy",
            observed_protocol_version=None,
            observed_evidence_role=None,
            observed_execution_mode=None,
            observed_revision=None,
            observed_topology=None,
            observed_realization=None,
        )
    )


class QualificationScope(BaseModel):
    """What the qualification covers and what it deliberately does not."""

    model_config = ConfigDict(extra="forbid")

    validated: list[str]
    excluded: list[str]


class ExperimentQualification(BaseModel):
    """A policy-scoped full-experiment qualification derived from all candidate bundles."""

    model_config = ConfigDict(extra="forbid")

    capability: str
    protocol: str
    scope: QualificationScope
    eligibility_policy: EvidenceEligibilityPolicy = Field(default_factory=historical_audit_policy)
    total_runs: int
    eligible_runs: int = 0
    excluded_runs: int = 0
    observed_clean_runs: int = 0
    clean_runs: int
    observed_effect_confirmed_runs: int = 0
    effect_confirmed_runs: int
    realizations_observed: list[str]
    eligible_realizations_observed: list[str] = Field(default_factory=list)
    set_revision: str | None
    current_revision: str
    total_seconds_median: float | None
    total_seconds_min: float | None
    total_seconds_max: float | None
    runs: list[ExperimentRunRecord]
    result_level: CapabilityLevel
    note: str


def _read_run(
    bundle: Path,
    policy: EvidenceEligibilityPolicy,
    project_root: Path | None,
) -> ExperimentRunRecord:
    lifecycle = json.loads((bundle / "lifecycle-result.json").read_text(encoding="utf-8"))
    experiment = json.loads((bundle / "experiment.json").read_text(encoding="utf-8"))
    operation = experiment.get("operation") or {}
    realization = experiment.get("realization", "unknown")
    topology = experiment.get("topology")
    revision = experiment.get("implementation_revision") or lifecycle.get("implementation_revision")
    return ExperimentRunRecord(
        label=lifecycle["label"],
        run_id=lifecycle["run_id"],
        final_state=lifecycle["final_state"],
        total_seconds=lifecycle["total_seconds"],
        realization=realization,
        topology=topology,
        operation_state=operation.get("operation_state"),
        effect_confirmed=experiment.get("independent_effect_confirmed"),
        stages_all_passed=all(stage["succeeded"] for stage in lifecycle["stages"]),
        implementation_revision=revision,
        bundle_manifest_sha256=hashlib.sha256((bundle / "manifest.json").read_bytes()).hexdigest(),
        eligibility=evaluate_evidence_eligibility(
            project_root=project_root,
            bundle=bundle,
            policy=policy,
            implementation_revision=revision,
            realization=realization,
            topology=topology,
        ),
    )


def _set_revision(records: list[ExperimentRunRecord]) -> str | None:
    """Return the one revision all eligible records share, otherwise ``None``."""

    revisions = {record.implementation_revision for record in records}
    if len(revisions) == 1 and None not in revisions:
        return revisions.pop()
    return None


def _derive_level(
    clean_runs: int,
    effect_confirmed_runs: int,
    set_revision: str | None,
    current_revision: str,
    policy: EvidenceEligibilityPolicy,
) -> CapabilityLevel:
    """Derive a level from policy-eligible runs; only a final policy may become reproducible."""

    full_and_effective = (
        clean_runs >= _MIN_CLEAN_RUNS_FOR_REPRODUCIBLE and effect_confirmed_runs >= clean_runs
    )
    on_current_revision = set_revision is not None and set_revision == current_revision
    if full_and_effective and on_current_revision and policy.final_qualification:
        return CapabilityLevel.REPRODUCIBLE
    if clean_runs >= 1 and effect_confirmed_runs >= 1:
        return CapabilityLevel.END_TO_END_VALIDATED
    return CapabilityLevel.INTEGRATION_TESTED


_SINGLE_HOST_SCOPE = QualificationScope(
    validated=[
        "per-run isolated Caldera (own container and port, destroyed by the run)",
        "real Sandcat enrollment against the isolated instance",
        "real ability, adversary, and operation",
        "effect confirmed by a probe independent of Caldera's reported status",
        "verified teardown and temporal verify-clean",
    ],
    excluded=[
        "real-CVE service realization (the Ray service is the documented surrogate)",
        "multi-host execution",
        "the QEMU/Vagrant backend",
    ],
)


def summarize(
    capability: str,
    bundles: list[Path],
    current_revision: str,
    scope: QualificationScope | None = None,
    *,
    policy: EvidenceEligibilityPolicy | None = None,
    project_root: Path | None = None,
) -> ExperimentQualification:
    """Aggregate all candidate bundles while deriving the level only from eligible evidence."""

    scope = scope or _SINGLE_HOST_SCOPE
    policy = policy or historical_audit_policy()
    records = [_read_run(bundle, policy, project_root) for bundle in sorted(bundles)]
    eligible = [record for record in records if record.eligibility.eligible]
    observed_clean = [record for record in records if record.final_state == "clean"]
    clean = [record for record in eligible if record.final_state == "clean"]
    observed_effect = [record for record in observed_clean if record.effect_confirmed is True]
    effect_confirmed = [record for record in clean if record.effect_confirmed is True]
    clean_seconds = [record.total_seconds for record in clean]
    realizations = sorted({record.realization for record in records})
    eligible_realizations = sorted({record.realization for record in eligible})
    set_revision = _set_revision(eligible)
    level = _derive_level(len(clean), len(effect_confirmed), set_revision, current_revision, policy)
    return ExperimentQualification(
        capability=capability,
        protocol=(
            "Per run: materialize isolated Caldera; verify readiness; materialize SUT; enroll a "
            "real Sandcat; register ability, adversary, and operation; execute; confirm the effect "
            "with a probe independent of Caldera's reported status; destroy every run-owned "
            "resource; verify-clean. Reproducible requires "
            f"{_MIN_CLEAN_RUNS_FOR_REPRODUCIBLE} eligible clean runs that each confirm the effect."
        ),
        scope=scope,
        eligibility_policy=policy,
        total_runs=len(records),
        eligible_runs=len(eligible),
        excluded_runs=len(records) - len(eligible),
        observed_clean_runs=len(observed_clean),
        clean_runs=len(clean),
        observed_effect_confirmed_runs=len(observed_effect),
        effect_confirmed_runs=len(effect_confirmed),
        realizations_observed=realizations,
        eligible_realizations_observed=eligible_realizations,
        set_revision=set_revision,
        current_revision=current_revision,
        total_seconds_median=round(statistics.median(clean_seconds), 3) if clean_seconds else None,
        total_seconds_min=min(clean_seconds) if clean_seconds else None,
        total_seconds_max=max(clean_seconds) if clean_seconds else None,
        runs=records,
        result_level=level,
        note=(
            f"Policy {policy.name!r}: {len(eligible)}/{len(records)} bundles are eligible; "
            f"{len(observed_clean)} observations completed clean and {len(observed_effect)} "
            "observed the independent effect; "
            f"{len(clean)} eligible observations completed clean and {len(effect_confirmed)} "
            "eligible observations confirmed the effect. Excluded bundles remain preserved with "
            "structured reasons; they are not invalidated. A surrogate effect qualifies integration "
            "and dispatch, not real-CVE exploitation. Reproducible requires a current shared "
            "revision and a policy explicitly designated final."
        ),
    )


def capability_record(
    qualification: ExperimentQualification,
    evidence_path: str = "release/experiments/caldera_experiment/qualification.json",
):
    """Build the capability record bounded by the summary's eligible evidence subset."""

    from .capability import CapabilityLevel, CapabilityRecord

    level = qualification.result_level
    if (
        level is CapabilityLevel.REPRODUCIBLE
        and not qualification.eligibility_policy.final_qualification
    ):
        level = CapabilityLevel.END_TO_END_VALIDATED
    return CapabilityRecord(
        capability=qualification.capability,
        level=level,
        clean_runs_observed=qualification.clean_runs,
        implementation_revision=qualification.set_revision,
        evidence_paths=[evidence_path],
        note=qualification.note,
    )
