"""Derive lifecycle qualifications from sealed bundles under an explicit evidence policy.

Evidence is not globally valid or invalid.  A historical direct bundle remains evidence of the
execution it recorded, while a final supervised qualification may deliberately exclude it because
that later protocol makes an additional claim about process control and recovery.  This module
therefore records every candidate bundle and evaluates its eligibility against a typed policy before
deriving a capability level.  It never silently mixes incompatible protocols.
"""

from __future__ import annotations

import hashlib
import json
import re
import statistics
from enum import Enum
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .capability import CapabilityLevel, CapabilityRecord
from .supervision_evidence import SupervisionEvidenceError, verify_qualified_bundle

_MIN_CLEAN_RUNS_FOR_REPRODUCIBLE = 5
_METADATA_FILENAME = "qualification-metadata.json"
_FROZEN_GIT_REVISION = re.compile(r"^[0-9a-f]{40}$")


class ExecutionMode(str, Enum):
    """How an experiment entrypoint was invoked for a recorded bundle."""

    DIRECT = "direct"
    SUPERVISED = "supervised"


class EvidenceRole(str, Enum):
    """The intended use of evidence, independent of whether it later qualifies a release."""

    DEVELOPMENT = "development"
    DIAGNOSTIC = "diagnostic"
    HISTORICAL = "historical"
    QUALIFICATION = "qualification"


class EligibilityExclusionReason(str, Enum):
    """A machine-readable reason a bundle is outside one declared qualification protocol."""

    MISSING_EVIDENCE_METADATA = "missing_evidence_metadata"
    INVALID_EVIDENCE_METADATA = "invalid_evidence_metadata"
    MISSING_PROTOCOL_VERSION = "missing_protocol_version"
    PROTOCOL_VERSION_MISMATCH = "protocol_version_mismatch"
    MISSING_EVIDENCE_ROLE = "missing_evidence_role"
    EVIDENCE_ROLE_NOT_ALLOWED = "evidence_role_not_allowed"
    UNSUPERVISED_FOR_SUPERVISED_PROTOCOL = "unsupervised_for_supervised_protocol"
    SUPERVISION_EVIDENCE_INVALID = "supervision_evidence_invalid"
    EXECUTION_MODE_MISMATCH = "execution_mode_mismatch"
    EXECUTION_MODE_METADATA_MISMATCH = "execution_mode_metadata_mismatch"
    MISSING_REVISION = "missing_revision"
    REVISION_MISMATCH = "revision_mismatch"
    REVISION_CONFLICT = "revision_conflict"
    REQUIRED_REVISION_NOT_FROZEN = "required_revision_not_frozen"
    OBSERVED_REVISION_NOT_FROZEN = "observed_revision_not_frozen"
    MISSING_TOPOLOGY = "missing_topology"
    TOPOLOGY_MISMATCH = "topology_mismatch"
    REALIZATION_NOT_ALLOWED = "realization_not_allowed"
    MISSING_REQUIRED_EVIDENCE_FILE = "missing_required_evidence_file"
    MANIFEST_INVALID = "manifest_invalid"


class QualificationEvidenceMetadata(BaseModel):
    """Declared protocol facts sealed with a run before it is eligible for final qualification.

    ``execution_mode`` is declarative only.  A supervised mode is accepted only after the separate
    parent receipt and child binding verify through :mod:`supervision_evidence`.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["autosut-evidence-metadata/v1"] = "autosut-evidence-metadata/v1"
    protocol_version: str
    evidence_role: EvidenceRole
    execution_mode: ExecutionMode
    topology: str | None = None
    implementation_revision: str | None = None


def prepare_supervised_qualification_metadata(
    *,
    protocol_version: str | None,
    required_revision: str | None,
    topology: str | None,
    observed_revision: str,
    supervised: bool,
) -> QualificationEvidenceMetadata | None:
    """Build the declaration a run must seal before final qualification.

    Qualifying an execution is an opt-in protocol action, never the default effect of using the
    supervisor.  Supplying any qualification argument therefore requires the complete declaration,
    a supervised child, and an exact clean commit.  This prevents a dirty working tree or a direct
    convenience invocation from becoming evidence for a later release claim.
    """

    values = (protocol_version, required_revision, topology)
    if not any(value is not None for value in values):
        return None
    if not all(isinstance(value, str) and value.strip() for value in values):
        raise ValueError(
            "qualification protocol version, revision, and topology must be supplied together"
        )
    if not supervised:
        raise ValueError("qualification metadata can be sealed only by a supervised run")
    assert protocol_version is not None
    assert required_revision is not None
    assert topology is not None
    if not _is_frozen_revision(required_revision):
        raise ValueError("qualification revision must be an immutable 40-character git commit")
    if observed_revision != required_revision:
        raise ValueError(
            "qualification revision must equal the clean source revision observed by the child"
        )
    return QualificationEvidenceMetadata(
        protocol_version=protocol_version,
        evidence_role=EvidenceRole.QUALIFICATION,
        execution_mode=ExecutionMode.SUPERVISED,
        topology=topology,
        implementation_revision=required_revision,
    )


def write_qualification_metadata(
    run_dir: Path, metadata: QualificationEvidenceMetadata | None
) -> Path | None:
    """Atomically seal optional qualification metadata before a run produces evidence.

    A second write is rejected: changing a declaration after a run began would defeat the point of
    putting it under the run manifest.
    """

    if metadata is None:
        return None
    path = run_dir / _METADATA_FILENAME
    if path.exists():
        raise FileExistsError(f"qualification metadata already exists: {path}")
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(metadata.model_dump_json(indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)
    return path


class EvidenceEligibilityPolicy(BaseModel):
    """Requirements a specific qualification imposes on its candidate evidence.

    A policy can require supervision, but supervision is deliberately not a universal artifact
    requirement.  For example, a deterministic STIX transformation may use a direct protocol,
    whereas a final lifecycle/recovery qualification can require a parent-owned supervisor receipt.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: str = "autosut-evidence-eligibility-policy/v1"
    name: str
    final_qualification: bool = False
    required_protocol_version: str | None = None
    required_execution_mode: ExecutionMode | None = None
    accepted_evidence_roles: list[EvidenceRole] | None = None
    required_revision: str | None = None
    require_immutable_revision: bool = False
    required_topology: str | None = None
    accepted_realizations: list[str] | None = None
    required_evidence_files: list[str] = Field(default_factory=list)
    require_manifest_validation: bool = False
    expected_experiment: str | None = None
    require_natural_completion: bool = True

    @model_validator(mode="after")
    def _requirements_are_coherent(self) -> "EvidenceEligibilityPolicy":
        if (
            self.required_execution_mode is ExecutionMode.SUPERVISED
            and not self.expected_experiment
        ):
            raise ValueError("a supervised evidence policy must name expected_experiment")
        if self.require_immutable_revision and self.required_revision is None:
            raise ValueError("an immutable-revision policy must name required_revision")
        for path in self.required_evidence_files:
            candidate = Path(path)
            if candidate.is_absolute() or ".." in candidate.parts:
                raise ValueError("required_evidence_files must be bundle-relative paths")
        return self


class EvidenceEligibility(BaseModel):
    """Eligibility of one bundle for one policy; exclusion does not invalidate the bundle."""

    model_config = ConfigDict(extra="forbid")

    policy_name: str
    eligible: bool
    metadata_status: str
    observed_protocol_version: str | None
    observed_evidence_role: EvidenceRole | None
    observed_execution_mode: ExecutionMode | None
    observed_revision: str | None
    observed_topology: str | None
    observed_realization: str | None
    supervision_id: str | None = None
    manifest_valid: bool | None = None
    missing_required_evidence_files: list[str] = Field(default_factory=list)
    exclusion_reasons: list[EligibilityExclusionReason] = Field(default_factory=list)


def historical_audit_policy(name: str = "historical-audit") -> EvidenceEligibilityPolicy:
    """Return a policy that preserves and describes evidence without release promotion.

    It intentionally imposes no supervision requirement.  Its resulting summary is bounded below
    ``reproducible`` because it is an audit of historical observations, not a final protocol.
    """

    return EvidenceEligibilityPolicy(name=name, final_qualification=False)


def supervised_final_policy(
    *,
    name: str,
    expected_experiment: str,
    required_revision: str,
    required_topology: str | None = None,
    accepted_realizations: list[str] | None = None,
    required_evidence_files: list[str] | None = None,
    protocol_version: str = "autosut-qualification/v1",
) -> EvidenceEligibilityPolicy:
    """Return the strict policy for a final canonical run set.

    The policy is strict only for the qualification that opts into it.  Direct and historical
    evidence remains available to other policies and is still emitted in this policy's audit list.
    """

    return EvidenceEligibilityPolicy(
        name=name,
        final_qualification=True,
        required_protocol_version=protocol_version,
        required_execution_mode=ExecutionMode.SUPERVISED,
        accepted_evidence_roles=[EvidenceRole.QUALIFICATION],
        required_revision=required_revision,
        require_immutable_revision=True,
        required_topology=required_topology,
        accepted_realizations=accepted_realizations,
        required_evidence_files=required_evidence_files or [],
        require_manifest_validation=True,
        expected_experiment=expected_experiment,
        require_natural_completion=True,
    )


def _sha256_of_text(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read_metadata(bundle: Path) -> tuple[QualificationEvidenceMetadata | None, str]:
    """Read an optional sealed metadata declaration without inventing facts for old bundles."""

    path = bundle / _METADATA_FILENAME
    if not path.is_file():
        return None, "absent"
    try:
        return (
            QualificationEvidenceMetadata.model_validate_json(path.read_text(encoding="utf-8")),
            "valid",
        )
    except (json.JSONDecodeError, ValueError):
        return None, "invalid"


def _is_frozen_revision(value: str | None) -> bool:
    """Only a committed SHA identifies a release revision; a ``+tree`` source state does not."""

    return value is not None and _FROZEN_GIT_REVISION.fullmatch(value) is not None


def _sealed_manifest_is_valid(bundle: Path) -> bool:
    """Validate a run-context manifest without assuming supervision is required.

    Direct protocols may still require an intact sealed bundle.  Supervised validation performs the
    same check through ``verify_qualified_bundle``; keeping this small local verifier lets a policy
    express manifest validation independently from execution mode.
    """

    manifest_path = bundle / "manifest.json"
    if not manifest_path.is_file():
        return False
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        entries = manifest["files"]
    except (json.JSONDecodeError, KeyError, TypeError):
        return False
    if not isinstance(entries, list):
        return False
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            return False
        relative_value = entry.get("path")
        expected_hash = entry.get("sha256")
        if not isinstance(relative_value, str) or not isinstance(expected_hash, str):
            return False
        relative = Path(relative_value)
        if relative.is_absolute() or ".." in relative.parts or relative.as_posix() in seen:
            return False
        seen.add(relative.as_posix())
        candidate = bundle / relative
        if not candidate.is_file() or _sha256_of_text(candidate) != expected_hash:
            return False
    return True


def _append_once(
    reasons: list[EligibilityExclusionReason], reason: EligibilityExclusionReason
) -> None:
    if reason not in reasons:
        reasons.append(reason)


def _observed_execution_mode(
    *,
    project_root: Path | None,
    bundle: Path,
    policy: EvidenceEligibilityPolicy,
    reasons: list[EligibilityExclusionReason],
) -> tuple[ExecutionMode | None, str | None]:
    """Verify supervision only when a bundle asserts it or a policy requires it.

    This is the boundary that prevents a final supervised protocol from accepting a direct run.  A
    policy that does not require supervision does not reject direct evidence merely for being direct.
    """

    binding_path = bundle / "supervision-binding.json"
    if not binding_path.is_file():
        # The bundle remains a direct observation.  It is ineligible only for a policy that opted
        # into a supervised property; retaining ``direct`` makes that distinction visible rather
        # than collapsing historical provenance into an ambiguous null value.
        if policy.required_execution_mode is ExecutionMode.SUPERVISED:
            _append_once(reasons, EligibilityExclusionReason.UNSUPERVISED_FOR_SUPERVISED_PROTOCOL)
        return ExecutionMode.DIRECT, None
    if project_root is None or policy.expected_experiment is None:
        if policy.required_execution_mode is ExecutionMode.SUPERVISED:
            _append_once(reasons, EligibilityExclusionReason.SUPERVISION_EVIDENCE_INVALID)
        return None, None
    try:
        receipt = verify_qualified_bundle(
            project_root=project_root,
            bundle=bundle,
            expected_experiment=policy.expected_experiment,
            require_natural_completion=policy.require_natural_completion,
        )
        return ExecutionMode.SUPERVISED, receipt.supervision_id
    except SupervisionEvidenceError:
        _append_once(reasons, EligibilityExclusionReason.SUPERVISION_EVIDENCE_INVALID)
        return None, None


def evaluate_evidence_eligibility(
    *,
    project_root: Path | None,
    bundle: Path,
    policy: EvidenceEligibilityPolicy,
    implementation_revision: str | None,
    realization: str | None = None,
    topology: str | None = None,
) -> EvidenceEligibility:
    """Evaluate one sealed bundle against one policy without deleting or hiding it.

    ``implementation_revision`` and ``realization`` come from the lifecycle/experiment records.
    Metadata supplements those records with protocol role and topology.  Every incompatibility is
    reported as a structured exclusion reason so a reviewer can distinguish an historical result
    from a failed or fabricated one.
    """

    metadata, metadata_status = _read_metadata(bundle)
    reasons: list[EligibilityExclusionReason] = []
    if metadata_status == "invalid":
        _append_once(reasons, EligibilityExclusionReason.INVALID_EVIDENCE_METADATA)

    observed_protocol = metadata.protocol_version if metadata is not None else None
    observed_role = metadata.evidence_role if metadata is not None else None
    observed_topology = (
        topology if topology is not None else (metadata.topology if metadata else None)
    )
    observed_revision = implementation_revision
    if metadata is not None and metadata.implementation_revision is not None:
        if observed_revision is not None and observed_revision != metadata.implementation_revision:
            _append_once(reasons, EligibilityExclusionReason.REVISION_CONFLICT)
        else:
            observed_revision = metadata.implementation_revision

    metadata_is_required = any(
        (
            policy.required_protocol_version is not None,
            policy.accepted_evidence_roles is not None,
            policy.required_topology is not None,
        )
    )
    if metadata_is_required and metadata_status == "absent":
        _append_once(reasons, EligibilityExclusionReason.MISSING_EVIDENCE_METADATA)

    if policy.required_protocol_version is not None:
        if observed_protocol is None:
            _append_once(reasons, EligibilityExclusionReason.MISSING_PROTOCOL_VERSION)
        elif observed_protocol != policy.required_protocol_version:
            _append_once(reasons, EligibilityExclusionReason.PROTOCOL_VERSION_MISMATCH)

    if policy.accepted_evidence_roles is not None:
        if observed_role is None:
            _append_once(reasons, EligibilityExclusionReason.MISSING_EVIDENCE_ROLE)
        elif observed_role not in policy.accepted_evidence_roles:
            _append_once(reasons, EligibilityExclusionReason.EVIDENCE_ROLE_NOT_ALLOWED)

    observed_mode, supervision_id = _observed_execution_mode(
        project_root=project_root,
        bundle=bundle,
        policy=policy,
        reasons=reasons,
    )
    if (
        metadata is not None
        and observed_mode is not None
        and metadata.execution_mode is not observed_mode
    ):
        _append_once(reasons, EligibilityExclusionReason.EXECUTION_MODE_METADATA_MISMATCH)
    if (
        policy.required_execution_mode is not None
        and observed_mode is not policy.required_execution_mode
    ):
        _append_once(reasons, EligibilityExclusionReason.EXECUTION_MODE_MISMATCH)

    if policy.required_revision is not None:
        if observed_revision is None:
            _append_once(reasons, EligibilityExclusionReason.MISSING_REVISION)
        elif observed_revision != policy.required_revision:
            _append_once(reasons, EligibilityExclusionReason.REVISION_MISMATCH)
    if policy.require_immutable_revision:
        if not _is_frozen_revision(policy.required_revision):
            _append_once(reasons, EligibilityExclusionReason.REQUIRED_REVISION_NOT_FROZEN)
        if observed_revision is not None and not _is_frozen_revision(observed_revision):
            _append_once(reasons, EligibilityExclusionReason.OBSERVED_REVISION_NOT_FROZEN)

    if policy.required_topology is not None:
        if observed_topology is None:
            _append_once(reasons, EligibilityExclusionReason.MISSING_TOPOLOGY)
        elif observed_topology != policy.required_topology:
            _append_once(reasons, EligibilityExclusionReason.TOPOLOGY_MISMATCH)

    if policy.accepted_realizations is not None and realization not in policy.accepted_realizations:
        _append_once(reasons, EligibilityExclusionReason.REALIZATION_NOT_ALLOWED)

    missing_files = [
        relative for relative in policy.required_evidence_files if not (bundle / relative).is_file()
    ]
    if missing_files:
        _append_once(reasons, EligibilityExclusionReason.MISSING_REQUIRED_EVIDENCE_FILE)
    manifest_valid = (
        _sealed_manifest_is_valid(bundle) if policy.require_manifest_validation else None
    )
    if manifest_valid is False:
        _append_once(reasons, EligibilityExclusionReason.MANIFEST_INVALID)

    return EvidenceEligibility(
        policy_name=policy.name,
        eligible=not reasons,
        metadata_status=metadata_status,
        observed_protocol_version=observed_protocol,
        observed_evidence_role=observed_role,
        observed_execution_mode=observed_mode,
        observed_revision=observed_revision,
        observed_topology=observed_topology,
        observed_realization=realization,
        supervision_id=supervision_id,
        manifest_valid=manifest_valid,
        missing_required_evidence_files=missing_files,
        exclusion_reasons=reasons,
    )


class RunRecord(BaseModel):
    """One lifecycle run and its eligibility for the summary's declared policy."""

    model_config = ConfigDict(extra="forbid")

    label: str
    run_id: str
    final_state: str
    total_seconds: float
    implementation_revision: str | None
    bundle_manifest_sha256: str
    evidence_dir: str
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
            manifest_valid=None,
            exclusion_reasons=[EligibilityExclusionReason.MISSING_EVIDENCE_METADATA],
        )
    )


class QualificationSummary(BaseModel):
    """A policy-scoped lifecycle summary that retains both eligible and excluded observations."""

    model_config = ConfigDict(extra="forbid")

    backend: str
    campaign: str
    eligibility_policy: EvidenceEligibilityPolicy = Field(default_factory=historical_audit_policy)
    total_runs: int
    eligible_runs: int = 0
    excluded_runs: int = 0
    observed_clean_runs: int = 0
    clean_runs: int
    failure_injection_runs: int
    failure_recovery_reached_clean: bool
    set_revision: str | None
    current_revision: str
    total_seconds_median: float | None
    total_seconds_min: float | None
    total_seconds_max: float | None
    runs: list[RunRecord]
    capability_level: CapabilityLevel
    note: str


def _read_run(
    bundle: Path,
    policy: EvidenceEligibilityPolicy,
    project_root: Path | None,
) -> RunRecord:
    """Read a lifecycle result and preserve its policy eligibility beside the observed outcome."""

    lifecycle = json.loads((bundle / "lifecycle-result.json").read_text(encoding="utf-8"))
    revision = lifecycle.get("implementation_revision")
    return RunRecord(
        label=lifecycle["label"],
        run_id=lifecycle["run_id"],
        final_state=lifecycle["final_state"],
        total_seconds=lifecycle["total_seconds"],
        implementation_revision=revision,
        bundle_manifest_sha256=_sha256_of_text(bundle / "manifest.json"),
        evidence_dir=lifecycle["evidence_dir"],
        eligibility=evaluate_evidence_eligibility(
            project_root=project_root,
            bundle=bundle,
            policy=policy,
            implementation_revision=revision,
        ),
    )


def _set_revision(records: list[RunRecord]) -> str | None:
    revisions = {record.implementation_revision for record in records}
    return revisions.pop() if len(revisions) == 1 and None not in revisions else None


def _derive_level(
    clean_runs: int,
    failure_recovery_reached_clean: bool,
    set_revision: str | None,
    current_revision: str,
    policy: EvidenceEligibilityPolicy,
) -> CapabilityLevel:
    """Derive a level only from eligible runs and never promote an audit policy to reproducible."""

    full = clean_runs >= _MIN_CLEAN_RUNS_FOR_REPRODUCIBLE and failure_recovery_reached_clean
    on_current_revision = set_revision is not None and set_revision == current_revision
    if full and on_current_revision and policy.final_qualification:
        return CapabilityLevel.REPRODUCIBLE
    if clean_runs >= 1:
        return CapabilityLevel.END_TO_END_VALIDATED
    return CapabilityLevel.INTEGRATION_TESTED


def summarize(
    backend: str,
    campaign: str,
    bundles: list[Path],
    current_revision: str,
    *,
    policy: EvidenceEligibilityPolicy | None = None,
    project_root: Path | None = None,
) -> QualificationSummary:
    """Aggregate bundles under one declared policy while retaining excluded historical evidence."""

    policy = policy or historical_audit_policy()
    records = [_read_run(bundle, policy, project_root) for bundle in sorted(bundles)]
    eligible = [record for record in records if record.eligibility.eligible]
    observed_clean = [record for record in records if record.final_state == "clean"]
    clean = [record for record in eligible if record.final_state == "clean"]
    failure_runs = [record for record in eligible if "failed" in record.final_state]
    failure_recovery_reached_clean = bool(failure_runs) and all(
        record.final_state == "failed_clean" for record in failure_runs
    )
    clean_seconds = [record.total_seconds for record in clean]
    set_revision = _set_revision(eligible)
    level = _derive_level(
        len(clean), failure_recovery_reached_clean, set_revision, current_revision, policy
    )
    return QualificationSummary(
        backend=backend,
        campaign=campaign,
        eligibility_policy=policy,
        total_runs=len(records),
        eligible_runs=len(eligible),
        excluded_runs=len(records) - len(eligible),
        observed_clean_runs=len(observed_clean),
        clean_runs=len(clean),
        failure_injection_runs=len(failure_runs),
        failure_recovery_reached_clean=failure_recovery_reached_clean,
        set_revision=set_revision,
        current_revision=current_revision,
        total_seconds_median=round(statistics.median(clean_seconds), 3) if clean_seconds else None,
        total_seconds_min=min(clean_seconds) if clean_seconds else None,
        total_seconds_max=max(clean_seconds) if clean_seconds else None,
        runs=records,
        capability_level=level,
        note=(
            f"Policy {policy.name!r}: {len(eligible)}/{len(records)} bundles are eligible; "
            f"{len(observed_clean)} historical or current bundle(s) observed clean and "
            f"{len(clean)} eligible bundle(s) observed clean. Scope: the SUT lifecycle "
            f"(materialize, execute, verified teardown, verify-clean) for campaign {campaign}; "
            "it does NOT include a Caldera instance created and destroyed inside the run, nor "
            "per-stage timing, so it does not qualify the full CTI-to-isolated-Caldera-to-verified-"
            "effect experiment. Excluded bundles remain preserved observations with per-bundle "
            "reasons; they are not invalidated. Reproducible requires at least "
            f"{_MIN_CLEAN_RUNS_FOR_REPRODUCIBLE} eligible clean runs, an eligible failure run that "
            "reached clean, one current revision, and a policy explicitly designated final."
        ),
    )


def capability_record(summary: QualificationSummary, capability: str) -> CapabilityRecord:
    """Turn a policy-scoped lifecycle summary into the capability record it justifies."""

    level = summary.capability_level
    # Legacy reports did not carry a policy.  They parse as a historical-audit policy and must not
    # retain an old ``reproducible`` label merely because they predate eligibility accounting.
    if level is CapabilityLevel.REPRODUCIBLE and not summary.eligibility_policy.final_qualification:
        level = CapabilityLevel.END_TO_END_VALIDATED
    return CapabilityRecord(
        capability=capability,
        level=level,
        clean_runs_observed=summary.clean_runs,
        implementation_revision=summary.set_revision,
        evidence_paths=[
            "release/experiments/docker_qualification/qualification.json",
            *[record.evidence_dir for record in summary.runs if record.eligibility.eligible],
        ],
        note=summary.note,
    )
