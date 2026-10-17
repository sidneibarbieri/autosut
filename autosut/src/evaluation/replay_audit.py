"""Audit recorded replay counts and file references without executing a campaign."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

Count = Annotated[int, Field(ge=0, strict=True)]
Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class FileObservation(StrictModel):
    path: str
    sha256: Digest | None


class RecordedStep(StrictModel):
    status: Literal["success", "failure", "skipped"]
    executed_mode: Literal[
        "real_controlled", "caldera_driven", "atomic_red_team", "naive_simulated"
    ]
    executed_fidelity: Literal["faithful", "adapted", "inspired"]
    evidence_files: tuple[str, ...]


class ManifestCounts(StrictModel):
    total: Count
    successful: Count
    evidence_backed_successful: Count
    marker_only_successful: Count
    caldera_driven_successful: Count
    inspired_execution_steps: Count
    steps_with_all_references_present: Count


class ReplayObservation(StrictModel):
    campaign_id: str
    reported_status: str
    reported_total: Count
    reported_successful: Count
    reported_evidence_backed: Count | None
    reported_markers: Count | None
    reported_caldera: Count | None
    reported_clean: bool | None = Field(strict=True)
    elapsed_seconds: float = Field(ge=0, allow_inf_nan=False)
    recorded_revision: str | None
    manifest_counts: ManifestCounts | None
    files: tuple[FileObservation, ...]
    issues: tuple[str, ...]


class ReplayAudit(StrictModel):
    schema_version: Literal["autosut-replay-audit/v1"] = "autosut-replay-audit/v1"
    source_report_name: str
    source_report_sha256: Digest
    records: tuple[ReplayObservation, ...] = Field(min_length=1)
    scope: str = (
        "Retrospective count and file-reference audit. File presence and hashes do not "
        "validate technique semantics, independent effects, current-revision qualification, "
        "or cross-host reproducibility. Source trace files remain in the local collection."
    )


def _relative_file(root: Path, relative: str) -> Path:
    candidate = Path(relative)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise ValueError("evidence path must be relative to its root")
    resolved = (root / candidate).resolve()
    if not resolved.is_relative_to(root.resolve()):
        raise ValueError("evidence path escapes its root")
    return resolved


def _observe_file(root: Path, relative: str) -> FileObservation:
    path = _relative_file(root, relative)
    digest = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
    return FileObservation(path=relative, sha256=digest)


def _manifest_counts(
    steps: tuple[RecordedStep, ...], present: set[str]
) -> ManifestCounts:
    successful = [step for step in steps if step.status == "success"]
    executions = [
        step for step in successful
        if step.executed_mode != "naive_simulated" and step.evidence_files
    ]
    return ManifestCounts(
        total=len(steps),
        successful=len(successful),
        evidence_backed_successful=len(executions),
        marker_only_successful=sum(
            step.executed_mode == "naive_simulated" for step in successful
        ),
        caldera_driven_successful=sum(
            step.executed_mode == "caldera_driven" for step in executions
        ),
        inspired_execution_steps=sum(
            step.executed_fidelity == "inspired" for step in executions
        ),
        steps_with_all_references_present=sum(
            set(step.evidence_files) <= present for step in executions
        ),
    )


def _audit_record(row: dict, root: Path) -> ReplayObservation:
    manifest_name = row["evidence_manifest"]
    manifest_path = _relative_file(root, manifest_name)
    observations = [_observe_file(root, manifest_name)]
    issues: list[str] = []
    counts = None
    recorded_revision = row.get("implementation_revision")
    if observations[0].sha256 is None:
        issues.append("missing_manifest")
    else:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest["campaign_id"] != row["campaign_id"]:
            issues.append("campaign_id_mismatch")
        steps = tuple(
            RecordedStep.model_validate({key: step[key] for key in RecordedStep.model_fields})
            for step in manifest["techniques"]
        )
        present: set[str] = set()
        for reference in sorted({name for step in steps for name in step.evidence_files}):
            _relative_file(manifest_path.parent, reference)
            relative = (Path(manifest_name).parent / reference).as_posix()
            observation = _observe_file(root, relative)
            observations.append(observation)
            if observation.sha256 is not None:
                present.add(reference)
        counts = _manifest_counts(steps, present)
        for key in (
            "total", "successful", "evidence_backed_successful",
            "marker_only_successful", "caldera_driven_successful",
        ):
            if row.get(key) is not None and row[key] != getattr(counts, key):
                issues.append(f"count_mismatch:{key}")
        if manifest.get("teardown_clean") is not True:
            issues.append("manifest_teardown_not_clean")
        if counts.inspired_execution_steps:
            issues.append("inspired_steps_counted_as_execution")
        if counts.steps_with_all_references_present != counts.evidence_backed_successful:
            issues.append("missing_execution_references")
        provenance_name = (Path(manifest_name).parent / "provenance.json").as_posix()
        provenance_observation = _observe_file(root, provenance_name)
        observations.append(provenance_observation)
        if provenance_observation.sha256:
            provenance = json.loads(_relative_file(root, provenance_name).read_text("utf-8"))
            manifest_revision = provenance.get("implementation_revision")
            if recorded_revision and recorded_revision != manifest_revision:
                issues.append("revision_mismatch")
            recorded_revision = recorded_revision or manifest_revision
    if not recorded_revision:
        issues.append("implementation_revision_not_recorded")
    if row.get("final_namespace_clean") is not True:
        issues.append("clean_namespace_not_recorded")
    if any(observation.sha256 is None for observation in observations):
        issues.append("source_files_missing")
    return ReplayObservation(
        campaign_id=row["campaign_id"],
        reported_status=row["status"],
        reported_total=row["total"],
        reported_successful=row["successful"],
        reported_evidence_backed=row.get("evidence_backed_successful"),
        reported_markers=row.get("marker_only_successful"),
        reported_caldera=row.get("caldera_driven_successful"),
        reported_clean=row.get("final_namespace_clean"),
        elapsed_seconds=row["elapsed_seconds"],
        recorded_revision=recorded_revision,
        manifest_counts=counts,
        files=tuple(observations),
        issues=tuple(issues),
    )


def audit_replay_report(report_path: Path, artifact_root: Path) -> ReplayAudit:
    """Keep every reported row, including failures and missing source files."""
    encoded = report_path.read_bytes()
    rows = json.loads(encoded)
    if not isinstance(rows, list) or not rows:
        raise ValueError("replay report must contain a nonempty list of rows")
    campaign_ids = [row["campaign_id"] for row in rows]
    if len(set(campaign_ids)) != len(campaign_ids):
        raise ValueError("replay report contains duplicate campaign identifiers")
    return ReplayAudit(
        source_report_name=report_path.name,
        source_report_sha256=hashlib.sha256(encoded).hexdigest(),
        records=tuple(_audit_record(row, artifact_root) for row in rows),
    )
