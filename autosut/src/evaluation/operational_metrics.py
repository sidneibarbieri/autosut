"""Denominator-complete metrics for autonomous multi-host experiments.

The data contract separates a planned experiment from collected observations. Missing,
unsupported, interrupted, and timed-out cells remain in the reliability denominator. Asset
acquisition contributes to Success and TotalAcquisition only when it is independently verified and
the surrounding lifecycle is qualified and clean.
"""

from __future__ import annotations

import hashlib
import json
from enum import Enum
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

SHA256_PATTERN = r"^[0-9a-f]{64}$"
SOURCE_REVISION_PATTERN = r"^[0-9a-f]{40}(?:\+tree-[0-9a-f]{16})?$"


def canonical_sha256(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )
    return hashlib.sha256(encoded).hexdigest()


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CellStatus(str, Enum):
    PLANNED = "planned"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    UNSUPPORTED = "unsupported"
    INTERRUPTED = "interrupted"


class InterventionActor(str, Enum):
    SYSTEM = "system"
    HUMAN = "human"


class EvidenceReference(StrictModel):
    path: str = Field(min_length=1)
    sha256: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def _path_stays_under_evidence_root(self) -> "EvidenceReference":
        candidate = Path(self.path)
        if candidate.is_absolute() or ".." in candidate.parts:
            raise ValueError("evidence path must be relative and stay inside its evidence root")
        return self

    def verify(self, evidence_root: Path) -> None:
        candidate = evidence_root / self.path
        if not candidate.is_file():
            raise ValueError(f"operational evidence is missing: {self.path}")
        observed = hashlib.sha256(candidate.read_bytes()).hexdigest()
        if observed != self.sha256:
            raise ValueError(f"operational evidence hash mismatch: {self.path}")


class CriticalAsset(StrictModel):
    asset_id: str = Field(min_length=1)
    description: str = Field(min_length=1)


class EnvironmentDefinition(StrictModel):
    environment_id: str = Field(min_length=1)
    critical_assets: tuple[CriticalAsset, ...] = Field(min_length=1)
    topology_sha256: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def _assets_are_unique(self) -> "EnvironmentDefinition":
        asset_ids = [asset.asset_id for asset in self.critical_assets]
        if len(asset_ids) != len(set(asset_ids)):
            raise ValueError("critical asset identifiers must be unique within an environment")
        return self


class ExperimentPlan(StrictModel):
    schema_version: Literal["autosut-operational-plan/v1"] = "autosut-operational-plan/v1"
    experiment_id: str = Field(min_length=1)
    arms: tuple[str, ...] = Field(min_length=1)
    environments: tuple[EnvironmentDefinition, ...] = Field(min_length=1)
    seeds: tuple[int, ...] = Field(min_length=1)
    implementation_revision: str = Field(pattern=SOURCE_REVISION_PATTERN)
    protocol_sha256: str = Field(pattern=SHA256_PATTERN)
    content_sha256: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def _plan_is_frozen_and_unique(self) -> "ExperimentPlan":
        for label, values in (
            ("arm", self.arms),
            ("environment", tuple(item.environment_id for item in self.environments)),
            ("seed", self.seeds),
        ):
            if len(values) != len(set(values)):
                raise ValueError(f"{label} values must be unique")
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"content_sha256"}))
        if self.content_sha256 != expected:
            raise ValueError("operational experiment plan hash mismatch")
        return self

    @classmethod
    def freeze(
        cls,
        *,
        experiment_id: str,
        arms: tuple[str, ...],
        environments: tuple[EnvironmentDefinition, ...],
        seeds: tuple[int, ...],
        implementation_revision: str,
        protocol_sha256: str,
    ) -> "ExperimentPlan":
        payload: dict[str, Any] = {
            "schema_version": "autosut-operational-plan/v1",
            "experiment_id": experiment_id,
            "arms": arms,
            "environments": [item.model_dump(mode="json") for item in environments],
            "seeds": seeds,
            "implementation_revision": implementation_revision,
            "protocol_sha256": protocol_sha256,
        }
        return cls(
            experiment_id=experiment_id,
            arms=arms,
            environments=environments,
            seeds=seeds,
            implementation_revision=implementation_revision,
            protocol_sha256=protocol_sha256,
            content_sha256=canonical_sha256(payload),
        )

    @property
    def expected_cell_keys(self) -> set[tuple[str, str, int]]:
        return {
            (arm, environment.environment_id, seed)
            for arm in self.arms
            for environment in self.environments
            for seed in self.seeds
        }


class ResourceAccounting(StrictModel):
    wall_seconds: float = Field(ge=0, allow_inf_nan=False)
    active_compute_seconds: float = Field(ge=0, allow_inf_nan=False)
    model_seconds: float = Field(ge=0, allow_inf_nan=False)
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    model_cost_usd: float = Field(ge=0, allow_inf_nan=False)


class Intervention(StrictModel):
    actor: InterventionActor
    category: str = Field(min_length=1)
    active_seconds: float = Field(ge=0, allow_inf_nan=False)
    reason: str = Field(min_length=1)


class AssetAcquisition(StrictModel):
    asset_id: str = Field(min_length=1)
    effect_verified: bool
    evidence: tuple[EvidenceReference, ...] = Field(min_length=1)


class OperationalCell(StrictModel):
    schema_version: Literal["autosut-operational-cell/v1"] = "autosut-operational-cell/v1"
    experiment_id: str = Field(min_length=1)
    plan_sha256: str = Field(pattern=SHA256_PATTERN)
    arm: str = Field(min_length=1)
    environment_id: str = Field(min_length=1)
    seed: int
    status: CellStatus
    lifecycle_qualified: bool = False
    clean_teardown: bool = False
    acquisitions: tuple[AssetAcquisition, ...] = ()
    interventions: tuple[Intervention, ...] = ()
    accounting: ResourceAccounting | None = None
    terminal_evidence: tuple[EvidenceReference, ...] = ()
    failure_reason: str | None = None

    @model_validator(mode="after")
    def _state_is_coherent(self) -> "OperationalCell":
        acquisition_ids = [item.asset_id for item in self.acquisitions]
        if len(acquisition_ids) != len(set(acquisition_ids)):
            raise ValueError("an operational cell cannot acquire the same asset twice")
        if self.status is CellStatus.PLANNED:
            if any(
                (
                    self.lifecycle_qualified,
                    self.clean_teardown,
                    self.acquisitions,
                    self.interventions,
                    self.accounting,
                    self.terminal_evidence,
                    self.failure_reason,
                )
            ):
                raise ValueError("a planned cell cannot contain observations")
            return self
        if self.accounting is None:
            raise ValueError("an attempted cell requires resource accounting")
        if not self.terminal_evidence:
            raise ValueError("an attempted cell requires terminal evidence")
        if self.status in {CellStatus.FAILED, CellStatus.UNSUPPORTED, CellStatus.INTERRUPTED}:
            if not self.failure_reason:
                raise ValueError("failed, unsupported, and interrupted cells require a reason")
        if self.status is CellStatus.COMPLETED and self.failure_reason:
            raise ValueError("a completed cell cannot carry a failure reason")
        return self

    @property
    def qualifying_asset_ids(self) -> set[str]:
        if not self.lifecycle_qualified or not self.clean_teardown:
            return set()
        if self.status in {CellStatus.PLANNED, CellStatus.UNSUPPORTED, CellStatus.INTERRUPTED}:
            return set()
        return {item.asset_id for item in self.acquisitions if item.effect_verified}

    @property
    def successful(self) -> bool:
        return bool(self.qualifying_asset_ids)

    def verify_evidence(self, evidence_root: Path) -> None:
        for reference in self.terminal_evidence:
            reference.verify(evidence_root)
        for acquisition in self.acquisitions:
            for reference in acquisition.evidence:
                reference.verify(evidence_root)


class OperationalLedger(StrictModel):
    schema_version: Literal["autosut-operational-ledger/v1"] = "autosut-operational-ledger/v1"
    plan: ExperimentPlan
    cells: tuple[OperationalCell, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def _matrix_is_exact_and_bound(self) -> "OperationalLedger":
        observed: set[tuple[str, str, int]] = set()
        assets_by_environment = {
            environment.environment_id: {asset.asset_id for asset in environment.critical_assets}
            for environment in self.plan.environments
        }
        for cell in self.cells:
            key = (cell.arm, cell.environment_id, cell.seed)
            if key in observed:
                raise ValueError(f"duplicate operational cell: {key}")
            observed.add(key)
            if cell.experiment_id != self.plan.experiment_id:
                raise ValueError("operational cell belongs to another experiment")
            if cell.plan_sha256 != self.plan.content_sha256:
                raise ValueError("operational cell is not bound to the frozen plan")
            unknown_assets = {
                acquisition.asset_id for acquisition in cell.acquisitions
            } - assets_by_environment.get(cell.environment_id, set())
            if unknown_assets:
                raise ValueError(
                    "cell names undeclared critical assets: " + ", ".join(sorted(unknown_assets))
                )
        missing = self.plan.expected_cell_keys - observed
        extra = observed - self.plan.expected_cell_keys
        if missing or extra:
            raise ValueError(
                f"operational matrix mismatch: {len(missing)} missing, {len(extra)} extra"
            )
        return self

    def verify_evidence(self, evidence_root: Path) -> None:
        for cell in self.cells:
            if cell.status is not CellStatus.PLANNED:
                cell.verify_evidence(evidence_root)


class EnvironmentMetrics(StrictModel):
    arm: str
    environment_id: str
    planned_trials: int = Field(ge=1)
    attempted_trials: int = Field(ge=0)
    qualifying_successes: int = Field(ge=0)
    success: bool
    reliability: float = Field(ge=0, le=1)
    total_acquisition: float = Field(ge=0, le=1)
    acquired_assets: tuple[str, ...]
    human_interventions: int = Field(ge=0)
    human_active_seconds: float = Field(ge=0, allow_inf_nan=False)
    wall_seconds: float = Field(ge=0, allow_inf_nan=False)
    active_compute_seconds: float = Field(ge=0, allow_inf_nan=False)
    model_seconds: float = Field(ge=0, allow_inf_nan=False)
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    model_cost_usd: float = Field(ge=0, allow_inf_nan=False)


def calculate_metrics(ledger: OperationalLedger) -> tuple[EnvironmentMetrics, ...]:
    assets_by_environment = {
        environment.environment_id: {asset.asset_id for asset in environment.critical_assets}
        for environment in ledger.plan.environments
    }
    results: list[EnvironmentMetrics] = []
    for arm in ledger.plan.arms:
        for environment in ledger.plan.environments:
            cells = [
                cell
                for cell in ledger.cells
                if cell.arm == arm and cell.environment_id == environment.environment_id
            ]
            successful_cells = [cell for cell in cells if cell.successful]
            acquired = set().union(*(cell.qualifying_asset_ids for cell in cells))
            accounting = [cell.accounting for cell in cells if cell.accounting is not None]
            human_interventions = [
                intervention
                for cell in cells
                for intervention in cell.interventions
                if intervention.actor is InterventionActor.HUMAN
            ]
            critical_assets = assets_by_environment[environment.environment_id]
            results.append(
                EnvironmentMetrics(
                    arm=arm,
                    environment_id=environment.environment_id,
                    planned_trials=len(cells),
                    attempted_trials=sum(cell.status is not CellStatus.PLANNED for cell in cells),
                    qualifying_successes=len(successful_cells),
                    success=bool(successful_cells),
                    reliability=len(successful_cells) / len(cells),
                    total_acquisition=len(acquired) / len(critical_assets),
                    acquired_assets=tuple(sorted(acquired)),
                    human_interventions=len(human_interventions),
                    human_active_seconds=sum(item.active_seconds for item in human_interventions),
                    wall_seconds=sum(item.wall_seconds for item in accounting),
                    active_compute_seconds=sum(item.active_compute_seconds for item in accounting),
                    model_seconds=sum(item.model_seconds for item in accounting),
                    input_tokens=sum(item.input_tokens for item in accounting),
                    output_tokens=sum(item.output_tokens for item in accounting),
                    model_cost_usd=sum(item.model_cost_usd for item in accounting),
                )
            )
    return tuple(results)
