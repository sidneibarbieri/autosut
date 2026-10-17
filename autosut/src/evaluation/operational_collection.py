"""Frozen bindings between operational ledger cells and supervised entrypoints."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, model_validator

from .operational_metrics import ExperimentPlan, StrictModel, canonical_sha256

SHA256_PATTERN = r"^[0-9a-f]{64}$"


class CollectionBinding(StrictModel):
    arm: str = Field(min_length=1)
    environment_id: str = Field(min_length=1)
    experiment: Literal["caldera", "multihost"]
    critical_asset_id: str = Field(min_length=1)
    effect_field: str = Field(min_length=1)
    driver_sha256: str = Field(pattern=SHA256_PATTERN)
    deadline_seconds: int = Field(ge=60, le=7200)
    experiment_args: tuple[str, ...] = ()


class OperationalCollectionProtocol(StrictModel):
    schema_version: Literal["autosut-operational-collection/v1"] = (
        "autosut-operational-collection/v1"
    )
    plan: ExperimentPlan
    bindings: tuple[CollectionBinding, ...] = Field(min_length=1)
    serial_execution: Literal[True] = True
    fresh_control_plane_per_cell: Literal[True] = True
    content_sha256: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def _protocol_is_complete_and_frozen(self) -> "OperationalCollectionProtocol":
        observed = {(binding.arm, binding.environment_id) for binding in self.bindings}
        if len(observed) != len(self.bindings):
            raise ValueError("collection bindings must be unique by arm and environment")
        expected = {
            (arm, environment.environment_id)
            for arm in self.plan.arms
            for environment in self.plan.environments
        }
        if observed != expected:
            raise ValueError("collection bindings do not cover the frozen arm/environment matrix")
        assets = {
            environment.environment_id: {asset.asset_id for asset in environment.critical_assets}
            for environment in self.plan.environments
        }
        for binding in self.bindings:
            if binding.critical_asset_id not in assets[binding.environment_id]:
                raise ValueError("collection binding names an undeclared critical asset")
        expected_hash = canonical_sha256(self.model_dump(mode="json", exclude={"content_sha256"}))
        if self.content_sha256 != expected_hash:
            raise ValueError("operational collection protocol hash mismatch")
        return self

    @classmethod
    def freeze(
        cls,
        *,
        plan: ExperimentPlan,
        bindings: tuple[CollectionBinding, ...],
    ) -> "OperationalCollectionProtocol":
        payload = {
            "schema_version": "autosut-operational-collection/v1",
            "plan": plan.model_dump(mode="json"),
            "bindings": [binding.model_dump(mode="json") for binding in bindings],
            "serial_execution": True,
            "fresh_control_plane_per_cell": True,
        }
        return cls(plan=plan, bindings=bindings, content_sha256=canonical_sha256(payload))
