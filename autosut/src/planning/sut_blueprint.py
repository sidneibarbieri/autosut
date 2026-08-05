"""Synthesize a minimal isolated SUT witness from a complete constraint set."""

from __future__ import annotations

import hashlib
import json

from pydantic import BaseModel, Field

from .sut_constraints import EnvironmentRequirement, SUTConstraintSet


class BackendRecipe(BaseModel):
    backend: str
    base_image: str
    memory_mb: int
    cpu_count: int


class BlueprintHost(BaseModel):
    host_id: str
    role: str
    platform: str
    recipe: BackendRecipe
    requirement_ids: list[str] = Field(default_factory=list)


class NetworkPolicy(BaseModel):
    host_network_access: bool = False
    internet_egress: bool = False
    lab_private_network: bool = True


class SUTBlueprint(BaseModel):
    schema_version: str = "1"
    campaign_id: str
    source_constraint_sha256: str
    synthesis_policy: str = "one_minimal_host_per_selected_platform"
    hosts: list[BlueprintHost] = Field(min_length=1)
    network_policy: NetworkPolicy = Field(default_factory=NetworkPolicy)
    concretized_requirements: list[EnvironmentRequirement]
    content_sha256: str = ""

    def finalize_hash(self) -> None:
        payload = self.model_dump(mode="json", exclude={"content_sha256"})
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        self.content_sha256 = hashlib.sha256(encoded).hexdigest()


BACKEND_RECIPES = {
    "Linux": BackendRecipe(
        backend="docker",
        base_image="python:3.11-slim",
        memory_mb=4096,
        cpu_count=2,
    ),
}


def _requirements_for_platform(
    requirements: list[EnvironmentRequirement], platform: str
) -> list[str]:
    assigned: list[str] = []
    for requirement in requirements:
        if requirement.kind != "platform" or platform in requirement.acceptable_values:
            assigned.append(requirement.requirement_id)
    return sorted(set(assigned))


def synthesize_blueprint(constraints: SUTConstraintSet) -> SUTBlueprint:
    resolution = constraints.platform_resolution
    if not resolution.complete:
        raise ValueError(
            "cannot synthesize a SUT witness from incomplete constraints: "
            + ", ".join(resolution.uncovered_technique_ids)
        )

    hosts: list[BlueprintHost] = []
    for host_index, platform in enumerate(resolution.selected_platforms, start=1):
        recipe = BACKEND_RECIPES.get(platform)
        if recipe is None:
            raise ValueError(f"no isolated backend recipe for platform {platform}")
        hosts.append(
            BlueprintHost(
                host_id=f"target-{host_index}",
                role="target",
                platform=platform,
                recipe=recipe,
                requirement_ids=_requirements_for_platform(
                    constraints.requirements, platform
                ),
            )
        )

    blueprint = SUTBlueprint(
        campaign_id=constraints.campaign_id,
        source_constraint_sha256=constraints.content_sha256,
        hosts=hosts,
        concretized_requirements=constraints.requirements,
    )
    blueprint.finalize_hash()
    return blueprint
