"""Integrity and resource admission shared by isolated corpus probes."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .sut_blueprint import SUTBlueprint
from .sut_constraints import EnvironmentRequirement, SUTConstraintSet


def _load_hashed(path: Path, model_type):
    model = model_type.model_validate_json(path.read_text())
    expected = model.content_sha256
    model.finalize_hash()
    if model.content_sha256 != expected:
        raise ValueError(f"content hash mismatch: {path.name}")
    return model


def load_corpus_blueprint(
    corpus: Path,
    campaign_id: str,
) -> tuple[SUTBlueprint, SUTConstraintSet, str]:
    """Bind one blueprint to its corpus entry and source constraints."""
    if not campaign_id.startswith("C") or not campaign_id[1:].isdigit():
        raise ValueError("invalid campaign ID")
    folder = corpus / campaign_id
    manifest = json.loads((corpus / "manifest.json").read_text())
    records = [item for item in manifest["records"] if item["campaign_id"] == campaign_id]
    if len(records) != 1 or records[0]["status"] != "blueprint_generated":
        raise ValueError("campaign has no generated blueprint in the corpus manifest")
    constraints = _load_hashed(folder / "constraints.json", SUTConstraintSet)
    blueprint_path = folder / "sut-blueprint.json"
    blueprint = _load_hashed(blueprint_path, SUTBlueprint)
    if records[0]["blueprint_sha256"] != blueprint.content_sha256:
        raise ValueError("blueprint differs from corpus manifest")
    if constraints.campaign_id != campaign_id or blueprint.campaign_id != campaign_id:
        raise ValueError("campaign identity mismatch")
    if blueprint.source_constraint_sha256 != constraints.content_sha256:
        raise ValueError("blueprint does not match source constraints")
    if blueprint.concretized_requirements != constraints.requirements:
        raise ValueError("blueprint omits source requirements")
    if not constraints.platform_resolution.complete:
        raise ValueError("incomplete platform resolution")
    policy = blueprint.network_policy
    if not policy.lab_private_network or policy.host_network_access or policy.internet_egress:
        raise ValueError("nonisolated blueprint")
    return blueprint, constraints, hashlib.sha256(blueprint_path.read_bytes()).hexdigest()


def admitted_resource_values(
    requirements: list[EnvironmentRequirement],
    *,
    supported: frozenset[str],
) -> tuple[str, ...]:
    """Return exact nonplatform values; reject alternatives and unknown providers."""
    values: set[str] = set()
    for requirement in requirements:
        if requirement.kind == "platform":
            continue
        if len(requirement.acceptable_values) != 1:
            raise ValueError(f"ambiguous resource: {requirement.requirement_id}")
        value = requirement.acceptable_values[0]
        if value not in supported:
            raise ValueError(f"unsupported resource: {value}")
        values.add(value)
    return tuple(sorted(values))
