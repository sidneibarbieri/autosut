"""Consumer-side models for the versioned STICKS procedural plan."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field


class ProceduralPlanSourceInput(BaseModel):
    """Pinned ATT&CK snapshot from which STICKS compiled the plan."""

    model_config = ConfigDict(extra="forbid")

    bundle_sha256: str
    object_count: int
    campaign_stix_id: str
    campaign_external_id: str


class ProcedureStepInput(BaseModel):
    """One STICKS procedure step, including its source relationship provenance."""

    model_config = ConfigDict(extra="forbid")

    technique_id: str
    technique_stix_id: str
    name: str
    execution_domain: str = "target"
    tactics: list[str] = Field(default_factory=list)
    platforms: list[str] = Field(default_factory=list)
    permissions_required: list[str] = Field(default_factory=list)
    system_requirements: list[str] = Field(default_factory=list)
    relationship_ids: list[str] = Field(min_length=1)
    procedure_descriptions: list[str] = Field(default_factory=list)


class ProceduralPlanInput(BaseModel):
    """Strict consumer schema for the versioned STICKS procedural-plan export.

    This model intentionally rejects unknown fields.  An upstream schema change must
    fail at the AutoSUT boundary rather than silently discard CTI provenance.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: str
    compiler_version: str
    campaign_id: str
    campaign_name: str
    source: ProceduralPlanSourceInput
    ordering_policy: str
    steps: list[ProcedureStepInput] = Field(min_length=1)
    limitations: list[str] = Field(default_factory=list)
    content_sha256: str


def load_procedural_plan(path: Path) -> ProceduralPlanInput:
    payload = json.loads(path.read_text(encoding="utf-8"))
    expected_hash = payload.get("content_sha256", "")
    hashed_payload = {key: value for key, value in payload.items() if key != "content_sha256"}
    encoded = json.dumps(hashed_payload, sort_keys=True, separators=(",", ":")).encode()
    actual_hash = hashlib.sha256(encoded).hexdigest()
    if actual_hash != expected_hash:
        raise ValueError(f"procedural plan hash mismatch: {path}")
    return ProceduralPlanInput.model_validate(payload)
