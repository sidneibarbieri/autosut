"""Generic, revision-bound contract for receiving an external procedural plan."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

SHA256_PATTERN = r"^[0-9a-f]{64}$"
GIT_REVISION_PATTERN = r"^[0-9a-f]{40}$"


def canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class ExecutionHandoff(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "1"
    experiment_id: str = Field(min_length=1)
    campaign_id: str = Field(min_length=1)
    seed: int
    producer: str = Field(min_length=1)
    producer_revision: str = Field(pattern=GIT_REVISION_PATTERN)
    consumer: str = Field(min_length=1)
    consumer_revision: str = Field(pattern=GIT_REVISION_PATTERN)
    contract: str = "execution_handoff.v1"
    procedural_plan_sha256: str = Field(pattern=SHA256_PATTERN)
    binding_catalog_sha256: str = Field(pattern=SHA256_PATTERN)
    action_catalog_sha256: str = Field(pattern=SHA256_PATTERN)
    execution_semantic_sha256: str = Field(pattern=SHA256_PATTERN)
    content_sha256: str = ""

    def finalize_hash(self) -> None:
        self.content_sha256 = canonical_sha256(
            self.model_dump(mode="json", exclude={"content_sha256"})
        )

    def validate_hash(self) -> bool:
        expected = self.content_sha256
        self.finalize_hash()
        return bool(expected) and self.content_sha256 == expected

    def validate_for_consumer(self, *, consumer: str, revision: str) -> None:
        if not self.validate_hash():
            raise ValueError("execution handoff hash mismatch")
        if self.consumer != consumer:
            raise ValueError(f"execution handoff targets {self.consumer}, not {consumer}")
        if self.consumer_revision != revision:
            raise ValueError("execution handoff does not target the current consumer revision")
