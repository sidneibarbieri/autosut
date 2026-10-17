#!/usr/bin/env python3
"""Fail if legacy multi-campaign evidence can be mistaken for current qualification."""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

PROJECT_ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_DIR = PROJECT_ROOT / "release" / "experiments" / "multi_campaign"


class HistoricalStatus(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str
    classification: str
    claim_eligible: bool
    applies_to_current_revision: bool
    records: list[str] = Field(min_length=1)
    reasons: list[str] = Field(min_length=1)


def main() -> int:
    status = HistoricalStatus.model_validate_json(
        (EVIDENCE_DIR / "STATUS.json").read_text(encoding="utf-8")
    )
    if status.schema_version != "autosut-historical-evidence-status/v1":
        raise ValueError("historical evidence status has an unsupported schema")
    if status.classification != "historical_non_qualifying":
        raise ValueError("legacy evidence must be classified as historical_non_qualifying")
    if status.claim_eligible or status.applies_to_current_revision:
        raise ValueError("legacy evidence cannot be eligible or apply to the current revision")
    discovered = sorted(
        path.name for path in EVIDENCE_DIR.glob("*.json") if path.name != "STATUS.json"
    )
    if sorted(status.records) != discovered:
        raise ValueError("historical evidence status does not account for every JSON record")
    for name in status.records:
        payload = json.loads((EVIDENCE_DIR / name).read_text(encoding="utf-8"))
        if "implementation_revision" in payload:
            raise ValueError(f"historical record unexpectedly claims a revision: {name}")
    print(f"[historical-evidence] {len(status.records)} records are explicitly non-qualifying")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
