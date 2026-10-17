from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from src.planning.procedural_plan import load_procedural_plan

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PROCEDURAL_PLAN_PATH = (
    PROJECT_ROOT / "release" / "inputs" / "sticks" / "c0045-v1" / "C0045.procedural-plan.json"
)


def _with_hash(payload: dict) -> dict:
    hashed_payload = {key: value for key, value in payload.items() if key != "content_sha256"}
    payload["content_sha256"] = hashlib.sha256(
        json.dumps(hashed_payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return payload


def test_loader_round_trips_sticks_procedure_provenance() -> None:
    payload = json.loads(PROCEDURAL_PLAN_PATH.read_text(encoding="utf-8"))

    plan = load_procedural_plan(PROCEDURAL_PLAN_PATH)

    first_payload_step = payload["steps"][0]
    first_step = plan.steps[0]
    assert first_step.technique_stix_id == first_payload_step["technique_stix_id"]
    assert first_step.relationship_ids == first_payload_step["relationship_ids"]
    assert first_step.procedure_descriptions == first_payload_step["procedure_descriptions"]
    assert plan.source.model_dump(mode="json") == payload["source"]
    assert plan.model_dump(mode="json") == payload


def test_loader_rejects_unknown_step_fields_instead_of_silently_dropping_them(
    tmp_path: Path,
) -> None:
    payload = json.loads(PROCEDURAL_PLAN_PATH.read_text(encoding="utf-8"))
    payload["steps"][0]["unmodeled_provenance"] = "must fail loudly"
    invalid_path = tmp_path / "invalid.procedural-plan.json"
    invalid_path.write_text(
        json.dumps(_with_hash(payload), indent=2) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValidationError, match="unmodeled_provenance"):
        load_procedural_plan(invalid_path)


def test_loader_requires_relationship_provenance_for_each_procedure_step(
    tmp_path: Path,
) -> None:
    payload = json.loads(PROCEDURAL_PLAN_PATH.read_text(encoding="utf-8"))
    del payload["steps"][0]["relationship_ids"]
    invalid_path = tmp_path / "missing-relationship.procedural-plan.json"
    invalid_path.write_text(
        json.dumps(_with_hash(payload), indent=2) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValidationError, match="relationship_ids"):
        load_procedural_plan(invalid_path)
