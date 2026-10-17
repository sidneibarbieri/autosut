from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from infrastructure.execution_handoff import ExecutionHandoff

PRODUCER_REVISION = "a" * 40
CONSUMER_REVISION = "b" * 40
CONTENT_HASH = "c" * 64


def handoff() -> ExecutionHandoff:
    record = ExecutionHandoff(
        experiment_id="comparison-1",
        campaign_id="C0010",
        seed=1,
        producer="external-planner",
        producer_revision=PRODUCER_REVISION,
        consumer="autosut",
        consumer_revision=CONSUMER_REVISION,
        procedural_plan_sha256=CONTENT_HASH,
        binding_catalog_sha256=CONTENT_HASH,
        action_catalog_sha256=CONTENT_HASH,
        execution_semantic_sha256=CONTENT_HASH,
    )
    record.finalize_hash()
    return record


def test_handoff_accepts_exact_consumer_and_revision() -> None:
    record = handoff()
    record.validate_for_consumer(consumer="autosut", revision=CONSUMER_REVISION)


def test_handoff_rejects_wrong_consumer_revision() -> None:
    with pytest.raises(ValueError, match="current consumer revision"):
        handoff().validate_for_consumer(consumer="autosut", revision="d" * 40)


def test_handoff_rejects_modified_content() -> None:
    payload = json.loads(handoff().model_dump_json())
    payload["seed"] = 2
    altered = ExecutionHandoff.model_validate(payload)
    with pytest.raises(ValueError, match="hash mismatch"):
        altered.validate_for_consumer(consumer="autosut", revision=CONSUMER_REVISION)
