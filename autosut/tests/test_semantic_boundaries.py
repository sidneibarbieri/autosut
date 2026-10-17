"""Semantic R4 boundaries describe observed runtime states, not function entry."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = PROJECT_ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from infrastructure.caldera_instance import CalderaInstance  # noqa: E402
from orchestrator.caldera_client import CalderaClient  # noqa: E402


def _caldera_experiment_module():
    spec = importlib.util.spec_from_file_location(
        "semantic_boundary_caldera_experiment", SCRIPTS / "run_caldera_experiment.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_readiness_boundary_is_emitted_before_the_first_real_probe(monkeypatch):
    events: list[str] = []
    instance = CalderaInstance(container_name="unused", host_port=1)
    monkeypatch.setattr(instance, "_landing_answers", lambda: events.append("probe") or True)

    instance.wait_until_ready(timeout_seconds=1, on_probe_started=lambda: events.append("boundary"))

    assert events == ["boundary", "probe"]


def test_enrollment_boundary_requires_a_real_empty_agent_query(monkeypatch):
    events: list[str] = []
    client = CalderaClient("http://invalid", "not-used", "not-used")
    monkeypatch.setattr(client, "list_agents", lambda: events.append("query") or [])

    result = client.wait_agent_registered(
        paw_substring="expected",
        max_seconds=0.01,
        poll_seconds=0,
        on_pending_poll=lambda: events.append("pending"),
    )

    assert result is None
    assert events[:2] == ["query", "pending"]


def test_semantic_boundary_writer_records_condition_and_nonsecret_evidence(tmp_path):
    module = _caldera_experiment_module()
    module._write_semantic_boundary(
        tmp_path,
        "enroll_agent",
        "enrollment_poll_active",
        {"sandcat_started": True, "matching_agent_registered": False},
    )

    path = tmp_path / "enroll_agent--enrollment_poll_active.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["stage"] == "enroll_agent"
    assert payload["condition"] == "enrollment_poll_active"
    assert payload["evidence"] == {
        "sandcat_started": True,
        "matching_agent_registered": False,
    }
