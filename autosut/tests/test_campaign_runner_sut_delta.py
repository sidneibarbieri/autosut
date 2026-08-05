from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


PROJECT_ROOT = Path(__file__).resolve().parent.parent
RUNNER_PATH = PROJECT_ROOT / "src" / "runners" / "campaign_runner.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("campaign_runner_sut_delta", RUNNER_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_execute_step_records_step_conditioned_sut_delta(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = _load_module()

    monkeypatch.setattr(module, "bootstrap_campaign_executors", lambda campaign_id: None)
    monkeypatch.setattr(
        module,
        "apply_step_sut_delta",
        lambda **kwargs: {
            "target_hosts": ["target-base"],
            "applied": ["declared:exposed_ray_jobs_api", "service:ray-dashboard"],
            "errors": [],
            "results": [],
            "notes": "Expose the Ray boundary before T1190.",
        },
    )
    monkeypatch.setattr(
        module,
        "execute_technique",
        lambda **kwargs: SimpleNamespace(
            status="success",
            execution_mode="real_controlled",
            execution_fidelity="adapted",
            fidelity_justification="Technique executed after declared SUT conditioning.",
            artifacts_created=["target-vm:/tmp/shadowray.txt"],
            prerequisites_consumed=["access:initial"],
            capabilities_produced=["code_execution"],
            stdout="executed inside target VM",
            stderr="",
        ),
    )
    monkeypatch.setattr(module.registry, "get_metadata", lambda technique_id: None)
    monkeypatch.setattr(module, "resolve_target_vm_name", lambda campaign_id: "target-linux-1")

    runner = module.UnifiedCampaignRunner("0.shadowray", tmp_path)
    runner._infrastructure_provider = "qemu"

    step = runner.campaign.steps[0]
    evidence = runner._execute_step(step)

    assert evidence.status == "success"
    assert evidence.host == "target-linux-1"
    assert evidence.sut_adjustment_errors == []
    assert evidence.sut_adjustments_applied == [
        "declared:exposed_ray_jobs_api",
        "service:ray-dashboard",
    ]


def test_execute_step_fails_fast_when_sut_delta_application_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = _load_module()

    monkeypatch.setattr(module, "bootstrap_campaign_executors", lambda campaign_id: None)
    monkeypatch.setattr(
        module,
        "apply_step_sut_delta",
        lambda **kwargs: {
            "target_hosts": ["target-base"],
            "applied": ["service:ray-dashboard"],
            "errors": ["Failed to configure service ray-dashboard"],
            "results": [],
            "notes": "Expose the Ray boundary before T1190.",
        },
    )

    execute_calls: list[dict] = []

    def fake_execute_technique(**kwargs):
        execute_calls.append(kwargs)
        raise AssertionError("execute_technique should not be called after SUT delta failure")

    monkeypatch.setattr(module, "execute_technique", fake_execute_technique)
    monkeypatch.setattr(module.registry, "get_metadata", lambda technique_id: None)

    runner = module.UnifiedCampaignRunner("0.shadowray", tmp_path)
    runner._infrastructure_provider = "qemu"

    step = runner.campaign.steps[0]
    evidence = runner._execute_step(step)

    assert evidence.status == "failed"
    assert execute_calls == []
    assert evidence.sut_adjustments_applied == ["service:ray-dashboard"]
    assert evidence.sut_adjustment_errors == ["Failed to configure service ray-dashboard"]
    assert "SUT delta application failed" in evidence.stderr
