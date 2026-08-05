from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODULE_PATH = PROJECT_ROOT / "src" / "utils" / "infra_automation.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("sticks_infra_automation", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_infra_automation_summary_counts_current_published_subset() -> None:
    sys.path.insert(0, str((PROJECT_ROOT / "src").resolve()))
    sys.path.insert(0, str(PROJECT_ROOT.resolve()))

    from loaders.campaign_loader import (  # type: ignore
        list_campaigns,
        list_sut_profiles,
        load_campaign,
        load_sut_profile,
        validate_campaign_sut_pair,
    )
    from scripts.generate_corpus_state import latest_summary  # type: ignore

    module = _load_module()
    campaign_ids = sorted(set(list_campaigns()) & set(list_sut_profiles()))
    summary = module.build_infra_automation_summary(
        project_root=PROJECT_ROOT,
        campaign_ids=campaign_ids,
        load_campaign=load_campaign,
        load_sut_profile=load_sut_profile,
        validate_campaign_sut_pair=validate_campaign_sut_pair,
        latest_summary=latest_summary,
    )

    assert summary.totals.published_campaigns == 14
    assert summary.totals.campaigns_with_strict_pair_validation == 12
    assert summary.totals.campaigns_with_base_weaknesses == 14
    assert summary.totals.campaigns_with_step_overlays == 1
    # After the S21 evidence-hygiene sweep, only canonical golden runs
    # live at the evidence root. Non-golden runs (partial, empty, broken,
    # pre-final-orchestrator) are under release/evidence/_archive/ so the
    # campaigns_with_latest_evidence count reflects the strict golden
    # subset rather than every historical run. See release/golden_runs.json.
    assert summary.totals.campaigns_with_latest_evidence >= 1
    assert summary.totals.campaigns_with_single_target_host == 14
    assert summary.totals.campaigns_with_multi_target_host == 0
    assert summary.totals.campaigns_with_multi_vm_runtime == 14


def test_infra_automation_supports_multi_target_topology_classification() -> None:
    module = _load_module()

    class _Delta:
        def __init__(self):
            self.services = []
            self.files = []
            self.deliberate_weaknesses = []

    class _Step:
        def __init__(self, sut_delta):
            self.sut_delta = sut_delta

    class _Campaign:
        def __init__(self):
            self.sut_profile_id = "demo"
            self.steps = [_Step(None), _Step(_Delta())]

    class _Host:
        def __init__(self):
            self.services = []
            self.users = []
            self.files = []
            self.deliberate_weaknesses = []

    class _SUT:
        def __init__(self):
            self.required_vms = ["caldera", "attacker", "target-base", "target-secondary"]
            self.extra_vms = []
            self.min_hosts = 4
            self.hosts = {"target-base": _Host(), "target-secondary": _Host()}

    summary = module.build_infra_automation_summary(
        project_root=PROJECT_ROOT,
        campaign_ids=["demo"],
        load_campaign=lambda _: _Campaign(),
        load_sut_profile=lambda _: _SUT(),
        validate_campaign_sut_pair=lambda _: None,
        latest_summary=lambda _: None,
    )
    row = summary.rows[0]

    assert row.target_host_count == 2
    assert row.topology_kind == "multi_target"
    assert row.runtime_vm_count == 4
    assert row.declared_runtime_vms == [
        "caldera",
        "attacker",
        "target-linux-1",
        "target-linux-2",
    ]
