from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODULE_PATH = PROJECT_ROOT / "scripts" / "generate_corpus_state.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("autosut_generate_corpus_state", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_report_is_deterministic_contract_state_not_historical_execution() -> None:
    module = _load_module()

    report = module.build_report()
    serialized = json.dumps(report.model_dump(mode="json"), sort_keys=True)

    assert report.schema_version == "autosut-corpus-contract-state/v2"
    assert report.generated_at == "2026-07-18T00:00:00Z"
    assert report.totals.available_campaign_definitions == 25
    assert report.totals.campaigns_with_declared_sut_profile == 14
    assert report.totals.campaigns_with_strict_pair_validation == 12
    assert report.totals.campaigns_with_pair_validation_findings == 2
    assert report.totals.campaigns_with_bounded_dispatch_witness == 1
    assert report.bounded_dispatch_witness.campaign_id == "0.shadowray"
    assert "latest" not in serialized.lower()
    assert "success_rate" not in serialized
    assert "release/evidence" not in serialized


def test_main_writes_a_typed_static_report(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module = _load_module()
    json_output = tmp_path / "corpus_state.json"
    markdown_output = tmp_path / "CORPUS_STATE.md"
    monkeypatch.setattr(module, "OUTPUT_JSON", json_output)
    monkeypatch.setattr(module, "OUTPUT_MD", markdown_output)

    module.main()

    payload = json.loads(json_output.read_text(encoding="utf-8"))
    markdown = markdown_output.read_text(encoding="utf-8")
    assert payload["schema_version"] == "autosut-corpus-contract-state/v2"
    assert "Campaign/SUT Contract State" in markdown
    assert "success rate" in markdown
    assert "latest evidence" not in markdown.lower()


def test_missing_bounded_witness_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    module = _load_module()

    class BlockedAssessment:
        status = "blocked_execution_gate"
        witness = None
        failure_reason = "sealed evidence no longer validates"

    monkeypatch.setattr(
        module,
        "assess_caldera_dispatch_witness",
        lambda _: BlockedAssessment(),
    )

    with pytest.raises(RuntimeError, match="sealed evidence no longer validates"):
        module.build_report()
