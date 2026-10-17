import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from evaluation.replay_audit import (  # noqa: E402
    ManifestCounts, ReplayAudit, ReplayObservation,
)


def _dashboard():
    specification = importlib.util.spec_from_file_location(
        "replay_dashboard_test", PROJECT_ROOT / "scripts/build_reviewer_dashboard.py"
    )
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


def test_dashboard_exposes_unqualified_audit_and_preserves_source_bytes(tmp_path):
    module = _dashboard()
    module.PROJECT_ROOT = tmp_path
    module.DATA_DIR = tmp_path / "dashboard/data"
    audit = ReplayAudit(
        source_report_name="report.json", source_report_sha256="a" * 64,
        records=(ReplayObservation(
            campaign_id="test", reported_status="PASS", reported_total=2,
            reported_successful=2, reported_evidence_backed=1, reported_markers=1,
            reported_caldera=0, reported_clean=True, elapsed_seconds=2,
            recorded_revision=None,
            manifest_counts=ManifestCounts(
                total=2, successful=2, evidence_backed_successful=1,
                marker_only_successful=1, caldera_driven_successful=0,
                inspired_execution_steps=1, steps_with_all_references_present=1,
            ),
            files=(), issues=("implementation_revision_not_recorded",),
        ),),
    )
    audit_file = tmp_path / "release" / module.REPLAY_AUDIT_FILE
    audit_file.parent.mkdir()
    audit_file.write_text(audit.model_dump_json(), encoding="utf-8")

    module.copy_replay_reports()
    html = module.render_replay_reports()

    assert "no current-revision qualification" in html
    assert "Marker-only steps" in html
    assert "Inspired execution steps" in html
    assert "0/1" in html
    assert "PASS" not in html
    assert (module.DATA_DIR / "replay_reports" / module.REPLAY_AUDIT_FILE).read_bytes() == audit_file.read_bytes()


def test_dashboard_keyboard_navigation_has_a_focusable_main_target():
    module = _dashboard()
    merged = SimpleNamespace(
        total_elements=1,
        percentages={"corpus_supported": 100.0, "external_reference": 0.0,
                     "autosut_concretized": 0.0, "analyst_authored": 0.0},
    )
    html = module.render_html(module.load_macros(), "", merged, module.load_claim_ledger())
    assert "<a class='skip-link' href='#main'>Skip to main content</a>" in html
    assert "<main id='main' tabindex='-1'>" in html
    assert ":focus-visible" in module.STYLE
    assert "prefers-reduced-motion: reduce" in module.STYLE


def test_invalid_audit_is_not_silently_hidden(tmp_path):
    module = _dashboard()
    module.PROJECT_ROOT = tmp_path
    audit_file = tmp_path / "release" / module.REPLAY_AUDIT_FILE
    audit_file.parent.mkdir()
    audit_file.write_text("{}", encoding="utf-8")

    with pytest.raises(ValidationError):
        module.render_replay_reports()


def test_dashboard_copies_contract_state_for_standalone_serving(tmp_path):
    module = _dashboard()
    module.PROJECT_ROOT = tmp_path
    module.DATA_DIR = tmp_path / "dashboard/data"
    module.AUDIT_DIR = tmp_path / "audit"
    module.AUDIT_DIR.mkdir()
    state = tmp_path / "results/CORPUS_STATE.md"
    state.parent.mkdir()
    state.write_text("# Contract state\nPending does not mean executed.\n", encoding="utf-8")
    module.copy_data_files()
    assert (module.DATA_DIR / state.name).read_bytes() == state.read_bytes()


def test_claim_ledger_renders_checked_relative_evidence_links(tmp_path):
    module = _dashboard()
    module.PROJECT_ROOT = tmp_path
    evidence = tmp_path / "release" / "experiments" / "witness.json"
    evidence.parent.mkdir(parents=True)
    evidence.write_text("{}\n", encoding="utf-8")
    ledger = {
        "claims": [
            {
                "claim_id": "WITNESS-01",
                "status": "supported_bounded",
                "claim": "A bounded witness was recorded.",
                "scope": "One controlled case.",
                "measured_value": {"runs": 1},
                "evidence_artifacts": ["release/experiments/witness.json"],
                "reproduction_command": "bash run_review_check.sh",
                "caveat": "It is not a population result.",
            }
        ],
        "blocked_interpretations": [
            {"claim": "universal execution", "reason": "The catalog is bounded."}
        ],
    }

    html = module.render_claim_ledger(ledger)

    assert "WITNESS-01" in html
    assert "supported_bounded" in html
    assert "../experiments/witness.json" in html
    assert "Not claimed:" in html


def test_claim_ledger_rejects_missing_or_unsafe_evidence_paths(tmp_path):
    module = _dashboard()
    module.PROJECT_ROOT = tmp_path

    with pytest.raises(FileNotFoundError):
        module._dashboard_href("release/experiments/missing.json")
    with pytest.raises(ValueError):
        module._dashboard_href("../outside.json")


def test_reviewer_path_links_to_the_regenerated_contract_state_report():
    module = _dashboard()
    merged = SimpleNamespace(
        total_elements=1,
        percentages={
            "corpus_supported": 100.0,
            "external_reference": 0.0,
            "autosut_concretized": 0.0,
            "analyst_authored": 0.0,
        },
    )
    ledger = {"claims": [{"status": "supported_bounded"}]}

    html = module.render_audit_overview(merged, ledger)

    assert "Inspect campaign/SUT contracts" in html
    assert "data/CORPUS_STATE.md" in html
    assert "outside the audited contract set" in html
