from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODULE_PATH = PROJECT_ROOT / "src" / "utils" / "cve_resolution.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("sticks_cve_resolution", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_resolution_summary_marks_shadowray_as_open_package_candidate() -> None:
    module = _load_module()
    summary = module.resolve_campaign_cves(
        rules_path=PROJECT_ROOT / "data" / "cve_resolution_rules.yml",
        campaign_cves_path=PROJECT_ROOT
        / "measurement"
        / "sut"
        / "scripts"
        / "results"
        / "audit"
        / "campaign_cves.csv",
        campaign_structure_path=PROJECT_ROOT
        / "measurement"
        / "sut"
        / "scripts"
        / "results"
        / "audit"
        / "campaign_factual_structure.csv",
        attack_bundle_path=PROJECT_ROOT
        / "measurement"
        / "sut"
        / "scripts"
        / "data"
        / "enterprise-attack.json",
    )

    row = next(
        item
        for item in summary.rows
        if item.campaign_name == "ShadowRay" and item.cve_id == "CVE-2023-48022"
    )

    assert row.resolution_kind == "open_package"
    assert row.ecosystem == "pip"
    assert row.package_name == "ray"
    assert row.automatic_sut_support is True
    assert row.overlay_template == "ray_jobs_api_exposure"
    assert row.attck_binding_status == "cve_only_curated_binding"
    assert row.source_basis == "NVD CVE record plus PyPI package metadata and release tags"
    assert "https://nvd.nist.gov/vuln/detail/CVE-2023-48022" in row.evidence_sources
    assert "https://pypi.org/project/ray/" in row.evidence_sources


def test_resolution_summary_counts_only_one_automatic_campaign() -> None:
    module = _load_module()
    summary = module.resolve_campaign_cves(
        rules_path=PROJECT_ROOT / "data" / "cve_resolution_rules.yml",
        campaign_cves_path=PROJECT_ROOT
        / "measurement"
        / "sut"
        / "scripts"
        / "results"
        / "audit"
        / "campaign_cves.csv",
        campaign_structure_path=PROJECT_ROOT
        / "measurement"
        / "sut"
        / "scripts"
        / "results"
        / "audit"
        / "campaign_factual_structure.csv",
        attack_bundle_path=PROJECT_ROOT
        / "measurement"
        / "sut"
        / "scripts"
        / "data"
        / "enterprise-attack.json",
    )

    assert summary.totals.total_cve_positive_campaigns == 5
    assert summary.totals.total_campaign_cve_pairs == 8
    assert summary.totals.automatic_candidate_pairs == 1
    assert summary.totals.automatic_candidate_campaigns == 1
    assert summary.totals.direct_attck_binding_pairs == 0
    assert summary.totals.open_package_pairs == 1
    assert summary.totals.open_package_campaigns == 1


def test_markdown_report_states_scope_and_source_provenance() -> None:
    module = _load_module()
    summary = module.resolve_campaign_cves(
        rules_path=PROJECT_ROOT / "data" / "cve_resolution_rules.yml",
        campaign_cves_path=PROJECT_ROOT
        / "measurement"
        / "sut"
        / "scripts"
        / "results"
        / "audit"
        / "campaign_cves.csv",
        campaign_structure_path=PROJECT_ROOT
        / "measurement"
        / "sut"
        / "scripts"
        / "results"
        / "audit"
        / "campaign_factual_structure.csv",
        attack_bundle_path=PROJECT_ROOT
        / "measurement"
        / "sut"
        / "scripts"
        / "data"
        / "enterprise-attack.json",
    )

    markdown = module.markdown_report(summary)

    assert "It is not an exhaustive crawl of the `apt` or `pip` ecosystems" in markdown
    assert "Automatically supported `pip` pairs: `1`" in markdown
    assert "Automatically supported `apt` pairs: `0`" in markdown
    assert "## Automatic-Path Source URLs" in markdown
