from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "measurement" / "sut" / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import nvd_enrichment  # noqa: E402

CVE = "CVE-2099-0001"


def _record(matches: list[dict], operator: str = "OR", privileges: str = "NONE") -> dict:
    return {
        "configurations": [{"nodes": [{"operator": operator, "cpeMatch": matches}]}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"attackVector": "NETWORK", "privilegesRequired": privileges, "userInteraction": "NONE"}}]},
    }


def _match(criteria: str, **bounds: str) -> dict:
    return {"vulnerable": True, "criteria": criteria, **bounds}


def _bundle(*objects: dict) -> dict:
    return {"objects": list(objects)}


EXPOSED_TECHNIQUE = {"type": "attack-pattern", "id": "attack-pattern--x", "external_references": [{"source_name": "mitre-attack", "external_id": "T1190"}]}
CAMPAIGN = {"type": "campaign", "id": "campaign--a", "description": f"Exploited {CVE}."}
USES_EXPOSED = {"type": "relationship", "relationship_type": "uses", "id": "relationship--1", "source_ref": "campaign--a", "target_ref": "attack-pattern--x"}


def test_cti_without_a_product_field_names_no_product_but_nvd_does() -> None:
    record = _record([_match("cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*", versionEndExcluding="2.0")])
    report = nvd_enrichment.build_report(_bundle(CAMPAIGN), {CVE: "freetext_only"}, {CVE: record})
    named = report.dimensions[0]
    assert (named.structured_cti, named.cti_plus_nvd) == (0, 1)
    assert report.rows[0].nvd_version_bounded


def test_a_campaign_using_an_exposed_service_technique_implies_exposure() -> None:
    record = _record([_match("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*")])
    report = nvd_enrichment.build_report(
        _bundle(CAMPAIGN, EXPOSED_TECHNIQUE, USES_EXPOSED), {CVE: "freetext_only"}, {CVE: record}
    )
    assert report.rows[0].cti_implies_exposure


def test_a_single_exact_version_without_a_platform_is_a_unique_deployment() -> None:
    exact = _record([_match("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*")])
    ranged = _record([_match("cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*", versionEndExcluding="2.0")])
    on_platform = _record([_match("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*")], operator="AND")
    assert nvd_enrichment.build_report(_bundle(CAMPAIGN), {CVE: "s"}, {CVE: exact}).unique_deployment_after_nvd == 1
    assert nvd_enrichment.build_report(_bundle(CAMPAIGN), {CVE: "s"}, {CVE: ranged}).unique_deployment_after_nvd == 0
    assert nvd_enrichment.build_report(_bundle(CAMPAIGN), {CVE: "s"}, {CVE: on_platform}).unique_deployment_after_nvd == 0


def test_topology_is_never_resolved() -> None:
    record = _record([_match("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*")])
    topology = nvd_enrichment.build_report(_bundle(CAMPAIGN), {CVE: "s"}, {CVE: record}).dimensions[-1]
    assert (topology.structured_cti, topology.cti_plus_nvd) == (0, 0)


def test_an_empty_population_is_refused() -> None:
    with pytest.raises(ValueError, match="no CVEs"):
        nvd_enrichment.build_report(_bundle(), {}, {})


def test_the_pinned_snapshot_reproduces_the_frozen_report() -> None:
    frozen = (SCRIPTS_DIR / "results" / "nvd_enrichment.json").read_text(encoding="utf-8")
    sources = nvd_enrichment.load_sources()
    bundle = json.loads(nvd_enrichment.BUNDLE.read_text(encoding="utf-8"))
    report = nvd_enrichment.build_report(bundle, sources, nvd_enrichment.load_records(sources))
    assert report.model_dump_json(indent=2) + "\n" == frozen
