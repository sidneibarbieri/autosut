"""Unit tests for provenance aggregation (S29/S30).

These verify the pure tally contract of ``orchestrator.provenance``: given a
SUTProfile whose elements carry deliberate ProvenanceSource tags, the summary
counts them by source and by dimension, computes percentages, flattens them
into a stable per-element audit list, merges across campaigns, and exports a
dimension x source support matrix. No live run, no Docker — pure data.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Make the orchestrator package importable from tests/.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from orchestrator.models import (  # noqa: E402
    ApplicationStack, Credential, CVEInjection, FidelityLevel, NetworkExposure,
    ProvenanceSource, Realization, StagedArtifact, SUTComposition, SUTHost,
    SUTProfile, Topology, Zone,
)
from orchestrator.provenance import (  # noqa: E402
    DIMENSIONS, collect_elements, merge_summaries, summarize_profile,
    support_matrix_rows,
)


def _sample_profile() -> SUTProfile:
    """Multi-host + topology profile with one tag per source, every dimension."""
    target = SUTComposition(
        applications=[
            ApplicationStack(
                name="apache_httpd", version="2.4.49",
                recipe="apache_httpd_2.4.49_cve_2021_41773",
                cve_pins=["CVE-2021-41773"],
                source=ProvenanceSource.corpus_supported,
            ),
        ],
        credentials=[
            Credential(kind="password", user="vulnuser", secret="x",
                       source=ProvenanceSource.analyst_authored),
            Credential(kind="api_token", user="api", secret="LAB-TOKEN",
                       source=ProvenanceSource.autosut_concretized),
        ],
        exposures=[
            NetworkExposure(port=80, service="http",
                            source=ProvenanceSource.corpus_supported),
            NetworkExposure(port=8443, service="mgmt",
                            source=ProvenanceSource.inferred),
        ],
        artifacts=[
            StagedArtifact(path="/tmp/decoy.txt", content_text="x",
                           source=ProvenanceSource.analyst_authored),
        ],
    )
    return SUTProfile(
        sut_id="sample", base_image="httpd:2.4.49",
        hosts=[
            SUTHost(name="target", base_image="httpd:2.4.49",
                    platform_source=ProvenanceSource.corpus_supported,
                    composition=target),
            SUTHost(name="attacker", base_image="alpine:3.19",
                    platform_source=ProvenanceSource.corpus_supported),
        ],
        topology=Topology(zones=[
            Zone(name="dmz", source=ProvenanceSource.analyst_authored),
            Zone(name="enterprise", source=ProvenanceSource.analyst_authored),
        ]),
    )


def test_by_source_counts_and_percentages():
    summary = summarize_profile(_sample_profile(), campaign_id="0.sample")

    assert summary.campaign_id == "0.sample"
    # 2 platform (one per host, auto-emitted) + 6 composition + 2 topology = 10.
    assert summary.total_elements == 10
    assert summary.by_source == {
        # corpus = apache software + port 80 exposure + 2 host platforms.
        "corpus_supported": 4,
        "external_reference": 0,
        # analyst = vulnuser cred + decoy artifact + 2 topology zones.
        "analyst_authored": 4,
        "autosut_concretized": 1,
        "inferred": 1,
    }
    assert summary.percentages == {
        "corpus_supported": 40.0,
        "external_reference": 0.0,
        "analyst_authored": 40.0,
        "autosut_concretized": 10.0,
        "inferred": 10.0,
    }


def test_by_dimension_breakdown():
    summary = summarize_profile(_sample_profile())

    assert set(summary.by_dimension) == set(DIMENSIONS)
    # Both hosts' base images map to the linux OS family (ATT&CK platform),
    # which is definitional corpus evidence — derived, not analyst-tagged.
    assert summary.by_dimension["platform"]["corpus_supported"] == 2
    assert summary.by_dimension["software"]["corpus_supported"] == 1
    assert summary.by_dimension["credentials"]["analyst_authored"] == 1
    assert summary.by_dimension["credentials"]["autosut_concretized"] == 1
    assert summary.by_dimension["exposures"]["corpus_supported"] == 1
    assert summary.by_dimension["exposures"]["inferred"] == 1
    assert summary.by_dimension["artifacts"]["analyst_authored"] == 1
    assert summary.by_dimension["topology"]["analyst_authored"] == 2


def test_vulnerability_dimension_uses_declared_provenance():
    # Identifier syntax does not determine provenance.  The declaration must
    # distinguish evaluated-corpus evidence from an AutoSUT-only surrogate.
    cves = [
        CVEInjection(
            cve_id="CVE-2021-41773", target_software="apache_httpd",
            target_version="2.4.49", fidelity=FidelityLevel.adapted,
            realization=Realization.real_cve, install_recipe="recipe",
            source=ProvenanceSource.corpus_supported,
        ),
        CVEInjection(
            cve_id="N/A", target_software="custom_app",
            fidelity=FidelityLevel.inspired, realization=Realization.surrogate,
            install_recipe="recipe",
            source=ProvenanceSource.autosut_concretized,
        ),
    ]
    summary = summarize_profile(
        SUTProfile(sut_id="vuln", base_image="alpine:3.19"), cves=cves
    )

    vuln = summary.by_dimension["vulnerability"]
    assert vuln["corpus_supported"] == 1
    assert vuln["autosut_concretized"] == 1
    ids = [e.identifier for e in summary.elements if e.dimension == "vulnerability"]
    assert ids == ["vulnerability.CVE-2021-41773", "vulnerability.N/A"]


def test_element_flattening_is_ordered_and_host_attributed():
    elements = collect_elements(_sample_profile())

    assert len(elements) == 10
    # Hosts walked in declaration order; within a host: platform first, then
    # the composition (apps, creds, exposures, artifacts). Topology zones come
    # last (SUT-level, no host).
    assert elements[0].identifier == "target.platform.linux"
    assert elements[0].host == "target"
    assert elements[0].source is ProvenanceSource.corpus_supported
    assert elements[1].identifier == "target.software.apache_httpd@2.4.49"
    assert elements[1].dimension == "software"
    assert elements[-1].dimension == "topology"
    assert elements[-1].host is None
    assert elements[-1].identifier == "topology.zone.enterprise"


def test_determinism_same_profile_same_elements():
    a = collect_elements(_sample_profile())
    b = collect_elements(_sample_profile())
    assert [e.identifier for e in a] == [e.identifier for e in b]


def test_merge_summaries_rolls_up_across_campaigns():
    s1 = summarize_profile(_sample_profile(), campaign_id="a")
    s2 = summarize_profile(_sample_profile(), campaign_id="b")
    merged = merge_summaries([s1, s2])

    assert merged.campaign_id == "ALL"
    assert merged.total_elements == 20
    assert merged.by_source["analyst_authored"] == 8
    assert merged.percentages["analyst_authored"] == 40.0


def test_support_matrix_rows_one_per_dimension():
    summary = summarize_profile(_sample_profile())
    rows = support_matrix_rows(summary)

    assert [r["dimension"] for r in rows] == list(DIMENSIONS)
    topology_row = next(r for r in rows if r["dimension"] == "topology")
    assert topology_row["total"] == 2
    assert topology_row["analyst_authored"] == 2
    assert topology_row["corpus_supported"] == 0


def test_minimal_profile_emits_only_platform():
    # A profile with just a base image (no composition, no topology) still
    # yields exactly one element: the platform, derived from the image.
    summary = summarize_profile(
        SUTProfile(sut_id="empty", base_image="alpine:3.19")
    )
    assert summary.total_elements == 1
    assert summary.by_dimension["platform"]["analyst_authored"] == 1
    assert summary.percentages["corpus_supported"] == 0.0
    assert summary.percentages["analyst_authored"] == 100.0


def test_merge_empty_list_is_div_zero_safe():
    # The only path to a genuinely empty tally is merging nothing; percentages
    # must not raise ZeroDivisionError and must report 0.0 across all sources.
    merged = merge_summaries([])
    assert merged.total_elements == 0
    assert all(pct == 0.0 for pct in merged.percentages.values())
