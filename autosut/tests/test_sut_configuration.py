"""Provenance of proposed SUT configuration values.

The measured constraints reach a platform family and, where a curated rule applies, a product.
A deployable configuration needs more than that, and these tests pin how the extra values are
classified: by comparing the proposal against the measured constraints, never by trusting what
the proposer says about its own output.
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from planning.sut_configuration import (  # noqa: E402
    ConfiguredService,
    SutConfigurationProposal,
    ValueProvenance,
    classify_proposal,
)
from planning.sut_constraints import EnvironmentRequirement, RequirementSource  # noqa: E402


def _platform_requirement(*values: str) -> EnvironmentRequirement:
    return EnvironmentRequirement(
        requirement_id="req.platform",
        kind="platform",
        acceptable_values=list(values),
        technique_ids=["T1190"],
        source=RequirementSource.stix_field,
        rationale="platform tags on the campaign's techniques",
    )


def _proposal(**service_fields: str) -> SutConfigurationProposal:
    return SutConfigurationProposal(
        campaign_id="C0045",
        proposer="model.1",
        platform=service_fields.pop("platform", "Linux"),
        services=[ConfiguredService(host_role="public-service", **service_fields)],
    )


def test_a_measured_value_is_attributed_to_the_intelligence():
    verdict = classify_proposal(
        _proposal(product="Ray"), [_platform_requirement("Linux")], deployment_catalog=set()
    )
    platform = next(item for item in verdict.classified_values if item.field_name == "platform")
    assert platform.provenance is ValueProvenance.cti_evidenced


def test_a_version_and_port_are_attributed_to_the_proposer():
    verdict = classify_proposal(
        _proposal(product="Ray", version="2.6.3", port="8265"),
        [_platform_requirement("Linux")],
        deployment_catalog={"Ray"},
    )
    introduced = {
        item.field_name
        for item in verdict.classified_values
        if item.provenance is ValueProvenance.proposer_introduced
    }
    # The constraints reach the product at most; the values that decide whether an exploit
    # applies are supplied by the proposer.
    assert {"version", "port"} <= introduced


def test_a_catalog_product_is_not_counted_as_intelligence():
    verdict = classify_proposal(
        _proposal(product="Ray"), [_platform_requirement("Linux")], deployment_catalog={"Ray"}
    )
    product = next(item for item in verdict.classified_values if item.field_name == "product")
    assert product.provenance is ValueProvenance.catalog_supplied


def test_an_unmet_requirement_is_reported_rather_than_ignored():
    verdict = classify_proposal(
        _proposal(platform="Windows", product="IIS"),
        [_platform_requirement("Linux")],
        deployment_catalog=set(),
    )
    assert verdict.unsatisfied_requirement_ids == ["req.platform"]
    assert verdict.satisfies_all_requirements is False


def test_empty_fields_do_not_inflate_the_denominator():
    verdict = classify_proposal(
        _proposal(product="Ray", version="", port="  "),
        [_platform_requirement("Linux")],
        deployment_catalog={"Ray"},
    )
    assert {item.field_name for item in verdict.classified_values} == {"platform", "product"}


def test_provenance_counts_occurrences_not_distinct_values():
    proposal = SutConfigurationProposal(
        campaign_id="C0045",
        proposer="model.1",
        platform="Linux",
        services=[
            ConfiguredService(host_role="a", product="Ray", port="8265"),
            ConfiguredService(host_role="b", product="Ray", port="8265"),
        ],
    )
    counts = classify_proposal(
        proposal, [_platform_requirement("Linux")], deployment_catalog={"Ray"}
    ).provenance_counts()
    # Two hosts running the same product are two deployment commitments, not one.
    assert counts["catalog_supplied"] == 2
    assert counts["proposer_introduced"] == 2
