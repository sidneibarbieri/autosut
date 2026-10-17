"""A resource probe admits only declared resources it can observe."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from planning.corpus_probe_admission import admitted_resource_values
from planning.sut_constraints import EnvironmentRequirement, RequirementSource


def _requirement(value: str) -> EnvironmentRequirement:
    return EnvironmentRequirement(
        requirement_id="T1105.network",
        kind="network",
        acceptable_values=[value],
        technique_ids=["T1105"],
        source=RequirementSource.curated_rule,
        rationale="synthetic test",
    )


def test_ingress_resource_is_admitted_by_its_explicit_value() -> None:
    assert admitted_resource_values(
        [_requirement("controlled-ingress-channel")],
        supported=frozenset({"controlled-ingress-channel"}),
    ) == ("controlled-ingress-channel",)


def test_unknown_resource_is_rejected() -> None:
    with pytest.raises(ValueError, match="unsupported resource"):
        admitted_resource_values(
            [_requirement("arbitrary-host-command")],
            supported=frozenset({"controlled-ingress-channel"}),
        )


def test_alternative_resource_values_require_explicit_choice() -> None:
    requirement = _requirement("controlled-ingress-channel")
    requirement.acceptable_values.append("private-lab-http-target")
    with pytest.raises(ValueError, match="ambiguous resource"):
        admitted_resource_values(
            [requirement],
            supported=frozenset({"controlled-ingress-channel"}),
        )
