from __future__ import annotations

import sys
from pathlib import Path

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "measurement" / "sut" / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import compatibility_policy_ablation as ablation  # noqa: E402
import sut_measurement_pipeline as pipeline  # noqa: E402


def _technique(platforms: list[str]) -> dict:
    return {"id": "attack-pattern--x", "name": "Benign Name", "description": "", "x_mitre_platforms": platforms}


@pytest.mark.parametrize(
    ("platforms", "container_rule", "label"),
    [
        (["Linux"], "subset", "CF"),
        (["Linux", "Windows"], "subset", "VMR"),
        (["Linux", "Windows"], "intersects", "CF"),
        (["Windows"], "intersects", "VMR"),
    ],
)
def test_container_rule_variants(platforms, container_rule, label) -> None:
    trace = pipeline.classify_technique_compatibility_trace(
        _technique(platforms), {}, {}, container_rule=container_rule
    )
    assert trace["class"] == label


def test_an_unknown_container_rule_is_rejected() -> None:
    with pytest.raises(ValueError, match="unknown container rule"):
        pipeline.classify_technique_compatibility_trace(_technique(["Linux"]), {}, {}, container_rule="any")


def _distribution(policy: str, cf: int, explicit: int, identity: int, total: int = 10):
    return ablation.PolicyDistribution(
        policy=policy, total=total, cf_count=cf, vmr_count=total - cf - identity, id_count=identity,
        unresolved_count=0, explicit_count=explicit, cf_pct=0.0, unresolved_pct=0.0,
    )


def test_a_conclusion_is_robust_only_when_every_policy_supports_it() -> None:
    distributions = [
        _distribution("strict", cf=1, explicit=3, identity=2),
        _distribution("current", cf=1, explicit=3, identity=2),
        _distribution("linux_admissible", cf=6, explicit=3, identity=2),
        _distribution("cf_floor", cf=8, explicit=3, identity=2),
    ]
    checks = {check.conclusion: check for check in ablation.check_conclusions(distributions)}
    assert checks["cf_minority"].fails_under == ["linux_admissible"]
    assert not checks["cf_minority"].robust
    assert checks["explicit_evidence_minority"].robust
    assert checks["id_policy_independent"].robust


def test_policies_are_declared_with_distinct_names() -> None:
    names = [policy.name for policy in ablation.POLICIES]
    assert len(names) == len(set(names))
    assert {"strict", "current", "linux_admissible"} <= set(names)
