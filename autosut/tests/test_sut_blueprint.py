from __future__ import annotations

import sys
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from planning.sut_blueprint import synthesize_blueprint
from planning.sut_constraints import PlatformResolution, SUTConstraintSet


def _constraints(*, complete: bool) -> SUTConstraintSet:
    constraints = SUTConstraintSet(
        campaign_id="C0045",
        source_plan_sha256="plan",
        platform_resolution=PlatformResolution(
            selected_platforms=["Linux"],
            materializable_platforms=["Linux"],
            unsupported_platforms=[] if complete else ["Windows"],
            uncovered_technique_ids=[] if complete else ["T1059.001"],
            complete=complete,
        ),
        requirements=[],
    )
    constraints.finalize_hash()
    return constraints


def test_synthesizer_builds_isolated_minimal_witness() -> None:
    blueprint = synthesize_blueprint(_constraints(complete=True))

    assert len(blueprint.hosts) == 1
    assert blueprint.hosts[0].recipe.backend == "docker"
    assert not blueprint.network_policy.host_network_access
    assert not blueprint.network_policy.internet_egress


def test_synthesizer_rejects_incomplete_constraints() -> None:
    with pytest.raises(ValueError, match="incomplete constraints"):
        synthesize_blueprint(_constraints(complete=False))
