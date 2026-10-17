"""Application requirements select a compatible SUT runtime."""

import json
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from planning.campaign_pair import _declared_services  # noqa: E402
from planning.sut_blueprint import synthesize_blueprint  # noqa: E402
from planning.sut_constraints import SUTConstraintSet  # noqa: E402


def _constraints(campaign_id: str) -> SUTConstraintSet:
    path = PROJECT_ROOT / "release/prepared-pairs" / campaign_id / "sut-constraints.json"
    return SUTConstraintSet.model_validate_json(path.read_text(encoding="utf-8"))


def _services(campaign_id: str) -> set[str]:
    path = PROJECT_ROOT / "campaigns" / f"{campaign_id}.json"
    return _declared_services(json.loads(path.read_text(encoding="utf-8")))


def test_ray_service_selects_python_310_for_real_ray_jobs() -> None:
    blueprint = synthesize_blueprint(
        _constraints("0.shadowray"), services=_services("0.shadowray")
    )

    assert blueprint.hosts[0].recipe.base_image.startswith("python:3.10-slim@sha256:")


def test_other_campaign_keeps_default_runtime() -> None:
    blueprint = synthesize_blueprint(_constraints("0.c0010"), services=_services("0.c0010"))

    assert blueprint.hosts[0].recipe.base_image == "python:3.11-slim"
