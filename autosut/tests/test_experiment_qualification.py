"""The full-experiment level is derived from clean runs that each confirmed the effect.

Five clean, effect-confirmed runs reach reproducible; fewer clean runs, or clean runs without a
confirmed effect, do not. The realization is carried through so a surrogate service is never read
as a real-CVE effect.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from infrastructure.capability import CapabilityLevel  # noqa: E402
from infrastructure.experiment_qualification import summarize  # noqa: E402
from infrastructure.qualification import (  # noqa: E402
    EligibilityExclusionReason,
    EvidenceEligibilityPolicy,
    ExecutionMode,
    supervised_final_policy,
)


def _bundle(
    tmp_path,
    label,
    final_state,
    effect,
    seconds=200.0,
    realization="surrogate",
    revision="rev-abc",
    topology=None,
):
    bundle = tmp_path / f"shadowray_caldera_{label}"
    bundle.mkdir()
    (bundle / "lifecycle-result.json").write_text(
        json.dumps(
            {
                "label": label,
                "run_id": f"{label}-id",
                "final_state": final_state,
                "total_seconds": seconds,
                "stages": [{"name": "execute", "succeeded": final_state == "clean"}],
            }
        ),
        encoding="utf-8",
    )
    (bundle / "experiment.json").write_text(
        json.dumps(
            {
                "realization": realization,
                "operation": {"operation_state": "finished"},
                "independent_effect_confirmed": effect,
                "implementation_revision": revision,
                "topology": topology,
            }
        ),
        encoding="utf-8",
    )
    (bundle / "manifest.json").write_text(json.dumps({"run_id": f"{label}-id"}), encoding="utf-8")
    return bundle


def _direct_final_policy(revision="rev-abc"):
    return EvidenceEligibilityPolicy(
        name="unit-direct-experiment-final/v1",
        final_qualification=True,
        required_execution_mode=ExecutionMode.DIRECT,
        required_revision=revision,
    )


def test_five_clean_effect_confirmed_runs_reach_reproducible(tmp_path):
    bundles = [_bundle(tmp_path, f"c{i}", "clean", True) for i in range(1, 6)]
    result = summarize("experiment.iso_caldera", bundles, "rev-abc", policy=_direct_final_policy())
    assert result.clean_runs == 5
    assert result.effect_confirmed_runs == 5
    assert result.result_level is CapabilityLevel.REPRODUCIBLE


def test_a_failed_run_keeps_the_level_below_reproducible(tmp_path):
    bundles = [_bundle(tmp_path, f"c{i}", "clean", True) for i in range(1, 5)]
    bundles.append(_bundle(tmp_path, "c5", "failed_clean", None))
    result = summarize("experiment.iso_caldera", bundles, "rev-abc")
    assert result.clean_runs == 4
    assert result.result_level is CapabilityLevel.END_TO_END_VALIDATED


def test_clean_runs_without_confirmed_effect_do_not_reach_reproducible(tmp_path):
    bundles = [_bundle(tmp_path, f"c{i}", "clean", False) for i in range(1, 6)]
    result = summarize("experiment.iso_caldera", bundles, "rev-abc")
    assert result.clean_runs == 5
    assert result.effect_confirmed_runs == 0
    assert result.result_level is CapabilityLevel.INTEGRATION_TESTED


def test_surrogate_realization_is_recorded_in_scope(tmp_path):
    bundles = [_bundle(tmp_path, "c1", "clean", True, realization="surrogate")]
    result = summarize("experiment.iso_caldera", bundles, "rev-abc")
    assert "surrogate" in result.realizations_observed
    assert any("surrogate" in item for item in result.scope.excluded)


def test_direct_history_is_visible_but_not_eligible_for_supervised_final_experiment(tmp_path):
    bundle = _bundle(
        tmp_path,
        "historical",
        "clean",
        True,
        revision="b" * 40,
        topology="single_host",
    )
    policy = supervised_final_policy(
        name="caldera-supervised-final/v1",
        expected_experiment="caldera",
        required_revision="b" * 40,
        required_topology="single_host",
        accepted_realizations=["surrogate"],
    )

    result = summarize(
        "experiment.iso_caldera",
        [bundle],
        "b" * 40,
        policy=policy,
        project_root=tmp_path,
    )

    assert result.total_runs == 1
    assert result.observed_clean_runs == 1
    assert result.observed_effect_confirmed_runs == 1
    assert result.eligible_runs == 0
    assert result.clean_runs == 0
    assert result.runs[0].eligibility.eligible is False
    assert EligibilityExclusionReason.UNSUPERVISED_FOR_SUPERVISED_PROTOCOL in (
        result.runs[0].eligibility.exclusion_reasons
    )
    assert EligibilityExclusionReason.MISSING_EVIDENCE_METADATA in (
        result.runs[0].eligibility.exclusion_reasons
    )


def test_policy_can_exclude_a_realization_without_hiding_the_observation(tmp_path):
    bundle = _bundle(tmp_path, "other", "clean", True, realization="real_cve")
    policy = EvidenceEligibilityPolicy(
        name="single-surrogate-direct/v1",
        final_qualification=True,
        required_execution_mode=ExecutionMode.DIRECT,
        required_revision="rev-abc",
        accepted_realizations=["surrogate"],
    )

    result = summarize("experiment.iso_caldera", [bundle], "rev-abc", policy=policy)

    assert result.realizations_observed == ["real_cve"]
    assert result.eligible_realizations_observed == []
    assert EligibilityExclusionReason.REALIZATION_NOT_ALLOWED in (
        result.runs[0].eligibility.exclusion_reasons
    )
