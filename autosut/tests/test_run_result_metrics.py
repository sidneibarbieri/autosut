from scripts.orchestrator.models import (
    AttackerProfile,
    ExecutionMode,
    FidelityLevel,
    Realization,
    RunResult,
    SUTProfile,
    TechniqueOutcome,
)


def _outcome(
    technique_id: str,
    fidelity: FidelityLevel,
    mode: ExecutionMode,
) -> TechniqueOutcome:
    return TechniqueOutcome(
        technique_id=technique_id,
        declared_fidelity=fidelity,
        executed_fidelity=fidelity,
        declared_mode=mode,
        executed_mode=mode,
        realization=Realization.surrogate,
        status="success",
        evidence_files=[f"techniques/{technique_id}.log"],
    )


def test_success_metrics_do_not_count_markers_as_execution() -> None:
    result = RunResult(
        campaign_id="test",
        run_id="test-run",
        attacker=AttackerProfile(profile_id="test"),
        sut=SUTProfile(sut_id="test", base_image="alpine:3.19"),
        techniques=[
            _outcome("T1", FidelityLevel.adapted, ExecutionMode.real_controlled),
            _outcome("T2", FidelityLevel.inspired, ExecutionMode.real_controlled),
            _outcome("T3", FidelityLevel.inspired, ExecutionMode.naive_simulated),
        ],
    )

    assert result.successful == 3
    assert result.evidence_backed_successful == 2
    assert result.adapted_successful == 1
    assert result.marker_only_successful == 1
