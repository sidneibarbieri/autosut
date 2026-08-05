from scripts.orchestrator.models import Realization
from scripts.orchestrator.multi_host_executor import (
    _outcome_failure,
    _outcome_success,
)


def test_multi_host_outcome_defaults_to_generic_primitive():
    outcome = _outcome_success("T0000", ["evidence.log"], "test", 0.1)

    assert outcome.realization == Realization.generic_primitive


def test_multi_host_outcome_records_declared_target_realization():
    success = _outcome_success(
        "T1190",
        ["evidence.log"],
        "test",
        0.1,
        realization=Realization.real_cve,
    )
    failure = _outcome_failure(
        "T1190",
        ["evidence.log"],
        "test",
        0.1,
        realization=Realization.real_cve,
    )

    assert success.realization == Realization.real_cve
    assert failure.realization == Realization.real_cve
