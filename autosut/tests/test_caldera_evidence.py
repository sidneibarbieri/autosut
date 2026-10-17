from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from infrastructure.caldera_evidence import ExpectedCalderaLink, verify_caldera_operation


def _report(*, paw: str = "agent-a", ability_id: str = "ability-1", status: int = 0) -> dict:
    return {
        "steps": {
            paw: {
                "steps": [
                    {
                        "ability_id": ability_id,
                        "status": status,
                        "output": {"exit_code": str(status)},
                    }
                ]
            }
        }
    }


def test_finished_operation_requires_the_expected_successful_agent_link() -> None:
    verified = verify_caldera_operation(
        operation_id="operation-1",
        finished_operation={"state": "finished"},
        report=_report(),
        required_links=(ExpectedCalderaLink(paw="agent-a", ability_id="ability-1"),),
    )

    assert verified.operation_state == "finished"
    assert verified.links[0].ability_id == "ability-1"


@pytest.mark.parametrize(
    "finished,report,message",
    [
        ({"state": "running"}, _report(), "finished state"),
        ({"state": "finished"}, _report(status=1), "no successful"),
        ({"state": "finished"}, _report(paw="other-agent"), "no successful"),
    ],
)
def test_incomplete_or_failed_operation_is_rejected(finished, report, message) -> None:
    with pytest.raises(ValueError, match=message):
        verify_caldera_operation(
            operation_id="operation-1",
            finished_operation=finished,
            report=report,
            required_links=(ExpectedCalderaLink(paw="agent-a", ability_id="ability-1"),),
        )


def test_negative_control_forbids_a_successful_link() -> None:
    with pytest.raises(ValueError, match="forbidden"):
        verify_caldera_operation(
            operation_id="operation-1",
            finished_operation={"state": "finished"},
            report=_report(),
            required_links=(),
            forbidden_links=(ExpectedCalderaLink(paw="agent-a", ability_id="ability-1"),),
        )
