"""Validate the minimum Caldera evidence required by an operational run."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ExpectedCalderaLink(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    paw: str = Field(min_length=1)
    ability_id: str = Field(min_length=1)


class CalderaLinkEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    paw: str
    ability_id: str
    status: int
    exit_code: str | None = None


class VerifiedCalderaOperation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    operation_id: str
    operation_state: str
    links: tuple[CalderaLinkEvidence, ...]


def _agent_links(report: dict[str, Any], paw: str) -> list[dict[str, Any]]:
    steps = report.get("steps")
    if not isinstance(steps, dict):
        raise ValueError("Caldera report has no steps mapping")
    agent = steps.get(paw)
    if agent is None:
        return []
    if not isinstance(agent, dict) or not isinstance(agent.get("steps"), list):
        raise ValueError(f"Caldera report has malformed steps for agent {paw}")
    if not all(isinstance(link, dict) for link in agent["steps"]):
        raise ValueError(f"Caldera report contains a malformed link for agent {paw}")
    return agent["steps"]


def _successful(link: dict[str, Any]) -> bool:
    output = link.get("output")
    exit_code = output.get("exit_code") if isinstance(output, dict) else None
    return link.get("status") == 0 and (exit_code is None or str(exit_code) == "0")


def verify_caldera_operation(
    *,
    operation_id: str,
    finished_operation: dict[str, Any] | None,
    report: dict[str, Any],
    required_links: tuple[ExpectedCalderaLink, ...],
    forbidden_links: tuple[ExpectedCalderaLink, ...] = (),
) -> VerifiedCalderaOperation:
    """Require a finished operation and the declared per-agent link outcomes."""
    if not finished_operation or finished_operation.get("state") != "finished":
        raise ValueError("Caldera operation did not reach the finished state")
    evidence: list[CalderaLinkEvidence] = []
    for expectation in required_links:
        matching = [
            link
            for link in _agent_links(report, expectation.paw)
            if link.get("ability_id") == expectation.ability_id and _successful(link)
        ]
        if not matching:
            raise ValueError(
                f"Caldera report has no successful {expectation.ability_id} link "
                f"for agent {expectation.paw}"
            )
        link = matching[-1]
        output = link.get("output")
        evidence.append(
            CalderaLinkEvidence(
                paw=expectation.paw,
                ability_id=expectation.ability_id,
                status=link["status"],
                exit_code=(
                    str(output.get("exit_code"))
                    if isinstance(output, dict) and output.get("exit_code") is not None
                    else None
                ),
            )
        )
    for expectation in forbidden_links:
        if any(
            link.get("ability_id") == expectation.ability_id and _successful(link)
            for link in _agent_links(report, expectation.paw)
        ):
            raise ValueError(
                f"forbidden Caldera link {expectation.ability_id} succeeded "
                f"for agent {expectation.paw}"
            )
    return VerifiedCalderaOperation(
        operation_id=operation_id,
        operation_state="finished",
        links=tuple(evidence),
    )
