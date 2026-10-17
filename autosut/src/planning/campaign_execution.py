"""Plan and statically rehearse campaign procedures without executing model output.

For each technique, a proposer suggests a command and a resource footprint. The engine checks that
footprint against the concrete host offering and records a proposal hash. That is useful planning
evidence, but it is not a technique-execution result: lexical resource checks cannot establish
shell semantics or ATT&CK fidelity, and a model-owned effect marker cannot be an independent oracle.

The public path therefore fails closed. It never sends a model-produced command to a host. A future
execution path must consume a versioned, pre-registered action contract with an independently
defined evidence predicate. ``HostRunner`` remains structural so the planning path is backend- and
provider-independent and can be tested with a fake host.
"""

from __future__ import annotations

import hashlib
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field

from orchestrator.models import SUTComposition
from planning.model_provider import CompletionFn
from planning.procedure_generator import (
    RehearsalResult,
    SutOffering,
    generate_executable_procedure,
    offering_from_composition,
)

# Directories on PATH where a host keeps its executables; the command surface is their union.
COMMAND_PATH_ROOTS = ("/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin")


class CommandOutcome(Protocol):
    """The part of a backend's command result the engine reads."""

    exit_code: int
    stdout: str


class HostRunner(Protocol):
    """A live host the engine can run shell commands against."""

    @property
    def host_id(self) -> str: ...

    def run_shell(self, command: str, log_name: str | None = ..., timeout: int = ...) -> CommandOutcome: ...


class TechniqueBrief(BaseModel):
    """One technique to realize: its ATT&CK id and a short natural-language summary."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    technique_id: str = Field(min_length=1)
    summary: str = Field(min_length=1)


class ProcedureRun(BaseModel):
    """A planning outcome, explicitly separate from an execution result."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    technique_id: str
    proposed: bool
    resource_compatible: bool
    admitted: bool
    executed: bool
    effect_observed: bool
    proposal_sha256: str
    command: str | None = None
    exit_code: int | None = None
    abstained_reason: str | None = None
    rehearsal: RehearsalResult


class CampaignExecutionReport(BaseModel):
    """A legacy-named report whose public entries are planning outcomes only."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    campaign_id: str
    host_id: str
    runs: list[ProcedureRun]

    @property
    def admitted_count(self) -> int:
        return sum(1 for run in self.runs if run.admitted)

    @property
    def abstained_count(self) -> int:
        return sum(1 for run in self.runs if not run.admitted)

    @property
    def executed_count(self) -> int:
        return sum(1 for run in self.runs if run.executed)

    @property
    def effect_observed_count(self) -> int:
        return sum(1 for run in self.runs if run.effect_observed)


def _abstention_reason(rehearsal: RehearsalResult) -> str:
    missing = {
        "credential users": rehearsal.missing_credential_users,
        "services": rehearsal.missing_services,
        "file paths": rehearsal.missing_artifact_paths,
        "commands": rehearsal.missing_commands,
        "remote tools with no reachable host": rehearsal.remote_requirement_unmet,
    }
    parts = [f"{label}: {', '.join(values)}" for label, values in missing.items() if values]
    return "command required resources the host does not provide - " + "; ".join(parts)


def probe_host_commands(host: HostRunner) -> list[str]:
    """The binaries installed on the host, read from its PATH directories."""
    roots = " ".join(COMMAND_PATH_ROOTS)
    listing = host.run_shell(f"ls -1 {roots} 2>/dev/null")
    names = {line.strip() for line in listing.stdout.splitlines() if line.strip() and "/" not in line}
    return sorted(names)


def _proposal_sha256(command: str) -> str:
    """Return a stable identifier without serializing untrusted shell text into a report."""
    return hashlib.sha256(command.encode("utf-8")).hexdigest()


def run_technique(
    host: HostRunner,
    brief: TechniqueBrief,
    offering: SutOffering,
    complete: CompletionFn,
    *,
    max_attempts: int = 3,
) -> ProcedureRun:
    """Generate a proposal, screen resource compatibility, and fail closed before execution."""
    procedure, rehearsal = generate_executable_procedure(
        brief.technique_id, brief.summary, offering, complete, max_attempts=max_attempts
    )
    if not rehearsal.consistent:
        return ProcedureRun(
            technique_id=brief.technique_id,
            proposed=True,
            resource_compatible=False,
            admitted=False,
            executed=False,
            effect_observed=False,
            proposal_sha256=_proposal_sha256(procedure.command),
            abstained_reason=_abstention_reason(rehearsal),
            rehearsal=rehearsal,
        )

    return ProcedureRun(
        technique_id=brief.technique_id,
        proposed=True,
        resource_compatible=True,
        admitted=False,
        executed=False,
        effect_observed=False,
        proposal_sha256=_proposal_sha256(procedure.command),
        abstained_reason=(
            "no pre-registered action contract and independent evidence predicate; "
            "proposal retained for offline review only"
        ),
        rehearsal=rehearsal,
    )


def execute_campaign(
    host: HostRunner,
    campaign_id: str,
    composition: SUTComposition,
    briefs: list[TechniqueBrief],
    complete: CompletionFn,
    *,
    reachable_hosts: list[str] | None = None,
    max_attempts: int = 3,
) -> CampaignExecutionReport:
    """Generate and screen every proposal in order without executing model output.

    The offering is built once from the declarative composition and the host's live command
    surface, so every technique is rehearsed against the same concrete statement of what the host
    provides. ``reachable_hosts`` is empty for a single-host SUT, which makes the feasibility screen
    refuse remote-transport proposals. All report entries remain non-executed until a trusted action
    contract and independent oracle are registered.
    """
    offering = offering_from_composition(
        composition, commands=probe_host_commands(host), reachable_hosts=reachable_hosts or []
    )
    runs = [run_technique(host, brief, offering, complete, max_attempts=max_attempts) for brief in briefs]
    return CampaignExecutionReport(campaign_id=campaign_id, host_id=host.host_id, runs=runs)
