"""Generate untrusted procedure proposals and check their declared resource footprint.

The proposer may suggest a command after seeing a concrete :class:`SutOffering`. Rehearsal checks
only resource compatibility: declared credentials, services, files, installed commands, and host
reachability. It does not establish that a command implements an ATT&CK technique, is safe to run,
or produces a valid effect. A proposal is therefore planning input, not an executable contract.

The model is injected as a ``complete`` callable, keeping this module independent of a provider and
straightforward to test. A future executor must use a versioned, pre-registered action contract and
an independently defined oracle; it must never promote a model-selected command or effect marker.
"""

from __future__ import annotations

import json
import re
from typing import Callable

from pydantic import BaseModel, ConfigDict, Field

from orchestrator.models import SUTComposition

# A completion callable maps (system_prompt, user_prompt) to the model's raw text response.
CompletionFn = Callable[[str, str], str]

# Remote-transport tools need a second host. A single-host offering (no reachable hosts) cannot
# satisfy them, so they are refused at rehearsal regardless of how the command is phrased.
REMOTE_TRANSPORT_TOOLS = frozenset({"ssh", "scp", "sftp", "rsync", "telnet"})

# Shell keywords and POSIX builtins are always available; they are not host binaries to check.
_SHELL_WORDS = frozenset({
    "if", "then", "else", "elif", "fi", "for", "while", "until", "do", "done", "case", "esac",
    "in", "function", "select", "true", "false", "echo", "printf", "cd", "pwd", "export", "set",
    "unset", "read", "local", "readonly", "declare", "exit", "return", "shift", "trap", "wait",
    "break", "continue", "alias", "umask", "eval", "exec", "source", "test", ".", ":", "[", "[[",
})
# Wrappers that precede the real command; skip them to reach the binary they run.
_COMMAND_WRAPPERS = frozenset({"sudo", "env", "command", "nohup", "nice", "doas", "xargs", "time"})
# Keywords that immediately introduce a command (unlike ``for``/``case``, which introduce a word
# list). Skipping them lets the extractor see the binary in ``do nc ...`` or ``if grep ...``.
_COMMAND_INTRODUCERS = frozenset({"if", "while", "until", "elif", "then", "do", "else", "!"})
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")

SYSTEM_PROMPT = """You propose one laboratory procedure for a declared host.
You receive the technique and exactly what the host provides: credential users, exposed services,
staged file paths, the commands installed on the host, and any other reachable hosts. Return one
JSON object:
{
  "command": string,                 // an untrusted candidate command for offline review
  "uses_credential_users": [string], // credential users the command authenticates with
  "uses_services": [string],         // exposed services the command targets
  "uses_artifact_paths": [string]    // staged files the command reads or writes
}
Constraints. Use only the commands the host lists as installed. Target only this host: do not use
ssh, scp, sftp, or rsync unless the host lists a reachable host. Reference only credential users,
services, and paths the host declares. Do not claim that the command succeeded and do not add a
marker or other self-authored proof of effect. This response is never executed solely because it
appears here.
"""


class ExecutableProcedure(BaseModel):
    """An untrusted candidate procedure retained for static planning only."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    technique_id: str = Field(min_length=1)
    command: str = Field(min_length=1)
    uses_credential_users: list[str] = Field(default_factory=list)
    uses_services: list[str] = Field(default_factory=list)
    uses_artifact_paths: list[str] = Field(default_factory=list)


class SutOffering(BaseModel):
    """What a host actually provides, across every axis rehearsal checks."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    credential_users: list[str] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)
    artifact_paths: list[str] = Field(default_factory=list)
    commands: list[str] = Field(default_factory=list)
    reachable_hosts: list[str] = Field(default_factory=list)
    # Staged scripts by path: their content is known, so rehearsal can check the binaries a
    # command inherits by running one, not only the binaries it names directly.
    staged_scripts: dict[str, str] = Field(default_factory=dict)


class RehearsalResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    consistent: bool
    missing_credential_users: list[str] = Field(default_factory=list)
    missing_services: list[str] = Field(default_factory=list)
    missing_artifact_paths: list[str] = Field(default_factory=list)
    missing_commands: list[str] = Field(default_factory=list)
    remote_requirement_unmet: list[str] = Field(default_factory=list)


class MalformedProcedureError(ValueError):
    """The model reply could not be parsed into an executable procedure."""


def offering_from_composition(
    composition: SUTComposition, *, commands: list[str], reachable_hosts: list[str]
) -> SutOffering:
    """Build the offering from the declarative SUT plus the host's live command surface."""
    return SutOffering(
        credential_users=sorted({credential.user for credential in composition.credentials}),
        services=sorted({exposure.service for exposure in composition.exposures if exposure.service}),
        artifact_paths=sorted({artifact.path for artifact in composition.artifacts}),
        commands=sorted(set(commands)),
        reachable_hosts=sorted(set(reachable_hosts)),
        staged_scripts={
            a.path: a.content_text
            for a in composition.artifacts
            if a.content_text and (a.path.endswith(".sh") or a.content_text.startswith("#!"))
        },
    )


def invoked_commands(command: str) -> set[str]:
    """Extract likely binaries for a conservative, lexical feasibility screen."""
    found: set[str] = set()
    for segment in re.split(r"[\n;|&]+", command):
        tokens = segment.strip().split()
        index = 0
        while index < len(tokens) and (
            _ASSIGNMENT.match(tokens[index])
            or tokens[index] in _COMMAND_WRAPPERS
            or tokens[index] in _COMMAND_INTRODUCERS
        ):
            index += 1
        if index >= len(tokens):
            continue
        head = tokens[index]
        if head[0] in "(){}<>`$":
            continue
        name = head.rsplit("/", 1)[-1]
        if name and name not in _SHELL_WORDS:
            found.add(name)
    return found


def rehearse(procedure: ExecutableProcedure, offering: SutOffering) -> RehearsalResult:
    """Check resource compatibility without admitting the proposal for execution."""
    invoked = invoked_commands(procedure.command)
    # A command that runs a staged script inherits the binaries the script itself invokes.
    for script_path, script_content in offering.staged_scripts.items():
        if script_path in procedure.command:
            invoked |= invoked_commands(script_content)
    remote_unmet = sorted(invoked & REMOTE_TRANSPORT_TOOLS) if not offering.reachable_hosts else []
    missing = RehearsalResult(
        consistent=False,
        missing_credential_users=sorted(set(procedure.uses_credential_users) - set(offering.credential_users)),
        missing_services=sorted(set(procedure.uses_services) - set(offering.services)),
        missing_artifact_paths=sorted(set(procedure.uses_artifact_paths) - set(offering.artifact_paths)),
        missing_commands=sorted(invoked - set(offering.commands) - REMOTE_TRANSPORT_TOOLS),
        remote_requirement_unmet=remote_unmet,
    )
    consistent = not (
        missing.missing_credential_users
        or missing.missing_services
        or missing.missing_artifact_paths
        or missing.missing_commands
        or missing.remote_requirement_unmet
    )
    return missing.model_copy(update={"consistent": consistent})


def build_user_prompt(technique_id: str, technique_summary: str, offering: SutOffering) -> str:
    payload = {
        "technique_id": technique_id,
        "technique_summary": technique_summary,
        "host_provides": {
            "credential_users": offering.credential_users,
            "services": offering.services,
            "artifact_paths": offering.artifact_paths,
            "commands": offering.commands,
            "reachable_hosts": offering.reachable_hosts,
            "staged_script_paths": sorted(offering.staged_scripts),
        },
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def _parse_procedure(technique_id: str, raw: str) -> ExecutableProcedure:
    start = raw.find("{")
    end = raw.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise MalformedProcedureError("response contains no JSON object")
    payload = json.loads(raw[start : end + 1])
    payload["technique_id"] = technique_id
    return ExecutableProcedure.model_validate(payload)


def _feedback(result: RehearsalResult) -> str:
    return "\nPrevious attempt referenced resources the host cannot satisfy: " + json.dumps({
        "missing_credential_users": result.missing_credential_users,
        "missing_services": result.missing_services,
        "missing_artifact_paths": result.missing_artifact_paths,
        "missing_commands": result.missing_commands,
        "remote_requirement_unmet": result.remote_requirement_unmet,
    })


def generate_executable_procedure(
    technique_id: str,
    technique_summary: str,
    offering: SutOffering,
    complete: CompletionFn,
    *,
    max_attempts: int = 3,
) -> tuple[ExecutableProcedure, RehearsalResult]:
    """Generate a proposal and retry until it is resource-compatible or attempts run out.

    A rehearsal failure is fed back so the next proposal can bind to the declared offering. The
    final proposal is returned even when incompatible so callers can record an explicit abstention.
    A malformed reply raises. Resource compatibility is not an execution or semantic-validity claim.
    """
    feedback = ""
    procedure = None
    result = None
    for _ in range(max_attempts):
        raw = complete(SYSTEM_PROMPT, build_user_prompt(technique_id, technique_summary, offering) + feedback)
        procedure = _parse_procedure(technique_id, raw)
        result = rehearse(procedure, offering)
        if result.consistent:
            return procedure, result
        feedback = _feedback(result)
    return procedure, result
