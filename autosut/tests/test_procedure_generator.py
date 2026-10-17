from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

import pytest  # noqa: E402

from orchestrator.models import Credential, NetworkExposure, ProvenanceSource, StagedArtifact, SUTComposition  # noqa: E402
from planning.procedure_generator import (  # noqa: E402
    ExecutableProcedure,
    MalformedProcedureError,
    SutOffering,
    generate_executable_procedure,
    offering_from_composition,
    rehearse,
)


def _composition() -> SUTComposition:
    return SUTComposition(
        credentials=[Credential(kind="password", user="labuser", secret="secret://cred/1", purpose="ssh_login")],
        artifacts=[StagedArtifact(path="/opt/loot/decoy.txt", content_text="x", owner="root", mode="0644",
                                  purpose="decoy", source=ProvenanceSource.analyst_authored)],
        exposures=[NetworkExposure(port=22, service="ssh")],
    )


def _offering(commands=("ssh", "curl", "cat")):
    return offering_from_composition(_composition(), commands=list(commands), reachable_hosts=["peer"])


def _reply(command: str, users: list[str], services: list[str], paths: list[str]) -> str:
    return json.dumps({
        "command": command, "uses_credential_users": users, "uses_services": services,
        "uses_artifact_paths": paths,
    })


def test_rehearsal_accepts_a_command_within_the_sut_offering():
    proc = ExecutableProcedure(technique_id="T1021", command="ssh labuser@host",
                               uses_credential_users=["labuser"], uses_services=["ssh"],
                               uses_artifact_paths=["/opt/loot/decoy.txt"])
    result = rehearse(proc, _offering())
    assert result.consistent


def test_rehearsal_rejects_a_credential_the_sut_lacks():
    proc = ExecutableProcedure(technique_id="T1021", command="ssh admin@host",
                               uses_credential_users=["admin"])
    result = rehearse(proc, _offering())
    assert not result.consistent
    assert result.missing_credential_users == ["admin"]


def test_generation_retries_until_consistent_with_the_sut():
    replies = [
        _reply("ssh admin@host", ["admin"], [], []),          # references a missing credential
        _reply("ssh labuser@host", ["labuser"], ["ssh"], []), # binds to what the SUT provides
    ]
    calls = {"n": 0}
    def complete(system, user):
        reply = replies[min(calls["n"], len(replies) - 1)]
        calls["n"] += 1
        return reply
    procedure, result = generate_executable_procedure("T1021", "Remote Services: SSH", _offering(), complete)
    assert result.consistent
    assert calls["n"] == 2
    assert procedure.uses_credential_users == ["labuser"]


def test_generation_returns_inconsistent_result_when_it_cannot_bind():
    def complete(system, user):
        return _reply("curl http://evil", [], ["https"], [])  # service the SUT does not expose
    procedure, result = generate_executable_procedure("T1071", "App layer protocol", _offering(),
                                                       complete, max_attempts=2)
    assert not result.consistent
    assert result.missing_services == ["https"]


def test_malformed_reply_raises():
    def complete(system, user):
        return "no json here"
    with pytest.raises(MalformedProcedureError):
        generate_executable_procedure("T1021", "s", _offering(), complete)


def test_extractor_sees_commands_after_do_and_then():
    from planning.procedure_generator import invoked_commands
    found = invoked_commands("for h in a b; do nc -z $h 22; done")
    assert "nc" in found
    assert "for" not in found and "do" not in found and "done" not in found


def test_rehearsal_recurses_into_a_staged_script_the_command_runs():
    from planning.procedure_generator import SutOffering
    offering = SutOffering(
        credential_users=["reconuser"], services=[], artifact_paths=["/opt/scan.sh"],
        commands=["bash", "cat"], reachable_hosts=[],
        staged_scripts={"/opt/scan.sh": "for h in a b; do nc -z $h 22; done"},
    )
    proc = ExecutableProcedure(technique_id="T1046", command="bash /opt/scan.sh")
    result = rehearse(proc, offering)
    assert not result.consistent
    assert "nc" in result.missing_commands  # inherited from the staged script, not named directly


def test_prompt_exposes_staged_script_paths_but_not_their_contents():
    from planning.procedure_generator import build_user_prompt

    offering = SutOffering(
        artifact_paths=["/opt/scan.sh"],
        staged_scripts={"/opt/scan.sh": "sensitive staged content"},
    )
    prompt = build_user_prompt("T1046", "discover services", offering)
    assert "/opt/scan.sh" in prompt
    assert "sensitive staged content" not in prompt
