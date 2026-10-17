from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from orchestrator.models import Credential, StagedArtifact, SUTComposition  # noqa: E402
from planning.campaign_execution import (  # noqa: E402
    TechniqueBrief,
    execute_campaign,
    probe_host_commands,
    run_technique,
)
from planning.procedure_generator import SutOffering, offering_from_composition  # noqa: E402


class FakeOutcome:
    def __init__(self, exit_code: int, stdout: str):
        self.exit_code = exit_code
        self.stdout = stdout


class FakeHost:
    """A host exposing only the command-surface operation used by planning."""

    def __init__(self, host_id: str = "fake-host", available_commands=None):
        self._host_id = host_id
        self.available_commands = set(available_commands or {"cat", "sh", "ls", "grep", "python3"})
        self.executed_commands: list[str] = []

    @property
    def host_id(self) -> str:
        return self._host_id

    def run_shell(self, command: str, log_name=None, timeout: int = 600) -> FakeOutcome:
        if command.startswith("ls -1 "):
            return FakeOutcome(0, "\n".join(sorted(self.available_commands)))
        self.executed_commands.append(command)
        return FakeOutcome(0, "")


def _composition() -> SUTComposition:
    return SUTComposition(
        credentials=[Credential(kind="password", user="reconuser", secret="x", purpose="lab")],
        artifacts=[StagedArtifact(path="/home/reconuser/notes.txt", content_text="secret", owner="reconuser")],
    )


def _offering(commands, reachable_hosts=None) -> SutOffering:
    return offering_from_composition(_composition(), commands=list(commands), reachable_hosts=reachable_hosts or [])


def _completion(command: str, uses_paths=None, uses_users=None):
    reply = {
        "command": command,
        "uses_credential_users": uses_users or [],
        "uses_services": [],
        "uses_artifact_paths": uses_paths or [],
    }
    return lambda system, user: json.dumps(reply)


def test_resource_compatible_proposal_is_never_executed_without_a_registered_contract():
    host = FakeHost()
    brief = TechniqueBrief(technique_id="T1005", summary="read a declared file")
    complete = _completion(
        "cat /home/reconuser/notes.txt",
        uses_paths=["/home/reconuser/notes.txt"],
    )
    run = run_technique(host, brief, _offering({"cat"}), complete)
    assert run.proposed and run.resource_compatible
    assert not run.admitted and not run.executed and not run.effect_observed
    assert run.command is None
    assert len(run.proposal_sha256) == 64
    assert not host.executed_commands


def test_abstains_when_command_invokes_a_binary_the_host_lacks():
    host = FakeHost()
    brief = TechniqueBrief(technique_id="T1053.005", summary="scheduled task")
    complete = _completion("crontab -l")  # crontab not among host commands
    run = run_technique(host, brief, _offering({"cat", "sh"}), complete, max_attempts=1)
    assert not run.admitted and not run.executed
    assert "crontab" in run.abstained_reason
    assert not host.executed_commands


def test_abstains_on_remote_tool_when_no_reachable_host():
    host = FakeHost()
    brief = TechniqueBrief(technique_id="T1105", summary="ingress tool transfer")
    complete = _completion("scp /home/reconuser/notes.txt user@peer:/tmp/",
                           uses_paths=["/home/reconuser/notes.txt"])
    run = run_technique(host, brief, _offering({"scp", "cat"}), complete, max_attempts=1)
    assert not run.admitted
    assert "scp" in run.abstained_reason


def test_resource_compatible_proposal_records_a_contract_boundary():
    host = FakeHost(available_commands={"cat", "python3"})
    brief = TechniqueBrief(technique_id="T1046", summary="discover services")
    complete = _completion("python3 -c 'pass'")
    run = run_technique(host, brief, _offering({"python3"}), complete)
    assert run.resource_compatible
    assert not run.admitted and not run.executed
    assert "pre-registered action contract" in (run.abstained_reason or "")


def test_report_counts_reflect_mixed_outcomes():
    host = FakeHost(available_commands={"cat", "sh", "ls", "grep"})
    briefs = [
        TechniqueBrief(technique_id="T1005", summary="collect"),
        TechniqueBrief(technique_id="T1105", summary="transfer"),
    ]
    replies = iter([
        json.dumps({"command": "echo HIT > /tmp/m", "uses_credential_users": [],
                    "uses_services": [], "uses_artifact_paths": []}),
        json.dumps({"command": "scp a peer:/b", "uses_credential_users": [],
                    "uses_services": [], "uses_artifact_paths": []}),
    ])
    report = execute_campaign(host, "0.demo", _composition(), briefs,
                              lambda s, u: next(replies), max_attempts=1)
    assert report.admitted_count == 0
    assert report.abstained_count == 2
    assert report.executed_count == 0
    assert report.effect_observed_count == 0
    assert sum(run.resource_compatible for run in report.runs) == 1


def test_probe_host_commands_reads_the_path_listing():
    host = FakeHost(available_commands={"cat", "python3", "nmap"})
    assert probe_host_commands(host) == ["cat", "nmap", "python3"]


def test_report_does_not_serialize_the_untrusted_proposal_command():
    host = FakeHost()
    brief = TechniqueBrief(technique_id="T1005", summary="read a declared file")
    run = run_technique(host, brief, _offering({"cat"}), _completion("cat /home/reconuser/notes.txt"))
    assert run.command is None
    assert run.proposal_sha256
