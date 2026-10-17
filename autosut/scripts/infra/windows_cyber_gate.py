"""Run the Windows cyber-execution experiment through the canonical lifecycle and backend.

This is the SAME experiment that G1 validated, now driven by the canonical machinery rather than a
private Windows guest lifecycle:

    fresh clone (WindowsQemuEnvironment) -> negative control -> per-run isolated Caldera + native
    arm64 agent enrollment -> ATT&CK T1112 ability -> in-guest oracle independent of Caldera ->
    teardown -> fail-closed verify-clean -> sealed bundle

The driver never touches qcow2, swtpm, or the WinRM transport: every guest interaction goes through
``env.run_shell``, and the substrate is chosen by ``select_backend(sut)`` from the SUT profile. Caldera
is never its own oracle: the gate passes only when an in-guest probe, read over WinRM independently of
Caldera, observes the exact per-run nonce, the negative control was clean beforehand, a Windows PAW
registered, the operation reached a terminal state, the guest shut down on its own, the base image is
unchanged, and the fail-closed residual inventory is empty.

Layering (kept strict): the scientific layer (negative control, procedure, oracle) and the execution
layer (Caldera, agent enrollment, ability) sit above the canonical lifecycle, which sits above the
provider. The provider knows its transport is WinRM; it does not know what T1112, Caldera, a PAW, or the
nonce are.

This run is INTEGRATION evidence on an unfrozen revision in the author environment, not qualification:
the sealed verdict records ``evidence_role: integration`` and is not claim-eligible.
"""

from __future__ import annotations

import argparse
import http.server
import importlib.util
import json
import os
import secrets
import socket
import socketserver
import struct
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path

from pydantic import BaseModel, ConfigDict

SCRIPTS_DIR = Path(__file__).resolve().parents[1]
PROJECT_ROOT = SCRIPTS_DIR.parent
for import_root in (SCRIPTS_DIR, PROJECT_ROOT / "src"):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))

from infrastructure.caldera_instance import CalderaInstance
from infrastructure.evidence_bundle import (
    ArtifactProvenance,
    EvidenceBundle,
    EvidenceClassification,
    LifecycleEvidence,
    OracleEvidence,
    ProcedureEvidence,
    ResidualEvidence,
    RunIdentity,
    SecretAuditEvidence,
    seal_bundle,
    validate_bundle,
)
from infrastructure.lifecycle import (
    LifecycleController,
    ResidualReport,
    Stage,
)
from infrastructure.revision import current_revision
from infrastructure.run_context import RunContext
from orchestrator.environment_base import select_backend
from orchestrator.models import SUTProfile
from orchestrator.windows_qemu_environment import WindowsQemuEnvironment

AGENT_GUEST_PATH = "C:\\Users\\Public\\sandcat_arm64.exe"
AGENT_OUTPUT_PATH = "C:\\Users\\Public\\sandcat_arm64.out"


def _record_stage_start(run_dir: Path, stage_name: str) -> None:
    event = {"stage": stage_name, "started_ns": time.time_ns()}
    with (run_dir / "stage-starts.jsonl").open("a", encoding="utf-8") as output:
        output.write(json.dumps(event, sort_keys=True) + "\n")
        output.flush()
        os.fsync(output.fileno())

_MARKER_READ = (
    "$v=(Get-ItemProperty 'HKLM:\\SOFTWARE\\AutoSUT' -Name marker -ErrorAction SilentlyContinue).marker;"
    "if ($null -eq $v) {'absent'} else {'present:' + $v}"
)


def _load_caldera_client():
    spec = importlib.util.spec_from_file_location(
        "caldera_client_mod", str(PROJECT_ROOT / "scripts" / "orchestrator" / "caldera_client.py")
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["caldera_client_mod"] = module
    spec.loader.exec_module(module)
    return module.CalderaClient


def _clear_panther_answer(environment) -> None:
    """Remove the clone's active answer file after the experiment."""
    command = (
        "$answer='C:\\Windows\\Panther\\unattend.xml';"
        "if(Test-Path -LiteralPath $answer){"
        "Remove-Item -LiteralPath $answer -Force -ErrorAction Stop};"
        "if(Test-Path -LiteralPath $answer){throw 'Panther answer remains'};"
        "Write-Output 'panther-answer-absent'"
    )
    result = environment.run_shell(command)
    if result.exit_code != 0 or result.stdout.strip() != "panther-answer-absent":
        raise RuntimeError("Windows Panther answer cleanup was not confirmed")


def _teardown_windows_guest(environment, guest_ready: bool,
                            clear_panther_answer: bool = False) -> None:
    """Release the guest even when agent cleanup fails or boot never completed."""
    if environment is None:
        return
    try:
        if guest_ready:
            if clear_panther_answer:
                _clear_panther_answer(environment)
            environment.run_shell(
                "Unregister-ScheduledTask -TaskName 'autosut-cyber-agent' -Confirm:$false -ErrorAction SilentlyContinue;"
                "Get-Process sandcat_arm64 -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue"
            )
    finally:
        environment.teardown()


def _sha256(path: Path) -> str:
    return subprocess.run(["shasum", "-a", "256", str(path)], capture_output=True, text=True,
                          check=True, timeout=900).stdout.split()[0]


def _pe_machine(binary: bytes) -> str:
    if binary[:2] != b"MZ":
        return "not-PE"
    offset = struct.unpack_from("<I", binary, 0x3C)[0]
    machine = struct.unpack_from("<H", binary, offset + 4)[0]
    return {0x8664: "x64/amd64", 0xAA64: "ARM64", 0x14C: "x86"}.get(machine, hex(machine))


def _serve_directory(directory: Path, port: int) -> socketserver.TCPServer:
    def _handler(*args, **kwargs):
        return http.server.SimpleHTTPRequestHandler(*args, directory=str(directory), **kwargs)

    httpd = socketserver.TCPServer(("127.0.0.1", port), _handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class CyberGateVerdict(BaseModel):
    """The scientific assertions of the run, sealed alongside the lifecycle result."""

    model_config = ConfigDict(extra="forbid")

    evidence_role: str = "integration"
    scientific_claim_eligible: bool = False
    frozen_revision: bool = False
    clean_room: bool = False

    base_sha256_before: str
    base_sha256_after: str
    guest_host_id: str
    guest_hostname: str
    guest_machine_sid: str
    specialize_confirmed: bool
    agent_sha256: str
    agent_pe_machine: str
    paw_registered: bool
    paw_id: str
    paw_platform: str
    negative_control_absent_before: bool
    ability_dispatched: bool
    operation_reached_terminal_state: bool
    independent_effect_observed: bool
    effect_matches_expected: bool

    @property
    def science_passed(self) -> bool:
        return (
            self.base_sha256_before == self.base_sha256_after
            and self.specialize_confirmed
            and self.paw_registered
            and self.paw_platform == "windows"
            and self.negative_control_absent_before
            and self.ability_dispatched
            and self.operation_reached_terminal_state
            and self.independent_effect_observed
            and self.effect_matches_expected
        )


def _failure_verdict(base_sha_before: str, base_sha_after: str,
                     agent_sha: str, agent_pe: str) -> CyberGateVerdict:
    return CyberGateVerdict(
        base_sha256_before=base_sha_before,
        base_sha256_after=base_sha_after,
        guest_host_id="",
        guest_hostname="",
        guest_machine_sid="",
        specialize_confirmed=False,
        agent_sha256=agent_sha,
        agent_pe_machine=agent_pe,
        paw_registered=False,
        paw_id="",
        paw_platform="",
        negative_control_absent_before=False,
        ability_dispatched=False,
        operation_reached_terminal_state=False,
        independent_effect_observed=False,
        effect_matches_expected=False,
    )


class CalderaStateDiagnostic(BaseModel):
    """Secret-free state retained before the run's container is destroyed."""

    model_config = ConfigDict(extra="forbid", strict=True)
    inspection_completed: bool
    inspect_exit_code: int
    status: str | None = None
    running: bool | None = None
    restarting: bool | None = None
    oom_killed: bool | None = None
    container_exit_code: int | None = None


def _record_caldera_state(container_name: str, output: Path) -> None:
    result = subprocess.run(
        ["docker", "inspect", "--format", "{{json .State}}", container_name],
        capture_output=True, text=True, check=False, timeout=30,
    )
    values = {}
    if result.returncode == 0:
        state = json.loads(result.stdout)
        values = {
            "status": state["Status"], "running": state["Running"],
            "restarting": state["Restarting"], "oom_killed": state["OOMKilled"],
            "container_exit_code": state["ExitCode"],
        }
    report = CalderaStateDiagnostic(
        inspection_completed=result.returncode == 0,
        inspect_exit_code=result.returncode, **values,
    )
    output.write_text(report.model_dump_json(indent=2) + "\n", encoding="utf-8")
    if not report.inspection_completed:
        raise RuntimeError(f"Caldera state inspection failed: exit {result.returncode}")


class CalderaResidualInventory(BaseModel):
    """Whether the controller container presence probe completed."""

    model_config = ConfigDict(extra="forbid", strict=True)
    completed: bool
    residual_resources: list[str]


def _caldera_container_residual(container_name: str) -> CalderaResidualInventory:
    """Treat an incomplete container inventory as a residual uncertainty."""
    listing = subprocess.run(
        ["docker", "ps", "-a", "--filter", f"name={container_name}", "--format", "{{.Names}}"],
        capture_output=True, text=True, check=False, timeout=30,
    )
    if listing.returncode:
        return CalderaResidualInventory(
            completed=False,
            residual_resources=[f"caldera-container-inventory-incomplete:{listing.returncode}"],
        )
    if container_name in listing.stdout.split():
        return CalderaResidualInventory(
            completed=True, residual_resources=[f"caldera-container:{container_name}"],
        )
    return CalderaResidualInventory(completed=True, residual_resources=[])


def _ready_caldera_client(caldera: CalderaInstance):
    """Require server readiness before reading its generated API configuration."""
    caldera.wait_until_ready(timeout_seconds=300)
    return _load_caldera_client()(
        caldera.base_url, caldera.read_red_api_key(), caldera.container_name,
    )


def run_cyber_gate(base: Path, agent_binary: Path, evidence_root: Path, label: str,
                   *, stopped_disk_observer: Callable[[Path], None] | None = None,
                   stopped_disk_observer_factory: Callable[[Path], Callable[[Path], None]] | None = None,
                   on_run_created: Callable[[Path], None] | None = None,
                   clear_panther_answer: bool = False,
                   immutable_base_image: Path | None = None):
    """Drive the Windows cyber experiment through LifecycleController and return (result, verdict)."""
    if stopped_disk_observer is not None and stopped_disk_observer_factory is not None:
        raise ValueError("provide either a stopped-disk observer or its run-scoped factory")
    immutable_base_sha256 = (
        _sha256(immutable_base_image) if immutable_base_image is not None else None
    )
    sut = SUTProfile(sut_id="windows-cyber", base_image=str(base), backend="windows-qemu",
                     memory_mb=6144, smp=4)
    backend_cls = select_backend(sut)
    assert backend_cls is WindowsQemuEnvironment  # the SUT profile selects the provider, not the driver

    readiness = backend_cls.check()
    if not readiness.ready:
        raise RuntimeError(f"windows-qemu preflight refused: {'; '.join(readiness.gaps)}")
    if not os.environ.get("AUTOSUT_WIN_PASSWORD"):
        raise RuntimeError("windows-qemu preflight refused: AUTOSUT_WIN_PASSWORD is required")

    run_context = RunContext.create(evidence_root, label=label)
    if on_run_created is not None:
        on_run_created(run_context.run_dir)
    run_observer = (stopped_disk_observer_factory(run_context.run_dir)
                    if stopped_disk_observer_factory is not None else stopped_disk_observer)
    observed_revision = current_revision(PROJECT_ROOT)
    nonce = "autosut-" + secrets.token_hex(8)

    agent_bytes = agent_binary.read_bytes()
    agent_sha = _sha256(agent_binary)
    agent_pe = _pe_machine(agent_bytes)
    serve_port = _free_port()
    httpd = _serve_directory(agent_binary.parent, serve_port)
    caldera = CalderaInstance.materialize(run_context.namespaced("caldera"))

    state: dict = {"env": None, "guest_ready": False}

    def prepare_execution_layer() -> None:
        state["client"] = _ready_caldera_client(caldera)

    def track_environment(environment) -> None:
        state["env"] = environment

    def materialize() -> None:
        backend_cls.bring_up(
            sut, run_context.run_dir, on_created=track_environment,
            stopped_disk_observer=run_observer,
        )
        state["guest_ready"] = True

    def negative_control() -> None:
        env = state["env"]
        identity = env.run_shell(
            "$sid=((New-Object System.Security.Principal.NTAccount('labadmin'))."
            "Translate([System.Security.Principal.SecurityIdentifier]).Value);"
            "$sid=$sid.Substring(0,$sid.LastIndexOf('-'));"
            "$spec=Select-String -Path C:\\Windows\\Panther\\setupact.log -Pattern 'specialize' "
            "-ErrorAction SilentlyContinue | Select-Object -First 1;"
            "$env:COMPUTERNAME + '|' + $sid + '|' + [bool]$spec",
            log_name="execution/identity.log",
        ).stdout.strip().split("|")
        state["hostname"], state["sid"], state["specialize"] = (
            identity[0], identity[1], identity[2] == "True")
        before = env.run_shell(_MARKER_READ, log_name="execution/negative_control.log").stdout.strip()
        state["negative_control_absent"] = before == "absent"

    def enroll_agent() -> None:
        env = state["env"]
        client = state["client"]
        for _ in range(8):
            if client.list_agents() is not None:
                break
            time.sleep(10)
        caldera_port = int(caldera.base_url.rsplit(":", 1)[1])
        agent_url = f"http://10.0.2.2:{serve_port}/{agent_binary.name}"
        server = f"http://10.0.2.2:{caldera_port}"
        argument = f"/c {AGENT_GUEST_PATH} -server {server} -group red -v > {AGENT_OUTPUT_PATH} 2>&1"
        env.run_shell(
            f"$dl=0;foreach($i in 1..8){{ try {{"
            f"(New-Object System.Net.WebClient).DownloadFile('{agent_url}','{AGENT_GUEST_PATH}');"
            f"$dl=(Get-Item '{AGENT_GUEST_PATH}').Length;break"
            "} catch { Start-Sleep -Seconds 10 } }"
            f"$a=New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '{argument}';"
            "$p=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest;"
            "Register-ScheduledTask -TaskName 'autosut-cyber-agent' -Action $a -Principal $p -Force | Out-Null;"
            "Start-ScheduledTask -TaskName 'autosut-cyber-agent';'downloaded=' + $dl",
            log_name="execution/agent_deploy.log",
        )
        paw_id = paw_platform = ""
        for _ in range(30):
            for agent in client.list_agents():
                if agent.get("platform") == "windows":
                    paw_id, paw_platform = agent.get("paw", ""), agent.get("platform", "")
                    break
            if paw_id:
                break
            time.sleep(10)
        state["paw_id"], state["paw_platform"] = paw_id, paw_platform

    def execute_ability() -> None:
        client = state["client"]
        state["ability_dispatched"] = state["operation_terminal"] = False
        if not state.get("paw_id"):
            return
        ability_id = client.create_ability(
            ability_id=f"autosut-regmarker-{secrets.token_hex(4)}",
            name="AutoSUT registry marker (T1112)",
            technique_id="T1112", technique_name="Modify Registry", tactic="defense-evasion",
            command=("New-Item -Path HKLM:\\SOFTWARE\\AutoSUT -Force | Out-Null;"
                     f"New-ItemProperty -Path HKLM:\\SOFTWARE\\AutoSUT -Name marker -Value '{nonce}' -PropertyType String -Force"),
            platform="windows", executor_name="psh",
        )
        state["ability_dispatched"] = bool(ability_id)
        if not ability_id:
            return
        adversary_id = client.create_adversary(name=f"autosut-win-{secrets.token_hex(3)}",
                                                ability_ids=[ability_id])
        operation_id = client.start_operation(name=f"autosut-win-op-{secrets.token_hex(3)}",
                                              adversary_id=adversary_id)
        state["operation_terminal"] = bool(client.wait_operation_done(operation_id, max_seconds=600))

    def independent_oracle() -> None:
        env = state["env"]
        after = env.run_shell(_MARKER_READ, log_name="execution/oracle.log").stdout.strip()
        state["oracle_observed"] = after
        state["effect_observed"] = after.startswith("present:")
        state["effect_matches"] = after == f"present:{nonce}"

    def collect_evidence() -> None:
        env = state["env"]
        verdict = CyberGateVerdict(
            base_sha256_before=state["base_sha_before"],
            base_sha256_after=_sha256(base),
            guest_host_id=env.host_id,
            guest_hostname=state.get("hostname", ""),
            guest_machine_sid=state.get("sid", ""),
            specialize_confirmed=state.get("specialize", False),
            agent_sha256=agent_sha,
            agent_pe_machine=agent_pe,
            paw_registered=bool(state.get("paw_id")),
            paw_id=state.get("paw_id", ""),
            paw_platform=state.get("paw_platform", ""),
            negative_control_absent_before=state.get("negative_control_absent", False),
            ability_dispatched=state.get("ability_dispatched", False),
            operation_reached_terminal_state=state.get("operation_terminal", False),
            independent_effect_observed=state.get("effect_observed", False),
            effect_matches_expected=state.get("effect_matches", False),
        )
        state["verdict"] = verdict
        report = verdict.model_dump()
        report["science_passed"] = verdict.science_passed
        (run_context.run_dir / "verdict.json").write_text(
            __import__("json").dumps(report, indent=2) + "\n", encoding="utf-8")

    def teardown_guest() -> None:
        _teardown_windows_guest(
            state.get("env"), state["guest_ready"],
            clear_panther_answer=clear_panther_answer,
        )

    def teardown_execution_layer() -> None:
        caldera.destroy()
        httpd.shutdown()

    def collect_execution_layer_state() -> None:
        _record_caldera_state(caldera.container_name, run_context.run_dir / "caldera-state.json")

    def inspect_residual() -> ResidualReport:
        residual: list[str] = []
        env = state.get("env")
        if env is not None:
            inventory = env.residual_inventory()
            state["inventory_completed"] = inventory.inventory_completed
            (run_context.run_dir / "windows-qemu" / "residual-inventory.json").write_text(
                inventory.model_dump_json(indent=2), encoding="utf-8")
            if not inventory.inventory_completed:
                residual.append(f"windows-inventory-incomplete:{inventory.probe_errors}")
            residual.extend(inventory.residual_resources)
        else:
            state["inventory_completed"] = False
            residual.append("windows-env-absent:cannot-inventory")
        caldera_inventory = _caldera_container_residual(caldera.container_name)
        state["inventory_completed"] &= caldera_inventory.completed
        residual.extend(caldera_inventory.residual_resources)
        return ResidualReport(scope=f"windows-qemu+caldera:{run_context.run_id}",
                              residual_resources=residual)

    state["base_sha_before"] = _sha256(base)
    controller = LifecycleController(run_context, backend_readiness=lambda: backend_cls.check().ready)

    def record_stage_start(stage_name: str) -> None:
        _record_stage_start(run_context.run_dir, stage_name)

    def tracked_stage(name: str, action: Callable[[], None], timeout_seconds: int,
                      *, is_teardown: bool = False) -> Stage:
        return Stage(name, action, timeout_seconds=timeout_seconds,
                     is_teardown=is_teardown, on_started=record_stage_start)

    result = controller.run(
        label=label,
        forward_stages=[
            tracked_stage("prepare_execution_layer", prepare_execution_layer, 350),
            tracked_stage("materialize", materialize, 1700),
            tracked_stage("negative_control", negative_control, 180),
            tracked_stage("enroll_agent", enroll_agent, 500),
            tracked_stage("execute_ability", execute_ability, 700),
            tracked_stage("independent_oracle", independent_oracle, 180),
            tracked_stage("collect_evidence", collect_evidence, 120),
        ],
        teardown_stages=[
            tracked_stage("collect_execution_layer_state", collect_execution_layer_state,
                          40, is_teardown=True),
            tracked_stage("teardown_guest", teardown_guest, 600, is_teardown=True),
            tracked_stage("teardown_execution_layer", teardown_execution_layer,
                          120, is_teardown=True),
        ],
        inspect_residual=inspect_residual,
    )
    result.evidence_dir = str(run_context.run_dir)
    result.implementation_revision = observed_revision
    (run_context.run_dir / "lifecycle-result.json").write_text(
        result.model_dump_json(indent=2), encoding="utf-8")

    if "verdict" not in state:
        verdict = _failure_verdict(state["base_sha_before"], _sha256(base), agent_sha, agent_pe)
        state["verdict"] = verdict
        (run_context.run_dir / "verdict.json").write_text(
            __import__("json").dumps({**verdict.model_dump(), "science_passed": False}, indent=2) + "\n",
            encoding="utf-8",
        )

    if immutable_base_image is not None and _sha256(immutable_base_image) != immutable_base_sha256:
        raise RuntimeError("immutable Windows base image changed during the run")
    bundle = _build_bundle(
        run_context, observed_revision, result, state, agent_sha, nonce,
        immutable_base_sha256=immutable_base_sha256,
    )
    validation = validate_bundle(bundle)
    (run_context.run_dir / "bundle-validation.json").write_text(
        validation.model_dump_json(indent=2), encoding="utf-8")
    seal_bundle(bundle, run_context.run_dir, result.run_id, run_context.created_at)
    return result, state.get("verdict"), bundle, validation


def _build_bundle(run_context: RunContext, revision: str, result, state: dict, agent_sha: str,
                  nonce: str, *, immutable_base_sha256: str | None = None) -> EvidenceBundle:
    """Map one Windows cyber run into the canonical schema. Integration evidence, not claim-eligible."""
    verdict = state["verdict"]
    env = state.get("env")
    teardown = env.teardown_record if env is not None else None
    return EvidenceBundle(
        experiment_id="windows-cyber",
        identity=RunIdentity(
            run_id=result.run_id, label=result.label, created_at=run_context.created_at,
            backend="windows-qemu", sut_id="windows-cyber", host_id=verdict.guest_host_id),
        provenance=ArtifactProvenance(
            git_revision=revision, revision_dirty="+tree-" in revision,
            base_image_sha256=verdict.base_sha256_before,
            agent_sha256=agent_sha,
            image_digests=(
                {"immutable_base_sha256": immutable_base_sha256}
                if immutable_base_sha256 is not None else {}
            )),
        classification=EvidenceClassification(
            evidence_role="integration", frozen_revision=False, clean_room=False,
            supervised=False, claim_eligible=False),
        procedure=ProcedureEvidence(
            technique_id="T1112", technique_name="Modify Registry", tactic="defense-evasion",
            negative_control_absent_before=verdict.negative_control_absent_before,
            dispatched=verdict.ability_dispatched,
            operation_reached_terminal_state=verdict.operation_reached_terminal_state),
        oracle=OracleEvidence(
            independent_of_executor=True, observed=state.get("oracle_observed", ""),
            expected=f"present:{nonce}", matches=verdict.effect_matches_expected),
        lifecycle=LifecycleEvidence(
            total_seconds=result.total_seconds, forward_completed=result.forward_completed,
            final_state=result.final_state.value,
            guest_exited_naturally=teardown.guest_exited_naturally if teardown else False,
            forced_termination_used=teardown.forced_termination_used if teardown else True,
            stage_names=[stage.name for stage in result.stages]),
        residual=ResidualEvidence(
            scope=result.residual.scope, inventory_completed=state.get("inventory_completed", False),
            residual_resources=result.residual.residual_resources),
        secret_audit=SecretAuditEvidence(
            performed=False, scan_completed=False, scanned_locations=[], leak_found=False),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", type=Path, required=True)
    parser.add_argument("--agent", type=Path, required=True,
                        help="native windows/arm64 gocat agent (PE Aarch64)")
    parser.add_argument("--evidence-root", type=Path,
                        default=PROJECT_ROOT / "release" / "experiments"
                        / "windows_backend_qualification" / "cyber_gate_canonical")
    parser.add_argument("--label", default="run")
    args = parser.parse_args()

    result, verdict, _bundle, validation = run_cyber_gate(
        args.base, args.agent, args.evidence_root, args.label)
    print(f"[cyber-gate] final_state: {result.final_state.value}")
    for stage in result.stages:
        mark = "ok" if stage.succeeded else f"FAILED ({stage.error})"
        print(f"[cyber-gate]   {stage.name}: {stage.seconds}s {mark}")
    print(f"[cyber-gate] residual: {result.residual.residual_resources or 'none'}")
    if verdict is not None:
        print(f"[cyber-gate] science_passed: {verdict.science_passed} paw={verdict.paw_id} "
              f"effect_matches={verdict.effect_matches_expected}")
    print(f"[cyber-gate] bundle admissible: {validation.admissible} "
          f"violations={validation.violations or 'none'}")
    print(f"[cyber-gate] sealed bundle: {result.evidence_dir}")
    lifecycle_clean = result.final_state.value == "clean"
    science_ok = verdict is not None and verdict.science_passed
    return 0 if (lifecycle_clean and science_ok and validation.admissible) else 1


if __name__ == "__main__":
    raise SystemExit(main())
