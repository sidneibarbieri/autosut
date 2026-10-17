#!/usr/bin/env python3
"""Run one campaign end to end through the canonical lifecycle with a per-run isolated Caldera.

Every resource belongs to the run: the SUT container, the attacker container, and a fresh Caldera
server materialized on its own port. The client is pointed at that isolated Caldera, a real Sandcat
enrolls against it, a real ability and operation run, and the effect is confirmed by a probe
independent of Caldera's own status. Each stage is timed. Teardown always runs and destroys all
three containers; verify-clean then samples until the environment is confirmed empty. The
persistent development Caldera is never used here.

Scope note: the ShadowRay service realization is the documented surrogate on this host, so the
service is not the real CVE. The Caldera dispatch, agent, operation, and the independent
marker-file probe are real, and that is what this experiment certifies.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
import time
from contextlib import nullcontext
from pathlib import Path
from collections.abc import Callable

SCRIPTS_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPTS_DIR.parent
for import_root in (SCRIPTS_DIR, PROJECT_ROOT / "src"):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))

from infrastructure.caldera_instance import CALDERA_IMAGE, CalderaInstance  # noqa: E402
from infrastructure.caldera_evidence import (  # noqa: E402
    ExpectedCalderaLink,
    verify_caldera_operation,
)
from infrastructure.docker_namespace import (  # noqa: E402
    DockerInventoryError,
    autosut_resources,
)
from infrastructure.experiment_identity import seeded_hex, seeded_uuid  # noqa: E402
from infrastructure.lifecycle import LifecycleController, ResidualReport, Stage  # noqa: E402
from infrastructure.revision import current_revision  # noqa: E402
from infrastructure.run_context import ExecutionLock, RunContext, seal_directory  # noqa: E402
from infrastructure.qualification import (  # noqa: E402
    prepare_supervised_qualification_metadata,
    write_qualification_metadata,
)
from infrastructure.scenario_observer import (  # noqa: E402
    ProbeSpec,
    collect_scenario_observation,
    run_probe,
)
from infrastructure.supervision_evidence import bind_child_run  # noqa: E402
from infrastructure.verify_clean import sample_until_clean  # noqa: E402
from orchestrator.caldera_client import CalderaClient  # noqa: E402
from orchestrator.catalog import shadowray_sut  # noqa: E402
from orchestrator.environment import DockerEnvironment  # noqa: E402
from orchestrator.injector import inject_ray_2_6_3, inject_ray_dashboard_surrogate  # noqa: E402
from planning.binding_catalog import BindingCatalog  # noqa: E402
from planning.executable_contract import ExecutableCampaignContract  # noqa: E402
from planning.scenario_admission import admit_scenario  # noqa: E402
from planning.scenario_slice import derive_scenario_slice  # noqa: E402
from run_shadowray_via_caldera import (  # noqa: E402
    ABILITY_NAME,
    _confirm_answering_service,
    _ray_job_submission_command,
    _target_container_ip,
)

EVIDENCE_ROOT = PROJECT_ROOT / "release" / "evidence"
LOCK_PATH = PROJECT_ROOT / "release" / "experiments" / "lifecycle" / "experiment.lock"
_SANDCAT_BUILD_ATTEMPTS = 6
_PYTHON_IMAGE_DIGEST = (
    "python@sha256:94c50be2dc994b873b55bc123e95e6dbade08095b3dfd790f51c34de3f08cbb7"
)
_C0045_CONTRACT_PATH = PROJECT_ROOT / "release/plans/C0045.verified-executable-contract.json"
_C0045_CATALOG_PATH = PROJECT_ROOT / "release/plans/C0045.binding-catalog.json"


PROTOCOL_VERSION = "caldera-experiment/1"
_EXPECTED_GUEST_ARCH = "aarch64"

# Conditions emitted only after the corresponding real lifecycle state is observed.  The R4 v2
# protocol imports this contract in its regression test; adding a cell for an invented condition
# therefore fails before any qualifying run begins.
SEMANTIC_BOUNDARY_CONDITIONS = {
    "materialize_caldera": {"caldera_container_created"},
    "verify_caldera_readiness": {"readiness_probe_started"},
    "materialize_sut": {"sut_container_created"},
    "enroll_agent": {"enrollment_poll_active", "agent_registered"},
    "register_and_execute": {"operation_created", "operation_running"},
    "verify_effect": {"effect_probe_started"},
    "persist_execution_evidence": {"execution_evidence_ready"},
    "destroy_attacker": {"attacker_teardown_started"},
    "destroy_sut": {"sut_teardown_started"},
    "destroy_caldera": {"caldera_teardown_started"},
}


def _tool_version(command: list[str]) -> str | None:
    proc = subprocess.run(command, capture_output=True, text=True, check=False, timeout=15)
    output = (proc.stdout or proc.stderr).strip().splitlines()
    return output[0] if output else None


def _image_facts(reference: str) -> dict:
    """The resolved id, architecture, and repo digest of a materialized image.

    Captured after the image is pulled, so a declared multi-arch reference is pinned to the exact
    build that actually ran. check=True: a missing image at provenance time is a real defect that
    must surface, not be recorded as an empty string.
    """
    inspected = subprocess.run(
        [
            "docker",
            "image",
            "inspect",
            reference,
            "--format",
            "{{.Id}}|{{.Architecture}}|{{if .RepoDigests}}{{index .RepoDigests 0}}{{end}}",
        ],
        capture_output=True,
        text=True,
        check=True,
        timeout=15,
    )
    image_id, architecture, repo_digest = (inspected.stdout.strip().split("|", 2) + ["", "", ""])[
        :3
    ]
    return {
        "declared_reference": reference,
        "image_id": image_id,
        "architecture": architecture,
        "resolved_repo_digest": repo_digest,
    }


def _environment_provenance(revision: str) -> dict:
    """Everything about the environment and revision a run executed on, for its bundle."""
    return {
        "implementation_revision": revision,
        "protocol_version": PROTOCOL_VERSION,
        "host_os": _tool_version(["uname", "-sr"]),
        "host_architecture": platform.machine(),
        "python": _tool_version(["python3", "--version"]),
        "docker_client": _tool_version(["docker", "version", "--format", "{{.Client.Version}}"]),
        "docker_server": _tool_version(["docker", "version", "--format", "{{.Server.Version}}"]),
        "images": {
            "caldera": _image_facts(CALDERA_IMAGE),
            "sut_and_attacker": _image_facts(_PYTHON_IMAGE_DIGEST),
        },
    }


def _assert_container_arch(container_name: str) -> None:
    """Fail the run if a materialized container is not the expected guest architecture.

    A digest can resolve to another platform under emulation; this observes the arch that actually
    materialized (uname inside the container) rather than trusting the declared reference.
    """
    observed = subprocess.run(
        ["docker", "exec", container_name, "uname", "-m"],
        capture_output=True,
        text=True,
        check=True,
        timeout=15,
    ).stdout.strip()
    if observed != _EXPECTED_GUEST_ARCH:
        raise RuntimeError(
            f"{container_name} materialized as {observed!r}, expected {_EXPECTED_GUEST_ARCH!r}"
        )


_ELF_MACHINE_AARCH64 = b"\xb7\x00"  # ELF e_machine field for AArch64, little-endian.


def _is_aarch64_elf(binary: bytes) -> bool:
    """True when the bytes are an ELF whose target machine is AArch64.

    A cold Caldera intermittently returns an x86_64 sandcat for an arm64 request; run on an arm64
    host that binary fails under qemu-x86_64 with a missing x86_64 loader. The agent's architecture
    is therefore verified from the ELF header before it is installed, rather than trusted.
    """
    return len(binary) >= 20 and binary[:4] == b"\x7fELF" and binary[18:20] == _ELF_MACHINE_AARCH64


def _download_sandcat_with_retry(client, architecture: str) -> tuple[bytes, list[str]]:
    """Fetch a sandcat binary of the requested architecture, verifying its ELF machine field.

    Each attempt is recorded. An attempt that returns no binary, or a binary of the wrong
    architecture, is retried; after the budget is exhausted this raises rather than installing an
    agent that cannot run on the target.
    """
    attempts: list[str] = []
    for attempt in range(1, _SANDCAT_BUILD_ATTEMPTS + 1):
        binary = client.download_sandcat(platform="linux", architecture=architecture)
        if not binary:
            outcome = "no binary returned"
        elif not _is_aarch64_elf(binary):
            outcome = "wrong architecture (not aarch64)"
        else:
            attempts.append(f"attempt {attempt}: built aarch64")
            return binary, attempts
        attempts.append(f"attempt {attempt}: {outcome}")
        if attempt < _SANDCAT_BUILD_ATTEMPTS:
            time.sleep(5)
    raise RuntimeError(
        f"no aarch64 sandcat after {_SANDCAT_BUILD_ATTEMPTS} attempts: " + "; ".join(attempts)
    )


def _install_and_start_sandcat(client, container: str, caldera_url: str, paw: str) -> list[str]:
    """Install a freshly-built sandcat into the attacker container and start it against Caldera.

    Returns the per-attempt build log so the run bundle records how the agent was obtained.
    """
    binary, build_attempts = _download_sandcat_with_retry(client, architecture="arm64")
    tmp = Path(f"/tmp/sandcat_{container}.bin")
    tmp.write_bytes(binary)
    subprocess.run(
        ["docker", "cp", str(tmp), f"{container}:/usr/local/bin/sandcat"],
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        ["docker", "exec", container, "chmod", "+x", "/usr/local/bin/sandcat"],
        check=True,
        capture_output=True,
        text=True,
    )
    tmp.unlink(missing_ok=True)
    command = (
        f"nohup /usr/local/bin/sandcat -server {caldera_url} -group red "
        f"-paw {paw} -v >/tmp/sandcat.log 2>&1 & echo $! >/tmp/sandcat.pid"
    )
    subprocess.run(
        ["docker", "exec", "-d", container, "bash", "-c", command],
        check=True,
        capture_output=True,
        text=True,
    )
    return build_attempts


def _autosut_resources() -> set[str]:
    """Every autosut-prefixed docker resource, labelled by kind."""
    return autosut_resources()


def _force_remove_container(name: str) -> None:
    subprocess.run(
        ["docker", "rm", "-f", name], capture_output=True, text=True, check=False, timeout=60
    )


def _capture_sandcat_diagnostics(container: str, run_context: RunContext) -> None:
    """Copy the agent's own log and process state into the bundle before the attacker is destroyed.

    Whether enrollment succeeds or times out, the agent's log is the primary evidence of what
    happened, so it is captured unconditionally rather than reconstructed from a guess.
    """
    log = subprocess.run(
        ["docker", "exec", container, "cat", "/tmp/sandcat.log"],
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    process = subprocess.run(
        ["docker", "exec", container, "sh", "-c", "ps aux | grep -i sandcat"],
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    run_context.path("sut", "sandcat.log").write_text(
        f"--- /tmp/sandcat.log ---\n{log.stdout}{log.stderr}\n"
        f"--- process table ---\n{process.stdout}\n",
        encoding="utf-8",
    )


def _write_stage_status(path: Path, stage_name: str) -> None:
    """Atomically record the latest lifecycle stage for an external supervisor."""
    payload = {
        "stage": stage_name,
        "pid": os.getpid(),
        "recorded_at": time.time(),
    }
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    temporary.replace(path)


def _write_semantic_boundary(
    directory: Path,
    stage_name: str,
    condition: str,
    evidence: dict[str, object],
) -> None:
    """Persist one observed lifecycle condition for a versioned interruption protocol.

    A semantic boundary is deliberately separate from the legacy stage-entry status file.  It is
    emitted only after the event named by ``condition`` has been observed in the real lifecycle;
    a matrix driver can therefore refuse to inject when the required state never materializes.
    """
    safe_stage = "".join(
        character if character.isalnum() or character in "-_" else "-" for character in stage_name
    )
    safe_condition = "".join(
        character if character.isalnum() or character in "-_" else "-" for character in condition
    )
    payload = {
        "stage": stage_name,
        "condition": condition,
        "pid": os.getpid(),
        "observed_at": time.time(),
        "evidence": evidence,
    }
    target = directory / f"{safe_stage}--{safe_condition}.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(target.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    temporary.replace(target)


def _build_stages(
    run_context: RunContext,
    state: dict,
    stage_started: Callable[[str], None] | None = None,
    semantic_boundary: Callable[[str, str, dict[str, object]], None] | None = None,
    seed: int = 0,
) -> tuple[list[Stage], list[Stage]]:
    """The full experiment as ordered, individually-timed forward and teardown stages."""
    marker_suffix = seeded_hex(seed, f"{run_context.run_id}-effect-path", 16)
    marker_file = f"/tmp/autosut_effect_{marker_suffix}.txt"
    marker_value = f"autosut-{seeded_hex(seed, f'{run_context.run_id}-effect-value', 32)}"
    state["effect_marker_file"] = marker_file
    state["effect_marker_value"] = marker_value

    def materialize_caldera() -> None:
        cache_hit, preparation_seconds = CalderaInstance.prepare_image()
        state["caldera_image_cache_hit"] = cache_hit
        state["caldera_image_preparation_seconds"] = preparation_seconds
        state["caldera"] = CalderaInstance.materialize(run_context.namespaced("caldera"))
        state["caldera_container_ip"] = _target_container_ip(state["caldera"].container_name)
        if semantic_boundary is not None:
            semantic_boundary(
                "materialize_caldera",
                "caldera_container_created",
                {"container_materialized": True},
            )

    def verify_caldera_readiness() -> None:
        instance = state["caldera"]
        state["caldera_ready_seconds"] = instance.wait_until_ready(
            timeout_seconds=300,
            on_probe_started=(
                lambda: (
                    semantic_boundary(
                        "verify_caldera_readiness",
                        "readiness_probe_started",
                        {"caldera_materialized": True},
                    )
                    if semantic_boundary is not None
                    else None
                )
            ),
        )
        # Bind a client to this run's isolated instance; no module-level global state is involved.
        state["client"] = CalderaClient(
            instance.base_url, instance.read_red_api_key(), instance.container_name
        )

    def materialize_sut() -> None:
        sut = shadowray_sut()
        env = DockerEnvironment.bring_up(sut, run_context.run_dir)
        state["sut_env"] = env
        if semantic_boundary is not None:
            semantic_boundary(
                "materialize_sut",
                "sut_container_created",
                {"sut_materialized": True},
            )
        fidelity = inject_ray_2_6_3(env)
        if not fidelity.success:
            env.run_shell(
                "ray stop --force 2>&1 | head -3 || true", log_name="sut/ray_stop_after_failure.log"
            )
            fidelity = inject_ray_dashboard_surrogate(env)
        if not fidelity.success:
            raise RuntimeError("Ray injection failed on both real and surrogate paths")
        _assert_container_arch(env.container_name)
        state["realization"] = fidelity.realization.value
        state["ray_ip"] = _target_container_ip(env.container_name)
        state["confirmed_answering_service"] = _confirm_answering_service(
            env.container_name, fidelity.realization.value
        )
        # Both images are materialized by now (Caldera and the python base); pin their exact builds.
        state["environment_provenance"] = _environment_provenance(state["implementation_revision"])

    def enroll_agent() -> None:
        attacker = run_context.namespaced("attacker")
        subprocess.run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                attacker,
                "python@sha256:94c50be2dc994b873b55bc123e95e6dbade08095b3dfd790f51c34de3f08cbb7",
                "sleep",
                "900",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=120,
        )
        state["attacker"] = attacker
        _assert_container_arch(attacker)
        paw = f"exp{seeded_hex(seed, 'attacker-paw', 10)}"
        state["paw"] = paw
        client = state["client"]
        caldera_url = f"http://{state['caldera_container_ip']}:8888"
        state["sandcat_build_attempts"] = _install_and_start_sandcat(
            client, attacker, caldera_url, paw
        )
        agent = client.wait_agent_registered(
            paw_substring=paw,
            max_seconds=150,
            on_pending_poll=(
                lambda: (
                    semantic_boundary(
                        "enroll_agent",
                        "enrollment_poll_active",
                        {"sandcat_started": True, "matching_agent_registered": False},
                    )
                    if semantic_boundary is not None
                    else None
                )
            ),
        )
        _capture_sandcat_diagnostics(attacker, run_context)
        if not agent:
            raise RuntimeError("sandcat agent did not register with the isolated Caldera")
        state["agent_paw"] = agent.get("paw")
        if semantic_boundary is not None:
            semantic_boundary(
                "enroll_agent",
                "agent_registered",
                {"matching_agent_registered": True},
            )

    def admit_execution_slice() -> None:
        source_contract = ExecutableCampaignContract.model_validate_json(
            _C0045_CONTRACT_PATH.read_text(encoding="utf-8")
        )
        source_catalog = BindingCatalog.model_validate_json(
            _C0045_CATALOG_PATH.read_text(encoding="utf-8")
        )
        contract, catalog = derive_scenario_slice(source_contract, source_catalog, ("T1190",))
        scenario_dir = run_context.path("scenario")
        scenario_dir.mkdir(parents=True, exist_ok=True)
        run_context.path("scenario", "contract.json").write_text(
            contract.model_dump_json(indent=2) + "\n", encoding="utf-8"
        )
        run_context.path("scenario", "binding-catalog.json").write_text(
            catalog.model_dump_json(indent=2) + "\n", encoding="utf-8"
        )
        endpoint_probe = (
            "import urllib.request; "
            f"response=urllib.request.urlopen('http://{state['ray_ip']}:8265/', timeout=10); "
            "raise SystemExit(0 if response.status == 200 else 1)"
        )

        def running_probe(container: str) -> tuple[str, ...]:
            return (
                "docker",
                "inspect",
                "--format",
                "{{.State.Running}}",
                container,
            )

        observation = collect_scenario_observation(
            contract=contract,
            catalog=catalog,
            run_id=run_context.run_id,
            binding_probes=(
                ProbeSpec(
                    subject_id="actor.primary",
                    argv=running_probe(state["attacker"]),
                    expected_stdout="true",
                ),
                ProbeSpec(
                    subject_id="target.primary",
                    argv=running_probe(state["sut_env"].container_name),
                    expected_stdout="true",
                ),
                ProbeSpec(
                    subject_id="endpoint.public_service",
                    argv=("docker", "exec", state["attacker"], "python3", "-c", endpoint_probe),
                ),
            ),
            fact_probes=(
                ProbeSpec(
                    subject_id="sut.ready",
                    argv=running_probe(state["sut_env"].container_name),
                    expected_stdout="true",
                ),
                ProbeSpec(
                    subject_id="actor.ready",
                    argv=running_probe(state["attacker"]),
                    expected_stdout="true",
                ),
                ProbeSpec(
                    subject_id="sut.ray_dashboard.reachable",
                    argv=("docker", "exec", state["attacker"], "python3", "-c", endpoint_probe),
                ),
                ProbeSpec(
                    subject_id="network:http_available",
                    argv=("docker", "exec", state["attacker"], "python3", "-c", endpoint_probe),
                ),
                ProbeSpec(
                    subject_id="c2_channel",
                    argv=(
                        "docker",
                        "exec",
                        state["attacker"],
                        "sh",
                        "-c",
                        'test -s /tmp/sandcat.pid && kill -0 "$(cat /tmp/sandcat.pid)"',
                    ),
                ),
            ),
            goal_absence_probes=tuple(
                ProbeSpec(
                    subject_id=goal_fact,
                    argv=(
                        "docker",
                        "exec",
                        state["sut_env"].container_name,
                        "sh",
                        "-c",
                        'if [ -e "$1" ]; then printf present; else printf absent; fi',
                        "autosut-goal-probe",
                        marker_file,
                    ),
                    expected_stdout="absent",
                )
                for goal_fact in catalog.goal_facts
            ),
            evidence_root=run_context.run_dir,
        )
        admit_scenario(
            contract,
            catalog,
            observation,
            run_id=run_context.run_id,
            goal_facts=tuple(catalog.goal_facts),
            evidence_root=run_context.run_dir,
        )
        run_context.path("scenario", "observation.json").write_text(
            observation.model_dump_json(indent=2) + "\n", encoding="utf-8"
        )
        state["admitted_contract_sha256"] = contract.content_sha256
        state["admitted_goal_facts"] = catalog.goal_facts

    def register_and_execute() -> None:
        client = state["client"]
        ability_id = client.create_ability(
            ability_id=str(seeded_uuid(seed, "shadowray-ability")),
            name=ABILITY_NAME,
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            tactic="initial-access",
            command=_ray_job_submission_command(
                state["ray_ip"], marker_file=marker_file, marker_value=marker_value
            ),
            description="Posts a job to the Ray dashboard job-submission API and polls it.",
        )
        if not ability_id:
            raise RuntimeError("Caldera ability creation failed")
        adversary_id = client.create_adversary(
            name=f"experiment-{run_context.run_id}",
            ability_ids=[ability_id],
        )
        operation_id = client.start_operation(
            name=f"experiment-{run_context.run_id}",
            adversary_id=adversary_id,
        )
        if not operation_id:
            raise RuntimeError("Caldera operation creation failed")
        if semantic_boundary is not None:
            semantic_boundary(
                "register_and_execute",
                "operation_created",
                {"operation_created": True},
            )
        current_operation = client.get_operation(operation_id) or {}
        if semantic_boundary is not None and current_operation.get("state") == "running":
            semantic_boundary(
                "register_and_execute",
                "operation_running",
                {"operation_state": "running"},
            )
        finished = client.wait_operation_done(operation_id, max_seconds=120)
        operation_report = client.get_operation_report(operation_id) or {}
        run_context.path("caldera", "operation-report.json").write_text(
            json.dumps(operation_report, indent=2) + "\n", encoding="utf-8"
        )
        verified = verify_caldera_operation(
            operation_id=operation_id,
            finished_operation=finished,
            report=operation_report,
            required_links=(ExpectedCalderaLink(paw=state["agent_paw"], ability_id=ability_id),),
        )
        state["operation"] = verified.model_dump(mode="json")

    def verify_effect() -> None:
        if semantic_boundary is not None:
            semantic_boundary(
                "verify_effect",
                "effect_probe_started",
                {"operation_recorded": bool(state.get("operation"))},
            )
        probe = run_probe(
            ProbeSpec(
                subject_id="run.effect_marker",
                argv=(
                    "docker",
                    "exec",
                    state["sut_env"].container_name,
                    "cat",
                    marker_file,
                ),
                expected_stdout=marker_value,
            )
        )
        run_context.path("scenario", "effect-probe.json").write_text(
            probe.model_dump_json(indent=2) + "\n", encoding="utf-8"
        )
        state["independent_effect_confirmed"] = probe.observed
        if not probe.observed:
            raise RuntimeError("independent effect probe did not confirm the run-specific marker")

    def persist_execution_evidence() -> None:
        """Persist the execution-facing state before teardown destroys the live resources.

        This is an actual lifecycle boundary: the operation and independent probe have completed,
        but the final lifecycle result has not yet been produced.  Recording this intermediate
        state makes a fault injected during persistence distinguishable from a failure during
        execution or cleanup.
        """
        persisted = {
            key: value
            for key, value in state.items()
            if key not in ("caldera", "sut_env", "client")
        }
        if semantic_boundary is not None:
            semantic_boundary(
                "persist_execution_evidence",
                "execution_evidence_ready",
                {"independent_effect_observed": "independent_effect_confirmed" in state},
            )
        run_context.path("execution-state-before-teardown.json").write_text(
            json.dumps(persisted, indent=2, default=str), encoding="utf-8"
        )
        state["execution_state_persisted"] = True

    def destroy_attacker() -> None:
        if state.get("attacker"):
            if semantic_boundary is not None:
                semantic_boundary(
                    "destroy_attacker",
                    "attacker_teardown_started",
                    {"attacker_present": True},
                )
            _force_remove_container(state["attacker"])

    def destroy_sut() -> None:
        if state.get("sut_env"):
            if semantic_boundary is not None:
                semantic_boundary(
                    "destroy_sut",
                    "sut_teardown_started",
                    {"sut_present": True},
                )
            _force_remove_container(state["sut_env"].container_name)

    def destroy_caldera() -> None:
        if state.get("caldera"):
            if semantic_boundary is not None:
                semantic_boundary(
                    "destroy_caldera",
                    "caldera_teardown_started",
                    {"caldera_present": True},
                )
            state["caldera"].destroy()

    # Per-stage timeouts bound each step so a stalled stage triggers teardown instead of hanging.
    # Each is set above the stage's own internal waits, so the watchdog fires only on a true stall.
    forward = [
        Stage(
            "materialize_caldera",
            materialize_caldera,
            timeout_seconds=1080,
            on_started=stage_started,
        ),
        Stage(
            "verify_caldera_readiness",
            verify_caldera_readiness,
            timeout_seconds=360,
            on_started=stage_started,
        ),
        Stage("materialize_sut", materialize_sut, timeout_seconds=360, on_started=stage_started),
        Stage("enroll_agent", enroll_agent, timeout_seconds=360, on_started=stage_started),
        Stage(
            "admit_execution_slice",
            admit_execution_slice,
            timeout_seconds=60,
            on_started=stage_started,
        ),
        Stage(
            "register_and_execute",
            register_and_execute,
            timeout_seconds=240,
            on_started=stage_started,
        ),
        Stage("verify_effect", verify_effect, timeout_seconds=60, on_started=stage_started),
        Stage(
            "persist_execution_evidence",
            persist_execution_evidence,
            timeout_seconds=30,
            on_started=stage_started,
        ),
    ]
    teardown = [
        Stage(
            "destroy_attacker",
            destroy_attacker,
            is_teardown=True,
            timeout_seconds=120,
            on_started=stage_started,
        ),
        Stage(
            "destroy_sut",
            destroy_sut,
            is_teardown=True,
            timeout_seconds=120,
            on_started=stage_started,
        ),
        Stage(
            "destroy_caldera",
            destroy_caldera,
            is_teardown=True,
            timeout_seconds=120,
            on_started=stage_started,
        ),
    ]
    return forward, teardown


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--label", default="run", help="tag to distinguish reruns, e.g. run1")
    parser.add_argument("--seed", type=int, default=0, help="frozen experimental seed")
    parser.add_argument(
        "--evidence-root",
        type=Path,
        default=EVIDENCE_ROOT,
        help="directory for raw run bundles",
    )
    parser.add_argument(
        "--stage-status-file",
        type=Path,
        help="atomic status record for an external interruption supervisor",
    )
    parser.add_argument(
        "--semantic-boundary-dir",
        type=Path,
        help="directory for observed semantic-boundary records used by a versioned R4 protocol",
    )
    parser.add_argument("--supervision-id", help="opaque identifier created by run_supervised.py")
    parser.add_argument(
        "--supervision-receipt-file",
        type=Path,
        help="supervisor-owned receipt path; required with --supervision-id",
    )
    parser.add_argument(
        "--supervision-handoff-file",
        type=Path,
        help="child-to-supervisor handoff path; required with --supervision-id",
    )
    parser.add_argument(
        "--supervision-lock-held",
        action="store_true",
        help="the parent supervisor holds the canonical execution lock",
    )
    parser.add_argument(
        "--qualification-protocol-version",
        help="opt in to a final supervised qualification protocol; requires revision and topology",
    )
    parser.add_argument(
        "--qualification-revision",
        help="immutable clean git commit required by the opted-in qualification protocol",
    )
    parser.add_argument(
        "--qualification-topology",
        help="declared topology required by the opted-in qualification protocol",
    )
    args = parser.parse_args()

    supervision_values = (
        args.supervision_id,
        args.supervision_receipt_file,
        args.supervision_handoff_file,
    )
    if any(value is not None for value in supervision_values) and not all(
        value is not None for value in supervision_values
    ):
        parser.error("supervision id, receipt file, and handoff file must be supplied together")
    if args.supervision_lock_held and args.supervision_id is None:
        parser.error("--supervision-lock-held requires supervision evidence arguments")

    observed_revision = current_revision(PROJECT_ROOT)
    try:
        qualification_metadata = prepare_supervised_qualification_metadata(
            protocol_version=args.qualification_protocol_version,
            required_revision=args.qualification_revision,
            topology=args.qualification_topology,
            observed_revision=observed_revision,
            supervised=args.supervision_id is not None,
        )
    except ValueError as error:
        parser.error(str(error))

    run_context = RunContext.create(
        args.evidence_root.resolve(), label=f"shadowray_caldera_{args.label}"
    )
    if args.supervision_id is not None:
        bind_child_run(
            project_root=PROJECT_ROOT,
            run_dir=run_context.run_dir,
            run_id=run_context.run_id,
            experiment="caldera",
            entrypoint=Path(__file__).name,
            supervision_id=args.supervision_id,
            receipt_path=args.supervision_receipt_file,
            handoff_path=args.supervision_handoff_file,
        )
    write_qualification_metadata(run_context.run_dir, qualification_metadata)
    controller = LifecycleController(run_context, backend_readiness=lambda: True)
    baseline = _autosut_resources()
    state: dict = {"implementation_revision": observed_revision, "seed": args.seed}
    stage_started: Callable[[str], None] | None = None
    if args.stage_status_file is not None:
        args.stage_status_file.parent.mkdir(parents=True, exist_ok=True)

        def record_stage_started(stage_name: str) -> None:
            _write_stage_status(args.stage_status_file, stage_name)

        stage_started = record_stage_started
    semantic_boundary: Callable[[str, str, dict[str, object]], None] | None = None
    if args.semantic_boundary_dir is not None:
        args.semantic_boundary_dir.mkdir(parents=True, exist_ok=True)

        def record_semantic_boundary(
            stage: str, condition: str, evidence: dict[str, object]
        ) -> None:
            _write_semantic_boundary(args.semantic_boundary_dir, stage, condition, evidence)

        semantic_boundary = record_semantic_boundary
    forward, teardown = _build_stages(
        run_context, state, stage_started, semantic_boundary, seed=args.seed
    )

    def inspect_residual() -> ResidualReport:
        try:
            temporal = sample_until_clean(
                scope="docker.autosut",
                inventory=lambda: sorted(_autosut_resources() - baseline),
            )
        except DockerInventoryError as error:
            run_context.path("verify-clean-inventory-error.json").write_text(
                error.diagnostic.model_dump_json(indent=2), encoding="utf-8"
            )
            return ResidualReport(
                scope="docker.autosut",
                residual_resources=[f"inventory-unavailable:{error.diagnostic.failure_kind.value}"],
            )
        run_context.path("verify-clean.json").write_text(
            temporal.model_dump_json(indent=2), encoding="utf-8"
        )
        final_sample = temporal.samples[-1].resources if temporal.samples else []
        return ResidualReport(scope=temporal.scope, residual_resources=final_sample)

    lock_context = nullcontext() if args.supervision_lock_held else ExecutionLock(LOCK_PATH)
    with lock_context:
        result = controller.run(args.label, forward, teardown, inspect_residual)

    # Store the bundle location relative to the project root so a published bundle carries no
    # host-specific absolute path.
    result.evidence_dir = str(run_context.run_dir.relative_to(PROJECT_ROOT))
    result.implementation_revision = state["implementation_revision"]
    run_context.path("experiment.json").write_text(
        json.dumps(
            {k: v for k, v in state.items() if k not in ("caldera", "sut_env", "client")},
            indent=2,
            default=str,
        ),
        encoding="utf-8",
    )
    run_context.path("lifecycle-result.json").write_text(
        result.model_dump_json(indent=2), encoding="utf-8"
    )
    run_context.path("stage-timings.json").write_text(
        json.dumps([stage.model_dump() for stage in result.stages], indent=2), encoding="utf-8"
    )
    manifest = seal_directory(run_context.run_dir, result.run_id, run_context.created_at)

    for stage in result.stages:
        mark = "ok" if stage.succeeded else f"FAILED ({stage.error})"
        print(f"[experiment]   {stage.name}: {stage.seconds}s {mark}")
    print(f"[experiment] operation: {state.get('operation')}")
    print(f"[experiment] independent effect confirmed: {state.get('independent_effect_confirmed')}")
    print(f"[experiment] realization: {state.get('realization')}")
    print(
        f"[experiment] final state: {result.final_state.value}; residual: "
        f"{result.residual.residual_resources or 'none'}"
    )
    print(f"[experiment] sealed bundle: {run_context.run_dir} ({manifest.file_count} files)")
    return 0 if result.final_state.value == "clean" else 2


if __name__ == "__main__":
    raise SystemExit(main())
