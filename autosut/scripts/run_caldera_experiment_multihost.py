#!/usr/bin/env python3
"""Qualify the multi-host infrastructure: two hosts, a per-run network, a fact produced on one host
and consumed on the other, through a per-run isolated Caldera.

This is an infrastructure_qualification_scenario, not a campaign reconstruction: the corpus has no
CTI-grounded Linux credential-to-lateral-movement chain (that grounding is Windows-only, C0029), so
the fact chain here is synthetic and labelled as such. What it qualifies is the real multi-host
infrastructure -- a private per-run network, two distinct host identities each running its own real
Sandcat, a fact produced by host A's agent and consumed by host B's agent through the isolated
Caldera, an effect confirmed on host B by a probe independent of Caldera, and verified teardown of
every run-owned container and network.

Same canonical LifecycleController, RunContext, CalderaInstance, and CalderaClient as the
single-host path; no parallel orchestrator.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from contextlib import nullcontext
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPTS_DIR.parent
for import_root in (SCRIPTS_DIR, PROJECT_ROOT / "src"):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))

from infrastructure.caldera_instance import CalderaInstance  # noqa: E402
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
from infrastructure.run_context import ExecutionLock, RunContext, seal_directory  # noqa: E402
from infrastructure.qualification import (  # noqa: E402
    prepare_supervised_qualification_metadata,
    write_qualification_metadata,
)
from infrastructure.supervision_evidence import bind_child_run  # noqa: E402
from infrastructure.verify_clean import sample_until_clean  # noqa: E402
from orchestrator.caldera_client import CalderaClient  # noqa: E402
from run_caldera_experiment import (  # noqa: E402
    LOCK_PATH,
    _PYTHON_IMAGE_DIGEST,
    _assert_container_arch,
    _environment_provenance,
    _force_remove_container,
    _install_and_start_sandcat,
)

EVIDENCE_ROOT = PROJECT_ROOT / "release" / "evidence"
_HOST_A_CREDENTIAL_PATH = "/tmp/host_a_credential"
_HOST_B_MARKER_PATH = "/tmp/host_b_marker"


def _autosut_multihost_resources() -> set[str]:
    """Autosut resources across containers, networks, and volumes for verified teardown."""
    return autosut_resources()


def _run_host(name: str, network: str) -> None:
    subprocess.run(
        [
            "docker",
            "run",
            "-d",
            "--name",
            name,
            "--network",
            network,
            _PYTHON_IMAGE_DIGEST,
            "sleep",
            "1200",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    )
    _assert_container_arch(name)


def _host_ip(name: str, network: str) -> str:
    return subprocess.run(
        [
            "docker",
            "inspect",
            "-f",
            f'{{{{(index .NetworkSettings.Networks "{network}").IPAddress}}}}',
            name,
        ],
        capture_output=True,
        text=True,
        check=True,
        timeout=15,
    ).stdout.strip()


def _build_stages(run_context: RunContext, state: dict, negative_control: bool, seed: int = 0):
    network = run_context.namespaced("net")
    credential = f"s3cr3t-{seeded_hex(seed, 'credential', 16)}"
    state["synthetic_credential"] = credential
    state["negative_control"] = negative_control

    def materialize_network() -> None:
        subprocess.run(
            ["docker", "network", "create", network],
            check=True,
            capture_output=True,
            text=True,
            timeout=60,
        )
        state["network"] = network

    def materialize_caldera() -> None:
        cache_hit, preparation_seconds = CalderaInstance.prepare_image()
        state["caldera_image_cache_hit"] = cache_hit
        state["caldera_image_preparation_seconds"] = preparation_seconds
        instance = CalderaInstance.materialize(run_context.namespaced("caldera"))
        state["caldera"] = instance
        subprocess.run(
            ["docker", "network", "connect", network, instance.container_name],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        state["caldera_net_ip"] = _host_ip(instance.container_name, network)

    def verify_caldera_readiness() -> None:
        instance = state["caldera"]
        state["caldera_ready_seconds"] = instance.wait_until_ready(timeout_seconds=300)
        state["client"] = CalderaClient(
            instance.base_url, instance.read_red_api_key(), instance.container_name
        )

    def materialize_hosts() -> None:
        host_a = run_context.namespaced("host-a")
        host_b = run_context.namespaced("host-b")
        _run_host(host_a, network)
        _run_host(host_b, network)
        state["host_a"], state["host_b"] = host_a, host_b
        # Host A holds the synthetic credential that its agent will extract into a Caldera fact.
        subprocess.run(
            [
                "docker",
                "exec",
                host_a,
                "sh",
                "-c",
                f"printf '%s' '{credential}' > {_HOST_A_CREDENTIAL_PATH}",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        state["environment_provenance"] = _environment_provenance(state["implementation_revision"])

    def enroll_agents() -> None:
        client = state["client"]
        caldera_url = f"http://{state['caldera_net_ip']}:8888"
        state["build_attempts"] = {}
        for role, container in (("a", state["host_a"]), ("b", state["host_b"])):
            paw = f"host{role}{seeded_hex(seed, f'host-{role}-paw', 10)}"
            state[f"paw_{role}"] = paw
            state["build_attempts"][role] = _install_and_start_sandcat(
                client, container, caldera_url, paw
            )
            agent = client.wait_agent_registered(paw_substring=paw, max_seconds=150)
            if not agent:
                raise RuntimeError(f"sandcat on host {role} did not register")
            state[f"agent_paw_{role}"] = agent["paw"]

    def register_and_execute() -> None:
        client = state["client"]
        produce = client.create_ability(
            ability_id=str(seeded_uuid(seed, "produce-ability")),
            name="produce host-A credential fact",
            technique_id="T1552.001",
            technique_name="Credentials In Files",
            tactic="credential-access",
            command=f"cat {_HOST_A_CREDENTIAL_PATH}",
            fact_source="shadow.credential",
        )
        consume = client.create_ability(
            ability_id=str(seeded_uuid(seed, "consume-ability")),
            name="consume fact on host-B",
            technique_id="T1021",
            technique_name="Remote Services",
            tactic="lateral-movement",
            command=f"printf '%s' '#{{shadow.credential}}' > {_HOST_B_MARKER_PATH} "
            f"&& cat {_HOST_B_MARKER_PATH}",
        )
        if not produce or not consume:
            raise RuntimeError("Caldera ability creation failed")
        state["produce_ability_id"] = produce
        state["consume_ability_id"] = consume
        # Negative control omits the producing ability, so the fact never exists and the consuming
        # ability cannot run: the marker must not appear on host B.
        ordering = [consume] if negative_control else [produce, consume]
        adversary = client.create_adversary(
            name=f"multihost-{run_context.run_id}", ability_ids=ordering
        )
        operation = client.start_operation(
            name=f"multihost-{run_context.run_id}", adversary_id=adversary
        )
        if not operation:
            raise RuntimeError("Caldera operation creation failed")
        finished = client.wait_operation_done(operation, max_seconds=150)
        report = client.get_operation_report(operation) or {}
        run_context.path("caldera", "operation-report.json").write_text(
            json.dumps(report, indent=2) + "\n", encoding="utf-8"
        )
        required = ()
        forbidden = ()
        if negative_control:
            forbidden = (ExpectedCalderaLink(paw=state["agent_paw_b"], ability_id=consume),)
        else:
            required = (
                ExpectedCalderaLink(paw=state["agent_paw_a"], ability_id=produce),
                ExpectedCalderaLink(paw=state["agent_paw_b"], ability_id=consume),
            )
        verified = verify_caldera_operation(
            operation_id=operation,
            finished_operation=finished,
            report=report,
            required_links=required,
            forbidden_links=forbidden,
        )
        state["operation"] = verified.model_dump(mode="json")

    def verify_effect() -> None:
        # Independent of Caldera's status: distinguish an absent marker from a failed probe.
        probe = subprocess.run(
            [
                "docker",
                "exec",
                state["host_b"],
                "sh",
                "-c",
                'if [ -e "$1" ]; then cat "$1"; else printf __ABSENT__; fi',
                "autosut-effect-probe",
                _HOST_B_MARKER_PATH,
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=15,
        )
        marker = probe.stdout.strip()
        state["effect_probe"] = {
            "returncode": probe.returncode,
            "stdout": probe.stdout,
            "stderr": probe.stderr,
            "expected": "__ABSENT__" if negative_control else credential,
        }
        run_context.path("scenario", "effect-probe.json").write_text(
            json.dumps(state["effect_probe"], indent=2) + "\n", encoding="utf-8"
        )
        state["host_b_marker"] = marker
        state["fact_propagated"] = probe.returncode == 0 and marker == credential
        # Success means the effect matches the scenario: propagated in the positive run, absent in
        # the negative control.
        state["scenario_effect_confirmed"] = probe.returncode == 0 and (
            (not negative_control and marker == credential)
            or (negative_control and marker == "__ABSENT__")
        )
        # Aggregator-compatible aliases: the qualifying (positive) runs are the ones whose effect
        # is the propagated fact; the negative control is scored by its own scenario field.
        state["realization"] = "multi_host_infrastructure_scenario"
        state["independent_effect_confirmed"] = state["scenario_effect_confirmed"]
        if not state["scenario_effect_confirmed"]:
            raise RuntimeError("independent multi-host effect probe did not match the scenario")

    def destroy_hosts() -> None:
        for key in ("host_a", "host_b"):
            if state.get(key):
                _force_remove_container(state[key])

    def destroy_caldera() -> None:
        if state.get("caldera"):
            state["caldera"].destroy()

    def destroy_network() -> None:
        if state.get("network"):
            subprocess.run(
                ["docker", "network", "rm", state["network"]],
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )

    forward = [
        Stage("materialize_network", materialize_network, timeout_seconds=60),
        Stage("materialize_caldera", materialize_caldera, timeout_seconds=1080),
        Stage("verify_caldera_readiness", verify_caldera_readiness, timeout_seconds=360),
        Stage("materialize_hosts", materialize_hosts, timeout_seconds=180),
        Stage("enroll_agents", enroll_agents, timeout_seconds=420),
        Stage("register_and_execute", register_and_execute, timeout_seconds=240),
        Stage("verify_effect", verify_effect, timeout_seconds=60),
    ]
    teardown = [
        Stage("destroy_hosts", destroy_hosts, is_teardown=True, timeout_seconds=120),
        Stage("destroy_caldera", destroy_caldera, is_teardown=True, timeout_seconds=120),
        Stage("destroy_network", destroy_network, is_teardown=True, timeout_seconds=60),
    ]
    return forward, teardown


def main() -> int:
    from infrastructure.revision import current_revision

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--label", default="run")
    parser.add_argument("--seed", type=int, default=0, help="frozen experimental seed")
    parser.add_argument(
        "--evidence-root",
        type=Path,
        default=EVIDENCE_ROOT,
        help="directory for raw run bundles",
    )
    parser.add_argument(
        "--negative-control",
        action="store_true",
        help="omit the producing ability; the fact must not propagate",
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
        args.evidence_root.resolve(), label=f"multihost_caldera_{args.label}"
    )
    if args.supervision_id is not None:
        bind_child_run(
            project_root=PROJECT_ROOT,
            run_dir=run_context.run_dir,
            run_id=run_context.run_id,
            experiment="multihost",
            entrypoint=Path(__file__).name,
            supervision_id=args.supervision_id,
            receipt_path=args.supervision_receipt_file,
            handoff_path=args.supervision_handoff_file,
        )
    write_qualification_metadata(run_context.run_dir, qualification_metadata)
    controller = LifecycleController(run_context, backend_readiness=lambda: True)
    baseline = _autosut_multihost_resources()
    state: dict = {"implementation_revision": observed_revision, "seed": args.seed}
    forward, teardown = _build_stages(run_context, state, args.negative_control, seed=args.seed)

    def inspect_residual() -> ResidualReport:
        try:
            temporal = sample_until_clean(
                scope="docker.autosut.multihost",
                inventory=lambda: sorted(_autosut_multihost_resources() - baseline),
            )
        except DockerInventoryError as error:
            run_context.path("verify-clean-inventory-error.json").write_text(
                error.diagnostic.model_dump_json(indent=2), encoding="utf-8"
            )
            return ResidualReport(
                scope="docker.autosut.multihost",
                residual_resources=[f"inventory-unavailable:{error.diagnostic.failure_kind.value}"],
            )
        run_context.path("verify-clean.json").write_text(
            temporal.model_dump_json(indent=2), encoding="utf-8"
        )
        final = temporal.samples[-1].resources if temporal.samples else []
        return ResidualReport(scope=temporal.scope, residual_resources=final)

    lock_context = nullcontext() if args.supervision_lock_held else ExecutionLock(LOCK_PATH)
    with lock_context:
        result = controller.run(args.label, forward, teardown, inspect_residual)

    result.evidence_dir = str(run_context.run_dir.relative_to(PROJECT_ROOT))
    result.implementation_revision = state["implementation_revision"]
    run_context.path("experiment.json").write_text(
        json.dumps(
            {k: v for k, v in state.items() if k not in ("caldera", "client")},
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
        print(
            f"[multihost]   {stage.name}: {stage.seconds}s "
            f"{'ok' if stage.succeeded else 'FAILED (' + str(stage.error) + ')'}"
        )
    print(
        f"[multihost] negative_control={args.negative_control} "
        f"fact_propagated={state.get('fact_propagated')} "
        f"scenario_effect_confirmed={state.get('scenario_effect_confirmed')}"
    )
    print(
        f"[multihost] final state: {result.final_state.value}; "
        f"residual: {result.residual.residual_resources or 'none'}"
    )
    print(f"[multihost] sealed bundle: {run_context.run_dir} ({manifest.file_count} files)")
    return 0 if result.final_state.value == "clean" else 2


if __name__ == "__main__":
    raise SystemExit(main())
