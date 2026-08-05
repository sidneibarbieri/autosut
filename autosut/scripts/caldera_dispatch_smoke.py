"""End-to-end Caldera dispatch smoke test.

Verifies the sandcat-deployment + REST-API operation flow:

  1. Probe Caldera (must be reachable).
  2. Pick a Caldera ability with a Linux executor for a chosen technique.
  3. Spawn a throwaway python:3.11-slim container on the bridge network.
  4. Drop the matching sandcat binary into it, start it pointing at Caldera.
  5. Wait until Caldera registers the agent in the `red` group.
  6. Create an adversary with just that ability and start an operation.
  7. Wait for the operation to finish, fetch its report, print the link
     outcome (status + stdout) so we can audit the round-trip.
  8. Tear the container and the agent record down.

Run:
    .venv/bin/python scripts/caldera_dispatch_smoke.py
    .venv/bin/python scripts/caldera_dispatch_smoke.py T1083
"""

from __future__ import annotations

import argparse
import platform as _platform
import subprocess
import sys
import time
import uuid
from pathlib import Path

# Make the orchestrator package importable when run as a top-level script.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from orchestrator import caldera_client  # noqa: E402


SANDCAT_PATH_IN_CONTAINER = "/usr/local/bin/sandcat"


def _host_arch_for_sandcat() -> str:
    """Map host architecture (Python's `platform.machine`) to the value
    Caldera expects in the `architecture` download header."""
    machine = _platform.machine().lower()
    if machine in ("aarch64", "arm64"):
        return "arm64"
    return "amd64"


def _spawn_target_container() -> str:
    name = f"autosut-smoke-{uuid.uuid4().hex[:8]}"
    subprocess.run(
        ["docker", "run", "-d", "--name", name, "--rm",
         "--memory", "512m", "--cpus", "1.0",
         "python:3.11-slim", "sleep", "300"],
        check=True, capture_output=True, text=True,
    )
    return name


def _install_sandcat(container: str, binary: bytes) -> None:
    """Copy the sandcat binary into the container via `docker cp` over stdin."""
    tmp = Path(f"/tmp/sandcat_{container}.bin")
    tmp.write_bytes(binary)
    subprocess.run(
        ["docker", "cp", str(tmp), f"{container}:{SANDCAT_PATH_IN_CONTAINER}"],
        check=True, capture_output=True, text=True,
    )
    subprocess.run(
        ["docker", "exec", container, "chmod", "+x", SANDCAT_PATH_IN_CONTAINER],
        check=True, capture_output=True, text=True,
    )
    tmp.unlink(missing_ok=True)


def _start_sandcat(container: str, caldera_url: str, group: str = "red",
                   paw: str | None = None) -> None:
    paw = paw or f"smoke{uuid.uuid4().hex[:6]}"
    cmd = (
        f"nohup {SANDCAT_PATH_IN_CONTAINER} "
        f"-server {caldera_url} "
        f"-group {group} "
        f"-paw {paw} "
        f"-v "
        ">/tmp/sandcat.log 2>&1 &"
    )
    subprocess.run(
        ["docker", "exec", "-d", container, "bash", "-c", cmd],
        check=True, capture_output=True, text=True,
    )


def _teardown_container(container: str) -> None:
    subprocess.run(["docker", "stop", container],
                   capture_output=True, text=True, timeout=30)


def run(target_technique: str = "T1083") -> int:
    print(f"[smoke] target technique: {target_technique}")

    info = caldera_client.probe()
    if not info.api_ok:
        print(f"[smoke] FAIL: Caldera API unreachable at {info.url}")
        return 2
    print(f"[smoke] Caldera OK: {info.url} version={info.server_version}")

    ability = caldera_client.best_ability_for(target_technique, "linux")
    if not ability:
        print(f"[smoke] FAIL: no Caldera ability for {target_technique}")
        return 3
    print(f"[smoke] ability: {ability['ability_id']} — {ability['name']}")
    # Confirm a linux executor exists.
    linux_execs = [e for e in ability.get("executors", [])
                   if e.get("platform") == "linux"]
    if not linux_execs:
        print(f"[smoke] FAIL: ability has no linux executor")
        return 4
    print(f"[smoke] linux executors: {[e.get('name') for e in linux_execs]}")

    caldera_ip = caldera_client.container_ip()
    if not caldera_ip:
        print("[smoke] FAIL: cannot resolve Caldera container IP")
        return 5
    caldera_url = f"http://{caldera_ip}:8888"
    print(f"[smoke] Caldera reachable to SUT at: {caldera_url}")

    arch = _host_arch_for_sandcat()
    binary = caldera_client.download_sandcat(platform="linux",
                                              architecture=arch)
    if not binary:
        print(f"[smoke] FAIL: sandcat download (linux/{arch})")
        return 6
    print(f"[smoke] sandcat binary: {len(binary)} bytes (linux/{arch})")

    container = _spawn_target_container()
    print(f"[smoke] target container: {container}")
    paw = f"smoke{uuid.uuid4().hex[:6]}"

    try:
        _install_sandcat(container, binary)
        _start_sandcat(container, caldera_url, group="red", paw=paw)
        print(f"[smoke] sandcat started; waiting for agent registration ...")
        agent = caldera_client.wait_agent_registered(paw_substring=paw,
                                                      max_seconds=45)
        if not agent:
            # Surface sandcat log to diagnose registration failure.
            proc = subprocess.run(
                ["docker", "exec", container, "cat", "/tmp/sandcat.log"],
                capture_output=True, text=True,
            )
            print(f"[smoke] FAIL: agent did not register; sandcat log:\n{proc.stdout[-800:]}")
            return 7
        print(f"[smoke] agent registered: paw={agent.get('paw')} "
              f"platform={agent.get('platform')} host={agent.get('host')}")

        adv_id = caldera_client.create_adversary(
            name=f"autosut-smoke-{target_technique}",
            ability_ids=[ability["ability_id"]],
            description=f"AutoSUT smoke for {target_technique}",
        )
        if not adv_id:
            print("[smoke] FAIL: create_adversary returned no id")
            return 8
        print(f"[smoke] adversary: {adv_id}")

        op_name = f"autosut-smoke-{int(time.time())}"
        op_id = caldera_client.start_operation(name=op_name,
                                                adversary_id=adv_id,
                                                group="red")
        if not op_id:
            print("[smoke] FAIL: start_operation returned no id")
            return 9
        print(f"[smoke] operation: {op_id} (state=running)")

        op = caldera_client.wait_operation_done(op_id, max_seconds=90)
        if not op:
            print("[smoke] FAIL: could not fetch operation status")
            return 10
        print(f"[smoke] operation final state: {op.get('state')}")

        report = caldera_client.get_operation_report(op_id) or {}
        steps = report.get("steps", {})
        # `steps` is {paw: {steps: [{...}]}} in stock Caldera 5.x.
        any_link = False
        for paw_in_report, info in steps.items():
            for link in info.get("steps", []):
                any_link = True
                ability_block = link.get("ability", {})
                status = link.get("status")
                output_block = link.get("output", "")
                print(f"[smoke]   link: paw={paw_in_report} "
                      f"ability={ability_block.get('ability_id')} "
                      f"name={ability_block.get('name')} status={status}")
                if isinstance(output_block, dict):
                    stdout = (output_block.get("stdout") or "")[:400]
                else:
                    stdout = (output_block or "")[:400]
                if stdout:
                    print(f"[smoke]   stdout (truncated):\n{stdout}")
        if not any_link:
            print("[smoke] FAIL: report contained no links — likely the agent "
                  "never picked up the ability before timeout. Sandcat log:")
            proc = subprocess.run(
                ["docker", "exec", container, "cat", "/tmp/sandcat.log"],
                capture_output=True, text=True,
            )
            print(proc.stdout[-1200:])
            return 11

        print("[smoke] SUCCESS: end-to-end Caldera dispatch verified.")
        return 0
    finally:
        _teardown_container(container)
        print(f"[smoke] teardown: container {container} removed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("technique", nargs="?", default="T1083",
                        help="MITRE technique id to dispatch (default T1083)")
    args = parser.parse_args()
    sys.exit(run(args.technique))
