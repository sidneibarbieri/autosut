"""Attacker-side capability installer.

Capabilities are declared in catalog.py via the AttackerProfile.
This module turns each capability label into a concrete install recipe that
runs in a SEPARATE attacker container. The attacker container has network
reach to the SUT container.
"""

from __future__ import annotations

import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path

from .models import AttackerProfile


PROJECT_ROOT = Path(__file__).resolve().parents[2]
ATTACKER_IMAGE = "autosut/dmz-host:s28"
ATTACKER_DOCKERFILE = PROJECT_ROOT / ".docker" / "dmz-host" / "Dockerfile"


CAPABILITY_INSTALL = {
    # The attacker image bakes these tools in. Per-campaign "install" logs are
    # now deterministic readiness checks rather than network package installs.
    "rpc_rce": "python3 -c 'import requests; print(\"requests_ok\")' && curl --version | head -1",
    "db_dump": "mysql --version",
    "pivot": "ssh -V 2>&1 | head -1; socat -V | head -1",
    "cert_gen": "openssl version",
    "web_rce": "curl --version | head -1",
}


def ensure_attacker_image() -> str:
    """Ensure the reusable attacker image exists before a campaign starts."""
    inspect = subprocess.run(
        ["docker", "image", "inspect", ATTACKER_IMAGE],
        capture_output=True,
        text=True,
        check=False,
    )
    if inspect.returncode == 0:
        return ATTACKER_IMAGE
    if not ATTACKER_DOCKERFILE.exists():
        raise RuntimeError(
            f"Missing attacker Dockerfile: {ATTACKER_DOCKERFILE}. "
            f"Cannot build {ATTACKER_IMAGE}."
        )
    build = subprocess.run(
        [
            "docker", "build",
            "-t", ATTACKER_IMAGE,
            "-f", str(ATTACKER_DOCKERFILE),
            str(ATTACKER_DOCKERFILE.parent),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if build.returncode != 0:
        raise RuntimeError(
            f"Could not build {ATTACKER_IMAGE}. stderr:\n{build.stderr[-2000:]}"
        )
    return ATTACKER_IMAGE


@dataclass
class AttackerEnv:
    container_name: str
    run_dir: Path

    def run_shell(self, command: str, log_name: str | None = None,
                  timeout: int = 300):
        proc = subprocess.run(
            ["docker", "exec", self.container_name, "bash", "-c", command],
            capture_output=True, text=True, timeout=timeout,
        )
        if log_name:
            log_path = self.run_dir / log_name
            log_path.parent.mkdir(parents=True, exist_ok=True)
            log_path.write_text(
                f"$ {command}\nexit_code: {proc.returncode}\n"
                f"--- stdout ---\n{proc.stdout}\n--- stderr ---\n{proc.stderr}\n",
                encoding="utf-8",
            )
        return proc


def bring_up_attacker(profile: AttackerProfile, run_dir: Path,
                      shared_network: str | None = None) -> AttackerEnv:
    container_name = f"autosut-att-{uuid.uuid4().hex[:8]}"
    base_image = ensure_attacker_image()
    args = [
        "docker", "run", "-d",
        "--name", container_name,
        "--rm",
        base_image,
        "sleep", "infinity",
    ]
    if shared_network:
        args[5:5] = ["--network", shared_network]
    subprocess.run(args, capture_output=True, text=True, check=True)

    env = AttackerEnv(container_name=container_name, run_dir=run_dir)
    log_path = run_dir / "attacker" / "install.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text(f"# attacker bring-up\nimage: {base_image}\nname: {container_name}\n",
                        encoding="utf-8")

    for capability in profile.capabilities:
        recipe = CAPABILITY_INSTALL.get(capability)
        if recipe is None:
            continue
        env.run_shell(recipe, log_name=f"attacker/install_{capability}.log", timeout=300)
    return env


def teardown_attacker(env: AttackerEnv) -> bool:
    proc = subprocess.run(
        ["docker", "stop", env.container_name],
        capture_output=True, text=True, check=False, timeout=60,
    )
    log = env.run_dir / "attacker" / "teardown.log"
    log.write_text(
        f"docker stop {env.container_name}\nexit_code: {proc.returncode}\n"
        f"stdout: {proc.stdout}\nstderr: {proc.stderr}\n",
        encoding="utf-8",
    )
    return proc.returncode == 0
