#!/usr/bin/env python3
"""Read-only preflight for each reviewer path, with the exact fix for every failure.

The Docker checks reuse the namespace inventory and the pinned Caldera image the
replay runner itself uses, so this report and the runner cannot disagree about
what belongs to AutoSUT. Nothing here starts a container, pulls an image,
creates a network, or deletes anything.
"""

from __future__ import annotations

import argparse
import importlib
import ipaddress
import json
import platform
import shutil
import socket
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
for import_root in (PROJECT_ROOT / "scripts", PROJECT_ROOT / "src"):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))

# Same modules as autosut_python_has_reviewer_deps in scripts/python_env.sh;
# tests/test_doctor.py fails if the two lists drift apart.
CORE_MODULES = ("pydantic", "yaml", "click", "pytest")
# Same tools as MEDIA_TOOLS in scripts/qualify_windows_media.py (checked by a test).
MEDIA_TOOLS = ("qemu-img", "mformat", "mcopy", "mtype", "xorriso")
# The replay's persistent C2 publishes this host port (run_all_orchestrated_campaigns.py).
CALDERA_HOST_PORT = 8888
CALDERA_CONTAINER = "autosut-caldera"
# Docker's default local address pools: 172.17.0.0/12 split into /16 networks
# and 192.168.0.0/16 split into /20 networks, 31 bridge networks in total.
DEFAULT_POOLS = (ipaddress.ip_network("172.17.0.0/16").supernet(new_prefix=12),
                 ipaddress.ip_network("192.168.0.0/16"))
DEFAULT_POOL_CAPACITY = 31
# The README's declared floor. Measured host use: about 0.5 GiB for the package,
# its .venv, and a full replay's evidence; image layers live in Docker's own storage.
DISK_FLOOR_GIB = 2


@dataclass
class Check:
    name: str
    status: str  # OK, WARN, FAIL
    detail: str
    fix: str = ""


def run(command: list[str], timeout: int = 20) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(command, capture_output=True, text=True, check=False, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as error:
        return subprocess.CompletedProcess(command, 127, "", str(error))


def check_python() -> list[Check]:
    version = sys.version.split()[0]
    checks = [Check("python", "OK", version)]
    if sys.version_info < (3, 10):
        checks[0] = Check("python", "FAIL", version, "Install Python 3.10 or newer.")
    missing = []
    for module in CORE_MODULES:
        try:
            importlib.import_module(module)
        except ImportError:
            missing.append(module)
    if missing:
        checks.append(Check("python packages", "FAIL", "missing: " + ", ".join(missing),
                            "./run.sh demo   # creates .venv and installs requirements-reviewer.txt"))
    else:
        checks.append(Check("python packages", "OK", ", ".join(CORE_MODULES) + " importable"))
    return checks


def check_docker_daemon() -> tuple[list[Check], bool]:
    if not shutil.which("docker"):
        return [Check("docker", "FAIL", "not on PATH",
                      "Install Docker Desktop, or: brew install colima docker && colima start")], False
    info = run(["docker", "info", "--format", "{{.ServerVersion}} {{.Architecture}}"])
    if info.returncode != 0:
        return [Check("docker", "FAIL", "daemon unreachable",
                      "colima start   # or start Docker Desktop, then rerun ./run.sh doctor")], False
    server, _, architecture = info.stdout.strip().partition(" ")
    checks = [Check("docker", "OK", f"server {server}, {architecture}")]
    if architecture in ("aarch64", "arm64"):
        checks.append(Check("amd64 emulation", "WARN",
                            "the pinned Caldera image is linux/amd64 and runs emulated on this host",
                            "If the Caldera-backed campaigns fail to start, enable amd64 emulation "
                            "(Docker Desktop: Rosetta; colima: start --vm-type vz --vz-rosetta)."))
    return checks, True


def check_namespace() -> list[Check]:
    from infrastructure.docker_namespace import DockerInventoryError, autosut_resources

    try:
        resources = sorted(autosut_resources())
    except DockerInventoryError as error:
        return [Check("autosut- namespace", "FAIL", str(error), "colima start   # or start Docker Desktop")]
    if not resources:
        return [Check("autosut- namespace", "OK", "empty")]
    if shutil.which("pgrep") is None:
        return [Check("autosut- namespace", "FAIL", "occupied; process ownership could not be inspected",
                      "Inspect the resource owner before cleanup; pgrep is unavailable.")]
    running = run(["pgrep", "-f",
                   "run_all_orchestrated_campaigns.py|run_reviewer_supervised.py|prove_subdetermination.py"]).stdout.split()
    if running:
        return [Check("autosut- namespace", "FAIL",
                      f"an operation is in progress (pid {', '.join(running)}); "
                      f"{len(resources)} autosut-* resource(s) exist",
                      "Let that operation finish; it removes its own resources.")]
    commands = []
    for resource in resources:
        kind, _, name = resource.partition(":")
        commands.append({"container": f"docker rm -f {name}", "network": f"docker network rm {name}",
                         "volume": f"docker volume rm {name}"}[kind])
    return [Check("autosut- namespace", "FAIL",
                  f"{len(resources)} resource(s) use the reserved prefix: " + ", ".join(resources[:6]),
                  "The supervised entry point refuses an occupied namespace. If these are confirmed leftovers of an "
                  "interrupted replay: " + " && ".join(commands[:6])
                  + "; if they belong to something else, rename them first.")]


def port_is_bound(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(1)
        return probe.connect_ex(("127.0.0.1", port)) == 0


def check_caldera_port() -> list[Check]:
    if not port_is_bound(CALDERA_HOST_PORT):
        return [Check("port 8888", "OK", "free for the replay's C2")]
    owner = run(["docker", "ps", "--filter", f"publish={CALDERA_HOST_PORT}", "--format", "{{.Names}}"])
    names = owner.stdout.split()
    if names == [CALDERA_CONTAINER]:
        return [Check("port 8888", "FAIL", f"held by existing {CALDERA_CONTAINER}",
                      "Let its owner finish; remove only confirmed leftovers listed by the namespace check.")]
    holder = ", ".join(names) if names else "a non-Docker process"
    fix = (f"docker stop {' '.join(names)}" if names else
           "lsof -nP -iTCP:8888 -sTCP:LISTEN   # then stop that process")
    return [Check("port 8888", "FAIL", f"in use by {holder}; the replay's C2 publishes 8888", fix)]


def check_address_pool() -> list[Check]:
    listing = run(["docker", "network", "ls", "--format", "{{.Name}}"])
    used = []
    for name in listing.stdout.split():
        for network in json.loads(run(["docker", "network", "inspect", name]).stdout or "[]"):
            for config in network.get("IPAM", {}).get("Config") or []:
                subnet = config.get("Subnet", "")
                try:
                    parsed = ipaddress.ip_network(subnet)
                except ValueError:
                    continue
                if parsed.version == 4 and any(parsed.subnet_of(pool) for pool in DEFAULT_POOLS):
                    used.append(name)
    free = DEFAULT_POOL_CAPACITY - len(used)
    # A campaign creates at most a few internal networks at once.
    if free >= 4:
        return [Check("docker address pool", "OK", f"{len(used)} of ~{DEFAULT_POOL_CAPACITY} default subnets in use")]
    return [Check("docker address pool", "FAIL",
                  f"{len(used)} of ~{DEFAULT_POOL_CAPACITY} default subnets in use; new networks "
                  "would fail with 'could not find an available, non-overlapping IPv4 address pool'",
                  "docker network ls   # remove networks you no longer need with docker network rm NAME")]


def check_disk(path: Path) -> list[Check]:
    probe = path
    while not probe.exists():
        probe = probe.parent
    free = shutil.disk_usage(probe).free / 1024**3
    if free < DISK_FLOOR_GIB:
        return [Check("disk space", "FAIL", f"{free:.0f} GiB free (floor {DISK_FLOOR_GIB} GiB)",
                      f"Free at least {DISK_FLOOR_GIB} GiB, or reclaim unused images: docker image prune")]
    return [Check("disk space", "OK", f"{free:.0f} GiB free (floor {DISK_FLOOR_GIB} GiB)")]


def check_caldera_image() -> list[Check]:
    from infrastructure.caldera_instance import CALDERA_IMAGE

    if run(["docker", "image", "inspect", CALDERA_IMAGE]).returncode == 0:
        return [Check("Caldera image", "OK", "pinned digest present locally")]
    return [Check("Caldera image", "WARN", "pinned digest not present; the first replay pulls it",
                  "Needs network access to ghcr.io on the first run (no action if online).")]


def check_media_tools() -> list[Check]:
    missing = [tool for tool in MEDIA_TOOLS if shutil.which(tool) is None]
    if not missing:
        return [Check("media tools", "OK", ", ".join(MEDIA_TOOLS))]
    return [Check("media tools", "FAIL", "missing: " + ", ".join(missing),
                  "brew install qemu mtools xorriso   # Debian/Ubuntu: apt install qemu-utils mtools xorriso")]


def collect(path: str) -> list[Check]:
    checks = check_python()
    if path in ("replay", "all"):
        docker_checks, reachable = check_docker_daemon()
        checks += docker_checks
        if reachable:
            checks += check_namespace()
            checks += check_caldera_port()
            checks += check_address_pool()
            checks += check_caldera_image()
        checks += check_disk(PROJECT_ROOT)
    if path in ("windows-media", "all"):
        checks += check_media_tools()
    return checks


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--path", choices=("review", "replay", "windows-media", "all"), default="replay",
                        help="review: offline gate; replay: Docker campaigns and witness; "
                             "windows-media: FAT/ISO qualification")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable results.")
    args = parser.parse_args()
    checks = collect(args.path)
    failed = sum(check.status == "FAIL" for check in checks)
    if args.json:
        print(json.dumps([asdict(check) for check in checks], indent=2))
    else:
        width = max(len(check.name) for check in checks)
        print(f"host: {platform.system()} {platform.machine()}; path: {args.path}")
        for check in checks:
            print(f"[{check.status:<4}] {check.name:<{width}}  {check.detail}")
            if check.fix and check.status != "OK":
                print(f"{'':7}{'':<{width}}  fix: {check.fix}")
        print(f"\n{len(checks)} checks, {failed} failing" + ("" if failed else ": ready"))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
