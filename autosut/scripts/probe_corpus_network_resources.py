#!/usr/bin/env python3
"""Witness declared network resources on a private, gateway-blocked lab network."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import uuid
from contextlib import ExitStack
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from planning.corpus_probe_admission import (  # noqa: E402
    admitted_resource_values,
    load_corpus_blueprint,
)
import planning.corpus_probe_admission as admission_module  # noqa: E402
import planning.gateway_guard as gateway_module  # noqa: E402
import planning.ingress_probe_runtime as runtime_module  # noqa: E402
from planning.gateway_guard import GatewayGuard  # noqa: E402
from planning.ingress_probe_runtime import (  # noqa: E402
    container_command,
    verify_http_service_observations,
    verify_ingress_observations,
    verify_local_resource_observations,
    verify_resolver_observations,
)
from planning.sut_blueprint import BACKEND_RECIPES  # noqa: E402

FIXTURE = b"AUTOSUT SYNTHETIC INGRESS FIXTURE\n"
INGRESS_RESOURCE = "controlled-ingress-channel"
HTTP_RESOURCES = frozenset({"private-lab-http-target", "public-facing-application"})
RESOLVER_RESOURCE = "private-lab-resolver"
DATA_RESOURCE = "declared-decoy-data"
ARCHIVE_RESOURCE = "local-archive-utility"
CHUNK_RESOURCE = "bounded-local-chunk-store"
SUPPORTED_RESOURCES = (
    frozenset(
        {
            INGRESS_RESOURCE,
            RESOLVER_RESOURCE,
            DATA_RESOURCE,
            ARCHIVE_RESOURCE,
            CHUNK_RESOURCE,
        }
    )
    | HTTP_RESOURCES
)
SERVICE_PAGE = b"AUTOSUT SYNTHETIC LAB HTTP SERVICE\n"
DATA_FIXTURE = b"AUTOSUT SYNTHETIC DECOY RECORD\n"


def _run(arguments: list[str], *, timeout: int = 30) -> str:
    return subprocess.run(
        arguments,
        capture_output=True,
        text=True,
        check=True,
        timeout=timeout,
    ).stdout.strip()


def _guest(container: str, source: str) -> str:
    return _run(["docker", "exec", container, "python3", "-c", source])


def _admit(corpus: Path, campaign_id: str):
    blueprint, constraints, file_sha256 = load_corpus_blueprint(corpus, campaign_id)
    if len(blueprint.hosts) != 1 or blueprint.hosts[0].platform != "Linux":
        raise ValueError("network-resource probe requires one Linux target")
    recipe = blueprint.hosts[0].recipe
    if recipe != BACKEND_RECIPES["Linux"]:
        raise ValueError("network-resource probe requires the reviewed Linux recipe")
    values = admitted_resource_values(
        constraints.requirements,
        supported=SUPPORTED_RESOURCES,
    )
    if not values:
        raise ValueError("campaign has no declared network resource")
    return blueprint, file_sha256, values


def _observe_transfer(actor: str, target: str) -> tuple[str, str, str]:
    _guest(
        actor,
        "import pathlib; root=pathlib.Path('/tmp/autosut-probe'); "
        f"root.mkdir(); (root/'fixture').write_bytes({FIXTURE!r})",
    )
    _run(
        [
            "docker",
            "exec",
            "-d",
            actor,
            "sh",
            "-c",
            "python3 -u -m http.server 8769 --bind 0.0.0.0 "
            "--directory /tmp/autosut-probe >/tmp/autosut-probe/server.log 2>&1",
        ]
    )
    transfer = (
        "import pathlib,time,urllib.request; data=None\n"
        "for attempt in range(40):\n"
        " try:\n"
        "  data=urllib.request.urlopen('http://autosut-actor.test:8769/fixture',timeout=2).read(); break\n"
        " except OSError:\n"
        "  if attempt==39: raise\n"
        "  time.sleep(0.1)\n"
        "pathlib.Path('/tmp/ingress-fixture').write_bytes(data)"
    )
    _guest(target, transfer)
    source = _guest(
        actor,
        "import hashlib,pathlib; print(hashlib.sha256("
        "pathlib.Path('/tmp/autosut-probe/fixture').read_bytes()).hexdigest())",
    )
    destination = _guest(
        target,
        "import hashlib,pathlib; print(hashlib.sha256("
        "pathlib.Path('/tmp/ingress-fixture').read_bytes()).hexdigest())",
    )
    server_log = _guest(
        actor, "import pathlib; print(pathlib.Path(" "'/tmp/autosut-probe/server.log').read_text())"
    )
    return source, destination, server_log


def _observe_http_service(actor: str, target: str) -> tuple[str, str, str]:
    _guest(
        target,
        "import pathlib; root=pathlib.Path('/tmp/autosut-service'); "
        f"root.mkdir(); (root/'index.html').write_bytes({SERVICE_PAGE!r})",
    )
    _run(
        [
            "docker",
            "exec",
            "-d",
            target,
            "sh",
            "-c",
            "python3 -u -m http.server 8770 --bind 0.0.0.0 "
            "--directory /tmp/autosut-service >/tmp/autosut-service/server.log 2>&1",
        ]
    )
    request = (
        "import pathlib,time,urllib.request; data=None\n"
        "for attempt in range(40):\n"
        " try:\n"
        "  data=urllib.request.urlopen('http://autosut-target.test:8770/index.html',timeout=2).read(); break\n"
        " except OSError:\n"
        "  if attempt==39: raise\n"
        "  time.sleep(0.1)\n"
        "pathlib.Path('/tmp/service-copy').write_bytes(data)"
    )
    _guest(actor, request)
    source = _guest(
        target,
        "import hashlib,pathlib; print(hashlib.sha256("
        "pathlib.Path('/tmp/autosut-service/index.html').read_bytes()).hexdigest())",
    )
    destination = _guest(
        actor,
        "import hashlib,pathlib; print(hashlib.sha256("
        "pathlib.Path('/tmp/service-copy').read_bytes()).hexdigest())",
    )
    server_log = _guest(
        target,
        "import pathlib; print(pathlib.Path('/tmp/autosut-service/server.log').read_text())",
    )
    return source, destination, server_log


def _observe_resolver(actor: str, target: str, network_name: str) -> tuple[str, str]:
    inspected = json.loads(_run(["docker", "inspect", actor]))[0]
    declared_address = inspected["NetworkSettings"]["Networks"][network_name]["IPAddress"]
    observed_address = _guest(
        target,
        "import socket; print(socket.gethostbyname('autosut-actor.test'))",
    )
    return observed_address, declared_address


def _observe_decoy_data(target: str) -> str:
    _guest(
        target,
        "import pathlib; pathlib.Path('/tmp/autosut-decoy').write_bytes(" f"{DATA_FIXTURE!r})",
    )
    observed = _guest(
        target,
        "import hashlib,pathlib; print(hashlib.sha256("
        "pathlib.Path('/tmp/autosut-decoy').read_bytes()).hexdigest())",
    )
    expected = hashlib.sha256(DATA_FIXTURE).hexdigest()
    verify_local_resource_observations("decoy-data", expected, observed)
    return observed


def _observe_archive(target: str) -> str:
    created = _guest(
        target,
        "import hashlib,pathlib,tarfile\n"
        "path=pathlib.Path('/tmp/autosut-archive.tar')\n"
        "with tarfile.open(path,'w') as archive:\n"
        " archive.add('/tmp/autosut-decoy',arcname='decoy')\n"
        "print(hashlib.sha256(path.read_bytes()).hexdigest())",
    )
    observed = _guest(
        target,
        "import hashlib,pathlib,tarfile\n"
        "path=pathlib.Path('/tmp/autosut-archive.tar')\n"
        "with tarfile.open(path,'r') as archive:\n"
        " assert archive.getnames()==['decoy']\n"
        f" assert archive.extractfile('decoy').read()=={DATA_FIXTURE!r}\n"
        "print(hashlib.sha256(path.read_bytes()).hexdigest())",
    )
    verify_local_resource_observations("archive", created, observed)
    return observed


def _observe_chunk_store(target: str, archive_sha256: str) -> dict:
    _guest(
        target,
        "import pathlib; root=pathlib.Path('/tmp/autosut-chunks'); root.mkdir(); "
        "data=pathlib.Path('/tmp/autosut-archive.tar').read_bytes(); "
        "[(root/f'chunk-{offset:04}').write_bytes(data[offset:offset+1024]) "
        "for offset in range(0,len(data),1024)]",
    )
    observed = json.loads(
        _guest(
            target,
            "import hashlib,json,pathlib; root=pathlib.Path('/tmp/autosut-chunks'); "
            "chunks=sorted(root.glob('chunk-*')); "
            "assert chunks and all(0<len(chunk.read_bytes())<=1024 for chunk in chunks); "
            "data=b''.join(chunk.read_bytes() for chunk in chunks); "
            "assert data==pathlib.Path('/tmp/autosut-archive.tar').read_bytes(); "
            "print(json.dumps({'sha256':hashlib.sha256(data).hexdigest(),"
            "'chunk_count':len(chunks),'maximum_bytes':max(len(chunk.read_bytes()) for chunk in chunks)}))",
        )
    )
    verify_local_resource_observations(
        "bounded-chunk-store",
        archive_sha256,
        observed["sha256"],
    )
    return observed


def probe(corpus: Path, campaign_id: str, output: Path) -> dict:
    if output.exists():
        raise ValueError("receipt already exists")
    blueprint, blueprint_file_sha256, required_resources = _admit(corpus, campaign_id)
    image = blueprint.hosts[0].recipe.base_image
    image_id = _run(["docker", "image", "inspect", image, "--format", "{{.Id}}"])
    suffix = uuid.uuid4().hex[:12]
    network_name = f"autosut-resource-{suffix}"
    actor = f"autosut-actor-{suffix}"
    target = f"autosut-target-{suffix}"
    guard = GatewayGuard(suffix)
    with ExitStack() as cleanup:
        _run(["docker", "network", "create", "--internal", network_name])
        cleanup.callback(_run, ["docker", "network", "rm", network_name])
        network = json.loads(_run(["docker", "network", "inspect", network_name]))[0]
        if not network["Internal"]:
            raise ValueError("resource network has external routing")
        for name, alias in ((actor, "autosut-actor.test"), (target, "autosut-target.test")):
            _run(container_command(name, network_name, image, alias))
            cleanup.callback(_run, ["docker", "rm", "-f", name])
        cleanup.callback(guard.close)
        gateway = guard.install(network, [actor, target])
        observations = {}
        if INGRESS_RESOURCE in required_resources:
            source, destination, server_log = _observe_transfer(actor, target)
            verify_ingress_observations(
                source,
                destination,
                server_log,
                gateway["host_gateway_access"],
            )
            observations[INGRESS_RESOURCE] = {
                "source_sha256": source,
                "destination_sha256": destination,
                "server_log": server_log,
                "request_observed": "GET /fixture " in server_log,
            }
        if HTTP_RESOURCES.intersection(required_resources):
            source, destination, server_log = _observe_http_service(actor, target)
            verify_http_service_observations(
                source,
                destination,
                server_log,
                gateway["host_gateway_access"],
            )
            for resource in HTTP_RESOURCES.intersection(required_resources):
                observations[resource] = {
                    "target_sha256": source,
                    "actor_sha256": destination,
                    "server_log": server_log,
                    "request_observed": "GET /index.html " in server_log,
                    "scope": "Actor-reachable synthetic HTTP service inside the isolated lab.",
                }
        if RESOLVER_RESOURCE in required_resources:
            observed_address, declared_address = _observe_resolver(actor, target, network_name)
            verify_resolver_observations(
                observed_address,
                declared_address,
                gateway["host_gateway_access"],
            )
            observations[RESOLVER_RESOURCE] = {
                "resolved_address": observed_address,
                "declared_address": declared_address,
            }
        if {DATA_RESOURCE, ARCHIVE_RESOURCE, CHUNK_RESOURCE}.intersection(required_resources):
            decoy_hash = _observe_decoy_data(target)
            if DATA_RESOURCE in required_resources:
                observations[DATA_RESOURCE] = {"fixture_sha256": decoy_hash}
            if ARCHIVE_RESOURCE in required_resources or CHUNK_RESOURCE in required_resources:
                archive_hash = _observe_archive(target)
                if ARCHIVE_RESOURCE in required_resources:
                    observations[ARCHIVE_RESOURCE] = {"archive_sha256": archive_hash}
                if CHUNK_RESOURCE in required_resources:
                    observations[CHUNK_RESOURCE] = _observe_chunk_store(target, archive_hash)
    remaining = _run(
        [
            "docker",
            "ps",
            "-a",
            "--filter",
            f"name=autosut-.*-{suffix}$",
            "--format",
            "{{.Names}}",
        ]
    )
    network_remaining = _run(
        [
            "docker",
            "network",
            "ls",
            "--filter",
            f"name=^{network_name}$",
            "--format",
            "{{.Name}}",
        ]
    )
    teardown_clean = not remaining and not network_remaining
    receipt = {
        "schema_version": "autosut-network-resource-probe/v1",
        "campaign_id": campaign_id,
        "blueprint_file_sha256": blueprint_file_sha256,
        "blueprint_content_sha256": blueprint.content_sha256,
        "image_id": image_id,
        "implementation_sha256": {
            "probe": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "admission": hashlib.sha256(Path(admission_module.__file__).read_bytes()).hexdigest(),
            "runtime": hashlib.sha256(Path(runtime_module.__file__).read_bytes()).hexdigest(),
            "gateway_guard": hashlib.sha256(Path(gateway_module.__file__).read_bytes()).hexdigest(),
        },
        "required_resources": required_resources,
        "observations": observations,
        "gateway": gateway,
        "network_internal": True,
        "teardown_clean": teardown_clean,
        "resource_witnessed": teardown_clean,
        "campaign_executed": False,
        "scope": "Synthetic private-lab resource witnesses only; no campaign technique effect or product fidelity certified.",
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(receipt, indent=2) + "\n")
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", required=True, type=Path)
    parser.add_argument("--campaign", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    receipt = probe(args.corpus.resolve(), args.campaign, args.output.resolve())
    print(
        json.dumps(
            {
                key: receipt[key]
                for key in (
                    "campaign_id",
                    "resource_witnessed",
                    "teardown_clean",
                    "campaign_executed",
                )
            }
        )
    )
    return 0 if receipt["resource_witnessed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
