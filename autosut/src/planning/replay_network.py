"""Move prepared Docker actors to a private internal network for execution."""

import json
import subprocess
import uuid
from pathlib import Path
from .gateway_guard import GatewayGuard


class ReplayNetwork:
    def __init__(self):
        self.name = f"autosut-joint-{uuid.uuid4().hex[:12]}"
        self.created = False
        self.guard = GatewayGuard(self.name.removeprefix("autosut-joint-"))
        self.attached: list[str] = []

    def __enter__(self):
        return self

    def isolate(self, target, attacker, run_dir: Path) -> str:
        subprocess.run(["docker", "network", "create", "--internal", self.name], capture_output=True, text=True, check=True, timeout=30)
        self.created = True
        for container in (target.container_name, attacker.container_name):
            inspected = subprocess.run(["docker", "inspect", container], capture_output=True, text=True, check=True, timeout=30)
            networks = json.loads(inspected.stdout)[0]["NetworkSettings"]["Networks"]
            subprocess.run(["docker", "network", "connect", "--alias", ("autosut-channel.test" if container == attacker.container_name else "autosut-target.test"), self.name, container], capture_output=True, text=True, check=True, timeout=30)
            self.attached.append(container)
            for previous in networks:
                subprocess.run(["docker", "network", "disconnect", previous, container], capture_output=True, text=True, check=True, timeout=30)
        receipt = subprocess.run(["docker", "network", "inspect", self.name], capture_output=True, text=True, check=True, timeout=30)
        network = json.loads(receipt.stdout)[0]
        if not network["Internal"]:
            raise RuntimeError("prepared replay network permits external routing")
        observations = []
        target_ip = ""
        for container in self.attached:
            inspected = subprocess.run(["docker", "inspect", container], capture_output=True, text=True, check=True, timeout=30)
            connections = json.loads(inspected.stdout)[0]["NetworkSettings"]["Networks"]
            if set(connections) != {self.name}:
                raise RuntimeError(f"container has an undeclared network: {container}")
            address = connections[self.name]["IPAddress"]
            if container == target.container_name:
                target_ip = address
            observations.append({"container": container, "network": self.name, "address": address})
        gateway_observation = self.guard.install(network, self.attached)
        (run_dir / "gateway-isolation.json").write_text(json.dumps(gateway_observation, indent=2) + "\n")
        (run_dir / "replay-network.json").write_text(json.dumps({"internal": True, "network": self.name, "containers": observations, "setup_network_access": "Package installation precedes replay isolation.", "host_gateway_access": gateway_observation["host_gateway_access"]}, indent=2) + "\n")
        return target_ip

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            self.guard.close()
        finally:
            if self.created:
                subprocess.run(["docker", "network", "rm", self.name], capture_output=True, text=True, check=True, timeout=30)
