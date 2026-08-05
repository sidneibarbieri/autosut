#!/usr/bin/env python3
"""
Caldera server manager for AutoSUT.

Manages the MITRE Caldera server running locally on the Mac host.
VMs connect to the host via QEMU user-mode gateway (10.0.2.2).

Architecture:
    Mac host: Caldera server -> localhost:8888
    QEMU VMs: Sandcat agent -> http://10.0.2.2:8888
"""

import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

# Caldera installation path; adjust if different.
CALDERA_DIR = Path.home() / "caldera"
CALDERA_SERVER_SCRIPT = CALDERA_DIR / "server.py"
CALDERA_MOCK_SCRIPT = Path(__file__).resolve().parent / "caldera_mock.py"
CALDERA_LOG = Path(__file__).resolve().parent / "evidence" / "caldera-server.log"
CALDERA_PID_FILE = Path(__file__).resolve().parent / "evidence" / "caldera-server.pid"
CALDERA_MODE_FILE = Path(__file__).resolve().parent / "evidence" / "caldera-server.mode"

CALDERA_API_URL = "http://localhost:8888"
CALDERA_API_KEY = "REDAPIKEY123"

# How long to wait for server to become ready
SERVER_STARTUP_TIMEOUT = 120
SERVER_POLL_INTERVAL = 3


def log(msg: str) -> None:
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {msg}")


def is_server_running() -> bool:
    """Check if caldera process is alive via PID file."""
    if not CALDERA_PID_FILE.exists():
        return False
    pid = int(CALDERA_PID_FILE.read_text().strip())
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        CALDERA_PID_FILE.unlink(missing_ok=True)
        CALDERA_MODE_FILE.unlink(missing_ok=True)
        return False


def _read_mode() -> str:
    if not CALDERA_MODE_FILE.exists():
        return "unknown"
    return CALDERA_MODE_FILE.read_text().strip() or "unknown"


def _is_port_open(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)
        return sock.connect_ex((host, port)) == 0


def wait_for_api(timeout: int = SERVER_STARTUP_TIMEOUT) -> bool:
    """Poll Caldera REST API until it responds with abilities."""
    log(f"Waiting for Caldera API (timeout: {timeout}s)...")
    elapsed = 0
    while elapsed < timeout:
        result = subprocess.run(
            ["curl", "-s", "-H", f"KEY: {CALDERA_API_KEY}",
             f"{CALDERA_API_URL}/api/v2/abilities"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0 and result.stdout.strip():
            data = json.loads(result.stdout)
            if isinstance(data, list):
                log(f"OK Caldera API ready: {len(data)} abilities ({elapsed}s)")
                return True
        time.sleep(SERVER_POLL_INTERVAL)
        elapsed += SERVER_POLL_INTERVAL
    log(f"FAIL Caldera API not ready after {timeout}s")
    return False


def get_agent_count() -> int:
    """Return number of live agents registered with Caldera."""
    result = subprocess.run(
        ["curl", "-s", "-H", f"KEY: {CALDERA_API_KEY}",
         f"{CALDERA_API_URL}/api/v2/agents"],
        capture_output=True, text=True, timeout=10,
    )
    if result.returncode != 0:
        return 0
    agents = json.loads(result.stdout)
    return len([a for a in agents if a.get("trusted", False)])


def start() -> bool:
    """Start Caldera server as background process."""
    if is_server_running():
        log("Caldera server already running")
        return wait_for_api()

    if not CALDERA_SERVER_SCRIPT.exists():
        log(f"FAIL Caldera not found at {CALDERA_DIR}")
        log("Install with: git clone --recursive https://github.com/mitre/caldera.git ~/caldera")
        return False

    CALDERA_LOG.parent.mkdir(parents=True, exist_ok=True)
    log_file = CALDERA_LOG.open("w")

    proc = subprocess.Popen(
        [sys.executable, str(CALDERA_SERVER_SCRIPT), "--insecure"],
        cwd=str(CALDERA_DIR),
        stdout=log_file,
        stderr=log_file,
    )

    CALDERA_PID_FILE.write_text(str(proc.pid))
    CALDERA_MODE_FILE.write_text("real")
    log(f"Caldera server started with PID {proc.pid}")

    return wait_for_api()


def start_mock() -> bool:
    """Start the lightweight Caldera-compatible mock service."""
    if is_server_running():
        log("Caldera-compatible service already running")
        return wait_for_api()
    if _is_port_open("127.0.0.1", 8888):
        log("Caldera-compatible service already listening on localhost:8888")
        log("Refusing to overwrite an external service not started by caldera_manager.py")
        return wait_for_api()

    if not CALDERA_MOCK_SCRIPT.exists():
        log(f"FAIL mock server script not found: {CALDERA_MOCK_SCRIPT}")
        return False

    CALDERA_LOG.parent.mkdir(parents=True, exist_ok=True)
    log_file = CALDERA_LOG.open("w")

    proc = subprocess.Popen(
        [sys.executable, str(CALDERA_MOCK_SCRIPT)],
        cwd=str(Path(__file__).resolve().parent),
        stdout=log_file,
        stderr=log_file,
        start_new_session=True,
    )

    CALDERA_PID_FILE.write_text(str(proc.pid))
    CALDERA_MODE_FILE.write_text("mock")
    log(f"Mock Caldera-compatible service started with PID {proc.pid}")

    return wait_for_api()


def stop() -> None:
    """Stop the Caldera server."""
    if not CALDERA_PID_FILE.exists():
        log("Caldera server not running")
        return
    pid = int(CALDERA_PID_FILE.read_text().strip())
    try:
        os.kill(pid, signal.SIGTERM)
        time.sleep(2)
        os.kill(pid, signal.SIGKILL)
        log(f"Caldera server (PID {pid}) stopped")
    except ProcessLookupError:
        log("Caldera server already stopped")
    finally:
        CALDERA_PID_FILE.unlink(missing_ok=True)
        CALDERA_MODE_FILE.unlink(missing_ok=True)


def status() -> None:
    """Print Caldera server status."""
    running = is_server_running()
    if running:
        print("  Caldera server: 🟢 running")
        print(f"  Mode: {_read_mode()}")
        agents = get_agent_count()
        print(f"  Live agents: {agents}")
        print(f"  API: {CALDERA_API_URL}")
        return

    if _is_port_open("127.0.0.1", 8888):
        print("  Caldera server: 🟡 external service detected on localhost:8888")
        print("  Mode: external-or-unmanaged")
        print(f"  API: {CALDERA_API_URL}")
        return

    print("  Caldera server: 🔴 stopped")


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python3 caldera_manager.py [start|start-mock|stop|status|wait]")
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == "start":
        success = start()
        sys.exit(0 if success else 1)
    elif cmd == "start-mock":
        success = start_mock()
        sys.exit(0 if success else 1)
    elif cmd == "stop":
        stop()
    elif cmd == "status":
        status()
    elif cmd == "wait":
        success = wait_for_api()
        sys.exit(0 if success else 1)
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)


if __name__ == "__main__":
    main()
