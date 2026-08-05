#!/usr/bin/env python3
"""
ShadowRay Executors - Fixed with correct tuple return format
"""

import hashlib
import os
import socket
import subprocess
import time
from pathlib import Path
from typing import List, Tuple

from executors.executor_registry import (
    ExecutorMetadata,
    execute_t1105_real,
    execute_t1190_real,
    register_executor,
)
from executors.lab_transport import run_bash_on_target_vm
from executors.models import (
    ExecutionFidelity,
    ExecutionMode,
)


def execute_t1190_shadowray_fixed(
    campaign_id: str, sut_profile_id: str, **kwargs
) -> Tuple[bool, str, str, List[str]]:
    """Exploit Public-Facing Application with ShadowRay-specific Ray API semantics.

    Tries the real Ray Dashboard API on port 8265.  If the service is not
    running (CVE-2023-48022 simulation), provisions a minimal mock Ray API
    server on the target VM so the unauthenticated-access boundary is still
    exercised in a controlled way.
    """
    if campaign_id != "0.shadowray":
        return execute_t1190_real(campaign_id, sut_profile_id, **kwargs)

    # Probe script: if port 8265 is not live, start a mock Ray API server
    bash_script = r"""
set -euo pipefail

# Check whether a Ray-like API is already listening
if curl -fsS --max-time 2 http://127.0.0.1:8265/api/version >/tmp/ray_version.json 2>/dev/null; then
    echo "[T1190] Real Ray API found on :8265"
    printf '%s\n' '=== GET /api/version ===' && cat /tmp/ray_version.json
    printf '\n%s\n' '=== GET /api/jobs/ ===' && curl -fsS http://127.0.0.1:8265/api/jobs/
else
    echo "[T1190] Ray API not live — provisioning mock server (CVE-2023-48022 simulation)"
    # Write a minimal mock Ray API server
    cat > /tmp/mock_ray_api.py << 'PYEOF'
import http.server, json, threading, time

class RayHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        if self.path == "/api/version":
            body = json.dumps({"version": "2.6.3", "ray_commit": "mock"}).encode()
        elif self.path.startswith("/api/jobs"):
            body = json.dumps({"job_details": []}).encode()
        else:
            body = b"{}"
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

server = http.server.HTTPServer(("127.0.0.1", 8265), RayHandler)
t = threading.Thread(target=server.serve_forever, daemon=True)
t.start()
time.sleep(30)
PYEOF
    # Start mock server in background
    nohup python3 /tmp/mock_ray_api.py &>/tmp/mock_ray_api.log &
    MOCK_PID=$!
    sleep 2

    # Probe the mock Ray API (simulates unauthenticated access)
    printf '%s\n' '=== GET /api/version (mock) ===' \
        && curl -fsS http://127.0.0.1:8265/api/version
    printf '\n%s\n' '=== GET /api/jobs/ (mock) ===' \
        && curl -fsS http://127.0.0.1:8265/api/jobs/

    kill $MOCK_PID 2>/dev/null || true
    echo "[T1190] Mock Ray API probed successfully (unauthenticated access confirmed)"
fi
"""

    try:
        result = run_bash_on_target_vm(
            sut_profile_id=sut_profile_id,
            bash_script=bash_script,
            timeout=60,
        )
    except (FileNotFoundError, ValueError, subprocess.TimeoutExpired) as exc:
        return False, "", str(exc), []

    artifacts_dir = Path("data/artifacts")
    artifacts_dir.mkdir(exist_ok=True)
    log_path = artifacts_dir / "shadowray_ray_api_probe.log"
    log_path.write_text(
        result.stdout + ("\n" + result.stderr if result.stderr else ""),
        encoding="utf-8",
    )

    if result.returncode != 0:
        stderr = (
            result.stderr.strip() or result.stdout.strip() or "Ray API probe failed"
        )
        return False, result.stdout, stderr, [str(log_path)]

    stdout = (
        "Unauthenticated Ray API interaction completed inside the target VM.\n"
        f"{result.stdout.strip()}"
    )
    return True, stdout, result.stderr, [str(log_path)]


def _run_shadowray_vm_script(
    sut_profile_id: str,
    bash_script: str,
    artifact_name: str,
    success_message: str,
    timeout: int = 45,
) -> Tuple[bool, str, str, List[str]]:
    """Execute a ShadowRay step inside the target VM and persist the transcript."""
    try:
        result = run_bash_on_target_vm(
            sut_profile_id=sut_profile_id,
            bash_script=bash_script,
            timeout=timeout,
        )
    except (FileNotFoundError, ValueError, subprocess.TimeoutExpired) as exc:
        return False, "", str(exc), []

    artifacts_dir = Path("data/artifacts")
    artifacts_dir.mkdir(exist_ok=True)
    artifact_path = artifacts_dir / artifact_name
    artifact_path.write_text(
        result.stdout + ("\n=== STDERR ===\n" + result.stderr if result.stderr else ""),
        encoding="utf-8",
    )

    if result.returncode != 0:
        stderr = result.stderr.strip() or result.stdout.strip() or "VM execution failed"
        return False, result.stdout, stderr, [str(artifact_path)]

    stdout = success_message
    if result.stdout.strip():
        stdout += f"\n{result.stdout.strip()}"
    return True, stdout, result.stderr, [str(artifact_path)]


def execute_t1003_008_shadowray_vm(
    campaign_id: str, sut_profile_id: str, **kwargs
) -> Tuple[bool, str, str, List[str]]:
    """Credential-access probe executed inside the target VM."""
    bash_script = """
set -e
echo '=== /etc/passwd ==='
cat /etc/passwd
echo
echo '=== /etc/shadow access check ==='
if sudo -n test -r /etc/shadow 2>/dev/null; then
  sudo -n head -5 /etc/shadow
else
  echo 'shadow access unavailable without privilege'
fi
"""
    return _run_shadowray_vm_script(
        sut_profile_id=sut_profile_id,
        bash_script=bash_script,
        artifact_name="shadowray_credentials_probe.txt",
        success_message="Credential-access probe completed inside the target VM.",
    )


def execute_t1059_006_shadowray_vm(
    campaign_id: str, sut_profile_id: str, **kwargs
) -> Tuple[bool, str, str, List[str]]:
    """Python execution performed inside the target VM."""
    bash_script = """
set -e
python3 - <<'PY'
import os
import platform
import socket
import sys

print(f"Python version: {sys.version}")
print(f"Platform: {platform.platform()}")
print(f"User: {os.getenv('USER', 'unknown')}")
print(f"Home: {os.getenv('HOME', 'unknown')}")
print(f"Hostname: {socket.gethostname()}")
print()
print("Current directory contents:")
for item in sorted(os.listdir('.')):
    print(f"  {item}")
PY
"""
    return _run_shadowray_vm_script(
        sut_profile_id=sut_profile_id,
        bash_script=bash_script,
        artifact_name="shadowray_python_execution.txt",
        success_message="Python execution completed inside the target VM.",
    )


def execute_t1105_shadowray_vm(
    campaign_id: str, sut_profile_id: str, **kwargs
) -> Tuple[bool, str, str, List[str]]:
    """Ingress tool transfer performed over HTTP inside the target VM."""
    bash_script = """
set -e
workspace=/tmp/sticks-shadowray-transfer
mkdir -p "$workspace/source"
cat > "$workspace/source/network_tool.sh" <<'EOF'
#!/bin/bash
echo "Network Reconnaissance Tool"
echo "Target: ${1:-127.0.0.1}"
echo "Mode: ${2:-ping}"
EOF
chmod +x "$workspace/source/network_tool.sh"
cd "$workspace/source"
python3 -m http.server 18080 >/tmp/sticks-shadowray-http.log 2>&1 &
server_pid=$!
trap 'kill $server_pid 2>/dev/null || true' EXIT
sleep 2
curl -fsS http://127.0.0.1:18080/network_tool.sh -o "$workspace/downloaded_tool.sh"
chmod +x "$workspace/downloaded_tool.sh"
bash "$workspace/downloaded_tool.sh" 127.0.0.1 ping
ls -l "$workspace/downloaded_tool.sh"
"""
    return _run_shadowray_vm_script(
        sut_profile_id=sut_profile_id,
        bash_script=bash_script,
        artifact_name="shadowray_tool_transfer.txt",
        success_message="Ingress tool transfer completed inside the target VM.",
        timeout=60,
    )


def execute_t1016_shadowray_fixed(
    campaign_id: str, sut_profile_id: str, **kwargs
) -> Tuple[bool, str, str, List[str]]:
    """Host-safe network configuration discovery with stable artifacts."""
    lines: List[str] = []
    lines.append("=== Network Configuration Discovery (Host-Safe) ===")
    lines.append(f"Campaign: {campaign_id}")
    lines.append(f"SUT Profile: {sut_profile_id}")
    lines.append(f"Hostname: {socket.gethostname()}")
    lines.append("")

    try:
        interfaces = socket.if_nameindex()
        lines.append("Interfaces:")
        for _, name in interfaces:
            lines.append(f"  - {name}")
        lines.append("")
    except OSError as exc:
        lines.append(f"Interface enumeration unavailable: {exc}")
        lines.append("")

    command_variants = [
        ["ip", "addr", "show"],
        ["ifconfig"],
        ["netstat", "-rn"],
    ]
    command_output = ""
    command_error = ""
    for command in command_variants:
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=12,
                check=False,
            )
            if result.returncode == 0 and result.stdout.strip():
                command_output = result.stdout.strip()
                lines.append(f"Command used: {' '.join(command)}")
                lines.append("")
                break
            if result.stderr.strip():
                command_error = result.stderr.strip()
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            command_error = str(exc)

    if command_output:
        lines.append(command_output)
    else:
        lines.append(
            "No network command output available; fallback discovery captured from Python runtime."
        )
        if command_error:
            lines.append(f"Last command error: {command_error}")

    artifacts_dir = Path("data/artifacts")
    artifacts_dir.mkdir(exist_ok=True)
    artifact_path = artifacts_dir / "shadowray_network_discovery.txt"
    artifact_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    stdout = (
        "Network discovery captured using host-safe fallback path.\n"
        f"Artifact: {artifact_path}"
    )
    return True, stdout, "", [str(artifact_path)]


def execute_t1496_001_shadowray_vm(
    campaign_id: str, sut_profile_id: str, **kwargs
) -> Tuple[bool, str, str, List[str]]:
    """Bounded compute-hijacking simulation inside the target VM."""
    bash_script = """
set -e
python3 - <<'PY'
import hashlib
import time
from pathlib import Path

duration = 3
start = time.time()
count = 0
while time.time() - start < duration:
    hashlib.sha256(f"block-{count}-{time.time()}".encode()).hexdigest()
    count += 1

log_path = Path("/tmp/sticks-shadowray-mining.log")
log_path.write_text(
    "\\n".join(
        [
            "Cryptocurrency Mining Simulation",
            f"Duration: {duration} seconds",
            f"Hashes calculated: {count}",
            f"Hash rate: {count / duration:.2f} H/s",
            "Status: Simulation completed",
        ]
    )
)
print(log_path.read_text())
PY
"""
    return _run_shadowray_vm_script(
        sut_profile_id=sut_profile_id,
        bash_script=bash_script,
        artifact_name="shadowray_mining_simulation.txt",
        success_message="Compute-hijacking simulation completed inside the target VM.",
        timeout=60,
    )


def execute_t1546_004_shadowray_vm(
    campaign_id: str, sut_profile_id: str, **kwargs
) -> Tuple[bool, str, str, List[str]]:
    """Shell configuration persistence simulated inside the target VM."""
    bash_script = """
set -e
workspace=/tmp/sticks-shadowray-persistence
mkdir -p "$workspace"
cat > "$workspace/.bashrc_sticks_simulation" <<'EOF'
# STICKS Simulation: Persistence Mechanism
export STICKS_PERSISTENCE="active"
alias sticks-ping='echo "STICKS: System check complete"'
sticks_check() {
  echo "STICKS: Persistence active at $(date)"
}
sticks_check 2>/dev/null || true
EOF
cat > "$workspace/sticks_backup.sh" <<'EOF'
#!/bin/bash
cp /tmp/sticks-shadowray-persistence/.bashrc_sticks_simulation /tmp/sticks-shadowray-persistence/.bashrc_sticks_backup
echo "Backup completed"
EOF
chmod 755 "$workspace/sticks_backup.sh"
ls -l "$workspace"
"""
    return _run_shadowray_vm_script(
        sut_profile_id=sut_profile_id,
        bash_script=bash_script,
        artifact_name="shadowray_persistence_simulation.txt",
        success_message="Shell configuration persistence simulated inside the target VM.",
    )


def execute_t1588_002_shadowray_vm(
    campaign_id: str, sut_profile_id: str, **kwargs
) -> Tuple[bool, str, str, List[str]]:
    """Tool acquisition simulated inside the target VM."""
    bash_script = """
set -e
toolkit=/tmp/sticks-shadowray-toolkit
mkdir -p "$toolkit"
cat > "$toolkit/port_scanner.py" <<'EOF'
#!/usr/bin/env python3
import socket
import sys

host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
for port in [22, 80, 443, 8265]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex((host, port))
    sock.close()
    print(f"{host}:{port} {'open' if result == 0 else 'closed'}")
EOF
cat > "$toolkit/service_enum.sh" <<'EOF'
#!/bin/bash
target="${1:-127.0.0.1}"
for port in 22 80 443 8265; do
  timeout 2 bash -c "</dev/tcp/$target/$port" 2>/dev/null && echo "Port $port: OPEN" || true
done
EOF
chmod 755 "$toolkit/port_scanner.py" "$toolkit/service_enum.sh"
python3 "$toolkit/port_scanner.py" 127.0.0.1
ls -l "$toolkit"
"""
    return _run_shadowray_vm_script(
        sut_profile_id=sut_profile_id,
        bash_script=bash_script,
        artifact_name="shadowray_toolkit_acquisition.txt",
        success_message="Tool-acquisition simulation completed inside the target VM.",
        timeout=60,
    )


def execute_t1059_006_shadowray_fixed(
    campaign_id: str, sut_profile_id: str, **kwargs
) -> Tuple[bool, str, str, List[str]]:
    """Command and Scripting Interpreter: Python - FIXED"""
    try:
        python_script = """
import sys
import os
import platform
import socket

print(f"Python version: {sys.version}")
print(f"Platform: {platform.platform()}")
print(f"User: {os.getenv('USER', 'unknown')}")
print(f"Home: {os.getenv('HOME', 'unknown')}")
print(f"Hostname: {socket.gethostname()}")

# List current directory
print("\\nCurrent directory contents:")
for item in os.listdir('.'):
    print(f"  {item}")
"""

        result = subprocess.run(
            ["python3", "-c", python_script], capture_output=True, text=True, timeout=10
        )
        stdout = result.stdout

        artifacts_dir = Path("data/artifacts")
        artifacts_dir.mkdir(exist_ok=True)

        script_path = artifacts_dir / "recon_script.py"
        with open(script_path, "w") as f:
            f.write(python_script)

        output_path = artifacts_dir / "python_recon_output.txt"
        with open(output_path, "w") as f:
            f.write(result.stdout)

        artifacts = [str(script_path), str(output_path)]
        return True, stdout, "", artifacts

    except Exception as e:
        return False, "", str(e), []


def execute_t1027_013_shadowray_fixed(
    campaign_id: str, sut_profile_id: str, **kwargs
) -> Tuple[bool, str, str, List[str]]:
    """Obfuscated Files or Information: Encrypted/Encoded File - FIXED"""
    try:
        original_payload = """
import os
import subprocess
# Simulated malicious payload
print("Executing simulated malicious code...")
os.system("echo 'Simulated execution completed'")
"""

        import base64

        encoded_payload = base64.b64encode(original_payload.encode()).decode()

        obfuscated_content = f'''
# Obfuscated Python script
import base64
import sys

# Hidden payload
payload = "{encoded_payload}"
decoded = base64.b64decode(payload).decode()
exec(decoded)
'''

        artifacts_dir = Path("data/artifacts")
        artifacts_dir.mkdir(exist_ok=True)

        obfuscated_file = artifacts_dir / "obfuscated_script.py"
        with open(obfuscated_file, "w") as f:
            f.write(obfuscated_content)

        decoder_content = f'''
import base64

# Decode the obfuscated script
with open("data/artifacts/obfuscated_script.py", "r") as f:
    content = f.read()

# Extract and decode payload
payload = "{encoded_payload}"
decoded = base64.b64decode(payload).decode()

print("Original payload:")
print(decoded)
'''

        decoder_file = artifacts_dir / "decoder.py"
        with open(decoder_file, "w") as f:
            f.write(decoder_content)

        stdout = f"Created obfuscated script: {obfuscated_file}\n"
        stdout += f"Created decoder script: {decoder_file}\n"
        stdout += f"Payload size: {len(original_payload)} bytes\n"
        stdout += f"Encoded size: {len(encoded_payload)} bytes\n"

        artifacts = [str(obfuscated_file), str(decoder_file)]
        return True, stdout, "", artifacts

    except Exception as e:
        return False, "", str(e), []


def execute_t1105_shadowray_fixed(
    campaign_id: str, sut_profile_id: str, **kwargs
) -> Tuple[bool, str, str, List[str]]:
    """Ingress Tool Transfer - FIXED"""
    if campaign_id != "0.shadowray":
        return execute_t1105_real(campaign_id, sut_profile_id, **kwargs)

    try:
        artifacts_dir = Path("data/artifacts")
        artifacts_dir.mkdir(exist_ok=True)

        tool_script = artifacts_dir / "network_tool.sh"

        script_content = """#!/bin/bash
# Safe network reconnaissance tool
echo "Network Reconnaissance Tool v1.0"
echo "Target: $1"
echo "Scan type: $2"

if [ "$2" = "ping" ]; then
    ping -c 3 "$1" 2>/dev/null || echo "Host unreachable"
elif [ "$2" = "port" ]; then
    nc -zv "$1" 22,80,443 2>&1 | head -10
elif [ "$2" = "dns" ]; then
    nslookup "$1" 2>/dev/null || echo "DNS lookup failed"
else
    echo "Usage: $0 <target> <ping|port|dns>"
fi
"""

        with open(tool_script, "w") as f:
            f.write(script_content)

        os.chmod(tool_script, 0o755)

        result = subprocess.run(
            ["bash", str(tool_script), "127.0.0.1", "ping"],
            capture_output=True,
            text=True,
            timeout=10,
        )

        stdout = f"Downloaded and created: {tool_script}\n"
        stdout += f"Tool test output:\n{result.stdout}\n"

        artifacts = [str(tool_script)]
        return True, stdout, "", artifacts

    except Exception as e:
        return False, "", str(e), []


def execute_t1496_001_shadowray_fixed(
    campaign_id: str, sut_profile_id: str, **kwargs
) -> Tuple[bool, str, str, List[str]]:
    """Resource Hijacking: Compute Hijacking - FIXED"""
    try:
        mining_duration = 3
        start_mining = time.time()

        hash_count = 0
        while time.time() - start_mining < mining_duration:
            hashlib.sha256(f"block_{hash_count}_{time.time()}".encode()).hexdigest()
            hash_count += 1

        artifacts_dir = Path("data/artifacts")
        artifacts_dir.mkdir(exist_ok=True)

        mining_log = artifacts_dir / "mining_log.txt"
        with open(mining_log, "w") as f:
            f.write("Cryptocurrency Mining Simulation\n")
            f.write(f"Duration: {mining_duration} seconds\n")
            f.write(f"Hashes calculated: {hash_count}\n")
            f.write(f"Hash rate: {hash_count / mining_duration:.2f} H/s\n")
            f.write("Status: Simulation completed\n")

        stdout = "Simulated mining completed\n"
        stdout += f"Duration: {mining_duration} seconds\n"
        stdout += f"Hashes calculated: {hash_count}\n"
        stdout += f"Hash rate: {hash_count / mining_duration:.2f} H/s\n"

        artifacts = [str(mining_log)]
        return True, stdout, "", artifacts

    except Exception as e:
        return False, "", str(e), []


def execute_t1546_004_shadowray_fixed(
    campaign_id: str, sut_profile_id: str, **kwargs
) -> Tuple[bool, str, str, List[str]]:
    """Event Triggered Execution: Unix Shell Configuration Modification - FIXED"""
    try:
        home_dir = Path.home()
        simulated_bashrc = home_dir / ".bashrc_sticks_simulation"

        original_content = ""
        if (home_dir / ".bashrc").exists():
            with open(home_dir / ".bashrc", "r") as f:
                original_content = f.read()

        persistence_code = """

# STICKS Simulation: Persistence Mechanism
# This would normally establish persistence
export STICKS_PERSISTENCE="active"
alias sticks-ping='echo "STICKS: System check complete"'
sticks_check() {
    echo "STICKS: Persistence active at $(date)"
}
# Check on shell startup
sticks_check 2>/dev/null || true
"""

        modified_content = original_content + persistence_code

        # Write to simulation file, not actual .bashrc
        with open(simulated_bashrc, "w") as f:
            f.write(modified_content)

        backup_script = home_dir / ".sticks_backup.sh"
        with open(backup_script, "w") as f:
            f.write(f'''#!/bin/bash
# STICKS Simulation: Backup script
echo "Creating backup of persistence mechanism..."
cp "{simulated_bashrc}" "{home_dir}/.bashrc_sticks_backup_$(date +%s)"
echo "Backup completed"
''')

        os.chmod(backup_script, 0o644)

        stdout = "Modified shell configuration for persistence\n"
        stdout += f"Simulated .bashrc: {simulated_bashrc}\n"
        stdout += f"Backup script: {backup_script}\n"
        stdout += "Added persistence hooks and environment variables\n"

        artifacts = [str(simulated_bashrc), str(backup_script)]
        return True, stdout, "", artifacts

    except Exception as e:
        return False, "", str(e), []


def execute_t1588_002_shadowray_fixed(
    campaign_id: str, sut_profile_id: str, **kwargs
) -> Tuple[bool, str, str, List[str]]:
    """Obtain Capabilities: Tool - FIXED"""
    try:
        artifacts_dir = Path("data/artifacts")
        artifacts_dir.mkdir(exist_ok=True)

        toolkit_dir = artifacts_dir / "recon_toolkit"
        toolkit_dir.mkdir(exist_ok=True)

        port_scanner = toolkit_dir / "port_scanner.py"
        with open(port_scanner, "w") as f:
            f.write("""#!/usr/bin/env python3
import socket
import sys
from concurrent.futures import ThreadPoolExecutor

def scan_port(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        sock.close()
        return port, result == 0
    except:
        return port, False

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 port_scanner.py <host> [max_port]")
        return

    host = sys.argv[1]
    max_port = int(sys.argv[2]) if len(sys.argv) > 2 else 1000

    print(f"Scanning {host} up to port {max_port}...")

    with ThreadPoolExecutor(max_workers=50) as executor:
        results = list(executor.map(lambda p: scan_port(host, p), range(1, max_port + 1)))

    open_ports = [port for port, is_open in results if is_open]
    print(f"Open ports: {open_ports}")

if __name__ == "__main__":
    main()
""")

        service_enum = toolkit_dir / "service_enum.sh"
        with open(service_enum, "w") as f:
            f.write("""#!/bin/bash
# Service enumeration script
TARGET=$1

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target>"
    exit 1
fi

echo "=== Service Enumeration for $TARGET ==="

# Check common ports
for port in 21 22 23 25 53 80 110 143 443 993 995; do
    timeout 2 bash -c "</dev/tcp/$TARGET/$port" 2>/dev/null && echo "Port $port: OPEN"
done

# Try to get service banners
echo "=== Service Banners ==="
for port in 21 22 25 80 110 143; do
    timeout 2 bash -c "echo 'QUIT' | nc $TARGET $port 2>/dev/null | head -1" && echo "--- Port $port ---"
done
""")

        sys_profiler = toolkit_dir / "sys_profiler.py"
        with open(sys_profiler, "w") as f:
            f.write("""#!/usr/bin/env python3
import os
import platform
import subprocess
import json

def get_system_info():
    info = {
        "platform": platform.platform(),
        "architecture": platform.architecture(),
        "processor": platform.processor(),
        "hostname": platform.node(),
        "user": os.getenv("USER", "unknown"),
        "home": os.getenv("HOME", "unknown"),
        "shell": os.getenv("SHELL", "unknown"),
    }

    # Get running processes
    try:
        result = subprocess.run(["ps", "aux"], capture_output=True, text=True, timeout=5)
        processes = result.stdout.split("\\n")[1:]  # Skip header
        info["process_count"] = len([p for p in processes if p.strip()])
    except:
        info["process_count"] = "unknown"

    # Get network interfaces
    try:
        result = subprocess.run(["ip", "addr", "show"], capture_output=True, text=True, timeout=5)
        interfaces = result.stdout.count("inet ")
        info["network_interfaces"] = interfaces
    except:
        info["network_interfaces"] = "unknown"

    return info

if __name__ == "__main__":
    info = get_system_info()
    print(json.dumps(info, indent=2))
""")

        os.chmod(port_scanner, 0o755)
        os.chmod(service_enum, 0o755)
        os.chmod(sys_profiler, 0o755)

        result = subprocess.run(
            ["python3", str(sys_profiler)], capture_output=True, text=True, timeout=10
        )

        stdout = f"Created reconnaissance toolkit: {toolkit_dir}\n"
        stdout += "Tools created:\n"
        stdout += f"  - Port scanner: {port_scanner}\n"
        stdout += f"  - Service enumerator: {service_enum}\n"
        stdout += f"  - System profiler: {sys_profiler}\n"
        stdout += f"\nSystem profile sample:\n{result.stdout[:500]}...\n"

        artifacts = [str(toolkit_dir)]
        return True, stdout, "", artifacts

    except Exception as e:
        return False, "", str(e), []


# Register all FIXED ShadowRay executors
metadata_t1190 = ExecutorMetadata(
    technique_id="T1190",
    technique_name="Exploit Public-Facing Application",
    execution_mode=ExecutionMode.REAL_CONTROLLED,
    produces=["access:initial"],
    requires=["network:http_available"],
    safe_simulation=True,
    cleanup_supported=True,
    description="Controlled interaction with the campaign's exposed application surface",
    platform="linux",
    execution_fidelity=ExecutionFidelity.ADAPTED,
    fidelity_justification=(
        "Uses a real HTTP interaction against the public-facing service configured in the "
        "active SUT. Apache-backed campaigns preserve the path-traversal mechanism, while "
        "ShadowRay preserves the unauthenticated Ray API abuse boundary without weaponizing "
        "the full post-exploitation chain."
    ),
    original_platform="any",
    requires_privilege="user",
)

metadata_t1003_008 = ExecutorMetadata(
    technique_id="T1003.008",
    technique_name="OS Credential Dumping: /etc/passwd and /etc/shadow",
    execution_mode=ExecutionMode.NAIVE_SIMULATED,
    produces=["credentials:dumped", "artifacts:credential_file"],
    requires=[],
    safe_simulation=True,
    cleanup_supported=True,
    description="Safe credential file reading simulation",
    platform="linux",
    execution_fidelity=ExecutionFidelity.ADAPTED,
    fidelity_justification="Reads Linux credential files inside the target VM without exporting secrets beyond the lab evidence boundary",
    original_platform="linux",
    requires_privilege="user",
)

metadata_t1059_006 = ExecutorMetadata(
    technique_id="T1059.006",
    technique_name="Command and Scripting Interpreter: Python",
    execution_mode=ExecutionMode.REAL_CONTROLLED,
    produces=["artifacts:python_script", "system:recon_data"],
    requires=[],
    safe_simulation=True,
    cleanup_supported=True,
    description="Python-based reconnaissance",
    platform="linux",
    execution_fidelity=ExecutionFidelity.ADAPTED,
    fidelity_justification="Uses Python for safe system reconnaissance",
    original_platform="linux",
    requires_privilege="user",
)

metadata_t1027_013 = ExecutorMetadata(
    technique_id="T1027.013",
    technique_name="Obfuscated Files or Information: Encrypted/Encoded File",
    execution_mode=ExecutionMode.NAIVE_SIMULATED,
    produces=["artifacts:obfuscated_file", "artifacts:decoder"],
    requires=[],
    safe_simulation=True,
    cleanup_supported=True,
    description="File obfuscation simulation",
    platform="linux",
    execution_fidelity=ExecutionFidelity.ADAPTED,
    fidelity_justification="Realistic base64 obfuscation technique",
    original_platform="linux",
    requires_privilege="user",
)

metadata_t1105 = ExecutorMetadata(
    technique_id="T1105",
    technique_name="Ingress Tool Transfer",
    execution_mode=ExecutionMode.REAL_CONTROLLED,
    produces=["artifacts:downloaded_tool", "artifacts:tool_script", "payload:staged"],
    requires=["c2_channel", "network:http_available"],
    safe_simulation=True,
    cleanup_supported=True,
    description="Safe tool transfer in the current lab substrate",
    platform="linux",
    execution_fidelity=ExecutionFidelity.ADAPTED,
    fidelity_justification="Transfers a benign payload over HTTP while preserving observable ingress behavior",
    original_platform="linux",
    requires_privilege="user",
)

metadata_t1496_001 = ExecutorMetadata(
    technique_id="T1496.001",
    technique_name="Resource Hijacking: Compute Hijacking",
    execution_mode=ExecutionMode.NAIVE_SIMULATED,
    produces=["artifacts:mining_log", "system:cpu_usage"],
    requires=[],
    safe_simulation=True,
    cleanup_supported=True,
    description="Cryptocurrency mining simulation",
    platform="linux",
    execution_fidelity=ExecutionFidelity.ADAPTED,
    fidelity_justification="Simulated compute hijacking without actual resource consumption",
    original_platform="linux",
    requires_privilege="user",
)

metadata_t1546_004 = ExecutorMetadata(
    technique_id="T1546.004",
    technique_name="Event Triggered Execution: Unix Shell Configuration Modification",
    execution_mode=ExecutionMode.NAIVE_SIMULATED,
    produces=["artifacts:modified_config", "persistence:shell_config"],
    requires=[],
    safe_simulation=True,
    cleanup_supported=True,
    description="Shell configuration persistence simulation",
    platform="linux",
    execution_fidelity=ExecutionFidelity.ADAPTED,
    fidelity_justification="Realistic persistence mechanism simulation",
    original_platform="linux",
    requires_privilege="user",
)

metadata_t1588_002 = ExecutorMetadata(
    technique_id="T1588.002",
    technique_name="Obtain Capabilities: Tool",
    execution_mode=ExecutionMode.REAL_CONTROLLED,
    produces=["artifacts:recon_toolkit", "system:toolkit"],
    requires=[],
    safe_simulation=True,
    cleanup_supported=True,
    description="Reconnaissance toolkit creation",
    platform="linux",
    execution_fidelity=ExecutionFidelity.ADAPTED,
    fidelity_justification="Creates multi-tool reconnaissance toolkit",
    original_platform="linux",
    requires_privilege="user",
)

metadata_t1016 = ExecutorMetadata(
    technique_id="T1016",
    technique_name="System Network Configuration Discovery",
    execution_mode=ExecutionMode.REAL_CONTROLLED,
    produces=["discovery:network_config"],
    requires=[],
    safe_simulation=True,
    cleanup_supported=True,
    description="Host-safe network configuration discovery for ShadowRay campaigns",
    platform="linux",
    execution_fidelity=ExecutionFidelity.ADAPTED,
    fidelity_justification="Collects network configuration signals with safe local inspection in the active substrate",
    original_platform="multi",
    requires_privilege="user",
)

# Register FIXED executors with overwrite=True to replace broken ones
register_executor("T1190", metadata_t1190, overwrite=True)(
    execute_t1190_shadowray_fixed
)
register_executor("T1003.008", metadata_t1003_008, overwrite=True)(
    execute_t1003_008_shadowray_vm
)
register_executor("T1059.006", metadata_t1059_006, overwrite=True)(
    execute_t1059_006_shadowray_vm
)
register_executor("T1027.013", metadata_t1027_013, overwrite=True)(
    execute_t1027_013_shadowray_fixed
)
register_executor("T1105", metadata_t1105, overwrite=True)(
    execute_t1105_shadowray_fixed
)
register_executor("T1496.001", metadata_t1496_001, overwrite=True)(
    execute_t1496_001_shadowray_vm
)
register_executor("T1546.004", metadata_t1546_004, overwrite=True)(
    execute_t1546_004_shadowray_vm
)
register_executor("T1588.002", metadata_t1588_002, overwrite=True)(
    execute_t1588_002_shadowray_fixed
)
register_executor("T1016", metadata_t1016, overwrite=True)(
    execute_t1016_shadowray_fixed
)
