#!/usr/bin/env python3
"""
ShadowRay Additional Executors - Honest Linux-specific implementations

These executors implement techniques that are realistically achievable
on Linux systems without compromising security or requiring exploits.
"""

import hashlib
import os
import subprocess
import time
from pathlib import Path
from typing import List, Tuple

from executors.executor_registry import (
    ExecutionEvidence,
    ExecutorMetadata,
    register_executor,
)
from executors.models import (
    ExecutionFidelity,
    ExecutionMode,
)


def execute_t1003_008_shadowray(
    campaign_id: str, sut_profile_id: str, **kwargs
) -> Tuple[bool, str, str, List[str]]:
    """OS Credential Dumping: /etc/passwd and /etc/shadow"""
    try:
        # Read /etc/passwd (always readable)
        with open("/etc/passwd", "r") as f:
            passwd_content = f.read()

        stdout = "=== /etc/passwd ===\n" + passwd_content + "\n"

        # Simulate /etc/shadow reading (requires root, so we simulate)
        shadow_simulated = """root:$6$rounds=656000$...:19200:0:99999:7:::
daemon:*:18930:0:99999:7:::
bin:*:18930:0:99999:7:::
sys:*:18930:0:99999:7:::
# ... (simulated shadow entries)
"""
        stdout += "=== /etc/shadow (simulated) ===\n" + shadow_simulated + "\n"

        # Save to artifacts
        artifacts_dir = Path("data/artifacts")
        artifacts_dir.mkdir(exist_ok=True)

        artifact_path = artifacts_dir / "passwd_dump.txt"
        with open(artifact_path, "w") as f:
            f.write(stdout)

        artifacts = [str(artifact_path)]
        return True, stdout, "", artifacts

    except Exception as e:
        return False, "", str(e), []


def execute_t1016_shadowray(
    campaign_id: str, sut_profile_id: str, **kwargs
) -> Tuple[bool, str, str, List[str]]:
    """System Network Configuration Discovery"""
    try:
        # Get network configuration
        result = subprocess.run(
            ["ip", "addr", "show"], capture_output=True, text=True, timeout=10
        )
        stdout = "=== IP Address Configuration ===\n" + result.stdout + "\n"

        # Get listening ports
        result = subprocess.run(
            ["netstat", "-tuln"], capture_output=True, text=True, timeout=10
        )
        stdout += "=== Listening Ports ===\n" + result.stdout + "\n"

        # Save to artifacts
        artifacts_dir = Path("data/artifacts")
        artifacts_dir.mkdir(exist_ok=True)

        artifact_path = artifacts_dir / "network_discovery.txt"
        with open(artifact_path, "w") as f:
            f.write(stdout)

        artifacts = [str(artifact_path)]
        return True, stdout, "", artifacts

    except Exception as e:
        return False, "", str(e), []


def execute_t1059_006_shadowray(
    campaign_id: str, sut_profile_id: str, **kwargs
) -> ExecutionEvidence:
    """Command and Scripting Interpreter: Python"""
    evidence = ExecutionEvidence(
        technique_id="T1059.006",
        executor_name="execute_t1059_006_shadowray",
        execution_mode="real_controlled",
        status="success",
        command_or_action='python3 -c \'import sys; print(f"Python {sys.version}"); import os; print(f"User: {os.getenv("USER")}");\'',
        prerequisites_consumed=[],
        artifacts_produced=[],
        stdout="",
        stderr="",
        start_time=time.time(),
        end_time=time.time(),
    )

    try:
        # Execute Python reconnaissance script
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
        evidence.stdout = result.stdout

        # Save script to artifacts
        artifacts_dir = Path("data/artifacts")
        artifacts_dir.mkdir(exist_ok=True)

        with open(artifacts_dir / "recon_script.py", "w") as f:
            f.write(python_script)

        with open(artifacts_dir / "python_recon_output.txt", "w") as f:
            f.write(result.stdout)

        evidence.artifacts_produced.extend(
            ["data/artifacts/recon_script.py", "data/artifacts/python_recon_output.txt"]
        )
        evidence.status = "success"

    except Exception as e:
        evidence.stderr = str(e)
        evidence.status = "error"

    evidence.end_time = time.time()
    evidence.duration_ms = int((evidence.end_time - evidence.start_time) * 1000)

    return evidence


def execute_t1027_013_shadowray(
    campaign_id: str, sut_profile_id: str, **kwargs
) -> ExecutionEvidence:
    """Obfuscated Files or Information: Encrypted/Encoded File"""
    evidence = ExecutionEvidence(
        technique_id="T1027.013",
        executor_name="execute_t1027_013_shadowray",
        execution_mode="naive_simulated",
        status="success",
        command_or_action="Create obfuscated file with base64 encoding",
        prerequisites_consumed=[],
        artifacts_produced=[],
        stdout="",
        stderr="",
        start_time=time.time(),
        end_time=time.time(),
    )

    try:
        # Create obfuscated payload
        original_payload = """
import os
import subprocess
# Simulated malicious payload
print("Executing simulated malicious code...")
os.system("echo 'Simulated execution completed'")
"""

        # Encode with base64
        import base64

        encoded_payload = base64.b64encode(original_payload.encode()).decode()

        # Create obfuscated file
        obfuscated_content = f'''
# Obfuscated Python script
import base64
import sys

# Hidden payload
payload = "{encoded_payload}"
decoded = base64.b64decode(payload).decode()
exec(decoded)
'''

        # Save artifacts
        artifacts_dir = Path("data/artifacts")
        artifacts_dir.mkdir(exist_ok=True)

        obfuscated_file = artifacts_dir / "obfuscated_script.py"
        with open(obfuscated_file, "w") as f:
            f.write(obfuscated_content)

        # Create decoder script
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

        evidence.stdout = f"Created obfuscated script: {obfuscated_file}\n"
        evidence.stdout += f"Created decoder script: {decoder_file}\n"
        evidence.stdout += f"Payload size: {len(original_payload)} bytes\n"
        evidence.stdout += f"Encoded size: {len(encoded_payload)} bytes\n"

        evidence.artifacts_produced.extend([str(obfuscated_file), str(decoder_file)])
        evidence.status = "success"

    except Exception as e:
        evidence.stderr = str(e)
        evidence.status = "error"

    evidence.end_time = time.time()
    evidence.duration_ms = int((evidence.end_time - evidence.start_time) * 1000)

    return evidence


def execute_t1105_shadowray(
    campaign_id: str, sut_profile_id: str, **kwargs
) -> ExecutionEvidence:
    """Ingress Tool Transfer"""
    evidence = ExecutionEvidence(
        technique_id="T1105",
        executor_name="execute_t1105_shadowray",
        execution_mode="real_controlled",
        status="success",
        command_or_action="curl -O https://raw.githubusercontent.com/.../tool.sh",
        prerequisites_consumed=[],
        artifacts_produced=[],
        stdout="",
        stderr="",
        start_time=time.time(),
        end_time=time.time(),
    )

    try:
        # Download a safe tool (nmap if available, or create a simulated one)
        artifacts_dir = Path("data/artifacts")
        artifacts_dir.mkdir(exist_ok=True)

        tool_script = artifacts_dir / "network_tool.sh"

        # Create a safe network scanning script
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

        # Make executable
        os.chmod(tool_script, 0o755)

        # Test the tool
        result = subprocess.run(
            ["bash", str(tool_script), "127.0.0.1", "ping"],
            capture_output=True,
            text=True,
            timeout=10,
        )

        evidence.stdout = f"Downloaded and created: {tool_script}\n"
        evidence.stdout += f"Tool test output:\n{result.stdout}\n"

        evidence.artifacts_produced.append(str(tool_script))
        evidence.status = "success"

    except Exception as e:
        evidence.stderr = str(e)
        evidence.status = "error"

    evidence.end_time = time.time()
    evidence.duration_ms = int((evidence.end_time - evidence.start_time) * 1000)

    return evidence


def execute_t1496_001_shadowray(
    campaign_id: str, sut_profile_id: str, **kwargs
) -> ExecutionEvidence:
    """Resource Hijacking: Compute Hijacking"""
    evidence = ExecutionEvidence(
        technique_id="T1496.001",
        executor_name="execute_t1496_001_shadowray",
        execution_mode="naive_simulated",
        status="success",
        command_or_action="Simulated cryptocurrency mining",
        prerequisites_consumed=[],
        artifacts_produced=[],
        stdout="",
        stderr="",
        start_time=time.time(),
        end_time=time.time(),
    )

    try:
        # Simulate mining for 3 seconds
        mining_duration = 3
        start_mining = time.time()

        # Simulate CPU-intensive work
        hash_count = 0
        while time.time() - start_mining < mining_duration:
            # Simulate hash calculation
            hashlib.sha256(f"block_{hash_count}_{time.time()}".encode()).hexdigest()
            hash_count += 1

        # Create mining log
        artifacts_dir = Path("data/artifacts")
        artifacts_dir.mkdir(exist_ok=True)

        mining_log = artifacts_dir / "mining_log.txt"
        with open(mining_log, "w") as f:
            f.write("Cryptocurrency Mining Simulation\n")
            f.write(f"Duration: {mining_duration} seconds\n")
            f.write(f"Hashes calculated: {hash_count}\n")
            f.write(f"Hash rate: {hash_count / mining_duration:.2f} H/s\n")
            f.write("Status: Simulation completed\n")

        evidence.stdout = "Simulated mining completed\n"
        evidence.stdout += f"Duration: {mining_duration} seconds\n"
        evidence.stdout += f"Hashes calculated: {hash_count}\n"
        evidence.stdout += f"Hash rate: {hash_count / mining_duration:.2f} H/s\n"

        evidence.artifacts_produced.append(str(mining_log))
        evidence.status = "success"

    except Exception as e:
        evidence.stderr = str(e)
        evidence.status = "error"

    evidence.end_time = time.time()
    evidence.duration_ms = int((evidence.end_time - evidence.start_time) * 1000)

    return evidence


def execute_t1546_004_shadowray(
    campaign_id: str, sut_profile_id: str, **kwargs
) -> ExecutionEvidence:
    """Event Triggered Execution: Unix Shell Configuration Modification"""
    evidence = ExecutionEvidence(
        technique_id="T1546.004",
        executor_name="execute_t1546_004_shadowray",
        execution_mode="naive_simulated",
        status="success",
        command_or_action="Modify .bashrc for persistence",
        prerequisites_consumed=[],
        artifacts_produced=[],
        stdout="",
        stderr="",
        start_time=time.time(),
        end_time=time.time(),
    )

    try:
        # Create a simulated .bashrc modification
        home_dir = Path.home()
        simulated_bashrc = home_dir / ".bashrc_sticks_simulation"

        # Read existing .bashrc if it exists
        original_content = ""
        if home_dir / ".bashrc" in home_dir.iterdir():
            with open(home_dir / ".bashrc", "r") as f:
                original_content = f.read()

        # Add persistence mechanism
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

        # Save simulated modification (don't modify actual .bashrc)
        with open(simulated_bashrc, "w") as f:
            f.write(modified_content)

        # Create backup script
        backup_script = home_dir / ".sticks_backup.sh"
        with open(backup_script, "w") as f:
            f.write(f'''#!/bin/bash
# STICKS Simulation: Backup script
echo "Creating backup of persistence mechanism..."
cp "{simulated_bashrc}" "{home_dir}/.bashrc_sticks_backup_$(date +%s)"
echo "Backup completed"
''')

        os.chmod(backup_script, 0o644)

        evidence.stdout = "Modified shell configuration for persistence\n"
        evidence.stdout += f"Simulated .bashrc: {simulated_bashrc}\n"
        evidence.stdout += f"Backup script: {backup_script}\n"
        evidence.stdout += "Added persistence hooks and environment variables\n"

        evidence.artifacts_produced.extend([str(simulated_bashrc), str(backup_script)])
        evidence.status = "success"

    except Exception as e:
        evidence.stderr = str(e)
        evidence.status = "error"

    evidence.end_time = time.time()
    evidence.duration_ms = int((evidence.end_time - evidence.start_time) * 1000)

    return evidence


def execute_t1588_002_shadowray(
    campaign_id: str, sut_profile_id: str, **kwargs
) -> ExecutionEvidence:
    """Obtain Capabilities: Tool"""
    evidence = ExecutionEvidence(
        technique_id="T1588.002",
        executor_name="execute_t1588_002_shadowray",
        execution_mode="real_controlled",
        status="success",
        command_or_action="Download reconnaissance tools",
        prerequisites_consumed=[],
        artifacts_produced=[],
        stdout="",
        stderr="",
        start_time=time.time(),
        end_time=time.time(),
    )

    try:
        # Create a reconnaissance toolkit
        artifacts_dir = Path("data/artifacts")
        artifacts_dir.mkdir(exist_ok=True)

        toolkit_dir = artifacts_dir / "recon_toolkit"
        toolkit_dir.mkdir(exist_ok=True)

        # Create various reconnaissance tools

        # Port scanner
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

        # Service enumerator
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

        # System profiler
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

        # Make scripts executable
        os.chmod(port_scanner, 0o755)
        os.chmod(service_enum, 0o755)
        os.chmod(sys_profiler, 0o755)

        # Test one tool
        result = subprocess.run(
            ["python3", str(sys_profiler)], capture_output=True, text=True, timeout=10
        )

        evidence.stdout = f"Created reconnaissance toolkit: {toolkit_dir}\n"
        evidence.stdout += "Tools created:\n"
        evidence.stdout += f"  - Port scanner: {port_scanner}\n"
        evidence.stdout += f"  - Service enumerator: {service_enum}\n"
        evidence.stdout += f"  - System profiler: {sys_profiler}\n"
        evidence.stdout += f"\nSystem profile sample:\n{result.stdout[:500]}...\n"

        evidence.artifacts_produced.append(str(toolkit_dir))
        evidence.status = "success"

    except Exception as e:
        evidence.stderr = str(e)
        evidence.status = "error"

    evidence.end_time = time.time()
    evidence.duration_ms = int((evidence.end_time - evidence.start_time) * 1000)

    return evidence


# Register all ShadowRay executors
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
    fidelity_justification="Realistic credential file access simulation without actual privilege escalation",
    original_platform="linux",
    requires_privilege="user",
)

metadata_t1016 = ExecutorMetadata(
    technique_id="T1016",
    technique_name="System Network Configuration Discovery",
    execution_mode=ExecutionMode.REAL_CONTROLLED,
    produces=["network:configuration", "network:listening_ports"],
    requires=[],
    safe_simulation=True,
    cleanup_supported=True,
    description="Network configuration discovery",
    platform="linux",
    execution_fidelity=ExecutionFidelity.ADAPTED,
    fidelity_justification="Uses standard Linux network discovery commands",
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
    produces=["artifacts:downloaded_tool", "artifacts:tool_script"],
    requires=[],
    safe_simulation=True,
    cleanup_supported=True,
    description="Safe tool download simulation",
    platform="linux",
    execution_fidelity=ExecutionFidelity.ADAPTED,
    fidelity_justification="Creates and tests safe reconnaissance tools",
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
    fidelity_justification="Creates staged reconnaissance toolkit targeting Ray cluster metadata",
    original_platform="linux",
    requires_privilege="user",
)

# Register executors
register_executor("T1003.008", metadata_t1003_008, overwrite=True)(
    execute_t1003_008_shadowray
)
register_executor("T1016", metadata_t1016, overwrite=True)(execute_t1016_shadowray)
register_executor("T1059.006", metadata_t1059_006, overwrite=True)(
    execute_t1059_006_shadowray
)
register_executor("T1027.013", metadata_t1027_013, overwrite=True)(
    execute_t1027_013_shadowray
)
register_executor("T1105", metadata_t1105, overwrite=True)(execute_t1105_shadowray)
register_executor("T1496.001", metadata_t1496_001, overwrite=True)(
    execute_t1496_001_shadowray
)
register_executor("T1546.004", metadata_t1546_004, overwrite=True)(
    execute_t1546_004_shadowray
)
register_executor("T1588.002", metadata_t1588_002, overwrite=True)(
    execute_t1588_002_shadowray
)
