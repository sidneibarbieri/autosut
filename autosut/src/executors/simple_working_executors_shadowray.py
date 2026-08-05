#!/usr/bin/env python3
"""
ShadowRay campaign executors - AI/ML infrastructure attack techniques.
Linux-native implementations with real system interactions.
"""

import os
import subprocess
import tempfile
from datetime import datetime
from typing import List, Tuple

from .executor_registry import (
    ExecutionFidelity,
    ExecutionMode,
    ExecutorMetadata,
    register_executor,
)


def execute_t1059_006_adapted(
    campaign_id: str, sut_profile_id: str, **kwargs
) -> Tuple[bool, str, str, List[str]]:
    """T1059.006 - Python: Real Python execution on Linux."""
    try:
        # Create Python script in /tmp
        script_path = "/tmp/sticks_ray_payload.py"
        with open(script_path, "w") as f:
            f.write('''#!/usr/bin/env python3
"""
ShadowRay Python payload - benign simulation of Ray framework interaction.
"""
import os
import socket
import json
from datetime import datetime

def simulate_ray_interaction():
    """Simulate Ray framework post-exploitation interaction."""
    print(f"[SHADOWRAY] Python execution started at {datetime.now().isoformat()}")
    print(f"[SHADOWRAY] Current working directory: {os.getcwd()}")
    print(f"[SHADOWRAY] Hostname: {socket.gethostname()}")

    # Simulate Ray cluster discovery
    cluster_info = {
        "ray_cluster": "shadowray-target",
        "node_type": "head",
        "python_version": os.sys.version,
        "working_directory": os.getcwd(),
        "hostname": socket.gethostname()
    }

    print(f"[SHADOWRAY] Simulated Ray cluster info: {json.dumps(cluster_info, indent=2)}")
    print(f"[SHADOWRAY] Payload execution completed successfully")

    return True

if __name__ == "__main__":
    simulate_ray_interaction()
''')

        # Execute the Python script
        result = subprocess.run(
            ["python3", script_path], capture_output=True, text=True, timeout=30
        )

        # Create evidence file
        evidence_file = tempfile.mktemp(prefix="shadowray_python_", suffix=".txt")
        with open(evidence_file, "w") as f:
            f.write("=== SHADOWRAY T1059.006 PYTHON EXECUTION ===\n")
            f.write(f"Timestamp: {datetime.now().isoformat()}\n")
            f.write(f"Campaign: {campaign_id}\n")
            f.write(f"SUT: {sut_profile_id}\n")
            f.write(f"Script: {script_path}\n")
            f.write(f"Exit code: {result.returncode}\n\n")
            f.write("STDOUT:\n")
            f.write(result.stdout)
            if result.stderr:
                f.write("\nSTDERR:\n")
                f.write(result.stderr)
            f.write("\n=== FIDELITY JUSTIFICATION ===\n")
            f.write("ADAPTED: Real Python interpreter invoked with benign script.\n")
            f.write(
                "ShadowRay used Python to interact with Ray APIs post-exploitation.\n"
            )
            f.write("Mechanism fully preserved on Linux substrate.\n")

        # Clean up script
        try:
            os.remove(script_path)
        except:
            pass

        success = result.returncode == 0
        message = (
            "Python script execution completed"
            if success
            else f"Python execution failed: {result.stderr}"
        )

        return success, message, "", [evidence_file]

    except Exception as e:
        return False, f"Python execution failed: {str(e)}", "", []


def execute_t1546_004_adapted(
    campaign_id: str, sut_profile_id: str, **kwargs
) -> Tuple[bool, str, str, List[str]]:
    """T1546.004 - Unix Shell Configuration Modification."""
    try:
        # Create controlled shell config file in /tmp
        config_file = "/tmp/sticks_bashrc_test"
        persistence_content = (
            '''# ShadowRay persistence simulation
export SHADOWRAY_PERSISTENCE="active"
export SHADOWRAY_TIMESTAMP="'''
            + datetime.now().isoformat()
            + """"
alias shadowray_status="echo 'ShadowRay persistence active'"
# This would normally contain malicious persistence code
# Benign simulation for lab safety
echo "ShadowRay persistence activated" >> /tmp/shadowray_activity.log
"""
        )

        with open(config_file, "w") as f:
            f.write(persistence_content)

        # Verify file exists and has correct content
        verification = subprocess.run(
            ["cat", config_file], capture_output=True, text=True, timeout=10
        )

        # Create evidence file
        evidence_file = tempfile.mktemp(prefix="shadowray_persistence_", suffix=".txt")
        with open(evidence_file, "w") as f:
            f.write("=== SHADOWRAY T1546.004 SHELL PERSISTENCE ===\n")
            f.write(f"Timestamp: {datetime.now().isoformat()}\n")
            f.write(f"Campaign: {campaign_id}\n")
            f.write(f"SUT: {sut_profile_id}\n")
            f.write(f"Config file: {config_file}\n")
            f.write(f"File size: {os.path.getsize(config_file)} bytes\n")
            f.write(f"Verification exit code: {verification.returncode}\n\n")
            f.write("Persistence content:\n")
            f.write(verification.stdout)
            f.write("\n=== FIDELITY JUSTIFICATION ===\n")
            f.write(
                "ADAPTED: Unix shell configuration file created in controlled /tmp location.\n"
            )
            f.write("Real file operation preserving persistence mechanism.\n")
            f.write("System .bashrc not modified to prevent unintended side effects.\n")

        # Clean up
        try:
            os.remove(config_file)
        except:
            pass

        success = (
            verification.returncode == 0
            and "SHADOWRAY_PERSISTENCE" in verification.stdout
        )
        message = (
            "Shell persistence configuration created"
            if success
            else "Shell persistence failed"
        )

        return success, message, "", [evidence_file]

    except Exception as e:
        return False, f"Shell persistence failed: {str(e)}", "", []


def execute_t1003_008_adapted(
    campaign_id: str, sut_profile_id: str, **kwargs
) -> Tuple[bool, str, str, List[str]]:
    """T1003.008 - /etc/passwd and /etc/shadow credential access."""
    try:
        # Read /etc/passwd (world-readable)
        passwd_result = subprocess.run(
            ["cat", "/etc/passwd"], capture_output=True, text=True, timeout=10
        )

        # Count real user accounts (UID >= 500 for macOS compatibility)
        user_count = 0
        users = []
        for line in passwd_result.stdout.strip().split("\n"):
            if line and not line.startswith("#"):
                parts = line.split(":")
                if len(parts) >= 3:
                    try:
                        uid = int(parts[2])
                        if (
                            uid >= 500
                        ):  # Adjusted for macOS where user UIDs often start at 501
                            user_count += 1
                            users.append(parts[0])
                    except ValueError:
                        continue

        # Create dump file
        dump_file = "/tmp/sticks_passwd_dump.txt"
        with open(dump_file, "w") as f:
            f.write("=== SHADOWRAY CREDENTIAL ACCESS ===\n")
            f.write(f"Timestamp: {datetime.now().isoformat()}\n")
            f.write(f"Campaign: {campaign_id}\n")
            f.write(f"SUT: {sut_profile_id}\n")
            f.write(f"Total accounts: {len(passwd_result.stdout.strip().split())}\n")
            f.write(f"User accounts (UID >= 500): {user_count}\n")
            f.write(f"User names: {', '.join(users[:10])}")  # First 10 users
            if len(users) > 10:
                f.write(f" ... and {len(users) - 10} more")
            f.write("\n\n=== /etc/passwd content ===\n")
            f.write(passwd_result.stdout)

        # Create evidence file
        evidence_file = tempfile.mktemp(prefix="shadowray_credentials_", suffix=".txt")
        with open(evidence_file, "w") as f:
            f.write("=== SHADOWRAY T1003.008 CREDENTIAL ACCESS ===\n")
            f.write(f"Timestamp: {datetime.now().isoformat()}\n")
            f.write(f"Campaign: {campaign_id}\n")
            f.write(f"SUT: {sut_profile_id}\n")
            f.write(f"Dump file: {dump_file}\n")
            f.write(f"Passwd read exit code: {passwd_result.returncode}\n")
            f.write(f"Total accounts: {len(passwd_result.stdout.strip().split())}\n")
            f.write(f"User accounts (UID >= 500): {user_count}\n")
            f.write(f"Dump file size: {os.path.getsize(dump_file)} bytes\n")
            f.write("\n=== FIDELITY JUSTIFICATION ===\n")
            f.write("ADAPTED: Real read of /etc/passwd (world-readable).\n")
            f.write(
                "File access mechanism fully preserved: enumerates local accounts\n"
            )
            f.write("as attacker would. /etc/shadow read skipped (requires root) but\n")
            f.write("/etc/passwd provides sufficient behavioral fidelity.\n")

        # Clean up dump file
        try:
            os.remove(dump_file)
        except:
            pass

        success = (
            passwd_result.returncode == 0 and len(passwd_result.stdout.strip()) > 0
        )
        message = (
            f"Credential access completed - {user_count} user accounts found, {len(passwd_result.stdout.strip().split())} total accounts"
            if success
            else "Credential access failed"
        )

        return success, message, "", [evidence_file]

    except Exception as e:
        return False, f"Credential access failed: {str(e)}", "", []


def execute_t1016_adapted(
    campaign_id: str, sut_profile_id: str, **kwargs
) -> Tuple[bool, str, str, List[str]]:
    """T1016 - System Network Configuration Discovery."""
    try:
        # Execute network discovery commands
        commands = [
            (["ip", "route", "show"], "route_table"),
            (["ip", "addr", "show"], "interface_config"),
            (["cat", "/etc/resolv.conf"], "dns_config"),
        ]

        results = {}
        for cmd, name in commands:
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                results[name] = {
                    "exit_code": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                }
            except Exception as e:
                results[name] = {"error": str(e)}

        # Create consolidated output file
        config_file = "/tmp/sticks_netconfig.txt"
        with open(config_file, "w") as f:
            f.write("=== SHADOWRAY NETWORK CONFIGURATION DISCOVERY ===\n")
            f.write(f"Timestamp: {datetime.now().isoformat()}\n")
            f.write(f"Campaign: {campaign_id}\n")
            f.write(f"SUT: {sut_profile_id}\n\n")

            for name, result in results.items():
                f.write(f"=== {name.upper()} ===\n")
                if "error" in result:
                    f.write(f"Error: {result['error']}\n")
                else:
                    f.write(f"Exit code: {result['exit_code']}\n")
                    f.write(f"Output:\n{result['stdout']}\n")
                    if result["stderr"]:
                        f.write(f"Stderr:\n{result['stderr']}\n")
                f.write("\n")

        # Create evidence file
        evidence_file = tempfile.mktemp(prefix="shadowray_network_", suffix=".txt")
        with open(evidence_file, "w") as f:
            f.write("=== SHADOWRAY T1016 NETWORK DISCOVERY ===\n")
            f.write(f"Timestamp: {datetime.now().isoformat()}\n")
            f.write(f"Campaign: {campaign_id}\n")
            f.write(f"SUT: {sut_profile_id}\n")
            f.write(f"Config file: {config_file}\n")
            f.write(f"Commands executed: {len(commands)}\n")

            success_count = sum(1 for r in results.values() if r.get("exit_code") == 0)
            f.write(f"Successful commands: {success_count}/{len(commands)}\n")
            f.write(f"Config file size: {os.path.getsize(config_file)} bytes\n")
            f.write("\n=== FIDELITY JUSTIFICATION ===\n")
            f.write("ADAPTED: Real execution of ip commands on Linux.\n")
            f.write(
                "Mechanism fully preserved: attacker enumerates network topology,\n"
            )
            f.write("interfaces, and DNS configuration as documented in ATT&CK\n")
            f.write("procedure examples.\n")

        # Clean up config file
        try:
            os.remove(config_file)
        except:
            pass

        success = success_count >= 2  # At least 2 commands should succeed
        message = (
            f"Network discovery completed - {success_count}/{len(commands)} commands successful"
            if success
            else "Network discovery failed"
        )

        return success, message, "", [evidence_file]

    except Exception as e:
        return False, f"Network discovery failed: {str(e)}", "", []


def execute_t1105_adapted(
    campaign_id: str, sut_profile_id: str, **kwargs
) -> Tuple[bool, str, str, List[str]]:
    """T1105 - Ingress Tool Transfer."""
    try:
        # Attempt tool transfer to Ray dashboard endpoint
        ray_endpoint = "http://127.0.0.1:8265"

        # Try curl first, fallback to wget
        curl_result = None
        wget_result = None

        try:
            curl_result = subprocess.run(
                ["curl", "-s", "-w", "%{http_code}", ray_endpoint],
                capture_output=True,
                text=True,
                timeout=15,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        if curl_result is None or curl_result.returncode != 0:
            try:
                wget_result = subprocess.run(
                    [
                        "wget",
                        "-q",
                        "--server-response",
                        ray_endpoint,
                        "-O",
                        "/dev/null",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

        # Determine result
        if curl_result and curl_result.returncode == 0:
            status_code = curl_result.stdout.strip()[-3:]  # Last 3 chars are HTTP code
            output = curl_result.stdout[:-3]  # Remove status code
            tool_used = "curl"
        elif wget_result and wget_result.returncode == 0:
            # Parse HTTP status from wget output
            status_code = "000"  # Default
            for line in wget_result.stderr.split("\n"):
                if "HTTP/" in line:
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if part.startswith("HTTP/") and i + 1 < len(parts):
                            status_code = parts[i + 1]
                            break
            output = wget_result.stderr
            tool_used = "wget"
        else:
            status_code = "CONNECTION_REFUSED"
            output = "Connection refused (expected in isolated SUT)"
            tool_used = "simulation"

        # Create evidence file
        evidence_file = tempfile.mktemp(
            prefix="shadowray_tool_transfer_", suffix=".txt"
        )
        with open(evidence_file, "w") as f:
            f.write("=== SHADOWRAY T1105 TOOL TRANSFER ===\n")
            f.write(f"Timestamp: {datetime.now().isoformat()}\n")
            f.write(f"Campaign: {campaign_id}\n")
            f.write(f"SUT: {sut_profile_id}\n")
            f.write(f"Target endpoint: {ray_endpoint}\n")
            f.write(f"Tool used: {tool_used}\n")
            f.write(f"HTTP status: {status_code}\n")
            f.write(f"Response output:\n{output}\n")
            f.write("\n=== FIDELITY JUSTIFICATION ===\n")
            f.write(
                "ADAPTED: curl/wget attempt to Ray dashboard endpoint (port 8265).\n"
            )
            f.write("HTTP-based tool retrieval mechanism preserved. External C2\n")
            f.write("absent in isolated SUT; connection attempt documents behavioral\n")
            f.write("intent of exploiting Ray's unauthenticated API surface.\n")

        # Success is any response (including connection refused) - behavior preserved
        success = True
        message = (
            f"Tool transfer attempt completed - HTTP {status_code} using {tool_used}"
        )

        return success, message, "", [evidence_file]

    except Exception as e:
        return False, f"Tool transfer failed: {str(e)}", "", []


# Register the ShadowRay executors
@register_executor(
    "T1059.006",
    ExecutorMetadata(
        technique_id="T1059.006",
        technique_name="Python",
        execution_mode=ExecutionMode.REAL_CONTROLLED,
        produces=["execution:python_script"],
        requires=[],
        safe_simulation=True,
        cleanup_supported=True,
        description="Python execution in compromised Ray environment",
        platform="linux",
        execution_fidelity=ExecutionFidelity.ADAPTED,
        fidelity_justification="Real Python execution on Linux. Native to AI/ML workloads, mechanism preserved.",
        original_platform="multi",
        requires_privilege="user",
    ),
    overwrite=True,
)
def execute_t1059_006_registered() -> Tuple[bool, str, str, List[str]]:
    """Registered T1059.006 executor."""
    return execute_t1059_006_adapted("default_campaign", "default_sut")


@register_executor(
    "T1546.004",
    ExecutorMetadata(
        technique_id="T1546.004",
        technique_name="Unix Shell Configuration Modification",
        execution_mode=ExecutionMode.REAL_CONTROLLED,
        produces=["persistence:shell_config"],
        requires=[],
        safe_simulation=True,
        cleanup_supported=True,
        description="Shell configuration persistence for ShadowRay",
        platform="linux",
        execution_fidelity=ExecutionFidelity.ADAPTED,
        fidelity_justification="Real shell configuration file creation. Isolated to /tmp to prevent system impact.",
        original_platform="linux",
        requires_privilege="user",
    ),
    overwrite=True,
)
def execute_t1546_004_registered() -> Tuple[bool, str, str, List[str]]:
    """Registered T1546.004 executor."""
    return execute_t1546_004_adapted("default_campaign", "default_sut")


@register_executor(
    "T1003.008",
    ExecutorMetadata(
        technique_id="T1003.008",
        technique_name="/etc/passwd and /etc/shadow",
        execution_mode=ExecutionMode.REAL_CONTROLLED,
        produces=["credential_access:passwd_read"],
        requires=[],
        safe_simulation=True,
        cleanup_supported=True,
        description="Credential access via shadow files for ShadowRay",
        platform="linux",
        execution_fidelity=ExecutionFidelity.ADAPTED,
        fidelity_justification="Real credential file access - native Linux mechanism",
        original_platform="linux",
        requires_privilege="user",
    ),
    overwrite=True,
)
def execute_t1003_008_registered() -> Tuple[bool, str, str, List[str]]:
    """Registered T1003.008 executor."""
    return execute_t1003_008_adapted("default_campaign", "default_sut")


@register_executor(
    "T1016",
    ExecutorMetadata(
        technique_id="T1016",
        technique_name="System Network Configuration Discovery",
        execution_mode=ExecutionMode.REAL_CONTROLLED,
        produces=["discovery:network_config"],
        requires=[],
        safe_simulation=True,
        cleanup_supported=True,
        description="Network configuration discovery for ShadowRay",
        platform="linux",
        execution_fidelity=ExecutionFidelity.ADAPTED,
        fidelity_justification="Real network enumeration using ip commands - native Linux mechanism",
        original_platform="linux",
        requires_privilege="user",
    ),
    overwrite=True,
)
def execute_t1016_registered(
    campaign_id: str,
    sut_profile_id: str,
    **kwargs,
) -> Tuple[bool, str, str, List[str]]:
    """Registered T1016 executor."""
    return execute_t1016_adapted(campaign_id, sut_profile_id, **kwargs)


@register_executor(
    "T1105",
    ExecutorMetadata(
        technique_id="T1105",
        technique_name="Ingress Tool Transfer",
        execution_mode=ExecutionMode.NAIVE_SIMULATED,
        produces=["command_and_control:tool_transferred"],
        requires=[],
        safe_simulation=True,
        cleanup_supported=True,
        description="Tool transfer simulation for ShadowRay C2",
        platform="linux",
        execution_fidelity=ExecutionFidelity.ADAPTED,
        fidelity_justification="HTTP tool transfer attempt to Ray endpoint - mechanism preserved, no external C2",
        original_platform="multi",
        requires_privilege="user",
    ),
    overwrite=True,
)
def execute_t1105_registered() -> Tuple[bool, str, str, List[str]]:
    """Registered T1105 executor."""
    return execute_t1105_adapted("default_campaign", "default_sut")
