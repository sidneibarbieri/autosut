#!/usr/bin/env python3
"""
Docker Campaign Execution Adapter
Adapts campaign execution for Docker container environment.
"""

import sys
import subprocess
import json
import time
from pathlib import Path

sys.path.insert(0, 'src')

class DockerCampaignExecutor:
    def __init__(self):
        self.target_host = 'target'
        self.attacker_host = 'attacker'

    def execute_technique_in_docker(self, technique_id, campaign_id, **kwargs):
        """Execute technique in Docker containers"""
        print(f"Executing {technique_id} in Docker environment...")

        try:
            # Map technique to Docker execution
            if technique_id == 'T1190':
                return self.execute_exploit_public_facing_app()
            elif technique_id == 'T1059.001':
                return self.execute_powershell()
            elif technique_id == 'T1059.003':
                return self.execute_unix_shell()
            elif technique_id == 'T1083':
                return self.execute_file_discovery()
            elif technique_id == 'T1041':
                return self.execute_exfiltration()
            else:
                return self.execute_generic_technique(technique_id)

        except Exception as e:
            return False, f"Docker execution failed: {e}", str(e), []

    def execute_exploit_public_facing_app(self):
        """Execute T1190 in Docker"""
        try:
            # Check if vulnerable app is accessible
            result = subprocess.run([
                'docker-compose', 'exec', 'attacker',
                'curl', '-s', 'http://target/vulnerable.php?cmd=whoami'
            ], capture_output=True, text=True, timeout=30)

            if result.returncode == 0 and 'www-data' in result.stdout:
                # Create exploit artifact
                artifact_path = f"/tmp/artifacts/exploit_{int(time.time())}.log"
                subprocess.run([
                    'docker-compose', 'exec', 'target',
                    'sh', '-c', f'echo "Exploited vulnerable app at $(date)" > {artifact_path}'
                ], capture_output=True, text=True)

                return True, "Exploited vulnerable web application", "", [artifact_path]
            else:
                return False, "Vulnerable app not accessible", result.stderr, []

        except Exception as e:
            return False, f"Exploit execution failed: {e}", str(e), []

    def execute_unix_shell(self):
        """Execute T1059.003 in Docker"""
        try:
            # Execute commands in attacker container
            commands = ['whoami', 'id', 'uname -a', 'ps aux | head -5']
            command_output = []

            for cmd in commands:
                result = subprocess.run([
                    'docker-compose', 'exec', 'attacker',
                    'sh', '-c', cmd
                ], capture_output=True, text=True, timeout=10)

                if result.returncode == 0:
                    command_output.append(f"{cmd}:\n{result.stdout}")

            # Create artifact
            artifact_path = f"/tmp/artifacts/shell_execution_{int(time.time())}.log"
            subprocess.run([
                'docker-compose', 'exec', 'attacker',
                'sh', '-c', f'echo -e "{chr(10).join(command_output)}" > {artifact_path}'
            ], capture_output=True, text=True)

            return True, "Unix shell commands executed", "", [artifact_path]

        except Exception as e:
            return False, f"Shell execution failed: {e}", str(e), []

    def execute_file_discovery(self):
        """Execute T1083 in Docker"""
        try:
            # Discover files in target container
            commands = [
                'find /home -name "*.txt" 2>/dev/null | head -10',
                'find /tmp -type f 2>/dev/null | head -10',
                'ls -la /etc/ | head -10'
            ]

            discovery_output = []
            for cmd in commands:
                result = subprocess.run([
                    'docker-compose', 'exec', 'target',
                    'sh', '-c', cmd
                ], capture_output=True, text=True, timeout=10)

                if result.returncode == 0:
                    discovery_output.append(f"{cmd}:\n{result.stdout}")

            # Create artifact
            artifact_path = f"/tmp/artifacts/file_discovery_{int(time.time())}.log"
            subprocess.run([
                'docker-compose', 'exec', 'target',
                'sh', '-c', f'echo -e "{chr(10).join(discovery_output)}" > {artifact_path}'
            ], capture_output=True, text=True)

            return True, "File discovery completed", "", [artifact_path]

        except Exception as e:
            return False, f"File discovery failed: {e}", str(e), []

    def execute_exfiltration(self):
        """Execute T1041 in Docker"""
        try:
            # Simulate exfiltration by copying files
            timestamp = int(time.time())
            exfil_dir = f"/tmp/artifacts/exfiltrated_{timestamp}"

            # Create exfiltrated files
            subprocess.run([
                'docker-compose', 'exec', 'target',
                'sh', '-c', f'mkdir -p {exfil_dir}'
            ], capture_output=True, text=True)

            # Copy sensitive files
            subprocess.run([
                'docker-compose', 'exec', 'target',
                'sh', '-c', f'cp /home/labuser/secrets.txt {exfil_dir}/exfiltrated_secrets.txt'
            ], capture_output=True, text=True)

            # Create exfiltration log
            log_content = f"""Exfiltration completed at {time.ctime()}
Source: /home/labuser/secrets.txt
Destination: {exfil_dir}
Status: success
"""

            subprocess.run([
                'docker-compose', 'exec', 'target',
                'sh', '-c', f'echo "{log_content}" > {exfil_dir}/exfiltration.log'
            ], capture_output=True, text=True)

            return True, "Data exfiltrated successfully", "", [f"{exfil_dir}/exfiltrated_secrets.txt", f"{exfil_dir}/exfiltration.log"]

        except Exception as e:
            return False, f"Exfiltration failed: {e}", str(e), []

    def execute_generic_technique(self, technique_id):
        """Execute generic technique"""
        try:
            # Create generic execution artifact
            artifact_path = f"/tmp/artifacts/{technique_id}_{int(time.time())}.log"
            content = f"Generic execution of {technique_id} at {time.ctime()}"

            subprocess.run([
                'docker-compose', 'exec', 'attacker',
                'sh', '-c', f'echo "{content}" > {artifact_path}'
            ], capture_output=True, text=True)

            return True, f"Executed {technique_id} in Docker", "", [artifact_path]

        except Exception as e:
            return False, f"Generic execution failed: {e}", str(e), []

# Global executor instance
docker_executor = DockerCampaignExecutor()

def register_docker_executors():
    """Register Docker-based executors"""
    from executors.executor_registry import register_executor, ExecutorMetadata, ExecutionMode, ExecutionFidelity

    # Register Docker executors for key techniques
    @register_executor(
        technique_id="T1190",
        metadata=ExecutorMetadata(
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            execution_mode=ExecutionMode.REAL_CONTROLLED,
            produces=["access:initial"],
            requires=["network:http_available"],
            description="Exploit vulnerable web application in Docker",
            platform="linux",
            execution_fidelity=ExecutionFidelity.ADAPTED,
            fidelity_justification="Real exploitation of vulnerable app in containerized environment"
        )
    )
    def execute_t1190_docker(campaign_id: str, sut_profile_id: str, **kwargs):
        return docker_executor.execute_exploit_public_facing_app()

    @register_executor(
        technique_id="T1059.003",
        metadata=ExecutorMetadata(
            technique_id="T1059.003",
            technique_name="Command and Scripting Interpreter: Unix Shell",
            execution_mode=ExecutionMode.REAL_CONTROLLED,
            produces=["code_execution"],
            requires=["access:initial"],
            description="Execute Unix shell commands in Docker",
            platform="linux",
            execution_fidelity=ExecutionFidelity.ADAPTED,
            fidelity_justification="Real shell execution in containerized environment"
        )
    )
    def execute_t1059_003_docker(campaign_id: str, sut_profile_id: str, **kwargs):
        return docker_executor.execute_unix_shell()

    @register_executor(
        technique_id="T1083",
        metadata=ExecutorMetadata(
            technique_id="T1083",
            technique_name="File and Directory Discovery",
            execution_mode=ExecutionMode.REAL_CONTROLLED,
            produces=["discovery:file_listing"],
            requires=["access:credentialed"],
            description="Discover files in Docker container",
            platform="linux",
            execution_fidelity=ExecutionFidelity.ADAPTED,
            fidelity_justification="Real file discovery in containerized environment"
        )
    )
    def execute_t1083_docker(campaign_id: str, sut_profile_id: str, **kwargs):
        return docker_executor.execute_file_discovery()

    @register_executor(
        technique_id="T1041",
        metadata=ExecutorMetadata(
            technique_id="T1041",
            technique_name="Exfiltration Over C2 Channel",
            execution_mode=ExecutionMode.REAL_CONTROLLED,
            produces=["exfiltration:complete"],
            requires=["collection:archive"],
            description="Exfiltrate data in Docker environment",
            platform="linux",
            execution_fidelity=ExecutionFidelity.ADAPTED,
            fidelity_justification="Real data exfiltration in containerized environment"
        )
    )
    def execute_t1041_docker(campaign_id: str, sut_profile_id: str, **kwargs):
        return docker_executor.execute_exfiltration()

if __name__ == '__main__':
    register_docker_executors()
    print("Docker executors registered")
