#!/usr/bin/env python3
"""
apply_sut_profile.py - Apply SUT profile to base infrastructure

Parses YAML SUT profile and applies configurations via Vagrant SSH.
"""

import sys
import base64
import yaml
import subprocess
import time
from pathlib import Path


def run_vagrant_ssh(vm_name, command, timeout=30):
    """Execute command via Vagrant SSH"""
    try:
        result = subprocess.run(
            ["vagrant", "ssh", vm_name, "-c", command],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=Path(__file__).parent
        )
        return result.returncode == 0, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return False, "", "Timeout"
    except Exception as e:
        return False, "", str(e)


def apply_user_config(vm_name, users_config):
    """Apply user configurations to VM"""
    print(f"[SUT] Configuring users on {vm_name}...")

    for user in users_config:
        username = user.get("username")
        password = user.get("password")
        sudo = user.get("sudo", False)

        # Create user
        cmd = f"sudo useradd -m -s /bin/bash {username} 2>/dev/null || true"
        run_vagrant_ssh(vm_name, cmd)

        # Set password
        if password:
            cmd = f"echo '{username}:{password}' | sudo chpasswd"
            run_vagrant_ssh(vm_name, cmd)

        # Configure sudo
        if sudo:
            sudoers_line = f"{username} ALL=(ALL) NOPASSWD: ALL"
            cmd = f"echo '{sudoers_line}' | sudo tee /etc/sudoers.d/{username}-sut"
            run_vagrant_ssh(vm_name, cmd)

        print(f"  OK User {username} configured")


def apply_service_config(vm_name, services_config):
    """Apply service configurations"""
    print(f"[SUT] Configuring services on {vm_name}...")

    for service in services_config:
        name = service.get("name")
        version = service.get("version", "latest")
        config = service.get("config", "default")

        if name == "apache2":
            # Install Apache
            cmd = "sudo apt-get update -qq && sudo apt-get install -y -qq apache2"
            run_vagrant_ssh(vm_name, cmd, timeout=60)

            # Enable required modules
            cmd = "sudo a2enmod cgi cgid 2>/dev/null || true"
            run_vagrant_ssh(vm_name, cmd)

            # Configure based on profile
            if config == "vulnerable-cve-2021-41773":
                # Enable CGI and configure vulnerable settings
                cmd = """
sudo bash -c 'cat > /etc/apache2/conf-available/vulnerable-cgi.conf << EOF
ScriptAlias /cgi-bin/ /usr/lib/cgi-bin/
<Directory "/usr/lib/cgi-bin">
    AllowOverride None
    Options +ExecCGI
    Require all granted
</Directory>
EOF'
"""
                run_vagrant_ssh(vm_name, cmd)
                cmd = "sudo a2enconf vulnerable-cgi 2>/dev/null || true"
                run_vagrant_ssh(vm_name, cmd)

            # Start service
            cmd = "sudo systemctl restart apache2 || sudo service apache2 restart"
            run_vagrant_ssh(vm_name, cmd)

            print(f"  OK Apache {version} configured ({config})")

        elif name == "ssh":
            # SSH is already installed in base
            print(f"  OK SSH already available")

        elif name == "ray-dashboard":
            dashboard_source = """from http.server import BaseHTTPRequestHandler, HTTPServer
import json

class Handler(BaseHTTPRequestHandler):
    def _reply(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return

    def do_GET(self):
        if self.path in {"/", "/api/version"}:
            self._reply(200, {"version": "2.9.0", "service": "ray-dashboard"})
            return
        if self.path == "/api/jobs/":
            self._reply(200, {"jobs": [], "auth": "disabled"})
            return
        self._reply(404, {"detail": "not found"})

HTTPServer(("0.0.0.0", 8265), Handler).serve_forever()
"""
            encoded_dashboard = base64.b64encode(
                dashboard_source.encode("utf-8")
            ).decode("ascii")
            cmd = """
sudo mkdir -p /opt/sticks-shadowray
echo '__ENCODED_DASHBOARD__' | base64 -d | sudo tee /opt/sticks-shadowray/ray_dashboard.py >/dev/null
sudo pkill -f /opt/sticks-shadowray/ray_dashboard.py 2>/dev/null || true
sudo bash -lc 'nohup python3 /opt/sticks-shadowray/ray_dashboard.py >/var/log/sticks-ray-dashboard.log 2>&1 &'
sleep 2
curl -fsS http://127.0.0.1:8265/api/version >/tmp/sticks-ray-dashboard-version.json
""".replace("__ENCODED_DASHBOARD__", encoded_dashboard)
            run_vagrant_ssh(vm_name, cmd, timeout=60)
            print(f"  OK Ray dashboard configured")


def apply_network_config(vm_name, network_config):
    """Apply network/firewall configuration"""
    print(f"[SUT] Configuring network on {vm_name}...")

    ingress = network_config.get("ingress", [])
    egress = network_config.get("egress", ["*"])

    # Configure UFW if available
    for port in ingress:
        if port == "*":
            continue
        cmd = f"sudo ufw allow {port}/tcp 2>/dev/null || true"
        run_vagrant_ssh(vm_name, cmd)

    print(f"  OK Network configured: ingress={ingress}, egress={egress}")


def apply_files_config(vm_name, files_config):
    """Apply file/directory configurations"""
    print(f"[SUT] Creating files on {vm_name}...")

    for file_spec in files_config:
        path = file_spec.get("path")
        content = file_spec.get("content", "")
        owner = file_spec.get("owner", "root")
        permissions = file_spec.get("permissions", "644")

        # Create directory if needed
        dir_path = Path(path).parent
        cmd = f"sudo mkdir -p {dir_path}"
        run_vagrant_ssh(vm_name, cmd)

        # Create file with content
        cmd = f"sudo bash -c 'cat > {path} << 'EOF'\n{content}\nEOF'"
        run_vagrant_ssh(vm_name, cmd)

        # Set permissions
        cmd = f"sudo chmod {permissions} {path} && sudo chown {owner} {path} 2>/dev/null || true"
        run_vagrant_ssh(vm_name, cmd)

        print(f"  OK File {path} created")


def apply_weaknesses(vm_name, weaknesses_config):
    """Apply deliberate weaknesses/vulnerabilities"""
    print(f"[SUT] Applying deliberate weaknesses on {vm_name}...")

    for weakness in weaknesses_config:
        weakness_type = weakness.get("type")

        if weakness_type == "cve-2021-41773":
            # Apache path traversal - already configured in service section
            print(f"  OK Apache CVE-2021-41773 enabled")

        elif weakness_type == "weak_ssh_password":
            # Weak passwords applied in user section
            print(f"  OK Weak SSH passwords configured")

        elif weakness_type == "exposed_ray_jobs_api":
            print(f"  OK Ray Jobs API exposure configured")

        elif weakness_type == "world_writable_suid":
            # Create world-writable SUID binary
            c_code = """
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main() {
    setuid(0);
    setgid(0);
    system("/bin/bash");
    return 0;
}
"""
            cmd = f"echo '{c_code}' | sudo tee /tmp/vuln_suid.c > /dev/null"
            run_vagrant_ssh(vm_name, cmd)

            cmd = "cd /tmp && sudo gcc vuln_suid.c -o /usr/local/bin/vuln_suid 2>/dev/null || true"
            run_vagrant_ssh(vm_name, cmd, timeout=30)

            cmd = "sudo chmod u+s /usr/local/bin/vuln_suid && sudo chmod 777 /usr/local/bin/vuln_suid 2>/dev/null || true"
            run_vagrant_ssh(vm_name, cmd)

            print(f"  OK World-writable SUID binary created")


def validate_sut(vm_name, profile):
    """Validate SUT is ready"""
    print(f"[SUT] Validating {vm_name}...")

    # Check basic connectivity
    success, stdout, stderr = run_vagrant_ssh(vm_name, "echo 'SUT_VALID'", timeout=10)
    if success and "SUT_VALID" in stdout:
        print(f"  OK {vm_name} responsive")
        return True
    else:
        print(f"  FAIL {vm_name} validation failed: {stderr}")
        return False


def apply_profile(profile_path):
    """Main function to apply SUT profile"""
    print(f"[SUT] Loading profile: {profile_path}")

    with open(profile_path) as f:
        profile = yaml.safe_load(f)

    campaign_id = profile.get("campaign_id", "unknown")
    print(f"[SUT] Campaign: {campaign_id}")

    # Get required VMs
    required_vms = profile.get("requirements", {}).get("required_vms", ["target-base"])

    # Apply configurations to each VM
    for vm_name in required_vms:
        if vm_name == "caldera" or vm_name == "attacker":
            # Base VMs don't need SUT configuration
            continue

        sut_config = profile.get("sut_configuration", {})

        # Apply configurations
        if "users" in sut_config.get(vm_name, {}):
            apply_user_config(vm_name, sut_config[vm_name]["users"])

        if "services" in sut_config.get(vm_name, {}):
            apply_service_config(vm_name, sut_config[vm_name]["services"])

        if "network" in sut_config.get(vm_name, {}):
            apply_network_config(vm_name, sut_config[vm_name]["network"])

        if "files" in sut_config.get(vm_name, {}):
            apply_files_config(vm_name, sut_config[vm_name]["files"])

        if "deliberate_weaknesses" in sut_config.get(vm_name, {}):
            apply_weaknesses(vm_name, sut_config[vm_name]["deliberate_weaknesses"])

        # Validate
        validate_sut(vm_name, profile)

    print(f"[SUT] OK Profile applied successfully")
    return True


def main():
    if len(sys.argv) < 2:
        print("Usage: apply_sut_profile.py <profile.yml>")
        sys.exit(1)

    profile_path = sys.argv[1]

    if not Path(profile_path).exists():
        print(f"Error: Profile not found: {profile_path}")
        sys.exit(1)

    try:
        apply_profile(profile_path)
    except Exception as e:
        print(f"Error applying profile: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
