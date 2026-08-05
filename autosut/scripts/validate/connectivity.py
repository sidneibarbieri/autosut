#!/usr/bin/env python3
"""Validate multi-host connectivity matrix"""

import subprocess
import json
from pathlib import Path

EVIDENCE_DIR = Path(__file__).parent.parent.parent / "infra" / "evidence"
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

HOSTS = {
    "caldera": "172.20.0.10",
    "kali": "172.20.0.20",
    "nginx": "172.21.0.30",
    "db": "172.22.0.40",
}

EXPECTED = {
    ("kali", "nginx"): ["http"],
    ("nginx", "db"): ["postgresql"],
    ("caldera", "kali"): ["ssh"],
}

def ssh(host, cmd):
    return subprocess.run(
        ["ssh", "-o", "StrictHostKeyChecking=no", f"ubuntu@{HOSTS[host]}", cmd],
        capture_output=True, text=True, timeout=10,
    )

def test_http(src, dst):
    r = ssh(src, f"curl -s -o /dev/null -w %{{http_code}} http://{HOSTS[dst]}")
    return r.returncode == 0 and "200" in r.stdout

def test_postgres(src, dst):
    r = ssh(src, f"nc -zv {HOSTS[dst]} 5432")
    return r.returncode == 0

def test_ssh(src, dst):
    r = ssh(src, "echo ok")
    return r.returncode == 0 and "ok" in r.stdout

def main():
    matrix = {}
    for (src, dst), services in EXPECTED.items():
        results = {}
        for svc in services:
            if svc == "http":
                results[svc] = test_http(src, dst)
            elif svc == "postgresql":
                results[svc] = test_postgres(src, dst)
            elif svc == "ssh":
                results[svc] = test_ssh(src, dst)
        matrix[f"{src}->{dst}"] = results

    out_path = EVIDENCE_DIR / "connectivity_matrix.txt"
    out_path.write_text(json.dumps(matrix, indent=2))
    print(f"Connectivity matrix written to {out_path}")

if __name__ == "__main__":
    main()
