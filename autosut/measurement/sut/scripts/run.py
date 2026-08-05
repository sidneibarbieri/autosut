#!/usr/bin/env python3
"""
Unified CLI for SUT Measurement Artifact.

Usage:
    python3 run.py --mode smoke      # Quick validation
    python3 run.py --mode list       # List available campaigns
    python3 run.py --mode adversaries # List Caldera adversaries
    python3 run.py --mode clean       # Clean old operations
    python3 run.py --mode demo        # Demo execution
    python3 run.py --mode run        # Full execution
"""

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

CALDERA_URL = "http://localhost:8889"
ADVERSARY_DEFAULT = "50855e29-3b4e-4562-aa55-b3d7f93c26b8"


def check_caldera():
    """Check if Caldera is running."""
    import requests
    try:
        r = requests.get(CALDERA_URL, timeout=5)
        return r.status_code == 200
    except:
        return False


def get_agents():
    """Get agents from Caldera."""
    import requests
    session = requests.Session()
    try:
        session.post(f"{CALDERA_URL}/enter", data={"username": "red", "password": "BgbJ-PzikRWCp3BMpkg3PXUIz_RCyBaw6r2JeeGkdBI"})
        resp = session.get(f"{CALDERA_URL}/api/v2/agents")
        return resp.json() if resp.status_code == 200 else []
    except:
        return []


def get_adversaries():
    """Get adversaries from Caldera."""
    import requests
    session = requests.Session()
    try:
        session.post(f"{CALDERA_URL}/enter", data={"username": "red", "password": "BgbJ-PzikRWCp3BMpkg3PXUIz_RCyBaw6r2JeeGkdBI"})
        resp = session.get(f"{CALDERA_URL}/api/v2/adversaries")
        return resp.json() if resp.status_code == 200 else []
    except:
        return []


def list_campaigns():
    """List available campaigns from corpus."""
    campaign_dir = Path(__file__).parent.parent.parent.parent / "sticks" / "data" / "caldera_adversaries"
    if campaign_dir.exists():
        campaigns = sorted([f.stem for f in campaign_dir.glob("*.yml")])
        print("Available campaigns in corpus:")
        for c in campaigns:
            print(f"  - {c}")
    else:
        print("Campaign corpus not found")


def run_smoke():
    """Quick smoke test."""
    print("=== SMOKE TEST ===")
    print(f"Checking Caldera at {CALDERA_URL}...")
    if not check_caldera():
        print("ERROR: Caldera not reachable")
        return False
    print("OK: Caldera reachable")

    agents = get_agents()
    print(f"Agents: {len(agents)}")
    if len(agents) < 1:
        print("ERROR: No agents")
        return False
    print("OK: Agents available")
    return True


def run_list():
    """List available resources."""
    print("=== LIST MODE ===")
    list_campaigns()
    print()
    adversaries = get_adversaries()
    print(f"Adversaries in Caldera: {len(adversaries)}")
    for a in adversaries[:10]:
        print(f"  - {a.get('adversary_id')}: {a.get('name')}")
    return True


def run_adversaries():
    """List Caldera adversaries."""
    print("=== ADVERSARIES ===")
    adversaries = get_adversaries()
    for a in adversaries:
        print(f"{a.get('adversary_id')}: {a.get('name')}")
    return True


def run_clean():
    """Clean old operations."""
    print("=== CLEAN MODE ===")
    print("Note: Manual cleanup required in Caldera UI")
    print("Operations can be cleared via API if needed")
    return True


def run_demo():
    """Demo mode - simple execution."""
    print("=== DEMO MODE ===")
    if not run_smoke():
        return False

    print("\nRunning demo with default adversary...")
    result = subprocess.run(
        ["python3", "run_campaign.py", "--campaign", "demo", "--adversary", ADVERSARY_DEFAULT, "--wait", "30"],
        capture_output=True, text=True, cwd=Path(__file__).parent
    )
    print(result.stdout)
    if result.returncode != 0:
        print("ERROR:", result.stderr)
        return False
    return True


def run_full():
    """Full execution mode."""
    print("=== FULL MODE ===")
    return run_demo()


def main():
    parser = argparse.ArgumentParser(description="SUT Measurement CLI")
    parser.add_argument("--mode", choices=["smoke", "list", "adversaries", "clean", "demo", "run"], default="smoke")
    args = parser.parse_args()

    modes = {
        "smoke": run_smoke,
        "list": run_list,
        "adversaries": run_adversaries,
        "clean": run_clean,
        "demo": run_demo,
        "run": run_full
    }

    success = modes[args.mode]()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
