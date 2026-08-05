#!/usr/bin/env python3
"""
Campaign Runner - Enhanced version with polling and detailed results.

Usage:
    python3 run_campaign.py --campaign 0.solarwinds_compromise
    python3 run_campaign.py --campaign 0.apt28_nearest_neighbor_campaign --wait 60
"""

import argparse
import json
import sys
import time
from datetime import datetime
from pathlib import Path

import requests

CALDERA_URL = "http://localhost:8889"
USERNAME = "red"
PASSWORD = "BgbJ-PzikRWCp3BMpkg3PXUIz_RCyBaw6r2JeeGkdBI"
DEFAULT_ADVERSARY = "50855e29-3b4e-4562-aa55-b3d7f93c26b8"
TERMINAL_STATES = {"finished", "completed", "timeout", "error"}


def login(session):
    """Login to Caldera with proper redirect handling."""
    session.get(f"{CALDERA_URL}/enter")
    response = session.post(
        f"{CALDERA_URL}/enter",
        data={"username": USERNAME, "password": PASSWORD},
        allow_redirects=False
    )
    if response.status_code in (301, 302):
        location = response.headers.get("Location", "/")
        session.get(f"{CALDERA_URL}{location}")
    test = session.get(f"{CALDERA_URL}/api/v2/adversaries")
    return test.status_code == 200


def get_agents(session):
    """Get all agents."""
    resp = session.get(f"{CALDERA_URL}/api/v2/agents")
    return resp.json() if resp.status_code == 200 else []


def create_operation(session, name, adversary_id, host_group):
    """Create and start an operation."""
    payload = {
        "index": "operations",
        "name": name,
        "adversary_id": adversary_id,
        "host_group": host_group
    }
    resp = session.put(f"{CALDERA_URL}/api/rest", json=payload)
    if resp.status_code == 200:
        data = resp.json()
        return data[0] if isinstance(data, list) else data
    return None


def get_operation(session, name):
    """Get operation by name."""
    resp = session.get(f"{CALDERA_URL}/api/v2/operations")
    if resp.status_code == 200:
        for op in resp.json():
            if op.get("name") == name:
                return op
    return None


def wait_for_completion(session, operation_name, timeout=120, poll_interval=10):
    """Poll operation until terminal state or timeout."""
    start_time = time.time()
    while time.time() - start_time < timeout:
        op = get_operation(session, operation_name)
        if op:
            state = op.get("state", "")
            print(f"  State: {state}")
            if state in TERMINAL_STATES:
                return op
        time.sleep(poll_interval)
    return get_operation(session, operation_name)


def collect_detailed_results(operation):
    """Collect detailed results from operation."""
    result = {
        "state": operation.get("state"),
        "start_time": operation.get("start"),
        "host_count": len(operation.get("host_group", [])),
        "hosts": []
    }

    for host in operation.get("host_group", []):
        host_data = {
            "paw": host.get("paw"),
            "links_count": len(host.get("links", [])),
            "links": []
        }

        for link in host.get("links", []):
            link_info = {
                "ability_id": link.get("ability", {}).get("ability_id"),
                "technique_id": link.get("ability", {}).get("technique_id"),
                "status": link.get("status"),
                "output": link.get("output", "")[:500] if link.get("output") else ""
            }
            host_data["links"].append(link_info)

        result["hosts"].append(host_data)

    return result


def save_results(result, campaign_name):
    """Save results to JSON file."""
    results_dir = Path(__file__).parent / "results"
    results_dir.mkdir(exist_ok=True)
    output_file = results_dir / f"{campaign_name}_results.json"
    with open(output_file, "w") as f:
        json.dump(result, f, indent=2)
    print(f"Results saved to: {output_file}")
    return output_file


def main():
    parser = argparse.ArgumentParser(description="Run campaign on Caldera")
    parser.add_argument("--campaign", required=True, help="Campaign name")
    parser.add_argument("--adversary", default=DEFAULT_ADVERSARY, help="Adversary ID")
    parser.add_argument("--wait", type=int, default=60, help="Wait seconds for execution")
    parser.add_argument("--timeout", type=int, default=120, help="Max wait for completion")
    args = parser.parse_args()

    session = requests.Session()

    print("Logging in...")
    if not login(session):
        print("ERROR: Login failed")
        sys.exit(1)

    session.headers.update({"Content-Type": "application/json"})
    print("OK: Logged in")

    print("Getting agents...")
    agents = get_agents(session)
    if not agents:
        print("ERROR: No agents available")
        sys.exit(1)
    agent_paws = [a.get("paw") for a in agents if a.get("paw")]
    print(f"OK: {len(agent_paws)} agents: {agent_paws}")

    print(f"Running campaign: {args.campaign}")
    op_name = f"exp_{args.campaign}_{int(time.time())}"

    operation = create_operation(session, op_name, args.adversary, agent_paws)
    if not operation:
        print("ERROR: Failed to create operation")
        sys.exit(1)
    print(f"OK: Operation created: {op_name}")

    print(f"Waiting up to {args.wait}s for execution...")
    time.sleep(args.wait)

    result = get_operation(session, op_name)
    if not result:
        print("ERROR: Could not get operation result")
        sys.exit(1)

    print(f"\nFinal state: {result.get('state')}")

    # Collect detailed results
    detailed = collect_detailed_results(result)

    output = {
        "timestamp": datetime.now().isoformat(),
        "campaign": args.campaign,
        "operation_name": op_name,
        "execution": detailed,
        "agents": agent_paws
    }

    print(f"Hosts: {detailed['host_count']}")
    for host in detailed["hosts"]:
        print(f"  {host['paw']}: {host['links_count']} links")

    save_results(output, args.campaign)
    print("DONE")


if __name__ == "__main__":
    main()
