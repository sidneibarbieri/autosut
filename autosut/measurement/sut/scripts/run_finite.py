#!/usr/bin/env python3
"""
Finite execution runner for Caldera operations.

Creates operations with finite timeout and collects results properly.
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


def login():
    """Login to Caldera."""
    session = requests.Session()
    session.get(f"{CALDERA_URL}/enter")
    session.post(
        f"{CALDERA_URL}/enter",
        data={"username": USERNAME, "password": PASSWORD},
        allow_redirects=False
    )
    return session


def get_agents(session):
    """Get active agents."""
    resp = session.get(f"{CALDERA_URL}/api/v2/agents")
    if resp.status_code != 200:
        return []
    agents = resp.json()
    return [a for a in agents if a.get("paw")]


def create_operation(session, name, adversary_id, agent_paws, planner_id=None):
    """Create and start operation."""
    payload = {
        "index": "operations",
        "name": name,
        "adversary_id": adversary_id,
        "host_group": agent_paws
    }
    if planner_id:
        payload["planner"] = planner_id

    resp = session.put(f"{CALDERA_URL}/api/rest", json=payload)
    if resp.status_code == 200:
        data = resp.json()
        return data[0] if isinstance(data, list) else data
    return None


def get_operation(session, operation_id):
    """Get operation by ID."""
    resp = session.get(f"{CALDERA_URL}/api/v2/operations/{operation_id}")
    return resp.json() if resp.status_code == 200 else None


def collect_results(operation):
    """Collect results from operation."""
    result = {
        "state": operation.get("state"),
        "start": operation.get("start"),
        "host_count": len(operation.get("host_group", [])),
        "hosts": []
    }

    for host in operation.get("host_group", []):
        host_data = {
            "paw": host.get("paw"),
            "links": []
        }

        for link in host.get("links", []):
            ability = link.get("ability", {})
            host_data["links"].append({
                "ability_id": ability.get("ability_id"),
                "technique_id": ability.get("technique_id"),
                "status": link.get("status"),
                "output": link.get("output", "")[:200] if link.get("output") else ""
            })

        result["hosts"].append(host_data)

    return result


def save_results(data, campaign):
    """Save results to JSON."""
    results_dir = Path(__file__).parent / "results"
    results_dir.mkdir(exist_ok=True)

    output_file = results_dir / f"{campaign}_finite_results.json"
    with open(output_file, "w") as f:
        json.dump(data, f, indent=2)

    print(f"Results saved to: {output_file}")
    return output_file


def main():
    parser = argparse.ArgumentParser(description="Run finite campaign")
    parser.add_argument("--campaign", required=True)
    parser.add_argument("--adversary", required=True)
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--planner", default=None)
    args = parser.parse_args()

    print(f"=== Finite Execution: {args.campaign} ===")

    session = login()
    print("Logged in")

    agents = get_agents(session)
    if not agents:
        print("ERROR: No agents")
        sys.exit(1)

    agent_paws = [a.get("paw") for a in agents if a.get("paw")]
    print(f"Agents: {len(agent_paws)}")

    operation_name = f"finite_{args.campaign}_{int(time.time())}"
    print(f"Creating operation: {operation_name}")

    operation = create_operation(session, operation_name, args.adversary, agent_paws, args.planner)
    if not operation:
        print("ERROR: Failed to create operation")
        sys.exit(1)

    operation_id = operation.get("id")
    print(f"Operation ID: {operation_id}")

    print(f"Waiting {args.timeout}s for execution...")
    time.sleep(args.timeout)

    operation = get_operation(session, operation_id)
    if not operation:
        print("ERROR: Failed to get operation")
        sys.exit(1)

    state = operation.get("state", "unknown")
    print(f"Final state: {state}")

    results = collect_results(operation)

    techniques = set()
    for host in results["hosts"]:
        for link in host.get("links", []):
            if link.get("technique_id"):
                techniques.add(link["technique_id"])

    print(f"Techniques observed: {len(techniques)}")
    for t in techniques:
        print(f"  - {t}")

    output = {
        "timestamp": datetime.now().isoformat(),
        "campaign": args.campaign,
        "adversary_id": args.adversary,
        "operation_name": operation_name,
        "operation_id": operation_id,
        "state": state,
        "timeout_used": args.timeout,
        "agents": agent_paws,
        "techniques_observed": list(techniques),
        "execution": results
    }

    save_results(output, args.campaign)
    print("DONE")


if __name__ == "__main__":
    main()
