#!/usr/bin/env python3
"""CLI entry point for the per-campaign orchestrator.

Usage:
    python3 scripts/run_orchestrated_campaign.py 0.shadowray

Runs one campaign tuple end to end: bring up SUT and attacker containers,
inject the declared CVEs, execute the techniques, capture per-technique
evidence, and tear everything down. Manifest is written under
release/evidence/<run_id>/.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Make the orchestrator package importable without installing it.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from orchestrator import build_default
from orchestrator.catalog import implemented_campaigns, known_campaigns
from run_all_orchestrated_campaigns import (
    CALDERA_REQUIRED_CAMPAIGNS,
    ensure_caldera_ready,
    restore_docker_platform,
    set_caldera_platform_if_needed,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "campaign",
        nargs="?",
        help=f"campaign id (one of: {', '.join(implemented_campaigns())})",
    )
    parser.add_argument(
        "--fidelity",
        choices=("real_then_surrogate", "real_only", "surrogate"),
        default="real_then_surrogate",
        help="CVE materialization policy (default: real_then_surrogate).",
    )
    parser.add_argument("--list", action="store_true",
                        help="list all known campaigns and exit")
    args = parser.parse_args()

    if args.list:
        for cid in known_campaigns():
            marker = "x" if cid in implemented_campaigns() else " "
            print(f" [{marker}] {cid}")
        return 0

    if not args.campaign:
        parser.print_help()
        return 1

    # Caldera-driven campaigns need the C2 reachable and their SUT pinned to
    # the prebuilt-sandcat architecture; otherwise the agent registration cold-
    # starts a just-in-time build and the technique is recorded as a failure.
    # Applying it here means the single-campaign command behaves like the full
    # reviewer runner without extra steps.
    needs_caldera = args.campaign in CALDERA_REQUIRED_CAMPAIGNS
    prev_platform = None
    if needs_caldera:
        if not ensure_caldera_ready():
            print("[caldera] C2 not reachable; caldera-driven techniques will "
                  "be recorded as failures (run scripts/up_lab.sh or use "
                  "scripts/run_all_orchestrated_campaigns.py).", file=sys.stderr)
        prev_platform = set_caldera_platform_if_needed(args.campaign)

    try:
        orch = build_default()
        result = orch.run_campaign(
            args.campaign, fidelity_preference=args.fidelity,
        )
    finally:
        if needs_caldera:
            restore_docker_platform(prev_platform)

    print(f"\n[orchestrator] run_id: {result.run_id}")
    print(f"[orchestrator] techniques: {result.successful}/{result.total_techniques} successful")
    print(
        "[orchestrator] evidence-backed: "
        f"{result.evidence_backed_successful}/{result.total_techniques}"
    )
    print(
        "[orchestrator] adapted: "
        f"{result.adapted_successful}/{result.total_techniques}"
    )
    print(
        "[orchestrator] marker-only: "
        f"{result.marker_only_successful}/{result.total_techniques}"
    )
    print(
        "[orchestrator] Caldera-dispatched: "
        f"{result.caldera_driven_successful}/{result.total_techniques}"
    )
    print(f"[orchestrator] fidelity distribution: {result.fidelity_distribution}")
    print(f"[orchestrator] manifest: {result.manifest_path}")
    return (
        0
        if result.evidence_backed_successful == result.total_techniques
        and result.teardown_clean
        else 2
    )


if __name__ == "__main__":
    raise SystemExit(main())
