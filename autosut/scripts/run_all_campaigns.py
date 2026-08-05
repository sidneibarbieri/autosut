#!/usr/bin/env python3
"""
STICKS All Campaigns Runner - Execute all campaigns for regression testing.

Usage:
    python scripts/run_all_campaigns.py
    python scripts/run_all_campaigns.py --output results/batch_run
"""

import argparse
import sys
from datetime import datetime
from pathlib import Path

# Add src to Python path for src layout
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from loaders.campaign_loader import list_campaigns
from runners.campaign_runner import UnifiedCampaignRunner


def _duration_seconds(evidence) -> float:
    if evidence.end_time is None:
        return 0.0
    return (evidence.end_time - evidence.start_time).total_seconds()


def main():
    parser = argparse.ArgumentParser(
        description="Execute all STICKS campaigns for regression testing"
    )
    parser.add_argument(
        "--output", help="Base output directory (default: results/evidence)"
    )
    parser.add_argument("--campaign", help="Run specific campaign only (for testing)")

    args = parser.parse_args()

    # Get available campaigns
    all_campaigns = list_campaigns()
    campaigns = [args.campaign] if args.campaign else sorted(all_campaigns)

    if args.campaign and args.campaign not in all_campaigns:
        print(f"Error: Campaign '{args.campaign}' not found")
        print(f"Available campaigns: {', '.join(sorted(all_campaigns))}")
        sys.exit(1)

    # Execute campaigns
    base_output = Path(args.output) if args.output else Path("results/evidence")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    batch_output = base_output / f"batch_{timestamp}"
    batch_output.mkdir(parents=True, exist_ok=True)

    print(f"Executing {len(campaigns)} campaigns...")
    print(f"Output directory: {batch_output}")
    print("=" * 70)

    results = []
    failed_campaigns = []

    for i, campaign_id in enumerate(campaigns, 1):
        print(f"\n[{i}/{len(campaigns)}] {campaign_id}")
        print("-" * 40)

        try:
            campaign_output = batch_output / campaign_id
            runner = UnifiedCampaignRunner(campaign_id, campaign_output)
            evidence = runner.run()

            success_rate = (
                evidence.successful / evidence.total_techniques * 100
                if evidence.total_techniques
                else 0.0
            )
            results.append(
                {
                    "campaign": campaign_id,
                    "total": evidence.total_techniques,
                    "successful": evidence.successful,
                    "failed": evidence.failed,
                    "success_rate": success_rate,
                    "duration": _duration_seconds(evidence),
                }
            )

            if evidence.failed > 0:
                failed_campaigns.append(campaign_id)

            print(f"  Total: {evidence.total_techniques}")
            print(f"  Successful: {evidence.successful}")
            print(f"  Failed: {evidence.failed}")
            print(f"  Success Rate: {success_rate:.1f}%")

        except Exception as e:
            print(f"  ERROR: {e}")
            failed_campaigns.append(campaign_id)
            results.append(
                {
                    "campaign": campaign_id,
                    "total": 0,
                    "successful": 0,
                    "failed": 0,
                    "success_rate": 0,
                    "duration": 0,
                    "error": str(e),
                }
            )

    # Summary
    print("\n" + "=" * 70)
    print("BATCH EXECUTION SUMMARY")
    print("=" * 70)

    total_campaigns = len(campaigns)
    successful_campaigns = total_campaigns - len(failed_campaigns)

    print(f"Campaigns executed: {total_campaigns}")
    print(f"Successful campaigns: {successful_campaigns}")
    print(f"Failed campaigns: {len(failed_campaigns)}")

    if failed_campaigns:
        print(f"Failed: {', '.join(failed_campaigns)}")

    print("\nDetailed Results:")
    for result in results:
        status = "ok" if result.get("error") is None else "FAIL"
        print(
            f"  {status} {result['campaign']}: {result['successful']}/{result['total']} ({result['success_rate']:.1f}%)"
        )

    # Save batch summary
    import json

    summary_file = batch_output / "batch_summary.json"
    with open(summary_file, "w") as f:
        json.dump(
            {
                "timestamp": timestamp,
                "total_campaigns": total_campaigns,
                "successful_campaigns": successful_campaigns,
                "failed_campaigns": failed_campaigns,
                "results": results,
            },
            f,
            indent=2,
        )

    print(f"\nBatch summary saved to: {summary_file}")

    # Exit with error code if any campaigns failed
    if failed_campaigns:
        sys.exit(1)


if __name__ == "__main__":
    main()
