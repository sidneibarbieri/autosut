#!/usr/bin/env python3
"""Run a campaign in the multi-host environment"""

import json
import sys
from pathlib import Path

EVIDENCE_DIR = (
    Path(__file__).parent.parent.parent / "infra" / "evidence" / "campaigns_multi_host"
)
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)


def run_campaign(campaign_id):
    print(f"Starting campaign {campaign_id} in multi-host mode")
    # Placeholder for real campaign orchestration logic
    result = {
        "campaign": campaign_id,
        "status": "started",
        "hosts": ["caldera", "kali", "nginx", "db"],
    }
    out = EVIDENCE_DIR / f"{campaign_id}.json"
    out.write_text(json.dumps(result, indent=2))
    print(f"Campaign evidence written to {out}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: run.py <campaign-id>")
        sys.exit(1)
    run_campaign(sys.argv[1])
