#!/usr/bin/env python3
"""
Refresh the local MITRE ATT&CK Enterprise bundle from the official repository.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import urlopen


PROJECT_ROOT = Path(__file__).resolve().parent.parent
BUNDLE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)
OUTPUT_BUNDLE = PROJECT_ROOT / "data" / "stix" / "enterprise-attack.json"
OUTPUT_METADATA = PROJECT_ROOT / "data" / "stix" / "enterprise-attack.metadata.json"


def main() -> None:
    OUTPUT_BUNDLE.parent.mkdir(parents=True, exist_ok=True)

    with urlopen(BUNDLE_URL, timeout=60) as response:
        payload = response.read()

    OUTPUT_BUNDLE.write_bytes(payload)

    bundle = json.loads(payload)
    metadata = {
        "source_url": BUNDLE_URL,
        "downloaded_at": datetime.now(timezone.utc).isoformat(),
        "object_count": len(bundle.get("objects", [])),
    }
    OUTPUT_METADATA.write_text(json.dumps(metadata, indent=2))

    print(f"Wrote {OUTPUT_BUNDLE}")
    print(f"Wrote {OUTPUT_METADATA}")


if __name__ == "__main__":
    main()
