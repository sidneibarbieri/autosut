import json
import sys
from collections import Counter

def count_stix_types(file_path):
    """Count MITRE ATT&CK Enterprise STIX objects by type."""
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    objects = data.get("objects", [])
    counts = Counter(obj.get("type", "unknown") for obj in objects)

    print(f"\nCounts by STIX object type in {file_path}:\n")
    for t, c in counts.items():
        print(f"{t}: {c}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python count_types.py <path_to_enterprise-attack.json>")
        sys.exit(1)

    json_path = sys.argv[1]
    count_stix_types(json_path)
