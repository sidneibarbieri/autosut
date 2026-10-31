#!/usr/bin/env python3
"""Test whether profile specificity depends on STIX object identity rather than product identity.

The specificity analysis represents each intrusion set by the STIX software objects it uses, so
two distinct objects that name the same product are never merged. This study merges software
objects that share a normalized name or alias, rebuilds every profile over the merged products,
and recomputes the conditioned confusion statistic with the same functions and threshold.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))

import sut_measurement_pipeline as pipeline  # noqa: E402

OUTPUT = SCRIPTS / "results" / "canonical_product_sensitivity.json"


def _normalize(value: str | None) -> str:
    return re.sub(r"[^a-z0-9]", "", (value or "").lower())


def canonical_product_map(software_objects: list[dict]) -> dict[str, str]:
    """Map every software object to a representative of its name-or-alias equivalence class."""
    parent = {item["id"]: item["id"] for item in software_objects}

    def find(identifier: str) -> str:
        while parent[identifier] != identifier:
            parent[identifier] = parent[parent[identifier]]
            identifier = parent[identifier]
        return identifier

    first_owner: dict[str, str] = {}
    for item in sorted(software_objects, key=lambda entry: entry["id"]):
        keys = {_normalize(item.get("name"))}
        keys |= {_normalize(alias) for alias in item.get("x_mitre_aliases", [])}
        for key in sorted(keys - {""}):
            if key in first_owner:
                left, right = find(item["id"]), find(first_owner[key])
                if left != right:
                    parent[max(left, right)] = min(left, right)
            else:
                first_owner[key] = item["id"]
    return {identifier: find(identifier) for identifier in parent}


def main() -> int:
    objects = pipeline.load_bundle(pipeline.ENTERPRISE_FILE)
    by_type, by_id = pipeline.index_objects_by_type(objects)
    rel_fwd, _, _ = pipeline.build_relationship_index(by_type.get("relationship", []))
    intrusion_sets = by_type.get("intrusion-set", [])
    software = by_type.get("malware", []) + by_type.get("tool", [])
    built = pipeline.build_sut_profiles(intrusion_sets, software, rel_fwd, by_id)
    profiles = built[0] if isinstance(built, tuple) else built

    mapping = canonical_product_map(software)
    groups: dict[str, list[str]] = {}
    names = {item["id"]: item["name"] for item in software}
    for identifier, representative in mapping.items():
        groups.setdefault(representative, []).append(names[identifier])
    merged = sorted(sorted(group) for group in groups.values() if len(group) > 1)
    canonical = {
        profile_id: {mapping.get(feature, feature) for feature in features}
        for profile_id, features in profiles.items()
    }

    def statistic(selected: dict) -> dict:
        lower, upper, collapse = pipeline._threshold_collapse_statistic(selected, pipeline.JACCARD_DELTA)
        return {
            "profiles": lower["sample_size"],
            "k1_confused": lower["confused_count"],
            "k2_profiles": upper["sample_size"],
            "k2_confused": upper["confused_count"],
            "collapse_pp": round(collapse, 4),
        }

    payload = {
        "question": "Does merging software objects that name the same product change profile confusion?",
        "delta": pipeline.JACCARD_DELTA,
        "software_objects": len(software),
        "canonical_products": len(groups),
        "merged_groups": merged,
        "object_identity": statistic(profiles),
        "product_identity": statistic(canonical),
    }
    OUTPUT.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        f"[canonical-products] {payload['software_objects']} objects -> {payload['canonical_products']} "
        f"products; k>=1 confused {payload['object_identity']['k1_confused']} -> "
        f"{payload['product_identity']['k1_confused']}, k>=2 {payload['object_identity']['k2_confused']} -> "
        f"{payload['product_identity']['k2_confused']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
