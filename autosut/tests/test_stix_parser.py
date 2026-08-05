from __future__ import annotations

import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
ENTERPRISE_BUNDLE = PROJECT_ROOT / "data" / "stix" / "enterprise-attack.json"


def _load_bundle() -> dict:
    return json.loads(ENTERPRISE_BUNDLE.read_text(encoding="utf-8"))


def test_enterprise_bundle_has_stix_bundle_shape() -> None:
    bundle = _load_bundle()

    assert bundle["type"] == "bundle"
    assert isinstance(bundle.get("objects"), list)
    assert bundle["objects"], "Expected Enterprise bundle objects"


def test_enterprise_bundle_contains_attack_patterns_with_mitre_ids() -> None:
    objects = _load_bundle()["objects"]
    attack_patterns = [
        obj for obj in objects
        if obj.get("type") == "attack-pattern"
        and not obj.get("x_mitre_deprecated", False)
        and not obj.get("revoked", False)
    ]

    assert attack_patterns, "Expected active attack-pattern objects"
    assert any(
        ref.get("source_name") == "mitre-attack" and ref.get("external_id")
        for obj in attack_patterns
        for ref in obj.get("external_references", [])
    )


def test_enterprise_bundle_contains_relationship_graph() -> None:
    objects = _load_bundle()["objects"]
    object_ids = {obj["id"] for obj in objects if "id" in obj}
    relationships = [obj for obj in objects if obj.get("type") == "relationship"]

    assert relationships, "Expected relationship objects"
    assert any(
        rel.get("source_ref") in object_ids and rel.get("target_ref") in object_ids
        for rel in relationships
    )
