from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from planning.binding_catalog import build_binding_catalog, build_reference_catalog
from planning.sut_blueprint import (
    BackendRecipe,
    BlueprintHost,
    SUTBlueprint,
)


def test_binding_catalog_contains_references_not_credentials(tmp_path: Path) -> None:
    blueprint = SUTBlueprint(
        campaign_id="C0045",
        source_constraint_sha256="constraints",
        hosts=[
            BlueprintHost(
                host_id="target-1",
                role="target",
                platform="Linux",
                recipe=BackendRecipe(
                    backend="docker",
                    base_image="python:3.11-slim",
                    memory_mb=1024,
                    cpu_count=1,
                ),
            )
        ],
        concretized_requirements=[],
    )
    blueprint.finalize_hash()
    campaign_path = tmp_path / "campaign.json"
    campaign_path.write_text(
        json.dumps(
            {
                "campaign_id": "0.shadowray",
                "source_campaign_id": "C0045",
                "execution_contract": {
                    "initial_facts": ["sut.ready"],
                    "techniques": [],
                },
                "vulnerabilities": [
                    {
                        "type": "weak_credentials",
                        "config": {"username": "private", "password": "private"},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    catalog = build_binding_catalog(blueprint, campaign_path)
    encoded = catalog.model_dump_json()
    assert '"private"' not in encoded
    assert "secret://sut/0.shadowray/credential-fixture" in encoded
    assert catalog.content_sha256
    reference = build_reference_catalog(catalog)
    assert all(
        binding.kind not in {"endpoint", "credential_source", "channel"}
        for binding in reference.bindings
    )
    assert reference.initial_facts == ["sut.ready"]
