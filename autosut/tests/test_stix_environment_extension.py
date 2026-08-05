from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from planning.binding_catalog import BindingCatalog
from planning.concretized_plan import load_concretized_plan
from planning.procedural_plan import load_procedural_plan
from planning.stix_environment_extension import (
    ENVIRONMENT_PROPERTY,
    ResolutionStatus,
    attach_environment_semantics,
    parse_environment_property,
)
from planning.sut_blueprint import SUTBlueprint
from planning.sut_constraints import SUTConstraintSet


def test_c0045_environment_extension_is_typed_and_honest() -> None:
    input_root = PROJECT_ROOT / "release/inputs/sticks/c0045-v1"
    sticks_path = PROJECT_ROOT / "release/enriched/C0045.stix.json"
    assert sticks_path.is_file()
    output = attach_environment_semantics(
        sticks_bundle=json.loads(sticks_path.read_text()),
        procedural_plan=load_procedural_plan(
            input_root / "C0045.procedural-plan.json"
        ),
        concretized_plan=load_concretized_plan(
            input_root / "C0045.concretized-plan.json"
        ),
        constraints=SUTConstraintSet.model_validate_json(
            (PROJECT_ROOT / "release/plans/C0045.sut-constraints.json").read_text()
        ),
        blueprint=SUTBlueprint.model_validate_json(
            (PROJECT_ROOT / "release/plans/C0045.sut-blueprint.json").read_text()
        ),
        binding_catalog=BindingCatalog.model_validate_json(
            (PROJECT_ROOT / "release/plans/C0045.binding-catalog.json").read_text()
        ),
        cve_rules_path=PROJECT_ROOT / "data/cve_resolution_rules.yml",
    )
    relationships = [
        item
        for item in output["objects"]
        if ENVIRONMENT_PROPERTY in item
    ]
    assert len(relationships) == 10
    extensions = [parse_environment_property(item) for item in relationships]
    t1190 = next(item for item in extensions if item and item.technique_id == "T1190")
    assert t1190.backend_cue.values == ["docker"]
    assert t1190.software[0].cve_id == "CVE-2023-48022"
    assert t1190.software[0].package_name.values == ["ray"]
    assert t1190.software[0].cpe23_uri.status == ResolutionStatus.unresolved
    assert "cpe23_uri" in t1190.unresolved_applicable_fields
