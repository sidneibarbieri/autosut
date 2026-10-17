from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
STICKS_SRC = PROJECT_ROOT.parent.parent / "sticks" / "artifact" / "src"
if not STICKS_SRC.is_dir():
    pytest.skip(
        "joint-realization tests require an adjacent STICKS artifact checkout",
        allow_module_level=True,
    )
sys.path.insert(0, str(STICKS_SRC))

from concretization.models import (  # noqa: E402
    ActionTemplate,
    BindingCatalog as SticksBindingCatalog,
    BindingValue as SticksBindingValue,
)
from concretization.realization_space import enumerate_realization_space  # noqa: E402
from contracts.procedural_ir import (  # noqa: E402
    ProceduralPlan,
    ProcedureStep,
    SourceSnapshot,
)
from src.planning.binding_catalog import BindingCatalog  # noqa: E402
from src.planning.joint_realization import (  # noqa: E402
    certify_joint_realizations,
    load_realization_space,
)
from src.planning.sut_blueprint import (  # noqa: E402
    BackendRecipe,
    BlueprintHost,
    NetworkPolicy,
    SUTBlueprint,
)


def _inputs() -> tuple[ProceduralPlan, SticksBindingCatalog, list[ActionTemplate]]:
    plan = ProceduralPlan(
        campaign_id="CTEST",
        campaign_name="Fixture",
        source=SourceSnapshot(
            bundle_sha256="bundle",
            object_count=1,
            campaign_stix_id="campaign--fixture",
            campaign_external_id="CTEST",
        ),
        steps=[
            ProcedureStep(
                technique_id="T1001",
                technique_stix_id="attack-pattern--fixture",
                name="Fixture",
                execution_domain="target",
                relationship_ids=["relationship--fixture"],
            )
        ],
    )
    plan.finalize_hash()
    catalog = SticksBindingCatalog(
        sut_id="0.fixture",
        source_sha256="source",
        initial_facts=["sut.ready"],
        goal_facts=["goal.ready"],
        bindings=[
            SticksBindingValue(
                binding_id="target.primary",
                kind="target_host",
                value="lab://target-1",
                source="sut",
            )
        ],
    )
    catalog.finalize_hash()
    templates = [
        ActionTemplate(
            template_id="benign-fixture",
            technique_ids=["T1001"],
            execution_domain="target",
            parameter_kinds={"target": "target_host"},
            requires=["sut.ready"],
            produces=["goal.ready"],
            evidence_predicates=["fixture.observed"],
            fidelity_ceiling="adapted",
            description="Exercise a benign local fixture.",
        )
    ]
    return plan, catalog, templates


def _write_space(path: Path) -> None:
    plan, catalog, templates = _inputs()
    space = enumerate_realization_space(plan, catalog, templates)
    path.write_text(space.model_dump_json(indent=2) + "\n", encoding="utf-8")


def _blueprint() -> SUTBlueprint:
    blueprint = SUTBlueprint(
        campaign_id="CTEST",
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
        network_policy=NetworkPolicy(),
        concretized_requirements=[],
    )
    blueprint.finalize_hash()
    return blueprint


def _catalog() -> BindingCatalog:
    _, sticks_catalog, _ = _inputs()
    return BindingCatalog.model_validate(sticks_catalog.model_dump(mode="json"))


def test_certifies_joint_contract_without_claiming_execution(tmp_path: Path) -> None:
    path = tmp_path / "realizations.json"
    _write_space(path)

    result = certify_joint_realizations(
        load_realization_space(path),
        _blueprint(),
        _catalog(),
    )

    assert result.compatible_realization_count == 1
    assert result.selected_realization_sha256 is not None
    assert result.operational_status == "not_run"
    assert result.compatibility_scope == "declared_sut_contract_only"
    assert result.assessments[0].compatible


def test_rejects_catalog_from_another_pair(tmp_path: Path) -> None:
    path = tmp_path / "realizations.json"
    _write_space(path)
    catalog = _catalog()
    catalog.sut_id = "different-sut"
    catalog.finalize_hash()

    result = certify_joint_realizations(load_realization_space(path), _blueprint(), catalog)

    assert result.compatible_realization_count == 0
    assert {issue.code for issue in result.assessments[0].issues} >= {
        "BINDING_CATALOG_MISMATCH",
        "PLAN_BINDING_CATALOG_MISMATCH",
    }


def test_loader_rejects_tampered_graph(tmp_path: Path) -> None:
    path = tmp_path / "realizations.json"
    _write_space(path)
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["realizations"][0]["graph"]["nodes"][0]["template_id"] = "tampered"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="graph hash mismatch"):
        load_realization_space(path)


def _rehash_realization_space(payload: dict) -> None:
    canonical = {
        key: value for key, value in payload.items() if key != "content_sha256"
    }
    payload["content_sha256"] = hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def test_loader_rejects_unknown_realization_schema(tmp_path: Path) -> None:
    path = tmp_path / "realizations.json"
    _write_space(path)
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["schema_version"] = "2"
    _rehash_realization_space(payload)
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="schema_version"):
        load_realization_space(path)


def test_loader_rejects_unknown_realization_semantics(tmp_path: Path) -> None:
    path = tmp_path / "realizations.json"
    _write_space(path)
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["unmodeled_execution_semantics"] = "not-consumed"
    _rehash_realization_space(payload)
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="Extra inputs are not permitted"):
        load_realization_space(path)
