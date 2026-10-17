"""The pair-preparation CLI preserves executable paths across checkout boundaries."""

import importlib.util
import hashlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = PROJECT_ROOT / "scripts" / "prepare_campaign_pairs.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("autosut_prepare_campaign_pairs", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_explicit_relative_python_path_preserves_virtualenv_symlink(tmp_path: Path) -> None:
    module = _load_module()
    interpreter = tmp_path / ".venv/bin/python"
    interpreter.parent.mkdir(parents=True)
    interpreter.symlink_to(Path(sys.executable))

    observed = module.resolve_python_executable(".venv/bin/python", tmp_path)

    assert observed == str(interpreter)
    assert Path(observed).is_symlink()


def test_derived_source_identity_does_not_invent_execution_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_module()
    source = tmp_path / "plan.json"
    source.write_text('{"source":"preserved"}')
    monkeypatch.setattr(
        module, "load_procedural_plan",
        lambda path: SimpleNamespace(campaign_id="C9999", content_sha256="a" * 64),
    )
    generated_root = tmp_path / "generated"
    path = module.derive_missing_specification(source, generated_root)
    spec = json.loads(path.read_text())
    assert path.parent == generated_root
    assert spec["campaign_id"] == spec["source_campaign_id"] == "C9999"
    assert "execution_contract" not in spec
    assert spec["derivation"]["execution_contract_inferred"] is False
    assert spec["derivation"]["source_file_sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
    assert spec["derivation"]["source_plan_sha256"] == "a" * 64
    assert module.derive_missing_specification(source, generated_root) == path


def test_path_command_name_is_preserved(tmp_path: Path) -> None:
    module = _load_module()

    assert module.resolve_python_executable("python3", tmp_path) == "python3"


def test_corpus_discovery_prefers_curated_plan_and_keeps_enterprise_only(tmp_path: Path) -> None:
    module = _load_module()
    plan_root = tmp_path / "release/plans"
    enterprise = plan_root / "enterprise"
    enterprise.mkdir(parents=True)
    enterprise_copy = enterprise / "C0010.procedural-plan.json"
    enterprise_copy.write_text("enterprise")
    other_campaign = enterprise / "C0026.procedural-plan.json"
    other_campaign.write_text("other")
    curated_copy = plan_root / enterprise_copy.name
    curated_copy.write_text("curated")

    plans = module.discover_corpus_plans(plan_root)

    assert plans == {"C0010": curated_copy, "C0026": other_campaign}


def test_external_spec_discovery_checks_campaign_identity(tmp_path: Path) -> None:
    module = _load_module()
    spec_path = tmp_path / "custom.json"
    spec_path.write_text(json.dumps({"campaign_id": "custom", "source_campaign_id": "C9999"}))

    assert module.discover_campaign_specs(tmp_path, set()) == {"custom": spec_path}

    spec_path.write_text(json.dumps({"campaign_id": "different", "source_campaign_id": "C9999"}))
    with pytest.raises(ValueError, match="differs from specification filename"):
        module.discover_campaign_specs(tmp_path, set())


def test_external_corpus_can_omit_legacy_aliases(tmp_path: Path) -> None:
    module = _load_module()
    inventory = tmp_path / "legacy.json"
    inventory.write_text(
        json.dumps({"campaigns": [{"campaign_id": "old", "source_campaign_id": "C0010"}]}),
        encoding="utf-8",
    )

    assert module.load_legacy_inventory(None) == ({}, None)
    mappings, digest = module.load_legacy_inventory(inventory)
    assert mappings == {"old": "C0010"}
    assert digest == module.hashlib.sha256(inventory.read_bytes()).hexdigest()


def test_corpus_coverage_rejects_omitted_plan(tmp_path: Path, monkeypatch) -> None:
    module = _load_module()
    monkeypatch.setattr(
        module,
        "load_procedural_plan",
        lambda path: SimpleNamespace(campaign_id="C9999", content_sha256="source", steps=[1]),
    )
    with pytest.raises(ValueError, match="omits corpus plan C9999"):
        module.audit_corpus_coverage([], {"C9999": tmp_path / "missing.json"})


def test_trusted_coverage_uses_exact_ids_and_counts_repeated_steps(tmp_path, monkeypatch):
    module = _load_module()
    catalog = tmp_path / "catalog.json"
    catalog.write_text(json.dumps({"templates": [{"technique_ids": ["T1105"]}]}))
    monkeypatch.setattr(
        module,
        "load_procedural_plan",
        lambda path: SimpleNamespace(
            steps=[
                SimpleNamespace(technique_id="T1105"),
                SimpleNamespace(technique_id="T1105"),
                SimpleNamespace(technique_id="T1105.001"),
            ]
        ),
    )

    digest, rows = module.trusted_catalog_coverage({"new-study": tmp_path}, catalog)

    assert digest == module.hashlib.sha256(catalog.read_bytes()).hexdigest()
    assert rows[0].source_campaign_id == "new-study"
    assert rows[0].source_steps == 3
    assert rows[0].covered_steps == 2
    assert rows[0].uncovered_technique_ids == ("T1105.001",)
