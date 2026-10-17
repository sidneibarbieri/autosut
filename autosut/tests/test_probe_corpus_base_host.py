"""Base-host probes must reject resources they do not provision."""

import importlib.util
import json
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from planning.sut_blueprint import BACKEND_RECIPES, BlueprintHost, SUTBlueprint
from planning.sut_constraints import (
    EnvironmentRequirement,
    PlatformResolution,
    RequirementSource,
    SUTConstraintSet,
)


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/probe_corpus_base_host.py"
SPEC = importlib.util.spec_from_file_location("probe_corpus_base_host", SCRIPT)
probe_module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = probe_module
SPEC.loader.exec_module(probe_module)


def _corpus(tmp_path: Path, *, extra_resource: bool = False) -> Path:
    campaign_id = "C9999"
    requirements = []
    if extra_resource:
        requirements.append(EnvironmentRequirement(
            requirement_id="T1005.data",
            kind="data",
            acceptable_values=["declared-decoy-data"],
            technique_ids=["T1005"],
            source=RequirementSource.curated_rule,
            rationale="synthetic fixture",
        ))
    constraints = SUTConstraintSet(
        campaign_id=campaign_id,
        source_plan_sha256="0" * 64,
        platform_resolution=PlatformResolution(
            selected_platforms=["Linux"],
            materializable_platforms=["Linux"],
            unsupported_platforms=[],
            uncovered_technique_ids=[],
            complete=True,
        ),
        requirements=requirements,
    )
    constraints.finalize_hash()
    blueprint = SUTBlueprint(
        campaign_id=campaign_id,
        source_constraint_sha256=constraints.content_sha256,
        hosts=[BlueprintHost(
            host_id="target-1", role="target", platform="Linux",
            recipe=BACKEND_RECIPES["Linux"],
        )],
        concretized_requirements=requirements,
    )
    blueprint.finalize_hash()
    folder = tmp_path / campaign_id
    folder.mkdir()
    (folder / "constraints.json").write_text(constraints.model_dump_json())
    (folder / "sut-blueprint.json").write_text(blueprint.model_dump_json())
    (tmp_path / "manifest.json").write_text(json.dumps({"records": [{
        "campaign_id": campaign_id,
        "status": "blueprint_generated",
        "blueprint_sha256": blueprint.content_sha256,
    }]}))
    return tmp_path


def test_plain_linux_base_host_is_admissible(tmp_path: Path) -> None:
    corpus = _corpus(tmp_path)
    blueprint, file_hash = probe_module._checked_host(corpus, "C9999")

    assert blueprint.campaign_id == "C9999"
    assert len(file_hash) == 64


def test_unprovisioned_resource_is_rejected(tmp_path: Path) -> None:
    corpus = _corpus(tmp_path, extra_resource=True)

    with pytest.raises(ValueError, match="cannot satisfy nonplatform resources"):
        probe_module._checked_host(corpus, "C9999")


def test_manifest_substitution_is_rejected(tmp_path: Path) -> None:
    corpus = _corpus(tmp_path)
    manifest_path = corpus / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["records"][0]["blueprint_sha256"] = "0" * 64
    manifest_path.write_text(json.dumps(manifest))

    with pytest.raises(ValueError, match="differs from corpus manifest"):
        probe_module._checked_host(corpus, "C9999")
