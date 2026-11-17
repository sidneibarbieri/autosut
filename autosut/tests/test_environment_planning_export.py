"""First-use planning exports preserve provenance and never imply execution."""

from __future__ import annotations
import json
import subprocess
import sys
from pathlib import Path
import hashlib

ROOT = Path(__file__).resolve().parents[1]
PLAN = ROOT / "release/inputs/sticks/c0045-v1/C0045.procedural-plan.json"


def invoke(*arguments: str, cwd: Path):
    return subprocess.run(
        [sys.executable, str(ROOT / "scripts/emulate.py"), *arguments],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_cli_exports_constraints_with_verified_source_and_execution_boundary(tmp_path):
    output = tmp_path / "planning.json"
    result = invoke(str(PLAN), "--output", str(output), cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    payload = json.loads(output.read_text())
    source = json.loads(PLAN.read_text())
    assert payload["schema_version"] == "autosut-environment-planning/v1"
    assert payload["operational_status"] == "not_run"
    assert payload["plan"]["content_sha256"] == source["content_sha256"]
    assert payload["constraints"]["source_plan_sha256"] == source["content_sha256"]
    assert payload["constraints"]["platform_resolution"]["selected_platforms"] == [
        "Linux"
    ]
    assert {
        requirement["source"] for requirement in payload["constraints"]["requirements"]
    } >= {"stix_field", "curated_rule"}


def test_modified_input_is_rejected_without_output(tmp_path):
    source = json.loads(PLAN.read_text())
    source["campaign_name"] = "altered input without a new hash"
    changed = tmp_path / "changed.json"
    changed.write_text(json.dumps(source))
    output = tmp_path / "planning.json"
    result = invoke(str(changed), "--output", str(output), cwd=tmp_path)
    assert result.returncode != 0
    assert "hash mismatch" in result.stderr
    assert not output.exists()


def test_existing_output_is_preserved(tmp_path):
    output = tmp_path / "planning.json"
    output.write_text("preserve previous evidence")
    result = invoke(str(PLAN), "--output", str(output), cwd=tmp_path)
    assert result.returncode != 0
    assert output.read_text() == "preserve previous evidence"


def test_default_summary_remains_available(tmp_path):
    result = invoke(str(PLAN), cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    assert "CAMPAIGN C0045" in result.stdout
    assert "selected platforms:" in result.stdout


def test_export_uses_existing_constraint_resolver():
    from planning.environment_workbench import plan_environment
    from planning.procedural_plan import load_procedural_plan
    from planning.sut_constraints import resolve_sut_constraints

    result = plan_environment(PLAN)
    expected = resolve_sut_constraints(
        load_procedural_plan(PLAN), materializable_platforms={"Linux"}
    )
    assert result.constraints == expected


def test_unsupported_platforms_remain_explicit_in_export(tmp_path):
    source = json.loads(PLAN.read_text())
    for step in source["steps"]:
        step["platforms"] = ["Windows"]
    source.pop("content_sha256")
    encoded = json.dumps(source, sort_keys=True, separators=(",", ":")).encode()
    source["content_sha256"] = hashlib.sha256(encoded).hexdigest()
    plan = tmp_path / "windows-only-test-plan.json"
    plan.write_text(json.dumps(source))
    output = tmp_path / "planning.json"
    result = invoke(str(plan), "--output", str(output), cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    payload = json.loads(output.read_text())
    resolution = payload["constraints"]["platform_resolution"]
    assert resolution["complete"] is False
    assert resolution["uncovered_technique_ids"]
    assert payload["operational_status"] == "not_run"
