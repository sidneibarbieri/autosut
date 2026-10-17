"""Check that preparation preserves all independent admission blockers."""

import hashlib
import json
import sys
from pathlib import Path

import pytest
from planning.campaign_pair import (
    prepare_campaign_pair,
    unsupported_procedure_platforms,
)
from pydantic import ValidationError

ARTIFACT_ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    ("unsupported_platform", "has_contract", "expected_reasons"),
    [
        (
            True, False,
            ("unsupported_platform_requirements", "missing_execution_contract"),
        ),
        (True, True, ("unsupported_platform_requirements",)),
        (False, False, ("missing_execution_contract",)),
    ],
)
def test_preparation_reports_independent_blockers(
    tmp_path, unsupported_platform, has_contract, expected_reasons
):
    original = ARTIFACT_ROOT / "release/prepared-pairs/0.c0010/procedural-plan.json"
    payload = json.loads(original.read_text(encoding="utf-8"))
    if unsupported_platform:
        payload["steps"][0]["execution_domain"] = "target"
        payload["steps"][0]["platforms"] = ["Windows"]
    payload.pop("content_sha256")
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    payload["content_sha256"] = hashlib.sha256(encoded).hexdigest()
    source_path = tmp_path / "plan.json"
    source_path.write_text(json.dumps(payload), encoding="utf-8")
    spec = {"campaign_id": "0.c0010", "source_campaign_id": "C0010"}
    if has_contract:
        spec["execution_contract"] = {"techniques": []}
    spec_path = tmp_path / "campaign.json"
    spec_path.write_text(json.dumps(spec), encoding="utf-8")
    output = tmp_path / "prepared"

    result = prepare_campaign_pair(
        campaign_path=spec_path,
        plan_path=source_path,
        sticks_root=tmp_path / "unused-compiler",
        output_dir=output,
        python_executable=sys.executable,
        source_campaign_id="C0010",
    )

    assert result.status == "blocked"
    assert result.execution_status == "not_run"
    assert result.reasons == expected_reasons
    assert json.loads((output / "pair.json").read_text())["reasons"] == list(expected_reasons)
    assert (output / "procedural-plan.json").read_bytes() == source_path.read_bytes()
    assert not (output / "executable-contract.json").exists()


def test_declared_windows_procedure_is_not_admitted_by_linux_cti_alternative(tmp_path):
    source = ARTIFACT_ROOT / "release/prepared-pairs/0.c0010/procedural-plan.json"
    spec = {
        "campaign_id": "0.c0010",
        "source_campaign_id": "C0010",
        "techniques": [{"technique_id": "T1105", "platform": "windows"}],
    }
    specification = tmp_path / "campaign.json"
    specification.write_text(json.dumps(spec), encoding="utf-8")

    result = prepare_campaign_pair(
        campaign_path=specification,
        plan_path=source,
        sticks_root=tmp_path / "unused-compiler",
        output_dir=tmp_path / "prepared",
        python_executable=sys.executable,
        source_campaign_id="C0010",
    )

    assert result.status == "blocked"
    assert result.reasons == (
        "unsupported_procedure_platform_requirements", "missing_execution_contract"
    )
    assert result.unsupported_procedure_technique_ids == ("T1105",)


@pytest.mark.parametrize(
    ("platform", "expected"),
    [("LiNuX", ()), ("any", ()), ("windows", ("T1105",)), ("unknown-os", ("T1105",))],
)
def test_explicit_procedure_platforms_fail_closed(platform, expected):
    specification = {"techniques": [{"technique_id": "T1105", "platform": platform}]}
    assert unsupported_procedure_platforms(specification, {"Linux"}) == expected


def test_null_procedure_platform_is_not_treated_as_unspecified():
    with pytest.raises(ValidationError):
        unsupported_procedure_platforms(
            {"techniques": [{"technique_id": "T1105", "platform": None}]}, {"Linux"}
        )
