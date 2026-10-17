"""The declared R4 protocol must name actual, observable lifecycle stages."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = PROJECT_ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(PROJECT_ROOT / "src"))


def _caldera_module():
    spec = importlib.util.spec_from_file_location(
        "r4_caldera_experiment", SCRIPTS / "run_caldera_experiment.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_protocol_cells_name_actual_lifecycle_stages(tmp_path):
    module = _caldera_module()
    from infrastructure.run_context import RunContext

    context = RunContext.create(tmp_path, label="stage-contract")
    forward, teardown = module._build_stages(context, {"implementation_revision": "test"})
    actual = {stage.name for stage in forward + teardown}
    protocol = json.loads(
        (PROJECT_ROOT / "release" / "experiments" / "r4_interruption_matrix_protocol.json").read_text()
    )

    assert {cell["stage"] for cell in protocol["cells"]} <= actual
    assert "persist_execution_evidence" in actual
    assert "destroy_sut" in actual


def test_protocol_cells_are_unique_and_semantically_described():
    protocol = json.loads(
        (PROJECT_ROOT / "release" / "experiments" / "r4_interruption_matrix_protocol.json").read_text()
    )
    cells = protocol["cells"]
    assert len({cell["id"] for cell in cells}) == len(cells)
    assert all(cell["property"].strip() for cell in cells)


def test_v2_protocol_cells_name_emitted_semantic_boundaries():
    module = _caldera_module()
    protocol = json.loads(
        (
            PROJECT_ROOT
            / "release"
            / "experiments"
            / "r4_interruption_matrix_protocol_v2.json"
        ).read_text()
    )

    assert protocol["status"] == "predeclared_before_execution"
    assert protocol["execution_requirements"]["execution_mode"] == "supervised"
    assert protocol["execution_requirements"]["evidence_role"] == "qualification"
    assert protocol["execution_requirements"]["qualification_metadata_protocol_version"] == (
        "autosut-qualification/v1"
    )
    for cell in protocol["cells"]:
        assert cell["condition"] in module.SEMANTIC_BOUNDARY_CONDITIONS[cell["stage"]]


def test_draft_v2_protocol_cannot_start_a_qualification_attempt():
    driver_spec = importlib.util.spec_from_file_location(
        "run_interruption_matrix", SCRIPTS / "run_interruption_matrix.py"
    )
    assert driver_spec and driver_spec.loader
    driver = importlib.util.module_from_spec(driver_spec)
    sys.modules[driver_spec.name] = driver
    driver_spec.loader.exec_module(driver)
    protocol = json.loads(
        (
            PROJECT_ROOT
            / "release"
            / "experiments"
            / "r4_interruption_matrix_protocol_v2.json"
        ).read_text()
    )

    try:
        driver._v2_qualification_requirements(protocol, "a" * 40)
    except ValueError as error:
        assert "frozen" in str(error)
    else:
        raise AssertionError("a predeclared template must not launch a qualifying attempt")


def test_reviewer_docs_point_to_the_current_nonexecuted_v2_protocol():
    for name in ("README.md", "REVIEWER_GUIDE.md"):
        content = (PROJECT_ROOT / name).read_text(encoding="utf-8")
        assert "R4_INTERRUPTION_MATRIX_PROTOCOL_V2.md" in content
        assert "predeclared_nonexecuted" in content


def test_historical_r4_status_record_cannot_be_read_as_v2_qualification():
    record = json.loads(
        (
            PROJECT_ROOT / "release" / "experiments" / "R4_stage_termination_status.json"
        ).read_text()
    )

    assert record["record_role"] == "historical_development_status"
    assert record["superseded_for_qualification_by"]["qualification_result"] == "not_qualified"
    assert record["structured_matrix_prototype"]["protocol_role"] == (
        "historical_v1_development_protocol"
    )
