#!/usr/bin/env python3
"""Render LaTeX macros for the policy ablation, longitudinal, validation and consequence studies.

Every value is read from a recorded result file; none is typed by hand. The output
is the single file the manuscript inputs for these four studies.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

PROJECT_ROOT = Path(__file__).resolve().parents[1]
RESULTS = PROJECT_ROOT / "measurement" / "sut" / "scripts" / "results"
CONSEQUENCE_RUNS = PROJECT_ROOT / "release" / "experiments" / "consequence_study" / "runs"
CONSEQUENCE_PLAN = PROJECT_ROOT / "release/inputs/sticks/c0045-v1/C0045.procedural-plan.json"
CONSEQUENCE_CONTRACT = PROJECT_ROOT / "release/plans/C0045.verified-executable-contract.json"
PAPER_RUN_SELECTION = json.loads(
    (CONSEQUENCE_RUNS.parent / "paper_run.json").read_text(encoding="utf-8")
)
DEFAULT_OUTPUT = PROJECT_ROOT / "release" / "review_evidence_macros.tex"
DIGIT_WORDS = {"0": "zero", "1": "one", "2": "two", "3": "three", "4": "four",
               "5": "five", "6": "six", "7": "seven", "8": "eight", "9": "nine"}


class RecordedStep(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    step_index: int
    technique_id: str
    executed_with_evidence: bool
    status: str


class PaperRunSelection(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    run_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]*$")
    experimental_unit: Literal["C0045"]
    repetitions: int = Field(ge=2)
    runs_path: str | None = None
    plan_path: str | None = None
    contract_path: str | None = None
    implementation_revision: str | None = None


def _selected_path(relative: str | None, default: Path) -> Path:
    if relative is None:
        return default
    path = Path(relative)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        raise ValueError(f"unsafe paper evidence path: {relative}")
    selected = (PROJECT_ROOT / path).resolve()
    if not selected.is_relative_to(PROJECT_ROOT.resolve()):
        raise ValueError(f"paper evidence path escapes the package: {relative}")
    return selected


class RecordedArm(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    arm: str
    repetition: int
    environment_build_success: bool
    procedure_started: bool
    executed_with_evidence_count: int
    total_steps: int
    procedure_completed: bool
    failure_step_index: int | None
    failure_technique_id: str | None
    teardown_clean: bool
    steps: list[RecordedStep]
    execution_semantic_sha256: str


class ExecutionStep(BaseModel):
    """Fields required to bind a summary to its execution record."""

    technique_id: str
    status: str
    evidence_files: list[str]


class ExecutionManifest(BaseModel):
    campaign_id: Literal["0.shadowray"]
    teardown_clean: Literal[True]
    techniques: list[ExecutionStep]


class ExecutionState(BaseModel):
    campaign_id: Literal["0.shadowray"]
    source_plan_sha256: str
    executable_contract_sha256: str
    transitions: list[ExecutionStep]


def _checked_input(path: Path) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8"))
    content = {key: value for key, value in payload.items() if key != "content_sha256"}
    actual = hashlib.sha256(
        json.dumps(content, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    if payload["content_sha256"] != actual:
        raise ValueError(f"consequence input content hash mismatch: {path}")
    return payload


def _check_evidence_files(folder: Path, steps: list[ExecutionStep]) -> None:
    for step in steps:
        for reference in step.evidence_files:
            relative = Path(reference)
            path = (folder / relative).resolve()
            if relative.is_absolute() or ".." in relative.parts or not path.is_relative_to(folder.resolve()):
                raise ValueError("consequence evidence path escapes arm directory")
            if not path.is_file():
                raise FileNotFoundError(f"consequence evidence file is missing: {path}")


def _check_execution_binding(folder: Path, record: RecordedArm, plan: dict, contract: dict) -> None:
    manifest = ExecutionManifest.model_validate_json((folder / "manifest.json").read_bytes())
    state = ExecutionState.model_validate_json((folder / "campaign_state.json").read_bytes())
    if (state.source_plan_sha256, state.executable_contract_sha256) != (
        plan["content_sha256"], contract["content_sha256"],
    ):
        raise ValueError(f"consequence input binding mismatch: {folder}")
    expected = [step["technique_id"] for step in contract["transitions"]]
    if [step.technique_id for step in manifest.techniques] != expected:
        raise ValueError(f"consequence manifest/contract sequence mismatch: {folder}")
    if manifest.techniques != state.transitions:
        raise ValueError(f"consequence manifest/state mismatch: {folder}")
    for step, execution in zip(record.steps, manifest.techniques, strict=True):
        if (step.technique_id, step.status, step.executed_with_evidence) != (
            execution.technique_id, execution.status,
            execution.status == "success" and bool(execution.evidence_files),
        ):
            raise ValueError(f"consequence outcome/manifest mismatch: {folder}")
    _check_evidence_files(folder, manifest.techniques)


def _checked_arm(path: Path, arm_name: str, repetition: int) -> RecordedArm:
    record = RecordedArm.model_validate_json(path.read_text(encoding="utf-8"))
    if (record.arm, record.repetition) != (arm_name, repetition):
        raise ValueError(f"consequence arm identity mismatch: {path}")
    if not record.environment_build_success or not record.procedure_started or not record.teardown_clean:
        raise ValueError(f"consequence arm did not complete its laboratory boundary: {path}")
    if len(record.steps) != record.total_steps:
        raise ValueError(f"consequence step total mismatch: {path}")
    if any(step.step_index != index for index, step in enumerate(record.steps)):
        raise ValueError(f"consequence step order mismatch: {path}")
    if any(step.executed_with_evidence and step.status != "success" for step in record.steps):
        raise ValueError(f"consequence success/evidence mismatch: {path}")
    if sum(step.executed_with_evidence for step in record.steps) != record.executed_with_evidence_count:
        raise ValueError(f"consequence executed count mismatch: {path}")
    first_failure = next((step for step in record.steps if not step.executed_with_evidence), None)
    if (record.failure_step_index, record.failure_technique_id) != (
        first_failure.step_index if first_failure else None,
        first_failure.technique_id if first_failure else None,
    ):
        raise ValueError(f"consequence failure location mismatch: {path}")
    if record.procedure_completed != (first_failure is None):
        raise ValueError(f"consequence completion mismatch: {path}")
    semantic = [{"technique_id": step.technique_id, "status": step.status} for step in record.steps]
    expected_hash = hashlib.sha256(json.dumps(semantic, sort_keys=True).encode("utf-8")).hexdigest()
    if record.execution_semantic_sha256 != expected_hash:
        raise ValueError(f"consequence semantic hash mismatch: {path}")
    return record


def _selected_comparison() -> tuple[dict, int]:
    selection = PaperRunSelection.model_validate(PAPER_RUN_SELECTION)
    run = _selected_path(selection.runs_path, CONSEQUENCE_RUNS) / selection.run_id
    repetitions = selection.repetitions
    arms = {
        arm_name: [
            _checked_arm(run / f"{arm_name}-rep{repetition}" / "arm-outcome.json", arm_name, repetition)
            for repetition in range(1, repetitions + 1)
        ]
        for arm_name in ("ray_reachable", "ray_guarded")
    }
    procedure_sequences = {
        tuple(step.technique_id for step in record.steps)
        for records in arms.values()
        for record in records
    }
    if len(procedure_sequences) != 1:
        raise ValueError("consequence arms use different procedures")
    if any(len({record.execution_semantic_sha256 for record in records}) != 1 for records in arms.values()):
        raise ValueError("consequence repetitions disagree")
    plan = _checked_input(_selected_path(selection.plan_path, CONSEQUENCE_PLAN))
    contract = _checked_input(_selected_path(selection.contract_path, CONSEQUENCE_CONTRACT))
    if contract["source_plan_sha256"] != plan["content_sha256"]:
        raise ValueError("consequence contract/plan binding mismatch")
    for arm_name, records in arms.items():
        for record in records:
            folder = run / f"{arm_name}-rep{record.repetition}"
            _check_execution_binding(folder, record, plan, contract)
            if selection.implementation_revision is not None:
                provenance = json.loads((folder / "provenance.json").read_text(encoding="utf-8"))
                if provenance.get("implementation_revision") != selection.implementation_revision:
                    raise ValueError(f"consequence implementation revision mismatch: {folder}")
    reachable = arms["ray_reachable"][0]
    guarded = arms["ray_guarded"][0]
    expected = {
        "experimental_unit": selection.experimental_unit,
        "reachable_executed_steps": reachable.executed_with_evidence_count,
        "guarded_executed_steps": guarded.executed_with_evidence_count,
        "executed_step_delta": reachable.executed_with_evidence_count - guarded.executed_with_evidence_count,
        "guarded_failure_technique_id": guarded.failure_technique_id,
        "guarded_stops_at_vulnerability_dependent_step": guarded.failure_technique_id == "T1190",
        "reachable_repetitions_agree": True,
        "guarded_repetitions_agree": True,
        "consequence_observed": reachable.executed_with_evidence_count != guarded.executed_with_evidence_count,
    }
    comparison = json.loads((run / "comparison.json").read_text(encoding="utf-8"))
    if comparison != expected:
        raise ValueError("consequence comparison differs from recorded arm outcomes")
    return comparison, repetitions


def macro_name(*parts: str) -> str:
    """Join parts into a letters-only LaTeX command name."""
    words = []
    for part in parts:
        for character in part.replace(".", " ").replace("_", " ").replace("-", " "):
            words.append(DIGIT_WORDS.get(character, character))
    return "".join(character for character in "".join(words) if character.isalpha())


def ablation_macros() -> dict[str, str]:
    report = json.loads((RESULTS / "compatibility_policy_ablation.json").read_text())
    macros = {}
    for row in report["distributions"]:
        for label in ("cf", "vmr", "id", "unresolved"):
            macros[macro_name("ablation", row["policy"], label, "count")] = str(row[f"{label}_count"])
        macros[macro_name("ablation", row["policy"], "cf", "pct")] = f"{100 * row['cf_count'] / row['total']:.1f}"
    macros["ablationRobustConclusions"] = str(sum(check["robust"] for check in report["conclusions"]))
    macros["ablationDeclaredConclusions"] = str(len(report["conclusions"]))
    return macros


def longitudinal_macros() -> dict[str, str]:
    releases = json.loads((RESULTS / "longitudinal_gap.json").read_text())["releases"]
    first, last = releases[0], releases[-1]
    version_values = [row["software_with_version_pct"] for row in releases]
    return {
        "longitudinalReleaseCount": str(len(releases)),
        "longitudinalFirstRelease": first["release"],
        "longitudinalLastRelease": last["release"],
        "longitudinalFirstTechniques": str(first["active_techniques"]),
        "longitudinalLastTechniques": str(last["active_techniques"]),
        "longitudinalFirstSoftware": str(first["software_objects"]),
        "longitudinalLastSoftware": str(last["software_objects"]),
        "longitudinalVersionMinPct": f"{min(version_values):.1f}",
        "longitudinalVersionMaxPct": f"{max(version_values):.1f}",
        "longitudinalCpeMaxPct": f"{max(row['software_with_cpe_pct'] for row in releases):.1f}",
        "longitudinalFirstFallbackPct": f"{first['fallback_pct']:.1f}",
        "longitudinalLastFallbackPct": f"{last['fallback_pct']:.1f}",
    }


def nvd_enrichment_macros() -> dict[str, str]:
    report = json.loads((RESULTS / "nvd_enrichment.json").read_text())
    counts = {row["dimension"]: row for row in report["dimensions"]}
    shadowray = next(row for row in report["rows"] if row["cve_id"] == "CVE-2023-48022")
    return {
        "nvdCveCount": str(report["cves"]),
        "nvdProductCti": str(counts["vulnerable product named"]["structured_cti"]),
        "nvdProductEnriched": str(counts["vulnerable product named"]["cti_plus_nvd"]),
        "nvdSingleProduct": str(counts["single vulnerable product"]["cti_plus_nvd"]),
        "nvdVersionBounded": str(counts["version bounded"]["cti_plus_nvd"]),
        "nvdExposureCti": str(counts["network exposure"]["structured_cti"]),
        "nvdExposureEnriched": str(counts["network exposure"]["cti_plus_nvd"]),
        "nvdPrivilegeEnriched": str(counts["privilege the exploit assumes"]["cti_plus_nvd"]),
        "nvdUniqueDeployment": str(report["unique_deployment_after_nvd"]),
        "nvdMedianMatches": f"{report['median_vulnerable_matches']:.0f}",
        "nvdShadowRayPrivilege": shadowray["privileges_required"].lower(),
    }


def validation_macros() -> dict[str, str]:
    report = json.loads((RESULTS / "compatibility_judge_validation.json").read_text())
    consensus = report["autosut_vs_consensus"]
    estimate = report["population_estimate_pct"]
    return {
        "judgeSampleSize": str(report["sample_size"]),
        "judgeAgreementPct": f"{100 * report['inter_judge']['agreement']:.1f}",
        "judgeKappa": f"{report['inter_judge']['cohen_kappa']:.2f}",
        "judgeBoundaryItems": str(report["boundary_items"]),
        "judgeConsensusItems": str(consensus["all"]["items"]),
        "judgeAccuracyAll": f"{consensus['all']['accuracy']:.2f}",
        "judgeMacroFAll": f"{consensus['all']['macro_f1']:.2f}",
        "judgeAccuracyRule": f"{consensus['explicit_rule_strata']['accuracy']:.2f}",
        "judgeMacroFRule": f"{consensus['explicit_rule_strata']['macro_f1']:.2f}",
        "judgeAccuracyFallback": f"{consensus['fallback_stratum']['accuracy']:.2f}",
        "judgeFallbackItems": str(consensus["fallback_stratum"]["items"]),
        "judgeCfPrecision": f"{consensus['all']['per_class']['CF']['precision']:.2f}",
        "judgeCfRecall": f"{consensus['all']['per_class']['CF']['recall']:.2f}",
        "judgePopulationCfPct": f"{estimate['CF']:.1f}",
        "judgePopulationVmrPct": f"{estimate['VMR']:.1f}",
        "judgePopulationIdPct": f"{estimate['ID']:.1f}",
        "judgePopulationBoundaryPct": f"{estimate['boundary']:.1f}",
        "judgePopulationCfUpperPct": f"{estimate['CF'] + estimate['boundary']:.1f}",
    }


def consequence_macros() -> dict[str, str]:
    comparison, repetitions = _selected_comparison()
    return {
        "consequenceReachableSteps": str(comparison["reachable_executed_steps"]),
        "consequenceGuardedSteps": str(comparison["guarded_executed_steps"]),
        "consequenceStepDelta": str(comparison["executed_step_delta"]),
        "consequenceGuardedStop": comparison["guarded_failure_technique_id"],
        "consequenceRepetitions": str(repetitions),
    }


def longitudinal_table_rows() -> str:
    """One table row per release: techniques, software, version and CPE shares, campaigns, fallback."""
    rows = []
    for release in json.loads((RESULTS / "longitudinal_gap.json").read_text())["releases"]:
        campaigns = str(release["usable_campaigns"]) if release["usable_campaigns"] else "--"
        rows.append(
            f"{release['release']} & {release['active_techniques']} & {release['software_objects']} & "
            f"{release['software_with_version_pct']:.1f} & {release['software_with_cpe_pct']:.1f} & "
            f"{campaigns} & {release['cf_pct']:.1f} & {release['fallback_pct']:.1f} \\\\"
        )
    return "\n".join(rows)


def render(macros: dict[str, str], longitudinal_rows: str) -> str:
    lines = ["% Generated by scripts/render_review_evidence_macros.py from recorded results."]
    lines += [f"\\newcommand{{\\{name}}}{{{value}}}" for name, value in sorted(macros.items())]
    lines.append(f"\\newcommand{{\\longitudinalRows}}{{%\n{longitudinal_rows}}}")
    return "\n".join(lines) + "\n"


def check_output(path: Path) -> int:
    macros = {**ablation_macros(), **longitudinal_macros(), **validation_macros(), **consequence_macros(), **nvd_enrichment_macros()}
    expected = render(macros, longitudinal_table_rows())
    if path.read_text(encoding="utf-8") != expected:
        raise ValueError(f"review evidence macros are out of date: {path}")
    return len(macros)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--check", action="store_true", help="verify the published macros without rewriting them")
    args = parser.parse_args()
    if args.check:
        count = check_output(args.output)
        print(f"[review-evidence] verified {count} macros in {args.output}")
        return 0
    macros = {**ablation_macros(), **longitudinal_macros(), **validation_macros(), **consequence_macros(), **nvd_enrichment_macros()}
    args.output.write_text(render(macros, longitudinal_table_rows()), encoding="utf-8")
    print(f"[review-evidence] wrote {len(macros)} macros to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
