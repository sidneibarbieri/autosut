"""Validate the bounded public Caldera dispatch witness without running infrastructure.

The validator checks a sealed, released observation.  It does not launch Docker,
Caldera, an agent, or an SUT, and it does not promote the observation to a
campaign-wide or current-revision claim.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Literal

from pydantic import Field, ValidationError

from evaluation.operational_collection import OperationalCollectionProtocol
from evaluation.operational_metrics import (
    CellStatus,
    EvidenceReference,
    OperationalLedger,
    StrictModel,
)
from infrastructure.run_context import RunManifest
from infrastructure.supervision_evidence import (
    SupervisionEvidenceError,
    SupervisionReceipt,
    verify_qualified_bundle,
)

CANONICAL_COLLECTION_RELATIVE = Path("release/experiments/operational_qualification/2026-09-05-r6")
CANONICAL_ENVIRONMENT_ID = "shadowray-single-host-surrogate"
CANONICAL_ASSET_ID = "ray-command-effect"
CANONICAL_EXPERIMENT = "caldera"


class WitnessValidationError(ValueError):
    """The released witness violates its declared evidence contract."""


class CalderaDispatchWitness(StrictModel):
    """The exact bounded observation used for the public dispatch claim."""

    schema_version: Literal["autosut-canonical-caldera-dispatch-witness/v1"] = (
        "autosut-canonical-caldera-dispatch-witness/v1"
    )
    collection_relative_path: str = Field(min_length=1)
    implementation_revision: str = Field(min_length=1)
    protocol_content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    plan_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    bundle_relative_path: str = Field(min_length=1)
    receipt_relative_path: str = Field(min_length=1)
    campaign_id: str = Field(min_length=1)
    source_campaign_id: str = Field(min_length=1)
    operation_link_count: int = Field(ge=1)
    realization: Literal["surrogate"]


class CalderaDispatchWitnessAssessment(StrictModel):
    """A fail-closed assessment of the released witness."""

    schema_version: Literal["autosut-canonical-witness-assessment/v1"] = (
        "autosut-canonical-witness-assessment/v1"
    )
    status: Literal["supported_bounded", "blocked_missing_evidence", "blocked_execution_gate"]
    evidence_artifacts: tuple[str, ...] = ()
    witness: CalderaDispatchWitness | None = None
    failure_reason: str | None = None


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _safe_project_path(project_root: Path, relative_path: Path) -> Path:
    if relative_path.is_absolute() or ".." in relative_path.parts:
        raise WitnessValidationError("evidence path is not a safe project-relative path")
    candidate = (project_root / relative_path).resolve()
    try:
        candidate.relative_to(project_root.resolve())
    except ValueError as error:
        raise WitnessValidationError("evidence path escapes the project root") from error
    return candidate


def _json_object(path: Path) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise WitnessValidationError(f"JSON document must be an object: {path.name}")
    return payload


def _base_evidence_artifacts() -> tuple[str, ...]:
    return tuple(
        (CANONICAL_COLLECTION_RELATIVE / name).as_posix()
        for name in ("protocol.json", "ledger.json", "manifest.json")
    )


def _verify_collection_manifest(collection_dir: Path) -> None:
    manifest_path = collection_dir / "manifest.json"
    manifest = RunManifest.model_validate_json(manifest_path.read_text(encoding="utf-8"))
    if manifest.file_count != len(manifest.files):
        raise WitnessValidationError("collection manifest file_count does not match its entries")

    listed_paths: set[str] = set()
    observed_bytes = 0
    for entry in manifest.files:
        relative_path = Path(entry.path)
        if relative_path.is_absolute() or ".." in relative_path.parts:
            raise WitnessValidationError("collection manifest contains an unsafe path")
        path_key = relative_path.as_posix()
        if path_key in listed_paths:
            raise WitnessValidationError("collection manifest contains a duplicate path")
        listed_paths.add(path_key)
        candidate = collection_dir / relative_path
        if not candidate.is_file():
            raise WitnessValidationError(f"collection manifest file is missing: {path_key}")
        if candidate.stat().st_size != entry.bytes:
            raise WitnessValidationError(f"collection manifest byte count differs: {path_key}")
        if _sha256_file(candidate) != entry.sha256:
            raise WitnessValidationError(f"collection manifest hash differs: {path_key}")
        observed_bytes += entry.bytes

    if observed_bytes != manifest.total_bytes:
        raise WitnessValidationError("collection manifest total_bytes does not match its entries")

    actual_paths = {
        path.relative_to(collection_dir).as_posix()
        for path in collection_dir.rglob("*")
        if path.is_file() and path != manifest_path
    }
    if actual_paths != listed_paths:
        raise WitnessValidationError("collection manifest does not seal the exact file set")


def _single_matching_cell(ledger: OperationalLedger):
    cells = [cell for cell in ledger.cells if cell.environment_id == CANONICAL_ENVIRONMENT_ID]
    if len(cells) != 1:
        raise WitnessValidationError("canonical environment must have exactly one recorded cell")
    return cells[0]


def _single_binding(protocol: OperationalCollectionProtocol):
    bindings = [
        binding
        for binding in protocol.bindings
        if binding.environment_id == CANONICAL_ENVIRONMENT_ID
    ]
    if len(bindings) != 1:
        raise WitnessValidationError("canonical environment must have exactly one protocol binding")
    binding = bindings[0]
    if (
        binding.experiment != CANONICAL_EXPERIMENT
        or binding.critical_asset_id != CANONICAL_ASSET_ID
        or binding.effect_field != "independent_effect_confirmed"
    ):
        raise WitnessValidationError(
            "canonical protocol binding does not describe the dispatch witness"
        )
    return binding


def _single_receipt_reference(references: tuple[EvidenceReference, ...]) -> EvidenceReference:
    receipt_references = [
        reference
        for reference in references
        if "/receipts/" in reference.path and reference.path.endswith(".json")
    ]
    if len(receipt_references) != 1:
        raise WitnessValidationError("canonical cell must cite exactly one supervisor receipt")
    return receipt_references[0]


def _require_effect_evidence(bundle: Path, realization: str) -> dict:
    experiment = _json_object(bundle / "experiment.json")
    operation = experiment.get("operation")
    if not isinstance(operation, dict) or operation.get("operation_state") != "finished":
        raise WitnessValidationError("Caldera operation did not finish")
    links = operation.get("links")
    if not isinstance(links, list) or len(links) != 1:
        raise WitnessValidationError("bounded witness must record exactly one Caldera link")
    link = links[0]
    if not isinstance(link, dict) or link.get("status") != 0 or str(link.get("exit_code")) != "0":
        raise WitnessValidationError("Caldera link did not report successful completion")
    if experiment.get("independent_effect_confirmed") is not True:
        raise WitnessValidationError("independent effect confirmation is absent")
    if experiment.get("realization") != realization:
        raise WitnessValidationError("experiment realization differs from the declared witness")
    if experiment.get("confirmed_answering_service") != realization:
        raise WitnessValidationError("independent probe did not confirm the declared realization")

    operation_report = _json_object(bundle / "caldera" / "operation-report.json")
    steps = operation_report.get("steps")
    if not operation_report.get("name") or not isinstance(steps, (dict, list)) or not steps:
        raise WitnessValidationError("Caldera operation report is incomplete")

    effect_probe = _json_object(bundle / "scenario" / "effect-probe.json")
    if effect_probe.get("returncode") != 0:
        raise WitnessValidationError("effect probe did not exit successfully")
    if not effect_probe.get("expected_stdout") or (
        effect_probe.get("stdout") != effect_probe.get("expected_stdout")
    ):
        raise WitnessValidationError("effect probe output does not match its expected value")

    lifecycle = _json_object(bundle / "lifecycle-result.json")
    if lifecycle.get("final_state") != "clean":
        raise WitnessValidationError("lifecycle did not reach a clean terminal state")
    residual = lifecycle.get("residual")
    if not isinstance(residual, dict) or residual.get("residual_resources") != []:
        raise WitnessValidationError("lifecycle recorded residual resources")
    return operation


def _require_campaign_binding(bundle: Path) -> tuple[str, str, tuple[Path, Path]]:
    """Return the sealed campaign and SUT identifiers for the witness bundle."""
    contract_path = bundle / "scenario" / "contract.json"
    catalog_path = bundle / "scenario" / "binding-catalog.json"
    contract = _json_object(contract_path)
    catalog = _json_object(catalog_path)
    campaign_id = contract.get("campaign_id")
    source_campaign_id = contract.get("source_campaign_id")
    if not isinstance(campaign_id, str) or not campaign_id:
        raise WitnessValidationError("witness contract lacks a campaign identifier")
    if not isinstance(source_campaign_id, str) or not source_campaign_id:
        raise WitnessValidationError("witness contract lacks a source campaign identifier")
    if catalog.get("sut_id") != campaign_id:
        raise WitnessValidationError("witness contract and SUT binding describe different pairs")
    return campaign_id, source_campaign_id, (contract_path, catalog_path)


def _assessment(project_root: Path) -> CalderaDispatchWitnessAssessment:
    collection_dir = _safe_project_path(project_root, CANONICAL_COLLECTION_RELATIVE)
    required_paths = (
        collection_dir / "protocol.json",
        collection_dir / "ledger.json",
        collection_dir / "manifest.json",
    )
    missing = [
        path.relative_to(project_root).as_posix() for path in required_paths if not path.is_file()
    ]
    if missing:
        return CalderaDispatchWitnessAssessment(
            status="blocked_missing_evidence",
            evidence_artifacts=_base_evidence_artifacts(),
            failure_reason="missing required evidence: " + ", ".join(missing),
        )

    try:
        _verify_collection_manifest(collection_dir)
        protocol_path = collection_dir / "protocol.json"
        ledger_path = collection_dir / "ledger.json"
        protocol = OperationalCollectionProtocol.model_validate_json(
            protocol_path.read_text(encoding="utf-8")
        )
        ledger = OperationalLedger.model_validate_json(ledger_path.read_text(encoding="utf-8"))
        if protocol.plan.content_sha256 != ledger.plan.content_sha256:
            raise WitnessValidationError("protocol and ledger name different frozen plans")
        if protocol.plan.implementation_revision != ledger.plan.implementation_revision:
            raise WitnessValidationError(
                "protocol and ledger name different implementation revisions"
            )
        ledger.verify_evidence(project_root)

        binding = _single_binding(protocol)
        cell = _single_matching_cell(ledger)
        if cell.plan_sha256 != protocol.plan.content_sha256:
            raise WitnessValidationError("canonical cell is not bound to the frozen protocol plan")
        if cell.status is not CellStatus.COMPLETED:
            raise WitnessValidationError("canonical cell is not completed")
        if not cell.lifecycle_qualified or not cell.clean_teardown:
            raise WitnessValidationError("canonical cell lacks qualified clean lifecycle evidence")

        acquisitions = [
            acquisition
            for acquisition in cell.acquisitions
            if acquisition.asset_id == binding.critical_asset_id
        ]
        if len(acquisitions) != 1 or not acquisitions[0].effect_verified:
            raise WitnessValidationError(
                "canonical cell lacks a verified critical-asset acquisition"
            )

        receipt_reference = _single_receipt_reference(cell.terminal_evidence)
        receipt_path = _safe_project_path(project_root, Path(receipt_reference.path))
        receipt = SupervisionReceipt.model_validate_json(receipt_path.read_text(encoding="utf-8"))
        if receipt.handoff is None:
            raise WitnessValidationError("canonical supervisor receipt lacks a child handoff")
        bundle_relative = Path(receipt.handoff.bundle_relative_path)
        bundle = _safe_project_path(project_root, bundle_relative)
        try:
            bundle.relative_to(collection_dir)
        except ValueError as error:
            raise WitnessValidationError("canonical bundle lies outside the collection") from error
        verify_qualified_bundle(
            project_root=project_root,
            bundle=bundle,
            expected_experiment=CANONICAL_EXPERIMENT,
        )

        realization = "surrogate"
        operation = _require_effect_evidence(bundle, realization)
        campaign_id, source_campaign_id, binding_paths = _require_campaign_binding(bundle)
        lifecycle = _json_object(bundle / "lifecycle-result.json")
        if lifecycle.get("implementation_revision") != protocol.plan.implementation_revision:
            raise WitnessValidationError("lifecycle revision differs from the frozen protocol")

        evidence_paths = (
            collection_dir / "protocol.json",
            collection_dir / "ledger.json",
            collection_dir / "manifest.json",
            receipt_path,
            bundle / "manifest.json",
            bundle / "experiment.json",
            bundle / "lifecycle-result.json",
            *binding_paths,
            bundle / "scenario" / "effect-probe.json",
            bundle / "verify-clean.json",
            bundle / "caldera" / "operation-report.json",
        )
        evidence_artifacts = tuple(
            path.relative_to(project_root).as_posix() for path in evidence_paths
        )
        return CalderaDispatchWitnessAssessment(
            status="supported_bounded",
            evidence_artifacts=evidence_artifacts,
            witness=CalderaDispatchWitness(
                collection_relative_path=CANONICAL_COLLECTION_RELATIVE.as_posix(),
                implementation_revision=protocol.plan.implementation_revision,
                protocol_content_sha256=protocol.content_sha256,
                plan_sha256=protocol.plan.content_sha256,
                bundle_relative_path=bundle_relative.as_posix(),
                receipt_relative_path=receipt_reference.path,
                campaign_id=campaign_id,
                source_campaign_id=source_campaign_id,
                operation_link_count=len(operation["links"]),
                realization=realization,
            ),
        )
    except FileNotFoundError as error:
        return CalderaDispatchWitnessAssessment(
            status="blocked_missing_evidence",
            evidence_artifacts=_base_evidence_artifacts(),
            failure_reason=f"missing required evidence: {error.filename}",
        )
    except (
        json.JSONDecodeError,
        ValidationError,
        SupervisionEvidenceError,
        WitnessValidationError,
    ) as error:
        return CalderaDispatchWitnessAssessment(
            status="blocked_execution_gate",
            evidence_artifacts=_base_evidence_artifacts(),
            failure_reason=str(error),
        )


def assess_caldera_dispatch_witness(project_root: Path) -> CalderaDispatchWitnessAssessment:
    """Assess the released witness using only static, hash-bound evidence."""
    return _assessment(project_root.resolve())
