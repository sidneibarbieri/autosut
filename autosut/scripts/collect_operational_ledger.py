#!/usr/bin/env python3
"""Collect a frozen operational matrix serially through the canonical supervisor."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from evaluation.operational_collection import (  # noqa: E402
    CollectionBinding,
    OperationalCollectionProtocol,
)
from evaluation.operational_metrics import (  # noqa: E402
    AssetAcquisition,
    CellStatus,
    EvidenceReference,
    OperationalCell,
    OperationalLedger,
    ResourceAccounting,
)
from infrastructure.revision import current_revision  # noqa: E402
from infrastructure.supervision_evidence import (  # noqa: E402
    SupervisionEvidenceError,
    SupervisionReceipt,
    verify_qualified_bundle,
)

DRIVERS = {
    "caldera": PROJECT_ROOT / "scripts" / "run_caldera_experiment.py",
    "multihost": PROJECT_ROOT / "scripts" / "run_caldera_experiment_multihost.py",
}


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def evidence_reference(path: Path) -> EvidenceReference:
    relative = path.resolve().relative_to(PROJECT_ROOT.resolve()).as_posix()
    return EvidenceReference(path=relative, sha256=sha256_file(path))


def write_ledger(path: Path, ledger: OperationalLedger) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(ledger.model_dump_json(indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def portable_log_text(text: str) -> str:
    """Remove the checkout prefix while preserving command and process output."""
    return text.replace(str(PROJECT_ROOT.resolve()), ".")


def planned_ledger(protocol: OperationalCollectionProtocol) -> OperationalLedger:
    cells = tuple(
        OperationalCell(
            experiment_id=protocol.plan.experiment_id,
            plan_sha256=protocol.plan.content_sha256,
            arm=arm,
            environment_id=environment.environment_id,
            seed=seed,
            status=CellStatus.PLANNED,
        )
        for arm in protocol.plan.arms
        for environment in protocol.plan.environments
        for seed in protocol.plan.seeds
    )
    return OperationalLedger(plan=protocol.plan, cells=cells)


def replace_cell(ledger: OperationalLedger, completed: OperationalCell) -> OperationalLedger:
    key = (completed.arm, completed.environment_id, completed.seed)
    cells = tuple(
        completed if (cell.arm, cell.environment_id, cell.seed) == key else cell
        for cell in ledger.cells
    )
    return OperationalLedger(plan=ledger.plan, cells=cells)


def run_cell(
    protocol: OperationalCollectionProtocol,
    binding: CollectionBinding,
    seed: int,
    collection_dir: Path,
) -> OperationalCell:
    collection_dir = collection_dir.resolve()
    cell_id = f"{binding.arm}__{binding.environment_id}__s{seed}"
    receipt_path = collection_dir / "receipts" / f"{cell_id}.json"
    log_path = collection_dir / "logs" / f"{cell_id}.log"
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    command = [
        sys.executable,
        str(PROJECT_ROOT / "scripts" / "run_supervised.py"),
        "--experiment",
        binding.experiment,
        "--label",
        cell_id,
        "--deadline-seconds",
        str(binding.deadline_seconds),
        "--supervision-receipt-file",
        str(receipt_path.relative_to(PROJECT_ROOT)),
        "--experiment-arg=--seed",
        f"--experiment-arg={seed}",
        "--experiment-arg=--evidence-root",
        f"--experiment-arg={collection_dir / 'bundles'}",
    ]
    for argument in binding.experiment_args:
        command.append(f"--experiment-arg={argument}")
    started = time.monotonic()
    result = subprocess.run(command, cwd=PROJECT_ROOT, capture_output=True, text=True, check=False)
    elapsed = round(time.monotonic() - started, 3)
    log_path.write_text(
        portable_log_text(
            "$ "
            + " ".join(command)
            + "\n\n--- stdout ---\n"
            + result.stdout
            + "\n--- stderr ---\n"
            + result.stderr
        ),
        encoding="utf-8",
    )
    return build_cell_from_run(
        protocol=protocol,
        binding=binding,
        seed=seed,
        process_returncode=result.returncode,
        elapsed_seconds=elapsed,
        receipt_path=receipt_path,
        log_path=log_path,
    )


def build_cell_from_run(
    *,
    protocol: OperationalCollectionProtocol,
    binding: CollectionBinding,
    seed: int,
    process_returncode: int,
    elapsed_seconds: float,
    receipt_path: Path,
    log_path: Path,
) -> OperationalCell:
    references = [evidence_reference(log_path)]
    receipt: SupervisionReceipt | None = None
    bundle: Path | None = None
    experiment: dict = {}
    lifecycle: dict = {}
    lifecycle_qualified = False
    clean_teardown = False
    failure_reason: str | None = None
    if receipt_path.is_file():
        references.append(evidence_reference(receipt_path))
        receipt = SupervisionReceipt.model_validate_json(receipt_path.read_text(encoding="utf-8"))
        if receipt.handoff is not None:
            bundle = PROJECT_ROOT / receipt.handoff.bundle_relative_path
    if bundle is not None and bundle.is_dir():
        for filename in ("manifest.json", "experiment.json", "lifecycle-result.json"):
            candidate = bundle / filename
            if candidate.is_file():
                references.append(evidence_reference(candidate))
        experiment_path = bundle / "experiment.json"
        lifecycle_path = bundle / "lifecycle-result.json"
        if experiment_path.is_file():
            experiment = json.loads(experiment_path.read_text(encoding="utf-8"))
        if lifecycle_path.is_file():
            lifecycle = json.loads(lifecycle_path.read_text(encoding="utf-8"))
        try:
            verify_qualified_bundle(
                project_root=PROJECT_ROOT,
                bundle=bundle,
                expected_experiment=binding.experiment,
                require_natural_completion=True,
            )
            lifecycle_qualified = (
                lifecycle.get("implementation_revision") == protocol.plan.implementation_revision
            )
        except SupervisionEvidenceError as error:
            failure_reason = str(error)
        clean_teardown = lifecycle.get("final_state") == "clean" and not lifecycle.get(
            "residual", {}
        ).get("residual_resources", [])

    status = classify_status(receipt, process_returncode)
    if status in {CellStatus.FAILED, CellStatus.UNSUPPORTED, CellStatus.INTERRUPTED}:
        failure_reason = failure_reason or f"supervised process exited {process_returncode}"
    effect_verified = experiment.get(binding.effect_field) is True
    acquisitions: tuple[AssetAcquisition, ...] = ()
    if effect_verified and bundle is not None:
        acquisitions = (
            AssetAcquisition(
                asset_id=binding.critical_asset_id,
                effect_verified=True,
                evidence=tuple(
                    reference
                    for reference in references
                    if reference.path.endswith(("experiment.json", "lifecycle-result.json"))
                ),
            ),
        )
    total_seconds = float(lifecycle.get("total_seconds", elapsed_seconds))
    return OperationalCell(
        experiment_id=protocol.plan.experiment_id,
        plan_sha256=protocol.plan.content_sha256,
        arm=binding.arm,
        environment_id=binding.environment_id,
        seed=seed,
        status=status,
        lifecycle_qualified=lifecycle_qualified,
        clean_teardown=clean_teardown,
        acquisitions=acquisitions,
        accounting=ResourceAccounting(
            wall_seconds=elapsed_seconds,
            active_compute_seconds=total_seconds,
            model_seconds=0,
            input_tokens=0,
            output_tokens=0,
            model_cost_usd=0,
        ),
        terminal_evidence=tuple(references),
        failure_reason=failure_reason,
    )


def classify_status(receipt: SupervisionReceipt | None, process_returncode: int) -> CellStatus:
    if receipt is not None and receipt.supervisor_interruption is not None:
        return CellStatus.INTERRUPTED
    if receipt is not None and receipt.completed_naturally is False:
        return CellStatus.TIMED_OUT
    if process_returncode == 0:
        return CellStatus.COMPLETED
    return CellStatus.FAILED


def validate_protocol(protocol: OperationalCollectionProtocol) -> None:
    observed_revision = current_revision(PROJECT_ROOT)
    if observed_revision != protocol.plan.implementation_revision:
        raise ValueError(
            "current source revision differs from the frozen operational plan: "
            f"{observed_revision} != {protocol.plan.implementation_revision}"
        )
    for binding in protocol.bindings:
        if sha256_file(DRIVERS[binding.experiment]) != binding.driver_sha256:
            raise ValueError(f"driver changed after protocol freeze: {binding.experiment}")


def require_clean_previous_cells(ledger: OperationalLedger) -> None:
    for cell in ledger.cells:
        if cell.status is not CellStatus.PLANNED and not cell.clean_teardown:
            raise RuntimeError(
                "collection cannot continue without verified cleanup: "
                f"{cell.environment_id} seed={cell.seed}"
            )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("protocol", type=Path)
    parser.add_argument("ledger", type=Path)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--max-cells", type=int)
    args = parser.parse_args()
    protocol = OperationalCollectionProtocol.model_validate_json(
        args.protocol.read_text(encoding="utf-8")
    )
    validate_protocol(protocol)
    if args.ledger.exists():
        if not args.resume:
            raise FileExistsError(f"ledger already exists; use --resume: {args.ledger}")
        ledger = OperationalLedger.model_validate_json(args.ledger.read_text(encoding="utf-8"))
        if ledger.plan.content_sha256 != protocol.plan.content_sha256:
            raise ValueError("existing ledger belongs to another operational plan")
    else:
        ledger = planned_ledger(protocol)
        write_ledger(args.ledger, ledger)

    bindings = {(item.arm, item.environment_id): item for item in protocol.bindings}
    collected = 0
    for cell in ledger.cells:
        if cell.status is not CellStatus.PLANNED:
            continue
        if args.max_cells is not None and collected >= args.max_cells:
            break
        require_clean_previous_cells(ledger)
        validate_protocol(protocol)
        binding = bindings[(cell.arm, cell.environment_id)]
        completed = run_cell(protocol, binding, cell.seed, args.ledger.parent)
        ledger = replace_cell(ledger, completed)
        write_ledger(args.ledger, ledger)
        require_clean_previous_cells(ledger)
        collected += 1
        print(
            f"[operational] {binding.environment_id} seed={cell.seed} "
            f"status={completed.status.value} success={completed.successful}"
        )


if __name__ == "__main__":
    main()
