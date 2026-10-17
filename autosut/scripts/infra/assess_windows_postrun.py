"""Assess a sealed Windows run without modifying its evidence."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

if __name__ == "__main__":
    sys.dont_write_bytecode = True

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SOURCE_ROOT = PROJECT_ROOT / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from infrastructure.evidence_bundle import (
    SecretAuditSurface,
    SecretSurfaceReceipt,
)
from infrastructure.windows_postrun_qualification import assess_sealed_windows_run
from infrastructure.windows_surface_scan import SurfaceScan, sha256_file

RETAINED_SURFACES = (
    SecretAuditSurface.BASE_IMAGE,
    SecretAuditSurface.SOURCE_TREE,
    SecretAuditSurface.EVIDENCE_BUNDLE,
    SecretAuditSurface.RUN_LOGS,
    SecretAuditSurface.GUEST_PANTHER,
)


def retained_roots(run_dir: Path, base_image: Path, source_tree: Path) -> dict[str, Path]:
    return {
        "base_image": base_image,
        "source_tree": source_tree,
        "evidence_bundle": run_dir / "bundle.json",
        "run_logs": run_dir,
        "guest_panther": run_dir / "windows-qemu" / "panther-acquisition",
    }


def retained_reports(run_dir: Path) -> list[SecretSurfaceReceipt]:
    reports = []
    for surface in RETAINED_SURFACES:
        receipt = run_dir.with_name(
            f"{run_dir.name}.{surface.value.replace('_', '-')}-scan.json"
        )
        if not receipt.is_file() or receipt.is_symlink():
            continue
        scan = SurfaceScan.model_validate_json(receipt.read_text(encoding="utf-8"))
        reports.append(SecretSurfaceReceipt(
            surface=surface,
            receipt_path=receipt.name,
            receipt_sha256=sha256_file(receipt),
            files_scanned=scan.files_scanned,
            completed=scan.completed,
            leak_found=scan.leak_found,
        ))
    return reports


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--base-image", type=Path, required=True)
    parser.add_argument("--source-tree", type=Path, required=True)
    arguments = parser.parse_args()
    if arguments.run_dir.is_symlink():
        raise ValueError("run directory must not be a symlink")
    run_dir = arguments.run_dir.resolve(strict=True)
    if not run_dir.is_dir():
        raise ValueError("run directory must be a regular directory")
    decision = assess_sealed_windows_run(
        run_dir,
        receipt_root=run_dir.parent,
        surface_roots=retained_roots(run_dir, arguments.base_image, arguments.source_tree),
        reports=retained_reports(run_dir),
    )
    print(decision.model_dump_json(indent=2))
    return 0 if decision.admissible else 1


if __name__ == "__main__":
    raise SystemExit(main())
