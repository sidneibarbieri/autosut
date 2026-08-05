#!/usr/bin/env python3
"""
Sequential VM-backed batch runner for campaigns with lab SUT profiles.

This script reuses the canonical `run_lab_campaign.py` path and writes the
batch result in the tab-separated format already consumed by paper-ready
artifacts (`release/full_lab_batch_*.tsv`).
"""

from __future__ import annotations

import argparse
import csv
import importlib.util
import json
import subprocess
import sys
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Sequence

import yaml


PROJECT_ROOT = Path(__file__).resolve().parent.parent
LAB_SUT_DIR = PROJECT_ROOT / "data" / "sut_profiles"
RELEASE_DIR = PROJECT_ROOT / "release"
RUN_LAB_CAMPAIGN_SCRIPT = PROJECT_ROOT / "scripts" / "run_lab_campaign.py"
DESTROY_LAB_SCRIPT = PROJECT_ROOT / "scripts" / "destroy_lab.sh"


@dataclass(frozen=True)
class BatchRow:
    campaign_id: str
    status: str
    notes: str


def _load_run_lab_module():
    spec = importlib.util.spec_from_file_location(
        "run_lab_campaign_batch_target", RUN_LAB_CAMPAIGN_SCRIPT
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load {RUN_LAB_CAMPAIGN_SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _list_lab_campaigns() -> list[str]:
    return sorted(
        path.stem
        for path in LAB_SUT_DIR.glob("*.yml")
        if path.stem != "_profile_template"
    )


def _default_output_path() -> Path:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return RELEASE_DIR / f"full_lab_batch_{timestamp}.tsv"


def _load_topology_signature(campaign_id: str) -> tuple[str, ...]:
    profile_path = LAB_SUT_DIR / f"{campaign_id}.yml"
    if not profile_path.exists():
        raise SystemExit(f"Missing lab SUT profile for {campaign_id}: {profile_path}")

    raw = yaml.safe_load(profile_path.read_text(encoding="utf-8")) or {}
    required_vms = raw.get("requirements", {}).get("required_vms", [])
    if not required_vms:
        raise SystemExit(
            f"Missing requirements.required_vms in lab SUT profile: {profile_path}"
        )

    alias = {
        "target-base": "target-linux-1",
        "target-1": "target-linux-1",
        "target": "target-linux-1",
        "target-2": "target-linux-2",
    }

    resolved: list[str] = []
    for vm_name in required_vms:
        canonical_name = alias.get(vm_name, vm_name)
        if canonical_name not in resolved:
            resolved.append(canonical_name)
    return tuple(resolved)


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Execute the VM-backed campaign subset sequentially."
    )
    parser.add_argument(
        "--campaign",
        action="append",
        dest="campaigns",
        help="Specific campaign to execute. Repeat to run multiple campaigns.",
    )
    parser.add_argument(
        "--provider",
        choices=["qemu", "libvirt", "virtualbox"],
        help="Explicit Vagrant provider. Omit to use per-host detection.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Explicit TSV output path. Defaults to release/full_lab_batch_<timestamp>.tsv.",
    )
    parser.add_argument(
        "--reuse-lab",
        action="store_true",
        help=(
            "Opt-in development mode: keep a compatible lab topology running between "
            "campaigns to avoid repeated cold-start provisioning."
        ),
    )
    parser.add_argument(
        "--assume-lab-running",
        action="store_true",
        help=(
            "Opt-in development mode: assume a compatible lab is already running "
            "before the batch starts."
        ),
    )
    return parser.parse_args(argv)


def _write_tsv(rows: Sequence[BatchRow], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, delimiter="\t", lineterminator="\n")
        writer.writerow(["campaign", "status", "notes"])
        for row in rows:
            writer.writerow([row.campaign_id, row.status, row.notes])


def _write_json(rows: Sequence[BatchRow], output_path: Path) -> None:
    output_path.write_text(
        json.dumps([asdict(row) for row in rows], indent=2),
        encoding="utf-8",
    )


def _build_run_args(
    campaign_id: str,
    provider: str | None,
    *,
    keep_lab: bool = False,
    assume_lab_running: bool = False,
) -> list[str]:
    arguments = ["--campaign", campaign_id]
    if provider:
        arguments.extend(["--provider", provider])
    if keep_lab:
        arguments.append("--keep-lab")
    if assume_lab_running:
        arguments.append("--assume-lab-running")
    return arguments


def _validate_reuse_compatibility(campaigns: Sequence[str]) -> tuple[str, ...]:
    baseline_signature: tuple[str, ...] | None = None

    for campaign_id in campaigns:
        signature = _load_topology_signature(campaign_id)
        if baseline_signature is None:
            baseline_signature = signature
            continue
        if signature != baseline_signature:
            raise SystemExit(
                "Incompatible lab topologies for --reuse-lab: "
                f"{campaigns[0]}={baseline_signature}, {campaign_id}={signature}"
            )

    return baseline_signature or ()


def _destroy_reused_lab(anchor_campaign: str) -> None:
    print(f"[LAB-BATCH] Cleaning reused lab for {anchor_campaign}")
    subprocess.run(
        ["bash", str(DESTROY_LAB_SCRIPT), "--campaign", anchor_campaign],
        cwd=str(PROJECT_ROOT),
        check=True,
    )


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    campaigns = args.campaigns or _list_lab_campaigns()
    unknown = sorted(set(campaigns) - set(_list_lab_campaigns()))
    if unknown:
        raise SystemExit(f"Unknown lab campaign(s): {', '.join(unknown)}")
    if args.assume_lab_running and not args.reuse_lab:
        raise SystemExit("--assume-lab-running requires --reuse-lab")
    if args.reuse_lab:
        _validate_reuse_compatibility(campaigns)

    output_path = args.output or _default_output_path()
    json_path = output_path.with_suffix(".json")
    run_lab_module = _load_run_lab_module()

    rows: list[BatchRow] = []
    exit_code = 0

    print(f"[LAB-BATCH] Executing {len(campaigns)} campaign(s)")
    print(f"[LAB-BATCH] Provider: {args.provider or 'auto'}")
    print(f"[LAB-BATCH] Output: {output_path}")
    if args.reuse_lab:
        print("[LAB-BATCH] Reuse mode: enabled (compatible topology required)")
    if args.assume_lab_running:
        print("[LAB-BATCH] Warm lab mode: assuming a compatible lab is already running")

    try:
        for index, campaign_id in enumerate(campaigns, start=1):
            print(f"[LAB-BATCH] [{index}/{len(campaigns)}] {campaign_id}")
            try:
                assume_lab_running = args.assume_lab_running and index == 1
                run_lab_module.main(
                    _build_run_args(
                        campaign_id,
                        args.provider,
                        keep_lab=args.reuse_lab,
                        assume_lab_running=assume_lab_running,
                    )
                )
            except ExceptionGroup as error:
                exit_code = 1
                notes = "; ".join(type(item).__name__ for item in error.exceptions)
                rows.append(BatchRow(campaign_id=campaign_id, status="FAIL", notes=notes))
                print(f"[LAB-BATCH] FAIL {campaign_id}: {notes}")
                continue
            except Exception as error:  # noqa: BLE001 - batch runner records campaign failure and continues
                exit_code = 1
                rows.append(
                    BatchRow(
                        campaign_id=campaign_id,
                        status="FAIL",
                        notes=f"{type(error).__name__}: {error}",
                    )
                )
                print(f"[LAB-BATCH] FAIL {campaign_id}: {error}")
                continue

            rows.append(BatchRow(campaign_id=campaign_id, status="PASS", notes=""))
            print(f"[LAB-BATCH] PASS {campaign_id}")
    finally:
        if args.reuse_lab and campaigns:
            _destroy_reused_lab(campaigns[0])

    _write_tsv(rows, output_path)
    _write_json(rows, json_path)
    print(f"[LAB-BATCH] Wrote {output_path}")
    print(f"[LAB-BATCH] Wrote {json_path}")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
