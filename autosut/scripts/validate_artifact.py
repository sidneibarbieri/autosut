#!/usr/bin/env python3
"""
AutoSUT artifact validation pipeline.

Runs the full lifecycle for one or more campaigns:
  destroy -> up -> apply_sut -> run -> validate_evidence -> (cleanup)

Usage:
  python3 scripts/validate_artifact.py --campaign 0.c0011
  python3 scripts/validate_artifact.py --all
  python3 scripts/validate_artifact.py --all --skip-infra
  python3 scripts/validate_artifact.py --campaign 0.c0011 --cleanup

Options:
  --campaign ID    Single campaign to validate
  --all            Validate all campaigns listed in this script
  --skip-infra     Skip destroy/up/apply_sut (use already-running VMs)
  --cleanup        Destroy VMs after each campaign run
  --provider NAME  Vagrant provider [default: auto-detect]

Exit code is 0 only if every validated campaign is COMPLETE.
"""

from __future__ import annotations

import argparse
import json
import platform
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = PROJECT_ROOT / "scripts"
SRC_DIR = PROJECT_ROOT / "src"
EVIDENCE_DIR = PROJECT_ROOT / "release" / "evidence"
RESULTS_DIR = PROJECT_ROOT / "results"

# Ordered list of campaigns to validate with --all.
ALL_CAMPAIGNS = [
    "0.apt41_dust",
    "0.c0010",
    "0.c0026",
    "0.costaricto",
    "0.operation_midnighteclipse",
    "0.outer_space",
    "0.salesforce_data_exfiltration",
    "0.shadowray",
]


@dataclass
class StepResult:
    name: str
    success: bool
    duration_seconds: float
    stdout: str = ""
    stderr: str = ""


@dataclass
class CampaignValidation:
    campaign_id: str
    provider: str
    started_at: str
    finished_at: str = ""
    steps: list[StepResult] = field(default_factory=list)
    status: str = "UNKNOWN"  # COMPLETE | PARTIAL | MISSING | ERROR
    techniques_total: int = 0
    techniques_successful: int = 0
    techniques_failed: int = 0
    evidence_path: str = ""
    notes: list[str] = field(default_factory=list)


def detect_provider() -> str:
    if platform.system() == "Darwin" and platform.machine() == "arm64":
        return "qemu"
    return "libvirt"


def run_step(
    name: str,
    cmd: list[str],
    cwd: Path = PROJECT_ROOT,
    timeout: int = 600,
) -> StepResult:
    started = datetime.now()
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        duration = (datetime.now() - started).total_seconds()
        return StepResult(
            name=name,
            success=proc.returncode == 0,
            duration_seconds=duration,
            stdout=proc.stdout[-4000:] if len(proc.stdout) > 4000 else proc.stdout,
            stderr=proc.stderr[-2000:] if len(proc.stderr) > 2000 else proc.stderr,
        )
    except subprocess.TimeoutExpired:
        duration = (datetime.now() - started).total_seconds()
        return StepResult(
            name=name,
            success=False,
            duration_seconds=duration,
            stderr=f"Timed out after {timeout}s",
        )


def latest_evidence_summary(campaign_id: str) -> tuple[str, dict]:
    candidates = sorted(EVIDENCE_DIR.glob(f"{campaign_id}_*/summary.json"))
    if not candidates:
        return "", {}
    path = max(candidates, key=lambda p: p.parent.name)
    return str(path.parent), json.loads(path.read_text(encoding="utf-8"))


def validate_single(
    campaign_id: str,
    provider: str,
    skip_infra: bool,
    cleanup: bool,
) -> CampaignValidation:
    result = CampaignValidation(
        campaign_id=campaign_id,
        provider=provider,
        started_at=datetime.now().isoformat(timespec="seconds"),
    )
    separator = "=" * 60
    print(f"\n{separator}")
    print(f"  Validating: {campaign_id}")
    print(separator)

    def step(name: str, cmd: list[str], timeout: int = 600) -> bool:
        print(f"  [{name}]", end=" ", flush=True)
        sr = run_step(name, cmd, timeout=timeout)
        result.steps.append(sr)
        status_str = "OK" if sr.success else "FAIL"
        print(f"{status_str} ({sr.duration_seconds:.1f}s)")
        if not sr.success and sr.stderr:
            print(f"    stderr: {sr.stderr[:300]}")
        return sr.success

    if not skip_infra:
        # Destroy any existing state
        step(
            "destroy",
            [str(SCRIPTS_DIR / "destroy_lab.sh"), "--campaign", campaign_id],
            timeout=180,
        )
        # Bring up lab (this also runs health check and applies SUT profile)
        ok = step(
            "up",
            [
                str(SCRIPTS_DIR / "up_lab.sh"),
                "--campaign",
                campaign_id,
                "--provider",
                provider,
            ],
            timeout=900,
        )
        if not ok:
            result.status = "ERROR"
            result.notes.append("Lab bring-up failed")
            result.finished_at = datetime.now().isoformat(timespec="seconds")
            return result
    else:
        # Only apply SUT profile when skipping full infra cycle
        ok = step(
            "apply_sut",
            [
                sys.executable,
                str(PROJECT_ROOT / "apply_sut_profile.py"),
                "--campaign",
                campaign_id,
                "--base-dir",
                str(PROJECT_ROOT),
                "--provider",
                provider,
            ],
            timeout=120,
        )
        if not ok:
            result.notes.append("SUT profile application failed; continuing")

    # Run the campaign
    ok = step(
        "run_campaign",
        [
            sys.executable,
            str(SCRIPTS_DIR / "run_campaign.py"),
            "--campaign",
            campaign_id,
        ],
        timeout=300,
    )

    # Validate evidence
    ev_path, summary = latest_evidence_summary(campaign_id)
    result.evidence_path = ev_path
    if summary:
        result.techniques_total = summary.get("total_techniques", 0)
        result.techniques_successful = summary.get("successful", 0)
        result.techniques_failed = summary.get("failed", 0)
        infra = summary.get("infrastructure_provider", "")
        if not infra:
            result.notes.append("infrastructure_provider missing from summary")
        elif infra != provider:
            result.notes.append(
                f"infrastructure_provider={infra!r} differs from expected {provider!r}"
            )

        if result.techniques_failed == 0 and result.techniques_successful > 0:
            result.status = "COMPLETE"
        elif result.techniques_successful > 0:
            result.status = "PARTIAL"
        else:
            result.status = "MISSING"
    else:
        result.status = "MISSING"
        result.notes.append("No evidence summary found")

    print(
        f"  => {result.status}  ({result.techniques_successful}/{result.techniques_total})"
    )

    if cleanup and not skip_infra:
        step(
            "cleanup",
            [str(SCRIPTS_DIR / "destroy_lab.sh"), "--campaign", campaign_id],
            timeout=180,
        )

    result.finished_at = datetime.now().isoformat(timespec="seconds")
    return result


def write_report(results: list[CampaignValidation]) -> Path:
    RESULTS_DIR.mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = RESULTS_DIR / f"validation_report_{ts}.json"

    complete = [r for r in results if r.status == "COMPLETE"]
    partial = [r for r in results if r.status == "PARTIAL"]
    missing_error = [r for r in results if r.status in ("MISSING", "ERROR")]

    report = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "total": len(results),
        "complete": len(complete),
        "partial": len(partial),
        "missing_or_error": len(missing_error),
        "campaigns": [asdict(r) for r in results],
    }
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    md_lines = [
        "# AutoSUT Artifact Validation Report",
        "",
        f"Generated: `{report['generated_at']}`",
        "",
        "| Metric | Count |",
        "|---|---|",
        f"| Total campaigns validated | {report['total']} |",
        f"| COMPLETE | {report['complete']} |",
        f"| PARTIAL | {report['partial']} |",
        f"| MISSING / ERROR | {report['missing_or_error']} |",
        "",
        "## Per-Campaign Results",
        "",
        "| Campaign | Status | Successful | Failed | Total | Evidence |",
        "|---|:---:|---:|---:|---:|---|",
    ]
    for r in results:
        ev = f"`{Path(r.evidence_path).name}`" if r.evidence_path else "none"
        md_lines.append(
            f"| `{r.campaign_id}` | **{r.status}** | {r.techniques_successful} | "
            f"{r.techniques_failed} | {r.techniques_total} | {ev} |"
        )

    if any(r.notes for r in results):
        md_lines += ["", "## Notes", ""]
        for r in results:
            if r.notes:
                md_lines.append(f"**{r.campaign_id}**")
                for note in r.notes:
                    md_lines.append(f"- {note}")
                md_lines.append("")

    md_path = json_path.with_suffix(".md")
    md_path.write_text("\n".join(md_lines) + "\n", encoding="utf-8")

    # Also write a stable pointer to the latest report
    latest_json = RESULTS_DIR / "validation_report_latest.json"
    latest_md = RESULTS_DIR / "VALIDATION_REPORT.md"
    latest_json.write_text(json.dumps(report, indent=2), encoding="utf-8")
    latest_md.write_text("\n".join(md_lines) + "\n", encoding="utf-8")

    print(f"\nValidation report: {json_path}")
    return json_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="AutoSUT artifact validation pipeline")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--campaign", metavar="ID", help="Single campaign ID to validate"
    )
    group.add_argument(
        "--all", action="store_true", help="Validate all supported campaigns"
    )
    parser.add_argument(
        "--skip-infra",
        action="store_true",
        help="Skip destroy/up; assume VMs are already running",
    )
    parser.add_argument(
        "--cleanup", action="store_true", help="Destroy VMs after each run"
    )
    parser.add_argument("--provider", default="", help="Vagrant provider override")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    provider = args.provider or detect_provider()
    campaigns = ALL_CAMPAIGNS if args.all else [args.campaign]

    print("STICKS Validation Pipeline")
    print(f"  Provider : {provider}")
    print(f"  Campaigns: {len(campaigns)}")
    print(f"  Skip infra: {args.skip_infra}")
    print(f"  Cleanup  : {args.cleanup}")

    results: list[CampaignValidation] = []
    for cid in campaigns:
        r = validate_single(
            campaign_id=cid,
            provider=provider,
            skip_infra=args.skip_infra,
            cleanup=args.cleanup,
        )
        results.append(r)

    write_report(results)

    failed_campaigns = [r for r in results if r.status != "COMPLETE"]
    if failed_campaigns:
        print(f"\nFailed campaigns: {[r.campaign_id for r in failed_campaigns]}")
        return 1
    print(f"\nAll {len(results)} campaign(s) COMPLETE.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
