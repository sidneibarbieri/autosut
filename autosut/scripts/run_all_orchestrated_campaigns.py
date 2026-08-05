#!/usr/bin/env python3
"""Run implemented orchestrated campaigns sequentially.

Each campaign brings up its own SUT, injects CVEs (when declared), runs the
technique sequence, captures evidence, and tears the environment down before
the next one starts. The script prints a summary table at the end.

Usage:
    python3 scripts/run_all_orchestrated_campaigns.py
    python3 scripts/run_all_orchestrated_campaigns.py --list
    python3 scripts/run_all_orchestrated_campaigns.py --campaign 0.c0013
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import signal
import shutil
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence


sys.path.insert(0, str(Path(__file__).resolve().parent))

from orchestrator import build_default, caldera_client
from orchestrator import caldera_operation
from orchestrator.catalog import implemented_campaigns


PROJECT_ROOT = Path(__file__).resolve().parent.parent
RELEASE_DIR = PROJECT_ROOT / "release"
SLOW_DEFAULT_LAST = {"0.shadowray"}
CALDERA_REQUIRED_CAMPAIGNS = {
    "0.c0013",
    "0.caldera_linux_demo",
    "0.fin6_emulation",
}
CALDERA_DOCKER_PLATFORM = "linux/amd64"
CALDERA_IMAGE = "ghcr.io/mitre/caldera:latest"


class CampaignTimeout(RuntimeError):
    """Raised when a campaign exceeds the configured wall-clock budget."""


@dataclass
class ReplayRow:
    campaign_id: str
    status: str
    successful: int
    total: int
    fidelity_distribution: dict[str, int]
    elapsed_seconds: float
    evidence_manifest: str
    notes: str


def default_output_path() -> Path:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return RELEASE_DIR / f"orchestrated_replay_{timestamp}.tsv"


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run AutoSUT orchestrated campaign/SUT pairs sequentially and write "
            "a reviewer-readable replay report."
        )
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List implemented campaign ids and exit.",
    )
    parser.add_argument(
        "--campaign",
        action="append",
        dest="campaigns",
        help="Campaign id to run. Repeat to run a subset. Defaults to all.",
    )
    parser.add_argument(
        "--catalog-order",
        action="store_true",
        help=(
            "Use the catalog's original campaign order. By default, known slow "
            "campaigns run last so full replay gives quick feedback first."
        ),
    )
    parser.add_argument(
        "--skip",
        action="append",
        default=[],
        help="Campaign id to skip. Useful for intentionally omitting slow labs.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="TSV report path. Defaults to release/orchestrated_replay_<UTC>.tsv.",
    )
    parser.add_argument(
        "--preflight-only",
        action="store_true",
        help="Check host prerequisites and campaign selection, then exit.",
    )
    parser.add_argument(
        "--no-caldera-start",
        action="store_true",
        help="Do not attempt to start the local Caldera container automatically.",
    )
    parser.add_argument(
        "--restart-caldera-per-campaign",
        action="store_true",
        help=(
            "For Caldera-backed campaigns, restart autosut-caldera before "
            "the campaign so stale agents, operations, and randomized API "
            "keys cannot leak across a long batch."
        ),
    )
    parser.add_argument(
        "--isolate-campaigns",
        action="store_true",
        help=(
            "Clean AutoSUT containers before and after each campaign. For "
            "Caldera-backed campaigns, also restart Caldera before the run."
        ),
    )
    parser.add_argument(
        "--campaign-timeout-seconds",
        type=int,
        default=0,
        help=(
            "Optional wall-clock timeout per campaign. Timeout rows are "
            "recorded as ERROR and the batch continues unless "
            "--stop-on-failure is set."
        ),
    )
    parser.add_argument(
        "--clean-stale-autosut-containers",
        action="store_true",
        help=(
            "Before replay, remove stale Docker containers whose names start "
            "with autosut- except autosut-caldera. This is useful after an "
            "interrupted local run and is intentionally opt-in."
        ),
    )
    parser.add_argument(
        "--stop-on-failure",
        action="store_true",
        help="Stop the batch after the first failing campaign.",
    )
    parser.add_argument(
        "--retain-run-evidence-at-root",
        action="store_true",
        help=(
            "Developer/curation mode: leave newly generated replay evidence "
            "under release/evidence/. By default, reviewer replays are moved "
            "to release/evidence/_reviewer_runs/ so run_review_check.sh still "
            "validates the curated golden evidence after a full rerun."
        ),
    )
    return parser.parse_args(argv)


def ensure_caldera_ready(max_wait_seconds: int = 90) -> bool:
    """Bring the Caldera C2 up before the batch starts.

    A declared caldera_driven technique fails honestly when the C2 is
    unreachable, so the batch provisions the C2 rather than letting evidence
    degrade silently. Returns True once Caldera answers its health endpoint.
    """
    if caldera_client.probe().api_ok:
        return True

    print("[caldera] C2 unreachable; provisioning it before the batch ...")
    inspect_proc = subprocess.run(
        ["docker", "container", "inspect", "autosut-caldera"],
        check=False, capture_output=True, text=True,
    )
    if inspect_proc.returncode == 0:
        start_cmd = ["docker", "start", "autosut-caldera"]
    else:
        start_cmd = [
            "docker", "run", "-d",
            "--name", "autosut-caldera",
            "-p", "8888:8888",
            CALDERA_IMAGE,
        ]
    start_proc = subprocess.run(
        start_cmd,
        check=False, capture_output=True, text=True,
    )
    if start_proc.returncode != 0:
        print("[caldera] Could not provision autosut-caldera automatically:")
        print(start_proc.stderr.strip() or start_proc.stdout.strip() or "unknown error")
    deadline = time.monotonic() + max_wait_seconds
    while time.monotonic() < deadline:
        if caldera_client.probe().api_ok:
            print("[caldera] C2 ready.")
            return True
        time.sleep(5)

    print("[caldera] C2 still unreachable. Run ./scripts/up_lab.sh to provision "
          "it; caldera-driven techniques are otherwise recorded as failures.")
    return False


def reset_caldera_state(*, remove_container: bool = False) -> None:
    """Reset Caldera client/agent caches and optionally replace the C2."""
    caldera_client.reset_cache()
    caldera_operation.reset_agent_cache()
    if not remove_container:
        return
    subprocess.run(
        ["docker", "rm", "-f", "autosut-caldera"],
        check=False, capture_output=True, text=True,
    )
    caldera_client.reset_cache()
    caldera_operation.reset_agent_cache()


def preflight(
    campaigns: Sequence[str],
    *,
    needs_caldera: bool,
    start_caldera: bool,
) -> bool:
    """Print the host state a reviewer needs before starting a long replay."""
    ok = True
    print("[preflight] project:", PROJECT_ROOT)
    print("[preflight] campaigns:", ", ".join(campaigns))
    print("[preflight] python:", sys.executable)
    docker = shutil.which("docker")
    print("[preflight] docker:", docker or "not found")
    if docker is None:
        return False

    info = subprocess.run(
        ["docker", "info"],
        capture_output=True,
        text=True,
        timeout=20,
    )
    if info.returncode == 0:
        print("[preflight] docker daemon: reachable")
    else:
        print("[preflight] docker daemon: NOT reachable")
        print((info.stderr or info.stdout).strip()[:500])
        ok = False

    if not needs_caldera:
        print("[preflight] Caldera C2: not required by selected campaigns")
    elif start_caldera:
        caldera_ok = ensure_caldera_ready()
        print("[preflight] Caldera C2:", "reachable" if caldera_ok else "unreachable")
        ok = caldera_ok and ok
    else:
        caldera_ok = caldera_client.probe().api_ok
        print("[preflight] Caldera C2:", "reachable" if caldera_ok else "unreachable")
        ok = caldera_ok and ok
    return ok


def stale_autosut_containers() -> list[str]:
    docker = shutil.which("docker")
    if docker is None:
        return []
    proc = subprocess.run(
        ["docker", "ps", "-a", "--format", "{{.Names}}"],
        capture_output=True,
        text=True,
        timeout=20,
    )
    if proc.returncode != 0:
        return []
    return sorted(
        name for name in proc.stdout.splitlines()
        if name.startswith("autosut-") and name != "autosut-caldera"
    )


def clean_stale_autosut_containers() -> None:
    stale = stale_autosut_containers()
    if not stale:
        print("[preflight] stale autosut containers: none")
        return
    print("[preflight] removing stale autosut containers:", ", ".join(stale))
    subprocess.run(
        ["docker", "rm", "-f", *stale],
        check=False,
        capture_output=True,
        text=True,
    )


def run_with_optional_timeout(orch, campaign_id: str,
                              timeout_seconds: int):
    """Run one campaign, using SIGALRM only when configured."""
    if timeout_seconds <= 0:
        return orch.run_campaign(campaign_id)

    def _raise_timeout(signum, frame):  # noqa: ARG001
        raise CampaignTimeout(
            f"campaign exceeded {timeout_seconds}s wall-clock budget"
        )

    previous = signal.signal(signal.SIGALRM, _raise_timeout)
    signal.alarm(timeout_seconds)
    try:
        return orch.run_campaign(campaign_id)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


def set_caldera_platform_if_needed(campaign_id: str) -> str | None:
    """Pin Caldera-backed SUTs to amd64 so the prebuilt sandcat is usable."""
    previous = os.environ.get("AUTOSUT_DOCKER_PLATFORM")
    if campaign_id in CALDERA_REQUIRED_CAMPAIGNS and previous is None:
        os.environ["AUTOSUT_DOCKER_PLATFORM"] = CALDERA_DOCKER_PLATFORM
        print(f"[caldera] SUT Docker platform: {CALDERA_DOCKER_PLATFORM}")
    return previous


def restore_docker_platform(previous: str | None) -> None:
    if previous is None:
        os.environ.pop("AUTOSUT_DOCKER_PLATFORM", None)
    else:
        os.environ["AUTOSUT_DOCKER_PLATFORM"] = previous


def write_reports(rows: Sequence[ReplayRow], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle, delimiter="\t", lineterminator="\n")
        writer.writerow([
            "campaign",
            "status",
            "successful",
            "total",
            "fidelity_distribution",
            "elapsed_seconds",
            "evidence_manifest",
            "notes",
        ])
        for row in rows:
            writer.writerow([
                row.campaign_id,
                row.status,
                row.successful,
                row.total,
                json.dumps(row.fidelity_distribution, sort_keys=True),
                f"{row.elapsed_seconds:.1f}",
                row.evidence_manifest,
                row.notes,
            ])
    output_path.with_suffix(".json").write_text(
        json.dumps([asdict(row) for row in rows], indent=2, sort_keys=True),
        encoding="utf-8",
    )


def reviewer_path(path_value: str) -> str:
    """Return a path that remains valid after cloning the artifact."""
    if not path_value:
        return ""
    path = Path(path_value)
    try:
        return path.relative_to(PROJECT_ROOT).as_posix()
    except ValueError:
        return path_value


def archive_reviewer_evidence(manifest_path: str,
                              *,
                              retain_at_root: bool) -> str:
    """Move replay-generated evidence out of the curated evidence root.

    ``release/evidence/`` is the curated surface consumed by the dashboard and
    release gate: only golden runs belong there. A reviewer can still run all
    campaigns, but those fresh runs are ordinary replay evidence rather than
    newly curated golden runs. Keeping them under ``_reviewer_runs`` preserves
    their manifests while letting ``run_review_check.sh`` pass immediately
    after the reviewer has exercised the full replay command.
    """
    if retain_at_root or not manifest_path:
        return manifest_path
    manifest = Path(manifest_path)
    if not manifest.exists():
        return manifest_path
    run_dir = manifest.parent
    evidence_root = RELEASE_DIR / "evidence"
    try:
        run_dir.relative_to(evidence_root)
    except ValueError:
        return manifest_path
    if run_dir.parent != evidence_root:
        return manifest_path
    if not run_dir.name.startswith("0.") or "_2026" not in run_dir.name:
        return manifest_path

    archive_root = evidence_root / "_reviewer_runs"
    archive_root.mkdir(parents=True, exist_ok=True)
    destination = archive_root / run_dir.name
    if destination.exists():
        suffix = 1
        while (archive_root / f"{run_dir.name}_{suffix}").exists():
            suffix += 1
        destination = archive_root / f"{run_dir.name}_{suffix}"
    shutil.move(str(run_dir), str(destination))
    return str(destination / manifest.name)


def select_campaigns(args: argparse.Namespace) -> list[str]:
    all_campaigns = implemented_campaigns()
    if args.list:
        for cid in all_campaigns:
            print(cid)
        return []
    if args.campaigns:
        selected = args.campaigns
    elif args.catalog_order:
        selected = all_campaigns
    else:
        selected = [
            *[cid for cid in all_campaigns if cid not in SLOW_DEFAULT_LAST],
            *[cid for cid in all_campaigns if cid in SLOW_DEFAULT_LAST],
        ]
    unknown = sorted(set(selected) - set(all_campaigns))
    if unknown:
        raise SystemExit(f"Unknown campaign(s): {', '.join(unknown)}")
    skipped = set(args.skip or [])
    unknown_skip = sorted(skipped - set(all_campaigns))
    if unknown_skip:
        raise SystemExit(f"Unknown skipped campaign(s): {', '.join(unknown_skip)}")
    return [cid for cid in selected if cid not in skipped]


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    campaigns = select_campaigns(args)
    if args.list:
        return 0
    if not campaigns:
        raise SystemExit("No campaigns selected.")

    output_path = args.output or default_output_path()
    if args.clean_stale_autosut_containers:
        clean_stale_autosut_containers()
    else:
        stale = stale_autosut_containers()
        if stale:
            print("[preflight] stale autosut containers detected:",
                  ", ".join(stale))
            print("[preflight] rerun with --clean-stale-autosut-containers "
                  "after an interrupted local batch if these are not intentional.")
    needs_caldera = bool(set(campaigns) & CALDERA_REQUIRED_CAMPAIGNS)
    preflight_ok = preflight(
        campaigns,
        needs_caldera=needs_caldera,
        start_caldera=needs_caldera and not args.no_caldera_start,
    )
    if args.preflight_only:
        return 0 if preflight_ok else 2
    if not preflight_ok:
        print("[preflight] continuing would produce misleading failures; aborting.")
        return 2

    orch = build_default()
    rows: list[ReplayRow] = []
    for index, cid in enumerate(campaigns, start=1):
        print(f"\n=== Running {cid} ===")
        print(f"[batch] {index}/{len(campaigns)}")
        needs_campaign_caldera = cid in CALDERA_REQUIRED_CAMPAIGNS
        if args.isolate_campaigns:
            clean_stale_autosut_containers()
        if needs_campaign_caldera and (args.restart_caldera_per_campaign
                                       or args.isolate_campaigns):
            print("[caldera] restarting C2 for campaign isolation ...")
            reset_caldera_state(remove_container=True)
            if not args.no_caldera_start and not ensure_caldera_ready():
                rows.append(ReplayRow(
                    campaign_id=cid,
                    status="ERROR",
                    successful=0,
                    total=0,
                    fidelity_distribution={},
                    elapsed_seconds=0.0,
                    evidence_manifest="",
                    notes="Caldera did not become ready after restart",
                ))
                write_reports(rows, output_path)
                if args.stop_on_failure:
                    break
                continue
        t0 = time.monotonic()
        previous_platform = set_caldera_platform_if_needed(cid)
        try:
            result = run_with_optional_timeout(
                orch, cid, args.campaign_timeout_seconds,
            )
        except Exception as exc:
            elapsed = time.monotonic() - t0
            rows.append(ReplayRow(
                campaign_id=cid,
                status="ERROR",
                successful=0,
                total=0,
                fidelity_distribution={},
                elapsed_seconds=elapsed,
                evidence_manifest="",
                notes=f"{type(exc).__name__}: {exc}",
            ))
            write_reports(rows, output_path)
            if args.isolate_campaigns:
                clean_stale_autosut_containers()
            if args.stop_on_failure:
                break
            continue
        finally:
            restore_docker_platform(previous_platform)
        elapsed = time.monotonic() - t0
        status = (
            "PASS"
            if result.total_techniques > 0 and result.successful == result.total_techniques
            else "PARTIAL"
            if result.successful > 0
            else "FAIL"
        )
        evidence_manifest = archive_reviewer_evidence(
            str(result.manifest_path),
            retain_at_root=args.retain_run_evidence_at_root,
        )
        rows.append(ReplayRow(
            campaign_id=cid,
            status=status,
            successful=result.successful,
            total=result.total_techniques,
            fidelity_distribution=result.fidelity_distribution,
            elapsed_seconds=elapsed,
            evidence_manifest=reviewer_path(evidence_manifest),
            notes="ok",
        ))
        write_reports(rows, output_path)
        print(f"[batch] {cid}: {status} {result.successful}/{result.total_techniques} "
              f"in {elapsed:.1f}s")
        if args.isolate_campaigns:
            clean_stale_autosut_containers()
        if status != "PASS" and args.stop_on_failure:
            break

    print("\n" + "=" * 88)
    print(f"{'campaign':<35} {'status':<8} {'pass/total':>11}  {'fidelity':<28} elapsed")
    print("-" * 88)
    total_pass = total_all = 0
    fidelity_sum: dict[str, int] = {}
    for row in rows:
        total_pass += row.successful
        total_all += row.total
        for k, v in row.fidelity_distribution.items():
            fidelity_sum[k] = fidelity_sum.get(k, 0) + v
        fid_str = ", ".join(f"{k}={v}" for k, v in sorted(row.fidelity_distribution.items()))
        print(f"{row.campaign_id:<35} {row.status:<8} "
              f"{row.successful:>3}/{row.total:<7d}  {fid_str:<28} "
              f"{row.elapsed_seconds:.1f}s")
    print("-" * 88)
    fid_total = ", ".join(f"{k}={v}" for k, v in sorted(fidelity_sum.items()))
    print(f"{'TOTAL':<35} {total_pass:>3}/{total_all:<7d}  {fid_total}")
    print(f"[batch] TSV report:  {output_path}")
    print(f"[batch] JSON report: {output_path.with_suffix('.json')}")
    print("=" * 88)
    return 0 if rows and all(row.status == "PASS" for row in rows) else 2


if __name__ == "__main__":
    raise SystemExit(main())
