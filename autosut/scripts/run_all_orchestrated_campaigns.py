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
import re
import signal
import shutil
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence


SCRIPTS_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPTS_DIR.parent
for import_root in (SCRIPTS_DIR, PROJECT_ROOT / "src"):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))

from infrastructure.docker_namespace import (  # noqa: E402
    DockerInventoryError,
    autosut_resources,
    force_remove,
)
from infrastructure.caldera_instance import CALDERA_IMAGE  # noqa: E402
from infrastructure.revision import current_revision  # noqa: E402
from orchestrator import build_default, caldera_client
from orchestrator import caldera_operation
from orchestrator.catalog import implemented_campaigns
from orchestrator.models import RunResult


RELEASE_DIR = PROJECT_ROOT / "release"
SLOW_DEFAULT_LAST = {"0.shadowray"}
CALDERA_REQUIRED_CAMPAIGNS = {
    "0.c0013",
    "0.caldera_linux_demo",
    "0.fin6_emulation",
}
CALDERA_DOCKER_PLATFORM = "linux/amd64"


class CampaignTimeout(RuntimeError):
    """Raised when a campaign exceeds the configured wall-clock budget."""


@dataclass
class ReplayRow:
    campaign_id: str
    implementation_revision: str
    status: str
    successful: int
    evidence_backed_successful: int
    marker_only_successful: int
    caldera_driven_successful: int
    total: int
    fidelity_distribution: dict[str, int]
    final_namespace_clean: bool
    cleanup_removed_resources: list[str]
    elapsed_seconds: float
    evidence_manifest: str
    notes: str


def default_output_path() -> Path:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return RELEASE_DIR / f"orchestrated_replay_{timestamp}.tsv"


def evidence_collection_name(value: str) -> str:
    """Validate a portable single-directory collection name."""
    if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,63}", value):
        raise argparse.ArgumentTypeError(
            "collection must be 1-64 lowercase letters, digits, '.', '_', or '-'"
        )
    return value


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
            "Remove all AutoSUT containers, networks, and volumes before and "
            "after each campaign. Caldera-backed campaigns receive a fresh C2."
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
            "Before replay, remove stale AutoSUT Docker resources except the "
            "persistent development Caldera. This legacy option now covers "
            "containers, networks, and volumes."
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
    parser.add_argument(
        "--evidence-collection",
        type=evidence_collection_name,
        default=None,
        help=(
            "Move run evidence into release/evidence/<name>/ instead of the "
            "ephemeral _reviewer_runs directory. The collection must be empty."
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
            "--platform", CALDERA_DOCKER_PLATFORM,
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
    defer_caldera: bool = False,
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
    elif defer_caldera:
        print("[preflight] Caldera C2: deferred to each isolated campaign")
    elif start_caldera:
        caldera_ok = ensure_caldera_ready()
        print("[preflight] Caldera C2:", "reachable" if caldera_ok else "unreachable")
        ok = caldera_ok and ok
    else:
        caldera_ok = caldera_client.probe().api_ok
        print("[preflight] Caldera C2:", "reachable" if caldera_ok else "unreachable")
        ok = caldera_ok and ok
    return ok


def stale_autosut_resources(*, include_caldera: bool = False) -> list[str]:
    """List the complete AutoSUT Docker namespace, failing closed."""
    if shutil.which("docker") is None:
        raise RuntimeError("docker executable not found")
    try:
        resources = autosut_resources()
    except DockerInventoryError as exc:
        raise RuntimeError(str(exc)) from exc
    if not include_caldera:
        resources.discard("container:autosut-caldera")
    return sorted(resources)


def _remove_resources_until_absent(
    initial_resources: Sequence[str],
    *,
    include_caldera: bool,
    removal_timeout_seconds: float,
) -> list[str]:
    deadline = time.monotonic() + removal_timeout_seconds
    residual = list(initial_resources)
    while residual:
        for resource in residual:
            force_remove(resource)
        if time.monotonic() >= deadline:
            raise RuntimeError(
                "AutoSUT Docker cleanup incomplete: " + ", ".join(residual)
            )
        time.sleep(0.5)
        residual = stale_autosut_resources(include_caldera=include_caldera)
    return list(initial_resources)


def clean_stale_autosut_resources(
    *,
    include_caldera: bool = False,
    removal_timeout_seconds: float = 30.0,
) -> list[str]:
    stale = stale_autosut_resources(include_caldera=include_caldera)
    if not stale:
        print("[preflight] stale autosut resources: none")
        return []
    print("[preflight] removing stale autosut resources:", ", ".join(stale))
    return _remove_resources_until_absent(
        stale,
        include_caldera=include_caldera,
        removal_timeout_seconds=removal_timeout_seconds,
    )


def stale_autosut_containers() -> list[str]:
    """Compatibility view retained for callers that only need containers."""
    return [
        resource.removeprefix("container:")
        for resource in stale_autosut_resources()
        if resource.startswith("container:")
    ]


def clean_stale_autosut_containers(
    *, removal_timeout_seconds: float = 30.0
) -> list[str]:
    """Compatibility cleanup retained for the former container-only API."""
    stale = [f"container:{name}" for name in stale_autosut_containers()]
    if not stale:
        print("[preflight] stale autosut containers: none")
        return []
    removed = _remove_resources_until_absent(
        stale,
        include_caldera=False,
        removal_timeout_seconds=removal_timeout_seconds,
    )
    return [resource.removeprefix("container:") for resource in removed]


def classify_replay(result: RunResult, *, final_namespace_clean: bool) -> str:
    """Classify a replay from execution evidence and lifecycle invariants."""
    if not result.teardown_clean or not final_namespace_clean:
        return "FAIL"
    if (
        result.total_techniques > 0
        and result.evidence_backed_successful == result.total_techniques
    ):
        return "PASS"
    if result.evidence_backed_successful > 0:
        return "PARTIAL"
    return "FAIL"


def finalize_campaign_namespace(*, isolate: bool) -> tuple[list[str], bool]:
    """Clean when requested, then independently observe the final namespace."""
    removed = (
        clean_stale_autosut_resources(include_caldera=True)
        if isolate
        else []
    )
    return removed, not stale_autosut_resources(include_caldera=isolate)


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
            "implementation_revision",
            "status",
            "status_successful",
            "evidence_backed_successful",
            "marker_only_successful",
            "caldera_driven_successful",
            "total",
            "fidelity_distribution",
            "final_namespace_clean",
            "cleanup_removed_resources",
            "elapsed_seconds",
            "evidence_manifest",
            "notes",
        ])
        for row in rows:
            writer.writerow([
                row.campaign_id,
                row.implementation_revision,
                row.status,
                row.successful,
                row.evidence_backed_successful,
                row.marker_only_successful,
                row.caldera_driven_successful,
                row.total,
                json.dumps(row.fidelity_distribution, sort_keys=True),
                str(row.final_namespace_clean).lower(),
                json.dumps(row.cleanup_removed_resources),
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
                              retain_at_root: bool,
                              collection_name: str | None = None) -> str:
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

    archive_root = evidence_root / (collection_name or "_reviewer_runs")
    archive_root.mkdir(parents=True, exist_ok=True)
    destination = archive_root / run_dir.name
    if destination.exists():
        suffix = 1
        while (archive_root / f"{run_dir.name}_{suffix}").exists():
            suffix += 1
        destination = archive_root / f"{run_dir.name}_{suffix}"
    shutil.move(str(run_dir), str(destination))
    return str(destination / manifest.name)


def validate_evidence_collection(args: argparse.Namespace) -> None:
    """Refuse ambiguous archival modes or a collection containing older runs."""
    if args.retain_run_evidence_at_root and args.evidence_collection:
        raise SystemExit(
            "--retain-run-evidence-at-root and --evidence-collection are mutually exclusive"
        )
    if not args.evidence_collection:
        return
    collection = RELEASE_DIR / "evidence" / args.evidence_collection
    if collection.exists() and any(collection.iterdir()):
        raise SystemExit(f"Evidence collection is not empty: {collection}")


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
    validate_evidence_collection(args)

    output_path = args.output or default_output_path()
    batch_revision = current_revision(PROJECT_ROOT)
    print("[preflight] implementation revision:", batch_revision)
    try:
        if args.clean_stale_autosut_containers:
            clean_stale_autosut_resources()
        else:
            stale = stale_autosut_resources()
            if stale:
                print("[preflight] stale autosut resources detected:",
                      ", ".join(stale))
                print("[preflight] rerun with --clean-stale-autosut-containers "
                      "after an interrupted local batch if these are not intentional.")
    except RuntimeError as exc:
        print(f"[preflight] namespace inspection failed: {exc}")
        return 2
    needs_caldera = bool(set(campaigns) & CALDERA_REQUIRED_CAMPAIGNS)
    preflight_ok = preflight(
        campaigns,
        needs_caldera=needs_caldera,
        start_caldera=(
            needs_caldera
            and not args.no_caldera_start
            and not args.isolate_campaigns
        ),
        defer_caldera=args.isolate_campaigns and not args.no_caldera_start,
    )
    if args.preflight_only:
        return 0 if preflight_ok else 2
    if not preflight_ok:
        print("[preflight] continuing would produce misleading failures; aborting.")
        return 2

    orch = build_default()
    rows: list[ReplayRow] = []
    for index, cid in enumerate(campaigns, start=1):
        campaign_revision = current_revision(PROJECT_ROOT)
        if campaign_revision != batch_revision:
            rows.append(ReplayRow(
                campaign_id=cid,
                implementation_revision=campaign_revision,
                status="ERROR",
                successful=0,
                evidence_backed_successful=0,
                marker_only_successful=0,
                caldera_driven_successful=0,
                total=0,
                fidelity_distribution={},
                final_namespace_clean=False,
                cleanup_removed_resources=[],
                elapsed_seconds=0.0,
                evidence_manifest="",
                notes=(
                    "implementation revision changed before campaign; "
                    f"batch_revision={batch_revision}"
                ),
            ))
            write_reports(rows, output_path)
            break
        print(f"\n=== Running {cid} ===")
        print(f"[batch] {index}/{len(campaigns)}")
        needs_campaign_caldera = cid in CALDERA_REQUIRED_CAMPAIGNS
        if args.isolate_campaigns:
            try:
                clean_stale_autosut_resources(include_caldera=True)
                reset_caldera_state()
            except RuntimeError as exc:
                rows.append(ReplayRow(
                    campaign_id=cid,
                    implementation_revision=batch_revision,
                    status="ERROR",
                    successful=0,
                    evidence_backed_successful=0,
                    marker_only_successful=0,
                    caldera_driven_successful=0,
                    total=0,
                    fidelity_distribution={},
                    final_namespace_clean=False,
                    cleanup_removed_resources=[],
                    elapsed_seconds=0.0,
                    evidence_manifest="",
                    notes=f"pre-run isolation failed: {exc}",
                ))
                write_reports(rows, output_path)
                if args.stop_on_failure:
                    break
                continue
        if needs_campaign_caldera and (args.restart_caldera_per_campaign
                                       or args.isolate_campaigns):
            print("[caldera] restarting C2 for campaign isolation ...")
            reset_caldera_state(remove_container=not args.isolate_campaigns)
            caldera_ready = (
                caldera_client.probe().api_ok
                if args.no_caldera_start
                else ensure_caldera_ready()
            )
            if not caldera_ready:
                rows.append(ReplayRow(
                    campaign_id=cid,
                    implementation_revision=batch_revision,
                    status="ERROR",
                    successful=0,
                    evidence_backed_successful=0,
                    marker_only_successful=0,
                    caldera_driven_successful=0,
                    total=0,
                    fidelity_distribution={},
                    final_namespace_clean=False,
                    cleanup_removed_resources=[],
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
            cleanup_removed: list[str] = []
            final_namespace_clean = False
            cleanup_error = ""
            try:
                cleanup_removed, final_namespace_clean = finalize_campaign_namespace(
                    isolate=args.isolate_campaigns
                )
            except RuntimeError as cleanup_exc:
                cleanup_error = f"; namespace finalization failed: {cleanup_exc}"
            rows.append(ReplayRow(
                campaign_id=cid,
                implementation_revision=batch_revision,
                status="ERROR",
                successful=0,
                evidence_backed_successful=0,
                marker_only_successful=0,
                caldera_driven_successful=0,
                total=0,
                fidelity_distribution={},
                final_namespace_clean=final_namespace_clean,
                cleanup_removed_resources=cleanup_removed,
                elapsed_seconds=elapsed,
                evidence_manifest="",
                notes=f"{type(exc).__name__}: {exc}{cleanup_error}",
            ))
            write_reports(rows, output_path)
            if args.stop_on_failure:
                break
            continue
        finally:
            restore_docker_platform(previous_platform)
        elapsed = time.monotonic() - t0
        cleanup_removed = []
        final_namespace_clean = False
        cleanup_error = ""
        try:
            cleanup_removed, final_namespace_clean = finalize_campaign_namespace(
                isolate=args.isolate_campaigns
            )
        except RuntimeError as exc:
            cleanup_error = str(exc)
        revision_after = current_revision(PROJECT_ROOT)
        revision_stable = revision_after == batch_revision
        status = (
            "ERROR"
            if cleanup_error or not revision_stable
            else classify_replay(
                result, final_namespace_clean=final_namespace_clean
            )
        )
        evidence_manifest = archive_reviewer_evidence(
            str(result.manifest_path),
            retain_at_root=args.retain_run_evidence_at_root,
            collection_name=args.evidence_collection,
        )
        notes = (
            f"status_success={result.successful}; "
            f"evidence_backed={result.evidence_backed_successful}; "
            f"marker_only={result.marker_only_successful}; "
            f"caldera_dispatched={result.caldera_driven_successful}; "
            f"run_teardown_clean={str(result.teardown_clean).lower()}; "
            f"cleanup_removed_resources={len(cleanup_removed)}; "
            f"revision_stable={str(revision_stable).lower()}"
        )
        if cleanup_error:
            notes += f"; namespace finalization failed: {cleanup_error}"
        if not revision_stable:
            notes += f"; observed_revision_after={revision_after}"
        rows.append(ReplayRow(
            campaign_id=cid,
            implementation_revision=batch_revision,
            status=status,
            successful=result.successful,
            evidence_backed_successful=result.evidence_backed_successful,
            marker_only_successful=result.marker_only_successful,
            caldera_driven_successful=result.caldera_driven_successful,
            total=result.total_techniques,
            fidelity_distribution=result.fidelity_distribution,
            final_namespace_clean=final_namespace_clean,
            cleanup_removed_resources=cleanup_removed,
            elapsed_seconds=elapsed,
            evidence_manifest=reviewer_path(evidence_manifest),
            notes=notes,
        ))
        write_reports(rows, output_path)
        print(
            f"[batch] {cid}: {status}; evidence "
            f"{result.evidence_backed_successful}/{result.total_techniques}; "
            f"status-success {result.successful}/{result.total_techniques}; "
            f"markers {result.marker_only_successful}; "
            f"Caldera {result.caldera_driven_successful}; "
            f"namespace clean={str(final_namespace_clean).lower()}; "
            f"{elapsed:.1f}s"
        )
        if status != "PASS" and args.stop_on_failure:
            break
        if not revision_stable:
            break

    print("\n" + "=" * 118)
    print(
        f"{'campaign':<35} {'status':<8} {'evidence':>10} "
        f"{'raw':>10} {'markers':>8} {'caldera':>8} {'clean':>7}  elapsed"
    )
    print("-" * 118)
    total_raw = total_evidence = total_markers = total_caldera = total_all = 0
    fidelity_sum: dict[str, int] = {}
    for row in rows:
        total_raw += row.successful
        total_evidence += row.evidence_backed_successful
        total_markers += row.marker_only_successful
        total_caldera += row.caldera_driven_successful
        total_all += row.total
        for k, v in row.fidelity_distribution.items():
            fidelity_sum[k] = fidelity_sum.get(k, 0) + v
        clean_label = "yes" if row.final_namespace_clean else "no"
        print(
            f"{row.campaign_id:<35} {row.status:<8} "
            f"{row.evidence_backed_successful:>3}/{row.total:<6d} "
            f"{row.successful:>3}/{row.total:<6d} "
            f"{row.marker_only_successful:>8d} "
            f"{row.caldera_driven_successful:>8d} "
            f"{clean_label:>7}  {row.elapsed_seconds:.1f}s"
        )
    print("-" * 118)
    fid_total = ", ".join(f"{k}={v}" for k, v in sorted(fidelity_sum.items()))
    print(
        f"{'TOTAL':<35} {'':<8} {total_evidence:>3}/{total_all:<6d} "
        f"{total_raw:>3}/{total_all:<6d} {total_markers:>8d} "
        f"{total_caldera:>8d}"
    )
    print(f"[batch] fidelity distribution: {fid_total or 'none'}")
    print(f"[batch] TSV report:  {output_path}")
    print(f"[batch] JSON report: {output_path.with_suffix('.json')}")
    print("=" * 88)
    return 0 if rows and all(row.status == "PASS" for row in rows) else 2


if __name__ == "__main__":
    raise SystemExit(main())
