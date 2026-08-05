#!/usr/bin/env python3
"""Index all preserved campaign runs into a single experiment log.

Walks release/evidence/<campaign>_<timestamp>/ directories, extracts the
summary and manifest of each run, and emits a JSONL log plus a human-readable
markdown table. Reviewers can use the log to verify which experiments produced
the numbers in the paper.
"""

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
EVIDENCE_DIR = PROJECT_ROOT / "release" / "evidence"
LOG_JSONL = PROJECT_ROOT / "release" / "EXPERIMENT_LOG.jsonl"
LOG_MD = PROJECT_ROOT / "release" / "EXPERIMENT_LOG.md"


@dataclass
class RunEntry:
    run_id: str
    campaign_id: str
    timestamp: str
    total_techniques: int
    successful: int
    failed: int
    skipped: int
    fidelity_distribution: dict
    evidence_directory: str
    summary_file: str
    manifest_file: str
    has_health_check: bool


def parse_timestamp(stamp: str) -> str:
    try:
        return datetime.strptime(stamp, "%Y%m%d_%H%M%S").isoformat()
    except ValueError:
        return stamp


def index_run(run_dir: Path) -> RunEntry | None:
    manifest_path = run_dir / "manifest.json"
    summary_path = run_dir / "summary.json"
    if not manifest_path.exists():
        return None

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    health_path = EVIDENCE_DIR / f"health_{run_dir.name}.json"

    return RunEntry(
        run_id=run_dir.name,
        campaign_id=manifest.get("campaign_id", ""),
        timestamp=parse_timestamp(manifest.get("timestamp", "")),
        total_techniques=manifest.get("total_techniques", 0),
        successful=manifest.get("successful", 0),
        failed=manifest.get("failed", 0),
        skipped=manifest.get("skipped", 0),
        fidelity_distribution=manifest.get("fidelity_distribution", {}),
        evidence_directory=str(run_dir.relative_to(PROJECT_ROOT)),
        summary_file=str(summary_path.relative_to(PROJECT_ROOT)) if summary_path.exists() else "",
        manifest_file=str(manifest_path.relative_to(PROJECT_ROOT)),
        has_health_check=health_path.exists(),
    )


def collect_runs() -> list[RunEntry]:
    runs: list[RunEntry] = []
    for run_dir in sorted(EVIDENCE_DIR.iterdir()):
        if not run_dir.is_dir():
            continue
        entry = index_run(run_dir)
        if entry is not None:
            runs.append(entry)
    return runs


def current_git_commit() -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (subprocess.SubprocessError, FileNotFoundError):
        pass
    return ""


def write_jsonl(runs: list[RunEntry]) -> None:
    LOG_JSONL.parent.mkdir(parents=True, exist_ok=True)
    with LOG_JSONL.open("w", encoding="utf-8") as handle:
        for run in runs:
            handle.write(json.dumps(asdict(run), ensure_ascii=False) + "\n")


def write_markdown(runs: list[RunEntry]) -> None:
    indexed_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    commit = current_git_commit() or "(no git repository)"
    lines = [
        "# Experiment Log",
        "",
        f"Indexed at: `{indexed_at}`",
        f"Current commit: `{commit}`",
        f"Total runs: **{len(runs)}**",
        "",
        "Each row is one preserved campaign execution. Inspect the `summary.json` "
        "for technique-level outcomes (status, fidelity, artifacts, timing). The "
        "manifest is the run-level overview.",
        "",
        "| Run ID | Campaign | Timestamp | Total | Pass | Fail | Skip | Fidelity | Evidence |",
        "|--------|----------|-----------|-------|------|------|------|----------|----------|",
    ]
    for run in runs:
        fidelity = ", ".join(f"{k}={v}" for k, v in run.fidelity_distribution.items()) or "-"
        lines.append(
            f"| `{run.run_id}` | `{run.campaign_id}` | {run.timestamp} | "
            f"{run.total_techniques} | {run.successful} | {run.failed} | "
            f"{run.skipped} | {fidelity} | `{run.evidence_directory}` |"
        )
    lines.append("")
    LOG_MD.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    if not EVIDENCE_DIR.exists():
        print(f"[experiment-log] no evidence directory at {EVIDENCE_DIR}", file=sys.stderr)
        return 1

    runs = collect_runs()
    if not runs:
        print("[experiment-log] no runs found to index", file=sys.stderr)
        return 1

    write_jsonl(runs)
    write_markdown(runs)
    print(f"[experiment-log] indexed {len(runs)} runs")
    print(f"[experiment-log] wrote {LOG_JSONL.relative_to(PROJECT_ROOT)}")
    print(f"[experiment-log] wrote {LOG_MD.relative_to(PROJECT_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
