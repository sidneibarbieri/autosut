#!/usr/bin/env python3
"""Audit the paper directory for build residue and unexpected result files."""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict, dataclass
from pathlib import Path


SCRIPT_ROOT = Path(__file__).resolve().parent.parent

ROOT_RESIDUE_NAMES = {
    "main.aux",
    "main.bbl",
    "main.blg",
    "main.fdb_latexmk",
    "main.fls",
    "main.log",
    "main.out",
    "main.run.xml",
    "main.synctex.gz",
}

ALLOWED_RESULTS_NAMES = {
    "orchestrated_batch_macros.tex",
    "review_evidence_macros.tex",
    "values.tex",
    "provenance_values.tex",
    "release_links.tex",
}


def resolve_paper_dir() -> Path:
    explicit = os.environ.get("PAPER_DIR")
    if explicit:
        return Path(explicit)

    workspace_root = SCRIPT_ROOT.parent
    for name in ("paper", "manuscript"):
        candidate = workspace_root / name
        if (candidate / "main.tex").exists():
            return candidate

    raise FileNotFoundError(
        "Cannot locate paper directory. Set PAPER_DIR env var or place the "
        "paper at workspace/paper/ or workspace/manuscript/."
    )


@dataclass
class PaperHygieneReport:
    paper_dir: str
    root_residue: list[str]
    results_extras: list[str]

    @property
    def clean(self) -> bool:
        return not self.root_residue and not self.results_extras


def check_root_residue(paper_dir: Path) -> list[str]:
    return sorted(name for name in ROOT_RESIDUE_NAMES if (paper_dir / name).exists())


def check_results_directory(paper_dir: Path) -> list[str]:
    results_dir = paper_dir / "results"
    if not results_dir.exists():
        return ["results/ (missing)"]

    extras: list[str] = []
    for entry in sorted(results_dir.iterdir()):
        if entry.name == ".DS_Store":
            continue
        if entry.name not in ALLOWED_RESULTS_NAMES:
            extras.append(f"results/{entry.name}")
    return extras


def audit_paper(paper_dir: Path) -> PaperHygieneReport:
    return PaperHygieneReport(
        paper_dir=str(paper_dir),
        root_residue=check_root_residue(paper_dir),
        results_extras=check_results_directory(paper_dir),
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    return parser.parse_args()


def print_human(report: PaperHygieneReport) -> None:
    status = "clean" if report.clean else "issues"
    print(f"[paper-hygiene] {report.paper_dir}: {status}")
    if report.root_residue:
        print(f"  root residue: {', '.join(report.root_residue)}")
    if report.results_extras:
        print(f"  results extras: {', '.join(report.results_extras)}")


def main() -> int:
    args = parse_args()
    paper_dir = resolve_paper_dir()
    report = audit_paper(paper_dir)

    if args.json:
        print(json.dumps(asdict(report) | {"clean": report.clean}, indent=2))
    else:
        print_human(report)

    return 0 if report.clean else 1


if __name__ == "__main__":
    raise SystemExit(main())
