#!/usr/bin/env python3
"""Validate or explicitly synchronize paper macros from measurement outputs."""

from __future__ import annotations

import argparse
import json
import os
import re
from dataclasses import asdict, dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
REPO_ROOT = PROJECT_ROOT.parent

MEASUREMENT_VALUES = (
    PROJECT_ROOT / "measurement" / "sut" / "scripts" / "results" / "todo_values_latex.tex"
)
OUTPUT_JSON = PROJECT_ROOT / "results" / "manuscript_values_sync.json"
OUTPUT_MD = PROJECT_ROOT / "results" / "MANUSCRIPT_VALUES_SYNC.md"

MACRO_DEFINITION = re.compile(r"\\newcommand\{\\([A-Za-z][A-Za-z0-9]+)\}\{([^}]*)\}")
MACRO_USE = re.compile(r"\\([A-Za-z][A-Za-z0-9]+)")
TEX_INCLUDE = re.compile(r"\\(?:input|include)\{([^}]+)\}")


def resolve_paper_dir() -> Path:
    explicit = os.environ.get("PAPER_DIR")
    if explicit:
        candidate = Path(explicit)
        if candidate.exists():
            return candidate

    for root in (REPO_ROOT, PROJECT_ROOT):
        for name in ("paper", "manuscript"):
            candidate = root / name
            if (candidate / "main.tex").exists():
                return candidate

    raise FileNotFoundError(
        "Cannot locate paper directory. Set PAPER_DIR or place the paper at " "workspace/paper/."
    )


@dataclass
class SyncResult:
    status: str
    details: str
    macros_written: int = 0


def extract_macros(text: str) -> dict[str, str]:
    return {match.group(1): match.group(2) for match in MACRO_DEFINITION.finditer(text)}


def extract_used_macros(text: str) -> set[str]:
    return set(MACRO_USE.findall(text))


def read_active_manuscript_sources(paper_dir: Path) -> str:
    """Read main.tex and recursively included source, excluding definitions.

    `results/*.tex` files define macros and would make every definition look
    like a use. They are deliberately excluded; included figure templates are
    retained so their measurement macros participate in the read-only check.
    """
    root = paper_dir.resolve()
    pending = [root / "main.tex"]
    seen: set[Path] = set()
    texts: list[str] = []

    while pending:
        source = pending.pop()
        source = source.resolve()
        if source in seen or not source.is_file():
            continue
        try:
            relative = source.relative_to(root)
        except ValueError:
            continue
        if relative.parts and relative.parts[0] == "results":
            continue

        seen.add(source)
        text = source.read_text(encoding="utf-8")
        texts.append(text)
        for raw_target in TEX_INCLUDE.findall(text):
            target = Path(raw_target.strip())
            if not target.suffix:
                target = target.with_suffix(".tex")
            candidates = (root / target, source.parent / target)
            included = next((path for path in candidates if path.is_file()), None)
            if included is not None:
                pending.append(included)

    return "\n".join(texts)


def sync_paper(paper_dir: Path, *, check: bool = False) -> SyncResult:
    measurement_text = MEASUREMENT_VALUES.read_text(encoding="utf-8")
    paper_values = paper_dir / "results" / "values.tex"
    paper_text = paper_values.read_text(encoding="utf-8")
    manuscript_text = read_active_manuscript_sources(paper_dir)

    measurement_macros = extract_macros(measurement_text)
    paper_macros = extract_macros(paper_text)
    used_macros = extract_used_macros(manuscript_text)
    manuscript_macros = sorted(set(paper_macros) & used_macros)
    missing_from_measurement = sorted(set(manuscript_macros) - set(measurement_macros))
    missing_from_paper = sorted((set(measurement_macros) & used_macros) - set(paper_macros))

    if missing_from_measurement:
        return SyncResult(
            status="blocked",
            details=(
                "Paper uses macros not defined by the measurement pipeline output "
                f"({MEASUREMENT_VALUES.relative_to(PROJECT_ROOT)}): "
                + ", ".join(missing_from_measurement)
            ),
        )

    if missing_from_paper:
        return SyncResult(
            status="blocked",
            details=(
                "Paper uses measurement macros missing from results/values.tex: "
                + ", ".join(missing_from_paper)
            ),
        )

    mismatches = [
        (name, paper_macros[name], measurement_macros[name])
        for name in manuscript_macros
        if paper_macros[name] != measurement_macros[name]
    ]

    if check and mismatches:
        preview = "; ".join(
            f"{name}: paper={paper_value!r}, measured={measurement_value!r}"
            for name, paper_value, measurement_value in mismatches[:12]
        )
        if len(mismatches) > 12:
            preview += f"; ... and {len(mismatches) - 12} more"
        return SyncResult(
            status="out_of_sync",
            details=(
                f"{len(mismatches)} manuscript-used macro value(s) differ from "
                f"the measurement output: {preview}"
            ),
            macros_written=len(measurement_macros),
        )

    if check:
        status = "current"
        details = (
            "Every manuscript-used measurement macro matches results/values.tex "
            "(read-only check)."
        )
    elif paper_text == measurement_text:
        status = "current"
        details = "Paper values.tex already matches measurement pipeline output."
    else:
        paper_values.write_text(measurement_text, encoding="utf-8")
        status = "updated"
        details = "Paper values.tex replaced from measurement pipeline output."

    return SyncResult(status=status, details=details, macros_written=len(measurement_macros))


def write_report(result: SyncResult, report_dir: Path | None = None) -> tuple[Path, Path]:
    output_json = (report_dir / OUTPUT_JSON.name) if report_dir else OUTPUT_JSON
    output_md = (report_dir / OUTPUT_MD.name) if report_dir else OUTPUT_MD
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps({"result": asdict(result)}, indent=2), encoding="utf-8")

    lines = [
        "# Manuscript Values Sync",
        "",
        f"- Status: `{result.status}`",
        f"- Macros written: `{result.macros_written}`",
        f"- Details: {result.details}",
        "",
    ]
    output_md.write_text("\n".join(lines), encoding="utf-8")
    return output_json, output_md


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--report-dir",
        type=Path,
        help="directory for validation reports (keeps a sealed package unchanged)",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--check",
        action="store_true",
        help="validate manuscript-used macro values without modifying the paper",
    )
    mode.add_argument(
        "--dry-run",
        action="store_true",
        help="deprecated alias for --check",
    )
    args = parser.parse_args()

    paper_dir = resolve_paper_dir()
    result = sync_paper(paper_dir, check=args.check or args.dry_run)
    output_json, output_md = write_report(result, args.report_dir)

    print(f"Status: {result.status}")
    print(f"Details: {result.details}")
    print(f"Wrote {output_json}")
    print(f"Wrote {output_md}")
    return 1 if result.status in {"blocked", "out_of_sync"} else 0


if __name__ == "__main__":
    raise SystemExit(main())
