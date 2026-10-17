#!/usr/bin/env python3
"""Publish the generated study macros used by public reviewer interfaces."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE = (
    PROJECT_ROOT
    / "measurement"
    / "sut"
    / "scripts"
    / "results"
    / "todo_values_latex.tex"
)
DEFAULT_OUTPUT = PROJECT_ROOT / "release" / "study_values.tex"
MACRO_PATTERN = re.compile(r"\\newcommand\{\\([A-Za-z][A-Za-z0-9]+)\}\{[^}]*\}")


def validate_macro_source(text: str, source: Path) -> int:
    """Require a nonempty, unambiguous generated macro surface."""
    names = MACRO_PATTERN.findall(text)
    if not names:
        raise ValueError(f"no LaTeX macros found in {source}")
    duplicates = sorted({name for name in names if names.count(name) > 1})
    if duplicates:
        raise ValueError(f"duplicate LaTeX macros in {source}: {', '.join(duplicates)}")
    return len(names)


def publish(source: Path, output: Path) -> int:
    """Copy the measured macro file into the stable public release surface."""
    text = source.read_text(encoding="utf-8")
    count = validate_macro_source(text, source)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(text, encoding="utf-8")
    return count


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    count = publish(args.source, args.output)
    print(f"[study-values] published {count} macros to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
