#!/usr/bin/env python3
"""Enforce bibliography hygiene policies for the manuscript.

Current policy:
- reject/remove BibTeX entries whose title contains the word "poster"
  (case-insensitive), including common forms like "{POSTER:} ...".

Usage examples:
  # Check-only mode (non-zero exit if violations are present)
  python3 sanitize_bibliography_policy.py --input references.bib --check

  # In-place sanitization
  python3 sanitize_bibliography_policy.py --input references_official_downloaded.bib --write
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Tuple


ENTRY_START_RE = re.compile(r"(?m)^@")
ENTRY_KEY_RE = re.compile(r"@\w+\s*\{\s*([^,\s]+)\s*,")
POSTER_TITLE_RE = re.compile(
    r"(?is)\btitle\s*=\s*[{\"].*?\bposter\b",
)
POSTER_MARKER_RE = re.compile(r"(?i)\bposter\b\s*:")


@dataclass(frozen=True)
class Violation:
    key: str
    reason: str


def iter_entries(text: str) -> Iterable[Tuple[int, int, str]]:
    """Yield (start, end, block) for each BibTeX entry-like block."""
    starts = [m.start() for m in ENTRY_START_RE.finditer(text)]
    if not starts:
        return
    starts.append(len(text))
    for i in range(len(starts) - 1):
        start = starts[i]
        end = starts[i + 1]
        yield start, end, text[start:end]


def entry_key(block: str) -> str | None:
    m = ENTRY_KEY_RE.match(block.lstrip())
    if not m:
        return None
    return m.group(1).strip()


def detect_violation(block: str) -> Violation | None:
    key = entry_key(block)
    if not key:
        return None

    if POSTER_MARKER_RE.search(block):
        return Violation(key=key, reason="poster marker")
    if POSTER_TITLE_RE.search(block):
        return Violation(key=key, reason="poster title")
    return None


def sanitize_text(text: str) -> Tuple[str, List[Violation]]:
    starts = [m.start() for m in ENTRY_START_RE.finditer(text)]
    if not starts:
        return text, []

    out_parts: List[str] = [text[: starts[0]]]
    violations: List[Violation] = []
    starts.append(len(text))

    for i in range(len(starts) - 1):
        start = starts[i]
        end = starts[i + 1]
        block = text[start:end]
        violation = detect_violation(block)
        if violation is not None:
            violations.append(violation)
            continue
        out_parts.append(block)

    sanitized = "".join(out_parts)
    if sanitized and not sanitized.endswith("\n"):
        sanitized += "\n"
    return sanitized, violations


def process_file(path: Path, write: bool) -> Tuple[int, List[Violation]]:
    original = path.read_text(encoding="utf-8")
    sanitized, violations = sanitize_text(original)

    if write and violations:
        path.write_text(sanitized, encoding="utf-8")

    return len(violations), violations


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        action="append",
        required=True,
        help="BibTeX file path to validate/sanitize (repeatable).",
    )
    mode = parser.add_mutually_exclusive_group(required=False)
    mode.add_argument(
        "--check",
        action="store_true",
        help="Check-only mode (default): fail if violations are found.",
    )
    mode.add_argument(
        "--write",
        action="store_true",
        help="Sanitize files in-place by removing violating entries.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    check_mode = args.check or not args.write

    total = 0
    for raw in args.input:
        path = Path(raw)
        if not path.exists():
            print(f"[bib-policy][FAIL] missing file: {path}")
            return 2

        count, violations = process_file(path, write=args.write)
        total += count

        if violations:
            keys = ", ".join(v.key for v in violations)
            action = "removed" if args.write else "found"
            print(f"[bib-policy] {path.name}: {action} {count} violating entries ({keys})")
        else:
            print(f"[bib-policy] {path.name}: OK")

    if total > 0 and check_mode:
        print(f"[bib-policy][FAIL] detected {total} violating entries")
        return 1

    print(f"[bib-policy] done (violations={total}, mode={'write' if args.write else 'check'})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
