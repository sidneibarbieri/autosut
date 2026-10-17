#!/usr/bin/env python3
"""Validate a recovery journal and every hash-bound evidence reference."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from infrastructure.failure_recovery import (  # noqa: E402
    RecoveryAttempt,
    RecoveryRun,
    load_journal,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("journal", type=Path)
    parser.add_argument(
        "--evidence-root",
        type=Path,
        required=True,
        help="root used to resolve and verify relative evidence references",
    )
    args = parser.parse_args()

    records = load_journal(args.journal)
    if not records:
        raise ValueError("recovery journal is empty")
    terminal_runs = []
    attempt_count = 0
    for record in records:
        if record.event_type == "attempt":
            attempt = RecoveryAttempt.model_validate(record.payload)
            for reference in attempt.observation.evidence:
                reference.verify(args.evidence_root)
            attempt_count += 1
        else:
            terminal_runs.append(RecoveryRun.model_validate(record.payload))
    if len(terminal_runs) != 1:
        raise ValueError("recovery journal must contain exactly one terminal run")
    terminal = terminal_runs[0]
    if len(terminal.attempts) != attempt_count:
        raise ValueError("journal attempts do not match the terminal run denominator")
    print(
        f"[recovery-journal] {attempt_count} attempts; "
        f"terminal={terminal.disposition.value}; recovered={terminal.recovered}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
