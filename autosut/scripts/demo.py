#!/usr/bin/env python3
"""Show the environment semantics gap in a form a reader can follow live.

The reviewer check verifies that the artifact is intact. This shows what the artifact found: public
threat intelligence says which platform a technique runs on almost every time, and says almost
nothing about what that platform must actually provide. The distance between those two facts is the
work an analyst still has to do before a campaign can be replayed.

Values are read from the generated manuscript macros, so the demonstration, the dashboard, and the
paper report the same numbers by construction. Nothing is recomputed here.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
# The public artifact ships this generated value surface; a paper checkout is
# intentionally neither required nor assumed by the reviewer path.
DEFAULT_VALUES = PROJECT_ROOT / "release" / "study_values.tex"
RULE = "-" * 78


def load_values(path: Path) -> dict[str, str]:
    """Read the generated \\newcommand macros into a plain mapping."""
    pattern = re.compile(r"\\newcommand\{\\([A-Za-z]+)\}\{([^}]*)\}")
    return dict(pattern.findall(path.read_text(encoding="utf-8")))


def require(values: dict[str, str], name: str) -> str:
    """Fail loudly when the manuscript no longer defines a value the demonstration reports."""
    if name not in values:
        raise KeyError(f"{name} is not defined in the generated values; regenerate the artifact")
    return values[name]


def print_gradient(values: dict[str, str]) -> None:
    techniques = require(values, "enterpriseplatformcount")
    campaigns = require(values, "enterpriseactivecampaigncount")
    rows = [
        (
            "Which platform does this technique run on?",
            f"{require(values, 'enterpriseplatformpct')}%",
            f"of {techniques} techniques",
        ),
        (
            "What must that platform actually provide?",
            f"{require(values, 'enterprisesystemrequirementspct')}%",
            f"of {techniques} techniques",
        ),
        (
            "Which version of the software is it?",
            f"{require(values, 'softwarewithversionsignalpercentage')}%",
            "of active software objects",
        ),
        (
            "Which vulnerability does the campaign exploit?",
            f"{require(values, 'entcampaignswithcvepct')}%",
            f"of {campaigns} campaigns, after text extraction",
        ),
    ]
    print(RULE)
    print("WHAT PUBLIC THREAT INTELLIGENCE ANSWERS, AND WHAT IT LEAVES OPEN")
    print(RULE)
    print(f"  {'question a replay must answer':<48}{'answered':>10}  population")
    for question, answered, population in rows:
        print(f"  {question:<48}{answered:>10}  {population}")
    print(
        "\n  The intelligence names the operating system almost every time. It states what the"
        "\n  technique needs from that system almost never. Replay needs the second answer."
    )


def print_routing(values: dict[str, str]) -> None:
    by_rule = require(values, "compatibilityrulecoveragepercentage")
    by_fallback = require(values, "compatibilityfallbackassignmentpercentage")
    print()
    print(RULE)
    print("WHY A COVERAGE NUMBER CAN LOOK COMPLETE AND MEAN LITTLE")
    print(RULE)
    print(f"  labelled by an explicit rule, from evidence      {by_rule}%")
    print(f"  labelled by a conservative fallback, no evidence {by_fallback}%")
    print(
        "\n  Every technique receives a routing label, so coverage reads as total. Two thirds of it"
        "\n  is a default applied where the evidence was silent. Routing coverage and environment"
        "\n  evidence are different quantities and the artifact reports them apart."
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--values", default=str(DEFAULT_VALUES))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    values = load_values(Path(args.values))
    print()
    print_gradient(values)
    print_routing(values)
    print()
    print(RULE)
    print("Structured intelligence narrows the candidate environment. It does not determine one.")
    print("What remains is an analyst commitment, and the artifact records it as such.")
    print(RULE)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
