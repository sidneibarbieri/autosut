#!/usr/bin/env python3
"""
Fidelity decision rubric for AutoSUT.

Implements a 5-criterion rubric per technique to determine whether the
execution fidelity is faithful, adapted, or inspired.  This is the
artifact's own methodological taxonomy, not ACM terminology.

The rubric answers five questions per technique:
  Q1. Was the central mechanism preserved?
  Q2. Was the relevant substrate preserved?
  Q3. Did the required preconditions exist in the SUT?
  Q4. Does the observed effect follow from the mechanism (not a shortcut)?
  Q5. Can the evidence be independently audited?

Decision logic:
  - 5/5 yes -> faithful
  - Q1 yes + Q3 yes + (Q2 or Q4 partial) -> adapted
  - Otherwise -> inspired

Also generates LaTeX tables for the paper and validates existing
fidelity labels against the rubric.
"""

import json
import sys
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import List

# Add the src root to the import path for direct CLI execution.
script_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(script_dir.parent))


@dataclass
class RubricAnswer:
    """Answer to one rubric question for one technique."""

    question_id: str
    question: str
    answer: bool
    justification: str


@dataclass
class TechniqueRubricResult:
    """Full rubric result for a single technique."""

    technique_id: str
    technique_name: str
    campaign_id: str
    answers: List[RubricAnswer]
    computed_fidelity: str
    declared_fidelity: str
    consistent: bool
    platform_mismatch: bool
    execution_mode: str

    @property
    def yes_count(self) -> int:
        return sum(1 for a in self.answers if a.answer)


RUBRIC_QUESTIONS = [
    ("Q1", "Was the central mechanism of the technique preserved?"),
    ("Q2", "Was the relevant substrate (OS, runtime, service) preserved?"),
    ("Q3", "Did the required preconditions arise operationally (not pre-staged)?"),
    (
        "Q4",
        "Does the observed effect follow from the mechanism, not a semantic shortcut?",
    ),
    ("Q5", "Can the evidence be independently audited and verified?"),
]


def compute_fidelity(answers: List[RubricAnswer]) -> str:
    """
    Apply decision logic to rubric answers.

    Key distinction (from methodology review):
    - faithful: mechanism + substrate + operational preconditions + real effect + auditable
    - adapted:  mechanism preserved, but preconditions are pre-staged (lab context)
    - inspired: mechanism or substrate diverge from original technique

    A lab environment with pre-staged credentials, deliberate weaknesses, and
    controlled topology means Q3 is "no" for most techniques — the preconditions
    were designed, not discovered. This is the lab-vs-wild distinction that
    separates adapted from faithful.
    """
    by_id = {a.question_id: a.answer for a in answers}

    q1 = by_id.get("Q1", False)
    q2 = by_id.get("Q2", False)
    q3 = by_id.get("Q3", False)
    q4 = by_id.get("Q4", False)
    q5 = by_id.get("Q5", False)

    # All 5 yes -> faithful (rare in lab setting)
    if all([q1, q2, q3, q4, q5]):
        return "faithful"

    # Mechanism + substrate + real effect, but lab preconditions -> adapted
    if q1 and q2 and q4:
        return "adapted"

    # Mechanism preserved but substrate differs -> adapted (borderline)
    if q1 and (q2 or q4) and not q2:
        return "adapted"

    return "inspired"


def build_rubric_for_executor(
    technique_id: str, campaign_id: str
) -> TechniqueRubricResult:
    """Build rubric result from executor metadata for a technique."""
    from executors.executor_registry import registry

    metadata = registry.get_metadata(technique_id)
    if not metadata:
        return TechniqueRubricResult(
            technique_id=technique_id,
            technique_name="Unknown",
            campaign_id=campaign_id,
            answers=[],
            computed_fidelity="inspired",
            declared_fidelity="unknown",
            consistent=False,
            platform_mismatch=False,
            execution_mode="unknown",
        )

    is_real = metadata.execution_mode.value == "real_controlled"
    is_state_bridge = metadata.execution_mode.value == "state_bridge"
    plat_mismatch = (
        metadata.original_platform in ("windows",) and metadata.platform == "linux"
    )

    # Q1: Central mechanism preserved?
    # Real controlled on native platform -> yes
    # Simulated -> depends on whether it's the same mechanism type
    q1_yes = is_real and not plat_mismatch
    q1_just = (
        "Real execution of technique mechanism on compatible platform"
        if q1_yes
        else (
            f"Platform mismatch: original={metadata.original_platform}, "
            f"execution={metadata.platform}"
            if plat_mismatch
            else f"Execution mode: {metadata.execution_mode.value}"
        )
    )

    # Q2: Relevant substrate preserved?
    q2_yes = not plat_mismatch and metadata.platform in ("linux", "any")
    q2_just = (
        "Substrate matches technique requirements"
        if q2_yes
        else f"Substrate mismatch: technique requires {metadata.original_platform}"
    )

    # Q3: Preconditions arise operationally (not pre-staged)?
    # In a lab setting, preconditions are deliberately configured by the SUT
    # profile (weak passwords, staged files, known credentials). This is the
    # lab-vs-wild distinction: in the real world, the attacker discovers or
    # creates these conditions. In the lab, they are pre-staged.
    q3_yes = False  # Lab context: preconditions are always pre-staged
    q3_just = (
        "Lab context: preconditions (credentials, files, weaknesses) are "
        "pre-staged by SUT profile, not discovered operationally"
    )

    # Q4: Effect follows from mechanism?
    q4_yes = is_real and not is_state_bridge
    q4_just = (
        "Effect produced by actual execution of technique"
        if q4_yes
        else (
            "State bridge: effect is a marker, not operational result"
            if is_state_bridge
            else "Simulated: log entry rather than operational effect"
        )
    )

    # Q5: Evidence auditable?
    q5_yes = True  # All executors produce artifacts and logs
    q5_just = (
        "Executor produces artifacts, logs, timestamps, and fidelity justification"
    )

    answers = [
        RubricAnswer("Q1", RUBRIC_QUESTIONS[0][1], q1_yes, q1_just),
        RubricAnswer("Q2", RUBRIC_QUESTIONS[1][1], q2_yes, q2_just),
        RubricAnswer("Q3", RUBRIC_QUESTIONS[2][1], q3_yes, q3_just),
        RubricAnswer("Q4", RUBRIC_QUESTIONS[3][1], q4_yes, q4_just),
        RubricAnswer("Q5", RUBRIC_QUESTIONS[4][1], q5_yes, q5_just),
    ]

    computed = compute_fidelity(answers)
    declared = metadata.execution_fidelity.value

    return TechniqueRubricResult(
        technique_id=technique_id,
        technique_name=metadata.technique_name,
        campaign_id=campaign_id,
        answers=answers,
        computed_fidelity=computed,
        declared_fidelity=declared,
        consistent=(computed == declared),
        platform_mismatch=plat_mismatch,
        execution_mode=metadata.execution_mode.value,
    )


def validate_campaign_fidelity(campaign_id: str) -> List[TechniqueRubricResult]:
    """Run rubric on all techniques in a campaign, check consistency."""
    from loaders.campaign_loader import load_campaign

    campaign = load_campaign(campaign_id)
    results = []
    for step in campaign.steps:
        result = build_rubric_for_executor(step.technique_id, campaign_id)
        results.append(result)

    return results


# ---------------------------------------------------------------------------
# LaTeX table generator
# ---------------------------------------------------------------------------


def generate_latex_table(
    results: List[TechniqueRubricResult], caption: str = ""
) -> str:
    """Generate LaTeX tabular for per-technique fidelity (paper-ready)."""
    lines = []
    lines.append(r"\begin{table}[htbp]")
    lines.append(r"\centering")
    lines.append(
        r"\caption{" + (caption or "Per-technique fidelity classification") + "}"
    )
    lines.append(r"\label{tab:fidelity}")
    lines.append(r"\small")
    lines.append(r"\begin{tabular}{llcccccl}")
    lines.append(r"\toprule")
    lines.append(
        r"\textbf{Technique} & \textbf{Name} & "
        r"\textbf{Q1} & \textbf{Q2} & \textbf{Q3} & \textbf{Q4} & \textbf{Q5} & "
        r"\textbf{Fidelity} \\"
    )
    lines.append(r"\midrule")

    for r in results:
        marks = []
        for a in r.answers:
            marks.append(r"\cmark" if a.answer else r"\xmark")
        fid_label = r"\textsc{" + r.computed_fidelity + "}"
        name_escaped = r.technique_name.replace("&", r"\&")
        line = (
            f"{r.technique_id} & {name_escaped} & "
            f"{' & '.join(marks)} & {fid_label} \\\\"
        )
        if not r.consistent:
            line += r" % MISMATCH: declared=" + r.declared_fidelity
        lines.append(line)

    lines.append(r"\bottomrule")
    lines.append(r"\end{tabular}")
    lines.append(r"\end{table}")

    return "\n".join(lines)


def generate_latex_legend() -> str:
    """Generate LaTeX legend explaining rubric questions."""
    lines = [
        r"\noindent\textbf{Rubric questions:}",
        r"\begin{description}[nosep,leftmargin=1em]",
    ]
    for qid, question in RUBRIC_QUESTIONS:
        lines.append(f"  \\item[{qid}] {question}")
    lines.append(r"\end{description}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main():
    import argparse

    parser = argparse.ArgumentParser(description="AutoSUT fidelity rubric")
    parser.add_argument("--campaign", help="Campaign ID to evaluate")
    parser.add_argument("--all", action="store_true", help="Evaluate all campaigns")
    parser.add_argument("--latex", action="store_true", help="Output LaTeX table")
    parser.add_argument("--json", action="store_true", help="Output JSON report")
    parser.add_argument("--output", help="Output file path")

    args = parser.parse_args()

    from loaders.campaign_loader import list_campaigns

    if not args.campaign and not args.all:
        print("Available campaigns:")
        for cid in list_campaigns():
            print(f"  - {cid}")
        return 0

    campaign_ids = list_campaigns() if args.all else [args.campaign]

    all_results = []
    for cid in campaign_ids:
        results = validate_campaign_fidelity(cid)
        all_results.extend(results)

        # Console summary
        inconsistent = [r for r in results if not r.consistent]
        print(f"\n{'=' * 60}")
        print(f"  FIDELITY RUBRIC: {cid}")
        print(f"{'=' * 60}")

        for r in results:
            marks = "".join("Y" if a.answer else "N" for a in r.answers)
            consistency = "" if r.consistent else " ** MISMATCH **"
            print(
                f"  {r.technique_id:12s} [{marks}] "
                f"computed={r.computed_fidelity:10s} "
                f"declared={r.declared_fidelity:10s}{consistency}"
            )

        if inconsistent:
            print(
                f"\n  WARNING: {len(inconsistent)} techniques have mismatched fidelity"
            )
        else:
            print(
                f"\n  All {len(results)} techniques: rubric matches declared fidelity"
            )

    # LaTeX output
    if args.latex:
        all_latex_parts = []
        for idx, cid in enumerate(campaign_ids):
            campaign_results = [r for r in all_results if r.campaign_id == cid]
            label_suffix = cid.replace(".", "_")
            latex = generate_latex_table(
                campaign_results,
                caption=f"Per-technique fidelity classification for campaign \\texttt{{{cid}}}",
            )
            # Make labels unique per campaign
            latex = latex.replace("tab:fidelity", f"tab:fidelity_{label_suffix}")
            all_latex_parts.append(f"% === Campaign: {cid} ===\n{latex}")

        combined = "\n\n".join(all_latex_parts) + "\n\n" + generate_latex_legend()

        if args.output:
            outpath = Path(args.output)
            outpath.parent.mkdir(parents=True, exist_ok=True)
            with open(outpath, "w") as f:
                f.write(combined)
            print(f"\n[LATEX] Written to {outpath}")
        else:
            print(combined)

    # JSON output
    if args.json:
        report = {
            "generated_at": datetime.now().isoformat(),
            "campaigns": {},
        }
        for cid in campaign_ids:
            campaign_results = [r for r in all_results if r.campaign_id == cid]
            report["campaigns"][cid] = {
                "total": len(campaign_results),
                "consistent": sum(1 for r in campaign_results if r.consistent),
                "mismatches": sum(1 for r in campaign_results if not r.consistent),
                "distribution": {},
                "techniques": [asdict(r) for r in campaign_results],
            }
            for r in campaign_results:
                fid = r.computed_fidelity
                report["campaigns"][cid]["distribution"][fid] = (
                    report["campaigns"][cid]["distribution"].get(fid, 0) + 1
                )

        if args.output:
            outpath = Path(args.output)
            outpath.parent.mkdir(parents=True, exist_ok=True)
            with open(outpath, "w") as f:
                json.dump(report, f, indent=2, default=str)
            print(f"\n[JSON] Written to {outpath}")
        else:
            print(json.dumps(report, indent=2, default=str))

    return 0


if __name__ == "__main__":
    sys.exit(main())
