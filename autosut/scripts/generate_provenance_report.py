#!/usr/bin/env python3
"""Generate the environment-provenance report from the catalog (no live run).

This is the load-bearing measurement for AutoSUT's environment-gap argument.
For every campaign it flattens the concrete SUT into per-element provenance
tags, then rolls them up into a dimension x source table that answers the
question almost no adversary-emulation paper answers explicitly:

    *How much of the executable environment actually came from the CTI corpus,
     versus had to be concretized by AutoSUT or authored by the analyst?*

It reads :mod:`orchestrator.catalog` directly (the single source of truth for
campaign -> SUTProfile), so it needs no Docker and no live run. The provenance
data is fully deterministic --- two invocations emit identical tags, counts,
element ordering, and a source-date-controlled ``generated_at`` value. Results
land under ``release/provenance/``:

  * ``environment_provenance.json`` -- per-campaign + global summaries, each
    carrying the full per-element audit trail so every count is traceable down
    to one concrete SUT element.
  * ``support_matrix.csv`` -- dimension x source counts (global), the stable
    machine-readable table (always all four sources, in enum order).
  * ``ENVIRONMENT_PROVENANCE.md`` -- the human-facing dimension table the paper
    reports.
  * ``provenance_values.tex`` -- LaTeX macros for manuscript text that reports
    the same provenance surface.

Provenance is COUNTED, never invented: the only derived tags are definitional
(a real CVE id is corpus evidence; an OS family is an ATT&CK platform). See
``orchestrator/provenance.py`` for the contract.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

from release_clock import release_isoformat

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))

from orchestrator import catalog, provenance  # noqa: E402
from orchestrator.provenance import DIMENSIONS, ProvenanceSummary  # noqa: E402

DEFAULT_OUT = PROJECT_ROOT / "release" / "provenance"

# Display order separates evidence in the evaluated CTI snapshot from evidence
# imported from external advisories.  Collapsing those categories would inflate
# corpus-derived coverage.
_SOURCE_ORDER = [
    "corpus_supported", "external_reference", "autosut_concretized",
    "analyst_authored", "inferred",
]
_SOURCE_LABEL = {
    "corpus_supported": "Corpus",
    "external_reference": "External",
    "autosut_concretized": "AutoSUT",
    "analyst_authored": "Analyst",
    "inferred": "Inferred",
}
_DIM_LABEL = {
    "platform": "Platform",
    "software": "Software",
    "vulnerability": "Vulnerability",
    "credentials": "Credentials",
    "exposures": "Exposures",
    "artifacts": "Artifacts",
    "topology": "Topology",
}

# dmz_segmentation_demo is the topology reference. It is deliberately NOT in
# implemented_campaigns() (it is a topology demo, not a frozen-corpus port), but
# it is the only campaign that exercises the topology dimension, so include it
# explicitly --- otherwise the table's most analyst-heavy row reads empty.
_EXTRA_CAMPAIGNS = ["0.dmz_segmentation_demo"]


def _campaign_ids() -> list[str]:
    ids = list(catalog.implemented_campaigns())
    for extra in _EXTRA_CAMPAIGNS:
        if extra not in ids:
            ids.append(extra)
    return ids


def collect_summaries() -> tuple[list[ProvenanceSummary], list[str]]:
    """Resolve every campaign and summarize its SUT. Campaigns that are
    declared-but-not-implemented (resolve raises NotImplementedError) are
    reported as skipped rather than silently dropped."""
    summaries: list[ProvenanceSummary] = []
    skipped: list[str] = []
    for cid in _campaign_ids():
        try:
            _, sut, cves = catalog.resolve(cid)
        except NotImplementedError:
            skipped.append(cid)
            continue
        summaries.append(
            provenance.summarize_profile(sut, campaign_id=cid, cves=cves)
        )
    return summaries, skipped


def _human_sources(merged: ProvenanceSummary) -> list[str]:
    """Return the evidence columns, hiding unused heuristic inference."""
    shown = [s for s in _SOURCE_ORDER if s != "inferred"]
    if merged.by_source.get("inferred", 0) > 0:
        shown.append("inferred")
    return shown


def write_json(path: Path, summaries: list[ProvenanceSummary],
               merged: ProvenanceSummary, skipped: list[str]) -> None:
    payload = {
        "generated_at": release_isoformat(),
        "policy": "evidence_4category",
        "dimensions": list(DIMENSIONS),
        "skipped_unimplemented": skipped,
        "global": merged.model_dump(),
        "campaigns": [s.model_dump() for s in summaries],
    }
    path.write_text(json.dumps(payload, indent=2) + "\n")


def write_csv(path: Path, merged: ProvenanceSummary) -> None:
    # Stable machine schema: always all four sources, in enum order, plus an
    # ALL summary row. Downstream parsers can rely on this header forever.
    fieldnames = ["dimension", "total", *_SOURCE_ORDER]
    with path.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        for row in provenance.support_matrix_rows(merged):
            writer.writerow({key: row.get(key, 0) for key in fieldnames})
        total_row: dict[str, object] = {
            "dimension": "ALL", "total": merged.total_elements,
        }
        for source in _SOURCE_ORDER:
            total_row[source] = merged.by_source.get(source, 0)
        writer.writerow(total_row)


def _latex_macro(name: str, value: int | float) -> str:
    return f"\\newcommand{{\\{name}}}{{{value}}}"


def _dimension_count(merged: ProvenanceSummary, dimension: str,
                     source: str | None = None) -> int:
    counts = merged.by_dimension.get(dimension, {})
    if source is None:
        return sum(counts.values())
    return counts.get(source, 0)


def write_latex(path: Path, summaries: list[ProvenanceSummary],
                merged: ProvenanceSummary) -> None:
    pct = merged.percentages
    lines = [
        "% Auto-generated environment-provenance values",
        "% Source: autosut/scripts/generate_provenance_report.py",
        _latex_macro("provenanceprofilecount", len(summaries)),
        _latex_macro("provenancetotalelementcount", merged.total_elements),
        _latex_macro("provenancecorpussupportedcount",
                     merged.by_source.get("corpus_supported", 0)),
        _latex_macro("provenancecorpussupportedpct",
                     pct.get("corpus_supported", 0.0)),
        _latex_macro("provenanceexternalreferencecount",
                     merged.by_source.get("external_reference", 0)),
        _latex_macro("provenanceexternalreferencepct",
                     pct.get("external_reference", 0.0)),
        _latex_macro("provenanceautosutconcretizedcount",
                     merged.by_source.get("autosut_concretized", 0)),
        _latex_macro("provenanceautosutconcretizedpct",
                     pct.get("autosut_concretized", 0.0)),
        _latex_macro("provenanceanalystauthoredcount",
                     merged.by_source.get("analyst_authored", 0)),
        _latex_macro("provenanceanalystauthoredpct",
                     pct.get("analyst_authored", 0.0)),
        _latex_macro("provenanceplatformtotal",
                     _dimension_count(merged, "platform")),
        _latex_macro("provenanceplatformcorpus",
                     _dimension_count(merged, "platform", "corpus_supported")),
        _latex_macro("provenancetopologytotal",
                     _dimension_count(merged, "topology")),
        _latex_macro("provenancetopologyanalyst",
                     _dimension_count(merged, "topology", "analyst_authored")),
        _latex_macro("provenanceartifacttotal",
                     _dimension_count(merged, "artifacts")),
        _latex_macro("provenanceartifactanalyst",
                     _dimension_count(merged, "artifacts", "analyst_authored")),
        _latex_macro("provenancesoftwaretotal",
                     _dimension_count(merged, "software")),
        _latex_macro("provenancesoftwareanalyst",
                     _dimension_count(merged, "software", "analyst_authored")),
        _latex_macro("provenancevulnerabilitytotal",
                     _dimension_count(merged, "vulnerability")),
        _latex_macro("provenancevulnerabilitycorpus",
                     _dimension_count(merged, "vulnerability", "corpus_supported")),
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _pct(count: int, total: int) -> float:
    return round(100.0 * count / total, 1) if total else 0.0


def write_markdown(path: Path, summaries: list[ProvenanceSummary],
                   merged: ProvenanceSummary, skipped: list[str]) -> None:
    shown = _human_sources(merged)
    pct = merged.percentages
    headline = (
        f"Of the **{merged.total_elements}** concrete SUT elements materialised "
        f"across **{len(summaries)}** campaign SUT profiles, **{pct['corpus_supported']}%** is "
        f"anchored in the evaluated CTI corpus, "
        f"**{pct['external_reference']}%** comes from external advisories, "
        f"**{pct['autosut_concretized']}%** is an "
        f"AutoSUT concretization of an under-specified corpus signal, and "
        f"**{pct['analyst_authored']}%** is an explicit analyst lab choice the "
        f"corpus does not constrain."
    )

    lines = [
        "# Environment Provenance",
        "",
        f"- Generated at: `{release_isoformat()}`",
        f"- Campaigns measured: `{len(summaries)}`",
        f"- Total tagged SUT elements: `{merged.total_elements}`",
        "- Policy: four-category evidence separation "
        "(`corpus_supported` / `external_reference` / "
        "`autosut_concretized` / `analyst_authored`).",
        "",
        headline,
        "",
        "## Dimension x Source",
        "",
        "Each tagged element belongs to exactly one dimension. This table is "
        "the environment-gap measurement: it shows, dimension by dimension, "
        "how much of the executable environment public cyber knowledge "
        "actually supports.",
        "",
    ]

    header = "| Dimension | " + " | ".join(_SOURCE_LABEL[s] for s in shown) + " | Total |"
    sep = "|---|" + "".join("---:|" for _ in shown) + "---:|"
    lines.extend([header, sep])
    for dim in DIMENSIONS:
        counts = merged.by_dimension.get(dim, {})
        dim_total = sum(counts.values())
        cells = " | ".join(str(counts.get(s, 0)) for s in shown)
        lines.append(f"| {_DIM_LABEL[dim]} | {cells} | {dim_total} |")
    # Global row with percentages.
    all_cells = " | ".join(
        f"{merged.by_source.get(s, 0)} ({pct.get(s, 0.0)}%)" for s in shown
    )
    lines.append(f"| **All** | {all_cells} | **{merged.total_elements}** |")

    lines.extend([
        "",
        "## Per-Campaign Breakdown",
        "",
        "| Campaign | Elements | Corpus | AutoSUT | Analyst |",
        "|---|---:|---:|---:|---:|",
    ])
    for summary in summaries:
        total = summary.total_elements
        bs = summary.by_source
        lines.append(
            f"| `{summary.campaign_id}` | {total} | "
            f"{bs['corpus_supported']} ({_pct(bs['corpus_supported'], total)}%) | "
            f"{bs['autosut_concretized']} ({_pct(bs['autosut_concretized'], total)}%) | "
            f"{bs['analyst_authored']} ({_pct(bs['analyst_authored'], total)}%) |"
        )

    lines.extend([
        "",
        "## How to read this",
        "",
        "- **Corpus** = the value is anchored in CTI/NVD/ATT&CK evidence: a "
        "CVE-pinned product+version, the disclosed CVE itself, the documented "
        "exploit surface/port, or the OS platform family (an ATT&CK "
        "`x_mitre_platforms` field).",
        "- **AutoSUT** = AutoSUT concretized an under-specified corpus signal: "
        "the corpus implies *a* usable credential exists (valid-accounts / "
        "brute-force), AutoSUT picks the literal pair; or a named-product "
        "surrogate with no disclosed CVE.",
        "- **Analyst** = no corpus signal; pure lab construction: generic "
        "inherited services (the campaign needs *an* affordance, not that "
        "specific product), topology zones, and decoy files.",
        "- Provenance is **counted, never computed**: the aggregator only "
        "tallies tags an analyst set in `catalog.py`. The sole derived tags "
        "are definitional (a real CVE id *is* corpus evidence; an OS family "
        "*is* an ATT&CK platform).",
    ])
    if skipped:
        lines.extend([
            "",
            "## Declared but not yet implemented",
            "",
            "These campaigns are declared in the catalog but `resolve()` raises "
            "`NotImplementedError`, so they contribute no elements:",
            "",
            *[f"- `{cid}`" for cid in skipped],
        ])

    path.write_text("\n".join(lines) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out", type=Path, default=DEFAULT_OUT,
        help=f"Output directory (default: {DEFAULT_OUT}).",
    )
    args = parser.parse_args()
    out_dir: Path = args.out
    out_dir.mkdir(parents=True, exist_ok=True)

    summaries, skipped = collect_summaries()
    merged = provenance.merge_summaries(summaries, campaign_id="ALL")

    json_path = out_dir / "environment_provenance.json"
    csv_path = out_dir / "support_matrix.csv"
    md_path = out_dir / "ENVIRONMENT_PROVENANCE.md"
    latex_path = out_dir / "provenance_values.tex"
    write_json(json_path, summaries, merged, skipped)
    write_csv(csv_path, merged)
    write_markdown(md_path, summaries, merged, skipped)
    write_latex(latex_path, summaries, merged)

    for path in (json_path, csv_path, md_path, latex_path):
        try:
            display_path = path.relative_to(PROJECT_ROOT)
        except ValueError:
            display_path = path
        print(f"Wrote {display_path}")
    pct = merged.percentages
    print(
        f"  global: {merged.total_elements} elements | "
        f"corpus {pct['corpus_supported']}% | "
        f"autosut {pct['autosut_concretized']}% | "
        f"analyst {pct['analyst_authored']}%"
    )


if __name__ == "__main__":
    main()
