#!/usr/bin/env python3
"""Build a static HTML evidence dashboard from measurement CSVs and JSONs.

The dashboard is a single self-contained `index.html` (with co-located
stylesheet) under `release/dashboard/`. A reviewer opens it locally and
navigates the claim summaries, raw evidence CSVs, auxiliary metrics, worked
examples, and experiment log.

No JavaScript framework, no server, no third-party CDN: just one
HTML + CSS + the source CSV/JSON files copied into `release/dashboard/data/`.
"""

from __future__ import annotations

import csv
import json
import re
import shutil
import sys
from dataclasses import dataclass
from html import escape
from pathlib import Path

from release_clock import release_datetime


PROJECT_ROOT = Path(__file__).resolve().parent.parent
AUDIT_DIR = PROJECT_ROOT / "measurement" / "sut" / "scripts" / "results" / "audit"
RESULTS_DIR = PROJECT_ROOT / "measurement" / "sut" / "scripts" / "results"
MACRO_TEX = RESULTS_DIR / "todo_values_latex.tex"
EXPERIMENT_LOG = PROJECT_ROOT / "release" / "EXPERIMENT_LOG.jsonl"
DASHBOARD_DIR = PROJECT_ROOT / "release" / "dashboard"
DATA_DIR = DASHBOARD_DIR / "data"
MACRO_PATTERN = re.compile(r"\\newcommand\{\\([A-Za-z][A-Za-z0-9]+)\}\{([^}]*)\}")
TEXT_EVIDENCE_SUFFIXES = {".json", ".log", ".txt", ".md", ".csv", ".tsv", ".yml", ".yaml"}
PRIMARY_REPLAY_REPORTS = (
    "orchestrated_replay_full_19.tsv",
)
STYLE_VERSION = "20260602-realism-scrolltables"


# Reuse the provenance report's collectors and display labels (source order,
# dimension/source names, percentage formatting) so the dashboard can never
# drift from generate_provenance_report.py's markdown/CSV. The summary is
# computed live from the catalog (deterministic, no Docker), so the table the
# reviewer sees always matches the current corpus.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import generate_provenance_report as gpr  # noqa: E402
from orchestrator import provenance  # noqa: E402

# Execution-realism tiers. A real execution means a command ran, a
# Caldera operation fired, or an Atomic Red Team atomic invoked. naive_simulated
# is a declared-coverage marker and is surfaced as a limitation, never as
# execution evidence. This mirrors the real_modes set in fidelity_rubric.py.
REAL_EXECUTION_MODES = {"real_controlled", "caldera_driven", "atomic_red_team"}
SIMULATED_MODE = "naive_simulated"

# The claim each mode licenses. This is the bridge from "what ran" to "what a
# reviewer may conclude": the real tier supports a mechanism/procedure claim;
# naive_simulated supports only a representation claim, never an execution one.
EXECUTION_MODE_CLAIMS: tuple[tuple[str, str, str], ...] = (
    ("real_controlled", "real",
     "A bounded command, procedure, or vulnerability mechanism ran against "
     "the live SUT and left a verifiable effect. CVE witnesses identify "
     "when that effect is an actual exploit."),
    ("caldera_driven", "real",
     "The adversary procedure was dispatched by the MITRE Caldera C2 and the "
     "operation fired against the SUT."),
    ("atomic_red_team", "real",
     "The technique ran as a mediated Atomic Red Team test."),
    ("naive_simulated", "declared coverage",
     "Behavioral representation only: the effect is asserted, not executed. "
     "Never counted as execution evidence."),
)


# --- Claim summaries: maps macro names to human prose ---

@dataclass(frozen=True)
class Finding:
    number: int
    title: str
    claim_template: str
    macro_keys: tuple[str, ...]
    evidence_files: tuple[str, ...]
    claim_family: str


FINDINGS = (
    Finding(
        number=1,
        title="Software references rarely pin versions or CPEs",
        claim_template="In Enterprise, {softwarenoversionnocpepercentage}% of software "
                       "objects lack both a parseable version and a CPE identifier.",
        macro_keys=("softwarenoversionnocpepercentage", "softwarewithversionsignalpercentage",
                    "softwarewithcpepercentage"),
        evidence_files=("software_version_enrichment.csv",),
        claim_family="Software specificity",
    ),
    Finding(
        number=2,
        title="Campaign-level CVE evidence is sparse and fragmented",
        claim_template="Only {campaignlinkedcvecount} CVEs are tied directly "
                       "to campaign objects across the Enterprise STIX dataset.",
        macro_keys=("campaignlinkedcvecount", "cveuniquecount",
                    "entcampaignswithcvestructuredpct"),
        evidence_files=("campaign_cves.csv", "all_cves.csv"),
        claim_family="Vulnerability evidence",
    ),
    Finding(
        number=3,
        title="Platform tags are near-universal in Enterprise",
        claim_template="{enterpriseplatformpct}% of {enterpriseplatformcount} active "
                       "Enterprise techniques carry at least one platform tag.",
        macro_keys=("enterpriseplatformpct", "enterpriseplatformcount",
                    "enterprisesystemrequirementspct"),
        evidence_files=("platform_distribution.csv",),
        claim_family="Platform coverage",
    ),
    Finding(
        number=4,
        title="The k-threshold drop is descriptive, not actor separation",
        claim_template="Confusion drops from {thresholdkoneconfusionpct}% at k ≥ 1 "
                       "to {thresholdktwoconfusionpct}% at k ≥ 2; the direct "
                       "cardinality-null p-value is {thresholdcollapsenullpvalue}.",
        macro_keys=("thresholdkoneconfusionpct", "thresholdktwoconfusionpct",
                    "thresholdcollapsenullpvalue"),
        evidence_files=("evidence_threshold_curve.csv",
                        "null_model_confusion_distribution.csv",
                        "threshold_collapse_degree_null_distribution.csv",
                        "threshold_collapse_leave_one_out.csv"),
        claim_family="Profile specificity",
    ),
    Finding(
        number=5,
        title="The routing policy is dominated by conservative fallback",
        claim_template="The policy labels {compatibilitycontainerfeasiblepercentage}% CF, "
                       "{compatibilityvmrequiredpercentage}% VMR, and "
                       "{compatibilityinfrastructuredependentpercentage}% ID; "
                       "{compatibilityfallbackassignmentpercentage}% are fallback assignments.",
        macro_keys=("compatibilitycontainerfeasiblepercentage",
                    "compatibilityvmrequiredpercentage",
                    "compatibilityinfrastructuredependentpercentage",
                    "compatibilityfallbackassignmentpercentage"),
        evidence_files=("compatibility_denominator_summary.csv",
                        "compatibility_rule_breakdown.csv",
                        "technique_compatibility.csv"),
        claim_family="Compatibility routing policy",
    ),
)


# --- CSS: one block, austere palette, no decoration ---

STYLE = """\
:root {
  --fg: #18202a;
  --fg-dim: #516070;
  --bg: #f7f6f2;
  --bg-elev: #ffffff;
  --border: #d8d2c6;
  --accent: #24546f;
  --accent-strong: #16394e;
  --accent-soft: #e7f0f1;
  --panel: #fbfbf8;
  --ok: #2f6b45;
  --warn: #8a5a00;
  --bad: #8b2e22;
}
* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; font-family: "Avenir Next", Avenir,
  "Helvetica Neue", Helvetica, Arial, sans-serif; color: var(--fg);
  background:
    radial-gradient(circle at 12% -10%, rgba(36,84,111,0.12), transparent 30%),
    linear-gradient(180deg, #fbfaf6 0%, var(--bg) 220px);
  font-size: 15px; line-height: 1.56; overflow-x: hidden; }
header { background: rgba(255,255,255,0.86); border-bottom: 1px solid var(--border);
  padding: 26px 40px 22px; }
h1 { margin: 0; font-size: 25px; font-weight: 650; letter-spacing: -0.35px; }
header p { margin: 5px 0 0; color: var(--fg-dim); font-size: 13px; }
nav { background: rgba(231,240,241,0.92); border-bottom: 1px solid var(--border);
  padding: 10px 40px; display: flex; flex-wrap: wrap; gap: 8px 22px; }
nav a { color: var(--accent-strong); text-decoration: none; margin-right: 0;
  font-size: 13px; font-weight: 600; }
nav a:hover { text-decoration: underline; }
main { max-width: 1180px; margin: 0 auto; padding: 28px 40px; }
section { margin-bottom: 46px; }
h2 { font-size: 19px; font-weight: 650; margin: 0 0 14px; padding-bottom: 6px;
  border-bottom: 1px solid var(--border); }
h3 { font-size: 14px; font-weight: 600; margin: 18px 0 6px; }
table { width: 100%; border-collapse: collapse; background: var(--bg-elev);
  border: 0; margin: 0; table-layout: auto; }
th, td { padding: 8px 10px; text-align: left; border-bottom: 1px solid var(--border);
  font-size: 13px; vertical-align: top; overflow-wrap: anywhere; }
th { background: var(--accent-soft); font-weight: 600; color: var(--accent); }
th { overflow-wrap: normal; word-break: normal; }
tr:last-child td { border-bottom: none; }
td.numeric { text-align: right; font-variant-numeric: tabular-nums; }
td.mono, code { font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
  font-size: 12px; overflow-wrap: anywhere; word-break: break-word; }
.table-wrap td.mono { white-space: nowrap; overflow-wrap: normal; word-break: normal; }
a { overflow-wrap: anywhere; }
.table-wrap { width: 100%; max-width: 100%; overflow-x: auto; border: 1px solid var(--border);
  border-radius: 8px; background: var(--bg-elev); margin: 10px 0;
  box-shadow: 0 1px 2px rgba(20,40,70,0.05); -webkit-overflow-scrolling: touch; }
.table-wrap table { min-width: 680px; }
.table-wrap.compact table { min-width: 520px; }
.table-wrap.wide table { min-width: 920px; }
.finding { background: var(--bg-elev); border: 1px solid var(--border);
  padding: 16px 18px; margin-bottom: 14px; }
.finding-head { display: flex; gap: 12px; align-items: baseline; margin-bottom: 8px; }
.finding-num { color: var(--accent); font-weight: 700; font-size: 12px; }
.finding-title { font-weight: 600; }
.finding-claim { color: var(--fg); margin: 6px 0 10px; }
.finding-meta { font-size: 12px; color: var(--fg-dim); }
.finding-meta a { color: var(--accent); }
.muted { color: var(--fg-dim); font-size: 12px; }
.kbd { padding: 1px 5px; border: 1px solid var(--border); border-radius: 3px;
  font-family: ui-monospace, monospace; font-size: 11px; background: var(--bg); }
footer { margin: 40px 0 0; padding: 20px 40px; border-top: 1px solid var(--border);
  color: var(--fg-dim); font-size: 12px; }
.run-card { background: var(--bg-elev); border: 1px solid var(--border);
  border-left: 3px solid var(--accent); padding: 14px 18px; margin-bottom: 16px; }
.run-card h3 { margin: 0 0 6px; font-size: 14px; }
.run-card p { margin: 6px 0; }
.run-card table { margin: 8px 0; }
.lead { font-size: 15px; margin: 0 0 16px; }
.thesis { font-size: 17px; line-height: 1.45; margin: 0 0 16px;
  max-width: 900px; }
.sim { color: var(--warn); font-weight: 600; }
.bad { color: var(--bad); font-weight: 600; }
.realism-summary { background: var(--accent-soft); border: 1px solid var(--border);
  padding: 10px 14px; margin: 0 0 16px; }
.overview-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 14px; margin: 18px 0 4px; }
.overview-card { background: var(--bg-elev); border: 1px solid var(--border);
  border-top: 3px solid var(--accent); border-radius: 10px; padding: 14px 16px;
  box-shadow: 0 2px 12px rgba(20,40,70,0.06); min-width: 0; }
.overview-card strong { display: block; margin-bottom: 5px; font-size: 13px; }
.overview-card span { display: block; color: var(--fg-dim); font-size: 12px; }
.recipe-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 14px; margin: 18px 0 4px; }
.recipe-card { background: var(--panel); border: 1px solid var(--border);
  border-radius: 10px; padding: 14px 16px; min-width: 0; }
.recipe-card strong { display: block; margin-bottom: 6px; }
.recipe-card p { margin: 6px 0; color: var(--fg-dim); font-size: 12px; }
.recipe-card code { display: inline-block; margin-top: 5px; white-space: normal;
  overflow-wrap: anywhere; }
.finding, .run-card, .realism-summary { border-radius: 8px;
  box-shadow: 0 1px 2px rgba(20,40,70,0.05); }
details.evidence-group { background: var(--bg-elev); border: 1px solid var(--border);
  border-radius: 8px; margin: 10px 0; padding: 11px 14px; }
details.evidence-group summary { cursor: pointer; font-weight: 600; color: var(--accent); }
details.evidence-group p { margin: 8px 0 6px; }
details.evidence-group ul { margin: 8px 0 0; columns: 2; column-gap: 24px;
  padding-left: 18px; }
details.evidence-group li { break-inside: avoid; margin-bottom: 3px; }
details.evidence-group a,
details.evidence-group code { max-width: 100%; white-space: normal;
  overflow-wrap: anywhere; word-break: break-word; }
.table-wrap table { border-radius: 8px; overflow: hidden; }
.finding { transition: box-shadow .15s ease; }
.finding:hover { box-shadow: 0 3px 10px rgba(20,40,70,0.09); }
#nonuniqueness { background: var(--bg-elev); border: 1px solid var(--border);
  border-top: 3px solid var(--accent); border-radius: 10px; padding: 22px 26px;
  box-shadow: 0 2px 12px rgba(20,40,70,0.06); }
#nonuniqueness h2 { border-bottom: none; }
.real { color: var(--ok); font-weight: 600; }
@media (max-width: 850px) {
  header, nav { padding-left: 22px; padding-right: 22px; }
  main { padding: 22px; max-width: 100%; overflow-x: hidden; }
  .overview-grid { grid-template-columns: 1fr; }
  .recipe-grid { grid-template-columns: 1fr; }
  .recipe-card code { display: block; max-width: 100%; white-space: normal;
    word-break: break-word; overflow-wrap: anywhere; }
  p, .overview-card span, .recipe-card p { overflow-wrap: anywhere; }
  details.evidence-group ul { columns: 1; padding-left: 16px; }
  details.evidence-group li { max-width: 100%; }
  .finding-meta .kbd { display: inline-block; max-width: 100%;
    white-space: normal; word-break: break-word; }
  #nonuniqueness { padding: 18px; }
}
"""


def load_macros() -> dict[str, str]:
    if not MACRO_TEX.exists():
        return {}
    text = MACRO_TEX.read_text(encoding="utf-8")
    return {m.group(1): m.group(2) for m in MACRO_PATTERN.finditer(text)}


def load_csv(path: Path, limit: int | None = None) -> tuple[list[str], list[list[str]]]:
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.reader(handle)
        rows = list(reader)
    if not rows:
        return [], []
    header, *data = rows
    if limit is not None:
        data = data[:limit]
    return header, data


def load_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def copy_data_files() -> None:
    """Copy every audit CSV so reviewers can inspect any evidence."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    for src in AUDIT_DIR.glob("*.csv"):
        shutil.copy2(src, DATA_DIR / src.name)
    canonical_src = PROJECT_ROOT / "release" / "golden_runs.json"
    if canonical_src.exists():
        shutil.copy2(canonical_src, DATA_DIR / "canonical_runs.json")


def copy_replay_reports() -> None:
    """Copy reviewer replay reports into the dashboard with local paths scrubbed."""
    replay_dest = DATA_DIR / "replay_reports"
    if replay_dest.exists():
        shutil.rmtree(replay_dest)
    replay_dest.mkdir(parents=True, exist_ok=True)
    for name in PRIMARY_REPLAY_REPORTS:
        src = PROJECT_ROOT / "release" / name
        if not src.exists():
            continue
        shutil.copy2(src, replay_dest / src.name)
        normalize_replay_tsv(replay_dest / src.name)
        json_src = src.with_suffix(".json")
        if json_src.exists():
            shutil.copy2(json_src, replay_dest / json_src.name)
    scrub_local_paths(replay_dest)


def normalize_replay_tsv(path: Path) -> None:
    """Keep copied replay TSVs parseable and whitespace-clean for review."""
    if path.suffix != ".tsv" or not path.exists():
        return
    with path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.reader(handle, delimiter="\t"))
    if not rows or "notes" not in rows[0]:
        return
    notes_idx = rows[0].index("notes")
    status_idx = rows[0].index("status") if "status" in rows[0] else None
    normalized = [rows[0]]
    for row in rows[1:]:
        while len(row) <= notes_idx:
            row.append("")
        if not row[notes_idx].strip():
            status = row[status_idx].strip().upper() if status_idx is not None and len(row) > status_idx else ""
            row[notes_idx] = "ok" if status == "PASS" else "see JSON"
        normalized.append(row)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle, delimiter="\t", lineterminator="\n")
        writer.writerows(normalized)


def copy_curated_evidence_files() -> None:
    """Copy only canonical run evidence needed by dashboard links."""
    golden_runs_file = PROJECT_ROOT / "release" / "golden_runs.json"
    if not golden_runs_file.exists():
        return
    golden_data = json.loads(golden_runs_file.read_text(encoding="utf-8"))
    source_pairs: list[tuple[Path, str]] = []
    golden_run_names: set[str] = set()
    for entry in golden_data.get("campaigns", []):
        evidence_path = entry.get("evidence_path")
        if not evidence_path:
            continue
        src = PROJECT_ROOT / evidence_path
        run_name = str(entry.get("golden_run_id") or src.name)
        golden_run_names.add(run_name)
        source_pairs.append((src, run_name))

    evidence_dest = DATA_DIR / "evidence"
    evidence_dest.mkdir(parents=True, exist_ok=True)
    for src, run_name in source_pairs:
        dest = evidence_dest / run_name
        if src.is_dir() and src.resolve() != dest.resolve():
            if dest.exists():
                shutil.rmtree(dest)
            shutil.copytree(
                src,
                dest,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".DS_Store"),
            )
        # A public package intentionally carries the compact dashboard copy for
        # most goldens and only selected hash-bound runs under release/evidence.
        # Preserve an existing dashboard run when the full source run is absent.
        if dest.is_dir():
            scrub_local_paths(dest)

    for candidate in evidence_dest.iterdir():
        if candidate.is_dir() and candidate.name not in golden_run_names:
            shutil.rmtree(candidate)


def scrub_local_paths(path: Path) -> None:
    """Remove absolute developer paths from copied evidence files."""
    replacements = [
        str(PROJECT_ROOT.parent),
        str(PROJECT_ROOT),
        str(Path.home()),
    ]
    replacements = sorted({item for item in replacements if item}, key=len, reverse=True)
    for candidate in path.rglob("*"):
        if not candidate.is_file():
            continue
        if candidate.suffix.lower() not in TEXT_EVIDENCE_SUFFIXES:
            continue
        try:
            text = candidate.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        sanitized = text
        for value in replacements:
            sanitized = sanitized.replace(value, "<local-workspace>")
        if sanitized != text:
            candidate.write_text(sanitized, encoding="utf-8")


# Group evidence files by topic for the raw-evidence section.
EVIDENCE_GROUPS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("Platform coverage",
     "Per-corpus platform tag presence, OS family inference, and platform-unknown campaigns.",
     ("platform_distribution.csv", "platform_inference_quality_summary.csv",
      "campaign_os_family_counts.csv", "campaign_non_os_platform_counts.csv",
      "campaign_platform_unknown.csv", "campaign_platforms_software_only.csv",
      "cross_domain_coverage_density.csv")),
    ("Software specificity",
     "Version/CPE pinning per software object plus enrichment gains under bounded regex.",
     ("software_version_enrichment.csv",)),
    ("Vulnerability evidence (CVE)",
     "CVE coverage by campaign, intrusion set, and tactic; CVE-to-package resolution candidates.",
     ("all_cves.csv", "campaign_cves.csv", "campaign_cve_year_distribution.csv",
      "is_cves.csv", "cve_mentions_by_tactic.csv", "cve_resolution_candidates.csv",
      "cve_validation.csv")),
    ("Compatibility routing policy (CF/VMR/ID)",
     "Per-technique policy label, explicit denominators, rule breakdown, manual validation packet, and sensitivity.",
     ("technique_compatibility.csv", "compatibility_denominator_summary.csv",
      "compatibility_rule_breakdown.csv",
      "compatibility_by_tactic.csv", "compatibility_default_sensitivity.csv",
      "compatibility_validation_sample.csv",
      "compatibility_validation_confusion.csv",
      "compatibility_validation_disagreements.csv")),
    ("Campaign profile completeness",
     "Per-campaign software, profile tier, structural completeness, and correlation summaries.",
     ("campaign_software.csv", "campaign_profile_completeness.csv",
      "campaign_factual_structure.csv", "campaign_correlation_summary.csv")),
    ("Profile specificity (intrusion sets)",
     "Jaccard-based pairwise specificity under software-only and technique-only feature sets.",
     ("profile_specificity_software_only.csv",
      "profile_specificity_technique_only.csv", "profile_ablation_summary.csv",
      "is_software.csv")),
    ("Threshold sensitivity and robustness",
     "Direct cardinality null, degree-preserving sensitivity, leave-one-out influence, descriptive indicator resampling, delta sensitivity, and the k-threshold curve.",
     ("bootstrap_confusion_distribution.csv", "null_model_confusion_distribution.csv",
      "threshold_collapse_degree_null_distribution.csv",
      "threshold_collapse_leave_one_out.csv",
      "delta_sensitivity.csv", "evidence_threshold_curve.csv",
      "evidence_threshold_curve_technique_profile.csv",
      "evidence_convergence.csv")),
    ("Initial-access landscape",
     "Initial-access techniques and the campaigns that exercise them.",
     ("initial_access_techniques.csv", "initial_access_campaigns.csv",
      "environment_inference.csv")),
)


def render_table(header: list[str],
                 rows: list[list[str]],
                 numeric_cols: set[int] | None = None,
                 mono_cols: set[int] | None = None,
                 wide: bool = False) -> str:
    numeric_cols = numeric_cols or set()
    mono_cols = mono_cols or set()
    head = "".join(f"<th>{escape(col)}</th>" for col in header)
    body_lines = []
    for row in rows:
        cells = []
        for idx, cell in enumerate(row):
            classes = []
            if idx in numeric_cols:
                classes.append("numeric")
            if idx in mono_cols:
                classes.append("mono")
            cls = " ".join(classes)
            cells.append(f"<td class='{cls}'>{escape(cell)}</td>")
        body_lines.append("<tr>" + "".join(cells) + "</tr>")
    wrap_cls = "table-wrap wide" if wide else "table-wrap"
    return (f"<div class='{wrap_cls}'><table><thead><tr>{head}</tr></thead>"
            f"<tbody>{''.join(body_lines)}</tbody></table></div>")


def render_findings(macros: dict[str, str]) -> str:
    blocks = []
    for finding in FINDINGS:
        claim = finding.claim_template.format(**{
            key: macros.get(key, "?")
            for key in finding.macro_keys
        })
        evidence_links = ", ".join(
            f"<a href='data/{escape(name)}'><code>{escape(name)}</code></a>"
            for name in finding.evidence_files
        )
        macro_chips = " ".join(
            f"<span class='kbd'>\\{escape(key)} = {escape(macros.get(key, '?'))}</span>"
            for key in finding.macro_keys
        )
        blocks.append(f"""
<div class='finding'>
  <div class='finding-head'>
    <span class='finding-num'>F{finding.number}</span>
    <span class='finding-title'>{escape(finding.title)}</span>
  </div>
  <div class='finding-claim'>{escape(claim)}</div>
  <div class='finding-meta'>
    <strong>Macros:</strong> {macro_chips}<br>
    <strong>Evidence:</strong> {evidence_links}<br>
    <strong>Claim family:</strong> {escape(finding.claim_family)}
  </div>
</div>""")
    return "\n".join(blocks)


def render_audit_overview(merged) -> str:
    pct = merged.percentages
    return f"""
<section id='overview'>
  <h2>Reviewer Path</h2>
  <p class='thesis'><strong>Claim under audit:</strong> structured CTI
    constrains executable SUT environments but does not uniquely determine
    them. This page is organized around the checks a reviewer is likely to run:
    rederive the measurements, inspect the claim-to-evidence map, and reproduce
    at least one executable witness.</p>
  <div class='overview-grid'>
    <div class='overview-card'>
      <strong>Environment gap</strong>
      <span>{merged.total_elements} SUT elements: {pct['corpus_supported']}%
        corpus-supported, {pct['external_reference']}% externally anchored,
        {pct['autosut_concretized']}% AutoSUT-concretized,
        {pct['analyst_authored']}% analyst-authored.</span>
    </div>
    <div class='overview-card'>
      <strong>Non-uniqueness witness</strong>
      <span>CVE-2021-41773 preserves the same corpus fingerprint while
        executing compatible SUT variants under an external advisory
        fingerprint.</span>
    </div>
    <div class='overview-card'>
      <strong>Execution evidence</strong>
      <span>Canonical manifests distinguish real execution from declared
        behavioral coverage; simulated steps are never counted as execution.</span>
    </div>
    <div class='overview-card'>
      <strong>Boundary</strong>
      <span>No VM images are shipped; VM-backed reproduction uses a local
        provider.</span>
    </div>
  </div>
  <div class='recipe-grid'>
    <div class='recipe-card'>
      <strong>1. Fast deterministic audit</strong>
      <p>Regenerates measurements, figures, traceability files, and value
        checks from the shipped public inputs.</p>
      <code>bash run_review_check.sh</code>
    </div>
    <div class='recipe-card'>
      <strong>2. Small execution trace</strong>
      <p>Runs one repository-local campaign and validates the resulting JSON
        evidence manifest.</p>
      <code>cd autosut &amp;&amp; bash artifact/setup.sh &amp;&amp; bash artifact/run.sh &amp;&amp; bash artifact/validate.sh</code>
    </div>
    <div class='recipe-card'>
      <strong>3. Executable non-uniqueness witness</strong>
      <p>Runs the CVE-2021-41773 witness variants and checks that declared and
        executed modes match.</p>
      <code>cd autosut &amp;&amp; .venv/bin/python3 scripts/prove_subdetermination.py 0.cve_2021_41773 --variants 2 --execute</code>
    </div>
  </div>
</section>"""


def copy_provenance_files(summaries: list, merged, skipped: list[str]) -> None:
    """Write the provenance artifacts into data/ from the live computation.

    Reuses the report generator's writers so the downloadable JSON/CSV/MD are
    byte-for-byte what generate_provenance_report.py would emit. Because
    they share the in-memory summaries/merged, they cannot disagree with the
    table rendered on the page.
    """
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    gpr.write_json(DATA_DIR / "environment_provenance.json", summaries, merged, skipped)
    gpr.write_csv(DATA_DIR / "support_matrix.csv", merged)
    gpr.write_markdown(DATA_DIR / "ENVIRONMENT_PROVENANCE.md", summaries, merged, skipped)


def render_provenance_summary(summaries: list, merged) -> str:
    """Environment-provenance summary: the dashboard's lead measurement.

    Answers the question almost no adversary-emulation paper answers explicitly:
    how much of the executable environment actually came from the CTI corpus,
    versus had to be concretized by AutoSUT or authored by the analyst. This
    leads the dashboard on purpose: the main result is the environment gap,
    not the execution success rate.
    """
    if not summaries:
        return "<p class='muted'>No campaigns resolved; provenance unavailable.</p>"
    shown = gpr._human_sources(merged)
    pct = merged.percentages

    overview = (
        f"Of the <strong>{merged.total_elements}</strong> concrete SUT elements "
        f"materialised across <strong>{len(summaries)}</strong> campaign SUT profiles, "
        f"<strong>{pct['corpus_supported']}%</strong> is anchored in the evaluated CTI "
        f"corpus, <strong>{pct['external_reference']}%</strong> is anchored in "
        f"external advisories or package metadata, "
        f"<strong>{pct['autosut_concretized']}%</strong> is an AutoSUT "
        f"concretization of an under-specified corpus signal, and "
        f"<strong>{pct['analyst_authored']}%</strong> is an explicit analyst lab "
        f"choice the corpus does not constrain."
    )

    # Dimension x source (global): the load-bearing environment-gap table.
    dim_header = ["Dimension", *(gpr._SOURCE_LABEL[s] for s in shown), "Total"]
    dim_rows: list[list[str]] = []
    for dim in provenance.DIMENSIONS:
        counts = merged.by_dimension.get(dim, {})
        dim_total = sum(counts.values())
        dim_rows.append([
            gpr._DIM_LABEL[dim],
            *(str(counts.get(s, 0)) for s in shown),
            str(dim_total),
        ])
    dim_rows.append([
        "All",
        *(f"{merged.by_source.get(s, 0)} ({pct.get(s, 0.0)}%)" for s in shown),
        str(merged.total_elements),
    ])
    dim_table = render_table(dim_header, dim_rows,
                             numeric_cols=set(range(1, len(dim_header))))

    # Per-campaign breakdown, without conflating CTI and external evidence.
    camp_header = ["Campaign", "Elements", "Corpus", "External", "AutoSUT", "Analyst"]
    camp_rows = []
    for summary in summaries:
        total = summary.total_elements
        by_source = summary.by_source
        camp_rows.append([
            summary.campaign_id,
            str(total),
            f"{by_source['corpus_supported']} ({gpr._pct(by_source['corpus_supported'], total)}%)",
            f"{by_source['external_reference']} ({gpr._pct(by_source['external_reference'], total)}%)",
            f"{by_source['autosut_concretized']} ({gpr._pct(by_source['autosut_concretized'], total)}%)",
            f"{by_source['analyst_authored']} ({gpr._pct(by_source['analyst_authored'], total)}%)",
        ])
    camp_table = render_table(camp_header, camp_rows, numeric_cols={1, 2, 3, 4, 5})

    legend = (
        "<p class='muted'><strong>Corpus</strong> = explicitly anchored in the "
        "evaluated CTI snapshot. <strong>External</strong> = anchored in a vendor "
        "advisory, NVD record, or package metadata but absent from that snapshot. "
        "<strong>AutoSUT</strong> = "
        "AutoSUT concretized an under-specified corpus signal (the corpus implies "
        "<em>a</em> credential exists; AutoSUT picks the literal pair) or a "
        "named-product surrogate with no disclosed CVE. <strong>Analyst</strong> = "
        "no corpus signal; pure lab construction (generic inherited services, "
        "topology zones, decoy files). Provenance tags are explicit: this "
        "dashboard aggregates those tags and does not infer new provenance "
        "categories.</p>"
    )

    downloads = (
        "<p class='muted'>Audit files: "
        "<a href='data/ENVIRONMENT_PROVENANCE.md'><code>ENVIRONMENT_PROVENANCE.md</code></a>, "
        "<a href='data/support_matrix.csv'><code>support_matrix.csv</code></a>, "
        "<a href='data/environment_provenance.json'><code>environment_provenance.json</code></a> "
        "(per-element audit trail; every count traces to one concrete SUT element).</p>"
    )

    return (
        f"<p class='lead'>{overview}</p>"
        "<h3>Dimension &times; source (global)</h3>"
        "<p class='muted'>Each tagged element belongs to exactly one dimension. "
        "This is the environment-gap measurement: dimension by dimension, how much "
        "of the executable environment public cyber knowledge actually supports.</p>"
        f"{dim_table}"
        "<h3>Per-campaign breakdown</h3>"
        f"{camp_table}"
        f"{legend}"
        f"{downloads}"
    )


def render_campaign_cve_table() -> str:
    cves_path = AUDIT_DIR / "campaign_cves.csv"
    profile_path = AUDIT_DIR / "campaign_profile_completeness.csv"
    software_path = AUDIT_DIR / "campaign_software.csv"
    platform_path = AUDIT_DIR / "campaign_platforms_software_only.csv"

    cves_by_name: dict[str, str] = {}
    with cves_path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            if int(row.get("cve_count", "0")) > 0:
                cves_by_name[row["campaign_name"]] = row["cves"]
    sw_by_name: dict[str, int] = {}
    with software_path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            sw_by_name[row["campaign_name"]] = int(row["software_count"])
    plat_by_name: dict[str, bool] = {}
    with platform_path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            plat_by_name[row["campaign_name"]] = row["platform_signal"] == "True"
    tier_by_name: dict[str, str] = {}
    with profile_path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            tier_by_name[row["campaign_name"]] = (
                "CVE-associated" if row["tier_t3_cve_associated"] == "True" else "Not anchored"
            )

    headers = ["Campaign", "CVEs", "Linked SW", "Platform signal", "Tier"]
    rows = []
    for name in cves_by_name:
        rows.append([
            name,
            cves_by_name[name],
            str(sw_by_name.get(name, 0)),
            "yes" if plat_by_name.get(name, False) else "no",
            tier_by_name.get(name, ""),
        ])
    return render_table(headers, rows, numeric_cols={2})


def render_experiment_log() -> str:
    """Filtered EXPERIMENT_LOG: only canonical runs appear here.

    The historical EXPERIMENT_LOG.jsonl is the append-only ledger of every
    run AutoSUT ever produced. For public review, we filter it down to the
    canonical subset designated by the release manifest so the reviewer
    never compares partials against canonical evidence side-by-side.
    """
    entries = load_jsonl(EXPERIMENT_LOG)
    canonical_runs_file = PROJECT_ROOT / "release" / "golden_runs.json"
    if not canonical_runs_file.exists():
        return ("<p class='muted'>No canonical run manifest. "
                "Run <code>python scripts/curate_evidence.py --apply</code> "
                "to designate canonical evidence runs.</p>")
    canonical_data = json.loads(canonical_runs_file.read_text(encoding="utf-8"))
    canonical_run_ids = {entry["golden_run_id"]
                         for entry in canonical_data.get("campaigns", [])}
    if not entries:
        return "<p class='muted'>No experiment log entries.</p>"
    header = ["Run ID", "Campaign", "Timestamp", "Total", "Pass", "Fail", "Fidelity"]
    rows = []
    for entry in entries:
        if entry.get("run_id") not in canonical_run_ids:
            continue
        fidelity = ", ".join(f"{k}={v}" for k, v
                              in entry.get("fidelity_distribution", {}).items()) or "-"
        rows.append([
            entry.get("run_id", ""),
            entry.get("campaign_id", ""),
            entry.get("timestamp", ""),
            str(entry.get("total_techniques", "")),
            str(entry.get("successful", "")),
            str(entry.get("failed", "")),
            fidelity,
        ])
    if not rows:
        return ("<p class='muted'>Per-run outcomes are listed in the "
                "<a href='#execution'>Execution evidence</a> section above and "
                "stored under <code>release/evidence/&lt;run-id&gt;/</code>; the "
                "reproduction script regenerates the full ledger.</p>")
    return render_table(header, rows, numeric_cols={3, 4, 5}, mono_cols={0})


def render_rule_breakdown() -> str:
    path = AUDIT_DIR / "compatibility_rule_breakdown.csv"
    if not path.exists():
        return "<p class='muted'>compatibility_rule_breakdown.csv missing.</p>"
    header, rows = load_csv(path)
    if header and header[0] == "class":
        header[0] = "routing_label"
    if len(header) > 4 and header[4] == "pct_within_class":
        header[4] = "pct_within_label"
    return render_table(header, rows, numeric_cols={3, 4, 5}, mono_cols={1}, wide=True)


def render_evidence_groups() -> str:
    grouped_files: set[str] = set()
    blocks: list[str] = []
    for title, blurb, files in EVIDENCE_GROUPS:
        present = [name for name in files if (DATA_DIR / name).exists()]
        if not present:
            continue
        grouped_files.update(present)
        items = "".join(
            f"<li><a href='data/{escape(name)}'><code>{escape(name)}</code></a></li>"
            for name in present
        )
        blocks.append(
            "<details class='evidence-group'>"
            f"<summary>{escape(title)} ({len(present)} file{'s' if len(present) != 1 else ''})</summary>"
            f"<p class='muted'>{escape(blurb)}</p>"
            f"<ul>{items}</ul>"
            "</details>"
        )

    # Anything left over (e.g., a CSV we did not anticipate) goes in a tail group.
    leftover = sorted(p.name for p in DATA_DIR.iterdir()
                      if p.is_file() and p.suffix == ".csv" and p.name not in grouped_files)
    if leftover:
        items = "".join(
            f"<li><a href='data/{escape(name)}'><code>{escape(name)}</code></a></li>"
            for name in leftover
        )
        blocks.append(
            "<details class='evidence-group'>"
            f"<summary>Other ({len(leftover)} file{'s' if len(leftover) != 1 else ''})</summary>"
            "<p class='muted'>Supporting derived outputs not grouped above.</p>"
            f"<ul>{items}</ul>"
            "</details>"
        )
    return "".join(blocks)


def render_execution_claim_table() -> str:
    """Map each execution mode to the scientific claim a reviewer may draw."""
    rows = [[mode, tier, claim] for mode, tier, claim in EXECUTION_MODE_CLAIMS]
    return render_table(
        ["Execution mode", "Tier", "Claim it licenses"],
        rows,
        mono_cols={0},
        wide=True,
    )


def _load_replay_report(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle, delimiter="\t")
        return list(reader)


def render_replay_reports() -> str:
    """Summarize end-to-end replay reports generated by the batch runner."""
    reports = [
        PROJECT_ROOT / "release" / name
        for name in PRIMARY_REPLAY_REPORTS
        if (PROJECT_ROOT / "release" / name).exists()
    ]
    if not reports:
        return (
            "<p class='muted'>No replay report found yet. Run "
            "<code>.venv/bin/python3 scripts/run_all_orchestrated_campaigns.py "
            "--output release/orchestrated_replay_full.tsv</code>.</p>"
        )

    rows = []
    for report in reports:
        try:
            entries = _load_replay_report(report)
        except (csv.Error, OSError):
            continue
        if not entries:
            continue
        success = sum(int(row.get("successful") or 0) for row in entries)
        total = sum(int(row.get("total") or 0) for row in entries)
        elapsed = sum(float(row.get("elapsed_seconds") or 0) for row in entries)
        status_values = [row.get("status") or "UNKNOWN" for row in entries]
        status = "PASS" if status_values and all(v == "PASS" for v in status_values) else ",".join(sorted(set(status_values)))
        report_link = f"data/replay_reports/{report.name}"
        json_name = report.with_suffix(".json").name
        json_link = f"data/replay_reports/{json_name}"
        rows.append([
            report.name,
            status,
            str(len(entries)),
            f"{success}/{total}",
            f"{elapsed:.1f}s",
            report_link,
            json_link if (DATA_DIR / "replay_reports" / json_name).exists() else "",
        ])
    if not rows:
        return "<p class='muted'>Replay reports exist but could not be parsed.</p>"

    linked_rows = []
    for row in rows:
        linked_rows.append([
            row[0],
            row[1],
            row[2],
            row[3],
            row[4],
            f"<a href='{escape(row[5])}' title='{escape(row[5])}'><code>TSV</code></a>",
            (f"<a href='{escape(row[6])}' title='{escape(row[6])}'><code>JSON</code></a>"
             if row[6] else ""),
        ])
    header = ["Report", "Status", "Campaigns", "Planned steps", "Elapsed", "TSV", "JSON"]
    head = "".join(f"<th>{escape(col)}</th>" for col in header)
    body = []
    for row in linked_rows:
        body.append(
            "<tr>"
            f"<td class='mono'>{escape(row[0])}</td>"
            f"<td>{escape(row[1])}</td>"
            f"<td class='numeric'>{escape(row[2])}</td>"
            f"<td class='numeric'>{escape(row[3])}</td>"
            f"<td class='numeric'>{escape(row[4])}</td>"
            f"<td>{row[5]}</td>"
            f"<td>{row[6]}</td>"
            "</tr>"
        )
    return (
        "<div class='table-wrap wide'><table><thead><tr>"
        f"{head}</tr></thead><tbody>{''.join(body)}</tbody></table></div>"
    )


def _campaign_external_id(campaign_id: str) -> str | None:
    match = re.fullmatch(r"0\.(c\d{4})", campaign_id, flags=re.IGNORECASE)
    return match.group(1).upper() if match else None


def _load_attack_campaign_techniques() -> dict[str, dict[str, object]]:
    """Return ATT&CK campaign -> unique linked technique IDs from the frozen bundle."""
    bundle = PROJECT_ROOT / "data" / "stix" / "enterprise-attack.json"
    if not bundle.exists():
        bundle = PROJECT_ROOT / "measurement" / "sut" / "scripts" / "data" / "enterprise-attack.json"
    if not bundle.exists():
        return {}
    try:
        objects = json.loads(bundle.read_text(encoding="utf-8")).get("objects", [])
    except json.JSONDecodeError:
        return {}

    by_id = {obj.get("id"): obj for obj in objects}
    campaign_meta: dict[str, dict[str, object]] = {}
    for obj in objects:
        if obj.get("type") != "campaign":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        external_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                external_id = ref["external_id"].upper()
                break
        if external_id:
            campaign_meta[external_id] = {"name": obj.get("name", external_id), "techniques": set()}

    for obj in objects:
        if obj.get("type") != "relationship" or obj.get("relationship_type") != "uses":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        source = by_id.get(obj.get("source_ref"))
        target = by_id.get(obj.get("target_ref"))
        if not source or not target:
            continue
        if source.get("type") != "campaign" or target.get("type") != "attack-pattern":
            continue

        campaign_id = None
        technique_id = None
        for ref in source.get("external_references", []):
            if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                campaign_id = ref["external_id"].upper()
                break
        for ref in target.get("external_references", []):
            if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                technique_id = ref["external_id"]
                break
        if campaign_id in campaign_meta and technique_id:
            campaign_meta[campaign_id]["techniques"].add(technique_id)
    return campaign_meta


def _canonical_campaign_entries() -> list[dict]:
    canonical_runs_file = PROJECT_ROOT / "release" / "golden_runs.json"
    if not canonical_runs_file.exists():
        return []
    try:
        data = json.loads(canonical_runs_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    return [entry for entry in data.get("campaigns", []) if entry.get("campaign_id")]


def _canonical_manifest_techniques(entry: dict) -> list[str]:
    evidence_path = entry.get("evidence_path", "")
    candidates = []
    if evidence_path:
        candidates.append(DATA_DIR / "evidence" / Path(evidence_path).name / "manifest.json")
        candidates.append(PROJECT_ROOT / evidence_path / "manifest.json")
    for manifest_path in candidates:
        if not manifest_path.exists():
            continue
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        techniques = manifest.get("techniques", [])
        return [
            item.get("technique_id")
            for item in techniques
            if item.get("technique_id")
        ]

    # Fallback only for incomplete local builds; packaged dashboards use the
    # canonical manifest denominator above.
    campaign_path = PROJECT_ROOT / "campaigns" / f"{entry.get('campaign_id')}.json"
    if not campaign_path.exists():
        return []
    try:
        campaign = json.loads(campaign_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    return [
        item.get("technique_id")
        for item in campaign.get("techniques", [])
        if item.get("technique_id")
    ]


def _campaign_scope_rows() -> list[list[str]]:
    attack_campaigns = _load_attack_campaign_techniques()
    rows: list[list[str]] = []
    for entry in _canonical_campaign_entries():
        campaign_id = entry["campaign_id"]
        planned = _canonical_manifest_techniques(entry)
        planned_unique = set(planned)
        external_id = _campaign_external_id(campaign_id)
        if external_id and external_id in attack_campaigns:
            attack_techniques = set(attack_campaigns[external_id]["techniques"])
            overlap = planned_unique & attack_techniques
            if len(planned_unique) == len(attack_techniques) and len(overlap) == len(attack_techniques):
                interpretation = "ATT&CK campaign technique set covered in this planned replay."
            elif len(overlap) == len(attack_techniques):
                interpretation = "ATT&CK set plus local or subtechnique replay steps."
            else:
                interpretation = "Partial planned replay; not full ATT&CK campaign coverage."
            campaign_name = attack_campaigns[external_id]["name"]
            if campaign_name == external_id:
                campaign_name = f"ATT&CK campaign object {external_id}"
            attack_label = f"{external_id}: {campaign_name}"
            attack_count = str(len(attack_techniques))
            overlap_count = str(len(overlap))
        elif external_id:
            attack_label = external_id
            attack_count = "0"
            overlap_count = "0"
            interpretation = "No ATT&CK uses-links found in the frozen bundle."
        else:
            attack_label = "not a Cxxxx ATT&CK campaign object"
            attack_count = "n/a"
            overlap_count = "n/a"
            interpretation = "Curated witness, demo, or intrusion-set run; not a full MITRE campaign denominator."
        rows.append([
            campaign_id,
            attack_label,
            str(len(planned)),
            attack_count,
            overlap_count,
            interpretation,
        ])
    return rows


def write_campaign_scope_csv() -> None:
    rows = _campaign_scope_rows()
    if not rows:
        return
    with (DATA_DIR / "campaign_scope_check.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow([
            "campaign_id",
            "attack_campaign",
            "autosut_planned_steps",
            "attack_linked_techniques",
            "overlap_unique_techniques",
            "scope_interpretation",
        ])
        writer.writerows(rows)


def render_campaign_scope_check() -> str:
    rows = _campaign_scope_rows()
    if not rows:
        return "<p class='muted'>No campaign-scope rows could be computed.</p>"
    return render_table(
        [
            "Run",
            "ATT&CK campaign denominator",
            "AutoSUT planned steps",
            "ATT&CK linked techniques",
            "Match",
            "Scope interpretation",
        ],
        rows,
        numeric_cols={2, 3, 4},
        mono_cols={0},
        wide=True,
    )


def render_execution_tour() -> str:
    """Render the live-evidence section using only canonical evidence runs.

    By design, the dashboard surfaces exclusively the canonical evidence
    runs designated by ``scripts/curate_evidence.py`` and persisted in the
    release manifest. Partial, empty, broken, and superseded runs are not
    eligible for display here; they live under ``release/evidence/_archive/``
    but never represent the artifact.
    """
    canonical_runs_file = PROJECT_ROOT / "release" / "golden_runs.json"
    dashboard_evidence_root = DATA_DIR / "evidence"
    release_evidence_root = PROJECT_ROOT / "release" / "evidence"
    evidence_root = (
        dashboard_evidence_root
        if dashboard_evidence_root.exists()
        else release_evidence_root
    )

    if not canonical_runs_file.exists():
        return ("<p class='muted'>No canonical runs yet. Run "
                "<code>python scripts/curate_evidence.py --apply</code> "
                "to designate canonical runs and curate the tree.</p>")

    canonical_data = json.loads(canonical_runs_file.read_text(encoding="utf-8"))
    canonical_entries = canonical_data.get("campaigns", [])
    if not canonical_entries:
        return ("<p class='muted'>No campaigns met the canonical-run criteria. "
                "Re-run the canonical corpus, then re-curate.</p>")

    candidates = [evidence_root / Path(entry["evidence_path"]).name
                  for entry in canonical_entries]
    if not candidates:
        return "<p class='muted'>No canonical campaign evidence found.</p>"

    cards = []
    agg_real = agg_sim = agg_total = 0
    for run_dir in candidates:
        manifest_path = run_dir / "manifest.json"
        if not manifest_path.exists():
            continue
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        techniques = manifest.get("techniques", [])
        if not techniques:
            continue

        # Fidelity rubric section
        rubric_path = run_dir / "fidelity_report.json"
        rubric_summary = ""
        if rubric_path.exists():
            try:
                rubric = json.loads(rubric_path.read_text(encoding="utf-8"))
                dist = rubric["summary"]["fidelity_distribution"]
                total = rubric["summary"]["total"]
                consistent = rubric["summary"]["consistent"]
                dist_str = ", ".join(f"{k}: {v}" for k, v in sorted(dist.items()))
                rubric_summary = (
                    f"<p><strong>Fidelity rubric</strong> (five-question, per technique): "
                    f"{escape(dist_str)}; {consistent}/{total} consistent</p>"
                )
            except (json.JSONDecodeError, KeyError):
                pass

        # Caldera operations
        caldera_dir = run_dir / "caldera"
        caldera_block = ""
        if caldera_dir.exists():
            link_logs = sorted(caldera_dir.glob("*.log"))
            if link_logs:
                rows = []
                for t in techniques:
                    if t.get("caldera_ability_id"):
                        rows.append([
                            t["technique_id"],
                            t.get("caldera_ability_name", "?")[:32],
                            (t.get("caldera_ability_id") or "")[:8] + "…",
                            t["executed_mode"],
                            t["status"],
                        ])
                if rows:
                    caldera_block = (
                        "<p><strong>Caldera-driven evidence</strong>: every "
                        "row is a real MITRE Caldera operation; copied stdout "
                        "logs are under "
                        f"<code>data/evidence/{escape(run_dir.name)}/caldera</code>:</p>"
                        + render_table(
                            ["Technique", "ART ability", "ID", "Executed mode", "Status"],
                            rows,
                        )
                    )

        # Topology hint: if the manifest has multiple host_setup logs
        # under sut/ we mention the multi-host topology.
        sut_dir = run_dir / "sut"
        host_logs = list(sut_dir.glob("*_setup.log")) if sut_dir.exists() else []
        topo_note = ""
        if len(host_logs) > 1:
            host_names = sorted({p.stem.replace("_setup", "") for p in host_logs})
            topo_note = (
                f"<p><strong>Multi-host topology</strong>: "
                f"{escape(', '.join(host_names))} on a private Docker network</p>"
            )

        # Outcome distribution + execution-realism tiers (S31b). We split modes
        # into the real tier (a command/operation actually ran) and the
        # naive_simulated marker, which is declared coverage, not evidence.
        n_succ = sum(1 for t in techniques if t.get("status") == "success")
        n_total = len(techniques)
        modes: dict[str, int] = {}
        for t in techniques:
            mode = t.get("executed_mode", "?")
            modes[mode] = modes.get(mode, 0) + 1
        real_modes = {m: c for m, c in modes.items() if m in REAL_EXECUTION_MODES}
        n_real = sum(real_modes.values())
        n_sim = modes.get(SIMULATED_MODE, 0)
        agg_real += n_real
        agg_sim += n_sim
        agg_total += n_total

        real_str = ", ".join(f"{m}: {c}" for m, c in sorted(real_modes.items())) or "none"
        realism = (
            f"<p><strong>Execution realism:</strong> "
            f"<strong>{n_real}/{n_total}</strong> really executed "
            f"<span class='muted'>({escape(real_str)})</span>"
        )
        if n_sim:
            realism += (
                f" &middot; <span class='sim'>{n_sim}/{n_total} simulated</span> "
                "<span class='muted'>(declared coverage, not executed)</span>"
            )
        realism += "</p>"

        rel_path = f"data/evidence/{run_dir.name}/manifest.json"
        cards.append(
            "<article class='run-card'>"
            f"<h3>{escape(manifest.get('campaign_id', '?'))} "
            f"<span class='muted'>· {escape(manifest.get('run_id', run_dir.name))}</span></h3>"
            f"<p><strong>{n_succ}/{n_total}</strong> planned steps completed.</p>"
            f"{realism}"
            f"{topo_note}"
            f"{rubric_summary}"
            f"{caldera_block}"
            f"<p class='muted'>Evidence manifest: "
            f"<a href='{escape(rel_path)}'><code>{escape(rel_path)}</code></a></p>"
            "</article>"
        )

    if not cards:
        return "<p class='muted'>No parseable evidence found.</p>"

    # Aggregate realism banner: leads the run cards so the reviewer reads the
    # real-vs-simulated split before any per-campaign success count.
    banner = (
        "<p class='realism-summary'>Across these "
        f"<strong>{len(cards)}</strong> audited run(s): "
        f"<strong>{agg_real}/{agg_total}</strong> planned steps are real executions "
        "(real_controlled / caldera_driven / atomic_red_team)"
    )
    if agg_sim:
        banner += (
            f", and <strong>{agg_sim}/{agg_total}</strong> are "
            "<span class='sim'>simulated</span>: recorded as declared "
            "coverage, not counted as execution evidence"
        )
    banner += ".</p>"
    return banner + "\n".join(cards)


def render_subdetermination_section() -> str:
    """Render the environment-non-uniqueness proof from the curated artifact.

    Reads release/subdetermination_proof.json (written by
    build_subdetermination_artifact.py); never recomputes the proof.
    """
    artifact_file = PROJECT_ROOT / "release" / "subdetermination_proof.json"
    if not artifact_file.exists():
        return ("<p class='muted'>No "
                "<code>release/subdetermination_proof.json</code>. Run "
                "<code>python3 scripts/build_subdetermination_artifact.py</code>."
                "</p>")
    data = json.loads(artifact_file.read_text(encoding="utf-8"))
    rows = []
    for campaign_id, proof in data.get("proofs", {}).items():
        result = ("canonical and variants execute (real_controlled)"
                  if proof["executable"]
                  else "all variants remain compatible (structural)")
        fingerprint = f"{proof['invariant_fingerprint'][:16]}…"
        rows.append(
            f"<tr><td><code>{escape(campaign_id)}</code></td>"
            f"<td><code>{escape(fingerprint)}</code></td>"
            f"<td>{len(proof['variants'])}</td>"
            f"<td>{escape(result)}</td>"
            f"<td>{proof['invariant_count']}</td>"
            f"<td>{proof['free_count']}</td></tr>")
    # Fingerprint leads: the memorable claim is "same fingerprint, different
    # SUTs, same outcome", not the free fraction (which is only a property of
    # the partition, never the count of compatible models).
    table = (
        "<div class='table-wrap'><table><thead><tr><th>Campaign</th><th>Invariant fingerprint</th>"
        "<th>Generated variants</th><th>Result</th><th>Corpus-fixed</th>"
        "<th>Free</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table></div>")
    conclusion = (
        "<p><strong>Conclusion:</strong> structured CTI constrains the "
        "environment but does not uniquely determine it. Every variant preserves "
        "the same corpus fingerprint while varying only non-corpus elements.</p>")
    cve = data.get("proofs", {}).get("0.cve_2021_41773")
    witness = ""
    if cve and cve.get("executable"):
        realisations = len(cve["variants"]) + 1  # canonical + variants
        witness = (
            f"<p><strong>Executable witness:</strong> {realisations} compatible "
            "SUT realisations for CVE-2021-41773 (the canonical SUT plus "
            "generated variants) "
            "preserve the same corpus fingerprint and successfully execute the "
            "same real vulnerability: the path traversal leaking "
            "<code>/etc/passwd</code>, each with "
            "<code>declared_mode == executed_mode</code>.</p>")
    pivot = data.get("proofs", {}).get("0.pivot_demo")
    web = data.get("proofs", {}).get("0.web_demo")
    coincident = ""
    if (pivot and pivot.get("executable")) or (web and web.get("executable")):
        coincident = (
            "<p><strong>Coincident witnesses:</strong> two informative service "
            "substitutions are themselves executed, across two service classes. "
            "The SSH-pivot reference runs a canonical OpenSSH SUT and a generated "
            "Dropbear variant through the same multi-stage pivot. The edge-HTTP "
            "reference runs a canonical Apache SUT and a generated Nginx variant "
            "through the same HTTP Basic Auth brute-force and exfiltration chain. "
            "Each realisation preserves the same corpus fingerprint and runs with "
            "<code>declared_mode == executed_mode</code>. The executed variation "
            "is the service realisation itself, a structurally different "
            "server.</p>")
    coverage_note = (
        "<p class='muted'>Scope: the non-uniqueness result rests on the "
        "executable CVE-2021-41773 and coincident service-substitution "
        "witnesses above. "
        "Campaigns carrying "
        "<code>naive_simulated</code> techniques are included to study "
        "environment reconstruction and compatibility; declared behavioral "
        "coverage is never counted as procedural-execution evidence, so the "
        "simulated-technique ratio does not bear on the non-uniqueness claim.</p>")
    interpretation = (
        "<p class='muted'>Interpretation: ATT&amp;CK models adversary behaviour "
        "and STIX models threat intelligence; neither is designed to specify a "
        "complete executable environment. The result "
        "shows where downstream emulation must reconstruct the environment "
        "beyond the structured intelligence.</p>")
    return table + conclusion + witness + coincident + coverage_note + interpretation


def render_html(macros: dict[str, str], provenance_section: str, merged) -> str:
    return f"""<!doctype html>
<html lang='en'>
<head>
  <meta charset='utf-8'>
  <meta name='viewport' content='width=device-width, initial-scale=1'>
  <title>AutoSUT Evidence Dashboard</title>
  <link rel='stylesheet' href='style.css?v={STYLE_VERSION}'>
</head>
<body>
<header>
  <h1>AutoSUT Evidence Dashboard</h1>
  <p>Evidence view for reproducing and auditing the study claims.
     Generated {release_datetime().strftime('%B %d, %Y')}.</p>
</header>
<nav>
  <a href='#overview'>Reviewer path</a>
  <a href='#nonuniqueness'>Non-uniqueness proof</a>
  <a href='#provenance'>Reconstruction boundary</a>
  <a href='#findings'>Claim map</a>
  <a href='#replay'>Replay reports</a>
  <a href='#scope'>Campaign scope</a>
  <a href='#execution'>Execution evidence</a>
  <a href='#worked'>Worked examples</a>
  <a href='#rules'>Compatibility rules</a>
  <a href='#raw'>Raw evidence</a>
</nav>
<main>
{render_audit_overview(merged)}
<section id='nonuniqueness'>
  <h2>Environment Non-Uniqueness Proof</h2>
  <p class='muted'>The core result: the same CTI admits multiple distinct,
    compatible SUTs, including an executable witness. Each variant preserves
    every <code>corpus_supported</code>
    element (identical invariant fingerprint) and varies only the free region.
    <code>0.cve_2021_41773</code> is the executable witness, each variant
    running the real CVE with <code>declared_mode == executed_mode</code>.
    <code>0.pivot_demo</code> and <code>0.web_demo</code> are coincident
    witnesses, running the same attack across structurally different SSH servers
    (OpenSSH and Dropbear) and edge HTTP servers (Apache and Nginx).
    <code>0.apt41_dust</code> is the structural witness: a large free region
    with materially distinct services. Source:
    <code>release/subdetermination_proof.json</code>.</p>
  {render_subdetermination_section()}
</section>
<section id='provenance'>
  <h2>Environment reconstruction boundary: what CTI fixes and what must be reconstructed</h2>
  <p class='muted'>Why non-uniqueness exists: structured CTI fixes only part of
    the executable environment; the rest must be reconstructed. Every concrete
    SUT element is tagged by where it came from, then rolled up into a dimension
    &times; source table: the fixed (corpus) vs free (reconstructed) partition
    that the non-uniqueness result exploits. Computed deterministically from
    shipped provenance annotations; no live campaign run is required.</p>
  {provenance_section}
</section>
<section id='findings'>
  <h2>Claim-To-Evidence Map</h2>
  <p class='muted'>Each card shows a study claim, the reported values, and the
    CSV files that back them. Click any file name to open the raw evidence
    under <code>data/</code>.</p>
{render_findings(macros)}
</section>
<section id='replay'>
  <h2>End-to-End Replay Reports</h2>
  <p class='muted'>Replay reports summarize completed campaign reruns. They are
    separate from the audited runs below: reruns show what a reviewer executed
    locally, while audited runs are the stable evidence shipped for claim
    inspection. New reruns emit TSV and JSON reports for inspection.</p>
  {render_replay_reports()}
</section>
<section id='scope'>
  <h2>Campaign Scope Sanity Check</h2>
  <p class='muted'>This table prevents a common denominator error. AutoSUT
    replay counts are planned campaign/SUT steps from released manifests;
    they are not automatically the full set of ATT&amp;CK techniques linked to
    a MITRE campaign object. For Cxxxx runs, the table compares the planned
    replay against the frozen Enterprise ATT&amp;CK bundle. Source:
    <code>data/campaign_scope_check.csv</code>.</p>
  {render_campaign_scope_check()}
</section>
<section id='execution'>
  <h2>Audited Complete Runs</h2>
  <p class='muted'>
    Only audited complete runs are shown here: every planned step completed
    and the manifest, summary, and fidelity rubric are all present. Selection
    criteria are recorded in <code>data/canonical_runs.json</code>. Partial,
    empty, or superseded runs are excluded and are not used for claims.
    Execution is split into realism tiers:
    <code>real_controlled</code>, <code>caldera_driven</code>, and
    <code>atomic_red_team</code> are real executions (a command ran, an
    operation fired); <strong>simulated</strong> is declared behavioral
    coverage, reported as a limitation and never counted as execution evidence.
  </p>
  <p class='muted'>What each mode lets a reviewer conclude:</p>
  {render_execution_claim_table()}
  {render_execution_tour()}
</section>
<section id='worked'>
  <h2>Worked example: CVE-positive campaigns</h2>
  <p class='muted'>Enterprise campaigns with structured CVE evidence and their
    profile-completeness tier.</p>
  {render_campaign_cve_table()}
</section>
<section id='rules'>
  <h2>Compatibility routing-policy surface</h2>
  <p class='muted'>One row per CF/VMR/ID routing rule with technique count and
    share. Labels are heuristic policy outputs, not measured minimum-backend
    requirements. The manual-validation packet has no completed labels, so no
    accuracy estimate is reported. Sources:
    <code>data/compatibility_rule_breakdown.csv</code> and
    <code>data/compatibility_denominator_summary.csv</code>.</p>
  {render_rule_breakdown()}
</section>
<section id='raw'>
  <h2>Raw evidence grouped by analysis topic</h2>
  <p class='muted'>All {len(list(DATA_DIR.glob('*.csv')))} CSVs produced by the measurement pipeline,
    grouped by the question they answer. Open any file to verify a study claim
    directly against the underlying rows.</p>
  {render_evidence_groups()}
</section>
</main>
<footer>
  Dashboard regeneration:
  <code>python3 scripts/build_reviewer_dashboard.py</code>.
  Validate every macro: <code>bash run_review_check.sh</code>.
</footer>
</body>
</html>"""


def main() -> int:
    DASHBOARD_DIR.mkdir(parents=True, exist_ok=True)
    copy_data_files()
    copy_replay_reports()
    copy_curated_evidence_files()
    write_campaign_scope_csv()
    # Provenance is computed once from the catalog and fed to both the download
    # artifacts and the rendered summary, so the page and the files agree.
    summaries, skipped = gpr.collect_summaries()
    merged = provenance.merge_summaries(summaries, campaign_id="ALL")
    copy_provenance_files(summaries, merged, skipped)
    provenance_section = render_provenance_summary(summaries, merged)
    macros = load_macros()
    (DASHBOARD_DIR / "style.css").write_text(STYLE, encoding="utf-8")
    (DASHBOARD_DIR / "index.html").write_text(
        render_html(macros, provenance_section, merged), encoding="utf-8")
    csv_count = len(list(DATA_DIR.glob("*.csv")))
    evidence_count = len(list((DATA_DIR / "evidence").glob("*"))) if (DATA_DIR / "evidence").exists() else 0
    print(f"[dashboard] wrote {DASHBOARD_DIR / 'index.html'}")
    print(f"[dashboard] copied {csv_count} CSV evidence files into {DATA_DIR}")
    print(f"[dashboard] copied {evidence_count} canonical evidence run(s)")
    print(f"[dashboard] provenance: {merged.total_elements} elements across "
          f"{len(summaries)} campaigns "
          f"(corpus {merged.percentages['corpus_supported']}%, "
          f"autosut {merged.percentages['autosut_concretized']}%, "
          f"analyst {merged.percentages['analyst_authored']}%)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
