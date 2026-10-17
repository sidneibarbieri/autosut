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
MACRO_TEX = PROJECT_ROOT / "release" / "study_values.tex"
DASHBOARD_DIR = PROJECT_ROOT / "release" / "dashboard"
DATA_DIR = DASHBOARD_DIR / "data"
MACRO_PATTERN = re.compile(r"\\newcommand\{\\([A-Za-z][A-Za-z0-9]+)\}\{([^}]*)\}")
TEXT_EVIDENCE_SUFFIXES = {".json", ".log", ".txt", ".md", ".csv", ".tsv", ".yml", ".yaml"}
# Historical status-only logs remain in the source tree, outside the released claim surface.
PRIMARY_REPLAY_REPORTS: tuple[str, ...] = ()
REPLAY_AUDIT_FILE = "replay_evidence_audit.json"
STYLE_VERSION = "20261009-theme-mobile"
# Family mark shared with STICKS and SOCpilot; no font dependency.
BRAND_MARK = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" role="img" aria-label="AutoSUT mark">
  <rect width="64" height="64" rx="14" fill="#0b1b33"/>
  <path d="M32 14 48 23v18L32 50 16 41V23z" fill="none" stroke="#c9760a" stroke-width="5" stroke-linejoin="round"/>
  <path d="M16 23l16 9 16-9M32 32v18" fill="none" stroke="#c9760a" stroke-width="5" stroke-linejoin="round"/>
</svg>
"""
CLAIM_LEDGER_FILE = "claim_evidence_traceability.json"
_STALE_DASHBOARD_FILES = ("canonical_runs.json", "campaign_scope_check.csv")


# Reuse the provenance report's collectors and display labels (source order,
# dimension/source names, percentage formatting) so the dashboard can never
# drift from generate_provenance_report.py's markdown/CSV. The summary is
# computed live from the catalog (deterministic, no Docker), so the table the
# reviewer sees always matches the current corpus.
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(PROJECT_ROOT / "src"))
import generate_provenance_report as gpr
from evaluation.replay_audit import ReplayAudit
from orchestrator import provenance

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
  --ink: #1b2430;
  --ink-soft: #5b6675;
  --ink-faint: #8a94a0;
  --paper: #f5f6f8;
  --surface: #ffffff;
  --surface-2: #f5f6f8;
  --line: #dde2e8;
  --line-strong: #c3cad3;
  --accent: #0b1b33;
  --accent-ink: #0b1b33;
  --accent-wash: #eef1f6;
  --brand: #c9760a;
  --pass: #2f6b45;
  --warn: #8a5a00;
  --fail: #9a3324;
  --series-1: #2b4c6f;
  --series-2: #b8863b;
  --series-3: #6b7f8c;
  --shadow-sm: 0 1px 2px rgba(24,36,54,0.06);
  --shadow-md: 0 6px 22px rgba(24,36,54,0.08);
  --radius: 12px;
  --font-display: "Inter", "Helvetica Neue", Arial, sans-serif;
  --font-body: -apple-system, BlinkMacSystemFont, "Segoe UI", "Helvetica Neue",
    Helvetica, Arial, sans-serif;
  --font-mono: ui-monospace, "SF Mono", "JetBrains Mono", Menlo, Consolas,
    "Liberation Mono", monospace;
  --nav-h: 52px;
}
:root[data-theme="dark"] {
  --ink: #e9e6dd;
  --ink-soft: #a7afba;
  --ink-faint: #6f7a86;
  --paper: #13161b;
  --surface: #1b1f26;
  --surface-2: #20242c;
  --line: #2c313b;
  --line-strong: #3b414b;
  --accent: #7fb8d1;
  --accent-ink: #a9d4e6;
  --accent-wash: #17303a;
  --pass: #6cc08b;
  --warn: #d3a856;
  --fail: #dd8f83;
  --series-1: #7fb8d1;
  --series-2: #d3a856;
  --series-3: #9aa6b2;
  --shadow-sm: 0 1px 2px rgba(0,0,0,0.35);
  --shadow-md: 0 8px 26px rgba(0,0,0,0.45);
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --ink: #e9e6dd; --ink-soft: #a7afba; --ink-faint: #6f7a86;
    --paper: #13161b; --surface: #1b1f26; --surface-2: #20242c;
    --line: #2c313b; --line-strong: #3b414b;
    --accent: #7fb8d1; --accent-ink: #a9d4e6; --accent-wash: #17303a;
    --pass: #6cc08b; --warn: #d3a856; --fail: #dd8f83;
    --series-1: #7fb8d1; --series-2: #d3a856; --series-3: #9aa6b2;
    --shadow-sm: 0 1px 2px rgba(0,0,0,0.35); --shadow-md: 0 8px 26px rgba(0,0,0,0.45);
  }
}
* { box-sizing: border-box; }
html { scroll-behavior: smooth; scroll-padding-top: calc(var(--nav-h) + 16px); }
@media (prefers-reduced-motion: reduce) {
  html { scroll-behavior: auto; }
}
:focus-visible { outline: 3px solid var(--accent); outline-offset: 4px; }
.skip-link { position: absolute; top: 12px; left: 24px; z-index: 10;
  padding: 12px 16px; background: var(--paper); color: var(--ink);
  transform: translateY(-200%); }
.skip-link:focus { transform: translateY(0); }
body { margin: 0; padding: 0; font-family: var(--font-body); color: var(--ink);
  background: var(--paper); font-size: 15.5px; line-height: 1.62;
  overflow-x: hidden; -webkit-font-smoothing: antialiased;
  text-rendering: optimizeLegibility; }

/* Masthead */
header { background: var(--surface); border-bottom: 1px solid var(--line);
  box-shadow: var(--shadow-sm); }
.masthead { max-width: 1140px; margin: 0 auto; padding: 34px 40px 26px;
  display: flex; align-items: flex-start; justify-content: space-between; gap: 24px; }
.masthead::before { content: ""; position: absolute; left: 0; right: 0; top: 0;
  height: 3px; background: linear-gradient(90deg, var(--accent), transparent 70%); }
header { position: relative; }
.eyebrow { display: inline-block; font-size: 11px; letter-spacing: 0.18em;
  text-transform: uppercase; color: var(--accent); font-weight: 700;
  margin-bottom: 8px; }
h1 { margin: 0; font-family: var(--font-display); font-size: 34px; font-weight: 700;
  letter-spacing: -0.5px; line-height: 1.05; color: var(--ink); }
h1.wordmark { font-family: "Inter", "Helvetica Neue", Arial, sans-serif; font-weight: 800;
  letter-spacing: -1px; }
h1.wordmark span { color: var(--brand); }
.mast-sub { margin: 9px 0 0; color: var(--ink-soft); font-size: 13.5px;
  max-width: 640px; }
.theme-toggle { flex: none; border: 1px solid var(--line-strong);
  background: var(--surface-2); color: var(--ink-soft); border-radius: 999px;
  padding: 7px 14px; font: inherit; font-size: 12.5px; cursor: pointer;
  display: inline-flex; align-items: center; gap: 7px; transition: all .15s ease; }
.theme-toggle:hover { color: var(--accent); border-color: var(--accent); }

/* Section-index navigation */
nav { position: sticky; top: 0; z-index: 20; height: var(--nav-h);
  background: color-mix(in srgb, var(--surface) 92%, transparent);
  backdrop-filter: saturate(1.4) blur(8px); border-bottom: 1px solid var(--line);
  display: flex; align-items: center; gap: 4px; padding: 0 40px; overflow-x: auto;
  scrollbar-width: none; }
nav::-webkit-scrollbar { display: none; }
nav a { color: var(--ink-soft); text-decoration: none; font-size: 12.5px;
  font-weight: 600; white-space: nowrap; padding: 7px 11px; border-radius: 7px;
  transition: color .12s ease, background .12s ease; }
nav a:hover { color: var(--accent); background: var(--accent-wash); }
nav a.active { color: var(--accent-ink); background: var(--accent-wash); }

main { max-width: 1140px; margin: 0 auto; padding: 40px; }
section { margin-bottom: 56px; scroll-margin-top: calc(var(--nav-h) + 16px); }
h2 { font-family: var(--font-display); font-size: 24px; font-weight: 700;
  letter-spacing: -0.3px; margin: 0 0 8px; padding-left: 14px; position: relative;
  line-height: 1.2; }
h2::before { content: ""; position: absolute; left: 0; top: 5px; bottom: 5px;
  width: 4px; border-radius: 3px; background: var(--accent); }
section > h2 + p, section > h2 + .muted { margin-top: 4px; }
h3 { font-size: 12px; font-weight: 700; letter-spacing: 0.09em;
  text-transform: uppercase; color: var(--ink-soft); margin: 24px 0 8px; }
p { margin: 0 0 14px; }
a { color: var(--accent); overflow-wrap: anywhere; text-underline-offset: 2px; }

/* Tables */
.table-wrap { width: 100%; max-width: 100%; overflow-x: auto; border: 1px solid var(--line);
  border-radius: var(--radius); background: var(--surface); margin: 12px 0;
  box-shadow: var(--shadow-sm); -webkit-overflow-scrolling: touch; }
.table-wrap table { min-width: 680px; }
.table-wrap.compact table { min-width: 520px; }
.table-wrap.wide table { min-width: 920px; }
table { width: 100%; border-collapse: collapse; background: transparent; margin: 0; }
th, td { padding: 11px 14px; text-align: left; border-bottom: 1px solid var(--line);
  font-size: 13px; vertical-align: top; overflow-wrap: anywhere; }
thead th { position: sticky; top: 0; background: var(--surface-2); font-weight: 700;
  color: var(--accent-ink); font-size: 11px; letter-spacing: 0.06em;
  text-transform: uppercase; border-bottom: 1.5px solid var(--line-strong);
  overflow-wrap: normal; word-break: normal; z-index: 1; }
tbody tr { transition: background .1s ease; }
tbody tr:nth-child(even) { background: color-mix(in srgb, var(--surface-2) 55%, transparent); }
tbody tr:hover { background: var(--accent-wash); }
tr:last-child td { border-bottom: none; }
td.numeric { text-align: right; font-variant-numeric: tabular-nums; }
td.mono, code { font-family: var(--font-mono); font-size: 12px;
  overflow-wrap: anywhere; word-break: break-word; }
code { background: var(--surface-2); border: 1px solid var(--line);
  border-radius: 5px; padding: 0.5px 5px; font-size: 12px; color: var(--accent-ink); }
.table-wrap td.mono { white-space: nowrap; overflow-wrap: normal; word-break: normal;
  color: var(--ink-soft); }

/* Cards */
.finding, .run-card, .realism-summary, .overview-card, .recipe-card,
details.evidence-group, #nonuniqueness { background: var(--surface);
  border: 1px solid var(--line); border-radius: var(--radius); }
.finding { padding: 18px 20px; margin-bottom: 14px; box-shadow: var(--shadow-sm);
  transition: box-shadow .15s ease, transform .15s ease; }
.finding:hover { box-shadow: var(--shadow-md); transform: translateY(-1px); }
.finding-head { display: flex; gap: 12px; align-items: baseline; margin-bottom: 8px; }
.finding-num { color: var(--accent); font-weight: 800; font-size: 12px;
  font-family: var(--font-mono); }
.finding-title { font-weight: 700; font-size: 15px; }
.finding-claim { color: var(--ink); margin: 6px 0 10px; }
.finding-meta { font-size: 12px; color: var(--ink-soft); }
.finding-meta a { color: var(--accent); }
.measured-value { margin: 2px 0 4px; padding-left: 18px; }
.measured-value .measured-value { margin: 0; }
.value-key { display: inline-block; max-width: 100%;
  font-family: var(--mono, ui-monospace, monospace); color: var(--ink);
  white-space: normal; overflow-wrap: anywhere; word-break: break-word; }
.muted { color: var(--ink-soft); font-size: 13.5px; }
.kbd { display: inline-block; max-width: 100%; padding: 1.5px 6px;
  border: 1px solid var(--line-strong); border-radius: 5px;
  font-family: var(--font-mono); font-size: 11px; background: var(--surface-2);
  white-space: normal; overflow-wrap: anywhere; word-break: break-word; }
footer { margin: 56px 0 0; padding: 26px 40px; border-top: 1px solid var(--line);
  color: var(--ink-soft); font-size: 12.5px; background: var(--surface); }
footer code { }
.run-card { border-left: 3px solid var(--accent); padding: 16px 20px;
  margin-bottom: 16px; box-shadow: var(--shadow-sm); }
.run-card h3 { margin: 0 0 8px; }
.run-card p { margin: 6px 0; }
.run-card table { margin: 8px 0; }
.lead { font-size: 15.5px; margin: 0 0 16px; }
.thesis { font-family: var(--font-display); font-size: 20px; line-height: 1.4;
  margin: 0 0 18px; max-width: 860px; color: var(--ink); font-weight: 500; }
.sim, .warn { color: var(--warn); font-weight: 700; }
.bad { color: var(--fail); font-weight: 700; }
.real { color: var(--pass); font-weight: 700; }
.realism-summary { padding: 12px 16px; margin: 0 0 16px; border-left: 3px solid var(--accent); }
.overview-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 14px; margin: 20px 0 6px; }
.overview-card { border-top: 3px solid var(--accent); padding: 16px 18px;
  box-shadow: var(--shadow-sm); min-width: 0; }
.overview-card strong { display: block; margin-bottom: 6px; font-size: 13.5px;
  font-weight: 700; }
.overview-card span { display: block; color: var(--ink-soft); font-size: 12.5px; }
.recipe-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 14px; margin: 20px 0 6px; }
.recipe-card { background: var(--surface-2); padding: 16px 18px; min-width: 0; }
.recipe-card strong { display: block; margin-bottom: 8px; }
.recipe-card p { margin: 6px 0; color: var(--ink-soft); font-size: 12.5px; }
.recipe-card code { display: inline-block; margin-top: 6px; white-space: normal;
  overflow-wrap: anywhere; }
details.evidence-group { margin: 10px 0; padding: 13px 16px; }
details.evidence-group summary { cursor: pointer; font-weight: 700; color: var(--accent); }
details.evidence-group p { margin: 8px 0 6px; }
details.evidence-group ul { margin: 8px 0 0; columns: 2; column-gap: 24px; padding-left: 18px; }
details.evidence-group li { break-inside: avoid; margin-bottom: 3px; }
details.evidence-group a,
details.evidence-group code { max-width: 100%; white-space: normal;
  overflow-wrap: anywhere; word-break: break-word; }
#nonuniqueness { border-top: 3px solid var(--accent); padding: 26px 30px;
  box-shadow: var(--shadow-md); }
#nonuniqueness h2 { padding-left: 0; }
#nonuniqueness h2::before { display: none; }

/* Charts (inline SVG rendered by the generator) */
figure.chart { margin: 16px 0; background: var(--surface); border: 1px solid var(--line);
  border-radius: var(--radius); padding: 18px 20px 14px; box-shadow: var(--shadow-sm); }
figure.chart figcaption { font-size: 11px; letter-spacing: 0.08em; text-transform: uppercase;
  color: var(--ink-soft); font-weight: 700; margin-bottom: 12px; }
figure.chart svg { width: 100%; height: auto; display: block; overflow: visible; }
.chart .axis { stroke: var(--line-strong); stroke-width: 1; }
.chart .grid { stroke: var(--line); stroke-width: 1; stroke-dasharray: 2 3; }
.chart .tick { fill: var(--ink-faint); font-size: 10.5px; font-family: var(--font-body); }
.chart .lbl { fill: var(--ink-soft); font-size: 11.5px; font-family: var(--font-body); }
.chart .val { fill: var(--ink); font-size: 11px; font-weight: 700;
  font-variant-numeric: tabular-nums; font-family: var(--font-mono); }
.chart .s1 { fill: var(--series-1); } .chart .s2 { fill: var(--series-2); }
.chart .s3 { fill: var(--series-3); } .chart .s4 { fill: var(--ink-faint); }
.chart .line { fill: none; stroke: var(--series-1); stroke-width: 2.5;
  stroke-linejoin: round; stroke-linecap: round; }
.chart .dot { fill: var(--series-1); }
figure.chart svg.stacked { height: 46px; border-radius: 7px; overflow: hidden; }
.chart-legend { display: flex; flex-wrap: wrap; gap: 6px 20px; margin-top: 12px;
  font-size: 12.5px; color: var(--ink-soft); }
.chart-legend span { display: inline-flex; align-items: center; gap: 7px; }
.chart-legend strong { color: var(--ink); font-variant-numeric: tabular-nums; }
.chart-legend i { width: 11px; height: 11px; border-radius: 3px; display: inline-block; }
.chart-legend i.s1 { background: var(--series-1); }
.chart-legend i.s2 { background: var(--series-2); }
.chart-legend i.s3 { background: var(--series-3); }
.chart-legend i.s4 { background: var(--ink-faint); }

@media (max-width: 900px) {
  .masthead, nav, main, footer { padding-left: 22px; padding-right: 22px; }
  .masthead { flex-direction: column; }
  main { padding-top: 26px; padding-bottom: 26px; max-width: 100%; }
  h1 { font-size: 28px; } h2 { font-size: 21px; }
  .overview-grid, .recipe-grid { grid-template-columns: 1fr; }
  .recipe-card code { display: block; max-width: 100%; white-space: normal;
    word-break: break-word; overflow-wrap: anywhere; }
  details.evidence-group ul { columns: 1; padding-left: 16px; }
  #nonuniqueness { padding: 18px; }
}
@media print {
  nav, .theme-toggle { display: none; }
  body { background: #fff; font-size: 11pt; }
  .finding, .table-wrap, figure.chart, .overview-card { box-shadow: none; break-inside: avoid; }
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


class ClaimLedgerError(ValueError):
    """A decoded document does not satisfy the claim-ledger contract."""


def load_claim_ledger() -> dict:
    """Load the current claim surface that bounds every dashboard statement."""

    path = PROJECT_ROOT / "release" / CLAIM_LEDGER_FILE
    document = json.loads(path.read_text(encoding="utf-8"))
    claims = document.get("claims")
    if not isinstance(claims, list):
        raise ClaimLedgerError("claim ledger must contain a claims list")
    return document


def copy_data_files() -> None:
    """Copy every audit CSV so reviewers can inspect any evidence."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    for src in AUDIT_DIR.glob("*.csv"):
        shutil.copy2(src, DATA_DIR / src.name)
    shutil.copy2(PROJECT_ROOT / "results" / "CORPUS_STATE.md", DATA_DIR / "CORPUS_STATE.md")
    for filename in _STALE_DASHBOARD_FILES:
        path = DATA_DIR / filename
        if path.is_file():
            path.unlink()


def copy_replay_reports() -> None:
    """Copy reviewer replay reports into the dashboard with local paths scrubbed."""
    replay_dest = DATA_DIR / "replay_reports"
    if replay_dest.exists():
        shutil.rmtree(replay_dest)
    replay_dest.mkdir(parents=True, exist_ok=True)
    audit_source = PROJECT_ROOT / "release" / REPLAY_AUDIT_FILE
    if audit_source.is_file():
        shutil.copy2(audit_source, replay_dest / REPLAY_AUDIT_FILE)
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


def remove_legacy_dashboard_evidence() -> None:
    """Drop copied legacy run records without deleting their source-history records."""

    evidence_dir = DATA_DIR / "evidence"
    if evidence_dir.exists():
        shutil.rmtree(evidence_dir)


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


def wrap_table_region(table: str, label: str, wide: bool = False) -> str:
    """Make horizontal table scrolling explicitly keyboard-accessible."""
    classes = "table-wrap wide" if wide else "table-wrap"
    return (
        f"<div class='{classes}' tabindex='0' role='region' "
        f"aria-label='{escape(label, quote=True)}'>{table}</div>"
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
    table = (f"<table><thead><tr>{head}</tr></thead>"
             f"<tbody>{''.join(body_lines)}</tbody></table>")
    return wrap_table_region(table, "Data table: " + ", ".join(header), wide)


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


def render_stacked_bar(segments: list[tuple[str, float, str]], caption: str) -> str:
    """A single 100%-width horizontal bar of labeled segments, with a legend carrying the values.

    ``segments`` is a list of (label, percent, css_class); percents are drawn to scale and shown
    verbatim in the legend, so the figure never asserts a value the table does not.
    """
    width = 1000.0
    total = sum(value for _, value, _ in segments) or 1.0
    offset = 0.0
    rects, legend = [], []
    for label, value, css_class in segments:
        segment_width = width * value / total
        rects.append(
            f"<rect class='{css_class}' x='{offset:.1f}' y='0' "
            f"width='{max(segment_width, 0):.1f}' height='46'/>")
        legend.append(
            f"<span><i class='{css_class}'></i>{escape(label)} &middot; "
            f"<strong>{value:.1f}%</strong></span>")
        offset += segment_width
    svg = (f"<svg class='stacked' viewBox='0 0 {width:.0f} 46' preserveAspectRatio='none' "
           f"role='img' aria-label='{escape(caption)}'>{''.join(rects)}</svg>")
    return (f"<figure class='chart'><figcaption>{escape(caption)}</figcaption>{svg}"
            f"<div class='chart-legend'>{''.join(legend)}</div></figure>")


def _dashboard_href(relative_path: str) -> str:
    """Return a dashboard-relative link to a checked project artifact."""

    path = Path(relative_path)
    if not relative_path or path.is_absolute() or ".." in path.parts:
        raise ValueError(f"unsafe claim-evidence path: {relative_path!r}")
    if not (PROJECT_ROOT / path).is_file():
        raise FileNotFoundError(f"claim evidence is missing: {relative_path}")
    if path.parts and path.parts[0] == "release":
        return (Path("..") / Path(*path.parts[1:])).as_posix()
    return (Path("../..") / path).as_posix()


def _format_scalar(value: object) -> str:
    if isinstance(value, float):
        return f"{value:.3g}"
    return str(value).lower() if isinstance(value, bool) else str(value)


def _ledger_value_html(value: object) -> str:
    """Render a measured value as text, or as a nested key/value list for a mapping."""
    if not isinstance(value, dict):
        return f"<code>{escape(_format_scalar(value))}</code>"
    items = "".join(
        f"<li><span class='value-key'>{escape(str(key))}</span> {_ledger_value_html(value[key])}</li>"
        for key in sorted(value)
    )
    return f"<ul class='measured-value'>{items}</ul>"


def render_claim_ledger(ledger: dict) -> str:
    """Render the generated claim ledger without promoting historical records."""

    blocks = []
    for claim in ledger["claims"]:
        evidence_links = "".join(
            f"<li><a href='{escape(_dashboard_href(path), quote=True)}'>"
            f"<code>{escape(path)}</code></a></li>"
            for path in claim["evidence_artifacts"]
        )
        blocks.append(f"""
<div class='finding'>
  <div class='finding-head'>
    <span class='finding-num'>{escape(claim['claim_id'])}</span>
    <span class='finding-title'><code>{escape(claim['status'])}</code></span>
  </div>
  <div class='finding-claim'>{escape(claim['claim'])}</div>
  <div class='finding-meta'>
    <strong>Scope:</strong> {escape(claim['scope'])}<br>
    <strong>Measured value:</strong> {_ledger_value_html(claim['measured_value'])}<br>
    <strong>Reproduction:</strong> <code>{escape(claim['reproduction_command'])}</code><br>
    <strong>Caveat:</strong> {escape(claim['caveat'])}
  </div>
  <details class='evidence-group'>
    <summary>Evidence artifacts ({len(claim['evidence_artifacts'])})</summary>
    <ul>{evidence_links}</ul>
  </details>
</div>""")

    blocked = "".join(
        "<li><strong>Not claimed:</strong> {}. {}</li>".format(
            escape(item["claim"]), escape(item["reason"])
        )
        for item in ledger["blocked_interpretations"]
    )
    blocks.append(f"""
<details class='evidence-group'>
  <summary>Interpretations explicitly outside the evidence</summary>
  <ul>{blocked}</ul>
</details>""")
    return "\n".join(blocks)


def render_audit_overview(merged, ledger: dict) -> str:
    pct = merged.percentages
    bounded_claims = sum(
        claim["status"] == "supported_bounded" for claim in ledger["claims"]
    )
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
      <strong>Distinct reference roles</strong>
      <span>CVE-2021-41773 is a decoy-variation harness check, not a material
        non-uniqueness witness. Internal SSH and HTTP examples vary service
        implementations under declared invariants.</span>
    </div>
    <div class='overview-card'>
      <strong>Bounded operational witnesses</strong>
      <span>{bounded_claims} ledger claims are supported only within their
        stated witness scope; no card reports a campaign-wide execution rate.</span>
    </div>
    <div class='overview-card'>
      <strong>Boundary</strong>
      <span>No VM images are shipped; VM-backed reproduction uses a local
        provider.</span>
    </div>
  </div>
  {render_stacked_bar([
      ("CTI corpus (grounded)", pct['corpus_supported'], 's1'),
      ("External advisory", pct['external_reference'], 's2'),
      ("AutoSUT-concretized", pct['autosut_concretized'], 's3'),
      ("Analyst-authored (free)", pct['analyst_authored'], 's4'),
  ], f"Environment composition by provenance: {merged.total_elements} SUT elements")}
  <div class='recipe-grid'>
    <div class='recipe-card'>
      <strong>1. Fast deterministic audit</strong>
      <p>Regenerates measurements, figures, traceability files, and value
        checks from the shipped public inputs.</p>
      <code>bash run_review_check.sh</code>
    </div>
    <div class='recipe-card'>
      <strong>2. Inspect claim bounds</strong>
      <p>Read each scope, caveat, and evidence path before interpreting a
        result as operational or general.</p>
      <code>less autosut/release/CLAIM_EVIDENCE_TRACEABILITY.md</code>
    </div>
    <div class='recipe-card'>
      <strong>3. Inspect campaign/SUT contracts</strong>
      <p>See which released campaign definitions declare a SUT profile, pass
        strict pair validation, or remain outside the audited contract set.</p>
      <a href='data/CORPUS_STATE.md'>Open the contract-state report</a>
      <code>less autosut/results/CORPUS_STATE.md</code>
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
        f"materialized across <strong>{len(summaries)}</strong> campaign SUT profiles, "
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
    for name, cve_count in cves_by_name.items():
        rows.append([
            name,
            cve_count,
            str(sw_by_name.get(name, 0)),
            "yes" if plat_by_name.get(name, False) else "no",
            tier_by_name.get(name, ""),
        ])
    return render_table(headers, rows, numeric_cols={2})


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


def _load_replay_report(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle, delimiter="\t")
        return list(reader)


def render_replay_audit() -> str:
    """Show retrospective observations without upgrading them to qualification."""
    audit_path = PROJECT_ROOT / "release" / REPLAY_AUDIT_FILE
    if not audit_path.is_file():
        return "<p class='muted'>No retrospective replay audit is available.</p>"
    audit = ReplayAudit.model_validate_json(audit_path.read_text(encoding="utf-8"))
    records = audit.records
    counts = [record.manifest_counts for record in records if record.manifest_counts]
    complete = len(counts) == len(records)
    total = sum(record.reported_total for record in records)

    def observed_count(field: str) -> str:
        if not complete:
            return "Unavailable: incomplete source manifests"
        return str(sum(getattr(item, field) for item in counts))

    clean = sum(record.reported_clean is True for record in records)
    revision_count = sum(record.recorded_revision is not None for record in records)
    rows = [
        ["Planned steps", str(total), f"{len(records)} recorded campaign cases"],
        ["Status-success steps", observed_count("successful"), "Recorded executor status"],
        ["Execution-category steps", observed_count("evidence_backed_successful"),
         "Successful non-simulated mode with declared file references"],
        ["Referenced files present", observed_count("steps_with_all_references_present"),
         "Steps whose declared files were all present during this offline audit"],
        ["Marker-only steps", observed_count("marker_only_successful"),
         "Conceptual coverage; no technique execution claim"],
        ["Caldera-category steps", observed_count("caldera_driven_successful"),
         "Recorded dispatch mode; included in execution-category steps"],
        ["Inspired execution steps", observed_count("inspired_execution_steps"),
         "Included above; does not establish the technique mechanism"],
        ["Clean namespace recorded", f"{clean}/{len(records)}", "Reported post-run observation"],
        ["Implementation revision recorded", f"{revision_count}/{len(records)}",
         "Required for qualification of a specific implementation"],
    ]
    link = f"data/replay_reports/{REPLAY_AUDIT_FILE}"
    return (
        "<p><strong>Retrospective audit; no current-revision qualification.</strong></p>"
        + render_table(["Observation", "Count", "Interpretation"], rows, wide=True)
        + "<p class='muted'>File presence and hashes do not independently establish "
        "technique fidelity or causal effects. The local trace collection is not bundled "
        "with this audit summary. The observations predate subsequent source changes. "
        f"<a href='{escape(link)}'>Audit records and source-file hashes</a>.</p>"
    )


def render_replay_reports() -> str:
    """Summarize end-to-end replay reports generated by the batch runner."""
    reports = [
        PROJECT_ROOT / "release" / name
        for name in PRIMARY_REPLAY_REPORTS
        if (PROJECT_ROOT / "release" / name).exists()
    ]
    if not reports:
        return render_replay_audit()

    rows = []
    for report in reports:
        entries = _load_replay_report(report)
        if not entries:
            continue
        success = sum(int(row.get("status_successful", row.get("successful", "0"))) for row in entries)
        total = sum(int(row.get("total") or 0) for row in entries)
        elapsed = sum(float(row.get("elapsed_seconds") or 0) for row in entries)
        status = "Unqualified status log"
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
    header = ["Report", "Status", "Campaigns", "Status-success / planned", "Elapsed", "TSV", "JSON"]
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
    table = (
        "<table><thead><tr>"
        f"{head}</tr></thead><tbody>{''.join(body)}</tbody></table>"
    )
    return wrap_table_region(table, "Historical replay audit", wide=True)


REFERENCE_ROLES = {
    "0.cve_2021_41773": "Harness sanity check (external CVE reference)",
    "0.pivot_demo": "Internal service-substitution demonstration",
    "0.web_demo": "Internal service-substitution demonstration",
    "0.apt41_dust": "Structural compatibility illustration",
}


SERVICE_SUBSTITUTIONS = {
    "0.pivot_demo": "OpenSSH and Dropbear",
    "0.web_demo": "Apache and Nginx",
}


def render_reference_details(case_id: str, executable: bool) -> str:
    """Interpret a named case without upgrading its recorded execution status."""
    if not executable:
        return ""
    if case_id == "0.cve_2021_41773":
        return (
            "<p><strong>Harness sanity check:</strong> the external "
            "CVE-2021-41773 reference has recorded execution across decoy-only "
            "variants. This checks the harness, but is not a material "
            "service-substitution witness.</p>")
    if case_id in SERVICE_SUBSTITUTIONS:
        services = SERVICE_SUBSTITUTIONS[case_id]
        return (
            "<p><strong>Internal service-substitution demonstration:</strong> "
            f"<code>{escape(case_id)}</code> has recorded execution across "
            f"{escape(services)} under its declared invariant. These are "
            "controlled internal examples, not historical campaign replays.</p>")
    return ""


def render_subdetermination_section() -> str:
    """Render recorded reference cases and their distinct evidence roles.

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
    details = []
    for case_id, proof in data.get("proofs", {}).items():
        role = REFERENCE_ROLES.get(case_id, "Unclassified reference")
        result = ("Execution recorded in preserved artifact"
                  if proof["executable"] else "Execution not recorded")
        if case_id not in REFERENCE_ROLES:
            result += "; not a classified witness"
        fingerprint = f"{proof['invariant_fingerprint'][:16]}…"
        rows.append(
            f"<tr><td><code>{escape(case_id)}</code><br>{escape(role)}</td>"
            f"<td><code>{escape(fingerprint)}</code></td>"
            f"<td>{len(proof['variants'])}</td>"
            f"<td>{escape(result)}</td>"
            f"<td>{proof['invariant_count']}</td>"
            f"<td>{proof['free_count']}</td></tr>")
        details.append(render_reference_details(case_id, proof["executable"]))
    table = wrap_table_region(
        "<table><thead><tr><th>Reference case</th><th>Declared invariant fingerprint</th>"
        "<th>Generated variants</th><th>Recorded status</th><th>Fixed elements</th>"
        "<th>Free</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>", "Environment non-uniqueness evidence")
    coverage_note = (
        "<p class='muted'>Scope: the fingerprint describes the declared invariant "
        "under source tags assigned to each reference case. It is not independent "
        "validation of historical provenance. Structural compatibility is not "
        "deployment evidence; generated variants and simulated behavior do not "
        "establish observed effects. Recorded execution is preserved evidence, "
        "not a new execution in this dashboard.</p>")
    interpretation = (
        "<p class='muted'>Interpretation: ATT&amp;CK models adversary behavior "
        "and STIX models threat intelligence; neither is designed to specify a "
        "complete executable environment. Non-identification under a defined "
        "projection is a conditional argument; the selected reference cases "
        "do not measure its prevalence across real campaigns.</p>")
    return table + "".join(details) + coverage_note + interpretation


def render_html(
    macros: dict[str, str], provenance_section: str, merged, ledger: dict
) -> str:
    return f"""<!doctype html>
<html lang='en'>
<head>
  <meta charset='utf-8'>
  <meta name='viewport' content='width=device-width, initial-scale=1'>
  <meta name='color-scheme' content='light dark'>
  <link rel='icon' href='autosut-mark.svg' type='image/svg+xml'>
  <title>AutoSUT Evidence Dashboard</title>
  <link rel='stylesheet' href='style.css?v={STYLE_VERSION}'>
  <script>
    try {{ var stored = localStorage.getItem('autosut-theme');
      if (stored === 'light' || stored === 'dark')
        document.documentElement.setAttribute('data-theme', stored);
    }} catch (err) {{ if (err.name !== 'SecurityError') throw err; }}
  </script>
</head>
<body>
<a class='skip-link' href='#main'>Skip to main content</a>
<header>
  <div class='masthead'>
    <div class='mast-brand'>
      <span class='eyebrow'>Evidence &amp; Reproduction</span>
      <h1 class='wordmark'>Auto<span>SUT</span></h1>
      <p class='mast-sub'>Evidence dashboard for reproducing and auditing the study
        claims. Release snapshot: {release_datetime().strftime('%B %d, %Y')}.</p>
    </div>
    <button class='theme-toggle' type='button' onclick='toggleTheme()'
      aria-label='Toggle color theme' aria-pressed='false'>&#9681;&nbsp;Theme</button>
  </div>
</header>
<nav>
  <a href='#overview'>Reviewer path</a>
  <a href='#claims'>Claim ledger</a>
  <a href='#nonuniqueness'>Non-uniqueness proof</a>
  <a href='#provenance'>Reconstruction boundary</a>
  <a href='#findings'>Claim map</a>
  <a href='#replay'>Historical audit</a>
  <a href='#worked'>Worked examples</a>
  <a href='#rules'>Compatibility rules</a>
  <a href='#raw'>Raw evidence</a>
</nav>
<main id='main' tabindex='-1'>
{render_audit_overview(merged, ledger)}
<section id='claims'>
  <h2>Canonical Claim Ledger</h2>
  <p class='muted'>Every current claim is shown with its status, scope, measured
    value, evidence artifacts, and caveat. A bounded status never licenses a
    campaign-wide, historical, or human-effort conclusion.</p>
{render_claim_ledger(ledger).strip()}
</section>
<section id='nonuniqueness'>
  <h2>Environment Non-Uniqueness: Reference Cases</h2>
  <p class='muted'>These records separate an externally anchored CVE harness
    check, internal service-substitution demonstrations, and a structural
    compatibility illustration. Preserving a declared invariant is distinct
    from deployment, observed effects, and historical fidelity. Execution
    status below comes from the preserved artifact, not a live run. Source:
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
  <h2>Historical Record Audit</h2>
  <p class='muted'>This retrospective audit checks existing records and their file
    references. It does not rerun campaigns, certify the current implementation,
    or contribute an operational claim to the canonical ledger.</p>
  {render_replay_reports()}
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
    requirements. Two LLM judges from different model families label a stratified
    sample blind to these labels; their consensus is a reference, not ground
    truth, and disagreements are reported as boundary cases. Sources:
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
<script>
function effectiveTheme() {{
  var explicit = document.documentElement.getAttribute('data-theme');
  return explicit || (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
}}
function syncThemeToggle() {{
  document.querySelector('.theme-toggle').setAttribute('aria-pressed', String(effectiveTheme() === 'dark'));
}}
function toggleTheme() {{
  var current = effectiveTheme();
  var next = current === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  syncThemeToggle();
  try {{ localStorage.setItem('autosut-theme', next); }} catch (err) {{
    if (err.name !== 'SecurityError' && err.name !== 'QuotaExceededError') throw err;
  }}
}}
syncThemeToggle();
window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', syncThemeToggle);
(function () {{
  var links = Array.prototype.slice.call(document.querySelectorAll('nav a'));
  var sections = {{}};
  links.forEach(function (link) {{
    link.addEventListener('focus', function () {{
      var navigation = link.closest('nav');
      var navigationBox = navigation.getBoundingClientRect();
      var linkBox = link.getBoundingClientRect();
      var focusClearance = 8;
      if (linkBox.left < navigationBox.left + focusClearance) {{
        navigation.scrollLeft -= navigationBox.left + focusClearance - linkBox.left;
      }} else if (linkBox.right > navigationBox.right - focusClearance) {{
        navigation.scrollLeft += linkBox.right - navigationBox.right + focusClearance;
      }}
    }});
    var target = document.getElementById(link.getAttribute('href').slice(1));
    if (target) sections[target.id] = link;
  }});
  var observer = new IntersectionObserver(function (entries) {{
    entries.forEach(function (entry) {{
      if (!entry.isIntersecting) return;
      links.forEach(function (link) {{ link.classList.remove('active'); }});
      if (sections[entry.target.id]) sections[entry.target.id].classList.add('active');
    }});
  }}, {{ rootMargin: '-45% 0px -50% 0px', threshold: 0 }});
  Object.keys(sections).forEach(function (id) {{ observer.observe(document.getElementById(id)); }});
}})();
</script>
</body>
</html>"""


def main() -> int:
    DASHBOARD_DIR.mkdir(parents=True, exist_ok=True)
    copy_data_files()
    copy_replay_reports()
    remove_legacy_dashboard_evidence()
    # Provenance is computed once from the catalog and fed to both the download
    # artifacts and the rendered summary, so the page and the files agree.
    summaries, skipped = gpr.collect_summaries()
    merged = provenance.merge_summaries(summaries, campaign_id="ALL")
    copy_provenance_files(summaries, merged, skipped)
    provenance_section = render_provenance_summary(summaries, merged)
    macros = load_macros()
    ledger = load_claim_ledger()
    (DASHBOARD_DIR / "style.css").write_text(STYLE, encoding="utf-8")
    (DASHBOARD_DIR / "autosut-mark.svg").write_text(BRAND_MARK, encoding="utf-8")
    (DASHBOARD_DIR / "index.html").write_text(
        render_html(macros, provenance_section, merged, ledger), encoding="utf-8")
    csv_count = len(list(DATA_DIR.glob("*.csv")))
    print(f"[dashboard] wrote {DASHBOARD_DIR / 'index.html'}")
    print(f"[dashboard] copied {csv_count} CSV evidence files into {DATA_DIR}")
    print(f"[dashboard] rendered {len(ledger['claims'])} canonical claim entries")
    print(f"[dashboard] provenance: {merged.total_elements} elements across "
          f"{len(summaries)} campaigns "
          f"(corpus {merged.percentages['corpus_supported']}%, "
          f"autosut {merged.percentages['autosut_concretized']}%, "
          f"analyst {merged.percentages['analyst_authored']}%)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
