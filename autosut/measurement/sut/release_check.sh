#!/usr/bin/env bash
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1
export PYTEST_DISABLE_PLUGIN_AUTOLOAD=1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AUTOSUT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
MEAS_SCRIPTS="$AUTOSUT_ROOT/measurement/sut/scripts"
WORKSPACE_ROOT="$(cd "$AUTOSUT_ROOT/.." && pwd)"
source "$AUTOSUT_ROOT/scripts/python_env.sh"

PAPER_DIR_SOURCE="none"
if [[ "${PAPER_DIR+x}" == "x" ]]; then
  if [[ ! -d "$PAPER_DIR" ]]; then
    printf '[release-check][FAIL] explicit PAPER_DIR is not a directory: %s\n' \
      "$PAPER_DIR" >&2
    exit 1
  fi
  PAPER_DIR="$(cd "$PAPER_DIR" && pwd -P)"
  if [[ ! -f "$PAPER_DIR/main.tex" ]]; then
    printf '[release-check][FAIL] explicit PAPER_DIR has no main.tex: %s\n' \
      "$PAPER_DIR" >&2
    exit 1
  fi
  PAPER_DIR_SOURCE="explicit"
else
  PAPER_DIR=""
fi

HAS_MANUSCRIPT_DIR=0
if [[ -n "$PAPER_DIR" && -f "$PAPER_DIR/main.tex" ]]; then
  HAS_MANUSCRIPT_DIR=1
fi

SYNC_MANUSCRIPT_VALUES="${SYNC_MANUSCRIPT_VALUES:-0}"
case "$SYNC_MANUSCRIPT_VALUES" in
  0|1) ;;
  *)
    printf '[release-check][FAIL] SYNC_MANUSCRIPT_VALUES must be 0 or 1, got: %s\n' \
      "$SYNC_MANUSCRIPT_VALUES" >&2
    exit 1
    ;;
esac

export AUTOSUT_ROOT
export WORKSPACE_ROOT
export MEAS_SCRIPTS
export PAPER_DIR
export PAPER_DIR_SOURCE
export HAS_MANUSCRIPT_DIR
export SYNC_MANUSCRIPT_VALUES

log() { printf '[release-check] %s\n' "$*"; }
fail() { printf '[release-check][FAIL] %s\n' "$*" >&2; exit 1; }

PYTHON_BIN="$(autosut_resolve_python "$AUTOSUT_ROOT" "$AUTOSUT_ROOT/requirements-reviewer.txt")"

paper_source_fingerprint() {
  "$PYTHON_BIN" - "$PAPER_DIR" <<'PY'
import hashlib
import sys
from pathlib import Path

paper = Path(sys.argv[1])
paths = {
    paper / "main.tex",
    *paper.glob("*.bib"),
    *paper.glob("*.bst"),
    *paper.glob("*.cls"),
    *paper.glob("*.sty"),
    *paper.glob("figures/*.tex"),
    *paper.glob("results/*.tex"),
}
digest = hashlib.sha256()
for path in sorted((path for path in paths if path.is_file()), key=lambda p: p.as_posix()):
    relative = path.relative_to(paper).as_posix().encode("utf-8")
    digest.update(relative)
    digest.update(b"\0")
    digest.update(hashlib.sha256(path.read_bytes()).digest())
print(digest.hexdigest())
PY
}

PAPER_SOURCE_FINGERPRINT_BEFORE=""
if [[ "$HAS_MANUSCRIPT_DIR" == "1" && "$SYNC_MANUSCRIPT_VALUES" == "0" ]]; then
  PAPER_SOURCE_FINGERPRINT_BEFORE="$(paper_source_fingerprint)"
fi

if [[ "$HAS_MANUSCRIPT_DIR" == "1" ]]; then
  log "Manuscript directory ($PAPER_DIR_SOURCE): $PAPER_DIR"
else
  log "No manuscript directory selected; running standalone artifact checks"
fi
if [[ "$SYNC_MANUSCRIPT_VALUES" == "1" && "$HAS_MANUSCRIPT_DIR" != "1" ]]; then
  fail "SYNC_MANUSCRIPT_VALUES=1 requires an explicit PAPER_DIR"
fi

log "0) Verifying required input bundles"
required_inputs=(
  "data/enterprise-attack.json"
  "data/mobile-attack.json"
  "data/ics-attack.json"
  "data/stix-capec.json"
  "data/fight-3.1.0.yaml"
  "data/fight-3.1.0.normalized.json"
  "data/fight-3.1.0.metadata.json"
)
for f in "${required_inputs[@]}"; do
  [[ -f "$MEAS_SCRIPTS/$f" ]] || fail "missing input bundle: $MEAS_SCRIPTS/$f"
done

log "1) Running measurement pipeline"
cd "$MEAS_SCRIPTS"
"$PYTHON_BIN" sut_measurement_pipeline.py >/tmp/measurement_pipeline_release.log 2>&1 || {
  tail -n 120 /tmp/measurement_pipeline_release.log >&2
  fail "pipeline execution failed"
}

log "1b) Rendering TikZ figures from measured outputs"
"$PYTHON_BIN" render_figures.py >/tmp/measurement_render_release.log 2>&1 || {
  tail -n 120 /tmp/measurement_render_release.log >&2
  fail "figure rendering failed"
}

log "1c) Generating traceability appendix"
"$PYTHON_BIN" generate_traceability.py >/tmp/measurement_traceability_release.log 2>&1 || {
  tail -n 120 /tmp/measurement_traceability_release.log >&2
  fail "traceability generation failed"
}

log "1d) Evaluating compatibility manual-validation packet"
"$PYTHON_BIN" evaluate_compatibility_validation.py >/tmp/measurement_validation_release.log 2>&1 || {
  tail -n 120 /tmp/measurement_validation_release.log >&2
  fail "compatibility validation summary generation failed"
}

log "1e) Generating deterministic CVE resolution report"
"$PYTHON_BIN" "$AUTOSUT_ROOT/scripts/generate_cve_resolution_report.py" >/tmp/measurement_cve_resolution_release.log 2>&1 || {
  cat /tmp/measurement_cve_resolution_release.log >&2
  fail "CVE resolution report generation failed"
}

log "1ea) Generating infrastructure and SUT automation coverage report"
"$PYTHON_BIN" "$AUTOSUT_ROOT/scripts/generate_infra_automation_report.py" >/tmp/measurement_infra_automation_release.log 2>&1 || {
  cat /tmp/measurement_infra_automation_release.log >&2
  fail "infrastructure automation report generation failed"
}

log "1eaa) Generating environment provenance report"
"$PYTHON_BIN" "$AUTOSUT_ROOT/scripts/generate_provenance_report.py" >/tmp/measurement_provenance_release.log 2>&1 || {
  cat /tmp/measurement_provenance_release.log >&2
  fail "environment provenance report generation failed"
}

log "1eb) Generating compatibility rule surface report"
"$PYTHON_BIN" "$AUTOSUT_ROOT/scripts/generate_compatibility_rule_surface.py" >/tmp/measurement_rule_surface_release.log 2>&1 || {
  cat /tmp/measurement_rule_surface_release.log >&2
  fail "compatibility rule surface generation failed"
}

if [[ "$HAS_MANUSCRIPT_DIR" == "1" ]]; then
  if [[ "$SYNC_MANUSCRIPT_VALUES" == "1" ]]; then
    log "1f) Opt-in enabled: synchronizing manuscript values and generated figure templates"
    "$PYTHON_BIN" "$AUTOSUT_ROOT/scripts/sync_manuscript_values.py" >/tmp/measurement_sync_release.log 2>&1 || {
      cat /tmp/measurement_sync_release.log >&2
      fail "manuscript value synchronization failed"
    }

    generated_figure_dir="$MEAS_SCRIPTS/results/rendered_figures"
    paper_figure_dir="$PAPER_DIR/figures"
    mkdir -p "$paper_figure_dir"
    generated_figure_count=0
    for generated_figure in "$generated_figure_dir"/*.tex; do
      [[ -f "$generated_figure" ]] || continue
      cp "$generated_figure" "$paper_figure_dir/"
      ((generated_figure_count += 1))
    done
    ((generated_figure_count > 0)) || fail "no generated figure templates found in $generated_figure_dir"
    log "Copied $generated_figure_count generated figure template(s) into the manuscript (explicit opt-in)"
  else
    log "1f) Validating manuscript values against measured outputs (read-only)"
    "$PYTHON_BIN" "$AUTOSUT_ROOT/scripts/sync_manuscript_values.py" --check >/tmp/measurement_sync_release.log 2>&1 || {
      cat /tmp/measurement_sync_release.log >&2
      fail "manuscript values differ from measured outputs"
    }
  fi
else
  log "1f) No explicit manuscript tree selected; skipping manuscript integration"
fi

log "2) Checking required output artifacts"
required=(
  "results/todo_values.json"
  "results/todo_values_latex.tex"
  "results/figures_data.json"
  "results/audit/all_cves.csv"
  "results/audit/campaign_cves.csv"
  "results/audit/cve_resolution_candidates.csv"
  "results/audit/campaign_software.csv"
  "results/audit/campaign_platforms_software_only.csv"
  "results/audit/campaign_os_family_counts.csv"
  "results/audit/campaign_non_os_platform_counts.csv"
  "results/audit/campaign_platform_unknown.csv"
  "results/audit/is_cves.csv"
  "results/audit/is_software.csv"
  "results/audit/initial_access_campaigns.csv"
  "results/audit/initial_access_techniques.csv"
  "results/audit/profile_specificity_software_only.csv"
  "results/audit/profile_ablation_summary.csv"
  "results/audit/evidence_threshold_curve.csv"
  "results/audit/delta_sensitivity.csv"
  "results/audit/bootstrap_confusion_distribution.csv"
  "results/audit/platform_distribution.csv"
  "results/audit/cve_validation.csv"
  "results/audit/technique_compatibility.csv"
  "results/audit/compatibility_denominator_summary.csv"
  "results/audit/compatibility_rule_breakdown.csv"
  "results/audit/compatibility_validation_sample.csv"
  "results/compatibility_validation_summary.json"
  "results/audit/compatibility_validation_confusion.csv"
  "results/audit/compatibility_validation_disagreements.csv"
)
for f in "${required[@]}"; do
  [[ -f "$f" ]] || fail "missing artifact: $MEAS_SCRIPTS/$f"
done
[[ -f "$AUTOSUT_ROOT/results/cve_resolution_candidates.json" ]] || fail "missing artifact: $AUTOSUT_ROOT/results/cve_resolution_candidates.json"
[[ -f "$AUTOSUT_ROOT/results/CVE_RESOLUTION_CANDIDATES.md" ]] || fail "missing artifact: $AUTOSUT_ROOT/results/CVE_RESOLUTION_CANDIDATES.md"
[[ -f "$AUTOSUT_ROOT/release/cve_resolution_candidates.json" ]] || fail "missing artifact: $AUTOSUT_ROOT/release/cve_resolution_candidates.json"
[[ -f "$AUTOSUT_ROOT/release/CVE_RESOLUTION_CANDIDATES.md" ]] || fail "missing artifact: $AUTOSUT_ROOT/release/CVE_RESOLUTION_CANDIDATES.md"
[[ -f "$AUTOSUT_ROOT/results/infra_automation_coverage.json" ]] || fail "missing artifact: $AUTOSUT_ROOT/results/infra_automation_coverage.json"
[[ -f "$AUTOSUT_ROOT/results/INFRA_AUTOMATION_COVERAGE.md" ]] || fail "missing artifact: $AUTOSUT_ROOT/results/INFRA_AUTOMATION_COVERAGE.md"
[[ -f "$AUTOSUT_ROOT/results/infra_automation_coverage.csv" ]] || fail "missing artifact: $AUTOSUT_ROOT/results/infra_automation_coverage.csv"
[[ -f "$AUTOSUT_ROOT/release/infra_automation_coverage.json" ]] || fail "missing artifact: $AUTOSUT_ROOT/release/infra_automation_coverage.json"
[[ -f "$AUTOSUT_ROOT/release/INFRA_AUTOMATION_COVERAGE.md" ]] || fail "missing artifact: $AUTOSUT_ROOT/release/INFRA_AUTOMATION_COVERAGE.md"
[[ -f "$AUTOSUT_ROOT/release/provenance/environment_provenance.json" ]] || fail "missing artifact: $AUTOSUT_ROOT/release/provenance/environment_provenance.json"
[[ -f "$AUTOSUT_ROOT/release/provenance/support_matrix.csv" ]] || fail "missing artifact: $AUTOSUT_ROOT/release/provenance/support_matrix.csv"
[[ -f "$AUTOSUT_ROOT/release/provenance/ENVIRONMENT_PROVENANCE.md" ]] || fail "missing artifact: $AUTOSUT_ROOT/release/provenance/ENVIRONMENT_PROVENANCE.md"
[[ -f "$AUTOSUT_ROOT/release/provenance/provenance_values.tex" ]] || fail "missing artifact: $AUTOSUT_ROOT/release/provenance/provenance_values.tex"
[[ -f "$AUTOSUT_ROOT/results/compatibility_rule_surface.json" ]] || fail "missing artifact: $AUTOSUT_ROOT/results/compatibility_rule_surface.json"
[[ -f "$AUTOSUT_ROOT/results/COMPATIBILITY_RULE_SURFACE.md" ]] || fail "missing artifact: $AUTOSUT_ROOT/results/COMPATIBILITY_RULE_SURFACE.md"
[[ -f "$AUTOSUT_ROOT/release/compatibility_rule_surface.json" ]] || fail "missing artifact: $AUTOSUT_ROOT/release/compatibility_rule_surface.json"
[[ -f "$AUTOSUT_ROOT/release/COMPATIBILITY_RULE_SURFACE.md" ]] || fail "missing artifact: $AUTOSUT_ROOT/release/COMPATIBILITY_RULE_SURFACE.md"

log "3) Validating key numeric invariants"
"$PYTHON_BIN" - <<'PY'
import json, csv, os, sys
from pathlib import Path
base = Path('results')
with open(base/'todo_values.json') as f:
    d = json.load(f)

checks = []
checks.append((d['enterprise_platform_count'] == 691, 'enterprise_platform_count must be 691'))
checks.append((d['enterprise_campaigns_with_software_count'] == 47, 'campaigns_with_software_count must be 47'))
checks.append((d['enterprise_campaigns_with_platform_signal_count'] == 47, 'campaigns_with_platform_signal_count must be 47'))
checks.append((d['enterprise_campaigns_platform_unknown_count'] == 5, 'campaigns_platform_unknown_count must be 5'))
checks.append((d['ent_campaigns_with_cve_count'] == 5, 'campaigns_with_cve_count must be 5'))
checks.append((d['compatibility_container_feasible_count'] + d['compatibility_vm_required_count'] + d['compatibility_infrastructure_dependent_count'] == d['enterprise_platform_count'], 'CF+VMR+ID must equal enterprise_platform_count'))
checks.append((d['compatibility_explicit_assignment_count'] + d['compatibility_fallback_assignment_count'] == d['enterprise_platform_count'], 'explicit + fallback assignments must equal enterprise_platform_count'))
checks.append((d['compatibility_assignment_coverage_before_fallback_percentage'] == d['compatibility_explicit_assignment_percentage'], 'pre-fallback assignment coverage denominator mismatch'))
checks.append((d['compatibility_assignment_coverage_after_fallback_percentage'] == 100.0, 'post-fallback assignment coverage must be 100%'))
checks.append((d['compatibility_assignment_coverage_gain_pp'] == d['compatibility_fallback_assignment_percentage'], 'assignment coverage gain must equal corpus-wide fallback share'))
checks.append((d['compatibility_resolution_gain_pp'] == 67.3, 'legacy resolution-gain macro must no longer emit invalid 58.9 pp'))
checks.append((d['compatibility_explicit_non_cf_count'] == 207, 'explicit non-CF numerator must be 207'))
checks.append((d['compatibility_explicit_non_cf_percentage'] == 91.6, 'explicit-only non-CF composition must be 207/226 = 91.6%'))
checks.append((d['compatibility_final_non_cf_corpus_percentage'] == 97.3, 'final corpus-wide non-CF share must be 672/691 = 97.3%'))
checks.append((d['threshold_k_one_confusion_pct'] >= d['threshold_k_three_confusion_pct'], 'confusion should not increase from k>=1 to k>=3'))
checks.append((d['threshold_k_one_confusion_pct'] >= d['threshold_k_two_confusion_pct'], 'confusion should not increase from k>=1 to k>=2'))
checks.append((d['threshold_k_two_confusion_pct'] >= d['threshold_k_three_confusion_pct'], 'confusion should not increase from k>=2 to k>=3'))
checks.append((d['threshold_k_three_confusion_pct'] >= d['threshold_k_five_confusion_pct'], 'confusion should not increase from k>=3 to k>=5'))
checks.append((d['threshold_k_two_sample'] > 0, 'threshold_k_two_sample must be > 0'))
checks.append((d['delta_zero_zero_five_confusion_pct'] <= d['delta_zero_ten_confusion_pct'], 'confusion should not decrease when delta goes 0.05 -> 0.10'))
checks.append((d['delta_zero_ten_confusion_pct'] <= d['delta_zero_fifteen_confusion_pct'], 'confusion should not decrease when delta goes 0.10 -> 0.15'))
checks.append((d['enterprise_campaigns_with_software_ci_low'] <= d['enterprise_campaigns_with_software_percentage'] <= d['enterprise_campaigns_with_software_ci_high'], 'campaign software CI must bound point estimate'))
checks.append((d['ent_campaigns_with_cve_ci_low'] <= d['ent_campaigns_with_cve_pct'] <= d['ent_campaigns_with_cve_ci_high'], 'campaign CVE CI must bound point estimate'))
checks.append((d['campaigns_with_initial_access_ci_low'] <= d['campaigns_with_initial_access_pct'] <= d['campaigns_with_initial_access_ci_high'], 'initial access CI must bound point estimate'))
checks.append((d['bootstrap_confusion_ci_low'] <= d['bootstrap_confusion_pct'] <= d['bootstrap_confusion_ci_high'], 'bootstrap confusion CI must bound point estimate'))
checks.append((d['bootstrap_unique_ci_low'] <= d['bootstrap_unique_pct'] <= d['bootstrap_unique_ci_high'], 'bootstrap unique CI must bound point estimate'))
checks.append((0.0 <= d['sut_profile_confusion_software_platform_percentage'] <= 100.0, 'software+platform confusion pct out of range'))
checks.append((0.0 <= d['sut_profile_confusion_software_cve_platform_percentage'] <= 100.0, 'software+cve+platform confusion pct out of range'))
checks.append((0.0 <= d['sut_profile_confusion_software_family_only_percentage'] <= 100.0, 'software+family confusion pct out of range'))
checks.append((0.0 <= d['sut_profile_confusion_software_compat_percentage'] <= 100.0, 'software+compat confusion pct out of range'))
checks.append((d['capec_platform_percentage'] == 0.0, 'CAPEC platform percentage must be 0.0 for this bundle'))
checks.append((d['capec_software_link_pct'] == 0.0, 'CAPEC software-link percentage must be 0.0 for this bundle'))
checks.append((d['capec_cve_link_pct'] == 0.0, 'CAPEC CVE-link percentage must be 0.0 for this bundle'))
checks.append((d['capec_active_attack_pattern_count'] == 558, 'active CAPEC denominator must exclude 56 Deprecated and 1 Obsolete patterns'))

with open(base/'figures_data.json', encoding='utf-8') as f:
    figures = json.load(f)
checks.append((
    figures['coverage_chart']['capec']['attack_pattern_n'] == d['capec_active_attack_pattern_count'],
    'CAPEC figure denominator must match the active CAPEC measurement population',
))

with open(base/'compatibility_validation_summary.json', encoding='utf-8') as f:
    validation = json.load(f)
checks.append((validation['total_sample_rows'] == d['compatibility_validation_sample_size'], 'compatibility validation sample size mismatch'))
checks.append((validation['status'] in {'pending_manual_labels', 'partial_manual_labels', 'ready'}, 'unexpected compatibility validation status'))
if validation['status'] == 'pending_manual_labels':
    checks.append((validation['agreement_pct'] is None, 'pending manual labels must not emit a fake 0% agreement'))

unknown_names = []
with open(base/'audit'/'campaign_platform_unknown.csv', newline='', encoding='utf-8') as f:
    r = csv.DictReader(f)
    unknown_names = sorted(row['campaign_name'] for row in r if row.get('campaign_name'))
expected_unknown = sorted([
    'FrostyGoop Incident',
    'KV Botnet Activity',
    'Leviathan Australian Intrusions',
    'SPACEHOP Activity',
    'ShadowRay'
])
checks.append((unknown_names == expected_unknown, 'unknown campaign list mismatch'))

campaign_cve_map = {}
with open(base/'audit'/'campaign_cves.csv', newline='', encoding='utf-8') as f:
    r = csv.DictReader(f)
    for row in r:
        try:
            if int(row.get('cve_count', '0')) > 0:
                cves = '; '.join(c.strip() for c in row.get('cves', '').split(';') if c.strip())
                campaign_cve_map[row['campaign_name']] = cves
        except ValueError:
            continue
expected_campaign_cve_map = {
    'APT28 Nearest Neighbor Campaign': 'CVE-2022-38028',
    'ShadowRay': 'CVE-2023-48022',
    'Operation MidnightEclipse': 'CVE-2024-3400',
    'Versa Director Zero Day Exploitation': 'CVE-2024-39717',
    'SharePoint ToolShell Exploitation': 'CVE-2025-49704; CVE-2025-49706; CVE-2025-53770; CVE-2025-53771',
}
checks.append((campaign_cve_map == expected_campaign_cve_map, 'campaign-linked CVE table source map mismatch'))

with open(Path(os.environ['AUTOSUT_ROOT'])/'results'/'cve_resolution_candidates.json', encoding='utf-8') as f:
    resolution = json.load(f)
resolution_totals = resolution['totals']
checks.append((resolution_totals['total_cve_positive_campaigns'] == 5, 'CVE resolution campaign count mismatch'))
checks.append((resolution_totals['total_campaign_cve_pairs'] == 8, 'CVE resolution pair count mismatch'))
checks.append((resolution_totals['automatic_candidate_pairs'] == 1, 'automatic CVE candidate pair count mismatch'))
checks.append((resolution_totals['automatic_candidate_campaigns'] == 1, 'automatic CVE candidate campaign count mismatch'))
checks.append((resolution_totals['direct_attck_binding_pairs'] == 0, 'direct ATT&CK target-product binding count mismatch'))
checks.append((resolution_totals['open_package_pairs'] == 1, 'open-package CVE pair count mismatch'))
checks.append((resolution_totals['open_package_campaigns'] == 1, 'open-package CVE campaign count mismatch'))

shadowray_resolution = next(
    row
    for row in resolution['rows']
    if row['campaign_name'] == 'ShadowRay' and row['cve_id'] == 'CVE-2023-48022'
)
checks.append((shadowray_resolution['resolution_kind'] == 'open_package', 'ShadowRay resolution kind mismatch'))
checks.append((shadowray_resolution['ecosystem'] == 'pip', 'ShadowRay ecosystem mismatch'))
checks.append((shadowray_resolution['package_name'] == 'ray', 'ShadowRay package name mismatch'))
checks.append((shadowray_resolution['automatic_sut_support'] is True, 'ShadowRay automatic support mismatch'))
checks.append((shadowray_resolution['attck_binding_status'] == 'cve_only_curated_binding', 'ShadowRay binding status mismatch'))
checks.append((shadowray_resolution['source_basis'] == 'NVD CVE record plus PyPI package metadata and release tags', 'ShadowRay source basis mismatch'))
checks.append(('https://pypi.org/project/ray/' in shadowray_resolution['evidence_sources'], 'ShadowRay evidence sources missing PyPI URL'))

with open(Path(os.environ['AUTOSUT_ROOT'])/'results'/'compatibility_rule_surface.json', encoding='utf-8') as f:
    rule_surface = json.load(f)
checks.append((rule_surface['default_fallback_class'] == 'VMR', 'compatibility rule surface fallback mismatch'))
checks.append(('Windows Domain' in rule_surface['id_platform_keywords'], 'compatibility rule surface missing Windows Domain keyword'))
checks.append(('kerberos' in rule_surface['lateral_software_keywords'], 'compatibility rule surface missing kerberos keyword'))
checks.append(('boot|firmware|kernel' in rule_surface['kernel_boot_regex'], 'compatibility rule surface missing kernel regex fragment'))
checks.append(('lsass' in rule_surface['vmr_name_regex'], 'compatibility rule surface missing lsass regex fragment'))

with open(Path(os.environ['AUTOSUT_ROOT'])/'results'/'infra_automation_coverage.json', encoding='utf-8') as f:
    infra = json.load(f)
infra_totals = infra['totals']
evidence_root = Path(os.environ['AUTOSUT_ROOT']) / 'release' / 'evidence'
dashboard_evidence_root = Path(os.environ['AUTOSUT_ROOT']) / 'release' / 'dashboard' / 'data' / 'evidence'
expected_evidence_campaigns = 0
for campaign_id in {row['campaign_id'] for row in infra['rows']}:
    has_evidence = any(
        evidence_dir.exists()
        and any(
            candidate.is_dir()
            and candidate.name.startswith(f"{campaign_id}_")
            for candidate in evidence_dir.iterdir()
        )
        for evidence_dir in (dashboard_evidence_root, evidence_root)
    )
    expected_evidence_campaigns += int(has_evidence)
checks.append((infra_totals['published_campaigns'] == 14, 'infra coverage published campaign count mismatch'))
checks.append((infra_totals['campaigns_with_strict_pair_validation'] == 12, 'infra coverage pair-valid count mismatch'))
checks.append((infra_totals['campaigns_with_base_weaknesses'] == 14, 'infra coverage base-weakness count mismatch'))
checks.append((infra_totals['campaigns_with_step_overlays'] == 1, 'infra coverage overlay count mismatch'))
checks.append((infra_totals['campaigns_with_latest_evidence'] == expected_evidence_campaigns, 'infra coverage evidence count mismatch'))
checks.append((infra_totals['campaigns_with_single_target_host'] == 14, 'infra coverage single-target count mismatch'))
checks.append((infra_totals['campaigns_with_multi_target_host'] == 0, 'infra coverage multi-target count mismatch'))
checks.append((infra_totals['campaigns_with_multi_vm_runtime'] == 14, 'infra coverage multi-VM count mismatch'))

# Dataset table totals in main.tex are currently static and must stay aligned
# with local bundles used by the pipeline.
expected_bundle_totals = {
    'enterprise-attack.json': {'attack-pattern': 835, 'campaign': 52, 'intrusion-set': 187, 'malware': 696, 'tool': 91},
    'mobile-attack.json': {'attack-pattern': 190, 'campaign': 3, 'intrusion-set': 17, 'malware': 121, 'tool': 2},
    'ics-attack.json': {'attack-pattern': 95, 'campaign': 8, 'intrusion-set': 16, 'malware': 30, 'tool': 0},
    'stix-capec.json': {'attack-pattern': 615, 'campaign': 0, 'intrusion-set': 0, 'malware': 0, 'tool': 0},
}
for fname, exp in expected_bundle_totals.items():
    with open(Path('data')/fname, encoding='utf-8') as f:
        bundle = json.load(f).get('objects', [])
    counts = {'attack-pattern': 0, 'campaign': 0, 'intrusion-set': 0, 'malware': 0, 'tool': 0}
    for o in bundle:
        t = o.get('type')
        if t in counts:
            counts[t] += 1
    checks.append((counts == exp, f'bundle total count mismatch for {fname}: {counts} != {exp}'))

with open(Path('data')/'fight-3.1.0.normalized.json', encoding='utf-8') as f:
    fight = json.load(f)
expected_fight_counts = {
    'techniques': 183,
    'with_platforms': 140,
    'with_architecture_segments': 163,
    'with_software': 25,
    'with_cves': 5,
    'fight_namespace_ids': 183,
}
checks.append((fight.get('schema_version') == 'autosut.fight-normalized.v1', 'FiGHT normalized schema mismatch'))
checks.append((fight.get('counts') == expected_fight_counts, f"FiGHT normalized count mismatch: {fight.get('counts')} != {expected_fight_counts}"))
checks.append((len(fight.get('techniques', [])) == 183, 'FiGHT normalized technique population mismatch'))

bad = [msg for ok, msg in checks if not ok]
if bad:
    for msg in bad:
        print('[release-check][FAIL]', msg)
    sys.exit(1)
print('[release-check] numeric invariants OK')
PY

if [[ "$HAS_MANUSCRIPT_DIR" == "1" ]]; then
log "3b) Validating static tables in manuscript against measured artifacts"
"$PYTHON_BIN" - <<'PY'
import csv, re, sys
import os
from pathlib import Path

paper_dir = Path(os.environ["PAPER_DIR"])
meas_scripts = Path(os.environ["MEAS_SCRIPTS"])
main = (paper_dir / 'main.tex').read_text(encoding='utf-8')

required_dataset_rows = [
    (
        "Enterprise dataset row",
        [
            r"Enterprise & \enterprisetotalattackpatterncount{} & \enterpriseactivecampaigncount{} & \enterprisetotalintrusionsetcount{} & \enterprisetotalsoftwarecount{} \\",
            r"Enterprise & \enterprisetotalattackpatterncount{} & \enterpriseactivecampaigncount{}  & \enterprisetotalintrusionsetcount{} & \enterprisetotalmalwarecount{} & \enterprisetotaltoolcount{} \\",
            r"Enterprise & 835 & 52  & 187 & 696 & 91 \\",
        ],
    ),
    (
        "Mobile dataset row",
        [r"Mobile     & 190 & 3 & 17 & 123 \\"],
    ),
    (
        "ICS dataset row",
        [r"ICS        & 95 & 8 & 16 & 30 \\"],
    ),
    (
        "CAPEC raw-snapshot dataset row",
        [r"CAPEC      & 615 & 0 & 0 & 0 \\"],
    ),
    (
        "FiGHT dataset row",
        [r"FiGHT      & \fighttechniquecount{} & \fightcampaigncount{} & \fightgroupcount{} & \fightsoftwarecount{} \\"],
    ),
]
for label, alternatives in required_dataset_rows:
    if not any(row in main for row in alternatives):
        print(f"[release-check][FAIL] dataset table row missing/mismatched: {label}")
        sys.exit(1)

dataset_label = main.find(r"\label{tab:dataset}")
dataset_table_context = main[max(0, dataset_label - 600):dataset_label + 1200]
snapshot_scope_is_explicit = (
    "source snapshot" in dataset_table_context.lower()
    and (
        "before preprocessing" in dataset_table_context.lower()
        or "raw snapshot" in dataset_table_context.lower()
    )
)
if not snapshot_scope_is_explicit:
    print("[release-check][FAIL] dataset table must identify its 615 CAPEC patterns as raw snapshot totals")
    sys.exit(1)

coverage_figure = (paper_dir / 'figures' / 'coverage_template.tex').read_text(encoding='utf-8')
active_capec_count = 558
if (
    f"n={active_capec_count}" not in coverage_figure
    and r"\capecactiveattackpatterncount" not in coverage_figure
):
    print(f"[release-check][FAIL] coverage figure does not expose active CAPEC n={active_capec_count}")
    sys.exit(1)

campaign_cves = {}
with open(meas_scripts / 'results' / 'audit' / 'campaign_cves.csv', newline='', encoding='utf-8') as f:
    for row in csv.DictReader(f):
        if int(row.get('cve_count', '0')) > 0:
            cves = [cve.strip() for cve in row['cves'].split(';') if cve.strip()]
            campaign_cves[row['campaign_name']] = cves

# Content check: each CVE-positive campaign and its CVEs must appear in main.tex,
# regardless of how the author chose to format the table row.
for name, cves in campaign_cves.items():
    if name not in main:
        print(f"[release-check][FAIL] campaign with CVEs missing from main.tex: {name}")
        sys.exit(1)
    for cve in cves:
        # Accept both full form ("CVE-2025-49706") and abbreviated form ("-49706")
        # for compact tables that share a year prefix.
        cve_short = '-' + cve.split('-', 2)[2] if cve.count('-') >= 2 else cve
        if cve not in main and cve_short not in main:
            print(f"[release-check][FAIL] {cve} ({name}) missing from main.tex")
            sys.exit(1)

# Profile-completeness rows: the paper must mention every CVE-positive campaign
# alongside a semantically equivalent evidence-tier label.  The compact table
# uses ``Associated``/``Unanchored``; the dashboard spells the same categories
# out as ``CVE-associated``/``Not anchored``.  Treat vocabulary as presentation,
# but never accept a category change.
profile_tiers = {}
with open(meas_scripts / 'results' / 'audit' / 'campaign_profile_completeness.csv', newline='', encoding='utf-8') as f:
    for row in csv.DictReader(f):
        profile_tiers[row['campaign_name']] = (
            ('CVE-associated', 'Associated')
            if row['tier_t3_cve_associated'] == 'True'
            else ('Not anchored', 'Unanchored')
        )

for name in campaign_cves:
    accepted_tiers = profile_tiers[name]
    # Look for the tier label within 200 characters of the campaign name to
    # confirm the author placed them in the same row/paragraph.
    for match in re.finditer(re.escape(name), main):
        window = main[match.end(): match.end() + 200]
        if any(tier in window for tier in accepted_tiers):
            break
    else:
        expected = " or ".join(repr(tier) for tier in accepted_tiers)
        print(f"[release-check][FAIL] tier {expected} not found near {name} in main.tex")
        sys.exit(1)

# Rule breakdown rows: each rule must have its count and percentage rendered
# somewhere in main.tex with a recognizable label.
rule_labels = {
    'R1_ID_PLATFORM_KEYWORD': 'Domain, identity, or cloud cue',
    'R3_ID_LATERAL_TACTIC': 'Lateral-movement tactic cue',
    'R4_VMR_KERNEL_BOOT': 'Kernel or boot pattern',
    'R6_VMR_NAME_PATTERN': 'Privileged or kernel name pattern',
    'R7_CF_CONTAINER_COMPATIBLE': 'Container-compatible targets',
    'R8_DEFAULT_VMR': 'Conservative fallback',
}
with open(meas_scripts / 'results' / 'audit' / 'compatibility_rule_breakdown.csv', newline='', encoding='utf-8') as f:
    for row in csv.DictReader(f):
        label = rule_labels[row['rule_id']]
        count = row['count']
        pct = f"{float(row['pct_all_techniques']):.1f}"
        if label not in main:
            print(f"[release-check][FAIL] rule label missing in main.tex: {label}")
            sys.exit(1)
        # Each rule's row should mention its label, count, and percentage in
        # close proximity (within a typical table row).
        for match in re.finditer(re.escape(label), main):
            window = main[match.start(): match.start() + 200]
            if count in window and pct in window:
                break
        else:
            print(f"[release-check][FAIL] rule '{label}' missing count={count} or pct={pct} near label")
            sys.exit(1)

print('[release-check] static table checks OK')
PY
else
  log "3b) No manuscript tree detected; skipping static table checks"
fi

if [[ "$HAS_MANUSCRIPT_DIR" == "1" ]]; then
log "3c) Enforcing bibliography policy (no poster entries/citations)"
bib_policy_args=()
for bibliography_file in "$PAPER_DIR"/*.bib; do
  [[ -f "$bibliography_file" ]] || continue
  bib_policy_args+=(--input "$bibliography_file")
done
(( ${#bib_policy_args[@]} > 0 )) || fail "no BibTeX files found in $PAPER_DIR"
"$PYTHON_BIN" "$MEAS_SCRIPTS/sanitize_bibliography_policy.py" \
  "${bib_policy_args[@]}" --check >/tmp/measurement_bib_policy_check.log 2>&1 || {
    cat /tmp/measurement_bib_policy_check.log >&2
    fail "bibliography policy check failed"
  }

"$PYTHON_BIN" - <<'PY'
import os
import re
import sys
from pathlib import Path

paper_dir = Path(os.environ["PAPER_DIR"])
main_tex = paper_dir / 'main.tex'
tex = main_tex.read_text(encoding='utf-8')
cite_keys = set()
for group in re.findall(r'\\cite[a-zA-Z*]*\{([^}]*)\}', tex):
    for raw in group.split(','):
        key = raw.strip()
        if key:
            cite_keys.add(key)

poster_like_cites = sorted(k for k in cite_keys if re.search(r'(?i)(poster|kurt|chen_2020)', k))
if poster_like_cites:
    print(f"[release-check][FAIL] poster-like citation keys found in main.tex: {', '.join(poster_like_cites)}")
    sys.exit(1)

print('[release-check] bibliography policy checks OK')
PY
else
  log "3c) No manuscript tree detected; skipping bibliography policy checks"
fi

if [[ "$HAS_MANUSCRIPT_DIR" == "1" ]]; then
log "4) Building manuscript PDF in a read-only validation copy"
manuscript_check_root="$(mktemp -d "${TMPDIR:-/tmp}/autosut-paper-check.XXXXXX")"
manuscript_check_dir="$manuscript_check_root/paper"
mkdir -p "$manuscript_check_dir"
cp -R "$PAPER_DIR/." "$manuscript_check_dir/"
cleanup_manuscript_check() {
  if [[ -n "${manuscript_check_root:-}" && -d "$manuscript_check_root" ]]; then
    rm -rf -- "$manuscript_check_root"
  fi
}
trap cleanup_manuscript_check EXIT
"$PYTHON_BIN" "$AUTOSUT_ROOT/scripts/build_manuscript.py" --paper-dir "$manuscript_check_dir" >/tmp/measurement_paper_release.log 2>&1 || {
  tail -n 120 /tmp/measurement_paper_release.log >&2
  fail "latex build failed"
}
manuscript_build_log="$manuscript_check_dir/build_artifacts/main.log"
[[ -f "$manuscript_build_log" ]] || fail "LaTeX build log is missing from validation copy"
if rg -n \
  'LaTeX Warning: (Reference|Citation).*undefined|Package .* Warning: Citation.*undefined|There were undefined references|Label .* multiply defined|There were multiply-defined labels' \
  "$manuscript_build_log" >/tmp/measurement_latex_reference_warnings.log; then
  cat /tmp/measurement_latex_reference_warnings.log >&2
  fail "manuscript build contains unresolved citations/references or duplicate labels"
fi
cleanup_manuscript_check
trap - EXIT

cd "$PAPER_DIR"

log "5) Ensuring no active TODO placeholders in manuscript body"
# Ignore macro definition line; fail if TODO/TBD markers appear elsewhere.
if rg -n 'TODO\{|\[TBD\]' main.tex | rg -v '^87:' >/tmp/measurement_todo_hits.log; then
  cat /tmp/measurement_todo_hits.log >&2
  fail "found unresolved TODO/TBD markers"
fi

log "5b) Enforcing paper-directory hygiene"
"$PYTHON_BIN" "$AUTOSUT_ROOT/scripts/check_paper_hygiene.py" >/tmp/measurement_paper_hygiene.log 2>&1 || {
  cat /tmp/measurement_paper_hygiene.log >&2
  fail "paper directory hygiene check failed"
}

log "6) Ensuring manuscript imports generated measurement macros"
# Paper now uses results/values.tex (local copy of generated macros)
rg -n '\\input\{results/values\.tex\}' main.tex >/dev/null || \
  fail "main.tex is not importing results/values.tex"

log "6b) Ensuring rendered ablation figure template exists"
[[ -f "$PAPER_DIR/figures/ablation_template.tex" ]] || fail "missing ablation_template.tex"

log "6c) Ensuring rendered tier-collapse figure template exists"
[[ -f "$PAPER_DIR/figures/tier_collapse_template.tex" ]] || fail "missing tier_collapse_template.tex"
else
  log "4-6) No manuscript tree detected; skipping manuscript build and hygiene checks"
fi

log "6d) Ensuring macro coverage report exists and is non-empty"
[[ -f "$MEAS_SCRIPTS/results/macro_coverage.json" ]] || fail "missing macro_coverage.json"
"$PYTHON_BIN" - <<'PY'
import json, sys
import os
from pathlib import Path
meas_scripts = Path(os.environ["MEAS_SCRIPTS"])
p = meas_scripts / 'results' / 'macro_coverage.json'
d = json.loads(p.read_text(encoding='utf-8'))
used = int(d.get('manuscript_macro_count', 0))
generated = int(d.get('generated_macro_count', 0))
if generated <= 0:
    print('[release-check][FAIL] macro coverage report indicates empty generated/used macro sets')
    sys.exit(1)
if os.environ.get("HAS_MANUSCRIPT_DIR") == "1" and used <= 0:
    print('[release-check][FAIL] macro coverage report indicates empty generated/used macro sets')
    sys.exit(1)
print('[release-check] macro coverage report OK')
PY

if [[ "$HAS_MANUSCRIPT_DIR" == "1" ]]; then
log "6e) Checking macro consistency (defined vs used)"
"$PYTHON_BIN" - <<'PY'
import os
import re, sys
from pathlib import Path

paper_dir = Path(os.environ["PAPER_DIR"])
latex_files = [
    paper_dir / 'results' / 'values.tex',
]
main_file  = paper_dir / 'main.tex'

if any(not path.exists() for path in latex_files) or not main_file.exists():
    print('[release-check][WARN] cannot run macro consistency check (files missing)')
    sys.exit(0)

# Extract defined macros from generated LaTeX value files.
defined = set()
for latex_file in latex_files:
    for line in latex_file.read_text(encoding='utf-8').splitlines():
        m = re.match(r'\\newcommand\{\\([A-Za-z]+)\}', line)
        if m:
            defined.add(m.group(1))

# Extract macro uses from main.tex (backslash + alphabetic name)
main_text = main_file.read_text(encoding='utf-8')
used_all = set(re.findall(r'\\([A-Za-z][A-Za-z0-9]+)', main_text))

# Only check against our generated macros
used_from_generated = used_all & defined
used_but_undefined = set()
# Well-known LaTeX/package commands that match our heuristic but are NOT pipeline macros
latex_builtins = {
    'includegraphics', 'definecolor', 'textcolor', 'resizebox',
    'raggedright', 'arraybackslash', 'shortstack', 'nolinkurl',
    'multicolumn', 'bibliography', 'bibliographystyle',
}
# Check if main.tex uses macros that LOOK like pipeline macros but aren't defined
# Heuristic: pipeline macros are camelCase starting with lowercase
for name in used_all:
    if name[0].islower() and len(name) > 8 and name not in defined and name not in latex_builtins:
        # Likely intended as a pipeline macro
        if any(keyword in name.lower() for keyword in [
            'enterprise', 'campaign', 'software', 'compatibility',
            'threshold', 'bootstrap', 'null', 'cve', 'sut', 'delta',
            'capec', 'fight', 'ics', 'mobile', 'jaccard', 'profile',
            'provenance',
        ]):
            used_but_undefined.add(name)

defined_but_unused = defined - used_all

if used_but_undefined:
    print(f'[release-check][WARN] {len(used_but_undefined)} pipeline-like macros used in main.tex but NOT defined in todo_values_latex.tex:')
    for name in sorted(used_but_undefined):
        print(f'  \\{name}')

if defined_but_unused:
    print(f'[release-check][INFO] {len(defined_but_unused)} macros defined in todo_values_latex.tex but not used in main.tex (audit-only metrics)')

print(f'[release-check] macro consistency: {len(defined)} defined, {len(used_from_generated)} used in manuscript, {len(used_but_undefined)} potentially missing')
if used_but_undefined:
    sys.exit(1)
PY
else
  log "6e) No manuscript tree detected; skipping macro consistency check"
fi

log "7) Ensuring traceability appendix exists"
[[ -f "$AUTOSUT_ROOT/measurement/sut/TRACEABILITY.md" ]] || fail "missing TRACEABILITY.md"

if [[ "$HAS_MANUSCRIPT_DIR" == "1" ]]; then
  if [[ "$SYNC_MANUSCRIPT_VALUES" == "0" ]]; then
    PAPER_SOURCE_FINGERPRINT_AFTER="$(paper_source_fingerprint)"
    [[ "$PAPER_SOURCE_FINGERPRINT_AFTER" == "$PAPER_SOURCE_FINGERPRINT_BEFORE" ]] || \
      fail "manuscript source changed during read-only validation; rerun against a stable snapshot"
    log "Manuscript source fingerprint remained stable during read-only validation"
  fi
  log "PASS: pipeline + data + manuscript checks are consistent"
else
  log "PASS: pipeline + data + released output checks are consistent"
fi
