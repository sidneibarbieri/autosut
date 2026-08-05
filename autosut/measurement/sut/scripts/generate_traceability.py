#!/usr/bin/env python3
"""
Generate a claim-to-evidence appendix from measured outputs.
"""

import json
import csv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RESULTS = Path(__file__).resolve().parent / "results"
OUT = Path(__file__).resolve().parents[1] / "TRACEABILITY.md"
CSV_OUT = RESULTS / "claim_evidence_map.csv"


def v(d, k):
    return d.get(k, "N/A")


def add_row(rows, claim_id, paper_anchor, metric_value, metric_key, evidence_files):
    rows.append(
        {
            "claim_id": claim_id,
            "paper_anchor": paper_anchor,
            "measured_value": metric_value,
            "metric_keys": metric_key,
            "evidence_artifacts": evidence_files.replace("`", ""),
        }
    )


def main():
    todo = json.loads((RESULTS / "todo_values.json").read_text(encoding="utf-8"))

    rows = []
    add_row(
        rows, "RQ1-P1", "Analysis: Platform Constraint Coverage",
        f"{v(todo, 'enterprise_platform_count')}/{v(todo, 'enterprise_platform_count')} active attack-patterns ({v(todo, 'enterprise_platform_pct')}%)",
        "enterprise_platform_count, enterprise_platform_pct",
        "`results/todo_values.json`, `results/audit/platform_distribution.csv`",
    )
    add_row(
        rows, "RQ1-P2", "Analysis: Platform Constraint Coverage",
        f"{v(todo, 'enterprise_system_requirements_count')} ({v(todo, 'enterprise_system_requirements_pct')}%)",
        "enterprise_system_requirements_count, enterprise_system_requirements_pct",
        "`results/todo_values.json`",
    )
    add_row(
        rows, "RQ1-P3", "Figure 1 coverage by corpus",
        f"E={v(todo,'enterprise_platform_pct')} M={v(todo,'mobile_platform_pct')} I={v(todo,'ics_platform_percentage')} C={v(todo,'capec_platform_percentage')} F={v(todo,'fight_platform_percentage')}",
        "enterprise_platform_pct, mobile_platform_pct, ics_platform_percentage, capec_platform_percentage, fight_platform_percentage",
        "`results/figures_data.json`, `figures/coverage_template.tex`",
    )
    add_row(
        rows, "RQ1-S1", "Analysis: Software Reference Rate",
        f"campaigns {v(todo,'enterprise_campaigns_with_software_count')}/{v(todo,'enterprise_active_campaign_count')} ({v(todo,'enterprise_campaigns_with_software_percentage')}%, CI {v(todo,'enterprise_campaigns_with_software_ci_low')}-{v(todo,'enterprise_campaigns_with_software_ci_high')}), groups {v(todo,'enterprise_intrusion_sets_with_software_count')}/{v(todo,'enterprise_active_intrusion_set_count')} ({v(todo,'enterprise_intrusion_sets_with_software_percentage')}%)",
        "enterprise_campaigns_with_software_count, enterprise_campaigns_with_software_percentage, enterprise_intrusion_sets_with_software_count, enterprise_intrusion_sets_with_software_percentage",
        "`results/todo_values.json`, `results/audit/campaign_software.csv`, `results/audit/is_software.csv`",
    )
    add_row(
        rows, "RQ1-S2", "Analysis: Version/CPE specificity",
        f"version {v(todo,'software_with_version_signal_percentage')}%, cpe {v(todo,'software_with_cpe_percentage')}%",
        "software_with_version_signal_percentage, software_with_cpe_percentage",
        "`results/todo_values.json`, `results/figures_data.json`",
    )
    add_row(
        rows, "RQ1-C1", "Analysis: Vulnerability Reference Rate",
        f"unique={v(todo,'cve_unique_count')} structured={v(todo,'cve_structured_count')} free-text-only={v(todo,'cve_freetext_only_count')} ({v(todo,'cve_from_freetext_pct')}%)",
        "cve_unique_count, cve_structured_count, cve_freetext_only_count, cve_from_freetext_pct",
        "`results/todo_values.json`, `results/audit/all_cves.csv`, `results/figures_data.json`",
    )
    add_row(
        rows, "RQ1-C2", "Analysis: Campaign/IS CVE coverage",
        f"campaigns {v(todo,'ent_campaigns_with_cve_count')}/{v(todo,'enterprise_active_campaign_count')} ({v(todo,'ent_campaigns_with_cve_pct')}%, CI {v(todo,'ent_campaigns_with_cve_ci_low')}-{v(todo,'ent_campaigns_with_cve_ci_high')}), groups {v(todo,'ent_intrusion_sets_with_cve_count')}/{v(todo,'enterprise_active_intrusion_set_count')} ({v(todo,'ent_intrusion_sets_with_cve_pct')}%)",
        "ent_campaigns_with_cve_count, ent_campaigns_with_cve_pct, ent_intrusion_sets_with_cve_count, ent_intrusion_sets_with_cve_pct",
        "`results/todo_values.json`, `results/audit/campaign_cves.csv`, `results/audit/is_cves.csv`",
    )
    add_row(
        rows, "RQ1-C3", "Analysis: actionable vs illustrative CVEs",
        f"actionable={v(todo,'cve_actionable_count')} technique-only={v(todo,'cve_technique_only_count')} campaign-linked={v(todo,'campaign_linked_cve_count')}",
        "cve_actionable_count, cve_technique_only_count, campaign_linked_cve_count",
        "`results/todo_values.json`, `results/audit/campaign_cves.csv`",
    )
    add_row(
        rows, "RQ1-IA1", "Analysis: Initial Access Signals",
        f"IA techniques={v(todo,'initial_access_technique_count')} campaigns={v(todo,'campaigns_with_initial_access_count')}/{v(todo,'enterprise_active_campaign_count')} ({v(todo,'campaigns_with_initial_access_pct')}%)",
        "initial_access_technique_count, campaigns_with_initial_access_count, campaigns_with_initial_access_pct",
        "`results/todo_values.json`, `results/audit/initial_access_campaigns.csv`, `results/audit/initial_access_techniques.csv`",
    )
    add_row(
        rows, "RQ1-IA2", "Analysis: Initial Access social/CVE overlap",
        f"social-proxy={v(todo,'campaigns_with_social_initial_access_count')} ({v(todo,'campaigns_with_social_initial_access_pct')}%), IA+CVE={v(todo,'campaigns_with_initial_access_and_cve_count')} ({v(todo,'campaigns_with_initial_access_and_cve_pct')}%), IA-no-CVE={v(todo,'campaigns_with_initial_access_no_cve_count')} ({v(todo,'campaigns_with_initial_access_no_cve_pct')}%)",
        "campaigns_with_social_initial_access_count, campaigns_with_initial_access_and_cve_count, campaigns_with_initial_access_no_cve_count",
        "`results/todo_values.json`, `results/audit/initial_access_campaigns.csv`",
    )
    add_row(
        rows, "RQ2-K1", "Analysis: Compatibility table",
        f"CF={v(todo,'compatibility_container_feasible_count')} ({v(todo,'compatibility_container_feasible_percentage')}%), VMR={v(todo,'compatibility_vm_required_count')} ({v(todo,'compatibility_vm_required_percentage')}%), ID={v(todo,'compatibility_infrastructure_dependent_count')} ({v(todo,'compatibility_infrastructure_dependent_percentage')}%)",
        "compatibility_container_feasible_count, compatibility_vm_required_count, compatibility_infrastructure_dependent_count",
        "`results/todo_values.json`, `results/audit/technique_compatibility.csv`",
    )
    add_row(
        rows, "RQ2-O1", "Operationalization headroom: version enrichment",
        f"structured={v(todo,'software_with_version_signal_percentage')}%, description-enriched={v(todo,'software_version_enriched_total_pct')}% (+{v(todo,'software_version_enrichment_gain_pp')} pp)",
        "software_with_version_signal_percentage, software_version_enriched_total_pct, software_version_enrichment_gain_pp",
        "`results/todo_values.json`, `results/audit/software_version_enrichment.csv`",
    )
    add_row(
        rows, "RQ2-O2", "Operationalization headroom: CVE enrichment",
        f"structured={v(todo,'ent_campaigns_with_cve_structured_pct')}%, free-text-enriched={v(todo,'ent_campaigns_with_cve_pct')}% (+{v(todo,'ent_campaigns_with_cve_enrichment_gain_pp')} pp)",
        "ent_campaigns_with_cve_structured_pct, ent_campaigns_with_cve_pct, ent_campaigns_with_cve_enrichment_gain_pp",
        "`results/todo_values.json`, `results/audit/campaign_cves.csv`, `results/audit/all_cves.csv`",
    )
    add_row(
        rows, "RQ2-O3", "Operationalization headroom: compatibility routing policy",
        f"explicit assignments={v(todo,'compatibility_explicit_assignment_count')}/{v(todo,'enterprise_platform_count')} ({v(todo,'compatibility_assignment_coverage_before_fallback_percentage')}%), after fallback={v(todo,'enterprise_platform_count')}/{v(todo,'enterprise_platform_count')} ({v(todo,'compatibility_assignment_coverage_after_fallback_percentage')}%, +{v(todo,'compatibility_assignment_coverage_gain_pp')} pp corpus-wide); explicit-only non-CF composition={v(todo,'compatibility_explicit_non_cf_count')}/{v(todo,'compatibility_explicit_assignment_count')} ({v(todo,'compatibility_explicit_non_cf_percentage')}%)",
        "compatibility_explicit_assignment_count, compatibility_assignment_coverage_before_fallback_percentage, compatibility_assignment_coverage_after_fallback_percentage, compatibility_assignment_coverage_gain_pp, compatibility_explicit_non_cf_count, compatibility_explicit_non_cf_percentage",
        "`results/todo_values.json`, `results/audit/compatibility_denominator_summary.csv`, `results/audit/compatibility_rule_breakdown.csv`, `results/audit/technique_compatibility.csv`",
    )
    add_row(
        rows, "RQ3-J1", "Analysis: Profile specificity",
        f"unique(sw)={v(todo,'sut_profile_unique_software_percentage')}% unique(sw+cve)={v(todo,'sut_profile_unique_software_cve_percentage')}% confused={v(todo,'sut_profile_confusion_software_cve_percentage')}%",
        "sut_profile_unique_software_percentage, sut_profile_unique_software_cve_percentage, sut_profile_confusion_software_cve_percentage",
        "`results/todo_values.json`, `results/figures_data.json`, `figures/jaccard_cdf_template.tex`",
    )
    add_row(
        rows, "RQ3-J2", "Discussion: minimum-evidence threshold",
        f"k>=1 confusion={v(todo,'threshold_k_one_confusion_pct')}%, k>=2={v(todo,'threshold_k_two_confusion_pct')}%; direct cardinality-null p={v(todo,'threshold_collapse_null_p_value')}, degree-preserving sensitivity p={v(todo,'threshold_collapse_degree_null_p_value')}, numerator-influential profiles={v(todo,'threshold_collapse_influential_profile_count')}",
        "threshold_k_one_confusion_pct, threshold_k_two_confusion_pct, threshold_collapse_null_p_value, threshold_collapse_degree_null_p_value, threshold_collapse_influential_profile_count",
        "`results/todo_values.json`, `results/audit/evidence_threshold_curve.csv`, `results/audit/null_model_confusion_distribution.csv`, `results/audit/threshold_collapse_degree_null_distribution.csv`, `results/audit/threshold_collapse_leave_one_out.csv`",
    )
    add_row(
        rows, "RQ3-J3", "Analysis/Discussion: delta sensitivity",
        f"delta=0.05 -> {v(todo,'delta_zero_zero_five_confusion_pct')}%, delta=0.10 -> {v(todo,'delta_zero_ten_confusion_pct')}%, delta=0.15 -> {v(todo,'delta_zero_fifteen_confusion_pct')}%",
        "delta_zero_zero_five_confusion_pct, delta_zero_ten_confusion_pct, delta_zero_fifteen_confusion_pct",
        "`results/todo_values.json`, `results/audit/delta_sensitivity.csv`",
    )
    add_row(
        rows, "RQ3-J4", "Descriptive fixed-indicator resampling (not graph-functional bootstrap)",
        f"fixed-indicator confusion={v(todo,'bootstrap_confusion_pct')}% (resampling interval {v(todo,'bootstrap_confusion_ci_low')}-{v(todo,'bootstrap_confusion_ci_high')}%); inferential robustness is RQ3-J2",
        "bootstrap_confusion_pct, bootstrap_confusion_ci_low, bootstrap_confusion_ci_high, bootstrap_unique_pct, bootstrap_unique_ci_low, bootstrap_unique_ci_high",
        "`results/todo_values.json`, `results/audit/bootstrap_confusion_distribution.csv`",
    )
    add_row(
        rows, "RQ3-J5", "Analysis: profile ablation summary",
        f"unique(sw)={v(todo,'sut_profile_unique_software_percentage')}%, unique(sw+cve)={v(todo,'sut_profile_unique_software_cve_percentage')}%, unique(sw+platform)={v(todo,'sut_profile_unique_software_platform_percentage')}%, unique(sw+cve+platform)={v(todo,'sut_profile_unique_software_cve_platform_percentage')}%, unique(sw+family)={v(todo,'sut_profile_unique_software_family_only_percentage')}%, unique(sw+compat)={v(todo,'sut_profile_unique_software_compat_percentage')}%",
        "sut_profile_unique_software_percentage, sut_profile_unique_software_cve_percentage, sut_profile_unique_software_platform_percentage, sut_profile_unique_software_cve_platform_percentage, sut_profile_unique_software_family_only_percentage, sut_profile_unique_software_compat_percentage",
        "`results/todo_values.json`, `results/audit/profile_ablation_summary.csv`",
    )
    add_row(
        rows, "AUX-OS1", "Analysis: Campaign OS-family table",
        f"Windows={v(todo,'campaign_os_windows_count')} Linux={v(todo,'campaign_os_linux_count')} macOS={v(todo,'campaign_os_macos_count')}",
        "campaign_os_windows_count, campaign_os_linux_count, campaign_os_macos_count",
        "`results/todo_values.json`, `results/audit/campaign_os_family_counts.csv`",
    )
    add_row(
        rows, "AUX-OS2", "Analysis: Unknown-platform campaigns",
        f"{v(todo,'enterprise_campaigns_platform_unknown_count')} ({v(todo,'enterprise_campaigns_platform_unknown_pct')}%)",
        "enterprise_campaigns_platform_unknown_count, enterprise_campaigns_platform_unknown_pct",
        "`results/todo_values.json`, `results/audit/campaign_platform_unknown.csv`",
    )

    md = []
    md.append("# Traceability Appendix")
    md.append("")
    md.append("This file is auto-generated from measurement outputs.")
    md.append("Do not edit manually; run `python3 measurement/sut/scripts/generate_traceability.py`.")
    md.append("")
    md.append("## Claim-to-Evidence Map")
    md.append("")
    md.append("| Claim ID | Paper Anchor | Measured Value | Metric Key(s) | Evidence Artifact(s) |")
    md.append("|---|---|---|---|---|")
    for row in rows:
        md.append(
            f"| {row['claim_id']} | {row['paper_anchor']} | {row['measured_value']} | "
            f"`{row['metric_keys']}` | `{row['evidence_artifacts']}` |"
        )
    md.append("")
    md.append("## Reproduction Order")
    md.append("")
    md.append("1. `python3 measurement/sut/scripts/sut_measurement_pipeline.py`")
    md.append("2. `python3 measurement/sut/scripts/render_figures.py`")
    md.append("3. `python3 measurement/sut/scripts/generate_traceability.py`")
    md.append("4. `./measurement/sut/release_check.sh`")
    md.append("")

    OUT.write_text("\n".join(md), encoding="utf-8")
    CSV_OUT.parent.mkdir(parents=True, exist_ok=True)
    with CSV_OUT.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "claim_id",
                "paper_anchor",
                "measured_value",
                "metric_keys",
                "evidence_artifacts",
            ],
            lineterminator="\n",
        )
        w.writeheader()
        w.writerows(rows)
    print(f"Wrote {OUT}")
    print(f"Wrote {CSV_OUT}")


if __name__ == "__main__":
    main()
