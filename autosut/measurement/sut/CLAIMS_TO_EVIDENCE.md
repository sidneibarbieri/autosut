# Claims to Evidence Mapping

This file maps the main empirical claims of the AutoSUT study to the concrete artifacts
that readers can inspect or regenerate.

## Core Claims

| Claim | Artifact evidence | How it is checked |
|-------|-------------------|-------------------|
| Platform fields are near-universal, but software and CVE evidence are much sparser | `scripts/results/todo_values.json`, `scripts/results/audit/platform_distribution.csv`, `scripts/results/figures_data.json` | `release_check.sh` reruns `sut_measurement_pipeline.py` and validates key invariants |
| Campaign-level platform inference remains partially unknown under conservative rules | `scripts/results/audit/campaign_platforms_software_only.csv`, `scripts/results/audit/campaign_platform_unknown.csv`, `scripts/results/audit/campaign_os_family_counts.csv` | static-table and list checks inside `release_check.sh` |
| Software references rarely provide replay-ready specificity | `scripts/results/audit/campaign_software.csv`, `scripts/results/figures_data.json`, `scripts/results/software_specificity_table.csv` | figure regeneration plus measured-output checks |
| Campaign-level CVE signal is rare and unevenly useful | `scripts/results/audit/campaign_cves.csv`, `scripts/results/audit/is_cves.csv`, `scripts/results/audit/all_cves.csv` | static-table checks for campaign-linked CVEs and CVE-profile outcomes |
| Under the declared routing policy, CF is a narrow label and fallback assignments dominate | `scripts/results/audit/compatibility_denominator_summary.csv`, `scripts/results/audit/technique_compatibility.csv`, `scripts/results/audit/compatibility_rule_breakdown.csv`, `scripts/results/audit/compatibility_default_sensitivity.csv` | denominator, numeric-invariant, and rule-breakdown checks in `release_check.sh` |
| The observed `k >= 1` to `k >= 2` confusion drop is descriptive, driven by two singleton profiles, and compatible with cardinality- and degree-preserving nulls | `scripts/results/audit/profile_specificity_software_only.csv`, `scripts/results/audit/evidence_threshold_curve.csv`, `scripts/results/audit/null_model_confusion_distribution.csv`, `scripts/results/audit/threshold_collapse_degree_null_distribution.csv`, `scripts/results/audit/threshold_collapse_leave_one_out.csv` | conditioned-neighbor recomputation, direct Monte Carlo null, degree-preserving sensitivity, and leave-one-out influence analysis |
| The released outputs stay synchronized with the measured pipeline | `scripts/results/todo_values_latex.tex`, `TRACEABILITY.md`, `scripts/results/figures_data.json` | figure regeneration, traceability generation, and consistency checks |
| Multiple controlled SUT realizations preserve the checked contract in the bounded RQ4 witnesses | `../../release/subdetermination_proof.json` | the top-level `scripts/run_review_check.sh` verifies run counts, evidence hashes, mode/status consistency, containment records, and teardown |
| The C0045-derived surrogate case resolves and executes 10/10 steps only with the synthesized witness under fixed controls | `../../release/experiments/arm_comparison/C0045.json`, `../../release/experiments/execution_validity.json` | the canonical claim-ledger gate validates the three arms and the evidence-backed execution record |

The canonical cross-layer ledger is
`../../release/CLAIM_EVIDENCE_TRACEABILITY.md` (JSON:
`../../release/claim_evidence_traceability.json`). It is authoritative when a
legacy report or prose summary conflicts with current evidence.

## Honest Non-Claims

The artifact does **not** claim:

- faithful replay of historical intrusions,
- end-to-end automated SUT provisioning for arbitrary campaigns from CTI alone,
- actor-specific attribution from environment profiles,
- independent execution-ground-truth validation for every compatibility label,
- empirical accuracy or minimum-backend necessity for CF/VMR/ID routing labels,
- historical equivalence of the C0045 surrogate,
- measured analyst-effort reduction, scalability, or minimal overhead.

## Canonical Validation Entry Point

```bash
bash run_review_check.sh

# direct equivalent inside the workspace / packaged tree
cd autosut/measurement/sut
bash release_check.sh
```

The root wrapper is the smoothest validation path. The canonical
`release_check.sh` behind it is the reproducibility contract for this paper.

## Reviewer-Facing Assumptions

- The artifact is self-contained after clone; no network fetch is required.
- The measurement claims do not depend on Caldera, Docker, or any runtime
  emulation substrate.
- If a private manuscript tree is available locally, `release_check.sh` can
  also validate that it remains synchronized with the generated outputs.
