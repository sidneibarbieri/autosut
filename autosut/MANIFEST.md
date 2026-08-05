# Manifest

## Canonical Interface

- `run_review_check.sh`
- `run_vm_backed_campaign.sh`
- `artifact/setup.sh`
- `artifact/run.sh`
- `artifact/validate.sh`
- `artifact/teardown.sh`

## Core Execution Code

- `scripts/run_campaign.py`
- `scripts/generate_tables.py`
- `scripts/generate_claim_evidence_ledger.py`
- `src/loaders/campaign_loader.py`
- `src/runners/campaign_runner.py`
- `src/executors/executor_registry.py`
- `src/executors/registry_initializer.py`

## Campaign and SUT Inputs

- `campaigns/`
- `data/campaigns/`
- `data/sut_profiles/`

## Evidence and Results

- `release/evidence/` (generated at run time; public packages retain only runs
  hash-bound by the RQ4/C0045 gates)
- `release/dashboard/data/evidence/` (compact canonical evidence shipped for inspection)
- `release/CLAIM_EVIDENCE_TRACEABILITY.md`
- `release/claim_evidence_traceability.json`
- `release/subdetermination_proof.json`
- `release/experiments/` (bounded system-experiment records)
- `release/inputs/sticks/c0045-v1/` (hash-bound inputs and resolver outputs for the self-contained C0045 planning ablation)
- `results/tables/`
- `results/` synthesized reports and study-facing summaries

## Optional Infrastructure Helpers

- `scripts/up_lab.sh`
- `scripts/destroy_lab.sh`
- `multi_vm_manager_2vm.py`
- `lab/`

## Publication Boundaries

- `PUBLIC_REPOSITORY_SCOPE.md` defines what should remain public and stable for
  the canonical GitHub publication.
- `scripts/check_public_surface.py` audits the repository against that scope.
- Optional VM-backed infrastructure remains heavier than the fast validation
  path, but the public artifact can still expose it as an explicit second-tier
  execution path.

## Non-Canonical Historical Material

- exploratory reports and one-off root-level JSON/MD summaries
- root-level orchestration wrappers such as `campaign_pipeline.py`,
  `evidence_collector.py`, and `paper_generator.py`

These files may still be useful to the authors, but they are not part of the
primary public surface.
