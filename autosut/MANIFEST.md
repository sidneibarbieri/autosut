# Manifest

## Canonical Interface

- `run_review_check.sh`
- `artifact/setup.sh`
- `artifact/run.sh`
- `artifact/validate.sh`
- `artifact/teardown.sh`

## Core Execution Code

- `scripts/run_campaign.py`
- `scripts/run_reviewer_workflow.sh`
- `scripts/publish_study_values.py`
- `scripts/generate_tables.py`
- `scripts/generate_claim_evidence_ledger.py`
- `scripts/generate_corpus_state.py`
- `scripts/validate_claim_surface.py`
- `src/loaders/campaign_loader.py`
- `src/runners/campaign_runner.py`
- `src/executors/executor_registry.py`
- `src/executors/registry_initializer.py`
- `src/infrastructure/execution_handoff.py`
- `scripts/validate_execution_handoff.py`
- `src/infrastructure/failure_recovery.py`
- `src/infrastructure/recovery_adapters.py`
- `scripts/validate_recovery_journal.py`
- `scripts/validate_historical_evidence_status.py`
- `src/evaluation/operational_metrics.py`
- `scripts/validate_operational_ledger.py`

The generic `execution_handoff.v1` receiver accepts only hash-valid records targeting the exact
current consumer revision. It is reusable infrastructure, not evidence that an external procedure
was executed.

The generic recovery engine applies a frozen retry budget, deterministic failure classification,
independent admission, repeated-revision detection, and an optional append-only hash-chained
journal. It is mechanism code, not a recovery-rate result.

The operational evaluation contract keeps the full arm/environment/seed denominator and computes
asset acquisition, reliability, time, cost, and intervention metrics only from qualified evidence.
It ships no synthetic or uncollected operational result.

## Campaign and SUT Inputs

- `campaigns/`
- `data/campaigns/`
- `data/sut_profiles/`

## Evidence and Results

- `release/evidence/` (generated at run time; public packages retain only runs
  hash-bound by the RQ4/C0045 gates)
- `release/CLAIM_EVIDENCE_TRACEABILITY.md`
- `release/claim_evidence_traceability.json`
- `release/dashboard/` (static view of the canonical claim ledger)
- `release/study_values.tex` (published measurement macros consumed by the demo and dashboard)
- `release/subdetermination_proof.json`
- `release/experiments/` (bounded system-experiment records)
- `release/inputs/sticks/c0045-v1/` (hash-bound inputs and resolver outputs for the self-contained C0045 planning ablation)
- `results/tables/`
- `results/` synthesized reports and study-facing summaries

`release/experiments/multi_campaign/` is retained historical evidence. `STATUS.json` marks every
record there as non-qualifying and inapplicable to the current revision.

## Optional Infrastructure Helpers

- `run_vm_backed_campaign.sh`
- `scripts/up_lab.sh`
- `scripts/destroy_lab.sh`
- `multi_vm_manager_2vm.py`
- `lab/`

## Publication Boundaries

- `PUBLIC_REPOSITORY_SCOPE.md` defines what should remain public and stable for
  the canonical GitHub publication.
- `scripts/check_public_surface.py` audits the repository against that scope.
- Optional VM backend material remains outside the released claim gate. QEMU
  requires boot qualification and native Windows is still development work, so
  neither is an explicit second-tier execution claim.

## Non-Canonical Historical Material

- exploratory reports and one-off root-level JSON/MD summaries
- root-level orchestration wrappers such as `campaign_pipeline.py`,
  `evidence_collector.py`, and `paper_generator.py`

These files may still be useful to the authors, but they are not part of the
primary public surface.
