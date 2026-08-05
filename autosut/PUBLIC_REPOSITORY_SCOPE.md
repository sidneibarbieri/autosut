# Public Repository Scope

This document defines the surface that should remain stable when the repository
is prepared for a public GitHub release or artifact distribution.

## Public Entry Files

These files define the public entry points and should remain coherent:

- `run_review_check.sh`
- `run_vm_backed_campaign.sh`
- `README.md`
- `REVIEWER_GUIDE.md`
- `REPRODUCIBILITY.md`
- `MANIFEST.md`
- `ARCHITECTURE.md`
- `artifact/setup.sh`
- `artifact/run.sh`
- `artifact/validate.sh`
- `artifact/teardown.sh`

Private manuscript trees may consume generated values from this repository, but
those manuscript trees are not part of the public artifact contract.

## Public Execution Surface

These files and directories support the canonical artifact path:

- `run_review_check.sh`
- `scripts/run_campaign.py`
- `scripts/generate_tables.py`
- `scripts/generate_corpus_state.py`
- `scripts/audit_mitre_metadata.py`
- `scripts/audit_host_leakage.py`
- `scripts/generate_claim_evidence_ledger.py`
- `scripts/verify_artifact_manifest.py`
- `campaigns/`
- `data/campaigns/`
- `data/sut_profiles/`
- `data/stix/`
- `src/`
- `tests/`

## Optional but Retained

These components are useful for measurement or infrastructure work, but they
should be presented as optional and non-canonical:

- `run_vm_backed_campaign.sh`
- `lab/`
- `scripts/up_lab.sh`
- `scripts/destroy_lab.sh`
- `multi_vm_manager_2vm.py`
- `multi_vm_manager.py`
- `caldera_manager.py`
- `README_MULTI_VM.md`
- `docs/`

## Publication Blockers

The following categories should not be part of the public GitHub
surface:

- superseded repository mirrors such as `legacy/` and `software/`
- virtual environments and caches
- runtime QEMU images, overlays, boxes, and seed ISOs
- local `.vagrant/` machine state
- developer-local Caldera configuration such as `measurement/sut/caldera_conf/local.yml`
- generated evidence directories except the compact runs hash-bound by the
  canonical RQ4/C0045 gates
- exploratory result dumps
- ad hoc local logs
- historical `removed_reports/`

## Integrity Rules

- The public README must point to the canonical smoke path first.
- The public README must also expose the VM-backed wrapper when it is part of
  the publication surface.
- Historical compatibility snapshots should live in Git history or backup
  branches, not as parallel source trees in the active repository root.
- Public documentation must not claim that optional VM-backed paths are
  guaranteed to be green in every checkout.
- Public artifacts should remain venue-neutral and should not require bundling a
  manuscript tree unless a specific submission process demands it.
- ATT&CK, tactic, and procedure mapping should remain anchored to the current
  local MITRE bundle and the published campaign corpus.
- Claims about completeness, realism, or success rate must be grounded in the
  canonical ledger under `release/` and its referenced evidence. A legacy
  summary is not an authority when it conflicts with that ledger.

## Repository Hygiene Checks

Before publication or artifact packaging, run:

```bash
bash run_review_check.sh
bash artifact/setup.sh
bash artifact/run.sh
bash artifact/validate.sh
python3 scripts/check_public_surface.py
bash scripts/sanitize_repo.sh
python3 scripts/package_autosut_public_repo.py
```
