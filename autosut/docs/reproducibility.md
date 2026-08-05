# Detailed Reproducibility Notes

This document expands the top-level `REPRODUCIBILITY.md` without changing the
canonical validation contract.

## Canonical Path

The supported validation path is:

```bash
bash artifact/setup.sh
bash artifact/run.sh
bash artifact/validate.sh
```

This path exercises the repository-local runner, evidence generation, and table
generation with one representative campaign.

## Current Guarantees

- The canonical smoke path is lightweight and repository-local.
- Campaign loading supports both canonical YAML and compatibility JSON.
- Evidence is written under `release/evidence/`.
- Paper-facing LaTeX tables are regenerated under `results/tables/`.

## Current Non-Guarantees

- Not every published campaign is currently part of the live executable subset.
- Optional VM-backed infrastructure is not guaranteed to be green in every
  checkout.
- Frozen outputs are retained for traceability and comparison, not as a claim
  that every live path succeeds.

## Optional VM-Backed Layer

The repository also contains provider-aware VM helpers. They remain useful for
measurement and realism studies, but they are not required for the canonical
validation path.

Preferred VM-backed backends:

- Linux x86_64: `libvirt`
- macOS ARM64: `qemu`

## Hygiene and Publication Checks

Before packaging for reviewers or publication, run:

```bash
python3 scripts/check_public_surface.py
bash scripts/sanitize_repo.sh
```
