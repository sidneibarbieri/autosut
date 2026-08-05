# Artifact Guide

## Purpose

This document defines the public-facing artifact path for the current
repository state.

## Canonical Commands

```bash
bash artifact/setup.sh
bash artifact/run.sh
bash artifact/validate.sh
```

## Direct Commands

```bash
python3 scripts/run_orchestrated_campaign.py 0.c0017
python3 scripts/generate_tables.py
```

## Guarantees

- Campaign loading supports both canonical YAML and compatibility JSON.
- The smoke path writes structured evidence to `release/evidence/`.
- Table generation writes LaTeX outputs to `results/tables/`.

## Non-Guarantees

- Full replay depends on local Docker, Caldera, and host resources; use the
  generated TSV/JSON reports to audit any interrupted or failed campaign.
- Optional multi-VM helpers may report degraded state when the selected
  provider lacks the declared networking or virtualization features.
- Live validation from this checkout is the review contract; external historical
  workspaces are not required evidence.
