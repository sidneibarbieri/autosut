# Detailed Reproducibility Notes

This document expands the top-level `REPRODUCIBILITY.md` without introducing a
second validation contract.

## Start With the Claim Gate

Run the host-only reviewer workflow first:

```bash
bash scripts/run_reviewer_workflow.sh --mode kick-the-tires
bash scripts/run_reviewer_workflow.sh --mode full-reproduction
```

`kick-the-tires` checks the public surface, the host preflight, and the
claim-to-evidence ledger. `full-reproduction` additionally runs
`bash run_review_check.sh`, the canonical study-claim gate. Neither command
requires Docker, a VM, or a model API key.

## Optional Live Docker Replay

On a Docker-capable host, the repository-local live example is:

```bash
bash artifact/setup.sh
bash artifact/run.sh
bash artifact/validate.sh
```

It runs two compact slices: `0.c0017` as an infrastructure smoke replay and
`0.shadowray` as a C0045-derived surrogate state-contract replay. The generated
records remain reviewer-local under `release/evidence/_reviewer_runs/` and are
not promoted into the released claim ledger.

## Current Guarantees

- The host-only claim gate is deterministic and repository-local.
- The Docker smoke path validates two bounded live slices when Docker is
  available.
- Campaign loading supports both canonical YAML and compatibility JSON.
- Live replay evidence is archived under `release/evidence/_reviewer_runs/`.
- `bash run_review_check.sh` regenerates paper-facing LaTeX tables under
  `results/tables/`; the live replay leaves them unchanged.

## Current Non-Guarantees

- Not every published campaign is currently part of the live executable subset.
- Optional VM backend material is not a released execution result. QEMU still
  requires boot qualification and native Windows remains development work.
- Frozen outputs are retained for traceability and comparison, not as a claim
  that every live path succeeds.

## Optional VM-Backed Layer

The repository also contains provider-aware VM helpers. They remain useful for
implementation inspection and future qualification, but they are not required
for the canonical validation path and do not currently support a backend claim.

Candidate provider implementations:

- Linux x86_64: `libvirt`
- macOS ARM64: `qemu`

## Hygiene and Publication Checks

Before packaging for reviewers or publication, run:

```bash
python3 scripts/check_public_surface.py
```
