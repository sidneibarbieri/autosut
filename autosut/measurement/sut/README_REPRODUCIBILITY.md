# Reproduction Guide - Environment Semantics Gap Artifact

## Canonical Validation Path

In the packaged artifact, the smoothest validation command is:

```bash
bash run_review_check.sh
```

That wrapper enters `sticks/measurement/sut` and invokes the canonical verifier. In the workspace tree, the direct equivalent is:

```bash
cd sticks/measurement/sut
bash release_check.sh
```

The wrapper points readers to `sticks/measurement/sut/release_check.sh` as
the canonical script behind it. The verifier checks the local input bundles,
reruns the measurement pipeline, regenerates figure data and traceability files,
checks the key numeric invariants, and, when a private manuscript tree is
present, also validates manuscript sync and PDF build consistency. On the
current laptop-class development machine, the full pass completes in about
40 seconds.

The review artifact is intentionally offline once cloned. It does not require
network access, API keys, Caldera, container runtimes, or any cyber-range
orchestration stack. All bundle snapshots needed by the measurements are
already included in `scripts/data/`.

## What This Artifact Proves

| Claim | Evidence |
|-------|----------|
| The reported counts are reproducible from local CTI bundles | `release_check.sh` reruns `sut_measurement_pipeline.py` and validates key invariants |
| The generated values, figures, and traceability outputs are synchronized with measured outputs | output regeneration + consistency checks in `release_check.sh` |
| Audit files exist for the main findings | `scripts/results/audit/` contains campaign/software/CVE/platform/profile/compatibility traces |
| A private manuscript tree can be revalidated against the released pipeline when available | `release_check.sh` performs manuscript-specific checks only when the manuscript tree is present |

## What This Artifact Does NOT Prove

- Historical replay fidelity for real campaigns
- Fully automated SUT provisioning from CTI alone
- End-to-end offensive execution for every campaign in the corpus
- That optional runtime environments are required to reproduce the paper's measurements

## Artifact Boundary

The minimal review artifact should include only the components required by
`release_check.sh`. Optional runtime, orchestration, or cyber-range material
may exist in the broader research workspace, but it is outside the
reproducibility contract for this measurement artifact and should be excluded
from the public release.

## Key Files

- `release_check.sh` - canonical one-command verifier
- `scripts/sut_measurement_pipeline.py` - main measurement pipeline
- `scripts/render_figures.py` - figure-data regeneration
- `scripts/generate_traceability.py` - traceability appendix generation
- `scripts/results/audit/` - audit CSVs referenced by the manuscript
- `CLAIMS_TO_EVIDENCE.md` - claim-to-artifact mapping
