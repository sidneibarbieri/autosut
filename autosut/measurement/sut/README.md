# Environment Semantics Gap Reproducibility Artifact

This directory contains the measurement and reproduction artifact for the study
of the **environment semantics gap in structured CTI**. The main artifact claim
is not live offensive execution. It is that the released pipeline can recompute
the measured counts, regenerate the figure and traceability outputs, and expose
the audit files behind every reported result.

## Fastest Reproduction Path

In the packaged review artifact, the smoothest path is:

```bash
bash run_review_check.sh
```

From the workspace tree, the canonical equivalent is:

```bash
cd sticks/measurement/sut
bash release_check.sh
```

The wrapper/canonical flow:
- calls the canonical verifier at `sticks/measurement/sut/release_check.sh`,
- reruns the SUT measurement pipeline over the local ATT&CK/CAPEC/FiGHT bundles,
- regenerates TikZ data and traceability outputs,
- validates key numeric invariants,
- and, when a private manuscript tree is present, also checks manuscript sync,
  static tables, bibliography policy, and PDF build integrity.

On the current laptop-class development machine, the full check completes in about 40 seconds.

## Scope

This artifact is intentionally measurement-first. It is designed
to support the study's claims with the smallest practical surface:

- CTI bundle snapshots,
- the measurement pipeline,
- figure/traceability regeneration,
- generated output consistency checks.

The broader research workspace may also contain optional runtime or emulation
material, but that is **not required** to reproduce the released measurements
and should not be part of the minimal public artifact.

## Documentation

- [README_REPRODUCIBILITY.md](README_REPRODUCIBILITY.md)
- [FINAL_REVIEW_READINESS.md](FINAL_REVIEW_READINESS.md)
- [CLAIMS_TO_EVIDENCE.md](CLAIMS_TO_EVIDENCE.md)
- [PUBLICATION_CHECKLIST.md](PUBLICATION_CHECKLIST.md)

## Status

Use `bash run_review_check.sh` from the packaged artifact root for the smoothest validation flow, or `bash release_check.sh` from `sticks/measurement/sut` if you want the canonical script directly.
