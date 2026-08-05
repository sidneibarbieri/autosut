# Artifact Boundary

## Public in this repository

- Measurement code and frozen public CTI bundle snapshots.
- Deterministic audit outputs used by the study.
- Optional VM/lab orchestration code without local runtime images.

## Excluded from this repository

- Private notes, coauthor/admin material, and non-public study material.
- Manuscript source, venue submission files, and generated paper PDFs.
- Local virtual environments, Python caches, and LaTeX build residue.
- VM runtime images, overlays, `.vagrant` state, Docker database state, and superseded evidence archives.
- Claim-bound evidence referenced by the RQ4/C0045 gates is retained; unrelated local runs are excluded.
- Runtime credentials or locally generated certificates from exploratory lab runs.
- Historical frozen-workspace paths that are useful only for internal comparison.

The public validation path is designed to reproduce the study's
measurement claims without crossing this boundary.
