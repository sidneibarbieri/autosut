# Evidence Retention Policy

This policy governs how run evidence is stored, classified, and preserved. It exists because a
prior process error deleted broken and diagnostic bundles; the corrective rule is that evidence is
**excluded by metadata, never by deletion**.

## Tiers

Every run bundle lands in exactly one tier under `release/evidence/`:

| Tier | Holds | Immutable | Tracked in git |
|------|-------|-----------|----------------|
| `raw/` | Every run bundle as produced: clean, failed, interrupted, diagnostic. Includes stage timings, operation reports, downloaded-binary logs, teardown and verify-clean records. | Yes — never edited or removed after sealing. | No (gitignored: bundles carry large logs and downloaded binaries). |
| `diagnostic/` | Bundles retained specifically as evidence of a defect or a superseded protocol. Kept for the record; **excluded from qualification by metadata**, not by removal. | Yes. | No. |
| `qualified/` | The bundles a qualification actually consumed (e.g. a 5-clean-run set on one revision), copied or hard-linked from `raw/` at qualification time. | Yes. | No. |
| `release/experiments/<name>/` (aggregate) | Derived, small summaries: qualification JSON, the capability ledger, run indexes. These are what a reviewer reads first. Lives in the tracked `release/experiments/` tree, not under gitignored `release/evidence/`. | Regenerated from tier contents. | **Yes** — committed so a reviewer can read the claim without re-running. |

## Rules

1. **Raw is append-only.** A sealed bundle is never mutated or deleted. Re-runs create new bundles.
2. **Exclusion is metadata, not deletion.** A run excluded from a qualification (failed, interrupted,
   wrong revision, superseded protocol) stays on disk; its bundle metadata records *why* it was
   excluded. Aggregators skip it by reading that metadata.
3. **Derived summaries are tracked; raw bundles are not.** The `aggregate/` summaries record each
   consumed bundle's manifest hash, so a reviewer can (a) read the claim from git immediately, and
   (b) regenerate the bundles by re-running and confirm the same manifest hashes and derived level.
4. **A qualification names its revision.** Every summary records the implementation revision its
   run-set ran on. A set on a superseded revision is preserved evidence of that revision and is
   marked `applies_to_current_revision = false`; it does not qualify the code now present.

## Known gap (recorded, not hidden)

As of this writing the new-pipeline `aggregate/` summaries (`caldera_experiment/qualification.json`,
`multihost_qualification/qualification.json`, `capability_ledger/capabilities.json`) and the
canonical `src/` implementation are **untracked working-copy files**. A fresh public clone therefore
contains neither the qualifying bundles nor their derived summaries. Closing this gap is the freeze
step: commit the canonical implementation and the derived summaries on one frozen revision, then
re-run all backends on that revision so the committed evidence applies to it. Until then the ledger
correctly reports 0 claim-ready capabilities.
