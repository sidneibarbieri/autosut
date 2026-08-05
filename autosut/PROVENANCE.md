# Canonical Source Provenance

This directory became the canonical AutoSUT development root on
2026-07-27T20:02:35Z.

## Imported State

- Migration source: legacy local AutoSUT development workspace
- Public release reference: existing AutoSUT artifact release repository
- Public release reference commit:
  `5f3610f40993430f960058da6f7d266051648fbf`
- Imported relative-file manifest SHA-256:
  `9a2533e48f4e48bd0e8007856a51a9b48fae135355f2333a83f562388f67698b`

The migration copied source, tests, declared datasets, documentation, and retained
evidence. It excluded virtual environments, Vagrant state, Python caches, QEMU images
and runtime overlays, container database state, `.DS_Store`, and archived exploratory
evidence. Origin and destination manifests matched after these exclusions.

The source tree did not have its own Git root. Consequently, this manifest is the
baseline for subsequent provenance; the public release commit is a reference, not a
claim that the imported working tree was clean.

Exact local migration paths and file-level hashes are retained only in the private
migration ledger outside the artifact.

## Rule

Do not synchronize changes back to the migration source. Publish only after tests,
reviewer-path validation, sanitization, and an explicit release decision.
