# Optional Multi-VM Notes

This document describes the exploratory VM-backed utilities kept in the
repository for infrastructure work and realism studies.

Important:

- This is not the canonical validation path.
- The canonical validation path remains:

```bash
bash artifact/setup.sh
bash artifact/run.sh
bash artifact/validate.sh
```

## Scope

The repository retains one direct diagnostic helper,
`multi_vm_manager_2vm.py`, for an attacker/target topology. The provider-aware
lab scripts and this helper are implementation material, not a released
campaign-execution contract. Use the canonical review gate first, then inspect
the capability ledger before interpreting any local backend result.

## Current Expectations

- Linux `libvirt` and macOS ARM64 `qemu` are candidate implementations for
  future qualification.
- QEMU is currently `implemented` and requires boot qualification.
- Native Windows is `development_in_progress`; its architecture-specific,
  credential-free templates do not prove a guest run.

## Review Boundary

No VM command in this document is a reviewer reproduction recipe. A future
qualification must bind a campaign/SUT requirement, image hash, cold boot,
declared evidence predicate, independent observation, and clean teardown. The
ledger records the only valid promotion status.

## Integrity Notes

- VM-backed results are additional evidence, not a substitute for the canonical
  smoke path.
- Provider behavior differs across hosts, so backend-specific claims must be
  reported with the host and provider used in that run.
