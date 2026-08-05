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

The repository currently contains two families of VM-oriented helpers:

- `multi_vm_manager_2vm.py` for an attacker/target topology
- `multi_vm_manager.py` for older exploratory orchestration work

These tools are useful for lab inspection, provider experiments, and
measurement. They should not be used as the sole basis for reproducibility
claims unless they have been revalidated in the current checkout.

## Current Expectations

- Linux x86_64 is better served by `libvirt` through the provider-aware lab
  helpers.
- macOS ARM64 uses `qemu` when the VM-backed path is needed.
- Host-side Caldera or mock Caldera validation is optional and should be
  reported separately from the canonical smoke path.

## Common Commands

Check the 2-VM helper:

```bash
python3 multi_vm_manager_2vm.py status
```

Validate the VM-to-host callback path with the mock Caldera-compatible service:

```bash
python3 caldera_manager.py start-mock
python3 multi_vm_manager_2vm.py up
python3 multi_vm_manager_2vm.py status
python3 multi_vm_manager_2vm.py down
```

Bring up the provider-aware optional lab for a campaign:

```bash
./scripts/up_lab.sh --campaign 0.c0011
./scripts/destroy_lab.sh --campaign 0.c0011
```

## Integrity Notes

- VM-backed results are additional evidence, not a substitute for the canonical
  smoke path.
- Provider behavior differs across hosts, so backend-specific claims must be
  reported with the host and provider used in that run.
