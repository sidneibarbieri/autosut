# Detailed Architecture

## Purpose

This document expands the high-level architecture summary in `ARCHITECTURE.md`
and focuses on the execution boundaries that matter for reproducibility and
realism claims.

## Canonical Path

The canonical path is intentionally small:

- `artifact/setup.sh`
- `artifact/run.sh`
- `artifact/validate.sh`

It exercises the repository-local runner and evidence pipeline without requiring
the reviewer to provision the full VM lab. This path is the default basis for
reproducibility claims because it is the least backend-sensitive layer in the
artifact.

## Optional VM-Backed Path

The VM backend material exists for substrate qualification and expanded
measurement development. It includes:

- Vagrant definitions in `lab/vagrant/`
- provider-aware provisioning helpers in `scripts/up_lab.sh`
- provider-aware validation in `lab/health_check.py`
- a Caldera-compatible service provisioned by the selected lab topology when
  the chosen campaign requires one

It is not a released experimental path. Source availability and host preflight
do not qualify a guest boot, procedure execution, or teardown result.

## Platform Strategy

The repository is designed around provider selection rather than provider
monoculture.

Candidate implementations for future qualification:

- Linux x86_64: prefer `libvirt`
- macOS ARM64: prefer `qemu`
- other providers: use only when they are explicitly supported by the local host

Why these alternatives are retained:

- Linux with `libvirt` generally preserves private networking more faithfully.
- macOS ARM64 lacks an equally mature, friction-free equivalent, so `qemu` is
  the pragmatic choice for Apple Silicon.
- A single hypervisor requirement would make reviewer execution unnecessarily
  brittle.

## Data and Control Planes

The artifact separates control and execution concerns:

- control plane: Python runner, campaign metadata, report generation
- execution substrate: optional attacker/target VMs and their applied SUT state

This distinction matters because the reviewer does not need a VM substrate to
validate the canonical gate. The current ledger records QEMU Linux ARM64 as
`implemented` with boot qualification required and native Windows as
`development_in_progress`.

## Current Design Rule

When the canonical path and the VM-backed path disagree, the repository should
report that disagreement rather than smoothing it over. The artifact should
prefer honest failure and explicit backend notes over inflated claims.
