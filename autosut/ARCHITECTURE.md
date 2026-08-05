# Architecture

## Summary

AutoSUT exposes three reproducibility layers:

- a fast study-claim validation path in `run_review_check.sh`;
- a repository-local minimal working example based on the local runner and
  artifact wrappers;
- a provider-aware VM-backed realism path used for campaigns that need a
  concrete substrate, infrastructure checks, and measurement experiments.

The fast validation path is the primary reproducibility target for study-facing
claims. The minimal working example is the smallest repository-local execution
trace. The VM-backed path is also part of the supported architecture, but it
remains a heavier execution tier because backend behavior differs across
operating systems.

Detailed current-vs-target execution notes live in
`docs/architecture/EXECUTION_MODEL.md`.

## Layer 1: Canonical Validation Path

The canonical path is:

```bash
bash artifact/setup.sh
bash artifact/run.sh
bash artifact/validate.sh
```

This layer depends on Python and repository-local inputs only. It is the
smallest supported surface for artifact validation and should be used for any
claim about baseline reproducibility unless the optional lab path has been
revalidated in the same checkout.

Core components:

- `artifact/`: validation wrappers
- `scripts/run_campaign.py`: canonical campaign execution entry point
- `src/loaders/`: campaign and SUT loading
- `src/runners/`: orchestration and evidence generation
- `src/executors/`: technique realizations

## Layer 2: VM-Backed Realism Path

The repository also contains a canonical VM-backed execution contract for
substrate realism and network/service validation.

Core components:

- `scripts/run_lab_campaign.py`
- `scripts/up_lab.sh`
- `scripts/destroy_lab.sh`
- `lab/health_check.py`
- `lab/vagrant/`
- `multi_vm_manager_2vm.py`
- `caldera_manager.py`

Non-canonical root-level orchestration scripts may still exist for exploratory
author workflows, but they are not the primary public contract and should not
supersede the documented runner or artifact wrappers.

This layer is useful when a campaign requires a concrete attacker/target
substrate or when the paper needs additional infrastructure evidence.

## Provider Model

The VM-backed layer is provider-aware rather than provider-fixed.

Preferred defaults:

- Linux x86_64: `libvirt`
- macOS ARM64: `qemu`
- VirtualBox: optional where available and stable

Rationale:

- `libvirt` usually offers the most faithful private-network behavior on Linux.
- `qemu` is the practical backend for Apple Silicon, but it may ignore some
  Vagrant high-level network declarations.
- Users should not be forced into a single host platform or hypervisor when
  the canonical smoke path does not require it.

Current macOS ARM64 note:

- In the current `vagrant-qemu` path used by this repository, Vagrant snapshots
  are not available.
- The supported acceleration path is an opt-in warm-lab workflow
  (`run_all_lab_campaign.py --reuse-lab` and
  `run_lab_campaign.py --assume-lab-running`) for development-only reuse of a
  compatible running lab.
- Public commands remain cold-start and teardown clean by default.

## Separation of Concerns

AutoSUT keeps four concerns separate:

1. Campaign definition: what the adversary does.
2. SUT profile: where it happens and which weaknesses are present.
3. Executor implementation: how a technique is materialized.
4. Evidence generation: what was observed and how fidelity is classified.

This separation is important for honest reporting:

- published corpus is not automatically equivalent to executable corpus;
- VM-backed realism is not automatically equivalent to reviewer reproducibility;
- backend-specific constraints must be measured rather than assumed.

## Execution Flow

Canonical flow:

1. Load campaign metadata from `data/campaigns/` or `campaigns/`.
2. Load the matching SUT profile from `data/sut_profiles/`.
3. Execute the campaign runner.
4. Write evidence to `release/evidence/`.
5. Generate study-facing tables under `results/tables/`.

VM-backed realism flow:

1. Select provider based on host capabilities or explicit user choice.
2. Bring up only the VMs required by the SUT profile.
3. Validate substrate health.
4. Apply the SUT profile and deliberate weaknesses.
5. Execute the campaign through the canonical runner.
6. Refresh evidence summaries and corpus state.
7. Tear down the lab unless inspection was explicitly requested.

The canonical entry point for this path is:

```bash
python3 scripts/run_lab_campaign.py --campaign 0.c0011
```

## Current Integrity Rule

Reviewer-facing claims should be grounded in the canonical smoke path first.
VM-backed realism claims should be reported only when the same backend was
validated in the current environment through `scripts/run_lab_campaign.py` or
its equivalent command trace.
