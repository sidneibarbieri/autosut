# STICKS VM-Backed Lab Environment

## Overview
This directory contains the provider-aware Vagrant substrate used by the
canonical STICKS VM-backed realism path.

Use this path through the canonical orchestration entry point:

```bash
python3 scripts/run_lab_campaign.py --campaign 0.c0011
```

That command resolves the campaign topology from `data/sut_profiles/<campaign>.yml`,
brings up only the required VMs, runs health checks, applies the SUT profile,
executes the campaign, refreshes evidence summaries, and tears the lab down
unless `--keep-lab` is requested.

## Topology Model

Typical VM roles:

- `caldera`
- `attacker`
- `target-linux-1`
- `target-linux-2`

The exact topology is campaign-specific and comes from the SUT profile.

## Setup

### Prerequisites
- Vagrant 2.4+
- Linux x86_64: `libvirt` + `vagrant-libvirt`
- macOS ARM64: QEMU + `vagrant-qemu`

### Quick Start
```bash
python3 scripts/run_lab_campaign.py --campaign 0.c0011
```

By default, the `caldera` role installs only the Caldera core needed by the
canonical STICKS path. Optional Docker support is intentionally disabled to
reduce cold-start cost on ARM64/QEMU. Enable it only when you explicitly need
it:

```bash
STICKS_CALDERA_INSTALL_DOCKER=1 python3 scripts/run_lab_campaign.py --campaign 0.c0011 --provider qemu
```

The default `caldera` path also skips the optional build toolchain and installs
only the canonical runtime dependency slice needed by the enabled plugin set.
That slice is versioned in `shared/caldera-runtime-requirements.txt` instead of
being inferred ad hoc during provisioning. If your host needs compiled wheels
for Caldera dependencies, opt back into the heavier toolchain explicitly:

```bash
STICKS_CALDERA_INSTALL_BUILD_DEPS=1 python3 scripts/run_lab_campaign.py --campaign 0.c0011 --provider qemu
```

The `attacker` role follows the same pattern. Core tooling needed by the
current canonical path stays enabled by default, while heavier reconnaissance
and cracking packages are opt-in:

```bash
STICKS_ATTACKER_INSTALL_EXTENDED_TOOLS=1 python3 scripts/run_lab_campaign.py --campaign 0.c0011 --provider qemu
```

The shared `base` role now stays intentionally minimal. Role-specific packages
such as `git`, `pip`, `sshpass`, and extended reconnaissance tooling are
installed only where the canonical path actually needs them.

### Development Acceleration
On macOS ARM64 with `vagrant-qemu`, the current provider path does not expose
Vagrant snapshot support. The supported acceleration path is therefore warm-lab
reuse, not snapshot rollback.

Use these flags only for development and corpus expansion:

```bash
python3 scripts/run_all_lab_campaigns.py \
  --campaign 0.c0011 \
  --campaign 0.c0015 \
  --provider qemu \
  --reuse-lab
```

If a compatible lab is already running, the first startup step can also be
skipped explicitly:

```bash
python3 scripts/run_lab_campaign.py --campaign 0.c0015 --assume-lab-running
```

The canonical public-facing path remains a clean cold-start run without these
flags.

### Manual Setup
```bash
./scripts/up_lab.sh --campaign 0.c0011 --provider qemu
python3 scripts/run_campaign.py --campaign 0.c0011
./scripts/collect_evidence.sh
python3 scripts/generate_corpus_state.py
./scripts/destroy_lab.sh --campaign 0.c0011
```

## VM Access

### Target VM
```bash
cd target-linux-1
vagrant ssh
```

### Attacker VM
```bash
cd attacker
vagrant ssh
```

Provider-specific networking differs. On macOS ARM64 with `qemu`, forwarded
ports may be more reliable than private-network declarations. The canonical
health gate is `lab/health_check.py`, not ad hoc assumptions about host access.

## Cleanup
```bash
./scripts/destroy_lab.sh --campaign 0.c0011
```

## Troubleshooting

### Provider Detection
```bash
./scripts/up_lab.sh --campaign 0.c0011
```

Defaults:

- Linux x86_64 → `libvirt`
- macOS ARM64 → `qemu`

### Vagrant Issues
```bash
vagrant status
```

### Health Check
```bash
python3 lab/health_check.py --campaign 0.c0011 --provider qemu --output release/evidence
```
