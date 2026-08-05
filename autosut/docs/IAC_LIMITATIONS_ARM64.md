# IaC Limitations — macOS ARM64 (Apple Silicon)

## Context

AutoSUT uses Vagrant with multiple virtualization backends to provision the lab infrastructure. On macOS ARM64 (Apple Silicon), the available backends differ significantly from x86_64 Linux, which impacts network configuration, performance, and experimental validity.

## Provider Comparison

| Feature | VirtualBox | QEMU (vagrant-qemu) | Libvirt |
|---|---|---|---|
| **macOS ARM64 support** | No (x86_64 only) | Yes | Partial (requires libvirt daemon) |
| **Private network** | Full support | **Ignored** | Requires session URI |
| **Port forwarding** | Full support | Supported | Supported |
| **Performance** | Native x86 | Emulated ARM64 | Near-native (when available) |
| **Vagrant plugin** | Built-in | `vagrant-qemu` | `vagrant-libvirt` |
| **Artifact recommendation** | x86_64 hosts only | macOS ARM64 default | Linux hosts |

## Critical Issue: QEMU Ignores Private Network

The `vagrant-qemu` provider does **not** support Vagrant high-level network configurations:

```
The QEMU provider doesn't support any of the Vagrant high-level
network configurations (config.vm.network). They will be silently ignored.
```

### Impact

- **Declared IPs are unreliable**: `192.168.56.10`, `192.168.56.20`, etc. may not be reachable from the host.
- **Health checks must not assume private IPs**: The `lab/health_check.py` module attempts both private IP and forwarded port connections as fallback.
- **Inter-VM connectivity is not guaranteed**: Level 3 health checks (campaign readiness) may fail even when VMs are individually reachable.

### Mitigation

1. **SSH port forwarding**: Each VM has a unique forwarded SSH port on `127.0.0.1`:
   - caldera: `50022`
   - attacker: `50023`
   - target-linux-1: `50024`
   - target-linux-2: `50025`

2. **Health check fallback**: `lab/health_check.py` tries private IP first, then falls back to forwarded ports for QEMU provider.

3. **Explicit port forwarding for services**: Caldera API (`8888`), Apache (`80`), etc. must use explicit Vagrant `forwarded_port` configuration rather than relying on private network access.

## Caldera on ARM64

- Caldera 5.x uses **SQLite by default** — MongoDB is NOT required.
- Previous provisioning scripts attempted to start `mongodb.service`/`mongod.service`, which don't exist on Ubuntu 22.04 ARM64 without explicit MongoDB installation.
- The updated `caldera.sh` removes the MongoDB dependency and adds post-start verification (process running + port listening).

## Experimental Validity Considerations

The virtualization backend **influences experimental validity**:

1. **Network topology fidelity**: If the provider ignores private networks, the declared topology (attacker → target connectivity) may not reflect actual state. This must be measured, not assumed.

2. **Architecture emulation**: ARM64 guests on ARM64 host run natively. x86_64 guests would require full emulation, significantly impacting performance and potentially behavior.

3. **Evidence must record backend**: The health check report and campaign evidence include provider information so reviewers can assess infrastructure constraints.

## Recommendations for Artifact Reviewers

| Reviewer Host | Recommended Provider | Notes |
|---|---|---|
| Linux x86_64 | libvirt or VirtualBox | Full private network support |
| macOS x86_64 | VirtualBox | Full private network support |
| macOS ARM64 | QEMU | Private network limitations apply |

For maximum reproducibility on macOS ARM64:

1. Run `./setup.sh` to install QEMU and vagrant-qemu plugin.
2. Run `./up_lab.sh --campaign <ID>` which auto-detects the provider.
3. Review the health check report in `release/evidence/` for connectivity status.
4. If Level 3 health checks fail, inter-VM communication may need manual SSH tunneling.

## Related Files

- `lab/health_check.py` — 3-level health check with provider-aware fallback
- `lab/vagrant/shared/caldera.sh` — Fail-fast Caldera provisioning (no MongoDB)
- `lab/vagrant/shared/base.sh` — Fail-fast base provisioning
- `lab/vagrant/*/Vagrantfile` — Provider blocks for libvirt, virtualbox, qemu
- `up_lab.sh` — Provider auto-detection and health check integration
- `setup.sh` — Dependency installation including QEMU for ARM64
