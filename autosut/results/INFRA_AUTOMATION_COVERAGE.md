# Infrastructure and SUT Automation Coverage

This report describes what the current public artifact can provision
automatically for each published campaign/SUT pair. It measures declared
infrastructure and configuration coverage, not historical completeness.

## Summary

- Published campaign/SUT pairs: `14`
- Pairs passing strict validation: `12`
- Campaigns with base weaknesses configured automatically: `14`
- Campaigns with step-conditioned overlays: `1`
- Campaigns with latest shipped evidence: `14`
- Campaigns with single target host: `14`
- Campaigns with multi-target host topology: `0`
- Campaigns with multi-VM runtime substrate: `14`

## Interpretation

The current public subset already provisions a multi-VM substrate for every published campaign, automatically applies base weaknesses for every declared SUT, and supports step-conditioned overlays when a campaign declares them.
At the same time, the published subset is still operationally conservative: all currently shipped campaign/SUT pairs use one target host even though the IaC path can resolve multiple declared runtime VMs.

## Campaign Matrix

| Campaign | Pair Valid | Runtime VMs | Target Hosts | Topology | Base Weaknesses | Step Overlays | Latest Evidence |
|---|---|---:|---:|---|---:|---:|---|
| `0.apt41_dust` | yes | 3 | 1 | single_target | 3 | 0 | yes |
| `0.apt41_dust_full` | no | 3 | 1 | single_target | 1 | 0 | yes |
| `0.c0010` | yes | 3 | 1 | single_target | 2 | 0 | yes |
| `0.c0011` | yes | 3 | 1 | single_target | 1 | 0 | yes |
| `0.c0012` | yes | 3 | 1 | single_target | 2 | 0 | yes |
| `0.c0013` | no | 3 | 1 | single_target | 2 | 0 | yes |
| `0.c0015` | yes | 3 | 1 | single_target | 1 | 0 | yes |
| `0.c0017` | yes | 3 | 1 | single_target | 1 | 0 | yes |
| `0.c0026` | yes | 3 | 1 | single_target | 2 | 0 | yes |
| `0.costaricto` | yes | 3 | 1 | single_target | 2 | 0 | yes |
| `0.operation_midnighteclipse` | yes | 3 | 1 | single_target | 3 | 0 | yes |
| `0.outer_space` | yes | 3 | 1 | single_target | 1 | 0 | yes |
| `0.salesforce_data_exfiltration` | yes | 3 | 1 | single_target | 2 | 0 | yes |
| `0.shadowray` | yes | 3 | 1 | single_target | 1 | 1 | yes |

## Validation Exceptions

- `0.apt41_dust_full`: Fidelity mismatch for T1490: campaign expects adapted, SUT expects inspired
- `0.c0013`: Fidelity mismatch for T1059.004: campaign expects inspired, SUT expects adapted; Fidelity mismatch for T1105: campaign expects inspired, SUT expects adapted

## Source Paths

- `campaign_dir`: `campaigns/`
- `sut_profile_dir`: `data/sut_profiles/`
- `evidence_dir`: `release/evidence/`
