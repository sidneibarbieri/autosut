# Corpus State

- Generated at: `2026-06-01T13:11:20.082834`
- Published campaigns: `19`
- Executable campaigns with SUT profile: `14`
- Campaign/SUT pairs passing strict validation: `12`
- Campaigns with latest evidence: `19`
- Campaigns with zero failed techniques in latest evidence: `19`
- Campaigns with clean MITRE metadata audit: `14`
- Campaigns without host leakage in latest evidence: `19`

## Campaign Status

| Campaign | SUT | Pair Valid | Evidence | Latest Success | MITRE Clean | Host Leakage |
|---|---:|---:|---:|---:|---:|---:|
| 0.apt41_dust | yes | yes | yes | 23/23 (100.0%) | yes | no |
| 0.apt41_dust_full | yes | no | yes | 10/10 (100.0%) | yes | no |
| 0.c0010 | yes | yes | yes | 9/9 (100.0%) | yes | no |
| 0.c0011 | yes | yes | yes | 11/11 (100.0%) | yes | no |
| 0.c0012 | yes | yes | yes | 3/3 (100.0%) | yes | no |
| 0.c0013 | yes | no | yes | 4/4 (100.0%) | yes | no |
| 0.c0015 | yes | yes | yes | 5/5 (100.0%) | yes | no |
| 0.c0017 | yes | yes | yes | 6/6 (100.0%) | yes | no |
| 0.c0026 | yes | yes | yes | 6/6 (100.0%) | yes | no |
| 0.caldera_linux_demo | no | no | yes | 6/6 (100.0%) | no | no |
| 0.costaricto | yes | yes | yes | 10/10 (100.0%) | yes | no |
| 0.cve_2021_41773 | no | no | yes | 4/4 (100.0%) | no | no |
| 0.dmz_segmentation_demo | no | no | yes | 4/4 (100.0%) | no | no |
| 0.fin6_emulation | no | no | yes | 12/12 (100.0%) | no | no |
| 0.operation_midnighteclipse | yes | yes | yes | 17/17 (100.0%) | yes | no |
| 0.outer_space | yes | yes | yes | 8/8 (100.0%) | yes | no |
| 0.pivot_demo | no | no | yes | 6/6 (100.0%) | no | no |
| 0.salesforce_data_exfiltration | yes | yes | yes | 18/18 (100.0%) | yes | no |
| 0.shadowray | yes | yes | yes | 3/3 (100.0%) | yes | no |

## Validation Exceptions

- `0.apt41_dust_full`: Fidelity mismatch for T1490: campaign expects adapted, SUT expects inspired
- `0.c0013`: Fidelity mismatch for T1059.004: campaign expects inspired, SUT expects adapted; Fidelity mismatch for T1105: campaign expects inspired, SUT expects adapted