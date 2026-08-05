# Campaign-SUT-Fidelity Matrix

Source of truth:
- Published campaigns with a matching SUT profile only
- Exact `<campaign_id>_YYYYMMDD_HHMMSS` evidence directory matching per campaign
- `release/evidence/*/summary.json` (latest exact match per campaign)
- `release/fidelity_report.json` (rubric consistency when available)
- `src/loaders/campaign_loader.py` (`validate_campaign_sut_pair`)
- Rows without shipped evidence are shown explicitly rather than treated as failed runs

| Campaign | SUT Profile | Pair Valid | Evidence | Latest Evidence Dir | Total | Success | Failed | Skipped | Faithful | Adapted | Inspired | Rubric Total | Rubric Consistent | Rubric Mismatches |
|---|---|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `0.apt41_dust` | `0.apt41_dust` | yes | yes | `0.apt41_dust_20260603_193334` | 23 | 23 | 0 | 0 | 0 | 14 | 9 | 13 | 3 | 10 |
| `0.apt41_dust_full` | `0.apt41_dust_full` | no | yes | `0.apt41_dust_full_20260603_193427` | 10 | 10 | 0 | 0 | 0 | 9 | 1 | 10 | 2 | 8 |
| `0.c0010` | `0.c0010` | yes | yes | `0.c0010_20260603_192801` | 9 | 9 | 0 | 0 | 0 | 3 | 6 | 9 | 4 | 5 |
| `0.c0011` | `0.c0011` | yes | yes | `0.c0011_20260603_192838` | 11 | 11 | 0 | 0 | 0 | 2 | 9 | 11 | 9 | 2 |
| `0.c0012` | `0.c0012` | yes | yes | `0.c0012_20260603_192907` | 3 | 3 | 0 | 0 | 0 | 3 | 0 | 3 | 2 | 1 |
| `0.c0013` | `0.c0013` | no | yes | `0.c0013_20260603_192951` | 4 | 4 | 0 | 0 | 0 | 1 | 3 | 4 | 3 | 1 |
| `0.c0015` | `0.c0015` | yes | yes | `0.c0015_20260603_193201` | 5 | 5 | 0 | 0 | 0 | 3 | 2 | 5 | 2 | 3 |
| `0.c0017` | `0.c0017` | yes | yes | `0.c0017_20260603_193232` | 6 | 6 | 0 | 0 | 0 | 6 | 0 | 6 | 2 | 4 |
| `0.c0026` | `0.c0026` | yes | yes | `0.c0026_20260603_193302` | 6 | 6 | 0 | 0 | 0 | 4 | 2 | 6 | 6 | 0 |
| `0.costaricto` | `0.costaricto` | yes | yes | `0.costaricto_20260603_193458` | 10 | 10 | 0 | 0 | 0 | 3 | 7 | 10 | 8 | 2 |
| `0.operation_midnighteclipse` | `0.operation_midnighteclipse` | yes | yes | `0.operation_midnighteclipse_20260603_193617` | 17 | 17 | 0 | 0 | 0 | 5 | 12 | 18 | 4 | 14 |
| `0.outer_space` | `0.outer_space` | yes | yes | `0.outer_space_20260603_193538` | 8 | 8 | 0 | 0 | 0 | 2 | 6 | 8 | 6 | 2 |
| `0.salesforce_data_exfiltration` | `0.salesforce_data_exfiltration` | yes | yes | `0.salesforce_data_exfiltration_20260603_193647` | 18 | 18 | 0 | 0 | 0 | 8 | 10 | 12 | 3 | 9 |
| `0.shadowray` | `0.shadowray` | yes | yes | `0.shadowray_20260603_195045` | 3 | 3 | 0 | 0 | 0 | 3 | 0 | 10 | 4 | 6 |

## Pair Validation Exceptions

- `0.apt41_dust_full`: Fidelity mismatch for T1490: campaign expects adapted, SUT expects inspired
- `0.c0013`: Fidelity mismatch for T1059.004: campaign expects inspired, SUT expects adapted; Fidelity mismatch for T1105: campaign expects inspired, SUT expects adapted
