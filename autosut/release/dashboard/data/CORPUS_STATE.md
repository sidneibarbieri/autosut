# Campaign/SUT Contract State

This deterministic report describes released campaign definitions and their
declared SUT contracts. It does not summarize historical executor records,
report a success rate, or promote reviewer-generated runs to a claim.
Use `release/CLAIM_EVIDENCE_TRACEABILITY.md` for the canonical execution
claim and its hash-bound evidence.

## Summary

- Generated at: `2026-07-18T00:00:00Z`
- Available campaign definitions: `25`
- Campaigns with a declared SUT profile: `14`
- Campaign/SUT pairs passing strict validation: `12`
- Campaign/SUT pairs with validation findings: `2`
- Campaigns with clean MITRE metadata audit: `14`
- Campaigns not covered by the MITRE metadata audit: `11`
- Bounded dispatch witnesses: `1`

## Bounded Dispatch Witness

- Contract campaign: `0.shadowray`
- Source campaign: `C0045`
- Realization: `surrogate`

The witness is one sealed, static observation. It does not establish
campaign-wide execution, a current-revision live rerun, or an analyst-effort result.

## Contract State

| Campaign | Declared SUT Profile | Profile Present | Pair Valid | MITRE Audit | Bounded Dispatch Witness |
|---|---|---:|---:|---|---:|
| `0.apt41_dust` | `0.apt41_dust` | yes | yes | clean | no |
| `0.apt41_dust_full` | `0.apt41_dust_full` | yes | no | clean | no |
| `0.c0010` | `0.c0010` | yes | yes | clean | no |
| `0.c0011` | `0.c0011` | yes | yes | clean | no |
| `0.c0012` | `0.c0012` | yes | yes | clean | no |
| `0.c0013` | `0.c0013` | yes | no | clean | no |
| `0.c0015` | `0.c0015` | yes | yes | clean | no |
| `0.c0017` | `0.c0017` | yes | yes | clean | no |
| `0.c0026` | `0.c0026` | yes | yes | clean | no |
| `0.caldera_linux_demo` | `0.caldera_linux_demo` | no | no | not_audited | no |
| `0.costaricto` | `0.costaricto` | yes | yes | clean | no |
| `0.cve_2021_41773` | `0.cve_2021_41773` | no | no | not_audited | no |
| `0.dmz_segmentation_demo` | `0.dmz_segmentation_demo` | no | no | not_audited | no |
| `0.fin6_emulation` | `0.fin6_emulation` | no | no | not_audited | no |
| `0.operation_midnighteclipse` | `0.operation_midnighteclipse` | yes | yes | clean | no |
| `0.outer_space` | `0.outer_space` | yes | yes | clean | no |
| `0.pivot_demo` | `0.pivot_demo` | no | no | not_audited | no |
| `0.salesforce_data_exfiltration` | `0.salesforce_data_exfiltration` | yes | yes | clean | no |
| `0.shadowray` | `0.shadowray` | yes | yes | clean | yes |
| `0.web_demo` | `0.web_demo` | no | no | not_audited | no |
| `C0001` | `C0001` | no | no | not_audited | no |
| `C0002` | `C0002` | no | no | not_audited | no |
| `C0003` | `C0003` | no | no | not_audited | no |
| `C0004` | `C0004` | no | no | not_audited | no |
| `C0005` | `C0005` | no | no | not_audited | no |

## SUT Contract Findings

- `0.apt41_dust_full`: Fidelity mismatch for T1490: campaign expects adapted, SUT expects inspired
- `0.c0013`: Fidelity mismatch for T1059.004: campaign expects inspired, SUT expects adapted; Fidelity mismatch for T1105: campaign expects inspired, SUT expects adapted
- `0.caldera_linux_demo`: No published SUT profile matches declared profile `0.caldera_linux_demo`.
- `0.cve_2021_41773`: No published SUT profile matches declared profile `0.cve_2021_41773`.
- `0.dmz_segmentation_demo`: No published SUT profile matches declared profile `0.dmz_segmentation_demo`.
- `0.fin6_emulation`: No published SUT profile matches declared profile `0.fin6_emulation`.
- `0.pivot_demo`: No published SUT profile matches declared profile `0.pivot_demo`.
- `0.web_demo`: No published SUT profile matches declared profile `0.web_demo`.
- `C0001`: No published SUT profile matches declared profile `C0001`.
- `C0002`: No published SUT profile matches declared profile `C0002`.
- `C0003`: No published SUT profile matches declared profile `C0003`.
- `C0004`: No published SUT profile matches declared profile `C0004`.
- `C0005`: No published SUT profile matches declared profile `C0005`.
