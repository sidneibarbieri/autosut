# Environment Provenance

- Generated at: `2026-07-18T00:00:00Z`
- Campaigns measured: `20`
- Total tagged SUT elements: `139`
- Policy: four-category evidence separation (`corpus_supported` / `external_reference` / `autosut_concretized` / `analyst_authored`).

Of the **139** concrete SUT elements materialised across **20** campaign SUT profiles, **2.2%** is anchored in the evaluated CTI corpus, **3.6%** comes from external advisories, **15.8%** is an AutoSUT concretization of an under-specified corpus signal, and **78.4%** is an explicit analyst lab choice the corpus does not constrain.

## Dimension x Source

Each tagged element belongs to exactly one dimension. This table is the environment-gap measurement: it shows, dimension by dimension, how much of the executable environment public cyber knowledge actually supports.

| Dimension | Corpus | External | AutoSUT | Analyst | Total |
|---|---:|---:|---:|---:|---:|
| Platform | 0 | 0 | 0 | 27 | 27 |
| Software | 0 | 1 | 0 | 22 | 23 |
| Vulnerability | 2 | 1 | 0 | 0 | 3 |
| Credentials | 0 | 1 | 21 | 0 | 22 |
| Exposures | 1 | 2 | 1 | 25 | 29 |
| Artifacts | 0 | 0 | 0 | 32 | 32 |
| Topology | 0 | 0 | 0 | 3 | 3 |
| **All** | 3 (2.2%) | 5 (3.6%) | 22 (15.8%) | 109 (78.4%) | **139** |

## Per-Campaign Breakdown

| Campaign | Elements | Corpus | AutoSUT | Analyst |
|---|---:|---:|---:|---:|
| `0.shadowray` | 6 | 0 (0.0%) | 0 (0.0%) | 3 (50.0%) |
| `0.c0010` | 8 | 0 (0.0%) | 1 (12.5%) | 7 (87.5%) |
| `0.c0011` | 7 | 0 (0.0%) | 1 (14.3%) | 6 (85.7%) |
| `0.c0012` | 4 | 0 (0.0%) | 1 (25.0%) | 3 (75.0%) |
| `0.c0013` | 6 | 0 (0.0%) | 1 (16.7%) | 5 (83.3%) |
| `0.c0015` | 6 | 0 (0.0%) | 1 (16.7%) | 5 (83.3%) |
| `0.c0017` | 5 | 0 (0.0%) | 1 (20.0%) | 4 (80.0%) |
| `0.c0026` | 6 | 0 (0.0%) | 1 (16.7%) | 5 (83.3%) |
| `0.apt41_dust` | 11 | 0 (0.0%) | 1 (9.1%) | 10 (90.9%) |
| `0.apt41_dust_full` | 6 | 0 (0.0%) | 1 (16.7%) | 5 (83.3%) |
| `0.costaricto` | 9 | 0 (0.0%) | 1 (11.1%) | 8 (88.9%) |
| `0.outer_space` | 9 | 0 (0.0%) | 1 (11.1%) | 8 (88.9%) |
| `0.operation_midnighteclipse` | 5 | 2 (40.0%) | 1 (20.0%) | 2 (40.0%) |
| `0.salesforce_data_exfiltration` | 6 | 1 (16.7%) | 3 (50.0%) | 2 (33.3%) |
| `0.caldera_linux_demo` | 7 | 0 (0.0%) | 1 (14.3%) | 6 (85.7%) |
| `0.fin6_emulation` | 7 | 0 (0.0%) | 1 (14.3%) | 6 (85.7%) |
| `0.dmz_segmentation_demo` | 13 | 0 (0.0%) | 3 (23.1%) | 10 (76.9%) |
| `0.pivot_demo` | 9 | 0 (0.0%) | 2 (22.2%) | 7 (77.8%) |
| `0.web_demo` | 4 | 0 (0.0%) | 0 (0.0%) | 4 (100.0%) |
| `0.cve_2021_41773` | 5 | 0 (0.0%) | 0 (0.0%) | 3 (60.0%) |

## How to read this

- **Corpus** = the value is anchored in CTI/NVD/ATT&CK evidence: a CVE-pinned product+version, the disclosed CVE itself, the documented exploit surface/port, or the OS platform family (an ATT&CK `x_mitre_platforms` field).
- **AutoSUT** = AutoSUT concretized an under-specified corpus signal: the corpus implies *a* usable credential exists (valid-accounts / brute-force), AutoSUT picks the literal pair; or a named-product surrogate with no disclosed CVE.
- **Analyst** = no corpus signal; pure lab construction: generic inherited services (the campaign needs *an* affordance, not that specific product), topology zones, and decoy files.
- Provenance is **counted, never computed**: the aggregator only tallies tags an analyst set in `catalog.py`. The sole derived tags are definitional (a real CVE id *is* corpus evidence; an OS family *is* an ATT&CK platform).
