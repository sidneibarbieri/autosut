# Reproducibility Notes

## Scope

This repository supports controlled campaign execution and evidence collection.
The current reproducibility target has three layers: a fast study-claim
validation path, a repository-local minimal working example, and a supported
provider-aware VM-backed path for campaign/SUT pairs that need concrete lab
infrastructure.

## Fast Study-Claim Validation

```bash
bash run_review_check.sh
```

This path reruns the measurement pipeline, regenerates study-facing outputs,
and checks that the released values remain consistent from the same checkout.
It also rebuilds the canonical RQ1--RQ4/C0045 claim ledger and rejects required
claims whose declared evidence gate does not pass.

The C0045 gate is self-contained and can be isolated with:

```bash
python3 scripts/run_arm_comparison.py
```

The command consumes the hash-bound input set under
`release/inputs/sticks/c0045-v1/`; it does not require a sibling STICKS
checkout. It distinguishes the three deterministic resolver outputs from the
single arm for which execution evidence is released.

The public artifact uses this command in standalone mode. Internal manuscript
integration is explicit and read-only by default:

```bash
PAPER_DIR=/path/to/paper bash run_review_check.sh
```

This checks macro values, tables, bibliography policy, and compilation on a
temporary paper copy. It does not overwrite the manuscript. Intentional
replacement of `results/values.tex` and generated figure templates requires
`SYNC_MANUSCRIPT_VALUES=1` together with `PAPER_DIR`. Provenance macros remain
artifact-only and are never copied by this gate.

## Host and Runtime Expectations

| Path | Required tools | Recommended host | Interpretation |
| --- | --- | --- | --- |
| Fast study-claim validation | Python 3.10+, `venv` | commodity laptop/desktop | canonical validation of released values |
| Docker smoke replay | Python 3.10+, `venv`, `docker` | Docker-capable host | smallest live campaign/SUT execution example |
| VM-backed path | Python 3.10+, `venv`, `vagrant`, `qemu` or `libvirt` | 8 CPU cores, 16 GB RAM, 25 GB free disk recommended | heavier cold-start realism path for one campaign/SUT pair |

The canonical wrappers enforce the exact versions in
`requirements-reviewer.txt` inside a repo-local `.venv`. Optional development
and documentation tools are pinned separately in `requirements-dev.txt` so the
reviewer bootstrap does not install unrelated tooling.

The heavy path is allowed to be slow. First-boot package installation,
guest bootstrap, and Caldera-related service provisioning can dominate the run
time on a clean checkout, especially on macOS ARM64 with `qemu`.
By default, the VM-backed wrapper restores tracked study-facing summaries after
teardown and removes runtime-only lab byproducts. Use
`--persist-derived-state` only when you explicitly want to keep regenerated
summaries or local SUT reports in the checkout.

## Docker Smoke Replay

```bash
bash artifact/setup.sh
bash artifact/run.sh
bash artifact/validate.sh
```

The smoke path currently executes one representative campaign:

- `0.c0017`

and then regenerates the LaTeX tables used by the study-facing workflow.
It requires a reachable Docker daemon and may download/build public images and
packages on first use. The run wrapper performs an explicit Docker preflight.

## Generated Outputs

The smoke path writes:

- `release/evidence/<campaign>_<timestamp>/summary.json`
- `release/evidence/<campaign>_<timestamp>/manifest.json`
- `release/evidence/<campaign>_<timestamp>/fidelity_report.json`
- `results/tables/corpus_table.tex`
- `results/tables/fidelity_table.tex`
- `results/tables/execution_table.tex`

After validation, the checked smoke run is moved to
`release/evidence/_reviewer_runs/` so reviewer-generated runs remain available
without changing the curated golden evidence used by the dashboard.

Supporting state reports can be regenerated with:

```bash
python3 scripts/generate_corpus_state.py
python3 scripts/audit_mitre_metadata.py
python3 scripts/check_public_surface.py
python3 scripts/generate_cve_resolution_report.py
python3 scripts/generate_compatibility_rule_surface.py
```

The CVE resolution report is a deterministic downstream extension. It measures
which campaign-linked CVEs currently resolve to candidate SUT targets in the
public artifact and where ATT&CK still lacks a direct target-product binding.
It does not claim automatic exploit synthesis or online CTI-to-command
planning, and it is not an exhaustive crawl of the `apt` or `pip` ecosystems.
It only covers the ATT&CK-linked campaign/CVE slice already present in the
artifact under curated, source-backed rules.

The compatibility-rule surface report,
`results/COMPATIBILITY_RULE_SURFACE.md`, exposes the exact deterministic
keywords and regexes behind the CF/VMR/ID routing policy. The labels are
heuristic policy outputs, not measured minimum-backend requirements. Exact
percentage numerators, denominators, and scopes are recorded in
`measurement/sut/scripts/results/audit/compatibility_denominator_summary.csv`.

The infrastructure automation coverage report, `results/INFRA_AUTOMATION_COVERAGE.md`,
documents the current IaC and SUT automation boundary across the published
campaign/SUT pairs: runtime VM topology, target-host count, automatically
applied base weaknesses, step-conditioned overlays, and latest evidence
availability.

In the current published subset, those declared campaign/SUT pairs still use
single target-host examples. The underlying IaC path is able to lift broader
multi-host layouts when a future SUT profile declares them, but that should be
read as current capability rather than as shipped corpus coverage.

For a concrete VM-backed run that provisions the declared SUT automatically:

```bash
bash run_vm_backed_campaign.sh 0.c0011
bash run_vm_backed_campaign.sh 0.shadowray
```

That wrapper delegates to `scripts/run_lab_campaign.py`, which lifts the VM
substrate declared by the campaign's SUT profile, applies the declared base SUT
profile, applies step-conditioned SUT overlays for selected techniques,
executes the campaign, refreshes evidence/state reports, and tears the lab down
unless `--keep-lab` is requested.

The interpretation is intentionally conservative: the repository derives a
static lower-bound SUT profile from one corpus snapshot and then runs a
declared campaign/SUT pair. It does not perform online replanning or choose
final vulnerabilities/commands dynamically during execution; the step-level
overlays are explicit campaign metadata rather than new inference.

## Optional Infrastructure

Provider-aware lab helpers exist for broader infrastructure experiments and
realism checks:

- `scripts/up_lab.sh`
- `scripts/destroy_lab.sh`
- `multi_vm_manager_2vm.py`

These helpers are supported, but they are intentionally heavier than the smoke
path and should be interpreted campaign by campaign rather than as a promise of
historical replay fidelity.

Backend preference for the optional VM-backed path is currently:

- `libvirt` on Linux
- `qemu` on macOS ARM64

This is an implementation detail of the optional VM infrastructure layer; the
canonical smoke path instead requires Docker.

## Known Limits

- Docker-backed campaign replay is supported for the implemented campaign/SUT
  pairs, but it remains host- and Docker-dependent; reviewers should run
  preflight first so infrastructure failures are separated from campaign
  failures.
- Compatibility JSON campaigns and canonical YAML campaigns coexist in the same
  repository; the loader supports both.
- Raw evidence is generated locally under `release/evidence/` when a reviewer
  runs the included workflows.
- The public GitHub handoff keeps synthesized reports and compact dashboard
  evidence, not the full internal archive of exploratory and superseded runs.
- The executable witnesses remain deliberately bounded. They do not support
  claims of historical equivalence, arbitrary-campaign automation, measured
  analyst-effort reduction, or scalability/minimal overhead.

## Integrity Principle

The repository should not claim universal success where the current execution
path still reports real failures. Reviewer-facing instructions should therefore
start from `run_review_check.sh`, then widen to the repository-local example,
and only then to the VM-backed path when explicit substrate evidence matters.
