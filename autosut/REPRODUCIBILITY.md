# Reproducibility Notes

## Scope

This repository supports controlled campaign execution and evidence collection.
The current reproducibility target has two released layers: a fast study-claim
validation path and a repository-local minimal working example. It also retains
provider-aware VM backend material for future qualification, separate from the
released claim gate.

## Fast Study-Claim Validation

```bash
bash run_review_check.sh
```

This path reruns the measurement pipeline, regenerates study-facing outputs,
and checks that the released values remain consistent from the same checkout.
It also rebuilds the canonical RQ1--RQ4/C0045 and bounded dispatch claim ledger,
then rejects required claims whose declared evidence gate does not pass. The
dispatch row audits sealed public evidence; it does not launch a live backend.

Measurement diagnostics are retained under
`results/reviewer_runtime/measurement-<run-token>/`. Each invocation creates its
own directory and prints its location. Success and failure keep their logs for
inspection; no fixed shared `/tmp` log names are used. The manifest permits only
declared diagnostic filenames under this layout when `--allow-runtime-state` is
enabled. Logs are excluded from newly built release packages, while unknown
diagnostic content blocks packaging rather than being deleted. Diagnostic
isolation does not permit simultaneous result regeneration in the same checkout;
use separate extracted packages for concurrent full reproductions.

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
| Orchestrated Docker replay | Python 3.10+, `venv`, `docker` | Docker-capable host | sequential replay of the implemented campaign/SUT subset; reviewer-generated records are not promoted to claims |
| VM backend materials | Python 3.10+, `venv`, `vagrant`, `qemu` or `libvirt` | 8 CPU cores, 16 GB RAM, 25 GB free disk recommended | implementation and future qualification material, not a released claim path |

The canonical wrappers enforce the exact versions in
`requirements-reviewer.txt` inside a repo-local `.venv`. Optional development
and documentation tools are pinned separately in `requirements-dev.txt` so the
reviewer bootstrap does not install unrelated tooling.

The VM material is intentionally not a reviewer recipe. The current capability
ledger records QEMU Linux ARM64 as `implemented` with boot qualification still
required, and native Windows as `development_in_progress`. A local guest boot
or provider preflight does not alter the released ledger or establish a claim.

## Docker Smoke Replay

```bash
bash artifact/setup.sh
bash artifact/run.sh
bash artifact/validate.sh
```

The smoke path executes two compact, complementary campaign/SUT slices:

- `0.c0017`, an infrastructure smoke replay;
- `0.shadowray`, a C0045-derived state-contract surrogate.

The wrappers bind validation to the evidence created by that invocation and
archive the records under `release/evidence/_reviewer_runs/`. These local
records do not modify the released claim ledger or manifest-listed study
outputs. Study-facing tables are regenerated only by `bash run_review_check.sh`.
It requires a reachable Docker daemon and may download/build public images and
packages on first use. The run wrapper performs an explicit Docker preflight.

## Generated Outputs

The smoke path writes:

- `release/evidence/<campaign>_<timestamp>/summary.json`
- `release/evidence/<campaign>_<timestamp>/manifest.json`
- `release/evidence/<campaign>_<timestamp>/fidelity_report.json`

After validation, the checked smoke run is moved to
`release/evidence/_reviewer_runs/` so reviewer-generated runs remain available
without changing the released claim ledger or its ledger-linked evidence.
When executed from an extracted public package, `artifact/validate.sh` also
checks that the immutable package manifest still matches.

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
applied base weaknesses, step-conditioned overlays, and the exact pair covered
by the bounded dispatch witness.

`results/CORPUS_STATE.md` is a deterministic contract-state report. It
distinguishes available campaign definitions, declared SUT profiles, strict
campaign/SUT validation, MITRE-audit coverage, and the bounded dispatch witness.
It does not summarize historical executor status or use a successful executor
status as proof that a current implementation is qualified.

In the current published subset, those declared campaign/SUT pairs still use
single target-host examples. The underlying IaC path is able to lift broader
multi-host layouts when a future SUT profile declares them, but that should be
read as current capability rather than as shipped corpus coverage.

The retained VM wrapper is intended to lift a declared topology, apply the
base SUT profile and step-conditioned overlays, execute a campaign, collect
evidence, and tear down. Those source-level steps are not proof that a backend
has completed boot, execution, independent observation, and clean teardown.

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

These are source-level implementation helpers, intentionally outside the
released reviewer contract. They should not be represented as a qualified
campaign replay or a promise of historical replay fidelity.

Candidate provider implementations for a later qualification are:

- `libvirt` on Linux
- `qemu` on macOS ARM64

This is an implementation detail of the optional VM infrastructure layer; the
canonical reviewer path instead requires neither a VM backend nor a Windows
image.

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
and only then inspect VM source and the capability ledger when implementation
scope matters.
