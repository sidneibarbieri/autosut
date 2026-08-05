# Reviewer Guide

This guide keeps the validation path short and explicit.

## Main Results and Claim Boundary

AutoSUT separates two forms of evidence that must not be conflated:

- RQ1--RQ3 measure the environment information present in pinned CTI snapshots
  and the behavior of explicitly declared enrichment, routing, and profile
  analyses.
- RQ4 is a bounded constructive result: three controlled witnesses admit more
  than one SUT realization while preserving the checked technique sequence and
  oracle. It is an existence result, not a prevalence estimate.
- The C0045-derived case is a single controlled surrogate experiment. It is not
  a historical reconstruction of a Ray deployment.

The authoritative status, evidence paths, scope, and non-claims are generated
in `release/CLAIM_EVIDENCE_TRACEABILITY.md` and
`release/claim_evidence_traceability.json`. `bash run_review_check.sh` fails if
one of the required RQ1--RQ4/C0045 gates is not supported.

The C0045 check can also be run directly:

```bash
python3 scripts/run_arm_comparison.py
```

It verifies the vendored input set in
`release/inputs/sticks/c0045-v1/`, regenerates the comparison report, and
checks the released Arm-C evidence and fidelity record by hash. Arms A and B
are plan-synthesis outputs; only Arm C has execution evidence.

To rebuild the constructive witness records on a Docker-capable host:

```bash
python3 scripts/build_subdetermination_artifact.py
```

Inspect `release/subdetermination_proof.json` for variant definitions,
per-run hashes, technique-evidence hashes, teardown status, and the declared
fixed/free provenance counts. A passing witness supports only the contract in
the ledger; it does not establish historical equivalence or generalize to
arbitrary ATT&CK campaigns.

## Host Expectations

| Path | Required tools | Recommended host | Notes |
| --- | --- | --- | --- |
| `run_review_check.sh` | Python 3.10+ | commodity laptop/desktop | fastest way to validate study-facing outputs |
| `artifact/` smoke path | Python 3.10+, `venv`, `docker` | Docker-capable host | smallest live campaign/SUT execution trace |
| `scripts/run_all_orchestrated_campaigns.py` | Python 3.10+, `docker` | Docker-capable host | full sequential replay of implemented campaign/SUT pairs |
| `run_vm_backed_campaign.sh` | Python 3.10+, `vagrant`, `qemu` or `libvirt` | 8 CPU cores, 16 GB RAM, 25 GB free disk recommended | cold-start guest bootstrap can dominate runtime |

For the heavy path, Linux x86_64 with `libvirt` is preferred when available.
On macOS ARM64, the supported fallback is `qemu`.
By default, the VM-backed wrapper restores tracked study-facing summaries after
teardown and removes runtime-only lab byproducts. Use
`--persist-derived-state` only when you explicitly want to keep regenerated
summaries or local SUT reports in the checkout.
No path requires API keys or paid model access. On a cold Docker host, the
smoke and full-replay paths download public container images and packages.

## Recommended Order

1. Run the fast study-claim validation path (Section 1).
2. Use the Findings → Evidence map (Section 2) to spot-check individual claims against the raw CSV outputs.
3. On a Docker-capable host, run the smoke replay (Section 3) for the smallest live execution trace.
4. If you want a full Docker-backed replay, run the orchestrated campaign suite (Section 5).
5. If you want the realistic VM-backed substrate, run the canonical lab path (Section 6).

## 1. Fast Study-Claim Validation

```bash
bash run_review_check.sh
```

This path is the fastest way to revalidate the released measurement outputs and
study-facing synthesized artifacts.
The wrapper creates and reuses a repo-local `.venv`, enforcing the exact
versions in `requirements-reviewer.txt`. On a cold machine, the first bootstrap
downloads that pinned set; optional contributor tools are separated in
`requirements-dev.txt`.

This public reviewer path is standalone: it neither searches for nor modifies
a manuscript checkout. For maintainers, setting `PAPER_DIR=/path/to/paper`
adds read-only manuscript consistency and build checks. Only the explicit
combination `PAPER_DIR=/path/to/paper SYNC_MANUSCRIPT_VALUES=1` may replace the
paper's `results/values.tex` and generated TikZ templates. The default renderer
writes solely to
`measurement/sut/scripts/results/rendered_figures/`.

## 2. Findings → Evidence Map

Each headline number in the study traces to a generated macro, a raw evidence
file, and a step of `run_review_check.sh` that enforces it. Reviewers can
spot-check any claim without parsing the manuscript separately.

All evidence files referenced below are under
`measurement/sut/scripts/results/audit/`. The generated macros are in
`measurement/sut/scripts/results/todo_values_latex.tex`.

| # | Finding (study claim) | Macro | Evidence file | Enforced by |
|---|-----------------------|-------|---------------|-------------|
| 1 | Software refs rarely pin versions or CPEs (97.6% lack both) | `\softwarenoversionnocpepercentage` | `software_version_enrichment.csv` | step 3 (numeric invariants) |
| 2 | Campaign-level CVE evidence is sparse and fragmented (8 actionable, 5 campaigns) | `\campaignlinkedcvecount` | `campaign_cves.csv` | step 3b (table content) |
| 3 | Platform tags are near-universal in Enterprise (100%) | `\enterpriseplatformpct` | `platform_distribution.csv` | step 3 (numeric invariants) |
| 4 | The descriptive k≥1→k≥2 confusion drop is 1.3 pp, is driven by two singleton profiles, and is compatible with both declared nulls | `\thresholdcollapseobservedpp`, `\thresholdcollapsenullpvalue`, `\thresholdcollapsedegreenullpvalue` | `evidence_threshold_curve.csv`, `null_model_confusion_distribution.csv`, `threshold_collapse_degree_null_distribution.csv`, `threshold_collapse_leave_one_out.csv` | step 3 (numeric invariants), step 6e (macro consistency) |
| 5 | The routing policy assigns only 2.7% to CF and assigns 67.3% by fallback | `\compatibilitycontainerfeasiblepercentage`, `\compatibilityfallbackassignmentpercentage` | `compatibility_denominator_summary.csv`, `compatibility_rule_breakdown.csv`, `technique_compatibility.csv` | step 3b (rule breakdown rows) |

**Worked examples** are reproducible from the same
evidence files. The SharePoint ToolShell vs. ShadowRay contrast, for instance,
is two rows in `campaign_cves.csv` cross-referenced with
`campaign_profile_completeness.csv`.

**Robustness checks**: `null_model_confusion_distribution.csv` directly tests
the k≥1→k≥2 drop while preserving each profile's cardinality and the corpus
software universe. `threshold_collapse_degree_null_distribution.csv` also
preserves observed software popularity through bipartite double-edge swaps,
and `threshold_collapse_leave_one_out.csv` exposes numerator influence.
`bootstrap_confusion_distribution.csv` is retained only as descriptive
resampling of fixed nearest-neighbor indicators; it is not a bootstrap of the
dependent nearest-neighbor graph functional. δ-sensitivity values are in
`delta_sensitivity.csv`.

**Full traceability**: `release/CLAIM_EVIDENCE_TRACEABILITY.md` and
`release/claim_evidence_traceability.json` map RQ1--RQ4 and the bounded C0045
case back to generated outputs, executable gates, and explicit claim limits.

**Interactive view**: a static HTML dashboard with the same map plus tables
and the experiment log is available at `release/dashboard/index.html`. Build
or refresh it with:

```bash
python3 scripts/build_reviewer_dashboard.py
# Then open release/dashboard/index.html in any browser, or serve locally:
python3 -m http.server 8765 -d release/dashboard
```

The dashboard is fully self-contained (HTML + CSS + co-located CSVs); no
JavaScript framework, no server, no network calls.

**Compatibility adjudication**: the deterministic CF/VMR/ID routing policy ships with
a 36-row stratified packet at
`measurement/sut/scripts/results/audit/compatibility_validation_sample.csv`.
The submitted artifact leaves the manual columns blank on purpose, so the
paper does not claim completed inter-rater agreement. To adjudicate the packet,
fill `manual_expected_class`, `manual_verdict_match`, `manual_notes`, and
`reviewer`, then run:

```bash
python3 measurement/sut/scripts/evaluate_compatibility_validation.py
```

The evaluator regenerates
`measurement/sut/scripts/results/compatibility_validation_summary.json`,
`measurement/sut/scripts/results/audit/compatibility_validation_confusion.csv`,
and
`measurement/sut/scripts/results/audit/compatibility_validation_disagreements.csv`,
including agreement and Cohen's kappa once labels exist. With 0/36 manual labels,
agreement and kappa are undefined (`null`), not 0% accuracy. The policy labels
are routing cues; they are not measured minimum-backend requirements. Rerunning
the measurement pipeline preserves completed manual columns by technique ID.

## 3. Docker Smoke Replay

```bash
bash artifact/setup.sh
bash artifact/run.sh
bash artifact/validate.sh
```

`artifact/setup.sh` prepares the repo-local `.venv`; `artifact/run.sh` and
`artifact/validate.sh` reuse that interpreter automatically. A reachable
Docker daemon is required; the run wrapper reports preflight failures directly
and may pull/build public images on first use.

Expected outputs:

- `release/evidence/<campaign>_<timestamp>/summary.json`
- `release/evidence/<campaign>_<timestamp>/manifest.json`
- `results/tables/corpus_table.tex`
- `results/tables/fidelity_table.tex`
- `results/tables/execution_table.tex`

## 4. Direct Commands

If you prefer not to use the wrappers:

```bash
.venv/bin/python3 scripts/run_orchestrated_campaign.py 0.c0017
.venv/bin/python3 scripts/generate_tables.py
```

To list campaigns:

```bash
.venv/bin/python3 scripts/run_orchestrated_campaign.py --list
```

To audit the public-facing repository surface:

```bash
python3 scripts/check_public_surface.py
```

This audit checks for stale validation paths, duplicate documentation
directories, and local runtime residue that should not survive into a clean
artifact handoff.

To inspect the deterministic downstream CVE concretization report:

```bash
cat results/CVE_RESOLUTION_CANDIDATES.md
```

This report measures which campaign-linked CVEs currently resolve to concrete
candidate SUT targets in the public artifact. It does not infer exploits or
perform online target-product discovery, and it is not an exhaustive crawl of
the `apt` or `pip` ecosystems. It only covers the ATT&CK-linked campaign/CVE
slice already present in the artifact under curated, source-backed rules.

To inspect the exact public-facing compatibility routing-policy surface:

```bash
cat results/COMPATIBILITY_RULE_SURFACE.md
```

To inspect the current infrastructure/SUT automation boundary:

```bash
cat results/INFRA_AUTOMATION_COVERAGE.md
```

This report shows, per published campaign/SUT pair, how many runtime VMs are
declared, how many target hosts are configured, whether base weaknesses are
applied automatically, whether step-conditioned overlays exist, and whether
latest evidence is currently shipped.

## 5. Full Orchestrated Campaign Replay

This path is for reviewers who want to re-execute the implemented Docker-backed
campaign/SUT pairs rather than only inspect shipped evidence.

Start with preflight:

```bash
python3 scripts/run_all_orchestrated_campaigns.py --preflight-only
```

Run a single campaign:

```bash
python3 scripts/run_all_orchestrated_campaigns.py --campaign 0.c0013
```

Run all implemented campaigns:

```bash
python3 scripts/run_all_orchestrated_campaigns.py
```

After an interrupted local batch, clean only stale AutoSUT campaign containers
before replaying:

```bash
python3 scripts/run_all_orchestrated_campaigns.py --clean-stale-autosut-containers --preflight-only
```

Expected reports:

- `release/orchestrated_replay_<timestamp>.tsv`
- `release/orchestrated_replay_<timestamp>.json`

The runner attempts to bring the local Caldera C2 online before replaying
Caldera-driven campaigns. If Caldera or Docker is not reachable, preflight fails
before producing misleading campaign-level failures. By default, known slow
campaigns run last so the reviewer sees early progress from faster campaigns;
use `--catalog-order` only when exact catalog order matters.

## 6. VM-Backed Realism Path

The repository also contains a provider-aware VM-backed path for realism
checks. This path is not required for the smoke path, but it is the supported
way to validate the QEMU/libvirt-backed substrate.

Important:

- The smoke path does not depend on QEMU or Caldera being green.
- The smoke path does not require a specific host platform or hypervisor.
- The preferred VM-backed backend is `libvirt` on Linux and `qemu` on macOS ARM64.
- A cold-start VM-backed run can take materially longer than the smoke path
  because the guests may need first-boot package installation and service
  provisioning before campaign execution starts.
- VM-backed claims should be based on a fresh run of the canonical lab path in
  the same checkout.
- The VM-backed unit of validation is a single self-contained campaign/SUT pair.
  Reviewers may run any one campaign, any subset, or the full set, and each
  campaign should stand on its own without relying on prior campaign state.

### 5.1 Validated VM paths

| Host | Provider | Entry | Status |
|------|----------|-------|--------|
| Linux x86_64 | libvirt | `./run_vm_backed_campaign.sh <campaign>` | Supported (Vagrantfile in `lab/vagrant/`) |
| macOS Apple Silicon (M-series) | direct QEMU + Apple HVF | `python3 multi_vm_manager_2vm.py up` | Validated 2026-05-26 |

### 5.2 macOS Apple Silicon quick start (direct QEMU)

The Vagrant path on macOS requires libvirt, which is not available natively. Use
the direct-QEMU helper instead:

```bash
# One-time: download Ubuntu 22.04 ARM64 cloud image (~636 MB)
mkdir -p lab/qemu/images
curl -sSL https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-arm64.img \
  -o lab/qemu/images/jammy-server-cloudimg-arm64.img

# Bring up 2 VMs (attacker + target). Takes ~10s after image is cached.
python3 multi_vm_manager_2vm.py up

# SSH into either VM (password: ubuntu)
sshpass -p ubuntu ssh -p 2224 ubuntu@127.0.0.1   # attacker
sshpass -p ubuntu ssh -p 2223 ubuntu@127.0.0.1   # target

# Teardown
python3 multi_vm_manager_2vm.py down
```

Prerequisites (macOS): `brew install qemu xorriso sshpass`. Apple HVF is built
into macOS — no extra install needed. The helper uses `qemu-system-aarch64 -cpu
host -machine virt,accel=hvf`, which is the only combination that works on
M-series hardware.

Run the canonical VM-backed path:

```bash
bash run_vm_backed_campaign.sh 0.c0011
```

Keep the lab up for manual inspection:

`python3 scripts/run_lab_campaign.py --campaign 0.c0011 --keep-lab`

Use an explicit provider when needed:

`python3 scripts/run_lab_campaign.py --campaign 0.c0011 --provider qemu`

The orchestration does this in one path:

- `scripts/up_lab.sh`
- `apply_sut_profile.py`
- `scripts/run_campaign.py`
- `scripts/collect_evidence.sh`
- `scripts/generate_corpus_state.py`
- `scripts/destroy_lab.sh`

Operationally, `up_lab.sh` resolves the VM topology from the campaign's SUT
profile, starts the required provider-backed VMs, waits for core services, and
then applies the declared SUT profile automatically. That SUT application step
is where the lab receives campaign-specific weaknesses and prerequisites such as
weak users/passwords, writable directories, SUID binaries, and deliberately
vulnerable services like Apache. During execution, selected techniques may also
apply declared step-conditioned SUT overlays, such as exposing the Ray API
boundary immediately before `T1190` in `0.shadowray`. The follow-on execution
path then runs the campaign, collects evidence, refreshes corpus-state reports,
and tears the lab down unless `--keep-lab` is requested.

Important interpretation note:

- The repository derives a static SUT profile from a fixed corpus snapshot and
  then executes a declared campaign/SUT pair.
- Selected techniques may apply declared SUT overlays at runtime, but those
  overlays are explicit campaign metadata, not online CTI inference.
- The VM-backed path may bring up and health-check a Caldera node as part of
  the lab, but campaign execution is still driven by the AutoSUT runner rather
  than by the Caldera atomic planner.
- It does not act as an online planner that invents final commands or chooses
  vulnerabilities dynamically during execution.

The recommended representative VM-backed paths are:

- `bash run_vm_backed_campaign.sh 0.c0011` for the smallest end-to-end baseline;
- `bash run_vm_backed_campaign.sh 0.shadowray` when you want the same flow plus
  an explicit step-conditioned SUT overlay before `T1190`.

Use the direct Python entry point only when you need an explicit provider
override.

To inspect current campaign-by-campaign status before choosing a run:

```bash
cat results/CORPUS_STATE.md
cat results/CAMPAIGN_SUT_FIDELITY_MATRIX.md
```

For the most honest VM-backed read, prefer campaigns that are both:

- marked `Pair Valid = yes` in `results/CAMPAIGN_SUT_FIDELITY_MATRIX.md`;
- green in the latest evidence summary.

Development-only acceleration exists, but it is not the reviewer default:

```bash
python3 scripts/run_all_lab_campaigns.py --campaign 0.c0011 --campaign 0.c0015 --provider qemu --reuse-lab
```

```bash
python3 scripts/run_lab_campaign.py --campaign 0.c0015 --assume-lab-running
```

Use those only when you intentionally want to reuse a compatible running lab.
Reviewer-facing claims remain grounded in cold-start execution per campaign.

Exploratory helpers such as `multi_vm_manager_2vm.py` remain available for
infrastructure debugging, but they are not the public-facing realism
contract.

## Current Expectations

- The smoke path is intended to be lightweight and reproducible.
- The published corpus is broader than strict pair validation, so use the
  matrix rather than filename presence alone when choosing a realism run.
- Live runs regenerate run-generated evidence under `release/evidence/`.
- The repository also regenerates `results/CVE_RESOLUTION_CANDIDATES.md` from
  measured ATT&CK outputs plus curated CVE rules so reviewers can inspect how
  many campaign-linked CVEs currently resolve to package- or product-bound SUT
  candidates.
- The repository also regenerates `results/COMPATIBILITY_RULE_SURFACE.md` so
  reviewers can inspect the exact keywords and regexes behind the deterministic
  CF/VMR/ID routing policy. These labels do not establish backend necessity.
- The compatibility-validation packet is intentionally submitted without manual
  labels; the evaluator reports `pending_manual_labels` until independent
  adjudication is added.
- The repository also regenerates `results/INFRA_AUTOMATION_COVERAGE.md` so
  reviewers can see the current IaC/SUT automation boundary without reverse
  engineering it from YAML profiles and shell scripts.
- The public repository ships synthesized reports and source artifacts that can
  be regenerated from this checkout; heavyweight local runtime traces are not
  part of the reviewer contract.
- A clean checkout may therefore expose representative VM-backed evidence for
  only a subset of campaigns. The matrix and corpus-state reports make that
  explicit instead of implying that every campaign already has a shipped cold-start trace.
- On macOS ARM64 with `qemu`, the first cold-start can take materially longer
  than subsequent runs because guest bootstrap, package installation, and
  Caldera setup happen inside the VM. This is expected and should not be
  confused with hidden manual setup.

## Troubleshooting

If Python imports fail:

```bash
export PYTHONPATH="$PWD/src:$PYTHONPATH"
```

If you want to verify that the local Caldera-compatible endpoint is responding:

```bash
export CALDERA_API_KEY="${CALDERA_API_KEY:-<set-local-key>}"
curl -s -H "KEY: ${CALDERA_API_KEY}" http://localhost:8888/api/v2/abilities | python3 -c "import json,sys; print(len(json.load(sys.stdin)))"
```

If the VM-backed path reports degraded state, use that output as an
infrastructure signal rather than assuming a campaign runner bug.
