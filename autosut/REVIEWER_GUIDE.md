# Reviewer Guide

This guide keeps the validation path short and explicit.

## Current Automation Boundary

`scripts/prepare_campaign_pairs.py` is the joint STICKS--AutoSUT preparation entrypoint. It emits
one immutable directory per prepared campaign and a matrix that distinguishes `prepared` from
`blocked`. Every row starts with `execution_status=not_run`. The current command accounts for all
55 frozen upstream procedural plans and the eight legacy campaign identifiers. It prepares three pairs
(C0010, C0026, and C0045) and blocks the other 52 rows: 47 have no campaign specification,
four lack a supported platform, and one lacks an execution contract. The eight-case record under
`release/experiments/paired_preparation/2026-09-05-r4/` is an earlier, narrower snapshot.
Neither matrix is execution evidence. To generate a current matrix from adjacent artifact checkouts,
run the preparation command in `docs/joint_replay.md` and inspect its `matrix.json`.

The earlier supervised operational collector qualifies two cells: a C0045 T1190
surrogate slice and a synthetic multi-host Caldera fact-chain. It does not run the complete C0045
sequence or either complete C0010/C0026 sequence. A successful cell requires a finished expected
Caldera link, independent effect evidence, a sealed manifest, a natural supervisor completion, and
an empty run namespace. The multi-host cell does not claim real lateral movement.

The released same-revision records are
`release/experiments/paired_preparation/2026-09-05-r4/matrix.json` and
`release/experiments/operational_qualification/2026-09-05-r6/ledger.json`. Read the adjacent README
files before interpreting either collection. The operational protocol has one seed and qualifies a
bounded functional path; it does not estimate reliability or campaign-wide success.

The `CALDERA-DISPATCH-01` ledger row is bound to the sealed `r6` collection rather than a legacy
developer receipt. Its static audit verifies the collection manifest, protocol, ledger, qualified
supervision receipt, operation record, independent probe, and clean teardown. The result remains a
single-cell surrogate observation, not a live rerun or a campaign-wide execution claim.

The prepared-pair replay is a separate, later experiment. The current release contains
`release/prepared-pairs/` and same-revision receipts under
`release/evidence/2026-10-01-joint-e2e-r6/`. C0010, C0026, and C0045 execute all steps in their
declared controlled contracts with independent effect checks. C0045 provisions Ray 2.6.3 on a
pinned Python 3.10 image and uses its actual unauthenticated Jobs API. The gateway certificate
observes the Colima VM IPv4 INPUT boundary, and teardown must be clean. The five blocked legacy
pairs and 42 partial SUT plans remain explicitly outside this execution claim. Run the commands in
`docs/joint_replay.md` to reproduce the paired path. Its static audit command checks a saved replay
without starting Docker; the live command reobserves effects.

## Main Results and Claim Boundary

AutoSUT separates two forms of evidence that must not be conflated:

- RQ1--RQ3 measure the environment information present in pinned CTI snapshots
  and the behavior of explicitly declared enrichment, routing, and profile
  analyses.
- RQ4 is a bounded constructive result: three controlled witnesses admit more
  than one SUT realization while preserving the checked technique sequence and
  independent check. It is an existence result, not a prevalence estimate.
- The older Caldera C0045-derived cell is a controlled surrogate experiment. The
  later paired replay uses real Ray, while remaining an adapted controlled
  procedure rather than a historical reconstruction of a Ray deployment.

The authoritative status, evidence paths, scope, and non-claims are generated
in `release/CLAIM_EVIDENCE_TRACEABILITY.md` and
`release/claim_evidence_traceability.json`. `bash run_review_check.sh` fails if
one of the required claim-evidence gates is not supported.

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
| optional VM-backend materials | Python 3.10+, `vagrant`, `qemu` or `libvirt` | 8 CPU cores, 16 GB RAM, 25 GB free disk recommended | implementation/qualification material; not part of the released claim gate |

The released claim gate does not require or qualify a QEMU, libvirt, or Windows
guest. The provider-aware source remains available for inspection and future
qualification; backend status is reported by the capability ledger rather than
by a host-specific quick-start command.
No path requires API keys or paid model access. On a cold Docker host, the
smoke and full-replay paths download public container images and packages.

## Recommended Order

1. Run the evaluator report path below, then the fast study-claim validation path (Section 1).
2. Use the Findings → Evidence map (Section 2) to spot-check individual claims against the raw CSV outputs.
3. On a Docker-capable host, run the smoke replay (Section 3) for the smallest live execution trace.
4. If you want a full Docker-backed replay, run the orchestrated campaign suite (Section 5).
5. Inspect the optional VM-backend materials only when evaluating implementation
   scope; do not count an ad hoc host run as reproduction of a released claim.

## 0. Evaluator Report

The workflow below implements the two practical reviewer personas. It emits one
schema-validated JSON report with commands, durations, blocked host backends,
claim evidence anchors, and any failed contract. It does not turn a missing
optional Docker or VM backend into a passing live replay.

```bash
bash scripts/run_reviewer_workflow.sh --mode kick-the-tires
bash scripts/run_reviewer_workflow.sh --mode full-reproduction
```

The report is written to `results/reviewer_runtime/review-report.json` unless
`--output` selects another path. `kick-the-tires` is read-only with respect to experiment
execution. `full-reproduction` invokes the same `bash run_review_check.sh`
claim gate documented below. The Docker and VM paths remain separate because
their preflight requirements are real experimental conditions, not optional
shell details.
The wrapper creates or reuses the exact reviewer environment before executing
the typed Python workflow.

## 0.1 Lifecycle-interruption evidence

The R4 interruption protocol is distinct from RQ4. RQ4 is the bounded
constructive witness claim in the ledger; R4 asks whether a supervised lifecycle
interruption leaves its declared run namespace clean. The R4 work is
intentionally separate from the claim gate. Its current semantic-boundary
template and non-promotion rule are in
`release/experiments/R4_INTERRUPTION_MATRIX_PROTOCOL_V2.md`. It is currently
`predeclared_nonexecuted`: a clean commit must be bound before any cell can be
considered for qualification. The source workspace preserves v1 development
observations, but the public package intentionally excludes them: they are
historical observations, not released evidence and not a general reliability
claim.

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
`measurement/sut/scripts/results/audit/`. The generated macros are published
at `release/study_values.tex` and regenerated from
`measurement/sut/scripts/results/todo_values_latex.tex` by `run_review_check.sh`.

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

## 4. Direct Commands

If you prefer not to use the wrappers:

```bash
.venv/bin/python3 scripts/run_orchestrated_campaign.py 0.c0017
.venv/bin/python3 scripts/run_orchestrated_campaign.py 0.shadowray --fidelity surrogate
```

Study-facing tables are generated by `bash run_review_check.sh`, not by a live
reviewer replay.

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
the pair is covered by the single bounded dispatch witness.

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
python3 scripts/run_all_orchestrated_campaigns.py --isolate-campaigns --campaign-timeout-seconds 1200
```

The legacy cleanup option covers AutoSUT containers, networks, and volumes,
while retaining the persistent development Caldera:

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

`PASS` is deliberately strict: every step must be evidence-backed, the
run-level teardown check must pass, and the final AutoSUT namespace
must be empty in isolated mode. This includes containers, networks, volumes,
and the AutoSUT Caldera container. The `autosut-` prefix is reserved for this
workspace and must not be shared with unrelated resources.
Marker-only steps are reported separately and make a replay
`PARTIAL`; a catalog `ability_id` alone is not evidence that Caldera dispatched
the action.

The dashboard's `release/replay_evidence_audit.json` is a retrospective audit
of recorded counts and file references. File presence does not establish
technique fidelity or independent effects. This collection has no recorded
implementation revision and cannot qualify the current code. Its source trace
files remain local; the packaged audit contains observations and hashes only.

## 6. Optional VM Backend Materials

The package retains provider-aware VM source so that its implementation boundary
is inspectable. It is not part of the canonical reviewer path, and an ad hoc
host run cannot promote a released claim.

| Capability | Ledger status | Reviewer interpretation |
| --- | --- | --- |
| QEMU Linux ARM64 | `implemented`; requires boot qualification | The code and preflight exist, but no guest boot, execution, teardown, or independently reproducible evidence has qualified this backend. |
| Native Windows x86_64 | `development_in_progress` | The two architecture-specific unattended templates and renderer are inspectable; no native Windows boot, procedure execution, or teardown has qualified. |
| provider-aware Vagrant lab | retained implementation material | It may support a future, separately qualified backend experiment; it is not consumed by `run_review_check.sh`. |

For an exact status, read
`release/experiments/capability_ledger/capabilities.json`,
`docs/WINDOWS_PROVIDER_DEVELOPMENT.md`, and
`docs/NATIVE_WINDOWS_CORPUS_ADJUDICATION.md`. The semantic Step-2 boundary is
separate as well: `docs/SEMANTIC_ENRICHMENT_PROTOCOL.md` defines a typed,
provenance-bound proposal protocol, but the release contains no completed
provider experiment or qualified Step-2 claim.

The direct QEMU helper remains a source-level diagnostic for maintainers. It is
not a reviewer quick start because a local image, service configuration, or boot
attempt would be host-specific development state rather than released evidence.

## Current Expectations

- The smoke path is intended to be lightweight and reproducible.
- The available campaign definitions are broader than the strict pair-valid
  subset, so use `results/CORPUS_STATE.md` rather than filename presence alone
  when choosing a realism run.
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
- The package contains no boot-qualified QEMU result. Its current ledger level
  is `implemented`, with `requires_boot_qualification`; it is not a basis for a
  released execution claim.
- The Windows source is a development track. Its ARM64 and x86_64 templates are
  credential-free inputs to a future qualification protocol, not evidence that
  either guest booted or executed a procedure.

## Troubleshooting

If Python imports fail:

```bash
export PYTHONPATH="$PWD/src:$PYTHONPATH"
```

If an optional backend reports degraded state, record it as a host-specific
qualification outcome. Do not reinterpret it as a failure of the released
claim gate or as evidence for a broader execution claim.
