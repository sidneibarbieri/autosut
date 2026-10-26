# AutoSUT Reproducibility Artifact

AutoSUT is a reproducibility package for controlled ATT&CK-aligned campaign execution
and for measuring the environment semantics gap in structured CTI.
The repository contains:

- campaign definitions,
- SUT profiles,
- executor implementations,
- lab provisioning helpers,
- evidence and table-generation scripts.

This repository has two released validation layers and two retained execution
or implementation layers:

- a study-claim validation path in `run_review_check.sh`;
- a repository-local minimal working example in `artifact/` and
  `scripts/run_campaign.py`;
- an orchestrated campaign replay path in
  `scripts/run_all_orchestrated_campaigns.py`;
- retained provider-aware VM backend materials in `run_vm_backed_campaign.sh`
  and `scripts/run_lab_campaign.py`. They are implementation and future
  qualification material, not a released evidence path.

The fastest top-level validation path is
`bash run_review_check.sh`. The `artifact/` wrappers remain the smallest
repository-local execution example.

## Optional model-assisted planning

Procedure proposal generation can use an external provider. To use your own OpenAI key, copy the
example configuration and export the variable it names:

```bash
export OPENAI_API_KEY=sk-...            # your key; never commit it
```

`config.openai.example.json` carries only the environment-variable name, never a key. Its request,
prompt-token, completion-token, and estimated-cost limits are reserved conservatively before each
provider call; token prices are reviewer-supplied estimates, not billing records. The measurement
and claim-validation paths need no key. A model proposal is planning input only: it is checked for
declared-resource compatibility, never executed solely because the model emitted it, and never used
as its own evidence of technique effect. See `docs/architecture/PROPOSAL_ADMISSION_BOUNDARY.md`.

## See what a campaign needs, on a campaign you choose

```bash
python3 scripts/emulate.py release/inputs/sticks/c0045-v1/C0045.procedural-plan.json
```

Takes a procedural plan, the typed form of a campaign, and prints what the procedure requires from a
System Under Test, which of those requirements a laboratory can materialize today, and which
techniques are left uncovered. A Linux campaign resolves end to end; a campaign that needs Windows
for credential dumping or remote services reports those techniques as uncovered rather than
pretending the environment exists. That per-technique statement is the environment semantics gap
applied to one campaign.

For a corpus blueprint that needs no additional service or data resource, probe a real isolated
Linux base host and obtain a teardown receipt:

```bash
python3 scripts/probe_corpus_base_host.py \
  --corpus release/corpus-suts-20261001-enterprise-r3 \
  --campaign C0050 \
  --output /tmp/autosut-C0050-base-host.json
```

The probe checks the manifest and content hashes, boots the reviewed image with no network route,
observes the guest platform, and verifies removal. It rejects blueprints with resources it cannot
provision. This proves base-host materialization, not campaign execution or technique effect.

For campaigns with supported network and local resources, run the private laboratory witness:

```bash
python3 scripts/probe_corpus_network_resources.py \
  --corpus release/corpus-suts-20261001-enterprise-r3 \
  --campaign C0035 \
  --output /tmp/autosut-C0035-ingress.json
```

The witness starts an actor and target on an internal Docker network. It checks each declared
resource through a fixed synthetic operation and separate observation, verifies host-gateway
denial, and removes the lab. C0010's ingress and private HTTP target are both covered at this
resource level. A resource witness is not an executed campaign.

To reproduce and audit all 13 Linux blueprints with one command:

```bash
python3 scripts/run_corpus_resource_qualification.py \
  --output /tmp/autosut-corpus-resources
```

The command provisions only reviewed synthetic resource types, saves one receipt per campaign,
and checks every receipt against its blueprint and the retained observations. The final report is
`/tmp/autosut-corpus-resources/audit.json`. It reports two isolated base hosts and eleven
resource witnesses. The remaining 42 corpus plans require other platforms. This qualification
does not execute campaign procedures or establish product fidelity. A curated 13-run example is
under `release/experiments/corpus_resource_witnesses/2026-10-03-r1/` and is included in the
staged artifact.
The standard `bash run_review_check.sh` also audits those curated receipts offline,
including source hashes, resource observations, gateway blocking, and teardown.
It does not provision hosts or execute campaign steps.

## See the result first

```bash
python3 scripts/demo.py
```

Runs in under a second with no dependencies, no network, and no lab. It prints the measured
evidence gradient: public intelligence names the platform for nearly every technique and states
what that platform must provide for almost none of them. It also separates routing coverage, which
reads as complete, from the evidence behind it. The values are read from the generated manuscript
macros, so this demonstration and the paper report the same numbers.

## Joint campaign--SUT preparation and operational qualification

The joint path is deliberately split into preparation and execution. Preparation compiles an
upstream CTI procedural plan against an AutoSUT-derived blueprint and binding catalog. Its output status
`prepared` means that the causal contract is complete; it does not mean that the campaign ran.
With adjacent procedural-plan and AutoSUT artifact checkouts, run:

```bash
.venv/bin/python scripts/prepare_campaign_pairs.py \
  --sticks-root ../../sticks/artifact \
  --output runtime/pair-preparation-review
```

Use `--plans-root /path/to/plans` and `--campaign-specs /path/to/specifications`
to supply new procedural plans and campaign specifications.
Each JSON filename must match its `campaign_id`, and each new specification must
declare a `source_campaign_id` present in the procedural-plan corpus. Admission still
requires a complete platform blueprint, procedural contract, and reviewed adapter.

The matrix accounts for all 55 frozen CTI campaign plans and the eight legacy
campaign identifiers. It preserves each plan's source hash and step count, even
when no campaign specification exists. The deterministic path prepares C0010,
C0026, and C0045. Other rows state whether a campaign specification, platform
backend, or execution contract is missing. These are preparation diagnostics,
not evidence of 55 executable campaigns. No model or API key is required.

For each prepared pair, the same command now emits `realization-space.json`,
`joint-realization-certificate.json`, and `realization-compiler-receipt.json`. The space may
contain multiple admitted causal orders or procedure assignments. The joint certificate
independently replays causal reachability and validates every binding against the synthesized
blueprint while retaining `operational_status: not_run`. See
`docs/JOINT_REALIZATION_CERTIFICATE.md`.

The earlier supervised Caldera qualification is narrower. It executes the C0045 T1190 surrogate slice
and a synthetic multi-host fact-chain infrastructure scenario. Each cell owns a fresh Caldera,
fresh Sandcat agents, SUT resources, and network resources; cells run serially and the next cell is
refused unless teardown is observed as clean. The single-host cell requires the goal effect to be
absent before dispatch, a successful expected Caldera link, and the exact run-specific marker after
dispatch. The multi-host scenario is infrastructure evidence, not an APT reconstruction or proof
of lateral movement.

```bash
.venv/bin/python scripts/build_current_operational_protocol.py \
  runtime/operational-review/protocol.json --seeds 1
.venv/bin/python scripts/collect_operational_ledger.py \
  runtime/operational-review/protocol.json \
  runtime/operational-review/ledger.json
```

The released same-revision observations are indexed in
`release/experiments/paired_preparation/2026-09-05-r4/matrix.json` and
`release/experiments/operational_qualification/2026-09-05-r6/ledger.json`. Their adjacent README
files state the exact scope and non-claims. The operational collection uses one seed for functional
qualification and is not a success-rate estimate.

`CALDERA-DISPATCH-01` is derived only from the sealed `r6` collection. Its static gate checks the
collection manifest, protocol and ledger binding, qualified supervision receipt, clean teardown,
finished operation, and independent effect probe. It validates recorded evidence without launching
an environment and remains a `supported_bounded` one-cell surrogate result.

Those Caldera cells alone do not support a campaign-wide execution claim. The separate prepared-pair
replay executes the complete declared controlled slices for C0010 (9 steps), C0026 (6 steps),
and C0045 (10 steps). Earlier receipts are under `release/evidence/2026-10-01-joint-e2e-r6/`.
Sealed receipts for all three slices are under `release/evidence/2026-10-25-c0010-strict-r1/`,
`release/evidence/2026-10-25-c0026-strict-r1/`,
`release/evidence/2026-10-25-shadowray-strict-r0/`, and
`release/evidence/2026-10-25-shadowray-strict-r1/`. The latter two are separate ShadowRay
executions under the same frozen contract. Each includes the prepared inputs, observed
effect records, a file inventory, and a digest bound to its receipt. Audit one without starting
Docker using `python3 scripts/audit_prepared_pair_replay.py --pair release/prepared-pairs/0.c0010
--evidence release/evidence/2026-10-25-c0010-strict-r1 --require-integrity`; substitute the
matching pair and evidence directory for the other two slices.
C0045 uses the actual Ray 2.6.3 Jobs API on a pinned Python 3.10 image. The receipt reports
effect-backed completion, the real-CVE realization, gateway isolation, and clean teardown.
These bounded executions do not reconstruct the historical campaigns. Five of the eight legacy
pairs remain blocked, and the 55-plan upstream corpus has 13 complete SUT blueprints but no
claim of complete campaign execution. See `docs/joint_replay.md` for commands and limits.
To inspect a completed pair without starting Docker, run
`python3 scripts/audit_prepared_pair_replay.py --pair release/prepared-pairs/0.shadowray --evidence release/evidence/2026-10-01-joint-e2e-r6/0.shadowray`.

### Bounded operation qualification

Some Linux-compatible plans contain source techniques for which the full
historical operation cannot be reproduced safely or faithfully. The qualification
runner exercises a declared bounded sequence in a disposable networkless
container and records independent observers. For the C0050 supply-chain slice:

```bash
.venv/bin/python scripts/qualify_linux_supply_chain.py \
  --plan ../../sticks/artifact/release/plans/enterprise/C0050.procedural-plan.json \
  --evidence /tmp/autosut-C0050-supply-chain
```

The command qualifies four controlled operations and rejects an altered signed
fixture. Its receipt explicitly sets `campaign_execution_certified` to `false`.
It does not create a reviewed campaign adapter, reconstruct the historical
campaign, or change corpus coverage. Those claims require templates, a complete
execution contract, and the normal prepared-pair replay gate.
That check verifies the recorded identity, evidence paths, causal ledger, gateway observation,
and teardown. A fresh live replay remains a separate step.

For an evaluator-style report rather than a collection of separate commands,
run the published reviewer workflow:

```bash
bash scripts/run_reviewer_workflow.sh --mode kick-the-tires
bash scripts/run_reviewer_workflow.sh --mode full-reproduction
```

The first command is host-safe: it checks the public documentation, host
preflight, claim-to-evidence ledger, and public surface. The second additionally
executes the released claim gate. Both write
`results/reviewer_runtime/review-report.json`, which
distinguishes a failed artifact contract from a backend that is unavailable on
the evaluator's host. A live Docker or VM replay remains an explicit,
host-dependent follow-on protocol; it is never silently counted as reproduced.
The wrapper creates or reuses the exact reviewer environment before importing
the workflow's typed report models.

Before a backend-specific attempt, require that backend explicitly and retain
the live host report outside frozen evidence:

```bash
python3 scripts/preflight.py --require-backend windows_x86_64 \
  --output /path/to/new-run/host-preflight.json
```

Supported selectors are `docker`, `qemu_linux_arm64`, and `windows_x86_64`.
A blocked requested backend exits 1 even if another backend is available.
Without a selector, exit 0 means at least one backend is available for an
attempt. Neither form establishes guest boot, campaign effects or Windows
qualification. The separate development Windows ARM64 runner is not enumerated
by this generic host probe.

The R4 lifecycle-interruption protocol is distinct from the RQ4 constructive
witness claim. It is deliberately narrower than the study claim gate. The
current qualification template is
[`release/experiments/R4_INTERRUPTION_MATRIX_PROTOCOL_V2.md`](release/experiments/R4_INTERRUPTION_MATRIX_PROTOCOL_V2.md).
It is predeclared but not executed (`predeclared_nonexecuted`); it must first
be bound to one clean source revision. The source workspace retains v1
observations as historical development material, but the public package excludes
them. A passing raw cell is an auditable operational observation, not evidence
that AutoSUT has solved reliability in general.

The static evidence dashboard is `release/dashboard/index.html`. After a ZIP
download or clone, the lowest-friction local view is:

```bash
python3 -m http.server 8765 --bind 127.0.0.1
```

Run the command from the artifact root so linked evidence remains reachable.
Then open `http://127.0.0.1:8765/release/dashboard/` in a browser. Opening `index.html` directly
also works after extraction. The dashboard is designed as the reviewer-first
visual map of claims, the canonical claim ledger, bounded witness records, and raw CSV/JSON
anchors.

![AutoSUT evidence dashboard: the reviewer path, the environment non-uniqueness
proof, and the corpus-supported versus analyst-authored provenance surface](release/dashboard/dashboard-preview.png)

The public repository scope intended for GitHub publication and artifact
distribution is defined in `PUBLIC_REPOSITORY_SCOPE.md`.

The repository also ships a deterministic downstream report,
`results/CVE_RESOLUTION_CANDIDATES.md`, that asks a narrower question than the
main study itself: when a published campaign already carries CVE evidence, which
pairs can currently be turned into candidate SUT targets with explicit package
or product bindings? This report is an artifact extension, not a broader study
claim. It is also not an exhaustive crawl of the `apt` or `pip` ecosystems:
it only resolves the ATT&CK-linked campaign/CVE slice already present in the
artifact through curated, source-backed rules. In the current public artifact,
the automatic path is one `pip` case (`ShadowRay / CVE-2023-48022 -> ray`) and
zero automatic `apt` cases.

It also ships `results/INFRA_AUTOMATION_COVERAGE.md`, which makes the current
IaC/SUT automation boundary explicit per campaign/SUT pair: runtime VM set,
target-host topology, automatically applied base weaknesses, declared step
overlays, and the exact pair covered by the bounded dispatch witness.

It also ships `results/COMPATIBILITY_RULE_SURFACE.md`, which exposes the exact
deterministic keywords and regexes behind the CF/VMR/ID compatibility rules
used as routing-policy labels by the measurement pipeline. These labels are
heuristic policy outputs; they are not observations of a technique's minimum
backend requirement and they do not have a validated accuracy estimate.

It also ships `measurement/sut/scripts/results/audit/compatibility_validation_sample.csv`,
a 36-row stratified adjudication packet for the CF/VMR/ID routing policy. The manual
label columns are intentionally blank in the submitted artifact; after an
independent reviewer fills `manual_expected_class`, `manual_verdict_match`,
`manual_notes`, and `reviewer`, rerun
`python3 measurement/sut/scripts/evaluate_compatibility_validation.py` to
regenerate the agreement summary, confusion table, disagreements file, and
Cohen's kappa. Until those labels are added, the packet is a construct-audit
surface rather than a completed inter-rater agreement result. The released
summary uses `null`, not a fabricated zero, for agreement statistics with no
observations. Pipeline regeneration preserves completed manual fields by STIX
technique ID instead of silently erasing adjudication work.

The current published subset is still conservative: the shipped campaign/SUT
pairs currently use single target-host examples, even though the IaC path is
designed to lift multi-host topologies when a declared SUT profile requires
them.

## Execution Paths at a Glance

| Path | Command | Required tools | Recommended host | Typical role |
| --- | --- | --- | --- | --- |
| Fast study-claim validation | `bash run_review_check.sh` | Python 3.10+ | commodity laptop/desktop | revalidate released values and synthesized outputs |
| Docker smoke replay | `bash artifact/setup.sh && bash artifact/run.sh && bash artifact/validate.sh` | Python 3.10+, `venv`, `docker` | Docker-capable host | smallest live campaign/SUT execution trace |
| Orchestrated campaign replay | `python3 scripts/run_all_orchestrated_campaigns.py --preflight-only` then `python3 scripts/run_all_orchestrated_campaigns.py --isolate-campaigns --campaign-timeout-seconds 1200` | Python 3.10+, `docker` | Docker-capable host | sequentially replay all implemented campaign/SUT pairs and write TSV/JSON status reports |
| VM backend materials | inspect source and capability ledger | Python 3.10+, `vagrant`, `qemu` or `libvirt` | 8 CPU cores, 16 GB RAM, 25 GB free disk recommended | implementation and future qualification material; not a released claim gate |

The first path is the fast, host-only validation contract. The Docker smoke
path runs two compact, complementary campaign/SUT slices: one infrastructure
replay and one state-contract replay. The orchestrated Docker path replays all
implemented pairs. The VM source is intentionally outside this reviewer path:
QEMU is implemented but requires boot qualification, and native Windows is an
unqualified development track. A local VM attempt cannot promote either result
to a released claim.
These paths do not require API keys or cloud credits. On a cold Docker host,
the smoke and full-replay paths download public container images and packages.

## Fast Validation

```bash
bash run_review_check.sh
```

This path reruns the measurement pipeline, refreshes the released study-facing
outputs, and checks that the synthesized values remain internally consistent.
The wrapper creates and reuses a repo-local `.venv`, enforcing the exact
dependency versions in `requirements-reviewer.txt`. On a cold machine, that
first bootstrap downloads those packages. Optional lint, type-checking, and
coverage tools are isolated in `requirements-dev.txt`. Documentation tools are
in `requirements-docs.txt` and require Python 3.12 or later.

It is the recommended first step for anyone who wants to confirm the study
claims without provisioning VMs.

Ledger claim identifiers are stable and predate the manuscript's grouping into three questions: ledger RQ1 and RQ3 support manuscript RQ1, ledger RQ2 supports RQ2, and ledger RQ4 with the C0045 study supports RQ3.

The authoritative claim boundary is
[`release/CLAIM_EVIDENCE_TRACEABILITY.md`](release/CLAIM_EVIDENCE_TRACEABILITY.md)
(machine-readable form:
[`release/claim_evidence_traceability.json`](release/claim_evidence_traceability.json)).
The gate regenerates this ledger and fails if any required RQ1--RQ4 or bounded
C0045 claim lacks its declared evidence. The ledger also lists interpretations
that the artifact does not support.

The released package runs standalone and does not discover or modify a nearby
manuscript tree. Maintainers can add the manuscript consistency checks by
passing its path explicitly:

```bash
PAPER_DIR=/path/to/paper bash run_review_check.sh
```

That integrated mode validates `results/values.tex`, static tables,
bibliography policy, generated-macro coverage, and a PDF build without writing
to the paper directory. Generated TikZ templates always remain under
`measurement/sut/scripts/results/rendered_figures/`. To deliberately replace
the paper's generated macro file and generated figure templates, use the
separate mutation opt-in:

```bash
PAPER_DIR=/path/to/paper SYNC_MANUSCRIPT_VALUES=1 bash run_review_check.sh
```

The opt-in does not copy the artifact's analyst-authored provenance macros;
those values are outside the manuscript's current measured-claim contract.

## Docker Smoke Replay

```bash
bash artifact/setup.sh
bash artifact/run.sh
bash artifact/validate.sh
```

`artifact/setup.sh` prepares the repo-local `.venv`; the subsequent wrappers
reuse that interpreter automatically and do not require manual activation.
The replay requires a reachable Docker daemon and may pull/build its public
target and attacker images on first use. `artifact/run.sh` performs this
preflight and prints the Docker failure directly instead of hiding it in a
Python subprocess exception.

Equivalent direct commands:

```bash
.venv/bin/python3 scripts/run_orchestrated_campaign.py 0.c0017
.venv/bin/python3 scripts/run_orchestrated_campaign.py 0.shadowray --fidelity surrogate
```

The host-only claim gate regenerates the pinned study-facing tables. The live
replay deliberately leaves those manifest-listed outputs unchanged.

To list campaigns:

```bash
.venv/bin/python3 scripts/run_orchestrated_campaign.py --list
```

The state-contract slice can be reproduced with the deterministic surrogate
profile (the result is labelled `surrogate`, never as the upstream product):

```bash
source scripts/python_env.sh
PYTHON_BIN="$(autosut_resolve_python "$PWD" "$PWD/requirements-reviewer.txt")"
"$PYTHON_BIN" scripts/run_orchestrated_campaign.py 0.shadowray --fidelity surrogate
"$PYTHON_BIN" scripts/validate_semantic_slice.py
```

The released ledger and campaign metadata define the contract that this path
checks. Historical source-level explanations are not part of the public
reviewer surface.

This path is the smallest end-to-end execution example in the public checkout.
It should be preferred over the VM-backed path when the goal is simply to
confirm that the repository runs and emits structured evidence correctly.

## Full Orchestrated Campaign Replay

Use the preflight first. It checks Docker and the Caldera C2 dependency before
starting a long replay, so an infrastructure problem is reported before it
creates misleading campaign failures.

```bash
python3 scripts/run_all_orchestrated_campaigns.py --preflight-only
```

Run one campaign when debugging:

```bash
python3 scripts/run_all_orchestrated_campaigns.py --campaign 0.c0013
```

Run the full implemented campaign suite:

```bash
python3 scripts/run_all_orchestrated_campaigns.py --isolate-campaigns --campaign-timeout-seconds 1200
```

`--isolate-campaigns` is the recommended reviewer mode for the full suite: it
removes AutoSUT containers, networks, and volumes before and after every campaign,
including the AutoSUT Caldera container. The `autosut-` prefix is reserved for
this workspace; unrelated resources must not use it. On Apple Silicon, Caldera-backed SUTs are
pinned to `linux/amd64` so the prebuilt sandcat payload is used instead of a
fragile just-in-time ARM build.

The legacy cleanup option covers stale AutoSUT containers, networks, and volumes
while retaining the persistent development Caldera:

```bash
python3 scripts/run_all_orchestrated_campaigns.py --clean-stale-autosut-containers --preflight-only
```

The runner writes `release/orchestrated_replay_<timestamp>.tsv` and a matching
JSON report after each campaign. Fresh replay evidence is moved under
`release/evidence/_reviewer_runs/` by default, so reviewers can run the full
suite and then rerun `bash run_review_check.sh` without changing the released
claim ledger or its ledger-linked evidence. The public artifact never promotes
reviewer-generated records into the canonical ledger; retain them only for local
diagnosis when a host, Docker, or Caldera issue interrupts the batch. By default,
known slow campaigns run last so the reviewer gets early feedback from faster
campaigns; use `--catalog-order` to preserve catalog order.

Replay classification is evidence-based. `PASS` requires every declared step
to complete through a mechanistic execution mode with an evidence reference,
the run-level teardown check to pass, and no campaign container to remain in
the AutoSUT namespace. A run with at least one evidence-backed step and at
least one conceptual marker is `PARTIAL`, even when every step records
`status=success`. The report retains the raw status count for diagnosis and
reports evidence-backed, marker-only, and Caldera-dispatched counts separately.
Reports created by older versions of this runner used raw status alone and
must not be interpreted as full execution evidence.

## Canonical Entry Points

- `run_review_check.sh`: top-level study-claim validation path
- `run_vm_backed_campaign.sh`: retained VM qualification wrapper
- `artifact/setup.sh`: environment and dependency check
- `artifact/run.sh`: bounded compact replay of the infrastructure and state-contract slices
- `artifact/validate.sh`: output validation for the smoke path
- `artifact/teardown.sh`: cleanup helper
- `scripts/run_all_orchestrated_campaigns.py`: Docker-backed full campaign replay with preflight and TSV/JSON reports
- `scripts/run_orchestrated_campaign.py`: campaign execution
- `scripts/run_lab_campaign.py`: retained provider-aware VM implementation
- `scripts/generate_tables.py`: LaTeX table generation
- `scripts/up_lab.sh`: provider-aware lab provisioning and SUT application
- `scripts/destroy_lab.sh`: provider-aware lab teardown

## Validated Contracts and Boundaries

- `bash run_review_check.sh` revalidates the released study-facing outputs from
  a clean checkout.
- The released reports include a deterministic campaign/CVE concretization view
  in `results/CVE_RESOLUTION_CANDIDATES.md` and
  `results/cve_resolution_candidates.json`.
- The released reports include an infrastructure/SUT automation coverage view
  in `results/INFRA_AUTOMATION_COVERAGE.md` and
  `results/infra_automation_coverage.json`.
- The released reports include a compatibility-rule audit surface in
  `results/COMPATIBILITY_RULE_SURFACE.md` and
  `results/compatibility_rule_surface.json`.
- Compatibility percentages with different denominators are separated in
  `measurement/sut/scripts/results/audit/compatibility_denominator_summary.csv`.
  In particular, 91.6% is explicit-only composition (207/226), while 32.7%,
  67.3%, and 100.0% are corpus-wide assignment coverage/share metrics.
- The compatibility-validation packet is regenerated and evaluated as
  `pending_manual_labels` unless an independent reviewer supplies manual labels.
- The repository can list available campaigns.
- The canonical runner can execute campaign definitions from both:
  - `data/campaigns/*.yml`
  - `campaigns/*.json`
- The baseline smoke path writes structured evidence under `release/evidence/`.
- Table generation works from the repository state and writes to `results/tables/`.
- ATT&CK technique/tactic metadata in the published JSON corpus is audited against
  `data/stix/enterprise-attack.json`.
- The VM source describes topology resolution, base SUT application, and
  step-specific SUT overlays. Those implementation paths need their own
  boot/execution/teardown qualification before they can support a claim.
- The published campaign/SUT pairs currently exercise single target-host
  topologies; multi-host support exists at the IaC layer and is reported
  explicitly in `results/INFRA_AUTOMATION_COVERAGE.md` rather than implied.
- Declared SUT profiles remain the source of truth for host count, topology,
  and automatically applied weaknesses; the runner does not invent new runtime
  topology or vulnerability state online.
- The bounded C0045-derived case and constructive RQ4 witnesses are admitted
  only when the ledger's executable gates pass. Their status is not inferred
  from the presence of JSON files.

## Known Limits

- The host-only review gate, `bash run_review_check.sh`, is the canonical
  study-claim validation contract. The Docker smoke path is the smallest live
  replay example; it is not a substitute for the claim ledger.
- VM-backed source is retained for inspection and future qualification. The
  current ledger does not report a boot-qualified QEMU backend or any qualified
  native Windows execution.
- Strict campaign/SUT pair validation is tracked separately from mere profile
  presence in `results/CORPUS_STATE.md`.
- Fidelity labels such as `faithful`, `adapted`, and `inspired` remain part of
  the execution contract; a green run does not imply historical or observational
  equivalence to the original intrusion.
- The artifact does not claim historical replay equivalence, automatic
  reconstruction for arbitrary campaigns, measured analyst-effort reduction,
  or a scalability/overhead result.
- Optional multi-VM utilities are useful for development, but they are not the
  only supported validation path.
- The QEMU source remains at `implemented` and requires boot qualification; it
  is not a public quick-start or a released execution result.
- Native Windows source includes architecture-specific credential-free templates
  and a renderer, not qualified guest execution.
- The released Docker path regenerates run evidence under `release/evidence/`.
  A local VM trace remains unqualified development state until a separate
  backend protocol admits it.
- The CVE concretization report is regenerated deterministically from
  measured ATT&CK outputs plus curated CVE rules; it does not synthesize
  exploits or infer target products online, and it should not be read as a
  complete measurement of the `apt` or `pip` package ecosystems.
- Public release/results reports are shipped in regenerated, reviewer-facing
  form from this checkout rather than as opaque local runtime traces.
- The public handoff does not ship a boot-qualified QEMU or native-Windows VM
  trace. Broader corpus and pair-validation coverage remain visible in the
  synthesized reports without treating implementation source as evidence.

## Validation Notes

- Start with `bash run_review_check.sh`.
- Use the `artifact/` path when you want the smallest repository-local
  execution example rather than the full study-facing validation path.
- Use `python3 scripts/run_campaign.py` to inspect the available campaign IDs in
  the current checkout.
- Use `python3 scripts/generate_corpus_state.py` to inspect the available campaign
  definitions, declared SUT profiles, strict pair-validation boundary, and the
  one bounded dispatch witness. It does not report execution success rates.
- Use `cat results/CVE_RESOLUTION_CANDIDATES.md` to inspect which
  campaign-linked CVEs currently resolve to an open-package or product-bound
  SUT candidate in the public artifact.
- Use `cat results/COMPATIBILITY_RULE_SURFACE.md` to inspect the exact
  deterministic keyword and regex surface behind the CF/VMR/ID rules.
- Use `cat results/INFRA_AUTOMATION_COVERAGE.md` to inspect the current
  automation boundary for VM topology, target-host count, base weaknesses, and
  step-conditioned overlays per campaign/SUT pair.
- Inspect the capability ledger and the Windows/Step-2 protocol documents
  before evaluating optional backend source. Do not treat a local VM helper
  invocation as a released reproduction path.

## Repository Hygiene

- `scripts/sanitize_repo.sh` performs dry-run sanitization by default.
- `scripts/check_public_surface.py` audits the public repository
  surface for stale content and publication blockers.
- `release/` contains synthesized outputs plus runtime-generated evidence when
  the included workflows are executed.

## Primary Files

- `src/loaders/campaign_loader.py`
- `src/runners/campaign_runner.py`
- `src/executors/executor_registry.py`
- `data/sut_profiles/`
- `campaigns/`
- `artifact/`
