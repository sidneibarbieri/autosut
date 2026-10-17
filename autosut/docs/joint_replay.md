# Prepared campaign and SUT replay

The operational path links a STICKS plan to an AutoSUT blueprint, a bound procedural contract, a materialized Docker target, and observed effects. It uses the deterministic compiler, reviewed template adapters, and evidence ledger. It makes no LLM calls. C0010, C0026, and C0045 have prepared executable pairs. Their adapted and inspired fidelity labels remain part of every outcome.

## Prepare

For CTI plans without author-written campaign specifications, add
`--derive-missing-specs --no-legacy-inventory` to the preparation command below.
The compiler derives source identities, preserves both source hashes, and checks
the platform requirements. It writes the derived specifications beside the pair
matrix. It does not invent causal facts or an execution contract: a Linux plan
without one remains blocked as `missing_execution_contract`. Unsupported
platform requirements are reported separately. Preparation executes no campaigns.

From the AutoSUT artifact root:

```sh
.venv/bin/python scripts/prepare_campaign_pairs.py \
  --sticks-root ../../sticks/artifact \
  --python ../../sticks/artifact/.venv/bin/python \
  --output runtime/my-prepared-pairs
```

Read `matrix.json`. On the frozen 55-plan corpus, it records three prepared pairs and 52 blocked
rows. A blocked row includes its reason, source-plan hash, and source step count when that plan
exists. `trusted_catalog_coverage` counts exact technique-ID matches for every source plan,
records the catalog hash, and lists uncovered IDs. Its covered-step count is a planning diagnostic,
not an execution or effect result. A researcher can point `--plans-root` and `--campaign-specs` at a different plan corpus
and specification directory. Add `--no-legacy-inventory` for a new corpus without the frozen
historical aliases. Preparation does not execute a campaign.
An external campaign can reach a verified plan and contract yet remain blocked by
`missing_reviewed_execution_adapter`. The live executor currently supports the three
reviewed pairs named above; a new source plan needs an independently reviewed effect
adapter before the CLI can call it executable.
The release includes frozen prepared bundles for `0.c0010`, `0.c0026`, and `0.shadowray` under `release/prepared-pairs/`, so a reviewer can replay those without running STICKS first.
The completed C0010, C0026, and C0045 ShadowRay receipts are under
`release/evidence/2026-10-01-joint-e2e-r6/`. An additional C0045 ShadowRay receipt
from the latest local reproduction is under
`release/evidence/2026-10-05-shadowray-replay-r2/`. These receipts are bound to
their own implementation revisions and must not be combined as if they were one
frozen run.

## Execute

```sh
.venv/bin/python scripts/run_prepared_campaign_pair.py \
  --pair release/prepared-pairs/0.shadowray \
  --evidence release/evidence/my-joint-replay/0.shadowray
```

The evidence directory must be new. The runner rejects changed input files and an installed campaign specification that differs from the prepared source. It materializes the blueprint host, scopes the prepared contract to the replay, and validates the resulting causal ledger. It exits with code 2 for an incomplete execution. Replace `0.shadowray` with `0.c0010` or `0.c0026` to replay either bounded campaign slice.

Before campaign execution, both containers move to a unique internal Docker network and detach from all other networks. The Colima provider and the local Linux Docker provider install a temporary IPv4 INPUT drop rule for that network's subnet. Linux requires a local Unix-socket Docker daemon and noninteractive `sudo` access to `iptables`; remote Docker endpoints are refused. Both containers must reach a controlled listener before the rule, fail to reach it after the rule, and increment its counters. The listener must remain live through the probe. `replay-network.json` and `gateway-isolation.json` record these checks. Package installation occurs before isolation. Other Docker providers fail closed until they have an equivalent tested guard. The certificate covers traffic from the replay subnet to the Docker host's IPv4 INPUT boundary. It does not certify every host or external network path.

The C0045 profile declares a Ray dashboard. Its blueprint selects the pinned Python 3.10 image because Ray 2.6.3's Jobs API fails under Python 3.11. After the network move, the real Ray service restarts on the new private address and submits two more preflight jobs before T1190. The injection and post-isolation logs have separate paths under `sut/`. A failed real-service attempt remains visible if the fallback surrogate runs. The released completed C0045 receipt records `real_cve` only; no surrogate was needed.

## Inspect

- `joint-replay-receipt.json`: input identity, effects, markers, causal violations, cleanup, and the execution verdict.
- `materialized-profile.json`: the profile derived from the blueprint.
- `campaign_state.json`: ordered transitions and missing requirements.
- `gateway-isolation.json`: positive and negative gateway probes and firewall counters.
- `manifest.json` and `techniques/`: execution modes, fidelity, and concrete effect checks.

`execution_complete` requires an effect-backed result for every step, observed gateway isolation, no causal violations, and clean teardown. It does not certify historical APT fidelity or every network path. Initial facts are declared preconditions. ShadowRay service injection uses reviewed campaign recipes. Expanding to arbitrary inputs requires verified service recipes, executable template adapters, and independently observed readiness for every required fact.

To check a saved replay without provisioning another host, run:

```sh
.venv/bin/python scripts/audit_prepared_pair_replay.py \
  --pair release/prepared-pairs/0.shadowray \
  --evidence release/evidence/2026-10-01-joint-e2e-r6/0.shadowray
```

The audit checks pair hashes, plan and contract identity, the causal ledger,
evidence-file presence, the counted gateway denial, and teardown. It reads the
recorded predicates; a fresh replay is still needed to reobserve their effects.

New replays emit a version-2 receipt with a unique run identity and the SHA-256
of `replay-evidence-manifest.json`. That separate manifest binds retained input,
observation, state, network and profile files. The receipt and the integrity
manifest are excluded from the file inventory to avoid circular hashes. The
receipt binds the integrity manifest; the manifest binds the run identity and
retained files. Keep both beside the original observations.

For a newly generated replay, add `--require-integrity` to the audit command.
It rejects missing bindings, changed bytes, unexpected files, symlinks and
disagreeing run identities. Historical version-1 receipts remain readable, but
their audit reports `integrity_verified: false`; strict mode rejects them rather
than retroactively granting a run-local seal. Package integrity remains a
separate check. Hashes preserve byte bindings, not historical fidelity or
authenticity against an attacker who can replace the entire trusted receipt.

For C0010 and C0026, a fixed laboratory HTTP service and synthetic fixture implement the reviewed templates. The visit checks a real HTTP request and controlled page bytes, without a browser exploit. Resolution checks the private network alias. Transfer checks the destination digest and server request. Collection, archive creation, and chunking check actual local files and reconstructed bytes. The infrastructure and capability steps write and independently hash local laboratory manifests and specifications. These are inspired representations of the corresponding external activities.

## Generate plans for the full corpus

```sh
.venv/bin/python scripts/generate_corpus_suts.py \
  --plans ../../sticks/artifact/release/plans/enterprise \
  --output release/my-corpus-suts
```

`manifest.json` accounts for every source plan and step. Each campaign receives a hashed constraint set. Campaigns whose platforms all have isolated backend recipes receive a complete SUT blueprint. The others receive a non-executable partial SUT plan when at least one selected platform has a recipe. These files do not claim that services were provisioned or techniques executed. A Windows QEMU implementation exists elsewhere in the artifact, but its current credential and image setup is not a release-ready automatic recipe. The generated result on the pinned 55-plan corpus is 13 complete blueprints and 42 partial plans.

Measure the remaining platform boundary without promoting plans to executions:

```sh
python3 scripts/audit_corpus_sut_readiness.py release/corpus-suts-20261001-enterprise-r3
```

The audit checks each constraint hash and its source-plan identity. On this corpus, Linux alone covers the declared platform requirements in 13 of 55 campaigns. Adding Windows as a hypothetical available platform would cover 47, leaving eight with other platform requirements. This is a counterfactual platform calculation, not a Windows qualification or a claim that 47 SUTs have been built. Only two current blueprints have no additional declared resource requirements. Forty-three campaigns declare non-platform resources whose provisioning has not been established by the corpus generator. Only three source campaigns have a declared execution contract. Its manifest records zero materializations and zero executions in this batch. Prepared joint replays are separate experiments with their own receipts.

## Effect checks for the ShadowRay adapter

The supported procedural templates are explicitly matched to reviewed executors. An alternative template without an adapter is rejected before provisioning. Python execution must return the expected result. The shell configuration must contain the declared hook and the shell must load it. Decoding must reproduce the source bytes. Credential collection must match a predeclared synthetic fixture. Transfer success requires equal source and destination hashes. The compute workload has a two-second timeout and reports operation count, CPU time, and elapsed time for validation. Privilege assessment remains an inspired boundary check; it performs no privilege escalation.

These checks are executed by the observation path, separately from submission through the compromised API. A process exit code or a nonempty output file alone is insufficient for those effects.

## Reuse with an external experiment identity

Prepared replay can reuse the complete reviewed bounded procedures for C0010 and C0026
under a new experiment identifier. Admission matches the ordered technique/template pairs,
then validates every binding, evidence predicate and fidelity ceiling. Renaming a campaign
does not admit new operations, partial procedures, arbitrary commands or a higher fidelity.
The source campaign identity and hashes remain recorded separately from the experiment ID.

Provide procedural plans and campaign specifications, then prepare them without historical
alias discovery:

```sh
.venv/bin/python scripts/prepare_campaign_pairs.py \
  --sticks-root /path/to/sticks-artifact \
  --plans-root /path/to/experiment/plans \
  --campaign-specs /path/to/experiment/specs \
  --no-legacy-inventory --output /path/to/new/prepared-pairs
```

Each specification filename must match its `campaign_id`. Its `source_campaign_id` must
match the supplied procedural plan. Replay reads the hash-verified specification from the
prepared bundle, so an external experiment does not require modifying the installed campaign
catalog. The reusable procedure selects its reviewed attacker recipe, while the SUT profile
comes from the synthesized blueprint. ShadowRay remains tied to its reviewed campaign recipe.

Inspect `pair.json` before execution: `prepared` is admission, not an execution result.
Execute the resulting bundle using the runner above, then audit the recorded result.
This feature establishes reuse of reviewed procedures; it does not establish execution
coverage for additional historical campaigns.
