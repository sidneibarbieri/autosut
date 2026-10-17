# Execution Model

This document separates released reviewer paths from retained implementation
work. The capability ledger is authoritative whenever an implementation detail
and a claim appear to conflict.

## Released reviewer paths

The reviewer first runs the deterministic claim gate:

```bash
bash run_review_check.sh
```

The smallest live execution example is separate and Docker-gated:

```bash
bash artifact/setup.sh
bash artifact/run.sh
bash artifact/validate.sh
```

Those paths validate only their declared contracts. A missing optional backend
is reported as unavailable; it is not converted into a passing replay.

## Campaign and SUT contract

The execution path consumes a declared campaign, a declared SUT profile, and
explicit evidence predicates. A run records the declared sequence, observed
outcomes, fidelity labels, provenance, containment, and teardown state. It
does not infer historical attack order, invent a vulnerability, or promote a
later observation into success for a failed step.

Joint preparation first derives SUT constraints and a blueprint, then generates the binding
catalog consumed by the finite-domain compiler. The resulting executable contract is bound
to hashes of the procedural plan, catalog, planning certificate, and campaign specification.
Preparation never promotes execution status.

The preparation path also enumerates a bounded realization space before execution. It gives
procedure assignments priority over alternative topological orders, then independently checks
each graph against the exact SUT blueprint and binding catalog. This is a declared-compatibility
certificate, not an execution result. Technique-set discrimination, causal reconstruction,
campaign-SUT compatibility, and observed operational effects remain separate properties.

At runtime, the current C0045 slice has four independent gates: observable bindings and initial
facts, explicit pre-execution absence of the goal effect, the expected successful Caldera link on
the enrolled agent, and exact post-execution marker content observed directly in the SUT. Failure
at any gate makes the lifecycle `failed_clean` after teardown. A clean namespace alone cannot turn
a failed experiment into a successful one.

The current same-revision preparation and operational observations are frozen under
`release/experiments/paired_preparation/2026-09-05-r4/` and
`release/experiments/operational_qualification/2026-09-05-r6/`. These observations qualify the
bounded paths described in their README files, not complete campaign execution.

## Optional VM backend materials

The source tree retains provider-aware lab code, a direct QEMU diagnostic
helper, and architecture-specific Windows provisioning templates. They are not
reviewer recipes or released evidence:

- QEMU Linux ARM64 is `implemented` and requires boot qualification. No guest
  boot, procedure execution, independent observation, or teardown evidence is
  currently qualified.
- Native Windows x86_64 is `development_in_progress`. The ARM64 and x86_64
  answer-file templates are credential-free inputs to a future qualification;
  neither template proves that a guest booted or ran a procedure.
- A future backend claim must bind a campaign/SUT requirement, image hash,
  cold boot, evidence predicate, independent observation, and clean teardown.

The provider source is deliberately not registered as a completed backend until
that evidence exists. The status and promotion level are recorded in
`release/experiments/capability_ledger/capabilities.json`.

## RQ4, R4, and Step 2

RQ4 is the bounded constructive witness claim checked by the released ledger.
R4 is a separate lifecycle-interruption qualification protocol. Its v2 template
is `predeclared_nonexecuted`; therefore it cannot promote a reliability claim.
The public package excludes v1 historical observations so they cannot be
mistaken for current evidence.

Step 2 is also separate from execution. The semantic-enrichment protocol uses a
typed, provenance-bound proposal schema and refuses commands, credentials, and
free-text execution parameters. The release includes no completed provider
experiment and no qualified Step-2 claim. See
`docs/SEMANTIC_ENRICHMENT_PROTOCOL.md` for the exact boundary.
