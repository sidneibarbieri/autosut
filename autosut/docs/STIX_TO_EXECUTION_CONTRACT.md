# STIX-to-execution contract

AutoSUT consumes a versioned procedural plan produced from a STIX/ATT&CK
bundle. The plan is an operational reconstruction, not a claim that the
source bundle contains the historical order of an incident.

## What is compiled

Each plan step contains a technique identifier, source relationship IDs,
tactic and platform metadata, execution domain, and the state transition it
is expected to exercise. A procedural behavior is therefore an executable
transition:

```
(technique, campaign state, SUT state) -> bounded action + evidence predicate
```

This is narrower than a TTP. A TTP is a knowledge category; a procedural
behavior is one concretized action with preconditions, effects, and an
evidence predicate. An Attack Flow is already an explicit graph when supplied
by the source data. A campaign `uses` relationship alone is not such a graph,
so the compiler records the ordering policy and preserves the ambiguity.

## State and fidelity

The campaign ledger records the declared sequence, the executed sequence,
per-step status, fidelity, evidence paths, and the hash of the contract. The
runner rejects a run whose observed technique sequence differs from the
declared contract. A failed action remains failed; the runner does not infer
success from a later observation.

Fidelity is explicit:

- `adapted`: the action is exercised against a controlled implementation of
  the declared interface or vulnerability semantics;
- `inspired`: a bounded laboratory control represents the behavior, without
  claiming the original exploit or product was reproduced.

The released ShadowRay slice is reproducible with the `surrogate` fidelity
profile. The real-Ray profile is retained as an optional path and its result
is reported separately when the upstream dashboard accepts the request.

## Reproduction

```bash
source scripts/python_env.sh
PYTHON_BIN="$(autosut_resolve_python "$PWD" "$PWD/requirements-reviewer.txt")"
"$PYTHON_BIN" scripts/run_orchestrated_campaign.py 0.shadowray --fidelity surrogate
"$PYTHON_BIN" scripts/validate_semantic_slice.py
```

The command creates a fresh attacker/SUT pair, executes the ten-step contract,
writes one evidence log per step and emits `campaign_state.json`. The state
validator checks the contract hash, exact sequence, teardown status, and
evidence references. Campaigns are run sequentially because each campaign
requires a clean SUT; parallel execution would invalidate state isolation.
