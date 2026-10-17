# Pre-execution scenario admission

`scripts/validate_scenario_observation.py` checks a compiled campaign against its
binding catalog and an independently collected pre-execution observation.

```sh
python scripts/validate_scenario_observation.py \
  --contract contract.json --catalog catalog.json \
  --observation observation.json --run-id run-1 --evidence-root evidence
```

The validator requires matching campaign/catalog identities and hashes, matching
run and contract identifiers, evidence files with matching hashes, and an observed
resource for every binding consumed by a transition. Binding kinds and values must
agree exactly. Credential bindings use secret references, not plaintext credentials.

Declared initial facts must have been observed. The frozen goal must not already
hold before execution. The compiled requires/produces chain must reach the goal
using declared initial facts and preceding effects.

This is an additive fact model. It does not model deletion, arbitrary loops or
concurrent conflicting effects. Admission establishes agreement of supplied
records; it does not establish historical fidelity or successful execution.

The observation DTO is defined in `src/planning/scenario_admission.py`.
`src/infrastructure/scenario_observer.py` runs command-backed probes and persists
their stdout, stderr, return code and arguments before constructing the DTO. Hash
validation cannot establish that a collector observed truthfully or that a
resource remains unchanged after probing.

The canonical single-host Caldera driver invokes admission after SUT
materialization and Sandcat enrollment and before creating an operation. It uses
`src/planning/scenario_slice.py` to derive and rehash the exact T1190 contract and
catalog slice from the current C0045 inputs. The driver observes the actor, target,
public endpoint, SUT readiness, actor readiness, HTTP reachability and live C2
process. A missing observation blocks operation creation and still enters the
normal teardown path.

This integration qualifies only the bounded T1190 slice. It does not establish
admission or successful execution of the other nine C0045 transitions, C0010 or
C0026. Those require corresponding materializers, probes, Caldera abilities and
independent effect checks. Runtime freshness beyond the interval between probing
and operation creation also remains an explicit limitation.

Unit tests use synthetic observations and are not campaign results. Operational
bundles persist `scenario/contract.json`, `scenario/binding-catalog.json`,
`scenario/probes.json` and `scenario/observation.json`. Preserve post-execution
effect verification and lifecycle qualification as separate requirements.
