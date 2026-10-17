# R4 semantic-boundary interruption protocol

## Status

This is a predeclared qualification template for a future frozen revision. It has not yet been
bound to a commit or executed. Its current aggregate state is `predeclared_nonexecuted` and its
qualification result is `not_qualified`; neither is a scientific claim.

The v1 observations remain preserved as development evidence. They measured interruption after
stage entry; they do not satisfy this protocol's semantic-boundary requirement and are not deleted
or retroactively called invalid.

## Question

For the isolated-Caldera Docker lifecycle, does an interruption after a named, observed runtime
condition leave the declared run namespace clean and a sealed, supervisor-bound evidence chain?

This protocol does not establish campaign fidelity, historical adversary equivalence, Windows or
QEMU behavior, multi-host behavior, or general recovery outside the declared topology.

## Eligibility

Each qualifying bundle must declare the protocol version and role `qualification`, originate from
the supervised canonical entrypoint, run on one immutable clean commit, and carry an independent
supervisor receipt linked to its child `run_id`, binding hash, and manifest hash. The template
cannot be passed directly to the driver. First create one non-overwritable frozen instance after
the source and template have both been committed and are clean. Direct and older bundles remain
auditable but are excluded from this particular protocol with a structured reason.

## Semantic boundaries

The driver waits for the `condition` in the predeclared JSON, not merely for a function to begin.
For example, `enrollment_poll_active` requires Sandcat to have started and a real Caldera agent
query to have returned without the expected agent. `operation_running` requires Caldera to report
the operation state as `running`. If a condition never occurs, the cell is recorded as
`boundary_not_observed`; the driver does not inject a synthetic interruption to fill the table.

Freeze an execution instance for the clean commit, then run one cell through that frozen instance:

```bash
REVISION="$(git rev-parse HEAD)"
python3 scripts/freeze_r4_protocol.py \
  --revision "$REVISION" \
  --output "release/experiments/frozen/r4-v2-${REVISION}.json"

python3 scripts/run_interruption_matrix.py \
  --stage enroll_agent --injection sigterm --cell-id R4V2-04 \
  --protocol "release/experiments/frozen/r4-v2-${REVISION}.json" \
  --label candidate-1

python3 scripts/aggregate_r4_interruption_matrix.py \
  --protocol "release/experiments/frozen/r4-v2-${REVISION}.json" \
  --revision "$REVISION"
```

The aggregate must account for every planned cell, every retry, every exclusion, and every
unsuccessful boundary. A frozen template with missing cells remains `qualification_in_progress`.
