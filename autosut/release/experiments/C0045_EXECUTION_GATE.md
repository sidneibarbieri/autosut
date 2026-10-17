# C0045 Bounded Experiment Gate

## Supported result

The artifact supports two distinct observations and does not conflate them:

1. **Deterministic planning ablation.** Under one vendored procedural plan,
   action catalog, and resolver policy, the raw-STIX arm admits 0/10 steps, a
   fixed non-campaign reference SUT admits 1/10, and the
   campaign-conditioned AutoSUT witness admits 10/10. Two vendored resolver
   repetitions have the same execution-semantic hash. These are verified
   resolver outputs, not execution records.
2. **Arm-C execution.** The ten-step AutoSUT witness was executed once in the
   disposable surrogate laboratory. All ten steps have evidence files, the
   campaign contract is valid, and teardown is recorded as clean.

Arms A and B were not executed. Consequently, this artifact does **not**
support a three-arm execution comparison. It also does not show historical
reconstruction, exploitation of a real Ray deployment, or full-fidelity APT
replay.

## Realization and fidelity boundary

The real Ray 2.6.3 preflight was attempted and failed. The declared
`real_then_surrogate` policy then selected the isolated surrogate. The
successful technique records are therefore uniformly `surrogate`: nine are
reported as adapted and the privilege-boundary assessment as inspired. The
independent rubric computes a more optimistic tier for that assessment; the
gate accepts this conservative downgrade but rejects any reported tier above
the rubric result.

The verified AutoSUT plan records six explicit assumptions across five steps.
They are counted in the report rather than hidden or interpreted as analyst
time.

## Subsequent paired replay

The later `release/evidence/2026-10-01-joint-e2e-r6/0.shadowray/` experiment
uses the current prepared-pair workflow. It provisions Ray 2.6.3 on the
digest-pinned Python 3.10 target, restarts the service after network
isolation, and checks the Jobs API again before executing the ten-step
contract. This is a separate experiment from the surrogate Arm-C result above.
Its receipt reports ten effect-backed steps, `real_cve` realization, observed
gateway blocking, and clean teardown. The adapted and inspired technique
labels still apply. Arms A and B remain unexecuted.

## Self-contained inputs

All STICKS-derived planning inputs and resolver outputs used by this
experiment are versioned under:

```text
release/inputs/sticks/c0045-v1/
```

Its `manifest.json` binds every file by byte-level SHA-256 and, where the
format provides one, by an internal semantic hash. The gate also verifies
plan-to-procedural-plan, plan-to-binding-catalog, and plan-to-action-catalog
hash links. No sibling checkout of STICKS is required.

## Reproduction

From the AutoSUT artifact root:

```sh
python3 scripts/run_arm_comparison.py
```

The command fails closed if an input, source link, execution manifest,
per-technique evidence file, fidelity record, assumption count, or output
report hash is inconsistent. It writes:

- `release/experiments/arm_comparison/C0045.json`
- `release/experiments/arm_comparison/C0045.csv`

To create new execution evidence rather than audit the released run, first
execute the campaign with Docker access and rebuild the validity table:

```sh
python3 scripts/run_orchestrated_campaign.py 0.shadowray
python3 scripts/summarize_execution_validity.py --campaign 0.shadowray
python3 scripts/run_arm_comparison.py
```

Any manuscript use must retain the surrogate, bounded, and single-executed-arm
qualifiers above.
