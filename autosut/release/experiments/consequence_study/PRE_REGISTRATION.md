# Consequence study: does environment concretization change execution outcomes?

Pre-registered 2026-10-06, before any arm of this study was executed. The
population, the arms, and the outcome measures below are fixed here. Results
are recorded separately under `runs/<run-id>/` and are never edited back into
this file.

## Question

When structured CTI admits more than one SUT consistent with the evidence it
provides, does the choice among those SUTs change whether a campaign's
procedure executes and what it produces?

This is the downstream-consequence question the measurement study leaves open:
the corpus analysis shows the environment is underdetermined, and this study
tests whether that underdetermination has an observable execution effect.

## Experimental unit

One campaign whose structured CTI underdetermines a material environment
dimension, paired with at least two SUT concretizations that each satisfy the
same CTI-derived constraints and differ only in that free dimension.

## Population and selection

A campaign is eligible when, before any execution:

1. It has a vendored procedural plan and an executable contract.
2. Its CTI-derived constraints leave at least one material dimension free, so
   two concretizations can satisfy the same constraints while differing in it.
3. Both concretizations can be built in the disposable, networkless laboratory.

The first registered unit is **ShadowRay (C0045)**. Its structured CTI links
zero software objects (`linked_software_count: 0` in
`release/cve_resolution_candidates.json`), so the CTI does not name Ray, a
version, or the reachability of the Ray Jobs API. The external advisory for
CVE-2023-48022 supplies that software identity; it is not structured CTI. The
free dimension is therefore the service concretization itself.

## Arms

Both arms satisfy the identical set of CTI-derived constraints for C0045. They
differ only in the free service dimension the CTI does not resolve.

- **Arm RAY-REACHABLE.** A Ray concretization whose Jobs API is reachable
  without authentication, matching the advisory's named versions. This is the
  concretization the current prepared-pair workflow already produces.
- **Arm RAY-GUARDED.** A Ray concretization whose Jobs API requires
  authentication, an equally CTI-consistent choice because the CTI constrains
  neither the Ray version nor the API's auth posture.

Both run inside the same `--internal` (networkless) laboratory with the same
procedural plan, executable contract, action catalog, and resolver policy. A
recorded probe to an external address returns `SEALED` in each arm.

## Outcome measures

Recorded per step and per arm, reusing the prepared-pair receipt schema:

- environment build success (per arm)
- procedure start (the chain reaches its first step)
- per-step outcome: executed-with-evidence, or not
- overall procedure completion (all ten steps executed with evidence)
- failure stage: the step index and technique id where the chain first stops
- failure reason: the recorded cause at that step
- observable effects produced: the per-step evidence files each arm emits

Primary comparison: the executed-with-evidence step count of RAY-REACHABLE
minus that of RAY-GUARDED, and the step at which RAY-GUARDED first stops.

## Hypothesis

The two arms, equally consistent with the structured CTI, will produce
materially different execution outcomes: RAY-REACHABLE completes the chain,
while RAY-GUARDED stops at the T1190 step (the step that depends on the Jobs
API being reachable) and cannot start the downstream job-submitted steps.
Confirming this shows that the concretization choice, which the CTI does not
resolve, determines executability. A null result (both arms behave the same)
is also reportable and would weaken the consequence claim.

## What this study does not claim

It is not a historical reconstruction of the ShadowRay incident, not an
exploit of a production Ray deployment, and not a detection-effectiveness
result. It is a controlled laboratory measurement of whether a free
concretization dimension changes execution outcomes. Each arm runs on a
disposable surrogate with dropped capabilities and no external network.

## Analysis plan

For each arm, report the outcome vector above. Report the primary comparison
as a step-count delta and the failure stage of RAY-GUARDED. Repeat each arm
twice; report the execution-semantic hash of each repetition and whether the
two repetitions agree. No outcome is interpreted beyond the registered
measures.
