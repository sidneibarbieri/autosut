# Prospective cross-campaign consequence protocol

Status: design only. No cross-campaign outcome has been collected under this
protocol. The existing C0045 study is a pilot and must not be counted as a
prospectively selected unit.

## Question and estimand

For a fixed campaign and a fixed procedure, can two laboratory SUTs that both
satisfy its structured-CTI constraints produce different execution outcomes
when they differ in one material, CTI-unresolved environment property?

The estimand is the fraction of eligible campaign units for which the
predeclared two-arm construction changes the executed-with-evidence step
count. It is conditional on this construction protocol and on the eligible
subset. It is not the prevalence among all possible SUT pairs or all attacks.

## Population and screening

Freeze the 55 campaign records in
`release/corpus-suts-20261001-enterprise-r3/manifest.json` by SHA-256 before
screening. Record one row per campaign, including its source ID, CTI-constraint
hash, plan status, eligibility decision, and a single exclusion reason.
Screen every record before running either arm. A campaign is eligible only if
it has a vendored procedure, an executable contract, a disposable networkless
laboratory target, and one material property that the structured CTI does not
fix. Two proposed SUTs must satisfy the same recorded CTI constraints. An
independent contract check must reject any pair that changes a constrained
property, the procedure, the action catalog, or the observation policy.

The 13 generated blueprints and 42 partial plans in this frozen corpus are
screening inputs, not executed units. The eight campaign-CVE pairs across five
CVE-positive campaigns yield only one current automatic package candidate.
Neither count is an observed consequence numerator or denominator.

`screening_report.json` is a deterministic inventory of the 55 source records
and the existing pair-preparation matrix. It records input hashes and leaves
prospective eligibility and exclusion reason unset. A prepared contract is
not a qualified pair or an execution outcome. The release gate checks this
inventory against its frozen inputs; the study's eligibility adjudication
remains separate.

## Pair construction and execution

For each eligible campaign, register the free property, both concrete values,
the reason each remains CTI-consistent, the expected affected step, and the
contract hashes before execution. Select no property after viewing outcomes.
Run the same chain twice per arm in a disposable networkless laboratory.
Preserve the configuration, source revision, images and digests, raw step
evidence, build and teardown results, semantic hashes, runtime, and all
failures under a unique run ID. Do not overwrite the C0045 pilot or another
run. An arm that fails to build remains in the ledger as a feasibility failure,
not a zero-effect observation.

The primary outcome is whether the executed-with-evidence step counts differ
between arms. Report both counts, the first differing step, effect evidence,
repeat agreement, and the absolute step-count delta. A status-success without
an observed effect is not executed-with-evidence. Any pair whose variants
violate the same-CTI contract is excluded before outcome analysis, with its
reason and raw receipt retained.

## Analysis and claim boundary

Report the full screening flow: 55 source campaigns, eligible units, built
pairs, executed pairs, pairs with repeat agreement, and pairs with a measured
effect. The primary denominator is the number of executed, contract-valid,
repeat-consistent campaign pairs. Report exclusions and feasibility failures
separately, so this conditional denominator cannot be mistaken for 55. Include
the observed fraction and a binomial interval, without treating repeated runs
of one campaign as independent samples. If fewer than ten independent
campaigns qualify, present a feasibility case series and do not claim an
estimated population prevalence. Report a conservative all-55 bound that
treats unexecuted campaigns as unknown, not as negative observations.

The current C0045 result establishes one controlled consequence only. It
neither supplies the missing denominator nor licenses a prevalence claim.
