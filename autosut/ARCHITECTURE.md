# Architecture

## Summary

AutoSUT exposes three reproducibility layers:

- a fast study-claim validation path in `run_review_check.sh`;
- a repository-local minimal working example based on the local runner and
  artifact wrappers;
- retained provider-aware VM backend materials for future substrate
  qualification and implementation inspection.

The fast validation path is the primary reproducibility target for study-facing
claims. The minimal working example is the smallest repository-local execution
trace. VM source is retained separately: it is not a released backend result,
and provider code alone cannot support a claim.

Detailed current-vs-target execution notes live in
`docs/architecture/EXECUTION_MODEL.md`.

## External Execution Handoff

`execution_handoff.v1` is a generic JSON boundary for an external procedural planner. The receiver
does not import producer code. It validates content integrity, the intended consumer identifier,
and the exact immutable consumer revision before any downstream lifecycle can use the record.
Accepting a handoff does not qualify a backend or count as execution evidence; lifecycle evidence
must still pass the existing revision-aware qualification policy.

## Admission-Gated Failure Recovery

`src/infrastructure/failure_recovery.py` defines the provider-neutral recovery state machine. An
execution adapter supplies hash-bound observations, a revision adapter may propose a replacement,
and a separate admission adapter decides whether that proposal is allowed to execute. The engine
uses a frozen revision budget, stops on unclassified failures or repeated revisions, and can write
every transition to an append-only hash chain before continuing. Model-generated text is therefore
an untrusted proposal, never an execution authorization.

`src/infrastructure/recovery_adapters.py` converts a provider's JSON object into a canonical neutral
proposal and admits only strict executable contracts that preserve frozen provenance, catalogs,
scope, causal reachability, exact template-specific binding schemas and value patterns, and evidence
predicates. It deliberately does not execute the admitted contract or bypass the canonical
supervisor.

This module establishes an auditable automation mechanism. It does not by itself establish a
measured recovery rate. Such a claim requires a preregistered campaign matrix, immutable revision,
complete terminal accounting, independently verified effects, and clean teardown evidence.

## Operational Evaluation Contract

`src/evaluation/operational_metrics.py` freezes denominator-complete multi-arm experiment matrices
and derives asset-based Success, Reliability, and TotalAcquisition together with time, model cost,
and human-intervention accounting. Missing and unsupported cells remain visible. An acquisition
counts only with an independently verified effect, a qualified lifecycle, and clean teardown.

The module is evaluation infrastructure, not a measured campaign result. Operational observations
enter through `scripts/validate_operational_ledger.py` only after their evidence paths and hashes
are bound to the frozen matrix.

## Layer 1: Host-Only Study-Claim Validation

The canonical path is:

```bash
bash run_review_check.sh
```

This layer creates or reuses the pinned reviewer environment, regenerates the
study-facing outputs, and checks the canonical claim ledger. It does not launch
Docker or VM infrastructure. `scripts/run_reviewer_workflow.sh` provides a
typed evaluator report around the same gate.

Core components:

- `run_review_check.sh`: study-claim validation wrapper
- `scripts/run_reviewer_workflow.py`: evaluator report and host preflight
- `scripts/generate_claim_evidence_ledger.py`: canonical claim boundary
- `scripts/build_reviewer_dashboard.py`: reviewer-facing claim and evidence map

## Layer 2: Repository-Local Docker Replay

The optional live replay is:

```bash
bash artifact/setup.sh
bash artifact/run.sh
bash artifact/validate.sh
```

Docker is required for the live replay. It runs two compact, complementary
campaign/SUT slices, then archives reviewer-generated records without changing
the released claim ledger. This is the smallest live execution example, not a
study-claim validation substitute.

Core components:

- `artifact/`: Docker replay and validation wrappers
- `scripts/run_orchestrated_campaign.py`: one campaign/SUT replay
- `src/loaders/`: campaign and SUT loading
- `src/runners/`: orchestration and evidence generation
- `src/executors/`: technique realizations

## Layer 3: VM Backend Materials

The repository contains provider-aware VM source for substrate realism and
network/service qualification work. The source is inspectable, but no VM
backend is part of the canonical reviewer contract.

Core components:

- `scripts/run_lab_campaign.py`
- `scripts/up_lab.sh`
- `scripts/destroy_lab.sh`
- `lab/health_check.py`
- `lab/vagrant/`
- `multi_vm_manager_2vm.py`

Non-canonical root-level orchestration scripts may still exist for exploratory
author workflows, but they are not the primary public contract and should not
supersede the documented runner or artifact wrappers.

This layer may support a later campaign-bound qualification after it records
boot, procedure execution, independent observation, and clean teardown.

## Provider Model

The VM-backed layer is provider-aware rather than provider-fixed.

Candidate implementations:

- Linux x86_64: `libvirt`
- macOS ARM64: `qemu`
- VirtualBox: optional where available and stable

Rationale for retaining these alternatives:

- `libvirt` usually offers the most faithful private-network behavior on Linux.
- `qemu` is the practical backend for Apple Silicon, but it may ignore some
  Vagrant high-level network declarations.
- Users should not be forced into a single host platform or hypervisor when
  the host-only claim gate does not require it.

Current status:

- QEMU Linux ARM64 is `implemented` but requires boot qualification.
- Native Windows x86_64 is `development_in_progress`; its renderer and
  architecture-specific unattended templates do not establish a guest run.
- The capability ledger, not a provider selection or host preflight, is the
  authority for promotion.

## Separation of Concerns

AutoSUT keeps four concerns separate:

1. Campaign definition: what the adversary does.
2. SUT profile: where it happens and which weaknesses are present.
3. Executor implementation: how a technique is materialized.
4. Evidence generation: what was observed and how fidelity is classified.

This separation is important for honest reporting:

- published corpus is not automatically equivalent to executable corpus;
- VM-backed realism is not automatically equivalent to reviewer reproducibility;
- backend-specific constraints must be measured rather than assumed.

## Execution Flow

Live replay flow:

1. Load campaign metadata from `data/campaigns/` or `campaigns/`.
2. Load the matching SUT profile from `data/sut_profiles/`.
3. Execute the campaign runner.
4. Write evidence to `release/evidence/`.
5. Generate study-facing tables under `results/tables/`.

VM backend qualification intent:

1. Select an explicit provider and an architecture-matched, hash-pinned image.
2. Record a cold boot and declared substrate health.
3. Apply the campaign-bound SUT requirements.
4. Execute a procedure with declared evidence predicates.
5. Independently observe the intended effect.
6. Record clean teardown with the requirement, image, and run hashes.

Until that evidence is frozen and admitted by the capability ledger, the code
remains implementation material rather than an experiment result.

## Lab Deployment: Hosts, Roles, Networks, and Agents

Readers frequently arrive with a mental model taken from Kali-based emulation
labs, where a dedicated attacker box drives commands at a separate target. That
is not how this artifact runs, so the layout is stated explicitly here.

**Attacker host and execution host are separate concepts.** The single-target
path in `CampaignOrchestrator.run_campaign` creates a separate attacker
container through `bring_up_attacker`, using `autosut/dmz-host:s28`. Multi-host
campaigns use their declared `HostFleet` roles. Neither path implies Kali.
Some steps issue requests from the attacker; others run commands directly in
the target through the harness. The source must be determined per action,
not inferred from the campaign's name or the presence of an attacker container.

**Caldera dispatch uses the agent on the specified execution host.** When a campaign
declares `expected_mode: caldera_driven` for a technique, `dispatch_via_caldera`
installs and registers a Sandcat agent inside the supplied container, creates a
one-off adversary holding just that ability, runs an operation against the
agent's group, and captures the per-link stdout, stderr, and exit code. A fresh
paw is allocated per operation so a stale agent cannot silently answer for a
later campaign. Every other technique runs through a direct local executor with
no Caldera involvement at all: across the twenty-campaign corpus run, Caldera
dispatched 10 of 176 steps, in 3 campaigns.

**Addresses carry no semantics; zone membership does.** A multi-host profile
declares zones (`internet_edge`, `dmz`, `enterprise`), and the fleet creates one
Docker network per zone. A host joins the zones listed in its `zones` field, and
a host in two zones is dual-homed. Membership alone does not establish
packet forwarding between the zones; routing and firewall behavior require
separate configuration and validation. No CIDR is
declared anywhere in the catalog and no address is hand-assigned: Docker
allocates them, and the resulting IP is recorded as system-introduced
provenance rather than as evidence recovered from CTI. Reachability is therefore
a property of network membership, not of an address that merely looks internal.

**One backend is in use today.** `select_backend` chooses `qemu` or
`windows-qemu` when a profile requests it and Docker otherwise. All twenty
implemented campaigns currently resolve to Docker. The QEMU paths exist and are
exercised separately as VM backend material; they are not what the campaign
corpus runs on, and Vagrant appears only as a wrapper around that VM path, never
as a campaign backend.

| Element | What it is | Where it runs |
|---|---|---|
| Orchestrator | Campaign runner in this repository | Host shell |
| Caldera C2 | Started per campaign, torn down after | Container |
| Sandcat agent | Registered per campaign, fresh paw per operation | Inside the SUT container |
| SUT host | Single container, or several across zone networks | Docker |
| Attacker host | Separate container on the single-target path; declared roles in multi-host fleets | Docker |
| Zone network | One Docker network per declared zone | Docker |

**Campaigns are serialized, never concurrent.** `--isolate-campaigns` brings the
environment up, runs one campaign, tears everything down, and repeats. Caldera is
restarted per campaign for the same reason: a reused C2 leaves stale agents that
answer for the wrong campaign. Every run in the corpus batch reported a clean
namespace on exit.

## Current Integrity Rule

Reviewer-facing claims are grounded in the canonical ledger regenerated by
`bash run_review_check.sh`. Live Docker or VM records remain bounded to their
declared scope and do not replace the ledger. Backend claims require the
evidence and promotion level recorded in
`release/experiments/capability_ledger/capabilities.json`; a source file,
provider preflight, or local exploratory run is insufficient.

Historical records under `release/experiments/multi_campaign/` are explicitly non-qualifying. Their
`STATUS.json` classification is validated mechanically; those records cannot support a current
capability or paper claim.

## Entry conditions and interpretation

An external-entry experiment starts without a session on the target. Its declared
entry mechanism must produce that session, with causal evidence connecting the
source host, target service, execution identity, and observed transition.
An assumed-breach experiment starts with a declared compromised host or session.
It can evaluate subsequent behavior, but cannot claim to have established entry.

The Caldera wrapper records a typed `*_execution_scope.json` before dispatch,
including the execution host, harness-provided session, and limits on claims.
The record remains available on failure. This declaration does not certify that
an agent executed or that a mechanism succeeded; the operation/link evidence is
still required. Older bundles lacking this record are not retroactively upgraded.

Stealth requires measured defensive observations and a stated detection criterion.
No absence of an alert is evidence of stealth when the relevant sensor or rule
was absent. Container-local discovery does not establish enterprise-wide or
historically faithful campaign reproduction.
