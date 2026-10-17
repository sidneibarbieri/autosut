# G2 — Canonical provider contract across Docker / Linux-QEMU / Windows-QEMU

**Goal.** The experiment must traverse one lifecycle on every backend, and the scientific semantics
(tuple, procedure, oracle, fidelity) must not fork per backend.

## Layering (kept strict)

```
Scientific layer     CTI procedure · negative control · independent oracle · fidelity
        ↓
Execution layer      Caldera · agent enrollment · Sandcat · ability execution · PAW · operation
        ↓
Canonical lifecycle  LifecycleController (timed stages, always-teardown, sealed result)
        ↓
Provider contract    EnvironmentBackend
        ↓
Backends             Docker · Linux/QEMU · Windows/QEMU
```

The **provider** owns substrate mechanics only — `qcow2`, `swtpm`, `ramfb`, the WinRM transport,
Docker, Vagrant. It does NOT know what a procedure, Caldera, Sandcat, a PAW, or the nonce is.
**Sandcat and Caldera are execution-layer**, not provider mechanics: swapping Windows for Docker
changes how the SUT is reached, not the scientific meaning of the experiment. OS-specific procedure
and oracle command text is a property of the campaign and SUT profile, executed by the provider via
`run_shell` — never a fork in the provider.

## Evidence discipline (no smoke tests as qualification)

Engineering prechecks and narrow integration checks (import, schema, provider selection, a single
`bring_up → run_shell → teardown` round-trip) are for development feedback only and are **never**
sufficient for qualification. A capability is demonstrated only by the complete scientific execution
chain over the canonical lifecycle on a real backend, with a real CTI-derived procedure, the actual
execution mechanism, an independent effect oracle, provenance, teardown, verify-clean, and a sealed
bundle. Simplify incidental complexity, never the phenomenon being claimed. Every bundle carries an
`evidence_role` (`development | integration | qualification`); the claim ledger refuses anything below
`qualification`, and only a frozen-revision clean-room run may be `qualification`.

## What already exists (do not reinvent)

- `src/infrastructure/lifecycle.py` — `LifecycleController`: the one canonical lifecycle. Timed
  stages, always-run teardown (even after a forward-stage failure or SIGINT/SIGTERM), sealed
  `LifecycleResult` with per-stage timing, residual report, and final state. Stages are injected
  callables, so it is already backend-agnostic.
- `scripts/orchestrator/environment_base.py` — `EnvironmentBackend(ABC)`: `check()` → readiness,
  `bring_up(sut, run_dir)`, `host_id`, `run_shell(command) → CommandResult`, `teardown() → bool`;
  `select_backend(sut)` routes on `sut.backend`.
- Concrete backends: `DockerEnvironment` (canonical), `QEMUEnvironment` (Linux VM),
  **`WindowsQemuEnvironment` (new this pass)** — all three now implement the same contract.
- Attacker/executor substrate-agnostic already: `CalderaInstance` + `caldera_client`.

## Contract mapping (canonical stage → provider mechanism)

| canonical stage | Docker | Linux/QEMU | Windows/QEMU |
|---|---|---|---|
| preflight / readiness | `check()` docker daemon | `check()` vagrant+qemu+hvf | `check()` qemu+swtpm+edk2 |
| materialize + configure | `bring_up` run container | `bring_up` `vagrant up` | `bring_up` overlay+swtpm+boot, specialize |
| readiness (guest) | exec probe | ssh probe | WinRM probe (`_wait_ready`) |
| execute | `run_shell` (sh) | `run_shell` (vagrant ssh) | `run_shell` (PowerShell/WinRM) |
| teardown + verify_clean | `teardown()` rm | `teardown()` destroy | `teardown()` stop + residual sweep |

The enroll / ability / independent-oracle / negative-control steps are **experiment stages** over
`env.run_shell` + `CalderaClient`, not provider methods, so the same stages *can* serve every backend.
The Windows experiment now traverses the canonical lifecycle and provider contract; **cross-backend
convergence is not yet proven** — it holds only once the same orchestration entrypoint runs on Docker,
Linux/QEMU, and Windows/QEMU with schema-compatible evidence (item 4). OS-specific procedure/oracle
command text comes from the campaign + SUT profile, never the backend.

## The things G2 must do

1. **Migrate `windows_cyber_gate.py` to the canonical path — DONE.** It now runs the real experiment
   through `LifecycleController` + `WindowsQemuEnvironment`, selected by `select_backend(sut)`;
   enroll/ability/oracle/negative-control are stages over `env.run_shell` + `CalderaClient`. The
   duplicate `Guest` and the standalone enroll probes were removed. Validated end-to-end on a real
   guest with unchanged G1 semantics (fresh clone, specialize, real Caldera, native arm64 agent,
   negative control, T1112, independent oracle, natural teardown, fail-closed verify-clean, sealed
   bundle) — `cyber_gate_canonical/` (`science_passed: true`, `final_state: clean`).
2. **Ephemeral per-run Windows credential — by contract, not by chosen technology.** The
   sealed-image credential is a diagnostic of the current state, not the final design. The mechanism
   is selected by qualification against this fail-closed contract, and **no mechanism is canonical
   until it is empirically proven**:

   ```
   secret generated per run → absent from the immutable base → not committed → not printed in logs →
   not in the evidence bundle → guest receives it automatically → provider gets runtime access →
   experiment runs → guest destroyed → secret state destroyed →
   post-run sentinel scan over {base, source tree, bundle, logs, guest Panther, provisioning media,
   host temp, controller state} = 0 matches AND scan_completed = true (else NOT clean)
   ```

   Two runs must mint distinct credentials A ≠ B (A authenticates, B fails), with the base sha
   unchanged. Mechanism evaluation order (least persistence-surface first): **(a) ephemeral config
   disk + a minimal bootstrap already in the base** — the base carries no working credential; on
   first boot the bootstrap reads a random per-run secret from an attached medium, sets the automation
   account + WinRM, signals readiness without echoing the secret, and the medium is destroyed on
   teardown; **(b)** a `.ppkg` provisioning package (native, but adds an ADK dependency and persists
   under `%ProgramData%\Microsoft\Provisioning` until removed); **(c)** a per-run `Autounattend.xml`
   **last**, because Windows Setup caches answer files in `%WINDIR%\Panther` and persists them across
   reboots — the very persistence surface being eliminated. `(a)` avoids routing the secret through
   Windows Setup/Sysprep at all.
3. **One evidence-bundle schema across backends — schema + validator DONE; Windows emits it.**
   `src/infrastructure/evidence_bundle.py` defines composable DTOs (`RunIdentity`,
   `ArtifactProvenance`, `ProcedureEvidence`, `OracleEvidence`, `LifecycleEvidence`,
   `ResidualEvidence`, `SecretAuditEvidence`, `EvidenceClassification`, `EvidenceBundle`), one
   fail-closed `validate_bundle` (rejects incomplete inventory, forced teardown, non-natural exit,
   non-independent oracle, incomplete/failed secret scan, missing revision, and `integration`
   presented as `qualification`), and one `seal_bundle`. The Windows canonical gate emits a
   validated bundle (`cyber_gate_canonical/`, `bundle admissible: true`, credential absent from the
   sealed bundle). **Pending:** Docker and Linux/QEMU runs must emit the same schema.
4. **Drive all three through `LifecycleController`** from one entry point, proving no backend-specific
   scientific logic leaks into the experiment. **Pending.**

## G2 PASS criteria (declare before, not after)

G2 passes when ALL hold:

- The same orchestration entry point runs a representative campaign on Docker, Linux/QEMU, and
  Windows/QEMU by changing only `sut.backend`.
- No backend-specific mechanism (`qcow2`/`swtpm`/WinRM/Panther/Docker/Vagrant/Sandcat-arch) appears
  above the provider boundary.
- Each run seals a bundle in the common schema; the bundles validate against one validator.
- The Windows credential is ephemeral per-run, not read from the sealed image.

**Not** a G2 pass: three classes sharing an interface. It is a pass only when a campaign traverses
the same lifecycle on different backends and yields schema-compatible bundles.

## Status

- Canonical lifecycle + backend contract: **pre-existing, with substantial prior integration
  evidence** (Docker path). G2 does not reinvent it.
- Windows as a first-class backend under the contract: **done + validated on a live guest**
  (`windows_backend_contract_check.json`).
- Item 1 (real gate migrated to the canonical path, duplicate `Guest` removed): **done**
  (`cyber_gate_canonical/`).
- Items 2–4 (ephemeral credential, common bundle schema, drive Docker + Linux/QEMU + Windows through
  the one entry point): **pending**. Next priority is item 2 (ephemeral per-run credential), then the
  common schema, then cross-backend validation. Freeze happens only after G2, Step 2, ablation, R4 v2,
  and the corpus/provenance audit — never before.
