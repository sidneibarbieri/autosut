# Windows provider development boundary

Native Windows execution is an implementation target of AutoSUT. The Windows
workgroup provider accepts a hash-bound `CampaignRequirements` DTO and renders
a deterministic Vagrant plan for either libvirt or Hyper-V.
It does not import a fixed third-party laboratory and it does not contain a
Windows image, an image credential, a password, a procedure command, or a
provisioner script.

This is deliberate. The current implementation has not qualified a native
x86_64 Windows run through cold boot, agent enrolment, procedure execution,
independent observation, and clean teardown. Rendering a Vagrantfile is not
evidence that any of those events occurred. The corpus audit informs which
Windows topology, identity, network, procedure, and provenance requirements a
campaign needs; it does not decide that Windows may be removed from scope.

The provider is limited to a two-or-more-host Windows **workgroup**. A request
for Active Directory, a non-Windows host, an absent per-host administrator
reference, or a non-private topology fails instead of being replaced with a
different laboratory. Active Directory must receive its own requirements,
provider implementation, and qualification evidence.

## Inputs and secrets

Every requirement includes a reference to a hash-bound provenance record.
Administrator passwords are represented only by names such as
`AUTOSUT_WINDOWS_HOST_A_ADMIN_PASSWORD`. The rendered Vagrantfile obtains those
values with `ENV.fetch` only if an operator later performs materialization;
neither the plan nor the DTO stores a secret.

The image is an operator-supplied, hash-pinned x86_64 Vagrant box reference.
The provider does not download it. Before an execution-capability claim is
made, the operator must verify that image hash and run a versioned
qualification protocol on an x86_64 host with the selected backend.

### Architecture contract

The x86_64 Vagrant plan and a Windows unattended answer file use different
but explicit vocabulary: the plan declares `x86_64`, while Windows unattended
XML requires `processorArchitecture="amd64"`. The renderer requires an
explicit `--architecture` and selects a matching tracked template; it rejects
an ARM64 template for an x86_64 request and vice versa. The existing ARM64
template remains only for the separate ARM64/QEMU development path. Neither
template is evidence that the corresponding guest booted. The Vagrant plan
records both `autounattend.host_a.x86_64.xml` and `amd64`, so a later
qualification runner has one architecture-bound selection to consume.

### Isolated ARM64/QEMU qualification

The ARM64 development path has a separate, local qualification runner. It
does not qualify the x86_64 Vagrant provider above. It requires an
operator-supplied Windows ARM64 installation ISO and VirtIO driver ISO, plus
QEMU with HVF, swtpm, xorriso, mtools, tesseract, socat, Docker, and the
`autosut-guestfish:bookworm` helper image. Neither ISO nor a Windows base is
included in the public package. Verify media hashes and license terms before
running it. The primary reviewer environment does not install WinRM. Create a
separate qualification environment with the two packaged dependency sets:

```sh
QUALIFICATION_ENV=$(mktemp -d "${TMPDIR:-/tmp}/autosut-windows-env.XXXXXX")
python3 -m venv "$QUALIFICATION_ENV"
"$QUALIFICATION_ENV/bin/python" -m pip install \
  -r requirements-reviewer.txt -r requirements-windows-qualification.txt
"$QUALIFICATION_ENV/bin/python" -m pip check
```

Run these commands from the `autosut` directory in the same terminal. Use the new environment's
interpreter for the Windows commands below, not the system Python or the
primary reviewer environment. The dependency versions were qualified with
Python 3.14 on ARM64 macOS; other interpreter/provider combinations require
their own qualification. Keep run outputs outside the packaged source tree.

Build the helper from `lab/qemu/guestfish/Dockerfile` first:

```sh
docker build --platform linux/arm64 -t autosut-guestfish:bookworm \
  -f lab/qemu/guestfish/Dockerfile lab/qemu/guestfish
"$QUALIFICATION_ENV/bin/python" scripts/infra/windows_base_builder.py \
  --install-iso /private/path/Windows-ARM64.iso \
  --virtio-iso /private/path/virtio-win.iso \
  --workdir /private/path/new-base-attempt
```

Run `scripts/infra/windows_base_builder.py` with `--install-iso`,
`--virtio-iso`, and a new private `--workdir`. It installs into a new qcow2,
stops at Setup's first guest-requested reset, then stages the signed ARM64
NetKVM driver offline. The result is an **unqualified candidate**. Before
using it, inspect the guest's setup phase, SAM, Panther answer files, and
credential residue without booting it. Keep the image and all run outputs
private. The builder does not modify an existing base. The work directory
must not already exist.

```sh
"$QUALIFICATION_ENV/bin/python" scripts/infra/windows_credential_pair.py \
  --base /private/path/credential-free-candidate.qcow2 \
  --output-dir /private/path/new-pair-run
```

The credential-pair command
creates two disposable clones with separate passwords and computer names. It
requires positive authentication to each clone, rejection of the other
clone's password, distinct machine identities, an unchanged base hash, and
natural clean shutdowns. Its `residue_free` field covers retained pair logs;
it does **not** certify deleted overlays, guest free space, or the host's
physical storage. The per-clone Windows integration runner is
`scripts/infra/windows_ephemeral_gate.py`; its result remains classified as
integration evidence unless the broader promotion rule is satisfied.

For a fresh ARM64 integration with stopped-disk Panther acquisition:

```sh
"$QUALIFICATION_ENV/bin/python" scripts/infra/windows_ephemeral_gate.py \
  --base /private/path/credential-free-candidate.qcow2 \
  --agent /private/path/native-arm64-agent.exe \
  --evidence-root /path/shared-with-docker/new-integration-run \
  --guestfish-image sha256:YOUR_VERIFIED_HELPER_IMAGE_ID \
  --acquire-panther
```

Use a private evidence directory visible to Docker containers. On macOS,
Docker Desktop may not share `/private/tmp`: a bind mount can appear inside
the container as a directory even when the host path is a regular QCOW2 file.
When Panther acquisition is requested, the runner checks file visibility
before creating the VM and rejects an unshared evidence root. Use a private
directory under a Docker-shared path, and keep its contents out of releases.
The collector
mounts every runtime backing-chain image read-only, acquires Panther into an
uncompressed tar, and requires actual archive bytes on the caller's host. The
final credential scan includes that archive. Acquisition errors fail the run
after cleanup. Retain the archive privately: it contains guest logs, and its
acquisition receipt does not certify complete secret removal or eight-surface
coverage. Images, agent and helper are explicit operator-supplied prerequisites.
The acquisition is retained under the run's `windows-qemu/panther-acquisition`
directory. Its receipt counts populated password fields in answer files without
recording their values. The CLI returns failure if any such field remains;
the integration bundle alone must not be read as credential-free qualification.
While the per-run credential is still available in memory, the runner checks
the uncompressed archive against its acquisition digest, the answer-file fields,
and the bounded credential representations. It writes a sibling
`<run-id>.panther-secret-audit.json` without the credential. Any detected residue
fails the runner. This is a scoped Panther check, not one of the eight complete
qualification receipts.
For a separate cleanup experiment, add `--clear-panther-answer` to the command
above. After the guest procedure, this removes the active
`C:\Windows\Panther\unattend.xml`, requires an explicit guest confirmation, and
then acquires the stopped disk. The flag requires `--acquire-panther`. A clean
post-cleanup archive proves only that the acquired active answer files lack
populated password fields; it does not prove absence in logs, deleted blocks,
other guest locations, or the remaining credential-audit surfaces. Keep the
earlier raw acquisition private to preserve the pre-cleanup observation.

The Windows lifecycle checks Caldera readiness before guest materialization and
API-key access. Teardown retains `caldera-state.json` with container status,
running/restarting flags, OOM status and exit code. It excludes configuration,
keys, free-text Docker errors and raw container logs. A failed metadata probe
is recorded as incomplete; it does not certify the execution layer.

## Safe materialization entrypoint

`WindowsVagrantMaterializer` is the deliberately narrow path from a rendered
plan to a local Vagrant attempt. It requires an existing local `.box` file,
checks its SHA-256 against the plan before it invokes `vagrant`, verifies the
canonical requirements/Vagrantfile/manifest against the current renderer, and
requires every per-host administrator variable. It creates a fresh run
directory and invokes only `vagrant up --provider …` and, on failure or
explicit teardown, `vagrant destroy -f` in that directory.

The entrypoint records command return codes and output hashes, never command
output or credential values. It is lifecycle plumbing, not an execution
qualification. It must be connected to a campaign-bound procedure,
independent observation, and the promotion rule below before any experimental
claim is made.

The planning adapter is intentionally not registered in the generic
`select_backend` execution factory yet. That factory promises a runnable SUT;
registering an unqualified provider there would make a rendering capability
look like a completed Windows backend. Registration belongs after the
qualification rule has been satisfied, not before.

## Promotion rule

Canonical evidence bundles use schema `1.1.0`. The validator still reads
`1.0.0` integration records without rewriting them. A claim-eligible
`windows-qemu` bundle must declare all eight credential-audit surfaces in
`secret_audit.scanned_surfaces`: `base_image`, `source_tree`, `evidence_bundle`,
`run_logs`, `guest_panther`, `provisioning_media`, `host_temporary`, and
`controller_state`. A scan of retained run files alone cannot qualify Windows.
Unknown surface labels are rejected by the typed schema.

For a claim-eligible Windows bundle, each surface also needs a distinct,
completed, leak-free scan receipt. The bundle validator must be called with
the evidence root so it can check each receipt's relative path, SHA-256, and
recorded surface and outcome. A list of surface names, or receipts that cannot
be opened from the evidence root, is rejected. Existing integration bundles
do not need these receipts and remain non-claim-eligible.

This coverage declaration is necessary, not sufficient: actual scans and their
evidence must support each declaration. Adding surface names to a bundle does
not perform forensic inspection. A digest-bound receipt confirms what was
retained, not that the named scan actually examined the claimed guest or host
surface. Independent review of the scan method and its input inventory remains
required. Existing integration runners do not claim this complete coverage.

The ephemeral Windows runner seals its integration bundle before collecting
post-run scan receipts. It must not edit that sealed bundle. A later
`assess_sealed_windows_run` decision verifies the run manifest and the scan
receipts against retained inputs, then binds its decision to the original
manifest and bundle digests. The historical `base_image_sha256` field remains
the disk image delivered to the executor, which is a prepared overlay in this
runner. New ephemeral runs also record `image_digests.immutable_base_sha256`
for the underlying base, verified unchanged across execution. A `base_image`
receipt cannot stand for that base unless its scanned bytes match this named
digest. The `evidence_bundle` and `run_logs` receipts must likewise scan the
sealed bundle file and run directory themselves. Existing bundles are not
rewritten or promoted.

The ephemeral runner writes a post-seal `prepared-overlay-disposal/v1` sidecar
after removing the prepared overlay. Its verifier binds the former overlay
hash, run ID, and manifest hash and checks that the path is still absent. This
proves only logical removal of that overlay path at verification time; it is
not secure erasure or a scan of `provisioning_media` or `host_temporary`.

The same runner now scans the sealed `bundle.json` file and, when supplied,
the immutable base image while the per-run credential is still available.
Both receipts are outside the sealed run. The base scan checks the current
credential's bounded representations in those bytes; it does not certify that
an older credential or an arbitrary encoding is absent. The post-run assessor
still requires the base input to match the immutable-base digest in the seal.

The `guest_panther` input is also bound to the run's stopped-disk acquisition
directory. A stamped reviewer package can emit a `source_tree` scan while the
per-run credential is still available. The post-run assessor accepts that
surface only when the supplied package's verified source revision matches the
sealed run. Its inventory uses the revision's implementation paths (`src`,
`scripts`, `tests`, and `lab`) and exclusions; generated `.venv` and reviewer
outputs are outside this surface. A source checkout without a package stamp
emits no such receipt.
`provisioning_media`, `host_temporary`, and `controller_state` still lack
producer-bound provenance. Earlier runs are not promoted retroactively, and
the post-run decision rejects qualification until all required contracts and
receipts are present.
On macOS, the Windows runner now checks `lsof +L1` for deleted guestfish
`answer.xml` and prepared-overlay files still open under the immutable base's
directory, and rejects retained guestfish staging directories. It refuses a
new run before creating evidence, and checks again
after a completed run. This is a fail-closed host observation, not a complete
`provisioning_media` receipt: a missing pathname does not close an open inode,
and the check does not inspect arbitrary process memory or other users'
unavailable descriptors. Do not restart Docker Desktop merely to make a gate
pass while unrelated containers must remain available.
To inspect a sealed integration run without modifying it, use the assessment
CLI with the immutable base and the exact stamped source package used by that
run:

```sh
python scripts/infra/assess_windows_postrun.py \
  --run-dir /absolute/private/evidence-root/RUN_ID \
  --base-image /absolute/private/immutable-base.qcow2 \
  --source-tree /absolute/stamped-package/autosut
```

It prints a JSON decision and exits 1 when the run is not admissible. Current
integration runs are expected to fail qualification: they lack the three
transient producer contracts and do not have a frozen, supervised
qualification classification. The CLI verifies the original seal and retained
receipts; it does not edit the run, generate missing scans, or convert an
integration result into a scientific claim.
Even complete byte scans cannot establish absence of arbitrary encoded,
deleted, or unacquired credential copies.

`WindowsQemuEnvironment.bring_up` accepts an optional `stopped_disk_observer`.
It receives the actual runtime overlay after QEMU and the software TPM have
stopped and the process logs have closed, before that overlay is removed.
An acquisition failure propagates after resource cleanup and leaves teardown
unsuccessful. The observer runs at most once, including when teardown is retried.
After the QEMU and TPM processes stop, the backend clears its retained WinRM
credential before closing logs and acquiring the stopped disk. New WinRM
sessions then fail explicitly. Successful teardown records the logical cleanup
as `controller_credential_cleared`. This removes the backend reference; it does
not guarantee secure erasure of Python strings or all interpreter memory.
The integration wrapper also clears the preparation DTO's credential reference
after the retained-file scan, including when execution or audit raises. The
scanner keeps access to the credential until its checks complete. These are
logical lifetime controls, not claims about arbitrary copies in memory.
The caller must supply and validate the acquisition method. This hook performs
no inspection by itself and does not promote an integration bundle to qualification.

The retained-file scanner checks literal credential bytes and standard Base64
of their UTF-8, UTF-16LE and UTF-16BE encodings, including Base64 text stored in
those three encodings. It also checks the XML-escaped form produced by the
answer-file renderer in UTF-8, UTF-16LE and UTF-16BE. It also checks Base64
of the UTF-16LE credential followed
by `Password` or `AdministratorPassword`, as used in Microsoft's hidden-value
answer-file examples. The resulting Base64 text is checked in all three text
encodings. This is obfuscation coverage, not an encryption guarantee.
The receipt records `windows-unattend-obfuscated` in
`file_representations`, separately
from text encodings. Path names are checked for the literal credential only.
This bounded check does not decode arbitrary transformations, compressed files,
disk-image guest filesystems or other credentials combined with arbitrary text
before encoding. It cannot substitute for the eight-surface audit.

An abrupt host shutdown can bypass Python cleanup and leave the prepared clone
and QEMU overlay in a private evidence root. After restarting Docker, identify
the exact interrupted run and its `windows-credential-*` directory. Preview
the two owned disks, then explicitly dispose of them:

```sh
python scripts/infra/recover_interrupted_windows_run.py \
  --evidence-root /absolute/private/evidence-root \
  --run-id windows-ephemeral-integration_RUN_ID \
  --credential-directory windows-credential_DIRECTORY
# Repeat the same command with --dispose only after checking the preview.
```

The recovery tool refuses sealed runs, symlinks, open disks, active QEMU/TPM
processes, an unavailable Docker inventory, or an active container mounting
the evidence root. It also requires the run's preparation link to match the
credential directory and prepared-overlay digest. Runs without this link need
manual investigation; the tool must not guess a pairing. It removes only the
two named overlays and writes a receipt outside the run; logs remain. Its
receipt is crash cleanup evidence, not a successful lifecycle, complete
host-temporary audit, or qualification.

This source code is an implementation-in-development track. It becomes a
qualified execution backend only after a campaign-bound run records all of:

1. image verification and a cold boot;
2. host reachability and agent enrolment;
3. a procedure that satisfies declared evidence predicates;
4. independent observation of the intended effect; and
5. clean teardown with the plan and requirement hashes attached.

Until then, neither this provider nor a rendered plan supports a claim of
native Windows execution.
