# Native-Windows Corpus Adjudication

Native Windows execution is an implementation target of the final AutoSUT
architecture. This workflow characterizes which Windows semantics and
topologies a *frozen declared corpus* supports, which need enrichment or an
explicit engineering decision, and which must later be qualified. It is not a
backend implementation, a VM qualification, an execution experiment, or a
historical replay claim.

Its central boundary is deliberate: ATT&CK platform labels and procedure prose
are preserved as evidence, but neither labels, keywords, nor an LLM makes the
native-semantics decision. A human reviewer makes a structured decision only
after every source relationship in a candidate packet is available for review.

## Inputs and trust boundary

`scripts/build_native_windows_adjudication.py` accepts all source locations
explicitly. It has no default path to a sibling procedural-plan checkout and records no
absolute source path in its outputs. A development invocation may inspect a
sibling source tree, but is labeled `external_development_input` and cannot
qualify an AutoSUT release decision.

The preparation step validates all of the following before writing a candidate
set:

- `index.json` count accounting and index digest;
- each indexed compiled plan's file digest and canonical content digest;
- the pinned ATT&CK bundle digest and object count;
- the campaign and technique STIX identifiers and external identifiers;
- every `uses` relationship's source and target binding; and
- every copied procedure description against the corresponding STIX
  relationship description.

The result contains the source bundle digest, index digest, individual plan
digests, relationship IDs, and exact copied procedure text. It does not retain
the external local path.

## Freeze the protocol before preparing the corpus

Create and preserve the protocol file before anyone sees or annotates the
candidate queue. The default uses two annotation sets and label-based triage:

```bash
python3 scripts/build_native_windows_adjudication.py protocol-template \
  --protocol-id native-windows-scope-v1 \
  --candidate-selection windows_platform_label_triage \
  --required-independent-annotation-count 2 \
  --output /path/to/native-windows-scope-v1.protocol.json
```

There are two selection modes:

- `windows_platform_label_triage` selects a campaign when at least one verified
  technique label includes `Windows`. It may establish a positive witness if a
  fully reviewed candidate requires native Windows. It can never establish a
  negative corpus-wide conclusion, because nonselected campaigns were not
  semantically reviewed.
- `full_compiled_corpus` sends every compiled plan to review. Only this mode
  can support a negative scope conclusion, and only after the complete,
  matching protocol-defined annotation set is available.

Neither selection mode treats a platform label as a semantic conclusion.

## Prepare an external development input

The following is intentionally an external-development operation. It does not
make the AutoSUT release depend on the external procedural-plan checkout:

```bash
python3 scripts/build_native_windows_adjudication.py prepare \
  --protocol /path/to/native-windows-scope-v1.protocol.json \
  --plans-root /absolute/path/to/sticks/release/plans/enterprise \
  --attack-bundle data/stix/enterprise-attack.json \
  --source-identifier sticks-enterprise-plans-<frozen-identifier> \
  --source-mode external_development_input \
  --candidate-output /path/to/candidates.json \
  --template-output /path/to/annotation-template.json
```

The template deliberately has no fields for a person, email address, host,
provider, credential, or free-text note. Each reviewer receives the same
relationship-backed evidence packet and records only:

- one bounded decision for each campaign;
- the complete ordered list of evidence item IDs reviewed;
- a bounded reason code; and
- a subset of supporting evidence IDs.

The non-identifying annotation-set ID distinguishes two records, but it cannot
cryptographically prove that two people worked independently. Independence must
be controlled by the study procedure outside the machine-readable packet; the
assessment reports that limitation explicitly.

## Validate annotations and agreement

Create one completed JSON record per annotation set using the template's
hashes. The validator rejects a record that omits a candidate, omits an
evidence item, changes a protocol or corpus digest, adds identity fields, or
contains an unsupported decision/reason combination.

```bash
python3 scripts/build_native_windows_adjudication.py assess \
  --protocol /path/to/native-windows-scope-v1.protocol.json \
  --candidate-set /path/to/candidates.json \
  --annotation /path/to/blind-a.annotations.json \
  --annotation /path/to/blind-b.annotations.json \
  --output /path/to/assessment.json
```

The output keeps these states distinct:

- `requires_adjudication`: a required annotation set is missing or decisions
  disagree;
- `not_qualified`: source text is insufficient, label triage is being used to
  attempt a negative conclusion, or the source was only an external development
  input; and
- `qualified`: the protocol's complete coverage and agreement rule hold.

A qualified *scope* decision still does not qualify a Windows VM, image,
provisioner, agent, procedure, or experiment. Those need their own frozen
execution and cleanup evidence.

## Vendoring a future release corpus

Do not mark an external checkout as `vendored_snapshot`. To create a release
candidate later, copy the complete plan directory - `index.json` and every
indexed plan file - into a documented AutoSUT-owned input directory, and copy
or retain the exact ATT&CK bundle needed to verify it. Before preparing the
release candidate:

1. record a stable source identifier and the source revision outside the
   generated candidate set;
2. verify the copied `index.json` SHA-256 and ATT&CK bundle SHA-256 against the
   source snapshot;
3. run preparation with `--source-mode vendored_snapshot`; this mode is
   accepted only when the plan root is under the AutoSUT project root;
4. preserve the protocol, candidate set, annotation records, and assessment as
   separate hash-bound files; and
5. perform a clean-extraction review of the eventual public package before
   treating its scope decision as release evidence.

Vendoring is a future freeze operation, not an instruction to copy an evolving
sibling checkout into the current release.
