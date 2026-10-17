# Step-2 Semantic-Enrichment Protocol

The Step-2 boundary is a protocol for preserving uncertainty in structured CTI.
It is not an agent, a planner, a command generator, or an execution interface.
The canonical configuration is `config.example.json`, validated by
`cti.semantic_concretizer.ArtifactConfig`.

## Provider contract

The only canonical provider shape is `local_openai_compatible`. Its base URL
must equal the literal unauthenticated endpoint
`http://127.0.0.1:1234/v1`, matching an LM Studio server bound to loopback.
The configuration deliberately has no
API-key field, no cloud-provider variant, and no generic provider-parameter
map. It builds a typed chat-completions request; no tracked configuration or
default command initiates a provider call.

`request_timeout_seconds` is explicit and bounded to 1--600 seconds. The
draft-only library runner in `cti.local_openai_transport` is the sole local
transport implementation. It permits only
`http://127.0.0.1:1234/v1/chat/completions`, explicitly disables proxy routing,
sends no authorization header, has no retry or cloud fallback, and requires
the response's model ID to equal the configured model ID. There is
intentionally no default CLI command that contacts a model.

The closed response vocabulary contains only these categorical facts:

- `platform`: `linux`, `windows`, or `macos`;
- `privilege`: an allowlisted privilege category;
- `network_exposure`: an allowlisted laboratory-connectivity category;
- `software_role`: an allowlisted service role; and
- `credential_requirement`: an account category, never credential material.

Every returned fact must cite one or more compact, hash-bound input anchor IDs.
The transport must also record the provider's returned model identifier and it
must equal the requested local model identifier. The
response schema excludes commands, code, product names, versions, host names,
addresses, ports, credentials, free-text parameters, explanations, and extra
fields. A deterministic validator rejects a fact outside the request's
declared unresolved fields or platform boundary.

## Bounded public CTI evidence

Step 2 cannot infer a defensible categorical fact from an ATT&CK identifier
alone. Each input anchor therefore carries one `public_cti` excerpt from a
declared STIX procedure or source-text field. An anchor binds three distinct
objects: `source_object_sha256` binds the archived STIX object,
`source_field_sha256` binds the original field before derivation, and
`text_sha256` binds the exact excerpt inserted into the prompt. The bounded
input, including all three digests, is itself covered by `input_sha256`.

The bounded input also records the raw-byte SHA-256 and object count of the
pinned STIX bundle. `SemanticEvidenceStore.prepare` and `verify` require the
bundle path explicitly, recompute that digest, index its objects, and reject a
run if any anchor cannot be recomputed from its declared source object. This
prevents a caller from substituting a same-shaped excerpt or an unrelated
object after the input has been prepared.

The STIX-to-anchor adapter must build each anchor with
`derive_evidence_anchor_from_stix_object` and the reviewer can recompute it
with `verify_evidence_anchor_against_stix_object` against the pinned object.
Those functions use canonical JSON for the object digest and never add the
full object to the prompt. The current release contains the boundary and its
verification routine, not a completed provider experiment; no semantic claim
is qualified until a frozen evaluation supplies the pinned source objects and
verifies every anchor.

An excerpt uses exactly one versioned derivation:

- `exact_source_text_v1` retains one public source field exactly; or
- `normalized_public_context_v1` deterministically collapses whitespace and
  replaces material-looking credential assignments or recognizable access-token
  shapes with fixed redaction markers.

The protocol accepts at most 16 excerpts and 4,096 characters per excerpt. It
rejects disallowed control characters, unbound or malformed hashes, and
material-looking credential data in an exact excerpt. The normalization path
does not make arbitrary text trustworthy: it only produces a bounded,
replayable representation of an identified public source field. The upstream
STIX snapshot and its object hash remain the authority for source authenticity.
For `exact_source_text_v1`, the protocol additionally requires the source-field
and prompt-text digests to be identical; a normalized excerpt must be
recomputed against the pinned source field during review.

Public CTI may describe commands used by an adversary. Here it is inert,
versioned reference data, explicitly labeled as such in the prompt; no
execution component consumes this DTO and the response schema cannot reproduce
commands or parameters. Provider configuration is a separate strict model and
has no key, token, credential, or arbitrary-parameter field. It is never
embedded in the bounded input or prompt.

## Model identity and qualification

`model_attestation.status` defaults to `unverified`. A claimed digest is not
verification. Before any proposal may contribute to a qualified evaluation,
the protocol must be frozen and the configuration must carry a hash-bound
attestation record with a verified model digest. The record identifies its
verification method and a project-relative evidence file. Until then, a parsed
proposal can be inspected, but it is explicitly blocked from qualification.

## Evidence layout

An eventual, explicitly enabled attempt is stored in a new run directory below
`provenance.root`. The tracked example writes to the ignored
`results/evidence/semantic_enrichment/runs` tree; a release must select and
sanitize any evidence deliberately rather than collecting it in `release/` by
default. The evidence store creates each file with exclusive-create
semantics, appends file digests to `provenance.jsonl`, and seals the directory
with `manifest.json`. The immutable evidence path is:

1. `protocol-manifest.json`;
2. `input.json`;
3. `prompt.txt`;
4. `response-schema.json`;
5. `raw-model-output.json`, `parsed-proposal.json`, and `admission.json` for a
   conforming output; `rejected-output.json` containing only an unsafe output's
   hash, length, and rejection class; or `transport-failure.json` containing
   only a message-free exception class; and
6. `manifest.json`.

The store does not overwrite a run, accept duplicate JSON keys, repair
malformed output, or execute a proposal. It binds the response to the exact
input, prompt, schema, and protocol archived during preparation; a second
output for the same run or an unlisted artifact prevents sealing. A sealed run
is still not a campaign result: it is only a
provenance-complete semantic proposal attempt. It needs the separate frozen
evaluation protocol, independent environment qualification, execution evidence,
and claim-ledger gate before it can support a scientific claim.

The draft runner seals either a safe/rejected model response or a transport
failure, then propagates the original error to its caller. Its return type has
no claim-promotion operation and always reports `is_claim_eligible = false`.
Changing that boundary requires a separately frozen evaluation protocol; it is
not activated by setting a configuration flag.

For a conforming response, the immutable run preserves the prompt and the
hash-bound public CTI excerpt through `input.json` and `prompt.txt`. This makes
the public source context reviewable and replayable against the pinned STIX
snapshot. Malformed or schema-invalid model output is quarantined: only its
digest, byte length, and rejection class are preserved. The artifact performs
no provider call in this release, so it contains no generated proposal or
evaluation value.
