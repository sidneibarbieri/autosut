# Joint campaign-SUT realization certificate

AutoSUT consumes a STICKS realization space and independently checks each causal graph
against one SUT blueprint and binding catalog. The certificate verifies:

- source-plan and binding-catalog hashes;
- complete, non-duplicated coverage of source steps;
- causal reachability and graph-edge consistency;
- existence and laboratory scope of every used binding;
- opaque references for credential bindings;
- resolution of target-host bindings to blueprint hosts; and
- an isolated SUT network policy.

The consumer accepts only the supported STICKS realization schema (`schema_version: "1"`)
and fails closed on an unknown field in the consumed realization contract. A future
schema requires an explicit adapter and compatibility tests; a content hash alone does
not make an unknown semantic field safe to ignore.

```bash
python scripts/certify_joint_realizations.py \
  --realizations /tmp/C0010.realization-space.json \
  --blueprint release/plans/C0010.sut-blueprint.json \
  --bindings release/plans/C0010.binding-catalog.json \
  --output /tmp/C0010.joint-realization-certificate.json \
  --require-compatible
```

The certificate proves compatibility with the declared contract, not operational
success. Its `compatibility_scope` is `declared_sut_contract_only`, and its
`operational_status` remains `not_run`. Only a lifecycle-isolated campaign run with
effect evidence can promote a realization to an execution result.
