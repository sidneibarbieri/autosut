# Campaign--SUT preparation scope

This deterministic preparation run covers the eight identifiers in
`release/plans/legacy-campaign-inventory.json` on implementation revision
`be9c252d4cd4e7b9b08e03c27a48b471f3d61e79+tree-8d787d20c90221cf`.

- Three pairs are `prepared`: C0010, C0026, and C0045.
- Five pairs are `blocked`: four by unsupported platform requirements and one by a missing execution
  contract.
- All eight pairs have `execution_status=not_run`.

`prepared` means that the finite compiler emitted a hash-bound campaign, SUT blueprint, binding
catalog, and executable contract. It is planning evidence, not evidence that the campaign executed.
`matrix.json` is the authoritative index.
