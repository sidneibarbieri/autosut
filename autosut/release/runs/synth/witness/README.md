# Deprecated development record: STIX-derived plan C0045

This directory preserves an early synthesis prototype for audit. Its materializability check showed
only that a proposed composition had locally available recipes; it did not establish that the
composition was grounded in the source CTI or that a model-generated command implemented the named
technique. The model also selected the marker later used as an alleged effect oracle.

Accordingly, this record is not a witness for arbitrary STIX, end-to-end execution, independent
effects, or removal of offline curation. The current command at `scripts/execute_from_plan.py`
produces only a `not_run` synthesis proposal. Any qualified future execution must use the contract
boundary described in `docs/architecture/PROPOSAL_ADMISSION_BOUNDARY.md`.
