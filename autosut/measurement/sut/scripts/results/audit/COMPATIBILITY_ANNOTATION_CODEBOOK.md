# Compatibility annotation codebook (version 2)

This codebook defines how to label each technique's minimum execution substrate,
independently of AutoSUT. Independent LLM judges from different model families
apply it to the blind sheet (`compatibility_annotation_sheet_A.csv`), which never
shows AutoSUT's label or the rule that fired. Their consensus is the reference
label; items where they disagree are reported as boundary cases. The reference is
not ground truth: the codebook does not fix a container profile, so a class can
change with that profile without any judge misreading the technique.

## The question

For the technique as described, what is the least isolated substrate on which
its core mechanism can be executed with fidelity in a laboratory?

Decide from the technique's own semantics (name, tactics, platforms,
permissions, description), not from how AutoSUT routed it.

## Labels

Write one of `CF`, `VMR`, `ID` in `annotator_class`.

- **CF (container-feasible).** The mechanism runs inside an ordinary
  unprivileged **Linux** container: userspace processes, files, network clients,
  application-level actions. No kernel module, no boot or firmware state, no
  host-level privileged object. A technique that exists only on Windows or macOS
  cannot be CF, because a Linux container cannot run it.
- **VMR (VM-required).** The mechanism needs a full kernel or host it can treat
  as its own: loading a kernel module, touching boot or firmware, manipulating
  host-level privileged objects (the registry, LSASS, a privileged service),
  stepping outside a container's isolation, or running on Windows or macOS,
  which needs a virtual machine of that operating system.
- **ID (infrastructure-dependent).** The mechanism needs an external service,
  identity plane, or managed platform that is not a property of a single host:
  a domain controller, an IaaS or SaaS control plane, a cloud identity service,
  or lateral movement that depends on such infrastructure.

## Operational cues

- A technique that only reads or writes files, spawns userspace processes, or
  speaks an application protocol is **CF** when its Linux form exists. If it
  exists only on Windows or macOS, it is **VMR**.
- A technique whose core step is loading a driver, altering the boot chain, or
  reading or writing a host-privileged store is **VMR**.
- A technique that only makes sense against a directory, cloud, or SaaS control
  plane, or that moves laterally through one, is **ID**.
- Judge the **core mechanism**, not an optional variant. If a technique is
  usually userspace but has a rare kernel variant, label the core mechanism.
- Platform tags describe where behavior is *compatible*. Use them to decide
  whether a Linux form exists; a technique listed for Linux and Windows can be
  CF through its Linux form.

## Notes field

When a technique sits on a boundary, write one sentence in `annotator_notes`
naming the deciding factor. This feeds adjudication and is not scored.

## After annotation

`judge_compatibility_labels.py` records every request and raw reply.
`score_compatibility_judgments.py` reports inter-judge agreement and Cohen's kappa,
and scores AutoSUT against the consensus with a confusion matrix, per-class
precision and recall, and macro-F1, overall and separately for the explicit-rule
and fallback strata.
