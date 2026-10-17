# Reviewer Quickstart

This page gives the shortest reviewer path without introducing a second
execution contract.

## Start with the visual evidence map

Open [the evidence dashboard](../release/dashboard/index.html) after extracting
or cloning the artifact. It connects the paper's claims to the claim ledger and
CSV/JSON evidence. This is an inspection interface; viewing it does not execute
or validate the experiments.

Then run the commands below from the artifact root. Compare their exit status
and newly generated reports with the linked evidence. The optional live replay
is a separate step and is not required to inspect the published measurements.

## Claim Validation

```bash
bash scripts/run_reviewer_workflow.sh --mode kick-the-tires
bash scripts/run_reviewer_workflow.sh --mode full-reproduction
```

The first command is host-safe. The second rederives the released values and
claim ledger, but does not launch Docker or VM infrastructure.

## Native Windows Media Checks

The primary Python gate explicitly deselects the two real FAT/ISO checks. It
does not certify native media generation or Windows execution. Preserve that
distinction when interpreting a passing reviewer report.

After installing the reviewer environment, run from the artifact root:

```bash
.venv/bin/python scripts/qualify_windows_media.py --preflight-only
.venv/bin/python scripts/qualify_windows_media.py
```

This path requires `qemu-img`, `mformat`, `mcopy`, `mtype`, and `xorriso` on PATH.
Missing utilities and failed media checks produce nonzero exits. Preflight
proves only readiness; the full command validates real temporary FAT/ISO files,
not a running Windows guest. Nothing is installed automatically.

## Optional Live Replay

On a Docker-capable host, run the compact live example separately:

```bash
bash artifact/setup.sh
bash artifact/run.sh
bash artifact/validate.sh
```

It creates reviewer-local records for an infrastructure smoke slice and a
C0045-derived surrogate slice. Those records do not alter released claims.

## Read Next

- `../REVIEWER_GUIDE.md`
- `../REPRODUCIBILITY.md`
- `../PUBLIC_REPOSITORY_SCOPE.md`
