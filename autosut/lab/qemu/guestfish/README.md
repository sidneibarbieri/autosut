# Windows clone integration probe

This probe is for a local ARM64 Windows image prepared by the lab operator. It
does not build or distribute Windows media. The source image remains read-only.
The runner creates a disposable qcow2 overlay, injects a fresh credential into
the clone's cached answer file, executes the existing Windows cyber gate, then
removes the answer file and overlay. Run it only on a host with QEMU, Docker,
guestfish support, and the laboratory's native ARM64 agent.

Build the helper image from the versioned Dockerfile:

```sh
docker build --platform linux/arm64 -t autosut-guestfish:bookworm lab/qemu/guestfish
```

Run from the artifact root with a private evidence directory under a Docker-
shared host path. Do not set `AUTOSUT_WIN_PASSWORD` beforehand.

```sh
.venv/bin/python scripts/infra/windows_ephemeral_gate.py \
  --base /absolute/path/to/local-windows-base.qcow2 \
  --agent /absolute/path/to/native-arm64-agent.exe \
  --evidence-root /absolute/path/to/private-evidence
```

The output is **integration evidence only**. An existing base can still contain
an older account credential, and this command does not audit every guest and
host surface for secret residue. It does not qualify a credential-free base,
claim Windows generality, or replace a clean-host reviewer reproduction.
