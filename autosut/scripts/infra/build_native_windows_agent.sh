#!/usr/bin/env bash
# Build a native windows/arm64 Caldera gocat agent for the Windows ARM64 backend gate.
#
# Why this exists: Caldera compiles agents on download, but its pinned image is linux/amd64 and its Go
# toolchain segfaults cross-compiling to arm64, so a windows/arm64 request silently returns the stale
# amd64 binary. The amd64 agent only runs under Windows-on-ARM x64 emulation, which is unavailable in the
# SYSTEM / Task Scheduler context the gate launches from. A native arm64 agent runs in any context.
#
# The agent source is the gocat the pinned Caldera image carries; it is compiled by a native arm64 Go
# toolchain (Caldera ships Go 1.22.2). Both images are pinned by digest so the build is reproducible.
# gocat's HTTP contact base64-encodes its beacon and takes -server at runtime, so no compile-time key or
# server address is baked in.
set -euo pipefail

CALDERA_IMAGE="ghcr.io/mitre/caldera@sha256:97a8f9fd052aaabdee76e8367d1ec985b3e44e6add0b27a28d8fee9cafe426c7"
GOLANG_IMAGE="golang@sha256:1cf6c45ba39db9fd6db16922041d074a63c935556a05c5ccb62d181034df7f02"  # golang:1.22

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ARTIFACT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUT_DIR="$ARTIFACT_ROOT/lab/qemu/images/windows11-arm64/agent"
OUT_BIN="$OUT_DIR/sandcat_arm64.exe"
mkdir -p "$OUT_DIR"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

echo "[build-agent] extracting gocat source from the pinned Caldera image"
docker run --rm --platform linux/amd64 --entrypoint sh "$CALDERA_IMAGE" \
  -c 'tar -C /usr/src/app/plugins/sandcat -cf - gocat' > "$work/gocat_src.tar"
src_sha="$(shasum -a 256 "$work/gocat_src.tar" | cut -d' ' -f1)"

echo "[build-agent] capturing toolchain + module provenance"
prov="$(docker run --rm -i --platform linux/arm64 "$GOLANG_IMAGE" sh -c '
  mkdir -p /w && cd /w && tar -xf - >/dev/null 2>&1 && cd gocat &&
  printf "%s|%s|%s" "$(go version | awk "{print \$3}")" \
    "$(sha256sum go.mod | cut -d" " -f1)" "$(sha256sum go.sum | cut -d" " -f1)"
' < "$work/gocat_src.tar")"
go_version="${prov%%|*}"; rest="${prov#*|}"; go_mod_sha="${rest%%|*}"; go_sum_sha="${rest#*|}"

echo "[build-agent] compiling windows/arm64 with a native arm64 Go toolchain"
docker run --rm -i --platform linux/arm64 "$GOLANG_IMAGE" sh -c '
  mkdir -p /w && cd /w && tar -xf - && cd gocat &&
  GOOS=windows GOARCH=arm64 go build -o /tmp/sandcat_arm64.exe -ldflags="-s -w" . &&
  cat /tmp/sandcat_arm64.exe
' < "$work/gocat_src.tar" > "$OUT_BIN"

if [ ! -s "$OUT_BIN" ]; then
  echo "[build-agent] ERROR: build produced no output" >&2
  rm -f "$OUT_BIN"
  exit 1
fi

sha="$(shasum -a 256 "$OUT_BIN" | cut -d' ' -f1)"
size="$(wc -c < "$OUT_BIN" | tr -d ' ')"
cat > "$OUT_DIR/provenance.json" <<JSON
{
  "output": "lab/qemu/images/windows11-arm64/agent/sandcat_arm64.exe",
  "sha256": "$sha",
  "bytes": $size,
  "caldera_image": "$CALDERA_IMAGE",
  "golang_image": "$GOLANG_IMAGE",
  "go_version": "$go_version",
  "gocat_source_tar_sha256": "$src_sha",
  "go_mod_sha256": "$go_mod_sha",
  "go_sum_sha256": "$go_sum_sha",
  "goos": "windows",
  "goarch": "arm64",
  "ldflags": "-s -w"
}
JSON

echo "[build-agent] built $OUT_BIN"
echo "[build-agent] sha256=$sha bytes=$size"
file "$OUT_BIN" || true
