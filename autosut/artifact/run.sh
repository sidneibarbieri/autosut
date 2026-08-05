#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
source "$ROOT_DIR/scripts/python_env.sh"
PYTHON_BIN="$(autosut_resolve_python "$ROOT_DIR" "$ROOT_DIR/requirements-reviewer.txt")"

export PYTHONPATH="$ROOT_DIR/src${PYTHONPATH:+:$PYTHONPATH}"

fail() {
  printf '[artifact/run][FAIL] %s\n' "$*" >&2
  exit 1
}

if ! command -v docker >/dev/null 2>&1; then
  fail "Docker is required for the controlled replays but was not found on PATH"
fi

if ! docker_version="$(docker info --format '{{.ServerVersion}}' 2>&1)"; then
  printf '%s\n' "$docker_version" >&2
  fail "Docker is installed, but its daemon is not reachable"
fi
echo "[artifact/run] Docker daemon: $docker_version"

target_image="python:3.11-slim"
if ! docker image inspect "$target_image" >/dev/null 2>&1; then
  echo "[artifact/run] pulling target image $target_image..."
  docker pull "$target_image" || fail "could not pull target image $target_image"
fi

attacker_image="autosut/dmz-host:s28"
attacker_dockerfile="$ROOT_DIR/.docker/dmz-host/Dockerfile"
if ! docker image inspect "$attacker_image" >/dev/null 2>&1; then
  [[ -f "$attacker_dockerfile" ]] || fail \
    "missing attacker image $attacker_image and build recipe $attacker_dockerfile"
  echo "[artifact/run] building attacker image $attacker_image..."
  docker build \
    -t "$attacker_image" \
    -f "$attacker_dockerfile" \
    "$(dirname "$attacker_dockerfile")" \
    || fail "could not build attacker image $attacker_image"
fi

echo "[artifact/run] executing infrastructure smoke campaign..."
"$PYTHON_BIN" scripts/run_orchestrated_campaign.py 0.c0017

echo "[artifact/run] executing state-contract campaign..."
"$PYTHON_BIN" scripts/run_orchestrated_campaign.py 0.shadowray --fidelity surrogate

echo "[artifact/run] regenerating tables..."
"$PYTHON_BIN" scripts/generate_tables.py

echo "[artifact/run] done"
