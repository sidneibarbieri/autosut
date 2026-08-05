#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "[artifact/setup] resolving pinned reviewer environment..."
source "$ROOT_DIR/scripts/python_env.sh"
PYTHON_BIN="$(autosut_resolve_python "$ROOT_DIR" "$ROOT_DIR/requirements-reviewer.txt")"

echo "[artifact/setup] validating imports..."
PYTHONPATH="$ROOT_DIR/src${PYTHONPATH:+:$PYTHONPATH}" "$PYTHON_BIN" -c "import loaders.campaign_loader; import runners.campaign_runner"

if command -v vagrant >/dev/null 2>&1; then
  echo "[artifact/setup] vagrant detected"
else
  echo "[artifact/setup] vagrant not detected; optional lab helpers may be unavailable"
fi

if command -v qemu-system-aarch64 >/dev/null 2>&1; then
  echo "[artifact/setup] qemu detected"
else
  echo "[artifact/setup] qemu not detected; optional qemu helpers may be unavailable"
fi

echo "[artifact/setup] done"
