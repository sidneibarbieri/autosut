#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "[artifact/teardown] cleaning python caches..."
find . -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
find . -type f -name '*.pyc' -delete 2>/dev/null || true

if [[ -x "./scripts/destroy_lab.sh" ]]; then
  echo "[artifact/teardown] invoking lab teardown helper..."
  ./scripts/destroy_lab.sh >/dev/null 2>&1 || true
fi

echo "[artifact/teardown] done"
