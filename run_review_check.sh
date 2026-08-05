#!/usr/bin/env bash
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1
export PYTEST_DISABLE_PLUGIN_AUTOLOAD=1
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python3 "$ROOT_DIR/autosut/scripts/verify_artifact_manifest.py"   --root "$ROOT_DIR" --allow-runtime-state
cd "$ROOT_DIR/autosut"
bash run_review_check.sh
