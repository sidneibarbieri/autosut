#!/usr/bin/env bash
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1
export PYTEST_DISABLE_PLUGIN_AUTOLOAD=1

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR/measurement/sut"
bash release_check.sh
cd "$ROOT_DIR"
python3 scripts/build_reviewer_dashboard.py
bash scripts/run_review_check.sh
