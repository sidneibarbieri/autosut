#!/usr/bin/env bash
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1
export PYTEST_DISABLE_PLUGIN_AUTOLOAD=1

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ "${PAPER_DIR+x}" == "x" ]]; then
  if [[ ! -d "$PAPER_DIR" ]]; then
    printf '[review-check][FAIL] explicit PAPER_DIR is not a directory: %s\n' \
      "$PAPER_DIR" >&2
    exit 1
  fi
  PAPER_DIR="$(cd "$PAPER_DIR" && pwd -P)"
  export PAPER_DIR
fi
cd "$ROOT_DIR/measurement/sut"
bash release_check.sh
cd "$ROOT_DIR"

# Use the reviewer virtual environment when it exists, matching
# scripts/run_review_check.sh. A bare "python3" is the system interpreter, which
# on a clean host carries none of the pinned dependencies.
if [ -x "$ROOT_DIR/.venv/bin/python" ]; then
  PY="$ROOT_DIR/.venv/bin/python"
else
  PY="python3"
fi
"$PY" scripts/build_orchestrated_batch_values.py
"$PY" scripts/publish_study_values.py
"$PY" scripts/build_reviewer_dashboard.py
"$PY" scripts/validate_dashboard_links.py
bash scripts/run_review_check.sh
