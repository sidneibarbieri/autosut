#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"
source "$ROOT_DIR/scripts/python_env.sh"

campaign="${1:-0.c0011}"
PYTHON_BIN="$(autosut_resolve_python "$ROOT_DIR" "$ROOT_DIR/requirements-reviewer.txt")"
extra_args=()
if [[ $# -gt 0 ]]; then
  case "$1" in
    -h|--help)
      exec "$PYTHON_BIN" scripts/run_lab_campaign.py --help
      ;;
    --*)
      extra_args=("$@")
      ;;
    *)
      campaign="$1"
      shift
      extra_args=("$@")
      ;;
  esac
fi

cmd=("$PYTHON_BIN" scripts/run_lab_campaign.py --campaign "$campaign")
if [[ ${#extra_args[@]} -gt 0 ]]; then
  cmd+=("${extra_args[@]}")
fi

"${cmd[@]}"
