#!/usr/bin/env bash
# Reviewer front door: bash run.sh help lists one command per question.
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
case "${1:-help}" in
  replay|witness|all)
    source "$ROOT_DIR/autosut/scripts/python_env.sh"
    PYTHON_BIN="$(autosut_resolve_python "$ROOT_DIR/autosut" "$ROOT_DIR/autosut/requirements-reviewer.txt")" || exit 2
    exec "$PYTHON_BIN" "$ROOT_DIR/autosut/scripts/run_reviewer_supervised.py" "$@"
    ;;
  *) exec bash "$ROOT_DIR/autosut/run.sh" "$@" ;;
esac
