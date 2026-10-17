#!/usr/bin/env bash

create_measurement_log_directory() {
  local artifact_root="$1"
  local results_root="$artifact_root/results"
  local diagnostics_root="$results_root/reviewer_runtime"
  if [[ -L "$results_root" || -L "$diagnostics_root" ]]; then
    printf '[release-check][FAIL] diagnostic directory is a symlink\n' >&2
    return 1
  fi
  mkdir -p "$diagnostics_root" || return
  mktemp -d "$diagnostics_root/measurement-XXXXXX"
}
