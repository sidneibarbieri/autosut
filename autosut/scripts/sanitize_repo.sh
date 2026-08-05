#!/bin/bash
# sanitize_repo.sh - Safe repository sanitization helper (dry-run by default)
# Usage:
#   ./scripts/sanitize_repo.sh
#   ./scripts/sanitize_repo.sh --apply-temp
#   ./scripts/sanitize_repo.sh --apply-evidence-prune [--retain N]
#   ./scripts/sanitize_repo.sh --apply-artifact-prune

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
EVIDENCE_DIR="$ROOT_DIR/release/evidence"
APPLY_TEMP=false
APPLY_EVIDENCE_PRUNE=false
APPLY_ARTIFACT_PRUNE=false
RETAIN=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --apply-temp)
      APPLY_TEMP=true
      shift
      ;;
    --apply-evidence-prune)
      APPLY_EVIDENCE_PRUNE=true
      shift
      ;;
    --apply-artifact-prune)
      APPLY_ARTIFACT_PRUNE=true
      shift
      ;;
    --retain)
      RETAIN="${2:-1}"
      shift 2
      ;;
    --help|-h)
      echo "Usage: ./scripts/sanitize_repo.sh [--apply-temp] [--apply-evidence-prune] [--apply-artifact-prune] [--retain N]"
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

echo "======================================================================"
echo "AutoSUT Repository Sanitization (dry-run by default)"
echo "======================================================================"
echo "apply-temp: $APPLY_TEMP"
echo "apply-evidence-prune: $APPLY_EVIDENCE_PRUNE"
echo "apply-artifact-prune: $APPLY_ARTIFACT_PRUNE"
echo "retain-per-campaign: $RETAIN"

temp_files=$(find "$ROOT_DIR" -type f \( -name '.DS_Store' -o -name '*.tmp' -o -name '*.bak' -o -name '*.swp' \) | sort || true)
runtime_dirs=$(find "$ROOT_DIR" -type d \( -name '.vagrant' -o -name '__pycache__' -o -name '.pytest_cache' -o -name '.mypy_cache' -o -name '.ruff_cache' \) -prune | sort || true)

if [[ -n "$temp_files" ]]; then
  echo "Temporary files detected:"
  echo "$temp_files" | sed 's#^#  - #'
else
  echo "No temporary files detected under the repository root."
fi

if [[ -n "$runtime_dirs" ]]; then
  echo "Local runtime directories detected (excluded by the public packager):"
  echo "$runtime_dirs" | sed 's#^#  - #'
else
  echo "No local runtime directories detected under the repository root."
fi

echo ""
echo "Evidence retention check (keep latest run per campaign):"

stale_runs=""
if [[ -d "$EVIDENCE_DIR" ]]; then
  evidence_report="$(
    python3 - <<PY
from pathlib import Path
import re

evidence_dir = Path(r"$EVIDENCE_DIR")
retain = int("$RETAIN")
pattern = re.compile(r"^(?P<campaign>0\..+?)_\d{8}_\d{6}$")
groups = {}

for path in evidence_dir.iterdir():
    if not path.is_dir():
        continue
    match = pattern.match(path.name)
    if not match:
        continue
    groups.setdefault(match.group("campaign"), []).append(path)

for campaign in sorted(groups):
    runs = sorted(groups[campaign], key=lambda path: path.name, reverse=True)
    for index, run in enumerate(runs):
        label = "KEEP" if index < retain else "STALE"
        print(f"{label}\t{campaign}\t{run}")
PY
  )"

  last_campaign=""
  while IFS=$'\t' read -r label campaign run_dir; do
    [[ -n "$label" ]] || continue
    if [[ "$campaign" != "$last_campaign" ]]; then
      echo "  - $campaign retained:"
      last_campaign="$campaign"
    fi
    if [[ "$label" == "KEEP" ]]; then
      echo "      * $(basename "$run_dir")"
    else
      stale_runs+="$run_dir"$'\n'
    fi
  done <<< "$evidence_report"
else
  echo "  - evidence directory not found"
fi

if [[ -n "$stale_runs" ]]; then
  echo ""
  echo "Stale evidence runs (candidates):"
  echo "$stale_runs" | sed 's#^#  - #'
else
  echo ""
  echo "No stale evidence runs detected."
fi

echo ""
echo "Generated data/artifacts check:"

ARTIFACT_DIR="$ROOT_DIR/data/artifacts"
generated_artifacts=""
if [[ -d "$ARTIFACT_DIR" ]]; then
  generated_artifacts=$(find "$ARTIFACT_DIR" -maxdepth 1 -type f \( -name '*_default_campaign_*' -o -name '*_test_campaign_*' \) | sort || true)
  if [[ -n "$generated_artifacts" ]]; then
    count=$(echo "$generated_artifacts" | sed '/^$/d' | wc -l | tr -d ' ')
    echo "  generated artifact files: $count"
    printed=0
    while read -r artifact_file; do
      [[ -n "$artifact_file" ]] || continue
      echo "  - $artifact_file"
      printed=$((printed + 1))
      if [[ "$printed" -ge 20 ]]; then
        break
      fi
    done <<< "$generated_artifacts"
    if [[ "$count" -gt 20 ]]; then
      echo "  - ... (truncated)"
    fi
  else
    echo "  no generated campaign artifacts detected in data/artifacts"
  fi
else
  echo "  data/artifacts directory not found"
fi

if [[ "$APPLY_TEMP" == true || "$APPLY_EVIDENCE_PRUNE" == true || "$APPLY_ARTIFACT_PRUNE" == true ]]; then
  echo ""
  echo "Applying cleanup..."

  if [[ "$APPLY_TEMP" == true && -n "$temp_files" ]]; then
    while read -r file; do
      [[ -n "$file" ]] || continue
      rm -f "$file"
      echo "  removed temp: $file"
    done <<< "$temp_files"
  fi

  if [[ "$APPLY_EVIDENCE_PRUNE" == true && -n "$stale_runs" ]]; then
    while read -r run_dir; do
      [[ -n "$run_dir" ]] || continue
      rm -rf "$run_dir"
      echo "  removed stale evidence: $run_dir"
    done <<< "$stale_runs"
  fi

  if [[ "$APPLY_ARTIFACT_PRUNE" == true && -n "$generated_artifacts" ]]; then
    while read -r artifact_file; do
      [[ -n "$artifact_file" ]] || continue
      rm -f "$artifact_file"
      echo "  removed generated artifact: $artifact_file"
    done <<< "$generated_artifacts"
  fi

  echo "Cleanup complete."
else
  echo ""
  echo "Dry-run only. Use --apply-temp and/or --apply-evidence-prune to remove candidates."
fi
