#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
source "$ROOT_DIR/scripts/python_env.sh"
PYTHON_BIN="$(autosut_resolve_python "$ROOT_DIR" "$ROOT_DIR/requirements-reviewer.txt")"

export PYTHONPATH="$ROOT_DIR/src${PYTHONPATH:+:$PYTHONPATH}"

SMOKE_CAMPAIGN="0.c0017"
CONTRACT_CAMPAIGN="0.shadowray"
SESSION_FILE="release/evidence/_reviewer_runs/latest-smoke-session.json"

if [[ ! -f "$SESSION_FILE" ]]; then
  echo "[artifact/validate] missing reviewer session: $SESSION_FILE" >&2
  echo "[artifact/validate] run artifact/run.sh immediately before validation" >&2
  exit 1
fi

latest_run_dir="$("$PYTHON_BIN" - "$SESSION_FILE" "$SMOKE_CAMPAIGN" <<'PY'
import json
import sys
from pathlib import Path

session = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
print(session.get("campaign_runs", {}).get(sys.argv[2], ""))
PY
)"

if [[ -z "$latest_run_dir" ]]; then
  echo "[artifact/validate] missing evidence directory for $SMOKE_CAMPAIGN" >&2
  exit 1
fi

latest_summary="$latest_run_dir/summary.json"
latest_manifest="$latest_run_dir/manifest.json"
latest_rubric="$latest_run_dir/fidelity_report.json"
latest_state="$latest_run_dir/campaign_state.json"

if [[ ! -f "$latest_summary" ]]; then
  echo "[artifact/validate] missing summary for $SMOKE_CAMPAIGN" >&2
  exit 1
fi

if [[ ! -f "$latest_manifest" ]]; then
  echo "[artifact/validate] missing manifest for $SMOKE_CAMPAIGN" >&2
  exit 1
fi

if [[ ! -f "$latest_rubric" ]]; then
  echo "[artifact/validate] missing fidelity rubric for $SMOKE_CAMPAIGN" >&2
  exit 1
fi

if [[ ! -f "$latest_state" ]]; then
  echo "[artifact/validate] missing campaign state ledger for $SMOKE_CAMPAIGN" >&2
  exit 1
fi

"$PYTHON_BIN" - "$latest_run_dir" <<'PY'
import json
import sys
from pathlib import Path

latest_dir = Path(sys.argv[1])
summary_path = latest_dir / "summary.json"
manifest_path = latest_dir / "manifest.json"
rubric_path = latest_dir / "fidelity_report.json"
state_path = latest_dir / "campaign_state.json"

summary = json.loads(summary_path.read_text())
manifest = json.loads(manifest_path.read_text())
rubric = json.loads(rubric_path.read_text())
from scripts.orchestrator.campaign_state import CampaignStateLedger, validate_ledger
ledger = CampaignStateLedger.model_validate_json(state_path.read_text())

required_summary_keys = {
    "campaign_id", "total_techniques", "successful",
    "fidelity_distribution", "evidence_directory",
}
required_manifest_keys = {
    "campaign_id", "run_id", "timestamp", "techniques",
    "manifest_path", "summary_path",
}
required_rubric_keys = {"campaign_id", "run_id", "summary", "techniques"}

missing_summary = sorted(required_summary_keys - set(summary))
missing_manifest = sorted(required_manifest_keys - set(manifest))
missing_rubric = sorted(required_rubric_keys - set(rubric))

if missing_summary:
    raise SystemExit(f"missing summary keys: {missing_summary}")
if missing_manifest:
    raise SystemExit(f"missing manifest keys: {missing_manifest}")
if missing_rubric:
    raise SystemExit(f"missing rubric keys: {missing_rubric}")

if summary["campaign_id"] != "0.c0017" or manifest["campaign_id"] != "0.c0017":
    raise SystemExit("smoke path must validate campaign 0.c0017")

if summary["successful"] != summary["total_techniques"]:
    raise SystemExit("smoke campaign did not complete every planned step")

if len(manifest["techniques"]) != summary["total_techniques"]:
    raise SystemExit("manifest technique count does not match summary")

rubric_summary = rubric["summary"]
if rubric_summary.get("consistent") != rubric_summary.get("total"):
    raise SystemExit("fidelity rubric has mismatches")

violations = validate_ledger(ledger)
if violations:
    raise SystemExit(f"campaign-state violations: {violations}")

print(f"[artifact/validate] summary: {summary_path}")
print(f"[artifact/validate] manifest: {manifest_path}")
print(f"[artifact/validate] rubric: {rubric_path}")
print(f"[artifact/validate] campaign state: {state_path}")
print("[artifact/validate] smoke evidence OK")
PY

"$PYTHON_BIN" scripts/validate_semantic_slice.py

archive_root="release/evidence/_reviewer_runs"
mkdir -p "$archive_root"

# ``artifact/run.sh`` deliberately executes both the smallest campaign replay
# and the state-contract replay. They are reviewer-generated runtime state,
# not released golden evidence. Move only the paths bound into this session;
# never infer a target from a timestamp or directory glob.
for campaign in "$SMOKE_CAMPAIGN" "$CONTRACT_CAMPAIGN"; do
  while IFS= read -r run_dir; do
    [[ -n "$run_dir" ]] || continue
    archive_dest="$archive_root/$(basename "$run_dir")"
    if [[ -e "$archive_dest" ]]; then
      suffix=1
      while [[ -e "${archive_dest}_${suffix}" ]]; do
        suffix=$((suffix + 1))
      done
      archive_dest="${archive_dest}_${suffix}"
    fi
    mv "$run_dir" "$archive_dest"
    echo "[artifact/validate] archived reviewer evidence: $archive_dest"
  done < <("$PYTHON_BIN" - "$SESSION_FILE" "$campaign" <<'PY'
import json
import sys
from pathlib import Path

session = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
run = Path(session.get("campaign_runs", {}).get(sys.argv[2], ""))
if not run:
    raise SystemExit(f"session has no run for {sys.argv[2]}")
if run.parent != Path("release/evidence"):
    raise SystemExit(f"session path escapes evidence root: {run}")
print(run.as_posix())
PY
)
done

rm -f "$SESSION_FILE"

package_root="$(dirname "$ROOT_DIR")"
package_manifest="$package_root/ARTIFACT_MANIFEST.md"
if [[ -f "$package_manifest" ]]; then
  "$PYTHON_BIN" scripts/verify_artifact_manifest.py \
    --root "$package_root" \
    --allow-runtime-state
fi

echo "[artifact/validate] done"
