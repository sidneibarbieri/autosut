#!/bin/sh
# Artifact-evaluation smoke test (~5 minutes).
#
# Demonstrates four things in sequence:
#
#   1. The release gate is green on a fresh checkout.
#   2. The orchestrator can re-execute the canonical CVE-real reference
#      campaign end-to-end (0.cve_2021_41773 — Apache 2.4.49 path traversal),
#      producing fresh evidence under release/evidence/.
#   3. The curator promotes the freshly produced run as the canonical
#      evidence entry for that campaign without disturbing the other entries.
#   4. The release gate is still green after the re-curation.
#
# Exit code 0 means the artifact is functional. Anything else surfaces the
# failed contract verbatim.
#
# Usage (from project root)::
#
#     bash scripts/artifact_smoke.sh
#
set -eu

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"

if [ -x "$PROJECT_ROOT/.venv/bin/python" ]; then
    PY="$PROJECT_ROOT/.venv/bin/python"
else
    PY="python3"
fi

step() {
    printf "[smoke] %s\n" "$*"
}

step "1/4 Initial release gate check"
bash run_review_check.sh

step "2/4 Re-execute the canonical CVE-real reference (~ 45 s)"
"$PY" scripts/run_orchestrated_campaign.py 0.cve_2021_41773

step "3/4 Re-curate: promote the fresh run as canonical campaign evidence"
"$PY" scripts/curate_evidence.py --apply >/dev/null
"$PY" scripts/build_reviewer_dashboard.py >/dev/null

step "4/4 Final release gate check"
bash run_review_check.sh

step "PASS — artifact functional end-to-end."
printf "[smoke]\n"
printf "[smoke] Next steps for a deeper evaluation:\n"
printf "[smoke]   - Inspect release/golden_runs.json\n"
printf "[smoke]   - Run a second campaign: python scripts/run_orchestrated_campaign.py 0.pivot_demo\n"
printf "[smoke]   - Open release/dashboard/index.html in a browser\n"
printf "[smoke]   - Read REVIEWER_GUIDE.md\n"
