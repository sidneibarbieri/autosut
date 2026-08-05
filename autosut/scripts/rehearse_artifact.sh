#!/bin/sh
# Artifact rehearsal — prove the reviewer-facing surface rebuilds from a clean
# working tree.
#
# SAFETY: this script regenerates only DERIVED state (the subdetermination proof artifact,
# the dashboard, LaTeX aux, __pycache__). It NEVER deletes captured evidence
# (release/evidence/, release/golden_runs.json): those come from live
# Caldera/Docker/VM runs and cannot be regenerated without the substrate.
# Wiping them would silently destroy the artifact.
#
# Full pass requires the Docker daemon (the executable proof reconstructs
# CVE-2021-41773 live). Without Docker the proof falls back to structural and
# the release gate's subdetermination check (executable==true) will fail by design.
#
# Run from anywhere:  sh scripts/rehearse_artifact.sh
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
PY="${PY:-python3}"

echo "[rehearse] cleaning DERIVED/TEMP only (captured golden evidence preserved)"
find . -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null || true
rm -f /tmp/latexmk_*.log /tmp/rehearse_paper.log 2>/dev/null || true

echo "[rehearse] 1/5 regenerate subdetermination proof artifact"
"$PY" scripts/build_subdetermination_artifact.py

echo "[rehearse] 2/5 rebuild reviewer dashboard"
"$PY" scripts/build_reviewer_dashboard.py >/dev/null

echo "[rehearse] 3/5 fast test suite (fail-fast pre-check)"
"$PY" -m pytest -q -k "not execute_for_real" >/dev/null

echo "[rehearse] 4/5 release gate (8 fail-fast checks)"
sh scripts/run_review_check.sh >/dev/null

echo "[rehearse] 5/5 compile paper (if adjacent paper/ present)"
if [ -f "$ROOT/../paper/main.tex" ] && command -v latexmk >/dev/null 2>&1; then
    if ( cd "$ROOT/../paper" && latexmk -pdf -interaction=nonstopmode main.tex \
            >/tmp/rehearse_paper.log 2>&1 ); then
        echo "[rehearse] paper compiled (paper/main.pdf)"
    else
        echo "[rehearse] WARN: paper compile issues (see /tmp/rehearse_paper.log)" >&2
    fi
else
    echo "[rehearse] paper/ not adjacent or latexmk missing; skipping compile"
fi

echo "[rehearse] DONE — reviewer surface rebuilt from clean derived state"
