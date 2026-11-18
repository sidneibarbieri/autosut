#!/usr/bin/env bash
# Single front door for reviewers. Every path below is one command run from this
# directory; the pinned Python environment is created on first use and every
# container the Docker paths need is started and removed by the command itself.
set -uo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"
export PYTHONUNBUFFERED=1

usage() {
  cat <<'EOF'
AutoSUT -- one command per question.  Usage: ./run.sh <command> [options]

  command        what it establishes                                time      needs
  -------------  -------------------------------------------------  --------  -----------------------
  demo           the environment-semantics gap, read from the        1 s       python3 >= 3.10
                 generated study values (nothing recomputed)
  review         offline gate: manifest, measurement pipeline from   1.5 min   python3 >= 3.10
                 frozen snapshots, claim ledger, dashboard, tests
  doctor         read-only host check for the Docker paths, printing 1 s       -
                 the exact fix for anything that would stop them
  witness        executes CVE-2021-41773 in two SUT variants that    75 s      Docker daemon, network
                 share one fixed-evidence fingerprint (RQ4)                    for the first image pull
  replay         every implemented campaign/SUT pair replayed in     25 min    Docker daemon, network
                 Docker, one isolated namespace per campaign; prints           for the first image pull
                 PASS/PARTIAL/FAIL per pair and exits non-zero unless
                 every pair passes, which this release does not claim
  windows-media  creates and checks real FAT/ISO media (no VM boot)  < 1 min   qemu-img, mtools, xorriso
  workbench      local planning interface (planning only)            -         python3 >= 3.10
  dashboard      serves the evidence dashboard on 127.0.0.1:8765     -         python3
  all            demo + review + doctor + witness                    ~3 min    as for witness

Options:
  replay [--campaign ID ...]   default: all implemented campaigns (./run.sh replay --list)
  doctor [--path review|replay|windows-media|all]

Times were measured once on an Apple-silicon macOS host with colima, images
already pulled; a first run also downloads them. The replay ends 9 PASS,
10 PARTIAL, 1 FAIL on that host, and every namespace is removed afterwards.
Fresh replay evidence goes to release/evidence/_reviewer_runs/ and never
replaces the released claim ledger. What the replay does NOT establish: qualification of the current
implementation, technique fidelity, or a qualified pair for every public
campaign (see README, "Full Docker Replay").
EOF
}

python_bin() {
  source "$ROOT_DIR/scripts/python_env.sh"
  autosut_resolve_python "$ROOT_DIR" "$ROOT_DIR/requirements-reviewer.txt"
}

banner() { echo; echo "==> $*"; }

# Inside the public package the root wrapper adds the package-manifest and
# public-surface gates around the same review; use it when present.
packaged_review_wrapper() {
  local parent
  parent="$(cd "$ROOT_DIR/.." && pwd)"
  if [[ -f "$parent/ARTIFACT_MANIFEST.md" && -f "$parent/run_review_check.sh" ]]; then
    printf '%s\n' "$parent/run_review_check.sh"
  fi
}

cmd_demo() { "$(python_bin)" scripts/demo.py "$@"; }
cmd_doctor() {
  if [[ $# -eq 0 ]]; then set -- --path replay; fi
  "$(python_bin)" scripts/doctor.py "$@"
}
cmd_workbench() { "$(python_bin)" scripts/run_environment_workbench.py "$@"; }

cmd_review() {
  local python wrapper
  python="$(python_bin)" || return 1
  wrapper="$(packaged_review_wrapper)"
  if [[ -n "$wrapper" ]]; then
    bash "$wrapper"
  else
    bash run_review_check.sh
  fi
}

cmd_replay() {
  local python
  python="$(python_bin)" || return 1
  "$python" scripts/run_all_orchestrated_campaigns.py \
    --isolate-campaigns --campaign-timeout-seconds 1200 "$@"
}

cmd_witness() {
  local python
  python="$(python_bin)" || return 1
  "$python" scripts/prove_subdetermination.py 0.cve_2021_41773 --variants 2 --execute "$@"
}

cmd_windows_media() {
  local python
  python="$(python_bin)" || return 1
  "$python" scripts/qualify_windows_media.py --preflight-only && \
    "$python" scripts/qualify_windows_media.py "$@"
}

cmd_dashboard() {
  # Serve the package root: the dashboard links to evidence files outside its folder.
  local serve_root="$ROOT_DIR" page="release/dashboard/"
  if [[ -n "$(packaged_review_wrapper)" ]]; then
    serve_root="$(cd "$ROOT_DIR/.." && pwd)"; page="$(basename "$ROOT_DIR")/release/dashboard/"
  fi
  echo "Evidence dashboard: http://127.0.0.1:8765/$page   (Ctrl-C to stop)"
  python3 -m http.server 8765 --bind 127.0.0.1 --directory "$serve_root"
}

cmd_all() {
  local failed=()
  banner "demo";   cmd_demo   || failed+=(demo)
  banner "review"; cmd_review || failed+=(review)
  banner "doctor"; if cmd_doctor --path replay; then
    banner "witness (RQ4)"; cmd_witness "$@" || failed+=(witness)
  else
    failed+=(doctor); echo "witness skipped: apply the fix printed above, then ./run.sh witness" >&2
  fi
  echo
  # ${failed[*]-} keeps an empty array safe under set -u on bash 3.2 (macOS).
  if [[ -z "${failed[*]-}" ]]; then
    echo "==> all passed: demo, review, doctor, witness"
  else
    echo "==> failed: ${failed[*]}"; return 1
  fi
}

main() {
  local command="${1:-help}"
  [[ $# -gt 0 ]] && shift
  case "$command" in
    demo|review|doctor|replay|witness|workbench|dashboard|all) "cmd_$command" "$@" ;;
    windows-media) cmd_windows_media "$@" ;;
    help|-h|--help) usage ;;
    *) echo "unknown command: $command" >&2; usage >&2; return 2 ;;
  esac
}

# Sourcing defines the commands without running one (tests/test_front_door.py).
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
