#!/bin/sh
# Release gate.
#
# Fail-fast validation of the AutoSUT public release surface. Exits with
# non-zero whenever any of the contracts is broken so reviewers and CI
# learn about issues immediately instead of after manual inspection.
#
# Contracts checked (each is an independent subcheck):
#
#   1. unit tests pass
#   2. historical records are explicitly non-qualifying
#   3. the bounded C0045 gate and RQ1--RQ4 claim ledger are regenerated
#   4. every required claim has safe, present evidence and a declared bound
#   5. the dashboard renders only the canonical ledger surface
#   6. release/subdetermination_proof.json is present, the cve_2021_41773
#      executable witness ran (both variants), and the two coincident witnesses
#      ran (pivot_demo OpenSSH<->Dropbear and web_demo Apache<->Nginx service
#      substitutions executed, declared==executed)
#   7. manuscript study macros match the selected consequence receipts
#
# Run from the project root::
#
#     bash scripts/run_review_check.sh
#
set -eu

# Keep regenerated reviewer outputs byte-stable. Callers may override this
# standard reproducible-build timestamp explicitly.
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1784332800}"
export PYTHONDONTWRITEBYTECODE=1
export PYTEST_DISABLE_PLUGIN_AUTOLOAD=1

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"

if [ -x "$PROJECT_ROOT/.venv/bin/python" ]; then
    PY="$PROJECT_ROOT/.venv/bin/python"
else
    PY="python3"
fi
step() {
    printf "[review-check] %s\n" "$*"
}

fail() {
    printf "[review-check] FAIL: %s\n" "$*" >&2
    exit 1
}

# ---------------------------------------------------------------------------
# 1. unit tests
# ---------------------------------------------------------------------------
step "running Python-path tests; native FAT/ISO checks use scripts/qualify_windows_media.py"
"$PY" -m pytest tests/ --tb=short -q -p no:cacheprovider -m 'not windows_media' \
    || fail "unit tests did not pass"

step "checking prospective campaign screening against frozen inputs"
"$PY" scripts/screen_consequence_population.py \
    || fail "prospective campaign screening report drifted"

step "auditing the 13 published corpus resource receipts"
resource_audit_dir="$(mktemp -d)"
trap 'rm -rf "$resource_audit_dir"' EXIT
"$PY" scripts/audit_corpus_resource_witnesses.py \
    --corpus release/corpus-suts-20261001-enterprise-r3 \
    --base-receipts release/experiments/corpus_resource_witnesses/2026-10-04-r2/base \
    --network-receipts release/experiments/corpus_resource_witnesses/2026-10-04-r2/network \
    --output "$resource_audit_dir/audit.json" \
    || fail "published corpus resource receipts failed independent audit"

step "auditing source-bound prepared-pair replay receipts"
for replay_evidence in \
    release/evidence/2026-10-01-joint-e2e-r6/0.c0010 \
    release/evidence/2026-10-01-joint-e2e-r6/0.c0026 \
    release/evidence/2026-10-01-joint-e2e-r6/0.shadowray \
    release/evidence/2026-10-05-shadowray-replay-r2
do
    "$PY" scripts/audit_prepared_pair_replay.py \
        --pair "$replay_evidence/prepared-inputs" \
        --evidence "$replay_evidence" \
        || fail "prepared-pair receipt audit failed: $replay_evidence"
done

step "validating historical evidence cannot enter current qualification"
"$PY" scripts/validate_historical_evidence_status.py >/dev/null \
    || fail "historical evidence status is incomplete or promotable"

step "measuring provenance of proposed SUT configurations"
"$PY" scripts/build_sut_configuration_evidence.py >/dev/null \
    || fail "SUT configuration provenance measurement failed"

step "validating self-contained C0045 planning and execution gates"
"$PY" scripts/run_arm_comparison.py >/dev/null \
    || fail "C0045 bounded experiment gate failed"

step "generating canonical RQ1--RQ4/C0045 claim ledger"
"$PY" scripts/generate_claim_evidence_ledger.py \
    || fail "claim-to-evidence ledger generation failed"

# ---------------------------------------------------------------------------
# 2. Canonical ledger and rendered claim surface
# ---------------------------------------------------------------------------
step "building dashboard from the canonical claim ledger"
"$PY" scripts/build_reviewer_dashboard.py \
    || fail "reviewer dashboard generation failed"

step "validating canonical claim ledger and dashboard surface"
"$PY" scripts/validate_claim_surface.py \
    || fail "canonical claim surface validation failed"

# ---------------------------------------------------------------------------
# 3. Subdetermination proof artifact present + cve executable + pivot coincident
# ---------------------------------------------------------------------------
step "validating subdetermination proof artifact"
"$PY" - <<'PYEOF' || fail "subdetermination proof validation failed (see message above)"
import json
import hashlib
import sys
from pathlib import Path

PROJECT_ROOT = Path(".").resolve()
artifact = PROJECT_ROOT / "release" / "subdetermination_proof.json"
if not artifact.exists():
    print("  release/subdetermination_proof.json missing "
          "(run scripts/build_subdetermination_artifact.py)", file=sys.stderr)
    sys.exit(1)
proofs = json.loads(artifact.read_text()).get("proofs", {})
exit_code = 0

def validate_execution_records(campaign_id, proof, expected_count,
                               require_seal=False):
    global exit_code
    records = proof.get("execution_runs", [])
    if len(records) != expected_count:
        print(f"  {campaign_id}: expected {expected_count} indexed execution "
              f"runs, found {len(records)}", file=sys.stderr)
        exit_code = 1
        return
    for record in records:
        for path_key, hash_key in (
            ("manifest_path", "manifest_sha256"),
            ("summary_path", "summary_sha256"),
        ):
            path = PROJECT_ROOT / record.get(path_key, "")
            if not path.is_file():
                print(f"  {campaign_id}: missing {path_key}: {path}",
                      file=sys.stderr)
                exit_code = 1
                continue
            observed = hashlib.sha256(path.read_bytes()).hexdigest()
            if observed != record.get(hash_key):
                print(f"  {campaign_id}: hash mismatch for {path}",
                      file=sys.stderr)
                exit_code = 1
        manifest_path = PROJECT_ROOT / record.get("manifest_path", "")
        if manifest_path.is_file():
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            for key in ("manifest_path", "summary_path", "campaign_state_path"):
                value = manifest.get(key)
                if value and Path(value).is_absolute():
                    print(f"  {campaign_id}: non-portable absolute {key}: {value}",
                          file=sys.stderr)
                    exit_code = 1
            run_dir = manifest_path.parent
            for relative_path, expected_hash in record.get(
                    "evidence_sha256", {}).items():
                evidence_path = run_dir / relative_path
                if not evidence_path.is_file():
                    print(f"  {campaign_id}: missing technique evidence: "
                          f"{evidence_path}", file=sys.stderr)
                    exit_code = 1
                    continue
                observed_hash = hashlib.sha256(
                    evidence_path.read_bytes()).hexdigest()
                if observed_hash != expected_hash:
                    print(f"  {campaign_id}: technique-evidence hash mismatch: "
                          f"{evidence_path}", file=sys.stderr)
                    exit_code = 1
            if not record.get("evidence_sha256"):
                print(f"  {campaign_id}: no per-technique evidence hashes",
                      file=sys.stderr)
                exit_code = 1
        if not record.get("mode_status_consistent"):
            print(f"  {campaign_id}: inconsistent mode/status record",
                  file=sys.stderr)
            exit_code = 1
        if not record.get("teardown_clean"):
            print(f"  {campaign_id}: unclean teardown record", file=sys.stderr)
            exit_code = 1
        if record.get("techniques_success") != record.get("techniques_total"):
            print(f"  {campaign_id}: incomplete execution record",
                  file=sys.stderr)
            exit_code = 1
        if (record.get("evidence_backed_successful")
                != record.get("techniques_total")):
            print(f"  {campaign_id}: successful techniques are not all "
                  "evidence-backed", file=sys.stderr)
            exit_code = 1
        containment_value = record.get("containment_path")
        if containment_value:
            containment = PROJECT_ROOT / containment_value
            if not containment.is_file():
                print(f"  {campaign_id}: missing containment evidence: "
                      f"{containment}", file=sys.stderr)
                exit_code = 1
            else:
                observed = hashlib.sha256(containment.read_bytes()).hexdigest()
                if observed != record.get("containment_sha256"):
                    print(f"  {campaign_id}: containment hash mismatch: "
                          f"{containment}", file=sys.stderr)
                    exit_code = 1
        if require_seal:
            containment = PROJECT_ROOT / record.get("containment_path", "")
            if not containment.is_file() or not record.get("containment_sealed"):
                print(f"  {campaign_id}: containment evidence is absent or "
                      "not SEALED", file=sys.stderr)
                exit_code = 1
for campaign_id in ("0.cve_2021_41773", "0.apt41_dust"):
    proof = proofs.get(campaign_id)
    if proof is None:
        print(f"  {campaign_id}: proof missing from artifact", file=sys.stderr)
        exit_code = 1
        continue
    if not proof.get("invariant_fingerprint"):
        print(f"  {campaign_id}: empty invariant_fingerprint", file=sys.stderr)
        exit_code = 1
    if len(proof.get("variants", [])) < 2:
        print(f"  {campaign_id}: fewer than 2 variants", file=sys.stderr)
        exit_code = 1
if not proofs.get("0.cve_2021_41773", {}).get("executable"):
    print("  0.cve_2021_41773: executable proof is not true "
          "(regenerate with docker up)", file=sys.stderr)
    exit_code = 1
else:
    validate_execution_records(
        "0.cve_2021_41773", proofs["0.cve_2021_41773"], 3
    )
# Coincident witnesses: an informative free-region service substitution is
# itself executed, across two service classes (SSH: OpenSSH<->Dropbear; edge
# HTTP: Apache<->Nginx). Existence needs >= 2 campaign-equivalent SUTs
# (canonical + >= 1 variant); both must run with declared == executed.
for cid in ("0.pivot_demo", "0.web_demo"):
    proof = proofs.get(cid)
    if proof is None:
        print(f"  {cid}: coincident-witness proof missing from artifact",
              file=sys.stderr)
        exit_code = 1
        continue
    if not proof.get("invariant_fingerprint"):
        print(f"  {cid}: empty invariant_fingerprint", file=sys.stderr)
        exit_code = 1
    if len(proof.get("variants", [])) < 1:
        print(f"  {cid}: no compatible variant", file=sys.stderr)
        exit_code = 1
    if not proof.get("executable"):
        print(f"  {cid}: coincident witness is not executable "
              "(regenerate with docker up)", file=sys.stderr)
        exit_code = 1
    else:
        validate_execution_records(cid, proof, 2, require_seal=True)
sys.exit(exit_code)
PYEOF

step "checking paper study macros against selected consequence receipts"
"$PY" scripts/render_review_evidence_macros.py --check \
    || fail "paper study macros differ from recorded evidence"

step "ALL GATES PASSED"
