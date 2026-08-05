#!/bin/bash
# Run the published JSON corpus and save consolidated results.

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

echo "=== STICKS Published Corpus Execution ==="
echo "Timestamp: $(date)"

mkdir -p results/exploratory results/frozen

CSV_FILE="results/frozen/corpus_results.csv"
echo "campaign_id,status,total_techniques,successful,failed,success_rate,timestamp" > "$CSV_FILE"

while IFS= read -r campaign; do
    echo ""
    echo "=== $campaign ==="

    if [[ ! -f "data/sut_profiles/${campaign}.yml" ]]; then
        echo "  SKIP: missing SUT profile data/sut_profiles/${campaign}.yml"
        echo "$campaign,skipped_missing_sut,0,0,0,0,$(date -Iseconds)" >> "$CSV_FILE"
        continue
    fi

    output_file="results/exploratory/${campaign}_output.txt"
    python3 scripts/run_campaign.py --campaign "$campaign" > "$output_file" 2>&1 || true

    total=$(grep "Total:" "$output_file" | awk '{print $2}')
    successful=$(grep "Successful:" "$output_file" | awk '{print $2}')
    failed=$(grep "Failed:" "$output_file" | awk '{print $2}')

    if [[ -n "$total" && -n "$successful" && -n "$failed" ]]; then
        success_rate=$(python3 - <<PY
total = int("$total")
successful = int("$successful")
print(f"{(successful * 100 / total) if total else 0:.1f}")
PY
)
        timestamp=$(date -Iseconds)
        echo "$campaign,executed,$total,$successful,$failed,$success_rate,$timestamp" >> "$CSV_FILE"
        echo "  Total: $total"
        echo "  Successful: $successful"
        echo "  Failed: $failed"
        echo "  Success Rate: ${success_rate}%"
    else
        echo "  ERROR: Could not parse results"
        echo "$campaign,parse_error,0,0,0,0,$(date -Iseconds)" >> "$CSV_FILE"
    fi
done < <(find campaigns -maxdepth 1 -type f -name '*.json' -exec basename {} .json \; | sort)

echo ""
echo "=== Corpus Summary ==="
echo "Results saved to: $CSV_FILE"
cat "$CSV_FILE"
