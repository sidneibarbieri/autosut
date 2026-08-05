#!/bin/bash
# destroy.sh - Legacy wrapper
# Canonical teardown script: ./destroy_lab.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[destroy.sh] DEPRECATED: delegating to ./destroy_lab.sh"
"$SCRIPT_DIR/destroy_lab.sh" "$@"
