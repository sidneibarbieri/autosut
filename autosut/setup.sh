#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

cat <<'EOF'
[setup] root-level setup.sh is a compatibility wrapper.
[setup] The canonical validation path is:
  bash artifact/setup.sh
  bash artifact/run.sh
  bash artifact/validate.sh

[setup] Optional QEMU and Caldera helpers remain in the repository for
[setup] development and measurement, but they are not guaranteed to be green
[setup] in every checkout and should not be treated as the primary validation path.
EOF

exec bash artifact/setup.sh
