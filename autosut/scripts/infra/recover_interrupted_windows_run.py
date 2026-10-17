"""Inspect or dispose of two explicit overlays left by an interrupted Windows run."""

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from infrastructure.windows_crash_recovery import recover_interrupted_run  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--credential-directory", required=True)
    parser.add_argument("--dispose", action="store_true")
    arguments = parser.parse_args()
    receipt = recover_interrupted_run(
        arguments.evidence_root, arguments.run_id, arguments.credential_directory,
        dispose=arguments.dispose,
    )
    action = "removed" if arguments.dispose else "would remove"
    print(f"{action}: {len(receipt.removed_overlays)} run-owned overlays")
    print(receipt.model_dump_json(indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
