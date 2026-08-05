#!/usr/bin/env python3
"""STICKS SUT profile wrapper."""

import os
import sys


def _bootstrap_environment() -> None:
    project_root = os.path.abspath(os.path.dirname(__file__))
    os.chdir(project_root)

    if project_root not in sys.path:
        sys.path.insert(0, project_root)

    src = os.path.join(project_root, "src")
    if src not in sys.path:
        sys.path.insert(0, src)


def main() -> int:
    _bootstrap_environment()

    from src.apply_sut_profile import main as runner_main

    return runner_main()


if __name__ == "__main__":
    raise SystemExit(main())
