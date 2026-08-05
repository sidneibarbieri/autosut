#!/usr/bin/env python3
"""Campaign runner wrapper for direct in-process execution."""

import os
import sys


def _bootstrap_environment() -> None:
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    os.chdir(project_root)

    src = os.path.join(project_root, "src")
    if src not in sys.path:
        sys.path.insert(0, src)


def main() -> None:
    _bootstrap_environment()

    from executors.registry_initializer import initialize_registry
    from runners.campaign_runner import main as runner_main

    initialize_registry()
    runner_main()


if __name__ == "__main__":
    main()
