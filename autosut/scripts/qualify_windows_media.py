"""Qualify native FAT/ISO files without installing or booting Windows."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

MEDIA_TOOLS = ("qemu-img", "mformat", "mcopy", "mtype", "xorriso")
ROOT = Path(__file__).resolve().parents[1]


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--preflight-only", action="store_true")
    options = parser.parse_args(arguments)
    missing = [name for name in MEDIA_TOOLS if shutil.which(name) is None]
    if missing:
        parser.error("missing native media tools: " + ", ".join(missing))
    if options.preflight_only:
        print(json.dumps({"status": "ready", "scope": "media_files_only",
                          "qualified": False}))
        return 0
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/test_windows_base_builder.py",
         "-m", "windows_media", "-q", "-p", "no:cacheprovider"],
        cwd=ROOT, check=False,
        env={**os.environ, "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
             "PYTHONDONTWRITEBYTECODE": "1"},
    )
    if result.returncode == 0:
        print(json.dumps({"status": "passed", "scope": "media_files_only",
                          "qualified": True, "vm_execution": False}))
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
