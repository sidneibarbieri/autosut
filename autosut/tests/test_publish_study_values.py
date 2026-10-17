from __future__ import annotations

import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _run(source: Path, output: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "scripts/publish_study_values.py",
            "--source",
            str(source),
            "--output",
            str(output),
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )


def test_publisher_copies_a_nonempty_macro_surface(tmp_path: Path):
    source = tmp_path / "measurement-values.tex"
    output = tmp_path / "release" / "study_values.tex"
    source.write_text("\\newcommand{\\measuredValue}{7}\n", encoding="utf-8")

    result = _run(source, output)

    assert result.returncode == 0, result.stderr
    assert output.read_text(encoding="utf-8") == source.read_text(encoding="utf-8")


def test_publisher_rejects_an_empty_macro_surface(tmp_path: Path):
    source = tmp_path / "measurement-values.tex"
    output = tmp_path / "release" / "study_values.tex"
    source.write_text("% no generated values\n", encoding="utf-8")

    result = _run(source, output)

    assert result.returncode != 0
    assert "no LaTeX macros" in result.stderr
