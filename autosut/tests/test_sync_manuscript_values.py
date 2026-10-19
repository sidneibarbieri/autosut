from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = PROJECT_ROOT / "scripts" / "sync_manuscript_values.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("sync_manuscript_values", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_write_report_emits_json_and_markdown(tmp_path: Path) -> None:
    module = _load_module()
    original_json = module.OUTPUT_JSON
    original_md = module.OUTPUT_MD
    module.OUTPUT_JSON = tmp_path / "manuscript_values_sync.json"
    module.OUTPUT_MD = tmp_path / "MANUSCRIPT_VALUES_SYNC.md"

    try:
        module.write_report(
            module.SyncResult(
                status="updated",
                details="Paper values.tex replaced from measurement output.",
                macros_written=133,
            )
        )
    finally:
        module.OUTPUT_JSON = original_json
        module.OUTPUT_MD = original_md

    report_text = (tmp_path / "MANUSCRIPT_VALUES_SYNC.md").read_text(encoding="utf-8")
    assert "- Status: `updated`" in report_text
    assert "- Macros written: `133`" in report_text


def test_write_report_can_target_runtime_directory(tmp_path: Path) -> None:
    module = _load_module()
    output_json, output_md = module.write_report(
        module.SyncResult(status="in_sync", details="values match", macros_written=2),
        tmp_path / "runtime",
    )

    assert output_json == tmp_path / "runtime" / "manuscript_values_sync.json"
    assert output_md == tmp_path / "runtime" / "MANUSCRIPT_VALUES_SYNC.md"
    assert output_json.is_file() and output_md.is_file()


def test_extract_macros_parses_newcommand() -> None:
    module = _load_module()
    text = r"\newcommand{\fooCount}{42}\newcommand{\barPct}{12.3}"
    macros = module.extract_macros(text)
    assert macros == {"fooCount": "42", "barPct": "12.3"}


def test_extract_used_macros_finds_references() -> None:
    module = _load_module()
    text = r"We measured \fooCount{} items, of which \barPct\% were valid."
    used = module.extract_used_macros(text)
    assert "fooCount" in used
    assert "barPct" in used


def _write_paper(tmp_path: Path, values: str, main: str) -> Path:
    paper_dir = tmp_path / "paper"
    (paper_dir / "results").mkdir(parents=True)
    (paper_dir / "results" / "values.tex").write_text(values, encoding="utf-8")
    (paper_dir / "main.tex").write_text(main, encoding="utf-8")
    return paper_dir


def test_check_reports_used_macro_value_drift_without_writing(tmp_path: Path) -> None:
    module = _load_module()
    measurement_values = tmp_path / "measured.tex"
    measurement_values.write_text(r"\newcommand{\fooCount}{42}" + "\n", encoding="utf-8")
    paper_dir = _write_paper(
        tmp_path,
        r"\newcommand{\fooCount}{41}" + "\n",
        r"Measured \fooCount{} items.",
    )
    before = (paper_dir / "results" / "values.tex").read_bytes()
    original_measurement_values = module.MEASUREMENT_VALUES
    module.MEASUREMENT_VALUES = measurement_values

    try:
        result = module.sync_paper(paper_dir, check=True)
    finally:
        module.MEASUREMENT_VALUES = original_measurement_values

    assert result.status == "out_of_sync"
    assert "fooCount" in result.details
    assert (paper_dir / "results" / "values.tex").read_bytes() == before


def test_check_accepts_matching_used_macros_and_preserves_extra_comments(
    tmp_path: Path,
) -> None:
    module = _load_module()
    measurement_values = tmp_path / "measured.tex"
    measurement_values.write_text(r"\newcommand{\fooCount}{42}" + "\n", encoding="utf-8")
    paper_dir = _write_paper(
        tmp_path,
        "% manuscript note\n" + r"\newcommand{\fooCount}{42}" + "\n",
        r"Measured \fooCount{} items.",
    )
    before = (paper_dir / "results" / "values.tex").read_bytes()
    original_measurement_values = module.MEASUREMENT_VALUES
    module.MEASUREMENT_VALUES = measurement_values

    try:
        result = module.sync_paper(paper_dir, check=True)
    finally:
        module.MEASUREMENT_VALUES = original_measurement_values

    assert result.status == "current"
    assert (paper_dir / "results" / "values.tex").read_bytes() == before


def test_check_includes_figure_macro_uses_but_not_values_definitions(
    tmp_path: Path,
) -> None:
    module = _load_module()
    measurement_values = tmp_path / "measured.tex"
    measurement_values.write_text(
        r"\newcommand{\figurePct}{12.3}" + "\n" + r"\newcommand{\unusedCount}{9}" + "\n",
        encoding="utf-8",
    )
    paper_dir = _write_paper(
        tmp_path,
        r"\newcommand{\figurePct}{12.2}" + "\n" + r"\newcommand{\unusedCount}{8}" + "\n",
        r"\input{results/values.tex}\input{figures/chart}",
    )
    (paper_dir / "figures").mkdir()
    (paper_dir / "figures" / "chart.tex").write_text(
        r"Figure value: \figurePct{}.", encoding="utf-8"
    )
    original_measurement_values = module.MEASUREMENT_VALUES
    module.MEASUREMENT_VALUES = measurement_values

    try:
        result = module.sync_paper(paper_dir, check=True)
    finally:
        module.MEASUREMENT_VALUES = original_measurement_values

    assert result.status == "out_of_sync"
    assert "figurePct" in result.details
    assert "unusedCount" not in result.details
