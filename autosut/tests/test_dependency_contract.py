from __future__ import annotations

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _active_lines(path: Path) -> list[str]:
    return [
        line.split("#", 1)[0].strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.split("#", 1)[0].strip()
    ]


def test_reviewer_requirements_are_exact_and_minimal() -> None:
    lines = _active_lines(PROJECT_ROOT / "requirements-reviewer.txt")
    assert lines == [
        "pydantic==2.13.4",
        "PyYAML==6.0.3",
        "click==8.4.1",
        "pytest==9.0.3",
        "annotated-types==0.7.0",
        "colorama==0.4.6",
        "exceptiongroup==1.3.1",
        "iniconfig==2.3.0",
        "packaging==26.2",
        "pluggy==1.6.0",
        "pydantic-core==2.46.4",
        "Pygments==2.20.0",
        "tomli==2.4.1",
        "typing-extensions==4.16.0",
        "typing-inspection==0.4.2",
    ]
    assert all(
        "==" in line and not any(op in line for op in (">=", "<=", "~=", ">", "<"))
        for line in lines
    )


def test_compatibility_and_dev_requirements_reference_reviewer_lock() -> None:
    assert _active_lines(PROJECT_ROOT / "requirements.txt") == ["-r requirements-reviewer.txt"]
    dev_lines = _active_lines(PROJECT_ROOT / "requirements-dev.txt")
    assert dev_lines[0] == "-r requirements-reviewer.txt"
    assert all("==" in line for line in dev_lines[1:])


def test_reviewer_entrypoints_use_pinned_requirements() -> None:
    entrypoints = [
        "measurement/sut/release_check.sh",
        "artifact/setup.sh",
        "artifact/run.sh",
        "artifact/validate.sh",
        "run_vm_backed_campaign.sh",
        "scripts/setup.sh",
    ]
    for relative in entrypoints:
        text = (PROJECT_ROOT / relative).read_text(encoding="utf-8")
        assert "requirements-reviewer.txt" in text, relative


def test_declared_python_floor_matches_source_syntax() -> None:
    pyproject = (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'requires-python = ">=3.10"' in pyproject
    assert "Python :: 3.8" not in pyproject
    assert "Python :: 3.9" not in pyproject


def test_review_gates_disable_untracked_pytest_plugins() -> None:
    for relative in (
        "run_review_check.sh",
        "measurement/sut/release_check.sh",
        "scripts/run_review_check.sh",
    ):
        text = (PROJECT_ROOT / relative).read_text(encoding="utf-8")
        assert "PYTEST_DISABLE_PLUGIN_AUTOLOAD=1" in text, relative
