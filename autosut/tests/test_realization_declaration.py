"""A technique that exercises a CVE surface must declare its realization.

The outcome helpers default to a generic primitive, which is correct for steps that
reproduce an effect without the originally targeted product. It would be wrong for a step
that drives a documented CVE, so those calls must say so explicitly. This test reads the
executor's own source and fails if such a call relies on the default.
"""

from __future__ import annotations

import ast
from pathlib import Path

EXECUTOR = (
    Path(__file__).resolve().parent.parent
    / "scripts" / "orchestrator" / "multi_host_executor.py"
)
OUTCOME_HELPERS = {"_outcome_success", "_outcome_failure"}


def _outcome_calls_in(function: ast.FunctionDef) -> list[ast.Call]:
    return [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in OUTCOME_HELPERS
    ]


def _cve_technique_functions(tree: ast.Module) -> list[ast.FunctionDef]:
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and "cve_" in node.name
    ]


def test_cve_techniques_declare_their_realization():
    tree = ast.parse(EXECUTOR.read_text(encoding="utf-8"))
    undeclared = [
        function.name
        for function in _cve_technique_functions(tree)
        for call in _outcome_calls_in(function)
        if not any(keyword.arg == "realization" for keyword in call.keywords)
    ]
    assert not undeclared, (
        "these CVE-exercising techniques rely on the default realization: "
        f"{sorted(set(undeclared))}"
    )


def test_the_default_realization_is_named_once():
    source = EXECUTOR.read_text(encoding="utf-8")
    # The choice is stated at a single auditable place rather than repeated inline.
    assert "DEFAULT_REALIZATION = Realization.generic_primitive" in source
    assert "realization: Realization = Realization.generic_primitive" not in source
