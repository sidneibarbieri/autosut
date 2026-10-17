#!/usr/bin/env bash
set -euo pipefail

autosut_python_has_reviewer_deps() {
  local candidate="$1"
  "$candidate" - <<'PY' >/dev/null 2>&1
import importlib

for module in ("pydantic", "yaml", "click", "pytest"):
    importlib.import_module(module)
PY
}

autosut_python_matches_exact_requirements() {
  local candidate="$1"
  local requirements_file="$2"
  "$candidate" - "$requirements_file" <<'PY' >/dev/null 2>&1
import importlib.metadata
import sys
from pathlib import Path


def exact_requirements(path: Path, seen: set[Path] | None = None):
    seen = set() if seen is None else seen
    path = path.resolve()
    if path in seen:
        return
    seen.add(path)
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith(("-r ", "--requirement ")):
            include = line.split(maxsplit=1)[1]
            yield from exact_requirements(path.parent / include, seen)
            continue
        if "==" not in line or ";" in line:
            raise ValueError(f"reviewer requirement is not an unconditional exact pin: {line}")
        name, expected = (part.strip() for part in line.split("==", 1))
        yield name, expected


if sys.version_info < (3, 10):
    raise SystemExit(1)
for package, expected_version in exact_requirements(Path(sys.argv[1])):
    if importlib.metadata.version(package) != expected_version:
        raise SystemExit(1)
PY
}

autosut_resolve_python() {
  local root_dir="$1"
  local requirements_file="${2:-$root_dir/requirements-reviewer.txt}"
  local venv_dir="${root_dir}/.venv"
  local venv_python="${venv_dir}/bin/python3"

  if [[ -x "$venv_python" ]]; then
    "$venv_python" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' || {
      echo "[python-env][FAIL] existing $venv_dir uses Python older than 3.10; recreate that environment" >&2
      return 1
    }
    if autosut_python_has_reviewer_deps "$venv_python" && \
       autosut_python_matches_exact_requirements "$venv_python" "$requirements_file"; then
      printf '%s\n' "$venv_python"
      return 0
    fi
    echo "[python-env] enforcing pinned reviewer environment at $venv_dir" >&2
    # Environments created by uv ship without pip.
    "$venv_python" -m pip --version >/dev/null 2>&1 || "$venv_python" -m ensurepip --upgrade >&2
    PIP_DISABLE_PIP_VERSION_CHECK=1 "$venv_python" -m pip install --upgrade -r "$requirements_file" >&2
    autosut_python_has_reviewer_deps "$venv_python" || return 1
    autosut_python_matches_exact_requirements "$venv_python" "$requirements_file" || return 1
    printf '%s\n' "$venv_python"
    return 0
  fi

  if command -v python3 >/dev/null 2>&1; then
    local system_python
    system_python="$(command -v python3)"
    "$system_python" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' || {
      echo "[python-env][FAIL] Python 3.10 or newer is required" >&2
      return 1
    }

    echo "[python-env] creating repo-local virtual environment at $venv_dir" >&2
    "$system_python" -m venv "$venv_dir" >&2
    PIP_DISABLE_PIP_VERSION_CHECK=1 "$venv_python" -m pip install -r "$requirements_file" >&2
    autosut_python_has_reviewer_deps "$venv_python" || return 1
    autosut_python_matches_exact_requirements "$venv_python" "$requirements_file" || return 1
    printf '%s\n' "$venv_python"
    return 0
  fi

  echo "[python-env][FAIL] python3 is required but was not found on PATH" >&2
  return 1
}
