from __future__ import annotations

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
APT_GUARD = PROJECT_ROOT / "lab" / "vagrant" / "shared" / "apt_guard.sh"
BASE_SCRIPT = PROJECT_ROOT / "lab" / "vagrant" / "shared" / "base.sh"
ATTACKER_SCRIPT = PROJECT_ROOT / "lab" / "vagrant" / "shared" / "attacker.sh"
CALDERA_SCRIPT = PROJECT_ROOT / "lab" / "vagrant" / "shared" / "caldera.sh"
CALDERA_VAGRANTFILE = PROJECT_ROOT / "lab" / "vagrant" / "caldera" / "Vagrantfile"
CALDERA_RUNTIME_REQUIREMENTS = (
    PROJECT_ROOT / "lab" / "vagrant" / "shared" / "caldera-runtime-requirements.txt"
)
UP_LAB_SCRIPT = PROJECT_ROOT / "scripts" / "up_lab.sh"
DESTROY_LAB_SCRIPT = PROJECT_ROOT / "scripts" / "destroy_lab.sh"
APPLY_SUT_PROFILE = PROJECT_ROOT / "src" / "apply_sut_profile.py"
CAMPAIGN_RUNNER = PROJECT_ROOT / "src" / "runners" / "campaign_runner.py"
HEALTH_CHECK = PROJECT_ROOT / "lab" / "health_check.py"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_apt_guard_exposes_minimal_install_helper() -> None:
    text = _read(APT_GUARD)

    assert "apt_install_minimal()" in text
    assert "--no-install-recommends" in text


def test_base_script_avoids_role_specific_packages() -> None:
    text = _read(BASE_SCRIPT)

    assert "apt_install_minimal \\" in text
    for package in ("git", "python3-pip", "python3-venv", "sshpass", "jq", "vim"):
        assert f"    {package} \\" not in text


def test_attacker_script_keeps_sshpass_but_not_pip() -> None:
    text = _read(ATTACKER_SCRIPT)

    assert "apt_install_minimal \\" in text
    assert "\n    sshpass || {" in text
    assert "\n    python3-pip \\" not in text


def test_caldera_script_keeps_runtime_core_and_opt_in_build_stack() -> None:
    text = _read(CALDERA_SCRIPT)

    assert "    python3-pip \\" in text
    assert "    git \\" in text
    assert 'INSTALL_OPTIONAL_BUILD_DEPS="${STICKS_CALDERA_INSTALL_BUILD_DEPS:-0}"' in text
    assert "Skipping optional build toolchain" in text
    assert "build-essential" in text
    assert "python3-dev" in text
    assert 'RUNTIME_REQUIREMENTS_FILE="/tmp/caldera-runtime-requirements.txt"' in text
    assert 'Runtime requirements file missing: $RUNTIME_REQUIREMENTS_FILE' in text


def test_caldera_vagrantfile_provisions_runtime_requirements() -> None:
    text = _read(CALDERA_VAGRANTFILE)

    assert 'source: "../shared/caldera-runtime-requirements.txt"' in text
    assert 'destination: "/tmp/caldera-runtime-requirements.txt"' in text


def test_caldera_runtime_requirements_match_enabled_plugin_slice() -> None:
    text = _read(CALDERA_RUNTIME_REQUIREMENTS)
    dependency_lines = {
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }

    assert "aiohttp-apispec==3.0.0b2" in dependency_lines
    assert "networkx==2.8.5" in dependency_lines
    assert "numpy>=1.20" in dependency_lines
    assert "matplotlib>=3.5.2" in dependency_lines
    assert "donut-shellcode==1.0.2" not in dependency_lines
    assert "Sphinx==7.1.2" not in dependency_lines
    assert "reportlab==4.0.4" not in dependency_lines


def test_vm_backed_path_reads_versioned_sut_profiles() -> None:
    assert '"data" / "sut_profiles"' in _read(APPLY_SUT_PROFILE)
    assert '"data" / "sut_profiles"' in _read(UP_LAB_SCRIPT)
    assert 'Path("data/sut_profiles")' in _read(CAMPAIGN_RUNNER)


def test_health_check_and_destroy_lab_use_versioned_sut_profiles() -> None:
    assert '"data" / "sut_profiles"' in _read(DESTROY_LAB_SCRIPT)
    assert '"data" / "sut_profiles"' in _read(HEALTH_CHECK)


def test_health_check_does_not_gate_on_pre_sut_apache() -> None:
    text = _read(HEALTH_CHECK)
    assert '_campaign_uses_technique(campaign_id, "T1190")' not in text
    assert "Check base services that must be ready before SUT application" in text
