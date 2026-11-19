"""The preflight reads host state only and names an exact fix for each failure."""

import ast
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("autosut_doctor", ROOT / "scripts" / "doctor.py")
doctor = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = doctor
SPEC.loader.exec_module(doctor)

READ_ONLY_DOCKER = {("info",), ("ps",), ("network", "ls"), ("network", "inspect"), ("image", "inspect")}


def completed(stdout="", returncode=0):
    return subprocess.CompletedProcess([], returncode, stdout, "")


def test_core_modules_match_the_environment_contract():
    contract = (ROOT / "scripts" / "python_env.sh").read_text()
    [literal] = re.findall(r"for module in (\(.*?\)):", contract)
    assert ast.literal_eval(literal) == doctor.CORE_MODULES


def test_core_modules_are_pinned_by_the_reviewer_requirements():
    pinned = set()
    for line in (ROOT / "requirements-reviewer.txt").read_text().splitlines():
        if "==" in line and not line.lstrip().startswith("#"):
            pinned.add(line.split("==")[0].strip().lower())
    distribution = {"yaml": "pyyaml"}
    for module in doctor.CORE_MODULES:
        assert distribution.get(module, module) in pinned, module


def test_media_tools_match_the_qualification_script():
    source = (ROOT / "scripts" / "qualify_windows_media.py").read_text()
    [literal] = re.findall(r"MEDIA_TOOLS = (\(.*?\))", source)
    assert ast.literal_eval(literal) == doctor.MEDIA_TOOLS


def test_caldera_port_matches_the_replay_runner():
    source = (ROOT / "scripts" / "run_all_orchestrated_campaigns.py").read_text()
    assert f'"-p", "{doctor.CALDERA_HOST_PORT}:8888"' in source
    assert f'"--name", "{doctor.CALDERA_CONTAINER}"' in source


def test_review_path_checks_only_the_interpreter():
    checks = doctor.collect("review")
    assert [check.name for check in checks] == ["python", "python packages"]


def test_stopped_daemon_names_the_start_command(monkeypatch):
    monkeypatch.setattr(doctor.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(doctor, "run", lambda command, timeout=20: completed(returncode=1))
    checks, reachable = doctor.check_docker_daemon()
    assert not reachable
    assert checks[0].status == "FAIL" and checks[0].fix.startswith("colima start")


def test_foreign_resources_under_the_reserved_prefix_block_the_replay(monkeypatch):
    import infrastructure.docker_namespace as namespace

    monkeypatch.setattr(doctor.shutil, "which", lambda name: "/usr/bin/" + name)

    monkeypatch.setattr(namespace, "autosut_resources",
                        lambda: {"container:autosut-caldera", "network:autosut-mine"})
    monkeypatch.setattr(doctor, "run", lambda command, timeout=20: completed(""))  # no replay running
    [check] = doctor.check_namespace()
    assert check.status == "FAIL"
    assert "docker network rm autosut-mine" in check.fix
    assert "autosut-caldera" in check.detail


def test_preexisting_c2_requires_ownership_review(monkeypatch):
    import infrastructure.docker_namespace as namespace

    monkeypatch.setattr(doctor.shutil, "which", lambda name: "/usr/bin/" + name)

    monkeypatch.setattr(namespace, "autosut_resources", lambda: {"container:autosut-caldera"})
    monkeypatch.setattr(doctor, "run", lambda command, timeout=20: completed(""))
    check = doctor.check_namespace()[0]
    assert check.status == "FAIL"
    assert "autosut-caldera" in check.detail


def test_preexisting_c2_port_requires_ownership_review(monkeypatch):
    monkeypatch.setattr(doctor, "port_is_bound", lambda port: True)
    monkeypatch.setattr(doctor, "run", lambda command, timeout=20: completed("autosut-caldera\n"))
    check = doctor.check_caldera_port()[0]
    assert check.status == "FAIL"
    assert "owner" in check.fix


def test_port_held_outside_docker_names_the_lookup(monkeypatch):
    monkeypatch.setattr(doctor, "port_is_bound", lambda port: True)
    monkeypatch.setattr(doctor, "run", lambda command, timeout=20: completed(""))
    [check] = doctor.check_caldera_port()
    assert check.status == "FAIL" and check.fix.startswith("lsof -nP -iTCP:8888")


def test_exhausted_address_pool_fails_before_the_replay(monkeypatch):
    names = [f"net{index}" for index in range(29)]

    def fake_run(command, timeout=20):
        if command[:3] == ["docker", "network", "ls"]:
            return completed("\n".join(names))
        index = names.index(command[-1])
        subnet = f"172.{17 + index}.0.0/16" if index < 15 else f"192.168.{16 * (index - 15)}.0/20"
        return completed(json.dumps([{"IPAM": {"Config": [{"Subnet": subnet}]}}]))

    monkeypatch.setattr(doctor, "run", fake_run)
    [check] = doctor.check_address_pool()
    assert check.status == "FAIL"
    assert "non-overlapping IPv4 address pool" in check.detail


def test_doctor_issues_only_read_only_docker_commands(monkeypatch):
    issued = []

    def fake_run(command, timeout=20):
        issued.append(command)
        if command[:2] == ["docker", "info"]:
            return completed("29.0.0 aarch64")
        if command[:3] == ["docker", "network", "ls"]:
            return completed("bridge")
        if command[:3] == ["docker", "network", "inspect"]:
            return completed(json.dumps([{"IPAM": {"Config": [{"Subnet": "172.17.0.0/16"}]}}]))
        return completed("")

    import infrastructure.docker_namespace as namespace

    monkeypatch.setattr(doctor, "run", fake_run)
    monkeypatch.setattr(doctor.shutil, "which", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(doctor, "port_is_bound", lambda port: False)
    monkeypatch.setattr(namespace, "autosut_resources", lambda: set())
    doctor.collect("all")
    docker_verbs = {tuple(part for part in command[1:3] if not part.startswith("-"))
                    for command in issued if command[0] == "docker"}
    for verb in docker_verbs:
        assert verb in READ_ONLY_DOCKER or verb[:1] in READ_ONLY_DOCKER, verb


def test_resources_of_a_running_replay_say_wait_not_delete(monkeypatch):
    import infrastructure.docker_namespace as namespace

    monkeypatch.setattr(doctor.shutil, "which", lambda name: "/usr/bin/" + name)

    monkeypatch.setattr(namespace, "autosut_resources", lambda: {"container:autosut-1234"})
    monkeypatch.setattr(doctor, "run", lambda command, timeout=20: completed("4242\n"))
    [check] = doctor.check_namespace()
    assert check.status == "FAIL"
    assert "in progress" in check.detail and "docker rm" not in check.fix


def test_missing_process_inspector_does_not_authorize_cleanup(monkeypatch):
    import infrastructure.docker_namespace as namespace

    monkeypatch.setattr(namespace, "autosut_resources", lambda: {"container:autosut-existing"})
    monkeypatch.setattr(doctor.shutil, "which", lambda name: None)
    check = doctor.check_namespace()[0]
    assert check.status == "FAIL"
    assert "ownership" in check.detail and "unavailable" in check.fix
    assert "docker rm" not in check.fix
