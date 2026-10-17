from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from xml.etree import ElementTree

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODULE_PATH = PROJECT_ROOT / "scripts" / "render_windows_unattend.py"
ARM64_TEMPLATE_PATH = (
    PROJECT_ROOT / "lab" / "provisioning" / "windows-workgroup-lateral" / "autounattend.host_a.xml"
)
X86_64_TEMPLATE_PATH = (
    PROJECT_ROOT
    / "lab"
    / "provisioning"
    / "windows-workgroup-lateral"
    / "autounattend.host_a.x86_64.xml"
)


def _load_module():
    spec = importlib.util.spec_from_file_location("render_windows_unattend", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    ("architecture_name", "template_path", "expected_processor_architecture"),
    [
        ("ARM64", ARM64_TEMPLATE_PATH, "arm64"),
        ("X86_64", X86_64_TEMPLATE_PATH, "amd64"),
    ],
)
def test_tracked_template_contains_only_the_password_placeholder_and_declares_its_architecture(
    architecture_name: str,
    template_path: Path,
    expected_processor_architecture: str,
) -> None:
    module = _load_module()
    architecture = getattr(module.WindowsGuestArchitecture, architecture_name)
    template_text = template_path.read_text(encoding="utf-8")

    module.validate_template(template_text, architecture)
    assert template_text.count(module.PASSWORD_PLACEHOLDER) == 2
    root = ElementTree.fromstring(template_text)
    assert set(module.processor_architectures(root)) == {expected_processor_architecture}
    assert module.template_for_architecture(architecture) == template_path
    assert template_path.name == module.unattended_template_filename(architecture)


def test_renderer_writes_restricted_runtime_file(tmp_path: Path) -> None:
    module = _load_module()
    output = tmp_path / "runtime" / "autounattend.xml"

    module.render_answer_file(
        X86_64_TEMPLATE_PATH,
        output,
        "test-only-password",
        module.WindowsGuestArchitecture.X86_64,
    )

    rendered = output.read_text(encoding="utf-8")
    assert module.PASSWORD_PLACEHOLDER not in rendered
    root = ElementTree.fromstring(rendered)
    assert module.password_values(root) == ["test-only-password", "test-only-password"]
    assert set(module.processor_architectures(root)) == {"amd64"}
    assert output.stat().st_mode & 0o777 == 0o600


def test_renderer_can_assign_a_distinct_valid_clone_name(tmp_path: Path) -> None:
    module = _load_module()
    output = tmp_path / "clone.xml"

    module.render_answer_file(
        ARM64_TEMPLATE_PATH, output, "test-only-password",
        module.WindowsGuestArchitecture.ARM64, computer_name="AUTOSUT-B",
    )

    root = ElementTree.parse(output).getroot()
    names = [element.text for element in root.iter() if module.local_name(element) == "ComputerName"]
    assert names == ["AUTOSUT-B"]
    assert output.stat().st_mode & 0o777 == 0o600

    with pytest.raises(ValueError, match="computer name"):
        module.render_answer_file(
            ARM64_TEMPLATE_PATH, tmp_path / "bad.xml", "test-only-password",
            module.WindowsGuestArchitecture.ARM64, computer_name="BAD<NAME",
        )


def test_renderer_refuses_template_with_literal_password(tmp_path: Path) -> None:
    module = _load_module()
    unsafe_template = tmp_path / "unsafe.xml"
    unsafe_template.write_text(
        ARM64_TEMPLATE_PATH.read_text(encoding="utf-8").replace(
            module.PASSWORD_PLACEHOLDER,
            "test-only-password",
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="no literal password values"):
        module.render_answer_file(
            unsafe_template,
            tmp_path / "runtime" / "autounattend.xml",
            "different-test-password",
            module.WindowsGuestArchitecture.ARM64,
        )


def test_renderer_refuses_an_arm64_template_for_an_x86_64_guest(tmp_path: Path) -> None:
    module = _load_module()

    with pytest.raises(ValueError, match="does not match requested guest architecture x86_64"):
        module.render_answer_file(
            ARM64_TEMPLATE_PATH,
            tmp_path / "runtime" / "autounattend.xml",
            "test-only-password",
            module.WindowsGuestArchitecture.X86_64,
        )
