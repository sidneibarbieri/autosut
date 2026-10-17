#!/usr/bin/env python3
"""Render a runtime-only Windows unattended-install answer file."""

from __future__ import annotations

import argparse
import os
import re
import sys
import tempfile
from pathlib import Path
from xml.etree import ElementTree
from xml.sax.saxutils import escape as xml_escape

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.infrastructure.windows_architecture import (
    WindowsGuestArchitecture,
    unattend_processor_architecture,
    unattended_template_filename,
)

PASSWORD_PLACEHOLDER = "{{AUTOSUT_WINDOWS_LOCAL_ADMIN_PASSWORD}}"
_COMPUTER_NAME_ELEMENT = re.compile(r"<ComputerName>[^<]*</ComputerName>")
TEMPLATE_ROOT = PROJECT_ROOT / "lab" / "provisioning" / "windows-workgroup-lateral"
TEMPLATES_BY_ARCHITECTURE = {
    architecture: TEMPLATE_ROOT / unattended_template_filename(architecture)
    for architecture in WindowsGuestArchitecture
}


def local_name(element: ElementTree.Element) -> str:
    return element.tag.rsplit("}", 1)[-1]


def password_values(root: ElementTree.Element) -> list[str]:
    values: list[str] = []
    for password in root.iter():
        if local_name(password) != "Password":
            continue
        for child in password:
            if local_name(child) == "Value":
                values.append((child.text or "").strip())
    return values


def processor_architectures(root: ElementTree.Element) -> list[str]:
    """Return every declared Windows component architecture in document order."""
    values: list[str] = []
    for element in root.iter():
        if local_name(element) != "component":
            continue
        architecture = element.attrib.get("processorArchitecture", "").strip()
        if architecture:
            values.append(architecture)
    return values


def template_for_architecture(architecture: WindowsGuestArchitecture) -> Path:
    """Return the one tracked answer-file template valid for this guest architecture."""
    return TEMPLATES_BY_ARCHITECTURE[architecture]


def validate_template(template_text: str, architecture: WindowsGuestArchitecture) -> None:
    """Validate credential placeholders and an exact guest/XML architecture match."""
    root = ElementTree.fromstring(template_text)
    values = password_values(root)
    if values != [PASSWORD_PLACEHOLDER, PASSWORD_PLACEHOLDER]:
        raise ValueError(
            "unattend template must contain exactly two password placeholders "
            "and no literal password values"
        )
    if template_text.count(PASSWORD_PLACEHOLDER) != len(values):
        raise ValueError(
            "unattend template may contain password placeholders only in its two Password/Value nodes"
        )
    if sum(local_name(element) == "AutoLogon" for element in root.iter()) != 1:
        raise ValueError("unattend template must contain exactly one AutoLogon block")
    expected_architecture = unattend_processor_architecture(architecture)
    declared_architectures = processor_architectures(root)
    if not declared_architectures:
        raise ValueError("unattend template must declare processorArchitecture on every component")
    if set(declared_architectures) != {expected_architecture}:
        raise ValueError(
            "unattend template processorArchitecture does not match requested guest architecture "
            f"{architecture.value}: expected {expected_architecture}, found "
            f"{sorted(set(declared_architectures))}"
        )


def password_from_environment(variable_name: str) -> str:
    password = os.environ.get(variable_name, "")
    if not password.strip():
        raise ValueError(f"environment variable {variable_name} is required")
    if PASSWORD_PLACEHOLDER in password:
        raise ValueError("runtime password must not contain the template placeholder")
    return password


def render_answer_file(
    template: Path,
    output: Path,
    password: str,
    architecture: WindowsGuestArchitecture,
    computer_name: str | None = None,
) -> Path:
    """Render a runtime-only answer file after enforcing its guest architecture."""
    template = template.resolve()
    output = output.resolve()
    if template == output:
        raise ValueError("refusing to render a credential into the tracked template")

    template_text = template.read_text(encoding="utf-8")
    validate_template(template_text, architecture)
    if computer_name is not None:
        if (
            re.fullmatch(r"[A-Z][A-Z0-9-]{0,14}", computer_name) is None
            or computer_name.endswith("-")
            or len(_COMPUTER_NAME_ELEMENT.findall(template_text)) != 1
        ):
            raise ValueError("invalid or ambiguous Windows computer name")
        template_text = _COMPUTER_NAME_ELEMENT.sub(
            f"<ComputerName>{computer_name}</ComputerName>", template_text,
        )
    rendered = template_text.replace(PASSWORD_PLACEHOLDER, xml_escape(password))
    if PASSWORD_PLACEHOLDER in rendered:
        raise ValueError("unattend template replacement was incomplete")
    root = ElementTree.fromstring(rendered)
    if password_values(root) != [password, password]:
        raise ValueError("rendered answer file does not preserve both password values")
    expected_architecture = unattend_processor_architecture(architecture)
    if set(processor_architectures(root)) != {expected_architecture}:
        raise ValueError("rendered answer file architecture changed unexpectedly")

    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=output.parent,
        prefix=f".{output.name}.",
        suffix=".tmp",
        delete=False,
    ) as handle:
        handle.write(rendered)
        temporary_path = Path(handle.name)
    temporary_path.chmod(0o600)
    temporary_path.replace(output)
    output.chmod(0o600)
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--architecture",
        choices=[architecture.value for architecture in WindowsGuestArchitecture],
        required=True,
        help="guest architecture; selects and validates the matching unattended template",
    )
    parser.add_argument(
        "--template",
        type=Path,
        help="optional tracked template override; it must match --architecture exactly",
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--password-env",
        default="AUTOSUT_WINDOWS_LOCAL_ADMIN_PASSWORD",
        help="environment variable containing the per-run local administrator password",
    )
    args = parser.parse_args()

    architecture = WindowsGuestArchitecture(args.architecture)
    template = args.template or template_for_architecture(architecture)
    password = password_from_environment(args.password_env)
    rendered = render_answer_file(template, args.output, password, architecture)
    print(
        "[render-windows-unattend] wrote runtime-only answer file: "
        f"{rendered} ({architecture.value})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
