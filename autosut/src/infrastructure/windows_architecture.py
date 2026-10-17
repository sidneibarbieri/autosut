"""Architecture vocabulary shared by Windows planning and answer-file rendering.

Windows product and Vagrant documentation commonly describe the 64-bit x86
guest as ``x86_64``.  Windows unattended XML uses the distinct token
``amd64``.  Keeping that mapping in one module prevents a plan for one guest
architecture from silently selecting an answer file for another.
"""

from __future__ import annotations

from enum import Enum


class WindowsGuestArchitecture(str, Enum):
    """Guest CPU architectures currently represented in the development tree."""

    ARM64 = "arm64"
    X86_64 = "x86_64"


_UNATTEND_PROCESSOR_ARCHITECTURES = {
    WindowsGuestArchitecture.ARM64: "arm64",
    WindowsGuestArchitecture.X86_64: "amd64",
}
_UNATTEND_TEMPLATE_FILENAMES = {
    WindowsGuestArchitecture.ARM64: "autounattend.host_a.xml",
    WindowsGuestArchitecture.X86_64: "autounattend.host_a.x86_64.xml",
}


def unattend_processor_architecture(architecture: WindowsGuestArchitecture) -> str:
    """Return the Windows unattended-XML token for a guest architecture."""
    return _UNATTEND_PROCESSOR_ARCHITECTURES[architecture]


def unattended_template_filename(architecture: WindowsGuestArchitecture) -> str:
    """Return the tracked template filename selected for this guest architecture."""
    return _UNATTEND_TEMPLATE_FILENAMES[architecture]
