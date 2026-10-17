"""Pure admission checks shared by composition planning and application."""

from __future__ import annotations

import re
from pathlib import Path

from .models import SUTComposition


_POSIX_USER = re.compile(r"[a-z_][a-z0-9_-]*[$]?\Z")
_OCTAL_MODE = re.compile(r"0?[0-7]{3,4}\Z")


def valid_posix_user(user: str) -> bool:
    return bool(_POSIX_USER.fullmatch(user))


def valid_sut_path(path: str) -> bool:
    return path.startswith("/") and ".." not in Path(path).parts


def valid_octal_mode(mode: str) -> bool:
    return bool(_OCTAL_MODE.fullmatch(mode))


def composition_input_issues(composition: SUTComposition) -> list[str]:
    """Reject fields that the POSIX composer cannot apply safely."""
    issues: list[str] = []
    for credential in composition.credentials:
        if not valid_posix_user(credential.user):
            issues.append(f"credential user {credential.user!r} is not a POSIX account name")
        if credential.kind == "password" and (
            not credential.secret or "\n" in credential.secret or "\r" in credential.secret
        ):
            issues.append("password credential cannot be empty or multiline")
        if credential.location is not None and not valid_sut_path(credential.location):
            issues.append(f"credential location {credential.location!r} is not a safe absolute path")
    for artifact in composition.artifacts:
        if not valid_sut_path(artifact.path):
            issues.append(f"artifact path {artifact.path!r} is not a safe absolute path")
        if not valid_posix_user(artifact.owner):
            issues.append(f"artifact owner {artifact.owner!r} is not a POSIX account name")
        if not valid_octal_mode(artifact.mode):
            issues.append(f"artifact mode {artifact.mode!r} is not octal")
        if (artifact.content_text is None) == (artifact.content_b64 is None):
            issues.append(f"artifact {artifact.path!r} needs exactly one content field")
    return sorted(set(issues))
