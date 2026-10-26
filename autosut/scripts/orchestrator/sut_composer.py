"""Apply a declarative :class:`SUTComposition` to a running host.

Architecture
------------

The orchestrator brings up a host (Docker container or QEMU VM); the
composer then walks the host's :attr:`SUTHost.composition` and applies
each element via :meth:`EnvironmentBackend.run_shell`. Every applied
element produces an evidence log under ``release/evidence/<run>/sut/``,
so a reviewer can audit *exactly* which credentials, artifacts, ports,
and application stacks the SUT contributed to the campaign's realism.

This is the load-bearing primitive behind the paper claim that
**AutoSUT increases realism through composable, declarative SUT
configuration**: each composition element is auditable in declaration,
auditable in application, and reusable across campaigns.
"""

from __future__ import annotations

import json
import base64
import re
import shlex
from dataclasses import dataclass
from pathlib import Path

from .environment_base import EnvironmentBackend
from .composition_contract import composition_input_issues, valid_posix_user, valid_sut_path, valid_octal_mode
from .models import (
    ApplicationStack,
    Credential,
    NetworkExposure,
    StagedArtifact,
    SUTComposition,
)
from .sut_applications import RECIPES


@dataclass
class CompositionResult:
    """Aggregate outcome of applying one host's composition."""

    host_name: str
    credentials_applied: int
    artifacts_applied: int
    exposures_declared: int
    applications_installed: int
    applications_failed: int
    evidence_files: list[str]


_HOST_SLUG = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*\Z")


_CREATE_USER_SCRIPT = """
if id {user} >/dev/null 2>&1; then
  :
elif command -v adduser >/dev/null 2>&1 && adduser --help 2>&1 | grep -q "BusyBox\\|Alpine"; then
  adduser -D -s /bin/sh {user}
elif command -v useradd >/dev/null 2>&1; then
  useradd -m -s /bin/bash {user}
elif command -v adduser >/dev/null 2>&1; then
  adduser --disabled-password --gecos "" {user}
else
  echo "no usable user-create tool" 1>&2
  exit 1
fi
printf '%s:%s\n' {user} {secret} | chpasswd
"""


def _run_sensitive_command(env: EnvironmentBackend, command: str,
                           run_dir: Path, log_name: str) -> None:
    """Record only the outcome; backend command logs contain input material."""
    outcome = env.run_shell(command, log_name=None, timeout=30)
    log_path = run_dir / log_name
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text(f"exit_code: {outcome.exit_code}\n", encoding="utf-8")
    if outcome.exit_code != 0:
        raise RuntimeError(f"SUT composition failed; see {log_path}")


def _require_user(user: str) -> str:
    if not valid_posix_user(user):
        raise ValueError(f"invalid POSIX account name: {user!r}")
    return shlex.quote(user)


def _require_path(path: str) -> str:
    if not valid_sut_path(path):
        raise ValueError(f"invalid absolute SUT path: {path!r}")
    return shlex.quote(path)


def _validate_composition(comp: SUTComposition, host_name: str) -> None:
    if not _HOST_SLUG.fullmatch(host_name) or host_name in {".", ".."}:
        raise ValueError(f"invalid SUT host name: {host_name!r}")
    issues = composition_input_issues(comp)
    if issues:
        raise ValueError("; ".join(issues))


def _apply_credential(env: EnvironmentBackend, cred: Credential,
                      run_dir: Path, idx: int) -> list[str]:
    """Apply one credential. Supports ``password`` (chpasswd with
    distro-detected user creation) and ``ssh_key`` (authorized_keys drop).
    Anything else lands as a declarative breadcrumb so the manifest still
    records the intent."""
    log_base = f"sut/credential_{idx:02d}"
    evidence: list[str] = []
    if cred.kind == "password":
        _run_sensitive_command(
            env, _CREATE_USER_SCRIPT.format(
                user=_require_user(cred.user), secret=shlex.quote(cred.secret)),
            run_dir, f"{log_base}_password.log",
        )
        evidence.append(f"{log_base}_password.log")
    elif cred.kind == "ssh_key":
        user = _require_user(cred.user)
        location = _require_path(cred.location or f"/home/{cred.user}/.ssh/authorized_keys")
        _run_sensitive_command(
            env,
            f"mkdir -p \"$(dirname {location})\" && "
            f"printf '%s\\n' {shlex.quote(cred.secret)} >> {location} && "
            f"chown -R {user}:{user} \"$(dirname {location})\" && "
            f"chmod 600 {location}",
            run_dir, f"{log_base}_ssh_key.log",
        )
        evidence.append(f"{log_base}_ssh_key.log")
    else:
        # Fall through: declarative-only credential (api_token, cookie).
        # Record it in evidence so the manifest knows it exists.
        breadcrumb = run_dir / f"{log_base}_declarative.json"
        breadcrumb.parent.mkdir(parents=True, exist_ok=True)
        breadcrumb.write_text(
            json.dumps({
                "kind": cred.kind, "user": cred.user, "purpose": cred.purpose,
                "location": cred.location,
            }, indent=2),
            encoding="utf-8",
        )
        evidence.append(str(breadcrumb.relative_to(run_dir)))
    return evidence


def _apply_artifact(env: EnvironmentBackend, art: StagedArtifact,
                    run_dir: Path, idx: int) -> list[str]:
    log_name = f"sut/artifact_{idx:02d}.log"
    path = _require_path(art.path)
    owner = _require_user(art.owner)
    if not valid_octal_mode(art.mode):
        raise ValueError(f"invalid artifact mode: {art.mode!r}")
    if art.content_text is not None:
        encoded = base64.b64encode(art.content_text.encode("utf-8")).decode("ascii")
    elif art.content_b64 is not None:
        encoded = art.content_b64
    else:
        raise ValueError(f"artifact {art.path!r} has no content")
    _run_sensitive_command(
        env,
        f"mkdir -p \"$(dirname {path})\" && "
        f"printf '%s' {shlex.quote(encoded)} | base64 -d > {path} && "
        f"chmod {art.mode} {path} && "
        f"chown {owner} {path}",
        run_dir, log_name,
    )
    return [log_name]


def _record_exposure(exposure: NetworkExposure, run_dir: Path,
                     idx: int) -> list[str]:
    """Exposures are largely declarative on the per-run private network —
    the host port is already reachable on its assigned IP. We persist a
    breadcrumb so the manifest carries the intentional surface."""
    breadcrumb = run_dir / "sut" / f"exposure_{idx:02d}.json"
    breadcrumb.parent.mkdir(parents=True, exist_ok=True)
    breadcrumb.write_text(
        json.dumps({
            "port": exposure.port, "protocol": exposure.protocol,
            "service": exposure.service, "expose_to": exposure.expose_to,
        }, indent=2),
        encoding="utf-8",
    )
    return [str(breadcrumb.relative_to(run_dir))]


def _apply_application(env: EnvironmentBackend, stack: ApplicationStack,
                        run_dir: Path) -> tuple[bool, list[str]]:
    fn = RECIPES.get(stack.recipe)
    if fn is None:
        # No installer registered - record the gap honestly.
        log_path = run_dir / "sut" / f"app_{stack.name}_no_recipe.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(
            f"no recipe '{stack.recipe}' in sut_applications.RECIPES.\n"
            f"stack: name={stack.name} version={stack.version} "
            f"cve_pins={stack.cve_pins}\n",
            encoding="utf-8",
        )
        return False, [str(log_path.relative_to(run_dir))]
    result = fn(env, stack, run_dir)
    return result.ok, result.evidence_files


def apply_composition(env: EnvironmentBackend, host_name: str,
                       comp: SUTComposition,
                       run_dir: Path) -> CompositionResult:
    """Apply every element in ``comp`` to ``env``. Order matters:

    1. Credentials first (the declared account may own a later artifact).
    2. Applications next (the recipe may create a service account such as
       ``www-data`` that owns a later artifact).
    3. Artifacts after their declared owners exist (application configs may
       reference the decoy data once it is present).
    4. Exposures last (record the post-install network surface).
    """
    _validate_composition(comp, host_name)
    all_evidence: list[str] = []

    for idx, cred in enumerate(comp.credentials):
        all_evidence.extend(_apply_credential(env, cred, run_dir, idx))

    app_ok = 0
    app_fail = 0
    for stack in comp.applications:
        ok, ev = _apply_application(env, stack, run_dir)
        all_evidence.extend(ev)
        if ok:
            app_ok += 1
        else:
            app_fail += 1

    for idx, art in enumerate(comp.artifacts):
        all_evidence.extend(_apply_artifact(env, art, run_dir, idx))

    for idx, expo in enumerate(comp.exposures):
        all_evidence.extend(_record_exposure(expo, run_dir, idx))

    # Persist a per-host composition manifest so the reviewer can read the
    # *declared* shape next to what was actually applied.
    comp_dump_path = run_dir / "sut" / f"composition_{host_name}.json"
    comp_dump_path.parent.mkdir(parents=True, exist_ok=True)
    public_composition = comp.model_dump()
    for credential in public_composition["credentials"]:
        credential.pop("secret", None)
    for artifact in public_composition["artifacts"]:
        artifact.pop("content_text", None)
        artifact.pop("content_b64", None)
    comp_dump_path.write_text(json.dumps(public_composition, indent=2), encoding="utf-8")
    all_evidence.append(str(comp_dump_path.relative_to(run_dir)))

    return CompositionResult(
        host_name=host_name,
        credentials_applied=len(comp.credentials),
        artifacts_applied=len(comp.artifacts),
        exposures_declared=len(comp.exposures),
        applications_installed=app_ok,
        applications_failed=app_fail,
        evidence_files=all_evidence,
    )
