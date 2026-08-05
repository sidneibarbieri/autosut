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
from dataclasses import dataclass
from pathlib import Path

from .environment_base import EnvironmentBackend
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


_CREATE_USER_SCRIPT = """
if id "{user}" >/dev/null 2>&1; then
  :
elif command -v adduser >/dev/null 2>&1 && adduser --help 2>&1 | grep -q "BusyBox\\|Alpine"; then
  adduser -D -s /bin/sh "{user}"
elif command -v useradd >/dev/null 2>&1; then
  useradd -m -s /bin/bash "{user}"
elif command -v adduser >/dev/null 2>&1; then
  adduser --disabled-password --gecos "" "{user}"
else
  echo "no usable user-create tool" 1>&2
  exit 1
fi
echo "{user}:{secret}" | chpasswd
"""


def _apply_credential(env: EnvironmentBackend, cred: Credential,
                      run_dir: Path, idx: int) -> list[str]:
    """Apply one credential. Supports ``password`` (chpasswd with
    distro-detected user creation) and ``ssh_key`` (authorized_keys drop).
    Anything else lands as a declarative breadcrumb so the manifest still
    records the intent."""
    log_base = f"sut/credential_{idx:02d}"
    evidence: list[str] = []
    if cred.kind == "password":
        env.run_shell(
            _CREATE_USER_SCRIPT.format(user=cred.user, secret=cred.secret),
            log_name=f"{log_base}_password.log", timeout=30,
        )
        evidence.append(f"{log_base}_password.log")
    elif cred.kind == "ssh_key":
        location = cred.location or f"/home/{cred.user}/.ssh/authorized_keys"
        r = env.run_shell(
            f"mkdir -p $(dirname {location}) && "
            f"printf '%s\\n' '{cred.secret}' >> {location} && "
            f"chown -R {cred.user}:{cred.user} $(dirname {location}) 2>/dev/null || true && "
            f"chmod 600 {location}",
            log_name=f"{log_base}_ssh_key.log", timeout=15,
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
    if art.content_text is not None:
        # Write via heredoc so multi-line content survives shell quoting.
        env.run_shell(
            f"mkdir -p $(dirname {art.path}) && "
            f"cat > {art.path} <<'AUTOSUT_ART_EOF'\n"
            f"{art.content_text}\n"
            f"AUTOSUT_ART_EOF\n"
            f"chmod {art.mode} {art.path} && "
            f"chown {art.owner}:{art.owner} {art.path} 2>/dev/null || true",
            log_name=log_name, timeout=15,
        )
    elif art.content_b64 is not None:
        env.run_shell(
            f"mkdir -p $(dirname {art.path}) && "
            f"printf '%s' '{art.content_b64}' | base64 -d > {art.path} && "
            f"chmod {art.mode} {art.path}",
            log_name=log_name, timeout=15,
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
        # No installer registered — record the gap honestly.
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

    1. Artifacts first (decoy data the application configs may reference).
    2. Credentials next (some apps consume them at install time).
    3. Applications (each recipe runs its own install + start).
    4. Exposures last (record the post-install network surface).
    """
    all_evidence: list[str] = []

    for idx, art in enumerate(comp.artifacts):
        all_evidence.extend(_apply_artifact(env, art, run_dir, idx))

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

    for idx, expo in enumerate(comp.exposures):
        all_evidence.extend(_record_exposure(expo, run_dir, idx))

    # Persist a per-host composition manifest so the reviewer can read the
    # *declared* shape next to what was actually applied.
    comp_dump_path = run_dir / "sut" / f"composition_{host_name}.json"
    comp_dump_path.write_text(
        json.dumps(comp.model_dump(), indent=2), encoding="utf-8",
    )
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
