"""Subdetermination: construct multiple SUTs compatible with one campaign.

The provenance tags in `catalog.py` partition a SUT into a fixed evidence
region (`corpus_supported` or `external_reference`) and a free construction
region (`analyst_authored` + `autosut_concretized`). This module reads that
partition, fingerprints the
fixed region, and constructs alternative SUTs that vary only the free region —
a constructive witness that the corpus does not uniquely determine the
environment.
"""

from __future__ import annotations

import hashlib
import json
import random
import shutil
from pathlib import Path
from typing import Optional, Protocol

from pydantic import BaseModel, Field

from . import catalog, provenance
from .models import ProvenanceSource, SUTComposition, SUTProfile
from .provenance import ProvenanceElement, ProvenanceSummary

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_ARCHIVE_ROOT = _PROJECT_ROOT / "release" / "evidence" / "_archive"


class SubdeterminationError(RuntimeError):
    """Raised when a perturbation changes the fixed (corpus) region.

    A real bug in a strategy, not a recoverable condition. We raise rather than
    mask (the T1.2 lesson) so an incompatible variant can never be emitted as
    if it were compatible.
    """


def partition(
    summary: ProvenanceSummary,
) -> tuple[list[ProvenanceElement], list[ProvenanceElement]]:
    """Split a summary into (invariant, free) strictly by provenance tag."""
    invariant = [
        element for element in summary.elements
        if element.source in (
            ProvenanceSource.corpus_supported,
            ProvenanceSource.external_reference,
        )
    ]
    free = [e for e in summary.elements
            if e.source in (ProvenanceSource.analyst_authored,
                            ProvenanceSource.autosut_concretized)]
    return invariant, free


def invariant_fingerprint(summary: ProvenanceSummary) -> str:
    """Stable hash over sorted fixed-evidence triples.

    Two SUTs share a fingerprint iff both their corpus and external anchors are
    identical.  The source tag is hashed so external evidence cannot be
    relabelled as evaluated-corpus evidence without changing the invariant.
    """
    anchored = sorted(
        (element.source.value, element.identifier, element.value)
        for element in summary.elements
        if element.source in (
            ProvenanceSource.corpus_supported,
            ProvenanceSource.external_reference,
        )
    )
    return hashlib.sha256(repr(anchored).encode("utf-8")).hexdigest()


class CompatibleVariant(BaseModel):
    """One SUT that satisfies the same corpus constraints as the canonical."""

    variant_id: str
    seed: int
    sut_profile: SUTProfile
    free_elements_changed: list[str] = Field(default_factory=list)
    free_fraction: float


class VariantExecution(BaseModel):
    """Persistent audit record for one executed compatible variant."""

    variant_id: str
    run_id: str
    manifest_path: str
    manifest_sha256: str
    summary_path: str
    summary_sha256: str
    evidence_sha256: dict[str, str] = Field(default_factory=dict)
    containment_path: Optional[str] = None
    containment_sha256: Optional[str] = None
    containment_sealed: Optional[bool] = None
    techniques_total: int
    techniques_success: int
    evidence_backed_successful: int
    mode_status_consistent: bool
    teardown_clean: bool


class SubdeterminationProof(BaseModel):
    """The constructive existence proof for one campaign."""

    campaign_id: str
    invariant_fingerprint: str
    invariant_count: int
    free_count: int
    free_fraction: float
    canonical: CompatibleVariant
    variants: list[CompatibleVariant] = Field(default_factory=list)
    execution_runs: list[VariantExecution] = Field(default_factory=list)
    executable: bool = False


def _composition_for(
    profile: SUTProfile, host_name: Optional[str]
) -> Optional[SUTComposition]:
    """Return the composition that owns elements tagged with `host_name`.

    Single-host profiles carry one composition (host_name is None); multi-host
    profiles carry one per host, matched by name.
    """
    if profile.is_multi_host:
        for host in profile.hosts or []:
            if host.name == host_name:
                return host.composition
        return None
    return profile.composition


def _prefix(host: Optional[str]) -> str:
    return f"{host}." if host else ""


def _token(rng: random.Random) -> str:
    return f"{rng.randrange(16 ** 6):06x}"


class PerturbationStrategy(Protocol):
    """Varies ONE kind of free element, leaving the invariant intact."""

    def applies_to(self, element: ProvenanceElement) -> bool: ...

    def perturb(self, profile: SUTProfile, element: ProvenanceElement,
                rng: random.Random) -> SUTProfile: ...


class RelocateDecoyArtifact:
    """Cosmetic: relocate + rewrite an analyst decoy artifact (path + content)."""

    def applies_to(self, element: ProvenanceElement) -> bool:
        return (element.dimension == "artifacts"
                and element.source is ProvenanceSource.analyst_authored)

    def perturb(self, profile, element, rng):
        variant = profile.model_copy(deep=True)
        composition = _composition_for(variant, element.host)
        token = _token(rng)
        for artifact in composition.artifacts:
            if (f"{_prefix(element.host)}artifact.{artifact.path}"
                    == element.identifier):
                base = artifact.path.rsplit("/", 1)[0]
                artifact.path = f"{base}/decoy_{token}.txt"
                artifact.content_text = f"lab decoy {token}\n"
                break
        return variant


class RotateCredentialLiteral:
    """Cosmetic: rotate a free credential's user:secret literal."""

    def applies_to(self, element: ProvenanceElement) -> bool:
        return (element.dimension == "credentials"
                and element.source in (ProvenanceSource.analyst_authored,
                                        ProvenanceSource.autosut_concretized))

    def perturb(self, profile, element, rng):
        variant = profile.model_copy(deep=True)
        composition = _composition_for(variant, element.host)
        token = _token(rng)
        for cred in composition.credentials:
            if (f"{_prefix(element.host)}credential.{cred.user}"
                    == element.identifier):
                cred.user = f"labuser_{token}"
                cred.secret = f"Lab-{token}!"
                break
        return variant


# Each free service product maps to a structurally different product that
# satisfies the same abstract precondition. The precondition is recorded in the
# variant element's `purpose` so the substitution is auditable as
# same-requirement / different-realisation rather than a relabel.
_SERVICE_EQUIVALENTS: dict[str, tuple[str, str]] = {
    "openssh": ("dropbear", "remote authenticated service (SSH)"),
    "apache_httpd": ("nginx", "edge HTTP service"),
    "mysql": ("mariadb", "relational database service"),
}


class SubstituteEquivalentService:
    """Material: replace a free service product with a structurally different
    one that satisfies the same abstract precondition."""

    def applies_to(self, element: ProvenanceElement) -> bool:
        if element.dimension != "software":
            return False
        if element.source in (
            ProvenanceSource.corpus_supported,
            ProvenanceSource.external_reference,
        ):
            return False
        product = element.value.split("@", 1)[0]
        return product in _SERVICE_EQUIVALENTS

    def perturb(self, profile, element, rng):
        variant = profile.model_copy(deep=True)
        composition = _composition_for(variant, element.host)
        for app in composition.applications:
            if (f"{_prefix(element.host)}software.{app.name}@{app.version}"
                    == element.identifier):
                alternative, precondition = _SERVICE_EQUIVALENTS[app.name]
                app.name = alternative
                app.recipe = f"{alternative}_equivalent"
                app.purpose = (f"Realises the same abstract precondition: "
                               f"{precondition}.")
                break
        return variant


# Material substitution is tried first so a service element becomes a different
# product rather than only a relabel; credential + artifact strategies cover the
# remaining free dimensions. Exposures intentionally have no strategy - their
# free variation adds nothing the service substitution does not already show.
_DEFAULT_STRATEGIES: list[PerturbationStrategy] = [
    SubstituteEquivalentService(),
    RotateCredentialLiteral(),
    RelocateDecoyArtifact(),
]


class VariantGenerator:
    """Builds one compatible variant per seed by perturbing only free elements.

    Strategy pattern: each free element is matched to the first strategy that
    applies; corpus elements match nothing and are unreachable. The fingerprint
    re-check after perturbation is a verified backstop - if it ever fails, a
    strategy reached the invariant, which is a bug we surface, never mask.
    """

    def __init__(self, strategies: Optional[list[PerturbationStrategy]] = None):
        self._strategies = (list(strategies) if strategies is not None
                            else list(_DEFAULT_STRATEGIES))

    def _match(self, element: ProvenanceElement
               ) -> Optional[PerturbationStrategy]:
        for strategy in self._strategies:
            if strategy.applies_to(element):
                return strategy
        return None

    def generate(self, campaign_id: str, seed: int) -> CompatibleVariant:
        _, sut, cves = catalog.resolve(campaign_id)
        canonical = provenance.summarize_profile(sut, campaign_id, cves)
        target_fingerprint = invariant_fingerprint(canonical)
        rng = random.Random(seed)
        _, free = partition(canonical)
        variant_sut = sut
        changed: list[str] = []
        for element in free:
            strategy = self._match(element)
            if strategy is not None:
                variant_sut = strategy.perturb(variant_sut, element, rng)
                changed.append(element.identifier)
        variant_summary = provenance.summarize_profile(
            variant_sut, campaign_id, cves)
        if invariant_fingerprint(variant_summary) != target_fingerprint:
            raise SubdeterminationError(
                f"{campaign_id}: a perturbation changed the corpus invariant")
        free_fraction = round(canonical.percentages["analyst_authored"]
                              + canonical.percentages["autosut_concretized"], 1)
        variant_sut = variant_sut.model_copy(
            update={"sut_id": f"{sut.sut_id}-s{seed}"})
        return CompatibleVariant(
            variant_id=f"{campaign_id}#seed{seed}",
            seed=seed,
            sut_profile=variant_sut,
            free_elements_changed=changed,
            free_fraction=free_fraction,
        )


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _relative(path: Path) -> str:
    return path.relative_to(_PROJECT_ROOT).as_posix()


def _make_archived_metadata_portable(run_dir: Path) -> None:
    """Replace pre-move absolute paths with run-relative references.

    The orchestrator writes the manifest before proof evidence is moved under
    ``_archive``.  Leaving those paths untouched makes a released proof point
    back to the author's workstation and to a directory that no longer exists.
    """
    manifest_path = run_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for key, filename in (
        ("manifest_path", "manifest.json"),
        ("summary_path", "summary.json"),
        ("campaign_state_path", "campaign_state.json"),
    ):
        if key in manifest:
            manifest[key] = filename
    manifest_path.write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8",
    )

    summary_path = run_dir / "summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    if "evidence_directory" in summary:
        summary["evidence_directory"] = "."
    summary_path.write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8",
    )


def _technique_evidence_hashes(run_dir: Path) -> dict[str, str]:
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    evidence_paths = sorted({
        evidence_path
        for technique in manifest.get("techniques", [])
        for evidence_path in technique.get("evidence_files", [])
    })
    hashes: dict[str, str] = {}
    for evidence_path in evidence_paths:
        path = run_dir / evidence_path
        if not path.is_file():
            raise SubdeterminationError(
                f"missing technique evidence in proof run: {path}"
            )
        hashes[evidence_path] = _sha256(path)
    return hashes


def _execution_record(
    variant: CompatibleVariant,
    result,
    run_dir: Path,
) -> VariantExecution:
    manifest_path = run_dir / "manifest.json"
    summary_path = run_dir / "summary.json"
    containment_path = run_dir / "sut" / "containment.log"
    seal_lines: list[str] = []
    if containment_path.exists():
        seal_lines = [
            line
            for line in containment_path.read_text(encoding="utf-8").splitlines()
            if line.startswith("[seal]")
        ]
    containment_sealed = (
        all("egress=SEALED" in line for line in seal_lines)
        if seal_lines
        else None
    )
    consistent = all(
        outcome.declared_mode == outcome.executed_mode
        and outcome.status == "success"
        for outcome in result.techniques
    )
    return VariantExecution(
        variant_id=variant.variant_id,
        run_id=result.run_id,
        manifest_path=_relative(manifest_path),
        manifest_sha256=_sha256(manifest_path),
        summary_path=_relative(summary_path),
        summary_sha256=_sha256(summary_path),
        evidence_sha256=_technique_evidence_hashes(run_dir),
        containment_path=(
            _relative(containment_path) if containment_path.exists() else None
        ),
        containment_sha256=(
            _sha256(containment_path) if containment_path.exists() else None
        ),
        containment_sealed=containment_sealed,
        techniques_total=result.total_techniques,
        techniques_success=result.successful,
        evidence_backed_successful=result.evidence_backed_successful,
        mode_status_consistent=consistent,
        teardown_clean=result.teardown_clean,
    )


def _execute_variants(
    campaign_id: str,
    variants: list[CompatibleVariant],
) -> list[VariantExecution]:
    """Run each variant through the unchanged orchestrator path and confirm the
    honesty invariant (declared_mode == executed_mode) on every technique, plus
    a clean teardown. Imported lazily to avoid a module-load import cycle."""
    from .orchestrator import build_default
    orchestrator = build_default()
    records: list[VariantExecution] = []
    for index, variant in enumerate(variants):
        label = "-canonical" if index == 0 else f"-v{index}"
        result = orchestrator.run_campaign(
            campaign_id, sut_override=variant.sut_profile, run_label=label)
        consistent = all(
            outcome.declared_mode == outcome.executed_mode
            and outcome.status == "success"
            for outcome in result.techniques
        )
        # Proof runs are not golden evidence; relocate under _archive so the
        # release gate's "golden-only at evidence root" check stays satisfied
        # while the audit trail is preserved.
        run_dir = Path(result.manifest_path).parent
        _ARCHIVE_ROOT.mkdir(parents=True, exist_ok=True)
        destination = _ARCHIVE_ROOT / run_dir.name
        if destination.exists():
            raise SubdeterminationError(
                f"refusing to overwrite existing proof run: {destination}"
            )
        shutil.move(str(run_dir), str(destination))
        _make_archived_metadata_portable(destination)
        records.append(_execution_record(variant, result, destination))
    return records


def prove_subdetermination(campaign_id: str, n_variants: int = 2,
                           seed: int = 1, execute: bool = False
                           ) -> SubdeterminationProof:
    """Assemble the constructive non-uniqueness proof for one campaign."""
    _, sut, cves = catalog.resolve(campaign_id)
    canonical_summary = provenance.summarize_profile(sut, campaign_id, cves)
    fingerprint = invariant_fingerprint(canonical_summary)
    invariant, free = partition(canonical_summary)
    free_fraction = round(canonical_summary.percentages["analyst_authored"]
                          + canonical_summary.percentages["autosut_concretized"],
                          1)
    canonical = CompatibleVariant(
        variant_id=f"{campaign_id}#canonical", seed=0, sut_profile=sut,
        free_elements_changed=[], free_fraction=free_fraction,
    )
    generator = VariantGenerator()
    variants = [generator.generate(campaign_id, seed=seed + offset)
                for offset in range(n_variants)]
    execution_runs = (
        _execute_variants(campaign_id, [canonical, *variants])
        if execute
        else []
    )
    executable = bool(execution_runs) and all(
        record.mode_status_consistent
        and record.teardown_clean
        and record.techniques_success == record.techniques_total
        and record.evidence_backed_successful == record.techniques_total
        for record in execution_runs
    )
    return SubdeterminationProof(
        campaign_id=campaign_id,
        invariant_fingerprint=fingerprint,
        invariant_count=len(invariant),
        free_count=len(free),
        free_fraction=free_fraction,
        canonical=canonical,
        variants=variants,
        execution_runs=execution_runs,
        executable=executable,
    )
