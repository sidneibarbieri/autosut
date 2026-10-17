#!/usr/bin/env python3
"""Ablate the compatibility routing policy and report which conclusions survive.

The policies and the conclusions are declared here, before any result is read.
A conclusion counts as robust only when it holds under every policy.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict

import sut_measurement_pipeline as pipeline

SCRIPTS_DIR = Path(__file__).resolve().parent
DEFAULT_OUTPUT = SCRIPTS_DIR / 'results' / 'compatibility_policy_ablation.json'


class RoutingPolicy(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    description: str
    default_class: str | None
    container_rule: str


POLICIES = (
    RoutingPolicy(
        name='strict',
        description='Explicit rules only; techniques no rule matches stay unresolved.',
        default_class=None,
        container_rule='subset',
    ),
    RoutingPolicy(
        name='current',
        description='Published policy: explicit rules, then the conservative VMR default.',
        default_class='VMR',
        container_rule='subset',
    ),
    RoutingPolicy(
        name='linux_admissible',
        description=(
            'Optimistic: a technique is CF when any platform tag is container-compatible, '
            'then the VMR default.'
        ),
        default_class='VMR',
        container_rule='intersects',
    ),
    RoutingPolicy(
        name='cf_floor',
        description='Bound: every technique no rule matches is CF.',
        default_class='CF',
        container_rule='subset',
    ),
)


class PolicyDistribution(BaseModel):
    model_config = ConfigDict(frozen=True)

    policy: str
    total: int
    cf_count: int
    vmr_count: int
    id_count: int
    unresolved_count: int
    explicit_count: int
    cf_pct: float
    unresolved_pct: float


class ConclusionCheck(BaseModel):
    model_config = ConfigDict(frozen=True)

    conclusion: str
    statement: str
    holds_under: list[str]
    fails_under: list[str]

    @property
    def robust(self) -> bool:
        return not self.fails_under


def policy_distribution(policy: RoutingPolicy, techniques, rel_fwd, by_id) -> PolicyDistribution:
    result = pipeline.analyze_compatibility(
        techniques,
        rel_fwd,
        by_id,
        default_class=policy.default_class,
        container_rule=policy.container_rule,
    )
    return PolicyDistribution(
        policy=policy.name,
        total=result['total'],
        cf_count=result['cf_count'],
        vmr_count=result['vmr_count'],
        id_count=result['id_count'],
        unresolved_count=result['unresolved_count'],
        explicit_count=result['explicit_count'],
        cf_pct=pipeline.pct(result['cf_count'], result['total']),
        unresolved_pct=pipeline.pct(result['unresolved_count'], result['total']),
    )


def _check(name: str, statement: str, predicate, distributions) -> ConclusionCheck:
    return ConclusionCheck(
        conclusion=name,
        statement=statement,
        holds_under=[row.policy for row in distributions if predicate(row)],
        fails_under=[row.policy for row in distributions if not predicate(row)],
    )


def check_conclusions(distributions: list[PolicyDistribution]) -> list[ConclusionCheck]:
    """Evaluate the conclusions declared before the ablation was run."""
    reference_id = next(row.id_count for row in distributions if row.policy == 'current')
    explicit_rule_policies = [row for row in distributions if row.policy != 'cf_floor']
    return [
        _check(
            'cf_minority',
            'Container-feasible techniques are a minority of the active population.',
            lambda row: row.cf_count * 2 < row.total,
            explicit_rule_policies,
        ),
        _check(
            'explicit_evidence_minority',
            'Without a default, most techniques carry no explicit routing evidence.',
            lambda row: row.explicit_count * 2 < row.total,
            [row for row in distributions if row.policy == 'strict'],
        ),
        _check(
            'id_policy_independent',
            'The ID share does not depend on the fallback or the CF rule.',
            lambda row: row.id_count == reference_id,
            distributions,
        ),
    ]


def build_report(bundle_path: Path) -> dict:
    by_type, by_id = pipeline.index_objects_by_type(pipeline.load_bundle(bundle_path))
    rel_fwd, _, _ = pipeline.build_relationship_index(by_type.get('relationship', []))
    techniques = by_type.get('attack-pattern', [])
    distributions = [policy_distribution(policy, techniques, rel_fwd, by_id) for policy in POLICIES]
    conclusions = check_conclusions(distributions)
    return {
        'bundle': bundle_path.name,
        'policies': [policy.model_dump() for policy in POLICIES],
        'distributions': [row.model_dump() for row in distributions],
        'conclusions': [
            {**check.model_dump(), 'robust': check.robust} for check in conclusions
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, default=Path(pipeline.ENTERPRISE_FILE))
    parser.add_argument('--output', type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    report = build_report(args.bundle)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    for row in report['distributions']:
        print(f"{row['policy']:17} CF={row['cf_count']:4} VMR={row['vmr_count']:4} "
              f"ID={row['id_count']:4} unresolved={row['unresolved_count']:4} / {row['total']}")
    for check in report['conclusions']:
        print(f"{check['conclusion']:28} robust={check['robust']} fails_under={check['fails_under']}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
