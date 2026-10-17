#!/usr/bin/env python3
"""Generate every corpus constraint set and all supported SUT blueprints offline."""

import argparse
import hashlib
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / 'src'))
from planning.procedural_plan import load_procedural_plan
from planning.sut_constraints import resolve_sut_constraints
from planning.sut_blueprint import BACKEND_RECIPES, synthesize_blueprint, synthesize_partial_plan


def generate(plans: Path, output: Path):
    sources = sorted(plans.glob('*.procedural-plan.json'))
    if not sources:
        raise ValueError('no procedural plans found')
    if output.exists():
        raise ValueError('corpus output already exists; preserve earlier evidence')
    loaded = [(source, load_procedural_plan(source)) for source in sources]
    identifiers = [plan.campaign_id for _, plan in loaded]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError('duplicate campaign IDs in procedural corpus')
    output.mkdir(parents=True)
    records = []
    for source, plan in loaded:
        folder = output / plan.campaign_id
        folder.mkdir()
        constraints = resolve_sut_constraints(plan, materializable_platforms=set(BACKEND_RECIPES))
        (folder / 'constraints.json').write_text(constraints.model_dump_json(indent=2)+'\n')
        record = {'campaign_id': plan.campaign_id, 'steps': len(plan.steps),
                  'source_file_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
                  'source_plan_sha256': plan.content_sha256,
                  'selected_platforms': constraints.platform_resolution.selected_platforms,
                  'unsupported_platforms': constraints.platform_resolution.unsupported_platforms,
                  'uncovered_techniques': constraints.platform_resolution.uncovered_technique_ids,
                  'status': 'unsupported_platform', 'materialized': False, 'executed': False}
        if constraints.platform_resolution.complete:
            blueprint = synthesize_blueprint(constraints)
            (folder / 'sut-blueprint.json').write_text(blueprint.model_dump_json(indent=2)+'\n')
            record.update(status='blueprint_generated', blueprint_sha256=blueprint.content_sha256,
                          required_resources=[item.model_dump(mode='json') for item in blueprint.concretized_requirements])
        elif set(constraints.platform_resolution.selected_platforms) & set(BACKEND_RECIPES):
            partial = synthesize_partial_plan(constraints)
            (folder / 'partial-sut-plan.json').write_text(partial.model_dump_json(indent=2)+'\n')
            record.update(status='partial_plan_only', partial_plan_sha256=partial.content_sha256)
        records.append(record)
    report = {'schema_version': 'autosut-corpus-suts/v1', 'campaigns': len(records),
              'steps': sum(item['steps'] for item in records),
              'blueprints_generated': sum(item['status']=='blueprint_generated' for item in records),
              'partial_plans_generated': sum(item['status']=='partial_plan_only' for item in records),
              'records': records, 'scope': 'Generated host blueprints and declared resources; no claim of corpus-wide materialization or procedural execution.'}
    (output / 'manifest.json').write_text(json.dumps(report, indent=2)+'\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plans', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    report = generate(args.plans.resolve(), args.output.resolve())
    print(json.dumps({key: report[key] for key in ('campaigns','steps','blueprints_generated','partial_plans_generated')}, indent=2))
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
