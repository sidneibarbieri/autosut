"""Reviewed local operations and separate observers for two prepared campaign slices."""

import hashlib
import json
import shlex
from pathlib import Path


ROOT = '/tmp/autosut-bound'
PAYLOAD = b'print("AUTOSUT_BENIGN_TOOL")\n'
FIXTURE = b'SYNTHETIC LAB RECORD\nNo operational data.\n'
TEMPLATE_OPERATIONS = {
    'record-controlled-domain': 'domain',
    'record-controlled-compromised-domain': 'compromised-domain',
    'specify-benign-capability': 'specification',
    'stage-benign-toolkit': 'toolkit',
    'stage-benign-payload': 'payload',
    'stage-benign-tool': 'toolkit',
    'stage-lab-web-target': 'index.html',
    'visit-declared-web-target': 'visit',
    'resolve-lab-domain': 'resolve',
    'transfer-staged-benign-tool': 'transfer',
    'transfer-over-resolved-lab-channel': 'transfer',
    'collect-declared-data-fixture': 'collect',
    'archive-declared-collection': 'archive',
    'split-declared-archive': 'chunks',
}
CAMPAIGN_TEMPLATES = {
    '0.c0010': {
        'T1583.001': 'record-controlled-domain',
        'T1584.001': 'record-controlled-compromised-domain',
        'T1587.001': 'specify-benign-capability',
        'T1588.002': 'stage-benign-toolkit',
        'T1608.001': 'stage-benign-payload',
        'T1608.002': 'stage-benign-tool',
        'T1608.004': 'stage-lab-web-target',
        'T1189': 'visit-declared-web-target',
        'T1105': 'transfer-staged-benign-tool',
    },
    '0.c0026': {
        'T1583.001': 'record-controlled-domain',
        'T1568': 'resolve-lab-domain',
        'T1105': 'transfer-over-resolved-lab-channel',
        'T1005': 'collect-declared-data-fixture',
        'T1560.001': 'archive-declared-collection',
        'T1030': 'split-declared-archive',
    },
}
TEMPLATE_BINDINGS = {
    'record-controlled-domain': {'actor': 'actor.primary', 'manifest': 'infrastructure.lab_manifest'},
    'record-controlled-compromised-domain': {'actor': 'actor.primary', 'manifest': 'infrastructure.lab_manifest'},
    'specify-benign-capability': {'actor': 'actor.primary', 'specification': 'capability.benign_specification'},
    'stage-benign-toolkit': {'actor': 'actor.primary', 'toolkit': 'toolkit.benign'},
    'stage-benign-payload': {'actor': 'actor.primary', 'payload': 'payload.benign'},
    'stage-benign-tool': {'actor': 'actor.primary', 'toolkit': 'toolkit.benign'},
    'stage-lab-web-target': {'actor': 'actor.primary', 'web_asset': 'web_asset.benign_landing'},
    'visit-declared-web-target': {'endpoint': 'endpoint.public_service', 'target': 'target.primary'},
    'resolve-lab-domain': {'domain': 'infrastructure.lab_manifest', 'target': 'target.primary'},
    'transfer-staged-benign-tool': {'channel': 'channel.private_http', 'payload': 'payload.benign', 'target': 'target.primary'},
    'transfer-over-resolved-lab-channel': {'channel': 'channel.private_http', 'payload': 'payload.benign', 'target': 'target.primary'},
    'collect-declared-data-fixture': {'data_source': 'data.synthetic_fixture', 'target': 'target.primary'},
    'archive-declared-collection': {'archive_tool': 'archive_tool.local', 'target': 'target.primary'},
    'split-declared-archive': {'archive': 'archive.synthetic_collection', 'chunk_policy': 'chunk_policy.bounded_local'},
}
TEMPLATE_PREDICATES = {
    'record-controlled-domain': ['manifest_hash_recorded', 'no_external_registration'],
    'record-controlled-compromised-domain': ['manifest_hash_recorded', 'no_external_compromise'],
    'specify-benign-capability': ['specification_hash_recorded', 'no_harmful_payload_present'],
    'stage-benign-toolkit': ['artifact_hash_recorded'],
    'stage-benign-payload': ['artifact_hash_recorded', 'payload_policy_verified'],
    'stage-benign-tool': ['artifact_hash_recorded', 'tool_policy_verified'],
    'stage-lab-web-target': ['web_asset_hash_recorded', 'lab_scope_verified'],
    'visit-declared-web-target': ['http_request_logged', 'no_exploit_delivered'],
    'transfer-staged-benign-tool': ['source_and_destination_hashes_match'],
    'resolve-lab-domain': ['resolver_query_logged', 'external_dns_absent'],
    'transfer-over-resolved-lab-channel': ['source_and_destination_hashes_match'],
    'collect-declared-data-fixture': ['fixture_hash_recorded', 'no_host_data_collected'],
    'archive-declared-collection': ['archive_hash_recorded', 'input_manifest_recorded'],
    'split-declared-archive': ['chunk_manifest_recorded', 'no_external_transfer'],
}
INSPIRED_TEMPLATES = frozenset({
    'record-controlled-domain',
    'record-controlled-compromised-domain',
    'specify-benign-capability',
})


def bounded_recipe_id(contract):
    actual = [(step.technique_id, step.template_id) for step in contract.transitions]
    for recipe_id, templates in CAMPAIGN_TEMPLATES.items():
        if actual == list(templates.items()):
            if contract.campaign_id in CAMPAIGN_TEMPLATES and contract.campaign_id != recipe_id:
                raise ValueError('bounded replay sequence differs from declared campaign')
            return recipe_id
    raise ValueError('no reviewed execution adapter for campaign sequence')


def validate_bound_template(contract):
    expected = CAMPAIGN_TEMPLATES[bounded_recipe_id(contract)]
    if expected is None or len(contract.transitions) != len(expected):
        raise ValueError('no reviewed execution adapter for campaign sequence')
    if [step.technique_id for step in contract.transitions] != list(expected):
        raise ValueError('bounded replay transition order differs from reviewed sequence')
    for step in contract.transitions:
        if expected.get(step.technique_id) != step.template_id:
            raise ValueError(f'no reviewed execution adapter for {step.template_id}')
        if step.bindings != TEMPLATE_BINDINGS[step.template_id]:
            raise ValueError(f'binding mismatch for {step.template_id}')
        if step.evidence_predicates != TEMPLATE_PREDICATES[step.template_id]:
            raise ValueError(f'evidence predicate mismatch for {step.template_id}')
        expected_fidelity = 'inspired' if step.template_id in INSPIRED_TEMPLATES else 'adapted'
        if step.fidelity_ceiling != expected_fidelity:
            raise ValueError(f'fidelity ceiling exceeds reviewed adapter for {step.template_id}')


def python_command(source):
    return 'python3 -c ' + shlex.quote(source)


def checked(host, source, log):
    result = host.run_shell(python_command(source), log_name=log, timeout=30)
    if getattr(result, "exit_code", getattr(result, "returncode", None)) != 0:
        raise RuntimeError(f'bounded operation failed: {log}: {result.stderr}')
    return result.stdout


def content_for(operation):
    if operation in {'toolkit', 'payload'}:
        return PAYLOAD
    if operation == 'index.html':
        return b'<html><body>Controlled benign lab target</body></html>\n'
    return json.dumps({'scope': 'private laboratory only', 'operation': operation,
                       'domain': 'autosut-channel.test', 'external_action': False}, sort_keys=True).encode()


def observe_file(host, path, expected, log):
    actual = checked(host, f'import pathlib,hashlib; print(hashlib.sha256(pathlib.Path({path!r}).read_bytes()).hexdigest())', log).strip()
    if actual != expected:
        raise ValueError(f'independent file observer mismatch: {path}')
    return {'path': path, 'expected_sha256': expected, 'observed_sha256': actual}


def bounded_executor(contract):
    from orchestrator.models import ExecutionMode, FidelityLevel, TechniqueOutcome
    validate_bound_template(contract)

    def execute(target, attacker, target_ip, run_dir, realization):
        checked(attacker, f'import pathlib; pathlib.Path({ROOT!r}).mkdir(); pathlib.Path({ROOT + "/payload"!r}).write_bytes({PAYLOAD!r})', 'setup/actor.log')
        checked(target, f'import pathlib; pathlib.Path({ROOT!r}).mkdir(); pathlib.Path({ROOT + "/fixture"!r}).write_bytes({FIXTURE!r})', 'setup/fixture.log')
        attacker.run_shell(f'python3 -u -m http.server 8769 --bind 0.0.0.0 --directory {ROOT} > {ROOT}/http.log 2>&1 &', log_name='setup/http.log', timeout=10)
        address = checked(attacker, 'import socket; print(socket.gethostbyname(socket.gethostname()))', 'setup/address.log').strip()
        known = set(contract.initial_facts)
        outcomes = []
        for step in contract.transitions:
            missing = set(step.requires) - known
            if missing:
                raise ValueError(f'causal admission refused: {step.technique_id}: {sorted(missing)}')
            operation = TEMPLATE_OPERATIONS[step.template_id]
            prefix = f'techniques/{step.technique_id}'
            observations = []
            if operation in {'domain', 'compromised-domain', 'specification', 'toolkit', 'payload', 'index.html'}:
                content = content_for(operation)
                path = f'{ROOT}/{operation}'
                checked(attacker, f'import pathlib; pathlib.Path({path!r}).write_bytes({content!r})', prefix + '-operation.log')
                observations.append(observe_file(attacker, path, hashlib.sha256(content).hexdigest(), prefix + '-observer.log'))
            elif operation == 'resolve':
                answer = checked(target, 'import socket; print(socket.gethostbyname("autosut-channel.test"))', prefix + '-resolver.log').strip()
                if answer != address:
                    raise ValueError('lab resolver returned an undeclared endpoint')
                observations.append({'resolved_address': answer, 'expected_address': address, 'resolver_scope': 'Docker embedded DNS on private network'})
            elif operation in {'visit', 'transfer'}:
                filename = 'index.html' if operation == 'visit' else 'payload'
                destination = f'{ROOT}/{operation}'
                endpoint = 'autosut-channel.test' if step.template_id == 'transfer-over-resolved-lab-channel' else address
                checked(target, f'import pathlib,urllib.request; pathlib.Path({destination!r}).write_bytes(urllib.request.urlopen("http://{endpoint}:8769/{filename}",timeout=10).read())', prefix + '-request.log')
                observations.append(observe_file(target, destination, hashlib.sha256(content_for(filename)).hexdigest(), prefix + '-observer.log'))
                log = checked(attacker, f'import pathlib; print(pathlib.Path({ROOT + "/http.log"!r}).read_text())', prefix + '-server-observer.log')
                if f'GET /{filename} ' not in log:
                    raise ValueError('server did not observe the declared request')
                observations.append({'server_request_observed': True, 'no_exploit_delivered': True})
            elif operation == 'collect':
                observe_file(target, ROOT + '/fixture', hashlib.sha256(FIXTURE).hexdigest(), prefix + '-input-observer.log')
                checked(target, f'import shutil; shutil.copyfile({ROOT + "/fixture"!r},{ROOT + "/collection"!r})', prefix + '-operation.log')
                observations.append(observe_file(target, ROOT + '/collection', hashlib.sha256(FIXTURE).hexdigest(), prefix + '-observer.log'))
            elif operation == 'archive':
                checked(target, f'import tarfile; archive=tarfile.open({ROOT + "/collection.tar"!r},"w"); archive.add({ROOT + "/collection"!r},arcname="collection"); archive.close()', prefix + '-operation.log')
                output = checked(target, f'import tarfile,hashlib,pathlib; archive=tarfile.open({ROOT + "/collection.tar"!r}); assert archive.getnames()==["collection"]; assert archive.extractfile("collection").read()=={FIXTURE!r}; print(hashlib.sha256(pathlib.Path({ROOT + "/collection.tar"!r}).read_bytes()).hexdigest())', prefix + '-observer.log').strip()
                observations.append({'archive_sha256': output, 'input_manifest': ['collection'], 'fixture_sha256': hashlib.sha256(FIXTURE).hexdigest()})
            elif operation == 'chunks':
                checked(target, f'import pathlib; root=pathlib.Path({ROOT!r}); data=(root/"collection.tar").read_bytes(); [(root/f"chunk-{{index:04}}").write_bytes(data[index:index+1024]) for index in range(0,len(data),1024)]', prefix + '-operation.log')
                output = checked(target, f'import pathlib,hashlib,json; root=pathlib.Path({ROOT!r}); chunks=sorted(root.glob("chunk-*")); assert chunks and all(0<len(item.read_bytes())<=1024 for item in chunks); data=b"".join(item.read_bytes() for item in chunks); assert data==(root/"collection.tar").read_bytes(); print(json.dumps({{"sha256":hashlib.sha256(data).hexdigest(),"chunks":[item.name for item in chunks],"external_transfer":False}}))', prefix + '-observer.log')
                observations.append(json.loads(output))
            relative = prefix + '-predicates.json'
            (run_dir / relative).parent.mkdir(parents=True, exist_ok=True)
            (run_dir / relative).write_text(json.dumps({'template_id': step.template_id, 'bindings': step.bindings, 'declared_predicates': step.evidence_predicates, 'observations': observations, 'fidelity_ceiling': step.fidelity_ceiling}, indent=2)+'\n')
            fidelity = FidelityLevel(step.fidelity_ceiling)
            outcomes.append(TechniqueOutcome(technique_id=step.technique_id, declared_fidelity=fidelity, executed_fidelity=fidelity, declared_mode=ExecutionMode.real_controlled, executed_mode=ExecutionMode.real_controlled, realization=realization, status='success', evidence_files=[relative], notes='Observed bounded contract operation; historical APT fidelity is not certified.'))
            known.update(step.produces)
        return outcomes
    return execute
