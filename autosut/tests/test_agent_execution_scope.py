import json
from pathlib import Path
import sys

import pytest
from pydantic import ValidationError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from orchestrator import caldera_operation
from orchestrator.execution_scope import AgentExecutionScope


@pytest.mark.parametrize('success', [True, False])
def test_dispatch_records_granted_session_on_success_and_failure(tmp_path, monkeypatch, success):
    monkeypatch.setattr(caldera_operation, '_dispatch_via_caldera', lambda *args:
                        caldera_operation.CalderaLinkResult(ok=success, technique_id='T1082',
                                                           ability_id='fixture', ability_name='fixture'))
    result = caldera_operation.dispatch_via_caldera('target-lab', 'T1082', tmp_path)
    evidence = json.loads((tmp_path / result.evidence_files[0]).read_text())
    assert evidence['execution_host'] == 'target-lab'
    assert evidence['access_origin'] == 'harness_provided_session'
    assert evidence['initial_access_demonstrated'] is False
    assert result.ok is success


def test_scope_survives_a_dispatch_exception(tmp_path, monkeypatch):
    def fail(*args):
        raise ConnectionError('provider unavailable')
    monkeypatch.setattr(caldera_operation, '_dispatch_via_caldera', fail)
    with pytest.raises(ConnectionError, match='provider unavailable'):
        caldera_operation.dispatch_via_caldera('target-lab', 'T1082', tmp_path)
    assert len(list((tmp_path / 'caldera').glob('*_execution_scope.json'))) == 1


def test_granted_session_cannot_be_relabeled_as_initial_compromise():
    with pytest.raises(ValidationError):
        AgentExecutionScope(execution_host='target-lab', technique_id='T1082',
                            initial_access_demonstrated=True)


def test_failed_entry_probe_returns_failure_without_inventing_a_session(tmp_path):
    from types import SimpleNamespace
    from orchestrator.executor import _shadowray_t1190
    from orchestrator.models import ExecutionMode, Realization

    attacker = SimpleNamespace(run_shell=lambda *args, **kwargs:
                               SimpleNamespace(stdout='unreachable', returncode=1))
    outcome = _shadowray_t1190(None, attacker, '192.0.2.1', tmp_path,
                              Realization.generic_primitive)
    assert outcome.status == 'failure'
    assert outcome.executed_mode is ExecutionMode.real_controlled
    assert outcome.evidence_files == ['techniques/T1190_dashboard_probe.log']
