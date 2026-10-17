"""Gateway enforcement must target the actual local Docker host."""

import pytest

from planning import gateway_guard


def test_linux_firewall_uses_noninteractive_sudo(monkeypatch):
    calls = []

    def record_command(arguments):
        calls.append(arguments)
        return 'default\n' if arguments == ['docker', 'context', 'show'] else ''

    monkeypatch.setattr(gateway_guard, 'command', record_command)
    monkeypatch.setattr(gateway_guard.platform, 'system', lambda: 'Linux')
    gateway_guard.firewall('-N', 'AS_synthetic')
    assert calls[-1] == ['sudo', '-n', 'iptables', '-w', '-N', 'AS_synthetic']


def test_remote_docker_is_refused_before_listener_or_rule_creation(monkeypatch):
    calls = []

    def record_command(arguments):
        calls.append(arguments)
        if arguments == ['docker', 'context', 'show']:
            return 'default\n'
        if arguments[:3] == ['docker', 'context', 'inspect']:
            return 'tcp://remote.example:2376\n'
        pytest.fail('remote Docker must be refused before mutation')

    monkeypatch.setattr(gateway_guard, 'command', record_command)
    monkeypatch.setattr(gateway_guard.platform, 'system', lambda: 'Linux')
    with pytest.raises(RuntimeError, match='local Unix-socket'):
        gateway_guard.GatewayGuard('synthetic').install({}, [])
    assert len(calls) == 2


def test_unqualified_platform_is_refused(monkeypatch):
    monkeypatch.setattr(gateway_guard, 'command', lambda arguments: 'default\n')
    monkeypatch.setattr(gateway_guard.platform, 'system', lambda: 'Darwin')
    with pytest.raises(RuntimeError, match='local Linux'):
        gateway_guard.firewall('-N', 'AS_synthetic')
