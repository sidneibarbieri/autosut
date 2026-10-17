"""Block the replay subnet at the Docker host INPUT boundary and probe it."""

import platform
import os
import secrets
import subprocess
import time


def command(arguments):
    return subprocess.run(arguments, capture_output=True, text=True, check=True, timeout=30).stdout


def firewall(*arguments):
    context = command(['docker', 'context', 'show']).strip()
    if context == 'colima':
        return command(['colima', 'ssh', '--', 'sudo', 'iptables', '-w', *arguments])
    if platform.system() == 'Linux' and context == 'default':
        return command(['sudo', '-n', 'iptables', '-w', *arguments])
    raise RuntimeError('gateway enforcement requires local Linux Docker or Colima')


class GatewayGuard:
    def __init__(self, suffix):
        self.chain = 'AS_' + suffix
        self.listener = 'autosut-gateway-' + suffix
        self.subnet = None
        self.created = False
        self.linked = False
        self.listener_started = False

    def install(self, network, containers):
        context = command(['docker', 'context', 'show']).strip()
        if context != 'colima':
            if platform.system() != 'Linux' or context != 'default':
                raise RuntimeError('gateway enforcement requires local Linux Docker or Colima')
            if os.environ.get('DOCKER_HOST') and not os.environ['DOCKER_HOST'].startswith('unix://'):
                raise RuntimeError('Linux gateway enforcement refuses a remote DOCKER_HOST override')
            endpoint = command(['docker', 'context', 'inspect', '--format', '{{.Endpoints.docker.Host}}']).strip()
            if not endpoint.startswith('unix://'):
                raise RuntimeError('Linux gateway enforcement requires a local Unix-socket Docker daemon')
            firewall('-L', 'INPUT', '-n')
        if network.get('EnableIPv6'):
            raise ValueError('IPv6 replay networks are not qualified')
        config = network['IPAM']['Config'][0]
        self.subnet = config['Subnet']
        gateway = config['Gateway']
        port = 30000 + secrets.randbelow(20000)
        source = ('import socket; listener=socket.socket(); listener.bind(("0.0.0.0",'+str(port)+')); listener.listen(); '
                  '\nwhile True:\n connection,address=listener.accept(); connection.sendall(b"AUTOSUT_GATEWAY_PROBE"); connection.close()')
        command(['docker', 'run', '-d', '--name', self.listener, '--network', 'host', 'python:3.11-slim', 'python3', '-u', '-c', source])
        self.listener_started = True
        time.sleep(0.5)
        def probe(address):
            return (f'import socket; connection=socket.create_connection(({address!r},{port}),2); '
                    'assert connection.recv(64)==b"AUTOSUT_GATEWAY_PROBE"')
        for container in containers:
            command(['docker', 'exec', container, 'python3', '-c', probe(gateway)])
        firewall('-N', self.chain)
        self.created = True
        firewall('-A', self.chain, '-j', 'DROP')
        firewall('-I', 'INPUT', '1', '-s', self.subnet, '-j', self.chain)
        self.linked = True
        blocked = []
        for container in containers:
            source = f'import socket; result=socket.socket(); result.settimeout(2); assert result.connect_ex(({gateway!r},{port})) != 0'
            command(['docker', 'exec', container, 'python3', '-c', source])
            blocked.append(container)
        command(['docker', 'exec', self.listener, 'python3', '-c', probe('127.0.0.1')])
        rules = firewall('-L', self.chain, '-n', '-v', '-x')
        drop_counts = [int(line.split()[0]) for line in rules.splitlines()
                       if ' DROP ' in f' {line} ']
        if not drop_counts or max(drop_counts) < len(containers):
            raise RuntimeError('gateway firewall did not count both denied probes')
        return {'host_gateway_access': 'blocked_observed', 'gateway': gateway, 'subnet': self.subnet,
                'blocked_containers': blocked, 'positive_before_rule': True, 'listener_live_after_rule': True,
                'dropped_packets': max(drop_counts), 'rule_counters': rules,
                'scope': 'IPv4 INPUT to Docker host from this replay subnet; all protocols and ports',
                'provider': 'colima' if context == 'colima' else 'linux-local-docker'}

    def close(self):
        errors = []
        cleanup = []
        if self.linked:
            cleanup.append(("unlink firewall", lambda: firewall('-D', 'INPUT', '-s', self.subnet, '-j', self.chain)))
        if self.created:
            cleanup.extend([
                ("flush firewall", lambda: firewall('-F', self.chain)),
                ("remove firewall", lambda: firewall('-X', self.chain)),
            ])
        if self.listener_started:
            cleanup.append(("remove listener", lambda: command(['docker', 'rm', '-f', self.listener])))
        for action, operation in cleanup:
            try:
                operation()
            except subprocess.CalledProcessError as exc:
                errors.append(f'{action}: {exc.stderr}')
        if errors:
            raise RuntimeError('gateway cleanup failed: ' + '; '.join(errors))
        self.linked = self.created = self.listener_started = False
