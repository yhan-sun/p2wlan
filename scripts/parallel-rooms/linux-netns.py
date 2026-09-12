#!/usr/bin/env python3
"""Exercise real room daemons and TUNs inside disposable Linux namespaces."""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any


HTTP_HELPER = r'''
import json, sys, urllib.request, urllib.error
p = json.load(sys.stdin)
headers = {"Content-Type": "application/json"}
if p["token"]: headers["Authorization"] = "Bearer " + p["token"]
data = None if p["body"] is None else json.dumps(p["body"]).encode()
r = urllib.request.Request(p["url"], data=data, headers=headers, method=p["method"])
try:
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(r, timeout=3) as response:
        text = response.read(1048576).decode()
        try: body = json.loads(text)
        except ValueError: body = text
        print(json.dumps({"status": response.status, "body": body}))
except urllib.error.HTTPError as error:
    print(json.dumps({"status": error.code, "body": None}))
'''


def redact_text(value: str) -> str:
    patterns = [
        (r'(?i)\bBearer\s+[^\s,;]+', 'Bearer [REDACTED]'),
        (r'(?i)(["\']?(?:access[_-]?token|token|password|private[_-]?key|public[_-]?key|secret|diag[_-]?auth|session[_-]?id|session[_-]?key|probe[_-]?ephemeral[_-]?public[_-]?key)["\']?\s*[:=]\s*)("[^"\r\n]*"|\'[^\'\r\n]*\'|[^\s,;]+)', r'\1[REDACTED]'),
        (r'(?i)(["\']?handshake(?:_init|_response)?["\']?\s*[:=]\s*)("[^"\r\n]*"|\'[^\'\r\n]*\'|[^\s,;]+)', r'\1[REDACTED]'),
    ]
    result = value
    for pattern, replacement in patterns:
        result = re.sub(pattern, replacement, result)
    return result


def safe_filename(value: str) -> str:
    return re.sub(r'[^A-Za-z0-9._-]+', '_', value)[:80] or 'stage'


def verify_same_profile_restart(
    previous: dict[str, Any], current: dict[str, Any], expected_process_id: int,
) -> None:
    previous_timeline = previous.get('connection_timeline') or {}
    current_timeline = current.get('connection_timeline') or {}
    if current.get('process_id') != expected_process_id:
        raise RuntimeError('restart readiness process_id does not match the new process')
    if current_timeline.get('correlation_id') == previous_timeline.get('correlation_id'):
        raise RuntimeError('restart readiness still refers to the old instance correlation_id')
    if current.get('node_id') != previous.get('node_id'):
        raise RuntimeError('same-profile restart changed node identity')
    if current.get('network_id') != previous.get('network_id'):
        raise RuntimeError('same-profile restart changed network identity')


def run(args: list[str], *, check: bool = True, **kwargs: Any) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, text=True, capture_output=True, check=check, timeout=20, **kwargs)


class Lab:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.prefix = 'pr' + secrets.token_hex(4)
        self.bridge = self.prefix + 'br'
        self.namespaces: list[str] = []
        self.links: list[str] = []
        self.processes: list[subprocess.Popen[str]] = []
        self.temp = tempfile.TemporaryDirectory(prefix='p2wlan-parallel-')
        self.root = Path(self.temp.name)
        os.chmod(self.root, 0o700)
        self.logs: list[Any] = []
        self.daemons: dict[str, dict[str, Any]] = {}
        self.daemon_history: dict[str, list[dict[str, Any]]] = {}
        self.run_id = 'parallel-' + secrets.token_hex(6)
        self.debug_dir = Path(args.debug_dir).resolve() if args.debug_dir else None
        if self.debug_dir is not None:
            self.debug_dir.mkdir(parents=True, exist_ok=True)
            os.chmod(self.debug_dir, 0o755)
        self.last_predicate: dict[str, Any] | None = None
        self.last_successful_statuses: dict[str, Any] = {}
        self.evidence: dict[str, Any] = {
            'source_commit': args.head,
            'run_id': self.run_id,
            'transport': 'direct',
            'uses_real_tun': True,
            'same_host_namespaces': True,
            'checks': {},
            'stages': [],
            'passed': False,
        }

    def ns(self, label: str) -> str:
        return self.prefix + '-' + label

    def setup(self) -> None:
        run(['ip', 'link', 'add', self.bridge, 'type', 'bridge'])
        self.links.append(self.bridge)
        run(['ip', 'link', 'set', self.bridge, 'up'])
        for index, label in enumerate(['control', 'a', 'b', 'c'], start=2):
            name = self.ns(label)
            run(['ip', 'netns', 'add', name])
            self.namespaces.append(name)
            host, peer = self.prefix + str(index) + 'h', self.prefix + str(index) + 'n'
            run(['ip', 'link', 'add', host, 'type', 'veth', 'peer', 'name', peer])
            self.links.append(host)
            run(['ip', 'link', 'set', peer, 'netns', name])
            run(['ip', 'link', 'set', host, 'master', self.bridge])
            run(['ip', 'link', 'set', host, 'up'])
            self.cmd(label, ['ip', 'link', 'set', 'lo', 'up'])
            self.cmd(label, ['ip', 'link', 'set', peer, 'name', 'eth0'])
            self.cmd(label, ['ip', 'addr', 'add', f'192.0.2.{index}/24', 'dev', 'eth0'])
            self.cmd(label, ['ip', 'link', 'set', 'eth0', 'up'])

    def cmd(self, label: str, command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        return run(['ip', 'netns', 'exec', self.ns(label), *command], **kwargs)

    def spawn(self, label: str, name: str, command: list[str], *, env: dict[str, str] | None = None, token: str | None = None) -> subprocess.Popen[str]:
        log = (self.root / (name + '.console')).open('x')
        self.logs.append(log)
        clean = {key: value for key, value in os.environ.items() if not key.startswith('P2WLAN_')}
        clean.update({'RUST_LOG': 'info', 'RUST_BACKTRACE': '0'})
        clean['P2WLAN_TEST_RUN_ID'] = self.run_id
        clean.update(env or {})
        process = subprocess.Popen(
            ['ip', 'netns', 'exec', self.ns(label), *command],
            text=True, stdin=subprocess.PIPE, stdout=log, stderr=log, env=clean,
        )
        self.processes.append(process)
        if token is not None:
            assert process.stdin is not None
            process.stdin.write(token + '\n')
            process.stdin.flush()
        if process.stdin is not None:
            process.stdin.close()
        return process

    def http(self, label: str, path: str, *, token: str = '', method: str = 'GET', body: Any = None, port: int | None = None) -> Any:
        url = f'http://127.0.0.1:{port}{path}' if port else 'http://192.0.2.2:8080' + path
        result = self.cmd(label, [sys.executable, '-c', HTTP_HELPER], input=json.dumps({
            'url': url, 'method': method, 'token': token, 'body': body,
        }))
        response = json.loads(result.stdout)
        if not 200 <= response['status'] < 300:
            raise RuntimeError(f'HTTP {response["status"]} at {method} {path}')
        return response['body']

    def wait(self, label: str, predicate: Any, timeout: float = 90) -> Any:
        deadline = time.monotonic() + timeout
        last_error: dict[str, str] | None = None
        last_result: Any = None
        while time.monotonic() < deadline:
            try:
                value = predicate()
                if value:
                    self.last_predicate = {
                        'label': label,
                        'outcome': 'ready',
                        'elapsed_ms': round((timeout - max(0, deadline - time.monotonic())) * 1000),
                    }
                    return value
                last_result = False
            except (RuntimeError, subprocess.SubprocessError, OSError, ValueError) as error:
                last_error = {
                    'type': type(error).__name__,
                    'message': redact_text(str(error))[:300],
                }
                last_result = None
            time.sleep(0.5)
        self.last_predicate = {
            'label': label,
            'outcome': 'timeout',
            'timeout_ms': round(timeout * 1000),
            'last_result': last_result,
            'last_exception': last_error,
        }
        raise RuntimeError(f'Timed out: {label}')

    def daemon(self, name: str, label: str, room: dict[str, Any], token: str, port: int) -> dict[str, Any]:
        directory = self.root / name
        directory.mkdir(exist_ok=True)
        instance = len(self.daemon_history.get(name, [])) + 1
        interface = 'p2r' + name
        command = [
            str(self.args.daemon), '--config', str(directory / 'config.json'),
            '--control', 'http://192.0.2.2:8080', '--network', room['id'],
            '--interface', interface, '--diagnostics-bind', f'127.0.0.1:{port}',
            '--log-file', str(directory / f'p2wlan-daemon.instance-{instance}.log'),
            '--device-name', name, '--udp-bind', '0.0.0.0:0',
            '--stun', '', '--heartbeat-interval', '1', '--managed', '--token-stdin',
        ]
        process_name = f'{name}.instance-{instance}'
        process = self.spawn(label, process_name, command, token=token)
        entry = dict(
            process=process,
            namespace=label,
            directory=directory,
            port=port,
            interface=interface,
            room=room,
            instance=instance,
            console=self.root / (process_name + '.console'),
            daemon_log=directory / f'p2wlan-daemon.instance-{instance}.log',
        )
        self.daemon_history.setdefault(name, []).append(entry)
        self.daemons[name] = entry
        return entry

    def status(self, name: str) -> dict[str, Any]:
        entry = self.daemons[name]
        if entry['process'].poll() is not None:
            raise RuntimeError(f'{name} instance {entry["instance"]} exited with {entry["process"].returncode}')
        token = (entry['directory'] / 'p2wlan-daemon.diag-auth').read_text().strip()
        status = self.http(entry['namespace'], '/status', token=token, port=entry['port'])
        if status.get('process_id') != entry['process'].pid:
            raise RuntimeError(f'{name} diagnostics process_id does not match launched PID')
        if status.get('network_id') != entry['room']['id'] or not status.get('virtual_ip'):
            raise RuntimeError('Room diagnostics identity mismatch')
        return status

    def verify_restart(self, name: str, previous: dict[str, Any]) -> dict[str, Any]:
        status = self.status(name)
        verify_same_profile_restart(previous, status, self.daemons[name]['process'].pid)
        return status

    def _safe_status(self, name: str, status: dict[str, Any]) -> dict[str, Any]:
        entry = self.daemons[name]
        timeline = status.get('connection_timeline') or {}
        peer_ids = sorted(
            peer.get('node_id', '')
            for peer in status.get('peers', [])
            if peer.get('node_id')
        )
        peer_status: dict[str, Any] = {}
        diag_token_path = entry['directory'] / 'p2wlan-daemon.diag-auth'
        if diag_token_path.exists():
            token = diag_token_path.read_text().strip()
            for peer_id in peer_ids:
                try:
                    peer = self.http(
                        entry['namespace'],
                        '/status/peer/' + peer_id,
                        token=token,
                        port=entry['port'],
                    )
                    scoped = peer.get('peer') or {}
                    peer_status[peer_id] = {
                        key: scoped.get(key)
                        for key in (
                            'online', 'state', 'active_path', 'direct_generation',
                            'remote_candidate_generation', 'remote_candidate_epoch',
                            'bytes_sent', 'bytes_received',
                            'direct', 'selected_pair', 'current_direct_pair',
                        )
                    }
                    probe_session_id = scoped.get('probe_session_id')
                    peer_status[peer_id]['probe_session_id_fingerprint'] = (
                        hashlib.sha256(probe_session_id.encode()).hexdigest()[:16]
                        if isinstance(probe_session_id, str) and probe_session_id
                        else None
                    )
                    peer_status[peer_id]['peer_session_generation'] = peer.get('peer_session_generation')
                    peer_status[peer_id]['network_generation'] = peer.get('network_generation')
                except (RuntimeError, subprocess.SubprocessError, OSError, ValueError) as error:
                    peer_status[peer_id] = {'capture_error': redact_text(str(error))[:200]}
        return {
            'name': name,
            'instance': entry['instance'],
            'pid': entry['process'].pid,
            'process_alive': entry['process'].poll() is None,
            'process_id': status.get('process_id'),
            'runtime_incarnation': status.get('runtime_incarnation'),
            'correlation_id': timeline.get('correlation_id'),
            'run_id': timeline.get('run_id'),
            'node_id': status.get('node_id'),
            'network_id': status.get('network_id'),
            'network_generation': status.get('network_generation'),
            'uptime_ms': status.get('uptime_ms'),
            'ready_phase': status.get('ready_phase'),
            'candidate_snapshot_version': status.get('candidate_snapshot_version'),
            'candidate_snapshot_hash': status.get('candidate_snapshot_hash'),
            'udp_local_addr': status.get('udp_local_addr'),
            'udp_socket_count': status.get('udp_socket_count'),
            'peer_snapshot_stale': status.get('peer_snapshot_stale'),
            'health': {
                'status': (status.get('health') or {}).get('status'),
                'reason': redact_text((status.get('health') or {}).get('reason') or '')[:300],
                'critical_tasks': [
                    {
                        'name': task.get('name'),
                        'running': task.get('running'),
                        'finished': task.get('finished'),
                        'error': redact_text(task.get('error') or '')[:300],
                    }
                    for task in ((status.get('health') or {}).get('critical_tasks') or [])[:64]
                ],
            },
            'peers': peer_status,
            'connection_timeline_events': [
                {
                    'at_ms': event.get('at_ms'),
                    'event': event.get('event'),
                    'path': event.get('path'),
                    'reason_code': event.get('reason_code'),
                    'detail': redact_text(event.get('detail') or '')[:500],
                }
                for event in (timeline.get('events') or [])[-120:]
            ],
        }

    def _network_state(self, name: str) -> dict[str, Any]:
        entry = self.daemons[name]
        interface = entry['interface']
        namespace = entry['namespace']
        commands = {
            'tun_link': ['ip', '-j', '-details', 'link', 'show', 'dev', interface],
            'tun_addresses': ['ip', '-j', 'address', 'show', 'dev', interface],
            'tun_routes': ['ip', '-j', '-4', 'route', 'show', 'table', 'all', 'dev', interface],
            'room_routes': ['ip', '-j', '-4', 'route', 'show', 'exact', entry['room']['cidr']],
            'udp_sockets': ['ss', '-H', '-u', '-a', '-n', '-p'],
        }
        result: dict[str, Any] = {}
        for key, command in commands.items():
            try:
                completed = self.cmd(namespace, command, check=False)
                result[key] = {
                    'returncode': completed.returncode,
                    'output': redact_text(completed.stdout + completed.stderr)[:12000],
                }
            except (RuntimeError, subprocess.SubprocessError, OSError, ValueError) as error:
                result[key] = {'error': redact_text(str(error))[:300]}
        return result

    def capture_stage(self, label: str, *, successful: bool = False) -> None:
        stage: dict[str, Any] = {
            'label': label,
            'captured_at_unix_ms': int(time.time() * 1000),
            'last_predicate': self.last_predicate,
            'daemons': {},
        }
        for name in ['a1', 'a2', 'b1', 'c2']:
            entry = self.daemons.get(name)
            if entry is None:
                continue
            try:
                status = self.status(name)
                safe_status = self._safe_status(name, status)
                daemon_stage = {
                    'status': safe_status,
                    'network': self._network_state(name),
                }
                stage['daemons'][name] = daemon_stage
                if successful:
                    self.last_successful_statuses[name] = daemon_stage
            except (RuntimeError, subprocess.SubprocessError, OSError, ValueError) as error:
                stage['daemons'][name] = {
                    'status_error': {
                        'type': type(error).__name__,
                        'message': redact_text(str(error))[:300],
                    },
                    'process': {
                        'pid': entry['process'].pid,
                        'returncode': entry['process'].poll(),
                        'instance': entry['instance'],
                    },
                    'network': self._network_state(name),
                }
        self.evidence['stages'].append(stage)
        if successful:
            self.evidence['last_successful_statuses'] = self.last_successful_statuses
        if self.debug_dir is not None:
            stage_path = self.debug_dir / f'{len(self.evidence["stages"]):02d}-{safe_filename(label)}.json'
            stage_path.write_text(json.dumps(stage, indent=2) + '\n')
            os.chmod(stage_path, 0o644)

    def preserve_logs(self) -> None:
        if self.debug_dir is None:
            return
        for name, entries in self.daemon_history.items():
            for entry in entries:
                for kind, source in [('console', entry['console']), ('daemon', entry['daemon_log'])]:
                    if not source.exists():
                        continue
                    # Keep bounded tails while retaining one file per daemon instance.
                    lines = source.read_text(errors='replace').splitlines()[-5000:]
                    destination = self.debug_dir / f'{name}.instance-{entry["instance"]}.{kind}.log'
                    destination.write_text('\n'.join(redact_text(line) for line in lines) + '\n')
                    os.chmod(destination, 0o644)

    def capture_failure(self, error: Exception) -> None:
        self.evidence['failure_type'] = type(error).__name__
        self.evidence['failure_stage'] = self.last_predicate
        self.evidence['last_predicate_exception'] = self.last_predicate
        self.evidence['failure_detail'] = redact_text(str(error))[:300]
        self.capture_stage('failure')
        self.preserve_logs()

    def ping(self, label: str, address: str, count: int = 2) -> bool:
        return self.cmd(label, ['ping', '-n', '-c', str(count), '-i', '0.2', '-W', '1', address], check=False).returncode == 0

    def check(self, name: str, condition: bool) -> None:
        self.evidence['checks'][name] = bool(condition)
        if not condition:
            raise RuntimeError('Check failed: ' + name)
        print('PASS ' + name, flush=True)

    def exercise(self) -> None:
        identity = json.loads(run([str(self.args.daemon), '--build-info']).stdout)
        self.check('binary_matches_source', identity.get('git_commit') == self.args.head)
        self.setup()
        self.spawn('control', 'control', [str(self.args.control)], env={
            'PORT': '8080', 'DB_PATH': str(self.root / 'control.db'), 'JWT_SECRET': secrets.token_hex(32),
        })
        self.wait('control readiness', lambda: self.http('control', '/health'), 20)
        users = {}
        password = secrets.token_urlsafe(24)
        for label in ['a', 'b', 'c']:
            users[label] = self.http('control', '/api/v1/register', method='POST', body={
                'email': label + '@parallel.example', 'password': password,
            })
        rooms = {}
        for number, owner in [(1, 'b'), (2, 'c')]:
            rooms[number] = self.http('control', '/api/v1/rooms', method='POST', token=users[owner]['token'], body={
                'name': f'Parallel Room {number}', 'password': password,
            })['room']
            self.http('control', '/api/v1/rooms/join', method='POST', token=users['a']['token'], body={
                'room_code': rooms[number]['room_code'], 'password': password,
            })
        self.check('distinct_room_cidrs', rooms[1]['cidr'] != rooms[2]['cidr'])
        for name, namespace, number, port in [('a1', 'a', 1, 41001), ('a2', 'a', 2, 41002), ('b1', 'b', 1, 41001), ('c2', 'c', 2, 41001)]:
            self.daemon(name, namespace, rooms[number], users[namespace]['token'], port)
        snapshots = {name: self.wait(name + ' readiness', lambda name=name: self.status(name)) for name in self.daemons}
        ips = {name: snapshot['virtual_ip'] for name, snapshot in snapshots.items()}
        self.evidence['assigned_ips'] = ips
        for name in ['a1', 'a2', 'b1', 'c2']:
            routes = json.loads(self.cmd(self.daemons[name]['namespace'], ['ip', '-j', '-4', 'route', 'show', 'exact', self.daemons[name]['room']['cidr']]).stdout)
            self.check(name + '_real_tun_route', any(row.get('dev') == self.daemons[name]['interface'] for row in routes))
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            futures = [pool.submit(self.wait, 'bidirectional ' + name, lambda namespace=namespace, peer=peer: self.ping(namespace, ips[peer]))
                       for name, namespace, peer in [('a1', 'a', 'b1'), ('a2', 'a', 'c2'), ('b1', 'b', 'a1'), ('c2', 'c', 'a2')]]
            self.check('both_rooms_bidirectional_parallel', all(future.result() for future in futures))
        self.capture_stage('initial_bidirectional_direct', successful=True)
        self.check('independent_node_ids', snapshots['a1']['node_id'] != snapshots['a2']['node_id'])
        other = self.daemons['a2']['process']
        first = self.daemons['a1']
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            uninterrupted = pool.submit(self.ping, 'a', ips['c2'], 40)
            auth = (first['directory'] / 'p2wlan-daemon.diag-auth').read_text().strip()
            pre_restart_status = self.status('a1')
            self.capture_stage('a1_pre_restart', successful=True)
            self.http('a', '/shutdown', token=auth, method='POST', port=41001)
            first['process'].wait(timeout=15)
            self.check('one_room_stop_preserves_other_traffic', uninterrupted.result())
        self.check('other_process_unchanged', other.poll() is None and self.status('a2')['process_id'] == snapshots['a2']['process_id'])
        routes = json.loads(self.cmd('a', ['ip', '-j', '-4', 'route', 'show', 'exact', rooms[1]['cidr']]).stdout)
        self.check('stopped_room_route_removed', not routes)
        self.capture_stage('a1_stopped_before_restart')
        self.daemon('a1', 'a', rooms[1], users['a']['token'], 41001)
        self.wait('restarted a1', lambda: self.verify_restart('a1', pre_restart_status))
        self.capture_stage('a1_post_restart_ready', successful=True)
        self.wait('restarted room traffic', lambda: self.ping('a', ips['b1']))
        self.capture_stage('a1_post_restart_traffic', successful=True)
        self.check('room_restart_preserves_other', self.ping('a', ips['c2']))
        started = time.monotonic()
        self.http('control', f'/api/v1/rooms/{rooms[1]["id"]}/members/{users["a"]["user"]["id"]}',
                  method='DELETE', token=users['b']['token'])
        time.sleep(max(0, 31 - (time.monotonic() - started)))
        self.check('revoked_room_cannot_send_after_lease', not self.ping('a', ips['b1']))
        self.check('revoked_room_cannot_receive_after_lease', not self.ping('b', ips['a1']))
        self.check('other_room_survives_revocation', self.ping('a', ips['c2']) and self.ping('c', ips['a2']))
        self.evidence['passed'] = True
        self.capture_stage('all_assertions_passed', successful=True)

    def close(self) -> None:
        for process in reversed(self.processes):
            if process.poll() is None:
                process.terminate()
        for process in reversed(self.processes):
            try:
                process.wait(timeout=12)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        for namespace in reversed(self.namespaces):
            run(['ip', 'netns', 'delete', namespace], check=False)
        for link in reversed(self.links):
            run(['ip', 'link', 'delete', link], check=False)
        for log in self.logs:
            log.close()
        self.temp.cleanup()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--daemon', type=lambda value: Path(value).resolve(), required=True)
    parser.add_argument('--control', type=lambda value: Path(value).resolve(), required=True)
    parser.add_argument('--head', required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--debug-dir', type=Path)
    args = parser.parse_args()
    if sys.platform != 'linux' or os.geteuid() != 0 or not Path('/dev/net/tun').exists():
        parser.error('Linux root and /dev/net/tun are required; mock TUN is not accepted')
    if not shutil.which('ip') or not shutil.which('ping'):
        parser.error('iproute2 and iputils-ping are required')
    for binary in [args.daemon, args.control]:
        if not binary.is_file() or not os.access(binary, os.X_OK):
            parser.error('Missing executable: ' + str(binary))
    lab = Lab(args)
    try:
        lab.exercise()
        return 0
    except Exception as error:
        lab.capture_failure(error)
        if isinstance(error, RuntimeError):
            print(redact_text(str(error)), file=sys.stderr)
        for name, entries in lab.daemon_history.items():
            for entry in entries:
                for kind, log_path in [('daemon', entry['daemon_log']), ('console', entry['console'])]:
                    if not log_path.exists():
                        continue
                    lines = [redact_text(line) for line in log_path.read_text(errors='replace').splitlines()[-120:]]
                    if lines:
                        print(f"=== {name} instance {entry['instance']} {kind} tail ===", file=sys.stderr)
                        print("\n".join(lines), file=sys.stderr)
        print('FAIL real TUN parallel rooms: ' + type(error).__name__, file=sys.stderr)
        return 1
    finally:
        try:
            lab.close()
            lab.evidence['cleanup_completed'] = True
        except Exception as error:
            lab.evidence['cleanup_completed'] = False
            lab.evidence['passed'] = False
            lab.evidence['cleanup_error_type'] = type(error).__name__
            raise
        finally:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(lab.evidence, indent=2) + '\n')


if __name__ == '__main__':
    raise SystemExit(main())
