"""Test the Docker installer without a daemon, registry or privileged writes."""
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import unittest

if os.name == 'posix':
    import pty


ROOT = Path(__file__).resolve().parents[2]
ACCOUNT_INPUT = [('管理员账号', 'operator'), ('管理员密码（', 'sample pass for test'), ('确认管理员密码', 'sample pass for test')]
IMAGE = 'registry.example.test/p2wlan-server@sha256:' + 'a' * 64
IMAGE_ID = 'sha256:' + 'b' * 64
COMMIT = 'c' * 40


class DockerInstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        self.target = self.path / 'deployment'
        self.bin = self.path / 'bin'
        self.bin.mkdir()
        self.log = self.path / 'docker-calls.jsonl'
        self.script = self.path / 'install-server-docker.sh'
        self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ['PATH'],
                        DOCKER_FIXTURE_LOG=str(self.log), DOCKER_FIXTURE_IMAGE=IMAGE,
                        DOCKER_FIXTURE_ID=IMAGE_ID, DOCKER_FIXTURE_COMMIT=COMMIT)
        self.executable(self.bin / 'docker', '#!' + sys.executable + '\n' + r'''
import json, os, pathlib, sys, urllib.parse
args = sys.argv[1:]
with open(os.environ['DOCKER_FIXTURE_LOG'], 'a') as log:
    log.write(json.dumps({'args': args, 'env': {key: os.environ.get(key) for key in
        ('P2WLAN_IMAGE', 'P2WLAN_CONFIG_DIR', 'RELAY_PUBLISH_HOST', 'P2WLAN_BUILD_CONTEXT',
         'P2WLAN_BUILD_IMAGE', 'P2WLAN_VERSION', 'P2WLAN_COMMIT')}}) + '\n')
if args[:1] == ['info']:
    if os.environ.get('FAIL_DOCKER_INFO'): sys.exit(1)
    print(json.dumps({'OSType': os.environ.get('DOCKER_FIXTURE_OS', 'linux'),
                      'Architecture': 'x86_64',
                      'SecurityOptions': [os.environ['DOCKER_FIXTURE_SECURITY']] if os.environ.get('DOCKER_FIXTURE_SECURITY') else []}))
elif args[:2] == ['context', 'inspect']:
    print(os.environ.get('DOCKER_FIXTURE_CONTEXT', 'unix:///fixture/docker.sock'))
elif args[:2] == ['compose', 'version']:
    print('2.39.4')
elif args[:2] == ['compose', 'up'] and '--help' in args:
    print('' if os.environ.get('DOCKER_FIXTURE_NO_WAIT') else '--wait --wait-timeout')
elif args[:1] == ['ps']:
    if os.environ.get('FIXTURE_WEB_CONTAINER') and pathlib.Path(os.environ['FIXTURE_WEB_CONTAINER']).exists():
        print('f' * 64)
elif args[:2] == ['container', 'inspect']:
    entry = json.loads(pathlib.Path(os.environ['FIXTURE_WEB_CONTAINER']).read_text())
    print('\t'.join(['f' * 64, '/' + entry['name'], json.dumps(entry.get('removable', False)), json.dumps(entry.get('project', '')),
                    json.dumps(entry.get('service', '')), json.dumps(entry['ports'])]))
elif args[:1] == ['stop']:
    assert args[-1] == 'f' * 64
    if os.environ.get('FAIL_FIXTURE_STOP'): sys.exit(1)
    pathlib.Path(os.environ['FIXTURE_WEB_CONTAINER']).unlink()
elif args[:2] == ['image', 'inspect']:
    print(json.dumps({'Id': os.environ['DOCKER_FIXTURE_ID'], 'RepoDigests': [os.environ['DOCKER_FIXTURE_IMAGE']],
          'Os': 'linux', 'Architecture': 'amd64',
          'Config': {'Labels': {'org.opencontainers.image.revision': os.environ.get('DOCKER_FIXTURE_LABEL_COMMIT', os.environ['DOCKER_FIXTURE_COMMIT']),
                               'org.opencontainers.image.version': os.environ.get('DOCKER_FIXTURE_VERSION', 'server-v9.9.9')}}}))
elif args[:1] == ['pull']:
    if os.environ.get('FAIL_DOCKER_PULL'): sys.exit(1)
elif args[:1] == ['run']:
    if '--version' in args and '--entrypoint' in args:
        component = pathlib.Path(args[args.index('--entrypoint') + 1]).name
        version = os.environ.get('DOCKER_FIXTURE_VERSION', 'server-v9.9.9')
        commit = os.environ.get('DOCKER_FIXTURE_BINARY_COMMIT', os.environ['DOCKER_FIXTURE_COMMIT'])
        print(f"{component} {version} ({commit})")
        sys.exit(0)
    if '--help' in args:
        print('--mode --output --relay-endpoint --tls-cert --tls-key --dev-localhost')
        sys.exit(0)
    if '--output' not in args: sys.exit(0)
    if '--admin-user' in args:
        assert '--interactive' in args and args[args.index('--admin-user') + 1] == 'operator'
        assert sys.stdin.readline().rstrip('\n') == 'sample pass for test'
    if os.environ.get('FAIL_DOCKER_GENERATE'): sys.exit(1)
    mounts = []
    for index, arg in enumerate(args):
        if arg == '--mount':
            mount = dict(item.split('=', 1) for item in args[index + 1].split(',') if '=' in item)
            mounts.append((mount.get('dst') or mount.get('target'), mount.get('src') or mount.get('source')))
    output = args[args.index('--output') + 1]
    for destination, source in sorted(mounts, key=lambda item: len(item[0] or ''), reverse=True):
        if output == destination or output.startswith(destination + '/'):
            output = source + output[len(destination):]
            break
    output = pathlib.Path(output)
    output.mkdir(mode=0o700)
    (output / 'data').mkdir(mode=0o700)
    uid, gid = (int(value) for value in args[args.index('--user') + 1].split(':'))
    uid, gid = uid or 10001, gid or 10001
    control_port = int(args[args.index('--control-port') + 1]) if '--control-port' in args else 18080
    metrics_port = int(args[args.index('--metrics-port') + 1]) if '--metrics-port' in args else 18082
    endpoint = args[args.index('--relay-endpoint') + 1]
    relay_port = urllib.parse.urlparse(endpoint).port or 18081
    values = {
        'control.env': f'PORT={control_port}\nCONTROL_BIND=:{control_port}\nDB_PATH=/data/p2pnet.db\nLOG_UPLOAD_DIR=/data/log-uploads\nCONTROL_ADMIN_TOKEN=fixture-private-token\n',
        'relay.env': f'RELAY_BIND=:{relay_port}\nRELAY_METRICS_BIND=127.0.0.1:{metrics_port}\nRELAY_TLS_CERT=/etc/p2wlan/tls.crt\n',
        'compose.env': f'P2WLAN_UID={uid}\nP2WLAN_GID={gid}\nCONTROL_PORT={control_port}\nRELAY_PORT={relay_port}\nMETRICS_PORT={metrics_port}\nRELAY_PUBLISH_HOST=127.0.0.1\n',
        'tls.crt': 'fixture-certificate', 'tls.key': 'fixture-private-key',
    }
    if (output.parent / 'input.crt').is_file():
        values['tls.crt'] = (output.parent / 'input.crt').read_text()
        values['tls.key'] = (output.parent / 'input.key').read_text()
    for name, value in values.items():
        path = output / name
        path.write_text(value)
        path.chmod(0o600)
    if os.getuid() == 0:
        for path in [output, output / 'data'] + list(output.iterdir()): os.chown(path, uid, gid)
elif args[:1] == ['compose']:
    if 'build' in args:
        if os.environ.get('FAIL_DOCKER_BUILD'): sys.exit(1)
    elif 'config' in args:
        if os.environ.get('FAIL_COMPOSE_CONFIG'): sys.exit(1)
    elif 'up' in args:
        if os.environ.get('FAIL_FIXTURE_IMAGE') == os.environ.get('P2WLAN_IMAGE') and os.environ.get('FAIL_FIXTURE_IMAGE'):
            import sqlite3
            with sqlite3.connect(os.environ['FIXTURE_DATABASE']) as db:
                db.execute("INSERT INTO entries VALUES ('during-upgrade')")
                if os.environ.get('FIXTURE_MIGRATION'):
                    db.execute("ALTER TABLE entries ADD COLUMN device TEXT")
            sys.exit(1)
        if os.environ.get('FAIL_COMPOSE_UP'): sys.exit(1)
    elif 'ps' in args:
        services = os.environ.get('DOCKER_FIXTURE_RUNNING', '')
        if '--all' in args: services = os.environ.get('DOCKER_FIXTURE_PRESENT', services)
        print(services if '--services' in args else '[]')
else:
    print('unsupported fake Docker command', file=sys.stderr)
    sys.exit(92)
''')
        # A deployment must not unexpectedly install Docker or build source.
        self.executable(self.bin / 'curl', '#!/bin/sh\ncase "$*" in *--connect-to*https://*/health) echo "${FIXTURE_PANEL_CODE:-200}";; *) exit 94;; esac\n')
        for command in ('apt-get', 'dnf', 'sudo'):
            self.executable(self.bin / command, '#!/bin/sh\necho unexpected-external-command >&2\nexit 94\n')

    def assert_no_application_pull(self, calls):
        edge = 'nginxinc/nginx-unprivileged:1.27-alpine'
        pulled = [call['args'] for call in calls if call['args'][:1] == ['pull'] and call['args'][1:2] != [edge]]
        self.assertEqual(pulled, [])

    @staticmethod
    def executable(path, content):
        if path.is_symlink():
            path.unlink()
        path.write_text(content)
        path.chmod(0o755)

    def run_installer(self, *args, image=IMAGE):
        shutil.copyfile(ROOT / 'scripts/install-server-docker.sh', self.script)
        shutil.copyfile(ROOT / 'deploy/selfhost/compose.production.yml', self.path / 'compose.production.yml')
        command = ['bash', str(self.script), '--non-interactive', '--dir', str(self.target)]
        if image is not None:
            command += ['--image', image]
        command += list(args)
        return subprocess.run(command, cwd=self.path, env=self.env, input='', capture_output=True,
                              text=True, start_new_session=True, timeout=20)

    def calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def run_interactive(self, steps, *args, include_dir=True, image=IMAGE, before_reply=None):
        shutil.copyfile(ROOT / 'scripts/install-server-docker.sh', self.script)
        shutil.copyfile(ROOT / 'deploy/selfhost/compose.production.yml', self.path / 'compose.production.yml')
        command = ['bash', str(self.script), '--interactive']
        if image is not None:
            command += ['--image', image]
        if include_dir:
            command += ['--dir', str(self.target)]
        command += list(args)
        pid, terminal = pty.fork()
        if pid == 0:
            os.chdir(self.path)
            os.execve('/bin/bash', command, self.env)
        transcript, status, cursor = bytearray(), None, 0
        pending = list(steps)
        try:
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                if select.select([terminal], [], [], 0.1)[0]:
                    try:
                        transcript.extend(os.read(terminal, 65536))
                    except OSError:
                        pass
                    output = transcript.decode(errors='replace')
                    while pending:
                        needle, reply = pending[0]
                        found = output.find(needle, cursor)
                        if found < 0:
                            break
                        if before_reply:
                            before_reply(needle, output)
                        data = reply if isinstance(reply, bytes) else reply.encode()
                        os.write(terminal, data + b'\n')
                        cursor = found + len(needle)
                        pending.pop(0)
                waited, child_status = os.waitpid(pid, os.WNOHANG)
                if waited:
                    status = child_status
                    break
            output = transcript.decode(errors='replace')
            self.assertIsNotNone(status, output)
            self.assertTrue(os.WIFEXITED(status), output)
            self.assertFalse(pending, f'unanswered prompts {pending!r}\n{output}')
            return os.WEXITSTATUS(status), output
        finally:
            os.close(terminal)
            if status is None:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)

    def assert_not_deployed(self):
        self.assertFalse(self.target.exists())
        for call in self.calls():
            arguments = call['args']
            self.assertFalse(arguments[:1] in (['pull'], ['run']), arguments)
            self.assertFalse(arguments[:1] == ['compose'] and 'up' in arguments and '--help' not in arguments, arguments)
            self.assertFalse(arguments[:1] == ['compose'] and 'build' in arguments, arguments)

    def source_bundle(self, *, name='source-bundle', commit=COMMIT, version='server-v9.9.9'):
        directory = self.path / name
        files = {
            'server/Dockerfile': (ROOT / 'server/Dockerfile').read_bytes(),
            'server/go.mod': b'module example.test/server\n',
            'server/go.sum': b'',
            'server/main.go': b'package main\nfunc main() {}\n',
            'scripts/install-server-docker.sh': (ROOT / 'scripts/install-server-docker.sh').read_bytes(),
            'deploy/selfhost/compose.production.yml': (ROOT / 'deploy/selfhost/compose.production.yml').read_bytes(),
            'deploy/selfhost/compose.build.yml': b'''services:
  builder:
    image: "${P2WLAN_BUILD_IMAGE}"
    build:
      context: "${P2WLAN_BUILD_CONTEXT}"
      args:
        VERSION: "${P2WLAN_VERSION}"
        COMMIT: "${P2WLAN_COMMIT}"
''',
        }
        for relative, content in files.items():
            path = directory / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        metadata = dict(schema_version=1, version=version, source_sha=commit, context='server',
                        files={relative: hashlib.sha256(content).hexdigest() for relative, content in files.items()})
        self.write_source_manifest(directory, metadata)
        return directory

    @staticmethod
    def write_source_manifest(directory, metadata):
        content = (json.dumps(metadata, sort_keys=True, indent=2) + '\n').encode()
        (directory / 'SERVER-SOURCE.json').write_bytes(content)
        digest = hashlib.sha256(content).hexdigest()
        (directory / 'SERVER-SOURCE.json.sha256').write_text(f'{digest}  SERVER-SOURCE.json\n')

    def manifest(self, *, commit=COMMIT, checksum=True):
        path = self.path / 'SERVER-IMAGE.json'
        path.write_text(json.dumps({'schema_version': 1, 'version': 'server-v9.9.9',
                                    'source_sha': commit, 'image': IMAGE}))
        digest = hashlib.sha256(path.read_bytes()).hexdigest() if checksum else '0' * 64
        (self.path / 'SERVER-IMAGE.json.sha256').write_text(f'{digest}  SERVER-IMAGE.json\n')

    def test_busy_acme_port_reports_planned_addresses_before_any_build(self):
        import socket
        self.certbot_stub('relay.example.test')
        with socket.socket() as busy:
            busy.bind(('127.0.0.1', 0))
            busy.listen()
            # Exercise a real bind collision without reserving privileged host port 80.
            (self.path / 'sitecustomize.py').write_text(
                'import socket\noriginal = socket.socket.bind\n'
                'def bind(sock, addr):\n'
                f'    if addr == ("0.0.0.0", 80): addr = ("127.0.0.1", {busy.getsockname()[1]})\n'
                '    return original(sock, addr)\nsocket.socket.bind = bind\n')
            self.env['PYTHONPATH'] = str(self.path)
            result = self.run_installer('--tls-mode', 'auto', '--tls-domain', 'relay.example.test',
                                        '--relay-endpoint', 'tls://relay.example.test:18081', '--no-start')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('TCP 80 已被占用', result.stderr)
        self.assertIn('本次部署未完成', result.stderr)
        self.assertIn('管理后台地址：https://relay.example.test/admin/', result.stderr)
        self.assertFalse(self.target.exists())
        self.assertEqual(self.calls(), [])

    def test_dry_run_does_not_contact_docker_or_create_the_deployment(self):
        result = self.run_installer('--dev-localhost', '--dry-run')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.target.exists())
        self.assertEqual(self.calls(), [])

    def existing_web_conflict(self):
        cert, key = self.path / 'cert.pem', self.path / 'key.pem'
        cert.write_text('fixture-certificate')
        key.write_text('fixture-private-key')
        result = self.run_installer('--relay-endpoint', 'tls://relay.example.test:18081',
                                    '--tls-cert', str(cert), '--tls-key', str(key), '--no-start')
        self.assertEqual(result.returncode, 0, result.stderr)
        # Older deployments persisted neither of the host web port fields.
        settings = self.target / '.env'
        settings.write_text(''.join(line for line in settings.read_text().splitlines(keepends=True)
                                    if not line.startswith(('P2WLAN_HTTP_PORT=', 'P2WLAN_HTTPS_PORT=', 'P2WLAN_EDGE_CONF='))))
        container = self.path / 'published-ports.json'
        container.write_text(json.dumps({'name': 'existing-site', 'ports': {
            '8080/tcp': [{'HostPort': '80', 'HostIp': '0.0.0.0'}],
            '8443/tcp': [{'HostPort': '443', 'HostIp': '0.0.0.0'}]}}))
        self.env['FIXTURE_WEB_CONTAINER'] = str(container)
        self.log.unlink()
        return container

    def test_unattended_conflict_preserves_previous_deployment_and_recovery_record(self):
        owner = self.existing_web_conflict()
        marker = self.target / '.recovery-required'
        marker.write_text('Keep the original pre-migration snapshot')
        original = (self.target / '.env').read_bytes()
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('TCP 80 已被占用', result.stderr)
        self.assertEqual(original, (self.target / '.env').read_bytes())
        self.assertEqual(marker.read_text(), 'Keep the original pre-migration snapshot')
        self.assertTrue(owner.exists())
        self.assertFalse(any(call['args'][0] in ('stop', 'pull', 'run') or 'build' in call['args']
                             or 'up' in call['args'] and '--help' not in call['args'] for call in self.calls()))

    @unittest.skipUnless(os.name == 'posix', 'interactive terminal requires POSIX')
    def test_conflicting_upgrade_can_keep_the_site_and_select_new_web_ports(self):
        owner = self.existing_web_conflict()
        private = (self.target / 'config/control.env').read_bytes()
        snapshot = self.target / '.upgrade-example' / 'database.sqlite'
        snapshot.parent.mkdir()
        snapshot.write_bytes(b'original pre-migration snapshot')
        recovery = self.target / '.recovery-required'
        recovery.write_text(f'Activation in progress. Snapshot: {snapshot}\n')
        code, output = self.run_interactive([
            ('启动方式', '1'), ('确认部署', '1'), ('处理端口冲突', '1'),
            ('网页 HTTP 端口', '38000'), ('网页 HTTPS 端口', '38443'), ('确认使用这些网页端口', '1')])
        self.assertEqual(code, 0, output)
        self.assertIn('Docker existing-site', output)
        self.assertIn('管理后台地址：https://relay.example.test:38443/admin/', output)
        self.assertTrue(owner.exists())
        self.assertFalse(recovery.exists())
        self.assertEqual(snapshot.read_bytes(), b'original pre-migration snapshot')
        self.assertEqual(private, (self.target / 'config/control.env').read_bytes())
        settings = (self.target / '.env').read_text()
        self.assertIn('P2WLAN_HTTP_PORT=38000', settings)
        self.assertIn('P2WLAN_HTTPS_PORT=38443', settings)
        self.assertIn('https://$host:38443$request_uri', (self.target / 'config/edge/nginx-38443.conf').read_text())
        self.assertIn('https://$host$request_uri', (self.target / 'config/edge/nginx.conf').read_text())
        self.assertFalse(any(call['args'][0] == 'stop' for call in self.calls()))

    @unittest.skipUnless(os.name == 'posix', 'interactive terminal requires POSIX')
    def test_stopping_a_named_container_requires_confirmation_and_rechecks_the_owner(self):
        owner = self.existing_web_conflict()
        code, output = self.run_interactive([
            ('启动方式', '1'), ('确认部署', '1'), ('处理端口冲突', '3'),
            ('确认停止请完整输入', 'wrong-site'), ('处理端口冲突', '3'),
            ('确认停止请完整输入', 'existing-site')])
        self.assertEqual(code, 0, output)
        self.assertFalse(owner.exists())
        stops = [call['args'] for call in self.calls() if call['args'][0] == 'stop']
        self.assertEqual(stops, [['stop', '--timeout', '30', 'f' * 64]])

    @unittest.skipUnless(os.name == 'posix', 'interactive terminal requires POSIX')
    def test_stop_failure_returns_to_port_selection(self):
        owner = self.existing_web_conflict()
        self.env['FAIL_FIXTURE_STOP'] = '1'
        code, output = self.run_interactive([
            ('启动方式', '1'), ('确认部署', '1'), ('处理端口冲突', '3'),
            ('确认停止请完整输入', 'existing-site'), ('处理端口冲突', '1'),
            ('网页 HTTP 端口', '38000'), ('网页 HTTPS 端口', '38443'), ('确认使用这些网页端口', '1')])
        self.assertEqual(code, 0, output)
        self.assertIn('未能停止 existing-site', output)
        self.assertTrue(owner.exists())

    @unittest.skipUnless(os.name == 'posix', 'interactive terminal requires POSIX')
    def test_occupied_acme_port_allows_an_explicit_change_of_certificate_method(self):
        owner = self.path / 'published-ports.json'
        owner.write_text(json.dumps({'name': 'site', 'ports': {
            '8080/tcp': [{'HostPort': '80', 'HostIp': '0.0.0.0'}]}}))
        self.env['FIXTURE_WEB_CONTAINER'] = str(owner)
        self.executable(self.bin / 'certbot', '#!/bin/sh\nexit 94\n')
        code, output = self.run_interactive([
            ('部署模式', '1'), ('证书域名', ''), ('ACME 邮箱', ''), ('Control端口', ''),
            ('metrics端口', ''), ('Relay绑定IP', ''), ('确认部署', '1'), ('处理端口冲突', '1'),
            ('更换证书方式', '2'), ('网页 HTTP 端口', '38000'), ('网页 HTTPS 端口', '38443'),
            ('确认使用这些网页端口', '1'), *ACCOUNT_INPUT],
            '--relay-endpoint', 'tls://relay.example.test:18081', '--tls-mode', 'auto', '--no-start')
        self.assertEqual(code, 0, output)
        self.assertIn('P2WLAN_TLS_MODE=selfsigned', (self.target / '.env').read_text())
        self.assertTrue((self.target / 'config/relay-ca.crt').is_file())
        self.assertTrue(owner.exists())

    def test_own_active_edge_bindings_are_reused_during_upgrade(self):
        owner = self.existing_web_conflict()
        project = 'p2wlan-' + hashlib.sha256(str(self.target.resolve()).encode()).hexdigest()[:12]
        data = json.loads(owner.read_text())
        owner.write_text(json.dumps(dict(data, project=project, service='edge')))
        result = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(owner.exists())

    @unittest.skipUnless(os.name == 'posix', 'interactive terminal requires POSIX')
    def test_stale_confirmed_owner_and_auto_remove_containers_are_not_stopped(self):
        owner = self.existing_web_conflict()
        def replace_owner(needle, _output):
            if needle == '确认停止请完整输入':
                data = json.loads(owner.read_text())
                owner.write_text(json.dumps(dict(data, name='new-site', removable=True)))
        code, output = self.run_interactive([
            ('启动方式', '1'), ('确认部署', '1'), ('处理端口冲突', '3'),
            ('确认停止请完整输入', 'existing-site'), ('处理端口冲突', 'q')],
            before_reply=replace_owner)
        self.assertNotEqual(code, 0)
        self.assertIn('占用者已变化', output)
        self.assertIn('停止即删除', output)
        self.assertTrue(owner.exists())
        self.assertFalse(any(call['args'][0] == 'stop' for call in self.calls()))

    @unittest.skipUnless(os.name == 'posix', 'interactive terminal requires POSIX')
    def test_wizard_can_stop_a_confirmed_systemd_web_service(self):
        owner = self.existing_web_conflict()
        owner.unlink()
        occupied = self.path / 'listener-active'
        occupied.touch()
        self.env.update(PYTHONPATH=str(self.path), FIXTURE_LISTENER=str(occupied))
        (self.path / 'sitecustomize.py').write_text("""
import errno, os, pathlib, socket
original_bind = socket.socket.bind
original_read = pathlib.Path.read_text
def bind(sock, addr):
    if addr == ('0.0.0.0', 80) and os.path.exists(os.environ['FIXTURE_LISTENER']):
        raise OSError(errno.EADDRINUSE, 'fixture listener')
    return original_bind(sock, addr)
def read(path, *args, **kwargs):
    if str(path) == '/proc/123456/cgroup':
        return '0::/system.slice/nginx.service'
    return original_read(path, *args, **kwargs)
socket.socket.bind = bind
pathlib.Path.read_text = read
""")
        self.executable(self.bin / 'ss', '#!/bin/sh\necho \'LISTEN 0 128 *:80 *:* users:(("nginx",pid=123456,fd=3))\'\n')
        self.executable(self.bin / 'systemctl', """#!/bin/sh
case "$1" in
    show) echo 1234567890abcdef1234567890abcdef ;;
    stop) [ "$2" = nginx.service ] && rm "$FIXTURE_LISTENER" ;;
    *) exit 1 ;;
esac
""")
        code, output = self.run_interactive([
            ('启动方式', '1'), ('确认部署', '1'), ('处理端口冲突', '3'),
            ('确认停止请完整输入', 'nginx.service')])
        self.assertEqual(code, 0, output)
        self.assertIn('sudo systemctl start nginx.service', output)
        self.assertFalse(occupied.exists())

    def test_complete_release_bundle_selects_its_adjacent_image_manifest_by_default(self):
        self.manifest()
        result = self.run_installer('--dev-localhost', '--no-start', image=None)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(any(call['args'] == ['pull', IMAGE] for call in self.calls()))
        settings = (self.target / '.env').read_text()
        self.assertIn(f'P2WLAN_IMAGE={IMAGE}', settings)
        self.assertIn(f'P2WLAN_COMMIT={COMMIT}', settings)

    def test_adjacent_manifest_checksum_mismatch_fails_before_docker(self):
        self.manifest(checksum=False)
        result = self.run_installer('--dev-localhost', '--no-start', image=None)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.calls(), [])
        self.assertFalse((self.target / 'config/control.env').exists())

    def test_release_source_mismatch_cannot_generate_or_start_containers(self):
        self.manifest(commit='d' * 40)
        result = self.run_installer('--dev-localhost', '--no-start', image=None)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(call['args'][:1] == ['run'] and '--output' in call['args'] for call in self.calls()))
        self.assertFalse((self.target / 'config/control.env').exists())

    def test_fixed_version_downloads_only_its_checksum_bound_image_manifest(self):
        self.manifest()
        downloads = self.path / 'downloads'
        downloads.mkdir()
        for name in ('SERVER-IMAGE.json', 'SERVER-IMAGE.json.sha256'):
            shutil.move(str(self.path / name), downloads / name)
        hooks = self.path / 'python-hooks'
        hooks.mkdir()
        (hooks / 'sitecustomize.py').write_text('''import io, os, pathlib, urllib.request
def fixture_urlopen(url, timeout=None):
    prefix = 'https://github.com/yhan-sun/p2wlan/releases/download/server-v9.9.9/'
    if not isinstance(url, str) or not url.startswith(prefix):
        raise OSError('unexpected fixture download')
    name = url[len(prefix):]
    if name not in ('SERVER-IMAGE.json', 'SERVER-IMAGE.json.sha256'):
        raise OSError('unexpected fixture asset')
    return io.BytesIO((pathlib.Path(os.environ['FIXTURE_DOWNLOADS']) / name).read_bytes())
urllib.request.urlopen = fixture_urlopen
''')
        self.env['PYTHONPATH'] = str(hooks)
        self.env['FIXTURE_DOWNLOADS'] = str(downloads)
        result = self.run_installer('--version', 'server-v9.9.9', '--dev-localhost', '--no-start', image=None)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(f'P2WLAN_COMMIT={COMMIT}', (self.target / '.env').read_text())

    def test_mutable_or_malformed_image_references_are_rejected_before_docker(self):
        for image in ('latest', 'registry.example.test/server:latest', 'registry.example.test/server@sha256:bad',
                      'registry.example.test/server@sha256:' + 'a' * 64 + '\nother', 'https://registry.example.test/server@sha256:' + 'a' * 64):
            with self.subTest(image=image):
                result = self.run_installer('--dev-localhost', '--dry-run', image=image)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.calls(), [])
                self.assertFalse(self.target.exists())

    def test_no_argument_mode_requires_a_real_terminal(self):
        result = subprocess.run(['bash', str(ROOT / 'scripts/install-server-docker.sh')], cwd=self.path,
                                env=self.env, input='', capture_output=True, text=True,
                                start_new_session=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('--non-interactive', result.stdout + result.stderr)
        self.assertEqual(self.calls(), [])

    @unittest.skipUnless(os.name == 'posix', 'interactive terminal requires POSIX')
    def test_interactive_mode_uses_dev_tty_while_python_source_occupies_stdin(self):
        code, output = self.run_interactive([
            ('Relay主机', ''), ('Relay端口', ''), ('Control端口', ''),
            ('metrics端口', ''), ('Relay绑定IP', ''), ('确认部署', '1'), *ACCOUNT_INPUT,
        ], '--dev-localhost', '--no-start', before_reply=lambda *_: self.assert_not_deployed())
        self.assertEqual(code, 0, output)
        self.assertTrue((self.target / 'config/control.env').exists())
        self.assertNotIn('fixture-private-token', output)

    @unittest.skipUnless(os.name == 'posix', 'interactive terminal requires POSIX')
    def test_wizard_prompts_for_default_directory_and_can_prepare_a_local_deployment(self):
        code, output = self.run_interactive([
            ('部署目录', str(self.target)), ('部署模式', '2'), ('Relay主机', ''),
            ('Relay端口', ''), ('Control端口', ''), ('metrics端口', ''),
            ('Relay绑定IP', ''), ('启动方式', '2'), ('确认部署', '1'), *ACCOUNT_INPUT,
        ], include_dir=False, before_reply=lambda *_: self.assert_not_deployed())
        self.assertEqual(code, 0, output)
        self.assertIn('/opt/p2wlan-docker', output)
        settings = (self.target / '.env').read_text()
        self.assertIn('P2WLAN_DEV_LOCALHOST=true', settings)
        self.assertIn('RELAY_PUBLISH_HOST=127.0.0.1', settings)
        self.assertFalse(any('up' in call['args'] and '--help' not in call['args'] for call in self.calls()))

    @unittest.skipUnless(os.name == 'posix', 'interactive terminal requires POSIX')
    def test_public_wizard_uses_custom_ports_tls_paths_and_starts_after_confirmation(self):
        certificate, key = self.path / 'certificate.pem', self.path / 'key.pem'
        certificate.write_text('fixture-certificate')
        key.write_text('fixture-private-key')
        code, output = self.run_interactive([
            ('部署模式', '1'), ('Relay主机', 'relay.example.test'), ('Relay端口', '28081'),
            ('证书来源', '3'), ('证书链路径', str(certificate)), ('私钥路径', str(key)),
            ('Control端口', '28080'), ('metrics端口', '28082'),
            ('Relay绑定IP', '0.0.0.0'), ('启动方式', '1'), ('确认部署', '1'), *ACCOUNT_INPUT,
        ], before_reply=lambda *_: self.assert_not_deployed())
        self.assertEqual(code, 0, output)
        settings = (self.target / '.env').read_text()
        for entry in ('CONTROL_PORT=28080', 'RELAY_PORT=28081', 'METRICS_PORT=28082',
                      'RELAY_PUBLISH_HOST=0.0.0.0', 'P2WLAN_DEV_LOCALHOST=false'):
            self.assertIn(entry, settings)
        generator = next(call['args'] for call in self.calls() if '--output' in call['args'])
        self.assertEqual(generator[generator.index('--relay-endpoint') + 1], 'tls://relay.example.test:28081')
        self.assertTrue(any('up' in call['args'] and '--help' not in call['args'] for call in self.calls()))
        self.assertNotIn('fixture-private-key', output)
        self.assertNotIn('sample pass for test', output + self.log.read_text())
        self.assertIn('健康检查通过，访问地址', output)
        self.assertIn('服务端地址（Control）：https://relay.example.test', output)
        self.assertIn('管理后台地址：https://relay.example.test/admin/', output)

    @unittest.skipUnless(os.name == 'posix', 'interactive terminal requires POSIX')
    def test_wizard_retries_invalid_choices_ports_addresses_and_directory(self):
        code, output = self.run_interactive([
            ('部署目录', 'relative'), ('部署目录', str(self.target)),
            ('部署模式', '99'), ('部署模式', '2'),
            ('Relay主机', 'relay.example.test'), ('Relay主机', 'localhost'),
            ('Relay端口', '99999'), ('Relay端口', '18081'),
            ('Control端口', 'invalid'), ('Control端口', '28080'),
            ('metrics端口', '28080'), ('metrics端口', '28082'),
            ('Relay绑定IP', '0.0.0.0'), ('Relay绑定IP', '127.0.0.2'),
            ('启动方式', '99'), ('启动方式', '2'),
            ('确认部署', '99'), ('确认部署', '1'), *ACCOUNT_INPUT,
        ], include_dir=False, before_reply=lambda *_: self.assert_not_deployed())
        self.assertEqual(code, 0, output)
        settings = (self.target / '.env').read_text()
        self.assertIn('CONTROL_PORT=28080', settings)
        self.assertIn('METRICS_PORT=28082', settings)
        self.assertIn('RELAY_PUBLISH_HOST=127.0.0.2', settings)

    def certbot_stub(self, domain):
        self.executable(self.bin / 'certbot',
            '#!/bin/sh\n'
            'printf "%s\\n" "$*" >> "$CERTBOT_LOG"\n'
            'live="$P2WLAN_ACME_LIVE_DIR/' + domain + '"\n'
            'mkdir -p "$live"\n'
            'mkdir -p "$P2WLAN_ACME_LIVE_DIR/../renewal"\n'
            'printf "[renewalparams]\\nauthenticator = standalone\\n" > "$P2WLAN_ACME_LIVE_DIR/../renewal/' + domain + '.conf"\n'
            'echo fixture-chain > "$live/fullchain.pem"\n'
            'echo fixture-key > "$live/privkey.pem"\n')

    def test_automatic_tls_issues_a_certificate_and_serves_the_panel_over_https(self):
        certbot_log = self.path / 'certbot.log'
        self.env['CERTBOT_LOG'] = str(certbot_log)
        self.env['P2WLAN_ACME_LIVE_DIR'] = str(self.path / 'acme-live')
        self.env['P2WLAN_RENEWAL_HOOKS_DIR'] = str(self.path / 'acme-hooks')
        self.certbot_stub('relay.example.test')
        result = self.run_installer('--relay-endpoint', 'tls://relay.example.test:18081',
                                    '--tls-mode', 'auto', '--tls-domain', 'relay.example.test',
                                    '--tls-email', 'ops@example.test', '--publish-host', '0.0.0.0')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        arguments = certbot_log.read_text()
        self.assertIn('--standalone', arguments)
        self.assertIn('-d relay.example.test', arguments)
        self.assertIn('-m ops@example.test', arguments)
        edge = (self.target / 'config/edge/nginx.conf').read_text()
        self.assertIn('server_name relay.example.test;', edge)
        self.assertIn('proxy_pass http://control:18080;', edge)
        settings = (self.target / '.env').read_text()
        self.assertIn('COMPOSE_PROFILES=edge', settings)
        self.assertIn('P2WLAN_TLS_MODE=auto', settings)
        self.assertIn('P2WLAN_TLS_DOMAIN=relay.example.test', settings)
        self.assertTrue(any('--profile' in call['args'] and 'edge' in call['args'] for call in self.calls()))
        hooks = self.path / 'acme-hooks'
        registration = next(hooks.glob('p2wlan-*'))
        renewal = (Path(self.env['P2WLAN_ACME_LIVE_DIR']).parent / 'renewal/relay.example.test.conf').read_text()
        for kind in ('pre', 'post', 'deploy'):
            hook = registration / kind
            self.assertTrue(hook.is_file() and not hook.is_symlink(), kind)
            self.assertEqual(hook.stat().st_mode & 0o777, 0o700)
            self.assertIn(str(hook), renewal)
            self.assertFalse((hooks / kind).exists())
        before = len(self.calls())
        for kind in ('pre', 'post', 'deploy'):
            result_hook = subprocess.run([str(registration / kind)], env=dict(self.env, RENEWED_LINEAGE='/unrelated'),
                                         capture_output=True, text=True)
            self.assertEqual(result_hook.returncode, 0, result_hook.stderr)
        self.assertFalse(any('up' in call['args'] or 'stop' in call['args'] for call in self.calls()[before:]))
        self.assertIn('https://relay.example.test/', result.stdout)

    def test_renewal_recreates_running_services_and_rejects_a_stale_served_certificate(self):
        domain = 'relay.example.test'
        live = self.path / 'live'
        hooks = self.path / 'hooks'
        self.env.update(CERTBOT_LOG=str(self.path / 'certbot.log'), P2WLAN_ACME_LIVE_DIR=str(live),
                        P2WLAN_RENEWAL_HOOKS_DIR=str(hooks))
        self.certbot_stub(domain)
        result = self.run_installer('--relay-endpoint', 'tls://' + domain + ':18081', '--tls-mode', 'auto',
                                    '--tls-domain', domain, '--publish-host', '127.0.0.1')
        self.assertEqual(result.returncode, 0, result.stderr)
        registration = next(hooks.glob('p2wlan-*'))
        self.executable(self.bin / 'timeout', '#!/bin/sh\nshift\nexec "$@"\n')
        self.executable(self.bin / 'openssl', '''#!/bin/sh
case "$*" in
  s_client*) echo "$SERVED_FINGERPRINT";;
  *' -in '*) cat "$3";;
  *) cat;;
esac
''')
        def hook(kind, running, fingerprint='renewed'):
            return subprocess.run([str(registration / kind)], env=dict(self.env, DOCKER_FIXTURE_RUNNING=running,
                                  RENEWED_LINEAGE=str(live / domain), SERVED_FINGERPRINT=fingerprint),
                                  capture_output=True, text=True)
        (live / domain / 'fullchain.pem').write_text('renewed\n')
        before = len(self.calls())
        self.assertEqual(hook('pre', 'edge\nrelay').returncode, 0)
        self.assertTrue((registration / 'edge-stopped').exists())
        applied = hook('deploy', 'relay')
        self.assertEqual(applied.returncode, 0, applied.stderr)
        restored = hook('post', 'relay')
        self.assertEqual(restored.returncode, 0, restored.stderr)
        self.assertFalse((registration / 'edge-stopped').exists())
        recreated = [call['args'][-1] for call in self.calls()[before:] if '--force-recreate' in call['args']]
        self.assertEqual(recreated, ['relay', 'edge'])
        self.assertNotEqual(hook('deploy', 'relay', 'stale').returncode, 0)

    def test_self_signed_tls_covers_an_ip_relay_without_a_domain_or_email(self):
        result = self.run_installer('--relay-endpoint', 'tls://203.0.113.10:18081',
                                    '--tls-mode', 'selfsigned', '--publish-host', '0.0.0.0')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        certificate = (self.target / 'config/tls.crt').read_text()
        self.assertIn('BEGIN CERTIFICATE', certificate)
        san = subprocess.run(['openssl', 'x509', '-noout', '-ext', 'subjectAltName',
                              '-in', str(self.target / 'config/tls.crt')],
                             capture_output=True, text=True, timeout=20)
        self.assertIn('IP Address:203.0.113.10', san.stdout)
        ca = subprocess.run(['openssl', 'verify', '-CAfile', str(self.target / 'config/relay-ca.crt'),
                             str(self.target / 'config/tls.crt')], capture_output=True, text=True, timeout=20)
        self.assertEqual(ca.returncode, 0, ca.stderr)
        edge = (self.target / 'config/edge/nginx.conf').read_text()
        self.assertIn('server_name 203.0.113.10;', edge)
        settings = (self.target / '.env').read_text()
        self.assertIn('P2WLAN_TLS_MODE=selfsigned', settings)

    def test_automatic_tls_rejects_an_ip_relay_host(self):
        result = self.run_installer('--relay-endpoint', 'tls://203.0.113.10:18081',
                                    '--tls-mode', 'auto', '--tls-domain', 'relay.example.test',
                                    '--publish-host', '0.0.0.0')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Relay 是 IP', result.stdout + result.stderr)
        self.assertFalse(self.target.exists())

    def test_automatic_tls_rejects_a_domain_that_does_not_match_the_relay_host(self):
        result = self.run_installer('--relay-endpoint', 'tls://relay.example.test:18081',
                                    '--tls-mode', 'auto', '--tls-domain', 'other.example.test',
                                    '--tls-email', 'ops@example.test', '--publish-host', '0.0.0.0')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('--tls-domain must equal the Relay host', result.stdout + result.stderr)
        self.assertFalse(self.target.exists())

    def test_automatic_tls_without_an_email_registers_without_a_contact(self):
        certbot_log = self.path / 'certbot.log'
        self.env['CERTBOT_LOG'] = str(certbot_log)
        self.env['P2WLAN_ACME_LIVE_DIR'] = str(self.path / 'acme-live')
        self.env['P2WLAN_RENEWAL_HOOKS_DIR'] = str(self.path / 'acme-hooks')
        self.certbot_stub('relay.example.test')
        result = self.run_installer('--relay-endpoint', 'tls://relay.example.test:18081',
                                    '--tls-mode', 'auto', '--tls-domain', 'relay.example.test',
                                    '--publish-host', '0.0.0.0')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        arguments = certbot_log.read_text()
        self.assertIn('--register-unsafely-without-email', arguments)
        self.assertNotIn('--no-eff-email', arguments)

    @unittest.skipUnless(os.name == 'posix', 'interactive terminal requires POSIX')
    def test_q_at_the_first_prompt_cancels_without_writing_a_deployment(self):
        code, output = self.run_interactive([('部署目录', 'q')], include_dir=False,
                                            before_reply=lambda *_: self.assert_not_deployed())
        self.assertNotEqual(code, 0, output)
        self.assertIn('installation cancelled', output)
        self.assert_not_deployed()

    @unittest.skipUnless(os.name == 'posix', 'interactive terminal requires POSIX')
    def test_cancel_reply_in_a_legacy_encoding_cancels_instead_of_raising_a_codec_error(self):
        code, output = self.run_interactive([('部署目录', '取消'.encode('gb18030'))], include_dir=False,
                                            before_reply=lambda *_: self.assert_not_deployed())
        self.assertNotEqual(code, 0, output)
        self.assertIn('installation cancelled', output)
        self.assertNotIn('codec', output)
        self.assert_not_deployed()

    @unittest.skipUnless(os.name == 'posix', 'interactive terminal requires POSIX')
    def test_q_at_the_certificate_prompt_cancels_before_configuration(self):
        code, output = self.run_interactive([
            ('部署模式', '1'), ('Relay主机', 'relay.example.test'), ('Relay端口', ''),
            ('证书来源', '3'), ('证书链路径', 'q'),
        ], before_reply=lambda *_: self.assert_not_deployed())
        self.assertNotEqual(code, 0, output)
        self.assertIn('installation cancelled', output)
        self.assert_not_deployed()

    @unittest.skipUnless(os.name == 'posix', 'interactive terminal requires POSIX')
    def test_final_cancellation_does_not_pull_execute_or_write_a_deployment(self):
        code, output = self.run_interactive([('确认部署', '0')],
            '--dev-localhost', '--relay-endpoint', 'tls://localhost:18081',
            '--control-port', '18080', '--metrics-port', '18082',
            '--publish-host', '127.0.0.1', '--no-start',
            before_reply=lambda *_: self.assert_not_deployed())
        self.assertIn(code, (0, 1), output)
        self.assert_not_deployed()

    @unittest.skipUnless(os.name == 'posix', 'interactive terminal requires POSIX')
    def test_reentering_the_summary_replaces_prefilled_fields_before_any_deployment(self):
        code, output = self.run_interactive([
            ('确认部署', '2'), ('部署目录', str(self.target)), ('部署模式', '2'),
            ('Relay主机', 'localhost'), ('Relay端口', '38081'),
            ('Control端口', '38080'), ('metrics端口', '38082'),
            ('Relay绑定IP', '127.0.0.1'), ('启动方式', '2'), ('确认部署', '1'), *ACCOUNT_INPUT,
        ], '--dev-localhost', '--relay-endpoint', 'tls://localhost:28081',
            '--control-port', '28080', '--metrics-port', '28082',
            '--publish-host', '127.0.0.1', '--no-start',
            before_reply=lambda *_: self.assert_not_deployed())
        self.assertEqual(code, 0, output)
        settings = (self.target / '.env').read_text()
        for entry in ('CONTROL_PORT=38080', 'RELAY_PORT=38081', 'METRICS_PORT=38082'):
            self.assertIn(entry, settings)
        self.assertEqual(sum('--output' in call['args'] for call in self.calls()), 1)

    @unittest.skipUnless(os.name == 'posix', 'interactive terminal requires POSIX')
    def test_reentering_a_public_plan_as_a_local_test_restores_the_loopback_bind_default(self):
        certificate, key = self.path / 'certificate.pem', self.path / 'key.pem'
        certificate.write_text('fixture-certificate')
        key.write_text('fixture-private-key')
        code, output = self.run_interactive([
            ('确认部署', '2'), ('部署目录', str(self.target)), ('部署模式', '2'),
            ('Relay主机', 'localhost'), ('Relay端口', '38081'),
            ('Control端口', '38080'), ('metrics端口', '38082'),
            ('Relay绑定IP', ''), ('启动方式', '2'), ('确认部署', '1'), *ACCOUNT_INPUT,
        ], '--relay-endpoint', 'tls://relay.example.test:28081',
            '--tls-cert', str(certificate), '--tls-key', str(key),
            '--control-port', '28080', '--metrics-port', '28082',
            '--publish-host', '0.0.0.0', '--no-start',
            before_reply=lambda *_: self.assert_not_deployed())
        self.assertEqual(code, 0, output)
        settings = (self.target / '.env').read_text()
        self.assertIn('P2WLAN_DEV_LOCALHOST=true', settings)
        self.assertIn('RELAY_PUBLISH_HOST=127.0.0.1', settings)
        self.assertEqual(sum('--output' in call['args'] for call in self.calls()), 1)

    @unittest.skipUnless(os.name == 'posix', 'interactive terminal requires POSIX')
    def test_existing_deployment_is_confirmed_without_recreating_configuration(self):
        first = self.run_installer('--dev-localhost', '--no-start')
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        config = self.target / 'config'
        (config / 'data/p2pnet.db').write_bytes(b'existing-database')
        before = {str(path.relative_to(config)): path.read_bytes() for path in config.rglob('*') if path.is_file()}
        calls_before = len(self.calls())
        def unchanged_before_confirmation(*_):
            self.assertEqual(before, {str(path.relative_to(config)): path.read_bytes() for path in config.rglob('*') if path.is_file()})
            self.assertFalse(any(call['args'][:1] == ['run'] for call in self.calls()[calls_before:]))
        self.assert_no_application_pull(self.calls()[calls_before:])
        code, output = self.run_interactive([('确认部署', '1')], '--no-start', before_reply=unchanged_before_confirmation)
        self.assertEqual(code, 0, output)
        self.assertEqual(before, {str(path.relative_to(config)): path.read_bytes() for path in config.rglob('*') if path.is_file()})
        self.assertEqual(sum('--output' in call['args'] for call in self.calls()), 1)

    def test_unattended_custom_control_and_metrics_ports_are_rendered_into_configuration(self):
        result = self.run_installer('--dev-localhost', '--relay-endpoint', 'tls://localhost:28081',
                                    '--control-port', '28080', '--metrics-port', '28082', '--no-start')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        settings = (self.target / '.env').read_text()
        for entry in ('CONTROL_PORT=28080', 'RELAY_PORT=28081', 'METRICS_PORT=28082'):
            self.assertIn(entry, settings)

    def test_dry_run_rejects_invalid_explicit_ports_before_docker_or_directory_writes(self):
        for arguments in (
            ('--control-port', '0'), ('--control-port', '65536'),
            ('--metrics-port', '0'), ('--metrics-port', '65536'),
            ('--control-port', '28080', '--metrics-port', '28080'),
            ('--control-port', '18081', '--relay-endpoint', 'tls://localhost:18081'),
        ):
            with self.subTest(arguments=arguments):
                result = self.run_installer('--dev-localhost', '--dry-run', *arguments)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.calls(), [])
                self.assertFalse(self.target.exists())

    def test_new_public_edge_reserves_http_and_https_before_build(self):
        source = self.source_bundle()
        for port in (80, 443):
            for options in (('--dry-run',), ('--no-start',)):
                with self.subTest(port=port, options=options):
                    result = self.run_installer('--source', str(source), '--tls-mode', 'selfsigned',
                        '--relay-endpoint', f'tls://relay.example.test:{port}', *options, image=None)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('80/443', result.stderr)
                    self.assert_not_deployed()

    def test_public_web_port_flags_are_validated_in_dry_run(self):
        for arguments in (('--http-port', '0'), ('--https-port', '65536'),
                          ('--http-port', '8080', '--https-port', '8080'),
                          ('--http-port', '18080'), ('--https-port', '18081'),
                          ('--dev-localhost', '--http-port', '8080')):
            with self.subTest(arguments=arguments):
                result = self.run_installer('--dry-run', *arguments)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.target.exists())
                self.assertEqual(self.calls(), [])

    def test_invalid_publish_hosts_are_rejected_before_docker(self):
        for host in ('relay.example.com', '0.0.0.0\nOTHER=value', '127.0.0.1:18081'):
            with self.subTest(host=host):
                result = self.run_installer('--dev-localhost', '--publish-host', host, '--dry-run')
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.calls(), [])

    def test_local_image_escape_hatch_requires_loopback_development_mode(self):
        result = self.run_installer('--local-image', IMAGE_ID, '--dry-run', image=None)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.calls(), [])

    def test_local_image_development_path_never_pulls_from_a_registry(self):
        result = self.run_installer('--local-image', IMAGE_ID, '--dev-localhost', '--no-start', image=None)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assert_no_application_pull(self.calls())
        self.assertTrue((self.target / 'config/control.env').exists())

    def test_development_certificate_cannot_be_published_on_a_wildcard_address(self):
        result = self.run_installer('--dev-localhost', '--publish-host', '0.0.0.0', '--dry-run')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.calls(), [])

    def test_unavailable_docker_does_not_generate_or_start_the_deployment(self):
        self.env['FAIL_DOCKER_INFO'] = '1'
        result = self.run_installer('--dev-localhost')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(call['args'][:1] == ['run'] for call in self.calls()))
        self.assertFalse((self.target / 'config/control.env').exists())

    def test_remote_daemon_context_is_rejected_before_mounting_configuration(self):
        self.env['DOCKER_FIXTURE_CONTEXT'] = 'tcp://remote.example.test:2376'
        result = self.run_installer('--dev-localhost')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(call['args'][:1] == ['run'] for call in self.calls()))

    def test_rootless_or_remapped_daemon_is_rejected_before_generating_private_files(self):
        for security in ('name=rootless', 'name=userns'):
            with self.subTest(security=security):
                self.env['DOCKER_FIXTURE_SECURITY'] = security
                result = self.run_installer('--dev-localhost')
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(any(call['args'][:1] == ['run'] for call in self.calls()))

    def test_compose_without_health_wait_support_cannot_start_services(self):
        self.env['DOCKER_FIXTURE_NO_WAIT'] = '1'
        result = self.run_installer('--dev-localhost')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(call['args'][:1] == ['run'] for call in self.calls()))

    def test_new_deployment_generates_before_starting_and_uses_health_wait(self):
        result = self.run_installer('--dev-localhost')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        calls = self.calls()
        generate = next(i for i, call in enumerate(calls) if call['args'][:1] == ['run'] and '--output' in call['args'])
        start = next(i for i, call in enumerate(calls) if call['args'][:1] == ['compose'] and 'up' in call['args'] and '--help' not in call['args'])
        self.assertLess(generate, start)
        arguments = calls[start]['args']
        self.assertIn('--wait', arguments)
        self.assertEqual(arguments[arguments.index('--wait-timeout') + 1], '90')
        self.assertIn('--no-build', arguments)
        self.assertIn('--pull', arguments)
        self.assertEqual(arguments[arguments.index('--pull') + 1], 'never')
        self.assertTrue((self.target / 'config/control.env').exists())
        self.assertEqual(stat.S_IMODE((self.target / '.env').stat().st_mode), 0o600)
        self.assertNotIn('fixture-private-token', result.stdout + result.stderr)
        self.assertNotIn('fixture-private-key', result.stdout + result.stderr)

    def test_generator_is_isolated_from_the_network_and_container_privileges(self):
        result = self.run_installer('--dev-localhost', '--no-start')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        arguments = next(call['args'] for call in self.calls() if call['args'][:1] == ['run'] and '--output' in call['args'])
        self.assertEqual(arguments[arguments.index('--network') + 1], 'none')
        self.assertIn('--read-only', arguments)
        self.assertEqual(arguments[arguments.index('--cap-drop') + 1], 'ALL')
        self.assertIn('no-new-privileges=true', arguments)
        self.assertIn('--user', arguments)
        self.assertFalse(any(call['args'][:1] == ['compose'] and 'up' in call['args'] and '--help' not in call['args'] for call in self.calls()))

    def test_public_deployment_publishes_relay_and_keeps_control_on_loopback(self):
        certificate, key = self.path / 'certificate.pem', self.path / 'key.pem'
        certificate.write_text('fixture-certificate')
        key.write_text('fixture-key')
        result = self.run_installer('--relay-endpoint', 'tls://relay.example.test:18081',
                                    '--tls-cert', str(certificate), '--tls-key', str(key), '--no-start')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        environment = (self.target / '.env').read_text()
        self.assertIn('RELAY_PUBLISH_HOST=0.0.0.0', environment)
        compose = (self.target / 'compose.yml').read_text()
        self.assertIn('127.0.0.1:', compose)
        self.assertNotIn('build:', compose)
        self.assertFalse((self.target / 'config/compose.env').exists())

    def test_existing_configuration_and_database_are_not_regenerated(self):
        first = self.run_installer('--dev-localhost', '--no-start')
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        config = self.target / 'config'
        database = config / 'data/p2pnet.db'
        database.write_bytes(b'fixture-existing-database')
        before = {str(path.relative_to(config)): path.read_bytes() for path in config.rglob('*') if path.is_file()}
        second = self.run_installer('--no-start')
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        after = {str(path.relative_to(config)): path.read_bytes() for path in config.rglob('*') if path.is_file()}
        self.assertEqual(before, after)
        self.assertEqual(sum(call['args'][:1] == ['run'] and '--output' in call['args'] for call in self.calls()), 1)

    def test_existing_local_development_image_is_restored_without_a_registry_pull(self):
        first = self.run_installer('--local-image', IMAGE_ID, '--dev-localhost', '--no-start', image=None)
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        second = self.run_installer('--no-start', image=None)
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        self.assert_no_application_pull(self.calls())
        self.assertEqual(sum(call['args'][:1] == ['run'] and '--output' in call['args'] for call in self.calls()), 1)

    def test_saved_environment_cannot_inject_docker_host_or_compose_controls(self):
        first = self.run_installer('--dev-localhost', '--no-start')
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        settings = self.target / '.env'
        with settings.open('a') as stream:
            stream.write('DOCKER_HOST=tcp://remote.example.test:2376\n')
        before = settings.read_bytes()
        second = self.run_installer('--no-start')
        self.assertNotEqual(second.returncode, 0)
        self.assertEqual(settings.read_bytes(), before)
        self.assertEqual(sum(call['args'][:1] == ['run'] and '--output' in call['args'] for call in self.calls()), 1)

    def test_saved_development_mode_cannot_bypass_loopback_publication(self):
        first = self.run_installer('--dev-localhost', '--no-start')
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        settings = (self.target / '.env').read_bytes()
        second = self.run_installer('--publish-host', '0.0.0.0', '--no-start')
        self.assertNotEqual(second.returncode, 0)
        self.assertEqual((self.target / '.env').read_bytes(), settings)

    def test_partial_existing_configuration_is_preserved_and_not_regenerated(self):
        config = self.target / 'config'
        config.mkdir(parents=True)
        sentinel = b'JWT_SECRET=fixture-existing-secret\n'
        (config / 'control.env').write_bytes(sentinel)
        result = self.run_installer('--dev-localhost')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((config / 'control.env').read_bytes(), sentinel)
        self.assertFalse(any(call['args'][:1] == ['run'] and '--output' in call['args'] for call in self.calls()))

    def test_generator_failure_does_not_start_services_or_publish_partial_configuration(self):
        self.env['FAIL_DOCKER_GENERATE'] = '1'
        result = self.run_installer('--dev-localhost')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.target / 'config/control.env').exists())
        self.assertFalse(any(call['args'][:1] == ['compose'] and 'up' in call['args'] and '--help' not in call['args'] for call in self.calls()))

    def test_health_failure_is_not_reported_as_success(self):
        self.env['FAIL_COMPOSE_UP'] = '1'
        result = self.run_installer('--dev-localhost')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('fixture-private-token', result.stdout + result.stderr)

    def test_source_dry_run_verifies_files_without_docker_or_temporary_snapshots(self):
        source = self.source_bundle()
        hooks = self.path / 'python-hooks'
        hooks.mkdir()
        (hooks / 'sitecustomize.py').write_text('''import tempfile
def forbidden(*args, **kwargs):
    raise AssertionError('dry-run created a temporary source snapshot')
tempfile.TemporaryDirectory = forbidden
''')
        self.env['PYTHONPATH'] = str(hooks)
        result = self.run_installer('--source', str(source), '--dev-localhost', '--dry-run', image=None)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(COMMIT, result.stdout)
        self.assert_not_deployed()

    def test_source_build_uses_an_isolated_builder_and_immutable_runtime_image_id(self):
        source = self.source_bundle()
        certificate, key = self.path / 'certificate.pem', self.path / 'key.pem'
        certificate.write_text('fixture-certificate')
        key.write_text('fixture-private-key')
        result = self.run_installer('--source', str(source), '--relay-endpoint', 'tls://relay.example.test:18081',
                                    '--tls-cert', str(certificate), '--tls-key', str(key), image=None)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        calls = self.calls()
        build = next(call for call in calls if call['args'][:1] == ['compose'] and 'build' in call['args'])
        self.assertEqual(build['args'][-2:], ['build', 'builder'])
        self.assertEqual(build['args'][build['args'].index('--env-file') + 1], '/dev/null')
        saved = (self.target / 'sources' / COMMIT).resolve()
        self.assertEqual(build['env']['P2WLAN_BUILD_CONTEXT'], str(saved / 'server'))
        self.assertEqual(build['env']['P2WLAN_VERSION'], 'server-v9.9.9')
        self.assertEqual(build['env']['P2WLAN_COMMIT'], COMMIT)
        settings = (self.target / '.env').read_text()
        self.assertIn('P2WLAN_INSTALL_MODE=source', settings)
        self.assertIn(f'P2WLAN_IMAGE={IMAGE_ID}', settings)
        self.assertIn(f'P2WLAN_SOURCE_DIR={saved}', settings)
        self.assertIn('P2WLAN_DEV_LOCALHOST=false', settings)
        self.assertIn('P2WLAN_BUILD_IMAGE=' + build['env']['P2WLAN_BUILD_IMAGE'], settings)
        self.assert_no_application_pull(calls)
        containers = [call['args'] for call in calls if call['args'][:1] == ['run']]
        self.assertTrue(any('--version' in arguments for arguments in containers))
        self.assertTrue(any('--output' in arguments for arguments in containers))
        self.assertTrue(all(IMAGE_ID in arguments for arguments in containers))

    @unittest.skipUnless(os.name == 'posix', 'interactive terminal requires POSIX')
    def test_source_wizard_cancel_does_not_build_generate_or_create_the_deployment(self):
        source = self.source_bundle()
        code, output = self.run_interactive([('确认部署', '0')], '--source', str(source),
            '--dev-localhost', '--relay-endpoint', 'tls://localhost:18081', '--control-port', '18080',
            '--metrics-port', '18082', '--publish-host', '127.0.0.1', '--no-start', image=None,
            before_reply=lambda *_: self.assert_not_deployed())
        self.assertIn(code, (0, 1), output)
        self.assert_not_deployed()

    def test_source_manifest_checksum_and_identity_are_validated_before_building(self):
        for field, value in (('schema_version', 2), ('version', 'latest'), ('source_sha', 'unknown'), ('context', '../server')):
            with self.subTest(field=field):
                source = self.source_bundle(name='invalid-' + field)
                metadata = json.loads((source / 'SERVER-SOURCE.json').read_text())
                metadata[field] = value
                self.write_source_manifest(source, metadata)
                result = self.run_installer('--source', str(source), '--dev-localhost', '--dry-run', image=None)
                self.assertNotEqual(result.returncode, 0)
                self.assert_not_deployed()
        source = self.source_bundle(name='bad-metadata-checksum')
        (source / 'SERVER-SOURCE.json.sha256').write_text(f'{"0" * 64}  SERVER-SOURCE.json\n')
        result = self.run_installer('--source', str(source), '--dev-localhost', '--dry-run', image=None)
        self.assertNotEqual(result.returncode, 0)
        self.assert_not_deployed()

    def test_source_file_hash_mismatch_cannot_build_or_publish_configuration(self):
        source = self.source_bundle()
        (source / 'server/main.go').write_text('changed after packaging')
        result = self.run_installer('--source', str(source), '--dev-localhost', image=None)
        self.assertNotEqual(result.returncode, 0)
        self.assert_not_deployed()

    def test_source_manifest_rejects_traversal_and_unsupported_paths(self):
        for index, name in enumerate(('../outside', 'server/../outside', 'server//file', '/server/main.go',
                                      'deploy/selfhost/unverified.yml')):
            with self.subTest(name=name):
                source = self.source_bundle(name='invalid-path-' + str(index))
                metadata = json.loads((source / 'SERVER-SOURCE.json').read_text())
                metadata['files'][name] = '0' * 64
                self.write_source_manifest(source, metadata)
                result = self.run_installer('--source', str(source), '--dev-localhost', '--dry-run', image=None)
                self.assertNotEqual(result.returncode, 0)
                self.assert_not_deployed()

    def test_source_rejects_symbolic_links_linked_ancestors_and_hard_links(self):
        for kind in ('file-symlink', 'directory-symlink', 'hard-link', 'metadata-symlink'):
            with self.subTest(kind=kind):
                source = self.source_bundle(name=kind)
                if kind == 'directory-symlink':
                    (source / 'server').rename(source / 'real-server')
                    (source / 'server').symlink_to(source / 'real-server', target_is_directory=True)
                else:
                    path = source / ('SERVER-SOURCE.json' if kind == 'metadata-symlink' else 'server/main.go')
                    original = self.path / (kind + '-original')
                    path.rename(original)
                    os.link(original, path) if kind == 'hard-link' else path.symlink_to(original)
                result = self.run_installer('--source', str(source), '--dev-localhost', '--dry-run', image=None)
                self.assertNotEqual(result.returncode, 0)
                self.assert_not_deployed()

    def test_source_limits_metadata_file_count_individual_and_total_bytes(self):
        source = self.source_bundle(name='too-many-files')
        metadata = json.loads((source / 'SERVER-SOURCE.json').read_text())
        metadata['files'].update({f'server/extra-{index}': '0' * 64 for index in range(4097)})
        self.write_source_manifest(source, metadata)
        result = self.run_installer('--source', str(source), '--dev-localhost', '--dry-run', image=None)
        self.assertNotEqual(result.returncode, 0)
        source = self.source_bundle(name='oversized-metadata')
        (source / 'SERVER-SOURCE.json').write_bytes(b' ' * (1024 * 1024 + 1))
        result = self.run_installer('--source', str(source), '--dev-localhost', '--dry-run', image=None)
        self.assertNotEqual(result.returncode, 0)
        source = self.source_bundle(name='oversized-file')
        large = source / 'server/large.bin'
        with large.open('wb') as stream:
            stream.truncate(64 * 1024 * 1024 + 1)
        metadata = json.loads((source / 'SERVER-SOURCE.json').read_text())
        metadata['files']['server/large.bin'] = '0' * 64
        self.write_source_manifest(source, metadata)
        result = self.run_installer('--source', str(source), '--dev-localhost', '--dry-run', image=None)
        self.assertNotEqual(result.returncode, 0)
        source = self.source_bundle(name='oversized-total')
        metadata = json.loads((source / 'SERVER-SOURCE.json').read_text())
        digest = hashlib.sha256()
        zeroes = b'\0' * (1024 * 1024)
        for _ in range(64):
            digest.update(zeroes)
        for index in range(5):
            name = f'server/large-{index}.bin'
            with (source / name).open('wb') as stream:
                stream.truncate(64 * 1024 * 1024)
            metadata['files'][name] = digest.hexdigest()
        self.write_source_manifest(source, metadata)
        result = self.run_installer('--source', str(source), '--dev-localhost', '--dry-run', image=None)
        self.assertNotEqual(result.returncode, 0)
        self.assert_not_deployed()

    def test_unlisted_source_files_are_never_copied_into_the_build_context(self):
        source = self.source_bundle()
        (source / 'server/unlisted.txt').write_text('not part of the verified source')
        result = self.run_installer('--source', str(source), '--dev-localhost', '--no-start', image=None)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((self.target / 'sources' / COMMIT / 'server/unlisted.txt').exists())

    def test_source_reinstallation_restores_its_build_mode_and_preserves_credentials_and_database(self):
        source = self.source_bundle()
        first = self.run_installer('--source', str(source), '--dev-localhost', '--no-start', image=None)
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        config = self.target / 'config'
        (config / 'data/p2pnet.db').write_bytes(b'persisted database')
        before = {str(path.relative_to(config)): path.read_bytes() for path in config.rglob('*') if path.is_file()}
        second = self.run_installer('--no-start', image=None)
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        self.assertEqual(before, {str(path.relative_to(config)): path.read_bytes() for path in config.rglob('*') if path.is_file()})
        calls = self.calls()
        self.assertEqual(sum(call['args'][:1] == ['compose'] and 'build' in call['args'] for call in calls), 1)
        self.assertEqual(sum('--output' in call['args'] for call in calls), 1)
        self.assert_no_application_pull(calls)

    def test_source_rebuilds_when_the_cached_image_id_is_missing(self):
        source = self.source_bundle()
        first = self.run_installer('--source', str(source), '--dev-localhost', '--no-start', image=None)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.env['DOCKER_FIXTURE_ID'] = 'sha256:' + 'e' * 64
        second = self.run_installer('--no-start', image=None)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(sum('build' in call['args'] for call in self.calls()), 2)
        self.assertIn('P2WLAN_IMAGE=' + self.env['DOCKER_FIXTURE_ID'], (self.target / '.env').read_text())

    def test_source_build_failure_preserves_the_existing_runtime_configuration(self):
        source = self.source_bundle()
        first = self.run_installer('--source', str(source), '--dev-localhost', '--no-start', image=None)
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        config = self.target / 'config'
        (config / 'data/p2pnet.db').write_bytes(b'persisted database')
        before = {str(path.relative_to(self.target)): path.read_bytes() for path in config.rglob('*') if path.is_file()}
        environment = (self.target / '.env').read_bytes()
        runtime = (self.target / 'compose.yml').read_bytes()
        calls_before = len(self.calls())
        newer = self.source_bundle(name='newer', commit='e' * 40, version='server-v9.9.10')
        self.env['FAIL_DOCKER_BUILD'] = '1'
        result = self.run_installer('--source', str(newer), image=None)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.target / '.env').read_bytes(), environment)
        self.assertEqual((self.target / 'compose.yml').read_bytes(), runtime)
        self.assertEqual(before, {str(path.relative_to(self.target)): path.read_bytes() for path in config.rglob('*') if path.is_file()})
        later = self.calls()[calls_before:]
        self.assertFalse(any(call['args'][:1] == ['run'] for call in later))
        self.assertFalse(any('up' in call['args'] and '--help' not in call['args'] for call in later))

    def failed_upgrade(self, migration=False):
        first = self.run_installer('--dev-localhost')
        self.assertEqual(first.returncode, 0, first.stderr)
        previous = (self.target / '.env').read_bytes()
        database = self.target / 'config/data/p2pnet.db'
        with sqlite3.connect(str(database)) as db:
            db.execute('PRAGMA journal_mode=WAL')
            db.execute('CREATE TABLE entries (value TEXT)')
            db.execute("INSERT INTO entries VALUES ('before-upgrade')")
        newer = IMAGE.replace('a' * 64, 'd' * 64)
        self.env.update(DOCKER_FIXTURE_IMAGE=newer, FAIL_FIXTURE_IMAGE=newer, FIXTURE_DATABASE=str(database),
                        DOCKER_FIXTURE_RUNNING='control', DOCKER_FIXTURE_PRESENT='control\nrelay',
                        DOCKER_FIXTURE_VERSION='server-v9.9.10')
        prepared = self.run_installer('--no-start', image=newer)
        self.assertEqual(prepared.returncode, 0, prepared.stderr)
        self.assertNotEqual((self.target / '.env').read_bytes(), previous)
        if migration:
            self.env['FIXTURE_MIGRATION'] = 'yes'
        result = self.run_installer(image=None)
        self.assertNotEqual(result.returncode, 0)
        snapshot = next(self.target.glob('.upgrade-*/database.sqlite'))
        with sqlite3.connect(str(snapshot)) as before, sqlite3.connect(str(database)) as after:
            self.assertEqual(before.execute('SELECT value FROM entries').fetchall(), [('before-upgrade',)])
            self.assertEqual(after.execute('SELECT value FROM entries').fetchall(), [('before-upgrade',), ('during-upgrade',)])
        return previous, result

    def test_failed_prepared_upgrade_preserves_writes_and_restores_only_running_services(self):
        previous, result = self.failed_upgrade()
        self.assertIn('Restored the prior deployment', result.stderr)
        self.assertEqual((self.target / '.env').read_bytes(), previous)
        activation = self.calls()[-1]
        self.assertEqual(activation['args'][-2:], ['--no-deps', 'control'])
        self.assertEqual(activation['env']['P2WLAN_IMAGE'], IMAGE)
        self.assertTrue(any('--no-start' in call['args'] and call['args'][-1] == 'relay'
                            for call in self.calls()))

    def test_failed_upgrade_with_changed_schema_keeps_the_snapshot_and_stops(self):
        previous, result = self.failed_upgrade(migration=True)
        self.assertIn('schema changed', result.stderr)
        self.assertNotEqual((self.target / '.env').read_bytes(), previous)
        self.assertEqual(self.calls()[-1]['args'][-1], 'stop')
        self.assertTrue((self.target / '.recovery-required').is_file())

    def test_public_activation_requires_the_real_panel_route(self):
        self.env['FIXTURE_PANEL_CODE'] = '502'
        result = self.run_installer('--relay-endpoint', 'tls://relay.example.test:28081', '--tls-mode', 'selfsigned')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('HTTPS edge verification failed', result.stderr)
        self.assertEqual(self.calls()[-1]['args'][-1], 'stop')

    def test_saved_source_corruption_is_rejected_before_rebuilding(self):
        source = self.source_bundle()
        first = self.run_installer('--source', str(source), '--dev-localhost', '--no-start', image=None)
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        environment = (self.target / '.env').read_bytes()
        (self.target / 'sources' / COMMIT / 'server/main.go').write_text('corrupted')
        result = self.run_installer('--source', str(source), '--no-start', image=None)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.target / '.env').read_bytes(), environment)
        self.assertEqual(sum('build' in call['args'] for call in self.calls()), 1)

    def test_built_labels_and_binary_versions_must_match_the_verified_source(self):
        for field in ('DOCKER_FIXTURE_LABEL_COMMIT', 'DOCKER_FIXTURE_BINARY_COMMIT'):
            with self.subTest(field=field):
                source = self.source_bundle(name=field)
                self.env[field] = 'd' * 40
                result = self.run_installer('--source', str(source), '--dev-localhost', '--no-start', image=None)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.target / '.env').exists())
                self.assertFalse((self.target / 'config').exists())
                self.assertFalse(any('--output' in call['args'] for call in self.calls()))
                self.env.pop(field)

    def test_source_upgrade_builds_the_selected_new_commit_without_regenerating_configuration(self):
        source = self.source_bundle()
        first = self.run_installer('--source', str(source), '--dev-localhost', '--no-start', image=None)
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        config = self.target / 'config'
        (config / 'data/p2pnet.db').write_bytes(b'persisted database')
        before = {str(path.relative_to(config)): path.read_bytes() for path in config.rglob('*') if path.is_file()}
        commit, version = 'e' * 40, 'server-v9.9.10'
        newer = self.source_bundle(name='upgrade', commit=commit, version=version)
        self.env.update(DOCKER_FIXTURE_COMMIT=commit, DOCKER_FIXTURE_VERSION=version,
                        DOCKER_FIXTURE_ID='sha256:' + 'd' * 64)
        second = self.run_installer('--source', str(newer), '--no-start', image=None)
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        self.assertEqual(before, {str(path.relative_to(config)): path.read_bytes() for path in config.rglob('*') if path.is_file()})
        settings = (self.target / '.env').read_text()
        self.assertIn(f'P2WLAN_COMMIT={commit}', settings)
        self.assertIn(f'P2WLAN_VERSION={version}', settings)
        self.assertIn('P2WLAN_IMAGE=sha256:' + 'd' * 64, settings)
        self.assertEqual(sum('--output' in call['args'] for call in self.calls()), 1)


if __name__ == '__main__':
    unittest.main()
