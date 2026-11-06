"""Test the Docker installer without a daemon, registry or privileged writes."""
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest

if os.name == 'posix':
    import pty


ROOT = Path(__file__).resolve().parents[2]
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
        ('P2WLAN_IMAGE', 'P2WLAN_CONFIG_DIR', 'RELAY_PUBLISH_HOST')}}) + '\n')
if args[:1] == ['info']:
    if os.environ.get('FAIL_DOCKER_INFO'): sys.exit(1)
    print(json.dumps({'OSType': os.environ.get('DOCKER_FIXTURE_OS', 'linux'),
                      'SecurityOptions': [os.environ['DOCKER_FIXTURE_SECURITY']] if os.environ.get('DOCKER_FIXTURE_SECURITY') else []}))
elif args[:2] == ['context', 'inspect']:
    print(os.environ.get('DOCKER_FIXTURE_CONTEXT', 'unix:///fixture/docker.sock'))
elif args[:2] == ['compose', 'version']:
    print('2.39.4')
elif args[:2] == ['compose', 'up'] and '--help' in args:
    print('' if os.environ.get('DOCKER_FIXTURE_NO_WAIT') else '--wait --wait-timeout')
elif args[:2] == ['image', 'inspect']:
    print(json.dumps({'Id': os.environ['DOCKER_FIXTURE_ID'], 'RepoDigests': [os.environ['DOCKER_FIXTURE_IMAGE']],
          'Config': {'Labels': {'org.opencontainers.image.revision': os.environ['DOCKER_FIXTURE_COMMIT'],
                               'org.opencontainers.image.version': 'server-v9.9.9'}}}))
elif args[:1] == ['pull']:
    if os.environ.get('FAIL_DOCKER_PULL'): sys.exit(1)
elif args[:1] == ['run']:
    if '--version' in args and '--entrypoint' in args:
        component = pathlib.Path(args[args.index('--entrypoint') + 1]).name
        print(f"{component} server-v9.9.9 ({os.environ['DOCKER_FIXTURE_COMMIT']})")
        sys.exit(0)
    if '--help' in args:
        print('--mode --output --relay-endpoint --tls-cert --tls-key --dev-localhost')
        sys.exit(0)
    if '--output' not in args: sys.exit(0)
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
    for name, value in values.items():
        path = output / name
        path.write_text(value)
        path.chmod(0o600)
    if os.getuid() == 0:
        for path in [output, output / 'data'] + list(output.iterdir()): os.chown(path, uid, gid)
elif args[:1] == ['compose']:
    if 'config' in args:
        if os.environ.get('FAIL_COMPOSE_CONFIG'): sys.exit(1)
    elif 'up' in args:
        if os.environ.get('FAIL_COMPOSE_UP'): sys.exit(1)
    elif 'ps' in args:
        print('[]')
else:
    print('unsupported fake Docker command', file=sys.stderr)
    sys.exit(92)
''')
        # A deployment must not unexpectedly install Docker or build source.
        for command in ('curl', 'apt-get', 'dnf', 'sudo'):
            self.executable(self.bin / command, '#!/bin/sh\necho unexpected-external-command >&2\nexit 94\n')

    @staticmethod
    def executable(path, content):
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
                        os.write(terminal, (reply + '\n').encode())
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

    def manifest(self, *, commit=COMMIT, checksum=True):
        path = self.path / 'SERVER-IMAGE.json'
        path.write_text(json.dumps({'schema_version': 1, 'version': 'server-v9.9.9',
                                    'source_sha': commit, 'image': IMAGE}))
        digest = hashlib.sha256(path.read_bytes()).hexdigest() if checksum else '0' * 64
        (self.path / 'SERVER-IMAGE.json.sha256').write_text(f'{digest}  SERVER-IMAGE.json\n')

    def test_dry_run_does_not_contact_docker_or_create_the_deployment(self):
        result = self.run_installer('--dev-localhost', '--dry-run')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.target.exists())
        self.assertEqual(self.calls(), [])

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
            ('metrics端口', ''), ('Relay绑定IP', ''), ('确认部署', '1'),
        ], '--dev-localhost', '--no-start', before_reply=lambda *_: self.assert_not_deployed())
        self.assertEqual(code, 0, output)
        self.assertTrue((self.target / 'config/control.env').exists())
        self.assertNotIn('fixture-private-token', output)

    @unittest.skipUnless(os.name == 'posix', 'interactive terminal requires POSIX')
    def test_wizard_prompts_for_default_directory_and_can_prepare_a_local_deployment(self):
        code, output = self.run_interactive([
            ('部署目录', str(self.target)), ('部署模式', '2'), ('Relay主机', ''),
            ('Relay端口', ''), ('Control端口', ''), ('metrics端口', ''),
            ('Relay绑定IP', ''), ('启动方式', '2'), ('确认部署', '1'),
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
            ('证书链路径', str(certificate)), ('私钥路径', str(key)),
            ('Control端口', '28080'), ('metrics端口', '28082'),
            ('Relay绑定IP', '0.0.0.0'), ('启动方式', '1'), ('确认部署', '1'),
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
            ('确认部署', '99'), ('确认部署', '1'),
        ], include_dir=False, before_reply=lambda *_: self.assert_not_deployed())
        self.assertEqual(code, 0, output)
        settings = (self.target / '.env').read_text()
        self.assertIn('CONTROL_PORT=28080', settings)
        self.assertIn('METRICS_PORT=28082', settings)
        self.assertIn('RELAY_PUBLISH_HOST=127.0.0.2', settings)

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
            ('Relay绑定IP', '127.0.0.1'), ('启动方式', '2'), ('确认部署', '1'),
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
            ('Relay绑定IP', ''), ('启动方式', '2'), ('确认部署', '1'),
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
            self.assertFalse(any(call['args'][:1] in (['pull'], ['run']) for call in self.calls()[calls_before:]))
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
        self.assertFalse(any(call['args'][:1] == ['pull'] for call in self.calls()))
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
        self.assertFalse(any(call['args'][:1] == ['pull'] for call in self.calls()))
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


if __name__ == '__main__':
    unittest.main()
