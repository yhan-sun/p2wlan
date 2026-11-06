"""Exercise remote bootstrap selection and verification without host changes."""
import hashlib
import io
import json
import os
from pathlib import Path
import select
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest

if os.name == 'posix':
    import pty


ROOT = Path(__file__).resolve().parents[2]
VERSION = 'server-v9.9.9'
COMMIT = 'c' * 40
IMAGE = 'registry.example.test/p2wlan-server@sha256:' + 'a' * 64
ARCHIVE = 'p2wlan-server-docker.tar.gz'
ASSETS = (ARCHIVE, ARCHIVE + '.sha256', 'SERVER-IMAGE.json', 'SERVER-IMAGE.json.sha256')
NATIVE_ARCHIVE = 'p2wlan-server-linux-amd64.tar.gz'
NATIVE_ASSETS = (NATIVE_ARCHIVE, NATIVE_ARCHIVE + '.sha256')
SOURCE_ARCHIVE = 'p2wlan-server-source.tar.gz'
SOURCE_ASSETS = (SOURCE_ARCHIVE, SOURCE_ARCHIVE + '.sha256')


class BootstrapServerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        self.bin = self.path / 'bin'
        self.bin.mkdir()
        self.downloads = self.path / 'downloads'
        self.downloads.mkdir()
        self.target = self.path / 'deployment'
        self.curl_log = self.path / 'curl.jsonl'
        self.system_log = self.path / 'system.jsonl'
        self.installer_log = self.path / 'installer-args.json'
        self.os_release = self.path / 'os-release'
        self.os_release.write_text('ID=ubuntu\nVERSION_ID="24.04"\nVERSION_CODENAME=noble\n')
        systemd = self.path / 'systemd'
        systemd.mkdir()
        temporary = self.path / 'tmp'
        temporary.mkdir()
        self.env = dict(os.environ, PATH=str(self.bin), TMPDIR=str(temporary),
                        BOOTSTRAP_FIXTURE=str(self.path), BOOTSTRAP_DOWNLOADS=str(self.downloads),
                        BOOTSTRAP_CURL_LOG=str(self.curl_log), BOOTSTRAP_SYSTEM_LOG=str(self.system_log),
                        BOOTSTRAP_INSTALLER_LOG=str(self.installer_log),
                        BOOTSTRAP_EXECUTION_DIR_LOG=str(self.path / 'executed-package-dir'),
                        BOOTSTRAP_COMPOSE_READY=str(self.path / 'compose-ready'),
                        P2WLAN_DOCKER_MODE='image',
                        BOOTSTRAP_REAL_PYTHON=sys.executable,
                        P2WLAN_BOOTSTRAP_OS_RELEASE=str(self.os_release), P2WLAN_SYSTEMD_DIR=str(systemd))
        for name in ('bash', 'cat', 'cp', 'dirname', 'mktemp', 'rm', 'chmod', 'awk', 'sed', 'tar',
                     'sha256sum', 'date', 'readlink', 'stat', 'sleep', 'tee', 'head', 'tr', 'cut', 'sort',
                     'wc', 'mv', 'touch', 'rmdir', 'basename', 'find', 'openssl', 'cmp', 'env'):
            executable = shutil.which(name)
            if executable:
                (self.bin / name).symlink_to(executable)
        (self.bin / 'python3').symlink_to(sys.executable)
        self.env['BOOTSTRAP_REAL_MKTEMP'] = shutil.which('mktemp')
        (self.bin / 'mktemp').unlink()
        self.executable(self.bin / 'mktemp', '#!' + sys.executable + '\n' + r'''
import json, os, subprocess, sys
with open(os.environ['BOOTSTRAP_SYSTEM_LOG'], 'a') as log: log.write(json.dumps(['mktemp'] + sys.argv[1:]) + '\n')
sys.exit(subprocess.call([os.environ['BOOTSTRAP_REAL_MKTEMP']] + sys.argv[1:]))
''')
        self.executable(self.bin / 'id', '#!/bin/sh\ncase "$1" in -u) echo "${BOOTSTRAP_FAKE_UID:-0}";; *) exit 0;; esac\n')
        self.executable(self.bin / 'uname', '#!/bin/sh\ncase "$1" in -m) echo x86_64;; *) echo Linux;; esac\n')
        self.executable(self.bin / 'dpkg', '#!/bin/sh\necho amd64\n')
        self.executable(self.bin / 'sudo', '#!/bin/sh\nexit 95\n')
        self.executable(self.bin / 'mkdir', '#!' + sys.executable + '\n' + r'''
import os, pathlib, sys
args = sys.argv[1:]
paths = []
index = 0
while index < len(args):
    value = args[index]
    if value in ('-m', '--mode'): index += 2; continue
    if not value.startswith('-'): paths.append(value)
    index += 1
for value in paths:
    path = pathlib.Path(value).absolute()
    if not (str(path).startswith(os.environ['BOOTSTRAP_FIXTURE'] + '/')
            or str(path).startswith('/tmp/p2wlan-server-install.')
            or str(path).startswith('/private/tmp/p2wlan-server-install.')):
        sys.exit('fixture refused host directory write')
    path.mkdir(parents='-p' in args, exist_ok='-p' in args)
''')
        real_install = shutil.which('install')
        self.env['BOOTSTRAP_REAL_INSTALL'] = real_install
        self.executable(self.bin / 'install', '#!' + sys.executable + '\n' + r'''
import json, os, subprocess, sys
args = sys.argv[1:]
with open(os.environ['BOOTSTRAP_SYSTEM_LOG'], 'a') as log: log.write(json.dumps(['install'] + args) + '\n')
destination = args[-1]
if destination == '/etc' or destination.startswith('/etc/') or destination == '/usr/local/bin' or destination.startswith('/usr/local/bin/'): sys.exit(0)
if not destination.startswith(os.environ['BOOTSTRAP_FIXTURE'] + '/'):
    sys.exit('fixture refused host installation')
sys.exit(subprocess.call([os.environ['BOOTSTRAP_REAL_INSTALL']] + args))
''')
        self.executable(self.bin / 'curl', '#!' + sys.executable + '\n' + r'''
import json, os, pathlib, sys, urllib.parse
args = sys.argv[1:]
urls = [value for value in args if value.startswith('https://')]
if len(urls) != 1: sys.exit('unexpected fixture URL')
url = urls[0]
with open(os.environ['BOOTSTRAP_CURL_LOG'], 'a') as log: log.write(json.dumps(url) + '\n')
parsed = urllib.parse.urlparse(url)
fixture = pathlib.Path(os.environ['BOOTSTRAP_FIXTURE'])
if parsed.netloc == 'api.github.com' and parsed.path == '/repos/yhan-sun/p2wlan/releases':
    page = urllib.parse.parse_qs(parsed.query).get('page', ['1'])[0]
    source = fixture / ('releases-' + page + '.json')
    data = source.read_bytes() if source.exists() else b'[]'
elif parsed.netloc == 'github.com' and parsed.path.startswith('/yhan-sun/p2wlan/releases/download/' + os.environ.get('BOOTSTRAP_EXPECTED_VERSION', 'server-v9.9.9') + '/'):
    name = parsed.path.rsplit('/', 1)[-1]
    data = (pathlib.Path(os.environ['BOOTSTRAP_DOWNLOADS']) / name).read_bytes()
elif parsed.netloc == 'download.docker.com' and parsed.path.endswith('/gpg'):
    data = b'fixture-docker-public-key'
else:
    sys.exit('fixture refused unexpected network request')
output = None
for index, value in enumerate(args):
    if value in ('-o', '--output'): output = args[index + 1]
    elif value.startswith('--output='): output = value.split('=', 1)[1]
if output: pathlib.Path(output).write_bytes(data)
else: sys.stdout.buffer.write(data)
''')
        docker = self.path / 'fixture-docker'
        self.executable(docker, '#!' + sys.executable + '\n' + r'''
import json, os, pathlib, sys
args = sys.argv[1:]
with open(os.environ['BOOTSTRAP_SYSTEM_LOG'], 'a') as log: log.write(json.dumps(['docker'] + args) + '\n')
if args[:1] == ['info'] and os.environ.get('BOOTSTRAP_FAIL_DOCKER'): sys.exit(1)
ready = pathlib.Path(os.environ['BOOTSTRAP_COMPOSE_READY']).exists()
if args[:2] == ['compose', 'version'] and os.environ.get('BOOTSTRAP_NO_COMPOSE') and not ready: sys.exit(1)
if args[:2] == ['buildx', 'version'] and os.environ.get('BOOTSTRAP_NO_BUILDX') and not ready: sys.exit(1)
if args[:2] == ['context', 'inspect']: print('unix:///fixture/docker.sock')
elif args[:2] == ['compose', 'up'] and '--help' in args:
    print('' if os.environ.get('BOOTSTRAP_OLD_COMPOSE') and not ready else '--wait --wait-timeout')
else: print('2.39.4' if args[:1] == ['compose'] else 'linux')
''')
        self.env['BOOTSTRAP_DOCKER_SOURCE'] = str(docker)
        shutil.copyfile(docker, self.bin / 'docker')
        (self.bin / 'docker').chmod(0o755)
        for name in ('apt-get', 'dnf', 'systemctl', 'useradd', 'chown'):
            self.executable(self.bin / name, '#!' + sys.executable + '\n' + r'''
import json, os, pathlib, shutil, sys
name, args = pathlib.Path(sys.argv[0]).name, sys.argv[1:]
with open(os.environ['BOOTSTRAP_SYSTEM_LOG'], 'a') as log: log.write(json.dumps([name] + args) + '\n')
if name in ('apt-get', 'dnf') and 'install' in args:
    binary = pathlib.Path(os.environ['PATH'])
    if not (binary / 'python3').exists(): (binary / 'python3').symlink_to(os.environ['BOOTSTRAP_REAL_PYTHON'])
    if any('docker' in value for value in args):
        shutil.copyfile(os.environ['BOOTSTRAP_DOCKER_SOURCE'], binary / 'docker')
        (binary / 'docker').chmod(0o755)
    if 'docker-compose-plugin' in args or 'docker-buildx-plugin' in args:
        pathlib.Path(os.environ['BOOTSTRAP_COMPOSE_READY']).touch()
''')
        self.manifest = {'schema_version': 1, 'version': VERSION, 'source_sha': COMMIT, 'image': IMAGE,
                         'digest': IMAGE.split('@')[1], 'platforms': ['linux/amd64', 'linux/arm64']}
        self.members = {
            'install-server-docker.sh': b'''#!/bin/bash
printf '%s\\n' "$(dirname -- "$0")" > "$BOOTSTRAP_EXECUTION_DIR_LOG"
python3 - "$@" <<'FIXTURE'
import json, os, pathlib, sys
pathlib.Path(os.environ['BOOTSTRAP_INSTALLER_LOG']).write_text(json.dumps(sys.argv[1:]))
sys.exit(int(os.environ.get('BOOTSTRAP_INSTALLER_EXIT', '0')))
FIXTURE
''',
            'compose.production.yml': b'services: {}\n',
        }
        self.pack()
        self.releases([
            self.release('v99.0.0', published='2026-11-05T00:00:00Z'),
            self.release('server-v9.9.10', published='2026-11-04T00:00:00Z', names=ASSETS[:-1]),
            self.release(VERSION, published='2026-11-03T00:00:00Z'),
            self.release('server-v9.9.8', published='2026-11-02T00:00:00Z'),
        ])
        self.native_metadata = dict(version=VERSION, commit=COMMIT, arch='amd64')
        self.native_members = {
            name: f'#!/bin/sh\necho "{name} {VERSION} ({COMMIT})"\n'.encode()
            for name in ('p2wlan-control', 'p2wlan-relay', 'p2wlan-config', 'p2wlan-db', 'p2wlan-server', 'deploy-server.sh')
        }
        self.native_members['install-server.sh'] = b'''#!/bin/bash
if [ "${1:-}" = --help ]; then echo '--interactive --control-port --metrics-port --no-start'; exit 0; fi
printf '%s\\n' "$(dirname -- "$0")" > "$BOOTSTRAP_EXECUTION_DIR_LOG"
python3 - "$@" <<'FIXTURE'
import json, os, pathlib, sys
pathlib.Path(os.environ['BOOTSTRAP_INSTALLER_LOG']).write_text(json.dumps(sys.argv[1:]))
sys.exit(int(os.environ.get('BOOTSTRAP_INSTALLER_EXIT', '0')))
FIXTURE
'''
        self.pack_native()
        self.source_members = {
            'scripts/install-server-docker.sh': self.members['install-server-docker.sh'],
            'deploy/selfhost/compose.production.yml': b'services: {}\n',
            'deploy/selfhost/compose.build.yml': b'services: {builder: {build: {context: "${P2WLAN_BUILD_CONTEXT}"}}}\n',
            'server/Dockerfile': b'FROM scratch\n',
            'server/go.mod': b'module example.test/server\n',
            'server/go.sum': b'',
        }
        self.source_metadata = dict(schema_version=1, version=VERSION, source_sha=COMMIT, context='server')
        self.pack_source()

    @staticmethod
    def executable(path, content):
        if path.is_symlink():
            path.unlink()
        path.write_text(content)
        path.chmod(0o755)

    @staticmethod
    def release(tag, *, published, names=ASSETS, **extra):
        value = dict(tag_name=tag, published_at=published, draft=False, prerelease=False,
                     assets=[dict(name=name, state='uploaded', browser_download_url='https://untrusted.example.test/asset') for name in names])
        value.update(extra)
        return value

    def releases(self, values, page=1):
        (self.path / f'releases-{page}.json').write_text(json.dumps(values))

    def pack(self, *, bad_inner=False, duplicate=None, symlink=None):
        raw = json.dumps(self.manifest).encode()
        self.members['SERVER-IMAGE.json'] = raw
        digest = '0' * 64 if bad_inner else hashlib.sha256(raw).hexdigest()
        self.members['SERVER-IMAGE.json.sha256'] = f'{digest}  SERVER-IMAGE.json\n'.encode()
        archive = self.downloads / ARCHIVE
        with tarfile.open(archive, 'w:gz') as bundle:
            for name, data in self.members.items():
                member = tarfile.TarInfo(name)
                member.mode = 0o755 if name.endswith('.sh') else 0o644
                member.size = len(data)
                if name == symlink:
                    member.type, member.linkname, member.size = tarfile.SYMTYPE, '/outside/fixture', 0
                    bundle.addfile(member)
                else:
                    bundle.addfile(member, io.BytesIO(data))
                if name == duplicate:
                    bundle.addfile(member, io.BytesIO(data))
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        (self.downloads / (ARCHIVE + '.sha256')).write_text(f'{digest}  {ARCHIVE}\n')
        for name in ('SERVER-IMAGE.json', 'SERVER-IMAGE.json.sha256'):
            (self.downloads / name).write_bytes(self.members[name])

    def pack_native(self, *, bad_inner=False, duplicate=None, symlink=None):
        self.native_members['BUILD-METADATA.txt'] = ''.join(f'{key}={value}\n' for key, value in self.native_metadata.items()).encode()
        sums = []
        for name in ('p2wlan-control', 'p2wlan-relay', 'p2wlan-config', 'p2wlan-db'):
            digest = hashlib.sha256(self.native_members[name]).hexdigest()
            if bad_inner and name == 'p2wlan-control':
                digest = '0' * 64
            sums.append(f'{digest}  {name}\n')
        self.native_members['SHA256SUMS'] = ''.join(sums).encode()
        archive = self.downloads / NATIVE_ARCHIVE
        with tarfile.open(archive, 'w:gz') as bundle:
            for name, data in self.native_members.items():
                member = tarfile.TarInfo(name)
                member.mode = 0o644 if name in ('BUILD-METADATA.txt', 'SHA256SUMS') else 0o755
                member.size = len(data)
                if name == symlink:
                    member.type, member.linkname, member.size = tarfile.SYMTYPE, '/outside/fixture', 0
                    bundle.addfile(member)
                else:
                    bundle.addfile(member, io.BytesIO(data))
                if name == duplicate:
                    bundle.addfile(member, io.BytesIO(data))
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        (self.downloads / (NATIVE_ARCHIVE + '.sha256')).write_text(f'{digest}  {NATIVE_ARCHIVE}\n')

    def pack_source(self, *, bad_inner=False, duplicate=None, symlink=None, extra=None, altered=None):
        metadata = dict(self.source_metadata,
                        files={name: hashlib.sha256(data).hexdigest() for name, data in self.source_members.items()})
        raw = json.dumps(metadata).encode()
        digest = '0' * 64 if bad_inner else hashlib.sha256(raw).hexdigest()
        content = dict(self.source_members)
        content.update({'SERVER-SOURCE.json': raw,
                        'SERVER-SOURCE.json.sha256': f'{digest}  SERVER-SOURCE.json\n'.encode()})
        if extra:
            content[extra] = b'unexpected archive member'
        if altered:
            content[altered] += b'tampered after hashing'
        archive = self.downloads / SOURCE_ARCHIVE
        with tarfile.open(archive, 'w:gz') as bundle:
            for name, data in content.items():
                member = tarfile.TarInfo(name)
                member.mode = 0o755 if name.endswith('.sh') else 0o644
                member.size = len(data)
                if name == symlink:
                    member.type, member.linkname, member.size = tarfile.SYMTYPE, '/outside/fixture', 0
                    bundle.addfile(member)
                else:
                    bundle.addfile(member, io.BytesIO(data))
                if name == duplicate:
                    bundle.addfile(member, io.BytesIO(data))
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        (self.downloads / (SOURCE_ARCHIVE + '.sha256')).write_text(f'{digest}  {SOURCE_ARCHIVE}\n')

    def run_bootstrap(self, *args, version=VERSION, headless=True, include_dir=True):
        command = ['/bin/bash', '-s', '--']
        if headless:
            command += ['--non-interactive']
        if version is not None:
            command += ['--version', version]
        if include_dir:
            command += ['--dir', str(self.target)]
        command += list(args)
        return subprocess.run(command, cwd=self.path, env=self.env,
                              input=(ROOT / 'scripts/bootstrap-server.sh').read_text(),
                              capture_output=True, text=True, start_new_session=True, timeout=30)

    def run_piped_pty(self, *args, steps=None, before_reply=None, method='docker'):
        source_read, source_write = os.pipe()
        pid, terminal = pty.fork()
        if pid == 0:
            os.close(source_write)
            os.dup2(source_read, 0)
            os.close(source_read)
            os.chdir(self.path)
            os.execve('/bin/bash', ['bash', '-s', '--'] + list(args), self.env)
        os.close(source_read)
        transcript, status, cursor = bytearray(), None, 0
        pending = list(steps) if steps is not None else [('请选择版本编号', '1')]
        if '--method' not in args and method is not None:
            pending.insert(0, ('安装方式', '1' if method == 'native' else '2'))
        try:
            with os.fdopen(source_write, 'wb') as pipe:
                pipe.write((ROOT / 'scripts/bootstrap-server.sh').read_bytes())
            deadline = time.monotonic() + 40
            while time.monotonic() < deadline:
                if select.select([terminal], [], [], 0.1)[0]:
                    try:
                        chunk = os.read(terminal, 65536)
                    except OSError:
                        chunk = b''
                    transcript.extend(chunk)
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
            self.assertIsNotNone(status, transcript.decode(errors='replace'))
            self.assertTrue(os.WIFEXITED(status), transcript.decode(errors='replace'))
            self.assertFalse(pending, f'unanswered prompts {pending!r}\n{transcript.decode(errors="replace")}')
            return os.WEXITSTATUS(status), transcript.decode(errors='replace')
        finally:
            os.close(terminal)
            if status is None:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)

    @staticmethod
    def json_lines(path):
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def assert_installer_not_run(self):
        self.assertFalse(self.installer_log.exists())
        self.assertFalse(self.target.exists())

    def simulate_fresh_docker_host(self):
        (self.bin / 'docker').unlink()
        # A runner may already have Docker apt sources. Simulate their absence
        # only for this read-only shell predicate; all /etc writes remain fake.
        startup = self.path / 'bash-fixture-environment'
        startup.write_text('''function [() {
  if [[ "${1:-}" == -f ]] && [[ "${2:-}" == /etc/apt/sources.list.d/docker.sources || "${2:-}" == /etc/apt/sources.list.d/docker.list ]]; then
    return 1
  fi
  builtin [ "$@"
}
''')
        self.env['BASH_ENV'] = str(startup)

    def test_default_docker_pipe_selects_source_release_and_hands_off_verified_source(self):
        # The remaining image tests explicitly select their legacy path using
        # the fixture environment. No override is present in this default test.
        self.env.pop('P2WLAN_DOCKER_MODE')
        self.releases([
            self.release('v99.0.0', published='2026-11-06T00:00:00Z', names=SOURCE_ASSETS),
            self.release('server-v9.9.10', published='2026-11-05T00:00:00Z'),
            self.release(VERSION, published='2026-11-04T00:00:00Z', names=SOURCE_ASSETS),
        ])
        code, output = self.run_piped_pty()
        self.assertEqual(code, 0, output)
        self.assertIn('Compose 本机源码构建', output)
        self.assertIn('Verified source ' + VERSION, output)
        self.assertNotIn('1) server-v9.9.10', output)
        arguments = json.loads(self.installer_log.read_text())
        self.assertIn('--interactive', arguments)
        source = Path(arguments[arguments.index('--source') + 1])
        self.assertFalse(source.exists(), 'bootstrap temporary source must be cleaned')
        self.assertNotIn('--manifest', arguments)
        downloads = [url for url in self.json_lines(self.curl_log) if '/releases/download/' in url]
        self.assertEqual({url.rsplit('/', 1)[-1] for url in downloads}, set(SOURCE_ASSETS))
        self.assertFalse(any('ghcr.io' in url for url in self.json_lines(self.curl_log)))

    def test_explicit_source_build_automation_pins_version_without_image_metadata(self):
        result = self.run_bootstrap('--docker-mode', 'build', '--no-start')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        arguments = json.loads(self.installer_log.read_text())
        self.assertIn('--source', arguments)
        self.assertIn('--non-interactive', arguments)
        self.assertIn('--no-start', arguments)
        self.assertNotIn('--manifest', arguments)
        self.assertTrue(all(f'/releases/download/{VERSION}/' in url for url in self.json_lines(self.curl_log)))

    def test_source_dry_run_never_executes_installer_or_builds(self):
        result = self.run_bootstrap('--docker-mode', 'build', '--dry-run')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('Verified source', result.stdout)
        self.assert_installer_not_run()
        self.assertFalse(any(call[0] == 'docker' and 'build' in call for call in self.json_lines(self.system_log)))

    def test_invalid_source_archives_cannot_execute_the_installer(self):
        cases = (
            ({'bad_inner': True}, 'source manifest checksum mismatch'),
            ({'duplicate': 'server/Dockerfile'}, 'unsafe or duplicate path'),
            ({'symlink': 'scripts/install-server-docker.sh'}, 'bounded regular source members'),
            ({'extra': '../outside'}, 'unsafe or duplicate path'),
            ({'extra': 'server/unlisted.go'}, 'checksum manifest does not match'),
            ({'altered': 'server/go.mod'}, 'source file checksum mismatch'),
        )
        for options, reason in cases:
            with self.subTest(options=options):
                self.pack_source(**options)
                result = self.run_bootstrap('--docker-mode', 'build')
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn(reason, result.stderr)
                self.assertNotIn('Traceback', result.stderr)
                self.assert_installer_not_run()

    def test_source_metadata_requires_version_commit_and_expected_build_context(self):
        for key, value in (('version', 'server-v8.8.8'), ('source_sha', 'unknown'),
                           ('context', '../server'), ('schema_version', 2)):
            with self.subTest(key=key):
                old = self.source_metadata[key]
                self.source_metadata[key] = value
                self.pack_source()
                result = self.run_bootstrap('--docker-mode', 'build')
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('source archive requires the selected version', result.stderr)
                self.assertNotIn('Traceback', result.stderr)
                self.assert_installer_not_run()
                self.source_metadata[key] = old

    def test_source_build_prepares_only_missing_buildx_on_an_existing_engine(self):
        self.env['BOOTSTRAP_NO_BUILDX'] = '1'
        result = self.run_bootstrap('--docker-mode', 'build', '--install-deps', '--no-start')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        installs = [call for call in self.json_lines(self.system_log) if call[:1] == ['apt-get'] and 'install' in call]
        self.assertTrue(any('docker-buildx-plugin' in call for call in installs))
        self.assertFalse(any('docker-ce' in call or 'docker-compose-plugin' in call for call in installs))

    def test_invalid_docker_mode_is_rejected_before_network_or_deployment(self):
        result = self.run_bootstrap('--docker-mode', 'unknown')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.json_lines(self.curl_log), [])
        self.assert_installer_not_run()

    def test_fixed_version_bootstrap_uses_only_that_tags_assets(self):
        result = self.run_bootstrap('--no-start')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        urls = self.json_lines(self.curl_log)
        self.assertTrue(urls)
        self.assertTrue(all(f'/releases/download/{VERSION}/' in url for url in urls))
        self.assertFalse(any('/releases/latest' in url or 'api.github.com' in url for url in urls))
        arguments = json.loads(self.installer_log.read_text())
        self.assertIn('--non-interactive', arguments)
        self.assertIn('--no-start', arguments)
        self.assertNotIn('--version', arguments)

    def test_dry_run_verifies_the_bundle_without_system_or_deployment_mutations(self):
        result = self.run_bootstrap('--dry-run')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assert_installer_not_run()
        mutations = [call for call in self.json_lines(self.system_log) if call[0] in ('apt-get', 'dnf', 'install', 'systemctl')]
        self.assertEqual(mutations, [])

    def test_noninteractive_mode_requires_an_explicit_fixed_server_version(self):
        result = self.run_bootstrap(version=None)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.json_lines(self.curl_log), [])
        self.assert_installer_not_run()

    def test_client_latest_or_unsafe_versions_are_rejected_before_network(self):
        for version in ('latest', 'v99.0.0', 'server-v', 'server-v1/other', 'server-v1?other=1'):
            with self.subTest(version=version):
                result = self.run_bootstrap(version=version)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.json_lines(self.curl_log), [])
                self.assert_installer_not_run()

    def test_outer_checksum_failure_cannot_execute_downloaded_installer(self):
        (self.downloads / (ARCHIVE + '.sha256')).write_text(f'{"0" * 64}  {ARCHIVE}\n')
        result = self.run_bootstrap()
        self.assertNotEqual(result.returncode, 0)
        self.assert_installer_not_run()

    def test_inner_manifest_checksum_failure_cannot_execute_installer(self):
        self.pack(bad_inner=True)
        result = self.run_bootstrap()
        self.assertNotEqual(result.returncode, 0)
        self.assert_installer_not_run()

    def test_manifest_version_commit_and_image_must_be_valid(self):
        for key, value in (('version', 'server-v8.8.8'), ('source_sha', 'unknown'), ('image', 'server:latest'),
                           ('digest', 'sha256:' + 'f' * 64), ('platforms', ['linux/arm64'])):
            with self.subTest(key=key):
                original = self.manifest[key]
                self.manifest[key] = value
                self.pack()
                result = self.run_bootstrap()
                self.assertNotEqual(result.returncode, 0)
                self.assert_installer_not_run()
                self.manifest[key] = original

    def test_truncated_curl_source_cannot_execute_dependency_or_deployment_commands(self):
        source = (ROOT / 'scripts/bootstrap-server.sh').read_text()
        result = subprocess.run(['/bin/bash', '-s', '--', '--version', VERSION, '--non-interactive', '--install-deps'],
                                cwd=self.path, env=self.env, input=source[:-100], capture_output=True,
                                text=True, start_new_session=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.json_lines(self.system_log), [])
        self.assertEqual(self.json_lines(self.curl_log), [])
        self.assert_installer_not_run()

    def test_duplicate_and_symlink_archive_members_are_rejected(self):
        for kind in ('duplicate', 'symlink'):
            with self.subTest(kind=kind):
                self.pack(**{kind: 'install-server-docker.sh'})
                result = self.run_bootstrap()
                self.assertNotEqual(result.returncode, 0)
                self.assert_installer_not_run()

    def test_automation_arguments_are_forwarded_without_shell_interpretation(self):
        certificate, key = self.path / 'certificate.pem', self.path / 'key.pem'
        certificate.write_text('fixture-certificate')
        key.write_text('fixture-private-key')
        result = self.run_bootstrap('--relay-endpoint', 'tls://relay.example.test:18081',
                                    '--tls-cert', str(certificate), '--tls-key', str(key),
                                    '--control-port', '28080', '--metrics-port', '28082',
                                    '--wait-timeout', '120', '--no-start')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        arguments = json.loads(self.installer_log.read_text())
        for option, value in (('--dir', str(self.target)), ('--relay-endpoint', 'tls://relay.example.test:18081'),
                              ('--tls-cert', str(certificate)), ('--tls-key', str(key)), ('--wait-timeout', '120')):
            self.assertEqual(arguments[arguments.index(option) + 1], value)
        for option, value in (('--control-port', '28080'), ('--metrics-port', '28082')):
            self.assertEqual(arguments[arguments.index(option) + 1], value)
        self.assertNotIn('fixture-private-key', result.stdout + result.stderr)

    def test_downloaded_installer_failure_is_propagated(self):
        self.env['BOOTSTRAP_INSTALLER_EXIT'] = '7'
        result = self.run_bootstrap()
        self.assertEqual(result.returncode, 7, result.stdout + result.stderr)

    def test_verified_temporary_bundle_is_removed_after_installer_returns(self):
        result = self.run_bootstrap('--no-start')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        directory = Path((self.path / 'executed-package-dir').read_text().strip())
        self.assertFalse(directory.exists())

    def test_missing_docker_in_automation_requires_explicit_dependency_installation(self):
        (self.bin / 'docker').unlink()
        result = self.run_bootstrap()
        self.assertNotEqual(result.returncode, 0)
        self.assert_installer_not_run()
        self.assertFalse(any(call[0] in ('apt-get', 'dnf', 'install', 'systemctl') for call in self.json_lines(self.system_log)))

    def test_authorized_fresh_ubuntu_installs_official_docker_packages_and_compose(self):
        self.simulate_fresh_docker_host()
        result = self.run_bootstrap('--install-deps', '--no-start')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        calls = self.json_lines(self.system_log)
        installs = [call for call in calls if call[0] == 'apt-get' and 'install' in call]
        packages = [value for call in installs for value in call]
        self.assertIn('docker-ce', packages)
        self.assertIn('docker-compose-plugin', packages)
        self.assertTrue(any('download.docker.com' in url for url in self.json_lines(self.curl_log)))
        self.assertTrue(any(call[0] == 'systemctl' and 'docker' in call for call in calls))
        self.assertTrue(self.installer_log.exists())

    def test_os_release_is_parsed_as_data_without_executing_its_shell_contents(self):
        marker = self.path / 'os-release-executed'
        self.os_release.write_text(f'touch {marker}\nID=ubuntu\nVERSION_ID="24.04"\nVERSION_CODENAME=noble\n')
        self.simulate_fresh_docker_host()
        result = self.run_bootstrap('--install-deps', '--no-start')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(marker.exists())

    def assert_compose_only_repair(self, problem):
        self.env[problem] = '1'
        result = self.run_bootstrap('--install-deps', '--no-start')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        calls = self.json_lines(self.system_log)
        packages = [value for call in calls if call[0] == 'apt-get' and 'install' in call for value in call]
        self.assertIn('docker-compose-plugin', packages)
        for package in ('docker-ce', 'docker-ce-cli', 'containerd.io', 'docker-buildx-plugin'):
            self.assertNotIn(package, packages)
        self.assertFalse(any(call[0] == 'systemctl' and 'enable' in call for call in calls))

    def test_missing_compose_plugin_is_installed_without_replacing_the_existing_engine(self):
        self.assert_compose_only_repair('BOOTSTRAP_NO_COMPOSE')

    def test_old_compose_plugin_is_upgraded_without_replacing_the_existing_engine(self):
        self.assert_compose_only_repair('BOOTSTRAP_OLD_COMPOSE')

    @unittest.skipUnless(os.name == 'posix', 'a real controlling terminal requires POSIX')
    def test_interactive_fresh_host_can_confirm_missing_dependencies_and_then_select_release(self):
        self.simulate_fresh_docker_host()
        code, output = self.run_piped_pty(steps=[('请选择 [', '1'), ('请选择版本编号', '1')])
        self.assertEqual(code, 0, output)
        self.assertTrue(self.installer_log.exists())
        calls = self.json_lines(self.system_log)
        self.assertTrue(any(call[0] == 'apt-get' and 'docker-ce' in call for call in calls))
        self.assertIn('--interactive', json.loads(self.installer_log.read_text()))

    def test_existing_docker_can_be_reused_on_other_linux_distributions(self):
        self.os_release.write_text('ID=fedora\nVERSION_ID="41"\n')
        result = self.run_bootstrap('--no-start')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(any(call[0] in ('apt-get', 'dnf') for call in self.json_lines(self.system_log)))

    def real_installer_fixture(self):
        import test_docker_installer as docker_tests

        docker = docker_tests.DockerInstallerTests('test_dry_run_does_not_contact_docker_or_create_the_deployment')
        docker.setUp()
        self.addCleanup(docker.doCleanups)
        shutil.copyfile(docker.bin / 'docker', self.bin / 'docker')
        (self.bin / 'docker').chmod(0o755)
        self.env.update({key: value for key, value in docker.env.items() if key.startswith('DOCKER_FIXTURE_')})
        self.members['install-server-docker.sh'] = (ROOT / 'scripts/install-server-docker.sh').read_bytes()
        self.members['compose.production.yml'] = (ROOT / 'deploy/selfhost/compose.production.yml').read_bytes()
        self.pack()
        return docker

    def real_native_installer_fixture(self):
        import test_installer as native_tests

        native = native_tests.InstallerTests('test_standalone_dry_run_verifies_package_without_running_or_installing_it')
        native.setUp()
        self.addCleanup(native.doCleanups)
        self.native_members = dict(native.members)
        self.native_members['install-server.sh'] = (ROOT / 'scripts/install-server.sh').read_bytes()
        self.native_metadata = dict(version=VERSION, commit=native_tests.COMMIT, arch='amd64')
        self.pack_native()
        self.env['INSTALL_CALLS'] = str(native.calls)
        self.executable(self.bin / 'sleep', '#!/bin/sh\nexit 0\n')
        return native

    def test_verified_release_bundle_runs_the_real_installer_through_compose_health_wait(self):
        docker = self.real_installer_fixture()
        result = self.run_bootstrap('--dev-localhost')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue((self.target / 'config/control.env').is_file())
        self.assertTrue((self.target / 'config/data').is_dir())
        settings = (self.target / '.env').read_text()
        self.assertIn(f'P2WLAN_IMAGE={IMAGE}', settings)
        self.assertIn(f'P2WLAN_COMMIT={COMMIT}', settings)
        self.assertIn(f'P2WLAN_CONFIG_DIR={(self.target / "config").resolve()}', settings)
        calls = docker.calls()
        self.assertTrue(any(call['args'] == ['pull', IMAGE] for call in calls))
        start = next(call['args'] for call in calls if call['args'][:1] == ['compose'] and 'up' in call['args'] and '--help' not in call['args'])
        self.assertIn('--wait', start)
        self.assertIn('--no-build', start)
        self.assertNotIn('fixture-private-token', result.stdout + result.stderr)
        self.assertFalse(self.installer_log.exists())

    @unittest.skipUnless(os.name == 'posix', 'a real controlling terminal requires POSIX')
    def test_curl_pipe_keeps_the_terminal_usable_through_the_real_deployment_wizard(self):
        docker = self.real_installer_fixture()
        def not_deployed(*_):
            self.assertFalse(self.target.exists())
            self.assertFalse(any(call['args'][:1] in (['pull'], ['run']) for call in docker.calls()))
        code, output = self.run_piped_pty(steps=[
            ('请选择版本编号', '1'), ('部署目录', str(self.target)), ('部署模式', '2'),
            ('Relay主机', ''), ('Relay端口', ''),
            ('Control端口', ''), ('metrics端口', ''), ('Relay绑定IP', ''),
            ('启动方式', '1'), ('确认部署', '1'),
        ], before_reply=not_deployed)
        self.assertEqual(code, 0, output)
        self.assertTrue((self.target / 'config/control.env').is_file())
        self.assertIn('/opt/p2wlan-docker', output)
        self.assertIn(f'P2WLAN_IMAGE={IMAGE}', (self.target / '.env').read_text())
        self.assertTrue(any(call['args'][:1] == ['compose'] and 'up' in call['args'] and '--help' not in call['args'] for call in docker.calls()))
        self.assertNotIn('fixture-private-token', output)

    def test_bootstrap_upgrade_applies_the_selected_new_image_and_preserves_configuration_and_database(self):
        docker = self.real_installer_fixture()
        first = self.run_bootstrap('--dev-localhost')
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        config = self.target / 'config'
        (config / 'data/p2pnet.db').write_bytes(b'fixture-existing-database')
        before = {str(path.relative_to(config)): path.read_bytes() for path in config.rglob('*') if path.is_file()}
        new_version = 'server-v9.9.10'
        new_commit = 'e' * 40
        new_image = 'registry.example.test/p2wlan-server@sha256:' + 'd' * 64
        executable = self.bin / 'docker'
        executable.write_text(executable.read_text().replace(VERSION, new_version))
        self.env.update(BOOTSTRAP_EXPECTED_VERSION=new_version, DOCKER_FIXTURE_IMAGE=new_image,
                        DOCKER_FIXTURE_COMMIT=new_commit)
        self.manifest.update(version=new_version, source_sha=new_commit, image=new_image,
                             digest=new_image.split('@')[1])
        self.pack()
        second = self.run_bootstrap(version=new_version)
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        settings = (self.target / '.env').read_text()
        self.assertIn(f'P2WLAN_IMAGE={new_image}', settings)
        self.assertIn(f'P2WLAN_VERSION={new_version}', settings)
        self.assertIn(f'P2WLAN_COMMIT={new_commit}', settings)
        after = {str(path.relative_to(config)): path.read_bytes() for path in config.rglob('*') if path.is_file()}
        self.assertEqual(before, after)
        calls = docker.calls()
        self.assertTrue(any(call['args'] == ['pull', new_image] for call in calls))
        self.assertEqual(sum(call['args'][:1] == ['run'] and '--output' in call['args'] for call in calls), 1)

    @unittest.skipUnless(os.name == 'posix', 'a real controlling terminal requires POSIX')
    def test_no_argument_curl_pipe_bootstrap_selects_a_complete_server_release(self):
        code, output = self.run_piped_pty()
        self.assertEqual(code, 0, output)
        arguments = json.loads(self.installer_log.read_text())
        self.assertIn('--interactive', arguments)
        urls = self.json_lines(self.curl_log)
        self.assertTrue(any('api.github.com' in url for url in urls))
        downloads = [url for url in urls if '/releases/download/' in url]
        self.assertTrue(downloads)
        self.assertTrue(all(f'/releases/download/{VERSION}/' in url for url in downloads))
        self.assertFalse(any('/releases/latest' in url for url in urls))
        self.assertIn(f'1) {VERSION}', output)

    @unittest.skipUnless(os.name == 'posix', 'a real controlling terminal requires POSIX')
    def test_version_menu_can_choose_an_older_numbered_release(self):
        selected = 'server-v9.9.8'
        self.env['BOOTSTRAP_EXPECTED_VERSION'] = selected
        self.manifest['version'] = selected
        self.pack()
        code, output = self.run_piped_pty(steps=[('请选择版本编号', '2')])
        self.assertEqual(code, 0, output)
        self.assertIn(f'1) {VERSION}', output)
        self.assertIn(f'2) {selected}', output)
        downloads = [url for url in self.json_lines(self.curl_log) if '/releases/download/' in url]
        self.assertTrue(downloads)
        self.assertTrue(all(f'/releases/download/{selected}/' in url for url in downloads))

    @unittest.skipUnless(os.name == 'posix', 'a real controlling terminal requires POSIX')
    def test_version_menu_retries_bad_numbers_without_repeating_release_discovery(self):
        code, output = self.run_piped_pty(steps=[
            ('请选择版本编号', '99'), ('请选择版本编号', 'invalid'), ('请选择版本编号', '1'),
        ])
        self.assertEqual(code, 0, output)
        api = [url for url in self.json_lines(self.curl_log) if 'api.github.com' in url]
        self.assertEqual(len(api), 1)
        self.assertTrue(self.installer_log.exists())

    @unittest.skipUnless(os.name == 'posix', 'a real controlling terminal requires POSIX')
    def test_version_menu_manual_entry_retries_a_client_or_latest_tag(self):
        code, output = self.run_piped_pty(steps=[
            ('请选择版本编号', 'm'), ('请输入固定版本', 'latest'),
            ('请选择版本编号', 'm'), ('请输入固定版本', VERSION),
        ])
        self.assertEqual(code, 0, output)
        downloads = [url for url in self.json_lines(self.curl_log) if '/releases/download/' in url]
        self.assertTrue(downloads)
        self.assertTrue(all(f'/releases/download/{VERSION}/' in url for url in downloads))

    @unittest.skipUnless(os.name == 'posix', 'a real controlling terminal requires POSIX')
    def test_version_menu_cancel_does_not_download_or_execute_a_release_bundle(self):
        code, output = self.run_piped_pty(steps=[('请选择版本编号', '0')])
        self.assertEqual(code, 0, output)
        self.assert_installer_not_run()
        self.assertFalse(any('/releases/download/' in url for url in self.json_lines(self.curl_log)))

    @unittest.skipUnless(os.name == 'posix', 'a real controlling terminal requires POSIX')
    def test_explicit_version_in_interactive_mode_skips_the_version_menu(self):
        code, output = self.run_piped_pty('--interactive', '--version', VERSION, steps=[])
        self.assertEqual(code, 0, output)
        self.assertIn(VERSION, output)
        self.assertNotIn('请选择版本编号', output)
        self.assertFalse(any('api.github.com' in url for url in self.json_lines(self.curl_log)))

    @unittest.skipUnless(os.name == 'posix', 'a real controlling terminal requires POSIX')
    def test_dependency_menu_cancel_does_not_install_packages_or_download_a_release(self):
        self.simulate_fresh_docker_host()
        code, output = self.run_piped_pty(steps=[('请选择 [', '0')])
        self.assertEqual(code, 0, output)
        self.assert_installer_not_run()
        self.assertFalse(any(call[0] in ('apt-get', 'install', 'systemctl') for call in self.json_lines(self.system_log)))
        self.assertEqual(self.json_lines(self.curl_log), [])

    @unittest.skipUnless(os.name == 'posix', 'a real controlling terminal requires POSIX')
    def test_installation_method_cancel_precedes_all_dependencies_downloads_and_temporary_files(self):
        code, output = self.run_piped_pty(method=None, steps=[('安装方式', '0')])
        self.assertEqual(code, 0, output)
        self.assertEqual(self.json_lines(self.system_log), [])
        self.assertEqual(self.json_lines(self.curl_log), [])
        self.assert_installer_not_run()

    @unittest.skipUnless(os.name == 'posix', 'a real controlling terminal requires POSIX')
    def test_installation_method_menu_retries_and_can_continue_with_docker(self):
        code, output = self.run_piped_pty(method=None, steps=[
            ('安装方式', '99'), ('安装方式', '2'), ('请选择版本编号', '1'),
        ])
        self.assertEqual(code, 0, output)
        self.assertTrue(self.installer_log.exists())

    def test_native_download_and_handoff_never_inspects_or_installs_docker(self):
        (self.bin / 'docker').unlink()
        result = self.run_bootstrap('--method', 'native', '--root', str(self.path / 'native-root'),
                                    '--config-dir', str(self.path / 'native-config'),
                                    '--data-dir', str(self.path / 'native-data'), '--no-start', include_dir=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        arguments = json.loads(self.installer_log.read_text())
        self.assertEqual(arguments[arguments.index('--version') + 1], VERSION)
        self.assertIn('--archive', arguments)
        self.assertIn('--non-interactive', arguments)
        self.assertIn('--no-start', arguments)
        self.assertNotIn('--manifest', arguments)
        self.assertFalse(any(call[0] in ('docker', 'apt-get', 'dnf') for call in self.json_lines(self.system_log)))
        urls = self.json_lines(self.curl_log)
        self.assertEqual(len(urls), 2)
        self.assertTrue(all(NATIVE_ARCHIVE in url for url in urls))

    def test_native_only_installs_its_missing_prerequisites_without_a_docker_repository(self):
        (self.bin / 'docker').unlink()
        (self.bin / 'python3').unlink()
        result = self.run_bootstrap('--method', 'native', '--install-deps', '--no-start', include_dir=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        calls = self.json_lines(self.system_log)
        packages = [value for call in calls if call[0] == 'apt-get' and 'install' in call for value in call]
        self.assertIn('python3', packages)
        self.assertFalse(any('docker' in value for value in packages))
        self.assertFalse(any(call[0] == 'docker' for call in calls))
        self.assertFalse(any('download.docker.com' in url for url in self.json_lines(self.curl_log)))

    def test_native_archive_requires_correct_architecture_binary_checksums_and_regular_members(self):
        (self.downloads / (NATIVE_ARCHIVE + '.sha256')).write_text(f'{"0" * 64}  {NATIVE_ARCHIVE}\n')
        result = self.run_bootstrap('--method', 'native', '--dry-run', include_dir=False)
        self.assertNotEqual(result.returncode, 0)
        self.assert_installer_not_run()
        self.native_metadata['arch'] = 'arm64'
        self.pack_native()
        result = self.run_bootstrap('--method', 'native', '--dry-run', include_dir=False)
        self.assertNotEqual(result.returncode, 0)
        self.assert_installer_not_run()
        self.native_metadata['arch'] = 'amd64'
        for options in ({'bad_inner': True}, {'duplicate': 'install-server.sh'}, {'symlink': 'install-server.sh'}):
            with self.subTest(options=options):
                self.pack_native(**options)
                result = self.run_bootstrap('--method', 'native', '--dry-run', include_dir=False)
                self.assertNotEqual(result.returncode, 0)
                self.assert_installer_not_run()

    def test_method_specific_arguments_are_rejected_before_runtime_or_package_actions(self):
        for arguments in (
            ('--method', 'native', '--dir', str(self.target)),
            ('--method', 'native', '--publish-host', '127.0.0.1'),
            ('--method', 'native', '--wait-timeout', '120'),
            ('--method', 'docker', '--root', str(self.path / 'native-root')),
            ('--method', 'docker', '--config-dir', str(self.path / 'native-config')),
            ('--method', 'docker', '--data-dir', str(self.path / 'native-data')),
            ('--method', 'docker', '--start'),
        ):
            with self.subTest(arguments=arguments):
                result = self.run_bootstrap(*arguments, include_dir=False)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.json_lines(self.curl_log), [])
                self.assertEqual(self.json_lines(self.system_log), [])
                self.assert_installer_not_run()

    def test_native_bootstrap_runs_the_real_installer_and_manager_without_a_second_download(self):
        native = self.real_native_installer_fixture()
        (self.bin / 'docker').unlink()
        program, config, data = (self.path / name for name in ('native-root', 'native-config', 'native-data'))
        result = self.run_bootstrap('--method', 'native', '--root', str(program),
                                    '--config-dir', str(config), '--data-dir', str(data),
                                    '--dev-localhost', '--start', include_dir=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue((config / 'control.env').exists())
        self.assertIn(f'DB_PATH={data}/p2pnet.db', (config / 'control.env').read_text())
        calls = native.calls.read_text().splitlines()
        self.assertTrue(any(call.startswith('manager init ') for call in calls))
        self.assertTrue(any(call.startswith('manager update ') and '--no-restart' in call for call in calls))
        self.assertTrue(any(call.startswith('manager start ') for call in calls))
        self.assertTrue(any(call.startswith('manager check ') for call in calls))
        urls = self.json_lines(self.curl_log)
        self.assertEqual(len(urls), 2)
        self.assertTrue(all(NATIVE_ARCHIVE in url for url in urls))
        self.assertFalse(any(call[0] == 'docker' for call in self.json_lines(self.system_log)))

    @unittest.skipUnless(os.name == 'posix', 'a real controlling terminal requires POSIX')
    def test_native_release_menu_filters_by_selected_method_and_host_architecture(self):
        (self.bin / 'docker').unlink()
        self.releases([
            self.release('server-v9.9.11', published='2026-11-06T00:00:00Z',
                         names=('p2wlan-server-linux-arm64.tar.gz', 'p2wlan-server-linux-arm64.tar.gz.sha256')),
            self.release('server-v9.9.10', published='2026-11-05T00:00:00Z', names=ASSETS),
            self.release(VERSION, published='2026-11-03T00:00:00Z', names=NATIVE_ASSETS),
            self.release('server-v9.9.8', published='2026-11-02T00:00:00Z', names=NATIVE_ASSETS),
        ])
        code, output = self.run_piped_pty('--interactive', '--root', str(self.path / 'native-root'),
            '--config-dir', str(self.path / 'native-config'), '--data-dir', str(self.path / 'native-data'),
            '--no-start', method='native', steps=[('请选择版本编号', '1')])
        self.assertEqual(code, 0, output)
        self.assertIn(f'1) {VERSION}', output)
        self.assertNotIn('1) server-v9.9.10', output)
        arguments = json.loads(self.installer_log.read_text())
        self.assertEqual(arguments[arguments.index('--version') + 1], VERSION)
        self.assertFalse(any(call[0] == 'docker' for call in self.json_lines(self.system_log)))
        downloads = [url for url in self.json_lines(self.curl_log) if '/releases/download/' in url]
        self.assertTrue(all(NATIVE_ARCHIVE in url for url in downloads))

    def test_legacy_native_installer_without_wizard_capabilities_is_not_executed(self):
        self.native_members['install-server.sh'] = b'#!/bin/sh\n[ "${1:-}" = --help ] && echo legacy-helper\n'
        self.pack_native()
        result = self.run_bootstrap('--method', 'native', '--no-start', include_dir=False)
        self.assertNotEqual(result.returncode, 0)
        self.assert_installer_not_run()
        self.assertFalse(any(call[0] == 'docker' for call in self.json_lines(self.system_log)))

    @unittest.skipUnless(os.name == 'posix', 'a real controlling terminal requires POSIX')
    def test_no_argument_curl_pipe_can_install_native_through_the_complete_real_wizard(self):
        native = self.real_native_installer_fixture()
        (self.bin / 'docker').unlink()
        self.releases([self.release(VERSION, published='2026-11-03T00:00:00Z', names=NATIVE_ASSETS)])
        program, config, data = (self.path / name for name in ('native-root', 'native-config', 'native-data'))
        def nothing_published(*_):
            for path in (program, config, data):
                self.assertFalse(path.exists())
            self.assertFalse(native.calls.exists())
            self.assertFalse(any(call[0] == 'docker' for call in self.json_lines(self.system_log)))
        code, output = self.run_piped_pty(method='native', steps=[
            ('请选择版本编号', '1'), ('程序目录', str(program)), ('配置目录', str(config)), ('数据目录', str(data)),
            ('部署模式', '2'), ('Relay主机', 'localhost'), ('Relay端口', ''),
            ('Control端口', '28080'), ('metrics端口', '28082'),
            ('启动方式', '1'), ('确认部署', '1'),
        ], before_reply=nothing_published)
        self.assertEqual(code, 0, output)
        self.assertIn(f'DB_PATH={data}/p2pnet.db', (config / 'control.env').read_text())
        self.assertIn('PORT=28080', (config / 'control.env').read_text())
        calls = native.calls.read_text().splitlines()
        self.assertTrue(any(call.startswith('manager start ') for call in calls))
        self.assertTrue(any(call.startswith('manager check ') for call in calls))
        downloads = [url for url in self.json_lines(self.curl_log) if '/releases/download/' in url]
        self.assertEqual(len(downloads), 2)
        self.assertTrue(all(NATIVE_ARCHIVE in url for url in downloads))
        self.assertNotIn('fixture-private-value', output)

    @unittest.skipUnless(os.name == 'posix', 'a real controlling terminal requires POSIX')
    def test_discovery_skips_drafts_prereleases_incomplete_and_duplicate_assets(self):
        not_uploaded = self.release('server-v9.9.14', published='2026-11-06T00:00:00Z')
        not_uploaded['assets'][0]['state'] = 'new'
        self.releases([
            self.release('server-v9.9.15', published='2026-11-06T03:00:00Z', draft=True),
            self.release('server-v9.9.16', published='2026-11-06T02:00:00Z', prerelease=True),
            self.release('server-v9.9.17', published='2026-11-06T01:00:00Z', names=ASSETS + (ASSETS[0],)),
            not_uploaded,
            self.release('server-v9.9.8', published='2026-11-02T00:00:00Z'),
            self.release(VERSION, published='2026-11-03T00:00:00Z'),
        ])
        code, output = self.run_piped_pty('--interactive', '--dry-run')
        self.assertEqual(code, 0, output)
        downloads = [url for url in self.json_lines(self.curl_log) if '/releases/download/' in url]
        self.assertTrue(downloads)
        self.assertTrue(all(f'/releases/download/{VERSION}/' in url for url in downloads))
        self.assert_installer_not_run()

    @unittest.skipUnless(os.name == 'posix', 'a real controlling terminal requires POSIX')
    def test_discovery_follows_bounded_release_pages_instead_of_client_latest(self):
        clients = [self.release(f'v99.0.{index}', published='2026-11-05T00:00:00Z') for index in range(100)]
        self.releases(clients)
        self.releases([self.release(VERSION, published='2026-11-03T00:00:00Z')], page=2)
        code, output = self.run_piped_pty('--interactive', '--dry-run')
        self.assertEqual(code, 0, output)
        api = [url for url in self.json_lines(self.curl_log) if 'api.github.com' in url]
        self.assertTrue(any('page=2' in url for url in api))
        self.assertLessEqual(len(api), 5)
        self.assert_installer_not_run()

    def test_pipe_without_a_terminal_fails_with_automation_guidance(self):
        result = self.run_bootstrap(version=None, headless=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('--non-interactive', result.stdout + result.stderr)
        self.assert_installer_not_run()


if __name__ == '__main__':
    unittest.main()
