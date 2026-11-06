"""Exercise the released installer without network access or host mutations."""
import hashlib
import io
import os
from pathlib import Path
import select
import signal
import shutil
import stat
import subprocess
import tarfile
import tempfile
import time
import unittest

if os.name == 'posix':
    import pty


ROOT = Path(__file__).resolve().parents[2]
VERSION = 'server-v9.9.9'
COMMIT = 'a' * 40


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        self.bin = self.path / 'bin'
        self.bin.mkdir()
        self.calls = self.path / 'calls'
        self.root = self.path / 'root'
        self.config = self.path / 'config'
        self.data = self.path / 'data'
        self.archive = self.path / 'p2wlan-server-linux-amd64.tar.gz'
        self.script = self.path / 'install-server.sh'
        self.executable(self.bin / 'id', '#!/bin/sh\n[ "$1" = -u ] && echo 0\n')
        self.executable(self.bin / 'uname', '#!/bin/sh\ncase "$1" in -m) echo x86_64;; *) echo Linux;; esac\n')
        self.executable(self.bin / 'systemctl', '#!/bin/sh\nexit 0\n')
        self.executable(self.bin / 'chown', '#!/bin/sh\nexit 0\n')
        self.executable(self.bin / 'useradd', '#!/bin/sh\nexit 0\n')
        # Never let a fixture reach the network, even when validation regresses.
        self.executable(self.bin / 'curl', '#!/bin/sh\necho unexpected-network >> "$INSTALL_CALLS"\nexit 90\n')
        real_install = shutil.which('install')
        self.assertIsNotNone(real_install)
        self.executable(self.bin / 'install', '''#!/bin/bash
for value in "$@"; do
  case "$value" in /usr/local/bin|/usr/local/bin/*) exit 0;; esac
done
exec "$REAL_INSTALL" "$@"
''')
        self.executable(self.bin / 'sleep', '#!/bin/sh\nexit 0\n')
        systemd = self.path / 'systemd'
        systemd.mkdir()
        self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ['PATH'],
                        INSTALL_CALLS=str(self.calls), REAL_INSTALL=real_install,
                        P2WLAN_SYSTEMD_DIR=str(systemd))
        self.env.pop('P2WLAN_SERVER_VERSION', None)
        self.env.pop('P2WLAN_REPO', None)
        self.members = {
            name: f'#!/bin/sh\necho "{name} {VERSION} ({COMMIT})"\n'.encode()
            for name in ('p2wlan-control', 'p2wlan-relay', 'p2wlan-db')
        }
        self.members['p2wlan-server'] = b'''#!/bin/bash
set -eu
if [ "$1" = --help ]; then echo 'update --no-restart'; exit 0; fi
printf 'manager %s\\n' "$*" >> "$INSTALL_CALLS"
if [ "$1" = init ]; then
  test -f "$P2WLAN_SERVER_CONFIG/control.env"
  test -f "$P2WLAN_SERVER_CONFIG/relay.env"
fi
if [ "$1" = update ] && [ -n "${SNAPSHOT_SOURCE:-}" ]; then
  shift
  archive=
  while [ "$#" -gt 0 ]; do
    if [ "$1" = --archive ]; then archive=$2; shift 2; else shift; fi
  done
  test "$archive" != "$SNAPSHOT_SOURCE"
  cmp "$archive" "$SNAPSHOT_EXPECTED"
  printf 'snapshot-verified\\n' >> "$INSTALL_CALLS"
  exit 0
fi
if [ "$1" = check ] && [ "${FAIL_HEALTH:-0}" = 1 ]; then exit 1; fi
'''
        self.members['p2wlan-config'] = b'''#!/bin/bash
set -eu
if [ "$1" = --help ]; then echo '-config-dir -data-dir'; exit 0; fi
if [ "${FAIL_CONFIG:-0}" = 1 ]; then exit 1; fi
output= config= data= endpoint=tls://localhost:18081 control=18080 metrics=18082
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output) output=$2; shift 2;;
    --config-dir) config=$2; shift 2;;
    --data-dir) data=$2; shift 2;;
    --relay-endpoint) endpoint=$2; shift 2;;
    --control-port) control=$2; shift 2;;
    --metrics-port) metrics=$2; shift 2;;
    --dev-localhost) shift;;
    *) shift 2;;
  esac
done
if [ -n "${MUTATE_SOURCE:-}" ]; then printf replaced > "$MUTATE_SOURCE"; fi
printf 'generate %s %s %s %s %s\\n' "$config" "$data" "$control" "$metrics" "$endpoint" >> "$INSTALL_CALLS"
mkdir "$output"
printf 'DB_PATH=%s/p2pnet.db\\nCONTROL_ADMIN_TOKEN=fixture-private-value\\nPORT=%s\\nCONTROL_BIND=127.0.0.1:%s\\n' "$data" "$control" "$control" > "$output/control.env"
printf 'RELAY_TLS_CERT=%s/tls.crt\\nRELAY_BIND=:%s\\nRELAY_METRICS_BIND=127.0.0.1:%s\\n' "$config" "${endpoint##*:}" "$metrics" > "$output/relay.env"
printf fixture-cert > "$output/tls.crt"
printf fixture-key > "$output/tls.key"
'''
        self.members.update({
            'install-server.sh': b'#!/bin/sh\nexit 0\n',
            'deploy-server.sh': b'#!/bin/sh\nexit 0\n',
            'BUILD-METADATA.txt': f'version={VERSION}\ncommit={COMMIT}\narch=amd64\n'.encode(),
        })
        self.pack()

    @staticmethod
    def executable(path, content):
        if path.is_symlink():
            path.unlink()
        path.write_text(content)
        path.chmod(0o755)

    def pack(self, *, bad_inner=False, duplicate=None, symlink=None):
        sums = []
        for name in ('p2wlan-control', 'p2wlan-relay', 'p2wlan-config', 'p2wlan-db'):
            digest = hashlib.sha256(self.members[name]).hexdigest()
            if bad_inner and name == 'p2wlan-control':
                digest = '0' * 64
            sums.append(f'{digest}  {name}\n')
        self.members['SHA256SUMS'] = ''.join(sums).encode()
        with tarfile.open(self.archive, 'w:gz') as archive:
            for name, data in self.members.items():
                member = tarfile.TarInfo(name)
                member.size = len(data)
                member.mode = 0o755 if name not in ('BUILD-METADATA.txt', 'SHA256SUMS') else 0o644
                if name == symlink:
                    member.type = tarfile.SYMTYPE
                    member.linkname = '/outside/fixture'
                    member.size = 0
                    archive.addfile(member)
                else:
                    archive.addfile(member, io.BytesIO(data))
                if name == duplicate:
                    archive.addfile(member, io.BytesIO(data))
        digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        Path(str(self.archive) + '.sha256').write_text(f'{digest}  {self.archive.name}\n')

    def run_installer(self, *args, archive=True):
        # Execute a standalone copy: no adjacent manager or generator is present.
        shutil.copyfile(ROOT / 'scripts/install-server.sh', self.script)
        command = ['bash', str(self.script), '--non-interactive']
        if archive:
            command += ['--archive', str(self.archive)]
        command += ['--root', str(self.root), '--config-dir', str(self.config), '--data-dir', str(self.data)]
        command += list(args)
        return subprocess.run(command, cwd=self.path, env=self.env, input='',
                              capture_output=True, text=True, timeout=30, start_new_session=True)

    def assert_no_mutation(self):
        self.assertFalse(self.root.exists())
        self.assertFalse(self.config.exists())
        self.assertFalse(self.data.exists())
        self.assertFalse(self.calls.exists())

    def run_interactive(self, steps, *args, include_paths=True, no_arguments=False, env=None, before_reply=None):
        shutil.copyfile(ROOT / 'scripts/install-server.sh', self.script)
        command = ['bash', str(self.script)]
        if not no_arguments:
            command += ['--interactive', '--archive', str(self.archive), '--version', VERSION]
            if include_paths:
                command += ['--root', str(self.root), '--config-dir', str(self.config), '--data-dir', str(self.data)]
            command += list(args)
        pid, terminal = pty.fork()
        if pid == 0:
            os.chdir(self.path)
            os.execve('/bin/bash', command, env or self.env)
        transcript, status, cursor = bytearray(), None, 0
        pending = list(steps)
        try:
            deadline = time.monotonic() + 40
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

    def test_standalone_dry_run_verifies_package_without_running_or_installing_it(self):
        result = self.run_installer('--dry-run')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(VERSION, result.stdout)
        self.assert_no_mutation()

    def test_no_arguments_without_a_terminal_fails_with_headless_guidance(self):
        result = subprocess.run(['bash', str(ROOT / 'scripts/install-server.sh')], cwd=self.path,
                                env=self.env, input='', capture_output=True, text=True,
                                timeout=5, start_new_session=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('--non-interactive', result.stderr + result.stdout)
        self.assert_no_mutation()

    def test_unsafe_versions_are_rejected_before_any_download(self):
        for version in ('latest', 'server-v1/other', 'server-v1?download=1', 'server-v1\nextra', 'server-v'):
            with self.subTest(version=version):
                result = self.run_installer('--version', version, '--dry-run', archive=False)
                self.assertNotEqual(result.returncode, 0)
                self.assert_no_mutation()

    def test_relative_or_systemd_special_paths_are_rejected_before_mutation(self):
        for path in ('relative', '/tmp/fixture path', '/tmp/fixture%u', '/tmp/fixture\nextra'):
            with self.subTest(path=path):
                result = self.run_installer('--root', path, '--dry-run')
                self.assertNotEqual(result.returncode, 0)
                self.assert_no_mutation()

    def test_outer_checksum_mismatch_is_rejected(self):
        Path(str(self.archive) + '.sha256').write_text(f'{"0" * 64}  {self.archive.name}\n')
        result = self.run_installer('--dry-run')
        self.assertNotEqual(result.returncode, 0)
        self.assert_no_mutation()

    def test_checksum_file_cannot_redirect_verification_to_another_file(self):
        other = self.path / 'other.tar.gz'
        other.write_bytes(b'not-the-requested-package')
        digest = hashlib.sha256(other.read_bytes()).hexdigest()
        Path(str(self.archive) + '.sha256').write_text(f'{digest}  {other.name}\n')
        result = self.run_installer('--dry-run')
        self.assertNotEqual(result.returncode, 0)
        self.assert_no_mutation()

    def test_inner_checksum_mismatch_is_rejected_even_with_valid_outer_checksum(self):
        self.pack(bad_inner=True)
        result = self.run_installer('--dry-run')
        self.assertNotEqual(result.returncode, 0)
        self.assert_no_mutation()

    def test_duplicate_or_symlink_members_are_rejected(self):
        for mode in ('duplicate', 'symlink'):
            with self.subTest(mode=mode):
                self.pack(**{mode: 'p2wlan-server'})
                result = self.run_installer('--dry-run')
                self.assertNotEqual(result.returncode, 0)
                self.assert_no_mutation()

    def test_metadata_must_bind_requested_version_commit_and_architecture(self):
        for metadata in (
            f'version={VERSION}\ncommit=unknown\narch=amd64\n',
            f'version={VERSION}\ncommit={COMMIT}\narch=arm64\n',
            f'version=server-v8.8.8\ncommit={COMMIT}\narch=amd64\n',
        ):
            with self.subTest(metadata=metadata):
                self.members['BUILD-METADATA.txt'] = metadata.encode()
                self.pack()
                result = self.run_installer('--version', VERSION, '--dry-run')
                self.assertNotEqual(result.returncode, 0)
                self.assert_no_mutation()

    def test_duplicate_metadata_cannot_disagree_with_executable_identity(self):
        self.members['BUILD-METADATA.txt'] = (
            f'version={VERSION}\ncommit=unknown\ncommit={COMMIT}\narch=amd64\n'.encode()
        )
        for name in ('p2wlan-control', 'p2wlan-relay'):
            self.members[name] = f'#!/bin/sh\necho "{name} {VERSION} (unknown)"\n'.encode()
        self.pack()
        result = self.run_installer('--dev-localhost', '--no-start')
        self.assertNotEqual(result.returncode, 0)
        self.assert_no_mutation()

    def test_first_install_generates_configuration_before_initializing_and_starting(self):
        result = self.run_installer('--dev-localhost', '--start')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        calls = self.calls.read_text().splitlines()
        generate = next(i for i, call in enumerate(calls) if call.startswith('generate '))
        initialize = next(i for i, call in enumerate(calls) if call.startswith('manager init '))
        update = next(i for i, call in enumerate(calls) if call.startswith('manager update '))
        start = next(i for i, call in enumerate(calls) if call.startswith('manager start '))
        check = next(i for i, call in enumerate(calls) if call.startswith('manager check '))
        self.assertLess(generate, initialize)
        self.assertLess(initialize, update)
        self.assertLess(update, start)
        self.assertLess(start, check)
        self.assertIn('--no-restart', calls[update])
        self.assertIn('--service all', calls[update])
        self.assertIn(str(self.config), calls[generate])
        self.assertIn(str(self.data), calls[generate])
        self.assertIn(f'DB_PATH={self.data}/p2pnet.db', (self.config / 'control.env').read_text())
        self.assertIn(f'RELAY_TLS_CERT={self.config}/tls.crt', (self.config / 'relay.env').read_text())
        self.assertNotIn('fixture-private-value', result.stdout + result.stderr)

    def test_old_release_manager_is_rejected_before_persistent_configuration_or_units(self):
        self.members['p2wlan-server'] = b'#!/bin/sh\necho old-manager\n'
        self.pack()
        result = self.run_installer('--dev-localhost', '--start')
        self.assertNotEqual(result.returncode, 0)
        self.assert_no_mutation()

    def test_old_configuration_generator_is_rejected_before_persistent_configuration(self):
        self.members['p2wlan-config'] = b'#!/bin/sh\necho old-config\n'
        self.pack()
        result = self.run_installer('--dev-localhost', '--start')
        self.assertNotEqual(result.returncode, 0)
        self.assert_no_mutation()

    def test_binary_identity_must_match_release_metadata_before_persistent_install(self):
        self.members['p2wlan-control'] = b'#!/bin/sh\necho "p2wlan-control server-v8.8.8 (bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb)"\n'
        self.pack()
        result = self.run_installer('--dev-localhost', '--start')
        self.assertNotEqual(result.returncode, 0)
        self.assert_no_mutation()

    def test_local_archive_replacement_after_verification_cannot_change_installed_bytes(self):
        expected = self.path / 'expected-archive'
        shutil.copyfile(self.archive, expected)
        self.env.update(MUTATE_SOURCE=str(self.archive), SNAPSHOT_SOURCE=str(self.archive),
                        SNAPSHOT_EXPECTED=str(expected))
        result = self.run_installer('--dev-localhost', '--no-start')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.archive.read_bytes(), b'replaced')
        self.assertIn('snapshot-verified', self.calls.read_text())

    def test_reinstall_preserves_existing_configuration_and_does_not_regenerate_secrets(self):
        first = self.run_installer('--dev-localhost', '--no-start')
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        before = {path.name: path.read_bytes() for path in self.config.iterdir() if path.is_file()}
        second = self.run_installer('--no-start')
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        self.assertEqual(before, {path.name: path.read_bytes() for path in self.config.iterdir() if path.is_file()})
        calls = self.calls.read_text().splitlines()
        self.assertEqual(sum(call.startswith('generate ') for call in calls), 1)
        self.assertFalse(any(call.startswith('manager start ') for call in calls))
        self.assertFalse(any(call.startswith('manager check ') for call in calls))

    def test_invalid_tls_configuration_cannot_initialize_or_start_services(self):
        self.env['FAIL_CONFIG'] = '1'
        result = self.run_installer('--dev-localhost', '--start')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.calls.exists())
        self.assertFalse((self.config / 'control.env').exists())
        self.assertFalse((self.config / 'relay.env').exists())

    def test_failed_health_check_stops_after_bounded_attempts(self):
        self.env['FAIL_HEALTH'] = '1'
        result = self.run_installer('--dev-localhost', '--start')
        self.assertNotEqual(result.returncode, 0)
        calls = self.calls.read_text().splitlines()
        checks = [call for call in calls if call.startswith('manager check ')]
        self.assertGreater(len(checks), 0)
        self.assertLessEqual(len(checks), 12)

    def test_partial_existing_configuration_is_preserved_and_rejected_for_generation(self):
        self.config.mkdir()
        sentinel = b'JWT_SECRET=preserve-existing-value\n'
        (self.config / 'control.env').write_bytes(sentinel)
        result = self.run_installer('--dev-localhost', '--start')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.config / 'control.env').read_bytes(), sentinel)
        self.assertFalse(self.calls.exists())

    @unittest.skipUnless(os.name == 'posix', 'a real controlling terminal requires POSIX')
    def test_no_argument_wizard_completes_using_its_controlling_terminal(self):
        shutil.copyfile(ROOT / 'scripts/install-server.sh', self.script)
        certificate, private_key = self.path / 'certificate.pem', self.path / 'private.pem'
        certificate.write_text('fixture certificate')
        private_key.write_text('fixture private key')
        self.executable(self.bin / 'curl', '''#!/bin/bash
set -eu
output=
while [ "$#" -gt 0 ]; do
  if [ "$1" = -o ]; then output=$2; shift 2; else shift; fi
done
case "$output" in
  *.sha256) cp "$FIXTURE_ARCHIVE.sha256" "$output";;
  *) cp "$FIXTURE_ARCHIVE" "$output";;
esac
''')
        env = dict(self.env, P2WLAN_SERVER_VERSION=VERSION, P2WLAN_SERVER_ROOT=str(self.root),
                   P2WLAN_SERVER_CONFIG=str(self.config), P2WLAN_SERVER_DATA=str(self.data),
                   FIXTURE_ARCHIVE=str(self.archive))
        code, output = self.run_interactive([
            ('程序目录', ''), ('配置目录', ''), ('数据目录', ''),
            ('部署模式', '1'), ('Relay主机', 'relay.example.com'), ('Relay端口', ''),
            ('证书链路径', str(certificate)), ('私钥路径', str(private_key)),
            ('Control端口', ''), ('metrics端口', ''), ('启动方式', '2'), ('确认部署', '1'),
        ], no_arguments=True, env=env, before_reply=lambda *_: self.assert_no_mutation())
        self.assertEqual(code, 0, output)
        self.assertTrue((self.config / 'control.env').exists())
        calls = self.calls.read_text().splitlines()
        self.assertTrue(any(call.startswith('generate ') for call in calls))
        self.assertFalse(any(call.startswith('manager start ') for call in calls))
        self.assertNotIn('fixture-private-value', output)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o700)

    @unittest.skipUnless(os.name == 'posix', 'a real controlling terminal requires POSIX')
    def test_native_local_wizard_uses_custom_ports_and_starts_only_after_confirmation(self):
        code, output = self.run_interactive([
            ('部署模式', '2'), ('Relay主机', 'localhost'), ('Relay端口', '28081'),
            ('Control端口', '28080'), ('metrics端口', '28082'),
            ('启动方式', '1'), ('确认部署', '1'),
        ], before_reply=lambda *_: self.assert_no_mutation())
        self.assertEqual(code, 0, output)
        self.assertIn('PORT=28080', (self.config / 'control.env').read_text())
        self.assertIn('RELAY_BIND=:28081', (self.config / 'relay.env').read_text())
        self.assertIn('RELAY_METRICS_BIND=127.0.0.1:28082', (self.config / 'relay.env').read_text())
        calls = self.calls.read_text().splitlines()
        self.assertTrue(any(call.startswith('manager start ') for call in calls))
        self.assertTrue(any(call.startswith('manager check ') for call in calls))

    @unittest.skipUnless(os.name == 'posix', 'a real controlling terminal requires POSIX')
    def test_native_wizard_cancel_leaves_all_persistent_paths_and_manager_untouched(self):
        code, output = self.run_interactive([('确认部署', '0')],
            '--dev-localhost', '--relay-endpoint', 'tls://localhost:18081',
            '--control-port', '18080', '--metrics-port', '18082', '--no-start',
            before_reply=lambda *_: self.assert_no_mutation())
        self.assertIn(code, (0, 1), output)
        self.assert_no_mutation()

    @unittest.skipUnless(os.name == 'posix', 'a real controlling terminal requires POSIX')
    def test_native_wizard_reenter_changes_paths_without_publishing_the_first_plan(self):
        program, config, data = (self.path / name for name in ('other-root', 'other-config', 'other-data'))
        def nothing_published(*_):
            self.assert_no_mutation()
            for path in (program, config, data):
                self.assertFalse(path.exists())
        code, output = self.run_interactive([
            ('确认部署', '2'), ('程序目录', str(program)), ('配置目录', str(config)), ('数据目录', str(data)),
            ('部署模式', '2'), ('Relay主机', 'localhost'), ('Relay端口', '38081'),
            ('Control端口', '38080'), ('metrics端口', '38082'),
            ('启动方式', '2'), ('确认部署', '1'),
        ], '--dev-localhost', '--relay-endpoint', 'tls://localhost:28081',
            '--control-port', '28080', '--metrics-port', '28082', '--no-start',
            before_reply=nothing_published)
        self.assertEqual(code, 0, output)
        self.assertFalse(self.config.exists())
        self.assertIn(f'DB_PATH={data}/p2pnet.db', (config / 'control.env').read_text())
        self.assertIn('PORT=38080', (config / 'control.env').read_text())
        self.assertEqual(sum(call.startswith('generate ') for call in self.calls.read_text().splitlines()), 1)

    @unittest.skipUnless(os.name == 'posix', 'a real controlling terminal requires POSIX')
    def test_native_wizard_retries_overlapping_paths_and_invalid_mode_or_ports(self):
        code, output = self.run_interactive([
            ('程序目录', str(self.root)), ('配置目录', str(self.root / 'config')), ('数据目录', str(self.data)),
            ('程序目录', str(self.root)), ('配置目录', str(self.config)), ('数据目录', str(self.data)),
            ('部署模式', '99'), ('部署模式', '2'),
            ('Relay主机', 'relay.example.test'), ('Relay主机', 'localhost'),
            ('Relay端口', '65536'), ('Relay端口', '28081'),
            ('Control端口', 'invalid'), ('Control端口', '28080'),
            ('metrics端口', '28080'), ('metrics端口', '28082'),
            ('启动方式', '99'), ('启动方式', '2'), ('确认部署', '1'),
        ], include_paths=False, before_reply=lambda *_: self.assert_no_mutation())
        self.assertEqual(code, 0, output)
        self.assertIn('PORT=28080', (self.config / 'control.env').read_text())
        self.assertIn('RELAY_METRICS_BIND=127.0.0.1:28082', (self.config / 'relay.env').read_text())

    def test_native_port_arguments_are_normalized_to_decimal_before_calling_the_generator(self):
        result = self.run_installer('--dev-localhost', '--relay-endpoint', 'tls://localhost:018081',
                                    '--control-port', '018080', '--metrics-port', '018082', '--no-start')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        generation = next(call for call in self.calls.read_text().splitlines() if call.startswith('generate '))
        self.assertIn(' 18080 18082 tls://localhost:18081', generation)


if __name__ == '__main__':
    unittest.main()
