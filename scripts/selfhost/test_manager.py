import hashlib
import io
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest

from test_support_log_storage import SupportLogStorageTests

ROOT = Path(__file__).resolve().parents[2]


class ManagerHealthTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = self.root / 'config'
        self.config.mkdir()
        self.data = self.root / 'data'
        self.data.mkdir()
        release = self.root / 'release'
        release.mkdir()
        (self.root / 'current').symlink_to(release, target_is_directory=True)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        for name in ('p2wlan-control', 'p2wlan-relay'):
            self.executable(release / name, '#!/bin/sh\necho test-binary\n')
        self.executable(release / 'p2wlan-db', '#!/bin/sh\n[ "$1" = --verify ]\n')
        self.executable(self.bin / 'systemctl', '#!/bin/sh\nexit 0\n')
        self.executable(self.bin / 'id', '#!/bin/sh\nif [ "$1" = "-u" ]; then echo 0; else exec /usr/bin/id "$@"; fi\n')
        # Storage transactions have their own real-filesystem tests above;
        # this fixture isolates doctor aggregation from privileged identity setup.
        self.executable(self.bin / 'python3', '#!/bin/sh\ncat >/dev/null\n[ "${FAIL_STORAGE:-0}" = 0 ]\n')
        self.executable(self.bin / 'curl', '''#!/bin/sh
printf '%s\\n' "$*" >> "$HEALTH_CALLS"
case "$*" in *'/readyz'*) [ "${FAIL_RELAY:-0}" = 0 ] || exit 22;; esac
exit 0
''')
        (self.config / 'control.env').write_text(
            'PORT=18080\n'
            'CONTROL_BIND=127.0.0.1:18080\n'
            f'DB_PATH={self.data / "p2pnet.db"}\n'
            f'CONTROL_ADMIN_TOKEN={"a" * 64}\n'
        )
        (self.data / 'p2pnet.db').write_text('test-db')
        (self.config / 'relay.env').write_text('RELAY_METRICS_BIND=127.0.0.1:18082\n')
        self.systemd = self.root / 'systemd'
        self.systemd.mkdir()
        self.env = dict(os.environ, PATH=str(self.bin)+os.pathsep+os.environ['PATH'],
                        P2WLAN_SERVER_ROOT=str(self.root), P2WLAN_SERVER_CONFIG=str(self.config),
                        P2WLAN_SERVER_DATA=str(self.data), HEALTH_CALLS=str(self.root/'calls'),
                        P2WLAN_SYSTEMD_DIR=str(self.systemd))

    @staticmethod
    def executable(path, content):
        path.write_text(content)
        path.chmod(0o755)

    def run_check(self, service='all'):
        return subprocess.run(['bash', str(ROOT/'scripts/p2wlan-server'), 'check', '--service', service],
                              env=self.env, capture_output=True, text=True, timeout=10)

    def test_all_checks_control_and_relay_readiness_with_deadlines(self):
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stderr)
        calls=(self.root/'calls').read_text().splitlines()
        self.assertEqual(len(calls), 2)
        self.assertIn('/health', calls[0])
        self.assertIn('/readyz', calls[1])
        self.assertTrue(all('--connect-timeout 3 --max-time 10' in call for call in calls))

    def test_relay_failure_is_not_hidden_by_healthy_control(self):
        self.env['FAIL_RELAY']='1'
        result=self.run_check()
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('health check passed', result.stdout)
        self.assertIn('relay /readyz failed', result.stderr)

    def test_missing_metrics_is_not_reported_as_verified(self):
        (self.config/'relay.env').write_text('')
        result=self.run_check('relay')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('cannot be verified', result.stderr)

    def test_ipv6_loopback_url_and_role_isolation(self):
        (self.config/'relay.env').write_text('RELAY_METRICS_BIND=[::1]:18082\n')
        result=self.run_check('relay')
        self.assertEqual(result.returncode, 0, result.stderr)
        calls=(self.root/'calls').read_text()
        self.assertIn('http://[::1]:18082/readyz', calls)
        self.assertNotIn('/health', calls)

    def test_doctor_control_reports_layered_health_without_treating_warnings_as_failure(self):
        result = subprocess.run(
            ['bash', str(ROOT/'scripts/p2wlan-server'), 'doctor', '--service', 'control'],
            env=self.env, capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('PASS  release bundle', result.stdout)
        self.assertIn('PASS  selected systemd services are active', result.stdout)
        self.assertIn('PASS  admin console credential is configured', result.stdout)
        self.assertIn('PASS  SQLite integrity verification passed', result.stdout)
        self.assertIn('WARN  no managed backup snapshot was found', result.stdout)
        self.assertIn('Result: 0 failure(s)', result.stdout)

    def test_doctor_rejects_short_admin_credential(self):
        (self.config/'control.env').write_text(
            'PORT=18080\n'
            'CONTROL_BIND=127.0.0.1:18080\n'
            f'DB_PATH={self.data / "p2pnet.db"}\n'
            'CONTROL_ADMIN_TOKEN=short\n'
        )
        result = subprocess.run(
            ['bash', str(ROOT/'scripts/p2wlan-server'), 'doctor', '--service', 'control'],
            env=self.env, capture_output=True, text=True, timeout=10,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('CONTROL_ADMIN_TOKEN is shorter than the server minimum', result.stdout)
        self.assertIn('Result: 1 failure(s)', result.stdout)

    def test_doctor_storage_failure_is_not_hidden_by_healthy_http(self):
        self.env['FAIL_STORAGE'] = '1'
        result = subprocess.run(
            ['bash', str(ROOT/'scripts/p2wlan-server'), 'doctor', '--service', 'control'],
            env=self.env, capture_output=True, text=True, timeout=10,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('PASS  selected local health/readiness endpoints respond', result.stdout)
        self.assertIn('FAIL  support log storage configuration or host permissions failed', result.stdout)
        self.assertIn('Result: 1 failure(s)', result.stdout)

    def test_doctor_relay_fails_closed_when_tls_files_are_not_configured(self):
        result = subprocess.run(
            ['bash', str(ROOT/'scripts/p2wlan-server'), 'doctor', '--service', 'relay'],
            env=self.env, capture_output=True, text=True, timeout=10,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Relay TLS certificate/key are not configured as readable files', result.stdout)

    def test_backup_restore_and_rollback_contracts_are_explicit(self):
        manager = (ROOT/'scripts/p2wlan-server').read_text()
        self.assertIn('p2wlan-db" --source "$db_path" --output', manager)
        self.assertIn('p2wlan-db" --verify', manager)
        self.assertIn('p2wlan-db" --source "$db_path" --output "$rollback_copy/database.sqlite"', manager)
        self.assertIn('systemctl stop p2wlan-control.service || die', manager)
        self.assertIn('relay_was_active', manager)
        self.assertIn('database.state', manager)
        self.assertIn('control.env.state', manager)
        self.assertIn('relay.env.state', manager)
        self.assertIn('rollback could not fully restore the original state', manager)
        self.assertIn('restore failed; original database, configuration and service state were restored', manager)
        self.assertIn('rollback target is incomplete', manager)
        self.assertNotIn('systemctl stop p2wlan-control.service || true', manager)
        self.assertIn('"CONTROL_ADMIN_TOKEN=$(openssl rand -hex 32)"', manager)
        self.assertIn('setup_server()', manager)
        self.assertIn('doctor_server()', manager)
        self.assertIn('p2wlan-db" --verify "$db_path"', manager)
        self.assertIn('openssl x509 -checkend 604800', manager)
        self.assertIn('Result: $failures failure(s), $warnings warning(s)', manager)


class ManagerUpdateTests(unittest.TestCase):
    executable = staticmethod(ManagerHealthTests.executable)

    def setUp(self):
        ManagerHealthTests.setUp(self)
        self.manager_calls = self.root / 'manager-calls'
        self.env['MANAGER_CALLS'] = str(self.manager_calls)
        real_install = shutil.which('install')
        self.assertIsNotNone(real_install)
        self.env['REAL_INSTALL'] = real_install
        self.executable(self.bin / 'systemctl', '''#!/bin/sh
printf 'systemctl %s\\n' "$*" >> "$MANAGER_CALLS"
''')
        self.executable(self.bin / 'python3', '''#!/bin/sh
printf 'storage %s\\n' "$*" >> "$MANAGER_CALLS"
cat >/dev/null
''')
        self.executable(self.bin / 'chown', '''#!/bin/sh
printf 'chown %s\\n' "$*" >> "$MANAGER_CALLS"
''')
        # Release extraction and publication stay real inside the temporary
        # installation; intercept the manager's global launcher installation.
        self.executable(self.bin / 'install', '''#!/bin/sh
for value in "$@"; do
  if [ "$value" = /usr/local/bin/p2wlan-server ]; then
    printf 'install-launcher\\n' >> "$MANAGER_CALLS"
    exit 0
  fi
done
exec "$REAL_INSTALL" "$@"
''')
        self.version = 'server-v9.9.9'
        self.archive = self.root / 'p2wlan-server-linux-amd64.tar.gz'
        members = {
            name: b'#!/bin/sh\nexit 0\n'
            for name in ('p2wlan-control', 'p2wlan-relay', 'p2wlan-config', 'p2wlan-db',
                         'p2wlan-server', 'install-server.sh', 'deploy-server.sh')
        }
        members['BUILD-METADATA.txt'] = f'version={self.version}\n'.encode()
        with tarfile.open(self.archive, 'w:gz') as archive:
            for name, content in members.items():
                member = tarfile.TarInfo(name)
                member.size = len(content)
                member.mode = 0o755 if name != 'BUILD-METADATA.txt' else 0o644
                archive.addfile(member, io.BytesIO(content))
        digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        Path(str(self.archive) + '.sha256').write_text(f'{digest}  {self.archive.name}\n')

    def run_update(self, *options):
        self.manager_calls.write_text('')
        return subprocess.run(
            ['bash', str(ROOT / 'scripts/p2wlan-server'), 'update', '--archive', str(self.archive), *options],
            env=self.env, capture_output=True, text=True, timeout=10,
        )

    def test_no_restart_installs_release_without_restarting_services(self):
        result = self.run_update('--service', 'control', '--no-restart')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.root / 'current').resolve(), (self.root / 'releases' / self.version).resolve())
        calls = self.manager_calls.read_text().splitlines()
        self.assertIn('install-launcher', calls)
        self.assertTrue(any(call.startswith('storage ') for call in calls))
        self.assertFalse(any(call.startswith('systemctl ') for call in calls), calls)

    def test_default_update_restarts_only_selected_services(self):
        for service, expected in (
            ('control', ['p2wlan-control.service']),
            ('relay', ['p2wlan-relay.service']),
            (None, ['p2wlan-control.service', 'p2wlan-relay.service']),
        ):
            with self.subTest(service=service or 'default-all'):
                options = ['--service', service] if service else []
                result = self.run_update(*options)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                calls = self.manager_calls.read_text().splitlines()
                restarts = [call.removeprefix('systemctl restart ') for call in calls
                            if call.startswith('systemctl restart ')]
                self.assertEqual(restarts, expected)
                self.assertIn('systemctl daemon-reload', calls)
                self.assertEqual(any(call.startswith('storage ') for call in calls), service != 'relay')


if __name__ == '__main__':
    unittest.main()
