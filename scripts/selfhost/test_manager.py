import os
from pathlib import Path
import subprocess
import tempfile
import unittest

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
        self.env = dict(os.environ, PATH=str(self.bin)+os.pathsep+os.environ['PATH'],
                        P2WLAN_SERVER_ROOT=str(self.root), P2WLAN_SERVER_CONFIG=str(self.config),
                        P2WLAN_SERVER_DATA=str(self.data), HEALTH_CALLS=str(self.root/'calls'))

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


if __name__ == '__main__':
    unittest.main()
