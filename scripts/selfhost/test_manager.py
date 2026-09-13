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
        release = self.root / 'release'
        release.mkdir()
        (self.root / 'current').symlink_to(release, target_is_directory=True)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        for name in ('p2wlan-control', 'p2wlan-relay'):
            self.executable(release / name, '#!/bin/sh\necho test-binary\n')
        self.executable(self.bin / 'systemctl', '#!/bin/sh\nexit 0\n')
        self.executable(self.bin / 'curl', '''#!/bin/sh
printf '%s\\n' "$*" >> "$HEALTH_CALLS"
case "$*" in *'/readyz'*) [ "${FAIL_RELAY:-0}" = 0 ] || exit 22;; esac
exit 0
''')
        (self.config / 'control.env').write_text('PORT=18080\nCONTROL_BIND=127.0.0.1:18080\n')
        (self.config / 'relay.env').write_text('RELAY_METRICS_BIND=127.0.0.1:18082\n')
        self.env = dict(os.environ, PATH=str(self.bin)+os.pathsep+os.environ['PATH'],
                        P2WLAN_SERVER_ROOT=str(self.root), P2WLAN_SERVER_CONFIG=str(self.config),
                        HEALTH_CALLS=str(self.root/'calls'))

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


if __name__ == '__main__':
    unittest.main()
