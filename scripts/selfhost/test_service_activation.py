"""Exercise manager activation decisions without touching host service state."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]


class ServiceActivationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.units = self.root / 'units'
        self.units.mkdir()
        self.active = self.root / 'active'
        self.active.mkdir()
        self.config = self.root / 'config'
        self.calls = self.root / 'calls.jsonl'
        self.calls.write_text('')
        self.executable(self.bin / 'id', '#!/bin/sh\n[ "$1" != -u ] || echo 0\n')
        self.executable(self.bin / 'chown', '#!/bin/sh\nexit 0\n')
        self.executable(self.bin / 'systemctl', f'#!{sys.executable}\n' + '''
import json, os, pathlib, sys
args = sys.argv[1:]
with open(os.environ['SERVICE_CALLS'], 'a') as output:
    output.write(json.dumps(args) + '\\n')
unit = args[-1]
units = pathlib.Path(os.environ['SERVICE_UNITS'])
active = pathlib.Path(os.environ['SERVICE_ACTIVE'])
if args[0] == 'cat':
    sys.exit(0 if (units / unit).is_file() else 1)
if args[0] in ('restart', 'try-restart'):
    if unit == os.environ.get('FAIL_RESTART'):
        sys.exit(7)
    if args[0] == 'restart' or (active / unit).exists():
        (active / unit).write_text('running')
if args[0] == 'enable':
    (active / unit).write_text('running')
''')
        source = (ROOT / 'scripts/p2wlan-server').read_text()
        functions, dispatcher = source.split('cmd=${1:-}', 1)
        # Keep the production command dispatcher and lifecycle functions. Only
        # archive installation and privileged filesystem boundaries are faked;
        # init still creates/preserves its real private configuration files.
        self.manager = self.root / 'manager'
        self.manager.write_text(functions + '''
install_unit() { touch "$SERVICE_UNITS/$1"; }
prepare_managed_support_storage() { :; }
archive_install() { printf '[]\\n' >> "$SERVICE_CALLS"; }
cmd=${1:-}''' + dispatcher)
        self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ['PATH'],
                        P2WLAN_SERVER_ROOT=str(self.root / 'server'),
                        P2WLAN_SERVER_CONFIG=str(self.config),
                        P2WLAN_SERVER_DATA=str(self.root / 'data'),
                        P2WLAN_SYSTEMD_DIR=str(self.units), SERVICE_UNITS=str(self.units),
                        SERVICE_ACTIVE=str(self.active), SERVICE_CALLS=str(self.calls))

    @staticmethod
    def executable(path, content):
        path.write_text(content)
        path.chmod(0o755)

    def run_manager(self, *args):
        return subprocess.run(['bash', str(self.manager), *args], env=self.env,
                              capture_output=True, text=True, timeout=10)

    def initialize(self, role='all'):
        result = self.run_manager('init', '--role', role)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.calls.write_text('')

    def service_calls(self, operation):
        return [args for line in self.calls.read_text().splitlines()
                if (args := json.loads(line)) and args[0] == operation]

    def configure_relay(self):
        (self.config / 'relay.env').write_text(
            'RELAY_REQUIRE_AUTH=true\nRELAY_ALLOW_INSECURE_PLAINTEXT=false\n'
            'RELAY_TICKET_KEYRING_JSON={"fixture":"' + '01' * 32 + '"}\n'
            'RELAY_AUDIENCE=fixture\nRELAY_REGION=fixture\n'
            'RELAY_TLS_CERT=/fixture/tls.crt\nRELAY_TLS_KEY=/fixture/tls.key\n'
            'RELAY_REVOCATION_FEED_URL=http://127.0.0.1:18080/api/v1/relay/revocations\n'
            'RELAY_REVOCATION_FEED_TOKEN=fixture-private-feed\n')

    def test_initial_install_update_does_not_start_unconfigured_services(self):
        self.initialize()
        before = {p.name: p.read_bytes() for p in self.config.iterdir()}
        result = self.run_manager('update', '--archive', 'fixture.tar.gz', '--service', 'all')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(list(self.active.iterdir()), [])
        self.assertEqual(self.service_calls('restart'), [])
        self.assertEqual(self.service_calls('try-restart'), [
            ['try-restart', 'p2wlan-control.service'], ['try-restart', 'p2wlan-relay.service']])
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.config.iterdir()})

    def test_upgrade_restarts_only_active_service_and_preserves_credentials(self):
        self.initialize()
        self.configure_relay()
        before = {p.name: p.read_bytes() for p in self.config.iterdir()}
        (self.active / 'p2wlan-control.service').write_text('old-running')
        self.initialize()
        result = self.run_manager('update', '--archive', 'fixture.tar.gz')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.active / 'p2wlan-control.service').read_text(), 'running')
        self.assertFalse((self.active / 'p2wlan-relay.service').exists())
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.config.iterdir()})

    def test_update_honors_role_and_propagates_restart_failure(self):
        self.initialize()
        self.env['FAIL_RESTART'] = 'p2wlan-control.service'
        result = self.run_manager('update', '--archive', 'fixture.tar.gz', '--service', 'control')
        self.assertEqual(result.returncode, 7)
        self.assertEqual(self.service_calls('try-restart'), [['try-restart', 'p2wlan-control.service']])

    def test_start_all_rejects_missing_relay_config_before_starting_control(self):
        self.initialize()
        before = (self.config / 'control.env').read_bytes()
        result = self.run_manager('start', '--service', 'all')
        self.assertNotEqual(result.returncode, 0)
        for name in ('RELAY_TICKET_KEYRING_JSON', 'RELAY_AUDIENCE', 'RELAY_REGION', 'RELAY_TLS_CERT', 'RELAY_TLS_KEY'):
            self.assertIn(name, result.stderr)
        self.assertIn('p2wlan-config', result.stderr)
        self.assertEqual(self.service_calls('enable'), [])
        self.assertEqual(before, (self.config / 'control.env').read_bytes())
        for line in before.decode().splitlines():
            if line.startswith(('JWT_SECRET=', 'CONTROL_ADMIN_TOKEN=')):
                self.assertNotIn(line.split('=', 1)[1], result.stdout + result.stderr)

    def test_explicit_relay_restart_uses_same_missing_config_preflight(self):
        self.initialize()
        result = self.run_manager('restart', '--service', 'relay')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('RELAY_TICKET_KEYRING_JSON', result.stderr)
        self.assertEqual(self.service_calls('restart'), [])

    def test_configured_start_and_restart_preserve_existing_env_bytes(self):
        self.initialize()
        self.configure_relay()
        before = (self.config / 'relay.env').read_bytes()
        for command in ('start', 'restart'):
            result = self.run_manager(command, '--service', 'relay')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn('fixture-private-feed', result.stdout + result.stderr)
        self.assertEqual(before, (self.config / 'relay.env').read_bytes())
        self.assertEqual(self.service_calls('enable'), [['enable', '--now', 'p2wlan-relay.service']])
        self.assertEqual(self.service_calls('restart'), [['restart', 'p2wlan-relay.service']])

    def test_control_only_start_does_not_require_uninstalled_relay_configuration(self):
        self.initialize('control')
        result = self.run_manager('start', '--service', 'all')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.service_calls('enable'), [['enable', '--now', 'p2wlan-control.service']])

    def test_quoted_empty_keyring_and_missing_feed_token_are_reported_without_values(self):
        self.initialize()
        self.configure_relay()
        relay = self.config / 'relay.env'
        content = relay.read_text()
        content = '\n'.join('RELAY_TICKET_KEYRING_JSON="  "' if line.startswith('RELAY_TICKET_KEYRING_JSON=') else line
                            for line in content.splitlines() if not line.startswith('RELAY_REVOCATION_FEED_TOKEN=')) + '\n'
        relay.write_text(content)
        result = self.run_manager('start', '--service', 'relay')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('RELAY_TICKET_KEYRING_JSON', result.stderr)
        self.assertIn('RELAY_REVOCATION_FEED_TOKEN', result.stderr)
        self.assertEqual(self.service_calls('enable'), [])

    def test_preflight_uses_last_assignment_without_rewriting_existing_configuration(self):
        self.initialize()
        self.configure_relay()
        relay = self.config / 'relay.env'
        content = 'RELAY_TICKET_KEYRING_JSON=\n' + relay.read_text()
        relay.write_text(content)
        result = self.run_manager('start', '--service', 'relay')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(relay.read_text(), content)
        self.calls.write_text('')
        relay.write_text(content + '  RELAY_TICKET_KEYRING_JSON = ""\n')
        result = self.run_manager('restart', '--service', 'relay')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('RELAY_TICKET_KEYRING_JSON', result.stderr)
        self.assertEqual(self.service_calls('restart'), [])

    def test_empty_feed_url_does_not_require_feed_token(self):
        self.initialize()
        self.configure_relay()
        relay = self.config / 'relay.env'
        content = '\n'.join(line for line in relay.read_text().splitlines()
                            if not line.startswith('RELAY_REVOCATION_FEED_')) + '\n'
        for empty in ('', '  ', '""', '"  "', "''", "'  '"):
            with self.subTest(empty=empty):
                relay.write_text(content + 'RELAY_REVOCATION_FEED_URL=' + empty + '\n')
                result = self.run_manager('start', '--service', 'relay')
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_existing_explicit_development_opt_ins_are_preserved(self):
        self.initialize()
        relay = self.config / 'relay.env'
        content = 'RELAY_REQUIRE_AUTH="false"\nRELAY_ALLOW_INSECURE_PLAINTEXT="true"\n'
        relay.write_text(content)
        result = self.run_manager('start', '--service', 'relay')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(relay.read_text(), content)
        self.assertEqual(self.service_calls('enable'), [['enable', '--now', 'p2wlan-relay.service']])


if __name__ == '__main__':
    unittest.main()
