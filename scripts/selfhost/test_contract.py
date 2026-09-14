"""Keep the deployment example tied to the actual toolchain and security defaults."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]


class SelfhostContracts(unittest.TestCase):
    def test_docker_toolchain_satisfies_module_without_auto_download(self):
        module = (ROOT/'server/go.mod').read_text()
        docker = (ROOT/'server/Dockerfile').read_text()
        required = tuple(map(int, re.search(r'^go ([\d.]+)', module, re.M)[1].split('.')))
        configured = tuple(map(int, re.search(r'^ARG GO_VERSION=([\d.]+)', docker, re.M)[1].split('.')))
        self.assertGreaterEqual(configured, required)
        self.assertIn('GOTOOLCHAIN=local', docker)
        self.assertNotIn('CGO_ENABLED=1', docker)
        self.assertIn('/out/p2wlan-relay ./relay', docker)
        self.assertIn('/out/p2wlan-db ./cmd/p2wlan-db', docker)
        self.assertIn('ca-certificates', docker)
        self.assertIn('USER p2wlan', docker)

    def test_compose_keeps_control_private_and_checks_relay_readiness(self):
        compose=(ROOT/'deploy/selfhost/compose.yml').read_text()
        self.assertIn('127.0.0.1:${CONTROL_PORT', compose)
        self.assertIn('RELAY_METRICS_BIND/readyz', compose)
        self.assertIn('no-new-privileges:true', compose)
        self.assertNotIn('docker.sock', compose)
        self.assertNotIn('privileged: true', compose)

    def test_service_logs_have_persistent_location(self):
        manager=(ROOT/'scripts/p2wlan-server').read_text()
        self.assertIn('WorkingDirectory=${DATA_DIR}', manager)
        self.assertIn('LOG_UPLOAD_DIR=$DATA_DIR/log-uploads', manager)

    def test_staging_deploys_only_the_exact_built_source(self):
        workflow=(ROOT/'.github/workflows/build-server.yml').read_text()
        self.assertNotIn('remote-fetch', workflow)
        self.assertIn('steps.source-sha.outputs.sha', workflow)
        self.assertIn('bundle source mismatch', workflow)
        self.assertIn('uploaded bundle source mismatch', workflow)
        self.assertIn('actual_sha', workflow)
        self.assertIn('EXPECTED_SHA', workflow)

    def test_client_release_requires_exact_sha_quality_evidence(self):
        workflow=(ROOT/'.github/workflows/release.yml').read_text()
        self.assertIn('Release required checks gate', workflow)
        self.assertIn('head_sha=$RELEASE_SHA', workflow)
        self.assertIn('release SHA is not reachable from origin/main', workflow)
        self.assertIn('Self-hosted Server', workflow)
        self.assertIn('Security Audit', workflow)
        self.assertIn('Rekey Reliability', workflow)
        self.assertNotIn('sort | tail -n 1', workflow)


if __name__=='__main__':
    unittest.main()
