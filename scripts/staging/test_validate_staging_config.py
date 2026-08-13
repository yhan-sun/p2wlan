#!/usr/bin/env python3
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/staging/validate_staging_config.py"
CONTROL = ROOT / "deploy/staging/control.env.example"
RELAY = ROOT / "deploy/staging/relay.env.example"


class StagingValidatorTests(unittest.TestCase):
    def run_validator(self, control: Path = CONTROL, relay: Path = RELAY, *extra: str):
        return subprocess.run(
            ["python3", str(SCRIPT), "--control-env", str(control), "--relay-env", str(relay), *extra],
            cwd=ROOT,
            text=True,
            capture_output=True,
        )

    def test_templates_pass_local_read_only_validation(self):
        result = self.run_validator()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PASS staging configuration preflight", result.stdout)

    def test_tcp_catalog_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            control = Path(directory) / "control.env"
            text = CONTROL.read_text(encoding="utf-8").replace("tls://relay.example.net:443", "tcp://relay.example.net:443")
            control.write_text(text, encoding="utf-8")
            result = self.run_validator(control)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("tls://", result.stderr)

    def test_missing_metrics_bind_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            relay = Path(directory) / "relay.env"
            relay.write_text(
                RELAY.read_text(encoding="utf-8").replace("RELAY_METRICS_BIND=127.0.0.1:<METRICS_PORT>\n", ""),
                encoding="utf-8",
            )
            result = self.run_validator(relay=relay)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("RELAY_METRICS_BIND", result.stderr)


if __name__ == "__main__":
    unittest.main()
