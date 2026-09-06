from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

SECURITY_DIR = Path(__file__).resolve().parents[1]
if str(SECURITY_DIR) not in sys.path:
    sys.path.insert(0, str(SECURITY_DIR))

import dependency_reports


class ZeroAdvisoryExceptionTests(unittest.TestCase):
    def test_repository_contract_has_zero_active_exceptions(self) -> None:
        root = Path(__file__).resolve().parents[3]
        findings: list[dict[str, object]] = []
        exceptions = dependency_reports.load_advisory_exception_contract(
            root / "deny.toml",
            root / "security" / "advisory-exceptions.json",
            findings,
        )
        self.assertEqual(exceptions, [])
        self.assertEqual(findings, [])

    def test_python39_fallback_accepts_missing_ignore(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            deny = root / "deny.toml"
            metadata = root / "advisory-exceptions.json"
            deny.write_text(
                "[advisories]\nyanked = \"deny\"\nunsound = \"all\"\n",
                encoding="utf-8",
            )
            metadata.write_text(
                json.dumps({"exceptions": []}),
                encoding="utf-8",
            )
            findings: list[dict[str, object]] = []
            original_tomllib = dependency_reports.tomllib
            dependency_reports.tomllib = None
            try:
                exceptions = dependency_reports.load_advisory_exception_contract(
                    deny,
                    metadata,
                    findings,
                )
            finally:
                dependency_reports.tomllib = original_tomllib
            self.assertEqual(exceptions, [])
            self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
