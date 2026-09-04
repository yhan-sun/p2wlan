#!/usr/bin/env python3
"""Contract shape and fixed scenario IDs are regression-tested."""

from __future__ import annotations

import unittest

try:
    from .contract import load_contract
except ImportError:  # pragma: no cover - direct test execution
    from contract import load_contract


class ContractTest(unittest.TestCase):
    def test_canonical_contract_has_fixed_matrix(self) -> None:
        contract = load_contract()
        self.assertEqual(contract["schema_version"], 2)
        self.assertEqual(contract["repository"], "yhan-sun/p2wlan")
        self.assertEqual(contract["components"], ["flutter", "android_jvm", "rust"])
        self.assertEqual(
            [item["id"] for item in contract["required_scenarios"]],
            [f"ML-{i:02d}" for i in range(1, 19)],
        )
        self.assertNotIn("deferred", contract["outcomes"])
        self.assertIn("deferred", contract["forbidden_outcomes"])


if __name__ == "__main__":
    unittest.main()
