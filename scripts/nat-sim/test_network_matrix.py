import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

from network_conditions import load_profiles
from test_launch_identity import write_valid_launch_evidence


spec = importlib.util.spec_from_file_location("network_matrix", Path(__file__).with_name("run-network-matrix.py"))
MATRIX = importlib.util.module_from_spec(spec)
spec.loader.exec_module(MATRIX)


class NetworkMatrixTests(unittest.TestCase):
    def test_each_scenario_is_valid_and_uses_normal_traversal(self):
        with tempfile.TemporaryDirectory() as directory:
            profile = Path(directory) / "profile.json"
            for name, (changes, options) in MATRIX.SCENARIOS.items():
                with self.subTest(scenario=name):
                    profile.write_text(json.dumps({"schema_version": 1, **options}))
                    load_profiles(profile)
                    env = MATRIX.case_environment({"PATH": "/bin", "MODE": "hard-hard", "LOSS": "1",
                                                   "P2WLAN_A0_SIGNAL_TRACE": "1", "RELAY_FAILOVER": "1",
                                                   "CONTROL_API_TOKEN": "must-not-inherit"},
                                                  changes, Path(directory), profile, 12)
                    self.assertEqual(env["MODE"], "normal")
                    self.assertEqual(env["EGRESS_CAPTURE"], "shim")
                    for key in ("LOSS", "RELAY_FAILOVER", "P2WLAN_A0_SIGNAL_TRACE", "CONTROL_API_TOKEN"):
                        self.assertNotIn(key, env)

    def test_result_requires_business_mapping_continuity_and_graceful_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            round_dir = root / "round-1"
            round_dir.mkdir()
            write_valid_launch_evidence(root)
            observed = {side: {"first_usable": {"path": "relay"}, "overlay_verified": 2} for side in ("a", "b")}
            data = {"nat-evidence": {"result": "pass", "observed": observed, "decision": {}},
                    "mapping-evidence": {"valid": True}, "continuity-evidence": {"valid": True},
                    "cleanup": {"all_reaped": True, "forced_termination": False}}
            for name, value in data.items():
                (round_dir / f"{name}.json").write_text(json.dumps(value))
            for side in ("a", "b"):
                (round_dir / f"node-{side}.status.json").write_text(
                    json.dumps({"peers": [{"state": "relay", "active_path": "relay", "online": True}]}))
            self.assertTrue(MATRIX.read_case(root, 0)["valid"])
            self.assertFalse(MATRIX.read_case(root, 1)["valid"])
            samples = [{"monotonic_ns": 1_000_000_000, "direct": {"a": 2, "b": 2}},
                       {"monotonic_ns": 5_000_000_000, "direct": {"a": 5, "b": 5}}]
            sample_path = round_dir / "business-samples.jsonl"
            sample_path.write_text("\n".join(map(json.dumps, samples)) + "\n")
            self.assertFalse(MATRIX.read_case(root, 0, True)["valid"], "Relay cannot satisfy Direct")
            for side in ("a", "b"):
                (round_dir / f"node-{side}.status.json").write_text(
                    json.dumps({"peers": [{"state": "direct", "active_path": "direct", "online": True}]}))
            self.assertTrue(MATRIX.read_case(root, 0, True)["valid"])
            samples[1]["direct"] = samples[0]["direct"]
            sample_path.write_text("\n".join(map(json.dumps, samples)) + "\n")
            self.assertFalse(MATRIX.read_case(root, 0, True)["valid"], "historic Direct is insufficient")
            for name in data:
                path = round_dir / f"{name}.json"
                original = path.read_text()
                path.unlink()
                self.assertFalse(MATRIX.read_case(root, 0)["valid"])
                path.write_text(original)
            (round_dir / "continuity-evidence.json").write_text('{"valid": 1}')
            self.assertFalse(MATRIX.read_case(root, 0)["valid"])
            (round_dir / "continuity-evidence.json").write_text('{"valid": true}')
            for peer in ({"state": "relay", "active_path": None, "online": True},
                         {"state": "relay", "active_path": "relay", "online": False}):
                (round_dir / "node-a.status.json").write_text(json.dumps({"peers": [peer]}))
                self.assertFalse(MATRIX.read_case(root, 0)["valid"])

    def test_execution_cap_rejects_before_creating_output(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "untouched"
            with self.assertRaises(SystemExit) as raised:
                MATRIX.main(["--rounds", "33", "--output", str(output)])
            self.assertEqual(raised.exception.code, 2)
            self.assertFalse(output.exists())

    def test_success_requires_launch_identity_even_when_business_and_cleanup_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            round_dir = root / "round-1"
            round_dir.mkdir()
            observed = {side: {"first_usable": {"path": "relay"}, "overlay_verified": 2}
                        for side in ("a", "b")}
            evidence = {"nat-evidence": {"result": "pass", "observed": observed, "decision": {}},
                        "mapping-evidence": {"valid": True}, "continuity-evidence": {"valid": True},
                        "cleanup": {"all_reaped": True, "forced_termination": False}}
            for name, value in evidence.items():
                (round_dir / f"{name}.json").write_text(json.dumps(value))
            for side in ("a", "b"):
                (round_dir / f"node-{side}.status.json").write_text(json.dumps(
                    {"peers": [{"state": "relay", "active_path": "relay", "online": True}]}))
            result = MATRIX.read_case(root, 0)
            self.assertFalse(result["valid"], "passing business evidence cannot invent launch identity")
            self.assertTrue(any("launch_identity" in error for error in result["errors"]), result)


if __name__ == "__main__":
    unittest.main()
