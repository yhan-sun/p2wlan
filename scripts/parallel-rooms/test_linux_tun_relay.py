"""Plain report/key/file controls; no kernel, daemon or native owner is built."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

import linux_tun_contract as original
import linux_tun_relay as relay
import retain_linux_tun_programs as retention


class RelayDataControls(unittest.TestCase):
    def test_standby_requires_one_established_socket_cookie(self):
        endpoint = "tls://192.0.2.2:18082"
        address = "192.0.2.2:18082"
        output = SimpleNamespace(stdout=f"0 0 192.0.2.3:5000 {address} ino:77 sk:4abc <->\n")
        lab = SimpleNamespace(daemons={"a1": {"namespace": "a"}}, cmd=lambda *args: output)
        self.assertEqual(relay.standby_socket(lab, "a1", endpoint)["socket_cookie"], "4abc")
        output.stdout += output.stdout
        self.assertIsNone(relay.standby_socket(lab, "a1", endpoint))
        output.stdout = f"0 0 192.0.2.3:5000 {address}\n"
        self.assertIsNone(relay.standby_socket(lab, "a1", endpoint))

    def readiness_data(self):
        return dict(network_generation=0, relay_connected=True, peers=[dict(node_id="peer-1", online=True,
            active_path="direct", relay_ready_generation=0, relay_confirmed_generation=0,
            relay_ready_connection_id=1, relay_confirmed_connection_id=1,
            relay_ready_endpoint=relay.ENDPOINT, relay_confirmed_endpoint=relay.ENDPOINT,
            current_path_selection=dict(path="relay", reason_code="path_direct_disabled"))])

    def test_diagnostic_readiness_uses_current_business_selection_and_matching_confirmation(self):
        snapshot = self.readiness_data()
        before = copy.deepcopy(snapshot)
        result = relay.readiness(snapshot, "peer-1")
        self.assertTrue(result["ready"])
        self.assertFalse(result["native_evidence"])
        self.assertEqual(result["observed_connection_active_path"], "direct")
        self.assertEqual(result["current_business_selection"], "relay")
        self.assertEqual(snapshot, before)

    def test_local_connect_stale_generation_replacement_or_wrong_selector_is_not_ready(self):
        changes = [dict(relay_confirmed_generation=None), dict(relay_confirmed_generation=1),
                   dict(relay_confirmed_generation=False), dict(relay_confirmed_connection_id=2),
                   dict(relay_confirmed_connection_id=True), dict(relay_ready_connection_id=0),
                   dict(relay_confirmed_endpoint="tcp://192.0.2.2:18082"), dict(online=False),
                   dict(node_id="other-peer"), dict(current_path_selection=dict(path="direct", reason_code="path_direct_disabled")),
                   dict(current_path_selection=dict(path="relay", reason_code="other"))]
        for change in changes:
            snapshot = self.readiness_data()
            snapshot["peers"][0].update(change)
            self.assertFalse(relay.readiness(snapshot, "peer-1")["ready"], change)
        for change in [dict(network_generation=1), dict(network_generation=False), dict(relay_connected=False)]:
            snapshot = self.readiness_data()
            snapshot.update(change)
            self.assertFalse(relay.readiness(snapshot, "peer-1")["ready"])
        snapshot = self.readiness_data()
        snapshot["peers"] *= 2
        self.assertFalse(relay.readiness(snapshot, "peer-1")["ready"])

    def test_original_service_file_tails_are_bounded_and_redacted_before_private_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            debug = root / "debug"
            debug.mkdir()
            for role in ["control", "relay"]:
                (root / (role + ".console")).write_text("public-line\n" * 30000 + "Bearer ephemeral-fixture\n")
            relay.preserve_service_logs(SimpleNamespace(root=root, debug_dir=debug),
                                        lambda line: line.replace("Bearer ephemeral-fixture", "Bearer [REDACTED]"))
            for path in debug.iterdir():
                text = path.read_text()
                self.assertLessEqual(len(text.splitlines()), 1000)
                self.assertLess(path.stat().st_size, 256 * 1024)
                self.assertNotIn("ephemeral-fixture", text)
                self.assertIn("Bearer [REDACTED]", text)

    def test_separate_fixed16_uses_original_eight_slots_and_all_original_timing(self):
        for protocol in ["udp", "tcp"]:
            entries = relay.manifest("11" * 16, "22" * 16, protocol)
            self.assertEqual(entries, [e for e in original.manifest("11" * 16, "22" * 16) if e["protocol"] == protocol])
            report = relay.summarize(entries)
            self.assertEqual(report["prescheduled_requests"], 16)
            self.assertEqual(report["terminal_counts"], {"not_started": 16})
            self.assertFalse(report["all_responses_observed"])
            self.assertIsNone(report["canonical_current_owner_verified"])
        self.assertEqual(original.summarize(original.manifest("11" * 16, "22" * 16))["prescheduled_requests"], 32)

    def test_missing_started_and_failed_requests_stay_in_original_denominator(self):
        entries = relay.manifest("11" * 16, "22" * 16, "udp")
        entries[0].update(outcome="started", records=[dict(status="success")] * 7 + [dict(status="timeout")])
        entries[1]["outcome"] = "started"
        result = relay.summarize(entries)
        self.assertEqual(result["terminal_counts"], dict(success=7, timeout=1, unknown=8))
        self.assertEqual(result["prescheduled_requests"], 16)
        self.assertFalse(result["all_responses_observed"])

    def test_changed_protocol_direction_count_or_slot_denominator_is_rejected(self):
        for change in [lambda e: e.pop(), lambda e: e[1].update(protocol="tcp"),
                       lambda e: e[1].update(direction="a-to-b"), lambda e: e[0].update(count=7),
                       lambda e: e[0].update(records=[dict(status="success")] * 7)]:
            entries = relay.manifest("11" * 16, "22" * 16, "udp")
            change(entries)
            with self.assertRaises(ValueError):
                relay.summarize(entries)
        with self.assertRaises(ValueError):
            relay.manifest("11" * 16, "22" * 16, "quic")

    def test_all_application_success_still_grants_no_native_path_credit(self):
        entries = relay.manifest("11" * 16, "22" * 16, "tcp")
        for entry in entries:
            entry["records"] = [dict(status="success")] * 8
        self.assertTrue(relay.summarize(entries)["all_responses_observed"])
        result = relay.path_summary(entries)
        self.assertFalse(result["complete"])
        self.assertEqual(result["missing_or_nonrelay_node_records"], 32)

    def test_serialized_path_comparison_preserves_nonrelay_gap_and_missing_node(self):
        # Minimal dictionaries exercise a reducer only. No actual collector,
        # snapshot endpoint, KernelRead, SystemTun or native Full is produced.
        entries = relay.manifest("11" * 16, "22" * 16, "udp")
        for entry in entries:
            entry["original_kernel_reads"] = dict(passed=True, full128_owner_evidence_complete=True,
                requests=[dict(full128_owner_qualified=True,
                    source_native_transaction=dict(matched=True, physical_path="relay"),
                    response_native_transaction=dict(matched=True, physical_path="relay")) for _ in range(8)])
        before = copy.deepcopy(entries)
        self.assertTrue(relay.path_summary(entries)["complete"])
        self.assertEqual(entries, before)
        row = entries[1]["original_kernel_reads"]["requests"][7]
        row["response_native_transaction"]["physical_path"] = "udp"
        result = relay.path_summary(entries)
        self.assertEqual(result["paths"], dict(relay=31, udp=1))
        self.assertFalse(result["complete"])
        row["response_native_transaction"] = dict(matched=False, gap_reason="native_frame_original_once_missing")
        result = relay.path_summary(entries)
        self.assertEqual(result["collected_qualified_node_records"], 31)
        self.assertEqual(result["missing_or_nonrelay_node_records"], 1)
        self.assertFalse(result["complete"])
        entries[0]["original_kernel_reads"]["passed"] = False
        self.assertEqual(relay.path_summary(entries)["missing_or_nonrelay_node_records"], 17)

    def test_ephemeral_key_output_must_be_exactly_two_complete_hex_values(self):
        self.assertEqual(relay.parse_keypair("11" * 32 + " " + "22" * 32 + "\n"), ["11" * 32, "22" * 32])
        for text in ["", "11" * 32, "11" * 32 + " " + "ZZ" * 32, "11" * 32 + " " + "22" * 32 + " extra"]:
            with self.assertRaises(ValueError):
                relay.parse_keypair(text)

    def test_optional_relay_retention_copies_only_existing_digest_matched_file_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = {role: root / role for role in ["daemon", "control", "relay"]}
            hashes = {}
            for role, path in sources.items():
                path.write_bytes(("plain-file-fixture-" + role).encode())
                hashes[role] = hashlib.sha256(path.read_bytes()).hexdigest()
            report = root / "report.json"
            report.write_text(json.dumps(dict(source_commit="a" * 40, binary_sha256=hashes)))
            output = root / "saved"
            output.mkdir()
            args = SimpleNamespace(**sources, head="a" * 40, report=[report], output=output)
            manifest = dict(images=[])
            retention.retain(args, manifest)
            self.assertEqual(len(manifest["images"]), 3)
            for row in manifest["images"]:
                self.assertTrue(row["available"])
                self.assertEqual(row["sha256"], hashes[row["role"]])
                self.assertEqual((output / row["file"]).read_bytes(), sources[row["role"]].read_bytes())


if __name__ == "__main__":
    unittest.main()
