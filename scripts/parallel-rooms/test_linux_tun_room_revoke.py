"""Actual socket metadata and serialized negative controls; no native-owner facts."""
from copy import deepcopy
import json
import itertools
import socket
from types import SimpleNamespace
import unittest

from linux_tun_contract import manifest as original_manifest
from linux_tun_kernel_capture import Endpoint
from linux_tun_revoke_contract import (DeferredLastWindow, historical_last_sources,
                                       SCOPE, exit_status, kernel_evidence_passed,
                                       manifest, refused_credit, summarize)


class DeferredMetadataTests(unittest.TestCase):
    def bridge(self):
        class Capture:
            pass
        capture = Capture()
        original = SimpleNamespace(unavailable_reason=None, boot_id="a" * 36)
        capture.stream = SimpleNamespace(child=original, gap=None, owner_verified=True, clock_verified=True,
            records=5, headers=[None] * 5,
            requests=[dict(sequence=i, complete=True, original_sent_ns=100+i,
                           original_deadline_ns=200+i, last_returned_ns=101+i) for i in range(8)],
            started=1, expected_frames=[(191, "a" * 64)] * 8, accepted_in_time=lambda r:r["complete"])
        capture.prepared = SimpleNamespace(producer_scope="b" * 32, nonces=[f"{i:032x}" for i in range(8)])
        endpoints, peers = [], []
        for _ in range(2):
            left, right = socket.socketpair()
            endpoint = Endpoint(left, None, None, "a" * 32, "b" * 32)
            self.addCleanup(endpoint.close); self.addCleanup(right.close)
            endpoints.append(endpoint); peers.append(right)
        bridge = DeferredLastWindow(capture, endpoints)
        bridge.bind(capture, SimpleNamespace(returncode=None))
        return capture, bridge, endpoints, peers

    def receive(self, peer, count):
        peer.settimeout(1)
        raw = b""
        for _ in range(16):
            if raw.count(b"\n") >= count:
                break
            raw += peer.recv(4096)
        self.assertEqual(raw.count(b"\n"), count)
        return [json.loads(line) for line in raw.splitlines()]

    def test_actual_sockets_defer_only_last_metadata_and_release_original_once_to_survivor(self):
        capture, bridge, endpoints, peers = self.bridge()
        bridge.observe(capture, 110)
        first = [self.receive(peer, 7) for peer in peers]
        self.assertEqual(first[0], first[1])
        self.assertEqual([v["window"]["sequence"] for v in first[0]], list(range(7)))
        held = deepcopy(bridge.pending)
        self.assertEqual(bridge.release_to_survivor(endpoints[0], 111), held)
        self.assertEqual(self.receive(peers[0], 1)[0]["window"], held)
        peers[1].setblocking(False)
        with self.assertRaises(BlockingIOError):peers[1].recv(1)
        summary = bridge.summary()
        self.assertFalse(summary["requests"][7]["delivered"])
        self.assertEqual(summary["requests"][7]["delivered_endpoints"], 1)
        for key in ["native_os_write_verified", "physical_send_verified", "canonical_current_owner_verified"]:
            self.assertFalse(summary[key])
        with self.assertRaisesRegex(ValueError, "release_once"):
            bridge.release_to_survivor(endpoints[0], 112)

    def test_late_release_is_terminal_and_cannot_be_repaired_with_an_earlier_clock(self):
        capture, bridge, endpoints, peers = self.bridge(); bridge.observe(capture, 110)
        for peer in peers:self.receive(peer, 7)
        with self.assertRaisesRegex(ValueError, "expired"):
            bridge.release_to_survivor(endpoints[0], 207)
        self.assertIsNone(bridge.pending)
        with self.assertRaisesRegex(ValueError, "release_once"):
            bridge.release_to_survivor(endpoints[0], 111)

    def test_sealing_drops_deferred_metadata_without_catchup_or_credit(self):
        capture, bridge, endpoints, peers = self.bridge(); bridge.observe(capture, 110)
        for peer in peers:self.receive(peer, 7)
        bridge.seal()
        with self.assertRaises(ValueError):bridge.release_to_survivor(endpoints[0], 111)
        self.assertIsNone(bridge.pending)
        self.assertEqual(bridge.summary()["requests"][7]["delivered_endpoints"], 0)

    def test_foreign_equal_endpoint_is_rejected_by_identity_and_consumes_attempt(self):
        capture, bridge, _, _ = self.bridge(); bridge.observe(capture, 110)
        class Equal:
            def __eq__(self, other):return True
        with self.assertRaisesRegex(ValueError, "original_endpoint"):
            bridge.release_to_survivor(Equal(), 111)
        self.assertIsNone(bridge.pending)
        self.assertTrue(bridge.release_attempted)

    def test_partial_actual_control_write_closes_original_channel_and_never_refills(self):
        capture, bridge, endpoints, peers = self.bridge(); bridge.observe(capture, 110)
        for peer in peers:self.receive(peer, 7)
        original = endpoints[0].connection
        class Partial:
            def setblocking(self, value):original.setblocking(value)
            def send(self, raw):return original.send(raw[:7])
            def close(self):original.close()
        endpoints[0].connection = Partial()
        with self.assertRaises(ValueError):bridge.release_to_survivor(endpoints[0], 111)
        self.assertEqual(peers[0].recv(512), b'{"op":"')
        self.assertIsNone(endpoints[0].connection)
        with self.assertRaisesRegex(ValueError, "release_once"):
            bridge.release_to_survivor(endpoints[0], 112)

    def test_preexisting_clock_gap_never_retains_a_window(self):
        capture, bridge, _, _ = self.bridge();capture.stream.clock_verified = False
        bridge.observe(capture, 110)
        self.assertIsNone(bridge.pending)
        self.assertIsNotNone(bridge.gap)


class SerializedControls(unittest.TestCase):
    """Hypothetical dictionaries exercise comparisons, never KernelRead/Full/owner constructors."""
    def model(self):
        span = dict(slot=7, start=0, end=1)
        full = dict(flow=1, read_ordinal=8, read_monotonic_ns=101, publication_observed_monotonic_ns=102,
            full_observed_monotonic_ns=103, packet_len=219, packet_sha256="a"*64, spans=[span],
            encryption_generation=0, encryption_peer_lifecycle=1, encryption_session_instance=2, physical_path="udp")
        write = dict(flow=1, write_ordinal=8, authenticated_observed_monotonic_ns=104, write_observed_monotonic_ns=105,
            packet_len=219, packet_sha256="b"*64, spans=[span], network_generation=0, peer_lifecycle=1,
            session_instance=2, original_session_role="active", original_room_captured=[True],
            original_room_restricted=[True], canonical_current_owner_verified=False,
            scope="original_authenticated_system_tun_full_history_only")
        row = dict(sequence=7, protocol="udp", kind="request", flow=1, kernel_frame_read_complete=True,
            flow_invalid=False, historical_frame_full_complete=True, incoming_frame_system_write_complete=True,
            incoming_flow_invalid=False, first_read_monotonic_ns=101, last_read_monotonic_ns=101,
            original_peer=dict(known=True, capture_failure=None, network_generation=0, peer_lifecycle=1),
            original_request_room=dict(known=True, restricted=True, capture_failure=None))
        snapshot = dict(original_read_observation_complete=True, original_full_retention_complete=True,
            incoming_provenance_complete=True, observed_monotonic_ns=110,
            historical_full_packets=[full], system_tun_full_writes=[write])
        window = dict(original_sent_ns=100, original_deadline_ns=200, complete_returned_ns=101)
        return snapshot, row, window

    def test_serialized_sources_return_only_original_dictionary_records(self):
        snapshot, row, window = self.model();unchanged = deepcopy(snapshot)
        result = historical_last_sources(snapshot, row, window)
        self.assertEqual(snapshot, unchanged)
        self.assertEqual(result, dict(full=snapshot["historical_full_packets"], writes=snapshot["system_tun_full_writes"]))
        self.assertNotIn("native_credit", result)

    def test_unknown_missing_mixed_session_late_and_unrestricted_sources_are_rejected(self):
        for change in ["gap", "missing", "session", "late", "unrestricted", "empty", "ordering", "duplicate", "coverage", "room"]:
            snapshot, row, window = self.model()
            if change == "gap":snapshot["original_full_retention_complete"] = False
            elif change == "missing":snapshot["historical_full_packets"] = []
            elif change == "session":snapshot["system_tun_full_writes"][0]["session_instance"] = 3
            elif change == "late":snapshot["observed_monotonic_ns"] = 200
            elif change == "unrestricted":snapshot["system_tun_full_writes"][0]["original_room_restricted"] = [False]
            elif change == "empty":snapshot["system_tun_full_writes"][0]["original_room_captured"] = []
            elif change == "ordering":snapshot["system_tun_full_writes"][0]["authenticated_observed_monotonic_ns"] = 101
            elif change == "duplicate":snapshot["historical_full_packets"] *= 2
            elif change == "coverage":snapshot["historical_full_packets"][0]["spans"] = [dict(slot=6,start=0,end=1)]
            else:row["original_request_room"]["known"] = False
            with self.subTest(change=change), self.assertRaises(ValueError):
                historical_last_sources(snapshot, row, window)

    def test_only_exact_original_room_refusal_without_once_is_accepted(self):
        value = dict(status="stale", owner_check="room", outcome="Stale(RoomAuthority)",
            once_committed=False, physical_send_verified=False, canonical_current_owner_verified=False,
            native_os_write_verified=False, commit_monotonic_ns=None)
        refused_credit(value)
        for field, bad in [("status","contended"),("owner_check","emit"),("outcome","Stale(Lifecycle)"),
                           ("once_committed",True),("physical_send_verified",True),
                           ("canonical_current_owner_verified",True),("commit_monotonic_ns",1)]:
            with self.subTest(field=field), self.assertRaises(ValueError):refused_credit(dict(value, **{field:bad}))

    def test_original32_remains_unchanged_and_supplement_unknowns_keep_all16_slots(self):
        original = original_manifest("a"*32,"b"*32)
        entries = manifest("a"*32,"b"*32)
        self.assertEqual(len(original),4)
        self.assertEqual(len(entries),2)
        result = summarize(entries)
        self.assertEqual(result["prescheduled_requests"],16)
        self.assertEqual(result["terminal_counts"],dict(not_started=16))
        self.assertFalse(result["all_responses_observed"])
        entries[0]["count"] = 7
        with self.assertRaises(ValueError):summarize(entries)

    def exit_model(self):
        return dict(scope=SCOPE, passed=True, original_write_observations=dict(passed=True),
                    kernel_control_cleanup=dict(complete=True),
                    original_kernel_read_observations=dict(passed=False, full128_owner_evidence_complete=False),
                    room_revocation=dict(scope="actual_survivor_original_room_refusal", passed=True))

    def test_expected_negative_report_exits_zero_without_claiming_all_positive_native_credit(self):
        report = self.exit_model()
        self.assertTrue(kernel_evidence_passed(report, room_revocation=True))
        self.assertEqual(exit_status(report, write_facts=True, kernel_read_facts=True, room_revocation=True), 0)
        self.assertFalse(report["original_kernel_read_observations"]["passed"])
        self.assertEqual(exit_status(report, write_facts=True, kernel_read_facts=True, room_revocation=False), 1)

    def test_negative_exit_still_requires_writes_cleanup_report_and_exact_explicit_scope(self):
        for change in ["write", "cleanup", "report", "negative", "scope", "negative_scope", "missing"]:
            report = self.exit_model()
            if change == "write":report["original_write_observations"]["passed"] = False
            elif change == "cleanup":report["kernel_control_cleanup"]["complete"] = False
            elif change == "report":report["passed"] = False
            elif change == "negative":report["room_revocation"]["passed"] = False
            elif change == "scope":report["scope"] = "linux_same_host_kernel_tun_application"
            elif change == "negative_scope":report["room_revocation"]["scope"] = "label_only"
            else:report.pop("room_revocation")
            with self.subTest(change=change):
                self.assertEqual(exit_status(report, write_facts=True, kernel_read_facts=True, room_revocation=True), 1)
        for writes, kernel in [(False,True),(True,False),(False,False)]:
            self.assertEqual(exit_status(self.exit_model(), write_facts=writes, kernel_read_facts=kernel, room_revocation=True), 1)

    def test_positive_exit_boolean_models_preserve_original_constructor_and_cleanup_rule(self):
        for scope in ["normal", "blackhole", "stall", "relay"]:
            for healthy, native_passed, complete, writes, cleanup in itertools.product([False,True], repeat=5):
                passed = healthy and native_passed and complete
                report = dict(scope=scope, passed=passed, original_write_observations=dict(passed=writes),
                    kernel_control_cleanup=dict(complete=cleanup),
                    original_kernel_read_observations=dict(passed=native_passed,full128_owner_evidence_complete=complete),
                    room_revocation=dict(scope="actual_survivor_original_room_refusal",passed=True))
                expected = int(not passed or not writes or not(native_passed and cleanup))
                self.assertEqual(exit_status(report,write_facts=True,kernel_read_facts=True,room_revocation=False),expected)

    def test_positive_scope_never_accepts_missing_or_incomplete_native_sources(self):
        for value in [None, {}, dict(passed=True), dict(passed=True,full128_owner_evidence_complete=False),
                      dict(passed="true",full128_owner_evidence_complete=True)]:
            report = self.exit_model();report["original_kernel_read_observations"] = value
            self.assertFalse(kernel_evidence_passed(report,room_revocation=False))
            self.assertEqual(exit_status(report,write_facts=True,kernel_read_facts=True,room_revocation=False),1)


if __name__ == "__main__":
    unittest.main()
