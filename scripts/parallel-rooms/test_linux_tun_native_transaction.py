"""Serialized-data comparisons only; these fixtures certify no kernel or IO fact."""
import copy
import unittest

import linux_tun_native_transaction as native


def data(protocol="tcp", kind="request"):
    """Plain dictionaries for comparison; no KernelCaptures or owner is built."""
    length = 195 if protocol == "tcp" else 1
    spans = [dict(slot=0, start=0, end=length)]
    credit = dict(status="committed", once_committed=True, physical_send_verified=True,
                  canonical_current_owner_verified=True, native_os_write_verified=False,
                  commit_monotonic_ns=180, network_generation=0, physical_path="udp",
                  original_kernel_read_ordinals=[2], original_system_write_ordinals=[3],
                  original_non_delivery_attempts=[[1, 7]])
    row = dict(flow=0, sequence=0, protocol=protocol, kind=kind, native_credit=credit,
               original_peer=dict(known=True, network_generation=0, peer_lifecycle=1))
    packet = dict(read_ordinal=2, flow=0, read_monotonic_ns=120,
                  publication_observed_monotonic_ns=130, full_observed_monotonic_ns=160,
                  encryption_generation=0, encryption_peer_lifecycle=1,
                  encryption_session_instance=11, physical_path="udp", spans=copy.deepcopy(spans))
    write = dict(write_ordinal=3, flow=0, authenticated_observed_monotonic_ns=140,
                 write_observed_monotonic_ns=150, scope="original_authenticated_system_tun_full_history_only",
                 network_generation=0, peer_lifecycle=1, original_session_role="active",
                 session_instance=11, canonical_current_owner_verified=False,
                 spans=copy.deepcopy(spans), original_room_captured=[True])
    if kind == "response":
        write.update(authenticated_observed_monotonic_ns=105, write_observed_monotonic_ns=110)
    snapshot = dict(historical_full_packets=[packet], system_tun_full_writes=[write])
    window = dict(original_sent_ns=100, original_deadline_ns=200, received_monotonic_ns=115)
    return snapshot, row, window


class ComparisonControls(unittest.TestCase):
    def test_destination_family_requires_original_udp_full(self):
        snapshot, row, window = data("udp", "request")
        packet = snapshot["historical_full_packets"][0]
        self.assertNotIn("udp_destination_family", native.frame_comparison(snapshot, row, window))
        packet["udp_destination_family"] = "ipv6"
        self.assertEqual(native.frame_comparison(snapshot, row, window)["udp_destination_family"], "ipv6")
        packet["physical_path"] = row["native_credit"]["physical_path"] = "relay"
        self.assertNotIn("udp_destination_family", native.frame_comparison(snapshot, row, window))

    def rejects(self, values, code):
        with self.assertRaises(native.ComparisonError) as caught:
            native.frame_comparison(*values)
        self.assertEqual(caught.exception.code, code)

    def test_comparison_matches_data_without_claiming_os_or_owner_authority(self):
        for protocol in ["udp", "tcp"]:
            for kind in ["request", "response"]:
                values = data(protocol, kind)
                before = copy.deepcopy(values)
                result = native.frame_comparison(*values)
                self.assertTrue(result["matched"])
                self.assertFalse(any("verified" in key for key in result))
                self.assertEqual(values, before)

    def test_terminal_unknown_or_changed_once_flags_are_rejected(self):
        changes = [dict(status=status) for status in ["unknown", "stale", "contended", "already_committed"]]
        changes += [dict(once_committed=False), dict(once_committed=1), dict(physical_send_verified=False),
                    dict(canonical_current_owner_verified=False), dict(native_os_write_verified=True)]
        for change in changes:
            with self.subTest(change=change):
                values = data()
                values[1]["native_credit"].update(change)
                self.rejects(values, "native_frame_original_once_missing")

    def test_original_half_open_commit_deadline_and_clock_types(self):
        for point in [None, True, 114, 200, 201, 1 << 64]:
            values = data()
            values[1]["native_credit"]["commit_monotonic_ns"] = point
            self.rejects(values, "native_frame_original_commit_deadline")
        for key, value in [("original_sent_ns", True), ("original_deadline_ns", 100),
                           ("received_monotonic_ns", 99)]:
            values = data()
            values[2][key] = value
            self.rejects(values, "native_frame_original_commit_deadline")

    def test_flow_slot_peer_and_path_identity(self):
        for key, value in [("flow", True), ("sequence", 8), ("sequence", False),
                           ("protocol", "quic"), ("kind", "other")]:
            values = data()
            values[1][key] = value
            self.rejects(values, "native_frame_flow_identity")
        for target, change in [("original_peer", dict(known=False)), ("original_peer", dict(peer_lifecycle=0)),
                               ("original_peer", dict(network_generation=False)),
                               ("native_credit", dict(network_generation=1)),
                               ("native_credit", dict(network_generation=False)),
                               ("native_credit", dict(physical_path="mixed"))]:
            values = data()
            values[1][target].update(change)
            self.rejects(values, "native_frame_first_peer_identity")

    def test_missing_duplicate_unsorted_or_changed_original_ordinals(self):
        for key in ["original_kernel_read_ordinals", "original_system_write_ordinals"]:
            for ids in [[], [True], [0], [2, 2], [3, 2], list(range(1, 1026))]:
                values = data()
                values[1]["native_credit"][key] = ids
                self.rejects(values, "native_frame_original_source_ordinals")
        for history in ["historical_full_packets", "system_tun_full_writes"]:
            values = data()
            values[0][history] *= 2
            self.rejects(values, "native_frame_duplicate_history_ordinal")
            values = data()
            values[0][history] = []
            self.rejects(values, "native_frame_original_full_missing" if history == "historical_full_packets"
                         else "native_frame_original_system_write_missing")

    def test_full_publication_time_lifecycle_session_and_path(self):
        for change in [dict(flow=True), dict(flow=1), dict(read_monotonic_ns=99),
                       dict(publication_observed_monotonic_ns=119), dict(full_observed_monotonic_ns=181),
                       dict(encryption_generation=False), dict(encryption_generation=1),
                       dict(encryption_peer_lifecycle=True), dict(encryption_peer_lifecycle=2),
                       dict(encryption_session_instance=0), dict(physical_path="relay")]:
            values = data()
            values[0]["historical_full_packets"][0].update(change)
            self.rejects(values, "native_frame_original_full_identity_or_time")
        values = data()
        values[0]["historical_full_packets"][0]["encryption_session_instance"] = 12
        self.rejects(values, "native_frame_incomplete_or_mixed_session")

    def test_authenticated_write_lifecycle_role_room_and_time(self):
        for change in [dict(scope="expected_inputs_only"), dict(flow=True), dict(flow=1),
                       dict(authenticated_observed_monotonic_ns=99), dict(write_observed_monotonic_ns=181),
                       dict(network_generation=True), dict(peer_lifecycle=True), dict(peer_lifecycle=2),
                       dict(original_session_role="previous"), dict(session_instance=0),
                       dict(canonical_current_owner_verified=True)]:
            values = data()
            values[0]["system_tun_full_writes"][0].update(change)
            self.rejects(values, "native_frame_original_write_identity_or_time")
        for rooms in [[], [False], [1], [True, True]]:
            values = data()
            values[0]["system_tun_full_writes"][0]["original_room_captured"] = rooms
            self.rejects(values, "native_frame_original_write_room_missing")

    def test_fragment_holes_invalid_spans_and_noncontributors(self):
        for history in ["historical_full_packets", "system_tun_full_writes"]:
            for spans, code in [([], "native_frame_span_capacity"),
                                ([dict(slot=True, start=0, end=195)], "native_frame_span_shape"),
                                ([dict(slot=0, start=0, end=196)], "native_frame_span_shape"),
                                ([dict(slot=1, start=0, end=195)], "native_frame_noncontributing_source"),
                                ([dict(slot=0, start=1, end=195)], "native_frame_incomplete_or_mixed_session")]:
                values = data()
                values[0][history][0]["spans"] = spans
                self.rejects(values, code)

    def test_earliest_partial_sources_and_delayed_retention_are_compared(self):
        values = data()
        original = values[0]["historical_full_packets"][0]
        original["spans"][0]["end"] = 100
        later = copy.deepcopy(original)
        later.update(read_ordinal=4, read_monotonic_ns=125)
        later["spans"] = [dict(slot=0, start=50, end=195)]
        values[0]["historical_full_packets"].append(later)
        values[1]["native_credit"]["original_kernel_read_ordinals"] = [2, 4]
        self.assertTrue(native.frame_comparison(*values)["matched"])
        # Retention may run after RX authentication; actual native provenance
        # checks the original publication point, never this later retention.
        original["full_observed_monotonic_ns"] = 175
        self.assertTrue(native.frame_comparison(*values)["matched"])
        later["publication_observed_monotonic_ns"] = 145
        self.rejects(values, "native_frame_response_before_original_full")

    def test_response_requires_original_request_write_before_response_read(self):
        values = data(kind="response")
        values[0]["system_tun_full_writes"][0]["write_observed_monotonic_ns"] = 121
        self.rejects(values, "native_frame_response_read_before_original_request_write")

    def test_non_delivery_fence_data_cannot_substitute_selected_reads(self):
        for skipped in [None, [[2, 7]], [[3, 7]], [[1, 0]], [[True, 7]], [[1, True]],
                        [[1, 7], [1, 8]], [[1, 7]] * 1025]:
            values = data()
            values[1]["native_credit"]["original_non_delivery_attempts"] = skipped
            self.rejects(values, "native_frame_original_non_delivery_fences")


class PerRecordComparisonControls(unittest.TestCase):
    def test_reported_relay_path_requires_the_same_original_full_path(self):
        values = data()
        values[1]["native_credit"]["physical_path"] = "relay"
        values[0]["historical_full_packets"][0]["physical_path"] = "relay"
        self.assertEqual(native.frame_comparison_or_gap(*values)["physical_path"], "relay")
        values[1]["native_credit"]["physical_path"] = "udp"
        self.assertEqual(native.frame_comparison_or_gap(*values),
                         dict(matched=False, gap_reason="native_frame_original_full_identity_or_time"))

    def test_one_terminal_gap_retains_all_eight_serialized_results_and_the_failure(self):
        for status in ["unknown", "stale", "contended", "already_committed"]:
            inputs = [data() for _ in range(8)]
            inputs[2][1]["native_credit"].update(status=status, once_committed=False)
            before = copy.deepcopy(inputs)
            results = [native.frame_comparison_or_gap(*values) for values in inputs]
            self.assertEqual(len(results), 8)
            self.assertEqual([i for i, row in enumerate(results) if not row["matched"]], [2])
            self.assertEqual(results[2], dict(matched=False, gap_reason="native_frame_original_once_missing"))
            self.assertFalse(all(row["matched"] for row in results))
            self.assertEqual(inputs, before)

    def test_half_open_original_deadline_failure_is_kept_without_losing_later_slots(self):
        inputs = [data() for _ in range(8)]
        inputs[0][1]["native_credit"]["commit_monotonic_ns"] = 200
        results = [native.frame_comparison_or_gap(*values) for values in inputs]
        self.assertEqual(results[0], dict(matched=False, gap_reason="native_frame_original_commit_deadline"))
        self.assertTrue(all(row["matched"] for row in results[1:]))
        self.assertFalse(all(row["matched"] for row in results))
        self.assertTrue(all(not any("verified" in key for key in row) for row in results))

    def test_success_data_is_identical_and_unexpected_programming_errors_are_not_swallowed(self):
        values = data()
        self.assertEqual(native.frame_comparison_or_gap(*values), native.frame_comparison(*values))
        with self.assertRaises(AttributeError):
            native.frame_comparison_or_gap(values[0], None, values[2])


if __name__ == "__main__":
    unittest.main()
