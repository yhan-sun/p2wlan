import unittest

from linux_tun_startup import summarize


class StartupAttribution(unittest.TestCase):
    def sample(self):
        clock = dict(join_requested_ns=100, boot_id="one")
        write = dict(sequence=0, request_nonce="request", original_sent_ns=200,
                     original_deadline_ns=1000, accepted_in_original_deadline=True)
        record = dict(sequence=0, request_nonce="request", status="success", sent_offset_ns=10,
                      completed_offset_ns=40, rtt_ns=30)
        native = dict(sequence=0, request_nonce="request", full128_owner_qualified=True,
                      source_native_transaction=dict(matched=True, physical_path="udp", commit_monotonic_ns=210),
                      response_native_transaction=dict(matched=True, physical_path="udp", commit_monotonic_ns=260))
        entry = dict(protocol="udp", direction="a-to-b", count=2, records=[record],
                     original_write_stream=dict(original_same_boot_clock_matched=True,
                                                original_child_binding=dict(boot_id="one"), requests=[write]),
                     original_kernel_reads=dict(requests=[native]))
        return clock, entry, native

    def test_first_direct_waits_for_both_legs_and_retains_missing_requests(self):
        clock, entry, _ = self.sample()
        report = summarize(clock, [entry])
        self.assertEqual(report["first_success_ms_by_direction"], {"a-to-b": .00013})
        self.assertEqual(report["first_native_direct_ms_by_direction"], {"a-to-b": .00016})
        self.assertIsNone(report["bidirectional_observed_by_5s"])
        self.assertEqual(report["terminal_counts"], {"success": 1, "not_observed": 1})

    def test_stale_boot_wrong_path_and_duplicate_rows(self):
        clock, entry, native = self.sample()
        self.assertFalse(summarize(dict(clock, boot_id="two"), [entry])["first_success_ms_by_direction"])
        native["response_native_transaction"].pop("physical_path")
        self.assertEqual(summarize(clock, [entry])["native_request_response_paths"], {"missing_native_evidence": 1})
        entry["original_kernel_reads"]["requests"].append(native)
        with self.assertRaises(ValueError):
            summarize(clock, [entry])
