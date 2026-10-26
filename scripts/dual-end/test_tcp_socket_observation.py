import copy
import errno
import socket
import struct
import sys
import unittest
from unittest.mock import patch
import tcp_socket_observation as tool


class ObservationControls(unittest.TestCase):
    def fixture(self, platform, value=7):
        _, size, counters, gauges = tool.LAYOUTS[platform]
        raw = bytearray(size)
        for fields in (counters, gauges):
            for offset, fmt, _ in fields.values():
                struct.pack_into("=" + fmt, raw, offset, value)
        return bytes(raw)

    def row(self, value=7):
        return dict(tool.decode("linux", self.fixture("linux", value)), availability="available",
                    platform="linux", started_monotonic_ns=1, finished_monotonic_ns=2,
                    connection={"descriptor": 9, "family": int(socket.AF_INET), "local": ["127.0.0.1", 12345],
                                "peer": ["127.0.0.1", 12346]})

    def test_decoders_preserve_platform_fields_units_and_cumulative_counters(self):
        expected = {"linux": {"tcpi_total_retrans": "segments"},
                    "darwin": {"tcpi_txretransmitbytes": "bytes", "tcpi_txretransmitpackets": "packets"},
                    "win32": {"BytesRetrans": "bytes"}}
        for platform, counters in expected.items():
            with self.subTest(platform=platform):
                row = tool.decode(platform, self.fixture(platform))
                self.assertEqual(row["counters"], {k: {"value": 7, "unit": v} for k, v in counters.items()})
                self.assertNotIn("tcpi_retrans", row["counters"])

    def test_all_layouts_reject_short_extra_and_nonbytes_without_guessed_offsets(self):
        for platform in tool.LAYOUTS:
            raw = self.fixture(platform)
            for malformed in (raw[:-1], raw + b"x", bytearray(raw)):
                with self.subTest(platform=platform, length=len(malformed)), self.assertRaises(ValueError):
                    tool.decode(platform, malformed)
        with self.assertRaises(ValueError):
            tool.decode("other", b"x" * 112)

    def test_interval_preserves_zero_and_never_guesses_counter_wrap(self):
        first = self.row()
        for value in (7, 12, 1):
            last = self.row(value); last.update(started_monotonic_ns=3, finished_monotonic_ns=4)
            counter = tool.interval(first, last)["counters"]["tcpi_total_retrans"]
            if value < 7:
                self.assertEqual(counter["reason"], "counter_decreased")
                self.assertNotIn("delta", counter)
            else:
                self.assertEqual(counter["delta"], value - 7)

    def test_interval_rejects_replacement_or_reversed_clock(self):
        first = self.row(); last = self.row(12); last.update(started_monotonic_ns=3, finished_monotonic_ns=4)
        for mutate in (lambda x: x["connection"].update(descriptor=10), lambda x: x.update(api="another"),
                       lambda x: x.update(platform="darwin"), lambda x: x.update(started_monotonic_ns=1)):
            modified = copy.deepcopy(last); mutate(modified)
            self.assertEqual(tool.interval(first, modified)["availability"], "unavailable")
        first["availability"] = "unavailable"
        self.assertEqual(tool.interval(first, last)["reason"], "incomplete_samples")

    def test_no_connected_socket_invents_neither_sample_nor_native_call(self):
        observation = tool.SocketObservation()
        with patch.object(tool, "_native", side_effect=AssertionError("must not read")):
            result = observation.finish()
        self.assertEqual(result["samples"], [])
        self.assertFalse(result["request_attribution_verified"])
        self.assertFalse(result["native_owner_credit_verified"])
        with self.assertRaises(ValueError):
            observation.finish()

    def test_real_connection_two_samples_keep_socket_settings_and_ownership(self):
        if sys.platform not in tool.LAYOUTS:
            self.skipTest("no native decoder for this host")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0)); listener.listen(1)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
                client.settimeout(.5); client.connect(listener.getsockname())
                accepted, _ = listener.accept()
                with accepted:
                    observation = tool.SocketObservation(); observation.begin(client)
                    client.sendall(b"sample"); self.assertEqual(accepted.recv(6), b"sample")
                    accepted.sendall(b"echo"); self.assertEqual(client.recv(4), b"echo")
                    result = observation.finish()
                    self.assertEqual(len(result["samples"]), 2)
                    self.assertEqual(result["availability"], "available", result)
                    self.assertEqual(client.gettimeout(), .5)
                    self.assertGreaterEqual(client.fileno(), 0)
                    self.assertEqual(result["samples"][0]["connection"], result["samples"][1]["connection"])
                    with self.assertRaises(ValueError):
                        observation.begin(client)

    def test_information_error_is_explicit_and_not_retried(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0)); listener.listen(1)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
                client.connect(listener.getsockname()); accepted, _ = listener.accept()
                with accepted, patch.object(tool, "_native", side_effect=OSError(errno.ENOPROTOOPT, "no information")) as native:
                    result = tool.sample(client)
                    self.assertEqual(native.call_count, 1)
                    self.assertEqual(result["availability"], "unavailable")
                    self.assertEqual(result["errno"], errno.ENOPROTOOPT)

    def test_closed_or_non_tcp_socket_has_no_zero_counter_fallback(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            result = tool.sample(udp)
            self.assertEqual(result["availability"], "unavailable")
            self.assertNotIn("counters", result)
        result = tool.sample(udp)
        self.assertEqual(result["availability"], "unavailable")
        self.assertNotIn("counters", result)


if __name__ == '__main__':
    unittest.main()
