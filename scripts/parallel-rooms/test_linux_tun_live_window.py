"""Actual control-socket and pure metadata controls, without TUN/native credit."""
import json
import os
import socket
from types import SimpleNamespace
import unittest

from linux_tun_kernel_capture import Endpoint
from linux_tun_live_window import OriginalWriteWindows


@unittest.skipUnless(os.name == "posix" and hasattr(socket, "AF_UNIX"), "actual Unix control sockets required")
class ControlSocketTests(unittest.TestCase):
    def pair(self):
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(right.close)
        endpoint = Endpoint(left, None, None, "a" * 32, "b" * 32)
        self.addCleanup(endpoint.close)
        return endpoint, right

    def test_actual_socket_sends_one_metadata_record_without_waiting_for_reply(self):
        endpoint, peer = self.pair()
        endpoint.connection.settimeout(1)
        endpoint.observe_original_write_window(dict(sequence=0))
        peer.settimeout(1)
        raw = peer.recv(512)
        self.assertEqual(json.loads(raw), dict(op="observe_original_write_window", window=dict(sequence=0)))
        self.assertEqual(endpoint.connection.gettimeout(), 0)
        self.assertEqual(endpoint.output_bytes, len(raw))
        self.assertEqual(endpoint.pending, b"")

    def test_actual_socket_backpressure_closes_channel_without_retry_or_buffer(self):
        endpoint, _ = self.pair()
        endpoint.connection.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        capacity = endpoint.connection.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
        self.assertLessEqual(capacity, 1024 * 1024)
        endpoint.connection.setblocking(False)
        for _ in range(capacity + 1):
            try:
                endpoint.connection.send(b"x")
            except BlockingIOError:
                break
        else:
            self.fail("bounded actual socket buffer did not reach backpressure")
        with self.assertRaises(BlockingIOError):
            endpoint.observe_original_write_window(dict(sequence=0))
        self.assertIsNone(endpoint.connection)
        self.assertEqual(endpoint.pending, b"")
        self.assertEqual(endpoint.output_bytes, 0)
        with self.assertRaises(ValueError):
            endpoint.observe_original_write_window(dict(sequence=0))

    def test_actual_partial_control_write_cannot_be_completed_by_later_observation(self):
        endpoint, peer = self.pair()
        original = endpoint.connection

        class Partial:
            def setblocking(self, value):
                original.setblocking(value)

            def send(self, raw):
                return original.send(raw[:7])

            def close(self):
                original.close()

        endpoint.connection = Partial()
        with self.assertRaisesRegex(ValueError, "short_control_write"):
            endpoint.observe_original_write_window(dict(sequence=0))
        self.assertEqual(peer.recv(512), b'{"op":"')
        self.assertIsNone(endpoint.connection)
        with self.assertRaises(ValueError):
            endpoint.observe_original_write_window(dict(sequence=1))


class MetadataControls(unittest.TestCase):
    """Hypothetical validated inputs exercise delivery; they prove no OS source."""
    def bridge(self):
        class Capture:
            pass
        capture = Capture()
        original = SimpleNamespace(unavailable_reason=None, boot_id="11111111-2222-3333-4444-555555555555")
        rows = [dict(sequence=i, complete=False) for i in range(8)]
        rows[0] = dict(sequence=0, complete=True, original_sent_ns=100,
                       original_deadline_ns=200, last_returned_ns=101)
        capture.stream = SimpleNamespace(child=original, gap=None, owner_verified=True, clock_verified=True,
                                         records=5, headers=[None] * 5,
                                         requests=rows, started=1, expected_frames=[(191, "a" * 64)] * 8,
                                         accepted_in_time=lambda r: r["complete"])
        capture.prepared = SimpleNamespace(producer_scope="b" * 32, nonces=[f"{i:032x}" for i in range(8)])
        sent = []
        endpoints = [SimpleNamespace(observe_original_write_window=lambda w: sent.append(dict(w))) for _ in range(2)]
        bridge = OriginalWriteWindows(capture, endpoints)
        bridge.bind(capture, SimpleNamespace(returncode=None))
        self.assertFalse(bridge.summary()["native_os_write_verified"])
        self.assertFalse(bridge.summary()["canonical_current_owner_verified"])
        return capture, bridge, sent

    def test_first_live_delivery_is_one_shot_and_sealing_prevents_final_catchup(self):
        capture, bridge, sent = self.bridge()
        bridge.observe(capture, 102)
        self.assertEqual(len(sent), 2)
        self.assertEqual(sent[0]["original_deadline_ns"], 200)
        bridge.observe(capture, 103)
        self.assertEqual(len(sent), 2)
        bridge.seal()
        capture.stream.requests[1] = dict(sequence=1, complete=True, original_sent_ns=110,
                                          original_deadline_ns=210, last_returned_ns=111)
        bridge.observe(capture, 112)
        self.assertEqual(len(sent), 2)
        self.assertFalse(bridge.summary()["requests"][1]["delivered"])

    def test_incomplete_ordered_headers_wait_without_delivery_or_terminal_identity_failure(self):
        capture, bridge, sent = self.bridge()
        for count in range(5):
            capture.stream.records = count
            capture.stream.owner_verified = count >= 3
            capture.stream.clock_verified = count >= 4
            bridge.observe(capture, 102)
            self.assertIsNone(bridge.gap)
            self.assertEqual(bridge.seen, set())
            self.assertEqual(sent, [])
        capture.stream.records = 5
        bridge.observe(capture, 103)
        self.assertEqual(len(sent), 2)
        self.assertEqual(bridge.seen, {0})
        self.assertEqual(sent[0]["original_sent_ns"], 100)
        self.assertEqual(sent[0]["original_deadline_ns"], 200)

    def test_late_first_complete_window_is_not_repaired_when_given_earlier_time(self):
        capture, bridge, sent = self.bridge()
        bridge.observe(capture, 200)
        bridge.observe(capture, 150)
        self.assertEqual(sent, [])
        self.assertEqual(bridge.summary()["requests"][0]["reason"], "original_window_live_deadline_missed")

    def test_unknown_clock_retired_child_and_foreign_stream_do_not_deliver(self):
        for change in ["clock", "child", "stream"]:
            capture, bridge, sent = self.bridge()
            if change == "clock":
                capture.stream.clock_verified = False
            elif change == "child":
                bridge.child.returncode = 0
            else:
                capture.stream.child = SimpleNamespace()
            bridge.observe(capture, 102)
            self.assertEqual(sent, [])
            self.assertIsNotNone(bridge.summary()["gap_reason"])
            capture.stream.clock_verified = True
            bridge.observe(capture, 103)
            self.assertEqual(sent, [])


if __name__ == "__main__":
    unittest.main()
