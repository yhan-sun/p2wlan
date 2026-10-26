#!/usr/bin/env python3
"""Real local TCP controls; no kernel TUN or remote-device claim."""
import copy
import errno
import json
import socket
import struct
import threading
import time
import unittest
from unittest.mock import patch

import tcp_business_probe as tool
from udp_business_probe import Config, UNVERIFIED


class TcpControls(unittest.TestCase):
    def test_early_sleep_wakeup_waits_original_target_and_total_deadline(self):
        for planned, end in [(10_000_000, 50_000_000), (50_000_000, 10_000_000)]:
            now = [0]
            sleeps = []

            def early_sleep(seconds):
                sleeps.append(seconds)
                now[0] += 6_000_000 if len(sleeps) == 1 else 4_000_000

            with self.subTest(planned=planned, end=end), patch.object(tool.time, "monotonic_ns", side_effect=lambda: now[0]), patch.object(tool.time, "sleep", side_effect=early_sleep):
                tool.wait_scheduled(planned, end)
            self.assertEqual(sleeps, [.01, .004])
            self.assertEqual(now[0], min(planned, end))

    def fixture(self, count=2, timeout_ms=200):
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.bind(("127.0.0.1", 0))
        listener.bind(("127.0.0.1", 0))
        a, b = client.getsockname(), listener.getsockname()
        probe = Config(a, b, "11" * 16, "22" * 16, count, 20, timeout_ms, 1000, 16)
        echo = Config(b, a, probe.run_nonce, probe.round_nonce, count, 20, timeout_ms, 1000, 16)
        return client, listener, probe, echo

    def test_actual_one_connection_two_matching_responses_and_socket_cleanup(self):
        client, listener, probe, echo = self.fixture()
        ready = threading.Event()
        result = {}
        worker = threading.Thread(target=lambda: result.update(echo=tool.run_echo(echo, listener, ready.set)))
        worker.start()
        try:
            self.assertTrue(ready.wait(1))
            report = tool.run_probe(probe, client)
        finally:
            client.close()
            worker.join(2)
            listener.close()
        self.assertFalse(worker.is_alive())
        records = tool.validate_probe(report)
        self.assertEqual(
            [r["status"] for r in records], ["success", "success"],
            msg=json.dumps({"original_probe_report": report,
                            "original_echo_report": result.get("echo"),
                            "echo_worker_alive_after_join": worker.is_alive()},
                           sort_keys=True),
        )
        self.assertEqual(result["echo"]["responses_sent"], 2)
        self.assertEqual(result["echo"]["accepted_connections"], 1)
        self.assertNotIn("connection_attempts", result["echo"])
        self.assertEqual(report["connection_attempts"], 1)
        self.assertEqual(report["evidence"], UNVERIFIED)

    def test_wrong_request_response_cannot_credit_and_no_reconnect(self):
        client, listener, probe, _ = self.fixture()
        listener.listen(1)
        def peer():
            connection, _ = listener.accept()
            with connection:
                frame = tool.decode(tool.read_frame(connection, time.monotonic_ns() + 1_000_000_000))
                wrong = tool.encode(probe, frame[3], "33" * 16, tool.RESPONSE)
                tool.write_frame(connection, wrong, time.monotonic_ns() + 1_000_000_000)
                time.sleep(.3)
        worker = threading.Thread(target=peer)
        worker.start()
        try:
            report = tool.run_probe(probe, client)
        finally:
            client.close()
            worker.join(2)
            listener.close()
        self.assertFalse(worker.is_alive())
        self.assertEqual([r["status"] for r in tool.validate_probe(report)], ["timeout", "not_sent"])
        self.assertEqual(report["invalid_frames"], 1)
        self.assertEqual(report["connection_attempts"], 1)

    def test_actual_connection_refusal_keeps_every_original_request(self):
        client, listener, probe, _ = self.fixture(count=3)
        listener.close()
        try:
            report = tool.run_probe(probe, client)
        finally:
            client.close()
        self.assertEqual([r["status"] for r in tool.validate_probe(report)], ["not_sent"] * 3)
        self.assertEqual(report["termination_reason"], "connect_failed")
        self.assertEqual(report["socket_error_errno"], errno.ECONNREFUSED)
        self.assertEqual(report["connection_attempts"], 1)

    def test_actual_bind_failure_does_not_invent_a_connect_attempt(self):
        occupied, listener, probe, _ = self.fixture()
        try:
            report = tool.run_probe(probe)
        finally:
            occupied.close()
            listener.close()
        self.assertEqual(report["termination_reason"], "bind_failed")
        self.assertEqual(report["socket_error_errno"], errno.EADDRINUSE)
        self.assertEqual(report["connection_attempts"], 0)
        self.assertEqual([r["status"] for r in tool.validate_probe(report)], ["not_sent"] * probe.count)

    def test_actual_echo_bind_failure_has_no_accept_connect_or_send_cost(self):
        client, occupied, _, echo = self.fixture()
        try:
            report = tool.run_echo(echo)
        finally:
            client.close()
            occupied.close()
        self.assertEqual(report["termination_reason"], "bind_failed")
        self.assertEqual(report["socket_error_errno"], errno.EADDRINUSE)
        self.assertEqual(report["accepted_connections"], 0)
        self.assertNotIn("connection_attempts", report)
        self.assertEqual((report["send_errors"], report["responses_sent"]), (0, 0))

    def test_actual_partial_reads_keep_one_absolute_deadline(self):
        left, right = socket.socketpair()
        frame = b"x" * tool.HEADER.size
        def peer():
            for part in (struct.pack("!I", len(frame))[:2], struct.pack("!I", len(frame))[2:], frame[:3], frame[3:]):
                right.sendall(part)
                time.sleep(.005)
            right.close()
        worker = threading.Thread(target=peer)
        worker.start()
        try:
            observed = tool.read_frame(left, time.monotonic_ns() + 200_000_000)
        finally:
            left.close()
            worker.join(1)
        self.assertFalse(worker.is_alive())
        self.assertEqual(observed, frame)

    def test_oversize_prefix_rejected_before_unbounded_read(self):
        left, right = socket.socketpair()
        right.sendall(struct.pack("!I", tool.MAX_FRAME + 1))
        try:
            with self.assertRaises(ValueError):
                tool.read_frame(left, time.monotonic_ns() + 200_000_000)
        finally:
            left.close()
            right.close()

    def test_actual_write_backpressure_obeys_shared_absolute_deadline(self):
        left, right = socket.socketpair()
        left.setblocking(False)
        try:
            while True:
                try:
                    left.send(b"x" * 4096)
                except BlockingIOError:
                    break
            started = time.monotonic()
            with self.assertRaises(TimeoutError):
                tool.write_frame(left, b"x" * tool.HEADER.size, time.monotonic_ns() + 100_000_000)
            self.assertLess(time.monotonic() - started, .5)
        finally:
            left.close()
            right.close()

    def test_validator_rejects_fake_attribution_and_changed_denominator(self):
        client, listener, probe, _ = self.fixture()
        listener.close()
        try:
            report = tool.run_probe(probe, client)
        finally:
            client.close()
        for mutate in (lambda r: r["evidence"].update(real_tun_verified=True),
                       lambda r: r["requests"].pop(),
                       lambda r: r.update(connection_attempts=2),
                       lambda r: r.update(socket_error_errno="ECONNREFUSED"),
                       lambda r: r["requests"][0].update(errno=True)):
            invalid = copy.deepcopy(report)
            mutate(invalid)
            with self.assertRaises(ValueError):
                tool.validate_probe(invalid)

    def test_legacy_errno_absence_and_unknown_null_remain_valid(self):
        client, listener, probe, _ = self.fixture()
        listener.close()
        try:
            report = tool.run_probe(probe, client)
        finally:
            client.close()
        legacy = copy.deepcopy(report)
        legacy.pop("socket_error_errno")
        tool.validate_probe(legacy)
        unknown = copy.deepcopy(legacy)
        unknown["socket_error_errno"] = None
        unknown["requests"][0]["errno"] = None
        tool.validate_probe(unknown)


if __name__ == "__main__":
    unittest.main()
