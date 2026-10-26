import errno
import json
import socket
import threading
import time
import unittest
from unittest.mock import patch

import tcp_business_probe as tool
import tcp_socket_observation as observation
from udp_business_probe import Config, UNVERIFIED


class TcpObservationIntegration(unittest.TestCase):
    def fixture(self, timeout=200):
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.bind(("127.0.0.1", 0)); listener.bind(("127.0.0.1", 0))
        a, b = client.getsockname(), listener.getsockname()
        probe = Config(a, b, "11" * 16, "22" * 16, 2, 20, timeout, 1000, 16)
        echo = Config(b, a, probe.run_nonce, probe.round_nonce, 2, 20, timeout, 1000, 16)
        return client, listener, probe, echo

    def run_pair(self, enabled):
        client, listener, probe, echo = self.fixture()
        ready, result = threading.Event(), {}
        worker = threading.Thread(target=lambda: result.update(echo=tool.run_echo(echo, listener, ready.set, observe_tcp=enabled)))
        worker.start()
        try:
            self.assertTrue(ready.wait(1))
            result["probe"] = tool.run_probe(probe, client, observe_tcp=enabled)
        finally:
            client.close(); worker.join(2); listener.close()
        self.assertFalse(worker.is_alive())
        self.assertEqual([r["status"] for r in tool.validate_probe(result["probe"])], ["success"] * 2,
                         json.dumps(result))
        self.assertEqual(result["probe"]["connection_attempts"], 1)
        self.assertEqual(result["probe"]["evidence"], UNVERIFIED)
        self.assertEqual(result["echo"]["accepted_connections"], 1)
        return result

    def test_default_does_not_construct_observer_or_change_report_shape(self):
        with patch.object(observation, "SocketObservation", side_effect=AssertionError("default must not observe")):
            result = self.run_pair(False)
        for report in result.values():
            self.assertNotIn("tcp_observation", report)
            self.assertNotIn("application_service_intervals", report)

    def test_opt_in_samples_existing_connections_and_binds_local_service_intervals_to_exact_nonce(self):
        result = self.run_pair(True)
        for report in result.values():
            row = report["tcp_observation"]
            self.assertEqual(row["availability"], "available", row)
            self.assertEqual(len(row["samples"]), 2)
            self.assertFalse(row["request_attribution_verified"])
            self.assertFalse(row["native_owner_credit_verified"])
        rows = result["echo"]["application_service_intervals"]
        self.assertEqual(len(rows), 2)
        for original, service in zip(result["probe"]["requests"], rows):
            self.assertEqual((original["sequence"], original["request_nonce"]),
                             (service["sequence"], service["request_nonce"]))
            self.assertEqual(service["status"], "response_complete")
            self.assertLessEqual(service["request_read_complete_ns"], service["response_write_started_ns"])
            self.assertLessEqual(service["response_write_started_ns"], service["response_write_returned_ns"])

    def test_native_counter_unavailable_does_not_retry_or_change_business_outcomes(self):
        with patch.object(observation, "_native", side_effect=OSError(errno.ENOPROTOOPT, "unsupported")) as native:
            result = self.run_pair(True)
        self.assertEqual(native.call_count, 4)  # Two original samples per endpoint.
        for report in result.values():
            self.assertEqual(report["tcp_observation"]["availability"], "unavailable")
            self.assertEqual(len(report["tcp_observation"]["samples"]), 2)

    def test_opt_in_preserves_stream_timeout_and_fixed_unsent_denominator(self):
        client, listener, probe, _ = self.fixture(timeout=30)
        listener.listen(1)
        errors = []
        def stalled():
            try:
                connection, _ = listener.accept()
                with connection:
                    frame = tool.decode(tool.read_frame(connection, time.monotonic_ns() + 1_000_000_000))
                    self.assertIsNotNone(frame)
                    time.sleep(.08)
            except BaseException as error:
                errors.append(error)
        worker = threading.Thread(target=stalled); worker.start()
        try:
            report = tool.run_probe(probe, client, observe_tcp=True)
        finally:
            client.close(); worker.join(2); listener.close()
        self.assertFalse(worker.is_alive()); self.assertEqual(errors, [])
        self.assertEqual([r["status"] for r in tool.validate_probe(report)], ["timeout", "not_sent"])
        self.assertEqual(report["termination_reason"], "stream_deadline")
        self.assertEqual(report["connection_attempts"], 1)
        self.assertEqual(report["configuration"]["timeout_ms"], 30)
        self.assertEqual(len(report["tcp_observation"]["samples"]), 2)


if __name__ == '__main__':
    unittest.main()
