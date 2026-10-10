#!/usr/bin/env python3
"""Protocol, accounting, and loopback-only tests for OS UDP measurement."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
import copy
import io
import json
import os
from pathlib import Path
import socket
import stat
import tempfile
import threading
import unittest
from unittest.mock import patch

import udp_business_probe as probe
import udp_business_summary as summary


def loopback_socket() -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    return sock


def config_for(client: socket.socket, server: socket.socket, **changes) -> probe.Config:
    value = probe.Config(client.getsockname(), server.getsockname(), "1" * 32, "2" * 32,
                         count=3, interval_ms=5, timeout_ms=200, duration_ms=500)
    return replace(value, **changes)


def pending_record() -> dict:
    return {"sequence": 0, "request_nonce": "3" * 32, "status": "pending",
            "reason": "awaiting_echo", "planned_offset_ns": 0, "sent_offset_ns": 10,
            "completed_offset_ns": None, "rtt_ns": None}


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.config = probe.Config(("127.0.0.1", 41001), ("127.0.0.1", 41002),
                                   "1" * 32, "2" * 32, count=1,
                                   timeout_ms=100, duration_ms=100)

    def test_reply_requires_exact_run_round_request_source_kind_and_payload(self):
        record = pending_record()
        wire = probe.encode(self.config, 0, record["request_nonce"], probe.RESPONSE)
        cases = [
            (b"bad", self.config.target, "malformed"),
            (wire + b"x", self.config.target, "malformed"),
            (wire, ("127.0.0.1", 41003), "wrong_source"),
            (probe.encode(replace(self.config, run_nonce="4" * 32), 0, "3" * 32, probe.RESPONSE),
             self.config.target, "wrong_run"),
            (probe.encode(replace(self.config, round_nonce="4" * 32), 0, "3" * 32, probe.RESPONSE),
             self.config.target, "wrong_round"),
            (probe.encode(self.config, 0, "4" * 32, probe.RESPONSE), self.config.target, "wrong_request"),
            (probe.encode(self.config, 1, "3" * 32, probe.RESPONSE), self.config.target, "wrong_request"),
            (probe.encode(self.config, 0, "3" * 32, probe.REQUEST), self.config.target, "wrong_kind"),
        ]
        for data, source, reason in cases:
            with self.subTest(reason=reason):
                records = [copy.deepcopy(record)]
                self.assertEqual(probe.observe_reply(self.config, records, data, source, 20), reason)
                self.assertEqual(records[0]["status"], "pending")
        records = [record]
        self.assertEqual(probe.observe_reply(self.config, records, wire, self.config.target, 25), "accepted")
        self.assertEqual(record["rtt_ns"], 15)
        self.assertEqual(probe.observe_reply(self.config, records, wire, self.config.target, 30), "duplicate")
        self.assertEqual(record["rtt_ns"], 15)

    def test_deadline_equality_late_and_unsent_responses_are_not_successes(self):
        wire = probe.encode(self.config, 0, "3" * 32, probe.RESPONSE)
        record = pending_record()
        self.assertEqual(probe.observe_reply(self.config, [record], wire, self.config.target,
                                            10 + self.config.timeout_ms * probe.NS_PER_MS), "late")
        self.assertEqual(record["status"], "pending")
        record.update(status="timeout", completed_offset_ns=100_000_010)
        self.assertEqual(probe.observe_reply(self.config, [record], wire, self.config.target, 100_000_011), "late")
        record.update(status="not_sent", sent_offset_ns=None)
        self.assertEqual(probe.observe_reply(self.config, [record], wire, self.config.target, 20), "wrong_request")

    def test_limits_reject_unbounded_work_and_wildcard_or_multicast_endpoints(self):
        changes = [
            {"count": 0}, {"count": probe.MAX_REQUESTS + 1}, {"count": True},
            {"duration_ms": probe.MAX_DURATION_MS + 1}, {"duration_ms": float("inf")},
            {"timeout_ms": 0}, {"interval_ms": 0},
            {"payload_bytes": probe.MAX_PAYLOAD_BYTES + 1}, {"payload_bytes": -1},
            {"bind": ("0.0.0.0", 41001)}, {"target": ("224.0.0.1", 41002)},
            {"target": ("255.255.255.255", 41002)}, {"target": ("localhost", 41002)},
            {"run_nonce": "not-a-nonce"}, {"round_nonce": "A" * 32},
            {"count": 2, "interval_ms": 1, "timeout_ms": 100, "duration_ms": 100},
        ]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                replace(self.config, **change).validate()
        maximum = replace(self.config, payload_bytes=probe.MAX_PAYLOAD_BYTES)
        self.assertEqual(len(probe.encode(maximum, 0, "3" * 32, probe.REQUEST)), probe.MAX_DATAGRAM_BYTES)


class LoopbackTests(unittest.TestCase):
    def test_loopback_echo_retains_all_requests_and_summary_keeps_evidence_unknown(self):
        with loopback_socket() as client, loopback_socket() as server:
            config = config_for(client, server)
            echo_result = []
            thread = threading.Thread(target=lambda: echo_result.append(
                probe.run_echo(replace(config, bind=config.target, target=config.bind), server)))
            thread.start()
            report = probe.run_probe(config, client)
            thread.join(2)
            self.assertFalse(thread.is_alive())
        self.assertEqual([row["status"] for row in report["requests"]], ["success"] * 3)
        self.assertEqual(echo_result[0]["responses_sent"], 3)
        result = summary.summarize([report])
        self.assertEqual(result["prescheduled_requests"], 3)
        self.assertEqual(result["success_fraction"], 1)
        self.assertEqual(result["evidence"], probe.UNVERIFIED)
        self.assertIsNone(result["evidence"]["real_tun_verified"])
        self.assertIsNone(result["evidence"]["exact_direct_verified"])
        self.assertIsNone(result["evidence"]["connection_start_attribution"])

    def test_malformed_old_run_duplicate_and_lost_responses_stay_out_of_success_count(self):
        with loopback_socket() as client, loopback_socket() as server:
            config = config_for(client, server, count=2)
            failures = []

            def responder():
                try:
                    server.settimeout(1)
                    data, source = server.recvfrom(probe.MAX_DATAGRAM_BYTES)
                    sequence, nonce = probe.decode(data)[3:5]
                    responses = [
                        b"bad", b"x" * (probe.MAX_DATAGRAM_BYTES + 1),
                        probe.encode(replace(config, run_nonce="4" * 32), sequence, nonce, probe.RESPONSE),
                        probe.encode(replace(config, round_nonce="4" * 32), sequence, nonce, probe.RESPONSE),
                        probe.encode(config, sequence, "4" * 32, probe.RESPONSE),
                        probe.encode(config, sequence, nonce, probe.REQUEST),
                        probe.encode(config, sequence, nonce, probe.RESPONSE),
                        probe.encode(config, sequence, nonce, probe.RESPONSE),
                    ]
                    for response in responses:
                        server.sendto(response, source)
                    server.recvfrom(probe.MAX_DATAGRAM_BYTES)  # Deliberately no reply to request 2.
                except BaseException as error:
                    failures.append(error)

            thread = threading.Thread(target=responder)
            thread.start()
            report = probe.run_probe(config, client)
            thread.join(2)
            self.assertFalse(thread.is_alive())
            self.assertEqual(failures, [])
        result = summary.summarize([report])
        self.assertEqual(result["status_counts"]["success"], 1)
        self.assertEqual(result["status_counts"]["timeout"], 1)
        self.assertEqual(result["prescheduled_requests"], 2)
        self.assertEqual(result["success_fraction"], 0.5)
        self.assertEqual(report["receive_counts"]["duplicate"], 1)
        self.assertEqual(report["receive_counts"]["malformed"], 2)
        self.assertEqual(report["receive_counts"]["wrong_run"], 1)
        self.assertEqual(report["receive_counts"]["wrong_round"], 1)
        self.assertEqual(result["rtt"]["sample_count"], 1)

    def test_echo_only_replies_to_configured_peer_once_with_equal_size(self):
        with loopback_socket() as client, loopback_socket() as server, loopback_socket() as stranger:
            config = config_for(client, server, count=2)
            result = []
            thread = threading.Thread(target=lambda: result.append(
                probe.run_echo(replace(config, bind=config.target, target=config.bind), server)))
            thread.start()
            first = probe.encode(config, 0, "3" * 32, probe.REQUEST)
            stranger.sendto(first, config.target)
            client.sendto(b"bad", config.target)
            client.sendto(probe.encode(replace(config, run_nonce="4" * 32), 0, "3" * 32, probe.REQUEST), config.target)
            client.sendto(first, config.target)
            client.settimeout(1)
            reply, source = client.recvfrom(probe.MAX_DATAGRAM_BYTES + 1)
            self.assertEqual(source, config.target)
            self.assertEqual(len(reply), len(first))
            client.sendto(first, config.target)  # Duplicate request cannot create another echo.
            client.sendto(reply, config.target)  # An echo cannot cause an echo loop.
            second = probe.encode(config, 1, "4" * 32, probe.REQUEST)
            client.sendto(second, config.target)
            reply2, _source = client.recvfrom(probe.MAX_DATAGRAM_BYTES + 1)
            self.assertEqual(probe.decode(reply2)[3], 1)
            self.assertEqual(len(reply2), len(second))
            thread.join(2)
            self.assertFalse(thread.is_alive())
            stranger.setblocking(False)
            with self.assertRaises(BlockingIOError):
                stranger.recvfrom(probe.MAX_DATAGRAM_BYTES)
            client.setblocking(False)
            with self.assertRaises(BlockingIOError):
                client.recvfrom(probe.MAX_DATAGRAM_BYTES)
        self.assertEqual(result[0]["responses_sent"], 2)
        self.assertEqual(result[0]["response_bytes"], len(first) + len(second))
        self.assertEqual(result[0]["receive_counts"]["wrong_source"], 1)
        self.assertEqual(result[0]["receive_counts"]["duplicate"], 1)
        self.assertEqual(result[0]["receive_counts"]["wrong_kind"], 1)

    def test_no_responses_retains_all_timeouts_and_no_rtt_samples(self):
        with loopback_socket() as client, loopback_socket() as blackhole:
            config = config_for(client, blackhole, count=3, interval_ms=2, timeout_ms=20, duration_ms=50)
            report = probe.run_probe(config, client)
        result = summary.summarize([report])
        self.assertEqual(result["status_counts"]["timeout"], 3)
        self.assertEqual(result["prescheduled_requests"], 3)
        self.assertEqual(result["rtt"]["sample_count"], 0)
        self.assertIsNone(result["rtt"]["p95"])

    def test_receive_budget_exhaustion_retains_every_prescheduled_request(self):
        with loopback_socket() as client, loopback_socket() as server:
            config = config_for(client, server, count=3, interval_ms=50)

            def noise():
                server.settimeout(1)
                _data, source = server.recvfrom(probe.MAX_DATAGRAM_BYTES)
                server.sendto(b"bad", source)
                server.sendto(b"bad", source)

            thread = threading.Thread(target=noise)
            thread.start()
            with patch.object(probe, "MAX_RX_DATAGRAMS", 2):
                report = probe.run_probe(config, client)
            thread.join(2)
            self.assertFalse(thread.is_alive())
        result = summary.summarize([report])
        self.assertEqual(report["termination_reason"], "receive_budget_exhausted")
        self.assertEqual(report["received_datagrams"], 2)
        self.assertEqual(result["prescheduled_requests"], 3)
        self.assertEqual(result["success_requests"], 0)
        self.assertEqual(result["status_counts"]["cancelled"] + result["status_counts"]["not_sent"], 3)

    def test_echo_receive_error_preserves_prior_counts_and_cli_returns_failure(self):
        with loopback_socket() as client, loopback_socket() as server:
            config = config_for(client, server)
            echo_config = replace(config, bind=config.target, target=config.bind)
            wire = probe.encode(config, 0, "3" * 32, probe.REQUEST)
            client.sendto(wire, config.target)
            with patch.object(probe.select, "select", side_effect=[([server], [], []), OSError("closed")]):
                report = probe.run_echo(echo_config, server)
            client.settimeout(1)
            self.assertEqual(probe.decode(client.recvfrom(probe.MAX_DATAGRAM_BYTES)[0])[0], probe.RESPONSE)
        self.assertEqual(report["termination_reason"], "udp_receive_failed")
        self.assertEqual(report["responses_sent"], 1)
        self.assertEqual(report["received_datagrams"], 1)
        with tempfile.TemporaryDirectory() as directory:
            output_path = Path(directory) / "echo-error.json"
            arguments = ["echo", "--bind-ip", config.bind[0], "--bind-port", str(config.bind[1]),
                         "--target-ip", config.target[0], "--target-port", str(config.target[1]),
                         "--run-nonce", config.run_nonce, "--round-nonce", config.round_nonce,
                         "--output", str(output_path)]
            with patch.object(probe, "run_echo", return_value=report), redirect_stdout(io.StringIO()):
                self.assertEqual(probe.main(arguments), 1)
            self.assertEqual(json.loads(output_path.read_text())["responses_sent"], 1)
            report["termination_reason"] = "duration_deadline"
            arguments[-1] = str(Path(directory) / "echo-complete.json")
            with patch.object(probe, "run_echo", return_value=report), redirect_stdout(io.StringIO()):
                self.assertEqual(probe.main(arguments), 0)


class AccountingTests(unittest.TestCase):
    def report(self) -> dict:
        config = probe.Config(("127.0.0.1", 41001), ("127.0.0.1", 41002),
                              "1" * 32, "2" * 32, count=2, interval_ms=1,
                              timeout_ms=10, duration_ms=20)
        value = probe.base_report(config, "probe")
        first = pending_record()
        first.update(status="success", reason="matched_echo", sent_offset_ns=10,
                     completed_offset_ns=25, rtt_ns=15)
        second = dict(sequence=1, request_nonce="4" * 32, status="timeout",
                      reason="response_deadline", planned_offset_ns=1_000_000,
                      sent_offset_ns=1_000_010, completed_offset_ns=11_000_010, rtt_ns=None)
        value.update(requests=[first, second], elapsed_ns=11_000_020, termination_reason="completed")
        value["receive_counts"]["accepted"] = 1
        value["received_datagrams"] = 1
        return value

    def test_interruption_preserves_sent_and_all_not_yet_sent_requests(self):
        with loopback_socket() as client, loopback_socket() as server:
            config = config_for(client, server)
            with patch.object(probe, "encode", side_effect=KeyboardInterrupt):
                report = probe.run_probe(config, client)
        result = summary.summarize([report])
        self.assertEqual(report["termination_reason"], "interrupted")
        self.assertEqual(result["status_counts"]["cancelled"], 1)
        self.assertEqual(result["status_counts"]["not_sent"], 2)
        self.assertEqual(result["prescheduled_requests"], 3)

    def test_bind_failure_retains_prescheduled_denominator(self):
        with loopback_socket() as occupied, loopback_socket() as server:
            config = config_for(occupied, server)
            report = probe.run_probe(config)
        result = summary.summarize([report])
        self.assertEqual(report["termination_reason"], "bind_failed")
        self.assertEqual(result["status_counts"]["not_sent"], 3)

    def test_duration_deadline_after_scheduler_pause_does_not_send_overdue_requests(self):
        with loopback_socket() as client, loopback_socket() as server:
            config = config_for(client, server, count=3, interval_ms=20, timeout_ms=100, duration_ms=140)
            clock = [0]

            def resumed_after_deadline(*_args):
                clock[0] = 141 * probe.NS_PER_MS
                return [], [], []

            with patch.object(probe.time, "monotonic_ns", side_effect=lambda: clock[0]), \
                    patch.object(probe.select, "select", side_effect=resumed_after_deadline):
                report = probe.run_probe(config, client)
            server.setblocking(False)
            self.assertEqual(probe.decode(server.recvfrom(probe.MAX_DATAGRAM_BYTES)[0])[3], 0)
            with self.assertRaises(BlockingIOError):
                server.recvfrom(probe.MAX_DATAGRAM_BYTES)
        result = summary.summarize([report])
        self.assertEqual(report["termination_reason"], "duration_deadline")
        self.assertEqual(result["status_counts"]["timeout"], 1)
        self.assertEqual(result["status_counts"]["not_sent"], 2)
        self.assertEqual(result["prescheduled_requests"], 3)

    def test_summary_rejects_removed_failures_duplicate_identity_and_path_claims(self):
        valid = self.report()
        self.assertEqual(summary.summarize([valid])["success_fraction"], 0.5)
        mutations = [
            lambda value: value["requests"].pop(),
            lambda value: value["requests"][1].update(sequence=0),
            lambda value: value["requests"][1].update(request_nonce="3" * 32),
            lambda value: value["requests"][0].update(rtt_ns=10_000_000),
            lambda value: value["requests"][1].update(rtt_ns=0),
            lambda value: value["evidence"].update(real_tun_verified=True),
            lambda value: value["evidence"].update(exact_direct_verified=True),
            lambda value: value["evidence"].update(connection_start_attribution="verified"),
            lambda value: value["receive_counts"].update(accepted=2),
            lambda value: value.update(clock="unix_ms"),
            lambda value: value.update(schema_version=True),
            lambda value: value["requests"][1].update(completed_offset_ns=2_000_010),
        ]
        for mutate in mutations:
            value = copy.deepcopy(valid)
            mutate(value)
            with self.subTest(mutation=mutate), self.assertRaises(ValueError):
                summary.summarize([value])
        with self.assertRaisesRegex(ValueError, "duplicate"):
            summary.summarize([valid, valid])
        other = copy.deepcopy(valid)
        other["run_nonce"] = "5" * 32
        with self.assertRaisesRegex(ValueError, "mix"):
            summary.summarize([valid, other])

    def test_offline_cli_exclusive_output_and_duplicate_json_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            report_path = Path(directory) / "probe.json"
            output_path = Path(directory) / "summary.json"
            probe.write_report(report_path, self.report())
            with redirect_stdout(io.StringIO()):
                self.assertEqual(summary.main([str(report_path), "--output", str(output_path)]), 0)
            result = json.loads(output_path.read_text())
            self.assertEqual(result["prescheduled_requests"], 2)
            self.assertEqual(len(result["input_sha256"][0]), 64)
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(report_path.stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(output_path.stat().st_mode), 0o600)
            original = output_path.read_bytes()
            with redirect_stderr(io.StringIO()):
                self.assertEqual(summary.main([str(report_path), "--output", str(output_path)]), 2)
            self.assertEqual(output_path.read_bytes(), original)
            report_path.write_text('{"scope":"os_udp_echo","scope":"other"}')
            with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
                summary.read_report(report_path)

    def test_output_preflight_rejects_checkout_relative_existing_and_symlink_targets_before_network(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            checkout = root / "checkout"
            checkout.mkdir()
            (checkout / ".git").write_text("gitdir: elsewhere")  # Managed worktree form.
            nested = checkout / "evidence"
            nested.mkdir()
            existing = root / "existing.json"
            existing.write_text("keep")
            redirected = root / "redirected"
            redirected.symlink_to(nested, target_is_directory=True)
            paths = [Path("relative.json"), nested / "probe.json", existing, redirected / "probe.json"]
            arguments = ["probe", "--bind-ip", "127.0.0.1", "--bind-port", "41001",
                         "--target-ip", "127.0.0.1", "--target-port", "41002",
                         "--run-nonce", "1" * 32, "--round-nonce", "2" * 32]
            for path in paths:
                with self.subTest(path=path), patch.object(probe, "run_probe") as run, \
                        redirect_stderr(io.StringIO()):
                    self.assertEqual(probe.main(arguments + ["--output", str(path)]), 2)
                    run.assert_not_called()
            self.assertEqual(existing.read_text(), "keep")
            self.assertFalse((nested / "probe.json").exists())

    def test_cli_has_no_route_or_direct_verification_override(self):
        with redirect_stdout(io.StringIO()) as output:
            self.assertEqual(probe.main(["new-nonces"]), 0)
        nonces = json.loads(output.getvalue())
        self.assertNotEqual(nonces["run_nonce"], nonces["round_nonce"])
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            probe.main(["probe", "--real-tun-verified", "--exact-direct-verified"])
        self.assertEqual(error.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
