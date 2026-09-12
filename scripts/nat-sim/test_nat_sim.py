#!/usr/bin/env python3
"""Regression tests for the deterministic dual-NAT simulator."""

import asyncio
import contextlib
import copy
import importlib.util
import io
import json
import os
import socket
import struct
import subprocess
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("nat_sim.py")
SPEC = importlib.util.spec_from_file_location("p2wlan_nat_sim", MODULE_PATH)
assert SPEC is not None
assert SPEC.loader is not None
NAT_SIM = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NAT_SIM)

OBSERVABILITY_PATH = Path(__file__).with_name("validate_observability.py")
OBS_SPEC = importlib.util.spec_from_file_location("p2wlan_observability", OBSERVABILITY_PATH)
assert OBS_SPEC is not None
assert OBS_SPEC.loader is not None
OBSERVABILITY = importlib.util.module_from_spec(OBS_SPEC)
OBS_SPEC.loader.exec_module(OBSERVABILITY)

COLLECT_PATH = Path(__file__).with_name("collect_evidence.py")
COLLECT_SPEC = importlib.util.spec_from_file_location("p2wlan_nat_collect_evidence", COLLECT_PATH)
assert COLLECT_SPEC is not None
assert COLLECT_SPEC.loader is not None
COLLECT_EVIDENCE = importlib.util.module_from_spec(COLLECT_SPEC)
COLLECT_SPEC.loader.exec_module(COLLECT_EVIDENCE)

AGGREGATE_PATH = Path(__file__).with_name("aggregate_evidence.py")
AGGREGATE_SPEC = importlib.util.spec_from_file_location("p2wlan_nat_aggregate_evidence", AGGREGATE_PATH)
assert AGGREGATE_SPEC is not None
assert AGGREGATE_SPEC.loader is not None
AGGREGATE_EVIDENCE = importlib.util.module_from_spec(AGGREGATE_SPEC)
AGGREGATE_SPEC.loader.exec_module(AGGREGATE_EVIDENCE)


READINESS_PATH = Path(__file__).with_name("daemon_readiness.py")
READINESS_SPEC = importlib.util.spec_from_file_location("p2wlan_daemon_readiness", READINESS_PATH)
assert READINESS_SPEC is not None
assert READINESS_SPEC.loader is not None
READINESS = importlib.util.module_from_spec(READINESS_SPEC)
READINESS_SPEC.loader.exec_module(READINESS)

TRANSIENT_PATH = Path(__file__).with_name("transient.py")
TRANSIENT_SPEC = importlib.util.spec_from_file_location("p2wlan_transient", TRANSIENT_PATH)
assert TRANSIENT_SPEC is not None
assert TRANSIENT_SPEC.loader is not None
TRANSIENT = importlib.util.module_from_spec(TRANSIENT_SPEC)
TRANSIENT_SPEC.loader.exec_module(TRANSIENT)


class CaptureProtocol(asyncio.DatagramProtocol):
    def __init__(self):
        self.received = asyncio.Queue()

    def datagram_received(self, data, addr):
        self.received.put_nowait((data, addr))


def unused_udp_port():
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]
    finally:
        probe.close()


class StunEncodingTests(unittest.TestCase):
    def test_binding_response_is_rfc5389_shaped_and_echoes_transaction_id(self):
        transaction_id = bytes(range(12))
        response = NAT_SIM.binding_response(transaction_id, "127.0.0.1", 36000)

        msg_type, message_length, cookie = struct.unpack("!HHI", response[:8])
        self.assertEqual(msg_type, NAT_SIM.BINDING_RESPONSE)
        self.assertEqual(message_length, 12)
        self.assertEqual(cookie, NAT_SIM.MAGIC_COOKIE)
        self.assertEqual(response[8:20], transaction_id)
        attr_type, attr_length, reserved, family, xor_port = struct.unpack("!HHBBH", response[20:28])
        self.assertEqual((attr_type, attr_length, reserved, family), (NAT_SIM.XOR_MAPPED_ADDRESS, 8, 0, 1))
        self.assertEqual(xor_port ^ (NAT_SIM.MAGIC_COOKIE >> 16), 36000)
        cookie_bytes = struct.pack("!I", NAT_SIM.MAGIC_COOKIE)
        decoded_ip = bytes(a ^ b for a, b in zip(response[28:32], cookie_bytes))
        self.assertEqual(decoded_ip, b"\x7f\x00\x00\x01")

    def test_stun_parser_rejects_wrong_cookie_length_and_type(self):
        transaction_id = bytes(range(12))
        valid = struct.pack("!HHI", NAT_SIM.BINDING_REQUEST, 0, NAT_SIM.MAGIC_COOKIE) + transaction_id
        self.assertEqual(NAT_SIM.parse_binding_request(valid), transaction_id)
        self.assertIsNone(NAT_SIM.parse_binding_request(valid[:-1]))
        wrong_cookie = struct.pack("!HHI", NAT_SIM.BINDING_REQUEST, 0, 0) + transaction_id
        self.assertIsNone(NAT_SIM.parse_binding_request(wrong_cookie))
        wrong_type = struct.pack("!HHI", NAT_SIM.BINDING_RESPONSE, 0, NAT_SIM.MAGIC_COOKIE) + transaction_id
        self.assertIsNone(NAT_SIM.parse_binding_request(wrong_type))


class ObservabilityFailClosedTests(unittest.TestCase):
    def test_missing_status_schema_is_rejected(self):
        with self.assertRaises(ValueError):
            OBSERVABILITY.validate_status({})
        with self.assertRaises(ValueError):
            OBSERVABILITY.validate_status(
                {"stats": {"outbound_drops": {}}, "connection_timeline": {}}
            )

    def test_missing_metrics_schema_is_rejected(self):
        with self.assertRaises(ValueError):
            OBSERVABILITY.validate_metrics({"forwarded_frames_total": 0})
        with self.assertRaises(ValueError):
            OBSERVABILITY.validate_metrics(
                {
                    "active_connections": 0,
                    "registered_peers": 0,
                    "forwarded_frames_total": 0,
                    "forward_errors_total": 0,
                    "source_key": "must-not-be-exposed",
                }
            )

    def test_drop_counters_are_packets_and_bytes_not_reason_cardinality(self):
        value = {
            "stats": {
                "outbound_drops": {
                    "queue_full": {"packets": 3, "bytes": 300},
                    "deadline": {"packets": 2, "bytes": 200},
                },
                "outbound_loss_events": [],
            },
            "connection_timeline": {"correlation_id": "node-1", "events": []},
        }
        validated = OBSERVABILITY.validate_status(value)
        drops = validated["stats"]["outbound_drops"]
        self.assertEqual(sum(item["packets"] for item in drops.values()), 5)
        self.assertEqual(sum(item["bytes"] for item in drops.values()), 500)


class NatEvidenceContractTests(unittest.TestCase):
    SOURCE_SHA = "a" * 40
    WORKFLOW_SHA = "b" * 40

    @staticmethod
    def _status(process_id: int, expected_path: str = "relay", revision: int = 4) -> dict:
        peer = {
            "node_id": "node-b",
            "online": True,
            "relay_confirmed_endpoint": "relay.test" if expected_path == "relay" else None,
            "relay_confirmed_generation": 1 if expected_path == "relay" else None,
            "relay_confirmed_connection_id": 12 if expected_path == "relay" else None,
            "relay_first_business_sent_generation": 1 if expected_path == "relay" else None,
            "relay_first_business_received_generation": 1 if expected_path == "relay" else None,
            "relay_first_business_exchange_generation": 1 if expected_path == "relay" else None,
        }
        summary = {
            "schema_version": 1,
            "peer_id": "node-b",
            "path": expected_path,
            "network_generation": 1,
            "first_usable_at_ms": 20,
            "transition_revision": 3,
            "relay_ready_at_ms": 10,
            "first_usable_delta_ms": 10,
            "business_sent": True,
            "business_received": True,
            "business_exchange": True,
            "relay_id": "relay.test" if expected_path == "relay" else None,
            "relay_connection_id": 12 if expected_path == "relay" else None,
            "source": "authoritative_business_ingress_commit",
        }
        return {
            "process_id": process_id,
            "node_id": "node-a",
            "network_generation": 1,
            "uptime_ms": 30,
            "revision": revision,
            "captured_revision": revision,
            "captured_at_ms": 30,
            "peer_snapshot_stale": False,
            "relay_connected": expected_path == "relay",
            "connection_timeline": {
                "correlation_id": "node-a-1",
                "events": [
                    {
                        "event": "relay_transport_ready_peer",
                        "at_ms": 10,
                        "peer_id": "node-b",
                        "connection_generation": 1,
                    },
                    {
                        "event": "first_usable_path",
                        "at_ms": 20,
                        "path": expected_path,
                        "peer_id": "node-b",
                        "connection_generation": 1,
                    },
                ],
                "first_usable_summaries": [summary],
            },
            "peers": [peer],
            "stats": {"outbound_drops": {}, "outbound_loss_events": []},
            "health": {
                "critical_tasks": [
                    {"critical": True, "running": True, "finished": False, "error": None}
                ]
            },
        }

    def _write_record(self, root: Path, topology: str, replica: int) -> dict:
        expected_path = "relay" if topology == "relay-blackhole" else "direct"
        baseline = self._status(1234, expected_path, revision=1)
        baseline["captured_at_ms"] = 5
        baseline["uptime_ms"] = 5
        final = self._status(1234, expected_path)
        record = self._build_record(
            root,
            topology,
            replica,
            baseline,
            baseline,
            final,
            final,
        )
        output_dir = root / f"record-{topology}-{replica}"
        output_dir.mkdir()
        (output_dir / "nat-evidence.json").write_text(
            json.dumps(record), encoding="utf-8"
        )
        (output_dir / "nat-attempts.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "scenario_id": record["scenario_id"],
                    "source_head_sha": self.SOURCE_SHA,
                    "workflow_sha": self.WORKFLOW_SHA,
                    "attempts": [
                        {
                            "attempt": 1,
                            "exit_code": 0,
                            "business_validation_started": True,
                            "reason_codes": [],
                            "evidence_path": "nat-evidence.json",
                            "readiness_paths": [],
                            "classification": {"retryable": False, "reason": "accepted"},
                            "infrastructure_evidence": None,
                        }
                    ],
                    "final_adjudication": {
                        "result": "pass",
                        "attempt": 1,
                        "reason_code": None,
                    },
                }
            ),
            encoding="utf-8",
        )
        return record

    def _build_record(
        self,
        root: Path,
        topology: str,
        replica: int,
        baseline_a: dict,
        baseline_b: dict,
        final_a: dict,
        final_b: dict,
        log_text: str = "overlay_payload_verified\noverlay_burst_complete\n",
    ) -> dict:
        expected_path = "relay" if topology == "relay-blackhole" else "direct"
        log = root / f"{topology}-{replica}.log"
        if expected_path == "direct" and "direct_promoted" not in log_text:
            log_text = "direct_promoted\n" + log_text
        log.write_text(log_text, encoding="utf-8")
        baseline_a_path = root / f"{topology}-{replica}.a.baseline.json"
        baseline_b_path = root / f"{topology}-{replica}.b.baseline.json"
        final_a_path = root / f"{topology}-{replica}.a.final.json"
        final_b_path = root / f"{topology}-{replica}.b.final.json"
        baseline_a_path.write_text(json.dumps(baseline_a), encoding="utf-8")
        baseline_b_path.write_text(json.dumps(baseline_b), encoding="utf-8")
        final_a_path.write_text(json.dumps(final_a), encoding="utf-8")
        final_b_path.write_text(json.dumps(final_b), encoding="utf-8")
        return COLLECT_EVIDENCE.build_record(
            Namespace(
                topology=topology,
                replica=replica,
                round=1,
                source_head_sha=self.SOURCE_SHA,
                workflow_sha=self.WORKFLOW_SHA,
                baseline_a=str(baseline_a_path),
                baseline_b=str(baseline_b_path),
                final_a=str(final_a_path),
                final_b=str(final_b_path),
                log_a=str(log),
                log_b=str(log),
                expected_path=expected_path,
                overlay_burst=64 if expected_path == "relay" else 0,
            )
        )

    def _all_records(self, root: Path) -> list[tuple[Path, dict]]:
        records = []
        for path in sorted(root.rglob("nat-evidence.json")):
            records.append((path, json.loads(path.read_text(encoding="utf-8"))))
        return records

    def _all_attempt_histories(self, root: Path) -> list[tuple[Path, dict]]:
        histories = []
        for path in sorted(root.rglob("nat-attempts.json")):
            histories.append((path, json.loads(path.read_text(encoding="utf-8"))))
        return histories

    @staticmethod
    def _remove_first_usable(status: dict, clear_relay_business: bool = False) -> dict:
        value = copy.deepcopy(status)
        timeline = value["connection_timeline"]
        timeline["events"] = [
            event for event in timeline["events"] if event.get("event") != "first_usable_path"
        ]
        timeline["first_usable_summaries"] = []
        if clear_relay_business:
            peer = value["peers"][0]
            peer["relay_first_business_sent_generation"] = None
            peer["relay_first_business_received_generation"] = None
            peer["relay_first_business_exchange_generation"] = None
        return value

    def test_transition_after_baseline_computes_delta_from_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            record = self._build_record(
                root,
                "relay-blackhole",
                1,
                self._status(1234, "relay", revision=1),
                self._status(1235, "relay", revision=1),
                self._status(1234, "relay"),
                self._status(1235, "relay"),
            )
            self.assertEqual(record["result"], "pass")
            self.assertEqual(record["observed"]["a"]["first_usable"]["delta_ms"], 10)
            self.assertFalse(record["observed"]["a"]["first_usable"]["baseline_after_transition"])

    def test_transition_before_baseline_requires_persistent_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline_a = self._status(1234, "relay", revision=4)
            baseline_b = self._status(1235, "relay", revision=4)
            record = self._build_record(
                root,
                "relay-blackhole",
                1,
                baseline_a,
                baseline_b,
                self._status(1234, "relay"),
                self._status(1235, "relay"),
            )
            self.assertEqual(record["result"], "pass")
            self.assertTrue(record["observed"]["a"]["first_usable"]["baseline_after_transition"])
            self.assertEqual(record["observed"]["a"]["first_usable"]["source"], "persistent_summary")

    def test_event_fallback_is_revision_fenced_and_computes_delta(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            final_a = self._status(1234, "relay")
            final_b = self._status(1235, "relay")
            for final in (final_a, final_b):
                timeline = final["connection_timeline"]
                timeline["first_usable_summaries"] = []
                for event in timeline["events"]:
                    if event["event"] == "first_usable_path":
                        event["transition_revision"] = 3
            baseline_a = self._status(1234, "relay", revision=1)
            baseline_b = self._status(1235, "relay", revision=1)
            for baseline in (baseline_a, baseline_b):
                baseline["captured_at_ms"] = 5
                baseline["uptime_ms"] = 5
            record = self._build_record(
                root,
                "relay-blackhole",
                1,
                baseline_a,
                baseline_b,
                final_a,
                final_b,
            )
            self.assertEqual(record["result"], "pass")
            self.assertEqual(record["observed"]["a"]["first_usable"]["source"], "event")
            self.assertEqual(record["observed"]["a"]["first_usable"]["transition_revision"], 3)
            self.assertEqual(record["observed"]["a"]["first_usable"]["delta_ms"], 10)

    def test_event_only_baseline_after_transition_fails_setup_order(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            final_a = self._status(1234, "relay")
            final_b = self._status(1235, "relay")
            for final in (final_a, final_b):
                timeline = final["connection_timeline"]
                timeline["first_usable_summaries"] = []
                for event in timeline["events"]:
                    if event["event"] == "first_usable_path":
                        event["transition_revision"] = 3
            baseline_a = self._status(1234, "relay", revision=4)
            baseline_b = self._status(1235, "relay", revision=4)
            record = self._build_record(
                root,
                "relay-blackhole",
                1,
                baseline_a,
                baseline_b,
                final_a,
                final_b,
            )
            self.assertEqual(record["result"], "fail")
            self.assertEqual(
                record["decision"]["reason_code"], "baseline_after_transition_event_retained"
            )

    def test_event_ring_eviction_uses_durable_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            final_a = self._status(1234, "relay")
            final_b = self._status(1235, "relay")
            for final in (final_a, final_b):
                final["connection_timeline"]["events"] = [
                    event
                    for event in final["connection_timeline"]["events"]
                    if event.get("event") != "first_usable_path"
                ]
            record = self._build_record(
                root,
                "relay-blackhole",
                1,
                self._status(1234, "relay", revision=1),
                self._status(1235, "relay", revision=1),
                final_a,
                final_b,
            )
            self.assertEqual(record["result"], "pass")
            self.assertTrue(record["collector"]["a"]["timeline_evicted"])

    def test_path_never_usable_is_not_a_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            final_a = self._remove_first_usable(self._status(1234, "direct"))
            final_b = self._remove_first_usable(self._status(1235, "direct"))
            record = self._build_record(
                root,
                "direct-cold-start",
                1,
                self._status(1234, "direct", revision=1),
                self._status(1235, "direct", revision=1),
                final_a,
                final_b,
                log_text="direct_promoted\n",
            )
            self.assertEqual(record["result"], "fail")
            self.assertEqual(record["decision"]["reason_code"], "first_usable_never_observed")

    def test_relay_connected_without_business_is_not_a_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            final_a = self._remove_first_usable(self._status(1234, "relay"), True)
            final_b = self._remove_first_usable(self._status(1235, "relay"), True)
            record = self._build_record(
                root,
                "relay-blackhole",
                1,
                self._status(1234, "relay", revision=1),
                self._status(1235, "relay", revision=1),
                final_a,
                final_b,
            )
            self.assertEqual(record["result"], "fail")
            self.assertEqual(record["decision"]["reason_code"], "first_business_not_passed")

    def test_diagnostics_revision_lag_is_not_a_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            final_a = self._status(1234, "relay")
            final_b = self._status(1235, "relay")
            for final in (final_a, final_b):
                final["captured_revision"] = final["revision"] - 1
                final["peer_snapshot_stale"] = True
            record = self._build_record(
                root,
                "relay-blackhole",
                1,
                self._status(1234, "relay", revision=1),
                self._status(1235, "relay", revision=1),
                final_a,
                final_b,
            )
            self.assertEqual(record["result"], "fail")
            self.assertEqual(record["decision"]["reason_code"], "diagnostics_revision_not_converged")

    def test_changed_process_identity_is_not_a_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            record = self._build_record(
                root,
                "relay-blackhole",
                1,
                self._status(1234, "relay", revision=1),
                self._status(1235, "relay", revision=1),
                self._status(4321, "relay"),
                self._status(1235, "relay"),
            )
            self.assertEqual(record["result"], "fail")
            self.assertEqual(record["decision"]["reason_code"], "stale_process_identity")

    def test_one_missing_side_is_reported_without_fanout(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            final_b = self._remove_first_usable(self._status(1235, "direct"))
            record = self._build_record(
                root,
                "direct-cold-start",
                1,
                self._status(1234, "direct", revision=1),
                self._status(1235, "direct", revision=1),
                self._status(1234, "direct"),
                final_b,
                log_text="direct_promoted\noverlay_payload_verified\n",
            )
            self.assertEqual(record["result"], "fail")
            self.assertEqual(record["observed"]["a"]["first_usable"]["path"], "direct")
            self.assertIsNone(record["observed"]["b"]["first_usable"]["path"])

    def test_duplicate_same_generation_summary_is_parser_loss(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            final_a = self._status(1234, "relay")
            final_b = self._status(1235, "relay")
            for final in (final_a, final_b):
                duplicate = copy.deepcopy(final["connection_timeline"]["first_usable_summaries"][0])
                duplicate["first_usable_at_ms"] = 30
                duplicate["first_usable_delta_ms"] = 20
                duplicate["transition_revision"] = 4
                final["connection_timeline"]["first_usable_summaries"].append(duplicate)
            record = self._build_record(
                root,
                "relay-blackhole",
                1,
                self._status(1234, "relay", revision=1),
                self._status(1235, "relay", revision=1),
                final_a,
                final_b,
            )
            self.assertEqual(record["result"], "fail")
            self.assertEqual(record["decision"]["reason_code"], "evidence_parser_loss")

    def test_valid_actual_execution_records_aggregate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_record(root, "direct-cold-start", 1)
            for replica in range(1, 6):
                self._write_record(root, "relay-blackhole", replica)
            aggregate = AGGREGATE_EVIDENCE.aggregate_records(
                self._all_records(root), self.SOURCE_SHA, self.WORKFLOW_SHA
            )
            self.assertEqual(aggregate["result"], "pass")
            self.assertEqual(aggregate["relay_replica_count"], 5)
            self.assertEqual(aggregate["attempt_stats"]["first_attempt_pass_count"], 6)
            self.assertEqual(aggregate["attempt_stats"]["diagnostic_retry_count"], 0)
            self.assertEqual(aggregate["attempt_stats"]["recovery_count"], 0)
            self.assertEqual(aggregate["attempt_stats"]["final_failure_count"], 0)
            self.assertTrue(aggregate["aggregate_digest"].startswith("sha256:"))

    def test_barrier_failure_without_business_evidence_is_included_in_final_aggregate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_record(root, "direct-cold-start", 1)
            for replica in (1, 2, 3, 5):
                self._write_record(root, "relay-blackhole", replica)

            failed_dir = root / "record-relay-blackhole-4"
            failed_dir.mkdir()
            (failed_dir / "nat-attempts.json").write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "scenario_id": "relay-blackhole:replica-4:round-1",
                        "source_head_sha": self.SOURCE_SHA,
                        "workflow_sha": self.WORKFLOW_SHA,
                        "attempts": [
                            {
                                "attempt": 1,
                                "exit_code": 1,
                                "business_validation_started": True,
                                "reason_codes": ["relay_peer_confirmation_timeout"],
                                "evidence_path": None,
                                "readiness_paths": ["relay-barrier.readiness.json"],
                                "classification": {
                                    "retryable": False,
                                    "reason": "barrier_timeout",
                                },
                                "infrastructure_evidence": None,
                            }
                        ],
                        "final_adjudication": {
                            "result": "fail",
                            "attempt": 1,
                            "reason_code": "barrier_timeout",
                        },
                    }
                ),
                encoding="utf-8",
            )
            output_path = root / "aggregate.json"
            completed = subprocess.run(
                [
                    "python3",
                    str(AGGREGATE_PATH),
                    "--input-root",
                    str(root),
                    "--source-head-sha",
                    self.SOURCE_SHA,
                    "--workflow-sha",
                    self.WORKFLOW_SHA,
                    "--output",
                    str(output_path),
                ],
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(completed.returncode, 1, completed.stderr)
            aggregate = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(aggregate["result"], "fail")
            self.assertEqual(aggregate["attempt_stats"]["scenario_count"], 6)
            self.assertEqual(aggregate["attempt_stats"]["first_attempt_pass_count"], 5)
            self.assertAlmostEqual(aggregate["attempt_stats"]["first_attempt_pass_rate"], 5 / 6)
            self.assertEqual(aggregate["attempt_stats"]["diagnostic_retry_count"], 0)
            self.assertEqual(aggregate["attempt_stats"]["recovery_count"], 0)
            self.assertEqual(aggregate["attempt_stats"]["final_failure_count"], 1)
            failed = next(
                item for item in aggregate["records"] if item["scenario_id"] == "relay-blackhole:replica-4:round-1"
            )
            self.assertEqual(failed["result"], "fail")
            self.assertIsNone(failed["evidence_path"])
            self.assertEqual(failed["attempts"][0]["exit_code"], 1)
            self.assertEqual(
                failed["attempts"][0]["reason_codes"], ["relay_peer_confirmation_timeout"]
            )
            self.assertEqual(
                failed["final_adjudication"]["reason_code"], "barrier_timeout"
            )

    def test_business_failure_evidence_is_included_as_final_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_record(root, "direct-cold-start", 1)
            for replica in range(1, 6):
                self._write_record(root, "relay-blackhole", replica)

            scenario_dir = root / "record-relay-blackhole-2"
            evidence_path = scenario_dir / "nat-evidence.json"
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
            evidence["result"] = "fail"
            evidence["decision"] = {
                "result": "fail",
                "reason_code": "relay_business_gate_failed",
                "observed_decision": "business_validation_failed",
            }
            evidence_path.write_text(json.dumps(evidence), encoding="utf-8")

            manifest_path = scenario_dir / "nat-attempts.json"
            history = json.loads(manifest_path.read_text(encoding="utf-8"))
            history["attempts"][0].update(
                {
                    "exit_code": 1,
                    "business_validation_started": True,
                    "reason_codes": ["relay_business_gate_failed"],
                    "classification": {
                        "retryable": False,
                        "reason": "business_validation_failed",
                    },
                }
            )
            history["final_adjudication"] = {
                "result": "fail",
                "attempt": 1,
                "reason_code": "business_validation_failed",
            }
            manifest_path.write_text(json.dumps(history), encoding="utf-8")

            output_path = root / "aggregate.json"
            completed = subprocess.run(
                [
                    "python3",
                    str(AGGREGATE_PATH),
                    "--input-root",
                    str(root),
                    "--source-head-sha",
                    self.SOURCE_SHA,
                    "--workflow-sha",
                    self.WORKFLOW_SHA,
                    "--output",
                    str(output_path),
                ],
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(completed.returncode, 1, completed.stderr)
            aggregate = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(aggregate["result"], "fail")
            self.assertEqual(aggregate["attempt_stats"]["first_attempt_pass_count"], 5)
            self.assertEqual(aggregate["attempt_stats"]["diagnostic_retry_count"], 0)
            self.assertEqual(aggregate["attempt_stats"]["recovery_count"], 0)
            self.assertEqual(aggregate["attempt_stats"]["final_failure_count"], 1)
            failed = next(
                item for item in aggregate["records"] if item["scenario_id"] == "relay-blackhole:replica-2:round-1"
            )
            self.assertEqual(failed["result"], "fail")
            self.assertTrue(failed["evidence_path"].endswith("nat-evidence.json"))
            self.assertEqual(failed["evidence_result"], "fail")
            self.assertEqual(failed["evidence_reason_code"], "relay_business_gate_failed")
            self.assertEqual(failed["attempts"][0]["exit_code"], 1)
            self.assertEqual(
                failed["final_adjudication"]["reason_code"], "business_validation_failed"
            )

    def test_missing_replica_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_record(root, "direct-cold-start", 1)
            for replica in range(1, 5):
                self._write_record(root, "relay-blackhole", replica)
            with self.assertRaisesRegex(ValueError, "missing_scenario:.*relay-blackhole:replica-5"):
                AGGREGATE_EVIDENCE.aggregate_records(
                    self._all_records(root), self.SOURCE_SHA, self.WORKFLOW_SHA
                )

    def test_mutated_test_name_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_record(root, "direct-cold-start", 1)
            for replica in range(1, 6):
                self._write_record(root, "relay-blackhole", replica)
            path = root / "record-relay-blackhole-3" / "nat-evidence.json"
            value = json.loads(path.read_text(encoding="utf-8"))
            value["exact_test_id"] = value["exact_test_id"].replace("replica-3", "replica-2")
            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "exact_test_id_scenario_mismatch"):
                AGGREGATE_EVIDENCE.aggregate_records(
                    self._all_records(root), self.SOURCE_SHA, self.WORKFLOW_SHA
                )

    def test_skipped_test_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_record(root, "direct-cold-start", 1)
            for replica in range(1, 6):
                self._write_record(root, "relay-blackhole", replica)
            path = root / "record-relay-blackhole-4" / "nat-evidence.json"
            value = json.loads(path.read_text(encoding="utf-8"))
            value["skipped"] = True
            path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "test_skipped"):
                AGGREGATE_EVIDENCE.aggregate_records(
                    self._all_records(root), self.SOURCE_SHA, self.WORKFLOW_SHA
                )

    def test_static_manifest_scenario_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_record(root, "direct-cold-start", 1)
            for replica in range(1, 6):
                self._write_record(root, "relay-blackhole", replica)
            value = json.loads(
                (root / "record-relay-blackhole-1" / "nat-evidence.json").read_text(
                    encoding="utf-8"
                )
            )
            value["topology"] = "relay-blackhole-fictional"
            value["scenario_id"] = "relay-blackhole-fictional:replica-1:round-1"
            extra = root / "record-fictional"
            extra.mkdir()
            (extra / "nat-evidence.json").write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "scenario_identity_invalid"):
                AGGREGATE_EVIDENCE.aggregate_records(
                    self._all_records(root), self.SOURCE_SHA, self.WORKFLOW_SHA
                )

    def test_duplicate_conflicting_records_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_record(root, "direct-cold-start", 1)
            for replica in range(1, 6):
                self._write_record(root, "relay-blackhole", replica)
            original = root / "record-relay-blackhole-2" / "nat-evidence.json"
            duplicate_dir = root / "duplicate"
            duplicate_dir.mkdir()
            (duplicate_dir / "nat-evidence.json").write_text(
                original.read_text(encoding="utf-8"), encoding="utf-8"
            )
            (duplicate_dir / "nat-attempts.json").write_text(
                (original.parent / "nat-attempts.json").read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "duplicate_conflicting_record"):
                AGGREGATE_EVIDENCE.aggregate_records(
                    self._all_records(root), self.SOURCE_SHA, self.WORKFLOW_SHA
                )

    def test_business_failure_cannot_be_hidden_by_later_success(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_record(root, "direct-cold-start", 1)
            for replica in range(1, 6):
                self._write_record(root, "relay-blackhole", replica)
            evidence_path = root / "record-relay-blackhole-1" / "nat-evidence.json"
            manifest_path = evidence_path.with_name("nat-attempts.json")
            history = json.loads(manifest_path.read_text(encoding="utf-8"))
            successful = copy.deepcopy(history["attempts"][0])
            failed = copy.deepcopy(successful)
            failed.update(
                {
                    "attempt": 1,
                    "exit_code": 1,
                    "business_validation_started": True,
                    "reason_codes": ["overlay_verification_failed"],
                    "evidence_path": "attempt-1/round-1/nat-evidence.json",
                    "classification": {"retryable": False, "reason": "business_validation_failed"},
                }
            )
            successful["attempt"] = 2
            history["attempts"] = [failed, successful]
            history["final_adjudication"]["attempt"] = 2
            manifest_path.write_text(json.dumps(history), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "business_failure_masked_by_later_attempt"):
                AGGREGATE_EVIDENCE.aggregate_records(
                    self._all_records(root), self.SOURCE_SHA, self.WORKFLOW_SHA
                )


class NatIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.transports = []
        self.nats = []

    async def asyncTearDown(self):
        for nat in self.nats:
            await nat.close()
        for transport in self.transports:
            transport.close()

    async def capture_endpoint(self):
        protocol = CaptureProtocol()
        transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: protocol, local_addr=("127.0.0.1", 0)
        )
        self.transports.append(transport)
        return transport, protocol, transport.get_extra_info("sockname")

    async def new_nat(self, name, fabric=None, strict_filtering=False, block_direct=False):
        nat = NAT_SIM.Nat(
            name,
            "127.0.0.1",
            1,
            seed=7 if name == "A" else 8,
            base_port=unused_udp_port(),
            strict_filtering=strict_filtering,
            block_direct=block_direct,
        )
        await nat.start(fabric)
        self.nats.append(nat)
        return nat

    async def test_stun_response_waits_for_a_bound_mapping_and_reuses_it(self):
        nat = await self.new_nat("A")
        observer = await nat.add_observer()
        client, received, client_addr = await self.capture_endpoint()
        transaction = bytes(range(12))
        request = struct.pack("!HHI", NAT_SIM.BINDING_REQUEST, 0, NAT_SIM.MAGIC_COOKIE) + transaction

        client.sendto(request, observer)
        response, source = await asyncio.wait_for(received.received.get(), timeout=1)
        mapping = nat.mappings[(client_addr, observer)]
        self.assertEqual(source, observer)
        self.assertEqual(response[8:20], transaction)
        self.assertIn(mapping.port, nat.forwarders)
        self.assertEqual(nat.observed_sequence, [mapping.port])

        client.sendto(request, observer)
        await asyncio.wait_for(received.received.get(), timeout=1)
        self.assertEqual(nat.observed_sequence, [mapping.port])

    async def test_public_forwarder_callback_delivers_exact_mapping_destination(self):
        nat = await self.new_nat("A")
        client, received, client_addr = await self.capture_endpoint()
        peer, _, peer_addr = await self.capture_endpoint()
        mapping = nat.mapping_for(client_addr, peer_addr)
        await nat.ensure_bound(mapping)

        payload = b"forwarder-callback-only"
        peer.sendto(payload, (nat.public_ip, mapping.port))
        delivered, source = await asyncio.wait_for(received.received.get(), timeout=1)
        self.assertEqual(delivered, payload)
        self.assertEqual(source, (nat.public_ip, mapping.port))

    async def test_private_sender_is_reemitted_from_the_sender_nat_public_mapping(self):
        fabric = NAT_SIM.NatFabric()
        nat_a = await self.new_nat("A", fabric)
        nat_b = await self.new_nat("B", fabric)
        client_a, received_a, client_a_addr = await self.capture_endpoint()
        client_b, received_b, client_b_addr = await self.capture_endpoint()
        nat_a.record_client(client_a_addr)
        nat_b.record_client(client_b_addr)

        # B's public endpoint is open before A starts punching.  The packet
        # from A reaches B once with A's private source, then NatFabric
        # re-emits it from the public mapping and B delivers only that copy.
        mapping_b = nat_b.mapping_for(client_b_addr, ("127.0.0.1", 9))
        await nat_b.ensure_bound(mapping_b)
        payload = b"source-nat-visible-to-peer"
        client_a.sendto(payload, (nat_b.public_ip, mapping_b.port))

        delivered, source = await asyncio.wait_for(received_b.received.get(), timeout=1)
        mapping_a = nat_a.mappings[(client_a_addr, (nat_b.public_ip, mapping_b.port))]
        self.assertEqual(delivered, payload)
        self.assertEqual(source, (nat_a.public_ip, mapping_a.port))
        self.assertNotEqual(source, client_a_addr)
        self.assertNotEqual(source, (nat_b.public_ip, mapping_b.port))

        reverse_payload = b"reverse-source-nat-visible-to-peer"
        client_b.sendto(reverse_payload, (nat_a.public_ip, mapping_a.port))
        reverse_delivered, reverse_source = await asyncio.wait_for(received_a.received.get(), timeout=1)
        reverse_mapping = nat_b.mappings[(client_b_addr, (nat_a.public_ip, mapping_a.port))]
        self.assertEqual(reverse_delivered, reverse_payload)
        self.assertEqual(reverse_source, (nat_b.public_ip, reverse_mapping.port))
        self.assertNotEqual(reverse_source, client_b_addr)

    async def test_unknown_private_sender_cannot_bypass_the_nat_filter(self):
        fabric = NAT_SIM.NatFabric()
        nat = await self.new_nat("A", fabric)
        _, received, client_addr = await self.capture_endpoint()
        attacker, _, _ = await self.capture_endpoint()
        mapping = nat.mapping_for(client_addr, ("127.0.0.1", 9))
        await nat.ensure_bound(mapping)

        attacker.sendto(b"must-drop", (nat.public_ip, mapping.port))
        with self.assertRaises(asyncio.TimeoutError):
            await asyncio.wait_for(received.received.get(), timeout=0.15)

    async def test_strict_filtering_rejects_peer_public_socket_not_destination(self):
        fabric = NAT_SIM.NatFabric()
        nat = await self.new_nat("A", fabric, strict_filtering=True)
        nat_b = await self.new_nat("B", fabric, strict_filtering=True)
        client, received, client_addr = await self.capture_endpoint()
        nat.record_client(client_addr)

        # B's public socket is a REAL peer public endpoint.
        peer_client, _, peer_client_addr = await self.capture_endpoint()
        nat_b.record_client(peer_client_addr)
        peer_mapping = nat_b.mapping_for(peer_client_addr, ("127.0.0.1", 9))
        await nat_b.ensure_bound(peer_mapping)

        # A's client mapping was created toward a DIFFERENT destination.  With
        # strict (endpoint-dependent) filtering the peer's unrelated public
        # socket is rejected even though the fallback mode would admit it.
        mapping = nat.mapping_for(client_addr, ("127.0.0.1", 12345))
        await nat.ensure_bound(mapping)
        peer_mapping.transport.sendto(b"strict-drop", (nat.public_ip, mapping.port))
        with self.assertRaises(asyncio.TimeoutError):
            await asyncio.wait_for(received.received.get(), timeout=0.15)

    async def test_block_direct_blackholes_data_plane_but_keeps_stun(self):
        fabric = NAT_SIM.NatFabric()
        nat_a = await self.new_nat("A", fabric, block_direct=True)
        nat_b = await self.new_nat("B", fabric, block_direct=True)
        client_a, received_a, client_a_addr = await self.capture_endpoint()
        client_b, received_b, client_b_addr = await self.capture_endpoint()
        nat_a.record_client(client_a_addr)
        nat_b.record_client(client_b_addr)

        # STUN observers keep working under the blackhole (Direct candidates
        # are still discovered; only the data plane is blocked).
        observer = await nat_a.add_observer()
        transaction = bytes(range(12))
        request = struct.pack("!HHI", NAT_SIM.BINDING_REQUEST, 0, NAT_SIM.MAGIC_COOKIE) + transaction
        client_a.sendto(request, observer)
        response, _ = await asyncio.wait_for(received_a.received.get(), timeout=1)
        self.assertEqual(response[8:20], transaction)

        # A direct data-plane datagram from A to B's public mapping never
        # arrives at B: the deterministic bidirectional UDP blackhole.
        mapping_b = nat_b.mapping_for(client_b_addr, ("127.0.0.1", 9))
        await nat_b.ensure_bound(mapping_b)
        client_a.sendto(b"blackhole", (nat_b.public_ip, mapping_b.port))
        with self.assertRaises(asyncio.TimeoutError):
            await asyncio.wait_for(received_b.received.get(), timeout=0.15)

    def test_strict_filtering_inbound_allowed_requires_exact_destination(self):
        strict = NAT_SIM.Nat("A", "127.0.0.1", 1, 7, unused_udp_port(), strict_filtering=True)
        mapping = NAT_SIM.Mapping(
            client=("127.0.0.1", 1000), destination=("127.0.0.1", 2000), port=3000
        )
        # Exact mapping destination is always admitted.
        self.assertTrue(strict.inbound_allowed(mapping, ("127.0.0.1", 2000)))
        # Any other source is rejected under endpoint-dependent filtering, even
        # a port that is clearly not the destination.
        self.assertFalse(strict.inbound_allowed(mapping, ("127.0.0.1", 2999)))
        self.assertFalse(strict.inbound_allowed(mapping, ("127.0.0.2", 2000)))
        # Without a fabric, the non-strict fallback also rejects an arbitrary
        # source (the peer-endpoint fallback requires a real peer socket).
        non_strict = NAT_SIM.Nat("B", "127.0.0.1", 1, 8, unused_udp_port())
        self.assertFalse(non_strict.inbound_allowed(mapping, ("127.0.0.1", 2999)))


class DaemonReadinessTests(unittest.TestCase):
    """Regression tests for the bounded daemon readiness gate.

    The status collector must never run before the daemon publishes its
    diagnostics token; these tests pin the poll-based wait, its hard bound,
    its fail-fast on a dead process, and the failure diagnostics bundle.
    """

    def _waiter(self, token_path: Path, alive=True, appear_after_calls=0, timeout_s=1.0,
                log_path: Path | None = None, runtime_dir: Path | None = None):
        state = {"sleeps": 0}

        def fake_sleep(_seconds):
            state["sleeps"] += 1
            if state["sleeps"] >= appear_after_calls > 0 and not token_path.exists():
                token_path.write_text("tokensecret", encoding="utf-8")

        ticks = {"now": 0.0}

        def fake_monotonic():
            return ticks["now"]

        def fake_advance(_seconds):
            ticks["now"] += 0.25

        def fake_sleep_advancing(seconds):
            fake_sleep(seconds)
            fake_advance(seconds)

        if alive:
            alive_fn = lambda _pid: True  # noqa: E731
        else:
            alive_fn = lambda _pid: False  # noqa: E731
        return READINESS.wait_for_token(
            token_path=token_path,
            pid=4242,
            timeout_s=timeout_s,
            poll_s=0.25,
            log_path=log_path,
            runtime_dir=runtime_dir,
            sleep=fake_sleep_advancing if appear_after_calls else fake_advance,
            monotonic=fake_monotonic,
            alive=alive_fn,
        )

    def test_token_published_mid_wait_reaches_token_ready(self):
        with tempfile.TemporaryDirectory() as tmp:
            token = Path(tmp) / "p2wlan-daemon.diag-auth"
            record = self._waiter(token, alive=True, appear_after_calls=3, timeout_s=10.0)
            self.assertEqual(record["result"], "ready")
            self.assertEqual(record["state"], "TOKEN_READY")
            self.assertGreaterEqual(record["polls"], 3)

    def test_timeout_is_bounded_and_carries_diagnostics(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = Path(tmp) / "runtime"
            runtime.mkdir()
            (runtime / "config.json").write_text("{}", encoding="utf-8")
            log = Path(tmp) / "node.log"
            log.write_text("line one\nERROR: bootstrap stalled\n", encoding="utf-8")
            token = runtime / "p2wlan-daemon.diag-auth"
            record = self._waiter(token, alive=True, timeout_s=1.0,
                                  log_path=log, runtime_dir=runtime)
            self.assertEqual(record["result"], "timeout")
            self.assertEqual(record["state"], "STARTING")
            self.assertFalse(record["token_present"])
            self.assertEqual(record["pid"], 4242)
            self.assertTrue(record["process_alive"])
            self.assertLessEqual(record["waited_ms"], 2000)
            names = [entry["name"] for entry in record["runtime_dir_listing"]]
            self.assertIn("config.json", names)
            self.assertIn("ERROR: bootstrap stalled", record["log_error_lines"])

    def test_dead_process_fails_fast_without_burning_the_bound(self):
        with tempfile.TemporaryDirectory() as tmp:
            token = Path(tmp) / "p2wlan-daemon.diag-auth"
            record = self._waiter(token, alive=False, timeout_s=30.0)
            self.assertEqual(record["result"], "process_exited")
            self.assertEqual(record["state"], "STARTING")
            self.assertFalse(record["process_alive"])
            self.assertLessEqual(record["waited_ms"], 500)

    def test_record_never_contains_token_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            token = Path(tmp) / "p2wlan-daemon.diag-auth"
            token.write_text("tokensecret", encoding="utf-8")
            record = READINESS.wait_for_token(
                token_path=token,
                pid=None,
                timeout_s=0.1,
                poll_s=0.05,
                log_path=None,
                runtime_dir=None,
                sleep=lambda _s: None,
                monotonic=lambda: 0.0,
                alive=lambda _pid: True,
            )
            self.assertEqual(record["result"], "ready")
            self.assertNotIn("tokensecret", json.dumps(record))

    def test_cli_records_the_daemon_side_for_attempt_correlation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            token = root / "p2wlan-daemon.diag-auth"
            output = root / "readiness.json"
            token.write_text("tokensecret", encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()):
                status = READINESS.main(
                    [
                        "wait-token",
                        "--pid",
                        str(os.getpid()),
                        "--side",
                        "b",
                        "--token-file",
                        str(token),
                        "--output",
                        str(output),
                    ]
                )
            record = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(status, 0)
            self.assertEqual(record["side"], "b")

    def test_state_machine_never_regresses(self):
        advance = READINESS.advance
        self.assertIs(
            advance(READINESS.DaemonReadyState.TOKEN_READY, process_alive=False, token_present=True),
            READINESS.DaemonReadyState.TOKEN_READY,
        )
        self.assertIs(
            advance(READINESS.DaemonReadyState.STARTING, process_alive=True, token_present=True),
            READINESS.DaemonReadyState.TOKEN_READY,
        )
        self.assertIs(
            advance(READINESS.DaemonReadyState.TOKEN_READY, process_alive=True, token_present=False),
            READINESS.DaemonReadyState.TOKEN_READY,
        )
        self.assertIs(
            advance(
                READINESS.DaemonReadyState.STATUS_READY,
                process_alive=True,
                token_present=True,
                status_ok=True,
                verification_running=True,
                peers_confirmed=True,
            ),
            READINESS.DaemonReadyState.RUNNING,
        )

    def test_running_requires_peer_confirmation(self):
        state = READINESS.advance(
            READINESS.DaemonReadyState.STATUS_READY,
            process_alive=True,
            token_present=True,
            status_ok=True,
            verification_running=True,
            peers_confirmed=False,
        )
        self.assertIs(state, READINESS.DaemonReadyState.STATUS_READY)


class BaselineShellCallChainTests(unittest.TestCase):
    def test_failed_baseline_saves_diagnostic_and_skips_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            sentinel = Path(directory) / "verification-ran"
            diagnostic = Path(directory) / "baseline-diagnostic.json"
            result = subprocess.run(
                [
                    "bash",
                    str(Path(__file__).with_name("test_baseline_gate.sh")),
                    str(sentinel),
                    str(diagnostic),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(diagnostic.is_file())
            self.assertFalse(sentinel.exists())


class TransientClassifierTests(unittest.TestCase):
    """Regressions for fail-closed classification and full-attempt priority."""

    _DEFAULT = object()

    STALL_LOG = (
        "[nat-sim] ROUND 1: FAIL reason_code=relay_business_gate_failed relay_first_evidence "
        "overlay_ok=0 a_direct=0 b_direct=0 a_overlay=67 b_overlay=2 "
        "a_relay_confirmed=1 b_relay_confirmed=1 "
        "a_ingress=relay:tcp://127.0.0.1:43801 b_ingress=relay:tcp://127.0.0.1:43801 "
        "a_delta_ms=177 b_delta_ms=3 sum_delta_ms=180 drops_a=0 drops_b=0 "
        "replay_a=0 replay_b=0 invalid_a=0 invalid_b=0 burst_a=0 burst_b=0 "
        "burst_bad_a=2 burst_bad_b=2 status_http_200_a=156/156 status_http_200_b=156/156 "
        "status_always_200_a=1 status_always_200_b=1 task_health_a=1 task_health_b=1 "
        "elapsed_ms=107801 failure_reason=none\n"
    )

    @staticmethod
    def _ready_records():
        records = []
        for side, pid in (("a", 101), ("b", 202)):
            records.append(
                {
                    "schema_version": 1,
                    "stage": "token",
                    "side": side,
                    "state": "TOKEN_READY",
                    "result": "ready",
                    "business_validation_started": True,
                    "pid": pid,
                    "process_alive": True,
                    "token_present": True,
                }
            )
            records.append(
                {
                    "schema_version": 1,
                    "stage": "baseline",
                    "side": side,
                    "state": "STATUS_READY",
                    "result": "ready",
                    "business_validation_started": True,
                    "pid": pid,
                    "process_alive": True,
                    "token_present": True,
                    "http_status": 200,
                    "attempts": 1,
                }
            )
        records.append(
            {
                "schema_version": 1,
                "stage": "barrier",
                "state": "RUNNING",
                "result": "ready",
                "business_validation_started": True,
                "pid_a": 101,
                "pid_b": 202,
                "process_alive_a": True,
                "process_alive_b": True,
                "relay_peer_confirmed_a": True,
                "relay_peer_confirmed_b": True,
                "http_status_a": 200,
                "http_status_b": 200,
                "task_health_a": True,
                "task_health_b": True,
            }
        )
        return records

    @staticmethod
    def _failed_evidence(reason="relay_business_gate_failed"):
        topology = "relay-blackhole"
        return {
            "schema_version": 1,
            "repository": "yhan-sun/p2wlan",
            "source_head_sha": "1" * 40,
            "workflow_sha": "2" * 40,
            "topology": topology,
            "replica": 1,
            "round": 1,
            "scenario_id": f"{topology}:replica-1:round-1",
            "exact_test_id": f"nat-sim-smoke.sh::{topology}::replica-1::round-1",
            "executed": True,
            "skipped": False,
            "result": "fail",
            "observed": {"a": {}, "b": {}},
            "collector": {"revision_converged": False},
            "invariants": {"a": {}, "b": {}},
            "decision": {
                "result": "fail",
                "reason_code": reason,
                "observed_decision": "first_usable_not_accepted",
            },
        }

    @classmethod
    def _direct_failed_evidence(cls):
        evidence = cls._failed_evidence(reason="business_validation_failed")
        evidence["topology"] = "direct-cold-start"
        evidence["scenario_id"] = "direct-cold-start:replica-1:round-1"
        evidence["exact_test_id"] = "nat-sim-smoke.sh::direct-cold-start::replica-1::round-1"
        return evidence

    def _classify(self, log=None, evidence=_DEFAULT, readiness=None, **kwargs):
        return TRANSIENT.classify_attempt(
            self.STALL_LOG if log is None else log,
            self._failed_evidence() if evidence is self._DEFAULT else evidence,
            1,
            profile="relay-blackhole",
            readiness=self._ready_records() if readiness is None else readiness,
            business_started=True,
            **kwargs,
        )

    def test_data_plane_stall_is_never_retryable_after_business_started(self):
        verdict = self._classify()
        self.assertFalse(verdict["retryable"])
        self.assertEqual(verdict["reason"], "business_validation_failed")

    def test_overlay_failure_without_required_health_evidence_is_hard(self):
        verdict = self._classify(
            log="ROUND 1: FAIL overlay_ok=0",
            evidence=None,
            readiness=None,
        )
        self.assertFalse(verdict["retryable"])
        self.assertIn(verdict["reason"], {"gate_line_reason_missing", "profile_fields_missing:overlay_ok"})

    def test_profile_missing_required_fields_is_hard(self):
        verdict = self._classify(
            log="ROUND 1: FAIL reason_code=relay_business_gate_failed overlay_ok=0",
            evidence=None,
        )
        self.assertFalse(verdict["retryable"])
        self.assertTrue(verdict["reason"].startswith("profile_fields_missing:"))

    def test_invalid_replay_type_is_not_treated_as_a_missing_field(self):
        verdict = self._classify(log=self.STALL_LOG.replace("replay_a=0", "replay_a=INVALID"))
        self.assertFalse(verdict["retryable"])
        self.assertEqual(verdict["reason"], "profile_field_type_invalid:replay_a")

    def test_direct_profile_requires_its_full_typed_summary_contract(self):
        line = (
            "ROUND 1: FAIL reason_code=business_validation_failed a_direct=0 b_direct=0 "
            "a_overlay=0 b_overlay=0 a_relay_confirmed=1 b_relay_confirmed=1 "
            "a_ingress=none b_ingress=none a_delta_ms=0 b_delta_ms=0 sum_delta_ms=0 "
            "drops_a=0 drops_b=0 replay_a=0 replay_b=0 invalid_a=0 invalid_b=0 elapsed_ms=100"
        )
        verdict = TRANSIENT.classify_attempt(
            line.replace("replay_a=0", "replay_a=INVALID"),
            self._direct_failed_evidence(),
            1,
            profile="direct-cold-start",
            readiness=self._ready_records(),
            business_started=True,
        )
        self.assertFalse(verdict["retryable"])
        self.assertEqual(verdict["reason"], "profile_field_type_invalid:replay_a")

        missing = TRANSIENT.classify_attempt(
            line.replace("a_overlay=0 ", ""),
            self._direct_failed_evidence(),
            1,
            profile="direct-cold-start",
            readiness=self._ready_records(),
            business_started=True,
        )
        self.assertFalse(missing["retryable"])
        self.assertTrue(missing["reason"].startswith("profile_fields_missing:"))

    def test_hard_failure_earlier_in_attempt_wins_over_later_summary(self):
        log = (
            "ROUND 1: FAIL reason_code=relay_first_slo_exceeded\n"
            + self.STALL_LOG
        )
        verdict = self._classify(log=log)
        self.assertFalse(verdict["retryable"])
        self.assertEqual(verdict["reason"], "hard_line_reason")

    def test_hard_failure_outweighs_later_unknown_reason_and_damaged_evidence(self):
        log = (
            "ROUND 1: FAIL reason_code=relay_first_slo_exceeded\n"
            "[nat-sim] FAIL reason_code=not_a_known_reason\n"
        )
        verdict = self._classify(
            log=log,
            evidence=None,
            readiness_errors=["node-a.readiness.json:JSONDecodeError"],
            evidence_error="nat-evidence.json:JSONDecodeError",
        )
        self.assertFalse(verdict["retryable"])
        self.assertEqual(verdict["reason"], "hard_line_reason")
        self.assertEqual(verdict["signature"]["hard_reason_codes"], ["relay_first_slo_exceeded"])

    def test_hard_evidence_reason_outweighs_later_readiness_summary(self):
        evidence = self._failed_evidence(reason="relay_first_slo_exceeded")
        timeout = {
            "schema_version": 1,
            "stage": "token",
            "state": "STARTING",
            "result": "timeout",
            "business_validation_started": True,
            "side": "a",
            "pid": 404,
            "process_alive": True,
            "token_present": False,
        }
        verdict = TRANSIENT.classify_attempt(
            "[nat-sim] FAIL reason_code=daemon_readiness_timeout",
            evidence,
            1,
            profile="relay-blackhole",
            readiness=[timeout],
            business_started=True,
        )
        self.assertFalse(verdict["retryable"])
        self.assertEqual(verdict["reason"], "hard_evidence_reason")

    def test_process_exit_readiness_wins_over_later_not_ready_text(self):
        process_exit = {
            "schema_version": 1,
            "stage": "token",
            "state": "STARTING",
            "result": "process_exited",
            "business_validation_started": False,
            "side": "a",
            "pid": 404,
            "process_alive": False,
            "token_present": False,
        }
        verdict = self._classify(
            log="[nat-sim] FAIL reason_code=daemon_not_token_ready",
            evidence=None,
            readiness=[process_exit],
        )
        self.assertFalse(verdict["retryable"])
        self.assertEqual(verdict["reason"], "process_exited")

    def test_missing_evidence_never_allows_overlay_failure_retry(self):
        verdict = self._classify(evidence=None)
        self.assertFalse(verdict["retryable"])
        self.assertEqual(verdict["reason"], "evidence_missing")

    def test_corrupt_evidence_json_is_hard(self):
        verdict = self._classify(evidence=None, evidence_error="nat-evidence.json:JSONDecodeError")
        self.assertFalse(verdict["retryable"])
        self.assertEqual(verdict["reason"], "evidence_corrupt")

    def test_unknown_failure_reason_is_hard(self):
        verdict = self._classify(log=self.STALL_LOG.replace("relay_business_gate_failed", "mystery_failure"))
        self.assertFalse(verdict["retryable"])
        self.assertEqual(verdict["reason"], "unknown_failure_reason")

    def test_structured_startup_timeout_is_not_process_exit_or_retry(self):
        timeout = {
            "schema_version": 1,
            "stage": "token",
            "state": "STARTING",
            "result": "timeout",
            "business_validation_started": False,
            "side": "a",
            "pid": 404,
            "process_alive": True,
            "token_present": False,
        }
        verdict = TRANSIENT.classify_attempt(
            "[nat-sim] FAIL reason_code=daemon_readiness_timeout",
            None,
            1,
            profile="relay-blackhole",
            readiness=[timeout],
            business_started=False,
        )
        self.assertFalse(verdict["retryable"])
        self.assertEqual(verdict["reason"], "readiness_not_ready")

    def test_barrier_timeout_is_hard_and_structured(self):
        barrier = {
            "schema_version": 1,
            "stage": "barrier",
            "state": "STATUS_READY",
            "result": "barrier_timeout",
            "business_validation_started": True,
            "pid_a": 101,
            "pid_b": 202,
            "process_alive_a": True,
            "process_alive_b": True,
            "relay_peer_confirmed_a": True,
            "relay_peer_confirmed_b": False,
            "http_status_a": 200,
            "http_status_b": 200,
            "task_health_a": True,
            "task_health_b": True,
        }
        verdict = TRANSIENT.classify_attempt(
            "[nat-sim] FAIL reason_code=relay_peer_confirmation_timeout",
            None,
            1,
            profile="relay-blackhole",
            readiness=[barrier],
            business_started=True,
        )
        self.assertFalse(verdict["retryable"])
        self.assertEqual(verdict["reason"], "barrier_timeout")

    def test_structured_barrier_timeout_is_not_misreported_as_missing_evidence(self):
        records = self._ready_records()
        barrier = records[-1]
        barrier.update(
            {
                "state": "STATUS_READY",
                "result": "barrier_timeout",
                "relay_peer_confirmed_b": False,
                "reason_code": "relay_peer_confirmation_timeout",
            }
        )
        verdict = self._classify(
            log="ROUND 1: FAIL reason_code=relay_peer_confirmation_timeout stage=barrier",
            evidence=None,
            evidence_error="nat-evidence.json:missing",
            readiness=records,
        )
        self.assertFalse(verdict["retryable"])
        self.assertEqual(verdict["reason"], "barrier_timeout")

    def test_barrier_http_and_task_failures_remain_observable(self):
        cases = (
            ("http_failure", "readiness_http_failure", {"http_status_a": 503, "reason_code": "status_unavailable"}),
            ("task_failed", "readiness_task_failure", {"task_health_a": False, "reason_code": "critical_tasks_unhealthy"}),
        )
        for result, expected, updates in cases:
            with self.subTest(result=result):
                records = self._ready_records()
                records[-1].update({"state": "STATUS_READY", "result": result, **updates})
                verdict = TRANSIENT.classify_attempt(
                    "",
                    self._failed_evidence(),
                    1,
                    profile="relay-blackhole",
                    readiness=records,
                    business_started=True,
                )
                self.assertFalse(verdict["retryable"])
                self.assertEqual(verdict["reason"], expected)

    def test_non_string_readiness_discriminator_is_corrupt_not_a_crash(self):
        readiness = self._ready_records()
        readiness[0]["stage"] = ["token"]
        verdict = self._classify(readiness=readiness)
        self.assertFalse(verdict["retryable"])
        self.assertEqual(verdict["reason"], "readiness_evidence_corrupt")

    def test_non_string_evidence_result_is_corrupt_not_a_crash(self):
        evidence = self._failed_evidence()
        evidence["result"] = ["fail"]
        verdict = self._classify(evidence=evidence)
        self.assertFalse(verdict["retryable"])
        self.assertEqual(verdict["reason"], "evidence_schema_invalid")

    def test_contradictory_process_exit_record_is_corrupt(self):
        contradictory = {
            "schema_version": 1,
            "stage": "token",
            "state": "TOKEN_READY",
            "result": "process_exited",
            "business_validation_started": False,
            "side": "a",
            "pid": 404,
            "process_alive": True,
            "token_present": True,
        }
        verdict = TRANSIENT.classify_attempt(
            "[nat-sim] FAIL reason_code=daemon_not_token_ready",
            None,
            1,
            profile="relay-blackhole",
            readiness=[contradictory],
            business_started=False,
        )
        self.assertFalse(verdict["retryable"])
        self.assertEqual(verdict["reason"], "readiness_evidence_corrupt")

    def test_cli_rejects_damaged_json_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / "attempt.log"
            evidence = root / "nat-evidence.json"
            output = root / "classification.json"
            log.write_text("[nat-sim] RESULT: FAIL\n", encoding="utf-8")
            evidence.write_text("{broken", encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()):
                status = TRANSIENT.main(
                    [
                        "classify",
                        "--profile",
                        "relay-blackhole",
                        "--log",
                        str(log),
                        "--evidence",
                        str(evidence),
                        "--output",
                        str(output),
                    ]
                )
            self.assertEqual(status, 1)
            self.assertEqual(json.loads(output.read_text())["reason"], "evidence_corrupt")

    def test_second_attempt_cannot_clear_first_business_failure(self):
        first = {"exit_code": 1, "business_validation_started": True}
        second = {"exit_code": 0, "business_validation_started": True}
        self.assertNotEqual(first["exit_code"], 0)
        self.assertEqual(second["exit_code"], 0)
        self.assertTrue(first["business_validation_started"])
        self.assertTrue(second["business_validation_started"])


if __name__ == "__main__":
    unittest.main()
