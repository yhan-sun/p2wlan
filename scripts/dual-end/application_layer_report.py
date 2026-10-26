#!/usr/bin/env python3
"""Join fixed TCP requests with local service, socket and initial-queue observations.

No cross-host clock subtraction or RTT-minus-service estimate. TCP retransmits
remain connection totals. Packet intervals shared by multiple frames are listed
for each matching request, never added into request or end-to-end latency.
"""
from __future__ import annotations

import argparse
from collections import Counter
import copy
import hashlib
import json
from pathlib import Path

import tcp_business_probe as tcp
import tcp_socket_observation as sockets
from udp_business_probe import UNVERIFIED, write_report

MAX_BYTES = 32 * 1024 * 1024
U64 = (1 << 64) - 1
QUEUE_SCOPE = "same_packet_initial_bounded_queue_intervals"
QUEUE_CLOCK = "process_local_std_instant_differences_only"


def integer(value, maximum=U64):
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError("integer_out_of_range")
    return value


def unavailable(reason):
    return {"availability": "unavailable", "reason": reason}


def service_rows(echo, requests):
    rows = echo.get("application_service_intervals")
    if rows is None:
        return {}
    if not isinstance(rows, list) or len(rows) > len(requests):
        raise ValueError("service_capacity_or_duplicate")
    result = {}
    for row in rows:
        seq = integer(row["sequence"], len(requests) - 1)
        if seq in result or row["request_nonce"] != requests[seq]["request_nonce"]:
            raise ValueError("service_request_identity_or_duplicate")
        if row["scope"] != "local_echo_decode_and_response_write_interval_only":
            raise ValueError("service_scope_changed")
        start = integer(row["request_read_complete_ns"])
        write = integer(row["response_write_started_ns"])
        end = integer(row["response_write_returned_ns"])
        if not start <= write <= end or row["status"] not in ("response_complete", "write_failed"):
            raise ValueError("service_interval_or_status_invalid")
        result[seq] = {"availability": "available", "scope": row["scope"],
                       "status": row["status"], "decode_to_write_started_ns": write - start,
                       "decode_through_write_returned_ns": end - start,
                       "includes_validation_scheduling_and_write_backpressure": True,
                       "clock": "echo_process_monotonic_differences_only"}
    return result


def socket_interval(report):
    observation = report.get("tcp_observation")
    if observation is None:
        return unavailable("TCP_observation_not_requested")
    if (observation.get("scope") != "same_OS_TCP_connection_interval_only"
            or observation.get("sample_budget") != 2
            or any(observation.get(k) is not False for k in (
                "request_attribution_verified", "p2wlan_path_verified", "native_owner_credit_verified"))):
        raise ValueError("TCP_observation_scope_or_credit_changed")
    samples = observation.get("samples")
    if samples == [] and observation.get("availability") == "unavailable":
        return unavailable(observation.get("reason", "no_connected_socket_observed"))
    if not isinstance(samples, list) or len(samples) != 2:
        raise ValueError("TCP_sample_budget_changed")
    computed = sockets.interval(*samples)
    if observation.get("interval") != computed or observation.get("availability") != computed["availability"]:
        raise ValueError("TCP_interval_does_not_match_original_samples")
    return {"scope": "connection_interval_only", "request_attribution_verified": False,
            "interval": copy.deepcopy(computed)}


def queue_interval(row):
    if row["availability"] == "available":
        return {"availability": "available", "nanoseconds": integer(row["nanoseconds"])}
    if row["availability"] != "unavailable" or row.get("reason") not in (
            "boundary_missing", "clock_order_invalid", "duration_out_of_range", "not_observed_by_this_scope"):
        raise ValueError("queue_interval_invalid")
    return unavailable(row["reason"])


def queue_rows(captures, probe, requests):
    if len(captures) > 2:
        raise ValueError("daemon_capture_capacity")
    result = {i: [] for i in range(len(requests))}
    prepared = probe.get("request_plan")
    producer = None if prepared is None else prepared.get("producer_scope")
    if prepared is not None and (not isinstance(producer, str) or len(producer) != 32
                                or any(c not in "0123456789abcdef" for c in producer)):
        raise ValueError("prepared_producer_scope_invalid")
    capture_owners = set()
    for capture in captures:
        if (capture.get("scope") != "registered_native_frame_capture"
                or capture.get("schema_version") != 2):
            raise ValueError("daemon_capture_scope_changed")
        identity = (capture["producer_scope"], capture["capture_id"], integer(capture["owner"]))
        if identity in capture_owners:
            raise ValueError("duplicate_daemon_capture")
        capture_owners.add(identity)
        rows, packets = capture["requests"], capture["historical_full_packets"]
        if len(rows) > 1000 or len(packets) > 1024:
            raise ValueError("original_daemon_capture_capacity")
        matching = {}
        for row in rows:
            if (row["run_nonce"], row["round_nonce"]) != (probe["run_nonce"], probe["round_nonce"]):
                continue
            # One descriptor contains multiple flows with the same run/round.
            # Select the original tool plan's producer before checking its
            # complete request identity; another flow never supplies bytes.
            if producer is not None and row.get("producer_scope") != producer:
                continue
            seq = integer(row["sequence"], len(requests) - 1)
            key = (integer(row["flow"], 999), seq)
            if (row["request_nonce"] != requests[seq]["request_nonce"] or row["kind"] not in ("request", "response")
                    or row["protocol"] != "tcp" or key in matching):
                raise ValueError("daemon_request_identity_or_duplicate")
            matching[key] = row
        seen_packets = set()
        for packet in packets:
            packet_key = (integer(packet["flow"], 999), integer(packet["read_ordinal"]))
            if packet_key in seen_packets:
                raise ValueError("duplicate_same_read_packet")
            seen_packets.add(packet_key)
            digest = packet["packet_sha256"]
            if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
                raise ValueError("packet_digest_invalid")
            spans = packet["spans"]
            if not isinstance(spans, list) or len(spans) > 8:
                raise ValueError("original_binding_capacity")
            selected = set()
            for span in spans:
                slot = integer(span["slot"], 999)
                if integer(span["start"], 1204) >= integer(span["end"], 1204):
                    raise ValueError("packet_frame_span_invalid")
                key = (packet_key[0], slot)
                if key in matching:
                    selected.add(key)
            timing = packet.get("initial_queue_intervals")
            if timing is None:
                observation = unavailable("first_queue_observation_unavailable")
            else:
                if (timing.get("schema_version"), timing.get("scope"), timing.get("clock")) != (1, QUEUE_SCOPE, QUEUE_CLOCK):
                    raise ValueError("queue_clock_or_scope_changed")
                observation = {"availability": "available", "scope": QUEUE_SCOPE, "clock": QUEUE_CLOCK,
                               **{k: queue_interval(timing[k]) for k in (
                                   "dataplane_queue", "network_outbound_queue", "pending_queue")}}
                if observation["pending_queue"] != unavailable("not_observed_by_this_scope"):
                    raise ValueError("unobserved_pending_queue_cannot_gain_a_value")
            for key in sorted(selected):
                row = matching[key]
                result[row["sequence"]].append({"capture_producer_scope": identity[0], "request_producer_scope": row["producer_scope"], "capture_id": identity[1],
                    "capture_owner": identity[2], "flow": packet_key[0], "read_ordinal": packet_key[1],
                    "packet_sha256": digest, "kind": row["kind"], "request_nonce": row["request_nonce"],
                    "shared_packet_across_request_frames": len(selected) > 1, "intervals": copy.deepcopy(observation)})
    return result


def combine(probe, echo, captures=()):
    requests = tcp.validate_probe(probe)
    if (echo.get("scope"), echo.get("schema_version"), echo.get("role")) != (tcp.SCOPE, 1, "echo"):
        raise ValueError("echo_scope_changed")
    if (probe["run_nonce"], probe["round_nonce"]) != (echo["run_nonce"], echo["round_nonce"]):
        raise ValueError("echo_round_identity_changed")
    if (echo.get("evidence") != UNVERIFIED or type(echo.get("accepted_connections")) is not int
            or echo["accepted_connections"] not in (0, 1)):
        raise ValueError("echo_credit_or_connection_attempts_changed")
    for key in ("count", "interval_ms", "timeout_ms", "duration_ms", "payload_bytes"):
        if probe["configuration"][key] != echo["configuration"][key]:
            raise ValueError("echo_fixed_workload_changed")
    service, queues = service_rows(echo, requests), queue_rows(captures, probe, requests)
    rows = [{**copy.deepcopy(row), "service_observation": service.get(i, unavailable("no_matching_service_observation")),
             "daemon_queue_observations": queues[i],
             "daemon_queue_availability": "packet_intervals_listed" if queues[i] else "unavailable"}
            for i, row in enumerate(requests)]
    return {"schema_version": 1, "scope": "same_request_layered_observations_only",
            "tool_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "run_nonce": probe["run_nonce"], "round_nonce": probe["round_nonce"],
            "configuration": copy.deepcopy(probe["configuration"]), "fixed_denominator": len(requests),
            "outcomes": {k: Counter(r["status"] for r in requests)[k] for k in tcp.STATUSES},
            "requests": rows, "connection_retransmissions": {"probe": socket_interval(probe), "echo": socket_interval(echo)},
            "queue_scope": "initial_dataplane_and_network_channels_including_backpressure_only",
            "unobserved": ["pending_queue", "lock_wait", "crypto_CPU", "kernel_queue", "cross_host_network_only_RTT"],
            "packet_intervals_summed_into_request_latency": False, "cross_host_clocks_subtracted": False,
            "RTT_minus_service_used_as_network_RTT": False, "evidence": dict(UNVERIFIED)}


def read_input(path):
    with path.open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("input_capacity_exceeded")
    return json.loads(raw), {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", type=Path, required=True)
    parser.add_argument("--echo", type=Path, required=True)
    parser.add_argument("--daemon-capture", type=Path, action="append", default=[])
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if len(args.daemon_capture) > 2:
        parser.error("at most two original daemon capture files")
    inputs = [read_input(p) for p in [args.probe, args.echo, *args.daemon_capture]]
    report = combine(inputs[0][0], inputs[1][0], [v[0] for v in inputs[2:]])
    report["input_files"] = [v[1] for v in inputs]
    write_report(args.out, report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
