#!/usr/bin/env python3
"""Strict, peer-scoped Direct evidence validation for the Mini/Air harness."""

from __future__ import print_function

import ipaddress
import json
import re
import sys


REQUIRED_STAGES = (
    "direct_validation_request_sent",
    "direct_validation_ack_received",
    "direct_validation_promoted",
    "direct_path_promoted",
)


def endpoint_is_public_ipv4(endpoint):
    try:
        host, _port = endpoint.rsplit(":", 1)
        address = ipaddress.ip_address(host)
    except (AttributeError, ValueError):
        return False
    return address.version == 4 and address.is_global


def peer_for(status, peer_id):
    scoped = status.get("peer")
    if scoped is not None:
        return scoped if scoped.get("node_id") == peer_id else None
    return next((peer for peer in status.get("peers", []) if peer.get("node_id") == peer_id), None)


def key_for(event, peer_id):
    values = (
        peer_id,
        event.get("network_generation"),
        event.get("validation_session_id"),
        event.get("request_id"),
        event.get("socket_index"),
    )
    return values if all(value is not None for value in values) else None


def validate(status, peer_id):
    peer = peer_for(status, peer_id)
    if peer is None:
        return False, "target_peer_missing", None
    # Scoped diagnostics expose the number of peer connections visible in the
    # test network. A two-device network has exactly one remote peer per side;
    # any larger roster is background activity and is not clean acceptance.
    if "network_peer_count" in status and status.get("network_peer_count") != 1:
        return False, "network_not_isolated", None
    pair = peer.get("selected_pair") or peer.get("current_direct_pair") or {}
    endpoint = pair.get("remote_endpoint") or ""
    if not (
        peer.get("state") == "direct"
        and peer.get("active_path") == "direct"
        and peer.get("is_public_udp_direct") is True
        and endpoint_is_public_ipv4(endpoint)
    ):
        return False, "target_not_public_direct", None

    current_generation = status.get("network_generation")
    grouped = {}
    for event in peer.get("direct_events", []):
        if event.get("stage") not in REQUIRED_STAGES:
            continue
        key = key_for(event, peer_id)
        if key is None or key[1] != current_generation:
            continue
        grouped.setdefault(key, {}).setdefault(event["stage"], []).append(event)

    for key, stages in grouped.items():
        if not all(stage in stages for stage in REQUIRED_STAGES):
            continue
        request = stages["direct_validation_request_sent"][-1]
        ack = stages["direct_validation_ack_received"][-1]
        promoted = stages["direct_validation_promoted"][-1]
        path = stages["direct_path_promoted"][-1]
        expected = request.get("expected_endpoint")
        observed = ack.get("observed_ack_endpoint")
        selected = promoted.get("selected_endpoint")
        if not expected or not observed or not selected:
            continue
        if ack.get("expected_endpoint") != expected:
            continue
        if promoted.get("expected_endpoint") != expected or path.get("expected_endpoint") != expected:
            continue
        if promoted.get("observed_ack_endpoint") != observed or path.get("observed_ack_endpoint") != observed:
            continue
        if path.get("selected_endpoint") != selected or selected != observed or endpoint != selected:
            continue
        if expected != observed and ack.get("ack_endpoint_authenticated") is not True:
            continue
        return True, "ok", {
            "peer_id": peer_id,
            "generation": key[1],
            "local_validation_session_id": key[2],
            "request_id": key[3],
            "socket_index": key[4],
            "expected_endpoint": expected,
            "observed_ack_endpoint": observed,
            "selected_endpoint": selected,
            # The peer-scoped endpoint records its own serialization time, so
            # this is the actual committed promotion instant, independent of
            # the later SSH/HTTP transfer that delivered this snapshot.
            "direct_promotion_at_ms": (
                status["captured_at_ms"] - path["age_ms"]
                if isinstance(status.get("captured_at_ms"), int)
                and isinstance(path.get("age_ms"), int)
                else None
            ),
        }
    return False, "no_current_complete_owned_validation_chain", None


def load(path):
    with open(path, "r") as stream:
        return json.load(stream)


def round_summary(status, peer_id):
    """Return peer-scoped audit metadata without relaxing strict acceptance."""
    peer = peer_for(status, peer_id)
    events = peer.get("direct_events", []) if peer else []

    def details_for(stage):
        return [event.get("detail", "") for event in events if event.get("stage") == stage]

    def last_detail_value(stage, field):
        pattern = re.compile(r"\b%s=(?:Some\()?(-?\d+)" % re.escape(field))
        for detail in reversed(details_for(stage)):
            match = pattern.search(detail)
            if match:
                return int(match.group(1))
        return None

    promotion_index = next(
        (
            index
            for index, event in enumerate(events)
            if event.get("stage") == "direct_path_promoted"
        ),
        None,
    )
    traversal_starts = {
        "punch_started",
        "peer_reflexive_fast_punch_started",
        "retry_punch_started",
        "direct_reclaim_punch_started",
    }
    post_direct_traversal_starts = (
        [
            event.get("stage")
            for event in events[promotion_index + 1:]
            if event.get("stage") in traversal_starts
        ]
        if promotion_index is not None
        else []
    )
    ok, reason, key = validate(status, peer_id)
    return {
        "strict": {"ok": ok, "reason": reason, "key": key},
        "background_peer_count": status.get(
            "network_peer_count",
            sum(1 for candidate in status.get("peers", []) if candidate.get("node_id") != peer_id),
        ),
        "network_generation": status.get("network_generation"),
        "candidate_snapshot_version": status.get("candidate_snapshot_version"),
        "candidate_snapshot_hash": status.get("candidate_snapshot_hash"),
        "nat_profile": status.get("nat_profile"),
        "relay_connected": status.get("relay_connected"),
        "relay_servers": status.get("relay_servers", []),
        "udp_socket_pool": status.get("udp_socket_pool", []),
        "punch_at_ms": last_detail_value("punch_first_packet_sent", "punch_at_ms"),
        "first_packet_at_ms": last_detail_value("punch_first_packet_sent", "actual_first_send_at_ms"),
        "first_packet_deviation_ms": last_detail_value(
            "punch_first_packet_sent", "first_send_deviation_ms"
        ),
        "post_direct_traversal_starts": post_direct_traversal_starts,
    }


def main(argv):
    if len(argv) == 3:
        status = load(argv[1])
        ok, reason, key = validate(status, argv[2])
        print(json.dumps({"ok": ok, "reason": reason, "key": key}, sort_keys=True))
        return 0 if ok else 1
    if len(argv) == 6 and argv[1] == "--pair":
        left = validate(load(argv[2]), argv[3])
        right = validate(load(argv[4]), argv[5])
        ok = left[0] and right[0]
        print(json.dumps({
            "ok": ok,
            "left": {"reason": left[1], "key": left[2]},
            "right": {"reason": right[1], "key": right[2]},
        }, sort_keys=True))
        return 0 if ok else 1
    if len(argv) == 4 and argv[1] == "--summary":
        print(json.dumps(round_summary(load(argv[2]), argv[3]), sort_keys=True))
        return 0
    raise SystemExit("usage: strict-direct-parser.py STATUS PEER_ID | --pair A_STATUS A_PEER B_STATUS B_PEER | --summary STATUS PEER_ID")


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
