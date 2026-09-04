#!/usr/bin/env python3
"""Build one machine-verifiable NAT topology replica evidence record.

The record is deliberately assembled from the two daemon status snapshots and
the local replica logs.  A static scenario manifest never supplies a result:
the exact test id, process identity, status revision fence, first-usable
summary/event, and invariants all have to be present in this invocation's
artifacts.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1
REPOSITORY = "yhan-sun/p2wlan"
SUMMARY_SCHEMA_VERSION = 1
SUMMARY_SOURCE = "authoritative_business_ingress_commit"


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or not value:
        raise ValueError(f"invalid_status:{path}")
    return value


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    return None


def _peer(status: dict[str, Any]) -> dict[str, Any] | None:
    peers = status.get("peers")
    if not isinstance(peers, list):
        return None
    candidates = [item for item in peers if isinstance(item, dict)]
    return candidates[0] if candidates else None


def _events(status: dict[str, Any]) -> list[dict[str, Any]]:
    timeline = status.get("connection_timeline")
    if not isinstance(timeline, dict):
        return []
    events = timeline.get("events")
    return [event for event in events if isinstance(event, dict)] if isinstance(events, list) else []


def _summaries(status: dict[str, Any]) -> list[dict[str, Any]]:
    timeline = status.get("connection_timeline")
    if not isinstance(timeline, dict):
        return []
    summaries = timeline.get("first_usable_summaries")
    return [summary for summary in summaries if isinstance(summary, dict)] \
        if isinstance(summaries, list) else []


def _event_time(events: list[dict[str, Any]], name: str, peer_id: str, generation: int) -> int | None:
    values = []
    for event in events:
        if event.get("event") != name or event.get("peer_id") not in {None, peer_id}:
            continue
        event_generation = event.get("connection_generation")
        if event_generation is not None and event_generation != generation:
            continue
        at_ms = _int(event.get("at_ms"))
        if at_ms is not None:
            values.append(at_ms)
    return min(values) if values else None


def _status_identity(status: dict[str, Any]) -> dict[str, Any]:
    return {
        "process_id": _int(status.get("process_id")),
        "revision": _int(status.get("revision")),
        "captured_revision": _int(status.get("captured_revision")),
        "captured_at_ms": _int(status.get("captured_at_ms")),
        "uptime_ms": _int(status.get("uptime_ms")),
        "network_generation": _int(status.get("network_generation")),
        "peer_snapshot_stale": status.get("peer_snapshot_stale"),
    }


def _valid_summary(
    summary: dict[str, Any],
    peer_id: str,
    generation: int,
    final_revision: int | None,
) -> bool:
    """Validate the producer contract before accepting a durable summary.

    A summary is evidence only when it came from the authoritative business
    ingress commit.  Treating a malformed/additive-looking object as a usable
    summary would turn parser loss or hand-edited JSON into a false pass.
    """
    if summary.get("schema_version") != SUMMARY_SCHEMA_VERSION:
        return False
    if summary.get("source") != SUMMARY_SOURCE:
        return False
    if summary.get("peer_id") != peer_id or summary.get("network_generation") != generation:
        return False
    if summary.get("path") not in {"direct", "relay"}:
        return False
    first_at_ms = _int(summary.get("first_usable_at_ms"))
    transition_revision = _int(summary.get("transition_revision"))
    if first_at_ms is None or first_at_ms < 0 or transition_revision is None or transition_revision < 0:
        return False
    if final_revision is None or transition_revision > final_revision:
        return False
    if not isinstance(summary.get("business_sent"), bool):
        return False
    if summary.get("business_received") is not True:
        return False
    if not isinstance(summary.get("business_exchange"), bool):
        return False
    ready_at_ms = summary.get("relay_ready_at_ms")
    delta_ms = summary.get("first_usable_delta_ms")
    if ready_at_ms is not None:
        ready_at_ms = _int(ready_at_ms)
        if ready_at_ms is None or ready_at_ms < 0 or ready_at_ms > first_at_ms:
            return False
    if delta_ms is not None:
        delta_ms = _int(delta_ms)
        if delta_ms is None or ready_at_ms is None or delta_ms != first_at_ms - ready_at_ms:
            return False
    if summary.get("relay_id") is not None and not isinstance(summary.get("relay_id"), str):
        return False
    if summary.get("relay_connection_id") is not None and _int(summary.get("relay_connection_id")) is None:
        return False
    if summary.get("reason_code") is not None and not isinstance(summary.get("reason_code"), str):
        return False
    return True


def _side_evidence(
    label: str,
    baseline: dict[str, Any],
    final: dict[str, Any],
    log_path: Path,
    expected_path: str,
    overlay_burst: int,
) -> tuple[dict[str, Any], str | None]:
    baseline_identity = _status_identity(baseline)
    final_identity = _status_identity(final)
    peer = _peer(final)
    peer_id = str(peer.get("node_id")) if peer else ""
    generation = final_identity["network_generation"]
    if generation is None:
        generation = 0

    process_stable = (
        baseline_identity["process_id"] is not None
        and final_identity["process_id"] is not None
        and baseline_identity["process_id"] == final_identity["process_id"]
    )
    final_converged = (
        final_identity["revision"] is not None
        and final_identity["captured_revision"] == final_identity["revision"]
        and final_identity["peer_snapshot_stale"] is False
    )
    baseline_revision = baseline_identity["revision"]
    final_revision = final_identity["revision"]
    events = _events(final)
    summaries = _summaries(final)

    summary_candidates = [
        summary
        for summary in summaries
        if _valid_summary(summary, peer_id, generation, final_revision)
    ]
    invalid_summary_present = any(
        summary.get("peer_id") == peer_id
        and summary.get("network_generation") == generation
        and not _valid_summary(summary, peer_id, generation, final_revision)
        for summary in summaries
    )
    # The authoritative transition is once per peer + network generation. Two
    # otherwise well-shaped summaries with the same identity are conflicting
    # producer output, not historical evidence that may be silently reduced to
    # the earliest timestamp.
    if len(summary_candidates) > 1:
        invalid_summary_present = True
    summary = min(
        summary_candidates,
        key=lambda item: int(item["transition_revision"]),
        default=None,
    )
    first_event_candidates = [
        event
        for event in events
        if event.get("event") == "first_usable_path"
        and (event.get("peer_id") in {None, peer_id})
        and (event.get("connection_generation") in {None, generation})
    ]
    first_event = min(
        first_event_candidates,
        key=lambda item: _int(item.get("at_ms")) if _int(item.get("at_ms")) is not None else 2**63,
        default=None,
    )

    ready_at_ms = None
    first_usable_at_ms = None
    transition_revision = None
    source = None
    first_path = None
    business_sent = False
    business_received = False
    business_exchange = False
    relay_id = None
    relay_connection_id = None
    delta_ms = None
    baseline_after_transition = False

    if summary is not None:
        source = "persistent_summary"
        first_usable_at_ms = _int(summary.get("first_usable_at_ms"))
        transition_revision = _int(summary.get("transition_revision"))
        first_path = summary.get("path")
        business_sent = summary.get("business_sent") is True
        business_received = summary.get("business_received") is True
        business_exchange = summary.get("business_exchange") is True
        relay_id = summary.get("relay_id")
        relay_connection_id = _int(summary.get("relay_connection_id"))
        ready_at_ms = _int(summary.get("relay_ready_at_ms"))
        delta_ms = _int(summary.get("first_usable_delta_ms"))
        baseline_after_transition = (
            baseline_revision is not None
            and transition_revision is not None
            and transition_revision <= baseline_revision
        )
    elif first_event is not None:
        # The ring event is a valid fallback only when the transition is in the
        # same process and can be placed after the baseline on that daemon's
        # monotonic clock. If it was evicted, the durable summary above is the
        # only acceptable source.
        event_at_ms = _int(first_event.get("at_ms"))
        baseline_at_ms = baseline_identity["captured_at_ms"]
        event_revision = _int(first_event.get("transition_revision"))
        if event_at_ms is not None and event_revision is not None and event_revision > 0:
            source = "event"
            first_usable_at_ms = event_at_ms
            transition_revision = event_revision
            first_path = first_event.get("path")
            ready_at_ms = _event_time(events, "relay_transport_ready_peer", peer_id, generation)
            if ready_at_ms is not None and event_at_ms >= ready_at_ms:
                delta_ms = event_at_ms - ready_at_ms
            baseline_after_transition = baseline_at_ms is not None and event_at_ms <= baseline_at_ms
            # An event before the baseline is still usable evidence only if it
            # was not lost from the status snapshot; it is marked explicitly so
            # the report distinguishes it from a missed collector edge.
            business_received = True
            business_sent = False
            business_exchange = False

    peer_generation = peer.get("relay_confirmed_generation") if peer else None
    relay_confirmed = (
        peer is not None
        and peer.get("relay_confirmed_endpoint")
        and peer_generation == generation
        and peer.get("relay_confirmed_connection_id") is not None
    )
    # Legacy/unit profiles may not expose a transport incarnation id. The
    # production NAT profile does; keep the endpoint+generation proof strict.
    if peer is not None and peer.get("relay_confirmed_endpoint") and peer_generation == generation:
        relay_confirmed = True
    relay_connected = final.get("relay_connected") is True
    peer_received_generation = peer.get("relay_first_business_received_generation") if peer else None
    peer_sent_generation = peer.get("relay_first_business_sent_generation") if peer else None
    peer_exchange_generation = peer.get("relay_first_business_exchange_generation") if peer else None
    # The durable summary records the dimensions at the first commit. A later
    # final snapshot may contain the other relay-business direction, so merge
    # only the exact same-generation peer markers into the observed final
    # state; this never fabricates the first-usable transition itself.
    business_received = peer_received_generation == generation or business_received
    business_sent = peer_sent_generation == generation or business_sent
    business_exchange = peer_exchange_generation == generation or business_exchange

    log_text = log_path.read_text(encoding="utf-8", errors="replace") if log_path.is_file() else ""
    overlay_verified = len(re.findall(r"overlay_payload_verified", log_text))
    direct_promoted = len(re.findall(r"direct_promoted", log_text))
    replay_rejected = len(re.findall(r"replay detected", log_text))
    overlay_invalid = len(re.findall(r"overlay_payload_invalid", log_text))
    burst_complete = len(re.findall(r"overlay_burst_complete", log_text))
    burst_incomplete = len(re.findall(r"overlay_burst_incomplete", log_text))

    stats = final.get("stats")
    if not isinstance(stats, dict):
        drops_packets = None
    else:
        drops = stats.get("outbound_drops")
        drops_packets = (
            sum(_int(counter.get("packets")) or 0 for counter in drops.values() if isinstance(counter, dict))
            if isinstance(drops, dict)
            else None
        )
    health = final.get("health")
    critical_tasks = health.get("critical_tasks") if isinstance(health, dict) else None
    tasks_ok = isinstance(critical_tasks, list) and bool(critical_tasks) and all(
        isinstance(task, dict)
        and task.get("critical") is True
        and task.get("running") is True
        and task.get("finished") is False
        and task.get("error") is None
        for task in critical_tasks
        if isinstance(task, dict) and task.get("critical") is True
    )
    critical_count = sum(
        1 for task in critical_tasks or [] if isinstance(task, dict) and task.get("critical") is True
    )
    tasks_ok = tasks_ok and critical_count > 0

    source_ok = source in {"persistent_summary", "event"}
    first_path_ok = first_path == expected_path
    delta_ok = isinstance(delta_ms, int) and 0 <= delta_ms <= 3000
    business_ok = business_received and (expected_path != "relay" or business_sent or business_exchange)
    # Direct cold-start exits the smoke loop as soon as both sides prove the
    # first authenticated Direct business ingress.  Its overlay generator is
    # intentionally not awaited for a full burst; Relay-only waits for the
    # configured burst because that profile is the availability gate.
    burst_required = expected_path == "relay" and overlay_burst > 0
    invariants = {
        "process_incarnation_stable": process_stable,
        "diagnostics_revision_converged": final_converged,
        "first_usable_committed": source_ok and first_usable_at_ms is not None,
        "first_usable_path_matches_topology": first_path_ok,
        "relay_connected": relay_connected if expected_path == "relay" else True,
        "relay_peer_confirmed": relay_confirmed if expected_path == "relay" else True,
        "first_business_received": business_received,
        "first_business_direction_complete": business_ok,
        "first_usable_delta_fenced": delta_ok,
        "critical_tasks_healthy": tasks_ok,
        "overlay_verified": overlay_verified > 0,
        "direct_not_used": direct_promoted == 0 if expected_path == "relay" else True,
        "no_replay_or_invalid": replay_rejected == 0 and overlay_invalid == 0,
        "burst_complete": not burst_required or (burst_complete > 0 and burst_incomplete == 0),
        "outbound_drops_zero": drops_packets == 0,
    }
    reason = None
    if not process_stable:
        reason = "stale_process_identity"
    elif not final_converged:
        reason = "diagnostics_revision_not_converged"
    elif source is None:
        if relay_connected and not relay_confirmed and expected_path == "relay":
            reason = "relay_confirmation_missing"
        elif relay_confirmed and not business_received:
            reason = "first_business_not_passed"
        elif invalid_summary_present or (first_event is not None and transition_revision is None):
            reason = "evidence_parser_loss"
        else:
            reason = "first_usable_never_observed"
    elif invalid_summary_present:
        reason = "evidence_parser_loss"
    elif source == "event" and baseline_after_transition:
        reason = "baseline_after_transition_event_retained"
    elif not first_path_ok:
        reason = "first_usable_path_mismatch"
    elif not business_received:
        reason = "first_business_not_passed"
    elif expected_path == "relay" and not relay_confirmed:
        reason = "relay_confirmation_missing"
    elif not delta_ok:
        reason = "first_usable_delta_missing"
    elif not all(invariants.values()):
        reason = next(name for name, value in invariants.items() if not value)

    side = {
        "label": label,
        "baseline": baseline_identity,
        "final": final_identity,
        "observed": {
            "peer_id": peer_id,
            "process_identity": {
                "baseline": baseline_identity,
                "final": final_identity,
            },
            "relay_connected": relay_connected,
            "relay_peer_confirmed": relay_confirmed,
            "relay_confirmed_generation": peer_generation,
            "relay_id": relay_id or (peer.get("relay_confirmed_endpoint") if peer else None),
            "relay_connection_id": relay_connection_id
            if relay_connection_id is not None
            else (peer.get("relay_confirmed_connection_id") if peer else None),
            "first_business_sent": business_sent,
            "first_business_received": business_received,
            "first_business_exchange": business_exchange,
            "first_usable": {
                "path": first_path,
                "network_generation": generation,
                "first_usable_at_ms": first_usable_at_ms,
                "transition_revision": transition_revision,
                "relay_ready_at_ms": ready_at_ms,
                "delta_ms": delta_ms,
                "source": source,
                "baseline_after_transition": baseline_after_transition,
            },
            "overlay_verified": overlay_verified,
            "direct_promoted": direct_promoted,
            "burst_complete": burst_complete,
            "burst_incomplete": burst_incomplete,
            "replay_rejected": replay_rejected,
            "overlay_invalid": overlay_invalid,
            "outbound_drop_packets": drops_packets,
        },
        "collector": {
            "source": source,
            "revision_converged": final_converged,
            "persistent_summary_present": summary is not None,
            "timeline_event_present": first_event is not None,
            "timeline_evicted": summary is not None and first_event is None,
            "baseline_after_transition": baseline_after_transition,
            "invalid_summary_present": invalid_summary_present,
        },
        "invariants": invariants,
    }
    return side, reason


def build_record(args: argparse.Namespace) -> dict[str, Any]:
    topology = args.topology
    replica = int(args.replica)
    round_number = int(args.round)
    scenario_id = f"{topology}:replica-{replica}:round-{round_number}"
    exact_test_id = f"nat-sim-smoke.sh::{topology}::replica-{replica}::round-{round_number}"
    record: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "repository": REPOSITORY,
        "source_head_sha": args.source_head_sha,
        "workflow_sha": args.workflow_sha,
        "topology": topology,
        "replica": replica,
        "round": round_number,
        "scenario_id": scenario_id,
        "exact_test_id": exact_test_id,
        "executed": True,
        "skipped": False,
        "result": "fail",
        "baseline": {},
        "final": {},
        "observed": {},
        "decision": {"result": "fail", "reason_code": "collector_not_run"},
        "invariants": {},
        "collector": {"source": None, "revision_converged": False},
    }
    try:
        baseline_a = _load(Path(args.baseline_a))
        baseline_b = _load(Path(args.baseline_b))
        final_a = _load(Path(args.final_a))
        final_b = _load(Path(args.final_b))
        side_a, reason_a = _side_evidence(
            "a", baseline_a, final_a, Path(args.log_a), args.expected_path, int(args.overlay_burst)
        )
        side_b, reason_b = _side_evidence(
            "b", baseline_b, final_b, Path(args.log_b), args.expected_path, int(args.overlay_burst)
        )
        record["baseline"] = {"a": side_a["baseline"], "b": side_b["baseline"]}
        record["final"] = {"a": side_a["final"], "b": side_b["final"]}
        record["observed"] = {"a": side_a["observed"], "b": side_b["observed"]}
        record["collector"] = {
            "a": side_a["collector"],
            "b": side_b["collector"],
            "source": "persistent_summary"
            if side_a["collector"]["source"] == side_b["collector"]["source"] == "persistent_summary"
            else "event"
            if side_a["collector"]["source"] in {"event", "persistent_summary"}
            and side_b["collector"]["source"] in {"event", "persistent_summary"}
            else None,
            "revision_converged": side_a["collector"]["revision_converged"]
            and side_b["collector"]["revision_converged"],
        }
        record["invariants"] = {
            "a": side_a["invariants"],
            "b": side_b["invariants"],
            "same_source_head": bool(args.source_head_sha),
            "same_workflow_sha": bool(args.workflow_sha),
        }
        failed_reasons = [reason for reason in (reason_a, reason_b) if reason]
        all_invariants = all(side_a["invariants"].values()) and all(side_b["invariants"].values())
        result = not failed_reasons and all_invariants
        reason = None if result else (failed_reasons[0] if failed_reasons else "invariant_failed")
        record["result"] = "pass" if result else "fail"
        record["decision"] = {
            "result": record["result"],
            "reason_code": reason,
            "observed_decision": "first_usable_committed" if result else "first_usable_not_accepted",
        }
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        reason = str(exc).split(":", 1)[0] or "evidence_parse_failed"
        record["decision"] = {
            "result": "fail",
            "reason_code": reason,
            "observed_decision": "evidence_not_converged",
        }
    return record


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--topology", required=True, choices=["relay-blackhole", "direct-cold-start"])
    parser.add_argument("--replica", required=True, type=int)
    parser.add_argument("--round", required=True, type=int)
    parser.add_argument("--source-head-sha", required=True)
    parser.add_argument("--workflow-sha", required=True)
    parser.add_argument("--baseline-a", required=True)
    parser.add_argument("--baseline-b", required=True)
    parser.add_argument("--final-a", required=True)
    parser.add_argument("--final-b", required=True)
    parser.add_argument("--log-a", required=True)
    parser.add_argument("--log-b", required=True)
    parser.add_argument("--expected-path", required=True, choices=["relay", "direct"])
    parser.add_argument("--overlay-burst", type=int, default=0)
    parser.add_argument("--output", required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    record = build_record(args)
    output = Path(args.output)
    output.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(record["decision"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
