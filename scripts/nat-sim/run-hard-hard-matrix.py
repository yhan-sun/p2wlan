#!/usr/bin/env python3
"""Run the bounded Hard<->Hard NAT experiment matrix without retries.

Every scenario writes its raw simulator directory outside the repository.  A
run is valid only when both final daemon status snapshots, the ordinary NAT
evidence record, a NAT packet trace, healthy critical tasks, and at least one
typed Hard<->Hard attempt report per side are present.  Direct failure is a
valid result for negative controls; missing evidence is never a valid result.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import math
import os
import platform
import re
import resource
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


SCHEMA_VERSION = 2
ATTEMPT_SCHEMA_VERSION = 2
REPOSITORY = "yhan-sun/p2wlan"
MAX_MATRIX_EXECUTIONS = 32
SHA1 = re.compile(r"^[0-9a-f]{40}$")
SAFE_NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")


@dataclass(frozen=True)
class Scenario:
    name: str
    seed: int
    category: str
    description: str
    negative_control: bool = False
    env: dict[str, str] = field(default_factory=dict)


SCENARIOS = (
    Scenario(
        "equal-step",
        42001,
        "mapping",
        "Equal deterministic allocation steps on both NATs.",
        env={"STEP_A": "1", "STEP_B": "1"},
    ),
    Scenario(
        "unequal-step",
        42011,
        "mapping",
        "Different deterministic allocation steps.",
        # Preserve the production 250ms reciprocal-response fence, but let the
        # simulator release its packet gate for a bounded larger observed
        # clock skew so the production attempt can classify the miss instead
        # of the harness aborting before either side sends.
        env={
            "STEP_A": "1",
            "STEP_B": "7",
            "HARD_HARD_GATE_MAX_SKEW_MS": "1000",
        },
    ),
    Scenario(
        "negative-wrap",
        42021,
        "mapping",
        "Negative allocation steps crossing the allocatable port-ring boundary.",
        env={"STEP_A": "-3", "STEP_B": "-5", "BASE_A": "1024", "BASE_B": "65535"},
    ),
    Scenario(
        "port-competition",
        42031,
        "mapping-noise",
        "Predictable mappings after deterministic external allocation noise.",
        env={"STEP_A": "2", "STEP_B": "3", "CONSUME_A": "16", "CONSUME_B": "23"},
    ),
    Scenario(
        "strict-one-sided",
        42041,
        "filtering",
        "Address/port-dependent filtering on one side only.",
        env={"STRICT_FILTERING_A": "1", "STRICT_FILTERING_B": "0"},
    ),
    Scenario(
        "strict-bilateral",
        42051,
        "filtering",
        "Address/port-dependent filtering on both sides.",
        env={"STRICT_FILTERING_A": "1", "STRICT_FILTERING_B": "1"},
    ),
    Scenario(
        "asymmetric-delay-preparation",
        42061,
        "timing",
        "Asymmetric NAT RTT, STUN sampling, signaling, and daemon preparation delay.",
        env={
            "DELAY_A_MS": "80",
            "DELAY_B_MS": "10",
            "STUN_DELAY_A_MS": "180",
            "STUN_DELAY_B_MS": "20",
            "SIGNAL_DELAY_A_MS": "120",
            "SIGNAL_DELAY_B_MS": "15",
            "PREPARE_DELAY_A_MS": "0",
            "PREPARE_DELAY_B_MS": "400",
        },
    ),
    Scenario(
        "loss-reorder-duplicate",
        42071,
        "delivery",
        "Seeded packet loss and reordering with bounded deterministic duplication.",
        env={
            "LOSS": "0.08",
            "REORDER": "1",
            # Every admitted datagram is duplicated once so the expected
            # replay rejection is evidence, not a probabilistic assertion.
            "DUPLICATE_RATE": "1.0",
            "ALLOW_REPLAY_REJECTS": "1",
        },
    ),
    Scenario(
        "random-high-entropy-negative",
        42081,
        "negative-control",
        "Seeded high-entropy mappings; Direct may fail but exit and Relay fallback stay bounded.",
        negative_control=True,
        env={
            "MAPPING_MODE_A": "random",
            "MAPPING_MODE_B": "random",
            "STRICT_FILTERING_A": "1",
            "STRICT_FILTERING_B": "1",
        },
    ),
    Scenario(
        "random-relay-reconnect",
        42091,
        "reconnect",
        "High-entropy negative control plus one forced Relay disconnect/reconnect.",
        negative_control=True,
        env={
            "MAPPING_MODE_A": "random",
            "MAPPING_MODE_B": "random",
            "STRICT_FILTERING_A": "1",
            "STRICT_FILTERING_B": "1",
            "RELAY_KILL_RESTART": "1",
        },
    ),
)
SCENARIO_BY_NAME = {scenario.name: scenario for scenario in SCENARIOS}


class EvidenceError(ValueError):
    pass


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def git_output(root: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def load_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"invalid_json:{path.name}:{exc}") from exc
    if not isinstance(value, dict):
        raise EvidenceError(f"json_not_object:{path.name}")
    return value


def required_int(value: Any, name: str, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise EvidenceError(f"{name}_invalid")
    return value


def optional_int(value: Any, name: str, minimum: int | None = 0) -> int | None:
    if value is None:
        return None
    if type(value) is not int or (minimum is not None and value < minimum):
        raise EvidenceError(f"{name}_invalid")
    return value


def critical_task_summary(status: dict[str, Any], side: str) -> dict[str, int | bool]:
    health = status.get("health")
    tasks = health.get("critical_tasks") if isinstance(health, dict) else None
    if not isinstance(tasks, list):
        raise EvidenceError(f"{side}_critical_tasks_missing")
    critical = [task for task in tasks if isinstance(task, dict) and task.get("critical") is True]
    if not critical:
        raise EvidenceError(f"{side}_critical_tasks_empty")
    unhealthy = sum(
        task.get("running") is not True
        or task.get("finished") is not False
        or task.get("error") is not None
        for task in critical
    )
    if unhealthy:
        raise EvidenceError(f"{side}_critical_tasks_unhealthy")
    return {"critical": len(critical), "unhealthy": unhealthy, "healthy": True}


def first_usable(status: dict[str, Any], side: str) -> dict[str, Any]:
    timeline = status.get("connection_timeline")
    summaries = timeline.get("first_usable_summaries") if isinstance(timeline, dict) else None
    if not isinstance(summaries, list) or not summaries:
        raise EvidenceError(f"{side}_first_usable_missing")
    summary = summaries[-1]
    if not isinstance(summary, dict) or summary.get("path") not in {"direct", "relay"}:
        raise EvidenceError(f"{side}_first_usable_invalid")
    first_at = required_int(
        summary.get("first_usable_at_ms"), f"{side}_first_usable_at_ms"
    )
    relay_ready_at = required_int(
        summary.get("relay_ready_at_ms"), f"{side}_relay_ready_at_ms"
    )
    delta_ms = required_int(
        summary.get("first_usable_delta_ms"), f"{side}_first_usable_delta_ms"
    )
    remaining_ms = required_int(
        summary.get("direct_first_remaining_ms_at_relay_ready"),
        f"{side}_direct_first_remaining_ms",
    )
    if first_at < relay_ready_at or delta_ms != first_at - relay_ready_at:
        raise EvidenceError(f"{side}_first_usable_timing_mismatch")
    if remaining_ms > 5000:
        raise EvidenceError(f"{side}_direct_first_remaining_ms_invalid")
    if summary.get("business_received") is not True:
        raise EvidenceError(f"{side}_business_ingress_missing")
    result = dict(summary)
    result["within_direct_first_protection"] = (
        result["path"] == "direct" and delta_ms <= remaining_ms
    )
    return result


def first_timeline_event_at(
    status: dict[str, Any],
    event_name: str,
    peer_id: str,
    path: str,
    report: dict[str, Any],
) -> tuple[int | None, str]:
    # A peer/generation pair is not an attempt identity. Require the exact
    # validation commit, transport instance, and socket before attaching MTU
    # readiness or decrypted business ingress to a measured attempt.
    identity = report.get("business_attribution_identity")
    identity_fields = (
        "validation_session_id",
        "direct_commit_sequence",
        "transport_instance_id",
        "socket_index",
    )
    if not isinstance(identity, dict) or any(
        type(identity.get(name)) is not int or identity[name] < 0
        for name in identity_fields
    ):
        return None, "not_attributable:attempt_identity_missing"
    timeline = status.get("connection_timeline")
    events = timeline.get("events") if isinstance(timeline, dict) else None
    if not isinstance(events, list):
        return None, "not_attributable:timeline_missing"
    matches: list[int] = []
    identity_seen = False
    for event in events:
        if not isinstance(event, dict) or event.get("event") != event_name:
            continue
        event_identity = event.get("business_attribution_identity")
        if not isinstance(event_identity, dict):
            continue
        identity_seen = True
        if (
            event.get("path") == path
            and event.get("peer_id") == peer_id
            and event.get("connection_generation") == report.get("network_generation")
            and all(event_identity.get(name) == identity[name] for name in identity_fields)
            and type(event.get("at_ms")) is int
            and event["at_ms"] >= 0
        ):
            matches.append(event["at_ms"])
    if matches:
        return min(matches), "attributed:exact_attempt_identity"
    if identity_seen:
        return None, "not_attributable:identity_mismatch"
    return None, "not_attributable:event_identity_missing"


def validate_attempt(
    report: Any,
    side: str,
    scenario: Scenario,
    expected_seed: int,
    source_sha: str,
    baseline_sha: str,
    first: dict[str, Any],
    business_ready_at_ms: int | None,
    direct_business_at_ms: int | None,
    business_attribution: str,
) -> dict[str, Any]:
    if not isinstance(report, dict):
        raise EvidenceError(f"{side}_attempt_not_object")
    if report.get("schema_version") != ATTEMPT_SCHEMA_VERSION:
        raise EvidenceError(f"{side}_attempt_schema_invalid")
    if report.get("source_git_commit") != source_sha:
        raise EvidenceError(f"{side}_attempt_source_sha_mismatch")
    if report.get("baseline_git_commit") != baseline_sha:
        raise EvidenceError(f"{side}_attempt_baseline_sha_mismatch")
    if report.get("scenario_id") != scenario.name or report.get("seed") != expected_seed:
        raise EvidenceError(f"{side}_attempt_scenario_identity_mismatch")
    for name in (
        "build_id",
        "role",
        "mode",
        "session_tag",
        "plan_tag",
        "failure_class",
        "terminal_reason",
    ):
        if not isinstance(report.get(name), str) or not report[name]:
            raise EvidenceError(f"{side}_attempt_{name}_missing")
    for name in ("session_tag", "plan_tag"):
        if not re.fullmatch(r"[0-9a-f]{16}", report[name]):
            raise EvidenceError(f"{side}_attempt_{name}_not_anonymized")
    for name in (
        "network_generation",
        "peer_session_generation",
        "remote_candidate_epoch",
        "local_profile_generation",
        "remote_profile_generation",
        "punch_generation",
        "attempt",
        "candidate_cap",
    ):
        required_int(report.get(name), f"{side}_attempt_{name}")
    socket_index = report.get("socket_index")
    if socket_index is not None:
        required_int(socket_index, f"{side}_attempt_socket_index")
    elif report.get("mode") != "measurement":
        raise EvidenceError(f"{side}_attempt_socket_identity_missing")
    counts = report.get("counts")
    timeline = report.get("timeline")
    tags = report.get("target_order_tags")
    if not isinstance(counts, dict) or not isinstance(timeline, dict) or not isinstance(tags, list):
        raise EvidenceError(f"{side}_attempt_shape_invalid")
    count_fields = (
        "requested",
        "generated",
        "unique",
        "advertised",
        "parsed_targets_for_plan",
        "planned_targets",
        "planned_sockets",
        "planned_socket_target_combinations",
        "planned_logical_probes",
        "planned_physical_datagram_cap",
        "attempted_targets",
        "logical_probes_attempted",
        "logical_probes_sent",
        "send_success_datagrams",
        "send_success_bytes",
        "send_errors",
        "send_error_bytes",
        "budget_skipped",
        "planned_logical_probes_not_attempted",
        "stun_send_success_datagrams",
        "stun_send_success_bytes",
        "stun_send_errors",
        "stun_send_error_bytes",
        "stun_responses",
        "candidate_signal_payload_logic_bytes",
    )
    for name in count_fields:
        required_int(counts.get(name), f"{side}_attempt_counts_{name}")
    # One admitted logical probe can emit a v2 datagram plus a bounded legacy
    # compatibility copy. Physical datagrams can therefore exceed the logical
    # schedule; the two dimensions must remain independent.
    if len(tags) != counts["planned_targets"]:
        raise EvidenceError(f"{side}_attempt_target_order_length_mismatch")
    if any(not isinstance(tag, str) or re.fullmatch(r"[0-9a-f]{16}", tag) is None for tag in tags):
        raise EvidenceError(f"{side}_attempt_target_tag_invalid")
    if counts["parsed_targets_for_plan"] != counts["planned_targets"]:
        raise EvidenceError(f"{side}_attempt_parsed_plan_mismatch")
    if counts["attempted_targets"] > counts["planned_targets"]:
        raise EvidenceError(f"{side}_attempt_distinct_target_overflow")
    if counts["attempted_targets"] > counts["logical_probes_attempted"]:
        raise EvidenceError(f"{side}_attempt_target_probe_mismatch")
    if not (
        counts["logical_probes_sent"]
        <= counts["logical_probes_attempted"]
        <= counts["planned_logical_probes"]
    ):
        raise EvidenceError(f"{side}_attempt_logical_probe_overflow")
    if counts["planned_logical_probes_not_attempted"] != (
        counts["planned_logical_probes"] - counts["logical_probes_attempted"]
    ):
        raise EvidenceError(f"{side}_attempt_cancelled_count_mismatch")
    if counts["planned_physical_datagram_cap"] != 2 * counts["planned_logical_probes"]:
        raise EvidenceError(f"{side}_attempt_physical_cap_mismatch")
    if counts["send_success_datagrams"] > counts["planned_physical_datagram_cap"]:
        raise EvidenceError(f"{side}_attempt_physical_send_overflow")

    timeline_fields = (
        "measurement_started_at_ms",
        "last_measurement_send_at_ms",
        "measurement_completed_at_ms",
        "candidate_signal_accepted_at_ms",
        "planned_send_at_ms",
        "send_dispatch_at_ms",
        "actual_first_send_at_ms",
        "probe_last_hit_at_ms",
        "encrypted_validation_completed_at_ms",
        "business_ready_at_ms",
        "first_business_success_at_ms",
        "measurement_age_at_send_ms",
        "measurement_to_first_send_ms",
        "last_probe_hit_to_validation_ms",
        "connection_to_first_business_ms",
        "validation_to_first_business_ms",
    )
    for name in timeline_fields:
        optional_int(timeline.get(name), f"{side}_attempt_timeline_{name}")
    optional_int(
        timeline.get("schedule_deviation_ms"),
        f"{side}_attempt_timeline_schedule_deviation_ms",
        minimum=None,
    )
    actual_send = timeline.get("actual_first_send_at_ms")
    last_measurement_send = timeline.get("last_measurement_send_at_ms")
    planned_send = timeline.get("planned_send_at_ms")
    if type(actual_send) is int and type(last_measurement_send) is int:
        expected_age = actual_send - last_measurement_send
        expected_age = expected_age if expected_age >= 0 else None
        if timeline.get("measurement_age_at_send_ms") != expected_age:
            raise EvidenceError(f"{side}_attempt_measurement_age_mismatch")
    measurement_started = timeline.get("measurement_started_at_ms")
    if type(actual_send) is int and type(measurement_started) is int:
        expected_age = actual_send - measurement_started
        expected_age = expected_age if expected_age >= 0 else None
        if timeline.get("measurement_to_first_send_ms") != expected_age:
            raise EvidenceError(f"{side}_attempt_measurement_to_send_mismatch")
    if type(actual_send) is int and type(planned_send) is int:
        if timeline.get("schedule_deviation_ms") != actual_send - planned_send:
            raise EvidenceError(f"{side}_attempt_schedule_deviation_mismatch")
    probe_hit = timeline.get("probe_last_hit_at_ms")
    validation_at = timeline.get("encrypted_validation_completed_at_ms")
    if type(probe_hit) is int and type(validation_at) is int:
        expected_duration = validation_at - probe_hit
        expected_duration = expected_duration if expected_duration >= 0 else None
        if timeline.get("last_probe_hit_to_validation_ms") != expected_duration:
            raise EvidenceError(f"{side}_attempt_last_hit_validation_mismatch")

    direct_confirmed = report.get("direct_confirmed")
    if type(direct_confirmed) is not bool:
        raise EvidenceError(f"{side}_attempt_direct_confirmed_invalid")
    confirmed_rank = optional_int(
        report.get("confirmed_target_rank"), f"{side}_attempt_confirmed_target_rank"
    )
    if confirmed_rank is not None and confirmed_rank >= counts["planned_targets"]:
        raise EvidenceError(f"{side}_attempt_confirmed_target_rank_out_of_bounds")
    if not direct_confirmed and confirmed_rank is not None:
        raise EvidenceError(f"{side}_attempt_unconfirmed_target_rank")
    if direct_confirmed:
        if type(validation_at) is not int:
            raise EvidenceError(f"{side}_attempt_encrypted_validation_missing")
        if report.get("failure_class") != "encrypted_validation_completed":
            raise EvidenceError(f"{side}_attempt_success_class_mismatch")
    elif validation_at is not None:
        raise EvidenceError(f"{side}_attempt_unconfirmed_validation_timestamp")

    enriched = json.loads(json.dumps(report))
    enriched["evidence_side"] = side
    enriched_timeline = enriched["timeline"]
    validation_at = enriched_timeline.get("encrypted_validation_completed_at_ms")
    if report.get("direct_confirmed") is True:
        enriched_timeline["business_ready_at_ms"] = business_ready_at_ms
        enriched_timeline["first_business_success_at_ms"] = direct_business_at_ms
    else:
        enriched_timeline["business_ready_at_ms"] = None
        enriched_timeline["first_business_success_at_ms"] = None
    enriched_timeline["connection_to_first_business_ms"] = None
    enriched_timeline["validation_to_first_business_ms"] = (
        direct_business_at_ms - validation_at
        if type(validation_at) is int
        and type(direct_business_at_ms) is int
        and direct_business_at_ms >= validation_at
        else None
    )
    enriched_timeline["business_evidence_attribution"] = business_attribution
    enriched_timeline["connection_timing_attribution"] = (
        "not_attributable:connection_start_identity_unavailable"
    )
    if report.get("direct_confirmed") is True:
        if business_attribution != "attributed:exact_attempt_identity":
            enriched["experiment_outcome_class"] = "validation_completed_business_evidence_unattributable"
        elif business_ready_at_ms is None:
            enriched["experiment_outcome_class"] = "validation_completed_business_not_ready"
        elif direct_business_at_ms is None:
            enriched["experiment_outcome_class"] = "business_ready_no_direct_business"
        elif first.get("path") == "direct":
            enriched["experiment_outcome_class"] = "direct_business_succeeded"
        else:
            enriched["experiment_outcome_class"] = "relay_first_then_direct_business_succeeded"
    else:
        enriched["experiment_outcome_class"] = report["failure_class"]
    return enriched


def extract_attempts(
    status: dict[str, Any],
    side: str,
    scenario: Scenario,
    seed: int,
    source_sha: str,
    baseline_sha: str,
    first: dict[str, Any],
) -> tuple[list[dict[str, Any]], str | None]:
    peers = status.get("peers")
    if not isinstance(peers, list) or not peers:
        raise EvidenceError(f"{side}_peers_missing")
    reports: list[dict[str, Any]] = []
    final_path = None
    for peer in peers:
        if not isinstance(peer, dict):
            continue
        peer_id = peer.get("node_id")
        active = peer.get("active_path")
        if active in {"direct", "relay"}:
            final_path = active
        events = peer.get("direct_events")
        if not isinstance(events, list):
            continue
        for event in events:
            if not isinstance(event, dict) or event.get("stage") != "hard_hard_attempt_report":
                continue
            raw_report = event.get("hard_hard_attempt")
            generation = (
                raw_report.get("network_generation") if isinstance(raw_report, dict) else None
            )
            ready_at = None
            direct_business_at = None
            attribution_reasons: list[str] = []
            if isinstance(peer_id, str) and type(generation) is int:
                ready_at, ready_reason = first_timeline_event_at(
                    status,
                    "direct_business_mtu_ready",
                    peer_id,
                    "direct",
                    raw_report,
                )
                direct_business_at, business_reason = first_timeline_event_at(
                    status,
                    "business_ingress_observed",
                    peer_id,
                    "direct",
                    raw_report,
                )
                attribution_reasons.extend((ready_reason, business_reason))
            else:
                attribution_reasons.append("not_attributable:peer_or_generation_missing")
            business_attribution = (
                "attributed:exact_attempt_identity"
                if attribution_reasons
                and all(reason == "attributed:exact_attempt_identity" for reason in attribution_reasons)
                else ";".join(dict.fromkeys(attribution_reasons))
            )
            reports.append(
                validate_attempt(
                    raw_report,
                    side,
                    scenario,
                    seed,
                    source_sha,
                    baseline_sha,
                    first,
                    ready_at,
                    direct_business_at,
                    business_attribution,
                )
            )
    if not reports:
        raise EvidenceError(f"{side}_hard_hard_attempt_missing")
    return reports, final_path


def validate_shared_plan_pair(
    attempts_a: list[dict[str, Any]], attempts_b: list[dict[str, Any]]
) -> None:
    combined = attempts_a + attempts_b
    if len(combined) != 2:
        raise EvidenceError("shared_plan_attempt_count_not_two")
    left, right = combined
    if left.get("session_tag") != right.get("session_tag"):
        raise EvidenceError("shared_plan_session_tag_mismatch")
    if left.get("plan_tag") != right.get("plan_tag"):
        raise EvidenceError("shared_plan_plan_tag_mismatch")
    if {left.get("role"), right.get("role")} != {"initiator", "responder"}:
        raise EvidenceError("shared_plan_roles_not_reciprocal")
    by_role = {value["role"]: value for value in combined}
    initiator = by_role["initiator"]
    responder = by_role["responder"]
    # The protocol reciprocates profile ownership. Network generations,
    # candidate epochs, peer-session generations, socket indexes, and attempt
    # counters remain endpoint-local and are never required to be numerically
    # equal across the pair.
    if initiator.get("local_profile_generation") != responder.get(
        "remote_profile_generation"
    ):
        raise EvidenceError("shared_plan_initiator_profile_mismatch")
    if initiator.get("remote_profile_generation") != responder.get(
        "local_profile_generation"
    ):
        raise EvidenceError("shared_plan_responder_profile_mismatch")


def validate_round(
    round_dir: Path,
    scenario: Scenario,
    round_number: int,
    source_sha: str,
    baseline_sha: str,
) -> dict[str, Any]:
    seed = scenario.seed + round_number - 1
    required_files = (
        "node-a.status.json",
        "node-b.status.json",
        "node-a.log",
        "node-b.log",
        "nat-evidence.json",
        "nat-trace.jsonl",
        "cleanup.json",
    )
    missing = [name for name in required_files if not (round_dir / name).is_file()]
    if missing:
        raise EvidenceError("raw_evidence_missing:" + ",".join(missing))
    if (round_dir / "nat-trace.jsonl").stat().st_size == 0:
        raise EvidenceError("nat_trace_empty")

    evidence = load_object(round_dir / "nat-evidence.json")
    if evidence.get("result") != "pass" or evidence.get("executed") is not True:
        reason = evidence.get("decision", {}).get("reason_code")
        raise EvidenceError(f"nat_evidence_rejected:{reason or 'unknown'}")
    cleanup = load_object(round_dir / "cleanup.json")
    if cleanup.get("schema_version") != 1 or cleanup.get("all_reaped") is not True:
        raise EvidenceError("cleanup_evidence_invalid")
    cleanup_duration_ms = required_int(cleanup.get("duration_ms"), "cleanup_duration_ms")
    cleanup_process_count = required_int(
        cleanup.get("process_count"), "cleanup_process_count", minimum=4
    )
    status_a = load_object(round_dir / "node-a.status.json")
    status_b = load_object(round_dir / "node-b.status.json")
    first_a = first_usable(status_a, "a")
    first_b = first_usable(status_b, "b")
    if first_a["path"] != first_b["path"]:
        raise EvidenceError("first_usable_path_disagrees")
    tasks_a = critical_task_summary(status_a, "a")
    tasks_b = critical_task_summary(status_b, "b")
    attempts_a, final_a = extract_attempts(
        status_a, "a", scenario, seed, source_sha, baseline_sha, first_a
    )
    attempts_b, final_b = extract_attempts(
        status_b, "b", scenario, seed, source_sha, baseline_sha, first_b
    )
    validate_shared_plan_pair(attempts_a, attempts_b)
    attempts = [dict(side="a", **report) for report in attempts_a]
    attempts.extend(dict(side="b", **report) for report in attempts_b)
    if first_a["path"] == "direct":
        for side, side_attempts in (("a", attempts_a), ("b", attempts_b)):
            successful = [attempt for attempt in side_attempts if attempt["direct_confirmed"]]
            if not successful:
                raise EvidenceError(f"{side}_direct_business_without_confirmed_attempt")
            for attempt in successful:
                timeline = attempt["timeline"]
                ready_at = timeline.get("business_ready_at_ms")
                business_at = timeline.get("first_business_success_at_ms")
                validation_at = timeline.get("encrypted_validation_completed_at_ms")
                # `business_ready` is the local outbound-selector milestone,
                # while `first_business_success` is authenticated inbound
                # delivery. Both must follow encrypted validation, but either
                # direction may win the race; imposing an order between them
                # would reject real bidirectional Direct evidence. These
                # attempt-local fields are optional until the exact commit,
                # transport, and socket identity is present on both events;
                # requested-round business proof remains in first_usable.
                if attempt["timeline"].get("business_evidence_attribution") == "attributed:exact_attempt_identity" and (
                    type(ready_at) is not int
                    or type(business_at) is not int
                    or type(validation_at) is not int
                    or not (validation_at <= ready_at and validation_at <= business_at)
                ):
                    raise EvidenceError(f"{side}_direct_business_timeline_invalid")
    direct_within_protection = (
        first_a["within_direct_first_protection"] is True
        and first_b["within_direct_first_protection"] is True
    )
    return {
        "round": round_number,
        "seed": seed,
        "result": "valid",
        "first_usable_path": first_a["path"],
        "direct_within_protection": direct_within_protection,
        "final_path_a": final_a,
        "final_path_b": final_b,
        "first_business_at_ms": {
            "a": first_a["first_usable_at_ms"],
            "b": first_b["first_usable_at_ms"],
        },
        "critical_tasks": {"a": tasks_a, "b": tasks_b},
        "cleanup": {
            "duration_ms": cleanup_duration_ms,
            "process_count": cleanup_process_count,
            "all_reaped": True,
        },
        "attempts": attempts,
        "raw": {name: str(round_dir / name) for name in required_files},
    }


def percentile(values: Iterable[int], fraction: float) -> int | None:
    ordered = sorted(values)
    if not ordered:
        return None
    return ordered[max(0, math.ceil(len(ordered) * fraction) - 1)]


def distribution(values: Iterable[int]) -> dict[str, int | None]:
    observed = list(values)
    return {
        "sample_count": len(observed),
        "min": min(observed) if observed else None,
        "p50": percentile(observed, 0.50),
        "p95": percentile(observed, 0.95),
        "max": max(observed) if observed else None,
    }


def observed_attempts(rounds: list[dict[str, Any]]) -> list[dict[str, Any]]:
    reports: list[dict[str, Any]] = []
    for item in rounds:
        values = item.get("attempts")
        if not isinstance(values, list):
            values = item.get("partial_attempts")
        if isinstance(values, list):
            reports.extend(value for value in values if isinstance(value, dict))
    return reports


def paired_plan_groups(attempts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for attempt in attempts:
        session_tag = attempt.get("session_tag")
        plan_tag = attempt.get("plan_tag")
        if not isinstance(session_tag, str) or not isinstance(plan_tag, str):
            continue
        groups.setdefault((session_tag, plan_tag), []).append(attempt)
    return [
        {"session_tag": key[0], "plan_tag": key[1], "attempts": values}
        for key, values in groups.items()
    ]


def extract_partial_attempt_reports(
    round_dir: Path,
    scenario: Scenario,
    seed: int,
    source_sha: str,
    baseline_sha: str,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Preserve typed costs from available sides when round evidence is invalid."""
    attempts: list[dict[str, Any]] = []
    errors: list[str] = []
    for side in ("a", "b"):
        path = round_dir / f"node-{side}.status.json"
        if not path.is_file():
            errors.append(f"{side}_status_missing")
            continue
        try:
            status = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            errors.append(f"{side}_status_unreadable")
            continue
        peers = status.get("peers") if isinstance(status, dict) else None
        if not isinstance(peers, list):
            errors.append(f"{side}_peers_missing")
            continue
        found = 0
        for peer in peers:
            events = peer.get("direct_events") if isinstance(peer, dict) else None
            if not isinstance(events, list):
                continue
            for event in events:
                if not isinstance(event, dict) or event.get("stage") != "hard_hard_attempt_report":
                    continue
                report = event.get("hard_hard_attempt")
                if not isinstance(report, dict):
                    continue
                if (
                    report.get("schema_version") != ATTEMPT_SCHEMA_VERSION
                    or report.get("source_git_commit") != source_sha
                    or report.get("baseline_git_commit") != baseline_sha
                    or report.get("scenario_id") != scenario.name
                    or report.get("seed") != seed
                    or not isinstance(report.get("counts"), dict)
                    or not isinstance(report.get("session_tag"), str)
                    or not isinstance(report.get("plan_tag"), str)
                    or re.fullmatch(r"[0-9a-f]{16}", report.get("session_tag", "")) is None
                    or re.fullmatch(r"[0-9a-f]{16}", report.get("plan_tag", "")) is None
                ):
                    errors.append(f"{side}_partial_attempt_identity_invalid")
                    continue
                partial = json.loads(json.dumps(report))
                partial["evidence_side"] = side
                partial["evidence_validity"] = "incomplete_round"
                if not isinstance(partial.get("timeline"), dict):
                    partial["timeline"] = {}
                partial["timeline"]["business_evidence_attribution"] = (
                    "not_attributable:round_evidence_incomplete"
                )
                attempts.append(partial)
                found += 1
        if found == 0:
            errors.append(f"{side}_attempt_report_missing")
    return attempts, errors


def cost_summary(
    rounds: list[dict[str, Any]], attempts: list[dict[str, Any]]
) -> dict[str, Any]:
    groups = paired_plan_groups(attempts)
    paired = 0
    incomplete = 0
    for group in groups:
        values = group["attempts"]
        roles = [value.get("role") for value in values]
        if roles.count("initiator") == 1 and roles.count("responder") == 1 and len(values) == 2:
            paired += 1
        else:
            incomplete += 1
    count_fields = {
        "probe_datagrams": "send_success_datagrams",
        "probe_bytes": "send_success_bytes",
        "probe_send_errors": "send_errors",
        "stun_datagrams": "stun_send_success_datagrams",
        "stun_bytes": "stun_send_success_bytes",
        "stun_send_errors": "stun_send_errors",
        "candidate_signal_payload_logic_bytes": "candidate_signal_payload_logic_bytes",
        "planned_logical_probes": "planned_logical_probes",
        "planned_logical_probes_not_attempted": "planned_logical_probes_not_attempted",
        "budget_skipped": "budget_skipped",
    }
    known: dict[str, int] = {}
    unknown: dict[str, int] = {}
    for output_name, field in count_fields.items():
        values = [
            attempt.get("counts", {}).get(field)
            for attempt in attempts
            if isinstance(attempt.get("counts"), dict)
        ]
        observed = [value for value in values if type(value) is int and value >= 0]
        known[output_name] = sum(observed)
        unknown[output_name] = len(values) - len(observed)
    reason_totals: dict[str, int] = {}
    for attempt in attempts:
        counts = attempt.get("counts")
        if not isinstance(counts, dict):
            continue
        missing = counts.get("planned_logical_probes_not_attempted")
        if type(missing) is not int or missing <= 0:
            continue
        if attempt.get("direct_confirmed") is True:
            reason = "success_cancelled"
        elif attempt.get("failure_class") == "budget_rejected":
            reason = "budget_rejected"
        elif attempt.get("failure_class") == "missed_schedule" or attempt.get("terminal_reason") == "deadline":
            reason = "expired"
        elif attempt.get("failure_class") == "cancelled_generation_changed":
            reason = "lifecycle_invalidated"
        else:
            reason = "unknown"
        reason_totals[reason] = reason_totals.get(reason, 0) + missing
    rounds_with_reports = sum(bool(observed_attempts([item])) for item in rounds)
    return {
        "basis": "all requested rounds; observed local side reports only",
        "observed_attempt_reports": len(attempts),
        "paired_shared_plan_samples": paired,
        "incomplete_shared_plan_samples": incomplete,
        "requested_rounds_without_attempt_costs": len(rounds) - rounds_with_reports,
        "known_observed_costs": known,
        "unknown_field_counts": unknown,
        "full_control_transport_bytes": None,
        "planned_minus_attempted_by_reason": reason_totals,
    }


def aggregate_runs(runs: list[dict[str, Any]]) -> dict[str, Any]:
    rounds = [item for run in runs for item in run.get("rounds", [])]
    valid = [item for item in rounds if item.get("result") == "valid"]
    attempts = observed_attempts(rounds)
    valid_attempts = observed_attempts(valid)
    direct_first = sum(item.get("direct_within_protection") is True for item in valid)
    relay_first = sum(item.get("first_usable_path") == "relay" for item in valid)
    relay_then_direct = sum(
        item.get("first_usable_path") == "relay"
        and item.get("final_path_a") == "direct"
        and item.get("final_path_b") == "direct"
        for item in valid
    )
    failures: dict[str, int] = {}
    terminal_reasons: dict[str, int] = {}
    for attempt in attempts:
        name = str(attempt.get("failure_class", "unknown"))
        failures[name] = failures.get(name, 0) + 1
        reason = str(attempt.get("terminal_reason", "unknown"))
        terminal_reasons[reason] = terminal_reasons.get(reason, 0) + 1
    first_business_durations = [
        value
        for attempt in valid_attempts
        for value in [attempt.get("timeline", {}).get("validation_to_first_business_ms")]
        if type(value) is int
    ]
    counts = [attempt["counts"] for attempt in attempts if isinstance(attempt.get("counts"), dict)]
    valid_counts = [
        attempt["counts"]
        for attempt in valid_attempts
        if isinstance(attempt.get("counts"), dict)
    ]
    def timeline_values(name: str, values: list[dict[str, Any]]) -> list[int]:
        return [
            value
            for attempt in values
            for value in [attempt.get("timeline", {}).get(name)]
            if type(value) is int
        ]
    target_ranks = [
        rank
        for attempt in valid_attempts
        for rank in [attempt.get("confirmed_target_rank")]
        if type(rank) is int
    ]
    confirmed_attempts = sum(attempt.get("direct_confirmed") is True for attempt in attempts)
    planned_targets = sum(value.get("planned_targets", 0) for value in counts)
    attempted_targets = sum(value.get("attempted_targets", 0) for value in counts)
    cleanups = [item["cleanup"]["duration_ms"] for item in valid]
    resource_usage = [run.get("resource_usage", {}) for run in runs]
    execution_results: dict[str, int] = {}
    for run in runs:
        exit_code = run.get("exit_code")
        label = str(exit_code) if type(exit_code) is int else "not_started"
        execution_results[label] = execution_results.get(label, 0) + 1
    all_requested_costs = cost_summary(rounds, attempts)
    valid_only_costs = cost_summary(valid, valid_attempts)
    return {
        "requested": {
            "scenario_runs": len(runs),
            "rounds": len(rounds),
        },
        "execution_result": {
            "completed_smoke_processes": sum(type(run.get("exit_code")) is int for run in runs),
            "smoke_exit_codes": execution_results,
        },
        "evidence_validity": {
            "valid_rounds": len(valid),
            "invalid_rounds": len(rounds) - len(valid),
            "direct_within_protection_requested": {
                "observed_successes": direct_first,
                "requested_denominator": len(rounds),
                "invalid_or_missing_evidence": len(rounds) - len(valid),
            },
        },
        "requested_rounds": len(rounds),
        "valid_rounds": len(valid),
        "invalid_rounds": len(rounds) - len(valid),
        "direct_within_protection_rounds": direct_first,
        "relay_first_rounds": relay_first,
        "relay_then_direct_rounds": relay_then_direct,
        "final_direct_rounds": sum(
            item.get("final_path_a") == "direct" and item.get("final_path_b") == "direct"
            for item in valid
        ),
        "attempt_count": len(attempts),
        "valid_only_attempt_count": len(valid_attempts),
        "paired_shared_plan_samples": all_requested_costs["paired_shared_plan_samples"],
        "attempt_failure_classes": failures,
        "attempt_terminal_reasons": terminal_reasons,
        "attempt_timeline_ms": {
            "measurement_age_at_send": distribution(
                timeline_values("measurement_age_at_send_ms", valid_attempts)
            ),
            "measurement_to_first_send": distribution(
                timeline_values("measurement_to_first_send_ms", valid_attempts)
            ),
            "schedule_deviation": distribution(
                timeline_values("schedule_deviation_ms", valid_attempts)
            ),
            "absolute_schedule_deviation": distribution(
                abs(value) for value in timeline_values("schedule_deviation_ms", valid_attempts)
            ),
            "last_probe_hit_to_validation": distribution(
                timeline_values("last_probe_hit_to_validation_ms", valid_attempts)
            ),
            "validation_to_first_business": distribution(first_business_durations),
            "connection_to_first_business": distribution(
                timeline_values("connection_to_first_business_ms", valid_attempts)
            ),
        },
        "candidate_execution": {
            "planned_targets": planned_targets,
            "distinct_attempted_targets": attempted_targets,
            "not_a_coverage_estimate": True,
            "confirmed_direct_attempts": confirmed_attempts,
            "confirmed_target_in_plan_attempts": len(target_ranks),
            "confirmed_target_rank_zero_based": distribution(target_ranks),
        },
        "validation_to_first_business_ms": {
            "condition": "exact attempt identity matched to both MTU readiness and decrypted Direct ingress",
            "sample_count": len(first_business_durations),
            "p50": percentile(first_business_durations, 0.50),
            "p95": percentile(first_business_durations, 0.95),
        },
        "costs": {
            "all_requested": all_requested_costs,
            "valid_only": valid_only_costs,
        },
        "peak_planned_sockets_per_attempt": max(
            (value.get("planned_sockets", 0) for value in counts), default=0
        ),
        "cleanup_duration_ms": distribution(cleanups),
        "resource_usage": {
            "scope": "local smoke subprocess trees; build/setup/experiment/teardown included",
            "total_user_cpu_seconds": round(
                sum(float(value.get("user_cpu_seconds", 0)) for value in resource_usage), 6
            ),
            "total_system_cpu_seconds": round(
                sum(float(value.get("system_cpu_seconds", 0)) for value in resource_usage), 6
            ),
            "peak_max_rss": max(
                (int(value.get("max_rss", 0)) for value in resource_usage), default=0
            ),
            "max_rss_unit": next(
                (value.get("max_rss_unit") for value in resource_usage if value.get("max_rss_unit")),
                None,
            ),
            "healthy_critical_task_snapshots": sum(
                side.get("healthy") is True
                for item in valid
                for side in item.get("critical_tasks", {}).values()
            ),
        },
    }


def write_manifest(path: Path, value: dict[str, Any]) -> None:
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.chmod(0o600)
    temporary.replace(path)


def execute_scenario(
    root: Path,
    output: Path,
    smoke_script: Path,
    scenario: Scenario,
    rounds: int,
    source_sha: str,
    baseline_sha: str,
    variant: str,
) -> dict[str, Any]:
    raw_dir = output / "raw" / scenario.name
    stdout_path = output / "runner-logs" / f"{scenario.name}.stdout.log"
    stderr_path = output / "runner-logs" / f"{scenario.name}.stderr.log"
    env = os.environ.copy()
    selected_env = {
        "MODE": "hard-hard",
        "ROUNDS": str(rounds),
        "NAT_SEED_BASE": str(scenario.seed - 1),
        "NAT_SIM_ARTIFACT_DIR": str(raw_dir),
        "NAT_SIM_RUN_ID": f"hard-hard-{scenario.name}",
        "NAT_TOPOLOGY_HEAD_SHA": source_sha,
        "EXPERIMENT_BASELINE_SHA": baseline_sha,
        "EXPERIMENT_VARIANT": variant,
        "EXPERIMENT_SCENARIO": scenario.name,
        **scenario.env,
    }
    env.update(selected_env)
    command = [str(smoke_script)]
    usage_before = resource.getrusage(resource.RUSAGE_CHILDREN)
    started_at = utc_now()
    start = time.monotonic()
    with stdout_path.open("w", encoding="utf-8") as stdout, stderr_path.open(
        "w", encoding="utf-8"
    ) as stderr:
        completed = subprocess.run(command, cwd=root, env=env, stdout=stdout, stderr=stderr)
    duration_ms = round((time.monotonic() - start) * 1000)
    completed_at = utc_now()
    usage_after = resource.getrusage(resource.RUSAGE_CHILDREN)
    errors: list[str] = []
    round_records: list[dict[str, Any]] = []
    for number in range(1, rounds + 1):
        try:
            round_records.append(
                validate_round(
                    raw_dir / f"round-{number}",
                    scenario,
                    number,
                    source_sha,
                    baseline_sha,
                )
            )
        except EvidenceError as exc:
            errors.append(f"round-{number}:{exc}")
            partial_attempts, partial_errors = extract_partial_attempt_reports(
                raw_dir / f"round-{number}",
                scenario,
                scenario.seed + number - 1,
                source_sha,
                baseline_sha,
            )
            round_records.append(
                {
                    "round": number,
                    "seed": scenario.seed + number - 1,
                    "result": "invalid",
                    "reason": str(exc),
                    "partial_attempts": partial_attempts,
                    "partial_report_errors": partial_errors,
                }
            )
    if completed.returncode != 0:
        errors.append(f"smoke_exit_code:{completed.returncode}")
    result = "pass" if not errors else "fail"
    return {
        "scenario_id": scenario.name,
        "category": scenario.category,
        "description": scenario.description,
        "negative_control": scenario.negative_control,
        "result": result,
        "started_at": started_at,
        "completed_at": completed_at,
        "duration_ms": duration_ms,
        "exit_code": completed.returncode,
        "command": command,
        "environment": selected_env,
        "raw_artifact_dir": str(raw_dir),
        "stdout_log": str(stdout_path),
        "stderr_log": str(stderr_path),
        "resource_usage": {
            "scope": "smoke subprocess tree",
            "user_cpu_seconds": round(usage_after.ru_utime - usage_before.ru_utime, 6),
            "system_cpu_seconds": round(usage_after.ru_stime - usage_before.ru_stime, 6),
            "max_rss": usage_after.ru_maxrss,
            "max_rss_unit": "bytes" if sys.platform == "darwin" else "KiB",
        },
        "validation_errors": errors,
        "rounds": round_records,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run the fixed-seed Hard<->Hard NAT matrix once per selected scenario; "
            "raw artifacts are retained and missing evidence fails closed."
        )
    )
    parser.add_argument("--list", action="store_true", help="list fixed scenarios and exit")
    parser.add_argument("--scenario", action="append", choices=sorted(SCENARIO_BY_NAME))
    parser.add_argument("--rounds", type=int, default=1, help="rounds per scenario (default: 1)")
    parser.add_argument("--output", type=Path, help="new absolute directory outside the repository")
    parser.add_argument("--source-sha", help="exact 40-character source commit (default: HEAD)")
    parser.add_argument("--baseline-sha", help="exact B1 baseline commit (default: merge-base with origin/main)")
    parser.add_argument("--variant", default="b1-hard-hard-observability")
    parser.add_argument(
        "--smoke-script",
        type=Path,
        help="override nat-sim-smoke.sh (intended for runner contract tests)",
    )
    parser.add_argument(
        "--max-executions",
        type=int,
        default=16,
        help=f"capacity fence, at most {MAX_MATRIX_EXECUTIONS} scenario-round executions",
    )
    parser.add_argument("--dry-run", action="store_true", help="print the resolved plan without executing")
    return parser


def resolve_scenarios(names: list[str] | None) -> list[Scenario]:
    if not names:
        return list(SCENARIOS)
    seen: set[str] = set()
    values: list[Scenario] = []
    for name in names:
        if name not in seen:
            seen.add(name)
            values.append(SCENARIO_BY_NAME[name])
    return values


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.list:
        for scenario in SCENARIOS:
            marker = "negative-control" if scenario.negative_control else scenario.category
            print(f"{scenario.name}\tseed={scenario.seed}\t{marker}\t{scenario.description}")
        return 0

    root = Path(__file__).resolve().parents[2]
    scenarios = resolve_scenarios(args.scenario)
    if args.rounds < 1:
        parser.error("--rounds must be positive")
    if args.max_executions < 1 or args.max_executions > MAX_MATRIX_EXECUTIONS:
        parser.error(f"--max-executions must be between 1 and {MAX_MATRIX_EXECUTIONS}")
    execution_count = len(scenarios) * args.rounds
    if execution_count > args.max_executions:
        parser.error(
            f"matrix requires {execution_count} executions, exceeding --max-executions={args.max_executions}"
        )
    if not SAFE_NAME.fullmatch(args.variant):
        parser.error("--variant must be a lowercase bounded label")

    source_sha = args.source_sha or git_output(root, "rev-parse", "HEAD")
    baseline_sha = args.baseline_sha or git_output(root, "merge-base", "HEAD", "origin/main")
    if SHA1.fullmatch(source_sha) is None or SHA1.fullmatch(baseline_sha) is None:
        parser.error("source and baseline SHA values must be lowercase 40-character hex commits")
    smoke_script = (args.smoke_script or root / "scripts/nat-sim/nat-sim-smoke.sh").resolve()
    if not smoke_script.is_file() or not os.access(smoke_script, os.X_OK):
        parser.error(f"smoke script is not executable: {smoke_script}")

    plan = {
        "source_head_sha": source_sha,
        "baseline_sha": baseline_sha,
        "variant": args.variant,
        "rounds_per_scenario": args.rounds,
        "execution_count": execution_count,
        "scenarios": [scenario.name for scenario in scenarios],
        "smoke_script": str(smoke_script),
    }
    if args.dry_run:
        print(json.dumps(plan, indent=2, sort_keys=True))
        return 0
    if args.output is None:
        parser.error("--output is required unless --list or --dry-run is used")
    output = args.output.expanduser()
    if not output.is_absolute():
        parser.error("--output must be absolute")
    output = output.resolve()
    try:
        output.relative_to(root)
    except ValueError:
        pass
    else:
        parser.error("--output must be outside the repository")
    if output.exists():
        parser.error(f"--output already exists: {output}")

    old_umask = os.umask(0o077)
    started_at = utc_now()
    try:
        output.mkdir(parents=True, mode=0o700)
        (output / "runner-logs").mkdir(mode=0o700)
        manifest: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "kind": "p2wlan_hard_hard_experiment_matrix",
            "repository": REPOSITORY,
            "source_head_sha": source_sha,
            "baseline_sha": baseline_sha,
            "variant": args.variant,
            "started_at": started_at,
            "completed_at": None,
            "result": "running",
            "plan": plan,
            "protocol_contract": {
                "direct_first_window_ms": 5000,
                "hard_hard_punch_lead_ms": 3500,
                "strategy_changed_by_observability": False,
                "diagnostic_retries": 0,
            },
            "environment": {
                "python": platform.python_version(),
                "platform": sys.platform,
                "physical_two_device_test": "exempt_not_run",
                "cpu_scope": "local smoke subprocess tree; not a cross-host comparison",
            },
            "coverage_notes": {
                "cancellation": "deterministic Rust generation/session cancellation regressions",
                "reconnect": "random-relay-reconnect matrix scenario",
                "real_carrier_nat": "not represented by the local simulator",
                "observability_overhead": (
                    "no isolated on/off performance A/B; CPU/RSS include the full local harness, "
                    "while deterministic regressions verify unchanged ordering, budgets, paths, and cancellation"
                ),
            },
            "runs": [],
        }
        write_manifest(output / "manifest.json", manifest)
        for scenario in scenarios:
            run = execute_scenario(
                root,
                output,
                smoke_script,
                scenario,
                args.rounds,
                source_sha,
                baseline_sha,
                args.variant,
            )
            manifest["runs"].append(run)
            write_manifest(output / "manifest.json", manifest)
        manifest["completed_at"] = utc_now()
        manifest["summary"] = aggregate_runs(manifest["runs"])
        manifest["result"] = (
            "pass" if all(run["result"] == "pass" for run in manifest["runs"]) else "fail"
        )
        write_manifest(output / "manifest.json", manifest)
        print(str(output / "manifest.json"))
        return 0 if manifest["result"] == "pass" else 1
    finally:
        os.umask(old_umask)


if __name__ == "__main__":
    raise SystemExit(main())
