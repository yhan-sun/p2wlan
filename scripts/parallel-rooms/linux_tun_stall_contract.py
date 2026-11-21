"""Fixed OS UDP application pause/fresh evidence; no native-owner authority."""
from __future__ import annotations

from collections import Counter
import hashlib

COUNT = 8
PHASES = ("paused", "fresh")
PORTS = (44100, 44120, 44101)
TIMING = {"interval_ms": 100, "timeout_ms": 1000, "duration_ms": 10000, "payload_bytes": 128}
HOLD_NS = 3_000_000_000
MAX_SAMPLES = 16
SCOPE = "linux_same_host_kernel_tun_udp_application_server_pause"


def manifest(run_nonce: str, seed: str) -> list[dict]:
    return [{"protocol": "udp", "direction": "a-to-b", "phase": phase, "count": COUNT,
             "run_nonce": run_nonce, "round_nonce": hashlib.sha256((seed + phase).encode()).hexdigest()[:32],
             "source_port": PORTS[index], "target_port": PORTS[2], **TIMING,
             "outcome": "not_started", "records": None} for index, phase in enumerate(PHASES)]


def validate_manifest(entries: list[dict]) -> None:
    if len(entries) != 2 or [e["phase"] for e in entries] != list(PHASES):
        raise ValueError("stall_fixed_two_phase_order_changed")
    for index, entry in enumerate(entries):
        if (entry["protocol"], entry["direction"], entry["count"], entry["source_port"], entry["target_port"]) != (
            "udp", "a-to-b", COUNT, PORTS[index], PORTS[2]
        ) or any(entry[key] != value for key, value in TIMING.items()):
            raise ValueError("stall_fixed_request_budget_changed")
    if entries[0]["run_nonce"] != entries[1]["run_nonce"] or entries[0]["round_nonce"] == entries[1]["round_nonce"]:
        raise ValueError("stall_fresh_nonce_identity_invalid")


def summarize(entries: list[dict]) -> dict:
    validate_manifest(entries)
    counts, nonces, missing = Counter(), [], 0
    phases = {}
    for entry in entries:
        if entry["records"] is None:
            missing += 1
            phase = Counter({"not_started" if entry["outcome"] == "not_started" else "unknown": COUNT})
        else:
            if len(entry["records"]) != COUNT:
                raise ValueError("stall_original_request_list_incomplete")
            phase = Counter(r["status"] for r in entry["records"])
            nonces.extend(r["request_nonce"] for r in entry["records"])
        phases[entry["phase"]] = dict(phase)
        counts.update(phase)
    if len(nonces) != len(set(nonces)):
        raise ValueError("stall_old_nonce_reused_as_fresh")
    paused = entries[0]["records"]
    timeouts = (entries[0].get("probe_exit") == 1 and paused is not None and all(
        r["status"] == "timeout" and r["reason"] == "response_deadline"
        and type(r["sent_offset_ns"]) is int and r["rtt_ns"] is None for r in paused))
    return {"denominator": "all_16_prescheduled_paused_and_fresh_requests_including_missing",
            "prescheduled_requests": 16, "success_requests": counts["success"],
            "terminal_counts": dict(counts), "phase_terminal_counts": phases, "missing_entry_count": missing,
            "paused_request_timeouts_observed": timeouts,
            "all_fresh_responses_observed": entries[1].get("probe_exit") == 0 and phases["fresh"] == {"success": COUNT},
            "all_16_distinct_request_nonces_observed": len(nonces) == 16,
            "canonical_current_owner_verified": None, "exact_direct_request_attribution": None,
            "default_keepalive_cycle_verified": False, "public_network_verified": None,
            "tcp_server_stall_verified": None, "first_application_recovery_ms": None}


def paused_request_window(entry: dict, pause: dict) -> dict:
    spawn, terminal = entry.get("probe_spawn_requested_monotonic_ns"), entry.get("probe_terminal_observed_monotonic_ns")
    if (type(spawn) is not int or type(terminal) is not int
            or not pause["stopped_monotonic_ns"] <= spawn <= terminal < pause["resume_requested_monotonic_ns"]
            or entry.get("observed_probe_exit") != 1):
        raise ValueError("stall_paused_requests_not_completed_while_original_echo_stopped")
    return {"all_paused_requests_terminal_while_original_echo_stopped": True,
            "spawn_requested_monotonic_ns": spawn, "terminal_observed_monotonic_ns": terminal,
            "observed_probe_exit": entry["observed_probe_exit"]}


def _peer(status: dict) -> tuple[str, dict]:
    if (status.get("process_alive") is not True or status.get("peer_snapshot_stale") is not False
            or type(status.get("pid")) is not int or type(status.get("process_id")) is not int
            or status.get("pid") <= 0 or status.get("pid") != status.get("process_id")
            or type(status.get("network_generation")) is not int
            or type(status.get("revision")) is not int or type(status.get("captured_revision")) is not int
            or status.get("revision") != status.get("captured_revision")
            or status.get("health", {}).get("status") != "healthy" or len(status.get("peers", {})) != 1):
        raise ValueError("stall_current_daemon_health_unknown")
    tasks = status["health"].get("critical_tasks", [])
    if (not {"dataplane", "udp-direct", "wireguard-inbound", "network-outbound"} <= {t.get("name") for t in tasks}
            or any(t.get("running") is not True or t.get("finished") is not False or t.get("error") for t in tasks)):
        raise ValueError("stall_original_daemon_task_not_running")
    node, peer = next(iter(status["peers"].items()))
    selector, pair = peer.get("current_path_selection") or {}, peer.get("selected_pair") or {}
    if (peer.get("state") != "direct" or peer.get("active_path") != "direct" or peer.get("online") is not True
            or selector.get("path") != "direct" or selector.get("direct_confirmed") is not True
            or pair.get("selected") is not True or pair.get("state") != "selected"
            or not isinstance(pair.get("remote_endpoint"), str) or not pair["remote_endpoint"]
            or selector.get("direct_endpoint") != pair.get("remote_endpoint")
            or peer.get("consent_endpoint") != pair.get("remote_endpoint")
            or peer.get("network_generation") != status.get("network_generation")
            or pair.get("local_generation") != status.get("network_generation")
            or any(type(peer.get(key)) is not int for key in (
                "peer_session_generation", "network_generation", "direct_generation", "remote_candidate_epoch"))
            or type(pair.get("local_generation")) is not int):
        raise ValueError("stall_original_selected_path_unknown")
    for health in (peer.get("direct") or {}, pair):
        if (type(health.get("failure_count")) is not int or type(health.get("success_count")) is not int
                or type(health.get("consecutive_failures")) is not int or health.get("consecutive_failures") != 0):
            raise ValueError("stall_original_health_counters_unknown")
    return node, peer


def health_evidence(before: dict, paused: list[dict], after: dict, pause: dict) -> dict:
    if not paused or len(paused) > MAX_SAMPLES:
        raise ValueError("stall_paused_samples_missing_or_unbounded")
    start, end = pause["stopped_monotonic_ns"], pause["resume_requested_monotonic_ns"]
    native = {}
    for name in ("a1", "b1"):
        baseline = before[name]
        node, base = _peer(baseline)
        events = []
        for sample in [*paused, after]:
            status = sample[name]
            observed_node, peer = _peer(status)
            if (observed_node != node or any(status.get(key) != baseline.get(key) for key in (
                "pid", "process_id", "runtime_incarnation", "instance", "run_id", "correlation_id", "node_id", "network_id", "network_generation"))
                    or any(peer.get(key) != base.get(key) for key in (
                        "peer_session_generation", "remote_candidate_epoch", "direct_generation", "consent_endpoint"))
                    or any(peer["selected_pair"].get(key) != base["selected_pair"].get(key) for key in (
                        "local_endpoint", "remote_endpoint", "local_generation"))):
                raise ValueError("stall_original_process_path_identity_changed")
            for health, original in ((peer["direct"], base["direct"]), (peer["selected_pair"], base["selected_pair"])):
                if health["failure_count"] != original["failure_count"] or health["success_count"] < original["success_count"]:
                    raise ValueError("stall_application_pause_changed_path_health")
            if sample is after:
                continue
            begin, finish = peer["observed_begin_monotonic_ns"], peer["observed_end_monotonic_ns"]
            if type(begin) is not int or type(finish) is not int or not start <= begin <= finish < end:
                raise ValueError("stall_sample_outside_actual_stopped_window")
            for event in peer.get("direct_events", []):
                if event.get("network_generation") != baseline["network_generation"] or event.get("endpoint") != base["consent_endpoint"]:
                    continue
                age = event.get("age_ms")
                if type(age) is int and age >= 0 and event.get("stage") == "consent_timeout" and finish - age * 1_000_000 >= start:
                    raise ValueError("stall_consent_timeout_observed")
                if event.get("stage") == "consent_ack_received" and type(age) is int and age >= 0:
                    earliest, latest = begin - (age + 1) * 1_000_000, finish - age * 1_000_000
                    if start <= earliest <= latest < end:
                        events.append({"generation": event["network_generation"], "endpoint": event["endpoint"],
                                       "event_window_begin_monotonic_ns": earliest, "event_window_end_monotonic_ns": latest})
        if not events:
            raise ValueError("stall_new_original_consent_missing_or_time_unknown")
        native[name] = events
    return {"both_original_paths_stable": True, "new_consent_while_application_stopped": native,
            "keepalive_interval_secs": 1, "native_ack_wait_ms": 2000, "exact_consent_nonce_verified": None}


def accepted(summary: dict, evidence: dict) -> bool:
    pause, echo = evidence.get("pause", {}), evidence.get("echo", {})
    return (summary.get("paused_request_timeouts_observed") is True
            and summary.get("all_fresh_responses_observed") is True
            and summary.get("all_16_distinct_request_nonces_observed") is True
            and summary.get("missing_entry_count") == 0 and evidence.get("health", {}).get("both_original_paths_stable") is True
            and evidence.get("paused_request_window", {}).get("all_paused_requests_terminal_while_original_echo_stopped") is True
            and pause.get("restored") is True and pause.get("original_pid_confirmed") is True
            and type(pause.get("stopped_lower_bound_ns")) is int and HOLD_NS <= pause["stopped_lower_bound_ns"] < HOLD_NS + 250_000_000
            and type(pause.get("stopped_observation_upper_bound_ns")) is int
            and pause["stopped_lower_bound_ns"] <= pause["stopped_observation_upper_bound_ns"] < HOLD_NS + 250_000_000
            and echo.get("responses_sent_by_phase") == {"paused": COUNT, "fresh": COUNT}
            and echo.get("send_errors") == 0 and echo.get("termination_reason") == "request_budget_exhausted")
