"""One fixed fault/fresh application slice; no canonical or native-owner credit."""
from __future__ import annotations

from collections import Counter
import hashlib

from linux_tun_contract import COUNT

PHASES = (("udp", "blackhole"), ("tcp", "blackhole"), ("udp", "recovery"), ("tcp", "recovery"))
PORTS = {"udp": (44000, 44020, 44001), "tcp": (44010, 44030, 44011)}
TIMING = {"interval_ms": 100, "timeout_ms": 1000, "duration_ms": 10000, "payload_bytes": 128}
SCOPE = "linux_same_host_kernel_tun_application_blackhole_recovery"


def manifest(run_nonce: str, round_seed: str) -> list[dict]:
    return [{"protocol": protocol, "direction": "a-to-b", "phase": phase, "count": COUNT,
             "run_nonce": run_nonce,
             "round_nonce": hashlib.sha256((round_seed + protocol + phase).encode()).hexdigest()[:32],
             "source_port": PORTS[protocol][0 if phase == "blackhole" else 1],
             "target_port": PORTS[protocol][2], **TIMING,
             "outcome": "not_started", "records": None} for protocol, phase in PHASES]


def validate_manifest(entries: list[dict]) -> None:
    if [(e["protocol"], e["phase"]) for e in entries] != list(PHASES):
        raise ValueError("original fault/fresh four-entry order changed")
    for entry in entries:
        expected = PORTS[entry["protocol"]]
        if (entry["count"], entry["direction"], entry["source_port"], entry["target_port"]) != (
            COUNT, "a-to-b", expected[0 if entry["phase"] == "blackhole" else 1], expected[2]
        ) or any(entry[k] != value for k, value in TIMING.items()):
            raise ValueError("fixed fault/fresh count/flow/timing changed")
    if len({e["run_nonce"] for e in entries}) != 1 or len({e["round_nonce"] for e in entries}) != 4:
        raise ValueError("fault and fresh rounds reused or changed original run nonce")


def expected_blackhole(entry: dict, probe: dict, echo: dict) -> bool:
    """Only precise original failure reports qualify, never generic exit1."""
    if entry["phase"] != "blackhole" or entry.get("probe_exit") != 1:
        return False
    if echo.get("termination_reason") != "duration_deadline" or echo.get("responses_sent") != 0 or echo.get("send_errors") != 0:
        return False
    if entry["protocol"] == "udp":
        return entry.get("echo_exit") == 0 and all(
            r["status"] == "timeout" and r["reason"] == "response_deadline" and r["sent_offset_ns"] is not None
            for r in entry["records"]
        )
    return (entry.get("echo_exit") == 1 and probe.get("connection_attempts") == 1
            and probe.get("termination_reason") == "connect_deadline" and echo.get("accepted_connections") == 0
            and all(r["status"] == "not_sent" and r["reason"] == "connect_deadline" and r["sent_offset_ns"] is None
                    for r in entry["records"]))


def summarize(entries: list[dict]) -> dict:
    validate_manifest(entries)
    counts, by_phase = Counter(), {phase: Counter() for phase in ("blackhole", "recovery")}
    nonces = []
    missing = 0
    for entry in entries:
        records = entry["records"]
        if records is None:
            missing += 1
            bucket = "not_started" if entry["outcome"] == "not_started" else "unknown"
            by_phase[entry["phase"]][bucket] += COUNT
        else:
            if len(records) != COUNT:
                raise ValueError("fault/fresh fixed request list incomplete")
            by_phase[entry["phase"]].update(r["status"] for r in records)
            nonces.extend(r["request_nonce"] for r in records)
    for phase_counts in by_phase.values():
        counts.update(phase_counts)
    if len(set(nonces)) != len(nonces):
        raise ValueError("old request nonce replayed in a fresh phase")
    expected = (all(e.get("expected_blackhole_observed") is True for e in entries[:2])
                and by_phase["blackhole"] == Counter({"timeout": 8, "not_sent": 8}))
    recovered = by_phase["recovery"]["success"] == 16
    return {"denominator": "all_32_prescheduled_fault_and_fresh_requests_including_missing",
            "prescheduled_requests": 32, "expected_fault_requests": 16, "fresh_recovery_requests": 16,
            "success_requests": counts["success"], "terminal_counts": dict(counts),
            "phase_terminal_counts": {k: dict(v) for k, v in by_phase.items()},
            "missing_entry_count": missing, "all_responses_observed": counts["success"] == 32 and missing == 0,
            "expected_blackhole_failures_observed": expected, "all_fresh_responses_observed": recovered,
            "all_32_distinct_request_nonces_observed": len(nonces) == 32,
            "canonical_current_owner_verified": None, "exact_direct_request_attribution": None,
            "first_usable_recovery_ms": None, "native_direct_recovery_ms": None,
            "other_platforms_verified": None, "public_network_verified": None}


def accepted(summary: dict, fault: dict) -> bool:
    before, blocked = fault.get("before_requests"), fault.get("after_blackhole")
    cleared = fault.get("normal_clear")
    if not before or not blocked or not cleared:
        return False
    if (len(before["rules"]) != 2 or len(blocked["rules"]) != 2 or not cleared.get("after")
            or before["namespace_identity"] != blocked["namespace_identity"]
            or before["namespace_identity"] != cleared["after"]["namespace_identity"]
            or cleared["after"]["rules"] != []):
        return False
    initial = {r["protocol"]: r for r in before["rules"]}
    actual = {r["protocol"]: r for r in blocked["rules"]}
    if set(initial) != {"udp", "tcp"} or set(actual) != {"udp", "tcp"}:
        return False
    if any(initial[p]["marker"] != actual[p]["marker"] for p in initial):
        return False
    hits = (all(r["packets"] == 0 and r["bytes"] == 0 for r in initial.values())
            and actual["udp"]["packets"] == COUNT and actual["udp"]["bytes"] > 0
            and actual["tcp"]["packets"] >= 1 and actual["tcp"]["bytes"] > 0)
    return (hits and cleared.get("complete") is True and cleared.get("remaining") == []
            and cleared.get("all_owned_rules_observed_absent") is True
            and summary["expected_blackhole_failures_observed"] and summary["all_fresh_responses_observed"]
            and summary["all_32_distinct_request_nonces_observed"] and summary["missing_entry_count"] == 0)
