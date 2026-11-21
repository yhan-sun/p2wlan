#!/usr/bin/env python3
"""Strict, offline block-placement evidence reducer; adapters execute separately.

Local request nonces are experiment identities, never invented wire echoes.
The v1 correlation contract requires an isolated scene and a different target
for every action. A file can assert those conditions but cannot prove them.
All results remain fixture or self-reported observations, not game acceptance.
"""

from __future__ import annotations

from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import re

from udp_business_summary import no_duplicate_keys, reject_constant


CONTRACT_PATH = Path(__file__).resolve().parents[2] / "contracts/minecraft_interaction.json"
CONTRACT_BYTES = CONTRACT_PATH.read_bytes()
CONTRACT = json.loads(CONTRACT_BYTES)
CONTRACT_SHA256 = hashlib.sha256(CONTRACT_BYTES).hexdigest()
STATUSES = ("success", "timeout", "action_error", "disconnected", "cancelled", "not_started")
TERMINATIONS = ("completed", "duration_deadline", "interrupted", "adapter_error", "adapter_unavailable")
IDENTITY_HASHES = (
    "p2wlan_client_binary_sha256", "p2wlan_server_binary_sha256", "p2wlan_patch_sha256",
    "configuration_sha256", "adapter_sha256", "adapter_lock_sha256", "scenario_sha256",
    "game_client_binary_sha256", "game_server_binary_sha256", "world_snapshot_sha256",
    "game_settings_sha256", "mods_sha256",
)
SOURCE_FIELDS = ("run_nonce", "round_nonce", "adapter_nonce", "session_nonce", "clock_nonce")


def keys(value: object, expected: set[str], name: str) -> None:
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError(f"{name} has missing or unsupported fields")


def integer(value: object, low: int, high: int, name: str) -> None:
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"{name} must be an integer in {low}..{high}")


def hex_value(value: object, length: int, name: str) -> None:
    if not isinstance(value, str) or re.fullmatch(f"[0-9a-f]{{{length}}}", value) is None:
        raise ValueError(f"invalid {name}")


def label(value: object, name: str) -> None:
    if not isinstance(value, str) or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,95}", value) is None:
        raise ValueError(f"invalid {name}")


def read_json(path: Path) -> tuple[dict, str]:
    with path.open("rb") as stream:
        raw = stream.read(CONTRACT["max_input_bytes"] + 1)
    if len(raw) > CONTRACT["max_input_bytes"]:
        raise ValueError("Minecraft evidence exceeds input byte limit")
    value = json.loads(raw, object_pairs_hook=no_duplicate_keys, parse_constant=reject_constant)
    if not isinstance(value, dict):
        raise ValueError("Minecraft evidence must be a JSON object")
    return value, hashlib.sha256(raw).hexdigest()


def validate_manifest(plan: dict) -> None:
    keys(plan, {"schema_version", "scope", "contract_sha256", "run_nonce", "execution_kind",
                "edition", "transport", "variant", "identity", "rounds"}, "manifest")
    integer(plan["schema_version"], 1, 1, "schema_version")
    if plan["scope"] != CONTRACT["scope"] or plan["contract_sha256"] != CONTRACT_SHA256:
        raise ValueError("manifest scope or contract digest mismatch")
    if (plan["execution_kind"] not in CONTRACT["execution_kinds"]
            or plan["edition"] not in CONTRACT["edition_transports"]
            or plan["transport"] != CONTRACT["edition_transports"][plan["edition"]]
            or plan["variant"] not in ("baseline", "candidate")):
        raise ValueError("invalid execution kind, edition/transport or variant")
    hex_value(plan["run_nonce"], 32, "run_nonce")
    identity = plan["identity"]
    text_fields = ("game_client_version", "game_server_version", "protocol_version",
                   "server_implementation", "runtime_version", "platform", "scenario_version")
    keys(identity, set(IDENTITY_HASHES) | set(text_fields)
         | {"p2wlan_client_commit", "p2wlan_server_commit"}, "identity")
    for name in IDENTITY_HASHES:
        hex_value(identity[name], 64, name)
    for name in ("p2wlan_client_commit", "p2wlan_server_commit"):
        hex_value(identity[name], 40, name)
    for name in text_fields:
        label(identity[name], name)
        if "version" in name and identity[name].lower() in ("latest", "current", "auto", "default"):
            raise ValueError("versions must be fixed, not discovered or mutable selectors")
    rounds = plan["rounds"]
    if not isinstance(rounds, list):
        raise ValueError("rounds must be a list")
    integer(len(rounds), 1, CONTRACT["max_rounds"], "round count")
    seen_rounds, seen_requests, seen_sessions = set(), set(), set()
    for round_ in rounds:
        keys(round_, {"round_nonce", "adapter_nonce", "session_nonce", "clock_nonce", "duration_ns",
                      "world_reset_sha256", "requests"}, "round")
        for name in SOURCE_FIELDS[1:]:
            hex_value(round_[name], 32, name)
        if round_["round_nonce"] in seen_rounds:
            raise ValueError("duplicate round nonce")
        seen_rounds.add(round_["round_nonce"])
        owner = (round_["adapter_nonce"], round_["session_nonce"])
        if owner in seen_sessions:
            raise ValueError("each round requires a fresh game session")
        seen_sessions.add(owner)
        hex_value(round_["world_reset_sha256"], 64, "world_reset_sha256")
        integer(round_["duration_ns"], 1, CONTRACT["max_duration_ns"], "duration_ns")
        requests = round_["requests"]
        if not isinstance(requests, list):
            raise ValueError("requests must be a list")
        integer(len(requests), 1, CONTRACT["max_requests_per_round"], "request count")
        previous = -1
        targets = set()
        for ordinal, request in enumerate(requests):
            keys(request, {"ordinal", "request_nonce", "planned_offset_ns", "timeout_ns", "action",
                           "target_sha256", "before_state_sha256", "after_state_sha256"}, "request")
            integer(request["ordinal"], ordinal, ordinal, "ordinal")
            hex_value(request["request_nonce"], 32, "request_nonce")
            if request["request_nonce"] in seen_requests:
                raise ValueError("duplicate request nonce")
            seen_requests.add(request["request_nonce"])
            for name in ("target_sha256", "before_state_sha256", "after_state_sha256"):
                hex_value(request[name], 64, name)
            if (request["target_sha256"] in targets
                    or request["before_state_sha256"] == request["after_state_sha256"]
                    or request["action"] != CONTRACT["action"]):
                raise ValueError("actions require unique targets and an actual block transition")
            targets.add(request["target_sha256"])
            integer(request["timeout_ns"], 1, CONTRACT["max_request_timeout_ns"], "timeout_ns")
            integer(request["planned_offset_ns"], previous + 1,
                    round_["duration_ns"] - request["timeout_ns"], "planned_offset_ns")
            previous = request["planned_offset_ns"]


def validate_telemetry(values: dict, edition: str) -> None:
    """Retain reported windows separately; never derive them from action RTT."""
    keys(values, set(CONTRACT["telemetry_units"]), "telemetry")
    for name, unit in CONTRACT["telemetry_units"].items():
        metric = values[name]
        keys(metric, {"value", "unit", "reason", "source_sha256", "clock_nonce",
                      "start_offset_ns", "end_offset_ns"}, name)
        if metric["unit"] != unit:
            raise ValueError("telemetry unit mismatch")
        if metric["value"] is None:
            if (metric["reason"] not in ("not_collected", "not_applicable")
                    or any(metric[field] is not None for field in
                           ("source_sha256", "clock_nonce", "start_offset_ns", "end_offset_ns"))):
                raise ValueError("unknown telemetry must remain null with an explicit reason")
            if metric["reason"] == "not_applicable" and name not in (
                {"raknet_retransmissions"} if edition == "java"
                else {"tcp_retransmissions", "server_gc_pause_ms"}
            ):
                raise ValueError("telemetry not_applicable contradicts edition")
            continue
        value = metric["value"]
        if (type(value) not in (int, float) or not 0 <= value <= 10**15 or not math.isfinite(value)
                or metric["reason"] is not None):
            raise ValueError("invalid reported telemetry")
        if name.endswith("retransmissions") and type(value) is not int:
            raise ValueError("retransmission count must be an integer")
        if name == ("raknet_retransmissions" if edition == "java" else "tcp_retransmissions"):
            raise ValueError("telemetry transport contradicts edition")
        hex_value(metric["source_sha256"], 64, "telemetry source")
        hex_value(metric["clock_nonce"], 32, "telemetry clock")
        integer(metric["start_offset_ns"], 0, CONTRACT["max_duration_ns"], "telemetry start")
        integer(metric["end_offset_ns"], metric["start_offset_ns"] + 1,
                CONTRACT["max_duration_ns"], "telemetry end")


def reduce_round(plan: dict, round_: dict, report: dict, manifest_sha256: str) -> dict:
    """Derive every terminal record from the original schedule and event stream."""
    keys(report, {"schema_version", "manifest_sha256", "round_nonce", "elapsed_ns",
                  "termination", "events", "telemetry"}, "report")
    integer(report["schema_version"], 1, 1, "schema_version")
    if report["manifest_sha256"] != manifest_sha256 or report["round_nonce"] != round_["round_nonce"]:
        raise ValueError("report does not belong to its frozen manifest/round")
    integer(report["elapsed_ns"], 0, round_["duration_ns"], "elapsed_ns")
    if report["termination"] not in TERMINATIONS:
        raise ValueError("unknown termination")
    if report["termination"] == "duration_deadline" and report["elapsed_ns"] != round_["duration_ns"]:
        raise ValueError("duration termination precedes fixed deadline")
    validate_telemetry(report["telemetry"], plan["edition"])
    events = report["events"]
    if not isinstance(events, list) or len(events) > CONTRACT["max_events_per_round"]:
        raise ValueError("event budget exceeded or events absent")
    records = [{**request, "status": "not_started", "reason": "no_start_observed",
                "started_offset_ns": None, "completed_offset_ns": None, "rtt_ns": None}
               for request in round_["requests"]]
    by_nonce = {record["request_nonce"]: record for record in records}
    source = {name: plan[name] if name == "run_nonce" else round_[name] for name in SOURCE_FIELDS}
    rejected = Counter()
    ready, closed, previous_time = False, False, -1
    active, next_request = None, 0
    common = set(SOURCE_FIELDS) | {"event_seq", "offset_ns", "kind"}

    def expire(now: int) -> None:
        nonlocal active
        if active is not None and now >= active["started_offset_ns"] + active["timeout_ns"]:
            active.update(status="timeout", reason="response_deadline",
                          completed_offset_ns=active["started_offset_ns"] + active["timeout_ns"])
            active = None

    for ordinal, event in enumerate(events):
        if not isinstance(event, dict):
            raise ValueError("event must be an object")
        kind = event.get("kind")
        extra = {"request_nonce"} if kind in (
            "action_started", "action_confirmed", "action_failed", "action_cancelled"
        ) else set()
        if kind == "action_confirmed":
            extra |= {"confirmation", "correlation", "wire_request_id", "target_sha256",
                      "before_state_sha256", "after_state_sha256", "observation_sha256"}
        elif kind == "action_failed":
            extra.add("reason")
        elif kind not in ("session_ready", "session_closed", "action_started", "action_cancelled"):
            raise ValueError("unsupported event kind")
        keys(event, common | extra, "event")
        integer(event["event_seq"], ordinal, ordinal, "event_seq")
        integer(event["offset_ns"], 0, CONTRACT["max_duration_ns"], "event offset")
        for name in SOURCE_FIELDS:
            hex_value(event[name], 32, name)
        if "request_nonce" in extra:
            hex_value(event["request_nonce"], 32, "request_nonce")
        if kind == "action_confirmed":
            if (event["confirmation"] != CONTRACT["confirmation"]
                    or event["correlation"] != CONTRACT["correlation"]
                    or event["wire_request_id"] is not None):
                raise ValueError("not a supported application confirmation; wire nonce cannot be invented")
            for name in ("target_sha256", "before_state_sha256", "after_state_sha256", "observation_sha256"):
                hex_value(event[name], 64, name)
        if kind == "action_failed" and event["reason"] not in (
            "action_rejected", "action_failed", "confirmation_ambiguous"
        ):
            raise ValueError("invalid action failure reason")
        if any(event[name] != value for name, value in source.items()):
            rejected["source_mismatch"] += 1
            continue
        # Only the current adapter clock can be compared with this report's
        # elapsed time or advance expiry. Foreign clocks remain rejected facts.
        integer(event["offset_ns"], 0, report["elapsed_ns"], "event offset")
        now = event["offset_ns"]
        if now < previous_time:
            raise ValueError("client adapter monotonic clock went backwards")
        previous_time = now
        expire(now)
        if closed:
            rejected["session_closed"] += 1
            continue
        if kind == "session_ready":
            if ready:
                rejected["duplicate_ready"] += 1
            ready = True
            continue
        if kind == "session_closed":
            closed = True
            if active is not None:
                active.update(status="disconnected", reason="session_closed", completed_offset_ns=now)
                active = None
            continue
        record = by_nonce.get(event["request_nonce"])
        if record is None:
            rejected["unknown_request"] += 1
            continue
        if kind == "action_started":
            if (not ready or record["status"] != "not_started"
                    or active is not None or record["ordinal"] != next_request
                    or now < record["planned_offset_ns"]
                    or now + record["timeout_ns"] > round_["duration_ns"]):
                raise ValueError("start violates readiness, single attempt/in-flight, schedule or fixed deadline")
            record.update(status="pending", reason="awaiting_confirmation", started_offset_ns=now)
            active = record
            next_request += 1
            continue
        if record["status"] != "pending":
            rejected["not_pending"] += 1
            continue
        if kind == "action_failed":
            record.update(status="action_error", reason=event["reason"], completed_offset_ns=now)
            active = None
        elif kind == "action_cancelled":
            record.update(status="cancelled", reason="action_cancelled", completed_offset_ns=now)
            active = None
        elif any(event[name] != record[name] for name in
                 ("target_sha256", "before_state_sha256", "after_state_sha256")):
            rejected["transition_mismatch"] += 1
        else:
            record.update(status="success", reason="reported_matching_block_transition",
                          completed_offset_ns=now, rtt_ns=now - record["started_offset_ns"])
            active = None
    expire(report["elapsed_ns"])
    if report["termination"] == "adapter_unavailable" and events:
        raise ValueError("unavailable adapter cannot produce events")
    for row in records:
        if row["status"] in ("pending", "not_started"):
            if report["termination"] == "completed":
                raise ValueError("completed report omitted scheduled outcomes")
            row.update(status="cancelled" if row["status"] == "pending" else "not_started",
                       reason=report["termination"], completed_offset_ns=report["elapsed_ns"])
    return {"round_nonce": round_["round_nonce"], "requests": records,
            "rejected_events": dict(sorted(rejected.items())), "termination": report["termination"],
            "reported_telemetry": report["telemetry"]}
