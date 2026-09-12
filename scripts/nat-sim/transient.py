#!/usr/bin/env python3
"""Fail-closed classifier for one NAT topology attempt.

The classifier is diagnostic only. A completed business-validation failure is
never made retryable: a later attempt must not erase an observed packet loss,
SLO miss, invalid packet, topology violation, or other acceptance failure.
Startup and baseline failures are read from structured readiness records so
"not ready", process exit, and damaged evidence remain distinct.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


PROFILES = {"relay-blackhole", "direct-cold-start"}
ROUND_FAIL = re.compile(r"ROUND\s+(\d+):\s+FAIL\b")
FIELD = re.compile(r"([a-z_][a-z_0-9]*)=([^\s]+)")
REASON = re.compile(r"(?:^|\s)reason_code=([^\s]+)")
INTEGER = re.compile(r"-?[0-9]+\Z")
RATIO = re.compile(r"[0-9]+/[0-9]+\Z")
SHA1 = re.compile(r"[0-9a-f]{40}\Z")

# The profile-specific summary lines are emitted by nat-sim-smoke.sh. Keeping
# their contracts here makes a missing counter or type change fail closed.
PROFILE_FIELDS: dict[str, dict[str, set[str]]] = {
    "relay-blackhole": {
        "integer": {
            "overlay_ok",
            "a_direct",
            "b_direct",
            "a_overlay",
            "b_overlay",
            "a_relay_confirmed",
            "b_relay_confirmed",
            "a_delta_ms",
            "b_delta_ms",
            "sum_delta_ms",
            "drops_a",
            "drops_b",
            "replay_a",
            "replay_b",
            "invalid_a",
            "invalid_b",
            "burst_a",
            "burst_b",
            "burst_bad_a",
            "burst_bad_b",
            "status_always_200_a",
            "status_always_200_b",
            "task_health_a",
            "task_health_b",
            "elapsed_ms",
        },
        "ratio": {"status_http_200_a", "status_http_200_b"},
        "text": {"reason_code", "a_ingress", "b_ingress"},
    },
    "direct-cold-start": {
        "integer": {
            "a_direct",
            "b_direct",
            "a_overlay",
            "b_overlay",
            "a_relay_confirmed",
            "b_relay_confirmed",
            "a_delta_ms",
            "b_delta_ms",
            "sum_delta_ms",
            "drops_a",
            "drops_b",
            "replay_a",
            "replay_b",
            "invalid_a",
            "invalid_b",
            "elapsed_ms",
        },
        "ratio": set(),
        "text": {"reason_code", "a_ingress", "b_ingress"},
    },
}

KNOWN_REASON_CODES = {
    "baseline_status_not_available",
    "blackhole_not_active",
    "business_validation_failed",
    "collector_not_run",
    "critical_tasks_unhealthy",
    "critical_tasks_healthy",
    "daemon_not_token_ready",
    "daemon_process_exited",
    "daemon_readiness_timeout",
    "diagnostics_revision_not_converged",
    "direct_business_ingress_missing",
    "direct_overlay_unverified",
    "evidence_not_converged",
    "evidence_parse_failed",
    "evidence_parser_loss",
    "first_usable_committed",
    "first_business_not_passed",
    "first_usable_delta_missing",
    "first_usable_never_observed",
    "first_usable_path_mismatch",
    "invariant_failed",
    "metrics_http_500_injected",
    "metrics_schema_invalid",
    "metrics_unavailable",
    "no_replay_or_invalid",
    "outbound_drops_zero",
    "outbound_drop",
    "overlay_burst_incomplete",
    "overlay_invalid",
    "overlay_verification_failed",
    "relay_confirmation_missing",
    "relay_direct_violation",
    "relay_failover_no_replacement_business",
    "relay_first_slo_exceeded",
    "relay_not_confirmed_before_direct_business",
    "relay_peer_confirmation_timeout",
    "relay_business_gate_failed",
    "replay_detected",
    "status_auth_token_missing",
    "status_http_500_injected",
    "status_http_failure",
    "status_schema_invalid",
    "status_unavailable",
    "process_incarnation_stable",
    "relay_connected",
    "relay_peer_confirmed",
    "first_business_received",
    "first_business_direction_complete",
    "first_usable_delta_fenced",
    "overlay_verified",
    "direct_not_used",
    "burst_complete",
    "stale_process_identity",
    "test_harness_failure",
    "test_harness_startup_failure",
    "unknown",
}

HARD_REASON_CODES = {
    "blackhole_not_active",
    "critical_tasks_unhealthy",
    "daemon_process_exited",
    "diagnostics_revision_not_converged",
    "direct_business_ingress_missing",
    "direct_overlay_unverified",
    "evidence_not_converged",
    "evidence_parse_failed",
    "evidence_parser_loss",
    "first_business_not_passed",
    "first_usable_delta_missing",
    "first_usable_never_observed",
    "first_usable_path_mismatch",
    "metrics_http_500_injected",
    "metrics_schema_invalid",
    "metrics_unavailable",
    "no_replay_or_invalid",
    "outbound_drop",
    "overlay_burst_incomplete",
    "overlay_invalid",
    "overlay_verification_failed",
    "relay_confirmation_missing",
    "relay_direct_violation",
    "relay_failover_no_replacement_business",
    "relay_first_slo_exceeded",
    "relay_not_confirmed_before_direct_business",
    "replay_detected",
    "stale_process_identity",
    "status_http_500_injected",
    "status_http_failure",
    "status_schema_invalid",
    "status_unavailable",
    "test_harness_failure",
    "test_harness_startup_failure",
}

READINESS_RESULTS = {
    "ready",
    "timeout",
    "process_exited",
    "http_failure",
    "schema_invalid",
    "barrier_timeout",
    "task_failed",
}


def _failure(reason: str, signature: dict[str, Any]) -> dict[str, Any]:
    return {"retryable": False, "reason": reason, "signature": signature}


def _parse_line_fields(line: str) -> tuple[dict[str, str], str | None]:
    fields: dict[str, str] = {}
    for key, value in FIELD.findall(line):
        normalized = value.rstrip(",")
        if key in fields:
            return fields, f"duplicate_field:{key}"
        fields[key] = normalized
    return fields, None


def _validate_profile_line(profile: str, fields: dict[str, str]) -> str | None:
    contract = PROFILE_FIELDS[profile]
    required = contract["integer"] | contract["ratio"] | contract["text"]
    missing = sorted(required - set(fields))
    if missing:
        return "profile_fields_missing:" + ",".join(missing)
    for name in contract["integer"]:
        if INTEGER.fullmatch(fields[name]) is None:
            return f"profile_field_type_invalid:{name}"
    for name in contract["ratio"]:
        if RATIO.fullmatch(fields[name]) is None:
            return f"profile_field_type_invalid:{name}"
    for name in contract["text"]:
        if not fields[name] or fields[name] == "none":
            if name == "reason_code":
                return "profile_field_type_invalid:reason_code"
    if "reason_code" not in fields or fields["reason_code"] not in KNOWN_REASON_CODES:
        return "unknown_failure_reason"
    if fields["reason_code"] in HARD_REASON_CODES:
        return "hard_business_failure"
    return None


def _validate_evidence(evidence: dict[str, Any], profile: str) -> tuple[str | None, str | None]:
    expected_scenario = "relay-blackhole" if profile == "relay-blackhole" else "direct-cold-start"
    if type(evidence.get("schema_version")) is not int or evidence["schema_version"] != 1:
        return None, "evidence_schema_invalid"
    if evidence.get("repository") != "yhan-sun/p2wlan" or evidence.get("topology") != expected_scenario:
        return None, "evidence_identity_invalid"
    replica, round_number = evidence.get("replica"), evidence.get("round")
    if type(replica) is not int or replica < 1 or type(round_number) is not int or round_number < 1:
        return None, "evidence_scenario_invalid"
    scenario = f"{expected_scenario}:replica-{replica}:round-{round_number}"
    exact_test = f"nat-sim-smoke.sh::{expected_scenario}::replica-{replica}::round-{round_number}"
    if evidence.get("scenario_id") != scenario or evidence.get("exact_test_id") != exact_test:
        return None, "evidence_scenario_invalid"
    if SHA1.fullmatch(str(evidence.get("source_head_sha", ""))) is None:
        return None, "evidence_source_identity_invalid"
    if SHA1.fullmatch(str(evidence.get("workflow_sha", ""))) is None:
        return None, "evidence_workflow_identity_invalid"
    if evidence.get("executed") is not True or evidence.get("skipped") is not False:
        return None, "evidence_execution_state_invalid"
    if not all(isinstance(evidence.get(name), dict) for name in ("observed", "collector", "invariants")):
        return None, "evidence_schema_invalid"
    if not isinstance(evidence["collector"].get("revision_converged"), bool):
        return None, "evidence_schema_invalid"
    result = evidence.get("result")
    decision = evidence.get("decision")
    if not isinstance(result, str) or result not in {"pass", "fail"} or not isinstance(decision, dict):
        return None, "evidence_schema_invalid"
    if decision.get("result") != result:
        return None, "evidence_result_conflict"
    reason = decision.get("reason_code")
    if result == "pass":
        if reason is not None:
            return None, "evidence_decision_conflict"
        return None, None
    if not isinstance(reason, str) or not reason:
        return None, "evidence_reason_missing"
    if reason not in KNOWN_REASON_CODES:
        return reason, "unknown_failure_reason"
    return reason, None


def _validate_readiness(record: dict[str, Any]) -> str | None:
    if type(record.get("schema_version")) is not int or record["schema_version"] != 1:
        return "readiness_schema_invalid"
    stage = record.get("stage")
    if not isinstance(stage, str) or stage not in {"token", "baseline", "barrier"}:
        return "readiness_stage_invalid"
    result = record.get("result")
    if not isinstance(result, str) or result not in READINESS_RESULTS:
        return "readiness_result_invalid"
    if not isinstance(record.get("state"), str) or not record["state"]:
        return "readiness_state_invalid"
    if not isinstance(record.get("business_validation_started"), bool):
        return "readiness_business_state_invalid"
    if record["stage"] in {"token", "baseline"}:
        if not isinstance(record.get("process_alive"), bool):
            return "readiness_process_state_invalid"
        if not isinstance(record.get("token_present"), bool):
            return "readiness_token_state_invalid"
        pid = record.get("pid")
        if type(pid) is not int or pid <= 0:
            return "readiness_pid_invalid"
        side = record.get("side")
        if not isinstance(side, str) or side not in {"a", "b"}:
            return "readiness_side_invalid"
        if record["result"] == "process_exited" and record["process_alive"] is not False:
            return "readiness_process_result_conflict"
        reason = record.get("reason_code")
        if reason is not None and (not isinstance(reason, str) or reason not in KNOWN_REASON_CODES):
            return "readiness_reason_invalid"
        if record["result"] == "ready" and reason is not None:
            return "readiness_reason_conflict"
        if record["result"] == "ready":
            if record["process_alive"] is not True or record["token_present"] is not True:
                return "readiness_ready_state_conflict"
            if record["stage"] == "baseline":
                if type(record.get("http_status")) is not int or record["http_status"] != 200:
                    return "baseline_http_status_invalid"
                if type(record.get("attempts")) is not int or record["attempts"] < 1:
                    return "baseline_attempt_count_invalid"
    if record["stage"] == "barrier":
        for side in ("a", "b"):
            pid = record.get(f"pid_{side}")
            if type(pid) is not int or pid <= 0:
                return f"barrier_pid_invalid:{side}"
        for side in ("a", "b"):
            if not isinstance(record.get(f"process_alive_{side}"), bool):
                return f"barrier_process_state_invalid:{side}"
            if not isinstance(record.get(f"relay_peer_confirmed_{side}"), bool):
                return f"barrier_confirmation_state_invalid:{side}"
            if not isinstance(record.get(f"task_health_{side}"), bool):
                return f"barrier_task_state_invalid:{side}"
            status = record.get(f"http_status_{side}")
            if type(status) is not int or not 0 <= status <= 599:
                return f"barrier_http_status_invalid:{side}"
        if record["result"] == "ready" and any(
            record.get(key) is not expected
            for key, expected in (
                ("process_alive_a", True),
                ("process_alive_b", True),
                ("relay_peer_confirmed_a", True),
                ("relay_peer_confirmed_b", True),
                ("task_health_a", True),
                ("task_health_b", True),
                ("http_status_a", 200),
                ("http_status_b", 200),
            )
        ):
            return "barrier_ready_state_conflict"
        reason = record.get("reason_code")
        if reason is not None and (not isinstance(reason, str) or reason not in KNOWN_REASON_CODES):
            return "barrier_reason_invalid"
        if record["result"] == "ready" and reason is not None:
            return "barrier_reason_conflict"
    return None


def _validate_readiness_chain(records: list[dict[str, Any]]) -> str | None:
    side_records: dict[str, list[dict[str, Any]]] = {"a": [], "b": []}
    barriers: list[dict[str, Any]] = []
    for record in records:
        if record["stage"] == "barrier":
            barriers.append(record)
        else:
            side_records[record["side"]].append(record)

    for side, values in side_records.items():
        pids = {record["pid"] for record in values}
        if len(pids) > 1:
            return f"readiness_process_identity_conflict:{side}"
        business_states = {record["business_validation_started"] for record in values}
        if len(business_states) > 1:
            return f"readiness_business_phase_conflict:{side}"
        token_records = [record for record in values if record["stage"] == "token"]
        baseline_records = [record for record in values if record["stage"] == "baseline"]
        if any(
            record.get("target") == "TOKEN_READY" and record["result"] == "process_exited"
            for record in token_records
        ) and any(record["result"] == "ready" for record in baseline_records):
            return f"readiness_process_lifecycle_conflict:{side}"

    for barrier in barriers:
        if barrier["result"] != "ready":
            continue
        if barrier["business_validation_started"] is not True:
            return "barrier_business_phase_conflict"
        for side in ("a", "b"):
            values = side_records[side]
            if barrier[f"pid_{side}"] not in {record["pid"] for record in values}:
                return f"barrier_process_identity_conflict:{side}"
            if not any(record["stage"] == "token" and record["result"] == "ready" for record in values):
                return f"barrier_without_token_readiness:{side}"
            if not any(record["stage"] == "baseline" and record["result"] == "ready" for record in values):
                return f"barrier_without_baseline_readiness:{side}"
            if any(record["result"] != "ready" for record in values):
                return f"barrier_after_failed_readiness:{side}"
    return None


def classify_attempt(
    log_text: str,
    evidence: dict[str, Any] | None = None,
    attempt: int = 1,
    *,
    profile: str | None = None,
    readiness: list[dict[str, Any]] | None = None,
    evidence_error: str | None = None,
    readiness_errors: list[str] | None = None,
    business_started: bool | None = None,
) -> dict[str, Any]:
    """Return a fail-closed classification; no observed business failure retries."""
    signature: dict[str, Any] = {"attempt": attempt, "profile": profile}
    if type(attempt) is not int or attempt != 1:
        return _failure("attempt_history_requires_final_adjudication", signature)
    if not isinstance(profile, str) or profile not in PROFILES:
        return _failure("profile_missing_or_unknown", signature)
    # Collect reasons across the whole attempt before inspecting summaries or
    # secondary artifacts. A later aggregate line, missing evidence file, or
    # malformed readiness record must never hide an observed hard failure.
    lines = log_text.splitlines()
    reason_codes = [
        match.group(1).rstrip(",")
        for line in lines
        for match in REASON.finditer(line)
    ]
    signature["reason_codes"] = reason_codes
    hard_reasons = [reason for reason in reason_codes if reason in HARD_REASON_CODES]
    if hard_reasons:
        signature["hard_reason_codes"] = hard_reasons
        return _failure("hard_line_reason", signature)
    unknown_reasons = [reason for reason in reason_codes if reason not in KNOWN_REASON_CODES]
    if unknown_reasons:
        signature["unknown_reason_codes"] = unknown_reasons
        return _failure("unknown_failure_reason", signature)

    if evidence is not None and not isinstance(evidence, dict):
        return _failure("evidence_schema_invalid", signature)
    if readiness is not None and not isinstance(readiness, list):
        return _failure("readiness_evidence_corrupt", signature)

    if evidence is not None and isinstance(evidence.get("decision"), dict):
        evidence_reason = evidence["decision"].get("reason_code")
        if isinstance(evidence_reason, str):
            signature["evidence_reason"] = evidence_reason
            if evidence_reason in HARD_REASON_CODES:
                return _failure("hard_evidence_reason", signature)
            if evidence_reason not in KNOWN_REASON_CODES:
                return _failure("unknown_failure_reason", signature)

    readiness_records = readiness or []
    for index, record in enumerate(readiness_records):
        if not isinstance(record, dict):
            signature["readiness_record_error"] = "readiness_record_not_object"
            signature["readiness_index"] = index
            return _failure("readiness_evidence_corrupt", signature)
        validation_error = _validate_readiness(record)
        if validation_error:
            signature["readiness_record_error"] = validation_error
            signature["readiness_index"] = index
            return _failure("readiness_evidence_corrupt", signature)
        if record["result"] == "process_exited" or record.get("process_alive") is False:
            signature["readiness_stage"] = record["stage"]
            signature["pid"] = record.get("pid")
            return _failure("process_exited", signature)
    chain_error = _validate_readiness_chain(readiness_records)
    if chain_error:
        signature["readiness_chain_error"] = chain_error
        return _failure("readiness_evidence_corrupt", signature)

    failed_records = [record for record in readiness_records if record["result"] != "ready"]
    if failed_records:
        first = failed_records[0]
        signature["readiness_stage"] = first["stage"]
        signature["readiness_result"] = first["result"]
        if evidence_error:
            signature["evidence_error"] = evidence_error
        return _failure(
            {
                "timeout": "readiness_not_ready",
                "http_failure": "readiness_http_failure",
                "schema_invalid": "readiness_schema_failure",
                "barrier_timeout": "barrier_timeout",
                "task_failed": "readiness_task_failure",
            }.get(first["result"], "readiness_failed"),
            signature,
        )

    if readiness_errors:
        signature["readiness_errors"] = readiness_errors
        missing = any("FileNotFoundError" in error or error.endswith(":missing") for error in readiness_errors)
        return _failure("readiness_evidence_missing" if missing else "readiness_evidence_corrupt", signature)
    if evidence_error:
        signature["evidence_error"] = evidence_error
        if evidence_error.endswith(":missing") or "FileNotFoundError" in evidence_error:
            return _failure("evidence_missing", signature)
        return _failure("evidence_corrupt", signature)

    evidence_reason = None
    if evidence is not None:
        evidence_reason, validation_error = _validate_evidence(evidence, profile)
        signature["evidence_reason"] = evidence_reason
        if validation_error:
            return _failure(validation_error, signature)
        if evidence_reason in HARD_REASON_CODES:
            return _failure("hard_evidence_reason", signature)
        if evidence_reason is not None and evidence_reason not in KNOWN_REASON_CODES:
            return _failure("unknown_failure_reason", signature)

    failed_lines = [line for line in lines if ROUND_FAIL.search(line)]
    if failed_lines:
        if business_started is not True:
            return _failure("business_phase_evidence_missing_or_conflicting", signature)
        parsed_lines: list[tuple[str, dict[str, str]]] = []
        for line in failed_lines:
            fields, parse_error = _parse_line_fields(line)
            if parse_error:
                signature["gate_line_error"] = parse_error
                return _failure("gate_line_invalid", signature)
            reason = fields.get("reason_code")
            if reason is None:
                return _failure("gate_line_reason_missing", signature)
            if reason not in KNOWN_REASON_CODES:
                signature["unknown_reason_code"] = reason
                return _failure("unknown_failure_reason", signature)
            parsed_lines.append((line, fields))

        schema_marker = "overlay_ok" if profile == "relay-blackhole" else "a_direct"
        detailed = [fields for _, fields in parsed_lines if schema_marker in fields]
        if not detailed:
            return _failure("profile_fields_missing:" + schema_marker, signature)
        for fields in detailed:
            validation_error = _validate_profile_line(profile, fields)
            if validation_error:
                return _failure(validation_error, signature)
        if evidence is None:
            return _failure("evidence_missing", signature)
        if evidence.get("result") != "fail":
            return _failure("evidence_result_conflict", signature)
        if not readiness_records:
            return _failure("readiness_evidence_missing", signature)
        coverage = {
            (record["stage"], record.get("side"))
            for record in readiness_records
            if record["stage"] != "barrier"
        }
        required_coverage = {
            ("token", "a"),
            ("token", "b"),
            ("baseline", "a"),
            ("baseline", "b"),
        }
        if not required_coverage.issubset(coverage) or not any(
            record["stage"] == "barrier" for record in readiness_records
        ):
            return _failure("readiness_evidence_missing", signature)
        if any(record["result"] != "ready" for record in readiness_records):
            return _failure("readiness_failed_during_business_attempt", signature)
        if business_started is not True:
            return _failure("business_phase_evidence_missing_or_conflicting", signature)
        signature["gate_line_count"] = len(failed_lines)
        signature["business_validation_started"] = True
        return _failure("business_validation_failed", signature)

    if evidence is not None and evidence.get("result") == "fail":
        return _failure("business_validation_failed", signature)

    if evidence is None:
        return _failure("evidence_missing", signature)
    if not readiness_records:
        return _failure("readiness_evidence_missing", signature)
    return _failure("unrecognized_failure", signature)


def _load_object(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return None, f"{path}:{type(exc).__name__}"
    if not isinstance(value, dict):
        return None, f"{path}:not_object"
    return value, None


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    command = parser.add_subparsers(dest="command", required=True)
    classify = command.add_parser("classify", help="classify one failed attempt")
    classify.add_argument("--profile", required=True, choices=sorted(PROFILES))
    classify.add_argument("--log", required=True, help="smoke attempt log")
    classify.add_argument("--evidence", default=None, help="nat-evidence.json if produced")
    classify.add_argument("--readiness", action="append", default=[], help="structured readiness JSON")
    classify.add_argument("--business-started", default=None, help="business-validation marker path")
    classify.add_argument("--attempt", type=int, default=1)
    classify.add_argument("--output", default=None, help="optional JSON classification path")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    try:
        log_text = Path(args.log).read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        log_text = ""
        log_error = f"{args.log}:{type(exc).__name__}"
    else:
        log_error = None

    evidence = None
    evidence_error = log_error
    if args.evidence:
        evidence_path = Path(args.evidence)
        if not evidence_path.is_file():
            evidence_error = f"{evidence_path}:missing"
        else:
            evidence, evidence_error = _load_object(evidence_path)

    readiness: list[dict[str, Any]] = []
    readiness_errors: list[str] = []
    for readiness_path_text in args.readiness:
        record, error = _load_object(Path(readiness_path_text))
        if error:
            readiness_errors.append(error)
        elif record is not None:
            readiness.append(record)

    verdict = classify_attempt(
        log_text,
        evidence,
        args.attempt,
        profile=args.profile,
        readiness=readiness,
        evidence_error=evidence_error,
        readiness_errors=readiness_errors,
        business_started=(Path(args.business_started).is_file() if args.business_started else None),
    )
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(verdict, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(verdict, sort_keys=True))
    return 0 if verdict["retryable"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
