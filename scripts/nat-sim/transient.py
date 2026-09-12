#!/usr/bin/env python3
"""Classify a failed NAT topology attempt as retryable or hard.

A bounded retry exists so a single noisy CI sample of a timing-sensitive
topology does not fail a required gate, while every real protocol or
acceptance regression still fails immediately.  The classifier therefore
DENIES retry by default: only a narrow, whitelisted set of signatures —
startup readiness races and data-plane stalls with a fully healthy control
plane — is retryable.

The retry never skips or fabricates a pass: the follow-up attempt must run
the full strict gate and produce its own genuine PASS evidence.  A real
regression fails both attempts and the job still fails.

Test-harness infrastructure only.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


MAX_RETRYABLE_ATTEMPT = 1

# Evidence decision reason codes that always indicate a hard failure.  They
# correspond to parser loss, identity fences, or protocol violations that a
# fresh attempt on a quiet runner cannot legitimately cure.
#
# `diagnostics_revision_not_converged` is deliberately NOT hard: it means the
# FAILED attempt's final status snapshot raced the daemon's revision counter
# (a fail-direction sampling artifact under runner load).  It never relaxes
# the gate — a passing attempt must still satisfy revision convergence, which
# aggregate_evidence.py enforces on every accepted record — so whether to
# retry is decided by the attempt log's health markers instead.
HARD_EVIDENCE_REASONS = {
    "stale_process_identity",
    "evidence_parser_loss",
    "first_usable_path_mismatch",
    "baseline_after_transition_event_retained",
    "no_replay_or_invalid",
    "collector_not_run",
    "evidence_parse_failed",
    "evidence_not_converged",
}

# Substrings whose presence anywhere in the attempt log makes the attempt
# hard-failing regardless of the parsed gate line.
HARD_LOG_MARKERS = (
    "daemon exited unexpectedly",
    "replay detected",
    "overlay_payload_invalid",
    "status_schema_invalid",
    "metrics_schema_invalid",
)

# Structured failure reason codes carried by the ROUND FAIL line that are
# never retryable (SLO and schema misses are strict acceptance criteria).
HARD_LINE_REASONS = {
    "relay_first_slo_exceeded",
    "status_schema_invalid",
    "metrics_schema_invalid",
    "first_usable_delta_missing",
}

# reason_code= values emitted by the startup readiness path that indicate the
# daemon was still starting (or the harness raced it), not a protocol fault.
# `status_auth_token_missing` is the fetch-time signature of the same race; a
# crashed daemon additionally leaves "daemon exited unexpectedly" (or its
# token removed mid-round plus a timeout) which stays a hard marker.
# `blackhole_not_active` is the simulator banner assertion failing — an
# infrastructure failure of this attempt, not a topology verdict.
STARTUP_TRANSIENT_REASONS = {
    "baseline_status_not_available",
    "daemon_not_token_ready",
    "status_auth_token_missing",
    "blackhole_not_active",
}

LINE_FIELD = re.compile(r"([a-z_0-9]+)=([^\s]+)")
ROUND_FAIL = re.compile(r"ROUND (\d+): FAIL")


def _parse_line_fields(line: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for key, value in LINE_FIELD.findall(line):
        fields[key] = value.rstrip(",")
    return fields


def _gate_line(log_text: str) -> str | None:
    """Select the round's FINAL verdict line.

    Relay rounds can emit an early FAIL (missing first-usable delta) before
    the comprehensive relay_first_evidence gate line; the last ROUND FAIL line
    is the authoritative verdict.  Startup failures have no ROUND line at all
    and fall back to the readiness reason_code line.
    """
    line = None
    for candidate in log_text.splitlines():
        if ROUND_FAIL.search(candidate):
            line = candidate
    if line is not None:
        return line
    for candidate in log_text.splitlines():
        if "] FAIL reason_code=" in candidate:
            return candidate
    return None


def _int_field(fields: dict[str, str], key: str, default: int | None = None) -> int | None:
    value = fields.get(key)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _control_plane_healthy(fields: dict[str, str]) -> bool:
    """True when every health signal present in the gate line is clean.

    Missing signals (profiles that do not print them) do not count against
    health; a present-but-dirty signal does.
    """
    for key in ("status_always_200_a", "status_always_200_b"):
        value = _int_field(fields, key)
        if value is not None and value != 1:
            return False
    for key in ("task_health_a", "task_health_b", "task_leak_a", "task_leak_b"):
        value = _int_field(fields, key)
        if value is None:
            continue
        if key.startswith("task_leak") and value != 0:
            return False
        if key.startswith("task_health") and value != 1:
            return False
    for key in ("replay_a", "replay_b", "invalid_a", "invalid_b"):
        value = _int_field(fields, key)
        if value is not None and value != 0:
            return False
    return True


def _hard_violation_in_log(log_text: str) -> str | None:
    for marker in HARD_LOG_MARKERS:
        if marker in log_text:
            return marker
    return None


def classify_attempt(
    log_text: str,
    evidence: dict[str, Any] | None = None,
    attempt: int = 1,
) -> dict[str, Any]:
    """Return {retryable, reason, signature} for one failed smoke attempt."""
    signature: dict[str, Any] = {"attempt": attempt}
    if attempt > MAX_RETRYABLE_ATTEMPT:
        return {"retryable": False, "reason": "retry_budget_exhausted", "signature": signature}

    marker = _hard_violation_in_log(log_text)
    if marker is not None:
        signature["hard_marker"] = marker
        return {"retryable": False, "reason": "hard_log_marker", "signature": signature}

    if evidence is not None:
        decision = evidence.get("decision")
        if isinstance(decision, dict):
            reason = decision.get("reason_code")
            signature["evidence_reason"] = reason
            if reason in HARD_EVIDENCE_REASONS:
                return {"retryable": False, "reason": "hard_evidence_reason", "signature": signature}

    line = _gate_line(log_text)
    if line is None:
        return {"retryable": False, "reason": "unrecognized_failure", "signature": signature}
    fields = _parse_line_fields(line)
    signature["gate_line"] = line

    reason = fields.get("reason_code")
    if reason in HARD_LINE_REASONS:
        return {"retryable": False, "reason": "hard_line_reason", "signature": signature}

    if reason in STARTUP_TRANSIENT_REASONS:
        signature["startup_reason"] = reason
        return {"retryable": True, "reason": "startup_readiness_race", "signature": signature}

    if not _control_plane_healthy(fields):
        return {"retryable": False, "reason": "control_plane_unhealthy", "signature": signature}

    # Data-plane stall with a fully healthy control plane: the topology never
    # converged (overlay window expired, burst incomplete) or a drop counter
    # observed a stall-induced loss.  A retry must pass the full strict gate.
    overlay_ok = _int_field(fields, "overlay_ok")
    a_direct = _int_field(fields, "a_direct")
    b_direct = _int_field(fields, "b_direct")
    if overlay_ok is not None:
        # Relay/blackhole profile: Direct establishing through the blackhole
        # is a topology violation, not an environment transient.
        if (a_direct is not None and a_direct != 0) or (b_direct is not None and b_direct != 0):
            return {"retryable": False, "reason": "blackhole_violated", "signature": signature}
        if overlay_ok == 0:
            signature["stall_class"] = "overlay_window_expired"
            return {"retryable": True, "reason": "relay_data_plane_stall", "signature": signature}
        burst_bad_a = _int_field(fields, "burst_bad_a", 0) or 0
        burst_bad_b = _int_field(fields, "burst_bad_b", 0) or 0
        if burst_bad_a > 0 or burst_bad_b > 0:
            signature["stall_class"] = "burst_incomplete"
            return {"retryable": True, "reason": "relay_data_plane_stall", "signature": signature}
        return {"retryable": False, "reason": "unrecognized_failure", "signature": signature}

    # Direct cold-start profile: the FAIL line carries a reason_code and
    # per-side counters only.
    if reason == "first_usable_never_observed" or reason == "direct_overlay_unverified":
        signature["stall_class"] = "topology_window_expired"
        return {"retryable": True, "reason": "topology_window_expired", "signature": signature}

    return {"retryable": False, "reason": "unrecognized_failure", "signature": signature}


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    command = parser.add_subparsers(dest="command", required=True)
    classify = command.add_parser("classify", help="classify one failed attempt")
    classify.add_argument("--log", required=True, help="smoke attempt log (tee'd smoke output)")
    classify.add_argument("--evidence", default=None, help="round nat-evidence.json, if produced")
    classify.add_argument("--attempt", type=int, default=1)
    classify.add_argument("--output", default=None, help="optional JSON record path")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    log_text = Path(args.log).read_text(encoding="utf-8", errors="replace")
    evidence: dict[str, Any] | None = None
    if args.evidence and Path(args.evidence).is_file():
        try:
            loaded = json.loads(Path(args.evidence).read_text(encoding="utf-8"))
            evidence = loaded if isinstance(loaded, dict) else None
        except json.JSONDecodeError:
            evidence = None
    verdict = classify_attempt(log_text, evidence, args.attempt)
    if args.output:
        Path(args.output).write_text(json.dumps(verdict, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(verdict, sort_keys=True))
    return 0 if verdict["retryable"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
