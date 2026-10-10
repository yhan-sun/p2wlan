#!/usr/bin/env python3
"""Validate and summarize bounded OS UDP probe reports without path inference.

Only probe reports contribute requests. Echo-side counters, active-path
snapshots, control validation request IDs, and cross-host clocks cannot create
a successful request. Repeated artifacts and mixed runs are rejected.
"""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import sys

from udp_business_probe import (
    Config, MAX_RX_DATAGRAMS, NS_PER_MS, RECEIVE_REASONS,
    SCHEMA_VERSION, SCOPE, UNVERIFIED, bounded_int, nonce_bytes, validate_output_path, write_report,
)


MAX_REPORT_BYTES = 1024 * 1024
MAX_REPORTS = 64
STATUSES = ("success", "timeout", "send_error", "not_sent", "cancelled")
TERMINATIONS = (
    "completed", "duration_deadline", "receive_budget_exhausted", "interrupted",
    "bind_failed", "udp_receive_failed",
)


def no_duplicate_keys(pairs: list[tuple]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def reject_constant(value: str) -> None:
    raise ValueError(f"nonfinite JSON number: {value}")


def read_report(path: Path) -> tuple[dict, str]:
    with path.open("rb") as stream:
        raw = stream.read(MAX_REPORT_BYTES + 1)
    if len(raw) > MAX_REPORT_BYTES:
        raise ValueError("probe report exceeds 1 MiB")
    value = json.loads(raw, object_pairs_hook=no_duplicate_keys, parse_constant=reject_constant)
    if not isinstance(value, dict):
        raise ValueError("probe report must be a JSON object")
    return value, hashlib.sha256(raw).hexdigest()


def validate_report(report: dict) -> Config:
    if (type(report.get("schema_version")) is not int or report["schema_version"] != SCHEMA_VERSION
            or report.get("scope") != SCOPE
            or report.get("role") != "probe" or report.get("clock") != "probe_process_monotonic_ns"):
        raise ValueError("unsupported probe schema, scope, role, or clock")
    if report.get("evidence") != UNVERIFIED:
        raise ValueError("OS UDP reports cannot claim TUN, Direct, or connection-start verification")
    tool_sha = report.get("tool_sha256")
    if not isinstance(tool_sha, str) or len(tool_sha) != 64 or any(
        character not in "0123456789abcdef" for character in tool_sha
    ):
        raise ValueError("tool SHA-256 missing")
    if report.get("termination_reason") not in TERMINATIONS:
        raise ValueError("unknown termination reason")
    config_data = report.get("configuration")
    if not isinstance(config_data, dict):
        raise ValueError("configuration missing")
    try:
        config = Config(
            (config_data["bind_ip"], config_data["bind_port"]),
            (config_data["target_ip"], config_data["target_port"]),
            report["run_nonce"], report["round_nonce"], config_data["count"],
            config_data["interval_ms"], config_data["timeout_ms"],
            config_data["duration_ms"], config_data["payload_bytes"],
        )
        config.validate()
    except (KeyError, TypeError) as error:
        raise ValueError("incomplete configuration") from error
    elapsed = report.get("elapsed_ns")
    bounded_int(elapsed, 0, 24 * 3600 * 1_000_000_000, "elapsed_ns")
    records = report.get("requests")
    if not isinstance(records, list) or len(records) != config.count:
        raise ValueError("all prescheduled requests must be retained")
    counts = report.get("receive_counts")
    if not isinstance(counts, dict) or set(counts) != set(RECEIVE_REASONS):
        raise ValueError("receive counters missing")
    for value in counts.values():
        bounded_int(value, 0, MAX_RX_DATAGRAMS, "receive_count")
    if type(report.get("received_datagrams")) is not int or sum(counts.values()) != report["received_datagrams"]:
        raise ValueError("receive counter total mismatch")
    bounded_int(report["received_datagrams"], 0, MAX_RX_DATAGRAMS, "received_datagrams")
    nonces = set()
    success_count = 0
    for sequence, record in enumerate(records):
        if not isinstance(record, dict) or type(record.get("sequence")) is not int or record["sequence"] != sequence:
            raise ValueError("request sequence missing, duplicated, or reordered")
        nonce_bytes(record.get("request_nonce"))
        if record["request_nonce"] in nonces:
            raise ValueError("duplicate request nonce")
        nonces.add(record["request_nonce"])
        planned = record.get("planned_offset_ns")
        if type(planned) is not int or planned != sequence * config.interval_ms * NS_PER_MS:
            raise ValueError("prescheduled request offset mismatch")
        completed = record.get("completed_offset_ns")
        bounded_int(completed, 0, elapsed, "completed_offset_ns")
        status, sent, rtt = record.get("status"), record.get("sent_offset_ns"), record.get("rtt_ns")
        if status not in STATUSES:
            raise ValueError("request has no terminal outcome")
        if status == "not_sent":
            if sent is not None:
                raise ValueError("not_sent request has send timestamp")
        else:
            bounded_int(sent, planned, completed, "sent_offset_ns")
            if sent >= config.duration_ms * NS_PER_MS:
                raise ValueError("request sent beyond duration deadline")
        if status == "success":
            bounded_int(rtt, 0, config.timeout_ms * NS_PER_MS - 1, "rtt_ns")
            if (completed - sent != rtt or completed >= config.duration_ms * NS_PER_MS
                    or record.get("reason") != "matched_echo"):
                raise ValueError("success is outside its matching echo deadline")
            success_count += 1
        elif rtt is not None:
            raise ValueError("failed requests cannot contribute RTT samples")
        if status == "timeout" and (
            completed - sent < config.timeout_ms * NS_PER_MS or record.get("reason") != "response_deadline"
        ):
            raise ValueError("timeout recorded before response deadline")
        if status == "send_error" and record.get("reason") != "udp_send_failed":
            raise ValueError("invalid send error reason")
        if status in ("not_sent", "cancelled") and (
            report["termination_reason"] == "completed" or record.get("reason") != report["termination_reason"]
        ):
            raise ValueError("unfinished request lacks bounded run failure reason")
    if success_count != counts["accepted"]:
        raise ValueError("successful requests do not match accepted responses")
    return config


def rtt_statistics(records: list[dict]) -> dict:
    samples = sorted(record["rtt_ns"] for record in records if record["status"] == "success")

    def percentile(fraction: float) -> float | None:
        return samples[max(0, math.ceil(len(samples) * fraction) - 1)] / NS_PER_MS if samples else None

    return {
        "sample_count": len(samples), "conditional_on_success": True,
        "method": "nearest_rank", "unit": "ms", "p50": percentile(0.50),
        "p95": percentile(0.95), "min": samples[0] / NS_PER_MS if samples else None,
        "max": samples[-1] / NS_PER_MS if samples else None,
    }


def summarize(reports: list[dict]) -> dict:
    bounded_int(len(reports), 1, MAX_REPORTS, "report_count")
    all_records, directions, identities = [], [], set()
    run_nonce = None
    for report in reports:
        config = validate_report(report)
        if run_nonce is not None and run_nonce != config.run_nonce:
            raise ValueError("cannot mix independent run nonces")
        run_nonce = config.run_nonce
        identity = (config.round_nonce, config.bind, config.target)
        if identity in identities:
            raise ValueError("duplicate round/direction report")
        identities.add(identity)
        records = report["requests"]
        all_records.extend(records)
        counts = Counter(record["status"] for record in records)
        directions.append({
            "round_nonce": config.round_nonce, "bind": list(config.bind), "target": list(config.target),
            "prescheduled_requests": config.count, "success_requests": counts["success"],
            "status_counts": {status: counts[status] for status in STATUSES},
            "rtt": rtt_statistics(records), "termination_reason": report["termination_reason"],
        })
    counts = Counter(record["status"] for record in all_records)
    return {
        "schema_version": SCHEMA_VERSION, "scope": SCOPE, "run_nonce": run_nonce,
        "evidence": dict(UNVERIFIED), "report_count": len(reports),
        "round_set_completeness": None, "round_set_reason": "no_prescheduled_round_manifest",
        "denominator": "all_prescheduled_requests_including_failures_and_timeouts",
        "prescheduled_requests": len(all_records), "success_requests": counts["success"],
        "success_fraction": counts["success"] / len(all_records),
        "status_counts": {status: counts[status] for status in STATUSES},
        "rtt": rtt_statistics(all_records), "directions": directions,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reports", nargs="+", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        bounded_int(len(args.reports), 1, MAX_REPORTS, "report_count")
        validate_output_path(args.output)
        loaded = [read_report(path) for path in args.reports]
        summary = summarize([report for report, _digest in loaded])
        summary["input_sha256"] = [digest for _report, digest in loaded]
        write_report(args.output, summary)
    except (OSError, ValueError, TypeError) as error:
        print(f"udp-business-summary: {error}", file=sys.stderr)
        return 2
    print(json.dumps({"scope": SCOPE, "prescheduled_requests": summary["prescheduled_requests"],
                      "success_requests": summary["success_requests"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
