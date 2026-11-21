#!/usr/bin/env python3
"""Validate a frozen MC schedule and offline reports; no game/network is run.

Example: minecraft_interaction_summary.py --manifest /outside/plan.json
  --report /outside/round.json --output /outside/new-summary.json
Omit --report to account for a wholly missing run. Successful validation is
not proof of genuine Minecraft execution, TUN, Direct or performance gains.
"""

from __future__ import annotations

import argparse
from collections import Counter
import math
from pathlib import Path
import sys

from minecraft_interaction import (
    CONTRACT, CONTRACT_SHA256, STATUSES, hex_value, read_json, reduce_round, validate_manifest,
)
from udp_business_probe import validate_output_path, write_report


def distribution(records: list[dict]) -> dict:
    values = sorted(row["rtt_ns"] for row in records if row["status"] == "success")
    return {"unit": "ms", "sample_count": len(values), "conditional_on_success": True,
            "method": "nearest_rank", **{
                name: values[math.ceil(len(values) * fraction) - 1] / 1_000_000 if values else None
                for name, fraction in (("p50", .5), ("p95", .95), ("p99", .99))}}


def summarize(plan: dict, reports: list[dict], manifest_sha256: str) -> dict:
    validate_manifest(plan)
    hex_value(manifest_sha256, 64, "manifest_sha256")
    if not isinstance(reports, list) or len(reports) > len(plan["rounds"]):
        raise ValueError("too many round reports")
    scheduled = {round_["round_nonce"]: round_ for round_ in plan["rounds"]}
    results = {}
    for report in reports:
        if not isinstance(report, dict) or not isinstance(report.get("round_nonce"), str):
            raise ValueError("report round identity absent")
        nonce = report["round_nonce"]
        if nonce not in scheduled or nonce in results:
            raise ValueError("unknown or duplicate round report")
        results[nonce] = reduce_round(plan, scheduled[nonce], report, manifest_sha256)
    rounds, all_records = [], []
    for nonce, round_ in scheduled.items():
        value = results.get(nonce)
        if value is None:
            value = {"round_nonce": nonce, "termination": "missing_evidence", "rejected_events": {},
                     "reported_telemetry": None, "requests": [
                         {**request, "status": "missing_evidence", "reason": "missing_round_report",
                          "started_offset_ns": None, "completed_offset_ns": None, "rtt_ns": None}
                         for request in round_["requests"]]}
        rounds.append(value)
        all_records.extend(value["requests"])
    counts = Counter(row["status"] for row in all_records)
    name = "fixture_latency_ms" if plan["execution_kind"] == "adapter_fixture" else "self_reported_latency_ms"
    return {
        "schema_version": 1, "scope": CONTRACT["scope"], "contract_sha256": CONTRACT_SHA256,
        "manifest_sha256": manifest_sha256, "run_nonce": plan["run_nonce"],
        "execution_kind": plan["execution_kind"], "edition": plan["edition"],
        "transport": plan["transport"], "variant": plan["variant"], "identity": plan["identity"],
        "validation": CONTRACT["provenance"], "denominator": CONTRACT["denominator"],
        "prescheduled_requests": len(all_records), "reported_successes": counts["success"],
        "reported_success_fraction": counts["success"] / len(all_records),
        "status_counts": {status: counts[status] for status in (*STATUSES, "missing_evidence")},
        "missing_rounds": len(scheduled) - len(results), "all_round_reports_present": len(results) == len(scheduled),
        "all_reported_actions_succeeded": counts["success"] == len(all_records),
        name: distribution(all_records), "application_interaction_ms": None,
        "application_interaction_unavailable_reason": "offline_input_cannot_authenticate_game_execution",
        "not_proven": CONTRACT["not_proven"], "rounds": rounds,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--report", action="append", default=[], type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        validate_output_path(args.output)
        plan, plan_sha = read_json(args.manifest)
        validate_manifest(plan)
        if len(args.report) > len(plan["rounds"]):
            raise ValueError("too many input reports")
        loaded = [read_json(path) for path in args.report]
        result = summarize(plan, [value for value, _ in loaded], plan_sha)
        result["report_sha256"] = [digest for _, digest in loaded]
        write_report(args.output, result)
    except (OSError, ValueError, TypeError, RecursionError) as error:
        print(f"minecraft-interaction-summary: {error}", file=sys.stderr)
        return 2
    print(f"offline structure validated; {result['prescheduled_requests']} scheduled actions; "
          "Minecraft execution remains unverified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
