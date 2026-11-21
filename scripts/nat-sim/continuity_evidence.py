"""Same-host monotonic observations of sustained business and exercised faults."""

from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import re

from network_conditions import load_profiles
from monotonic_clock import monotonic_ns


def sample(round_dir: Path) -> None:
    # Timestamp before reading: a post-fault baseline includes all earlier
    # business. Only subsequent counter growth proves post-fault traffic.
    row = {"monotonic_ns": monotonic_ns(), "direct": {}}
    for side in ("a", "b"):
        text = (round_dir / f"node-{side}.log").read_text(errors="replace")
        row[side] = text.count("overlay_payload_verified")
        row["direct"][side] = sum("overlay_payload_verified" in line
            and bool(re.search(r"\bingress=direct(?:\s|$)", line)) for line in text.splitlines())
    # A pre-fault proof must have finished reading before the fault, while a
    # post-fault baseline must have started reading after it.
    row["completed_monotonic_ns"] = monotonic_ns()
    with (round_dir / "business-samples.jsonl").open("a") as stream:
        stream.write(json.dumps(row) + "\n")


def summarize(round_dir: Path, profile_path=None, require_direct_before_fault=False) -> dict:
    errors = []
    profiles = load_profiles(profile_path)
    counts = {side: Counter() for side in ("A", "B")}
    delays = {side: set() for side in ("A", "B")}
    rebound_at = {}
    remapped = set()
    last_boundary = 0
    first_disruption = None
    try:
        for line in (round_dir / "nat-trace.jsonl").read_text().splitlines():
            row = json.loads(line)
            nat, event = row.get("nat"), row.get("event")
            if nat not in counts:
                continue
            counts[nat][event] += 1
            if event == "mapping_retired":
                counts[nat]["mapping_retired:" + str(row.get("reason"))] += 1
            if event in {"packet_delayed", "packet_conditioned"}:
                value = row.get("delay_ms")
                if type(value) in (int, float):
                    delays[nat].add(value)
            if event in {"network_rebound", "network_outage_started", "network_outage_ended"}:
                boundary = row["monotonic_ns"]
                if type(boundary) is not int or boundary <= 0:
                    raise ValueError("invalid_boundary_clock")
                if event != "network_outage_ended":
                    first_disruption = min(first_disruption or boundary, boundary)
                if event != "network_outage_started":
                    last_boundary = max(last_boundary, boundary)
                if event == "network_rebound":
                    rebound_at[nat] = boundary
                    if row.get("retired_mappings", 0) <= 0:
                        errors.append(f"{nat}:empty_rebind")
            if event == "mapping_created" and row["monotonic_ns"] > rebound_at.get(nat, 2**63):
                remapped.add(nat)
        samples = [json.loads(line) for line in (round_dir / "business-samples.jsonl").read_text().splitlines()]
        if not 2 <= len(samples) <= 1000:
            raise ValueError("invalid_sample_count")
        previous = None
        for row in samples:
            if any(type(row.get(key)) is not int or row[key] < 0 for key in ("monotonic_ns", "a", "b")):
                raise ValueError("invalid_business_sample")
            if require_direct_before_fault or "direct" in row:
                direct = row.get("direct")
                completed = row.get("completed_monotonic_ns")
                if (type(completed) is not int or completed < row["monotonic_ns"]
                        or not isinstance(direct, dict)
                        or any(type(direct.get(s)) is not int or not 0 <= direct[s] <= row[s] for s in ("a", "b"))):
                    raise ValueError("invalid_direct_business_sample")
            if previous and (row["monotonic_ns"] <= previous["monotonic_ns"]
                             or any(row[s] < previous[s] for s in ("a", "b"))):
                raise ValueError("nonmonotonic_business_sample")
            if previous and "direct" in row and "direct" in previous:
                if (row["monotonic_ns"] < previous["completed_monotonic_ns"]
                        or any(row["direct"][s] < previous["direct"][s] for s in ("a", "b"))):
                    raise ValueError("nonmonotonic_direct_business_sample")
            previous = row
    except (OSError, ValueError, KeyError, TypeError) as error:
        return {"schema_version": 1, "valid": False, "errors": [str(error)], "fault_events": counts}

    for nat, profile in profiles.items():
        expected = []
        if profile.loss_rate:
            expected.append("packet_dropped_loss")
        if profile.burst_loss_rate:
            expected.append("packet_dropped_burst")
        if profile.outage_after_ms:
            expected += ["network_outage_started", "network_outage_ended", "packet_dropped_outage"]
        if profile.rebind_after_ms:
            expected.append("network_rebound")
            if nat not in remapped:
                errors.append(f"{nat}:post_rebind_mapping_missing")
        if profile.mapping_idle_ms:
            expected.append("mapping_retired:idle_timeout")
        for event in expected:
            if counts[nat][event] == 0:
                errors.append(f"{nat}:fault_not_exercised:{event}")
        if profile.jitter_ms and len(delays[nat]) < 2:
            errors.append(f"{nat}:jitter_not_exercised")
        if profile.rate_kbps and not any(value > 0 for value in delays[nat]):
            errors.append(f"{nat}:serialization_not_exercised")
        if counts[nat]["network_packet_task_failed"]:
            errors.append(f"{nat}:network_packet_task_failed")

    final = samples[-1]
    # Observe at least two seconds in the final five-second window. Historic
    # success alone cannot pass after a transport silently stops delivering.
    recent = [row for row in samples
              if final["monotonic_ns"] - 5_000_000_000 <= row["monotonic_ns"]
              <= final["monotonic_ns"] - 2_000_000_000]
    base = recent[0] if recent else None
    progress = {side: final[side] - base[side] if base else None for side in ("a", "b")}
    if base is None or any(value < 2 for value in progress.values()):
        errors.append("recent_bidirectional_business_stalled")
    post_fault = [row for row in samples if row["monotonic_ns"] >= last_boundary + 200_000_000]
    recovered = not last_boundary or (len(post_fault) >= 2
        and post_fault[-1]["monotonic_ns"] - post_fault[0]["monotonic_ns"] >= 2_000_000_000
        and all(post_fault[-1][side] - post_fault[0][side] >= 2 for side in ("a", "b")))
    if not recovered:
        errors.append("post_fault_bidirectional_business_missing")
    direct_before_fault = None
    if require_direct_before_fault:
        direct_before_fault = bool(first_disruption and any(
            row["completed_monotonic_ns"] <= first_disruption - 200_000_000
            and all(row["direct"][side] >= 2 for side in ("a", "b")) for row in samples))
        if not direct_before_fault:
            errors.append("direct_business_before_fault_missing")
    return {"schema_version": 1, "scope": "same_host_monotonic_business_progress_not_direct_success",
            "valid": not errors, "errors": sorted(set(errors)), "samples": len(samples),
            "recent_business_delta": progress, "post_fault_recovered": recovered,
            "direct_before_fault": direct_before_fault,
            "first_disruption_ns": first_disruption,
            "last_fault_boundary_ns": last_boundary or None,
            "fault_events": counts, "observed_delay_values": {nat: sorted(values) for nat, values in delays.items()}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("sample", "verify"))
    parser.add_argument("round_dir", type=Path)
    parser.add_argument("--network-profile", type=Path)
    parser.add_argument("--require-direct-before-fault", action="store_true")
    args = parser.parse_args()
    if args.mode == "sample":
        sample(args.round_dir)
        return 0
    result = summarize(args.round_dir, args.network_profile, args.require_direct_before_fault)
    (args.round_dir / "continuity-evidence.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"continuity_valid": result["valid"], "errors": result["errors"]}))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
