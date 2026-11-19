"""Join original same-boot application deadlines and per-frame path receipts."""
from collections import Counter
import math

DIRECTIONS = ("a-to-b", "b-to-a")
MS = 1_000_000


def summarize(clock, entries):
    start = clock.get("join_requested_ns")
    first, direct, paths, statuses, families = {}, {}, Counter(), Counter(), Counter()
    samples, attempts = [], 0
    for entry in entries:
        direction = entry["direction"]
        if entry["protocol"] != "udp":
            continue
        attempts += entry["count"]
        records = entry.get("records") or []
        statuses["not_observed"] += entry["count"] - len(records)
        writes = entry.get("original_write_stream") or {}
        same_boot = (bool(clock.get("boot_id")) and writes.get("original_same_boot_clock_matched") is True and
                     (writes.get("original_child_binding") or {}).get("boot_id") == clock.get("boot_id"))
        native = entry.get("original_kernel_reads") or {}
        def by_id(rows):
            indexed = {(r["sequence"], r["request_nonce"]): r for r in rows}
            if len(indexed) != len(rows):
                raise ValueError("duplicate_original_request_record")
            return indexed
        w = by_id(writes.get("requests", []))
        n = by_id(native.get("requests", []))
        for row in records:
            statuses[row["status"]] += 1
            if row["status"] != "success":
                continue
            samples.append(row["rtt_ns"] / MS)
            key = row["sequence"], row["request_nonce"]
            write = w.get(key, {})
            sent = write.get("original_sent_ns")
            if (not same_boot or type(start) is not int or type(sent) is not int or
                    not write.get("accepted_in_original_deadline") or sent < start):
                continue
            done = sent + row["completed_offset_ns"] - row["sent_offset_ns"]
            if not sent <= done <= write["original_deadline_ns"]:
                continue
            elapsed = (done - start) / MS
            first[direction] = min(first.get(direction, elapsed), elapsed)
            receipt = n.get(key, {})
            legs = [receipt.get(k, {}) for k in ("source_native_transaction", "response_native_transaction")]
            if (receipt.get("full128_owner_qualified") is not True or
                    any(leg.get("matched") is not True or leg.get("physical_path") not in ("udp", "relay")
                        or type(leg.get("commit_monotonic_ns")) is not int
                        or not sent <= leg["commit_monotonic_ns"] <= write["original_deadline_ns"] for leg in legs)):
                paths["missing_native_evidence"] += 1
                continue
            mode = tuple(leg.get("physical_path") for leg in legs)
            paths["/".join(mode)] += 1
            if mode == ("udp", "udp"):
                family_pair = [leg.get("udp_destination_family", "unknown") for leg in legs]
                families["/".join(family_pair)] += 1
                proven = (max(done, *(leg["commit_monotonic_ns"] for leg in legs)) - start) / MS
                direct[direction] = min(direct.get(direction, proven), proven)
    both = max(first.values()) if len(first) == len(DIRECTIONS) else None
    direct_both = max(direct.values()) if len(direct) == len(DIRECTIONS) else None
    samples.sort()
    return dict(clock_scope="same_linux_boot_from_original_room_join_request",
                sampling="two_serial_prescheduled_udp_batches_after_tun_routes_exist",
                preplanned_requests=attempts, terminal_counts=dict(statuses),
                first_success_ms_by_direction=first, first_bidirectional_observed_ms=both,
                bidirectional_observed_by_5s=None if both is None else both <= 5000,
                first_native_direct_ms_by_direction=direct,
                bidirectional_native_direct_observed_by_10s=None if direct_both is None else direct_both <= 10000,
                native_request_response_paths=dict(paths), native_direct_request_response_families=dict(families),
                successful_rtt_samples=len(samples),
                success_rtt_p99_ms=samples[math.ceil(len(samples)*.99)-1] if samples else None)
