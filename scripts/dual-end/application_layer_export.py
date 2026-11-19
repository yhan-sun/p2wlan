"""Export observations from original completed TCP probes and retained snapshots.

No network request, process restart, extra snapshot or business acceptance credit.
"""
from pathlib import Path
import hashlib
import json

import application_layer_report as layers
import udp_business_summary as udp
from udp_business_probe import write_report


def retained_captures(kernel_captures, entry):
    if kernel_captures is None:
        return [], []
    records = [r for r in kernel_captures.entries if r["entry"] is entry]
    if len(records) != 1:
        raise ValueError("original_capture_record_missing_or_duplicate")
    endpoints = records[0]["endpoints"]
    if endpoints is not None and len(endpoints) != 2:
        raise ValueError("original_capture_endpoint_capacity")
    captures, digests = [], []
    for endpoint in endpoints or ():
        if endpoint.raw_snapshots:
            raw = endpoint.raw_snapshots[-1]
            if len(raw) > layers.MAX_BYTES:
                raise ValueError("original_snapshot_capacity")
            captures.append(json.loads(raw))
            digests.append(hashlib.sha256(raw).hexdigest())
    return captures, digests


def mixed_queues(output, entries, kernel_captures):
    if len(entries) != 2 or {e["direction"] for e in entries} != {"a-to-b", "b-to-a"}:
        raise ValueError("mixed_load_requires_two_directions")
    flows = []
    for entry in entries:
        if entry["protocol"] != "udp":
            raise ValueError("mixed_load_requires_udp_requests")
        probe, artifact = layers.read_input(output / ("udp-" + entry["direction"] + "-probe.json"))
        udp.validate_report(probe)
        if (artifact["sha256"] != entry["report_sha256"] or not probe.get("request_plan", {}).get("producer_scope")
                or (probe["run_nonce"], probe["round_nonce"]) != (entry["run_nonce"], entry["round_nonce"])
                or len(probe["requests"]) != entry["count"]):
            raise ValueError("original_udp_probe_identity_changed")
        captures, digests = retained_captures(kernel_captures, entry)
        joined = layers.queue_rows(captures, probe, probe["requests"], protocol="udp")
        covered = sum(len({p["kind"] for p in row}) for row in joined.values())
        flows.append(dict(direction=entry["direction"], expected_request_response_legs=2 * entry["count"],
                          legs_with_retained_packet=covered, duplicate_responses_observed=probe["receive_counts"]["duplicate"],
                          original_snapshot_sha256=digests, requests=[
                              dict(sequence=i, request_nonce=probe["requests"][i]["request_nonce"], packets=packets)
                              for i, packets in joined.items()]))
    return dict(scope="original_UDP_request_packet_process_local_intervals", flows=flows,
                extra_snapshot_requests=0, packet_intervals_summed=False, business_outcomes_reclassified=False)


def export(output, entries, kernel_captures=None):
    if len(entries) > 32:
        raise ValueError("original_manifest_capacity")
    rows = []
    for entry in entries:
        if entry["protocol"] != "tcp":
            continue
        if entry["direction"] not in ("a-to-b", "b-to-a"):
            raise ValueError("original_direction_invalid")
        stem = "tcp-" + entry["direction"]
        if "phase" in entry:
            if entry["phase"] not in ("baseline", "blackhole", "recovery", "pause", "fresh"):
                raise ValueError("original_phase_invalid")
            stem += "-" + entry["phase"]
        inputs = []
        for role in ("probe", "echo"):
            inputs.append(layers.read_input(output / (stem + "-" + role + ".json")))
        captures, digests = retained_captures(kernel_captures, entry)
        report = layers.combine(inputs[0][0], inputs[1][0], captures)
        report["input_files"] = [v[1] for v in inputs]
        report["original_daemon_snapshot_sha256"] = digests
        target = output / (stem + "-layers.json")
        write_report(target, report)
        complete = sum(bool(row["daemon_queue_observations"]) and all(
            p["intervals"]["availability"] == "available" and all(
                p["intervals"][key]["availability"] == "available"
                for key in ("dataplane_queue", "network_outbound_queue"))
            for p in row["daemon_queue_observations"])
            for row in report["requests"])
        rows.append(dict(file=target.name, sha256=hashlib.sha256(target.read_bytes()).hexdigest(),
                         fixed_denominator=report["fixed_denominator"],
                         same_request_both_channel_intervals_available=complete,
                         no_native_or_current_owner_credit=True))
    return dict(scope="original_TCP_request_layer_observations_only", reports=rows,
                extra_daemon_snapshot_requests=0, packet_intervals_summed=False,
                business_outcomes_reclassified=False)
