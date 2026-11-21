"""Bounded layered evidence; missing source/path facts never become authority."""
from __future__ import annotations

from collections import Counter
import ipaddress

COUNT = 8
ENTRIES = (("udp", "a-to-b"), ("udp", "b-to-a"), ("tcp", "a-to-b"), ("tcp", "b-to-a"))


def manifest(run_nonce: str, round_nonce: str) -> list[dict]:
    return [{"protocol": protocol, "direction": direction, "count": COUNT,
             "run_nonce": run_nonce, "round_nonce": round_nonce,
             "interval_ms": 100, "timeout_ms": 1000, "duration_ms": 10000, "payload_bytes": 128,
             "outcome": "not_started", "records": None} for protocol, direction in ENTRIES]


def identity(status: dict, pid: int, network: str, run_id: str) -> dict:
    timeline = status.get("connection_timeline") or {}
    if status.get("process_id") != pid or status.get("network_id") != network:
        raise ValueError("current endpoint process/network identity mismatch")
    if not timeline.get("correlation_id") or timeline.get("run_id") != run_id or not status.get("node_id"):
        raise ValueError("current endpoint run/instance identity missing")
    vip = str(ipaddress.IPv4Address(status["virtual_ip"]))
    return {"process_id": pid, "network_id": network, "run_id": run_id,
            "correlation_id": timeline["correlation_id"], "node_id": status["node_id"],
            "runtime_incarnation": status.get("runtime_incarnation"), "virtual_ip": vip,
            "identity_scope": "observed_pid_run_correlation_node_vip",
            "native_runtime_owner_generation_verified": None}


def kernel_route(interface: str, vip: str, peer_vip: str, links: list,
                 addresses: list, route: list) -> dict:
    if len(links) != 1 or links[0].get("ifname") != interface:
        raise ValueError("exact TUN link identity missing")
    link = links[0]
    if type(link.get("ifindex")) is not int or link["ifindex"] <= 0 or (
        (link.get("linkinfo") or {}).get("info_kind") != "tun"
    ):
        raise ValueError("observed interface is not a kernel TUN")
    if not any(a.get("ifname") == interface and a.get("ifindex") == link["ifindex"] and
               any(v.get("family") == "inet" and v.get("local") == vip for v in a.get("addr_info", []))
               for a in addresses):
        raise ValueError("assigned VIP not on this exact TUN")
    if len(route) != 1 or route[0].get("dev") != interface or route[0].get("dst") != peer_vip or (
        route[0].get("prefsrc") != vip
    ):
        raise ValueError("peer VIP route bypasses the original TUN/source")
    return {"ifname": interface, "ifindex": link["ifindex"], "kind": "tun", "vip": vip,
            "route_to_peer": {key: route[0][key] for key in ("dst", "dev", "prefsrc")},
            "kernel_route_observed": True}


def attach(entry: dict, report: dict, records: list[dict], bind: tuple, target: tuple,
           expected_tool_sha: str) -> None:
    c = report["configuration"]
    if report["scope"] != "os_" + entry["protocol"] + "_echo" or report["tool_sha256"] != expected_tool_sha:
        raise ValueError("original socket tool/source identity mismatch")
    if (report["run_nonce"], report["round_nonce"], c["count"]) != (
        entry["run_nonce"], entry["round_nonce"], entry["count"]
    ) or (c["bind_ip"], c["bind_port"]) != bind or (c["target_ip"], c["target_port"]) != target:
        raise ValueError("socket report differs from frozen entry")
    if any(c[key] != entry[key] for key in ("interval_ms", "timeout_ms", "duration_ms", "payload_bytes")):
        raise ValueError("socket report changed frozen timing/frame configuration")
    if len(records) != entry["count"]:
        raise ValueError("fixed request denominator changed")
    entry["records"] = records
    entry["outcome"] = "observed"


def summarize(entries: list[dict]) -> dict:
    if [(e["protocol"], e["direction"]) for e in entries] != list(ENTRIES) or any(e["count"] != COUNT for e in entries):
        raise ValueError("original four-entry manifest changed")
    counts = Counter()
    missing = 0
    for entry in entries:
        records = entry["records"]
        if records is None:
            missing += 1
            counts["not_started" if entry["outcome"] == "not_started" else "unknown"] += COUNT
        else:
            if len(records) != COUNT:
                raise ValueError("incomplete original request list")
            counts.update(r["status"] for r in records)
    return {"denominator": "all_32_prescheduled_requests_including_missing_entries",
            "prescheduled_requests": len(ENTRIES) * COUNT,
            "success_requests": counts["success"], "terminal_counts": dict(counts),
            "missing_entry_count": missing, "all_responses_observed": counts["success"] == 32 and missing == 0,
            "canonical_current_owner_verified": None, "exact_direct_request_attribution": None,
            "other_platforms_verified": None, "public_network_verified": None}
