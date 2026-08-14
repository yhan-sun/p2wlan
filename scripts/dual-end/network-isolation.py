#!/usr/bin/env python3
"""Real-time network isolation proof and per-round device cleanup for the
Mini/Air dual-end harness.

The production control plane keeps historical device rows (they expire from
the online lease after DeviceOnlineTTL seconds), so "isolation" is proven on
the LIVE roster: the set of devices the server currently reports online must
be exactly the two run-scoped test nodes, and after teardown it must be empty
again. Any third-party active node, any registration failure of the harness's
own nodes, or any cleanup leak fails the proof and the caller aborts.

Every failure reason is a distinct string so the harness can classify
isolation-invalid infrastructure problems separately from product failures.
"""

from __future__ import print_function

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


def _open(request, timeout_s):
    """Open control-plane HTTP directly unless proxy use is explicit.

    A desktop shell may export an application proxy for browsers.  Letting
    urllib inherit it can make control-plane DELETE/GET requests observe a
    proxy-generated 502 while the daemon's UDP path uses the host network.
    That produces a false roster/cleanup failure and, worse, mismatched
    endpoint diagnostics.  Operators who intentionally need a proxy must opt
    in with P2WLAN_CONTROL_PROXY=environment and test that path separately.
    """
    if os.environ.get("P2WLAN_CONTROL_PROXY", "direct").lower() == "environment":
        return urllib.request.urlopen(request, timeout=timeout_s)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    return opener.open(request, timeout=timeout_s)


def list_nodes(control_url, token, network_id, timeout_s=8):
    """GET /api/v1/nodes?network_id=... with the round account token."""
    url = "%s/api/v1/nodes?network_id=%s" % (control_url, urllib.parse.quote(network_id))
    request = urllib.request.Request(url, headers={"Authorization": "Bearer %s" % token})
    with _open(request, timeout_s) as response:
        body = json.load(response)
    return body.get("nodes", [])


def active_node_ids(nodes):
    """Device IDs the server currently reports within the online lease."""
    # A fully clean network can surface `nodes: null` (not just `[]`) from the
    # control plane; treat it as empty so cleanup proofs and roster checks
    # never crash on an empty network.
    nodes = nodes or []
    return {
        node.get("id")
        for node in nodes
        if node.get("online") is True and (node.get("last_seen") or 0) > 0
    }


def prove_isolation(control_url, token, network_id, expected_ids, deadline_s=20, poll_s=0.5):
    """Poll until the active roster is exactly `expected_ids`.

    Fails fast the moment a third-party active device appears; a harness node
    that has not registered yet is a transient condition and is retried until
    the deadline.  Returns a report dict; `ok` decides the harness gate.
    """
    expected = set(expected_ids)
    if len(expected) != 2:
        return {
            "ok": False,
            "reason": "expected_exactly_two_nodes",
            "expected_ids": sorted(expected),
        }
    deadline = time.time() + deadline_s
    last_error = None
    probes = []
    while time.time() < deadline:
        try:
            nodes = list_nodes(control_url, token, network_id)
        except (urllib.error.HTTPError, urllib.error.URLError, OSError, ValueError) as exc:
            last_error = {"reason": "nodes_list_failed", "detail": str(exc)}
            time.sleep(poll_s)
            continue
        active = active_node_ids(nodes)
        probes.append({
            "device_rows": len(nodes),
            "active_ids": sorted(active),
            "missing": sorted(expected - active),
            "extra": sorted(active - expected),
        })
        if active == expected:
            return {
                "ok": True,
                "reason": "isolated_exactly_two_active_nodes",
                "active_ids": sorted(active),
                "device_rows": len(nodes),
                "inert_historical_rows": len(nodes) - len(active),
                "probes": probes,
            }
        if active - expected:
            return {
                "ok": False,
                "reason": "third_party_active_node",
                "active_ids": sorted(active),
                "expected_ids": sorted(expected),
                "device_rows": len(nodes),
                "probes": probes,
            }
        last_error = {"reason": "active_roster_not_converged", "active": sorted(active), "expected": sorted(expected)}
        time.sleep(poll_s)
    return {
        "ok": False,
        "reason": (last_error or {"reason": "isolation_deadline"})["reason"],
        "detail": last_error.get("detail") if last_error else None,
        "expected_ids": sorted(expected),
        "probes": probes[-8:],
    }


def prove_target_nodes(control_url, token, network_id, expected_ids, deadline_s=20, poll_s=0.5):
    """Prove target nodes are online without claiming network isolation.

    This is an explicitly opt-in diagnostic for shared staging. It records
    every unrelated active device and never deletes or ignores those devices,
    so its result cannot be mistaken for a strict isolated acceptance.
    """
    expected = set(expected_ids)
    if len(expected) != 2:
        return {
            "ok": False,
            "reason": "expected_exactly_two_nodes",
            "expected_ids": sorted(expected),
        }
    deadline = time.time() + deadline_s
    last_error = None
    probes = []
    while time.time() < deadline:
        try:
            nodes = list_nodes(control_url, token, network_id)
        except (urllib.error.HTTPError, urllib.error.URLError, OSError, ValueError) as exc:
            last_error = {"reason": "nodes_list_failed", "detail": str(exc)}
            time.sleep(poll_s)
            continue
        active = active_node_ids(nodes)
        probes.append({
            "device_rows": len(nodes),
            "active_ids": sorted(active),
            "missing": sorted(expected - active),
            "third_party_active": sorted(active - expected),
        })
        if expected <= active:
            return {
                "ok": True,
                "reason": "target_nodes_online_shared_network",
                "active_ids": sorted(active),
                "expected_ids": sorted(expected),
                "third_party_active": sorted(active - expected),
                "device_rows": len(nodes),
                "inert_historical_rows": len(nodes) - len(active),
                "probes": probes,
            }
        last_error = {
            "reason": "target_roster_not_converged",
            "active": sorted(active),
            "expected": sorted(expected),
        }
        time.sleep(poll_s)
    return {
        "ok": False,
        "reason": (last_error or {"reason": "target_roster_deadline"})["reason"],
        "detail": last_error.get("detail") if last_error else None,
        "expected_ids": sorted(expected),
        "probes": probes[-8:],
    }


def delete_device(control_url, token, device_id, timeout_s=8):
    """DELETE /api/v1/devices/{id} with the round account token.

    Returns (ok, status, body).  A 404 is treated as success: the device was
    already removed, which is exactly the state the cleanup wants.
    """
    url = "%s/api/v1/devices/%s" % (control_url, urllib.parse.quote(device_id))
    request = urllib.request.Request(url, headers={
        "Authorization": "Bearer %s" % token,
    }, method="DELETE")
    try:
        with _open(request, timeout_s) as response:
            return True, response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return True, exc.code, exc.read().decode("utf-8", "replace")
        return False, exc.code, exc.read().decode("utf-8", "replace")
    except urllib.error.URLError as exc:
        return False, 0, "url_error: %s" % exc


def delete_devices_by_name(control_url, token, network_id, device_names, timeout_s=8):
    """Delete every active device in the network whose name matches.

    The harness names its nodes with a run-scoped unique prefix, so cleanup
    can run even on failure paths where the diagnostics node IDs were never
    resolved.  Returns (ok, deleted_ids, report) where report is a list of
    per-name outcomes.
    """
    report = []
    deleted = []
    try:
        nodes = list_nodes(control_url, token, network_id)
    except (urllib.error.HTTPError, urllib.error.URLError, OSError, ValueError) as exc:
        return False, [], [{"reason": "nodes_list_failed", "detail": str(exc)}]
    names = set(device_names)
    matched = [node for node in nodes if node.get("device_name") in names]
    ok = True
    for node in matched:
        name = node.get("device_name")
        device_id = node.get("id")
        delete_ok, status, body = delete_device(control_url, token, device_id, timeout_s)
        if not delete_ok:
            ok = False
        report.append({
            "device_name": name,
            "device_id": device_id,
            "delete_ok": delete_ok,
            "status": status,
            "body": body[:200],
        })
        if delete_ok:
            deleted.append(device_id)
    missing = names - {node.get("device_name") for node in matched}
    for name in sorted(missing):
        report.append({"device_name": name, "device_id": None, "delete_ok": True,
                       "status": 0, "body": "no matching device row"})
    return ok, deleted, report



def prove_cleaned(control_url, token, network_id, deleted_ids, deadline_s=10, poll_s=0.5,
                  reject_third_party=True):
    """After deleting this round's devices, prove they are no longer active.

    Strict mode also requires the whole network to be empty.  Availability
    runs on a shared staging network may set ``reject_third_party=False``:
    unrelated live devices are recorded in the report but are not deleted or
    allowed to invalidate a target-scoped relay/overlay result.
    """
    expected_gone = set(deleted_ids)
    deadline = time.time() + deadline_s
    last_error = None
    probes = []
    while time.time() < deadline:
        try:
            nodes = list_nodes(control_url, token, network_id)
        except (urllib.error.HTTPError, urllib.error.URLError, OSError, ValueError) as exc:
            last_error = {"reason": "nodes_list_failed", "detail": str(exc)}
            time.sleep(poll_s)
            continue
        active = active_node_ids(nodes)
        # A fully clean network can surface `nodes: null` from the control
        # plane; normalize before `len` (and `active_node_ids` already
        # normalizes its own iteration).
        nodes = nodes or []
        remaining = active & expected_gone
        probes.append({
            "device_rows": len(nodes),
            "active_ids": sorted(active),
            "deleted_but_still_active": sorted(remaining),
            "third_party_active": sorted(active - expected_gone),
        })
        if reject_third_party and active - expected_gone:
            return {
                "ok": False,
                "reason": "third_party_active_during_cleanup",
                "active_ids": sorted(active),
                "expected_gone": sorted(expected_gone),
                "probes": probes,
            }
        if not remaining:
            return {
                "ok": True,
                "reason": ("network_clean_no_active_nodes"
                           if not active else "deleted_nodes_inactive_third_party_recorded"),
                "active_ids": sorted(active),
                "third_party_active": sorted(active - expected_gone),
                "device_rows": len(nodes),
                "inert_historical_rows": len(nodes),
                "probes": probes,
            }
        last_error = {"reason": "cleanup_not_converged", "still_active": sorted(remaining)}
        time.sleep(poll_s)
    return {
        "ok": False,
        "reason": (last_error or {"reason": "cleanup_deadline"})["reason"],
        "detail": last_error.get("detail") if last_error else None,
        "expected_gone": sorted(expected_gone),
        "probes": probes[-8:],
    }


def main(argv):
    if len(argv) >= 6 and argv[1] == "--prove":
        control_url, token, network_id, mini_id, air_id = argv[2:7]
        deadline = 20
        if "--deadline" in argv:
            deadline = int(argv[argv.index("--deadline") + 1])
        report = prove_isolation(
            control_url, token, network_id, [mini_id, air_id], deadline_s=deadline
        )
        print(json.dumps(report, sort_keys=True))
        return 0 if report["ok"] else 1
    if len(argv) >= 7 and argv[1] == "--prove-target":
        control_url, token, network_id, mini_id, air_id = argv[2:7]
        deadline = 20
        if "--deadline" in argv:
            deadline = int(argv[argv.index("--deadline") + 1])
        report = prove_target_nodes(
            control_url, token, network_id, [mini_id, air_id], deadline_s=deadline
        )
        print(json.dumps(report, sort_keys=True))
        return 0 if report["ok"] else 1
    if len(argv) >= 5 and argv[1] == "--delete":
        control_url, token, device_id = argv[2:5]
        ok, status, body = delete_device(control_url, token, device_id)
        print(json.dumps({
            "ok": ok,
            "status": status,
            "device_id": device_id,
            "body": body[:500],
        }, sort_keys=True))
        return 0 if ok else 1
    if len(argv) >= 6 and argv[1] == "--delete-by-name":
        control_url, token, network_id = argv[2:5]
        device_names = argv[5:]
        ok, deleted, report = delete_devices_by_name(
            control_url, token, network_id, device_names
        )
        print(json.dumps({
            "ok": ok,
            "deleted_ids": deleted,
            "outcomes": report,
        }, sort_keys=True))
        return 0 if ok else 1
    if len(argv) >= 7 and argv[1] in ("--prove-cleaned", "--prove-cleaned-scoped"):
        control_url, token, network_id = argv[2:5]
        deadline = 15
        rest = argv[5:]
        if "--deadline" in rest:
            deadline = int(rest[rest.index("--deadline") + 1])
            rest = rest[:rest.index("--deadline")]
        deleted_ids = rest
        report = prove_cleaned(
            control_url,
            token,
            network_id,
            deleted_ids,
            deadline_s=deadline,
            reject_third_party=argv[1] == "--prove-cleaned",
        )
        print(json.dumps(report, sort_keys=True))
        return 0 if report["ok"] else 1
    raise SystemExit(
        "usage: network-isolation.py --prove CONTROL_URL TOKEN NETWORK_ID MINI_ID AIR_ID [--deadline S]\n"
        "       network-isolation.py --prove-target CONTROL_URL TOKEN NETWORK_ID MINI_ID AIR_ID [--deadline S]\n"
        "       network-isolation.py --delete CONTROL_URL TOKEN DEVICE_ID\n"
        "       network-isolation.py --delete-by-name CONTROL_URL TOKEN NETWORK_ID NAME...\n"
        "       network-isolation.py --prove-cleaned CONTROL_URL TOKEN NETWORK_ID DEVICE_ID... [--deadline S]\n"
        "       network-isolation.py --prove-cleaned-scoped CONTROL_URL TOKEN NETWORK_ID DEVICE_ID... [--deadline S]\n"
    )


if __name__ == "__main__":
    import urllib.parse
    raise SystemExit(main(sys.argv))
