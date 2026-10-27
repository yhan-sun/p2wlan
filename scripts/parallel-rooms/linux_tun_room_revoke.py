"""Actual production room leave between retained Full and original metadata delivery."""
import time

import linux_tun_native_transaction as native
from linux_tun_kernel_capture import read_pair
from linux_tun_probe_capture import MAX_FINAL_READS
from linux_tun_revoke_contract import (DeferredLastWindow, historical_last_sources,
                                       refused_credit, require, rows)


class Revocation:
    def __init__(self, harness, lab, report, snapshots, users, room):
        self.h, self.lab, self.report = harness, lab, report
        self.snapshots, self.users, self.room = snapshots, users, room
        self.bridge = None

    def prepare(self, capture, kernel):
        require(capture is not None and kernel is not None and kernel.get("gap") is None
                and kernel["endpoints"] is not None, "revocation_original_capture_missing")
        old = capture.live_window_bridge
        require(old is not None and old.child is None and not old.seen and not old.closed,
                "revocation_original_bridge_already_started")
        self.bridge = DeferredLastWindow(capture, old.endpoints)
        old.seal()
        capture.live_window_bridge = self.bridge

    def complete(self, entry, capture, kernel, application_report):
        bridge = self.bridge
        entry["original_live_write_windows"] = bridge.summary() if bridge is not None else None
        require(entry["protocol"] == "udp" and entry["direction"] == "b-to-a"
                and len(entry["records"]) == 8
                and all(r["status"] == "success" for r in entry["records"]),
                "revocation_original_eight_application_responses_missing")
        require(bridge is not None and bridge.pending is not None and bridge.gap is None
                and bridge.seen == set(range(8)), "revocation_original_window_not_retained")
        window = dict(bridge.pending)
        end = window["original_deadline_ns"] / 1_000_000_000
        # The original child was waited by the caller. Drain only bytes already
        # written in its bounded pipe, with no new wait or delivery catch-up.
        for _ in range(MAX_FINAL_READS):
            size = len(capture.raw)
            capture.drain(live=False)
            if capture.reader is None or len(capture.raw) == size:
                break
        require(capture.eof and capture.gap is None, "revocation_original_write_EOF_missing")
        writes = capture.stream.finish(application_report, time.monotonic_ns())
        require(writes["stream_complete"] is True
                and all(r["accepted_in_original_deadline"] for r in writes["requests"]),
                "revocation_original_OS_writes_unverified")
        entry["pre_revocation_original_write_verification"] = writes
        # Original complete OS writes and actual Full/read/write sources precede
        # leave. No native outcome is constructed from the withheld metadata.
        endpoints = kernel["endpoints"]  # Source b survives; guest a leaves.
        before = [endpoint.snapshot(deadline=end) for endpoint in endpoints]
        producer = capture.prepared.producer_scope
        paired = [rows(snapshot, producer) for snapshot in before]
        selected = []
        comparisons = [[], []]
        for snapshot, requests in zip(before, paired):
            last = requests[7]
            require(last["native_credit"] is None and last["original_write_window"] is None,
                    "revocation_last_outcome_already_terminal")
            require(last["run_nonce"] == entry["run_nonce"] and last["round_nonce"] == entry["round_nonce"]
                    and last["request_nonce"] == window["request_nonce"], "revocation_original_nonce_mismatch")
            selected.append(historical_last_sources(snapshot, last, window))
        for i in range(7):
            for side in range(2):
                row = paired[side][i]
                comparisons[side].append(native.frame_comparison(before[side], row, row["original_write_window"]))
        action = dict(started_monotonic_ns=time.monotonic_ns(),
                      production_operation="POST /api/v1/rooms/{room}/leave")
        self.report["room_revocation"] = dict(passed=False, original_window=window, action=action)
        response = self.lab.http("control", "/api/v1/rooms/" + self.room["id"] + "/leave",
                                 method="POST", token=self.users["a"]["token"], deadline=end)
        require(response == {"success": True}, "revocation_production_leave_failed")
        action["returned_monotonic_ns"] = time.monotonic_ns()
        action["leave_accepted"] = True
        observations = []
        self.report["room_revocation"]["survivor_peer_observations"] = observations
        while time.monotonic() < end:
            status = self.lab.status("b1", deadline=end)
            matching = [p for p in status.get("peers", []) if p.get("node_id") == self.snapshots["a1"]["node_id"]]
            require(len(matching) <= 1 and len(observations) < 50, "revocation_peer_observation_capacity")
            observation = dict(observed_monotonic_ns=time.monotonic_ns(), matching_peers=len(matching),
                               online=matching[0].get("online") if matching else None)
            observations.append(observation)
            if not matching or matching[0].get("online") is False:
                break
            time.sleep(min(.02, max(0, end - time.monotonic())))
        else:
            raise TimeoutError("revocation_original_window_peer_removal_deadline")
        release_ns = time.monotonic_ns()
        require(action["started_monotonic_ns"] <= action["returned_monotonic_ns"]
                <= observations[-1]["observed_monotonic_ns"] <= release_ns
                < window["original_deadline_ns"], "revocation_original_action_deadline")
        released = bridge.release_to_survivor(endpoints[0], release_ns)
        require(released == window, "revocation_original_window_changed")
        after = endpoints[0].snapshot(deadline=end)
        repeated = endpoints[0].snapshot(deadline=end)
        last, again = (rows(s, producer)[7] for s in [after, repeated])
        refused_credit(last["native_credit"])
        require(last["native_credit"] == again["native_credit"], "revocation_terminal_native_outcome_changed")
        require(historical_last_sources(after, last, window) == selected[0]
                == historical_last_sources(repeated, again, window), "revocation_original_sources_changed")
        credit = last["native_credit"]
        require(credit["original_kernel_read_ordinals"] == sorted(p["read_ordinal"] for p in selected[0]["full"])
                and credit["original_system_write_ordinals"] == sorted(p["write_ordinal"] for p in selected[0]["writes"]),
                "revocation_refusal_does_not_name_original_sources")
        received = last["original_write_window"]
        require(received is not None and all(received[k] == window[k] for k in ["request_nonce",
                "original_started_ns", "original_sent_ns", "original_deadline_ns", "complete_returned_ns",
                "frame_bytes", "frame_sha256"])
                and release_ns <= received["received_monotonic_ns"] < window["original_deadline_ns"],
                "revocation_original_received_window_changed_or_late")
        records = []
        for i, write in enumerate(writes["requests"]):
            value = read_pair(paired[0][i], paired[1][i], write)
            require(value["source_kernel_read_in_original_deadline"]
                    and value["response_kernel_read_in_original_deadline"], "revocation_original_read_missing")
            value.update(source_native_transaction=comparisons[0][i] if i < 7 else
                         dict(matched=False, expected_terminal_room_refusal=credit),
                         response_native_transaction=comparisons[1][i] if i < 7 else
                         dict(matched=False, original_window_withheld_from_departed_owner=True),
                         full128_owner_qualified=i < 7)
            records.append(value)
        result = dict(scope="original_owned_daemon_full128_kernel_transactions", request_count=8,
                      passed=False, full128_owner_evidence_complete=False, physical_send_verified=False,
                      canonical_current_owner_verified=False, requests=records,
                      gap_reason="supplementary_last_original_room_refusal_is_expected")
        kernel["result"] = entry["original_kernel_reads"] = result
        first = self.report["manifest"][0]["original_kernel_reads"]
        require(first["passed"] is True and first["full128_owner_evidence_complete"] is True,
                "revocation_first_positive_eight_missing")
        self.report["room_revocation"].update(passed=True, scope="actual_survivor_original_room_refusal",
            producer_scope=producer, original_source_kind="request", surviving_endpoint="b1",
            deferred_sequence=7, released_monotonic_ns=release_ns, original_sources_before_leave=selected,
            actual_terminal_credit=credit, repeated_terminal_credit=again["native_credit"],
            positive_original_node_transactions=30, expected_room_refusals=1,
            departed_endpoint_window_not_delivered=True, original_deadlines_unchanged=True,
            no_native_fact_or_owner_constructed_from_metadata=True,
            whole_B01_complete=False, original_Direct80_and_Relay32_unchanged=True)
