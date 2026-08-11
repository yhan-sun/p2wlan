#!/usr/bin/env python3
"""Fixture coverage for strict Direct acceptance predicates."""

from __future__ import print_function

import importlib.util
import json
import pathlib
import subprocess
import tempfile
import unittest


PARSER_PATH = pathlib.Path(__file__).with_name("strict-direct-parser.py")
HARNESS_PATH = pathlib.Path(__file__).with_name("mini-air-smoke.sh")
SPEC = importlib.util.spec_from_file_location("strict_direct_parser", str(PARSER_PATH))
PARSER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PARSER)


def event(stage, generation=7, session=11, request_id=13, socket_index=0,
          expected="8.8.8.8:50000", observed="8.8.8.8:50000",
          selected="8.8.8.8:50000", authenticated=None):
    value = {
        "stage": stage,
        "network_generation": generation,
        "validation_session_id": session,
        "request_id": request_id,
        "socket_index": socket_index,
        "expected_endpoint": expected,
    }
    if stage != "direct_validation_request_sent":
        value["observed_ack_endpoint"] = observed
    if stage in ("direct_validation_promoted", "direct_path_promoted"):
        value["selected_endpoint"] = selected
    if authenticated is not None:
        value["ack_endpoint_authenticated"] = authenticated
    return value


def status(peer_id="peer-b", events=None, endpoint="8.8.8.8:50000", generation=7):
    return {
        "network_generation": generation,
        "peers": [{
            "node_id": peer_id,
            "state": "direct",
            "active_path": "direct",
            "is_public_udp_direct": True,
            "selected_pair": {"remote_endpoint": endpoint},
            "direct_events": events or [],
        }],
    }


def scoped_status(peer_id="peer-b", events=None, endpoint="8.8.8.8:50000", generation=7):
    value = status(peer_id, events, endpoint, generation)
    return {
        "node_id": "local-node",
        "network_id": "strict-test-net",
        "network_generation": generation,
        "network_peer_count": 1,
        "captured_at_ms": 50_000,
        "peer": value["peers"][0],
    }


class StrictDirectParserTest(unittest.TestCase):
    def test_complete_current_owned_chain_passes(self):
        events = [event(stage) for stage in PARSER.REQUIRED_STAGES]
        ok, reason, key = PARSER.validate(status(events=events), "peer-b")
        self.assertTrue(ok, reason)
        self.assertEqual(key["request_id"], 13)

    def test_scoped_snapshot_has_committed_promotion_time(self):
        events = [event(stage) for stage in PARSER.REQUIRED_STAGES]
        events[-1]["age_ms"] = 321
        ok, reason, key = PARSER.validate(scoped_status(events=events), "peer-b")
        self.assertTrue(ok, reason)
        self.assertEqual(key["direct_promotion_at_ms"], 49_679)

    def test_scoped_snapshot_rejects_non_isolated_network(self):
        fixture = scoped_status(events=[event(stage) for stage in PARSER.REQUIRED_STAGES])
        fixture["network_peer_count"] = 2
        ok, reason, _ = PARSER.validate(fixture, "peer-b")
        self.assertFalse(ok)
        self.assertEqual(reason, "network_not_isolated")

    def test_stale_history_cannot_pass(self):
        events = [event(stage, generation=6) for stage in PARSER.REQUIRED_STAGES]
        ok, reason, _ = PARSER.validate(status(events=events), "peer-b")
        self.assertFalse(ok)
        self.assertEqual(reason, "no_current_complete_owned_validation_chain")

    def test_third_peer_cannot_pass_target(self):
        foreign = status("peer-c", [event(stage) for stage in PARSER.REQUIRED_STAGES])
        ok, reason, _ = PARSER.validate(foreign, "peer-b")
        self.assertFalse(ok)
        self.assertEqual(reason, "target_peer_missing")

    def test_wrong_request_id_cannot_form_chain(self):
        events = [event(stage) for stage in PARSER.REQUIRED_STAGES]
        events[1]["request_id"] = 14
        ok, reason, _ = PARSER.validate(status(events=events), "peer-b")
        self.assertFalse(ok)
        self.assertEqual(reason, "no_current_complete_owned_validation_chain")

    def test_endpoint_drift_requires_authentication(self):
        observed = "8.8.4.4:50001"
        events = [
            event("direct_validation_request_sent"),
            event("direct_validation_ack_received", observed=observed, authenticated=False),
            event("direct_validation_promoted", observed=observed, selected=observed, authenticated=False),
            event("direct_path_promoted", observed=observed, selected=observed, authenticated=False),
        ]
        ok, _, _ = PARSER.validate(status(events=events, endpoint=observed), "peer-b")
        self.assertFalse(ok)
        for value in events[1:]:
            value["ack_endpoint_authenticated"] = True
        ok, reason, _ = PARSER.validate(status(events=events, endpoint=observed), "peer-b")
        self.assertTrue(ok, reason)

    def test_single_sided_direct_cannot_pass_pair(self):
        good = status(events=[event(stage) for stage in PARSER.REQUIRED_STAGES])
        bad = status(events=[])
        self.assertTrue(PARSER.validate(good, "peer-b")[0])
        self.assertFalse(PARSER.validate(bad, "peer-b")[0])

    def test_status_poll_different_times_cannot_misreport_pass(self):
        current = status(events=[event(stage) for stage in PARSER.REQUIRED_STAGES])
        stale = status(events=[event(stage, generation=6) for stage in PARSER.REQUIRED_STAGES])
        left = PARSER.validate(current, "peer-b")
        right = PARSER.validate(stale, "peer-b")
        self.assertTrue(left[0])
        self.assertFalse(right[0])
        self.assertFalse(left[0] and right[0])

    def test_parser_false_leaves_strict_convergence_empty_in_harness(self):
        source = HARNESS_PATH.read_text(encoding="utf-8")
        self.assertIn('strict_validation_pair "$CURRENT_A_POLL"', source)
        self.assertIn('&& accepted_pair=1', source)
        self.assertIn('if [[ "$accepted_pair" -eq 1 ]]; then', source)
        self.assertIn('"direct_promotion_at_ms"', source)
        self.assertIn('STRICT_CONVERGENCE_MS="$promotion_ms"', source)

    def test_harness_uses_parallel_peer_scoped_capture(self):
        source = HARNESS_PATH.read_text(encoding="utf-8")
        self.assertIn('/status/peer/$AIR_NODE_ID', source)
        self.assertIn('/status/peer/$MINI_NODE_ID', source)
        self.assertIn('wait "$mini_pid"', source)
        self.assertIn('wait "$air_pid"', source)
        self.assertIn('ControlMaster=auto', source)

    def test_cli_false_parser_returns_nonzero(self):
        fixture = status(events=[])
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "status.json"
            path.write_text(json.dumps(fixture), encoding="utf-8")
            result = subprocess.run(
                ["python3", str(PARSER_PATH), str(path), "peer-b"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
        self.assertNotEqual(result.returncode, 0)

    def test_metrics_and_strict_success_use_same_snapshot_fields(self):
        source = HARNESS_PATH.read_text(encoding="utf-8")
        self.assertIn('EVIDENCE_A_STATUS="$ROUND_DIR/strict-success-node-a.json"', source)
        self.assertIn('snapshot_poll_index=$SNAPSHOT_POLL_INDEX', source)
        self.assertIn('snapshot_a_sha256=$SNAPSHOT_A_SHA256', source)
        self.assertIn('"poll_index": int(sys.argv[5])', source)

    def test_poll_files_are_indexed_and_not_overwritten(self):
        source = HARNESS_PATH.read_text(encoding="utf-8")
        self.assertIn('node-a.poll-$poll_id.json', source)
        self.assertIn('node-b.poll-$poll_id.json', source)
        self.assertIn('strict-result-$poll_id.json', source)
        self.assertNotIn('node-a.poll.json', source)
        self.assertNotIn('node-b.poll.json', source)

    def test_final_failure_snapshot_cannot_override_success_snapshot(self):
        source = HARNESS_PATH.read_text(encoding="utf-8")
        self.assertIn('strict-success-node-a.json', source)
        self.assertIn('strict-last-failed-node-a.json', source)
        self.assertIn('teardown-node-a.json', source)
        self.assertNotIn('cp "$CURRENT_A_POLL" "$ROUND_DIR/strict-success-node-a.json"\n      cp "$CURRENT_B_POLL" "$ROUND_DIR/strict-last-failed', source)

    def test_summary_keeps_target_and_background_evidence_separate(self):
        events = [event(stage) for stage in PARSER.REQUIRED_STAGES]
        events.append({
            "stage": "punch_first_packet_sent",
            "detail": "punch_at_ms=Some(1000) actual_first_send_at_ms=Some(1007) first_send_deviation_ms=Some(7) per_socket_actual_datagrams=0:2",
        })
        fixture = status(events=events)
        fixture["candidate_snapshot_version"] = 4
        fixture["candidate_snapshot_hash"] = 99
        fixture["relay_connected"] = True
        fixture["relay_servers"] = ["tcp://relay.example.test:28081"]
        fixture["udp_socket_pool"] = [{"socket_index": 0, "probes_sent": 2}]
        fixture["peers"].append({"node_id": "background-peer"})
        summary = PARSER.round_summary(fixture, "peer-b")
        self.assertTrue(summary["strict"]["ok"])
        self.assertEqual(summary["background_peer_count"], 1)
        self.assertEqual(summary["candidate_snapshot_hash"], 99)
        self.assertTrue(summary["relay_connected"])
        self.assertEqual(summary["punch_at_ms"], 1000)
        self.assertEqual(summary["first_packet_deviation_ms"], 7)
        self.assertEqual(summary["post_direct_traversal_starts"], [])

    def test_summary_flags_traversal_after_direct_promotion(self):
        events = [event(stage) for stage in PARSER.REQUIRED_STAGES]
        events.append({"stage": "punch_started"})
        summary = PARSER.round_summary(status(events=events), "peer-b")
        self.assertEqual(summary["post_direct_traversal_starts"], ["punch_started"])

    def test_harness_no_longer_hard_refuses_default_network(self):
        source = HARNESS_PATH.read_text(encoding="utf-8")
        self.assertNotIn("refusing default", source)
        self.assertNotIn("refusing to accept default", source)
        self.assertIn("ISOLATION_HELPER", source)

    def test_harness_requires_live_isolation_proof_before_traversal(self):
        source = HARNESS_PATH.read_text(encoding="utf-8")
        self.assertIn('--prove "$CONTROL_URL" "$TOKEN" "$NETWORK_ID"', source)
        self.assertIn("ISOLATION-INVALID", source)
        self.assertIn("isolation-prove.json", source)
        self.assertIn("network isolation proof failed", source)

    def test_harness_requires_per_round_device_cleanup(self):
        source = HARNESS_PATH.read_text(encoding="utf-8")
        self.assertIn("--delete-by-name", source)
        self.assertIn("--prove-cleaned", source)
        self.assertIn("network not clean after device deletion", source)
        self.assertIn("isolation-cleaned.json", source)

    def test_harness_aborts_run_on_isolation_failure(self):
        source = HARNESS_PATH.read_text(encoding="utf-8")
        self.assertIn('record_sequence_round "$round" 0 "" ""', source)
        self.assertIn("exit 1", source)


if __name__ == "__main__":
    unittest.main()
