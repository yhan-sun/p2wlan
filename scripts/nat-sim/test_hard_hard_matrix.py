#!/usr/bin/env python3
"""Contract tests for the bounded Hard<->Hard matrix runner."""

from __future__ import annotations

import json
import importlib.util
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


RUNNER = Path(__file__).with_name("run-hard-hard-matrix.py")
REPOSITORY_ROOT = RUNNER.parents[2]
SOURCE_SHA = subprocess.run(
    ["git", "-C", str(REPOSITORY_ROOT), "rev-parse", "HEAD"],
    check=True,
    capture_output=True,
    text=True,
).stdout.strip()
BASELINE_SHA = SOURCE_SHA
RUNNER_SPEC = importlib.util.spec_from_file_location("hard_hard_matrix_runner", RUNNER)
assert RUNNER_SPEC is not None and RUNNER_SPEC.loader is not None
MATRIX_RUNNER = importlib.util.module_from_spec(RUNNER_SPEC)
sys.modules[RUNNER_SPEC.name] = MATRIX_RUNNER
RUNNER_SPEC.loader.exec_module(MATRIX_RUNNER)


FAKE_SMOKE = r'''
import json
import struct
import os
from pathlib import Path

root = Path(os.environ["NAT_SIM_ARTIFACT_DIR"])
root.mkdir(parents=True)
rounds = int(os.environ["ROUNDS"])
scenario = os.environ["EXPERIMENT_SCENARIO"]

def report(side, seed):
    value = {
        "schema_version": 2,
        "baseline_git_commit": os.environ["EXPERIMENT_BASELINE_SHA"],
        "source_git_commit": os.environ["NAT_TOPOLOGY_HEAD_SHA"],
        "build_id": "test-build",
        "experiment_variant": os.environ["EXPERIMENT_VARIANT"],
        "scenario_id": scenario,
        "seed": seed,
        "role": "initiator" if side == "a" else "responder",
        "mode": "predictable",
        "session_tag": "0123456789abcdef",
        "plan_tag": "fedcba9876543210",
        "network_generation": 1,
        "peer_session_generation": 2,
        "remote_candidate_epoch": 3,
        "local_profile_generation": 4 if side == "a" else 5,
        "remote_profile_generation": 5 if side == "a" else 4,
        "punch_generation": 6,
        "socket_index": 4096,
        "attempt": 1,
        "counts": {
            "requested": 2,
            "generated": 2,
            "unique": 1,
            "advertised": 1,
            "parsed_targets_for_plan": 1,
            "planned_targets": 1,
            "planned_sockets": 1,
            "planned_socket_target_combinations": 1,
            "planned_logical_probes": 2,
            "planned_physical_datagram_cap": 4,
            "attempted_targets": 1,
            "logical_probes_attempted": 2,
            "logical_probes_sent": 2,
            "send_success_datagrams": 4,
            "send_success_bytes": 240,
            "send_errors": 0,
            "send_error_bytes": 0,
            "budget_skipped": 0,
            "planned_logical_probes_not_attempted": 0,
            "stun_send_success_datagrams": 3,
            "stun_send_success_bytes": 60,
            "stun_send_errors": 0,
            "stun_send_error_bytes": 0,
            "stun_responses": 3,
            "candidate_signal_payload_logic_bytes": 48,
        },
        "candidate_cap": 32,
        "truncation_reason": "none",
        "target_order_tags": ["fedcba9876543210"],
        "confirmed_target_rank": 0,
        "timeline": {
            "measurement_started_at_ms": 100,
            "last_measurement_send_at_ms": 120,
            "measurement_completed_at_ms": 140,
            "candidate_signal_accepted_at_ms": 180,
            "planned_send_at_ms": 3500,
            "send_dispatch_at_ms": 3501,
            "actual_first_send_at_ms": 3502,
            "probe_last_hit_at_ms": 3510,
            "probe_last_hit_source": "last_authenticated_probe",
            "encrypted_validation_completed_at_ms": 3520,
            "business_ready_at_ms": None,
            "first_business_success_at_ms": None,
            "measurement_age_at_send_ms": 3382,
            "schedule_deviation_ms": 2,
            "measurement_to_first_send_ms": 3402,
            "last_probe_hit_to_validation_ms": 10,
            "connection_to_first_business_ms": None,
            "validation_to_first_business_ms": None,
            "business_evidence_attribution": None,
        },
        "business_attribution_identity": {
            "validation_session_id": 100 if side == "a" else 200,
            "direct_commit_sequence": 7,
            "transport_instance_id": 10 if side == "a" else 20,
            "socket_index": 4096,
        },
        "probe_packets_received": 1,
        "matched_probe_acks": 1,
        "authenticated_probe_packets_received": 1,
        "authenticated_probe_acks_unmatched": 0,
        "direct_confirmed": True,
        "failure_class": "encrypted_validation_completed",
        "terminal_reason": "direct_confirmed",
    }
    if scenario == "port-competition" and side == "a":
        value["counts"]["attempted_targets"] = 2
    return value

def status(side, seed):
    attempt = report(side, seed)
    peer_id = "node-b" if side == "a" else "node-a"
    if scenario == "strict-one-sided" and side == "b":
        direct_events = []
    else:
        direct_events = [{
            "stage": "hard_hard_attempt_report",
            "hard_hard_attempt": attempt,
        }]
    business_ready_at = 3650 if scenario == "loss-reorder-duplicate" else 3550
    return {
        "health": {"critical_tasks": [{
            "name": "control",
            "critical": True,
            "running": True,
            "finished": False,
            "error": None,
        }]},
        "connection_timeline": {
            "events": [
                {
                    "event": "direct_business_mtu_ready",
                    "path": "direct",
                    "peer_id": peer_id,
                    "connection_generation": 1,
                    "at_ms": business_ready_at,
                    "business_attribution_identity": attempt["business_attribution_identity"],
                },
                {
                    "event": "business_ingress_observed",
                    "path": "direct",
                    "peer_id": peer_id,
                    "connection_generation": 1,
                    "at_ms": 3600,
                    "business_attribution_identity": attempt["business_attribution_identity"],
                },
            ],
            "first_usable_summaries": [{
                "path": "direct",
                "first_usable_at_ms": 3600,
                "relay_ready_at_ms": 200,
                "first_usable_delta_ms": 3400,
                "direct_first_remaining_ms_at_relay_ready": 4000,
                "business_received": True,
            }],
        },
        "peers": [{
            "node_id": peer_id,
            "active_path": "direct",
            "direct_events": direct_events,
        }],
    }

for number in range(1, rounds + 1):
    round_dir = root / f"round-{number}"
    round_dir.mkdir()
    seed = int(os.environ["NAT_SEED_BASE"]) + number
    for side in ("a", "b"):
        (round_dir / f"node-{side}.status.json").write_text(
            json.dumps(status(side, seed)), encoding="utf-8"
        )
        (round_dir / f"node-{side}.log").write_text("typed evidence\n", encoding="utf-8")
    (round_dir / "nat-evidence.json").write_text(
        json.dumps({"executed": True, "result": "pass"}), encoding="utf-8"
    )
    if scenario != "negative-wrap":
        (round_dir / "cleanup.json").write_text(
            json.dumps({
                "schema_version": 1,
                "duration_ms": 12,
                "process_count": 5,
                "all_reaped": True,
            }),
            encoding="utf-8",
        )
    if scenario != "strict-bilateral":
        features = {
            "egress_capture": "shim", "unassigned_egress_listeners": 0,
            "direct_gate_preserves_source_allocations": True,
            "strict_filtering_a": os.environ["STRICT_FILTERING_A"] == "1",
            "strict_filtering_b": os.environ["STRICT_FILTERING_B"] == "1",
            "consume_a": int(os.environ["CONSUME_A"]), "consume_b": int(os.environ["CONSUME_B"]),
            "sweep_noise_every": int(os.environ["SWEEP_NOISE_EVERY"]),
            "sweep_noise_count": int(os.environ["SWEEP_NOISE_COUNT"]),
            "sweep_noise_limit": int(os.environ["SWEEP_NOISE_LIMIT"]),
        }
        (round_dir / "nat-sim.out").write_text("NAT_FEATURES=" + json.dumps(features) + "\n")
        trace = []
        for side in ("A", "B"):
            for event in ("egress_gateway_ready", "egress_captured", "stun_mapping_observed"):
                trace.append({"nat": side, "event": event, "client": side + "-client",
                              "bytes": 0, "gateway_port": 45000 if side == "A" else 45001})
            (round_dir / ("node-" + side.lower() + ".egress-stats")).write_bytes(
                struct.pack("=8sQQQQ", b"P2CNT001", 1, 0, 0, 45000 if side == "A" else 45001))
            for _ in range(features["consume_" + side.lower()]):
                trace.append({"nat": side, "event": "mapping_consumed", "client": side + "-client",
                              "stage": "post_measurement_before_first_peer"})
            trace.append({"nat": side, "event": "peer_mapping_started", "client": side + "-client",
                          "prior_peer_mappings": 0})
            if features["sweep_noise_every"] and features["sweep_noise_count"]:
                trace.append({"nat": side, "event": "mapping_consumed", "client": side + "-client",
                              "stage": "during_sweep", "prior_peer_mappings": features["sweep_noise_every"]})
            trace.append({"nat": side, "event": "mapping_bound", "public_endpoint": side,
                          "destination": "B" if side == "A" else "A"})
        (round_dir / "nat-trace.jsonl").write_text("".join(
            json.dumps({"sequence": i + 1, **row}) + "\n" for i, row in enumerate(trace)))

raise SystemExit(7 if scenario == "unequal-step" else 0)
'''


class HardHardMatrixRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.fake_smoke = self.directory / "fake-smoke.py"
        self.fake_smoke.write_text(
            f"#!{sys.executable}\n" + textwrap.dedent(FAKE_SMOKE), encoding="utf-8"
        )
        self.fake_smoke.chmod(0o700)

    def tearDown(self):
        self.temporary.cleanup()

    def command(self, output: Path, scenario: str = "equal-step") -> list[str]:
        return [
            sys.executable,
            str(RUNNER),
            "--scenario",
            scenario,
            "--output",
            str(output),
            "--source-sha",
            SOURCE_SHA,
            "--baseline-sha",
            BASELINE_SHA,
            "--variant",
            "test-variant",
            "--smoke-script",
            str(self.fake_smoke),
        ]

    def test_help_and_list_are_real_entry_points(self):
        help_result = subprocess.run(
            [sys.executable, str(RUNNER), "--help"], capture_output=True, text=True
        )
        self.assertEqual(help_result.returncode, 0)
        self.assertIn("--max-executions", help_result.stdout)
        listed = subprocess.run(
            [sys.executable, str(RUNNER), "--list"], capture_output=True, text=True
        )
        self.assertEqual(listed.returncode, 0)
        self.assertIn("equal-step\tseed=42001", listed.stdout)
        self.assertIn("loss-only\tseed=42101", listed.stdout)
        self.assertIn("offer-dispatch-delay\tseed=42131", listed.stdout)
        self.assertIn("random-high-entropy-negative", listed.stdout)

    def test_a0_fault_scenarios_are_isolated_and_control_delay_is_separate(self):
        defaults = {
            "LOSS": "0",
            "REORDER": "0",
            "DUPLICATE_RATE": "0",
            "SIGNAL_DELAY_A_MS": "0",
            "SIGNAL_DELAY_B_MS": "0",
        }
        expected = {
            "equal-step": {},
            "loss-only": {"LOSS": "0.08"},
            "reorder-only": {"REORDER": "1"},
            "duplicate-only": {
                "DUPLICATE_RATE": "1.0",
                "ALLOW_REPLAY_REJECTS": "1",
            },
            "loss-reorder-duplicate": {
                "LOSS": "0.08",
                "REORDER": "1",
                "DUPLICATE_RATE": "1.0",
                "ALLOW_REPLAY_REJECTS": "1",
            },
            "offer-dispatch-delay": {
                "SIGNAL_DELAY_A_MS": "400",
                "SIGNAL_DELAY_B_MS": "0",
            },
        }
        for name, overrides in expected.items():
            with self.subTest(scenario=name):
                scenario = MATRIX_RUNNER.SCENARIO_BY_NAME[name]
                configured = {**defaults, **scenario.env}
                for key in defaults:
                    self.assertEqual(configured[key], {**defaults, **overrides}.get(key, defaults[key]))
                for key, value in overrides.items():
                    self.assertEqual(configured[key], value)
        self.assertIn(
            "admitted by simulated public mappings",
            MATRIX_RUNNER.SCENARIO_BY_NAME["loss-only"].description,
        )
        self.assertIn(
            "STUN observer replies, Control, and TCP Relay are outside this hook",
            MATRIX_RUNNER.SCENARIO_BY_NAME["reorder-only"].description,
        )
        self.assertIn("before its existing signaling API", MATRIX_RUNNER.SCENARIO_BY_NAME["offer-dispatch-delay"].description)

    def test_strict_cross_factor_scenarios_keep_filtering_and_measurement_drift(self):
        for name in ("strict-phase-drift", "strict-unequal-drift-delay", "strict-negative-drift-delay"):
            with self.subTest(scenario=name):
                env = MATRIX_RUNNER.SCENARIO_BY_NAME[name].env
                self.assertEqual((env["STRICT_FILTERING_A"], env["STRICT_FILTERING_B"]), ("1", "1"))
                self.assertEqual((env["CONSUME_A"], env["CONSUME_B"]), ("2", "3"))
        cross = MATRIX_RUNNER.SCENARIO_BY_NAME["strict-unequal-drift-delay"].env
        self.assertNotEqual(cross["STEP_A"], cross["STEP_B"])
        self.assertGreater(int(cross["SWEEP_NOISE_COUNT"]), 0)
        self.assertEqual(cross["SWEEP_NOISE_EVERY"], "1")
        sweep = MATRIX_RUNNER.SCENARIO_BY_NAME["strict-sweep-noise"].env
        self.assertEqual((sweep["STRICT_FILTERING_A"], sweep["STRICT_FILTERING_B"]), ("1", "1"))
        self.assertEqual((sweep["CONSUME_A"], sweep["CONSUME_B"]), ("1", "1"))
        self.assertEqual(sweep["SWEEP_NOISE_EVERY"], "1")
        self.assertEqual(sweep["SWEEP_NOISE_LIMIT"], "16")
        self.assertNotEqual(cross["STUN_DELAY_A_MS"], cross["STUN_DELAY_B_MS"])

    def test_capture_loss_retains_requested_denominator_and_partial_attempt_costs(self):
        self.fake_smoke.write_text(self.fake_smoke.read_text().replace(
            'raise SystemExit(7 if scenario == "unequal-step" else 0)',
            'for path in root.glob("round-*/node-b.egress-stats"):\n    path.unlink()\nraise SystemExit(0)'))
        output = self.directory / "capture-missing"
        result = subprocess.run(self.command(output), capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        manifest = json.loads((output / "manifest.json").read_text())
        self.assertEqual(manifest["summary"]["requested_rounds"], 1)
        self.assertEqual(manifest["summary"]["invalid_rounds"], 1)
        record = manifest["runs"][0]["rounds"][0]
        self.assertIn("b_shim_send_counters_missing_or_invalid", record["reason"])
        self.assertEqual(len(record["partial_attempts"]), 2)
        self.assertEqual(manifest["summary"]["costs"]["all_requested"]["known_observed_costs"]["probe_datagrams"], 8)

    def test_a0_stage_parser_keeps_only_redacted_allowlisted_fields(self):
        round_dir = self.directory / "a0-stage-parser"
        round_dir.mkdir()
        secret_marker = "peer_id=private-node endpoint=198.51.100.7:2345 opaque=raw-session-token"
        for side, role in (("a", "initiator"), ("b", "responder")):
            (round_dir / f"node-{side}.log").write_text(
                'INFO event="hard_hard_attempt_stage" '
                f'role="{role}" identity_scope="shared_session" '
                'session_tag="0123456789abcdef" plan_tag="fedcba9876543210" '
                'stage="local_measurement" reason_code="started" '
                + secret_marker
                + "\n",
                encoding="utf-8",
            )
        with (round_dir / "node-a.log").open("a", encoding="utf-8") as log:
            log.write(
                'INFO event="hard_hard_attempt_stage" role="unclassified" '
                'identity_scope="local_pre_session" session_tag="none" plan_tag="none" '
                'stage="peer_signal_admission" reason_code="malformed_envelope"\n'
            )
            log.write(
                'INFO event="hard_hard_attempt_stage" role="responder" '
                'identity_scope="shared_session" session_tag="0123456789abcdef" '
                'plan_tag="fedcba9876543210" stage="peer_signal_admission" '
                'reason_code="profile_missing" candidate_epoch=8 '
                'declared_profile_generation=7 profile_generation=none\n'
            )
        (round_dir / "server.log").write_text(
            '2026/09/23 event=hard_hard_attempt_stage role=initiator '
            'identity_scope=shared_session session_tag=0123456789abcdef '
            'plan_tag=fedcba9876543210 stage=signal_persisted '
            'reason_code=database_inserted raw_token=do-not-copy\n',
            encoding="utf-8",
        )
        evidence = MATRIX_RUNNER.extract_a0_stage_evidence(round_dir)
        self.assertEqual(evidence["schema_version"], 3)
        self.assertEqual(evidence["record_count"], 5)
        self.assertEqual(evidence["missing_sources"], [])
        self.assertEqual(evidence["sides"]["a"]["records"][0]["stage"], "local_measurement")
        self.assertEqual(evidence["sides"]["server"]["records"][0]["stage"], "signal_persisted")
        self.assertEqual(
            evidence["sides"]["a"]["records"][1]["reason_code"], "malformed_envelope"
        )
        self.assertEqual(
            evidence["sides"]["a"]["records"][2]["reason_code"], "profile_missing"
        )
        self.assertNotIn("candidate_epoch", json.dumps(evidence))
        self.assertNotIn(secret_marker, json.dumps(evidence))
        self.assertNotIn("198.51.100.7", json.dumps(evidence))
        self.assertNotIn("do-not-copy", json.dumps(evidence))

    def test_success_writes_schema_and_preserves_raw_evidence(self):
        output = self.directory / "success"
        result = subprocess.run(self.command(output), capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["schema_version"], 4)
        self.assertEqual(manifest["result"], "pass")
        self.assertEqual(manifest["source_head_sha"], SOURCE_SHA)
        self.assertEqual(manifest["summary"]["valid_rounds"], 1)
        self.assertEqual(manifest["summary"]["direct_within_protection_rounds"], 1)
        self.assertEqual(manifest["summary"]["attempt_count"], 2)
        self.assertEqual(
            manifest["summary"]["costs"]["all_requested"]["known_observed_costs"]["probe_datagrams"],
            8,
        )
        self.assertEqual(manifest["summary"]["costs"]["all_requested"]["paired_shared_plan_samples"], 1)
        self.assertEqual(
            manifest["summary"]["candidate_execution"]["confirmed_target_in_plan_attempts"],
            2,
        )
        self.assertEqual(manifest["summary"]["cleanup_duration_ms"]["p95"], 12)
        duplicate_evidence = manifest["runs"][0]["rounds"][0]["duplicate_fault_evidence"]
        self.assertEqual(duplicate_evidence["end_to_end_result"]["round_result"], "valid")
        self.assertEqual(duplicate_evidence["legacy_round_verdict"], "valid")
        self.assertTrue(manifest["summary"]["duplicate_fault_evidence"]["existing_end_to_end_verdicts_preserved"])
        attempts = manifest["runs"][0]["rounds"][0]["attempts"]
        self.assertEqual(attempts[0]["timeline"]["validation_to_first_business_ms"], 80)
        self.assertEqual(attempts[0]["timeline"]["business_ready_at_ms"], 3550)
        self.assertEqual(attempts[0]["experiment_outcome_class"], "direct_business_succeeded")
        self.assertTrue((output / "raw/equal-step/round-1/nat-trace.jsonl").is_file())

    def test_probe_duplicate_does_not_count_as_wireguard_replay_evidence(self):
        scenario = MATRIX_RUNNER.SCENARIO_BY_NAME["duplicate-only"]
        with tempfile.TemporaryDirectory(prefix="p2wlan-duplicate-evidence-") as raw:
            round_dir = Path(raw)
            (round_dir / "nat-trace.jsonl").write_text(
                json.dumps({"event": "packet_duplicated", "copies": 2}) + "\n",
                encoding="utf-8",
            )
            evidence = MATRIX_RUNNER.extract_duplicate_fault_evidence(
                round_dir, scenario, SOURCE_SHA, scenario.seed
            )
        self.assertTrue(evidence["fault_injection_requested"])
        self.assertFalse(evidence["simulator_target_protocol_layer_hit"])
        self.assertFalse(evidence["target_protocol_layer_hit"])
        self.assertEqual(evidence["nat_sim_duplicate_events"], 1)
        self.assertEqual(evidence["wireguard_transport_duplicate_events"], 0)
        self.assertEqual(evidence["transport_replay_chain_complete_identities"], 0)
        self.assertEqual(evidence["local_stage_evidence_validity"], "injection_missed_wireguard_transport")

    def test_reorder_is_reported_as_transport_delay_without_claiming_packet_order(self):
        scenario = MATRIX_RUNNER.SCENARIO_BY_NAME["reorder-only"]
        identity = {
            "payload_class": "wireguard_transport_v1",
            "receiver_index": 17,
            "wireguard_counter": 3,
            "wire_fp": "0123456789abcdef",
        }
        with tempfile.TemporaryDirectory(prefix="p2wlan-reorder-evidence-") as raw:
            round_dir = Path(raw)
            trace_rows = [
                {"event": "packet_delayed", "reorder_delay_injected": True, **identity},
                {"event": "simulator_delivery", "duplicate_copy": 0, **identity},
            ]
            (round_dir / "nat-trace.jsonl").write_text(
                "".join(json.dumps(row) + "\n" for row in trace_rows), encoding="utf-8"
            )
            evidence = MATRIX_RUNNER.extract_duplicate_fault_evidence(
                round_dir, scenario, SOURCE_SHA, scenario.seed
            )
        self.assertTrue(evidence["fault_injection_requested"])
        self.assertTrue(evidence["simulator_target_protocol_layer_hit"])
        self.assertFalse(evidence["target_protocol_layer_hit"])
        self.assertEqual(evidence["local_stage_evidence_validity"], "not_applicable_no_duplicate_requested")
        self.assertEqual(
            evidence["reorder_stage_evidence_validity"],
            "wireguard_transport_delay_injected_no_order_claim",
        )
        self.assertEqual(evidence["actual_packet_order_evidence"], "not_recorded_by_nat_sim_trace")

    def test_target_seed_override_is_limited_to_prebounded_single_round(self):
        result = subprocess.run(
            [
                sys.executable,
                str(RUNNER),
                "--dry-run",
                "--scenario",
                "loss-reorder-duplicate",
                "--target-seed",
                "42072",
                "--rounds",
                "1",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        plan = json.loads(result.stdout)
        self.assertEqual(plan["first_seed_by_scenario"], {"loss-reorder-duplicate": 42072})
        invalid = subprocess.run(
            [
                sys.executable,
                str(RUNNER),
                "--dry-run",
                "--scenario",
                "loss-reorder-duplicate",
                "--target-seed",
                "42073",
                "--rounds",
                "1",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(invalid.returncode, 2)
        self.assertIn("pre-bounded A0 diagnostic seeds", invalid.stderr)

    def test_business_events_require_exact_attempt_identity_across_shared_generation(self):
        old_identity = {
            "validation_session_id": 10,
            "direct_commit_sequence": 2,
            "transport_instance_id": 30,
            "socket_index": 4096,
        }
        current_identity = {
            "validation_session_id": 11,
            "direct_commit_sequence": 3,
            "transport_instance_id": 30,
            "socket_index": 4097,
        }
        status = {
            "connection_timeline": {
                "events": [
                    {
                        "event": "direct_business_mtu_ready",
                        "path": "direct",
                        "peer_id": "node-b",
                        "connection_generation": 5,
                        "at_ms": 200,
                        "business_attribution_identity": old_identity,
                    },
                    {
                        "event": "business_ingress_observed",
                        "path": "direct",
                        "peer_id": "node-b",
                        "connection_generation": 5,
                        "at_ms": 250,
                        "business_attribution_identity": old_identity,
                    },
                    {
                        "event": "business_ingress_observed",
                        "path": "direct",
                        "peer_id": "node-b",
                        "connection_generation": 5,
                        "at_ms": 500,
                        "business_attribution_identity": current_identity,
                    },
                ]
            }
        }
        matched, reason = MATRIX_RUNNER.first_timeline_event_at(
            status,
            "business_ingress_observed",
            "node-b",
            "direct",
            {"network_generation": 5, "business_attribution_identity": current_identity},
        )
        self.assertEqual(matched, 500)
        self.assertEqual(reason, "attributed:exact_attempt_identity")

    def test_socket_replacement_and_missing_attempt_identity_stay_unattributed(self):
        status = {
            "connection_timeline": {
                "events": [{
                    "event": "direct_business_mtu_ready",
                    "path": "direct",
                    "peer_id": "node-b",
                    "connection_generation": 5,
                    "at_ms": 400,
                    "business_attribution_identity": {
                        "validation_session_id": 11,
                        "direct_commit_sequence": 3,
                        "transport_instance_id": 30,
                        "socket_index": 4096,
                    },
                }]
            }
        }
        replaced_socket = {
            "network_generation": 5,
            "business_attribution_identity": {
                "validation_session_id": 11,
                "direct_commit_sequence": 3,
                "transport_instance_id": 30,
                "socket_index": 4097,
            },
        }
        missing_identity = {"network_generation": 5}
        self.assertEqual(
            MATRIX_RUNNER.first_timeline_event_at(
                status, "direct_business_mtu_ready", "node-b", "direct", replaced_socket
            ),
            (None, "not_attributable:identity_mismatch"),
        )
        self.assertEqual(
            MATRIX_RUNNER.first_timeline_event_at(
                status, "direct_business_mtu_ready", "node-b", "direct", missing_identity
            ),
            (None, "not_attributable:attempt_identity_missing"),
        )

    def test_smoke_exit_code_is_propagated_without_discarding_attempts(self):
        output = self.directory / "exit-code"
        result = subprocess.run(
            self.command(output, "unequal-step"), capture_output=True, text=True
        )
        self.assertEqual(result.returncode, 1)
        manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
        run = manifest["runs"][0]
        self.assertEqual(run["exit_code"], 7)
        self.assertIn("smoke_exit_code:7", run["validation_errors"])
        self.assertEqual(len(run["rounds"][0]["attempts"]), 2)

    def test_inbound_business_may_precede_local_outbound_mtu_readiness(self):
        output = self.directory / "directional-order"
        result = subprocess.run(
            self.command(output, "loss-reorder-duplicate"),
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
        timeline = manifest["runs"][0]["rounds"][0]["attempts"][0]["timeline"]
        self.assertLess(
            timeline["first_business_success_at_ms"],
            timeline["business_ready_at_ms"],
        )
        self.assertEqual(timeline["validation_to_first_business_ms"], 80)

    def test_missing_attempt_or_trace_fails_closed(self):
        for scenario, reason in (
            ("strict-one-sided", "b_hard_hard_attempt_missing"),
            ("strict-bilateral", "raw_evidence_missing:nat-trace.jsonl"),
        ):
            with self.subTest(scenario=scenario):
                output = self.directory / scenario
                result = subprocess.run(
                    self.command(output, scenario), capture_output=True, text=True
                )
                self.assertEqual(result.returncode, 1)
                manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
                self.assertEqual(manifest["result"], "fail")
                self.assertIn(reason, manifest["runs"][0]["rounds"][0]["reason"])
                all_requested = manifest["summary"]["costs"]["all_requested"]
                if scenario == "strict-one-sided":
                    self.assertEqual(
                        all_requested["known_observed_costs"]["probe_datagrams"], 4
                    )
                    self.assertEqual(all_requested["incomplete_shared_plan_samples"], 1)
                else:
                    self.assertEqual(
                        all_requested["known_observed_costs"]["probe_datagrams"], 8
                    )
                    self.assertEqual(all_requested["paired_shared_plan_samples"], 1)

    def test_inconsistent_attempt_dimensions_fail_closed(self):
        output = self.directory / "invalid-attempt"
        result = subprocess.run(
            self.command(output, "port-competition"), capture_output=True, text=True
        )
        self.assertEqual(result.returncode, 1)
        manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
        self.assertIn(
            "a_attempt_distinct_target_overflow",
            manifest["runs"][0]["rounds"][0]["reason"],
        )

    def test_missing_cleanup_evidence_fails_closed(self):
        output = self.directory / "missing-cleanup"
        result = subprocess.run(
            self.command(output, "negative-wrap"), capture_output=True, text=True
        )
        self.assertEqual(result.returncode, 1)
        manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
        self.assertIn(
            "raw_evidence_missing:cleanup.json",
            manifest["runs"][0]["rounds"][0]["reason"],
        )

    def test_existing_output_is_refused_without_cleanup_or_overwrite(self):
        output = self.directory / "existing"
        output.mkdir()
        sentinel = output / "keep.txt"
        sentinel.write_text("preserve", encoding="utf-8")
        result = subprocess.run(self.command(output), capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "preserve")
        self.assertFalse((output / "manifest.json").exists())

    def test_capacity_limit_rejects_before_creating_output(self):
        output = self.directory / "capacity"
        command = self.command(output) + ["--rounds", "2", "--max-executions", "1"]
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("exceeding --max-executions=1", result.stderr)
        self.assertFalse(output.exists())

    def test_source_sha_must_match_head_before_creating_output(self):
        output = self.directory / "source-sha-mismatch"
        command = self.command(output)
        command[command.index("--source-sha") + 1] = "f" * 40
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("--source-sha must match the checked-out HEAD commit", result.stderr)
        self.assertFalse(output.exists())

    def test_baseline_sha_must_resolve_before_creating_output(self):
        output = self.directory / "baseline-sha-missing"
        command = self.command(output)
        command[command.index("--baseline-sha") + 1] = "f" * 40
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("--baseline-sha must resolve to a locally available commit", result.stderr)
        self.assertFalse(output.exists())

    def test_dry_run_prints_resolved_plan_without_creating_output(self):
        output = self.directory / "dry-run"
        command = self.command(output) + ["--dry-run"]
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        plan = json.loads(result.stdout)
        self.assertEqual(plan["execution_count"], 1)
        self.assertEqual(plan["scenarios"], ["equal-step"])
        self.assertFalse(output.exists())


class HardHardAttemptSchemaCompatibilityTests(unittest.TestCase):
    """Schema-2 compatibility controls; Rust owns failure-class selection."""

    def report(self, failure_class: str, terminal_reason: str = "no_authenticated_direct_confirmation"):
        scenario = MATRIX_RUNNER.SCENARIO_BY_NAME["equal-step"]
        return {
            "schema_version": 2,
            "source_git_commit": SOURCE_SHA,
            "baseline_git_commit": BASELINE_SHA,
            "scenario_id": scenario.name,
            "seed": scenario.seed,
            "build_id": "test-build",
            "role": "initiator",
            "mode": "predictable",
            "session_tag": "0123456789abcdef",
            "plan_tag": "fedcba9876543210",
            "network_generation": 1,
            "peer_session_generation": 2,
            "remote_candidate_epoch": 3,
            "local_profile_generation": 4,
            "remote_profile_generation": 5,
            "punch_generation": 6,
            "socket_index": 4096,
            "attempt": 1,
            "candidate_cap": 32,
            "counts": {
                "requested": 2, "generated": 2, "unique": 1, "advertised": 1,
                "parsed_targets_for_plan": 1, "planned_targets": 1, "planned_sockets": 1,
                "planned_socket_target_combinations": 1,
                "planned_logical_probes": 2, "planned_physical_datagram_cap": 4,
                "attempted_targets": 1, "logical_probes_attempted": 1,
                "logical_probes_sent": 1, "send_success_datagrams": 2,
                "send_success_bytes": 120, "send_errors": 0, "send_error_bytes": 0,
                "budget_skipped": 0, "planned_logical_probes_not_attempted": 1,
                "stun_send_success_datagrams": 3, "stun_send_success_bytes": 60,
                "stun_send_errors": 0, "stun_send_error_bytes": 0, "stun_responses": 3,
                "candidate_signal_payload_logic_bytes": 48,
            },
            "timeline": {
                "planned_send_at_ms": 3500, "actual_first_send_at_ms": 3502,
                "schedule_deviation_ms": 2,
                "encrypted_validation_completed_at_ms": None,
                "last_probe_hit_to_validation_ms": None,
            },
            "target_order_tags": ["fedcba9876543210"],
            "confirmed_target_rank": None,
            "direct_confirmed": False,
            "failure_class": failure_class,
            "terminal_reason": terminal_reason,
        }

    def validate(self, report):
        scenario = MATRIX_RUNNER.SCENARIO_BY_NAME["equal-step"]
        return MATRIX_RUNNER.validate_attempt(
            report, "a", scenario, scenario.seed, SOURCE_SHA, BASELINE_SHA,
            {"path": "unknown"}, None, None, "not_attributable:attempt_identity_missing",
        )

    def aggregate(self, attempts, *, incomplete=False, extra_rounds=None):
        record = {
            "result": "invalid" if incomplete else "valid",
            "first_usable_path": "unknown",
            "direct_within_protection": False,
            "final_path_a": None,
            "final_path_b": None,
            "cleanup": {"duration_ms": 12},
            "partial_attempts" if incomplete else "attempts": attempts,
        }
        return MATRIX_RUNNER.aggregate_runs([{
            "exit_code": 1 if incomplete else 0,
            "rounds": [record, *(extra_rounds or [])],
        }])

    def test_schema2_execution_incomplete_and_unknown_keep_missing_work_unknown(self):
        for failure_class in ("execution_incomplete", "unknown"):
            with self.subTest(failure_class=failure_class):
                raw = self.report(failure_class, "probe_path_error")
                attempt = self.validate(raw)
                summary = self.aggregate([attempt])
                self.assertEqual(attempt["experiment_outcome_class"], failure_class)
                self.assertEqual(summary["attempt_failure_classes"], {failure_class: 1})
                self.assertEqual(summary["direct_within_protection_rounds"], 0)
                self.assertEqual(summary["final_direct_rounds"], 0)
                self.assertIsNone(attempt["timeline"]["first_business_success_at_ms"])
                self.assertEqual(
                    summary["costs"]["all_requested"]["planned_minus_attempted_by_reason"],
                    {"unknown": 1},
                )
                self.assertEqual(attempt["counts"], raw["counts"])

    def test_schema2_partial_budget_preserves_successful_handoff_costs_once(self):
        raw = self.report("budget_rejected")
        raw["counts"]["budget_skipped"] = 1
        attempt = self.validate(raw)
        summary = self.aggregate([attempt])
        costs = summary["costs"]["all_requested"]
        self.assertEqual(summary["attempt_failure_classes"], {"budget_rejected": 1})
        self.assertEqual(costs["known_observed_costs"]["probe_datagrams"], 2)
        self.assertEqual(costs["known_observed_costs"]["probe_bytes"], 120)
        self.assertEqual(costs["known_observed_costs"]["budget_skipped"], 1)
        self.assertEqual(costs["planned_minus_attempted_by_reason"], {"budget_rejected": 1})
        self.assertEqual(sum(costs["planned_minus_attempted_by_reason"].values()), 1)

    def test_schema2_stale_and_deadline_preserve_terminal_reason_attribution(self):
        for failure_class, terminal_reason, cause in (
            ("cancelled_generation_changed", "socket_revoked", "lifecycle_invalidated"),
            ("missed_schedule", "deadline", "expired"),
        ):
            with self.subTest(failure_class=failure_class):
                raw = self.report(failure_class, terminal_reason)
                attempt = self.validate(raw)
                summary = self.aggregate([attempt])
                self.assertEqual(summary["attempt_failure_classes"], {failure_class: 1})
                self.assertEqual(summary["attempt_terminal_reasons"], {terminal_reason: 1})
                costs = summary["costs"]["all_requested"]
                self.assertEqual(costs["planned_minus_attempted_by_reason"], {cause: 1})
                self.assertEqual(costs["known_observed_costs"]["probe_datagrams"], 2)
                self.assertEqual(attempt["counts"], raw["counts"])

    def test_schema2_mixed_causes_do_not_duplicate_or_guess_missing_work(self):
        raw = self.report("execution_incomplete", "probe_path_error")
        raw["counts"].update({
            "planned_logical_probes": 4, "planned_physical_datagram_cap": 8,
            "logical_probes_attempted": 2, "planned_logical_probes_not_attempted": 2,
            "budget_skipped": 1, "send_errors": 1, "send_error_bytes": 60,
        })
        attempt = self.validate(raw)
        summary = self.aggregate([attempt])
        costs = summary["costs"]["all_requested"]
        self.assertEqual(costs["planned_minus_attempted_by_reason"], {"unknown": 2})
        self.assertEqual(costs["known_observed_costs"]["budget_skipped"], 1)
        self.assertEqual(costs["known_observed_costs"]["probe_send_errors"], 1)
        self.assertEqual(costs["known_observed_costs"]["probe_datagrams"], 2)
        self.assertEqual(costs["known_observed_costs"]["probe_bytes"], 120)
        self.assertEqual(summary["attempt_count"], 1)
        self.assertEqual(attempt["counts"], raw["counts"])

    def test_schema2_direct_confirmation_only_accepts_encrypted_validation_completed(self):
        for failure_class in (
            "execution_incomplete", "budget_rejected", "cancelled_generation_changed",
            "missed_schedule", "send_error", "unknown", "no_response",
        ):
            with self.subTest(failure_class=failure_class):
                raw = self.report(failure_class, "direct_confirmed")
                raw["direct_confirmed"] = True
                raw["confirmed_target_rank"] = 0
                raw["timeline"]["encrypted_validation_completed_at_ms"] = 3520
                with self.assertRaisesRegex(MATRIX_RUNNER.EvidenceError, "success_class_mismatch"):
                    self.validate(raw)
        raw["failure_class"] = "encrypted_validation_completed"
        attempt = self.validate(raw)
        self.assertTrue(attempt["direct_confirmed"])
        self.assertEqual(attempt["failure_class"], "encrypted_validation_completed")
        self.assertEqual(attempt["counts"], raw["counts"])

    def test_schema2_partial_cost_fields_stay_unknown_and_keep_requested_denominator(self):
        raw = self.report("execution_incomplete", "probe_path_error")
        self.validate(raw)
        del raw["counts"]["send_success_bytes"]
        with self.assertRaisesRegex(MATRIX_RUNNER.EvidenceError, "counts_send_success_bytes"):
            self.validate(raw)
        scenario = MATRIX_RUNNER.SCENARIO_BY_NAME["equal-step"]
        with tempfile.TemporaryDirectory() as directory:
            round_dir = Path(directory)
            (round_dir / "node-a.status.json").write_text(json.dumps({"peers": [{
                "direct_events": [{"stage": "hard_hard_attempt_report", "hard_hard_attempt": raw}],
            }]}), encoding="utf-8")
            attempts, errors = MATRIX_RUNNER.extract_partial_attempt_reports(
                round_dir, scenario, scenario.seed, SOURCE_SHA, BASELINE_SHA,
            )
        self.assertEqual(errors, ["b_status_missing"])
        summary = self.aggregate(attempts, incomplete=True, extra_rounds=[{
            "result": "invalid", "partial_attempts": [],
        }])
        self.assertEqual(summary["requested_rounds"], 2)
        self.assertEqual(summary["invalid_rounds"], 2)
        self.assertEqual(summary["valid_only_attempt_count"], 0)
        self.assertEqual(summary["attempt_failure_classes"], {"execution_incomplete": 1})
        costs = summary["costs"]["all_requested"]
        self.assertEqual(costs["observed_attempt_reports"], 1)
        self.assertEqual(costs["requested_rounds_without_attempt_costs"], 1)
        self.assertEqual(costs["known_observed_costs"]["probe_datagrams"], 2)
        self.assertEqual(costs["known_observed_costs"]["probe_bytes"], 0)
        self.assertEqual(costs["unknown_field_counts"]["probe_bytes"], 1)
        self.assertEqual(costs["planned_minus_attempted_by_reason"], {"unknown": 1})
        self.assertEqual(costs["confirmation_costs"]["complete_attempt_reports"], 0)


class HardHardConfirmationCostsTests(unittest.TestCase):
    def test_old_and_partial_reports_keep_missing_confirmation_costs_unknown(self):
        confirmation = {
            purpose: {"datagrams": 1, "bytes": 80}
            for purpose in (
                "triggered_check", "nomination", "probe_ack", "validation_request", "validation_ack"
            )
        }
        confirmation.update({
            "retryable_not_sent": 0, "budget_deferred": 2, "delivery_unknown": 0, "stopped": 0
        })
        reports = [
            {"confirmation": confirmation},
            {},
            {"confirmation": {"probe_ack": {"datagrams": True, "bytes": -1}}},
        ]
        summary = MATRIX_RUNNER.confirmation_cost_summary(reports)
        self.assertEqual(summary["observed_attempt_reports"], 3)
        self.assertEqual(summary["complete_attempt_reports"], 1)
        self.assertEqual(summary["known_observed_costs"]["probe_ack_datagrams"], 1)
        self.assertEqual(summary["known_observed_costs"]["validation_request_bytes"], 80)
        self.assertEqual(summary["known_observed_costs"]["budget_deferred"], 2)
        self.assertEqual(summary["unknown_field_counts"]["probe_ack_datagrams"], 2)
        self.assertEqual(summary["unknown_field_counts"]["probe_ack_bytes"], 2)
        self.assertEqual(summary["unknown_field_counts"]["nomination_bytes"], 2)

    def test_confirmation_does_not_spend_or_inflate_the_sweep_datagram_cap(self):
        attempt = {
            "counts": {"send_success_datagrams": 4, "planned_physical_datagram_cap": 4},
            "confirmation": {"nomination": {"datagrams": 3, "bytes": 240}},
        }
        summary = MATRIX_RUNNER.cost_summary([], [attempt])
        self.assertEqual(summary["probe_cost_scope"], "sweep_only")
        self.assertEqual(summary["known_observed_costs"]["probe_datagrams"], 4)
        confirmation = summary["confirmation_costs"]
        self.assertEqual(confirmation["known_observed_costs"]["nomination_datagrams"], 3)
        self.assertEqual(confirmation["unknown_field_counts"]["validation_ack_bytes"], 1)
        self.assertEqual(confirmation["complete_attempt_reports"], 0)


if __name__ == "__main__":
    unittest.main()
