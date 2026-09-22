#!/usr/bin/env python3
"""Contract tests for the bounded Hard<->Hard matrix runner."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


RUNNER = Path(__file__).with_name("run-hard-hard-matrix.py")
SOURCE_SHA = "a" * 40
BASELINE_SHA = "b" * 40


FAKE_SMOKE = r'''
import json
import os
from pathlib import Path

root = Path(os.environ["NAT_SIM_ARTIFACT_DIR"])
root.mkdir(parents=True)
rounds = int(os.environ["ROUNDS"])
scenario = os.environ["EXPERIMENT_SCENARIO"]

def report(side, seed):
    value = {
        "schema_version": 1,
        "baseline_git_commit": os.environ["EXPERIMENT_BASELINE_SHA"],
        "source_git_commit": os.environ["NAT_TOPOLOGY_HEAD_SHA"],
        "build_id": "test-build",
        "experiment_variant": os.environ["EXPERIMENT_VARIANT"],
        "scenario_id": scenario,
        "seed": seed,
        "role": "initiator" if side == "a" else "responder",
        "mode": "predictable",
        "session_tag": "0123456789abcdef",
        "network_generation": 1,
        "peer_session_generation": 2,
        "remote_candidate_epoch": 3,
        "local_profile_generation": 4,
        "remote_profile_generation": 5,
        "punch_generation": 6,
        "socket_index": 4096,
        "attempt": 1,
        "counts": {
            "requested": 2,
            "generated": 2,
            "unique": 1,
            "advertised": 1,
            "received": 1,
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
            "cancelled_or_not_executed": 0,
            "stun_send_success_datagrams": 3,
            "stun_send_success_bytes": 60,
            "stun_send_errors": 0,
            "stun_send_error_bytes": 0,
            "stun_responses": 3,
            "candidate_signal_payload_bytes": 48,
        },
        "candidate_cap": 32,
        "truncation_reason": "none",
        "target_order_tags": ["fedcba9876543210"],
        "confirmed_target_rank": 0,
        "timeline": {
            "measurement_started_at_ms": 100,
            "last_measurement_send_at_ms": 120,
            "measurement_completed_at_ms": 140,
            "candidate_exchange_completed_at_ms": 180,
            "planned_send_at_ms": 3500,
            "send_dispatch_at_ms": 3501,
            "actual_first_send_at_ms": 3502,
            "probe_hit_at_ms": 3510,
            "encrypted_validation_completed_at_ms": 3520,
            "business_ready_at_ms": None,
            "first_business_success_at_ms": None,
            "measurement_age_at_send_ms": 3382,
            "schedule_deviation_ms": 2,
            "validation_duration_ms": 10,
            "time_to_first_business_ms": None,
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
                },
                {
                    "event": "business_ingress_observed",
                    "path": "direct",
                    "peer_id": peer_id,
                    "connection_generation": 1,
                    "at_ms": 3600,
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
        (round_dir / "nat-trace.jsonl").write_text('{"event":"mapped"}\n', encoding="utf-8")

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
        self.assertIn("random-high-entropy-negative", listed.stdout)

    def test_success_writes_schema_and_preserves_raw_evidence(self):
        output = self.directory / "success"
        result = subprocess.run(self.command(output), capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["schema_version"], 1)
        self.assertEqual(manifest["result"], "pass")
        self.assertEqual(manifest["source_head_sha"], SOURCE_SHA)
        self.assertEqual(manifest["summary"]["valid_rounds"], 1)
        self.assertEqual(manifest["summary"]["direct_within_protection_rounds"], 1)
        self.assertEqual(manifest["summary"]["attempt_count"], 2)
        self.assertEqual(manifest["summary"]["packet_cost"]["probe_datagrams"], 8)
        self.assertEqual(
            manifest["summary"]["candidate_execution"]["confirmed_target_in_plan_attempts"],
            2,
        )
        self.assertEqual(manifest["summary"]["cleanup_duration_ms"]["p95"], 12)
        attempts = manifest["runs"][0]["rounds"][0]["attempts"]
        self.assertEqual(attempts[0]["timeline"]["time_to_first_business_ms"], 80)
        self.assertEqual(attempts[0]["timeline"]["business_ready_at_ms"], 3550)
        self.assertEqual(attempts[0]["experiment_outcome_class"], "direct_business_succeeded")
        self.assertTrue((output / "raw/equal-step/round-1/nat-trace.jsonl").is_file())

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
        self.assertEqual(timeline["time_to_first_business_ms"], 80)

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

    def test_dry_run_prints_resolved_plan_without_creating_output(self):
        output = self.directory / "dry-run"
        command = self.command(output) + ["--dry-run"]
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        plan = json.loads(result.stdout)
        self.assertEqual(plan["execution_count"], 1)
        self.assertEqual(plan["scenarios"], ["equal-step"])
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
