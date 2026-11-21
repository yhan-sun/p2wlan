#!/usr/bin/env python3
"""Offline aggregation tests, not Minecraft or real-network acceptance."""

import copy
from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest

import minecraft_interaction as interaction
import minecraft_interaction_summary as summary
from test_minecraft_interaction import MANIFEST_SHA, event, manifest, nonce, report


class SummaryTests(unittest.TestCase):
    def test_missing_rounds_stay_in_denominator_and_fixture_never_becomes_game_latency(self):
        plan = manifest(rounds=2)
        value = summary.summarize(plan, [report(plan)], MANIFEST_SHA)
        self.assertEqual(value["prescheduled_requests"], 4)
        self.assertEqual(value["reported_successes"], 2)
        self.assertEqual(value["reported_success_fraction"], .5)
        self.assertEqual(value["missing_rounds"], 1)
        self.assertEqual(value["status_counts"]["missing_evidence"], 2)
        self.assertEqual(value["fixture_latency_ms"]["sample_count"], 2)
        self.assertIsNone(value["application_interaction_ms"])
        self.assertFalse(value["all_round_reports_present"])
        self.assertEqual(len(value["rounds"][1]["requests"]), 2)

    def test_no_reports_accounts_for_all_rounds_without_inventing_success_or_rtt(self):
        plan = manifest(rounds=3)
        value = summary.summarize(plan, [], MANIFEST_SHA)
        self.assertEqual(value["status_counts"]["missing_evidence"], 6)
        self.assertEqual(value["fixture_latency_ms"]["sample_count"], 0)
        self.assertIsNone(value["fixture_latency_ms"]["p99"])

    def test_failed_observed_round_counts_as_present_and_keeps_success_conditional(self):
        plan = manifest()
        events = [event(plan, "session_ready", 0), event(plan, "action_started", 10),
                  event(plan, "action_confirmed", 15), event(plan, "action_started", 40, 1)]
        value = summary.summarize(plan, [report(plan, events)], MANIFEST_SHA)
        self.assertTrue(value["all_round_reports_present"])
        self.assertFalse(value["all_reported_actions_succeeded"])
        self.assertEqual(value["status_counts"]["timeout"], 1)
        self.assertEqual(value["reported_success_fraction"], .5)
        self.assertTrue(value["fixture_latency_ms"]["conditional_on_success"])
        self.assertEqual(value["fixture_latency_ms"]["p99"], .000005)

    def test_recorded_game_claim_remains_unverified_self_reported_with_no_path_inference(self):
        plan = manifest(edition="bedrock", execution_kind="recorded_game_session")
        value = summary.summarize(plan, [report(plan)], MANIFEST_SHA)
        self.assertEqual(value["transport"], "raknet_udp")
        self.assertIn("self_reported_latency_ms", value)
        self.assertNotIn("fixture_latency_ms", value)
        self.assertIsNone(value["application_interaction_ms"])
        self.assertIn("real_minecraft_execution", value["not_proven"])
        self.assertIn("current_direct_path", value["not_proven"])
        self.assertEqual(value["validation"], "offline_structure_only_not_authenticated_game_execution")

    def test_duplicate_foreign_round_and_changed_manifest_are_rejected(self):
        plan = manifest(rounds=2)
        valid = report(plan)
        other = copy.deepcopy(valid)
        other["round_nonce"] = nonce(999)
        changed = copy.deepcopy(valid)
        changed["manifest_sha256"] = "b" * 64
        for rows in ([valid, valid], [other], [changed], [valid, valid, valid]):
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                summary.summarize(plan, rows, MANIFEST_SHA)

    def test_strict_json_rejects_duplicate_keys_nonfinite_and_oversized_files(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.json"
            for raw in ('{"x":1,"x":2}', '{"x":NaN}', '[]'):
                path.write_text(raw)
                with self.subTest(raw=raw), self.assertRaises(ValueError):
                    interaction.read_json(path)
            with path.open("wb") as stream:
                stream.truncate(interaction.CONTRACT["max_input_bytes"] + 1)
            with self.assertRaisesRegex(ValueError, "byte limit"):
                interaction.read_json(path)

    def test_cli_binds_raw_manifest_and_reports_preserves_output_and_sets_private_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan_path, report_path, output = root / "plan.json", root / "round.json", root / "summary.json"
            plan = manifest()
            plan_path.write_text(json.dumps(plan))
            _, digest = interaction.read_json(plan_path)
            value = report(plan)
            value["manifest_sha256"] = digest
            report_path.write_text(json.dumps(value))
            args = ["--manifest", str(plan_path), "--report", str(report_path), "--output", str(output)]
            with redirect_stdout(io.StringIO()):
                self.assertEqual(summary.main(args), 0)
            result = json.loads(output.read_text())
            self.assertEqual(result["manifest_sha256"], digest)
            self.assertEqual(result["report_sha256"], [interaction.read_json(report_path)[1]])
            self.assertIsNone(result["application_interaction_ms"])
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            original = output.read_bytes()
            with redirect_stderr(io.StringIO()):
                self.assertEqual(summary.main(args), 2)
            self.assertEqual(output.read_bytes(), original)
            plan["identity"]["game_client_version"] = "another-version"
            plan_path.write_text(json.dumps(plan))
            with redirect_stderr(io.StringIO()):
                self.assertEqual(summary.main(args[:-1] + [str(root / "changed.json")]), 2)
            self.assertFalse((root / "changed.json").exists())

    def test_cli_missing_reports_is_explicit_and_output_cannot_enter_checkout(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan_path = root / "plan.json"
            plan_path.write_text(json.dumps(manifest()))
            output = root / "missing.json"
            args = ["--manifest", str(plan_path), "--output", str(output)]
            with redirect_stdout(io.StringIO()):
                self.assertEqual(summary.main(args), 0)
            self.assertEqual(json.loads(output.read_text())["status_counts"]["missing_evidence"], 2)
            checkout = root / "checkout"
            checkout.mkdir()
            (checkout / ".git").write_text("gitdir: elsewhere")
            with redirect_stderr(io.StringIO()):
                self.assertEqual(summary.main(args[:-1] + [str(checkout / "no.json")]), 2)
            self.assertFalse((checkout / "no.json").exists())


if __name__ == "__main__":
    unittest.main()
