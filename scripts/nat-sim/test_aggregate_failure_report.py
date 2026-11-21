"""Offline original codec/record and CLI controls; no simulator or daemon."""
from contextlib import redirect_stdout
import copy
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import aggregate_evidence as aggregate
import aggregate_failure_report as failure
import round_finalization as finalization
import test_nat_sim as original_controls


SOURCE = original_controls.NatEvidenceContractTests.SOURCE_SHA
WORKFLOW = original_controls.NatEvidenceContractTests.WORKFLOW_SHA


def fixture_set(root):
    factory = original_controls.NatEvidenceContractTests()
    paths = {}
    for topology, replicas in aggregate.EXPECTED_TOPOLOGIES.items():
        for replica in sorted(replicas):
            factory._write_record(root, topology, replica)
            old = root/f"record-{topology}-{replica}"
            name = "nat-topology-direct-42-1" if topology == "direct-cold-start" else f"nat-topology-relay-42-1-{replica}-of-5"
            target = root/name
            old.rename(target)
            paths[f"{topology}:replica-{replica}:round-1"] = target
    return paths


def legacy_failure(directory, cause="daemon_process_exited"):
    path = directory/"nat-attempts.json"
    history = json.loads(path.read_text())
    history["attempts"][0].update(exit_code=1, reason_codes=[cause],
                                   classification={"reason": "hard_line_reason", "retryable": False})
    history["final_adjudication"].update(result="fail", reason_code="hard_line_reason")
    path.write_text(json.dumps(history))
    value = {"schema_version": 1, "executed": True, "result": "fail", "nat_terminal": None,
             "decision": {"result": "fail", "reason_code": "harness:"+cause},
             "collector_observations": {"available": True, "reference": ".collector-nat-evidence.json"}}
    (directory/"nat-evidence.json").write_text(json.dumps(value))
    return value


def invoke(root, output, *, source=SOURCE, workflow=WORKFLOW, run=42, attempt=1):
    argv = ["--input-root", str(root), "--source-head-sha", source, "--workflow-sha", workflow,
            "--output", str(output)]
    if run is not None:
        argv += ["--github-run-id", str(run)]
    if attempt is not None:
        argv += ["--github-run-attempt", str(attempt)]
    with redirect_stdout(io.StringIO()):
        code = aggregate.main(argv)
    return code, json.loads(output.read_text())


class FailureAggregateControls(unittest.TestCase):
    def test_original_six_valid_schema2_controls_still_pass_cli(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture_set(root)
            code, report = invoke(root, root/"aggregate.json")
        self.assertEqual(code, 0)
        self.assertEqual(report["result"], "pass")
        self.assertEqual(report["executed_record_count"], 6)
        self.assertEqual(report["attempt_stats"]["diagnostic_retry_count"], 0)

    def test_schema1_failures_keep_six_denominator_without_relaxing_validator(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = fixture_set(root)
            value = legacy_failure(paths["relay-blackhole:replica-3:round-1"])
            legacy_failure(paths["relay-blackhole:replica-4:round-1"], "collector_record_invalid")
            with self.assertRaisesRegex(ValueError, "unknown_schema_version"):
                aggregate.validate_record(value, SOURCE, WORKFLOW, allow_failure=True)
            code, report = invoke(root, root/"aggregate.json")
            self.assertEqual((root/"aggregate.json").stat().st_mode & 0o777, 0o600)
        self.assertEqual(code, 1)
        self.assertEqual(report["result"], "fail")
        self.assertEqual(report["scenario_count"], 6)
        self.assertEqual(report["scenario_result_counts"], {"pass": 4, "fail": 2, "unknown": 0})
        self.assertEqual(report["executed_record_count"], 4)
        self.assertEqual(report["attempt_stats"]["diagnostic_retry_count"], 0)
        failed = [row for row in report["records"] if row["result"] == "fail"]
        self.assertTrue(all(row["nat_terminal"] is None and row["record_execution_verified"] is None for row in failed))
        self.assertTrue(all(row["collector_observations"]["original_reference_present"] is False for row in failed))
        self.assertTrue(all(row["exact_test_id"] is None for row in failed))

    def test_missing_root_is_unknown_fixed6_and_exclusive_output_cannot_erase_it(self):
        with tempfile.TemporaryDirectory() as directory:
            root, output = Path(directory)/"missing", Path(directory)/"aggregate.json"
            code, report = invoke(root, output)
            original = output.read_bytes()
            with self.assertRaises(FileExistsError):
                invoke(root, output)
            self.assertEqual(output.read_bytes(), original)
        self.assertEqual(code, 1)
        self.assertEqual(report["scenario_result_counts"], {"pass": 0, "fail": 0, "unknown": 6})
        self.assertEqual(report["executed_record_count"], 0)

    def test_projection_requires_same_source_workflow_run_and_selected_attempt(self):
        for mutation in ({"source": "3"*40}, {"workflow": "4"*40}, {"run": 43}, {"attempt": None}):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                paths = fixture_set(root)
                legacy_failure(paths["relay-blackhole:replica-3:round-1"])
                code, report = invoke(root, root/"aggregate.json", **mutation)
            row = next(row for row in report["records"] if row["replica"] == 3)
            self.assertEqual((code, row["result"], row["record_execution_verified"]), (1, "unknown", None))

    def test_future_attempt_conflicting_nested_identity_and_duplicate_history_are_unknown(self):
        for variant in ("future", "nested", "duplicate"):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                paths = fixture_set(root)
                current = paths["relay-blackhole:replica-3:round-1"]
                legacy_failure(current)
                if variant == "future":
                    current.rename(root/"nat-topology-relay-42-2-3-of-5")
                elif variant == "nested":
                    nested = current/"p2wlan-nat-topology-42-2-relay-3-attempt-1"
                    nested.mkdir()
                    for name in ("nat-evidence.json", "nat-attempts.json"):
                        (current/name).rename(nested/name)
                else:
                    duplicate = root/"duplicate"
                    duplicate.mkdir()
                    (duplicate/"nat-attempts.json").write_bytes((current/"nat-attempts.json").read_bytes())
                code, report = invoke(root, root/"aggregate.json")
            row = next(row for row in report["records"] if row["replica"] == 3)
            self.assertEqual((code, row["result"]), (1, "unknown"))

    def test_incomplete_projection_or_schema1_pass_cannot_be_success(self):
        for mutate in (lambda v: v.update(result="pass"), lambda v: v.pop("nat_terminal"),
                       lambda v: v.update(executed="true"), lambda v: v["decision"].update(reason_code="accepted")):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                paths = fixture_set(root)
                current = paths["relay-blackhole:replica-3:round-1"]
                value = legacy_failure(current)
                mutate(value)
                (current/"nat-evidence.json").write_text(json.dumps(value))
                code, report = invoke(root, root/"aggregate.json")
            row = next(row for row in report["records"] if row["replica"] == 3)
            self.assertEqual((code, row["result"]), (1, "unknown"))

    def test_malformed_or_wrong_current_record_preserves_failure_artifact(self):
        for text in ("{invalid", "[]", '{"schema_version":99}'):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                paths = fixture_set(root)
                (paths["relay-blackhole:replica-3:round-1"]/"nat-evidence.json").write_text(text)
                code, report = invoke(root, root/"aggregate.json")
            row = next(row for row in report["records"] if row["replica"] == 3)
            self.assertEqual((code, row["result"]), (1, "unknown"))
            self.assertEqual(report["scenario_count"], 6)

    def test_old_business_failure_cannot_be_masked_by_later_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            current = fixture_set(root)["relay-blackhole:replica-3:round-1"]
            path = current/"nat-attempts.json"
            history = json.loads(path.read_text())
            success = history["attempts"][0]
            old = copy.deepcopy(success)
            old.update(exit_code=1, classification={"retryable": False, "reason": "business_validation_failed"})
            success["attempt"] = 2
            history.update(attempts=[old, success])
            history["final_adjudication"]["attempt"] = 2
            path.write_text(json.dumps(history))
            code, report = invoke(root, root/"aggregate.json")
        row = next(row for row in report["records"] if row["replica"] == 3)
        self.assertEqual((code, row["result"], row["reason_code"]), (1, "unknown", "business_failure_masked_by_later_attempt"))

    def test_public_alias_is_same_original_bytes_digest_and_never_terminal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            value = {"schema_version": 2, "result": "pass", "source_head_sha": SOURCE}
            declaration = finalization.preserve_collector_observations(root, value, True)
            hidden, public = root/".collector-nat-evidence.json", root/"collector-nat-evidence.json"
            self.assertEqual(hidden.read_bytes(), public.read_bytes())
            self.assertEqual(declaration["sha256"], hashlib.sha256(public.read_bytes()).hexdigest())
            self.assertEqual(public.stat().st_mode & 0o777, 0o600)
            observed = failure.public_observations(root/"nat-evidence.json", {
                "collector_observations": {"reference": hidden.name}, "collector_public_observations": declaration}, root)
            self.assertTrue(observed["public_alias_digest_matches_declaration"])
            self.assertFalse(observed["used_as_terminal"])
            public.write_text('{"result":"pass"}')
            observed = failure.public_observations(root/"nat-evidence.json", {"collector_public_observations": declaration}, root)
            self.assertFalse(observed["public_alias_digest_matches_declaration"])

    def test_unverified_prior_record_gets_no_public_alias(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            declaration = finalization.preserve_collector_observations(root, {"result": "unknown"}, False)
            self.assertIsNone(declaration)
            self.assertTrue((root/".collector-nat-evidence.json").exists())
            self.assertFalse((root/"collector-nat-evidence.json").exists())

    def test_failure_projection_ignores_private_extra_fields_and_capacity_is_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = fixture_set(root)
            current = paths["relay-blackhole:replica-3:round-1"]
            legacy_failure(current)
            path = current/"nat-attempts.json"
            history = json.loads(path.read_text())
            history["private_argv"] = "private-secret"
            history["attempts"][0]["private_argv"] = "private-secret"
            path.write_text(json.dumps(history))
            code, report = invoke(root, root/"aggregate.json")
            self.assertEqual(code, 1)
            self.assertNotIn("private-secret", json.dumps(report))
            with patch.object(failure, "MAX_FILES", 2):
                code, bounded = invoke(root, root/"bounded.json")
            self.assertEqual(code, 1)
            self.assertTrue(bounded["input_capacity_exceeded"])
            self.assertEqual(bounded["scenario_result_counts"]["unknown"], 6)
            self.assertEqual(len(bounded["attempt_input_observations"]), 2)


if __name__ == "__main__":
    unittest.main()
