"""Frozen schedules, paired seeds, failure denominators and evidence fences."""

import copy
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import textwrap
import time
import unittest
from unittest.mock import patch
import subprocess

import benchmark_campaign as campaign


class BenchmarkCampaignTests(unittest.TestCase):
    def setUp(self):
        self.plan = campaign.build_plan(["strict-normal"], 3, 100, 2)

    def record(self, batch, variant="baseline", success=True):
        changes, options = campaign.MATRIX.SCENARIOS[batch["scenario"]]
        rows = [{"scenario": batch["scenario"], "repetition": index + 1,
                 "seed_base": seed, "actual_nat_seed": seed + 1,
                 "valid": success, "exit_code": 0 if success else 1,
                 "errors": [] if success else ["smoke_exit:1"],
                 "environment_overrides": changes, "network_profile": {"schema_version": 1, **options}}
                for index, seed in enumerate(batch["seed_bases"])]
        return {"variant": variant, "batch_id": batch["id"], "exit_code": 0,
                "manifest": {"schema_version": 1, "valid": success, "scope": self.plan["scope"], "retries": 0,
                             "source": {"commit": "a" * 40, "patch_sha256": "b" * 64},
                             "requested_runs": batch["rounds"], "runs": rows}}

    def test_hundred_rounds_are_disjoint_bounded_batches_with_paired_variants(self):
        plan = campaign.build_plan(["strict-normal", "udp-queue-pressure"], 100, 50, 32)
        self.assertEqual(plan["requested_per_variant"], 200)
        self.assertEqual(len(plan["batches"]), 8)
        seeds = [seed for batch in plan["batches"] for seed in batch["seed_bases"]]
        self.assertEqual(len(seeds), len(set(seeds)))
        for batch in plan["batches"]:
            self.assertLessEqual(batch["rounds"], 32)
            index = list(campaign.MATRIX.SCENARIOS).index(batch["scenario"])
            self.assertEqual(batch["seed_bases"][0], batch["runner_seed"] + index * 100)
        campaign.validate_plan(json.loads(json.dumps(plan)))

    def test_failure_missing_batch_and_timeout_stay_in_requested_denominator(self):
        failed = self.record(self.plan["batches"][0], success=False)
        failed["manifest"]["runs"][0].update(valid=True, exit_code=0, errors=[])
        failed["manifest"]["runs"][1]["exit_code"] = 124
        summary = campaign.summarize(self.plan, [failed])
        baseline = summary["variants"]["baseline"]
        self.assertEqual(baseline["requested"], 3)
        self.assertEqual(baseline["successful_valid_smoke_rounds"], 1)
        self.assertEqual(baseline["failed_or_incomplete"], 1)
        self.assertEqual(baseline["missing"], 1)
        self.assertEqual(baseline["success_fraction_of_requested"], 1 / 3)
        self.assertFalse(summary["complete"])
        self.assertIsNone(baseline["direct_at_10s"])
        self.assertIsNone(baseline["first_business_ms"])

    def test_partial_or_absent_manifest_does_not_erase_failed_runs(self):
        partial = self.record(self.plan["batches"][0])
        partial["manifest"]["runs"].pop()
        partial["manifest"]["valid"] = False
        missing = self.record(self.plan["batches"][1])
        missing["manifest"] = None
        summary = campaign.summarize(self.plan, [partial, missing])
        baseline = summary["variants"]["baseline"]
        self.assertEqual(baseline["accounted"], 3)
        self.assertEqual(baseline["successful_valid_smoke_rounds"], 1)
        self.assertEqual(baseline["failed_or_incomplete"], 2)

    def test_duplicate_batch_cannot_inflate_success(self):
        record = self.record(self.plan["batches"][0])
        with self.assertRaisesRegex(ValueError, "duplicate"):
            campaign.summarize(self.plan, [record, copy.deepcopy(record)])

    def test_source_changed_between_batches_is_rejected(self):
        records = [self.record(batch) for batch in self.plan["batches"]]
        records[1]["manifest"]["source"]["patch_sha256"] = "c" * 64
        with self.assertRaisesRegex(ValueError, "source changed"):
            campaign.summarize(self.plan, records)

    def test_seed_outcome_scope_and_retry_mismatches_fail_closed(self):
        changes = [lambda value: value["manifest"]["runs"][0].update(seed_base=999),
                   lambda value: value["manifest"]["runs"][0].update(valid=1),
                   lambda value: value["manifest"]["runs"][0].update(actual_nat_seed=999),
                   lambda value: value["manifest"].update(scope="public_nat"),
                   lambda value: value["manifest"].update(retries=1)]
        for change in changes:
            record = self.record(self.plan["batches"][0])
            change(record)
            with self.subTest(record=record), self.assertRaises(ValueError):
                campaign.summarize(self.plan, [record])

    def test_plan_tamper_and_capacity_overrides_are_rejected(self):
        altered = copy.deepcopy(self.plan)
        altered["batches"][0]["seed_bases"][0] += 1
        with self.assertRaisesRegex(ValueError, "frozen"):
            campaign.validate_plan(altered)
        for rounds, seed, size in [(0, 1, 1), (1001, 1, 1), (1, -1, 1), (1, 1, 33)]:
            with self.subTest(rounds=rounds, seed=seed, size=size), self.assertRaises(ValueError):
                campaign.build_plan(["strict-normal"], rounds, seed, size)

    def test_wilson_boundaries_are_finite_and_nontrivial(self):
        self.assertIsNone(campaign.wilson(0, 0))
        lower, upper = campaign.wilson(0, 30)
        self.assertAlmostEqual(lower, 0)
        self.assertGreater(upper, 0)
        lower, upper = campaign.wilson(30, 30)
        self.assertLess(lower, 1)
        self.assertAlmostEqual(upper, 1)

    def test_plan_cli_never_overwrites_previous_schedule(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plan.json"
            arguments = ["plan", "--scenario", "strict-normal", "--rounds", "100", "--output", str(path)]
            self.assertEqual(campaign.main(arguments), 0)
            original = path.read_bytes()
            with self.assertRaises(SystemExit):
                campaign.main(arguments)
            self.assertEqual(path.read_bytes(), original)

    def test_run_retains_timeout_and_partial_manifest_and_collect_checks_raw_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            plan_path, output = root / "plan.json", root / "baseline"
            campaign.save(plan_path, self.plan)
            source = self.record(self.plan["batches"][0])["manifest"]["source"]

            class FakeProcess:
                pid = 987654

                def __init__(inner, command, **kwargs):
                    inner.interrupted = False
                    batch_output = Path(command[-1])
                    batch_output.mkdir()
                    batch = next(item for item in self.plan["batches"] if item["id"] == batch_output.name)
                    manifest = self.record(batch)["manifest"]
                    if batch == self.plan["batches"][0]:
                        manifest["runs"].pop()
                        manifest["valid"] = False
                        inner.interrupted = True
                    for index, row in enumerate(manifest["runs"]):
                        profile = batch_output / f"{row['scenario']}-{index + 1}.profile.json"
                        campaign.save(profile, row["network_profile"])
                        row.update(profile=str(profile), profile_sha256=campaign.digest(profile.read_bytes()))
                    campaign.save(batch_output / "manifest.json", manifest)
                    self.assertEqual(kwargs["cwd"], campaign.ROOT)
                    self.assertTrue(kwargs["start_new_session"])

                def wait(inner, timeout=None):
                    if inner.interrupted:
                        inner.interrupted = False
                        raise subprocess.TimeoutExpired("fake", timeout)
                    return 0

            with patch.object(campaign.MATRIX, "source_identity", return_value=source), \
                    patch.object(campaign, "harness_identity", return_value=self.plan["harness"]), \
                    patch.object(campaign.subprocess, "Popen", FakeProcess), \
                    patch.object(campaign.os, "killpg") as kill:
                self.assertEqual(campaign.run_campaign(plan_path, "baseline", output), 1)
                kill.assert_called_once_with(FakeProcess.pid, campaign.signal.SIGINT)
            records = campaign.collect_campaign(output / "campaign.json", self.plan, campaign.digest(plan_path.read_bytes()))
            self.assertEqual(records[0]["exit_code"], 124)
            summary = campaign.load_json(output / "summary.json")["variants"]["baseline"]
            self.assertEqual(summary["successful_valid_smoke_rounds"], 2)
            self.assertEqual(summary["failed_or_incomplete"], 1)
            self.assertEqual(summary["failed_batches"], 1)
            self.assertFalse(summary["execution_succeeded"])
            raw_manifest = output / self.plan["batches"][0]["id"] / "manifest.json"
            original = raw_manifest.read_text()
            raw_manifest.write_text(original + " ")
            with self.assertRaisesRegex(ValueError, "digest"):
                campaign.collect_campaign(output / "campaign.json", self.plan, campaign.digest(plan_path.read_bytes()))
            raw_manifest.write_text(original)
            profile = Path(records[0]["manifest"]["runs"][0]["profile"])
            profile.write_text(profile.read_text() + " ")
            with self.assertRaisesRegex(ValueError, "raw network profile"):
                campaign.collect_campaign(output / "campaign.json", self.plan, campaign.digest(plan_path.read_bytes()))

    def test_different_checkout_harness_is_rejected_before_creating_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan_path, output = root / "plan.json", root / "candidate"
            campaign.save(plan_path, self.plan)
            with patch.object(campaign, "harness_identity", side_effect=[self.plan["harness"], {}]):
                with self.assertRaisesRegex(ValueError, "harness"):
                    campaign.run_campaign(plan_path, "candidate", output)
            self.assertFalse(output.exists())

    def test_source_changed_manifest_cannot_count_valid_rows_as_success(self):
        record = self.record(self.plan["batches"][0])
        record["manifest"]["source_changed"] = True
        value = campaign.summarize(self.plan, [record])["variants"]["baseline"]
        self.assertEqual(value["successful_valid_smoke_rounds"], 0)
        self.assertEqual(value["failed_or_incomplete"], 2)

    def test_contradictory_schema_validity_errors_or_frozen_profile_are_rejected(self):
        changes = [lambda value: value["manifest"].update(schema_version=999),
                   lambda value: value["manifest"].update(valid=False),
                   lambda value: value["manifest"].update(retries=False),
                   lambda value: value["manifest"]["runs"][0].update(errors=["source_changed_during_case"]),
                   lambda value: value["manifest"]["runs"][0].update(environment_overrides={"MODE": "forced"}),
                   lambda value: value["manifest"]["runs"][0].update(network_profile={"schema_version": 999}),
                   lambda value: value["manifest"]["source"].update(commit="a" * 41),
                   lambda value: value["manifest"]["source"].update(patch_sha256=123)]
        for change in changes:
            record = self.record(self.plan["batches"][0])
            change(record)
            with self.subTest(record=record), self.assertRaises(ValueError):
                campaign.summarize(self.plan, [record])

    def test_nonzero_batch_exit_cannot_be_declared_successful_even_with_complete_valid_rows(self):
        records = [self.record(batch) for batch in self.plan["batches"]]
        records[-1]["exit_code"] = 124
        baseline = campaign.summarize(self.plan, records)["variants"]["baseline"]
        self.assertEqual(baseline["successful_valid_smoke_rounds"], 3)
        self.assertEqual(baseline["failed_batches"], 1)
        self.assertFalse(baseline["execution_succeeded"])

    def test_maximum_campaign_index_does_not_duplicate_raw_manifests(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "campaign.json"
            raw_manifest = {"large_diagnostic": "x" * 20_000}
            records = [{"variant": "baseline", "batch_id": str(index), "exit_code": 1,
                        "manifest_path": str(index) + "/manifest.json",
                        "manifest_sha256": "a" * 64, "manifest": raw_manifest}
                       for index in range(campaign.contract()["max_campaign_executions_per_variant"])]
            campaign.save_campaign(path, {"records": records})
            self.assertLess(path.stat().st_size, 16 * 1024 * 1024)
            stored = campaign.load_json(path)["records"]
            self.assertEqual(len(stored), 10_000)
            self.assertNotIn("manifest", stored[0])

    @unittest.skipUnless(os.name == "posix", "requires POSIX process groups")
    def test_real_timeout_reaps_independent_smoke_group_even_with_inherited_ignored_sigint(self):
        real_popen = subprocess.Popen
        for disposition in (signal.default_int_handler, signal.SIG_IGN):
            with self.subTest(ignored=disposition == signal.SIG_IGN), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                plan = campaign.build_plan(["strict-normal"], 1, 100, 1)
                plan_path, output = root / "plan.json", root / "baseline"
                campaign.save(plan_path, plan)
                source = {"commit": "a" * 40, "patch_sha256": "b" * 64}
                stub = root / "matrix.py"
                stub.write_text(textwrap.dedent('''\
                    import json, os, signal, subprocess, sys
                    from pathlib import Path
                    output = Path(sys.argv[sys.argv.index("--output") + 1])
                    output.mkdir()
                    child = subprocess.Popen(
                        [sys.executable, "-c", "import time; time.sleep(30)"],
                        start_new_session=True,
                    )
                    try:
                        (output / "ready.json").write_text(json.dumps({
                            "matrix_pid": os.getpid(), "smoke_pid": child.pid,
                            "smoke_pgid": os.getpgid(child.pid),
                            "sigint_ignored": signal.getsignal(signal.SIGINT) == signal.SIG_IGN,
                        }))
                        child.wait(timeout=30)
                    except KeyboardInterrupt:
                        os.killpg(child.pid, signal.SIGTERM)
                        child.wait(timeout=2)
                        (output / "reaped.json").write_text(json.dumps({
                            "smoke_pid": child.pid, "returncode": child.returncode,
                        }))
                    finally:
                        if child.poll() is None:
                            os.killpg(child.pid, signal.SIGKILL)
                            child.wait(timeout=2)
                    '''), encoding="utf-8")
                batch_output = output / plan["batches"][0]["id"]
                processes = []

                class RealTimeoutProcess:
                    def __init__(inner, command, **kwargs):
                        # Keep the production Python/runpy/signal wrapper;
                        # replace only its matrix script with a light fixture.
                        runner = str(campaign.ROOT / campaign.RUNNER.relative_to(campaign.ROOT))
                        actual = [str(stub) if argument == runner else argument for argument in command]
                        inner.process = real_popen(actual, **kwargs)
                        inner.pid = inner.process.pid
                        inner.first_wait = True
                        processes.append(inner.process)

                    def wait(inner, timeout=None):
                        if inner.first_wait:
                            inner.first_wait = False
                            deadline = time.monotonic() + 5
                            while not (batch_output / "ready.json").exists():
                                if inner.process.poll() is not None or time.monotonic() >= deadline:
                                    raise AssertionError("matrix fixture did not create its smoke group")
                                time.sleep(0.01)
                            raise subprocess.TimeoutExpired("matrix fixture", timeout)
                        return inner.process.wait(timeout=min(timeout, 5) if timeout else 5)

                previous = signal.signal(signal.SIGINT, disposition)
                try:
                    with patch.object(campaign.MATRIX, "source_identity", return_value=source), \
                            patch.object(campaign, "harness_identity", return_value=plan["harness"]), \
                            patch.object(campaign.subprocess, "Popen", RealTimeoutProcess):
                        self.assertEqual(campaign.run_campaign(plan_path, "baseline", output), 1)
                    ready = campaign.load_json(batch_output / "ready.json")
                    reaped = campaign.load_json(batch_output / "reaped.json")
                    self.assertFalse(ready["sigint_ignored"])
                    self.assertNotEqual(ready["matrix_pid"], ready["smoke_pgid"])
                    self.assertEqual(reaped["smoke_pid"], ready["smoke_pid"])
                    self.assertEqual(reaped["returncode"], -signal.SIGTERM)
                    with self.assertRaises(ProcessLookupError):
                        os.kill(ready["smoke_pid"], 0)
                    stored = campaign.load_json(output / "campaign.json")
                    self.assertEqual(stored["records"][0]["exit_code"], 124)
                    summary = campaign.load_json(output / "summary.json")["variants"]["baseline"]
                    self.assertEqual(summary["failed_batches"], 1)
                    self.assertFalse(summary["execution_succeeded"])
                finally:
                    signal.signal(signal.SIGINT, previous)
                    # Even a failed regression must not leave fixture groups.
                    for process in processes:
                        if process.poll() is None:
                            os.killpg(process.pid, signal.SIGKILL)
                        process.wait(timeout=2)
                    if (batch_output / "ready.json").exists():
                        smoke_pid = campaign.load_json(batch_output / "ready.json")["smoke_pid"]
                        try:
                            os.killpg(smoke_pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass


if __name__ == "__main__":
    unittest.main()
