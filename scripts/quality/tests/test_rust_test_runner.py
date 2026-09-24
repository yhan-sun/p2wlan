import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import run_rust_tests as runner


class RustTestRunnerTests(unittest.TestCase):
    def test_exact_selector_does_not_accept_prefix_match(self):
        names = ["transport::tests::key", "transport::tests::key_collision"]
        self.assertEqual(runner.select_tests(names, names[0], True), [names[0]])

    def test_stale_module_path_fails_closed(self):
        with self.assertRaises(runner.TestSelectionError):
            runner.select_tests(["dplpmtud::runtime::tests::base"], "dplpmtud::tests::base", True)

    def test_substring_selection_is_sorted_and_unique(self):
        self.assertEqual(runner.select_tests(["b::hard_hard_case", "a::hard_hard_case", "b::hard_hard_case"], "hard_hard_", False), ["a::hard_hard_case", "b::hard_hard_case"])

    def test_ignored_only_selection_fails_closed(self):
        with self.assertRaises(runner.TestSelectionError):
            runner.select_tests(["live"], "live", True, ["live"])

    def test_ignored_tests_are_not_counted_as_executed(self):
        self.assertEqual(runner.select_tests(["scope::normal", "scope::live"], "scope", False, ["scope::live"]), ["scope::normal"])

    def test_harness_list_does_not_count_summaries_or_benchmarks(self):
        self.assertEqual(runner.parse_test_names("module::case: test\nbench: benchmark\n1 test, 1 benchmark\n"), ["module::case"])

    def test_artifact_comes_from_cargo_not_directory_mtime(self):
        artifact = {"reason": "compiler-artifact", "target": {"kind": ["lib"]}, "profile": {"test": True}, "executable": "/tmp/current-test"}
        stale = {**artifact, "profile": {"test": False}, "executable": "/tmp/newer-non-test"}
        binary = {**artifact, "target": {"kind": ["bin"]}, "executable": "/tmp/unrelated-binary-test"}
        self.assertEqual(runner.test_executables([artifact, artifact, stale, binary, {}]), {Path("/tmp/current-test")})

    def test_zero_or_ignored_execution_is_not_success(self):
        with self.assertRaises(runner.TestSelectionError):
            runner.assert_executed("test result: ok. 0 passed; 0 failed; 1 ignored;", 1)

    def test_exact_execution_count_is_required(self):
        runner.assert_executed("test result: ok. 2 passed; 0 failed; 0 ignored;", 2)
        with self.assertRaises(runner.TestSelectionError):
            runner.assert_executed("test result: ok. 1 passed; 0 failed; 0 ignored;", 2)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "repo"
        self.root.mkdir()
        self.evidence = Path(self.temporary.name) / "evidence"
        self.binary = Path(self.temporary.name) / "daemon-tests"
        self.binary.write_bytes(b"test binary identity")
        self.test_names = [
            "maintenance_scheduler::test_preserves_owner",
            "maintenance_integration_tests::maintenance_rekey_loop_retries_binding_without_kick_and_preserves_business",
            "transport::tests::rekey_confirmation_survives_rotation",
            "transport::tests::ordinary_transport_path",
        ]
        self.ignored_names = ["maintenance_scheduler::ignored_platform_case"]

    def _source_identity(self, _root):
        return {
            "commit": "a" * 40,
            "dirty": True,
            "status_entry_count": 2,
            "status_sha256": "b" * 64,
            "worktree_patch_sha256": "c" * 64,
        }

    def _test_run_result(self, command, **_kwargs):
        selector = command[1]
        exact = "--exact" in command
        selected = [
            name
            for name in self.test_names
            if name == selector or (not exact and selector in name)
        ]
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=f"test result: ok. {len(selected)} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n",
            stderr="",
        )

    def _run_plan(self, plan, *, run_side_effect=None, list_side_effect=None):
        build = mock.Mock(return_value=self.binary)
        run = mock.Mock(side_effect=run_side_effect or self._test_run_result)
        listing = list_side_effect or (
            lambda _binary, ignored=False: self.ignored_names if ignored else self.test_names
        )
        with (
            mock.patch.object(runner, "build_test_binary", build),
            mock.patch.object(runner, "list_tests", side_effect=listing),
            mock.patch.object(runner.subprocess, "run", run),
            mock.patch.object(runner, "source_identity", side_effect=self._source_identity),
            mock.patch.object(
                runner,
                "toolchain_identity",
                return_value={"rustc_verbose": "test", "cargo": "test", "environment": {}},
            ),
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            result = runner.run_plan(
                self.root,
                "p2wlan-daemon",
                runner.parse_run_plan(json.dumps(plan)),
                self.evidence,
                60,
            )
        manifest = json.loads((self.evidence / "manifest.json").read_text())
        return result, manifest, build, run

    def test_grouped_plan_builds_once_and_repeats_exact_test_in_independent_processes(self):
        contention = self.test_names[1]
        result, manifest, build, run = self._run_plan(
            [
                {"name": "maintenance", "selector": "maintenance_"},
                {"name": "contention", "selector": contention, "exact": True, "repeat": 10},
                {"name": "existing-rekey", "selector": "rekey"},
            ]
        )
        self.assertEqual(result, 0)
        build.assert_called_once()
        self.assertEqual(run.call_count, 12)
        self.assertEqual(manifest["result"], "passed")
        self.assertTrue(manifest["source"]["dirty"])
        self.assertEqual(manifest["binary"]["sha256"], runner.sha256_file(self.binary))
        contention_group = manifest["groups"][1]
        self.assertEqual(contention_group["selected_tests"], [contention])
        self.assertEqual([entry["status"] for entry in contention_group["runs"]], ["passed"] * 10)
        self.assertEqual(len({entry["stdout_log"] for entry in contention_group["runs"]}), 10)
        self.assertTrue(all(entry["actual_executed"] == 1 for entry in contention_group["runs"]))
        self.assertEqual(manifest["groups"][0]["status"], "passed")
        self.assertEqual(manifest["groups"][2]["status"], "passed")
        self.assertEqual((self.evidence.stat().st_mode & 0o777), 0o700)
        self.assertEqual((self.evidence / "manifest.json").stat().st_mode & 0o777, 0o600)

    def test_empty_and_ignored_only_plan_groups_fail_before_any_test_runs(self):
        for selector, listing, message in (
            ("missing", None, "no tests matched"),
            (
                "ignored_platform_case",
                lambda _binary, ignored=False: self.ignored_names,
                "only ignored tests matched",
            ),
        ):
            with self.subTest(selector=selector):
                self.evidence = Path(self.temporary.name) / f"evidence-{selector}"
                result, manifest, build, run = self._run_plan(
                    [
                        {"name": "invalid-selection", "selector": selector},
                        {"name": "later", "selector": "rekey"},
                    ],
                    list_side_effect=listing,
                )
                self.assertEqual(result, 1)
                build.assert_called_once()
                run.assert_not_called()
                self.assertIn(message, manifest["groups"][0]["selection_error"])
                self.assertEqual(manifest["groups"][1]["status"], "not_run")
                self.assertEqual(manifest["groups"][0]["runs"][0]["status"], "not_run")

    def test_failed_repeat_marks_remaining_rounds_and_later_group_not_run(self):
        contention = self.test_names[1]
        calls = 0

        def fail_second_repeat(command, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 3:
                return subprocess.CompletedProcess(
                    command,
                    101,
                    stdout="test result: FAILED. 0 passed; 1 failed; 0 ignored;\n",
                    stderr="assertion failed\n",
                )
            return self._test_run_result(command, **kwargs)

        result, manifest, _build, run = self._run_plan(
            [
                {"name": "maintenance", "selector": "maintenance_"},
                {"name": "contention", "selector": contention, "exact": True, "repeat": 10},
                {"name": "existing-rekey", "selector": "rekey"},
            ],
            run_side_effect=fail_second_repeat,
        )
        self.assertEqual(result, 1)
        self.assertEqual(run.call_count, 3)
        self.assertEqual(manifest["groups"][1]["runs"][1]["status"], "failed")
        self.assertEqual(manifest["groups"][1]["runs"][1]["actual_executed"], 1)
        self.assertTrue(all(entry["status"] == "not_run" for entry in manifest["groups"][1]["runs"][2:]))
        self.assertEqual(manifest["groups"][2]["status"], "not_run")

    def test_timeout_is_not_pass_and_later_group_is_marked_not_run(self):
        command = [str(self.binary), "maintenance_", "--test-threads=1"]
        timeout = subprocess.TimeoutExpired(command, 60, output="partial output")
        result, manifest, _build, run = self._run_plan(
            [
                {"name": "maintenance", "selector": "maintenance_"},
                {"name": "existing-rekey", "selector": "rekey"},
            ],
            run_side_effect=timeout,
        )
        self.assertEqual(result, 1)
        self.assertEqual(manifest["groups"][0]["runs"][0]["status"], "timed_out")
        self.assertEqual(manifest["groups"][1]["status"], "not_run")
        self.assertEqual(run.call_count, 1)


if __name__ == "__main__":
    unittest.main()
