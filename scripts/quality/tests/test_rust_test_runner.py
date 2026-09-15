import sys
import unittest
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


if __name__ == "__main__":
    unittest.main()
