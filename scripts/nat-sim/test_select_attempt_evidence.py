import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import select_attempt_evidence as selector

RUN_ID = 424242


def artifact_name(kind, attempt, run_id=RUN_ID):
    if kind == "direct":
        return f"nat-topology-direct-{run_id}-{attempt}"
    index = kind.rsplit("-", 1)[1]
    return f"nat-topology-relay-{run_id}-{attempt}-{index}-of-5"


class SelectionTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name) / "artifacts"
        self.root.mkdir(parents=True)

    def tearDown(self):
        self._tmp.cleanup()

    def artifact(self, kind, attempt, *, run_id=RUN_ID, marker="x"):
        directory = self.root / artifact_name(kind, attempt, run_id)
        (directory / "round-1").mkdir(parents=True, exist_ok=True)
        (directory / "round-1" / "nat-evidence.json").write_text(marker, encoding="utf-8")
        return directory

    def all_kinds(self, attempt):
        for kind in selector.expected_scenarios():
            self.artifact(kind, attempt)

    def test_full_rerun_takes_the_current_attempt(self):
        self.all_kinds(1)
        self.all_kinds(2)
        chosen = selector.select(self.root, RUN_ID)
        self.assertEqual(set(chosen), set(selector.expected_scenarios()))
        for path in chosen.values():
            self.assertIn(f"-{RUN_ID}-2", path.name)

    def test_partial_rerun_keeps_the_newest_attempt_per_scenario(self):
        self.all_kinds(1)
        # only the direct scenario is re-run in attempt 2
        self.artifact("direct", 2)
        chosen = selector.select(self.root, RUN_ID)
        self.assertIn(f"-{RUN_ID}-2", chosen["direct"].name)
        self.assertIn(f"-{RUN_ID}-1", chosen["relay-blackhole-3"].name)

    def test_other_runs_are_ignored(self):
        self.all_kinds(1)
        self.artifact("direct", 9, run_id=RUN_ID + 1)
        chosen = selector.select(self.root, RUN_ID)
        self.assertIn(f"-{RUN_ID}-1", chosen["direct"].name)

    def test_attempts_beyond_the_current_one_are_ignored(self):
        self.all_kinds(1)
        self.artifact("direct", 7)
        chosen = selector.select(self.root, RUN_ID, max_attempt=3)
        self.assertIn(f"-{RUN_ID}-1", chosen["direct"].name)

    def test_missing_scenario_is_reported_with_the_kind(self):
        self.all_kinds(1)
        for entry in self.root.iterdir():
            if entry.name.startswith(f"nat-topology-relay-{RUN_ID}-1-4-of-5"):
                for child in sorted(entry.rglob("*"), reverse=True):
                    child.unlink() if child.is_file() else child.rmdir()
                entry.rmdir()
        with self.assertRaisesRegex(selector.SelectionError, "nat_evidence_missing:relay-blackhole-4"):
            selector.lay_out(self.root, Path(self._tmp.name) / "out", RUN_ID)

    def test_layout_keeps_exactly_one_copy_per_scenario(self):
        self.all_kinds(1)
        self.all_kinds(2)
        output = Path(self._tmp.name) / "out"
        selector.lay_out(self.root, output, RUN_ID)
        direct = sorted(p.name for p in (output / "direct").iterdir())
        relay = sorted(p.name for p in (output / "relay").iterdir())
        self.assertEqual(len(direct), 1, direct)
        self.assertEqual(len(relay), 5, relay)
        self.assertTrue((output / "direct" / direct[0] / "round-1" / "nat-evidence.json").is_file())

    def test_unrelated_artifact_names_are_ignored(self):
        self.all_kinds(1)
        (self.root / f"nat-topology-unit-{RUN_ID}").mkdir()
        (self.root / f"nat-topology-aggregate-{RUN_ID}-1").mkdir()
        chosen = selector.select(self.root, RUN_ID)
        self.assertEqual(set(chosen), set(selector.expected_scenarios()))

    def test_parse_rejects_a_different_run(self):
        self.assertIsNone(selector.parse_artifact(f"nat-topology-direct-{RUN_ID + 1}-1", RUN_ID))


if __name__ == "__main__":
    unittest.main()
