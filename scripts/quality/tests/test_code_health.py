import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import check_code_health as health


class CodeHealthTests(unittest.TestCase):
    def test_production_boundary(self):
        limit = health.RUST_PRODUCTION_MAX_BYTES
        self.assertEqual(health.validate_sizes({"src/core.rs": limit}, {}), [])
        self.assertEqual(len(health.validate_sizes({"src/core.rs": limit + 1}, {})), 1)

    def test_test_file_boundary(self):
        limit = health.RUST_TEST_MAX_BYTES
        for path in ["src/tests.rs", "src/tests/scenario.rs", "tests/end_to_end.rs", "src/test_codec.rs"]:
            with self.subTest(path=path):
                self.assertEqual(health.validate_sizes({path: limit}, {}), [])
                self.assertEqual(len(health.validate_sizes({path: limit + 1}, {})), 1)

    def test_test_like_name_does_not_exempt_production(self):
        self.assertFalse(health.is_rust_test("src/testsupport/core.rs"))
        self.assertFalse(health.is_rust_test("src/latest.rs"))

    def test_legacy_growth_fails(self):
        self.assertEqual(len(health.validate_sizes({"src/old.rs": 200_001}, {"src/old.rs": 200_000})), 1)

    def test_legacy_shrink_passes(self):
        self.assertEqual(health.validate_sizes({"src/old.rs": 150_000}, {"src/old.rs": 200_000}), [])

    def test_regrowth_below_static_ceiling_still_fails(self):
        errors = health.validate_sizes({"src/old.rs": 160_000}, {"src/old.rs": 200_000}, {"src/old.rs": 150_000})
        self.assertEqual(len(errors), 1)
        self.assertIn("150000", errors[0])

    def test_smaller_reviewed_ceiling_also_applies(self):
        self.assertEqual(len(health.validate_sizes({"src/old.rs": 160_000}, {"src/old.rs": 155_000}, {"src/old.rs": 180_000})), 1)

    def test_new_legacy_file_is_rejected(self):
        errors = health.validate_sizes({"src/new.rs": 150_000}, {"src/new.rs": 150_000}, {})
        self.assertIn("no file in the base revision", errors[0])

    def test_missing_legacy_file_is_reported(self):
        self.assertIn("missing", health.validate_sizes({}, {"src/old.rs": 200_000})[0])

    def test_completed_split_must_remove_exception(self):
        errors = health.validate_sizes({"src/old.rs": 80}, {"src/old.rs": 200_000})
        self.assertIn("obsolete", errors[0])

    def test_crlf_does_not_change_budget(self):
        self.assertEqual(health.source_size(b"a\nb\n"), health.source_size(b"a\r\nb\r\n"))
        self.assertEqual(health.source_size("网络".encode()), 6)

    def test_only_tracked_rust_sources_are_counted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            (root / "tracked.rs").write_bytes(b"a\r\nb\r\n")
            (root / "untracked.rs").write_text("ignored")
            (root / "tracked.txt").write_text("ignored")
            subprocess.run(["git", "add", "tracked.rs", "tracked.txt"], cwd=root, check=True)
            self.assertEqual(health.tracked_sizes(root), {"tracked.rs": 4})

    def test_committed_crlf_baseline_is_normalized_like_worktree(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            subprocess.run(["git", "config", "core.autocrlf", "false"], cwd=root, check=True)
            (root / "old.rs").write_bytes(b"a\r\nb\r\n")
            subprocess.run(["git", "add", "old.rs"], cwd=root, check=True)
            subprocess.run(["git", "-c", "user.name=Quality Test", "-c", "user.email=test@example.com", "commit", "-qm", "baseline"], cwd=root, check=True)
            with patch.object(health, "LEGACY_RUST_BYTE_CEILINGS", {"old.rs": 6}):
                self.assertEqual(health.base_sizes(root, "HEAD"), {"old.rs": 4})

    def test_invalid_base_ref_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            with self.assertRaises(subprocess.CalledProcessError):
                health.base_sizes(root, "not-a-commit")


if __name__ == "__main__":
    unittest.main()
