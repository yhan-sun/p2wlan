#!/usr/bin/env python3

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import check_code_health as policy


class BudgetTests(unittest.TestCase):
    def test_budget_boundary(self):
        self.assertIsNone(policy.evaluate("src/runtime.rs", policy.RUST_PRODUCTION_MAX_BYTES, None))
        self.assertFalse(policy.evaluate("src/runtime.rs", policy.RUST_PRODUCTION_MAX_BYTES + 1, None).allowed)

    def test_test_budget_does_not_apply_to_similar_directory_names(self):
        self.assertIsNone(policy.evaluate("src/tests/lifecycle.rs", policy.RUST_TEST_MAX_BYTES, None))
        self.assertFalse(policy.evaluate("src/contest/runtime.rs", policy.RUST_TEST_MAX_BYTES, None).allowed)

    def test_oversized_existing_file_can_only_shrink(self):
        size = policy.RUST_PRODUCTION_MAX_BYTES + 100
        self.assertTrue(policy.evaluate("src/runtime.rs", size, size).allowed)
        self.assertTrue(policy.evaluate("src/runtime.rs", size - 1, size).allowed)
        self.assertFalse(policy.evaluate("src/runtime.rs", size + 1, size).allowed)

    def test_old_small_file_cannot_acquire_an_exemption(self):
        self.assertFalse(policy.evaluate("src/runtime.rs", policy.RUST_PRODUCTION_MAX_BYTES + 1, 10).allowed)

    def test_line_endings_are_platform_independent(self):
        self.assertEqual(policy.normalized_size(b"one\r\ntwo\r\n"), policy.normalized_size(b"one\ntwo\n"))


class RepositoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.run_git("init", "-q")
        self.run_git("config", "user.email", "test@example.com")
        self.run_git("config", "user.name", "Policy tests")
        self.run_git("config", "core.autocrlf", "false")
        self.write("src/runtime.rs", "x" * (policy.RUST_PRODUCTION_MAX_BYTES + 10))
        self.write("src/small.rs", "fn main() {}\n")
        self.commit()
        self.base = self.run_git("rev-parse", "HEAD").strip()

    def run_git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.root, stderr=subprocess.PIPE, text=True)

    def write(self, relative, content):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", newline="")

    def commit(self):
        self.run_git("add", "-A")
        self.run_git("commit", "-qm", "fixture")

    def test_full_scan_discovers_unlisted_legacy_debt(self):
        report = policy.check(self.root, self.base)
        self.assertEqual(report["errors"], [])
        self.assertEqual(len(report["debt"]), 1)
        self.assertEqual(report["debt"][0]["path"], "src/runtime.rs")
        json.dumps(report)

    def test_new_untracked_file_cannot_evade_check(self):
        self.write("src/new.rs", "x" * (policy.RUST_PRODUCTION_MAX_BYTES + 1))
        self.assertEqual(len(policy.check(self.root, self.base)["errors"]), 1)

    def test_deleted_legacy_file_needs_no_manual_allowlist_update(self):
        (self.root / "src/runtime.rs").unlink()
        report = policy.check(self.root, self.base)
        self.assertEqual(report["errors"], [])
        self.assertEqual(report["debt"], [])

    def test_rename_does_not_launder_oversized_source(self):
        (self.root / "src/runtime.rs").rename(self.root / "src/renamed.rs")
        self.assertEqual(len(policy.check(self.root, self.base)["errors"]), 1)

    def test_a_later_commit_cannot_regrow_previously_reduced_debt(self):
        self.write("src/runtime.rs", "x" * (policy.RUST_PRODUCTION_MAX_BYTES + 5))
        self.commit()
        self.write("src/runtime.rs", "x" * (policy.RUST_PRODUCTION_MAX_BYTES + 6))
        self.assertEqual(len(policy.check(self.root, "HEAD")["errors"]), 1)

    def test_invalid_base_fails_closed(self):
        with self.assertRaises(policy.PolicyError):
            policy.check(self.root, "missing-ref")

    def test_option_like_ref_is_not_a_git_option(self):
        with self.assertRaises(policy.PolicyError):
            policy.check(self.root, "--all")

    def test_unicode_and_spaces_in_filename(self):
        self.write("src/连接 runtime.rs", "fn example() {}\n")
        self.commit()
        self.assertEqual(policy.check(self.root, "HEAD")["scanned_rust_files"], 3)

    @unittest.skipIf(os.name == "nt", "Windows requires symlink privileges")
    def test_symlink_cannot_read_outside_repository(self):
        (self.root / "src/alias.rs").symlink_to(self.root / "src/small.rs")
        errors = policy.check(self.root, self.base)["errors"]
        self.assertTrue(any("symlink" in error for error in errors))

    def test_crlf_does_not_regress_a_committed_lf_file(self):
        self.write("src/runtime.rs", "x\n" * (policy.RUST_PRODUCTION_MAX_BYTES // 2 + 1))
        self.commit()
        path = self.root / "src/runtime.rs"
        path.write_bytes(path.read_bytes().replace(b"\n", b"\r\n"))
        self.assertEqual(policy.check(self.root, "HEAD")["errors"], [])

    def test_invalid_utf8_fails_closed(self):
        (self.root / "src/small.rs").write_bytes(b"\xff")
        self.assertTrue(any("cannot inspect" in error for error in policy.check(self.root, self.base)["errors"]))


if __name__ == "__main__":
    unittest.main()
