#!/usr/bin/env python3
"""Ownership and preflight controls for the isolated Android Gradle home."""

import hashlib
import json
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest

import prepare_android_gradle_repositories as repositories


class IsolatedGradleHomeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.sdk = self.root / "flutter"
        settings = self.sdk / "packages/flutter_tools/gradle/settings.gradle.kts"
        settings.parent.mkdir(parents=True)
        settings.write_text("// SDK fixture; never modified by installer\n")

    def test_new_home_has_exact_private_init_and_sdk_is_unchanged(self):
        before = {p.relative_to(self.sdk): p.read_bytes() for p in self.sdk.rglob("*") if p.is_file()}
        home = self.root / "gradle"
        receipt = repositories.prepare(home, self.sdk)
        installed = home / "init.d" / repositories.INIT_SOURCE.name
        self.assertEqual(installed.read_bytes(), repositories.INIT_SOURCE.read_bytes())
        self.assertEqual(receipt["init_sha256"], hashlib.sha256(installed.read_bytes()).hexdigest())
        for directory in (home, home / "init.d"):
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(installed.stat().st_mode), 0o600)
        self.assertEqual(before, {p.relative_to(self.sdk): p.read_bytes() for p in self.sdk.rglob("*") if p.is_file()})

    def test_existing_home_and_symlink_are_refused_without_mutation(self):
        home = self.root / "existing"
        home.mkdir()
        marker = home / "owned"
        marker.write_bytes(b"preserve")
        link = self.root / "link"
        link.symlink_to(home, target_is_directory=True)
        dangling = self.root / "dangling"
        dangling.symlink_to(self.root / "absent")
        for destination in (home, link, dangling):
            with self.subTest(destination=destination), self.assertRaises(ValueError):
                repositories.prepare(destination, self.sdk)
        self.assertEqual(marker.read_bytes(), b"preserve")
        self.assertEqual(sorted(p.name for p in home.iterdir()), ["owned"])

    def test_relative_checkout_and_invalid_sdk_fail_before_creation(self):
        checkout = self.root / "checkout"
        checkout.mkdir()
        (checkout / ".git").write_text("gitdir: fixture\n")
        for destination, sdk in ((Path("relative"), self.sdk), (checkout / "gradle", self.sdk),
                                 (self.root / "bad-sdk", self.root / "missing-sdk")):
            with self.subTest(destination=destination), self.assertRaises((ValueError, OSError)):
                repositories.prepare(destination, sdk)
            self.assertFalse(destination.exists())

    def test_cli_uses_explicit_home_and_reports_exact_source_hash(self):
        home = self.root / "cli"
        result = subprocess.run([sys.executable, "-B", str(Path(repositories.__file__)),
                                 "--gradle-user-home", str(home), "--flutter-sdk", str(self.sdk)],
                                capture_output=True, text=True, check=True)
        receipt = json.loads(result.stdout)
        self.assertEqual(receipt["gradle_user_home"], str(home))
        self.assertEqual(receipt["flutter_sdk"], str(self.sdk))
        self.assertEqual(receipt["init_sha256"], hashlib.sha256(repositories.INIT_SOURCE.read_bytes()).hexdigest())
        self.assertEqual(result.stderr, "")


if __name__ == "__main__":
    unittest.main()
