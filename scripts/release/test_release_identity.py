#!/usr/bin/env python3
"""Regression tests for the fail-closed release identity gate."""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
VERIFY = ROOT / "scripts/release/verify_release_identity.py"
DAEMON = ROOT / "target/debug/p2wlan-daemon"


class ReleaseIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not DAEMON.is_file():
            raise unittest.SkipTest("build target/debug/p2wlan-daemon first")
        raw = subprocess.check_output([str(DAEMON), "--build-info"], text=True)
        cls.info = json.loads(raw)

    def run_gate(self, path, *extra):
        return subprocess.run(
            ["python3", str(VERIFY), "--build-info-file", str(path), *extra],
            cwd=ROOT,
            text=True,
            capture_output=True,
        )

    def test_version_mismatch_fails(self):
        value = dict(self.info)
        value["app_version"] = "0.0.0"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "build-info.json"
            path.write_text(json.dumps(value), encoding="utf-8")
            result = self.run_gate(path)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("version mismatch", result.stdout + result.stderr)

    def test_daemon_version_mismatch_fails(self):
        value = dict(self.info)
        value["daemon_version"] = "0.0.0"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "build-info.json"
            path.write_text(json.dumps(value), encoding="utf-8")
            result = self.run_gate(path)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("daemon/App version mismatch", result.stdout + result.stderr)

    def test_commit_mismatch_fails(self):
        value = dict(self.info)
        value["git_commit"] = "0" * 40
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "build-info.json"
            path.write_text(json.dumps(value), encoding="utf-8")
            result = self.run_gate(path)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match checkout", result.stdout + result.stderr)

    def test_binary_sha_mismatch_fails(self):
        value = dict(self.info)
        value["binary_sha256"] = "0" * 64
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "build-info.json"
            path.write_text(json.dumps(value), encoding="utf-8")
            result = self.run_gate(path)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("binary SHA", result.stdout + result.stderr)

    def test_damaged_build_info_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "build-info.json"
            path.write_text("{not-json", encoding="utf-8")
            result = self.run_gate(path)
        self.assertNotEqual(result.returncode, 0)

    def test_missing_dirty_diff_hash_fails(self):
        value = dict(self.info)
        value.pop("diff_hash", None)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "build-info.json"
            path.write_text(json.dumps(value), encoding="utf-8")
            result = self.run_gate(path)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("diff_hash", result.stdout + result.stderr)

    def test_manifest_mismatch_fails(self):
        manifest = {
            "app_version": self.info["app_version"],
            "git_commit": self.info["git_commit"],
            "build_id": self.info["build_id"],
            "daemon_sha256": self.info["binary_sha256"],
            "daemon_build_info": dict(self.info),
        }
        manifest["build_id"] = "wrong-build"
        with tempfile.TemporaryDirectory() as directory:
            info_path = Path(directory) / "build-info.json"
            manifest_path = Path(directory) / "manifest.json"
            info_path.write_text(json.dumps(self.info), encoding="utf-8")
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            result = self.run_gate(info_path, "--daemon", str(DAEMON), "--manifest", str(manifest_path))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("manifest build_id mismatch", result.stdout + result.stderr)

    def test_dirty_release_input_fails_closed(self):
        value = dict(self.info)
        value["dirty"] = True
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "build-info.json"
            path.write_text(json.dumps(value), encoding="utf-8")
            result = self.run_gate(path, "--release")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("dirty", result.stdout + result.stderr)

    def test_emit_manifest_roundtrip(self):
        # P2/ENG (audit §20.3): --emit-manifest writes an artifact identity
        # manifest that the same gate can later validate, and it records the
        # reproducible identity (commit, toolchain, binary sha) correctly.
        with tempfile.TemporaryDirectory() as directory:
            info_path = Path(directory) / "build-info.json"
            manifest_path = Path(directory) / "artifact.json"
            info_path.write_text(json.dumps(self.info), encoding="utf-8")

            emit = subprocess.run(
                [
                    "python3",
                    str(VERIFY),
                    "--build-info-file",
                    str(info_path),
                    "--daemon",
                    str(DAEMON),
                    "--emit-manifest",
                    str(manifest_path),
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
            )
            self.assertEqual(emit.returncode, 0, msg=emit.stderr)
            self.assertTrue(manifest_path.is_file(), "manifest must be written")

            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertIn("git_commit", manifest)
            self.assertIn("daemon_sha256", manifest)
            self.assertIn("toolchain", manifest)
            self.assertIn("cargo", manifest["toolchain"])
            self.assertIn("flutter", manifest["toolchain"])
            self.assertEqual(manifest["daemon_sha256"], self.info["binary_sha256"])
            self.assertEqual(manifest["git_commit"].lower(), self.info["git_commit"].lower())

            # The written manifest must be consumable by --manifest validation.
            validate = subprocess.run(
                [
                    "python3",
                    str(VERIFY),
                    "--build-info-file",
                    str(info_path),
                    "--daemon",
                    str(DAEMON),
                    "--manifest",
                    str(manifest_path),
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
            )
            self.assertEqual(validate.returncode, 0, msg=validate.stderr)


if __name__ == "__main__":
    unittest.main()
