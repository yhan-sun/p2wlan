#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VERIFY = ROOT / "scripts/release/verify_release_set.py"
WRITE_METADATA = ROOT / "scripts/release/write_artifact_metadata.py"
SOURCE_SHA = "0123456789abcdef0123456789abcdef01234567"
TAG = "v1.2.3"
PRIMARY = {
    "p2wlan-android-arm64-release.apk": ("android", "arm64", "client-stamped"),
    "p2wlan-ios-arm64-unsigned.ipa": ("ios", "arm64", "client-stamped"),
    "p2wlan-linux-arm64-cli.tar.gz": ("linux-cli", "arm64", "rust-source-bound"),
    "p2wlan-linux-x64-cli.tar.gz": ("linux-cli", "x64", "rust-source-bound"),
    "p2wlan-linux-x64.tar.gz": ("linux", "x64", "client-stamped-daemon-verified"),
    "p2wlan-macos-arm64.dmg": ("macos", "arm64", "client-stamped-daemon-verified"),
    "p2wlan-macos-x64.dmg": ("macos", "x64", "client-stamped-daemon-verified"),
    "p2wlan-windows-x64-setup.exe": ("windows", "x64", "client-stamped-daemon-verified"),
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ReleaseSetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for index, name in enumerate(PRIMARY, start=1):
            (self.root / name).write_bytes((f"artifact-{index}-{name}\n").encode())
        for name in ("p2wlan-linux-arm64-cli.tar.gz", "p2wlan-linux-x64-cli.tar.gz"):
            (self.root / f"{name}.sha256").write_text(
                f"{sha256(self.root / name)}  {name}\n", encoding="utf-8"
            )
        for name, (platform, arch, identity) in PRIMARY.items():
            result = subprocess.run(
                [
                    "python3",
                    str(WRITE_METADATA),
                    "--artifact",
                    str(self.root / name),
                    "--source-sha",
                    SOURCE_SHA,
                    "--tag",
                    TAG,
                    "--platform",
                    platform,
                    "--arch",
                    arch,
                    "--identity",
                    identity,
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)

    def verify(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "python3",
                str(VERIFY),
                "--directory",
                str(self.root),
                "--source-sha",
                SOURCE_SHA,
                "--tag",
                TAG,
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )

    def test_complete_metadata_bound_release_set_passes(self) -> None:
        result = self.verify()
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        manifest = json.loads((self.root / "RELEASE-MANIFEST.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["schema_version"], 2)
        self.assertEqual(manifest["source_sha"], SOURCE_SHA)
        self.assertEqual(len(manifest["files"]), 10)
        self.assertEqual(
            manifest["files"]["p2wlan-android-arm64-release.apk"]["identity"],
            "client-stamped",
        )

    def test_metadata_from_other_source_sha_fails(self) -> None:
        path = self.root / "p2wlan-android-arm64-release.apk.metadata.json"
        metadata = json.loads(path.read_text(encoding="utf-8"))
        metadata["source_sha"] = "f" * 40
        path.write_text(json.dumps(metadata), encoding="utf-8")
        result = self.verify()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("source_sha", result.stdout)

    def test_artifact_tamper_after_metadata_fails(self) -> None:
        path = self.root / "p2wlan-windows-x64-setup.exe"
        path.write_bytes(path.read_bytes() + b"tampered")
        result = self.verify()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("sha256", result.stdout)

    def test_missing_metadata_fails(self) -> None:
        (self.root / "p2wlan-macos-arm64.dmg.metadata.json").unlink()
        result = self.verify()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing artifact metadata", result.stdout)


if __name__ == "__main__":
    unittest.main()
