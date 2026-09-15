#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts/release/verify_published_release.py"
SPEC = importlib.util.spec_from_file_location("verify_published_release", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class PublishedReleaseAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.tag = "v0.1.999"
        self.commit = "a" * 40
        self.files = {}
        for index, name in enumerate(MODULE.EXPECTED_PAYLOADS):
            meta = {"bytes": index + 1, "sha256": f"{index + 1:064x}"}
            if name in MODULE.PRIMARY_ARTIFACTS:
                meta.update(
                    platform=MODULE.PRIMARY_ARTIFACTS[name][0],
                    arch=MODULE.PRIMARY_ARTIFACTS[name][1],
                    identity="test-identity",
                )
            self.files[name] = meta
        self.manifest = {
            "schema_version": 2,
            "tag": self.tag,
            "source_sha": self.commit,
            "files": self.files,
        }
        self.manifest_path = self.root / MODULE.MANIFEST_NAME
        self._write_manifest()
        self.release = self._release_fixture()

    def _write_manifest(self) -> None:
        self.manifest_path.write_text(
            json.dumps(self.manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def _release_fixture(self) -> dict:
        assets = []
        for name, meta in self.files.items():
            assets.append(
                {
                    "name": name,
                    "size": meta["bytes"],
                    "digest": f"sha256:{meta['sha256']}",
                    "state": "uploaded",
                }
            )
        manifest_bytes = self.manifest_path.read_bytes()
        assets.append(
            {
                "name": MODULE.MANIFEST_NAME,
                "size": len(manifest_bytes),
                "digest": f"sha256:{hashlib.sha256(manifest_bytes).hexdigest()}",
                "state": "uploaded",
            }
        )
        return {
            "tag_name": self.tag,
            "draft": False,
            "prerelease": False,
            "immutable": True,
            "published_at": "2026-09-15T00:00:00Z",
            "assets": assets,
        }

    def verify(self, require_immutable: bool = False):
        return MODULE.verify(
            self.release,
            self.manifest,
            self.manifest_path,
            self.tag,
            self.commit,
            require_immutable,
        )

    def test_valid_release_passes(self) -> None:
        errors, warnings, report = self.verify()
        self.assertEqual(errors, [])
        self.assertEqual(warnings, [])
        self.assertEqual(report["asset_count"], 11)
        self.assertEqual(report["source_sha"], self.commit)
        self.assertEqual(report["manifest_schema_version"], 2)

    def test_manifest_schema_one_is_rejected(self) -> None:
        self.manifest["schema_version"] = 1
        self._write_manifest()
        errors, _, _ = self.verify()
        self.assertTrue(any("schema_version" in error for error in errors))

    def test_primary_artifact_identity_is_required(self) -> None:
        self.files["p2wlan-windows-x64-setup.exe"].pop("identity")
        self._write_manifest()
        self.release = self._release_fixture()
        errors, _, _ = self.verify()
        self.assertTrue(any("artifact identity" in error for error in errors))

    def test_source_sha_must_match_tag_commit(self) -> None:
        self.manifest["source_sha"] = "b" * 40
        self._write_manifest()
        self.release = self._release_fixture()
        errors, _, _ = self.verify()
        self.assertTrue(any("source_sha" in error for error in errors))

    def test_asset_digest_mismatch_fails(self) -> None:
        self.release["assets"][0]["digest"] = "sha256:" + "f" * 64
        errors, _, _ = self.verify()
        self.assertTrue(any("digest mismatch" in error for error in errors))

    def test_missing_asset_fails(self) -> None:
        self.release["assets"] = self.release["assets"][1:]
        errors, _, _ = self.verify()
        self.assertTrue(any("missing asset" in error for error in errors))

    def test_unexpected_asset_fails_closed(self) -> None:
        self.release["assets"].append(
            {"name": "unexpected.bin", "size": 1, "digest": "sha256:" + "0" * 64, "state": "uploaded"}
        )
        errors, _, _ = self.verify()
        self.assertTrue(any("unexpected asset" in error for error in errors))

    def test_mutable_release_warns_by_default(self) -> None:
        self.release["immutable"] = False
        errors, warnings, _ = self.verify()
        self.assertEqual(errors, [])
        self.assertTrue(any("mutable" in warning for warning in warnings))

    def test_mutable_release_can_be_required(self) -> None:
        self.release["immutable"] = False
        errors, _, _ = self.verify(require_immutable=True)
        self.assertTrue(any("mutable" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
