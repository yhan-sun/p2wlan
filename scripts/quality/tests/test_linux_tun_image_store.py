import copy
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "parallel-rooms"))
import linux_tun_image_store as store
import retain_linux_tun_programs as producer


class OriginalImageStoreControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.daemon = self.root / "measured-daemon"
        self.control = self.root / "measured-control"
        self.daemon.write_bytes(b"\x7fELFactual-daemon")
        self.control.write_bytes(b"\x7fELFactual-control")
        self.report = self.root / "report.json"
        self.head = "a" * 40
        self.report.write_text(json.dumps(dict(source_commit=self.head, binary_sha256={
            "daemon": hashlib.sha256(self.daemon.read_bytes()).hexdigest(),
            "control": hashlib.sha256(self.control.read_bytes()).hexdigest()})))

    def run_scope(self, name, shared=True, run_id="123"):
        output = self.root / name
        output.mkdir()
        args = SimpleNamespace(output=output, daemon=self.daemon, control=self.control,
            relay=None, head=self.head, report=[self.report],
            image_store=self.root / store.STORE_NAME if shared else None)
        manifest = dict(schema_version=1, actual_checkout=self.head, run_id=run_id,
            run_attempt="1", images=[])
        producer.retain(args, manifest)
        return manifest

    def test_three_scopes_retain_each_original_image_once_with_separate_manifests(self):
        first = self.run_scope("normal")
        before = {p.name: p.stat().st_ino for p in (self.root / store.STORE_NAME).iterdir()}
        for scope in ("relay", "revocation"):
            current = self.run_scope(scope)
            self.assertTrue(all(row["shared_image_reused"] for row in current["images"]))
            self.assertEqual([r["sha256"] for r in current["images"]],
                             [r["sha256"] for r in first["images"]])
        self.assertEqual(before, {p.name: p.stat().st_ino for p in
            (self.root / store.STORE_NAME).iterdir()})
        self.assertEqual(first["schema_version"], 2)
        for row in first["images"]:
            self.assertEqual(row["archive_member"], store.STORE_NAME + "/p2wlan-" + row["role"])
            self.assertEqual((self.root / row["archive_member"]).read_bytes(),
                (self.daemon if row["role"] == "daemon" else self.control).read_bytes())
        self.assertEqual(list((self.root / "normal").iterdir()), [])

    def test_non_secret_store_can_be_traversed_and_read_by_the_uploading_runner(self):
        previous_umask = os.umask(0o077)
        try:
            manifest = self.run_scope("sudo-created")
        finally:
            os.umask(previous_umask)
        directory = self.root / store.STORE_NAME
        self.assertEqual(directory.stat().st_mode & 0o555, 0o555)
        for row in manifest["images"]:
            self.assertEqual((self.root / row["archive_member"]).stat().st_mode & 0o444, 0o444)
        self.assertEqual((directory / "owner.json").stat().st_mode & 0o444, 0o444)

    def test_legacy_scope_keeps_its_schema_and_own_original_bytes(self):
        manifest = self.run_scope("legacy", shared=False)
        self.assertEqual(manifest["schema_version"], 1)
        for row in manifest["images"]:
            self.assertNotIn("archive_member", row)
            self.assertEqual(store.read_image(self.root / "legacy" / row["file"]),
                             (row["bytes"], row["sha256"]))

    def test_conflicting_current_image_cannot_reuse_or_overwrite_retained_bytes(self):
        original = self.run_scope("first")
        self.daemon.write_bytes(b"changed original")
        with self.assertRaises(ValueError):
            self.run_scope("conflict")
        row = original["images"][0]
        self.assertEqual(store.read_image(self.root / row["archive_member"])[1], row["sha256"])

    def test_missing_actual_image_cannot_be_replaced_by_cached_bytes(self):
        self.run_scope("first")
        self.daemon.unlink()
        second = self.run_scope("missing")
        self.assertFalse(second["images"][0]["available"])
        self.assertEqual(second["images"][0]["reason"], "original_image_missing_or_conflicting")

    def test_foreign_run_or_unexpected_role_entries_fail_closed(self):
        self.run_scope("first")
        with self.assertRaises(ValueError):
            self.run_scope("foreign", run_id="124")
        (self.root / store.STORE_NAME / "unexpected").write_bytes(b"extra")
        with self.assertRaises(ValueError):
            self.run_scope("extra")

    def test_symlink_and_capacity_are_refused_without_native_execution(self):
        self.run_scope("first")
        target = self.root / store.STORE_NAME / "p2wlan-daemon"
        target.unlink()
        target.symlink_to(self.control)
        with self.assertRaises(ValueError):
            self.run_scope("symlink")
        with patch.object(store, "MAX_IMAGE_BYTES", 4):
            with self.assertRaises(ValueError):
                self.run_scope("oversize", shared=False)

    def test_descriptor_change_time_is_compared_separately_from_path_birth_time(self):
        real_fstat = os.fstat
        def descriptor_clock(fd):
            value = real_fstat(fd)
            return SimpleNamespace(**{name: getattr(value, name) for name in
                ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_mode")},
                st_ctime_ns=value.st_ctime_ns + 71)
        with patch.object(store.os, "fstat", side_effect=descriptor_clock):
            manifest = self.run_scope("separate-stat-APIs", shared=False)
        self.assertTrue(all(row["available"] for row in manifest["images"]))

    def test_replacing_source_path_during_read_is_still_rejected(self):
        real_fstat = os.fstat
        calls = []
        def replace_path(fd):
            value = real_fstat(fd)
            calls.append(fd)
            if len(calls) == 2:
                self.daemon.rename(self.root / "previous-original")
                self.daemon.write_bytes(b"different path object")
            return value
        with patch.object(store.os, "fstat", side_effect=replace_path):
            with self.assertRaisesRegex(ValueError, "path changed during retention"):
                self.run_scope("replaced", shared=False)

    def test_binary_newline_and_control_Z_bytes_are_preserved_exactly(self):
        original = b"\x7fELF\r\n\x1a\x00\n\r\n"
        self.daemon.write_bytes(original)
        report = json.loads(self.report.read_text())
        report["binary_sha256"]["daemon"] = hashlib.sha256(original).hexdigest()
        self.report.write_text(json.dumps(report))
        manifest = self.run_scope("binary", shared=False)
        self.assertTrue(manifest["images"][0]["available"])
        self.assertEqual((self.root / "binary" / "p2wlan-daemon").read_bytes(), original)

    def test_source_metadata_change_is_retained_as_failure(self):
        real_fstat = os.fstat
        calls = []
        def changed(fd):
            value = real_fstat(fd)
            calls.append(fd)
            if len(calls) == 2:
                changed = copy.copy(value)
                return SimpleNamespace(**{name: getattr(changed, name) for name in
                    ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_mode")},
                    st_ctime_ns=value.st_ctime_ns + 1)
            return value
        with patch.object(store.os, "fstat", side_effect=changed):
            with self.assertRaisesRegex(ValueError, "changed during retention"):
                self.run_scope("mutation", shared=False)
        self.assertTrue((self.root / "mutation" / "p2wlan-daemon").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
