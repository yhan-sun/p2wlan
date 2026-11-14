#!/usr/bin/env python3
"""Exercise the daemon's actual build script in small, isolated Git/Cargo repos."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
BUILD_SCRIPT = ROOT / "client/daemon/build.rs"


class DaemonGitWatcherTests(unittest.TestCase):
    def setUp(self):
        retained = os.environ.get("P2WLAN_BUILD_IDENTITY_TEST_ROOT")
        if retained:
            parent = Path(retained)
            parent.mkdir(parents=True, exist_ok=True)
            self.base = Path(tempfile.mkdtemp(prefix=self._testMethodName + "-", dir=parent)).resolve()
        else:
            temporary = tempfile.TemporaryDirectory(prefix="p2wlan-git-watch-")
            self.addCleanup(temporary.cleanup)
            self.base = Path(temporary.name).resolve()
        self.repo = self.base / "source"
        self.repo.mkdir()
        self.target = self.base / "target"
        self.env = os.environ.copy()
        for name in (
            "GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE", "GIT_OPTIONAL_LOCKS",
            "P2WLAN_SOURCE_GIT_COMMIT", "P2WLAN_SOURCE_BUILD_ID", "P2WLAN_SOURCE_DIRTY",
            "P2WLAN_SOURCE_DIFF_HASH", "P2WLAN_SOURCE_IDENTITY_REFRESH", "P2WLAN_BUILD_EPOCH_MS",
        ):
            self.env.pop(name, None)
        self.env.update(CARGO_TARGET_DIR=str(self.target), CARGO_INCREMENTAL="0", CARGO_BUILD_JOBS="2")
        (self.repo / "Cargo.toml").write_text(
            '[package]\nname = "daemon-git-watch-fixture"\nversion = "0.0.0"\nedition = "2021"\n',
            encoding="utf-8",
        )
        (self.repo / "src").mkdir()
        (self.repo / "src/main.rs").write_text(
            'fn main() { println!("{}|{}|{}|{}", env!("P2WLAN_GIT_COMMIT"), '
            'env!("P2WLAN_DIRTY"), env!("P2WLAN_DIFF_HASH"), env!("P2WLAN_BUILD_ID")); }\n',
            encoding="utf-8",
        )
        (self.repo / "README.md").write_text("identity fixture\n", encoding="utf-8")
        shutil.copy2(BUILD_SCRIPT, self.repo / "build.rs")
        self.build_number = 0
        self.command_number = 0
        self.command(["cargo", "generate-lockfile", "--offline"])
        self.git("init")
        self.git("config", "user.name", "Identity Fixture")
        self.git("config", "user.email", "fixture@invalid.example")
        self.git("symbolic-ref", "HEAD", "refs/heads/main")
        self.git("add", "--all")
        self.git("commit", "--quiet", "-m", "fixture A")
        (self.base / "fixture-source.json").write_text(json.dumps({
            "actual_build_script_sha256": hashlib.sha256(BUILD_SCRIPT.read_bytes()).hexdigest(),
            "test": self.id(),
        }, indent=2) + "\n", encoding="utf-8")

    def command(self, args, *, env=None):
        self.command_number += 1
        prefix = self.base / f"command-{self.command_number:03d}"
        prefix.with_suffix(".json").write_text(json.dumps(args) + "\n", encoding="utf-8")
        result = subprocess.run(
            args, cwd=self.repo, env=env or self.env, capture_output=True, timeout=120,
        )
        prefix.with_suffix(".stdout").write_bytes(result.stdout)
        prefix.with_suffix(".stderr").write_bytes(result.stderr)
        self.assertEqual(result.returncode, 0, result.stdout.decode(errors="replace") + result.stderr.decode(errors="replace"))
        return result

    def git(self, *args):
        # Assertion queries must not refresh the very index whose stability is tested.
        return self.command(["git", *args], env={**self.env, "GIT_OPTIONAL_LOCKS": "0"}).stdout.decode().strip()

    def git_path(self, name):
        path = Path(self.git("rev-parse", "--git-path", name))
        return path if path.is_absolute() else self.repo / path

    def build(self, *, refresh=None):
        self.build_number += 1
        env = self.env.copy()
        if refresh is not None:
            env["P2WLAN_SOURCE_IDENTITY_REFRESH"] = refresh
        result = self.command(
            ["cargo", "build", "--locked", "--offline", "--message-format=json"], env=env,
        )
        messages = [json.loads(line) for line in result.stdout.decode().splitlines() if line.startswith("{")]
        binaries = [m for m in messages if m.get("reason") == "compiler-artifact"
                    and m.get("target", {}).get("kind") == ["bin"] and m.get("executable")]
        builds = [m for m in messages if m.get("reason") == "build-script-executed"]
        self.assertEqual(len(binaries), 1)
        self.assertEqual(len(builds), 1)
        binary = Path(binaries[0]["executable"])
        identity = self.command([str(binary)]).stdout.decode().strip().split("|")
        self.assertEqual(len(identity), 4)
        # Cargo 1.100 stores the captured stdout in run/stdout. Older Cargo
        # stores it in output. Both are relative to this build script's OUT_DIR.
        build_unit = Path(builds[0]["out_dir"]).parent
        stdout_paths = [path for path in (build_unit / "run" / "stdout", build_unit / "output")
                        if path.is_file()]
        self.assertEqual(len(stdout_paths), 1, f"expected one build script stdout under {build_unit}")
        output = stdout_paths[0].read_text(encoding="utf-8")
        watchers = [Path(line.split("=", 1)[1]) for line in output.splitlines()
                    if line.startswith("cargo:rerun-if-changed=")]
        self.assertTrue(watchers, f"no file watchers in {stdout_paths[0]}")
        record = {
            "build": self.build_number, "fresh": binaries[0]["fresh"], "identity": identity,
            "binary": str(binary), "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "watchers": [str(p) for p in watchers],
        }
        (self.base / f"build-{self.build_number:02d}.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
        return record

    def assert_clean(self, record, commit):
        self.assertEqual(record["identity"], [commit, "false", "", commit[:12]])

    def test_detached_checkout_reuses_build_without_refreshing_index(self):
        self.git("checkout", "--detach")
        commit = self.git("rev-parse", "HEAD")
        index = self.git_path("index")
        before = index.stat().st_mtime_ns
        first = self.build()
        self.assertEqual(index.stat().st_mtime_ns, before)
        self.assert_clean(first, commit)
        second = self.build()
        self.assertTrue(second["fresh"])
        self.assertEqual(second["binary_sha256"], first["binary_sha256"])
        self.assert_clean(second, commit)

    def test_loose_branch_reuses_build_with_absent_optional_packed_refs(self):
        self.assertFalse(self.git_path("packed-refs").exists())
        first = self.build()
        self.assertTrue(all(Path(p).exists() for p in first["watchers"]))
        second = self.build()
        self.assertTrue(second["fresh"])
        self.assertEqual(first["identity"], second["identity"])

    def test_branch_commit_refreshes_identity_then_reuses_build(self):
        first = self.build()
        self.git("commit", "--allow-empty", "--quiet", "-m", "fixture B")
        commit = self.git("rev-parse", "HEAD")
        self.assertNotEqual(first["identity"][0], commit)
        changed = self.build()
        self.assertFalse(changed["fresh"])
        self.assert_clean(changed, commit)
        self.assertTrue(self.build()["fresh"])

    def test_packed_branch_detects_creation_of_new_loose_ref(self):
        self.git("pack-refs", "--all", "--prune")
        branch = self.git_path("refs/heads/main")
        self.assertFalse(branch.exists())
        first = self.build()
        self.assertIn(str(branch.parent), first["watchers"])
        self.git("commit", "--allow-empty", "--quiet", "-m", "fixture B")
        self.assertTrue(branch.exists())
        self.assert_clean(self.build(), self.git("rev-parse", "HEAD"))
        self.assertTrue(self.build()["fresh"])

    def test_packing_loose_ref_keeps_future_commit_fence(self):
        first = self.build()
        self.git("pack-refs", "--all", "--prune")
        packed = self.build()
        self.assertEqual(first["identity"], packed["identity"])
        self.git("commit", "--allow-empty", "--quiet", "-m", "fixture B")
        self.assert_clean(self.build(), self.git("rev-parse", "HEAD"))
        self.assertTrue(self.build()["fresh"])

    def test_linked_worktree_uses_its_git_paths_and_detached_head(self):
        parent = self.repo
        linked = self.base / "linked"
        self.git("worktree", "add", "--detach", str(linked), "HEAD")
        self.repo = linked
        self.assertTrue((linked / ".git").is_file())
        first = self.build()
        self.assertIn(str(self.git_path("HEAD")), first["watchers"])
        self.assertIn(str(self.git_path("index")), first["watchers"])
        self.assertTrue(all(Path(p).exists() for p in first["watchers"]))
        self.assertTrue(self.build()["fresh"])
        self.git("commit", "--allow-empty", "--quiet", "-m", "worktree B")
        self.assert_clean(self.build(), self.git("rev-parse", "HEAD"))
        original = self.command(["git", "-C", str(parent), "rev-parse", "HEAD"]).stdout.decode().strip()
        self.assertEqual(original, first["identity"][0])

    def test_staged_changes_remain_dirty_and_commit_refreshes_identity(self):
        self.build()
        (self.repo / "README.md").write_text("changed input\n", encoding="utf-8")
        self.git("add", "README.md")
        dirty = self.build()["identity"]
        self.assertEqual(dirty[1], "true")
        self.assertRegex(dirty[2], r"^[0-9a-f]{40}$")
        self.assertEqual(dirty[3], dirty[0][:12] + "-dirty-" + dirty[2][:12])
        self.git("commit", "--quiet", "-m", "fixture dirty input")
        self.assert_clean(self.build(), self.git("rev-parse", "HEAD"))

    def test_existing_untracked_input_changes_dirty_hash(self):
        path = self.repo / "input.txt"
        path.write_text("first\n", encoding="utf-8")
        first = self.build()["identity"]
        path.write_text("second\n", encoding="utf-8")
        second = self.build()["identity"]
        self.assertEqual(first[0], second[0])
        self.assertEqual(first[1], "true")
        self.assertEqual(second[1], "true")
        self.assertNotEqual(first[2], second[2])

    def test_explicit_source_refresh_detects_new_untracked_input(self):
        clean = self.build()
        (self.repo / "new-input.txt").write_text("new identity input\n", encoding="utf-8")
        dirty = self.build(refresh="new-input-snapshot")
        self.assertEqual(clean["identity"][0], dirty["identity"][0])
        self.assertEqual(dirty["identity"][1], "true")
        self.assertNotEqual(clean["identity"][2], dirty["identity"][2])


if __name__ == "__main__":
    unittest.main(verbosity=2)
