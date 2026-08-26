#!/usr/bin/env python3
from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/release/flutter_client_build_identity.py"
ANDROID_WORKFLOWS = (
    ".github/workflows/flutter-client.yml",
    ".github/workflows/package-test.yml",
    ".github/workflows/release.yml",
)


def run_git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=repo, text=True).strip()


def parse_defines(output: str) -> dict[str, str]:
    prefix = "--dart-define="
    values = {}
    for line in output.splitlines():
        if not line.startswith(prefix):
            raise AssertionError(f"unexpected identity output line: {line!r}")
        key, value = line[len(prefix) :].split("=", 1)
        values[key] = value
    return values


def make_identity_repo() -> tuple[tempfile.TemporaryDirectory, Path, Path]:
    temp_dir = tempfile.TemporaryDirectory(prefix="p2wlan-client-identity-")
    repo = Path(temp_dir.name)
    script = repo / "scripts/release/flutter_client_build_identity.py"
    script.parent.mkdir(parents=True)
    shutil.copy2(SCRIPT, script)
    app = repo / "apps/flutter_client"
    app.mkdir(parents=True)
    (app / "pubspec.yaml").write_text(
        "name: identity_test\nversion: 9.8.7+1\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "init", "--quiet"], cwd=repo, check=True)
    subprocess.run(
        ["git", "config", "user.email", "identity-test@example.invalid"],
        cwd=repo,
        check=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Identity Test"], cwd=repo, check=True
    )
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "--quiet", "-m", "identity fixture"], cwd=repo, check=True)
    return temp_dir, repo, script


class FlutterClientBuildIdentityTest(unittest.TestCase):
    def test_clean_temporary_checkout_has_exact_commit_identity(self):
        temp_dir, repo, script = make_identity_repo()
        self.addCleanup(temp_dir.cleanup)
        output = subprocess.check_output(
            ["python3", str(script), "windows", "--release"],
            cwd=repo,
            text=True,
        )
        values = parse_defines(output)
        expected_commit = run_git(repo, "rev-parse", "HEAD")
        self.assertEqual(values["P2WLAN_CLIENT_GIT_COMMIT"], expected_commit)
        self.assertEqual(values["P2WLAN_CLIENT_DIRTY"], "false")
        self.assertEqual(values["P2WLAN_CLIENT_DIFF_HASH"], "")
        self.assertEqual(values["P2WLAN_CLIENT_BUILD_ID"], expected_commit[:12])
        self.assertEqual(values["P2WLAN_CLIENT_PROFILE"], "release")
        self.assertEqual(
            set(values),
            {
                "P2WLAN_CLIENT_APP_VERSION",
                "P2WLAN_CLIENT_GIT_COMMIT",
                "P2WLAN_CLIENT_BUILD_ID",
                "P2WLAN_CLIENT_DIRTY",
                "P2WLAN_CLIENT_DIFF_HASH",
                "P2WLAN_CLIENT_PROFILE",
            },
        )

    def test_real_dirty_temporary_checkout_has_stable_diff_identity(self):
        temp_dir, repo, script = make_identity_repo()
        self.addCleanup(temp_dir.cleanup)
        pubspec = repo / "apps/flutter_client/pubspec.yaml"
        pubspec.write_text(
            "name: identity_test\nversion: 9.8.8+1\n",
            encoding="utf-8",
        )
        (repo / "apps/flutter_client/untracked.txt").write_text(
            "untracked dirty fixture\n", encoding="utf-8"
        )
        expected_commit = run_git(repo, "rev-parse", "HEAD")

        first = parse_defines(
            subprocess.check_output(
                ["python3", str(script), "apk", "--release"], cwd=repo, text=True
            )
        )
        second = parse_defines(
            subprocess.check_output(
                ["python3", str(script), "apk", "--release"], cwd=repo, text=True
            )
        )

        self.assertEqual(first, second)
        self.assertEqual(first["P2WLAN_CLIENT_GIT_COMMIT"], expected_commit)
        self.assertEqual(first["P2WLAN_CLIENT_DIRTY"], "true")
        self.assertRegex(first["P2WLAN_CLIENT_DIFF_HASH"], r"^[0-9a-f]{40}$")
        self.assertEqual(
            first["P2WLAN_CLIENT_BUILD_ID"],
            f"{expected_commit[:12]}-dirty-{first['P2WLAN_CLIENT_DIFF_HASH'][:12]}",
        )

    def test_flutter_android_workflow_orders_restore_identity_and_wrapper(self):
        workflow = (ROOT / ANDROID_WORKFLOWS[0]).read_text(encoding="utf-8")
        android_job = workflow[workflow.index("  android:\n") :]
        pub_get = android_job.index("run: flutter pub get")
        restore = android_job.index(
            "Restore Flutter-managed source files before identity stamping"
        )
        identity = android_job.index("Assert clean Flutter client identity")
        wrapper = android_job.index("scripts/release/build_flutter_client.sh apk")
        self.assertLess(pub_get, restore)
        self.assertLess(restore, identity)
        self.assertLess(identity, wrapper)
        self.assertIn("bash scripts/release/hermetic_build.sh restore", android_job)
        self.assertIn(
            "python3 scripts/release/flutter_client_build_identity.py apk --release",
            android_job,
        )

    def test_android_workflows_use_wrapper_without_bare_flutter_apk_build(self):
        for workflow_path in ANDROID_WORKFLOWS:
            workflow = (ROOT / workflow_path).read_text(encoding="utf-8")
            self.assertIn("build_flutter_client.sh apk", workflow, workflow_path)
            self.assertNotRegex(
                workflow,
                r"(?m)^\s*(?:run:\s+)?flutter build apk(?:\s|$)",
                workflow_path,
            )


if __name__ == "__main__":
    unittest.main()
