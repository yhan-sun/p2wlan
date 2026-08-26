#!/usr/bin/env python3
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/release/flutter_client_build_identity.py"
BUILD_WRAPPER = ROOT / "scripts/release/build_flutter_client.sh"
ANDROID_NATIVE_BUILD = ROOT / "scripts/build_android_native.sh"
HERMETIC_BUILD = ROOT / "scripts/release/hermetic_build.sh"
DAEMON_BUILD = ROOT / "client/daemon/build.rs"
ANDROID_WORKFLOWS = (
    ".github/workflows/flutter-client.yml",
    ".github/workflows/package-test.yml",
    ".github/workflows/release.yml",
)


def run_git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=repo, text=True).strip()


def init_git_repo(repo: Path) -> None:
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
    subprocess.run(
        ["git", "commit", "--quiet", "-m", "identity fixture"],
        cwd=repo,
        check=True,
    )


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
    init_git_repo(repo)
    return temp_dir, repo, script


def make_native_safety_repo() -> tuple[tempfile.TemporaryDirectory, Path, Path, Path]:
    temp_dir = tempfile.TemporaryDirectory(prefix="p2wlan-native-safety-")
    repo = Path(temp_dir.name)
    for source in (ANDROID_NATIVE_BUILD, HERMETIC_BUILD, SCRIPT):
        destination = repo / source.relative_to(ROOT)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
    app = repo / "apps/flutter_client"
    gradle = app / "android/app/build.gradle.kts"
    gradle.parent.mkdir(parents=True)
    (app / "pubspec.yaml").write_text(
        "name: native_safety_test\nversion: 9.8.7+1\n", encoding="utf-8"
    )
    gradle.write_bytes(b"original managed Gradle input\n")
    (repo / "Cargo.toml").write_text("[workspace]\n", encoding="utf-8")
    (repo / ".gitignore").write_text(
        "target/\napps/flutter_client/android/app/src/main/jniLibs/\n",
        encoding="utf-8",
    )
    init_git_repo(repo)
    untracked = app / "android/app/local-developer-source.gradle.kts"
    untracked.write_bytes(b"developer-only source\n")
    gradle.write_bytes(b"developer local tracked edit\n")
    return temp_dir, repo, gradle, untracked


def write_executable(path: Path, contents: str) -> None:
    path.write_text(contents, encoding="utf-8")
    path.chmod(0o755)


def run_build_script(binary: Path, env: dict[str, str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(binary)], cwd=cwd, env=env, text=True, capture_output=True
    )


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

    def test_android_native_build_preserves_tracked_and_untracked_local_changes(self):
        temp_dir, repo, gradle, untracked = make_native_safety_repo()
        self.addCleanup(temp_dir.cleanup)
        fake_bin = Path(temp_dir.name) / "fake-bin"
        fake_bin.mkdir()
        ndk_bin = Path(temp_dir.name) / "ndk/toolchains/llvm/prebuilt/darwin-arm64/bin"
        ndk_bin.mkdir(parents=True)
        write_executable(
            fake_bin / "rustup",
            "#!/bin/sh\nif [ \"$1\" = target ] && [ \"$2\" = list ] && [ \"$3\" = --installed ]; then\n  printf '%s\\n' aarch64-linux-android\nfi\n",
        )
        write_executable(
            fake_bin / "cargo",
            "#!/bin/sh\nset -eu\ntarget=\nprevious=\nfor arg in \"$@\"; do\n  if [ \"$previous\" = target ]; then target=\"$arg\"; previous=; continue; fi\n  if [ \"$arg\" = --target ]; then previous=target; fi\ndone\ntest -n \"$target\"\nmkdir -p \"$FAKE_REPO/target/$target/release\"\nprintf '%s\\n' fake-native > \"$FAKE_REPO/target/$target/release/libp2wlan_android.so\"\n",
        )
        write_executable(ndk_bin / "llvm-ar", "#!/bin/sh\nexit 0\n")
        write_executable(ndk_bin / "aarch64-linux-android23-clang", "#!/bin/sh\nexit 0\n")

        env = os.environ.copy()
        env["PATH"] = f"{fake_bin}:{env['PATH']}"
        env["ANDROID_NDK_HOME"] = str(Path(temp_dir.name) / "ndk")
        env["P2WLAN_ANDROID_ABIS"] = "arm64-v8a"
        env["FAKE_REPO"] = str(repo)
        result = subprocess.run(
            ["bash", str(repo / "scripts/build_android_native.sh")],
            cwd=repo,
            env=env,
            text=True,
            capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(gradle.read_bytes(), b"developer local tracked edit\n")
        self.assertTrue(untracked.exists())
        status = subprocess.check_output(
            ["git", "status", "--porcelain=v1", "--untracked-files=all"],
            cwd=repo,
            text=True,
        )
        self.assertIn(" M apps/flutter_client/android/app/build.gradle.kts", status)
        self.assertIn("?? apps/flutter_client/android/app/local-developer-source.gradle.kts", status)

        values = parse_defines(
            subprocess.check_output(
                ["python3", str(repo / "scripts/release/flutter_client_build_identity.py"), "apk", "--release"],
                cwd=repo,
                text=True,
            )
        )
        self.assertEqual(values["P2WLAN_CLIENT_DIRTY"], "true")
        self.assertRegex(values["P2WLAN_CLIENT_DIFF_HASH"], r"^[0-9a-f]{40}$")
        self.assertTrue(values["P2WLAN_CLIENT_BUILD_ID"].endswith(
            f"-dirty-{values['P2WLAN_CLIENT_DIFF_HASH'][:12]}"
        ))

    def test_build_wrapper_freezes_snapshot_for_flutter_and_cleans_it(self):
        expected = parse_defines(
            subprocess.check_output(
                ["python3", str(SCRIPT), "apk", "--release"], cwd=ROOT, text=True
            )
        )
        temp_dir = tempfile.TemporaryDirectory(prefix="p2wlan-wrapper-fake-flutter-")
        self.addCleanup(temp_dir.cleanup)
        fake_bin = Path(temp_dir.name) / "bin"
        fake_bin.mkdir()
        snapshot = ROOT / "target/p2wlan-source-identity.env"
        write_executable(
            fake_bin / "flutter",
            "#!/bin/sh\nset -eu\ntest \"$1\" = build\ntest -f \"$P2WLAN_TEST_SNAPSHOT\"\ngrep -Fx \"P2WLAN_SOURCE_GIT_COMMIT=$P2WLAN_TEST_COMMIT\" \"$P2WLAN_TEST_SNAPSHOT\"\ngrep -Fx \"P2WLAN_SOURCE_BUILD_ID=$P2WLAN_TEST_BUILD_ID\" \"$P2WLAN_TEST_SNAPSHOT\"\ngrep -Fx \"P2WLAN_SOURCE_DIRTY=$P2WLAN_TEST_DIRTY\" \"$P2WLAN_TEST_SNAPSHOT\"\ngrep -Fx \"P2WLAN_SOURCE_DIFF_HASH=$P2WLAN_TEST_DIFF_HASH\" \"$P2WLAN_TEST_SNAPSHOT\"\n",
        )
        env = os.environ.copy()
        env["PATH"] = f"{fake_bin}:{env['PATH']}"
        env["P2WLAN_TEST_SNAPSHOT"] = str(snapshot)
        env["P2WLAN_TEST_COMMIT"] = expected["P2WLAN_CLIENT_GIT_COMMIT"]
        env["P2WLAN_TEST_BUILD_ID"] = expected["P2WLAN_CLIENT_BUILD_ID"]
        env["P2WLAN_TEST_DIRTY"] = expected["P2WLAN_CLIENT_DIRTY"]
        env["P2WLAN_TEST_DIFF_HASH"] = expected["P2WLAN_CLIENT_DIFF_HASH"]
        result = subprocess.run(
            ["bash", str(BUILD_WRAPPER), "apk", "--release"],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(snapshot.exists())

    def test_daemon_source_identity_override_is_complete_and_fail_closed(self):
        temp_dir = tempfile.TemporaryDirectory(prefix="p2wlan-build-script-")
        self.addCleanup(temp_dir.cleanup)
        binary = Path(temp_dir.name) / "daemon-build-script"
        subprocess.run(["rustc", str(DAEMON_BUILD), "-o", str(binary)], check=True)

        base_env = os.environ.copy()
        for name in (
            "P2WLAN_SOURCE_GIT_COMMIT",
            "P2WLAN_SOURCE_BUILD_ID",
            "P2WLAN_SOURCE_DIRTY",
            "P2WLAN_SOURCE_DIFF_HASH",
        ):
            base_env.pop(name, None)
        no_override = run_build_script(binary, base_env, ROOT)
        self.assertEqual(no_override.returncode, 0, no_override.stderr)

        temp_identity, identity_repo, identity_script = make_identity_repo()
        self.addCleanup(temp_identity.cleanup)
        client_values = parse_defines(
            subprocess.check_output(
                ["python3", str(identity_script), "apk", "--release"],
                cwd=identity_repo,
                text=True,
            )
        )
        source_env = base_env | {
            "P2WLAN_SOURCE_GIT_COMMIT": client_values["P2WLAN_CLIENT_GIT_COMMIT"],
            "P2WLAN_SOURCE_BUILD_ID": client_values["P2WLAN_CLIENT_BUILD_ID"],
            "P2WLAN_SOURCE_DIRTY": client_values["P2WLAN_CLIENT_DIRTY"],
            "P2WLAN_SOURCE_DIFF_HASH": client_values["P2WLAN_CLIENT_DIFF_HASH"],
        }
        valid = run_build_script(binary, source_env, identity_repo)
        self.assertEqual(valid.returncode, 0, valid.stderr)
        self.assertIn(
            f"cargo:rustc-env=P2WLAN_GIT_COMMIT={client_values['P2WLAN_CLIENT_GIT_COMMIT']}",
            valid.stdout,
        )
        self.assertIn(
            f"cargo:rustc-env=P2WLAN_BUILD_ID={client_values['P2WLAN_CLIENT_BUILD_ID']}",
            valid.stdout,
        )

        partial = dict(base_env)
        partial["P2WLAN_SOURCE_GIT_COMMIT"] = client_values["P2WLAN_CLIENT_GIT_COMMIT"]
        result = run_build_script(binary, partial, identity_repo)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must provide all fields", result.stderr)

        commit = "0123456789abcdef0123456789abcdef01234567"
        malformed = [
            {"P2WLAN_SOURCE_GIT_COMMIT": "not-a-commit", "P2WLAN_SOURCE_BUILD_ID": "0123456789ab", "P2WLAN_SOURCE_DIRTY": "false", "P2WLAN_SOURCE_DIFF_HASH": ""},
            {"P2WLAN_SOURCE_GIT_COMMIT": commit, "P2WLAN_SOURCE_BUILD_ID": "0123456789ab", "P2WLAN_SOURCE_DIRTY": "maybe", "P2WLAN_SOURCE_DIFF_HASH": ""},
            {"P2WLAN_SOURCE_GIT_COMMIT": commit, "P2WLAN_SOURCE_BUILD_ID": "0123456789ab", "P2WLAN_SOURCE_DIRTY": "false", "P2WLAN_SOURCE_DIFF_HASH": "fedcba98765432100123456789abcdef01234567"},
            {"P2WLAN_SOURCE_GIT_COMMIT": commit, "P2WLAN_SOURCE_BUILD_ID": "0123456789ab-dirty-fedcba987654", "P2WLAN_SOURCE_DIRTY": "true", "P2WLAN_SOURCE_DIFF_HASH": ""},
            {"P2WLAN_SOURCE_GIT_COMMIT": commit, "P2WLAN_SOURCE_BUILD_ID": "wrong-build-id", "P2WLAN_SOURCE_DIRTY": "false", "P2WLAN_SOURCE_DIFF_HASH": ""},
        ]
        for override in malformed:
            result = run_build_script(binary, base_env | override, identity_repo)
            self.assertNotEqual(result.returncode, 0, override)
            self.assertIn("invalid frozen source identity override", result.stderr)

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
        gradle = (ROOT / "apps/flutter_client/android/app/build.gradle.kts").read_text(
            encoding="utf-8"
        )
        self.assertIn("p2wlan-source-identity.env", gradle)
        self.assertIn("environment(key, value)", gradle)
        native = ANDROID_NATIVE_BUILD.read_text(encoding="utf-8")
        self.assertNotIn("hermetic_build.sh restore", native)
        self.assertNotRegex(native, r"git (checkout|restore|reset|clean)")

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
