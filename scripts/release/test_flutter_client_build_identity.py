#!/usr/bin/env python3
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
import unittest
from contextlib import contextmanager
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/release/flutter_client_build_identity.py"
BUILD_WRAPPER = ROOT / "scripts/release/build_flutter_client.sh"
ANDROID_NATIVE_BUILD = ROOT / "scripts/build_android_native.sh"
HERMETIC_BUILD = ROOT / "scripts/release/hermetic_build.sh"
DAEMON_BUILD = ROOT / "client/daemon/build.rs"
ANDROID_GRADLE_DIR = ROOT / "apps/flutter_client/android"
GENERATED_NATIVE_LIBRARY = (
    ROOT
    / "apps/flutter_client/android/app/src/main/jniLibs/arm64-v8a/libp2wlan_android.so"
)
FIXED_SOURCE_IDENTITY_FILE = ROOT / "target/p2wlan-source-identity.env"
ANDROID_WORKFLOWS = (
    ".github/workflows/flutter-client.yml",
    ".github/workflows/package-test.yml",
    ".github/workflows/release.yml",
)
SOURCE_ENV_KEYS = (
    "P2WLAN_SOURCE_GIT_COMMIT",
    "P2WLAN_SOURCE_BUILD_ID",
    "P2WLAN_SOURCE_DIRTY",
    "P2WLAN_SOURCE_DIFF_HASH",
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
    for source in (ANDROID_NATIVE_BUILD, HERMETIC_BUILD, SCRIPT, DAEMON_BUILD):
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


@contextmanager
def preserve_file(path: Path):
    existed = path.exists()
    original = path.read_bytes() if existed else None
    original_mode = path.stat().st_mode & 0o777 if existed else None
    try:
        yield
    finally:
        if existed:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(original)
            path.chmod(original_mode)
        elif path.exists():
            path.unlink()


def write_source_snapshot(
    path: Path,
    *,
    commit: str,
    nonce: str,
    dirty: str = "false",
    diff_hash: str = "",
) -> None:
    build_id = (
        f"{commit[:12]}-dirty-{diff_hash[:12]}"
        if dirty == "true"
        else commit[:12]
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join(
            (
                f"P2WLAN_SOURCE_GIT_COMMIT={commit}",
                f"P2WLAN_SOURCE_BUILD_ID={build_id}",
                f"P2WLAN_SOURCE_DIRTY={dirty}",
                f"P2WLAN_SOURCE_DIFF_HASH={diff_hash}",
                f"P2WLAN_SOURCE_IDENTITY_NONCE={nonce}",
            )
        )
        + "\n",
        encoding="utf-8",
    )


def make_fake_android_toolchain(temp_dir: str) -> tuple[Path, Path]:
    root = Path(temp_dir)
    fake_bin = root / "fake-bin"
    fake_bin.mkdir()
    host_tag = "darwin-arm64" if os.uname().sysname == "Darwin" else "linux-x86_64"
    ndk_bin = root / f"ndk/toolchains/llvm/prebuilt/{host_tag}/bin"
    ndk_bin.mkdir(parents=True)
    write_executable(
        fake_bin / "rustup",
        """#!/bin/sh
set -eu
if [ "$#" -ge 3 ] && [ "$1" = target ] && [ "$2" = list ] && [ "$3" = --installed ]; then
  printf '%s\n' aarch64-linux-android
fi
""",
    )
    write_executable(
        fake_bin / "cargo",
        """#!/bin/sh
set -eu
target=
previous=
for arg in "$@"; do
  if [ "$previous" = target ]; then target="$arg"; previous=; continue; fi
  if [ "$arg" = --target ]; then previous=target; fi
done
test -n "$target"
source_commit="$(printenv P2WLAN_SOURCE_GIT_COMMIT 2>/dev/null || true)"
source_build_id="$(printenv P2WLAN_SOURCE_BUILD_ID 2>/dev/null || true)"
source_dirty="$(printenv P2WLAN_SOURCE_DIRTY 2>/dev/null || true)"
source_diff_hash="$(printenv P2WLAN_SOURCE_DIFF_HASH 2>/dev/null || true)"
if [ -z "$source_commit" ]; then source_commit=UNSET; fi
if [ -z "$source_build_id" ]; then source_build_id=UNSET; fi
if [ -z "$source_dirty" ]; then source_dirty=UNSET; fi
if [ -z "$source_diff_hash" ]; then source_diff_hash=UNSET; fi
printf '%s\t%s\t%s\t%s\n' "$source_commit" "$source_build_id" "$source_dirty" "$source_diff_hash" >> "$FAKE_CARGO_LOG"
build_script="$(printenv FAKE_BUILD_SCRIPT 2>/dev/null || true)"
if [ -n "$build_script" ]; then
  mkdir -p "$FAKE_BUILD_OUT"
  CARGO_MANIFEST_DIR="$FAKE_REPO/client/daemon" OUT_DIR="$FAKE_BUILD_OUT" \
    "$build_script" > "$FAKE_BUILD_SCRIPT_OUTPUT"
fi
mkdir -p "$FAKE_REPO/target/$target/release"
printf '%s\n' fake-native > "$FAKE_REPO/target/$target/release/libp2wlan_android.so"
""",
    )
    write_executable(ndk_bin / "llvm-ar", "#!/bin/sh\nexit 0\n")
    write_executable(
        ndk_bin / "aarch64-linux-android23-clang", "#!/bin/sh\nexit 0\n"
    )
    return fake_bin, root / "ndk"


def make_fake_android_env(
    temp_dir: str, repo: Path, cargo_log: Path
) -> dict[str, str]:
    fake_bin, ndk_root = make_fake_android_toolchain(temp_dir)
    env = os.environ.copy()
    env["PATH"] = f"{fake_bin}:{env['PATH']}"
    env["ANDROID_NDK_HOME"] = str(ndk_root)
    env["P2WLAN_ANDROID_ABIS"] = "arm64-v8a"
    env["FAKE_REPO"] = str(repo)
    env["FAKE_CARGO_LOG"] = str(cargo_log)
    for name in SOURCE_ENV_KEYS + (
        "ORG_GRADLE_PROJECT_p2wlanSourceIdentityFile",
        "ORG_GRADLE_PROJECT_p2wlanSourceIdentityNonce",
    ):
        env.pop(name, None)
    return env


def run_gradle_native(
    env: dict[str, str], *, no_daemon: bool, task: str = ":app:buildP2wlanNative"
) -> subprocess.CompletedProcess[str]:
    command = ["bash", "gradlew", task, "--console=plain"]
    command.append("--no-daemon" if no_daemon else "--daemon")
    return subprocess.run(
        command,
        cwd=ANDROID_GRADLE_DIR,
        env=env,
        text=True,
        capture_output=True,
    )


def read_fake_cargo_records(path: Path) -> list[tuple[str, str, str, str]]:
    if not path.exists():
        return []
    records = []
    for line in path.read_text(encoding="utf-8").splitlines():
        values = line.split("\t")
        if len(values) != 4:
            raise AssertionError(f"malformed fake Cargo record: {line!r}")
        records.append(tuple(values))
    return records


def remove_generated_native_library() -> None:
    if GENERATED_NATIVE_LIBRARY.exists():
        GENERATED_NATIVE_LIBRARY.unlink()
    try:
        GENERATED_NATIVE_LIBRARY.parent.rmdir()
    except OSError:
        pass


def wait_for_file(
    path: Path, process: subprocess.Popen[str], timeout: float = 15.0
) -> None:
    deadline = time.monotonic() + timeout
    while not path.exists():
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            raise AssertionError(
                f"process exited before {path}: rc={process.returncode}\n"
                f"stdout={stdout}\nstderr={stderr}"
            )
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out waiting for {path}")
        time.sleep(0.02)


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
        host_tag = "darwin-arm64" if os.uname().sysname == "Darwin" else "linux-x86_64"
        ndk_bin = Path(temp_dir.name) / f"ndk/toolchains/llvm/prebuilt/{host_tag}/bin"
        ndk_bin.mkdir(parents=True)
        write_executable(
            fake_bin / "rustup",
            "#!/bin/sh\n"
            "if [ \"$1\" = target ] && [ \"$2\" = list ] && [ \"$3\" = --installed ]; then\n"
            "  printf '%s\\n' aarch64-linux-android\n"
            "fi\n",
        )
        write_executable(
            fake_bin / "cargo",
            "#!/bin/sh\nset -eu\n"
            "target=\nprevious=\n"
            "for arg in \"$@\"; do\n"
            "  if [ \"$previous\" = target ]; then target=\"$arg\"; previous=; continue; fi\n"
            "  if [ \"$arg\" = --target ]; then previous=target; fi\n"
            "done\n"
            "test -n \"$target\"\n"
            "mkdir -p \"$FAKE_REPO/target/$target/release\"\n"
            "printf '%s\\n' fake-native > \"$FAKE_REPO/target/$target/release/libp2wlan_android.so\"\n",
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
                [
                    "python3",
                    str(repo / "scripts/release/flutter_client_build_identity.py"),
                    "apk",
                    "--release",
                ],
                cwd=repo,
                text=True,
            )
        )
        self.assertEqual(values["P2WLAN_CLIENT_DIRTY"], "true")
        self.assertRegex(values["P2WLAN_CLIENT_DIFF_HASH"], r"^[0-9a-f]{40}$")
        self.assertTrue(
            values["P2WLAN_CLIENT_BUILD_ID"].endswith(
                f"-dirty-{values['P2WLAN_CLIENT_DIFF_HASH'][:12]}"
            )
        )

    def test_direct_native_build_uses_current_dirty_git_not_historical_snapshot(self):
        temp_dir, repo, gradle, untracked = make_native_safety_repo()
        self.addCleanup(temp_dir.cleanup)
        build_script_binary = Path(temp_dir.name) / "daemon-build-script"
        subprocess.run(
            ["rustc", str(repo / "client/daemon/build.rs"), "-o", str(build_script_binary)],
            check=True,
        )
        cargo_log = Path(temp_dir.name) / "cargo.log"
        build_script_output = Path(temp_dir.name) / "build-script-output.log"
        fake_env = make_fake_android_env(temp_dir.name, repo, cargo_log)
        fake_env["FAKE_BUILD_SCRIPT"] = str(build_script_binary)
        fake_env["FAKE_BUILD_OUT"] = str(Path(temp_dir.name) / "build-out")
        fake_env["FAKE_BUILD_SCRIPT_OUTPUT"] = str(build_script_output)

        stale = repo / "target/p2wlan-source-identity.env"
        with preserve_file(stale):
            write_source_snapshot(
                stale,
                commit="1" * 40,
                nonce="1" * 32,
                dirty="false",
            )
            result = subprocess.run(
                ["bash", str(repo / "scripts/build_android_native.sh")],
                cwd=repo,
                env=fake_env,
                text=True,
                capture_output=True,
            )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(gradle.read_bytes(), b"developer local tracked edit\n")
        self.assertTrue(untracked.exists())
        values = {}
        for line in build_script_output.read_text(encoding="utf-8").splitlines():
            if line.startswith("cargo:rustc-env="):
                key, value = line[len("cargo:rustc-env=") :].split("=", 1)
                values[key] = value
        expected_commit = run_git(repo, "rev-parse", "HEAD")
        self.assertEqual(values["P2WLAN_GIT_COMMIT"], expected_commit)
        self.assertNotEqual(values["P2WLAN_GIT_COMMIT"], "1" * 40)
        self.assertEqual(values["P2WLAN_DIRTY"], "true")
        self.assertRegex(values["P2WLAN_DIFF_HASH"], r"^[0-9a-f]{40}$")
        self.assertRegex(
            values["P2WLAN_BUILD_ID"],
            rf"^{expected_commit[:12]}-dirty-[0-9a-f]{{12}}$",
        )

    def test_build_wrapper_freezes_unique_snapshot_for_flutter_and_cleans_it(self):
        expected = parse_defines(
            subprocess.check_output(
                ["python3", str(SCRIPT), "apk", "--release"], cwd=ROOT, text=True
            )
        )
        temp_dir = tempfile.TemporaryDirectory(prefix="p2wlan-wrapper-fake-flutter-")
        self.addCleanup(temp_dir.cleanup)
        fake_bin = Path(temp_dir.name) / "bin"
        fake_bin.mkdir()
        record = Path(temp_dir.name) / "snapshot.path"
        write_executable(
            fake_bin / "flutter",
            """#!/bin/sh
set -eu
test "$1" = build
snapshot="$(printenv ORG_GRADLE_PROJECT_p2wlanSourceIdentityFile 2>/dev/null || true)"
nonce="$(printenv ORG_GRADLE_PROJECT_p2wlanSourceIdentityNonce 2>/dev/null || true)"
test -n "$snapshot"
test -n "$nonce"
test -f "$snapshot"
test "$(sed -n 's/^P2WLAN_SOURCE_IDENTITY_NONCE=//p' "$snapshot")" = "$nonce"
grep -Fx "P2WLAN_SOURCE_GIT_COMMIT=$P2WLAN_TEST_COMMIT" "$snapshot"
grep -Fx "P2WLAN_SOURCE_BUILD_ID=$P2WLAN_TEST_BUILD_ID" "$snapshot"
grep -Fx "P2WLAN_SOURCE_DIRTY=$P2WLAN_TEST_DIRTY" "$snapshot"
grep -Fx "P2WLAN_SOURCE_DIFF_HASH=$P2WLAN_TEST_DIFF_HASH" "$snapshot"
printf '%s\n' "$snapshot" > "$P2WLAN_TEST_SNAPSHOT_RECORD"
""",
        )
        env = os.environ.copy()
        env["PATH"] = f"{fake_bin}:{env['PATH']}"
        env["P2WLAN_TEST_SNAPSHOT_RECORD"] = str(record)
        env["P2WLAN_TEST_COMMIT"] = expected["P2WLAN_CLIENT_GIT_COMMIT"]
        env["P2WLAN_TEST_BUILD_ID"] = expected["P2WLAN_CLIENT_BUILD_ID"]
        env["P2WLAN_TEST_DIRTY"] = expected["P2WLAN_CLIENT_DIRTY"]
        env["P2WLAN_TEST_DIFF_HASH"] = expected["P2WLAN_CLIENT_DIFF_HASH"]
        fixed_existed = FIXED_SOURCE_IDENTITY_FILE.exists()
        with preserve_file(FIXED_SOURCE_IDENTITY_FILE):
            result = subprocess.run(
                ["bash", str(BUILD_WRAPPER), "apk", "--release"],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            if not fixed_existed:
                self.assertFalse(FIXED_SOURCE_IDENTITY_FILE.exists())
        snapshot = Path(record.read_text(encoding="utf-8").strip())
        self.assertFalse(snapshot.exists())
        self.assertFalse(snapshot.parent.exists())

    def test_wrapper_failure_cleans_only_its_snapshot(self):
        temp_dir = tempfile.TemporaryDirectory(prefix="p2wlan-wrapper-failure-")
        self.addCleanup(temp_dir.cleanup)
        fake_bin = Path(temp_dir.name) / "bin"
        fake_bin.mkdir()
        record = Path(temp_dir.name) / "snapshot.path"
        write_executable(
            fake_bin / "flutter",
            """#!/bin/sh
set -eu
snapshot="$(printenv ORG_GRADLE_PROJECT_p2wlanSourceIdentityFile 2>/dev/null || true)"
test -f "$snapshot"
printf '%s\n' "$snapshot" > "$P2WLAN_TEST_SNAPSHOT_RECORD"
exit 23
""",
        )
        env = os.environ.copy()
        env["PATH"] = f"{fake_bin}:{env['PATH']}"
        env["P2WLAN_TEST_SNAPSHOT_RECORD"] = str(record)
        fixed_existed = FIXED_SOURCE_IDENTITY_FILE.exists()
        with preserve_file(FIXED_SOURCE_IDENTITY_FILE):
            result = subprocess.run(
                ["bash", str(BUILD_WRAPPER), "apk", "--release"],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
            )
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            if not fixed_existed:
                self.assertFalse(FIXED_SOURCE_IDENTITY_FILE.exists())
        snapshot = Path(record.read_text(encoding="utf-8").strip())
        self.assertFalse(snapshot.exists())
        self.assertFalse(snapshot.parent.exists())

    def test_concurrent_wrappers_have_isolated_snapshots_and_cleanup(self):
        expected = parse_defines(
            subprocess.check_output(
                ["python3", str(SCRIPT), "apk", "--release"], cwd=ROOT, text=True
            )
        )
        temp_dir = tempfile.TemporaryDirectory(prefix="p2wlan-wrapper-concurrent-")
        self.addCleanup(temp_dir.cleanup)
        fake_bin = Path(temp_dir.name) / "bin"
        fake_bin.mkdir()
        capture_dir = Path(temp_dir.name) / "captures"
        capture_dir.mkdir()
        write_executable(
            fake_bin / "flutter",
            """#!/bin/sh
set -eu
test "$1" = build
snapshot="$(printenv ORG_GRADLE_PROJECT_p2wlanSourceIdentityFile 2>/dev/null || true)"
nonce="$(printenv ORG_GRADLE_PROJECT_p2wlanSourceIdentityNonce 2>/dev/null || true)"
role="$(printenv P2WLAN_TEST_ROLE)"
test -f "$snapshot"
test -n "$nonce"
test "$(sed -n 's/^P2WLAN_SOURCE_IDENTITY_NONCE=//p' "$snapshot")" = "$nonce"
grep -Fx "P2WLAN_SOURCE_GIT_COMMIT=$P2WLAN_TEST_COMMIT" "$snapshot"
grep -Fx "P2WLAN_SOURCE_BUILD_ID=$P2WLAN_TEST_BUILD_ID" "$snapshot"
grep -Fx "P2WLAN_SOURCE_DIRTY=$P2WLAN_TEST_DIRTY" "$snapshot"
grep -Fx "P2WLAN_SOURCE_DIFF_HASH=$P2WLAN_TEST_DIFF_HASH" "$snapshot"
printf '%s\n' "$snapshot" > "$P2WLAN_TEST_CAPTURE_DIR/$role.path"
printf '%s\n' "$nonce" > "$P2WLAN_TEST_CAPTURE_DIR/$role.nonce"
touch "$P2WLAN_TEST_CAPTURE_DIR/$role.ready"
while [ ! -f "$P2WLAN_TEST_CAPTURE_DIR/$role.release" ]; do
  sleep 0.02
done
""",
        )
        base_env = os.environ.copy()
        base_env["PATH"] = f"{fake_bin}:{base_env['PATH']}"
        base_env["P2WLAN_TEST_CAPTURE_DIR"] = str(capture_dir)
        base_env["P2WLAN_TEST_COMMIT"] = expected["P2WLAN_CLIENT_GIT_COMMIT"]
        base_env["P2WLAN_TEST_BUILD_ID"] = expected["P2WLAN_CLIENT_BUILD_ID"]
        base_env["P2WLAN_TEST_DIRTY"] = expected["P2WLAN_CLIENT_DIRTY"]
        base_env["P2WLAN_TEST_DIFF_HASH"] = expected["P2WLAN_CLIENT_DIFF_HASH"]
        processes: dict[str, subprocess.Popen[str]] = {}
        fixed_existed = FIXED_SOURCE_IDENTITY_FILE.exists()
        try:
            for role in ("A", "B"):
                role_env = base_env.copy()
                role_env["P2WLAN_TEST_ROLE"] = role
                processes[role] = subprocess.Popen(
                    ["bash", str(BUILD_WRAPPER), "apk", "--release"],
                    cwd=ROOT,
                    env=role_env,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
            for role in ("A", "B"):
                wait_for_file(capture_dir / f"{role}.ready", processes[role])
            path_a = Path((capture_dir / "A.path").read_text(encoding="utf-8").strip())
            path_b = Path((capture_dir / "B.path").read_text(encoding="utf-8").strip())
            nonce_a = (capture_dir / "A.nonce").read_text(encoding="utf-8").strip()
            nonce_b = (capture_dir / "B.nonce").read_text(encoding="utf-8").strip()
            self.assertNotEqual(path_a, path_b)
            self.assertNotEqual(nonce_a, nonce_b)
            self.assertTrue(path_a.is_file())
            self.assertTrue(path_b.is_file())
            self.assertTrue(str(path_a).startswith(str(ROOT / "target")))
            self.assertTrue(str(path_b).startswith(str(ROOT / "target")))
            (capture_dir / "A.release").touch()
            self.assertEqual(processes["A"].wait(timeout=10), 0)
            self.assertFalse(path_a.exists())
            self.assertTrue(path_b.is_file())
            (capture_dir / "B.release").touch()
            self.assertEqual(processes["B"].wait(timeout=10), 0)
            self.assertFalse(path_b.exists())
            if not fixed_existed:
                self.assertFalse(FIXED_SOURCE_IDENTITY_FILE.exists())
        finally:
            for role in ("A", "B"):
                (capture_dir / f"{role}.release").touch()
            for process in processes.values():
                if process.poll() is None:
                    process.terminate()
                try:
                    process.communicate(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate()

    def test_identity_helper_failure_with_partial_output_stops_flutter(self):
        temp_dir = tempfile.TemporaryDirectory(prefix="p2wlan-wrapper-helper-failure-")
        self.addCleanup(temp_dir.cleanup)
        fake_bin = Path(temp_dir.name) / "bin"
        fake_bin.mkdir()
        marker = Path(temp_dir.name) / "flutter-called"
        write_executable(
            fake_bin / "python3",
            """#!/bin/sh
printf '%s\n' '--dart-define=P2WLAN_CLIENT_GIT_COMMIT=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
printf '%s\n' '--dart-define=P2WLAN_CLIENT_BUILD_ID=aaaaaaaaaaaa'
printf '%s\n' '--dart-define=P2WLAN_CLIENT_DIRTY=false'
printf '%s\n' '--dart-define=P2WLAN_CLIENT_DIFF_HASH='
exit 17
""",
        )
        write_executable(
            fake_bin / "flutter",
            """#!/bin/sh
touch "$P2WLAN_TEST_FLUTTER_MARKER"
exit 0
""",
        )
        env = os.environ.copy()
        env["PATH"] = f"{fake_bin}:{env['PATH']}"
        env["P2WLAN_TEST_FLUTTER_MARKER"] = str(marker)
        before = set((ROOT / "target").glob("p2wlan-source-identity.*"))
        result = subprocess.run(
            ["bash", str(BUILD_WRAPPER), "apk", "--release"],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
        )
        after = set((ROOT / "target").glob("p2wlan-source-identity.*"))
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("identity helper failed", result.stderr)
        self.assertFalse(marker.exists())
        self.assertEqual(before, after)

    def test_direct_gradle_ignores_stale_fixed_snapshot(self):
        temp_dir = tempfile.TemporaryDirectory(prefix="p2wlan-gradle-stale-")
        self.addCleanup(temp_dir.cleanup)
        cargo_log = Path(temp_dir.name) / "cargo.log"
        env = make_fake_android_env(temp_dir.name, ROOT, cargo_log)
        stale = ROOT / "target/p2wlan-source-identity.env"
        with preserve_file(stale), preserve_file(GENERATED_NATIVE_LIBRARY):
            remove_generated_native_library()
            write_source_snapshot(
                stale,
                commit="1" * 40,
                nonce="1" * 32,
                dirty="false",
            )
            result = run_gradle_native(env, no_daemon=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(
                read_fake_cargo_records(cargo_log),
                [("UNSET", "UNSET", "UNSET", "UNSET")],
            )

    def test_gradle_requires_explicit_matching_snapshot_path_and_nonce(self):
        temp_dir = tempfile.TemporaryDirectory(prefix="p2wlan-gradle-properties-")
        self.addCleanup(temp_dir.cleanup)
        cargo_log = Path(temp_dir.name) / "cargo.log"
        env = make_fake_android_env(temp_dir.name, ROOT, cargo_log)
        snapshot = Path(temp_dir.name) / "identity-a.env"
        nonce = "a" * 32
        write_source_snapshot(snapshot, commit="a" * 40, nonce=nonce)
        with preserve_file(GENERATED_NATIVE_LIBRARY):
            remove_generated_native_library()
            valid_env = env.copy()
            valid_env["ORG_GRADLE_PROJECT_p2wlanSourceIdentityFile"] = str(snapshot)
            valid_env["ORG_GRADLE_PROJECT_p2wlanSourceIdentityNonce"] = nonce
            result = run_gradle_native(valid_env, no_daemon=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(
                read_fake_cargo_records(cargo_log),
                [("a" * 40, "a" * 12, "false", "UNSET")],
            )

            missing_nonce = env.copy()
            missing_nonce["ORG_GRADLE_PROJECT_p2wlanSourceIdentityFile"] = str(snapshot)
            missing_path = env.copy()
            missing_path["ORG_GRADLE_PROJECT_p2wlanSourceIdentityNonce"] = nonce
            mismatch = env.copy()
            mismatch["ORG_GRADLE_PROJECT_p2wlanSourceIdentityFile"] = str(snapshot)
            mismatch["ORG_GRADLE_PROJECT_p2wlanSourceIdentityNonce"] = "b" * 32
            nonexistent = env.copy()
            nonexistent["ORG_GRADLE_PROJECT_p2wlanSourceIdentityFile"] = str(
                Path(temp_dir.name) / "does-not-exist.env"
            )
            nonexistent["ORG_GRADLE_PROJECT_p2wlanSourceIdentityNonce"] = nonce
            for case_name, case_env in (
                ("missing nonce", missing_nonce),
                ("missing path", missing_path),
                ("nonce mismatch", mismatch),
                ("missing file", nonexistent),
            ):
                invalid = run_gradle_native(
                    case_env, no_daemon=True, task=":app:tasks"
                )
                self.assertNotEqual(
                    invalid.returncode,
                    0,
                    f"{case_name} unexpectedly succeeded:\n"
                    f"{invalid.stdout}\n{invalid.stderr}",
                )

    def test_gradle_daemon_refreshes_identity_and_native_task_inputs(self):
        temp_dir = tempfile.TemporaryDirectory(prefix="p2wlan-gradle-daemon-")
        self.addCleanup(temp_dir.cleanup)
        cargo_log = Path(temp_dir.name) / "cargo.log"
        env = make_fake_android_env(temp_dir.name, ROOT, cargo_log)
        snapshot_a = Path(temp_dir.name) / "identity-a.env"
        snapshot_b = Path(temp_dir.name) / "identity-b.env"
        write_source_snapshot(snapshot_a, commit="a" * 40, nonce="a" * 32)
        write_source_snapshot(snapshot_b, commit="b" * 40, nonce="b" * 32)
        stale = ROOT / "target/p2wlan-source-identity.env"
        with preserve_file(stale), preserve_file(GENERATED_NATIVE_LIBRARY):
            remove_generated_native_library()
            for snapshot, nonce in (
                (snapshot_a, "a" * 32),
                (snapshot_b, "b" * 32),
            ):
                invocation_env = env.copy()
                invocation_env["ORG_GRADLE_PROJECT_p2wlanSourceIdentityFile"] = str(
                    snapshot
                )
                invocation_env["ORG_GRADLE_PROJECT_p2wlanSourceIdentityNonce"] = nonce
                result = run_gradle_native(invocation_env, no_daemon=False)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            write_source_snapshot(
                stale,
                commit="1" * 40,
                nonce="1" * 32,
                dirty="false",
            )
            direct_result = run_gradle_native(env, no_daemon=False)
            self.assertEqual(
                direct_result.returncode,
                0,
                direct_result.stdout + direct_result.stderr,
            )
        self.assertEqual(
            read_fake_cargo_records(cargo_log),
            [
                ("a" * 40, "a" * 12, "false", "UNSET"),
                ("b" * 40, "b" * 12, "false", "UNSET"),
                ("UNSET", "UNSET", "UNSET", "UNSET"),
            ],
        )

    def test_daemon_source_identity_override_is_complete_and_fail_closed(self):
        temp_dir = tempfile.TemporaryDirectory(prefix="p2wlan-build-script-")
        self.addCleanup(temp_dir.cleanup)
        binary = Path(temp_dir.name) / "daemon-build-script"
        subprocess.run(["rustc", str(DAEMON_BUILD), "-o", str(binary)], check=True)

        base_env = os.environ.copy()
        for name in SOURCE_ENV_KEYS:
            base_env.pop(name, None)
        no_override = subprocess.run(
            [str(binary)], cwd=ROOT, env=base_env, text=True, capture_output=True
        )
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
        valid = subprocess.run(
            [str(binary)],
            cwd=identity_repo,
            env=source_env,
            text=True,
            capture_output=True,
        )
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
        result = subprocess.run(
            [str(binary)],
            cwd=identity_repo,
            env=partial,
            text=True,
            capture_output=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must provide all fields", result.stderr)

        commit = "0123456789abcdef0123456789abcdef01234567"
        malformed = [
            {
                "P2WLAN_SOURCE_GIT_COMMIT": "not-a-commit",
                "P2WLAN_SOURCE_BUILD_ID": "0123456789ab",
                "P2WLAN_SOURCE_DIRTY": "false",
                "P2WLAN_SOURCE_DIFF_HASH": "",
            },
            {
                "P2WLAN_SOURCE_GIT_COMMIT": commit,
                "P2WLAN_SOURCE_BUILD_ID": "0123456789ab",
                "P2WLAN_SOURCE_DIRTY": "maybe",
                "P2WLAN_SOURCE_DIFF_HASH": "",
            },
            {
                "P2WLAN_SOURCE_GIT_COMMIT": commit,
                "P2WLAN_SOURCE_BUILD_ID": "0123456789ab",
                "P2WLAN_SOURCE_DIRTY": "false",
                "P2WLAN_SOURCE_DIFF_HASH": "fedcba98765432100123456789abcdef01234567",
            },
            {
                "P2WLAN_SOURCE_GIT_COMMIT": commit,
                "P2WLAN_SOURCE_BUILD_ID": "0123456789ab-dirty-fedcba987654",
                "P2WLAN_SOURCE_DIRTY": "true",
                "P2WLAN_SOURCE_DIFF_HASH": "",
            },
            {
                "P2WLAN_SOURCE_GIT_COMMIT": commit,
                "P2WLAN_SOURCE_BUILD_ID": "wrong-build-id",
                "P2WLAN_SOURCE_DIRTY": "false",
                "P2WLAN_SOURCE_DIFF_HASH": "",
            },
        ]
        for override in malformed:
            result = subprocess.run(
                [str(binary)],
                cwd=identity_repo,
                env=base_env | override,
                text=True,
                capture_output=True,
            )
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
        self.assertIn('providers.gradleProperty("p2wlanSourceIdentityFile")', gradle)
        self.assertIn('providers.gradleProperty("p2wlanSourceIdentityNonce")', gradle)
        self.assertIn('inputs.property("p2wlanSourceIdentityNonce"', gradle)
        self.assertNotIn("target/p2wlan-source-identity.env", gradle)
        self.assertIn("environment(key, sourceIdentityValues.getValue(key))", gradle)
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
