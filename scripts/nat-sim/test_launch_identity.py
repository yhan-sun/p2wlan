"""Actual exec identity, immutable artifacts and private configuration hashes."""

import copy
import hashlib
import importlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


SOURCE = {"commit": "a" * 40, "patch_sha256": "b" * 64}


class ExecObserved(Exception):
    """Leave the same pre-exec record a successful exec would retain."""


def write_valid_launch_evidence(base, source=SOURCE):
    """Emit real snapshots and typed records without starting service binaries."""
    launch = importlib.import_module("launch_identity")
    base.mkdir(parents=True, exist_ok=True, mode=0o700)
    executable = base / "fixture-program"
    executable.write_text("#!/bin/sh\nexit 0\n")
    executable.chmod(0o700)
    launch.prepare_artifacts(base, {name: executable for name in ("daemon", "control", "relay")}, source)
    executable.unlink()
    directory = base / "round-1" / "launches"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    with patch.dict(os.environ, {}, clear=True), patch.object(launch.os, "execve", side_effect=ExecObserved):
        for role in launch.REQUIRED_ROLES:
            try:
                launch.exec_launch(base / "artifact-set.json", launch.role_component(role),
                                   directory / f"{role}.json", role, [], [])
            except ExecObserved:
                pass
    return launch.read_launch_evidence(base, source)


class LaunchIdentityTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(
            importlib.util.find_spec("launch_identity"),
            "B-01 requires the launch boundary to own artifact and input identity",
        )
        self.launch = importlib.import_module("launch_identity")
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.executable = self.root / "shared-target" / "daemon"
        self.executable.parent.mkdir()
        self.executable.write_text("#!/bin/sh\nprintf 'original\\n'\n")
        self.executable.chmod(0o700)
        self.base = self.root / "run"
        self.base.mkdir(mode=0o700)
        self.artifacts = self.launch.prepare_artifacts(
            self.base, {"daemon": self.executable}, SOURCE,
        )
        self.artifact_set = self.base / "artifact-set.json"
        self.record_path = self.base / "round-1" / "launches" / "node-a.json"
        self.record_path.parent.mkdir(parents=True, mode=0o700)

    def emit_record(self, *, environment=None, arguments=None, stdin_authorization=True):
        environment = environment or {"FLAG": "enabled", "IGNORED": "not-a-config-input"}
        with patch.dict(os.environ, environment, clear=True), \
                patch.object(self.launch.os, "execve", side_effect=ExecObserved) as execute:
            with self.assertRaises(ExecObserved):
                self.launch.exec_launch(
                    self.artifact_set, "daemon", self.record_path, "node-a",
                    arguments or ["--config", str(self.base / "node-a" / "config.json"), "--token-stdin"],
                    ["FLAG"], config_file=self.base / "node-a" / "config.json",
                    stdin_authorization=stdin_authorization,
                )
        return json.loads(self.record_path.read_text()), execute.call_args

    def test_snapshot_survives_shared_target_replacement_and_is_private(self):
        artifact = self.artifacts["artifacts"]["daemon"]
        snapshot = self.base / artifact["path"]
        original = self.executable.read_bytes()
        self.executable.write_text("#!/bin/sh\nprintf 'rebuilt\\n'\n")
        self.assertEqual(snapshot.read_bytes(), original)
        self.assertEqual(artifact["sha256"], hashlib.sha256(original).hexdigest())
        self.assertEqual(artifact["size_bytes"], len(original))
        self.assertEqual(stat.S_IMODE(snapshot.stat().st_mode), 0o500)
        self.assertEqual(stat.S_IMODE(snapshot.parent.stat().st_mode), 0o700)
        self.assertEqual(self.artifacts["source"], SOURCE)

    def test_configuration_hash_binds_exact_argv_and_allowlisted_environment_without_plaintext(self):
        arguments = ["--device-name", "node-a", "--token-stdin"]
        environment = {"FLAG": "enabled", "SIGNING_KEY": "synthetic-private-key", "IGNORED": "a"}
        identity = self.launch.configuration_identity(
            arguments, environment, ["FLAG", "SIGNING_KEY"], stdin_authorization=True,
        )
        self.assertEqual(identity["source"], "cli_and_controlled_environment")
        self.assertEqual(identity["scope"], "argv_and_allowlisted_environment")
        self.assertEqual(identity["environment_keys"], ["FLAG", "SIGNING_KEY"])
        self.assertIn("stdin_authorization", identity["excluded_inputs"])
        self.assertNotIn("synthetic-private-key", json.dumps(identity))
        self.assertNotIn("node-a", json.dumps(identity))
        ignored = dict(environment, IGNORED="b")
        self.assertEqual(identity, self.launch.configuration_identity(
            arguments, ignored, ["SIGNING_KEY", "FLAG"], stdin_authorization=True,
        ))
        for argv, env in [(arguments + ["--no-host-candidates"], environment),
                          (arguments, dict(environment, FLAG="disabled")),
                          (arguments, dict(environment, SIGNING_KEY="different-private-key"))]:
            with self.subTest(argv=argv, environment_keys=sorted(env)):
                changed = self.launch.configuration_identity(
                    argv, env, ["FLAG", "SIGNING_KEY"], stdin_authorization=True,
                )
                self.assertNotEqual(identity["sha256"], changed["sha256"])

    def test_absent_configuration_is_launch_fact_and_generated_file_cannot_replace_it(self):
        record, _ = self.emit_record()
        self.assertEqual(record["configuration"]["config_file"],
                         {"state": "absent_at_launch", "sha256": None})
        generated = self.base / "node-a" / "config.json"
        generated.parent.mkdir()
        generated.write_text('{"token":"generated-runtime-secret"}')
        evidence = self.launch.read_launch_evidence(self.base, SOURCE, ["node-a"])
        self.assertTrue(evidence["valid"], evidence["errors"])
        reread = evidence["records"][0]["record"]
        self.assertEqual(reread["configuration"], record["configuration"])
        self.assertNotIn("generated-runtime-secret", json.dumps(evidence))

    def test_present_configuration_content_is_hashed_without_persisting_plaintext(self):
        path = self.base / "config.json"
        contents = b'{"key":"synthetic-config-file-secret"}'
        path.write_bytes(contents)
        identity = self.launch.configuration_identity(["--config", str(path)], {}, [], config_file=path)
        self.assertEqual(identity["config_file"], {"state": "present_at_launch",
                         "sha256": hashlib.sha256(contents).hexdigest()})
        path.write_bytes(contents + b" ")
        changed = self.launch.configuration_identity(["--config", str(path)], {}, [], config_file=path)
        self.assertNotEqual(identity["sha256"], changed["sha256"])
        self.assertNotIn("synthetic-config-file-secret", json.dumps(identity))

    def test_exec_failure_retains_typed_errno_and_cannot_be_collected_as_success(self):
        with patch.object(self.launch.os, "execve", side_effect=PermissionError(13, "synthetic-secret")):
            with self.assertRaises(PermissionError):
                self.launch.exec_launch(self.artifact_set, "daemon", self.record_path, "node-a", [], [])
        record = json.loads(self.record_path.read_text())
        self.assertEqual((record["state"], record["exec_errno"]), ("exec_failed", 13))
        self.assertNotIn("synthetic-secret", self.record_path.read_text())
        collected = self.launch.read_launch_evidence(self.base, SOURCE, ["node-a"])
        self.assertFalse(collected["valid"])
        self.assertIn("exec_failed:node-a", collected["errors"])

    def test_record_describes_the_exact_snapshot_passed_to_exec_and_has_monotonic_boundary(self):
        record, call = self.emit_record(environment={"FLAG": "synthetic-config-secret"})
        snapshot = self.base / self.artifacts["artifacts"]["daemon"]["path"]
        self.assertEqual(Path(call.args[0]), snapshot)
        self.assertEqual(Path(call.args[1][0]), snapshot)
        self.assertEqual(call.args[2]["FLAG"], "synthetic-config-secret")
        self.assertEqual(record["state"], "exec_requested")
        self.assertEqual(record["source"], SOURCE)
        self.assertEqual(record["artifact"], self.artifacts["artifacts"]["daemon"])
        self.assertEqual(record["pid"], os.getpid())
        self.assertIs(type(record["monotonic_ns"]), int)
        self.assertGreater(record["monotonic_ns"], 0)
        self.assertNotIn("synthetic-config-secret", self.record_path.read_text())

    def test_exec_wrapper_preserves_pid_and_stdin_authorization(self):
        self.executable.write_text(
            "#!/bin/sh\nread -r authorization\n"
            "test \"$authorization\" = \"synthetic-stdin-secret\" || exit 9\n"
            "printf '{\"pid\":%s,\"authorization_received\":true}\\n' \"$$\"\n"
        )
        process_base = self.root / "exec-run"
        process_base.mkdir(mode=0o700)
        self.launch.prepare_artifacts(process_base, {"daemon": self.executable}, SOURCE)
        record_path = process_base / "round-1" / "launches" / "node-a.json"
        record_path.parent.mkdir(parents=True, mode=0o700)
        process = subprocess.Popen(
            [sys.executable, str(Path(self.launch.__file__)), "exec",
             "--artifact-set", str(process_base / "artifact-set.json"),
             "--component", "daemon", "--record", str(record_path), "--role", "node-a",
             "--stdin-authorization", "--", "--token-stdin"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        stdout, stderr = process.communicate("synthetic-stdin-secret\n", timeout=5)
        self.assertEqual(process.returncode, 0, stderr)
        observed = json.loads(stdout)
        record = json.loads(record_path.read_text())
        self.assertEqual(observed["pid"], process.pid)
        self.assertEqual(record["pid"], process.pid)
        self.assertTrue(observed["authorization_received"])
        self.assertNotIn("synthetic-stdin-secret", record_path.read_text())

    def test_reader_rejects_missing_roles_and_strictly_typed_or_source_tampered_records(self):
        original, _ = self.emit_record()
        valid = self.launch.read_launch_evidence(self.base, SOURCE, ["node-a"])
        self.assertTrue(valid["valid"], valid["errors"])
        self.assertEqual(valid["records"][0]["sha256"],
                         hashlib.sha256(self.record_path.read_bytes()).hexdigest())
        missing = self.launch.read_launch_evidence(self.base, SOURCE, ["node-a", "node-b"])
        self.assertFalse(missing["valid"])
        changes = [lambda value: value.update(schema_version=True),
                   lambda value: value.update(pid=True),
                   lambda value: value.update(monotonic_ns=True),
                   lambda value: value.update(role=[]),
                   lambda value: value.update(state={}),
                   lambda value: value["source"].update(patch_sha256="c" * 64),
                   lambda value: value["artifact"].update(sha256="bad"),
                   lambda value: value["artifact"].update(path="../shared-target/daemon"),
                   lambda value: value["configuration"].update(sha256=123),
                   lambda value: value["configuration"]["config_file"].update(state="generated_after_start")]
        for change in changes:
            altered = copy.deepcopy(original)
            change(altered)
            self.record_path.write_text(json.dumps(altered))
            with self.subTest(change=changes.index(change)):
                rejected = self.launch.read_launch_evidence(self.base, SOURCE, ["node-a"])
                self.assertFalse(rejected["valid"], rejected)
        complete_base = self.root / "multiple-relays"
        write_valid_launch_evidence(complete_base)
        with patch.object(self.launch.os, "execve", side_effect=ExecObserved):
            for role in ("relay-2", "relay-1-restart-1"):
                with self.assertRaises(ExecObserved):
                    self.launch.exec_launch(complete_base / "artifact-set.json", "relay",
                        complete_base / "round-1" / "launches" / f"{role}.json", role, [], [])
        complete = self.launch.read_launch_evidence(complete_base, SOURCE)
        self.assertTrue(complete["valid"], complete["errors"])
        self.assertEqual(len(complete["records"]), 6)
        for role in ("relay-2", "relay-1-restart-1"):
            path = complete_base / "round-1" / "launches" / f"{role}.json"
            original = path.read_bytes()
            altered = json.loads(original)
            altered["artifact"]["sha256"] = "c" * 64
            path.write_text(json.dumps(altered))
            self.assertFalse(self.launch.read_launch_evidence(complete_base, SOURCE)["valid"])
            path.write_bytes(original)

    def test_snapshot_tamper_is_rejected_before_exec_or_collection(self):
        self.emit_record()
        snapshot = self.base / self.artifacts["artifacts"]["daemon"]["path"]
        snapshot.chmod(0o700)
        snapshot.write_text("#!/bin/sh\nprintf 'tampered\\n'\n")
        snapshot.chmod(0o500)
        with patch.object(self.launch.os, "execve") as execute:
            with self.assertRaises(ValueError):
                self.launch.exec_launch(
                    self.artifact_set, "daemon", self.base / "rejected.json", "node-b", [], [],
                )
            execute.assert_not_called()
        self.assertFalse(self.launch.read_launch_evidence(self.base, SOURCE, ["node-a"])["valid"])


if __name__ == "__main__":
    unittest.main()
