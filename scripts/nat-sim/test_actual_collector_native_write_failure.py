#!/usr/bin/env python3
"""External DRAFT: complete original CLI, real collector output-write EACCES.

Author has not imported, installed or executed this file. This test adds only
private filesystem inputs and a collector-only stderr redirection in its own
generated shell launcher. NEW late filesystem helper adds one interpreter
initialization in the same original command PID and consumes its unchanged
deadline. Production, existing tests and external tools stay unchanged. First future execution is expected GREEN, never a manufactured RED.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import sys
import tempfile
import time
import unittest

from fixture_http_owner_assertions import assert_http_owner_union, bounded_http_contract_json
from test_actual_round_callers import (
    ActualCliFixture,
    LOG_CAP,
    PROTOCOL_SECONDS,
    ROLES,
    SHELL,
    SOURCE_HEAD,
    TEARDOWN_SECONDS,
    WORKFLOW_HEAD,
    matrix_module,
    source_repository,
)

PREPARATION_SECONDS = 4
COLLECTOR_STDERR_CAP = 8 * 1024
FAULT_BYTES = b"{}\n"
MARKER = "B01_ACTUAL_COLLECTOR_NATIVE_OUTPUT_WRITE_FAILURE"


COLLECTOR_INPUT_HELPER = r'''#!/usr/bin/env python3
"""Fixture-only late FS input, then same-PID exec of bound original tool."""
import hashlib
import json
import os
from pathlib import Path
import shlex
import stat
import sys

ORIGINAL_COLLECTOR_SHA = "a0692c81a102eddfe4589f3a506b20e0f48b2aa752880e5ce5442137dde6a5ab"
ORIGINAL_EXTERNAL_TOOL_SHA = "b6e56e156abf4f649cff86358eb34ad638f1c3b6864f47ac2c1cabd53e09cbfa"
FAULT_BYTES = b"{}\n"


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def bounded_regular(path, cap, mode=None):
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                         | getattr(os, "O_NONBLOCK", 0))
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= cap,
                "input_not_bounded_regular")
        require(mode is None or stat.S_IMODE(before.st_mode) == mode, "input_mode_mismatch")
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            data = stream.read(cap + 1)
        after = os.fstat(descriptor)
        require(len(data) == before.st_size and len(data) <= cap,
                "input_short_or_over_cap")
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
                "input_changed_during_read")
        return data, before
    finally:
        os.close(descriptor)


def digest_regular(path, cap):
    return hashlib.sha256(bounded_regular(path, cap)[0]).hexdigest()


def main(argv):
    require(len(argv) >= 4, "helper_arguments_missing")
    old_tool, root, tool, *arguments = argv
    root = Path(root)
    require(root.is_absolute() and root.resolve() == root, "case_root_not_canonical")
    require(root.is_dir() and not root.is_symlink(), "case_root_invalid")
    require(tool == "python3" and arguments, "original_tool_arguments_invalid")
    settings = json.loads(bounded_regular(root / "fixture-config.json", 32 * 1024, 0o600)[0])
    require(settings.get("fixture_only") is True and settings.get("case") == "complete-direct"
            and type(settings.get("rounds")) is int and settings["rounds"] == 1,
            "fixture_case_or_round_mismatch")
    real_python = settings["real_python"]
    require(Path(real_python).resolve() == Path(sys.executable).resolve(), "real_python_changed")
    old_tool = Path(old_tool)
    require(old_tool == root / "fixture-external-tools.py", "old_tool_path_changed")
    require(digest_regular(old_tool, 64 * 1024) == ORIGINAL_EXTERNAL_TOOL_SHA
            and settings["external_tools_sha256"] == ORIGINAL_EXTERNAL_TOOL_SHA,
            "old_external_tool_not_original")
    entry = Path(settings["private_repository"]) / "scripts/nat-sim/collect_evidence.py"
    require(arguments[0] == str(entry), "not_original_collector_entry")
    require(digest_regular(entry, 64 * 1024) == ORIGINAL_COLLECTOR_SHA
            and settings["original_sources"]["scripts/nat-sim/collect_evidence.py"] == ORIGINAL_COLLECTOR_SHA,
            "collector_source_changed")
    require(arguments.count("--output") == 1 and arguments.count("--round") == 1,
            "collector_output_or_round_argument_count")
    require(arguments[arguments.index("--round") + 1] == "1", "collector_round_changed")
    round_dir = root / "artifacts/round-1"
    canonical = round_dir / "nat-evidence.json"
    require(arguments[arguments.index("--output") + 1] == str(canonical),
            "collector_original_output_changed")
    require(os.geteuid() != 0, "EACCES_requires_nonroot")
    require(round_dir.is_dir() and not round_dir.is_symlink()
            and round_dir.resolve() == round_dir, "original_round_directory_missing_or_changed")
    info = round_dir.stat()
    require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700
            and os.access(round_dir, os.W_OK), "original_round_parent_not_writable700")
    target = round_dir / ".collector-output-readonly.json"
    require(not os.path.lexists(target) and not os.path.lexists(canonical),
            "fault_leaf_or_canonical_already_exists")
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(FAULT_BYTES)
        stream.flush()
        os.fchmod(stream.fileno(), 0o400)
    data, target_info = bounded_regular(target, 4096, 0o400)
    require(target_info.st_uid == os.geteuid() and data == FAULT_BYTES
            and os.access(target, os.R_OK) and not os.access(target, os.W_OK),
            "fault_target_not_genuinely_readonly")
    target_before = {"dev": target_info.st_dev, "ino": target_info.st_ino,
                     "uid": target_info.st_uid, "mode": stat.S_IMODE(target_info.st_mode),
                     "size": target_info.st_size, "mtime_ns": target_info.st_mtime_ns,
                     "sha256": hashlib.sha256(data).hexdigest()}
    os.symlink(target.name, canonical)
    require(os.readlink(canonical) == target.name and canonical.resolve() == target.resolve(),
            "relative_fault_symlink_changed")
    original_exec = shlex.join([real_python, "-S", str(old_tool), str(root), "python3"])
    old_launcher = "#!/bin/sh\nexec " + original_exec + ' "$@"\n'
    command = ["python3", *arguments]
    input_record = {
        "fixture_only": True, "product_result_claimed": False, "setup_completed": True,
        "setup_scope": "original_collector_command_launch_after_original_CLI_ART_creation",
        "helper_pid": os.getpid(), "helper_source_sha256": digest_regular(Path(__file__), 32 * 1024),
        "fault": "readonly_regular_target_via_same_round_relative_symlink",
        "target": str(target), "target_before": target_before,
        "canonical_leaf": str(canonical), "symlink_target": target.name,
        "collector_native_stderr": str(root / "collector-native-stderr.log"),
        "original_generated_launcher_sha256": hashlib.sha256(old_launcher.encode()).hexdigest(),
        "new_private_generated_launcher_sha256": digest_regular(root / "fake-path/python3", 16 * 1024),
        "original_collector_sha256": ORIGINAL_COLLECTOR_SHA,
        "original_external_tool_sha256": ORIGINAL_EXTERNAL_TOOL_SHA,
        "original_command_argv_sha256": hashlib.sha256(json.dumps(command, ensure_ascii=True,
            separators=(",", ":")).encode()).hexdigest(),
        "same_PID_exec_chain": "fixtureinputhelper->old_external_tool->original_collector",
        "extra_helper_initialization_consumes_original_deadline": True,
        "production_or_existing_source_modified": False,
    }
    payload = (json.dumps(input_record, sort_keys=True) + "\n").encode()
    require(len(payload) <= 32 * 1024, "input_record_size_limit")
    descriptor = os.open(root / "collector-filesystem-input.json",
                         os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(payload)
    # No fork, fake exit1, source patch, extra grace or alternate argv.
    # The already-spawned command PID becomes the old tool and real collector.
    os.execv(real_python, [real_python, "-S", str(old_tool), str(root), "python3", *arguments])


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (OSError, ValueError, KeyError, IndexError, TypeError, UnicodeError) as error:
        print("B01_COLLECTOR_FIXTURE_INPUT_FAILURE:" + type(error).__name__ + ":" + str(error),
              file=sys.stderr)
        raise SystemExit(92)
'''


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def target_identity(path):
    value = path.stat()
    return {
        "dev": value.st_dev,
        "ino": value.st_ino,
        "uid": value.st_uid,
        "mode": stat.S_IMODE(value.st_mode),
        "size": value.st_size,
        "mtime_ns": value.st_mtime_ns,
        "sha256": digest(path),
    }


class ActualCollectorNativeWriteFailureTests(unittest.TestCase):
    def test_actual_collector_output_write_permission_error_preserves_native_cause_and_owned_cleanup(self):
        # Old ceilings stay exact. Helper/launcher generation consumes prep4;
        # late filesystem setup and extra interpreter initialization consume
        # the original collector supervised deadline, with no extra window.
        self.assertEqual((LOG_CAP, PROTOCOL_SECONDS, TEARDOWN_SECONDS, SHELL),
                         (2 * 1024 * 1024, 12, 2, "/bin/bash"))
        self.assertNotEqual(os.geteuid(), 0,
                            "B01_COLLECTOR_FIXTURE_PRECONDITION: EACCES requires non-root")
        preparation_end = time.monotonic() + PREPARATION_SECONDS
        evidence = os.environ.get("P2WLAN_B01_FIXTURE_ARTIFACTS")
        if evidence:
            directory = Path(evidence).resolve() / self._testMethodName
        else:
            temporary = tempfile.TemporaryDirectory(prefix="p2wlan-actual-collector-native-")
            self.addCleanup(temporary.cleanup)
            directory = Path(temporary.name).resolve() / "exclusive-case"
        fixture = ActualCliFixture(directory, source_repository(), "complete-direct", 1)
        self.addCleanup(fixture.close)
        self.assertEqual({key: fixture.environment[key] for key in
                          ("MODE", "ROUNDS", "EGRESS_CAPTURE", "ROUND_TIMEOUT_S",
                           "DIRECT_TIMEOUT_S", "OVERLAY_TIMEOUT_S", "ROUND_CLEANUP_GRACE_MS")},
                         {"MODE": "direct", "ROUNDS": "1", "EGRESS_CAPTURE": "listeners",
                          "ROUND_TIMEOUT_S": "20", "DIRECT_TIMEOUT_S": "2",
                          "OVERLAY_TIMEOUT_S": "2", "ROUND_CLEANUP_GRACE_MS": "1000"})

        # The original CLI must create ART itself (main309 rejects an
        # existing directory). Only paths are computed here; no ART mkdir.
        self.assertFalse(os.path.lexists(fixture.artifacts),
                         "B01_COLLECTOR_FIXTURE_PRECONDITION: ART must not preexist")
        round_dir = fixture.artifacts / "round-1"
        target = round_dir / ".collector-output-readonly.json"
        canonical = round_dir / "nat-evidence.json"
        helper_path = fixture.root / "collector-input-helper.py"
        with helper_path.open("x") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(COLLECTOR_INPUT_HELPER)
        helper_sha256 = digest(helper_path)

        # Non-collector arguments retain the exact old single exec. This
        # collector-only branch execs the bounded same-PID late FS helper,
        # then that helper execs the old tool/original collector unchanged.
        launcher = fixture.root / "fake-path/python3"
        old_exec = shlex.join([sys.executable, "-S", str(fixture.root / "fixture-external-tools.py"),
                              str(fixture.root), "python3"])
        old_launcher = "#!/bin/sh\nexec " + old_exec + ' "$@"\n'
        self.assertEqual(launcher.read_text(), old_launcher)
        self.assertEqual(stat.S_IMODE(launcher.stat().st_mode), 0o700)
        collector_entry = fixture.repository / "scripts/nat-sim/collect_evidence.py"
        native_stderr_path = fixture.root / "collector-native-stderr.log"
        self.assertFalse(native_stderr_path.exists())
        launcher_text = (
            "#!/bin/sh\n"
            "if [ \"$1\" = " + shlex.quote(str(collector_entry)) + " ]; then\n"
            "    set -C\n"
            "    exec " + shlex.join([sys.executable, "-S", str(helper_path),
                                       str(fixture.root / "fixture-external-tools.py"),
                                       str(fixture.root), "python3"])
            + ' "$@" 2> ' + shlex.quote(str(native_stderr_path)) + "\n"
            "fi\n"
            "exec " + old_exec + ' "$@"\n'
        )
        launcher.write_text(launcher_text)
        self.assertEqual(stat.S_IMODE(launcher.stat().st_mode), 0o700)
        self.assertFalse((fixture.root / "collector-filesystem-input.json").exists())
        self.assertFalse(os.path.lexists(fixture.artifacts),
                         "B01_COLLECTOR_FIXTURE_PRECONDITION: setup must wait for original collector launch")
        self.assertLess(time.monotonic(), preparation_end,
                        "B01_COLLECTOR_FIXTURE_PRECONDITION: original preparation4 expired")

        fixture.execute()
        # A helper capability/setup failure is a fixture failure, never the
        # target native collector1. Check bounded native diagnostics first.
        with native_stderr_path.open("rb") as stream:
            helper_diagnostics = stream.read(COLLECTOR_STDERR_CAP + 1)
        self.assertLessEqual(len(helper_diagnostics), COLLECTOR_STDERR_CAP,
                             "B01_COLLECTOR_FIXTURE_PRECONDITION: native stderr cap exceeded")
        self.assertNotIn(b"B01_COLLECTOR_FIXTURE_INPUT_FAILURE:", helper_diagnostics,
                         "B01_COLLECTOR_FIXTURE_PRECONDITION: late filesystem helper failed")
        input_record = bounded_http_contract_json(fixture.root / "collector-filesystem-input.json")
        self.assertIs(input_record["setup_completed"], True)
        self.assertEqual(input_record["setup_scope"],
                         "original_collector_command_launch_after_original_CLI_ART_creation")
        self.assertEqual(input_record["helper_source_sha256"], helper_sha256)
        self.assertEqual(digest(helper_path), helper_sha256)
        self.assertEqual(input_record["original_collector_sha256"],
                         fixture.original_sources["scripts/nat-sim/collect_evidence.py"])
        self.assertEqual(input_record["original_external_tool_sha256"],
                         digest(fixture.root / "fixture-external-tools.py"))
        self.assertEqual(input_record["new_private_generated_launcher_sha256"], digest(launcher))
        self.assertEqual(input_record["original_generated_launcher_sha256"],
                         hashlib.sha256(old_launcher.encode()).hexdigest())
        self.assertEqual(input_record["target"], str(target))
        self.assertEqual(input_record["canonical_leaf"], str(canonical))
        target_before = input_record["target_before"]
        self.assertEqual(fixture.cli_status, 1, MARKER)
        self.assertFalse(fixture.rescued)
        self.assertTrue((round_dir / "business-validation.start-gate").is_file())
        for side in ("a", "b"):
            ready = bounded_http_contract_json(round_dir / ("node-" + side + ".fixture-ready.json"))
            business = bounded_http_contract_json(round_dir / ("node-" + side + ".fixture-business.json"))
            self.assertEqual(business["pid"], ready["pid"])
            baseline = bounded_http_contract_json(round_dir / ("node-" + side + ".baseline.readiness.json"))
            self.assertEqual(baseline["result"], "ready")
            self.assertTrue(baseline["process_alive"])
            self.assertTrue(baseline["token_present"])
            final_status = bounded_http_contract_json(round_dir / (".final-status-" + side + ".json"))
            self.assertEqual(final_status["result"], "available")
            self.assertIsNone(final_status["reason_code"])
        relay = bounded_http_contract_json(round_dir / "relay-barrier.readiness.json")
        self.assertEqual(relay["result"], "ready")
        self.assertIsNone(relay["reason_code"])
        for side in ("a", "b"):
            self.assertEqual(relay["http_status_" + side], 200)
            self.assertIs(relay["task_health_" + side], True)
            self.assertIs(relay["process_alive_" + side], True)
            self.assertIs(relay["relay_peer_confirmed_" + side], True)
        self.assertNotIn("RESULT: PASS", fixture.stdout)

        collector_events = [row for row in fixture.events
                            if row["tool"] == "original_collector_enter" and row["round"] == 1]
        self.assertEqual(len(collector_events), 1)
        self.assertEqual(collector_events[0]["output"], str(canonical))
        self.assertEqual(collector_events[0]["original_script_sha256"],
                         fixture.original_sources["scripts/nat-sim/collect_evidence.py"])
        self.assertTrue(stat.S_ISREG(native_stderr_path.lstat().st_mode))
        self.assertFalse(native_stderr_path.is_symlink())
        self.assertEqual(stat.S_IMODE(native_stderr_path.stat().st_mode), 0o600)
        with native_stderr_path.open("rb") as stream:
            native_stderr_bytes = stream.read(COLLECTOR_STDERR_CAP + 1)
        self.assertLessEqual(len(native_stderr_bytes), COLLECTOR_STDERR_CAP,
                             "B01_COLLECTOR_FIXTURE_PRECONDITION: original stderr cap exceeded")
        native_stderr = native_stderr_bytes.decode("utf-8", errors="strict")
        self.assertIn(str(collector_entry), native_stderr)
        self.assertIn("output.write_text(", native_stderr)
        self.assertIn("PermissionError:", native_stderr)
        self.assertIn("[Errno 13]", native_stderr)
        self.assertIn(str(canonical), native_stderr)
        self.assertNotIn("B01_FIXTURE_INFRA_FAILURE:", native_stderr)

        collector = bounded_http_contract_json(round_dir / ".collector-result.json")
        for field in ("started", "command_wait_completed", "wait_completed",
                      "owned_group_shutdown_requested_before_wait"):
            self.assertIs(collector[field], True, MARKER)
        self.assertEqual(collector["result"], "completed", MARKER)
        self.assertIsNone(collector["reason_code"])
        self.assertEqual(collector["command_wait_status"], 1, MARKER)
        self.assertEqual(collector["wait_status"], -9, MARKER)
        self.assertIs(collector["forced_termination"], False)
        self.assertEqual(collector.get("outputs", []), [])
        self.assertEqual(collector["entry_source"]["sha256"],
                         fixture.original_sources["scripts/nat-sim/collect_evidence.py"])
        self.assertEqual(collector["entry_source"]["scope"], "bytes_at_capture")
        self.assertEqual(collector["command_argv_sha256"], input_record["original_command_argv_sha256"])
        self.assertIs(type(input_record["helper_pid"]), int)
        self.assertGreater(input_record["helper_pid"], 0)
        try:
            os.kill(input_record["helper_pid"], 0)
        except ProcessLookupError:
            pass
        else:
            self.fail("B01_COLLECTOR_FIXTURE_PRECONDITION: same-PID helper/collector command remains live")

        finalization = bounded_http_contract_json(round_dir / "round-finalization.json")
        self.assertEqual(finalization["terminal_reason_code"], "collector_command_failed", MARKER)
        self.assertEqual(finalization["original_exit_code"], 1, MARKER)
        self.assertEqual(finalization["round_result"], "invalid", MARKER)
        self.assertEqual(finalization["shell_exit_status"], 1)
        self.assertEqual(finalization["shell_exit_status_source"], "exit_trap")
        self.assertEqual(finalization["collector"], collector)
        cleanup = bounded_http_contract_json(round_dir / "cleanup.json")
        business_owners = assert_http_owner_union(
            self, fixture, round_dir, cleanup, ROLES, (1,), MARKER)
        self.assertEqual(len(business_owners), 5)
        self.assertEqual(len(cleanup["owned_processes"]), 7)
        self.assertTrue(all(row["wait_completed"] and row["wait_status"] == 0
                            for row in business_owners))
        self.assertLessEqual(cleanup["duration_ms"], 1000)
        expected_stages = {"status-a", "status-b", "collector",
                           "http-barrier-1-a", "http-barrier-1-b"}
        workers = cleanup["owned_workers"]
        self.assertEqual(len(workers), 5)
        by_stage = {row["stage"]: row for row in workers}
        self.assertEqual(set(by_stage), expected_stages)
        self.assertEqual(by_stage["collector"], {"stage": "collector", **collector})
        for stage, worker in by_stage.items():
            self.assertIs(worker["command_wait_completed"], True)
            self.assertIs(worker["wait_completed"], True)
            self.assertIs(worker["owned_group_shutdown_requested_before_wait"], True)
            self.assertEqual(worker["command_wait_status"], 1 if stage == "collector" else 0)
            self.assertEqual(worker["wait_status"], -9)
            self.assertIs(worker["forced_termination"], False)

        parent_prefix = rf"^\++ B01_CLI pid={fixture.process.pid} sub=([01]) line=[0-9]+: (.*)$"
        trace = [(int(sub), command) for sub, command
                 in re.findall(parent_prefix, fixture.stderr, re.MULTILINE)]
        parent = [command for sub, command in trace if sub == 0]
        first_cause = "round_fail collector_command_failed 1"
        self.assertEqual(parent.count(first_cause), 1)
        unexpected = [index for index, command in enumerate(parent)
                      if command == "round_fail unexpected_exit 1"]
        self.assertTrue(unexpected)
        self.assertLess(parent.index(first_cause), min(unexpected))
        self.assertIn("round_on_exit 1", parent)
        self.assertIn("_ROUND_EXIT_TRAP_STATUS=1", parent)
        pubs = [(index, command) for index, (sub, command) in enumerate(trace)
                if sub == 1 and command.startswith("python3 ")
                and "/round_finalization.py publish " in command]
        self.assertEqual(len(pubs), 1)
        arguments = shlex.split(pubs[0][1])
        self.assertEqual(arguments[arguments.index("--reason-code") + 1], "collector_command_failed")
        self.assertEqual(arguments[arguments.index("--exit-code") + 1], "1")
        for row in cleanup["owned_processes"]:
            wait = f"wait {row['pid']}"
            ledger = f"round_record_wait {row['pid']} 0"
            self.assertEqual(parent.count(wait), 1)
            self.assertEqual(parent.count(ledger), 1)
            self.assertLess(parent.index(wait), parent.index(ledger))
            ledger_index = next(index for index, (sub, command) in enumerate(trace)
                                if sub == 0 and command == ledger)
            self.assertLess(ledger_index, pubs[0][0])

        self.assertEqual(target_identity(target), target_before)
        self.assertEqual(target.read_bytes(), FAULT_BYTES)
        self.assertFalse(canonical.is_symlink())
        self.assertTrue(stat.S_ISREG(canonical.lstat().st_mode))
        self.assertEqual(stat.S_IMODE(canonical.stat().st_mode), 0o600)
        evidence_record = bounded_http_contract_json(canonical)
        self.assertEqual(evidence_record["schema_version"], 1)
        self.assertIs(evidence_record["executed"], False)
        self.assertEqual(evidence_record["result"], "fail")
        self.assertEqual(evidence_record["decision"]["reason_code"], "harness:collector_command_failed")
        self.assertIsNone(evidence_record["nat_terminal"])
        self.assertEqual(evidence_record["collector_observations"],
                         {"available": False, "reference": None})
        preserved = round_dir / ".collector-nat-evidence.json"
        if preserved.exists():
            self.assertEqual(bounded_http_contract_json(preserved),
                             {"result": "unknown", "reason_code": "not_captured"})

        matrix = matrix_module(fixture.repository)
        with self.assertRaises(matrix.EvidenceError) as rejected:
            matrix.validate_round(round_dir, matrix.SCENARIO_BY_NAME["equal-step"],
                                  1, SOURCE_HEAD, WORKFLOW_HEAD)
        summary = matrix.aggregate_runs([{"exit_code": 1, "rounds": [
            {"result": "invalid", "reason": str(rejected.exception)}]}])
        self.assertEqual(summary["requested"]["rounds"], 1)
        self.assertEqual(summary["evidence_validity"]["invalid_rounds"], 1)
        self.assertEqual(summary["evidence_validity"]["valid_rounds"], 0)

        fixture.close()
        sentinel = bounded_http_contract_json(fixture.root / "sentinel-cleanup.json")
        self.assertIs(sentinel["wait_completed"], True)
        self.assertEqual(sentinel["wait_status"], 0)


if __name__ == "__main__":
    unittest.main()
