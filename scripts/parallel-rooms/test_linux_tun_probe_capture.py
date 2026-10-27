#!/usr/bin/env python3
"""Actual anchored probe children and explicit pipe/deadline failure controls; no TUN."""
import copy
from contextlib import ExitStack, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import stat
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import linux_tun_evidence as harness
import linux_tun_probe_capture as captures
import linux_tun_stall as stall
from linux_tun_owned import OwnedGroups


class PlatformControls(unittest.TestCase):
    def test_non_POSIX_capture_and_inheritance_reject_before_native_access(self):
        path = Path("unused-original-child.log")
        with patch.object(captures.os, "name", "nt"), patch.object(captures.secrets, "token_hex") as nonce:
            with self.assertRaisesRegex(ValueError, "POSIX"):
                captures.WriteCaptures(path, 2)
            nonce.assert_not_called()
            with patch.object(os, "fstat") as descriptor, patch.object(harness.subprocess, "Popen") as spawn:
                with self.assertRaisesRegex(ValueError, "POSIX"):
                    OwnedGroups().spawn("invalid", [], path, env={}, pass_fds=(7,))
                descriptor.assert_not_called()
                spawn.assert_not_called()

    def test_missing_capture_keeps_fixed32_without_owner_or_kernel_claim(self):
        registry = captures.WriteCaptures.__new__(captures.WriteCaptures)
        registry.expected_probes, registry.capture_id, registry.captures = 4, "a" * 32, []
        entries = harness.manifest("1" * 32, "2" * 32)
        before = copy.deepcopy(entries)
        result = registry.summary(entries)
        self.assertEqual(entries, before)
        self.assertEqual((result["prescheduled_requests"], result["admitted_probes"], result["complete_probes"]), (32, 0, 0))
        self.assertFalse(result["passed"])
        for key in ["daemon_registration_verified", "kernel_tun_verified", "physical_send_verified", "canonical_current_owner_verified"]:
            self.assertIs(result[key], False)


@unittest.skipUnless(os.name == "posix", "actual nonblocking pipe required")
class PipeReapOrderingControls(unittest.TestCase):
    """Actual pipe bytes and explicit child-poll controls; no OS-write/native facts."""
    def pipe_capture(self):
        reader, writer = os.pipe()
        os.set_blocking(reader, False)
        capture = captures.ProbeCapture.__new__(captures.ProbeCapture)
        capture.reader, capture.writer, capture.gap = reader, writer, None
        capture.raw, capture.eof = bytearray(), False
        capture.stream = SimpleNamespace(gap=None, feed=lambda _raw: None)
        capture.live_window_bridge = None
        self.addCleanup(capture.close)
        return capture

    def test_original_pipe_tail_and_EOF_precede_child_reap_with_one_read_per_poll(self):
        capture = self.pipe_capture()
        payload = b"x" * 4176  # More than one original 4096-byte read.
        self.assertEqual(os.write(capture.writer, payload), len(payload))
        capture._close("writer")
        states = []
        capture.live_window_bridge = SimpleNamespace(
            observe=lambda owner, _now: states.append(bytes(owner.raw)), seal=lambda: None)
        child = SimpleNamespace(poll=unittest.mock.Mock(return_value=0))
        with patch.object(harness.time, "sleep"), patch.object(captures.os, "read", wraps=os.read) as reads:
            self.assertEqual(harness.wait_child(child, time.monotonic() + 1, capture=capture), 0)
        self.assertEqual(bytes(capture.raw), payload)
        self.assertTrue(capture.eof)
        self.assertIsNone(capture.reader)
        self.assertEqual(states, [payload[:4096], payload])
        self.assertEqual([call.args[1] for call in reads.call_args_list], [4096, 4096, 4096])
        child.poll.assert_called_once_with()

    def test_open_pipe_uses_original_deadline_without_polling_or_catchup(self):
        capture = self.pipe_capture()
        child = SimpleNamespace(poll=unittest.mock.Mock(return_value=0))
        clock = [0.0]
        with patch.object(harness.time, "monotonic", side_effect=lambda: clock[0]), \
                patch.object(harness.time, "sleep", side_effect=lambda seconds: clock.__setitem__(0, clock[0] + seconds)):
            with self.assertRaisesRegex(TimeoutError, "original application child deadline"):
                harness.wait_child(child, .05, capture=capture)
        child.poll.assert_not_called()
        self.assertFalse(capture.eof)
        self.assertEqual(capture.raw, b"")


@unittest.skipUnless(os.name == "posix", "owned probe captures require POSIX pipes and process groups")
class OwnedCaptureControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        retained = os.environ.get("P2WLAN_CAPTURE_TEST_ARTIFACT_DIR")
        if retained:
            cls.root = Path(retained)
            harness.udp.validate_output_path(cls.root)
            cls.root.mkdir(mode=0o700)
        else:
            cls.temporary = tempfile.TemporaryDirectory()
            cls.addClassCleanup(cls.temporary.cleanup)
            cls.root = Path(cls.temporary.name).resolve()
        cls.cases = {name: cls.actual(name) for name in ["udp", "tcp", "refused", "prepare-failed", "output-failed"]}

    @classmethod
    def actual(cls, name):
        protocol = "tcp" if name in ("tcp", "refused") else "udp"
        root = cls.root / name
        root.mkdir()
        kind = socket.SOCK_DGRAM if protocol == "udp" else socket.SOCK_STREAM
        reserved = [socket.socket(socket.AF_INET, kind) for _ in range(2)]
        for sock in reserved:
            sock.bind(("127.0.0.1", 0))
        bind, target = (sock.getsockname() for sock in reserved)
        entry = harness.manifest("1" * 32, "2" * 32)[0 if protocol == "udp" else 2]
        config = harness.udp.Config(bind, target, entry["run_nonce"], entry["round_nonce"])
        tool = harness.DUAL / (protocol + "_business_probe.py")
        groups = OwnedGroups()
        capture = None
        echo = None
        report_path, echo_path = root / "probe.json", root / "echo.json"
        try:
            if name != "refused":
                reserved[1].close()
                echo = groups.spawn("echo", harness.tool_argv(tool, "echo", target, bind, entry, echo_path),
                                    root / "echo.log", env=dict(os.environ), socket_tool=True)
                ready_end = time.monotonic() + 2
                while time.monotonic() < ready_end:
                    if echo.poll() is not None:
                        raise RuntimeError("original fixture echo exited before readiness")
                    if any(json.loads(line).get("event") == "echo_ready"
                           for line in (root / "echo.log").read_text().splitlines()):
                        break
                    time.sleep(.01)
                else:
                    raise TimeoutError("original fixture echo readiness")
            if name == "prepare-failed":
                registry = captures.WriteCaptures(root, 2)
                capture = registry.prepare(groups, entry, protocol, bind, target, "../invalid", "not-created")
                if capture is not None:
                    raise AssertionError("deliberate preparation failure was accepted")
            else:
                namespace = os.readlink("/proc/self/ns/net") if sys.platform == "linux" else None
                capture = captures.ProbeCapture(root, "probe", config, protocol, "a" * 32, "b" * 32, namespace)
            argv = harness.tool_argv(tool, "probe", bind, target, entry, report_path)
            if capture:
                argv.extend(capture.arguments())
            reserved[0].close()
            child = groups.spawn("probe", argv, root / "probe.log", env=dict(os.environ), socket_tool=True,
                                 pass_fds=(capture.writer,) if capture else ())
            end = time.monotonic() + 4
            if capture:
                capture.bind(groups, child)
                if capture.writer is not None:
                    raise AssertionError("parent retained original write descriptor")
            code = harness.wait_child(child, end, capture=capture)
            report = json.loads(report_path.read_text())
            echo_code = harness.wait_child(echo, time.monotonic() + 4) if echo else None
            if capture:
                if name == "output-failed":
                    capture.raw_path.write_bytes(b"preserve-existing-output")
                result = capture.finish(report)
            else:
                result = entry["original_write_stream"]
            expected_code = int(name == "refused")
            if code != expected_code or echo_code not in (None, 0):
                raise AssertionError((name, code, echo_code, (root / "probe.log").read_text()))
            return dict(result=result, report=report, echo=json.loads(echo_path.read_text()) if echo else None,
                        raw=(capture.raw_path.read_bytes() if capture else None),
                        result_file=(json.loads(capture.result_path.read_text()) if capture and capture.result_path.exists() else None),
                        config=config, plan=capture.prepared if capture else None,
                        capture=capture, groups=groups)
        finally:
            if capture:
                capture.close()
            for sock in reserved:
                sock.close()
            cleanup = groups.cleanup(grace_seconds=.1, join_seconds=2)
            (root / "original-cleanup.json").write_text(json.dumps(cleanup, indent=2) + "\n")
            if capture and capture.result is None:
                capture.finish(None)
            if not all(row["complete"] for row in cleanup):
                raise AssertionError((name, cleanup))

    def assert_no_authority(self, result):
        self.assertEqual((result["request_count"], len(result["requests"])), (8, 8))
        for key in ["daemon_registration_verified", "kernel_tun_verified", "physical_send_verified", "canonical_current_owner_verified"]:
            self.assertIs(result[key], False)
        if not result["stream_complete"]:
            self.assertTrue(all(not r["accepted_in_original_deadline"] for r in result["requests"]))

    def test_actual_UDP8_anchor_ownership_raw_digest_and_original_deadlines(self):
        case = self.cases["udp"]
        result = case["result"]
        self.assertTrue(result["stream_complete"], result["gap_reason"])
        self.assertEqual(result["write_calls"], 8)
        self.assertTrue(all(r["accepted_in_original_deadline"] for r in result["requests"]))
        self.assertEqual(result["raw_sha256"], hashlib.sha256(case["raw"]).hexdigest())
        self.assertEqual(result, case["result_file"])
        for path in [case["capture"].raw_path, case["capture"].plan_path, case["capture"].result_path]:
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(case["echo"]["responses_sent"], 8)
        self.assertEqual(result["original_child_birth_namespace_matched"], sys.platform == "linux")
        self.assertEqual(result["original_same_boot_clock_matched"], sys.platform == "linux")
        self.assert_no_authority(result)

    def test_actual_TCP8_has_one_original_connection_and_owned_cleanup(self):
        case = self.cases["tcp"]
        self.assertTrue(case["result"]["stream_complete"], case["result"]["gap_reason"])
        self.assertEqual(case["report"]["connection_attempts"], 1)
        self.assertEqual(case["echo"]["accepted_connections"], 1)
        self.assertTrue(all(r["accepted_in_original_deadline"] for r in case["result"]["requests"]))
        self.assert_no_authority(case["result"])

    def test_actual_refused_original_connection_keeps8_unsent_and_no_writes(self):
        case = self.cases["refused"]
        self.assertTrue(case["result"]["stream_complete"], case["result"]["gap_reason"])
        self.assertEqual(case["result"]["write_calls"], 0)
        self.assertEqual([r["status"] for r in case["report"]["requests"]], ["not_sent"] * 8)
        self.assert_no_authority(case["result"])

    def test_preparation_gap_preserves_actual_original8_business_results(self):
        case = self.cases["prepare-failed"]
        self.assertFalse(case["result"]["stream_complete"])
        self.assertEqual([r["status"] for r in case["report"]["requests"]], ["success"] * 8)
        self.assertNotIn("request_plan", case["report"])
        self.assertEqual(case["report"]["evidence"], harness.udp.UNVERIFIED)
        self.assert_no_authority(case["result"])

    def test_output_conflict_invalidates_capture_without_overwriting_or_changing8(self):
        case = self.cases["output-failed"]
        self.assertEqual(case["raw"], b"preserve-existing-output")
        self.assertEqual(case["result"]["gap_reason"], "owned_capture_output_failed")
        self.assertFalse(case["result"]["stream_complete"])
        self.assertEqual([r["status"] for r in case["report"]["requests"]], ["success"] * 8)
        self.assert_no_authority(case["result"])

    def test_descriptor_admission_rejects_file_read_end_and_blocking_writer_before_anchor(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryFile() as regular:
            groups = OwnedGroups()
            reader, writer = os.pipe()
            try:
                for descriptor in [regular.fileno(), reader, writer]:
                    with self.assertRaises(ValueError):
                        groups.spawn("invalid", [], Path(directory) / "unused.log", env={}, pass_fds=(descriptor,))
                self.assertEqual(groups.owners, [])
                self.assertFalse((Path(directory) / "unused.log").exists())
            finally:
                os.close(reader)
                os.close(writer)

    def test_unregistered_child_never_triggers_birth_lookup_and_closes_parent_pipe(self):
        with tempfile.TemporaryDirectory() as directory:
            capture = captures.ProbeCapture(Path(directory).resolve(), "probe", self.cases["udp"]["config"],
                                            "udp", "c" * 32, "d" * 32, None)
            with patch.object(captures.streams.OriginalChild, "from_spawn") as birth:
                capture.bind(SimpleNamespace(owners=[]), SimpleNamespace(returncode=None))
                birth.assert_not_called()
            self.assertIsNone(capture.reader)
            self.assertIsNone(capture.writer)
            result = capture.finish(None)
            self.assert_no_authority(result)
            self.assertFalse(result["stream_complete"])

    def test_each_poll_performs_only_one_bounded_nonblocking_read(self):
        reader, writer = os.pipe()
        capture = captures.ProbeCapture.__new__(captures.ProbeCapture)
        capture.reader, capture.writer, capture.gap, capture.raw = reader, writer, None, bytearray()
        capture.live_window_bridge = None
        feeds = []
        capture.stream = SimpleNamespace(gap=None, feed=feeds.append)
        try:
            with patch.object(captures.os, "read", return_value=b"x" * 4096) as read:
                capture.drain()
                read.assert_called_once_with(reader, 4096)
            self.assertEqual(feeds, [b"x" * 4096])
            self.assertEqual(len(capture.raw), 4096)
        finally:
            capture.close()

    def test_capture_cost_consumes_original_wait_deadline_before_child_poll(self):
        now = [0.0]
        observer = SimpleNamespace(drain=lambda: now.__setitem__(0, .06))
        child = SimpleNamespace(poll=unittest.mock.Mock(return_value=0))
        with patch.object(harness.time, "monotonic", side_effect=lambda: now[0]), patch.object(harness.time, "sleep") as sleep:
            with self.assertRaisesRegex(TimeoutError, "original application"):
                harness.wait_child(child, .05, capture=observer)
            child.poll.assert_not_called()
            sleep.assert_not_called()

    def test_capture_cost_cannot_refill_original_paused_sample_budget(self):
        now = [10_000_000_000]
        observer = SimpleNamespace(drain=lambda: now.__setitem__(0, now[0] + 600_000_000))
        lab = SimpleNamespace(status=unittest.mock.Mock())
        owner = SimpleNamespace(observe=lambda: {"state": "T"})
        child = SimpleNamespace(poll=unittest.mock.Mock())
        with self.assertRaisesRegex(TimeoutError, "original|admitted"):
            stall.collect_paused_samples(lab, owner, {}, child, [], now[0] + 3_000_000_000,
                                         now=lambda: now[0], sleep=lambda _seconds: None, capture=observer)
        lab.status.assert_not_called()
        child.poll.assert_not_called()

    def test_interrupted_capture_keeps_raw_prefix_and8_without_invented_owner(self):
        with tempfile.TemporaryDirectory() as directory:
            capture = captures.ProbeCapture(Path(directory).resolve(), "probe", self.cases["udp"]["config"],
                                            "udp", "e" * 32, "f" * 32, None)
            capture.raw.extend(b"partial-original-prefix")
            capture.close()
            result = capture.finish(None)
            self.assertEqual(capture.raw_path.read_bytes(), b"partial-original-prefix")
            self.assertFalse(result["stream_complete"])
            self.assertEqual(len(capture.raw), 0)
            self.assert_no_authority(result)

    def test_mocked_optin_main_keeps_business16_and_cleanup_but_rejects_missing_capture(self):
        # Dispatch/control-flow fixture only: no Linux service, namespace, PID
        # lookup or TUN is executed. Reuse the original stall contract inputs.
        import test_linux_tun_stall as original_controls
        with tempfile.TemporaryDirectory() as directory, ExitStack() as patches:
            root = Path(directory).resolve()
            daemon, control, out = root / "daemon", root / "control", root / "evidence"
            daemon.write_bytes(b"offline-daemon")
            control.write_bytes(b"offline-control")
            lab = SimpleNamespace(run_id="offline", evidence={"stages": []}, namespaces=[],
                                  temp=SimpleNamespace(cleanup=lambda: None), preserve_logs=lambda: None)
            groups = SimpleNamespace(cleanup=lambda: [{"complete": True}])
            def exercise(_lab, _groups, report, _out, **_kwargs):
                for entry, observed in zip(report["manifest"], original_controls.completed_manifest()):
                    entry.update(records=observed["records"], probe_exit=observed["probe_exit"], outcome="observed")
                report["server_stall"] = original_controls.completed_evidence()
            actual_exists = Path.exists
            patches.enter_context(patch.object(Path, "exists", lambda p:
                True if str(p) == "/dev/net/tun" else actual_exists(p)))
            patches.enter_context(patch.object(harness.sys, "platform", "linux"))
            patches.enter_context(patch.object(harness.os, "geteuid", return_value=0))
            patches.enter_context(patch.object(harness.sys, "argv", ["offline", "--server-stall", "--write-facts",
                "--daemon", str(daemon), "--control", str(control), "--head", "0" * 40, "--output-dir", str(out)]))
            patches.enter_context(patch.object(harness.original, "run", return_value=
                harness.subprocess.CompletedProcess([], 0, "0" * 40 + "\n", "")))
            patches.enter_context(patch.object(harness.subprocess, "check_output", side_effect=
                lambda argv, **_kwargs: (harness.ROOT / argv[-1].split(":", 1)[1]).read_bytes()))
            patches.enter_context(patch.object(harness, "OwnedGroups", return_value=groups))
            patches.enter_context(patch.object(harness, "EvidenceLab", return_value=lab))
            patches.enter_context(patch.object(harness, "resource_plan", return_value=None))
            patches.enter_context(patch.object(harness, "exercise", side_effect=exercise))
            patches.enter_context(patch.object(harness, "cleanup_network", return_value={"complete": True}))
            patches.enter_context(patch.object(stall, "restore_before_cleanup", return_value={"complete": True}))
            patches.enter_context(patch.object(harness.signal, "signal"))
            patches.enter_context(patch.dict(harness.os.environ, {}, clear=True))
            with redirect_stdout(io.StringIO()):
                code = harness.main()
            report = json.loads((out / "report.json").read_text())
            self.assertEqual(code, 1)
            self.assertTrue(report["passed"])
            self.assertTrue(report["cleanup_complete"])
            self.assertEqual(report["application"]["prescheduled_requests"], 16)
            self.assertFalse(report["original_write_observations"]["passed"])
            self.assertEqual(report["original_write_observations"]["prescheduled_requests"], 16)


if __name__ == "__main__":
    unittest.main()
