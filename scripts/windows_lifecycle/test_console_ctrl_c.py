#!/usr/bin/env python3
"""Exercise the actual injector against an explicitly detached owned target."""

import itertools
import json
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace


_DETACHED_TARGET = r"""import ctypes
from ctypes import wintypes
import json
import os
import sys

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
kernel32.FreeConsole.argtypes = []
kernel32.FreeConsole.restype = wintypes.BOOL
kernel32.GetConsoleProcessList.argtypes = [ctypes.POINTER(wintypes.DWORD), wintypes.DWORD]
kernel32.GetConsoleProcessList.restype = wintypes.DWORD
kernel32.GetCurrentProcessId.argtypes = []
kernel32.GetCurrentProcessId.restype = wintypes.DWORD

ctypes.set_last_error(0)
detached = bool(kernel32.FreeConsole())
detach_error = ctypes.get_last_error()
console_pids = (wintypes.DWORD * 1)()
ctypes.set_last_error(0)
console_count = int(kernel32.GetConsoleProcessList(console_pids, 1))
console_error = ctypes.get_last_error()
ready = {
    "request_id": sys.argv[2],
    "pid": os.getpid(),
    "native_pid": int(kernel32.GetCurrentProcessId()),
    "free_console_succeeded": detached,
    "free_console_error": detach_error,
    "console_process_count": console_count,
    "console_query_error": console_error,
    "no_console": console_count == 0 and console_error == 6,
}
# Publish the whole fresh ready record before blocking on the owner's stdin.
ready_path = sys.argv[1]
temporary_path = ready_path + ".tmp"
fd = os.open(temporary_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
with os.fdopen(fd, "wb") as stream:
    stream.write((json.dumps(ready, sort_keys=True) + "\n").encode("utf-8"))
os.replace(temporary_path, ready_path)
sys.stdin.buffer.read(1)
"""
_READY_TIMEOUT = 3
_RECORD_CAP = 16384


def _bounded_json(path):
    with path.open("rb") as stream:
        raw = stream.read(_RECORD_CAP + 1)
    if len(raw) > _RECORD_CAP:
        raise ValueError("console test record exceeded its fixed cap")
    return json.loads(raw.decode("utf-8-sig"))


def _injector_diagnostic(evidence, ready, injector, target, stdout, stderr):
    native = None
    native_error = None
    try:
        native = _bounded_json(evidence)
    except (OSError, UnicodeError, ValueError) as error:
        native_error = str(error)
    phase_records = []
    phase_error = None
    try:
        phase_paths = sorted(itertools.islice(
            Path(str(evidence) + ".diagnostic").glob("phase-*.json"), 13
        ))
        if not 1 <= len(phase_paths) <= 12:
            raise ValueError("phase count outside the fixed 1..12 bound")
        for phase_path in phase_paths:
            with phase_path.open("rb") as stream:
                raw = stream.read(2049)
            if len(raw) > 2048:
                raise ValueError("injector phase exceeded 2048 bytes")
            phase_records.append(json.loads(raw.decode("utf-8")))
    except (OSError, UnicodeError, ValueError) as error:
        phase_error = str(error)
    return {
        "returncode": injector.returncode,
        "stdout": stdout[:4096],
        "stderr": stderr[:4096],
        "target_ready": ready,
        "target_still_live": target.poll() is None,
        "injector_record": native,
        "injector_record_error": native_error,
        "injector_pid": injector.pid,
        "injector_phases": phase_records,
        "injector_phase_error": phase_error,
    }


class ConsoleDiagnosticBoundsTests(unittest.TestCase):
    def diagnostic(self, evidence, stdout="", stderr=""):
        return _injector_diagnostic(
            evidence, {"fixture_only": True},
            SimpleNamespace(pid=123, returncode=-1),
            SimpleNamespace(poll=lambda: None), stdout, stderr,
        )

    def test_partial_phases_survive_missing_final_native_record(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / "injector.json"
            phases = Path(str(evidence) + ".diagnostic")
            phases.mkdir()
            path = phases / "phase-01-initialize.json"
            raw = b'{"phase":"initialize","fixture_only":true}\n'
            path.write_bytes(raw)
            details = self.diagnostic(evidence)
            self.assertIsNone(details["injector_record"])
            self.assertIsNotNone(details["injector_record_error"])
            self.assertEqual(details["injector_phases"], [json.loads(raw)])
            self.assertIsNone(details["injector_phase_error"])
            self.assertEqual(path.read_bytes(), raw)

    def test_phase_count_and_byte_boundaries_remain_fail_closed(self):
        for count, size, accepted in [(12, 2048, True), (13, 2, False), (1, 2049, False)]:
            with self.subTest(count=count, size=size), tempfile.TemporaryDirectory() as directory:
                evidence = Path(directory) / "injector.json"
                phases = Path(str(evidence) + ".diagnostic")
                phases.mkdir()
                for number in range(count):
                    (phases / f"phase-{number:02}.json").write_bytes(b"{}" + b" " * (size - 2))
                details = self.diagnostic(evidence)
                if accepted:
                    self.assertIsNone(details["injector_phase_error"])
                    self.assertEqual(len(details["injector_phases"]), count)
                else:
                    self.assertIsNotNone(details["injector_phase_error"])

    def test_process_outputs_are_bounded_without_replacing_original_records(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / "injector.json"
            evidence.write_text('{"broadcast_succeeded":false}')
            details = self.diagnostic(evidence, "a" * 5000, "b" * 5000)
            self.assertEqual(details["stdout"], "a" * 4096)
            self.assertEqual(details["stderr"], "b" * 4096)
            self.assertIs(details["injector_record"]["broadcast_succeeded"], False)
            self.assertEqual(evidence.read_text(), '{"broadcast_succeeded":false}')


@unittest.skipUnless(sys.platform == "win32", "requires native Windows console API")
class ConsoleCtrlCInjectorTests(unittest.TestCase):
    def test_target_without_console_cannot_report_a_successful_broadcast(self):
        powershell = shutil.which("pwsh")
        self.assertIsNotNone(powershell)
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / "injector.json"
            ready_path = Path(directory) / "target-ready.json"
            request = uuid.uuid4().hex
            # CREATE_NO_WINDOW remains an input flag. The target's own native
            # FreeConsole plus independent query establish the precondition.
            target_process = subprocess.Popen(
                [sys.executable, "-c", _DETACHED_TARGET, str(ready_path), request],
                creationflags=subprocess.CREATE_NO_WINDOW,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            target = target_process.pid
            try:
                ready_end = time.monotonic() + _READY_TIMEOUT
                while not ready_path.exists():
                    self.assertIsNone(target_process.poll(), "target exited before native ready")
                    if time.monotonic() >= ready_end:
                        self.fail("target did not publish native detach readiness within 3 seconds")
                    time.sleep(0.01)
                ready = _bounded_json(ready_path)
                self.assertLess(time.monotonic(), ready_end, ready)
                self.assertIsInstance(ready, dict)
                self.assertEqual(ready["request_id"], request, ready)
                self.assertEqual(type(ready["pid"]), int, ready)
                self.assertEqual(type(ready["native_pid"]), int, ready)
                self.assertEqual(ready["pid"], target, ready)
                self.assertEqual(ready["native_pid"], target, ready)
                self.assertIs(ready["free_console_succeeded"], True, ready)
                self.assertEqual(ready["console_process_count"], 0, ready)
                self.assertEqual(ready["console_query_error"], 6, ready)
                self.assertIs(ready["no_console"], True, ready)
                self.assertIsNone(target_process.poll(), ready)
                injector_process = subprocess.Popen(
                    [
                        powershell,
                        "-NoLogo",
                        "-NoProfile",
                        "-NonInteractive",
                        "-ExecutionPolicy",
                        "Bypass",
                        "-File",
                        str(Path(__file__).with_name("send_console_ctrl_c.ps1")),
                        "-ProcessId",
                        str(target),
                        "-RequestId",
                        request,
                        "-EvidencePath",
                        str(evidence),
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                try:
                    injector_stdout, injector_stderr = injector_process.communicate(timeout=10)
                except subprocess.TimeoutExpired:
                    injector_process.kill()
                    injector_stdout = injector_stderr = ""
                    try:
                        injector_stdout, injector_stderr = injector_process.communicate(timeout=3)
                    finally:
                        # Retain bounded native phases before temporary cleanup;
                        # the original timeout still fails this test.
                        details = _injector_diagnostic(
                            evidence, ready, injector_process, target_process,
                            injector_stdout, injector_stderr,
                        )
                        details["reason_code"] = "console_injector_original_timeout"
                        print(json.dumps(details, sort_keys=True), file=sys.stderr)
                    raise
                result = subprocess.CompletedProcess(
                    injector_process.args, injector_process.returncode,
                    injector_stdout, injector_stderr,
                )
                details = _injector_diagnostic(
                    evidence, ready, injector_process, target_process,
                    result.stdout, result.stderr,
                )
                native = details["injector_record"]
                native_error = details["injector_record_error"]
                phase_records = details["injector_phases"]
                phase_error = details["injector_phase_error"]
                diagnostic = json.dumps(details, sort_keys=True)
                self.assertEqual(result.returncode, 1, diagnostic)
                self.assertIsNone(native_error, diagnostic)
                self.assertIsInstance(native, dict, diagnostic)
                self.assertEqual(native["target_process_id"], target, diagnostic)
                self.assertEqual(native["request_id"], request, diagnostic)
                self.assertIs(native["broadcast_succeeded"], False, diagnostic)
                self.assertEqual(native["stage"], "attach_console", diagnostic)
                self.assertEqual(type(native["native_error_code"]), int, diagnostic)
                self.assertEqual(native["native_error_code"], 6, diagnostic)
                self.assertTrue(native["detail"], diagnostic)
                self.assertIsNone(target_process.poll(), diagnostic)
                self.assertIsNone(phase_error, diagnostic)
                self.assertEqual(
                    [phase["phase"] for phase in phase_records],
                    ["initialize", "native_helper_ready", "attach_console",
                     "caught_exception", "write_native_evidence", "native_evidence_written"],
                    diagnostic,
                )
                previous_ticks = -1
                frequency = None
                for index, phase in enumerate(phase_records, 1):
                    self.assertEqual(phase["schema_version"], 1, diagnostic)
                    self.assertEqual(phase["request_id"], request, diagnostic)
                    self.assertEqual(phase["target_process_id"], target, diagnostic)
                    self.assertEqual(phase["helper_process_id"], injector_process.pid, diagnostic)
                    self.assertEqual(type(phase["helper_process_id"]), int, diagnostic)
                    self.assertEqual(phase["sequence"], index, diagnostic)
                    self.assertEqual(type(phase["elapsed_monotonic_ticks"]), int, diagnostic)
                    self.assertGreaterEqual(phase["elapsed_monotonic_ticks"], previous_ticks, diagnostic)
                    self.assertEqual(type(phase["monotonic_frequency_hz"]), int, diagnostic)
                    self.assertGreater(phase["monotonic_frequency_hz"], 0, diagnostic)
                    if frequency is not None:
                        self.assertEqual(phase["monotonic_frequency_hz"], frequency, diagnostic)
                    frequency = phase["monotonic_frequency_hz"]
                    previous_ticks = phase["elapsed_monotonic_ticks"]
                    self.assertIs(phase["broadcast_succeeded"], False, diagnostic)
            finally:
                try:
                    target_process.communicate(input=b"x", timeout=3)
                except subprocess.TimeoutExpired:
                    target_process.kill()
                    target_process.communicate(timeout=3)


if __name__ == "__main__":
    unittest.main()
