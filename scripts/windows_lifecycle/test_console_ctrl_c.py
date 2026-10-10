#!/usr/bin/env python3
"""Exercise the actual injector against an explicitly detached owned target."""

import json
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from pathlib import Path


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
                result = subprocess.run(
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
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                # Capture the helper record before the first result assertion.
                # Native 0 can never pass, but its own JSON is retained in the
                # failure message rather than discarded by TemporaryDirectory.
                native = None
                native_error = None
                try:
                    native = _bounded_json(evidence)
                except (OSError, UnicodeError, ValueError) as error:
                    native_error = str(error)
                diagnostic = json.dumps(
                    {
                        "returncode": result.returncode,
                        "stdout": result.stdout[:4096],
                        "stderr": result.stderr[:4096],
                        "target_ready": ready,
                        "target_still_live": target_process.poll() is None,
                        "injector_record": native,
                        "injector_record_error": native_error,
                    },
                    sort_keys=True,
                )
                self.assertEqual(result.returncode, 1, diagnostic)
                self.assertIsNone(native_error, diagnostic)
                self.assertIsInstance(native, dict, diagnostic)
                self.assertEqual(native["target_process_id"], target, diagnostic)
                self.assertEqual(native["request_id"], request, diagnostic)
                self.assertIs(native["broadcast_succeeded"], False, diagnostic)
                self.assertEqual(native["stage"], "attach_console", diagnostic)
                self.assertTrue(native["detail"], diagnostic)
                self.assertIsNone(target_process.poll(), diagnostic)
            finally:
                try:
                    target_process.communicate(input=b"x", timeout=3)
                except subprocess.TimeoutExpired:
                    target_process.kill()
                    target_process.communicate(timeout=3)


if __name__ == "__main__":
    unittest.main()
