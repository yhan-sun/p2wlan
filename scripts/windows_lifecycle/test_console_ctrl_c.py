#!/usr/bin/env python3
"""Exercise the actual injector's native failure path on the Windows runner."""

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


@unittest.skipUnless(sys.platform == "win32", "requires native Windows console API")
class ConsoleCtrlCInjectorTests(unittest.TestCase):
    def test_target_without_console_cannot_report_a_successful_broadcast(self):
        powershell = shutil.which("pwsh")
        self.assertIsNotNone(powershell)
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / "injector.json"
            # Own a live target created without a console. AttachConsole must
            # fail for this target, without broadcasting into the runner.
            target_process = subprocess.Popen(
                [sys.executable, "-c", "import sys; sys.stdin.buffer.read(1)"],
                creationflags=subprocess.CREATE_NO_WINDOW,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            target = target_process.pid
            request = "a" * 32
            try:
                self.assertIsNone(target_process.poll())
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
            finally:
                try:
                    target_process.communicate(input=b"x", timeout=3)
                except subprocess.TimeoutExpired:
                    target_process.kill()
                    target_process.communicate(timeout=3)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            native = json.loads(evidence.read_text(encoding="utf-8-sig"))
            self.assertEqual(native["target_process_id"], target)
            self.assertEqual(native["request_id"], request)
            self.assertIs(native["broadcast_succeeded"], False)
            self.assertEqual(native["stage"], "attach_console")
            self.assertTrue(native["detail"])


if __name__ == "__main__":
    unittest.main()
