#!/usr/bin/env python3
"""Real local subprocess tests using synthetic adapters, never a Minecraft game."""

import hashlib
import errno
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

import minecraft_interaction_runner as runner
from test_minecraft_interaction import manifest


HERE = Path(__file__).resolve().parent
PRELUDE = '''
import hashlib, json, os, signal, sys, time
envelope = json.load(sys.stdin)
plan = envelope["manifest"]
round_ = next(r for r in plan["rounds"] if r["round_nonce"] == envelope["round_nonce"])
seq = 0
def send(value):
    print(json.dumps(value), flush=True)
def event(kind, offset, request=0, **changes):
    global seq
    value = {name: plan[name] if name == "run_nonce" else round_[name]
             for name in ("run_nonce", "round_nonce", "adapter_nonce", "session_nonce", "clock_nonce")}
    value.update(kind=kind, offset_ns=offset, event_seq=seq)
    seq += 1
    if kind.startswith("action_"):
        value["request_nonce"] = round_["requests"][request]["request_nonce"]
    if kind == "action_confirmed":
        value.update(confirmation="server_block_update", correlation="isolated_unique_target_transition",
                     wire_request_id=None, observation_sha256="a" * 64)
        for name in ("target_sha256", "before_state_sha256", "after_state_sha256"):
            value[name] = round_["requests"][request][name]
    value.update(changes)
    send({"type": "event", "event": value})
def finish():
    units = {"server_tps": "ticks/s", "server_mspt": "ms/tick", "server_gc_pause_ms": "ms",
             "tcp_retransmissions": "count", "raknet_retransmissions": "count"}
    metrics = {name: {"value": None, "unit": unit, "reason": "not_collected", "source_sha256": None,
                      "clock_nonce": None, "start_offset_ns": None, "end_offset_ns": None}
               for name, unit in units.items()}
    send({"type": "finish", "elapsed_ns": len(round_["requests"]) * 30,
          "termination": "completed", "telemetry": metrics})
'''
SUCCESS = '''
event("session_ready", 0)
for i in range(len(round_["requests"])):
    event("action_started", 10 + i * 30, i)
    event("action_confirmed", 15 + i * 30, i)
finish()
'''
PENDING = 'event("session_ready", 0)\nevent("action_started", 10)\n'


def wait_path(path, timeout=5):
    deadline = time.monotonic() + timeout
    while not path.exists() and time.monotonic() < deadline:
        time.sleep(.01)
    if not path.exists():
        raise AssertionError("fixture did not become ready")


@unittest.skipUnless(os.name == "posix" and sys.version_info >= (3, 11), "POSIX Python 3.11+ ownership tests")
class RunnerTests(unittest.TestCase):
    def run_fixture(self, code, *, plan=None, timeout_ms=1500, cancel=None):
        raw = json.dumps(plan or manifest()).encode()
        argv = [sys.executable, "-u", "-c", PRELUDE + code]
        before = time.monotonic()
        result = runner.run_campaign(raw, argv, timeout_ms, cancel)
        self.assertLess(time.monotonic() - before, 8)
        self.assertEqual(result["frozen_manifest_json"].encode(), raw)
        self.assertEqual(result["manifest_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(result["summary"]["prescheduled_requests"],
                         sum(len(row["requests"]) for row in json.loads(raw)["rounds"]))
        self.assertIsNone(result["summary"]["application_interaction_ms"])
        for receipt in result["receipts"]:
            if receipt["child_pid"] is not None:
                self.assertTrue(receipt["cleanup"]["direct_child_reaped"])
                self.assertTrue(receipt["cleanup"]["anchor_reaped"])
                self.assertFalse(receipt["cleanup"]["ownership_failed"])
                self.assertEqual(len(receipt["cleanup"]["owned_group_signal_attempts"]), 2)
                self.assertNotIn("permission_denied", receipt["cleanup"]["owned_group_signal_attempts"])
                self.assertNotEqual(receipt["child_pid"], receipt["anchor_pid"])
                with self.assertRaises(ChildProcessError):
                    os.waitpid(receipt["child_pid"], os.WNOHANG)
                with self.assertRaises(ChildProcessError):
                    os.waitpid(receipt["anchor_pid"], os.WNOHANG)
        return result

    def test_full_frozen_campaign_success_and_child_clock_rtt(self):
        result = self.run_fixture(SUCCESS, plan=manifest(rounds=2))
        self.assertTrue(result["execution_completed_cleanly"])
        self.assertEqual(len({r["child_pid"] for r in result["receipts"]}), 2)
        self.assertEqual(result["summary"]["reported_successes"], 4)
        self.assertEqual(result["summary"]["fixture_latency_ms"]["p99"], .000005)
        self.assertTrue(all(r["returncode"] == 0 for r in result["receipts"]))

    def test_recorded_label_remains_self_reported_without_game_proof(self):
        result = self.run_fixture(SUCCESS, plan=manifest(execution_kind="recorded_game_session"))
        self.assertEqual(result["summary"]["execution_kind"], "recorded_game_session")
        self.assertIn("self_reported_latency_ms", result["summary"])
        self.assertIn("real_minecraft_execution", result["summary"]["not_proven"])

    def test_early_eof_seals_pending_once_and_does_not_retry(self):
        result = self.run_fixture(PENDING)
        self.assertEqual(result["receipts"][0]["reason"], "missing_finish")
        self.assertEqual(result["summary"]["status_counts"]["cancelled"], 1)
        self.assertEqual(result["summary"]["status_counts"]["not_started"], 1)
        self.assertFalse(result["execution_completed_cleanly"])

    def test_deadline_does_not_invent_client_clock_timeout(self):
        result = self.run_fixture(PENDING + "time.sleep(10)", timeout_ms=250)
        self.assertEqual(result["receipts"][0]["reason"], "supervisor_timeout")
        self.assertEqual(result["reports"][0]["elapsed_ns"], 10)
        self.assertEqual(result["summary"]["status_counts"]["timeout"], 0)
        self.assertEqual(result["summary"]["status_counts"]["cancelled"], 1)
        self.assertEqual(result["summary"]["fixture_latency_ms"]["sample_count"], 0)

    def test_finish_without_exit_is_bounded_execution_failure(self):
        result = self.run_fixture(SUCCESS + "time.sleep(10)", timeout_ms=250)
        self.assertEqual(result["receipts"][0]["reason"], "supervisor_timeout")
        self.assertFalse(result["execution_completed_cleanly"])

    def test_nonzero_exit_cannot_be_clean_execution(self):
        result = self.run_fixture(SUCCESS + "sys.exit(7)")
        self.assertEqual(result["receipts"][0]["reason"], "nonzero_exit")
        self.assertEqual(result["receipts"][0]["returncode"], 7)
        self.assertFalse(result["execution_completed_cleanly"])

    def test_no_newline_stdout_flood_is_bounded(self):
        result = self.run_fixture('while True: os.write(1, b"x" * 4096)')
        receipt = result["receipts"][0]
        self.assertEqual(receipt["reason"], "protocol_error")
        self.assertEqual(receipt["error"], "line_byte_limit")
        self.assertLessEqual(receipt["output_bytes_read"], runner.MAX_LINE_BYTES + 4096)

    def test_stderr_flood_is_bounded(self):
        result = self.run_fixture('while True: os.write(2, b"x" * 4096)')
        receipt = result["receipts"][0]
        self.assertEqual(receipt["error"], "stderr_byte_limit")
        self.assertLessEqual(len(receipt["stderr"]), runner.MAX_STDERR_BYTES)
        self.assertLessEqual(receipt["output_bytes_read"], runner.MAX_STDERR_BYTES + 4096)

    def test_total_output_budget_preserves_unlaunched_round_denominator(self):
        with mock.patch.object(runner, "MAX_TOTAL_BYTES", 4096):
            result = self.run_fixture('while True: os.write(2, b"x" * 4096)', plan=manifest(rounds=3))
        self.assertEqual(result["receipts"][0]["error"], "output_byte_limit")
        self.assertEqual([r["reason"] for r in result["receipts"][1:]],
                         ["not_launched_output_budget"] * 2)
        self.assertEqual(result["summary"]["status_counts"]["not_started"], 6)

    def test_event_count_budget_is_enforced_in_native_stream(self):
        result = self.run_fixture('for i in range(17000): send({"type":"event", "event":{}})')
        self.assertEqual(result["receipts"][0]["stream_reason"], "protocol_error")
        self.assertEqual(result["receipts"][0]["reason"], "invalid_evidence")
        self.assertEqual(result["reports"][0]["events"], [])

    def test_malformed_duplicate_nonfinite_and_non_utf8_lines_reject(self):
        for raw in (b'{"type":"event","type":"finish"}\n', b'{"x":NaN}\n', b'\xff\n', b'[]\n'):
            with self.subTest(raw=raw):
                result = self.run_fixture(f"os.write(1, {raw!r})")
                self.assertEqual(result["receipts"][0]["reason"], "protocol_error")

    def test_unterminated_finish_and_second_finish_reject(self):
        result = self.run_fixture(PENDING + 'sys.stdout.write("{}")')
        self.assertEqual(result["receipts"][0]["reason"], "truncated_line")
        result = self.run_fixture(SUCCESS + "finish()")
        self.assertEqual(result["receipts"][0]["error"], "message_after_finish")

    def test_foreign_clock_does_not_extend_salvaged_elapsed(self):
        code = PENDING + 'event("action_confirmed", 100000000000, clock_nonce="f" * 32)\n'
        result = self.run_fixture(code)
        self.assertEqual(result["reports"][0]["elapsed_ns"], 10)
        self.assertEqual(result["summary"]["rounds"][0]["rejected_events"], {"source_mismatch": 1})
        self.assertEqual(result["summary"]["status_counts"]["cancelled"], 1)

    def test_invalid_offset_and_fake_wire_nonce_cannot_certify_success(self):
        for mutation in ('wire_request_id="invented"', 'offset_ns=True'):
            code = PENDING + ('event("action_confirmed", 15, wire_request_id="invented")\n'
                              if mutation.startswith("wire") else
                              'event("action_confirmed", True)\n') + 'finish()'
            with self.subTest(mutation=mutation):
                result = self.run_fixture(code)
                self.assertEqual(result["receipts"][0]["reason"], "invalid_evidence")
                self.assertEqual(result["summary"]["reported_successes"], 0)

    def test_missing_executable_retains_all_requests(self):
        result = runner.run_campaign(json.dumps(manifest(rounds=2)).encode(),
                                     ["/nonexistent-p2wlan-fixture-adapter"], 100)
        self.assertEqual([r["reason"] for r in result["receipts"]], ["spawn_error"] * 2)
        self.assertEqual(result["summary"]["status_counts"]["not_started"], 4)

    def test_precancel_does_not_start_any_child(self):
        cancel = threading.Event()
        cancel.set()
        result = self.run_fixture(SUCCESS, plan=manifest(rounds=3), cancel=cancel)
        self.assertTrue(all(r["child_pid"] is None for r in result["receipts"]))
        self.assertEqual(result["summary"]["status_counts"]["not_started"], 6)

    def test_cancellation_reaps_owned_group_and_preserves_unrelated_child(self):
        with tempfile.TemporaryDirectory() as directory:
            child_ids = Path(directory) / "child-ids"
            # Grandchild stays in the owned group, ignores TERM, and retains the
            # pipes. A heartbeat must stop after cleanup; unrelated child survives.
            heartbeat = Path(directory) / "heartbeat"
            code = PENDING + f'''
pid = os.fork()
if pid == 0:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    while True:
        with open({str(heartbeat)!r}, "ab") as f: f.write(b"x")
        time.sleep(.01)
with open({str(child_ids)!r}, "w") as f: f.write(str(pid))
time.sleep(10)
'''
            unrelated = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"])
            cancel = threading.Event()
            def trigger():
                wait_path(heartbeat)
                cancel.set()
            trigger_thread = threading.Thread(target=trigger)
            trigger_thread.start()
            try:
                result = self.run_fixture(code, plan=manifest(rounds=2), cancel=cancel)
                trigger_thread.join(timeout=5)
                self.assertFalse(trigger_thread.is_alive())
                self.assertEqual(result["receipts"][0]["reason"], "cancelled")
                self.assertEqual(result["receipts"][1]["reason"], "not_launched_cancelled")
                self.assertIsNone(unrelated.poll())
                size = heartbeat.stat().st_size
                time.sleep(.1)
                self.assertEqual(heartbeat.stat().st_size, size)
            finally:
                unrelated.terminate()
                unrelated.wait(timeout=2)

    def test_exited_parent_with_pipe_holding_descendant_is_bounded(self):
        code = '''
if os.fork() == 0:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    time.sleep(10)
os._exit(0)
'''
        result = self.run_fixture(code, timeout_ms=250)
        self.assertEqual(result["receipts"][0]["reason"], "supervisor_timeout")
        self.assertEqual(result["receipts"][0]["returncode"], 0)

    def test_closed_pipes_without_exit_still_hits_deadline(self):
        result = self.run_fixture('os.close(1)\nos.close(2)\ntime.sleep(10)', timeout_ms=250)
        self.assertEqual(result["receipts"][0]["reason"], "supervisor_timeout")

    def test_invalid_inputs_fail_before_launch(self):
        for argv in ("echo text", [], ["relative"], [sys.executable, None], [sys.executable, "x" * 4097]):
            with self.subTest(argv=argv), mock.patch.object(runner, "run_round") as launch:
                with self.assertRaises(ValueError):
                    runner.run_campaign(json.dumps(manifest()).encode(), argv, 100)
                launch.assert_not_called()
        with mock.patch.object(runner.os, "name", "nt"), self.assertRaisesRegex(ValueError, "POSIX"):
            runner.run_campaign(json.dumps(manifest()).encode(), [sys.executable], 100)
        with mock.patch.object(runner.signal, "getsignal", return_value=signal.SIG_IGN):
            with self.assertRaisesRegex(ValueError, "exclusively own"):
                runner.run_campaign(json.dumps(manifest()).encode(), [sys.executable], 100)

    def test_cleanup_failure_prevents_further_launches_without_dropping_denominator(self):
        cleanup = runner.cleanup
        def report_incomplete(anchor, child):
            result = cleanup(anchor, child)
            result["owned_group_signal_attempts"] = ["permission_denied", "permission_denied"]
            result["ownership_failed"] = True
            return result
        with mock.patch.object(runner, "cleanup", side_effect=report_incomplete):
            result = runner.run_campaign(json.dumps(manifest(rounds=2)).encode(),
                                         [sys.executable, "-u", "-c", PRELUDE + SUCCESS], 1500)
        self.assertEqual(result["receipts"][0]["reason"], "cleanup_incomplete")
        self.assertEqual(result["receipts"][1]["reason"], "not_launched_cleanup_incomplete")
        self.assertEqual(result["summary"]["prescheduled_requests"], 4)

    def test_natural_adapter_exit_cleans_term_ignoring_grandchildren_in_two_rounds(self):
        with tempfile.TemporaryDirectory() as directory:
            code = f'''
heartbeat = {directory!r} + '/' + round_["round_nonce"]
if os.fork() == 0:
    os.close(1); os.close(2)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    while True:
        with open(heartbeat, 'ab') as f: f.write(b'x')
        time.sleep(.01)
while not os.path.exists(heartbeat): time.sleep(.005)
''' + SUCCESS
            result = self.run_fixture(code, plan=manifest(rounds=2))
            self.assertTrue(result["execution_completed_cleanly"])
            paths = [Path(directory) / r["round_nonce"] for r in result["receipts"]]
            sizes = [p.stat().st_size for p in paths]
            time.sleep(.1)
            self.assertEqual([p.stat().st_size for p in paths], sizes)
            for receipt in result["receipts"]:
                self.assertEqual(receipt["returncode"], 0)
                self.assertEqual(receipt["cleanup"]["anchor_returncode"], -signal.SIGKILL)
                self.assertEqual(receipt["cleanup"]["owned_group_signal_attempts"], ["sent", "sent"])

    def test_group_eperm_with_live_grandchild_fails_closed_and_stops_next_round(self):
        original_killpg = os.killpg
        groups = []
        def denied(group, sig):
            if group not in groups:
                groups.append(group)
            raise PermissionError(errno.EPERM, "injected ambiguous group failure")
        with tempfile.TemporaryDirectory() as directory:
            heartbeat = Path(directory) / 'heartbeat'
            code = PRELUDE + f'''
if os.fork() == 0:
    os.close(1); os.close(2)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        with open({str(heartbeat)!r}, 'ab') as f: f.write(b'x')
        time.sleep(.01)
    os._exit(0)
while not os.path.exists({str(heartbeat)!r}): time.sleep(.005)
''' + SUCCESS
            try:
                with mock.patch.object(runner.os, "killpg", side_effect=denied):
                    result = runner.run_campaign(json.dumps(manifest(rounds=2)).encode(),
                                                 [sys.executable, "-u", "-c", code], 1500)
                self.assertFalse(result["execution_completed_cleanly"])
                self.assertEqual(len(groups), 1)
                first, second = result["receipts"]
                self.assertEqual(first["reason"], "cleanup_incomplete")
                self.assertEqual(first["cleanup"]["owned_group_signal_attempts"], ["permission_denied"] * 2)
                self.assertTrue(first["cleanup"]["direct_child_reaped"])
                self.assertTrue(first["cleanup"]["anchor_reaped"])
                self.assertEqual(second["reason"], "not_launched_cleanup_incomplete")
                self.assertEqual(result["summary"]["prescheduled_requests"], 4)
                size = heartbeat.stat().st_size
                time.sleep(.1)
                self.assertGreater(heartbeat.stat().st_size, size)
            finally:
                for group in groups:
                    original_killpg(group, signal.SIGKILL)
                time.sleep(.05)
            stopped = heartbeat.stat().st_size
            time.sleep(.1)
            self.assertEqual(heartbeat.stat().st_size, stopped)

    def test_anchor_birth_failure_is_structured_and_stops_further_launches(self):
        with mock.patch.object(runner.subprocess, "Popen", side_effect=OSError("fixture spawn failure")) as launch:
            result = runner.run_campaign(json.dumps(manifest(rounds=2)).encode(), [sys.executable], 1500)
        launch.assert_called_once()
        self.assertEqual(result["receipts"][0]["observation_reason"], "anchor_spawn_error")
        self.assertEqual(result["receipts"][1]["reason"], "not_launched_cleanup_incomplete")
        self.assertEqual(result["summary"]["status_counts"]["not_started"], 4)

    def test_anchor_handshake_eof_bad_data_and_timeout_never_launch_adapter(self):
        cases = [("pass", "anchor_early_exit"),
                 ('import os; os.write(1, b"wrong")', "anchor_bad_handshake"),
                 ('import time; time.sleep(10)', "anchor_ready_timeout")]
        for code, reason in cases:
            with self.subTest(reason=reason), mock.patch.object(runner, "ANCHOR_CODE", code):
                result = runner.run_campaign(json.dumps(manifest(rounds=2)).encode(), [sys.executable], 250)
            first, second = result["receipts"]
            self.assertEqual(first["observation_reason"], reason)
            self.assertIsNone(first["child_pid"])
            self.assertTrue(first["cleanup"]["anchor_reaped"])
            with self.assertRaises(ChildProcessError):
                os.waitpid(first["anchor_pid"], os.WNOHANG)
            self.assertEqual(second["reason"], "not_launched_cleanup_incomplete")
            self.assertEqual(result["summary"]["prescheduled_requests"], 4)

    def test_anchor_unexpected_death_during_adapter_run_fails_closed(self):
        code = PRELUDE + PENDING + 'os.kill(os.getpgrp(), signal.SIGUSR1)\ntime.sleep(10)'
        # Only the anchor receives the uncaught USR1: the adapter ignores it.
        code = 'import signal\nsignal.signal(signal.SIGUSR1, signal.SIG_IGN)\n' + code
        result = runner.run_campaign(json.dumps(manifest(rounds=2)).encode(),
                                     [sys.executable, "-u", "-c", code], 1500)
        first, second = result["receipts"]
        self.assertEqual(first["observation_reason"], "anchor_early_exit")
        self.assertTrue(first["cleanup"]["ownership_failed"])
        self.assertEqual(first["cleanup"]["anchor_returncode"], -signal.SIGUSR1)
        self.assertTrue(first["cleanup"]["direct_child_reaped"])
        self.assertTrue(first["cleanup"]["anchor_reaped"])
        self.assertEqual(second["reason"], "not_launched_cleanup_incomplete")
        self.assertEqual(result["summary"]["status_counts"]["cancelled"], 1)

    def test_waitid_is_not_needed_with_owned_anchor(self):
        with mock.patch.object(runner.os, "waitid", None, create=True):
            result = self.run_fixture(SUCCESS)
        self.assertTrue(result["execution_completed_cleanly"])

    def test_cli_sigterm_writes_private_complete_cancelled_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            plan_path, output, ready = base / "plan.json", base / "result.json", base / "ready"
            raw = json.dumps(manifest(rounds=2), indent=2)
            plan_path.write_text(raw)
            code = PRELUDE + PENDING + f'open({str(ready)!r}, "w").close()\ntime.sleep(10)'
            args = [sys.executable, str(HERE / "minecraft_interaction_runner.py"),
                    "--manifest", str(plan_path), "--adapter-argv", json.dumps([sys.executable, "-u", "-c", code]),
                    "--timeout-ms", "5000", "--output", str(output)]
            process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                wait_path(ready)
                plan_path.write_text("changed after child launch")
                process.send_signal(signal.SIGTERM)
                stdout, stderr = process.communicate(timeout=5)
                self.assertEqual(process.returncode, 1, stderr)
                value = json.loads(output.read_text())
                self.assertEqual(value["frozen_manifest_json"], raw)
                self.assertEqual(value["summary"]["prescheduled_requests"], 4)
                self.assertEqual(value["receipts"][0]["reason"], "cancelled")
                self.assertEqual(value["receipts"][1]["reason"], "not_launched_cancelled")
                self.assertEqual(output.stat().st_mode & 0o777, 0o600)
                self.assertIn(b"unverified", stdout)
                again = subprocess.run(args, capture_output=True, timeout=5)
                self.assertEqual(again.returncode, 2)
                self.assertEqual(json.loads(output.read_text()), value)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=2)


if __name__ == "__main__":
    unittest.main()
