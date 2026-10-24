"""Original phase registration precedes traffic; one owned pipe remains the cap."""
from contextlib import ExitStack
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import linux_tun_probe_capture as capture
import linux_tun_stall as stall
import linux_tun_stall_contract as contract


@unittest.skipUnless(os.name == "posix", "original POSIX pipe registry")
class DeferredPipeControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.registry = capture.WriteCaptures(Path(self.temp.name), 2)
        self.addCleanup(self.registry.close)
        self.entries = contract.manifest("11" * 16, "22" * 16)

    def prepare(self, index, *, deferred=False):
        entry = self.entries[index]
        # Exercise real plans and real pipes without reading a host namespace.
        with patch.object(capture.sys, "platform", "darwin"):
            return self.registry.prepare(SimpleNamespace(), entry, "udp",
                ("192.0.2.1", entry["source_port"]), ("192.0.2.2", entry["target_port"]),
                "udp-" + entry["phase"], "owned-fixture", defer_pipe=deferred)

    def test_two_registered_plans_admit_only_one_pipe_and_preserve_same_plan(self):
        paused = self.prepare(0)
        with patch.object(capture.os, "pipe", wraps=os.pipe) as pipe:
            fresh = self.prepare(1, deferred=True)
            self.assertEqual(pipe.call_count, 0)
        self.assertIsNotNone(paused.reader)
        self.assertIsNone(fresh.reader)
        self.assertIsNone(fresh.writer)
        self.assertFalse(fresh.pipe_opened)
        self.assertIsNone(fresh.stream)
        self.assertIsNone(fresh.result)
        self.assertTrue(set(paused.prepared.nonces).isdisjoint(fresh.prepared.nonces))
        prepared, raw = fresh.prepared, fresh.plan_path.read_bytes()
        with self.assertRaisesRegex(ValueError, "previous_pipe_open"):
            self.registry.activate(fresh)
        paused.close()
        self.registry.activate(fresh)
        self.assertIs(fresh.prepared, prepared)
        self.assertEqual(fresh.plan_path.read_bytes(), raw)
        self.assertFalse(os.get_blocking(fresh.reader))
        self.assertFalse(os.get_blocking(fresh.writer))
        self.assertIn(str(fresh.writer), fresh.arguments())
        os.write(fresh.writer, b"original")
        self.assertEqual(os.read(fresh.reader, 16), b"original")

    def test_foreign_duplicate_closed_and_already_used_capture_never_admit_pipe(self):
        fresh = self.prepare(0, deferred=True)
        with self.assertRaisesRegex(ValueError, "owner_missing"):
            self.registry.activate(SimpleNamespace(reader=None, writer=None))
        self.registry.captures.append(({}, fresh))
        with self.assertRaisesRegex(ValueError, "owner_missing"):
            self.registry.activate(fresh)
        self.registry.captures.pop()
        self.registry.activate(fresh)
        with self.assertRaises(ValueError):
            self.registry.activate(fresh)
        fresh.close()
        with self.assertRaisesRegex(ValueError, "already_admitted_or_closed"):
            self.registry.activate(fresh)
        closed = self.prepare(1, deferred=True)
        closed.close()
        with self.assertRaisesRegex(ValueError, "already_admitted_or_closed"):
            self.registry.activate(closed)

    def test_pipe_acquisition_failure_has_no_retry_and_denominator_stays_fixed(self):
        fresh = self.prepare(0, deferred=True)
        with patch.object(capture.os, "pipe", side_effect=OSError("original failure")) as pipe:
            with self.assertRaises(OSError):
                self.registry.activate(fresh)
            with self.assertRaisesRegex(ValueError, "already_admitted_or_closed"):
                self.registry.activate(fresh)
            self.assertEqual(pipe.call_count, 1)
        self.prepare(1, deferred=True)
        self.assertIsNone(self.prepare(1, deferred=True))
        self.assertEqual(self.registry.summary(self.entries)["prescheduled_requests"], 16)
        self.assertFalse(self.registry.summary(self.entries)["passed"])


class FreshBoundary(Exception):
    pass


class StallPreparationControls(unittest.TestCase):
    def run_until_fresh(self, *, fail_registration=False, fail_paused_spawn=False):
        events, now = [], [10_000_000_000]
        entries = contract.manifest("11" * 16, "22" * 16)
        report = {"manifest": entries}
        groups = SimpleNamespace(owners=[], kernel_captures=SimpleNamespace(),
                                 write_captures=SimpleNamespace())

        class Owner:
            def __init__(self, *_args):
                self.evidence = {}
            def stop(self, _end):
                events.append("stop")
                self.evidence["stopped_monotonic_ns"] = now[0]
            def observe(self):
                return {"state": "T"}
            def resume(self, end):
                events.append("resume")
                self.evidence.update(resume_requested_monotonic_ns=now[0], resumed_monotonic_ns=now[0])
                self.assert_end = end
                now[0] += 1

        class Capture:
            writer = 77
            def __init__(self, phase):
                self.phase = phase
            def arguments(self):
                return []
            def bind(self, *_args):
                events.append("bind-" + self.phase)
            def drain(self):
                pass
            def finish(self, _result):
                events.append("finish-" + self.phase)
                return {"stream_complete": True}

        def prepare_write(_groups, entry, *_args, defer_pipe=False):
            events.append(("prepare-" + entry["phase"], defer_pipe))
            return Capture(entry["phase"])

        def prepare_kernel(_lab, _groups, entry, *_args, deadline):
            events.append("register-" + entry["phase"])
            self.assertEqual(deadline, 20)
            if fail_registration and entry["phase"] == "fresh":
                raise ValueError("original registration failure")
            return entry["phase"]

        def spawn(name, *_args, **_kwargs):
            events.append("spawn-" + name)
            if name == "udp-fresh-probe":
                self.assertGreater(entries[1]["probe_spawn_requested_monotonic_ns"],
                                   report["server_stall"]["pause"]["resumed_monotonic_ns"])
                raise FreshBoundary()
            if name == "udp-paused-probe" and fail_paused_spawn:
                raise ValueError("original spawn failure")
            child = SimpleNamespace(pid=101, poll=lambda: 1)
            groups.owners.append({"child": child})
            return child

        def paused_samples(_lab, _owner, entry, child, _samples, end, **_kwargs):
            now[0] = end - 1_000_000
            stall.observe_probe_terminal(entry, child, now=lambda: now[0])
            now[0] = end

        def attach(entry, _result, requests, *_args):
            entry["records"] = requests

        groups.spawn = spawn
        groups.kernel_captures.finish = lambda phase, **_kw: events.append("snapshot-" + phase)
        groups.write_captures.activate = lambda _capture: events.append("activate-fresh")
        result = {"requests": []}
        harness = SimpleNamespace(udp=SimpleNamespace(write_report=lambda p, v: p.write_text(json.dumps(v))),
            digest=lambda _path: "a" * 64, DUAL=Path("/fixture"), prepare_write_capture=prepare_write,
            prepare_kernel_capture=prepare_kernel, tool_argv=lambda *_args: [],
            wait_child=lambda *_args, **_kw: 1,
            udp_summary=SimpleNamespace(read_report=lambda _path: (result, None), validate_report=lambda _r: None),
            attach=attach)
        with tempfile.TemporaryDirectory() as directory, ExitStack() as patches:
            out = Path(directory)
            ready = {"process_id": 101, "tool_sha256": "a" * 64,
                     "started_monotonic_ns": 10_000_000_000, "end_monotonic_ns": 20_000_000_000}
            plan = {"entries": entries, "source_ip": "192.0.2.1", "target_ip": "192.0.2.2"}
            import hashlib
            ready["manifest_sha256"] = hashlib.sha256(json.dumps(plan, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            (out / "echo-ready.json").write_text(json.dumps(ready))
            patches.enter_context(patch.object(stall, "PauseOwner", Owner))
            patches.enter_context(patch.object(stall, "sample", return_value={}))
            patches.enter_context(patch.object(stall, "collect_paused_samples", side_effect=paused_samples))
            patches.enter_context(patch.object(stall.time, "monotonic_ns", side_effect=lambda: now[0]))
            try:
                stall.measure(harness, SimpleNamespace(ns=lambda role: role), groups, report, out,
                              {"a1": {"virtual_ip": "192.0.2.1"}, "b1": {"virtual_ip": "192.0.2.2"}}, [])
            except (FreshBoundary, ValueError) as error:
                return events, error, report
        self.fail("original fresh boundary was not reached")

    def test_both_original_registrations_precede_stop_and_original_traffic(self):
        events, error, report = self.run_until_fresh()
        self.assertIsInstance(error, FreshBoundary)
        for registration in ["register-paused", "register-fresh"]:
            self.assertLess(events.index(registration), events.index("stop"))
        self.assertLess(events.index("stop"), events.index("spawn-udp-paused-probe"))
        self.assertLess(events.index("resume"), events.index("finish-paused"))
        self.assertLess(events.index("finish-paused"), events.index("activate-fresh"))
        self.assertLess(events.index("activate-fresh"), events.index("spawn-udp-fresh-probe"))
        self.assertIn(("prepare-fresh", True), events)
        self.assertTrue(report["server_stall"]["paused_request_window"]["all_paused_requests_terminal_while_original_echo_stopped"])
        self.assertEqual(report["server_stall"]["pause"]["resume_requested_monotonic_ns"] -
                         report["server_stall"]["pause"]["stopped_monotonic_ns"], contract.HOLD_NS)
        contract.validate_manifest(report["manifest"])

    def test_failed_preparation_never_stops_echo_or_starts_request(self):
        events, error, _report = self.run_until_fresh(fail_registration=True)
        self.assertEqual(str(error), "original registration failure")
        self.assertNotIn("stop", events)
        self.assertNotIn("spawn-udp-paused-probe", events)

    def test_original_spawn_failure_still_resumes_same_echo(self):
        events, error, _report = self.run_until_fresh(fail_paused_spawn=True)
        self.assertEqual(str(error), "original spawn failure")
        self.assertEqual(events.count("resume"), 1)
        self.assertNotIn("activate-fresh", events)


if __name__ == "__main__":
    unittest.main()
