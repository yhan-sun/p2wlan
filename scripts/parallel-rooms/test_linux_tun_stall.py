"""Offline codec, original-owner and typed-diagnostic controls; no services/TUN."""
import copy
from contextlib import ExitStack, redirect_stdout
import io
import json
from pathlib import Path
import signal
import subprocess
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

import linux_tun_evidence as harness
import linux_tun_stall as stall
import linux_tun_stall_contract as contract
import udp_stall_echo as echo


class Clock:
    def __init__(self):
        self.value = 10_000_000_000
    def now(self):
        return self.value
    def sleep(self, seconds):
        self.value += int(seconds * 1_000_000_000)


class ProcessIO:
    def __init__(self):
        self.state, self.calls, self.closed, self.ticks = "S", [], [], 7
    def observe(self, _pid, _namespace):
        return {"state": self.state, "parent_pid": 1, "group_pid": 100, "start_ticks": self.ticks,
                "namespace_device": 2, "namespace_inode": 3}
    def open(self, pid, flags):
        self.calls.append(("open", pid, flags))
        return 55
    def send(self, fd, sig, _info, _flags):
        self.calls.append((fd, sig))
        self.state = "T" if sig == signal.SIGSTOP else "S"
    def close(self, fd):
        self.closed.append(fd)


def owner_fixture():
    child = SimpleNamespace(pid=101, returncode=None)
    registered = {"child": child, "anchor": SimpleNamespace(pid=100, returncode=None), "socket_tool": True}
    clock, io = Clock(), ProcessIO()
    owner = stall.PauseOwner(child, registered, "owned-b", io=io, now=clock.now, sleep=clock.sleep, parent_pid=1)
    return child, owner, clock, io


def healthy_snapshot(begin, end, *, ack_age=100):
    result = {}
    for index, name in enumerate(("a1", "b1")):
        endpoint = f"192.0.2.{4-index}:45000"
        health = {"failure_count": 0, "success_count": 10, "consecutive_failures": 0}
        pair = {**health, "selected": True, "state": "selected", "local_generation": 0,
                "local_endpoint": "0.0.0.0:40000", "remote_endpoint": endpoint}
        peer = {"state": "direct", "active_path": "direct", "online": True, "direct": health,
                "selected_pair": pair, "current_path_selection": {"path": "direct", "direct_confirmed": True,
                    "direct_endpoint": endpoint}, "consent_endpoint": endpoint, "network_generation": 0,
                "peer_session_generation": 1, "remote_candidate_epoch": 1, "direct_generation": 0,
                "observed_begin_monotonic_ns": begin, "observed_end_monotonic_ns": end,
                "direct_events": [{"stage": "consent_ack_received", "age_ms": ack_age,
                    "network_generation": 0, "endpoint": endpoint}]}
        result[name] = {"pid": 200+index, "process_id": 200+index, "instance": 1, "run_id": "run",
                       "correlation_id": name, "node_id": name, "network_id": "room", "network_generation": 0,
                       "process_alive": True, "peer_snapshot_stale": False, "revision": 4, "captured_revision": 4,
                       "health": {"status": "healthy", "critical_tasks": [
                           {"name": task, "running": True, "finished": False, "error": ""}
                           for task in ("dataplane", "udp-direct", "wireguard-inbound", "network-outbound")]},
                       "peers": {"peer-"+name: peer}}
    return result


def completed_manifest():
    entries = contract.manifest("11"*16, "22"*16)
    for index, entry in enumerate(entries):
        entry["probe_exit"] = 1 if index == 0 else 0
        entry["records"] = [{"sequence": n, "request_nonce": f"{index*8+n:032x}",
            "status": "timeout" if index == 0 else "success", "reason": "response_deadline" if index == 0 else "matched_echo",
            "sent_offset_ns": n*100_000_000, "rtt_ns": None if index == 0 else 1_000_000} for n in range(8)]
    return entries


def completed_evidence():
    return {"health": {"both_original_paths_stable": True},
            "paused_request_window": {"all_paused_requests_terminal_while_original_echo_stopped": True},
            "pause": {"restored": True, "original_pid_confirmed": True,
                      "stopped_lower_bound_ns": contract.HOLD_NS,
                      "stopped_observation_upper_bound_ns": contract.HOLD_NS+10_000_000},
            "echo": {"responses_sent_by_phase": {"paused": 8, "fresh": 8},
                     "send_errors": 0, "termination_reason": "request_budget_exhausted"}}


class StallContractControls(unittest.TestCase):
    def test_fixed16_missing_and_started_unknown_not_reduced_to_success(self):
        entries = contract.manifest("11"*16, "22"*16)
        self.assertEqual(contract.summarize(entries)["terminal_counts"], {"not_started": 16})
        entries[0]["outcome"] = "started"
        summary = contract.summarize(entries)
        self.assertEqual(summary["prescheduled_requests"], 16)
        self.assertEqual(summary["terminal_counts"], {"unknown": 8, "not_started": 8})
        for key, value in (("count", 7), ("timeout_ms", 2000), ("source_port", 44120)):
            changed = copy.deepcopy(entries)
            changed[0][key] = value
            with self.assertRaises(ValueError):
                contract.summarize(changed)

    def test_old_timeouts_and_fresh_nonces_are_distinct_and_not_upgraded(self):
        entries = completed_manifest()
        summary = contract.summarize(entries)
        self.assertTrue(summary["paused_request_timeouts_observed"])
        self.assertTrue(summary["all_fresh_responses_observed"])
        self.assertEqual(summary["terminal_counts"], {"timeout": 8, "success": 8})
        entries[1]["records"][0]["request_nonce"] = entries[0]["records"][0]["request_nonce"]
        with self.assertRaisesRegex(ValueError, "old_nonce"):
            contract.summarize(entries)

    def test_acceptance_rejects_unknown_health_or_pause_bounds_or_missing_echo(self):
        summary, evidence = contract.summarize(completed_manifest()), completed_evidence()
        self.assertTrue(contract.accepted(summary, evidence))
        for mutate in (
            lambda e: e.update(health={}),
            lambda e: e.update(paused_request_window={}),
            lambda e: e["pause"].update(restored=False),
            lambda e: e["pause"].update(stopped_lower_bound_ns=contract.HOLD_NS-1),
            lambda e: e["pause"].update(stopped_observation_upper_bound_ns=contract.HOLD_NS+250_000_000),
            lambda e: e["echo"].update(responses_sent_by_phase={"paused": 7, "fresh": 8}),
        ):
            changed = copy.deepcopy(evidence)
            mutate(changed)
            self.assertFalse(contract.accepted(summary, changed))

    def test_paused_probe_must_be_original_terminal_observation_before_resume(self):
        pause = {"stopped_monotonic_ns": 10_000_000_000, "resume_requested_monotonic_ns": 13_000_000_000}
        entry = {"probe_spawn_requested_monotonic_ns": 10_100_000_000,
                 "probe_terminal_observed_monotonic_ns": 11_900_000_000, "observed_probe_exit": 1}
        self.assertTrue(contract.paused_request_window(entry, pause)["all_paused_requests_terminal_while_original_echo_stopped"])
        for mutate in (
            lambda e: e.update(probe_spawn_requested_monotonic_ns=9_999_999_999),
            lambda e: e.update(probe_terminal_observed_monotonic_ns=13_000_000_000),
            lambda e: e.pop("probe_terminal_observed_monotonic_ns"),
            lambda e: e.update(observed_probe_exit=0),
        ):
            changed = copy.deepcopy(entry)
            mutate(changed)
            with self.assertRaises(ValueError):
                contract.paused_request_window(changed, pause)

    def test_typed_new_consent_inside_stopped_window_and_same_selector_required(self):
        pause = {"stopped_monotonic_ns": 10_000_000_000, "resume_requested_monotonic_ns": 13_000_000_000}
        before = healthy_snapshot(9_000_000_000, 9_010_000_000)
        middle = healthy_snapshot(11_000_000_000, 11_010_000_000)
        after = healthy_snapshot(14_000_000_000, 14_010_000_000)
        result = contract.health_evidence(before, [middle], after, pause)
        self.assertTrue(result["both_original_paths_stable"])
        for change in (
            lambda s: s["a1"].update(peer_snapshot_stale=True),
            lambda s: s["a1"].update(captured_revision=3),
            lambda s: s["a1"].update(process_id=999),
            lambda s: s["a1"]["peers"]["peer-a1"]["direct"].update(failure_count=1),
            lambda s: s["a1"]["peers"]["peer-a1"]["current_path_selection"].update(path="relay"),
            lambda s: s["a1"]["peers"]["peer-a1"].update(remote_candidate_epoch=2),
            lambda s: s["a1"]["peers"]["peer-a1"].update(direct_generation=None),
            lambda s: s["a1"]["peers"]["peer-a1"].update(direct_events=[]),
            lambda s: s["a1"]["peers"]["peer-a1"]["direct_events"][0].update(age_ms=2000),
            lambda s: s["a1"]["peers"]["peer-a1"]["direct_events"][0].update(stage="consent_timeout"),
        ):
            changed = copy.deepcopy(middle)
            change(changed)
            with self.assertRaises(ValueError):
                contract.health_evidence(before, [changed], after, pause)

    def test_post_resume_ack_or_stage_substring_cannot_supply_paused_consent(self):
        pause = {"stopped_monotonic_ns": 10_000_000_000, "resume_requested_monotonic_ns": 13_000_000_000}
        before = healthy_snapshot(9_000_000_000, 9_010_000_000)
        after = healthy_snapshot(14_000_000_000, 14_010_000_000)
        with self.assertRaises(ValueError):
            contract.health_evidence(before, [after], after, pause)
        middle = healthy_snapshot(11_000_000_000, 11_010_000_000)
        middle["a1"]["peers"]["peer-a1"]["direct_events"][0]["stage"] += "ish"
        with self.assertRaises(ValueError):
            contract.health_evidence(before, [middle], after, pause)


class PauseOwnerControls(unittest.TestCase):
    def test_only_original_child_pidfd_stop_confirm_cont_close_no_group_signal(self):
        _child, owner, clock, io = owner_fixture()
        owner.stop(clock.now()+500_000_000)
        clock.sleep(3)
        owner.resume(clock.now()+100_000_000)
        owner.close()
        self.assertEqual(io.calls, [("open", 101, 0), (55, signal.SIGSTOP), (55, signal.SIGCONT)])
        self.assertTrue(owner.evidence["restored"])
        self.assertEqual(io.closed, [55])
        self.assertEqual(owner.evidence["stopped_lower_bound_ns"], contract.HOLD_NS)

    def test_partial_stop_and_body_error_resume_before_original_cleanup_without_new_grace(self):
        _child, owner, clock, io = owner_fixture()
        def partial(fd, sig, info, flags):
            ProcessIO.send(io, fd, sig, info, flags)
            if sig == signal.SIGSTOP:
                raise OSError("fixture_stop_result_unknown")
        io.send = partial
        with self.assertRaises(OSError):
            owner.stop(clock.now()+500_000_000)
        restored = stall.restore_before_cleanup([owner])
        self.assertTrue(restored["complete"])
        self.assertEqual(io.state, "S")
        self.assertEqual(io.calls[-1], (55, signal.SIGCONT))
        self.assertEqual(io.closed, [55])

    def test_reaped_or_changed_start_ticks_never_signals_new_process(self):
        child, owner, clock, io = owner_fixture()
        io.ticks += 1
        with self.assertRaises(RuntimeError):
            owner.stop(clock.now()+500_000_000)
        self.assertEqual(io.calls, [("open", 101, 0)])
        owner.close()
        child.returncode = 0
        with self.assertRaises(ValueError):
            stall.PauseOwner(child, {"child": child, "socket_tool": True, "anchor": SimpleNamespace(pid=100, returncode=None)},
                             "owned-b", io=io, now=clock.now, parent_pid=1)

    def test_stop_signal_success_without_stopped_observation_fails_and_still_continues(self):
        _child, owner, clock, io = owner_fixture()
        io.send = lambda fd, sig, info, flags: io.calls.append((fd, sig))
        with self.assertRaises(TimeoutError):
            owner.stop(clock.now()+50_000_000)
        self.assertTrue(stall.restore_before_cleanup([owner])["complete"])
        self.assertEqual(io.calls[-1], (55, signal.SIGCONT))

    def test_ambiguous_pidfd_close_is_not_retried_or_manufactured_absent(self):
        _child, owner, clock, io = owner_fixture()
        owner.stop(clock.now()+500_000_000)
        clock.sleep(3)
        owner.resume(clock.now()+100_000_000)
        def failed_close(fd):
            io.closed.append(fd)
            raise OSError("fixture_close_unknown")
        io.close = failed_close
        result = stall.restore_before_cleanup([owner])
        self.assertFalse(result["complete"])
        self.assertFalse(stall.restore_before_cleanup([owner])["complete"])
        self.assertEqual(io.closed, [55])


class EchoCodecControls(unittest.TestCase):
    def setUp(self):
        self.plan = {"entries": contract.manifest("11"*16, "22"*16), "source_ip": "10.20.0.1", "target_ip": "10.20.0.2"}

    def test_two_registered_rounds_and_flows_only_duplicate_old_never_fresh(self):
        configurations = echo.configs(self.plan)
        seen = {phase: {} for phase in contract.PHASES}
        old = echo.udp.encode(configurations[0], 0, "33"*16, echo.udp.REQUEST)
        fresh = echo.udp.encode(configurations[1], 0, "44"*16, echo.udp.REQUEST)
        self.assertEqual(echo.accept_frame(configurations, seen, old, configurations[0].target)[0], "paused")
        self.assertIsNone(echo.accept_frame(configurations, seen, old, configurations[0].target))
        self.assertIsNone(echo.accept_frame(configurations, seen, old, configurations[1].target))
        accepted = echo.accept_frame(configurations, seen, fresh, configurations[1].target)
        self.assertEqual(accepted[0], "fresh")
        self.assertEqual(echo.udp.decode(accepted[2])[4], "44"*16)

    def test_absolute_echo_deadline_includes_pause_and_does_not_credit_late_frame(self):
        configurations = echo.configs(self.plan)
        clock = Clock()
        wire = echo.udp.encode(configurations[0], 0, "33"*16, echo.udp.REQUEST)
        class Socket:
            def getsockname(self): return configurations[0].bind
            def setblocking(self, _value): pass
            def recvfrom(self, _size):
                clock.sleep(11)
                return wire, configurations[0].target
            def sendto(self, *_args): raise AssertionError("late reply")
        with tempfile.TemporaryDirectory() as directory:
            result = echo.run_echo(self.plan, Path(directory)/"ready.json", sock=Socket(), now=clock.now,
                                   select_ready=lambda *_args: ([1], [], []))
        self.assertEqual(result["end_monotonic_ns"]-result["started_monotonic_ns"], 10_000_000_000)
        self.assertEqual(result["responses_sent_by_phase"], {"paused": 0, "fresh": 0})

    def test_full_two_phase_codec_echo_is_bounded16_and_retains_actual_send_times(self):
        configurations = echo.configs(self.plan)
        clock, frames, sent = Clock(), [], []
        for phase_index, config in enumerate(configurations):
            frames.extend((echo.udp.encode(config, sequence, f"{phase_index*8+sequence:032x}", echo.udp.REQUEST), config.target)
                          for sequence in range(8))
        class Socket:
            def getsockname(self): return configurations[0].bind
            def setblocking(self, _value): pass
            def recvfrom(self, _size): return frames.pop(0)
            def sendto(self, data, target):
                sent.append((echo.udp.decode(data), target))
                return len(data)
        with tempfile.TemporaryDirectory() as directory:
            result = echo.run_echo(self.plan, Path(directory)/"ready.json", sock=Socket(), now=clock.now,
                                   select_ready=lambda *_args: ([1], [], []))
        self.assertEqual(result["received_datagrams"], 16)
        self.assertEqual(len(sent), 16)
        self.assertEqual(result["responses_sent_by_phase"], {"paused": 8, "fresh": 8})
        self.assertEqual(result["termination_reason"], "request_budget_exhausted")
        self.assertTrue(all(value == clock.now() for phase in result["response_completed_monotonic_ns"].values()
                            for value in phase.values()))


class HarnessBoundaryControls(unittest.TestCase):
    def test_paused_sampling_admits_complete_two_end_diagnostics_before_cont_reserve(self):
        clock, calls, samples = Clock(), [], []
        start, hold_end = clock.now(), clock.now() + contract.HOLD_NS
        def rpc(name, *, deadline, projection=False):
            begin = clock.now()
            calls.append((name, projection, begin, int(deadline * 1_000_000_000)))
            if begin + 90_000_000 > int(deadline * 1_000_000_000):
                raise TimeoutError("original diagnostics phase deadline")
            clock.sleep(.09)
            return healthy_snapshot(begin, clock.now())[name] if projection else {}
        lab = SimpleNamespace(status=rpc, _safe_status=lambda name, _status, **kw: rpc(name, projection=True, **kw))
        owner = SimpleNamespace(observe=lambda: {"state": "T"})
        probe = SimpleNamespace(poll=lambda: None)
        stall.collect_paused_samples(lab, owner, {}, probe, samples, hold_end, now=clock.now, sleep=clock.sleep)
        self.assertEqual(len(samples), 5)
        self.assertEqual(len(calls), 20)
        self.assertEqual(set(samples[-1]), {"a1", "b1"})
        self.assertLessEqual(clock.now(), hold_end - 100_000_000)
        self.assertTrue(all(end <= hold_end - 100_000_000 for _side, _projection, _begin, end in calls))
        pause = {"stopped_monotonic_ns": start, "resume_requested_monotonic_ns": hold_end}
        result = contract.health_evidence(healthy_snapshot(start - 200_000_000, start - 100_000_000), samples,
                                         healthy_snapshot(hold_end + 100_000_000, hold_end + 200_000_000), pause)
        self.assertTrue(result["both_original_paths_stable"])

    def test_admitted_diagnostics_timeout_is_not_retried_or_dropped(self):
        clock, samples, calls = Clock(), [], []
        def failed_status(name, *, deadline):
            calls.append((name, deadline))
            raise TimeoutError("original diagnostics phase deadline")
        lab = SimpleNamespace(status=failed_status)
        with self.assertRaisesRegex(TimeoutError, "original diagnostics"):
            stall.collect_paused_samples(lab, SimpleNamespace(observe=lambda: {"state": "T"}), {},
                SimpleNamespace(poll=lambda: None), samples, clock.now()+contract.HOLD_NS,
                now=clock.now, sleep=clock.sleep)
        self.assertEqual(len(calls), 1)
        self.assertEqual(samples, [])

    def test_admitted_partial_peer_capture_remains_unacceptable(self):
        clock, samples = Clock(), []
        start, hold_end = clock.now(), clock.now()+contract.HOLD_NS
        def projected(name, _status, *, deadline):
            begin = clock.now()
            clock.sleep(.1)
            status = healthy_snapshot(begin, clock.now())[name]
            if name == "b1":
                status["peers"] = {"peer-b1": {"capture_error": "diagnostics_timeout"}}
            return status
        stall.collect_paused_samples(SimpleNamespace(status=lambda *_a, **_kw: {}, _safe_status=projected),
            SimpleNamespace(observe=lambda: {"state": "T"}), {}, SimpleNamespace(poll=lambda: None),
            samples, hold_end, now=clock.now, sleep=clock.sleep)
        self.assertTrue(samples)
        self.assertTrue(all("capture_error" in s["b1"]["peers"]["peer-b1"] for s in samples))
        with self.assertRaisesRegex(ValueError, "selected_path_unknown"):
            contract.health_evidence(healthy_snapshot(start-200_000_000, start-100_000_000), samples,
                healthy_snapshot(hold_end+100_000_000, hold_end+200_000_000),
                {"stopped_monotonic_ns": start, "resume_requested_monotonic_ns": hold_end})

    def test_original_probe_exit_observation_is_once_and_does_not_wait_or_retry(self):
        entry, clock = {}, Clock()
        codes = iter((None, 1, 1))
        child = SimpleNamespace(poll=lambda: next(codes))
        stall.observe_probe_terminal(entry, child, now=clock.now)
        self.assertEqual(entry, {})
        clock.sleep(1)
        stall.observe_probe_terminal(entry, child, now=clock.now)
        observed = copy.deepcopy(entry)
        clock.sleep(1)
        stall.observe_probe_terminal(entry, child, now=clock.now)
        self.assertEqual(entry, observed)
        self.assertEqual(entry["observed_probe_exit"], 1)

    def test_original_cli_gate_uses_stall_acceptance_and_resume_cleanup(self):
        # Full main dispatch, all execution boundaries mocked: no Linux process,
        # socket, namespace, signal, daemon or service is created by this test.
        for health_ok, cleanup_ok in ((True, True), (False, True), (True, False)):
            with tempfile.TemporaryDirectory() as directory, ExitStack() as patches:
                root = Path(directory)
                daemon, control = root/"daemon", root/"control"
                daemon.write_bytes(b"offline-daemon-identity")
                control.write_bytes(b"offline-control-identity")
                out = root/"evidence"
                lab = SimpleNamespace(run_id="offline", evidence={"stages": []},
                    temp=SimpleNamespace(cleanup=lambda: None), preserve_logs=lambda: None)
                groups = SimpleNamespace(cleanup=lambda: [{"complete": True}])
                def exercise(_lab, _groups, report, _out, **_kwargs):
                    observed = completed_manifest()
                    for entry, complete in zip(report["manifest"], observed):
                        entry.update(records=complete["records"], probe_exit=complete["probe_exit"], outcome="observed")
                    report["server_stall"] = completed_evidence()
                    report["server_stall"]["health"]["both_original_paths_stable"] = health_ok
                actual_exists = Path.exists
                patches.enter_context(patch.object(Path, "exists", lambda p:
                    True if str(p) == "/dev/net/tun" else actual_exists(p)))
                patches.enter_context(patch.object(harness.sys, "platform", "linux"))
                patches.enter_context(patch.object(harness.os, "geteuid", return_value=0))
                patches.enter_context(patch.object(harness.sys, "argv", ["offline", "--server-stall",
                    "--daemon", str(daemon), "--control", str(control), "--head", "0"*40, "--output-dir", str(out)]))
                patches.enter_context(patch.object(harness.original, "run", return_value=
                    subprocess.CompletedProcess([], 0, "0"*40+"\n", "")))
                patches.enter_context(patch.object(harness.subprocess, "check_output", side_effect=
                    lambda argv, **_kwargs: (harness.ROOT/argv[-1].split(":", 1)[1]).read_bytes()))
                patches.enter_context(patch.object(harness, "OwnedGroups", return_value=groups))
                patches.enter_context(patch.object(harness, "EvidenceLab", return_value=lab))
                patches.enter_context(patch.object(harness, "resource_plan", return_value=None))
                patches.enter_context(patch.object(harness, "exercise", side_effect=exercise))
                patches.enter_context(patch.object(harness, "cleanup_network", return_value={"complete": True}))
                patches.enter_context(patch.object(harness.signal, "signal"))
                patches.enter_context(patch.dict(harness.os.environ, {}, clear=True))
                patches.enter_context(patch.object(stall, "restore_before_cleanup", return_value={"complete": cleanup_ok}))
                with redirect_stdout(io.StringIO()):
                    code = harness.main()
                report = json.loads((out/"report.json").read_text())
                self.assertEqual(code, int(not (health_ok and cleanup_ok)))
                self.assertEqual(report["passed"], health_ok and cleanup_ok)
                self.assertEqual(report["application"]["prescheduled_requests"], 16)

    def test_diagnostics_deadline_clips_original_http_command_without_new_grace(self):
        lab = harness.original.Lab.__new__(harness.original.Lab)
        calls = []
        lab.cmd = lambda label, argv, **kwargs: (calls.append(kwargs) or
            subprocess.CompletedProcess(argv, 0, '{"status":200,"body":{}}', ''))
        with patch.object(harness.original.time, "monotonic", return_value=10):
            self.assertEqual(lab.http("a", "/status", deadline=10.2), {})
            self.assertAlmostEqual(calls[0]["timeout"], .2)
            self.assertAlmostEqual(json.loads(calls[0]["input"])["timeout"], .2)
            with self.assertRaises(TimeoutError):
                lab.http("a", "/status", deadline=10)
        self.assertEqual(len(calls), 1)

    def test_safe_projection_keeps_only_typed_consent_and_public_selector_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path/"p2wlan-daemon.diag-auth").write_text("private-diag-token")
            lab = harness.original.Lab.__new__(harness.original.Lab)
            lab.daemons = {"a1": {"directory": path, "namespace": "a", "port": 8000, "instance": 1,
                                  "process": SimpleNamespace(pid=101, poll=lambda: None)}}
            scoped = {"current_path_selection": {"path": "direct", "direct_confirmed": True,
                "direct_endpoint": "192.0.2.4:45000", "reason": "private-selector-text"},
                "direct_events": [{"stage": "consent_ack_received", "age_ms": 3, "network_generation": 0,
                    "endpoint": "192.0.2.4:45000", "detail": "private-event-text"},
                    {"stage": "unrelated", "detail": "private-other-text"}]}
            lab.http = lambda *_args, **_kwargs: {"peer": scoped, "peer_session_generation": 1, "network_generation": 0}
            result = lab._safe_status("a1", {"peers": [{"node_id": "peer"}], "health": {}, "revision": 4,
                                             "captured_revision": 4}, deadline=100)
            encoded = json.dumps(result)
            for secret in ("private-selector-text", "private-event-text", "private-other-text", "private-diag-token"):
                self.assertNotIn(secret, encoded)
            peer = result["peers"]["peer"]
            self.assertEqual(len(peer["direct_events"]), 1)
            self.assertEqual(peer["direct_events"][0]["stage"], "consent_ack_received")
            self.assertNotIn("reason", peer["current_path_selection"])
            self.assertLessEqual(peer["observed_begin_monotonic_ns"], peer["observed_end_monotonic_ns"])

    def test_only_explicit_stall_daemon_gets_existing_keepalive_cli_variant(self):
        for enabled in (False, True):
            received = []
            groups = SimpleNamespace(spawn=lambda role, argv, log, **kwargs:
                                     (received.append((role, argv)) or SimpleNamespace(pid=101, returncode=None)))
            args = SimpleNamespace(head="0"*40, debug_dir=None, daemon=Path("/fixture/daemon"), server_stall=enabled)
            lab = harness.EvidenceLab(args, groups)
            try:
                lab.spawn("a", "a1.instance-1", [str(args.daemon), "--token-stdin"])
                lab.spawn("control", "control", ["/fixture/control"])
                self.assertEqual(received[0][1][-2:] == ["--keepalive-interval-secs", "1"], enabled)
                self.assertNotIn("--keepalive-interval-secs", received[1][1])
                self.assertEqual(bool(lab.stall_daemon_inputs), enabled)
            finally:
                lab.temp.cleanup()

    def test_partial_failure_stays16_and_cleanup_still_runs(self):
        report = {"manifest": contract.manifest("11"*16, "22"*16)}
        groups = SimpleNamespace(cleanup=lambda: [{"complete": True}])
        harness.finalize_observations(report, groups, lambda: {"complete": True},
                                     summary=contract.summarize, requested_count=16)
        self.assertEqual(report["application"]["prescheduled_requests"], 16)
        self.assertEqual(report["application"]["terminal_counts"], {"not_started": 16})
        with patch.object(contract, "summarize", side_effect=ValueError("fixture")):
            harness.finalize_observations(report, groups, lambda: {"complete": True},
                                         summary=contract.summarize, requested_count=16)
        self.assertEqual(report["application"]["terminal_counts"], {"unknown": 16})

    def test_required_8minute_ci_cap_and_separate_output_scope_remain(self):
        workflow = (Path(__file__).resolve().parents[2]/".github/workflows/parallel-rooms.yml").read_text()
        self.assertIn("timeout-minutes: 8", workflow)
        self.assertIn("timeout-minutes: 25", workflow)
        self.assertEqual(workflow.count("--server-stall"), 1)
        self.assertIn("linux-tun-server-stall/", workflow)
        self.assertEqual((harness.MAX_GROUPS, harness.MAX_HANDLES), (11, 22))


if __name__ == "__main__":
    unittest.main()
