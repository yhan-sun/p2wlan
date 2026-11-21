#!/usr/bin/env python3
"""Modelled rule commands and real loopback CLI cleanup; never kernel DROP/TUN."""
import copy
import json
import os
from pathlib import Path
import shlex
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import linux_tun_evidence as harness
import linux_tun_fault as fault
import linux_tun_fault_contract as contract
from linux_tun_owned import OwnedGroups


def entries():
    return contract.manifest("11" * 16, "22" * 16)


def source():
    return {"process_id": 10, "run_id": "modelled-run", "virtual_ip": "10.20.0.1",
            "kernel": {"kind": "tun", "ifname": "owned-tun", "ifindex": 7, "vip": "10.20.0.1",
                       "route_to_peer": {"dst": "10.20.0.2", "dev": "owned-tun", "prefsrc": "10.20.0.1"}}}


def target():
    return {"process_id": 11, "run_id": "modelled-run", "virtual_ip": "10.20.0.2",
            "kernel": {"kind": "tun", "ifname": "owned-target-tun", "ifindex": 8, "vip": "10.20.0.2",
                       "route_to_peer": {"dst": "10.20.0.1", "dev": "owned-target-tun", "prefsrc": "10.20.0.2"}}}


class FakeRules:
    """Explicit command model, not a substitute for CI kernel observation."""
    def __init__(self):
        self.rows = {}
        self.calls = []
        self.fail_add = None
        self.fail_delete = None
        self.timeout_after_add = None
        self.snapshot_override = None
        self.foreign = "[5:55] -A INPUT -m comment --comment foreign-preserve -j ACCEPT"

    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        command = argv[3:]
        if command[0] == "iptables-save":
            if self.snapshot_override is not None:
                return subprocess.CompletedProcess(argv, 0, self.snapshot_override, "")
            lines = ["*filter", ":INPUT ACCEPT [0:0]", self.foreign]
            lines.extend(f'[{row["packets"]}:{row["bytes"]}] -A INPUT ' + shlex.join(row["args"])
                         for row in self.rows.values())
            return subprocess.CompletedProcess(argv, 0, "\n".join([*lines, "COMMIT"]) + "\n", "")
        action = command[3]
        args = command[5:]
        marker = args[args.index("--comment") + 1]
        protocol = args[args.index("-p") + 1]
        if action == "-A":
            if self.fail_add == protocol:
                return subprocess.CompletedProcess(argv, 1, "", "model add failure")
            self.rows[marker] = {"args": args, "packets": 0, "bytes": 0}
            if self.timeout_after_add == protocol:
                raise subprocess.TimeoutExpired(argv, kwargs["timeout"])
        elif action == "-D":
            if self.fail_delete == protocol:
                return subprocess.CompletedProcess(argv, 1, "", "model delete failure")
            self.rows.pop(marker)
        else:
            raise ValueError("unexpected model operation")
        return subprocess.CompletedProcess(argv, 0, "", "")


def model_owner(runner=None, plan=None):
    runner = runner or FakeRules()
    fd = os.open(os.devnull, os.O_RDONLY)
    try:
        with patch("linux_tun_fault.open_namespace", return_value=(fd, {"device": 1, "inode": 2})):
            owner = fault.FaultOwner("owned-b", plan or {"preflight_all_absent": True, "namespaces": ["owned-b"]},
                                     ["owned-b"], source(), target(),
                                     entries(), runner=runner)
    except BaseException:
        os.close(fd)
        raise
    return owner, runner


class RuleControls(unittest.TestCase):
    def test_model_original_target_pid_pins_descriptor_before_exact_input_rules(self):
        fd = os.open(os.devnull, os.O_RDONLY)
        runner = FakeRules()
        try:
            with patch("linux_tun_fault.open_namespace", return_value=(fd, {"device": 1, "inode": 2})) as opened:
                owner = fault.FaultOwner("owned-b", {"preflight_all_absent": True, "namespaces": ["owned-b"]},
                                         ["owned-b"], source(), target(), entries(), runner=runner)
                opened.assert_called_once_with("owned-b", target()["process_id"])
            owner.install()
            frozen = copy.deepcopy(owner.origin)
        finally:
            if "owner" in locals():
                cleanup = owner.cleanup(time.monotonic() + 20)
            else:
                os.close(fd)
        self.assertTrue(cleanup["complete"])
        self.assertEqual(frozen["source"], source())
        self.assertEqual(frozen["target"], target())
        self.assertTrue(all(argv[7] == "INPUT" for argv, _ in runner.calls if argv[3] == "iptables"))

    def test_model_old_output_hook_with_same_marker_is_rejected_before_cleanup(self):
        owner, runner = model_owner()
        error = None
        try:
            owner.install()
            args = shlex.join(owner.rules[0]["args"])
            runner.snapshot_override = "*filter\n:OUTPUT ACCEPT [0:0]\n[0:0] -A OUTPUT " + args + "\nCOMMIT\n"
            owner.read_rules()
        except Exception as caught:
            error = caught
        finally:
            runner.snapshot_override = None
            cleanup = owner.cleanup(time.monotonic() + 20)
        self.assertTrue(cleanup["complete"])
        self.assertIsInstance(error, ValueError)
        self.assertEqual(runner.rows, {})

    def test_model_exact_rules_include_both_old_and_fresh_ports_then_absence_and_fd_close(self):
        owner, runner = model_owner()
        saved_foreign = runner.foreign
        failure = None
        try:
            owner.install()
            decoded = copy.deepcopy([r["decoded"] for r in owner.rules])
            for rule in owner.rules:
                row = runner.rows[rule["marker"]]
                row.update(packets=8 if rule["protocol"] == "udp" else 1, bytes=800)
            blocked = owner.counter_snapshot()
            cleared = owner.clear()
        except BaseException as error:
            failure = error
        finally:
            cleanup = owner.cleanup(time.monotonic() + 20)
        if failure:
            raise failure
        self.assertEqual({r["protocol"]: r["packets"] for r in blocked["rules"]}, {"udp": 8, "tcp": 1})
        self.assertTrue(cleared["all_owned_rules_observed_absent"])
        self.assertTrue(cleanup["complete"])
        self.assertEqual(runner.rows, {})
        self.assertEqual(saved_foreign, runner.foreign)
        for record in decoded:
            ports = contract.PORTS[record["-p"]]
            self.assertEqual(record["--sports"], f"{ports[0]},{ports[1]}")
            self.assertEqual(record["--dport"], str(ports[2]))
            self.assertEqual(record["-i"], target()["kernel"]["ifname"])
            self.assertNotIn("-o", record)
        for argv, kwargs in runner.calls:
            self.assertEqual(argv[:3], ["nsenter", f"--net=/proc/self/fd/{owner.fd}", "--"])
            self.assertEqual(kwargs["pass_fds"], (owner.fd,))
            self.assertLessEqual(kwargs["timeout"], 20)
            self.assertNotIn("-F", argv)
            self.assertNotIn("owned-b", argv)
        with self.assertRaises(OSError):
            os.fstat(owner.fd)
        with patch("linux_tun_fault.os.close", side_effect=AssertionError("closed descriptor reused")):
            self.assertEqual(owner.cleanup(time.monotonic() + 20), cleanup)

    def test_model_uncleared_original_rule_still_covers_fresh_flow_parameter_negative(self):
        owner, runner = model_owner()
        try:
            owner.install()
            saved = copy.deepcopy(runner.rows)
            covered = []
            for entry in entries()[2:]:
                rule = next(r for r in owner.rules if r["protocol"] == entry["protocol"])
                allowed = {int(p) for p in rule["decoded"]["--sports"].split(",")}
                covered.append(entry["source_port"] in allowed and str(entry["target_port"]) == rule["decoded"]["--dport"])
        finally:
            cleanup = owner.cleanup(time.monotonic() + 20)
        self.assertTrue(cleanup["complete"])
        self.assertEqual(len(saved), 2)
        self.assertEqual(covered, [True, True], "fresh ports would bypass an uncleared original rule")

    def test_model_partial_second_add_preserves_first_then_cleans_it(self):
        runner = FakeRules()
        runner.fail_add = "tcp"
        owner, _ = model_owner(runner)
        error = None
        try:
            owner.install()
        except Exception as caught:
            error = caught
            saved_count = len(runner.rows)
        finally:
            cleanup = owner.cleanup(time.monotonic() + 20)
        self.assertIsInstance(error, RuntimeError)
        self.assertEqual(saved_count, 1)
        self.assertTrue(cleanup["complete"])
        self.assertEqual(runner.rows, {})

    def test_model_add_timeout_after_real_model_mutation_is_owned_before_return(self):
        runner = FakeRules()
        runner.timeout_after_add = "udp"
        owner, _ = model_owner(runner)
        error = None
        try:
            owner.install()
        except Exception as caught:
            error = caught
        finally:
            cleanup = owner.cleanup(time.monotonic() + 20)
        self.assertIsInstance(error, subprocess.TimeoutExpired)
        self.assertTrue(owner.registered)
        self.assertTrue(cleanup["complete"])
        self.assertEqual(runner.rows, {})

    def test_model_foreign_marker_preflight_is_never_deleted(self):
        owner, runner = model_owner()
        rule = owner.rules[0]
        runner.rows[rule["marker"]] = {"args": rule["args"], "packets": 3, "bytes": 300}
        error = None
        try:
            owner.install()
        except Exception as caught:
            error = caught
        finally:
            cleanup = owner.cleanup(time.monotonic() + 20)
        self.assertIsInstance(error, ValueError)
        self.assertFalse(owner.registered)
        self.assertTrue(cleanup["complete"])
        self.assertEqual(len(runner.rows), 1)
        self.assertFalse(any("-D" in argv or "-A" in argv for argv, _ in runner.calls))

    def test_model_delete_failure_collects_other_rule_and_keeps_failure(self):
        owner, runner = model_owner()
        error = None
        try:
            owner.install()
            runner.fail_delete = "udp"
            owner.clear()
        except Exception as caught:
            error = caught
            saved_clear = copy.deepcopy(owner.evidence["normal_clear"])
        finally:
            runner.fail_delete = None
            cleanup = owner.cleanup(time.monotonic() + 20)
        self.assertIsInstance(error, RuntimeError)
        self.assertEqual(len(saved_clear["operations"]), 2)
        self.assertFalse(saved_clear["complete"])
        self.assertTrue(cleanup["complete"])
        self.assertFalse(owner.evidence["normal_clear"]["complete"], "cleanup erased original clear failure")

    def test_model_replaced_same_comment_rule_is_unknown_and_not_blindly_deleted(self):
        owner, runner = model_owner()
        try:
            owner.install()
            row = runner.rows[owner.rules[0]["marker"]]
            row["args"] = [*row["args"][:-1], "ACCEPT"]
        finally:
            cleanup = owner.cleanup(time.monotonic() + 20)
        self.assertFalse(cleanup["complete"])
        self.assertEqual(cleanup["remaining"], ["rule_inventory_unknown"])
        self.assertEqual(cleanup["operations"], [])
        self.assertTrue(cleanup["original_namespace_fd_closed"])

    def test_unowned_namespace_is_rejected_before_native_descriptor_open(self):
        with patch("linux_tun_fault.open_namespace", side_effect=AssertionError("native open on foreign namespace")):
            with self.assertRaises(ValueError):
                fault.FaultOwner("foreign-ns", {"preflight_all_absent": True, "namespaces": ["owned-b"]},
                                 ["owned-b"], source(), target(), entries())

    def test_model_save_option_and_module_order_are_normalized_but_exact_identity_stays(self):
        owner, runner = model_owner()
        failure = None
        try:
            owner.install()
            lines = ["*filter", ":INPUT ACCEPT [0:0]"]
            for rule in owner.rules:
                tokens = rule["args"]
                pairs = [tokens[i:i + 2] for i in range(0, len(tokens), 2)]
                swapped = [v for pair in reversed(pairs) for v in pair]
                lines.append("[0:0] -A INPUT " + shlex.join(swapped))
            runner.snapshot_override = "\n".join([*lines, "COMMIT"])
            observed = owner.read_rules()
        except BaseException as caught:
            failure = caught
        finally:
            runner.snapshot_override = None
            cleanup = owner.cleanup(time.monotonic() + 20)
        if failure:
            raise failure
        self.assertTrue(cleanup["complete"])
        self.assertEqual(len(observed["rules"]), 2)

    def test_model_malformed_missing_counters_and_duplicate_comment_fail_closed(self):
        for grammar in ("bad_counter", "missing_counter", "duplicate", "missing_footer", "second_owned_comment", "dangling_comment", "duplicate_footer", "counter_after_footer"):
            owner, runner = model_owner()
            error = None
            try:
                owner.install()
                args = shlex.join(owner.rules[0]["args"])
                rule = "[0:0] -A INPUT " + args
                body = ("[bad:0] -A INPUT " + args if grammar == "bad_counter" else
                        "-A INPUT " + args if grammar == "missing_counter" else
                        rule + "\n" + rule if grammar == "duplicate" else
                        "[0:0] -A INPUT -m comment --comment foreign " + args if grammar == "second_owned_comment" else
                        rule + " --comment" if grammar == "dangling_comment" else
                        rule + "\nCOMMIT" if grammar == "duplicate_footer" else rule)
                runner.snapshot_override = ("*filter\nCOMMIT\n" + body if grammar == "counter_after_footer" else
                                            "*filter\n" + body + ("\nCOMMIT" if grammar != "missing_footer" else ""))
                owner.read_rules()
            except Exception as caught:
                error = caught
            finally:
                # Restore only the explicit fake reader for exact fixture
                # deletion; original parse failure remains saved for assertions.
                runner.snapshot_override = None
                cleanup = owner.cleanup(time.monotonic() + 20)
            self.assertIsInstance(error, ValueError)
            self.assertTrue(cleanup["complete"])
            self.assertEqual(runner.rows, {})


def model_complete_manifest():
    result = entries()
    for index, entry in enumerate(result):
        status = "timeout" if index == 0 else "not_sent" if index == 1 else "success"
        entry.update(outcome="observed", expected_blackhole_observed=index < 2,
                     records=[{"status": status, "request_nonce": f"{index * 8 + i:032x}"} for i in range(8)])
    return result


def model_fault_evidence():
    pin = {"device": 1, "inode": 2}
    before = [{"protocol": p, "marker": p, "packets": 0, "bytes": 0} for p in ("udp", "tcp")]
    after = [{**r, "packets": 8 if r["protocol"] == "udp" else 1, "bytes": 800} for r in before]
    return {"before_requests": {"rules": before, "namespace_identity": pin},
            "after_blackhole": {"rules": after, "namespace_identity": pin},
            "normal_clear": {"complete": True, "remaining": [], "all_owned_rules_observed_absent": True,
                             "after": {"rules": [], "namespace_identity": pin}}}


class ContractControls(unittest.TestCase):
    def test_fixed_32_partitions_expected_failures_from_16_fresh_successes(self):
        summary = contract.summarize(model_complete_manifest())
        self.assertEqual((summary["prescheduled_requests"], summary["success_requests"]), (32, 16))
        self.assertEqual(summary["phase_terminal_counts"], {"blackhole": {"timeout": 8, "not_sent": 8}, "recovery": {"success": 16}})
        self.assertFalse(summary["all_responses_observed"])
        self.assertTrue(contract.accepted(summary, model_fault_evidence()))
        self.assertIsNone(summary["canonical_current_owner_verified"])
        self.assertIsNone(summary["native_direct_recovery_ms"])

    def test_zero_kernel_hits_or_wrong_namespace_or_uncleared_rule_cannot_pass(self):
        summary = contract.summarize(model_complete_manifest())
        for mutate in (
            lambda f: f["after_blackhole"]["rules"][0].update(packets=0),
            lambda f: f["after_blackhole"].update(namespace_identity={"device": 9, "inode": 9}),
            lambda f: f["normal_clear"]["after"].update(rules=[{"marker": "still-present"}]),
            lambda f: f["after_blackhole"]["rules"][1].update(marker="later-owner"),
        ):
            value = model_fault_evidence()
            mutate(value)
            self.assertFalse(contract.accepted(summary, value))

    def test_missing_started_entries_keep_unknown_and_fixed_denominator(self):
        value = entries()
        value[0]["outcome"] = "started"
        summary = contract.summarize(value)
        self.assertEqual(summary["prescheduled_requests"], 32)
        self.assertEqual(summary["terminal_counts"], {"unknown": 8, "not_started": 24})
        self.assertFalse(contract.accepted(summary, model_fault_evidence()))

    def test_fresh_nonce_reuse_count_change_and_timing_reset_are_rejected(self):
        for change in (
            lambda v: v[2]["records"][0].update(request_nonce=v[0]["records"][0]["request_nonce"]),
            lambda v: v[2].update(round_nonce=v[0]["round_nonce"]),
            lambda v: v[2].update(count=9),
            lambda v: v[2].update(timeout_ms=2000),
        ):
            value = model_complete_manifest()
            change(value)
            with self.assertRaises(ValueError):
                contract.summarize(value)

    def test_generic_tcp_bind_or_connect_failure_is_not_expected_drop(self):
        entry = entries()[1]
        entry.update(probe_exit=1, echo_exit=1,
                     records=[{"status": "not_sent", "reason": "connect_deadline", "sent_offset_ns": None}] * 8)
        echo = {"termination_reason": "duration_deadline", "responses_sent": 0, "send_errors": 0, "accepted_connections": 0}
        self.assertTrue(contract.expected_blackhole(entry, {"connection_attempts": 1, "termination_reason": "connect_deadline"}, echo))
        for attempts, reason in ((0, "bind_failed"), (1, "connect_failed"), (2, "connect_deadline")):
            self.assertFalse(contract.expected_blackhole(entry, {"connection_attempts": attempts, "termination_reason": reason}, echo))

    def test_fault_summary_error_cannot_skip_actual_original_owner_or_rule_network_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            owners = OwnedGroups()
            owners.spawn("fault-summary", [sys.executable, "-c", "import time; time.sleep(30)"],
                         Path(directory) / "child.log", env=dict(os.environ))
            report = {"manifest": entries()}
            report["manifest"][0]["count"] = 9
            calls = []
            def rules(deadline):
                calls.append(("rules", deadline))
                raise RuntimeError("explicit fake rule-cleanup failure")
            def network(deadline):
                calls.append(("network", deadline))
                return {"complete": True, "explicit_fake_commands": True}
            try:
                harness.finalize_observations(report, owners, network, fault_cleanup=rules, summary=contract.summarize)
            finally:
                cleanup = owners.cleanup()
            self.assertTrue(all(r["complete"] for r in cleanup))
            self.assertTrue(all(r["anchor_reaped"] and r["group_absent"] for r in report["process_cleanup"]))
            self.assertEqual([c[0] for c in calls], ["rules", "network"])
            self.assertEqual(calls[0][1], calls[1][1], "network phase restarted its cleanup budget")
            self.assertFalse(report["fault_cleanup"]["complete"])
            self.assertEqual(report["application"]["terminal_counts"], {"unknown": 32})


@unittest.skipUnless(os.name == "posix", "original anchored CLI fixture needs POSIX")
class ActualCliControls(unittest.TestCase):
    def actual_rounds(self, protocol):
        owners, reports, exits = OwnedGroups(), [], []
        reserved = []
        error = None
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            try:
                for index in range(2):
                    kind = socket.SOCK_DGRAM if protocol == "udp" else socket.SOCK_STREAM
                    sockets = [socket.socket(socket.AF_INET, kind) for _ in range(2)]
                    reserved.extend(sockets)
                    for sock in sockets:
                        sock.bind(("127.0.0.1", 0))
                    bind, target = [s.getsockname() for s in sockets]
                    entry = contract.manifest("11" * 16, f"{index:032x}")[0 if protocol == "udp" else 1]
                    tool = harness.DUAL / (protocol + "_business_probe.py")
                    log = out / f"echo{index}.log"
                    sockets[1].close()
                    echo = owners.spawn(f"echo{index}", harness.tool_argv(tool, "echo", target, bind, entry, out / f"echo{index}.json"),
                                        log, env=dict(os.environ), socket_tool=True)
                    ready_end = time.monotonic() + 2
                    while time.monotonic() < ready_end:
                        if echo.poll() is not None:
                            raise RuntimeError("actual loopback echo failed readiness")
                        if any(json.loads(line).get("event") == "echo_ready" for line in log.read_text().splitlines()):
                            break
                        time.sleep(.01)
                    else:
                        raise TimeoutError("actual loopback echo readiness")
                    sockets[0].close()
                    report_path = out / f"probe{index}.json"
                    probe = owners.spawn(f"probe{index}", harness.tool_argv(tool, "probe", bind, target, entry, report_path),
                                         out / f"probe{index}.log", env=dict(os.environ), socket_tool=True)
                    exits.append((harness.wait_child(probe, time.monotonic() + 3), harness.wait_child(echo, time.monotonic() + 3)))
                    data, _ = harness.udp_summary.read_report(report_path)
                    if protocol == "udp":
                        harness.udp_summary.validate_report(data)
                    else:
                        harness.tcp.validate_probe(data)
                    reports.append(data)
            except BaseException as caught:
                error = caught
            finally:
                for sock in reserved:
                    sock.close()
                cleanup = owners.cleanup(grace_seconds=.1, join_seconds=2)
            if error:
                for path in out.iterdir():
                    print(path.name + ": " + path.read_text()[:65536], file=sys.stderr)
                raise error
            self.assertTrue(all(r["complete"] for r in cleanup))
            self.assertEqual(exits, [(0, 0), (0, 0)])
            self.assertEqual(len({r["request_nonce"] for report in reports for r in report["requests"]}), 16)
            self.assertNotEqual(reports[0]["round_nonce"], reports[1]["round_nonce"])
            self.assertTrue(all(r["status"] == "success" for report in reports for r in report["requests"]))
            self.assertTrue(all(report["evidence"] == harness.udp.UNVERIFIED for report in reports))

    def test_actual_fresh_udp_rounds_keep_distinct_nonces_and_original_anchors(self):
        self.actual_rounds("udp")

    def test_actual_fresh_tcp_rounds_keep_distinct_nonces_and_original_anchors(self):
        self.actual_rounds("tcp")

    def test_actual_udp_failure_report_is_preserved_when_distinct_fresh_requests_succeed(self):
        # An owned loopback receiver deliberately supplies no echo. This is an
        # original CLI/report retention control, not a kernel DROP/TUN result.
        owners, sockets = OwnedGroups(), []
        failure = None
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            try:
                reserved = [socket.socket(socket.AF_INET, socket.SOCK_DGRAM) for _ in range(2)]
                sockets.extend(reserved)
                for sock in reserved:
                    sock.bind(("127.0.0.1", 0))
                old_bind, old_target = [sock.getsockname() for sock in reserved]
                reserved[0].close()
                tool = harness.DUAL / "udp_business_probe.py"
                frozen = entries()
                old_path = out / "original-failed-probe.json"
                old = owners.spawn("original-failed-probe", harness.tool_argv(tool, "probe", old_bind, old_target,
                                   frozen[0], old_path), out / "original-failed-probe.log", env=dict(os.environ), socket_tool=True)
                old_exit = harness.wait_child(old, time.monotonic() + 3)
                old_report, _ = harness.udp_summary.read_report(old_path)
                harness.udp_summary.validate_report(old_report)
                old_sha = harness.digest(old_path)
                pin = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sockets.append(pin)
                pin.bind(old_bind)
                fresh_sockets = [socket.socket(socket.AF_INET, socket.SOCK_DGRAM) for _ in range(2)]
                sockets.extend(fresh_sockets)
                for sock in fresh_sockets:
                    sock.bind(("127.0.0.1", 0))
                fresh_bind, fresh_target = [sock.getsockname() for sock in fresh_sockets]
                fresh_sockets[1].close()
                echo_log = out / "fresh-echo.log"
                echo = owners.spawn("fresh-echo", harness.tool_argv(tool, "echo", fresh_target, fresh_bind,
                                    frozen[2], out / "fresh-echo.json"), echo_log, env=dict(os.environ), socket_tool=True)
                ready_end = time.monotonic() + 2
                while time.monotonic() < ready_end:
                    if echo.poll() is not None:
                        raise RuntimeError("actual fresh echo failed readiness")
                    if any(json.loads(line).get("event") == "echo_ready" for line in echo_log.read_text().splitlines()):
                        break
                    time.sleep(.01)
                else:
                    raise TimeoutError("actual fresh echo readiness")
                fresh_sockets[0].close()
                fresh_path = out / "fresh-probe.json"
                fresh = owners.spawn("fresh-probe", harness.tool_argv(tool, "probe", fresh_bind, fresh_target,
                                     frozen[2], fresh_path), out / "fresh-probe.log", env=dict(os.environ), socket_tool=True)
                fresh_exit = harness.wait_child(fresh, time.monotonic() + 3)
                echo_exit = harness.wait_child(echo, time.monotonic() + 3)
                fresh_report, _ = harness.udp_summary.read_report(fresh_path)
                harness.udp_summary.validate_report(fresh_report)
                preserved_sha = harness.digest(old_path)
            except BaseException as caught:
                failure = caught
            finally:
                for sock in sockets:
                    sock.close()
                cleanup = owners.cleanup(grace_seconds=.1, join_seconds=2)
            if failure:
                for path in out.iterdir():
                    print(path.name + ": " + path.read_text()[:65536], file=sys.stderr)
                raise failure
            self.assertTrue(all(r["complete"] and r["anchor_reaped"] and r["group_absent"] for r in cleanup))
            self.assertEqual((old_exit, fresh_exit, echo_exit), (1, 0, 0))
            self.assertEqual(old_sha, preserved_sha)
            self.assertTrue(all(r["status"] == "timeout" and r["reason"] == "response_deadline" and r["sent_offset_ns"] is not None
                                for r in old_report["requests"]))
            self.assertTrue(all(r["status"] == "success" for r in fresh_report["requests"]))
            self.assertEqual(len({r["request_nonce"] for report in (old_report, fresh_report) for r in report["requests"]}), 16)
            self.assertNotEqual(old_report["round_nonce"], fresh_report["round_nonce"])
            self.assertTrue(set((old_bind, old_target)).isdisjoint((fresh_bind, fresh_target)))
            self.assertEqual(old_report["evidence"], harness.udp.UNVERIFIED)
            self.assertEqual(fresh_report["evidence"], harness.udp.UNVERIFIED)
            print(json.dumps({"control": "actual_loopback_failed_udp_report_then_fresh_success_not_kernel_drop",
                              "original_timeout_requests": 8, "fresh_success_requests": 8,
                              "original_failed_report_sha256": old_sha, "original_report_preserved": old_sha == preserved_sha,
                              "cleanup": cleanup}, sort_keys=True))


if __name__ == "__main__":
    unittest.main()
