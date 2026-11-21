#!/usr/bin/env python3
"""Pure contract/fake-command controls and real owned-child cleanup; no TUN."""
import copy
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import linux_tun_contract as contract
import linux_tun_evidence as harness
from linux_tun_owned import MAX_GROUPS, MAX_HANDLES, OwnedGroups


class ContractControls(unittest.TestCase):
    def test_missing_entries_remain_in_fixed_32_denominator(self):
        entries = contract.manifest("11" * 16, "22" * 16)
        entries[0]["records"] = [{"status": "success"}] * 8
        report = contract.summarize(entries)
        self.assertEqual(report["prescheduled_requests"], 32)
        self.assertEqual(report["success_requests"], 8)
        self.assertEqual(report["terminal_counts"]["not_started"], 24)
        self.assertFalse(report["all_responses_observed"])
        self.assertIsNone(report["canonical_current_owner_verified"])
        entries[1]["outcome"] = "started"
        report = contract.summarize(entries)
        self.assertEqual(report["terminal_counts"]["unknown"], 8)
        self.assertEqual(report["terminal_counts"]["not_started"], 16)
        with self.assertRaises(ValueError):
            contract.summarize(entries[:-1])

    def test_current_process_network_and_run_identity_are_required(self):
        status = {"process_id": 10, "network_id": "room-1", "node_id": "a", "virtual_ip": "10.20.0.1",
                  "connection_timeline": {"correlation_id": "instance-a", "run_id": "run-1"}}
        accepted = contract.identity(status, 10, "room-1", "run-1")
        self.assertIsNone(accepted["runtime_incarnation"])
        for pid, network, run in ((11, "room-1", "run-1"), (10, "room-2", "run-1"), (10, "room-1", "run-2")):
            with self.assertRaises(ValueError):
                contract.identity(status, pid, network, run)

    def test_kernel_tun_exact_ifindex_vip_and_route_reject_bypass(self):
        links = [{"ifname": "tun-a", "ifindex": 7, "linkinfo": {"info_kind": "tun"}}]
        addresses = [{"ifname": "tun-a", "ifindex": 7, "addr_info": [{"family": "inet", "local": "10.20.0.1"}]}]
        route = [{"dst": "10.20.0.2", "dev": "tun-a", "prefsrc": "10.20.0.1"}]
        self.assertTrue(contract.kernel_route("tun-a", "10.20.0.1", "10.20.0.2", links, addresses, route)["kernel_route_observed"])
        for rows, value in ((links, {"linkinfo": {"info_kind": "veth"}}),
                            (addresses, {"ifindex": 8}), (route, {"dev": "eth0"}),
                            (route, {"prefsrc": "192.0.2.2"})):
            saved = copy.deepcopy(rows[0])
            rows[0].update(value)
            with self.assertRaises(ValueError):
                contract.kernel_route("tun-a", "10.20.0.1", "10.20.0.2", links, addresses, route)
            rows[0] = saved

    def test_started_missing_artifact_never_becomes_unsent_or_success(self):
        entries = contract.manifest("11" * 16, "22" * 16)
        entries[0]["outcome"] = "started"
        report = contract.summarize(entries)
        self.assertEqual(report["terminal_counts"], {"unknown": 8, "not_started": 24})
        self.assertEqual(report["prescheduled_requests"], 32)

    def test_fake_cleanup_checks_disappearance_and_collects_delete_failure(self):
        plan = {"namespaces": ["owned-a", "owned-b"], "host_link_names": ["owned-br"],
                "tun_interfaces": {"owned-a": "owned-tun"}}
        namespaces = {"owned-a", "owned-b"}
        links = {"owned-br"}
        commands = []
        def command(argv, **_kwargs):
            commands.append(argv)
            if argv == ["ip", "netns", "list"]:
                return subprocess.CompletedProcess(argv, 0, "\n".join(sorted(namespaces)), "")
            if argv == ["ip", "-j", "link", "show"]:
                return subprocess.CompletedProcess(argv, 0, json.dumps([{"ifname": n} for n in links]), "")
            if argv[:4] == ["ip", "netns", "exec", "owned-a"]:
                return subprocess.CompletedProcess(argv, 0, "[]", "")
            if argv[:3] == ["ip", "netns", "delete"]:
                if argv[-1] == "owned-b":
                    return subprocess.CompletedProcess(argv, 1, "", "fixture delete failure")
                namespaces.remove(argv[-1])
            if argv[:3] == ["ip", "link", "delete"]:
                links.discard(argv[-1])
            return subprocess.CompletedProcess(argv, 0, "", "")
        with patch("linux_tun_evidence.subprocess.run", side_effect=command):
            result = harness.cleanup_network(plan)
        self.assertFalse(result["complete"])
        self.assertIn("owned-b", result["remaining"])
        self.assertIn(["ip", "link", "delete", "owned-br"], commands)
        self.assertIn(["ip", "netns", "delete", "owned-a"], commands)

    def test_fake_cleanup_tun_still_present_is_failure_before_namespace_removal(self):
        plan = {"namespaces": ["owned-a"], "host_link_names": [], "tun_interfaces": {"owned-a": "owned-tun"}}
        present = [True]
        def command(argv, **_kwargs):
            if argv == ["ip", "netns", "list"]:
                return subprocess.CompletedProcess(argv, 0, "owned-a" if present[0] else "", "")
            if argv[:3] == ["ip", "netns", "exec"]:
                return subprocess.CompletedProcess(argv, 0, '[{"ifname":"owned-tun"}]', "")
            if argv[:3] == ["ip", "netns", "delete"]:
                present[0] = False
            return subprocess.CompletedProcess(argv, 0, "[]", "")
        with patch("linux_tun_evidence.subprocess.run", side_effect=command):
            result = harness.cleanup_network(plan)
        self.assertFalse(result["complete"])
        self.assertIn("tun_before_namespace_removal:owned-tun", result["remaining"])

    def test_fake_partial_setup_cleanup_preserves_foreign_resources(self):
        plan = {"namespaces": ["owned-a", "owned-b"], "host_link_names": ["owned-br", "owned-veth"],
                "tun_interfaces": {"owned-a": "owned-tun"}}
        namespaces, links, deleted = {"owned-a", "foreign-ns"}, {"owned-br", "foreign-link"}, []
        def command(argv, **_kwargs):
            if argv == ["ip", "netns", "list"]:
                return subprocess.CompletedProcess(argv, 0, "\n".join(sorted(namespaces)), "")
            if argv == ["ip", "-j", "link", "show"]:
                return subprocess.CompletedProcess(argv, 0, json.dumps([{"ifname": n} for n in links]), "")
            if argv[:3] == ["ip", "netns", "exec"]:
                return subprocess.CompletedProcess(argv, 0, "[]", "")
            deleted.append(argv[-1])
            if argv[:3] == ["ip", "netns", "delete"]:
                namespaces.discard(argv[-1])
            else:
                links.discard(argv[-1])
            return subprocess.CompletedProcess(argv, 0, "", "")
        with patch("linux_tun_evidence.subprocess.run", side_effect=command):
            result = harness.cleanup_network(plan)
        self.assertTrue(result["complete"])
        self.assertEqual(namespaces, {"foreign-ns"})
        self.assertEqual(links, {"foreign-link"})
        self.assertFalse(any("foreign" in name for name in deleted))


@unittest.skipUnless(os.name == "posix", "original anchored CLI groups require POSIX")
class CliSocketControls(unittest.TestCase):
    def actual_cli(self, protocol):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            sock_type = socket.SOCK_DGRAM if protocol == "udp" else socket.SOCK_STREAM
            reserved = [socket.socket(socket.AF_INET, sock_type) for _ in range(2)]
            for sock in reserved:
                sock.bind(("127.0.0.1", 0))
            bind, target = (sock.getsockname() for sock in reserved)
            entries = contract.manifest("11" * 16, "22" * 16)
            entry = entries[0 if protocol == "udp" else 2]
            tool = harness.DUAL / (protocol + "_business_probe.py")
            groups = OwnedGroups()
            probe_report, echo_report = out / "probe.json", out / "echo.json"
            error = None
            try:
                reserved[1].close()
                echo = groups.spawn("echo", harness.tool_argv(tool, "echo", target, bind, entry, echo_report),
                                    out / "echo.log", env=dict(os.environ), socket_tool=True)
                ready_end = time.monotonic() + 2
                while time.monotonic() < ready_end:
                    if echo.poll() is not None:
                        raise RuntimeError("actual echo CLI ended before bind readiness")
                    with (out / "echo.log").open() as stream:
                        if any(json.loads(line).get("event") == "echo_ready" for line in stream.read(4096).splitlines()):
                            break
                    time.sleep(.01)
                else:
                    raise TimeoutError("actual echo CLI readiness")
                reserved[0].close()
                probe = groups.spawn("probe", harness.tool_argv(tool, "probe", bind, target, entry, probe_report),
                                     out / "probe.log", env=dict(os.environ), socket_tool=True)
                entry["outcome"] = "started"
                probe_exit = harness.wait_child(probe, time.monotonic() + 3)
                report, _ = harness.udp_summary.read_report(probe_report)
                if protocol == "udp":
                    harness.udp_summary.validate_report(report)
                    records = report["requests"]
                else:
                    records = harness.tcp.validate_probe(report)
                contract.attach(entry, report, records, bind, target, harness.digest(tool))
                echo_exit = harness.wait_child(echo, time.monotonic() + 3)
            except BaseException as caught:
                error = caught
            finally:
                for sock in reserved:
                    sock.close()
                cleanup = groups.cleanup(grace_seconds=.1, join_seconds=2)
            if error is not None:
                for path in out.iterdir():
                    print(path.name + ": " + path.read_text()[:65536], file=sys.stderr)
                raise error
            self.assertTrue(all(r["complete"] for r in cleanup))
            self.assertEqual((probe_exit, echo_exit), (0, 0))
            summary = contract.summarize(entries)
            self.assertEqual((summary["success_requests"], summary["prescheduled_requests"]), (8, 32))
            self.assertEqual(report["evidence"], harness.udp.UNVERIFIED)
            # Explicit local socket fixture only. No fake kernel-route assertion.
            self.assertIsNone(summary["canonical_current_owner_verified"])

    def test_original_udp_cli_actual_echo_reducer_and_original_group_cleanup(self):
        self.actual_cli("udp")

    def test_new_tcp_cli_actual_echo_validator_and_original_group_cleanup(self):
        self.actual_cli("tcp")


@unittest.skipUnless(os.name == "posix", "original anchored process groups require POSIX")
class OwnerControls(unittest.TestCase):
    def test_actual_spawned_owner_join_and_fake_resource_cleanup_precede_summary_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            owners = OwnedGroups()
            owners.spawn("summary-fault", [sys.executable, "-c", "import time; time.sleep(30)"],
                         Path(directory) / "child.log", env=dict(os.environ))
            report = {"manifest": contract.manifest("11" * 16, "22" * 16)}
            report["manifest"][0]["count"] = 9
            network_called = []
            try:
                harness.finalize_observations(report, owners, lambda: (
                    network_called.append(True) or {"complete": True, "explicit_fake_commands": True}))
            finally:
                cleanup = owners.cleanup()
            self.assertEqual(network_called, [True])
            self.assertTrue(all(r["complete"] for r in cleanup))
            self.assertTrue(all(r["anchor_reaped"] and r["group_absent"] for r in report["process_cleanup"]))
            self.assertEqual(report["summary_error"], "ValueError")
            self.assertEqual(report["application"]["terminal_counts"], {"unknown": 32})
            self.assertIsNone(report["application"]["success_requests"])
            self.assertFalse(report["application"]["all_responses_observed"])

    def test_actual_normal_child_exit_keeps_unreaped_anchor_until_last_group_kill(self):
        with tempfile.TemporaryDirectory() as directory:
            owners = OwnedGroups()
            child = owners.spawn("normal", [sys.executable, "-c", "pass"], Path(directory) / "child.log", env=dict(os.environ))
            try:
                self.assertEqual(child.wait(timeout=2), 0)
                anchor = owners.owners[0]["anchor"]
                self.assertIsNone(anchor.returncode)
                os.killpg(anchor.pid, 0)
            finally:
                records = owners.cleanup(grace_seconds=.05, join_seconds=2)
            self.assertTrue(records[0]["complete"])
            self.assertEqual(records[0]["anchor_returncode"], -signal.SIGKILL)
            self.assertTrue(records[0]["group_absent"])
            # Idempotence never addresses that now-reusable identifier again.
            with patch("os.killpg", side_effect=AssertionError("signal after original reap")):
                self.assertEqual(owners.cleanup(), records)

    def test_actual_failed_spawn_still_reaps_original_anchor_and_reports_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            owners = OwnedGroups()
            try:
                with self.assertRaises(FileNotFoundError):
                    owners.spawn("missing", ["/nonexistent-linux-evidence-child"], Path(directory) / "child.log", env=dict(os.environ))
            finally:
                records = owners.cleanup(grace_seconds=.01, join_seconds=2)
            self.assertTrue(records[0]["anchor_reaped"])
            self.assertTrue(records[0]["group_absent"])
            self.assertFalse(records[0]["complete"])
            self.assertEqual(MAX_HANDLES, MAX_GROUPS * 2)

    def test_actual_two_running_children_all_results_collected_on_body_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            owners = OwnedGroups()
            try:
                for i in range(2):
                    owners.spawn(str(i), [sys.executable, "-c", "import time; time.sleep(30)"],
                                 Path(directory) / str(i), env=dict(os.environ))
                raise ValueError("original body failed")
            except ValueError:
                pass
            finally:
                records = owners.cleanup(grace_seconds=.05, join_seconds=2)
            self.assertEqual(len(records), 2)
            self.assertTrue(all(r["complete"] for r in records))


if __name__ == "__main__":
    unittest.main()
