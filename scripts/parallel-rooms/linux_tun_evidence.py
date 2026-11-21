#!/usr/bin/env python3
"""Linux same-host kernel-TUN routes plus fixed OS UDP/TCP application evidence.

No canonical request, current-owner, public-network or full D-03 assertion.
Original Lab ownership and UDP probe/codec are shared by the separate scopes.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import sys
import time

from linux_tun_contract import COUNT, attach, identity, kernel_route, manifest, summarize
from linux_tun_owned import MAX_GROUPS, MAX_HANDLES, OwnedGroups
import linux_tun_fault_contract as fault_contract
from linux_tun_fault import FaultOwner
import linux_tun_stall
import linux_tun_stall_contract as stall_contract

ROOT = Path(__file__).resolve().parents[2]
DUAL = ROOT / "scripts/dual-end"
sys.path.insert(0, str(DUAL))
import udp_business_probe as udp
import udp_business_summary as udp_summary
import tcp_business_probe as tcp

spec = importlib.util.spec_from_file_location("original_linux_netns", Path(__file__).with_name("linux-netns.py"))
original = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = original
spec.loader.exec_module(original)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class EvidenceLab(original.Lab):
    def __init__(self, args: argparse.Namespace, groups: OwnedGroups) -> None:
        super().__init__(args)
        self.groups = groups
        self.stall_daemon_inputs = {}

    def spawn(self, label: str, name: str, command: list[str], *, env=None, token=None):
        clean = {k: v for k, v in os.environ.items() if not k.startswith("P2WLAN_")}
        clean.update(RUST_LOG="info", RUST_BACKTRACE="0", P2WLAN_TEST_RUN_ID=self.run_id)
        clean.update(env or {})
        if getattr(self.args, "server_stall", False) and command[:1] == [str(self.args.daemon)]:
            # Explicit existing public CLI fixture input; product defaults and
            # the separate normal/blackhole entries retain their original argv.
            command = [*command, "--keepalive-interval-secs", "1"]
            self.stall_daemon_inputs[name] = {
                "keepalive_interval_secs": 1,
                "argv_sha256": hashlib.sha256(json.dumps(command, separators=(",", ":")).encode()).hexdigest(),
                "default_keepalive_cycle_verified": False,
            }
        child = self.groups.spawn(name, ["ip", "netns", "exec", self.ns(label), *command],
                                  self.root / (name + ".console"), env=clean, token=token)
        self.processes.append(child)
        return child


def network_inventory(runner=original.run) -> tuple[set[str], set[str]]:
    ns_result = runner(["ip", "netns", "list"])
    link_result = runner(["ip", "-j", "link", "show"])
    if ns_result.returncode != 0 or link_result.returncode != 0:
        raise RuntimeError("actual network inventory failed")
    ns = ns_result.stdout
    links = json.loads(link_result.stdout)
    return {line.split()[0] for line in ns.splitlines() if line.strip()}, {row["ifname"] for row in links}


def resource_plan(lab: EvidenceLab) -> dict:
    namespaces, links = network_inventory()
    owned_ns = [lab.ns(label) for label in ("control", "a", "b", "c")]
    owned_links = [lab.bridge] + [lab.prefix + str(i) + suffix for i in range(2, 6) for suffix in ("h", "n")]
    if set(owned_ns) & namespaces or set(owned_links) & links:
        raise RuntimeError("generated resource name already owned by another run")
    return {"preflight_all_absent": True, "namespaces": owned_ns, "host_link_names": owned_links,
            "fault_rules": [], "tun_interfaces": {lab.ns("a"): "p2ra1", lab.ns("b"): "p2rb1"}}


def cleanup_network(plan: dict | None, *, deadline: float | None = None) -> dict:
    if plan is None:
        return {"admitted": False, "complete": True, "operations": [], "remaining": []}
    operations = []
    end = time.monotonic() + 20 if deadline is None else deadline

    def command(argv: list[str]) -> subprocess.CompletedProcess:
        return subprocess.run(argv, text=True, capture_output=True, timeout=max(.001, end - time.monotonic()))

    # Test each actual original TUN before removing its namespace. Unknown is
    # failure, not a manufactured zero; process-group cleanup is separate.
    remaining = []
    try:
        namespaces, _ = network_inventory(command)
    except Exception as error:
        namespaces = set(plan["namespaces"])
        remaining.append("namespace_inventory_unknown:" + type(error).__name__)
    for name, interface in plan["tun_interfaces"].items():
        if name in namespaces:
            try:
                result = command(["ip", "netns", "exec", name, "ip", "-j", "link", "show"])
                if result.returncode != 0 or any(row.get("ifname") == interface for row in json.loads(result.stdout)):
                    remaining.append("tun_before_namespace_removal:" + interface)
            except Exception as error:
                remaining.append("tun_absence_unknown:" + type(error).__name__)
    for name in reversed(plan["namespaces"]):
        if name not in namespaces:
            continue
        try:
            result = command(["ip", "netns", "delete", name])
            operations.append({"kind": "namespace", "name": name, "returncode": result.returncode})
        except Exception as error:
            operations.append({"kind": "namespace", "name": name, "error": type(error).__name__})
    for name in reversed(plan["host_link_names"]):
        try:
            result = command(["ip", "link", "delete", name])
            operations.append({"kind": "link", "name": name, "returncode": result.returncode})
        except Exception as error:
            operations.append({"kind": "link", "name": name, "error": type(error).__name__})
    try:
        namespaces, links = network_inventory(command)
        remaining.extend(sorted(set(plan["namespaces"]) & namespaces))
        remaining.extend(sorted(set(plan["host_link_names"]) & links))
    except Exception as error:
        remaining.append("final_inventory_unknown:" + type(error).__name__)
    return {"admitted": True, "operations": operations, "remaining": remaining,
            "complete": not remaining and not any("error" in op for op in operations)}


def endpoint(lab: EvidenceLab, name: str, other_vip: str | None = None) -> dict:
    entry = lab.daemons[name]
    status = lab.status(name)
    result = identity(status, entry["process"].pid, entry["room"]["id"], lab.run_id)
    if other_vip is not None:
        interface = entry["interface"]
        links = json.loads(lab.cmd(entry["namespace"], ["ip", "-j", "-details", "link", "show", "dev", interface]).stdout)
        addresses = json.loads(lab.cmd(entry["namespace"], ["ip", "-j", "address", "show", "dev", interface]).stdout)
        route = json.loads(lab.cmd(entry["namespace"], ["ip", "-j", "-4", "route", "get", other_vip]).stdout)
        result["kernel"] = kernel_route(interface, result["virtual_ip"], other_vip, links, addresses, route)
        room_routes = json.loads(lab.cmd(entry["namespace"], ["ip", "-j", "-4", "route", "show", "exact", entry["room"]["cidr"]]).stdout)
        if not any(r.get("dev") == interface for r in room_routes):
            raise RuntimeError("original room route missing from exact TUN")
        result["room_route"] = room_routes
    return result


def same_endpoint(before: dict, after: dict) -> None:
    if before != after:
        raise RuntimeError("original endpoint/process/TUN/route identity changed during requests")


def wait_child(child: subprocess.Popen, deadline: float) -> int:
    # Reaping the measured child is safe: its original unreaped anchor pins PGID.
    while time.monotonic() < deadline:
        result = child.poll()
        if result is not None:
            return result
        time.sleep(.02)
    raise TimeoutError("original application child deadline")


def tool_argv(tool: Path, role: str, bind: tuple, target: tuple, entry: dict, output: Path) -> list[str]:
    return [sys.executable, "-u", str(tool), role, "--bind-ip", bind[0], "--bind-port", str(bind[1]),
            "--target-ip", target[0], "--target-port", str(target[1]), "--run-nonce", entry["run_nonce"],
            "--round-nonce", entry["round_nonce"], "--count", str(COUNT),
            "--interval-ms", str(entry["interval_ms"]), "--timeout-ms", str(entry["timeout_ms"]),
            "--duration-ms", str(entry["duration_ms"]), "--payload-bytes", str(entry["payload_bytes"]),
            "--output", str(output)]


def measure(lab: EvidenceLab, groups: OwnedGroups, entry: dict, out: Path, snapshots: dict,
            *, expected_fault: bool = False) -> None:
    for name, peer in (("a1", "b1"), ("b1", "a1")):
        same_endpoint(snapshots[name], endpoint(lab, name, snapshots[peer]["virtual_ip"]))
    index = 0 if entry["direction"] == "a-to-b" else 1
    source, target = (("a1", "b1") if index == 0 else ("b1", "a1"))
    protocol = entry["protocol"]
    port = 43000 + index * 2 + (10 if protocol == "tcp" else 0)
    bind = (snapshots[source]["virtual_ip"], entry.get("source_port", port))
    destination = (snapshots[target]["virtual_ip"], entry.get("target_port", port + 1))
    tool = DUAL / (protocol + "_business_probe.py")
    stem = protocol + "-" + entry["direction"] + ("-" + entry["phase"] if "phase" in entry else "")
    echo_log, probe_log = out / (stem + "-echo.log"), out / (stem + "-probe.log")
    echo_report, probe_report = out / (stem + "-echo.json"), out / (stem + "-probe.json")
    clean = {k: v for k, v in os.environ.items() if not k.startswith("P2WLAN_")}
    echo = groups.spawn(stem + "-echo", ["ip", "netns", "exec", lab.ns(lab.daemons[target]["namespace"]),
                                       *tool_argv(tool, "echo", destination, bind, entry, echo_report)],
                        echo_log, env=clean, socket_tool=True)
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        if echo.poll() is not None:
            raise RuntimeError("original echo child ended before readiness")
        with echo_log.open() as stream:
            lines = stream.read(4096).splitlines()
        if any(json.loads(line).get("event") == "echo_ready" for line in lines):
            break
        time.sleep(.02)
    else:
        raise TimeoutError("original echo socket readiness")
    probe = groups.spawn(stem + "-probe", ["ip", "netns", "exec", lab.ns(lab.daemons[source]["namespace"]),
                                          *tool_argv(tool, "probe", bind, destination, entry, probe_report)],
                         probe_log, env=clean, socket_tool=True)
    entry["outcome"] = "started"
    probe_exit = wait_child(probe, time.monotonic() + 12)
    report, _ = udp_summary.read_report(probe_report)
    if protocol == "udp":
        udp_summary.validate_report(report)
        records = report["requests"]
    else:
        records = tcp.validate_probe(report)
    attach(entry, report, records, bind, destination, digest(tool))
    if "phase" in entry:
        entry["probe_observed_complete_monotonic_ns"] = time.monotonic_ns()
    echo_exit = wait_child(echo, time.monotonic() + 12)
    entry.update(probe_exit=probe_exit, echo_exit=echo_exit,
                 report_sha256=digest(probe_report), echo_report_sha256=digest(echo_report))
    if expected_fault:
        echo_report_data, _ = udp_summary.read_report(echo_report)
        config = echo_report_data["configuration"]
        if (echo_report_data.get("role") != "echo" or echo_report_data.get("scope") != "os_" + protocol + "_echo"
                or echo_report_data.get("tool_sha256") != digest(tool)
                or echo_report_data.get("evidence") != udp.UNVERIFIED
                or (echo_report_data["run_nonce"], echo_report_data["round_nonce"]) != (entry["run_nonce"], entry["round_nonce"])
                or (config["bind_ip"], config["bind_port"]) != destination
                or (config["target_ip"], config["target_port"]) != bind
                or config["count"] != COUNT or any(config[k] != entry[k] for k in fault_contract.TIMING)):
            raise ValueError("original fault echo differs from frozen socket/nonce/configuration")
        entry["expected_blackhole_observed"] = fault_contract.expected_blackhole(entry, report, echo_report_data)
        entry["probe_termination_reason"] = report["termination_reason"]
        entry["echo_termination_reason"] = echo_report_data["termination_reason"]
        if not entry["expected_blackhole_observed"]:
            raise RuntimeError("actual application failure is not the frozen expected blackhole outcome")
    elif probe_exit != 0 or echo_exit != 0:
        raise RuntimeError("original application child failed; fixed denominator retained")
    for name, peer in (("a1", "b1"), ("b1", "a1")):
        after = endpoint(lab, name, snapshots[peer]["virtual_ip"])
        same_endpoint(snapshots[name], after)


def exercise(lab: EvidenceLab, groups: OwnedGroups, report: dict, out: Path,
             *, fault_slot: list | None = None, stall_slot: list | None = None) -> None:
    info = json.loads(original.run([str(lab.args.daemon), "--build-info"]).stdout)
    if info.get("git_commit") != lab.args.head or info.get("binary_sha256") != digest(lab.args.daemon):
        raise RuntimeError("original daemon/source/binary identity mismatch")
    lab.setup()
    lab.spawn("control", "control", [str(lab.args.control)], env={"PORT": "8080", "DB_PATH": str(lab.root / "control.db"),
                                                              "JWT_SECRET": secrets.token_hex(32)})
    lab.wait("control readiness", lambda: lab.http("control", "/health"), 20)
    password = secrets.token_urlsafe(24)
    users = {label: lab.http("control", "/api/v1/register", method="POST",
                            body={"email": label + "@parallel.example", "password": password}) for label in ("a", "b")}
    room = lab.http("control", "/api/v1/rooms", method="POST", token=users["b"]["token"],
                    body={"name": "Linux TUN application evidence", "password": password})["room"]
    lab.http("control", "/api/v1/rooms/join", method="POST", token=users["a"]["token"],
             body={"room_code": room["room_code"], "password": password})
    for name, label in (("a1", "a"), ("b1", "b")):
        lab.daemon(name, label, room, users[label]["token"], 41001)
    initial = {name: lab.wait(name + " readiness", lambda name=name: endpoint(lab, name)) for name in ("a1", "b1")}
    for name, peer in (("a1", "b1"), ("b1", "a1")):
        # Wait for the original committed encrypted Direct readiness; no probe
        # request is sent/retried to turn a failed application run into a pass.
        lab.wait(name + " original Direct readiness", lambda name=name, peer=peer: any(
            p.get("node_id") == initial[peer]["node_id"] and p.get("online") is True
            and p.get("active_path") == "direct" for p in lab.status(name).get("peers", [])
        ))
    snapshots = {name: endpoint(lab, name, initial[peer]["virtual_ip"]) for name, peer in (("a1", "b1"), ("b1", "a1"))}
    if snapshots["a1"]["node_id"] == snapshots["b1"]["node_id"]:
        raise RuntimeError("two original endpoint identities collapsed")
    report["endpoint_routes_before"] = snapshots
    report["kernel_environment_verified"] = True
    lab.capture_stage("kernel_tun_routes_ready", successful=True)
    if stall_slot is not None:
        report["daemon_fixture_inputs"] = lab.stall_daemon_inputs
        linux_tun_stall.measure(sys.modules[__name__], lab, groups, report, out, snapshots, stall_slot)
    elif fault_slot is None:
        for entry in report["manifest"]:
            measure(lab, groups, entry, out, snapshots)
            report["application"] = summarize(report["manifest"])
    else:
        fault = FaultOwner(lab.ns("b"), report["owned_resources"], lab.namespaces,
                           snapshots["a1"], snapshots["b1"], report["manifest"])
        fault_slot.append(fault)
        report["fault"] = fault.evidence
        report["owned_resources"]["fault_rules"] = [{"protocol": r["protocol"], "marker": r["marker"],
                                                      "exact_args": r["args"]} for r in fault.rules]
        fault.install()
        for entry in report["manifest"][:2]:
            measure(lab, groups, entry, out, snapshots, expected_fault=True)
        fault.counter_snapshot()
        cleared = fault.clear()
        for name, peer in (("a1", "b1"), ("b1", "a1")):
            same_endpoint(snapshots[name], endpoint(lab, name, snapshots[peer]["virtual_ip"]))
        for entry in report["manifest"][2:]:
            measure(lab, groups, entry, out, snapshots)
            entry["recovery_report_observation_upper_bound_ns"] = (
                entry["probe_observed_complete_monotonic_ns"] - cleared["observed_monotonic_ns"])
        report["application"] = fault_contract.summarize(report["manifest"])
    report["endpoint_routes_after"] = {name: endpoint(lab, name, initial[peer]["virtual_ip"])
                                       for name, peer in (("a1", "b1"), ("b1", "a1"))}
    lab.capture_stage("fixed_application_requests_complete", successful=True)


def finalize_observations(report: dict, groups: OwnedGroups, network_cleanup,
                          *, fault_cleanup=None, summary=summarize, requested_count=32) -> None:
    # No manifest computation precedes cleanup. Collect each cleanup phase
    # independently; malformed evidence cannot skip any original owner.
    try:
        report["process_cleanup"] = groups.cleanup()
    except Exception as cleanup_error:
        report["process_cleanup"] = [{"complete": False, "error": type(cleanup_error).__name__}]
    # Optional rules share the original network phase's twenty seconds. No
    # new cleanup allowance starts after the rules consume that deadline.
    network_end = time.monotonic() + 20
    if fault_cleanup is not None:
        try:
            report["fault_cleanup"] = fault_cleanup(network_end)
        except Exception as cleanup_error:
            report["fault_cleanup"] = {"complete": False, "error": type(cleanup_error).__name__}
    try:
        report["network_cleanup"] = (network_cleanup() if fault_cleanup is None else network_cleanup(network_end))
    except Exception as cleanup_error:
        report["network_cleanup"] = {"complete": False, "error": type(cleanup_error).__name__}
    try:
        report["application"] = summary(report["manifest"])
    except Exception as summary_error:
        report["summary_error"] = type(summary_error).__name__
        report["application"] = {"denominator": f"all_{requested_count}_prescheduled_requests_including_unknown",
                                 "prescheduled_requests": requested_count, "success_requests": None,
                                 "terminal_counts": {"unknown": requested_count}, "missing_entry_count": None,
                                 "all_responses_observed": False, "canonical_current_owner_verified": None,
                                 "exact_direct_request_attribution": None,
                                 "expected_blackhole_failures_observed": False,
                                 "all_fresh_responses_observed": False, "all_32_distinct_request_nonces_observed": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--daemon", type=lambda x: Path(x).resolve(), required=True)
    parser.add_argument("--control", type=lambda x: Path(x).resolve(), required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--fault-recovery", action="store_true",
                        help="independent fixed32 application DROP/clear/fresh scope; original baseline unchanged")
    mode.add_argument("--server-stall", action="store_true",
                      help="independent UDP fixed16 original echo STOP/CONT; explicit keepalive interval1")
    args = parser.parse_args()
    if sys.platform != "linux" or os.geteuid() != 0 or not Path("/dev/net/tun").exists():
        parser.error("Linux root and kernel /dev/net/tun required; no mock downgrade")
    if original.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"]).stdout.strip() != args.head:
        parser.error("actual checkout differs from frozen source argument")
    udp.validate_output_path(args.output_dir)
    args.output_dir.mkdir(mode=0o700)
    args.report = args.output_dir / "report.json"
    args.debug_dir = args.output_dir / "debug"
    groups = OwnedGroups()
    lab = EvidenceLab(args, groups)
    run_nonce, round_nonce = secrets.token_hex(16), secrets.token_hex(16)
    report = {"schema_version": 1, "scope": stall_contract.SCOPE if args.server_stall else fault_contract.SCOPE if args.fault_recovery else "linux_same_host_kernel_tun_application", "source_commit": args.head,
              "run_id": lab.run_id, "github_run_id": os.environ.get("GITHUB_RUN_ID"),
              "github_run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
              "manifest": (stall_contract.manifest(run_nonce, round_nonce) if args.server_stall else
                           fault_contract.manifest(run_nonce, round_nonce) if args.fault_recovery else manifest(run_nonce, round_nonce)),
              "kernel_environment_verified": None, "canonical_current_owner_verified": None,
              "full_d03_fault_matrix_verified": None, "passed": False,
              "limits": {"process_groups": MAX_GROUPS, "registry_handles_including_anchors": MAX_HANDLES,
                         "synchronous_command_slots": 1, "synchronous_command_timeout_seconds": 20},
              "source_sha256": {str(p.relative_to(ROOT)): digest(p) for p in
                                (Path(__file__), Path(__file__).with_name("linux-netns.py"),
                                 Path(__file__).with_name("linux_tun_owned.py"), Path(__file__).with_name("linux_tun_contract.py"),
                                 Path(__file__).with_name("linux_tun_fault.py"), Path(__file__).with_name("linux_tun_fault_contract.py"),
                                 Path(__file__).with_name("linux_tun_stall.py"), Path(__file__).with_name("linux_tun_stall_contract.py"),
                                 Path(__file__).with_name("udp_stall_echo.py"),
                                 DUAL / "udp_business_probe.py", DUAL / "udp_business_summary.py", DUAL / "tcp_business_probe.py",
                                 ROOT / ".github/workflows/parallel-rooms.yml")},
              "binary_sha256": {"daemon": None, "control": None}}
    plan = None
    fault_slot = [] if args.fault_recovery else None
    stall_slot = [] if args.server_stall else None
    if args.fault_recovery:
        report["limits"].update(fault_namespace_fds=1, fault_rules=2)
    if args.server_stall:
        report["limits"].update(pause_pidfds=1, paused_samples=stall_contract.MAX_SAMPLES,
                               application_requests=16, configured_keepalive_interval_secs=1)
    error = None
    try:
        report["binary_sha256"] = {"daemon": digest(args.daemon), "control": digest(args.control)}
        for path, expected in report["source_sha256"].items():
            committed = subprocess.check_output(["git", "-C", str(ROOT), "show", args.head + ":" + path], timeout=20)
            if hashlib.sha256(committed).hexdigest() != expected:
                raise RuntimeError("executed evidence source differs from actual committed checkout")
        plan = resource_plan(lab)
        report["owned_resources"] = plan
        exercise(lab, groups, report, args.output_dir, fault_slot=fault_slot, stall_slot=stall_slot)
        if any(digest(ROOT / path) != expected for path, expected in report["source_sha256"].items()):
            raise RuntimeError("original evidence source changed during execution")
        if {"daemon": digest(args.daemon), "control": digest(args.control)} != report["binary_sha256"]:
            raise RuntimeError("original executable bytes changed during execution")
    except BaseException as caught:
        error = caught
        report["failure_type"] = type(caught).__name__
        report["failure_detail"] = original.redact_text(str(caught))[:300]
    finally:
        # A second cancellation must not interrupt cleanup of original owners.
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        if stall_slot is not None:
            try:
                report["pause_cleanup"] = linux_tun_stall.restore_before_cleanup(stall_slot)
            except BaseException as pause_error:
                report["pause_cleanup"] = {"complete": False, "error": type(pause_error).__name__}
        finalize_observations(report, groups, lambda deadline=None: cleanup_network(plan, deadline=deadline),
                              fault_cleanup=(lambda deadline: fault_slot[0].cleanup(deadline) if fault_slot else
                                             {"complete": True, "admitted": False, "original_namespace_fd_closed": True}) if args.fault_recovery else None,
                              summary=stall_contract.summarize if args.server_stall else fault_contract.summarize if args.fault_recovery else summarize,
                              requested_count=16 if args.server_stall else 32)
        try:
            lab.preserve_logs()
        except Exception as capture_error:
            report["debug_capture_error"] = type(capture_error).__name__
        report["stages"] = lab.evidence["stages"]
        try:
            lab.temp.cleanup()
        except Exception as cleanup_error:
            report["private_temp_cleanup_error"] = type(cleanup_error).__name__
        complete = (all(o["complete"] for o in report["process_cleanup"])
                    and report["network_cleanup"]["complete"] and "private_temp_cleanup_error" not in report)
        if args.fault_recovery:
            complete = complete and report["fault_cleanup"]["complete"]
        if args.server_stall:
            complete = complete and report["pause_cleanup"]["complete"]
        report["cleanup_complete"] = complete
        if args.server_stall:
            application_ok = stall_contract.accepted(report["application"], report.get("server_stall", {}))
        elif args.fault_recovery:
            application_ok = fault_contract.accepted(report["application"], report.get("fault", {}))
        else:
            application_ok = report["application"]["all_responses_observed"]
        report["passed"] = (error is None and complete and "debug_capture_error" not in report
                            and application_ok)
        udp.write_report(args.report, report)
        # Preserve 0600 files while making only this non-secret output readable
        # by the invoking CI runner for upload; private Lab credentials were removed.
        if "SUDO_UID" in os.environ:
            uid, gid = int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"])
            for path in [*args.output_dir.rglob("*"), args.output_dir]:
                os.chown(path, uid, gid)
    print(json.dumps({"scope": report["scope"], "passed": report["passed"], "requests": 16 if args.server_stall else 32,
                      "success_requests": report["application"]["success_requests"], "cleanup_complete": report["cleanup_complete"]}))
    return int(not report["passed"])


if __name__ == "__main__":
    def interrupted(_signal, _frame):
        raise KeyboardInterrupt("original harness interrupted")
    signal.signal(signal.SIGTERM, interrupted)
    raise SystemExit(main())
