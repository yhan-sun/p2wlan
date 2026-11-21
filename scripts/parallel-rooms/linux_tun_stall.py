"""One original OS echo process STOP/CONT owner and bounded UDP-only driver."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import signal
import sys
import time

import linux_tun_stall_contract as contract

PAUSED_SAMPLE_BUDGET_NS = 500_000_000
CONT_RESERVE_NS = 100_000_000


class NativeProcessIO:
    @staticmethod
    def observe(pid: int, namespace: str) -> dict:
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        actual = os.stat(f"/proc/{pid}/ns/net")
        named = os.stat("/var/run/netns/" + namespace)
        if (actual.st_dev, actual.st_ino) != (named.st_dev, named.st_ino):
            raise RuntimeError("stall_original_application_namespace_changed")
        return {"state": fields[0], "parent_pid": int(fields[1]), "group_pid": int(fields[2]),
                "start_ticks": int(fields[19]), "namespace_device": actual.st_dev, "namespace_inode": actual.st_ino}

    open = staticmethod(os.pidfd_open) if hasattr(os, "pidfd_open") else None
    send = staticmethod(signal.pidfd_send_signal) if hasattr(signal, "pidfd_send_signal") else None
    close = staticmethod(os.close)


class PauseOwner:
    def __init__(self, child, registered: dict, namespace: str, *, io=None, now=time.monotonic_ns,
                 sleep=time.sleep, parent_pid=None) -> None:
        self.io, self.now, self.sleep = io or NativeProcessIO(), now, sleep
        self.child, self.namespace, self.fd = child, namespace, None
        self.restore_required = False
        self.evidence = {"original_child_pid": child.pid, "restored": False, "original_pid_confirmed": False}
        anchor = registered.get("anchor")
        if (registered.get("child") is not child or registered.get("socket_tool") is not True
                or anchor is None or anchor.returncode is not None or child.returncode is not None
                or self.io.open is None or self.io.send is None):
            raise ValueError("stall_original_unreaped_application_owner_missing")
        self.pin = self.io.observe(child.pid, namespace)
        if (self.pin["parent_pid"] != (os.getpid() if parent_pid is None else parent_pid)
                or self.pin["group_pid"] != anchor.pid or self.pin["state"] in {"T", "t", "Z", "X"}):
            raise ValueError("stall_original_application_process_not_live")
        try:
            self.fd = self.io.open(child.pid, 0)
            self.observe()
        except BaseException:
            if self.fd is not None:
                self.io.close(self.fd)
            raise
        self.evidence.update(original_pid_confirmed=True, original_identity=self.pin,
                             scope="only_original_echo_child_pidfd_not_daemon_or_group")

    def observe(self) -> dict:
        current = self.io.observe(self.child.pid, self.namespace)
        if (self.child.returncode is not None or any(current[k] != self.pin[k] for k in self.pin if k != "state")):
            raise RuntimeError("stall_original_unreaped_application_identity_changed")
        return current

    def stop(self, end_ns: int) -> None:
        self.observe()
        self.restore_required = True  # Before the syscall: partial STOP still needs CONT.
        self.evidence["stop_requested_monotonic_ns"] = self.now()
        self.io.send(self.fd, signal.SIGSTOP, None, 0)
        while self.now() < end_ns:
            if self.observe()["state"] == "T":
                self.evidence["stopped_monotonic_ns"] = self.now()
                return
            self.sleep(min(.01, max(0, end_ns - self.now()) / 1_000_000_000))
        raise TimeoutError("stall_original_application_stop_not_confirmed")

    def resume(self, end_ns: int) -> None:
        if not self.restore_required:
            return
        # The retained pidfd pins the original process even on an error path.
        # Send CONT before any deadline/observer failure can skip recovery.
        self.evidence["resume_requested_monotonic_ns"] = self.now()
        self.io.send(self.fd, signal.SIGCONT, None, 0)
        while True:
            state = self.observe()["state"]
            if state not in {"T", "t", "Z", "X"}:
                self.evidence.update(restored=True, resumed_monotonic_ns=self.now(),
                                     stopped_lower_bound_ns=self.evidence["resume_requested_monotonic_ns"] -
                                     self.evidence.get("stopped_monotonic_ns", self.evidence["resume_requested_monotonic_ns"]),
                                     stopped_observation_upper_bound_ns=self.now() -
                                     self.evidence.get("stopped_monotonic_ns", self.evidence["resume_requested_monotonic_ns"]))
                self.restore_required = False
                return
            if self.now() >= end_ns:
                break
            self.sleep(min(.01, max(0, end_ns - self.now()) / 1_000_000_000))
        raise TimeoutError("stall_original_application_resume_not_confirmed")

    def close(self) -> None:
        if self.fd is None:
            return
        descriptor = self.fd
        self.fd = None
        self.evidence["original_pidfd_closed"] = False
        self.io.close(descriptor)  # Never retry a numeric fd after an ambiguous close.
        self.evidence["original_pidfd_closed"] = True


def read_object(path: Path, max_bytes=8192) -> dict:
    if path.is_symlink() or path.stat().st_size > max_bytes:
        raise ValueError("stall_private_receipt_invalid")
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError("stall_receipt_not_object")
    return value


def sample(lab, end_ns: int) -> dict:
    result = {}
    for name in ("a1", "b1"):
        deadline = end_ns / 1_000_000_000
        status = lab.status(name, deadline=deadline)
        result[name] = lab._safe_status(name, status, deadline=deadline)
    return result


def observe_probe_terminal(entry: dict, child, *, now=time.monotonic_ns) -> None:
    code = child.poll()
    if code is not None and "probe_terminal_observed_monotonic_ns" not in entry:
        entry.update(probe_terminal_observed_monotonic_ns=now(), observed_probe_exit=code)


def collect_paused_samples(lab, owner, entry, probe, paused_samples: list, hold_end: int,
                           *, now=time.monotonic_ns, sleep=time.sleep) -> None:
    sampling_end = hold_end - CONT_RESERVE_NS
    while len(paused_samples) < contract.MAX_SAMPLES:
        sample_end = now() + PAUSED_SAMPLE_BUDGET_NS
        # One sample includes four sequential diagnostic commands. Admit its
        # entire bounded slot before CONT's reserve, rather than starting a
        # partial two-end capture against the last few milliseconds of STOP.
        if sample_end > sampling_end:
            break
        if owner.observe()["state"] != "T":
            raise RuntimeError("stall_original_application_not_stopped_during_sample")
        observe_probe_terminal(entry, probe, now=now)
        paused_samples.append(sample(lab, sample_end))
        if now() >= sample_end:
            raise TimeoutError("stall_admitted_diagnostics_sample_deadline")
        if owner.observe()["state"] != "T":
            raise RuntimeError("stall_original_application_resumed_during_sample")
        remaining = sampling_end - now()
        if remaining > 0:
            sleep(min(.15, remaining / 1_000_000_000))


def measure(harness, lab, groups, report: dict, out: Path, snapshots: dict, slot: list) -> None:
    entries = report["manifest"]
    contract.validate_manifest(entries)
    details = report.setdefault("server_stall", {"keepalive_interval_secs": 1, "native_ack_wait_ms": 2000,
                                                "default_keepalive_cycle_verified": False,
                                                "paused_sample_budget_ns": PAUSED_SAMPLE_BUDGET_NS,
                                                "cont_reserve_ns": CONT_RESERVE_NS})
    plan = {"entries": entries, "source_ip": snapshots["a1"]["virtual_ip"], "target_ip": snapshots["b1"]["virtual_ip"]}
    server_plan, ready, server_report = out / "echo-manifest.json", out / "echo-ready.json", out / "echo-report.json"
    harness.udp.write_report(server_plan, plan)
    script = Path(__file__).with_name("udp_stall_echo.py")
    clean = {k: v for k, v in os.environ.items() if not k.startswith("P2WLAN_")}
    echo = groups.spawn("udp-two-phase-echo", ["ip", "netns", "exec", lab.ns("b"), sys.executable, "-u", str(script),
                        "--manifest", str(server_plan), "--ready", str(ready), "--output", str(server_report)],
                        out / "echo.log", env=clean, socket_tool=True)
    readiness_end = time.monotonic_ns() + 3_000_000_000
    while not ready.exists():
        if echo.poll() is not None or time.monotonic_ns() >= readiness_end:
            raise RuntimeError("stall_original_echo_readiness_failed")
        time.sleep(.01)
    receipt = read_object(ready)
    expected_plan_sha = hashlib.sha256(json.dumps(plan, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if (receipt.get("process_id") != echo.pid or receipt.get("tool_sha256") != harness.digest(script)
            or receipt.get("manifest_sha256") != expected_plan_sha
            or type(receipt.get("started_monotonic_ns")) is not int
            or receipt.get("end_monotonic_ns") != receipt["started_monotonic_ns"] + 10_000_000_000):
        raise ValueError("stall_original_echo_ready_identity_invalid")
    echo_end = receipt["end_monotonic_ns"]
    details["echo_ready"] = receipt
    details["before"] = sample(lab, echo_end)
    original = next(owner for owner in groups.owners if owner["child"] is echo)
    owner = PauseOwner(echo, original, lab.ns("b"))
    slot.append(owner)  # Externally owned before the first STOP syscall.
    details["pause"] = owner.evidence

    def start_probe(entry):
        bind = (plan["source_ip"], entry["source_port"])
        target = (plan["target_ip"], entry["target_port"])
        path = out / (entry["phase"] + "-probe.json")
        entry["probe_spawn_requested_monotonic_ns"] = time.monotonic_ns()
        child = groups.spawn("udp-" + entry["phase"] + "-probe", ["ip", "netns", "exec", lab.ns("a"),
            *harness.tool_argv(harness.DUAL / "udp_business_probe.py", "probe", bind, target, entry, path)],
            out / (entry["phase"] + "-probe.log"), env=clean, socket_tool=True)
        entry["outcome"] = "started"
        return child, path, bind, target

    def collect_probe(entry, child, path, bind, target):
        code = harness.wait_child(child, echo_end / 1_000_000_000)
        result, _ = harness.udp_summary.read_report(path)
        harness.udp_summary.validate_report(result)
        harness.attach(entry, result, result["requests"], bind, target, harness.digest(harness.DUAL / "udp_business_probe.py"))
        entry.update(probe_exit=code, report_sha256=harness.digest(path))

    paused_samples = details["paused_samples"] = []
    try:
        owner.stop(min(echo_end, time.monotonic_ns() + 500_000_000))
        hold_end = owner.evidence["stopped_monotonic_ns"] + contract.HOLD_NS
        if hold_end + 2_000_000_000 >= echo_end:
            raise TimeoutError("stall_original_echo_budget_cannot_fit_both_phases")
        probe, path, bind, target = start_probe(entries[0])
        # Fixed capacity and bounded complete samples, with the original hold
        # end and CONT reserve. Admitted failures remain in the evidence.
        collect_paused_samples(lab, owner, entries[0], probe, paused_samples, hold_end)
        while time.monotonic_ns() < hold_end:
            time.sleep(min(.01, (hold_end - time.monotonic_ns()) / 1_000_000_000))
        if owner.observe()["state"] != "T":
            raise RuntimeError("stall_original_application_not_stopped_before_resume")
        observe_probe_terminal(entries[0], probe)
    finally:
        owner.resume(echo_end)
    details["paused_request_window"] = contract.paused_request_window(entries[0], owner.evidence)
    collect_probe(entries[0], probe, path, bind, target)
    probe, path, bind, target = start_probe(entries[1])
    collect_probe(entries[1], probe, path, bind, target)
    details["echo_exit"] = harness.wait_child(echo, echo_end / 1_000_000_000)
    details["echo"] = read_object(server_report)
    if (details["echo"].get("process_id") != echo.pid or details["echo"].get("manifest_sha256") != expected_plan_sha
            or details["echo"].get("tool_sha256") != harness.digest(script)
            or details["echo"].get("end_monotonic_ns") != echo_end or details["echo_exit"] != 0):
        raise ValueError("stall_original_same_echo_report_identity_invalid")
    for entry in entries:
        expected = {str(r["sequence"]): r["request_nonce"] for r in entry["records"]}
        if details["echo"].get("accepted_request_nonces", {}).get(entry["phase"]) != expected:
            raise ValueError("stall_original_echo_did_not_receive_all_fixed_requests")
        completed = details["echo"].get("response_completed_monotonic_ns", {}).get(entry["phase"], {})
        if (set(completed) != set(expected) or any(type(value) is not int or not
            owner.evidence["resume_requested_monotonic_ns"] <= value < echo_end for value in completed.values())):
            raise ValueError("stall_echo_response_outside_original_resume_deadline")
    if entries[1]["probe_spawn_requested_monotonic_ns"] < owner.evidence["resumed_monotonic_ns"]:
        raise ValueError("stall_fresh_request_started_before_original_resume")
    details["after"] = sample(lab, echo_end)
    details["health"] = contract.health_evidence(details["before"], paused_samples, details["after"], owner.evidence)
    report["application"] = contract.summarize(entries)
    owner.close()


def restore_before_cleanup(slot: list) -> dict:
    if not slot:
        return {"complete": True, "admitted": False}
    owner = slot[0]
    errors = []
    try:
        if owner.restore_required:
            # CONT is always sent; no new observation grace is introduced.
            owner.resume(owner.now())
    except BaseException as error:
        errors.append(type(error).__name__)
    finally:
        try:
            owner.close()
        except BaseException as error:
            errors.append(type(error).__name__)
    return {"complete": not errors and owner.restore_required is False and owner.evidence.get("original_pidfd_closed") is True,
            "original_pidfd_closed": owner.evidence.get("original_pidfd_closed"), "errors": errors}
