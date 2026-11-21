#!/usr/bin/env python3
"""Bounded POSIX supervisor for an explicitly supplied local adapter argv array.

No adapter, game, shell interpolation, download, network connection or retry is
built in. The supplied program is trusted code, not sandboxed. Windows is not
supported. Cleanup owns only trusted, same-credential processes in the new group;
descendants that leave it or change privilege are outside this contract. Results
cannot authenticate game execution. Python 3.11 or newer is required.

Each round starts the argv once, with a frozen manifest/round JSON envelope on
stdin. Stdout is UTF-8 NDJSON: {"type":"event","event":<contract event>} followed
by exactly one {"type":"finish","elapsed_ns":...,"termination":...,"telemetry":...}.
The child must then exit. Stderr is bounded diagnostic data, never control input.
Only child clock offsets produce RTT or request timeout evidence. Supervisor
deadlines stop execution without manufacturing a child-clock deadline observation.

CLI: --manifest /plan.json --adapter-argv '["/absolute/program","argument"]'
     --timeout-ms 5000 --output /outside-checkout/new-evidence.json
Exit 0 means all round processes and evidence streams completed cleanly, not that
all actions succeeded; 1 means an execution failed/cancelled; 2 is invalid input.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import tempfile
import threading
import time

from minecraft_interaction import (
    CONTRACT, SOURCE_FIELDS, integer, keys, no_duplicate_keys, reduce_round,
    reject_constant, validate_manifest,
)
from minecraft_interaction_summary import summarize
from udp_business_probe import validate_output_path, write_report


MAX_LINE_BYTES = 16 * 1024
MAX_ROUND_BYTES = 4 * 1024 * 1024
MAX_TOTAL_BYTES = 16 * 1024 * 1024
MAX_STDERR_BYTES = 256 * 1024
CLEANUP_GRACE_SECONDS = .05
ANCHOR_READY = b"p2wlan-group-ready\n"
ANCHOR_CODE = (
    "import os, signal\n"
    "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
    f"os.write(1, {ANCHOR_READY!r})\n"
    "while True: signal.pause()\n"
)


def decode(raw: bytes | str) -> dict:
    value = json.loads(raw.decode("utf-8") if isinstance(raw, bytes) else raw,
                       object_pairs_hook=no_duplicate_keys, parse_constant=reject_constant)
    if not isinstance(value, dict):
        raise ValueError("protocol message must be a JSON object")
    return value


def validate_argv(argv: list[str]) -> None:
    if (not isinstance(argv, list) or not 1 <= len(argv) <= 128
            or any(not isinstance(arg, str) or "\0" in arg or len(arg.encode()) > 4096 for arg in argv)
            or sum(len(arg.encode()) for arg in argv) > 32768
            or not Path(argv[0]).is_absolute()):
        raise ValueError("adapter argv must be a bounded explicit array with an absolute executable")


def unknown_telemetry() -> dict:
    return {name: {"value": None, "unit": unit, "reason": "not_collected", "source_sha256": None,
                   "clock_nonce": None, "start_offset_ns": None, "end_offset_ns": None}
            for name, unit in CONTRACT["telemetry_units"].items()}


def make_report(round_: dict, digest: str, termination: str) -> dict:
    return {"schema_version": 1, "manifest_sha256": digest, "round_nonce": round_["round_nonce"],
            "elapsed_ns": 0, "termination": termination, "events": [], "telemetry": unknown_telemetry()}


class Stream:
    """Bound every byte before parsing or buffering it; never read by unbounded readline."""

    def __init__(self, byte_budget: int):
        self.byte_budget = byte_budget
        self.bytes_read = 0
        self.pending = bytearray()
        self.stderr = bytearray()
        self.digests = {kind: hashlib.sha256() for kind in ("stdout", "stderr")}
        self.events = []
        self.finish = None

    def feed(self, kind: str, data: bytes) -> None:
        self.bytes_read += len(data)
        self.digests[kind].update(data)
        if self.bytes_read > self.byte_budget:
            raise ValueError("output_byte_limit")
        if kind == "stderr":
            if len(self.stderr) + len(data) > MAX_STDERR_BYTES:
                raise ValueError("stderr_byte_limit")
            self.stderr.extend(data)
            return
        self.pending.extend(data)
        while b"\n" in self.pending:
            line, _, rest = self.pending.partition(b"\n")
            if len(line) > MAX_LINE_BYTES:
                raise ValueError("line_byte_limit")
            self.pending = bytearray(rest)
            self.message(decode(line))
        if len(self.pending) > MAX_LINE_BYTES:
            raise ValueError("line_byte_limit")

    def message(self, value: dict) -> None:
        if self.finish is not None:
            raise ValueError("message_after_finish")
        if value.get("type") == "event":
            keys(value, {"type", "event"}, "event message")
            if len(self.events) >= CONTRACT["max_events_per_round"]:
                raise ValueError("event_count_limit")
            self.events.append(value["event"])
        elif value.get("type") == "finish":
            keys(value, {"type", "elapsed_ns", "termination", "telemetry"}, "finish message")
            self.finish = {name: value[name] for name in ("elapsed_ns", "termination", "telemetry")}
        else:
            raise ValueError("unsupported_message")


def await_anchor_ready(anchor: subprocess.Popen, deadline: float, cancel: threading.Event) -> str:
    """Keep the PGID owner alive, strong-referenced and unreaped, including on EOF."""
    pending = bytearray()
    os.set_blocking(anchor.stdout.fileno(), False)
    with selectors.DefaultSelector() as selector:
        selector.register(anchor.stdout, selectors.EVENT_READ)
        while True:
            if cancel.is_set():
                return "cancelled"
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return "anchor_ready_timeout"
            if selector.select(min(.02, remaining)):
                data = os.read(anchor.stdout.fileno(), len(ANCHOR_READY) + 1)
                if not data:
                    return "anchor_early_exit"
                pending.extend(data)
                if not ANCHOR_READY.startswith(pending):
                    return "anchor_bad_handshake"
                if pending == ANCHOR_READY:
                    return "ready"


def cleanup(anchor: subprocess.Popen, child: subprocess.Popen | None) -> dict:
    # The anchor is never polled/reaped before the final group signal. Its PID
    # therefore cannot be reused as an unrelated PGID. The adapter is a separate
    # direct child and may already have been reaped without changing group owner.
    outcomes = []
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(anchor.pid, sig)
            outcomes.append("sent")
        except ProcessLookupError:
            outcomes.append("absent")
        except PermissionError:
            outcomes.append("permission_denied")
        except OSError:
            outcomes.append("signal_error")
        if sig == signal.SIGTERM:
            time.sleep(CLEANUP_GRACE_SECONDS)
    # On ambiguous group failure, direct PID cleanup is still possible for our
    # unreaped children. It does not establish that same-group descendants died.
    if any(value != "sent" for value in outcomes):
        for process in (child, anchor):
            if process is not None and process.returncode is None:
                try:
                    os.kill(process.pid, signal.SIGKILL)
                except OSError:
                    pass
    joined = []
    for process in (child, anchor):
        if process is None:
            joined.append(None)
            continue
        try:
            process.wait(timeout=1)
            joined.append(True)
        except subprocess.TimeoutExpired:
            joined.append(False)
    return {"direct_child_reaped": joined[0], "anchor_reaped": joined[1],
            "anchor_returncode": anchor.returncode, "owned_group_signal_attempts": outcomes,
            "ownership_failed": (any(value != "sent" for value in outcomes)
                                 or False in joined or anchor.returncode != -signal.SIGKILL)}


def collect(anchor: subprocess.Popen, child: subprocess.Popen, stream: Stream,
            deadline: float, cancel: threading.Event) -> str:
    with selectors.DefaultSelector() as selector:
        for pipe, kind in ((child.stdout, "stdout"), (child.stderr, "stderr"), (anchor.stdout, "anchor")):
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, selectors.EVENT_READ, kind)
        while True:
            if cancel.is_set():
                return "cancelled"
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return "supervisor_timeout"
            anchor_failure = None
            for key, _ in selector.select(min(.02, remaining)):
                data = os.read(key.fd, 4096)
                if key.data == "anchor":
                    anchor_failure = "anchor_early_exit" if not data else "anchor_unexpected_output"
                    continue
                if not data:
                    selector.unregister(key.fileobj)
                else:
                    stream.feed(key.data, data)
            if anchor_failure is not None:
                return anchor_failure
            if len(selector.get_map()) == 1 and child.poll() is not None:
                return "truncated_line" if stream.pending else "eof"


def observed_report(plan: dict, round_: dict, digest: str, stream: Stream, reason: str) -> dict:
    report = make_report(round_, digest, "interrupted" if reason == "cancelled" else "adapter_error")
    report["events"] = stream.events
    if stream.finish is not None:
        report.update(stream.finish)
        if reason != "completed":
            report["termination"] = "interrupted" if reason == "cancelled" else "adapter_error"
    else:
        source = {name: plan[name] if name == "run_nonce" else round_[name] for name in SOURCE_FIELDS}
        offsets = [item.get("offset_ns") for item in stream.events if isinstance(item, dict)
                   and all(item.get(name) == value for name, value in source.items())]
        # A supervisor timestamp is never substituted for missing adapter time.
        report["elapsed_ns"] = max([0, *[value for value in offsets if type(value) is int]])
    reduce_round(plan, round_, report, digest)
    return report


def run_round(plan: dict, round_: dict, digest: str, argv: list[str], timeout_ms: int,
              byte_budget: int, cancel: threading.Event) -> tuple[dict, dict]:
    stream = Stream(byte_budget)
    started = time.monotonic_ns()
    child, anchor = None, None
    deadline = started / 1e9 + timeout_ms / 1000
    reason, error = "anchor_spawn_error", None
    cleaned = {"direct_child_reaped": None, "anchor_reaped": None,
               "owned_group_signal_attempts": [], "ownership_failed": True}
    try:
        anchor = subprocess.Popen([sys.executable, "-u", "-c", ANCHOR_CODE], stdin=subprocess.DEVNULL,
                                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, process_group=0)
        reason = await_anchor_ready(anchor, deadline, cancel)
        # A regular temporary file avoids deadlock if a child never reads stdin.
        if reason == "ready":
            reason = "spawn_error"
            with tempfile.TemporaryFile() as input_file:
                input_file.write(json.dumps({"schema_version": 1, "manifest_sha256": digest,
                                             "manifest": plan, "round_nonce": round_["round_nonce"]}).encode())
                input_file.seek(0)
                child = subprocess.Popen(argv, stdin=input_file, stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE, shell=False, process_group=anchor.pid)
                reason = collect(anchor, child, stream, deadline, cancel)
    except KeyboardInterrupt:
        cancel.set()
        reason = "cancelled"
    except (ValueError, UnicodeError, RecursionError) as exc:
        reason, error = "protocol_error", str(exc)[:256]
    except OSError as exc:
        reason = "anchor_spawn_error" if anchor is None else "spawn_error" if child is None else "io_error"
        error = type(exc).__name__
    finally:
        if anchor is not None:
            cleaned = cleanup(anchor, child)
            anchor.stdout.close()
        if child is not None:
            child.stdout.close()
            child.stderr.close()
    cleaned["ownership_failed"] = cleaned["ownership_failed"] or reason.startswith("anchor_")
    if reason == "eof":
        reason = ("nonzero_exit" if child.returncode != 0 else
                  "missing_finish" if stream.finish is None else "completed")
    observed_reason = reason
    if cleaned["ownership_failed"]:
        reason = "cleanup_incomplete"
    stream_reason = reason
    try:
        report = observed_report(plan, round_, digest, stream, reason)
    except (ValueError, TypeError, KeyError, RecursionError) as exc:
        # An invalid stream cannot partially certify success. Keep its digest and
        # explicit failure, while preserving every original request as unstarted.
        reason, error = "invalid_evidence", str(exc)[:256]
        report = make_report(round_, digest, "adapter_error")
    receipt = {"round_nonce": round_["round_nonce"], "reason": reason, "error": error,
               "stream_reason": stream_reason,
               "observation_reason": observed_reason, "anchor_pid": anchor.pid if anchor else None,
               "child_pid": child.pid if child else None, "returncode": child.returncode if child else None,
               "supervisor_elapsed_ns": time.monotonic_ns() - started,
               "supervisor_clock_is_not_adapter_clock": True, "output_bytes_read": stream.bytes_read,
               "observed_stream_sha256": {kind: digest.hexdigest() for kind, digest in stream.digests.items()},
               "stderr": stream.stderr.decode("utf-8", errors="replace"), "cleanup": cleaned}
    return report, receipt


def run_campaign(raw_manifest: bytes, argv: list[str], timeout_ms: int,
                 cancel: threading.Event | None = None) -> dict:
    if os.name != "posix" or sys.version_info < (3, 11):
        raise ValueError("this runner requires POSIX process groups and Python 3.11 or newer")
    if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
        raise ValueError("runner must exclusively own child reaping; SIGCHLD must be default")
    validate_argv(argv)
    integer(timeout_ms, 1, 125000, "timeout_ms")
    if len(raw_manifest) > CONTRACT["max_input_bytes"]:
        raise ValueError("manifest byte limit exceeded")
    plan = decode(raw_manifest)
    validate_manifest(plan)
    digest = hashlib.sha256(raw_manifest).hexdigest()
    cancel = cancel if cancel is not None else threading.Event()
    reports, receipts, used, cleanup_failed = [], [], 0, False
    for round_ in plan["rounds"]:
        if cancel.is_set() or used >= MAX_TOTAL_BYTES or cleanup_failed:
            report = make_report(round_, digest, "adapter_unavailable")
            receipt = {"round_nonce": round_["round_nonce"],
                       "reason": "not_launched_cancelled" if cancel.is_set() else
                                 "not_launched_cleanup_incomplete" if cleanup_failed else "not_launched_output_budget",
                       "child_pid": None, "output_bytes_read": 0}
        else:
            report, receipt = run_round(plan, round_, digest, argv, timeout_ms,
                                        min(MAX_ROUND_BYTES, MAX_TOTAL_BYTES - used), cancel)
        used += receipt["output_bytes_read"]
        cleaned = receipt.get("cleanup", {})
        cleanup_failed = cleanup_failed or cleaned.get("ownership_failed", False)
        reports.append(report)
        receipts.append(receipt)
    return {"schema_version": 1, "scope": "minecraft_adapter_supervision",
            "frozen_manifest_json": raw_manifest.decode("utf-8"), "manifest_sha256": digest,
            "adapter_argv": list(argv), "per_round_supervisor_timeout_ms": timeout_ms,
            "execution_completed_cleanly": all(row["reason"] == "completed" for row in receipts),
            "cleanup_scope": "owned_same_credential_posix_group_only_no_escape_or_windows_guarantee",
            "reports": reports, "receipts": receipts, "summary": summarize(plan, reports, digest)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--adapter-argv", required=True, help="explicit JSON argv array; no shell parsing")
    parser.add_argument("--timeout-ms", required=True, type=int)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    cancel = threading.Event()
    previous = {}
    try:
        validate_output_path(args.output)
        with args.manifest.open("rb") as source:
            raw = source.read(CONTRACT["max_input_bytes"] + 1)
        adapter = json.loads(args.adapter_argv)
        for sig in (signal.SIGINT, signal.SIGTERM):
            previous[sig] = signal.signal(sig, lambda _sig, _frame: cancel.set())
        result = run_campaign(raw, adapter, args.timeout_ms, cancel)
        write_report(args.output, result)
    except (OSError, ValueError, TypeError, RecursionError) as exc:
        print(f"minecraft-interaction-runner: {exc}", file=sys.stderr)
        return 2
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    print("adapter supervision recorded; genuine game execution remains unverified")
    return 0 if result["execution_completed_cleanly"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
