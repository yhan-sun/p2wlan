#!/usr/bin/env python3
"""Private bounded inputs and receipts for the shell's round-owned finalizer.

The shell owns live children and actual wait results. This module supervises
short-lived capture/collector workers and never infers a NAT/path terminal.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import resource
import select
import signal
import stat
import subprocess
import sys
import time


MAX_RECEIPT_BYTES = 128 * 1024
MAX_RECORDS = 128
MAX_STATUS_BYTES = 1024 * 1024
MAX_SCAN_BYTES = 16 * 1024 * 1024
MAX_LINE_BYTES = 64 * 1024
SAFE_REASON = re.compile(r"[a-zA-Z0-9_.:-]{1,128}\Z")
ENV_KEYS = {
    "PATH", "LANG", "LC_ALL", "PYTHONDONTWRITEBYTECODE", "ROOT_DIR", "BASE_DIR",
    "ROUND_DIR", "NODE_A_RUNTIME", "NODE_B_RUNTIME", "STATUS_FAILURE_INJECTION",
    "METRICS_FAILURE_INJECTION", "STATUS_SCHEMA_INJECTION", "STRICT_FILTERING_A",
    "STRICT_FILTERING_B", "CONSUME_A", "CONSUME_B", "SWEEP_NOISE_EVERY",
    "SWEEP_NOISE_COUNT", "SWEEP_NOISE_LIMIT", "BACKGROUND_DEVICES",
    "BACKGROUND_FLOWS", "BACKGROUND_INTERVAL_MS", "BACKGROUND_DURATION_MS",
    "NETWORK_PROFILE",
}


def now_ms():
    return time.monotonic_ns() // 1_000_000


class _FixedDeadlineExpired(ValueError):
    pass


def _before_deadline(deadline_ms):
    if deadline_ms is not None and now_ms() >= deadline_ms:
        raise _FixedDeadlineExpired()


def bounded_bytes(path, cap):
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > cap:
            raise ValueError("input_not_regular_or_size_exceeded")
        # Logs may append. This hash identifies exactly the captured prefix,
        # never the complete file at launch or any earlier point in time.
        value = stream.read(before.st_size)
        after = os.fstat(stream.fileno())
        if len(value) != before.st_size or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise ValueError("input_changed_during_capture")
    return value


def object_file(path, cap=MAX_RECEIPT_BYTES):
    value = json.loads(bounded_bytes(path, cap))
    if not isinstance(value, dict):
        raise ValueError("input_not_object")
    return value


def atomic_json(path, value, *, deadline_ms=None):
    _before_deadline(deadline_ms)
    path = Path(path)
    data = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(data) > MAX_RECEIPT_BYTES:
        raise ValueError("receipt_size_exceeded")
    _before_deadline(deadline_ms)
    temporary = path.with_name(path.name + ".writing")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        _before_deadline(deadline_ms)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
    return hashlib.sha256(data).hexdigest()


def reason(value, fallback="unknown"):
    return value if isinstance(value, str) and SAFE_REASON.fullmatch(value) else fallback


def supervise(command, deadline_ms, grace_end_ms, *, environment=None, pass_fds=(), file_cap=MAX_SCAN_BYTES):
    if now_ms() >= deadline_ms:
        return {"result": "unknown", "reason_code": "deadline_exhausted", "started": False}
    if now_ms() >= grace_end_ms:
        return {"result": "unknown", "reason_code": "resource_grace_exhausted", "started": False}
    worker_end_ms = min(deadline_ms, grace_end_ms)

    def limits():
        resource.setrlimit(resource.RLIMIT_FSIZE, (file_cap, file_cap))

    reader, writer = os.pipe()
    # The session leader stays owned and unreaped after reporting the command
    # result. Killing this still-owned group closes ordinary callback/collector
    # descendants before the actual leader wait; a completed parent alone is
    # not a receipt that its process group ended. Commands are fixed local
    # synchronous entry points, not a general detached-process plugin API.
    driver = ('import os,signal,subprocess,sys; signal.signal(signal.SIGTERM,lambda *_:None); '
              'p=subprocess.Popen(sys.argv[3:],pass_fds=tuple(map(int,sys.argv[2].split(","))) if sys.argv[2] else ()); '
              'rc=p.wait(); os.write(int(sys.argv[1]),str(rc).encode()+b"\\n"); '
              'os.kill(os.getpid(),signal.SIGSTOP)')
    process = subprocess.Popen([sys.executable, "-S", "-c", driver, str(writer),
                                ",".join(map(str, pass_fds)), *command],
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, env=environment, pass_fds=(*pass_fds, writer),
                               start_new_session=True, preexec_fn=limits)
    os.close(writer)
    command_status = None
    reaped = False
    group_closed = False
    try:
        try:
            if select.select([reader], [], [], max(0, (worker_end_ms - now_ms()) / 1000))[0]:
                message = os.read(reader, 32)
                if re.fullmatch(rb"-?[0-9]{1,3}\n", message):
                    command_status = int(message)
        except OSError:
            pass
        if command_status is None:
            # On input cutoff, allow the synchronous command's owning driver
            # to wait its TERM outcome. This uses the same absolute resource
            # end; it is not a fresh rescue interval for each worker.
            try:
                os.killpg(process.pid, signal.SIGTERM)
                if select.select([reader], [], [], max(0, (grace_end_ms - now_ms() - 100) / 1000))[0]:
                    message = os.read(reader, 32)
                    if re.fullmatch(rb"-?[0-9]{1,3}\n", message):
                        command_status = int(message)
            except OSError:
                pass
        # A single shared resource end comes from the shell. No worker creates
        # a new rescue timer. The leader has not been waited/polled yet, so its
        # PID/PGID cannot have been recycled when the owned group is signalled.
        try:
            os.killpg(process.pid, signal.SIGKILL)
            group_closed = True
        except ProcessLookupError:
            group_closed = True
        except OSError:
            pass
        try:
            process.wait(timeout=max(0, (grace_end_ms - now_ms()) / 1000))
            reaped = True
        except subprocess.TimeoutExpired:
            pass
    finally:
        os.close(reader)
    input_expired = now_ms() >= worker_end_ms
    return {"result": "completed" if command_status is not None and reaped and group_closed and not input_expired else "unknown",
            "reason_code": (("deadline_exhausted" if deadline_ms <= grace_end_ms else "resource_grace_exhausted")
                            if input_expired or command_status is None else "worker_unreaped" if not reaped
                            else "worker_group_closure_unknown" if not group_closed else None),
            "started": True, "pid": process.pid, "wait_completed": reaped,
            "wait_status": process.returncode if reaped else None,
            "command_wait_status": command_status, "command_wait_completed": command_status is not None,
            "owned_group_shutdown_requested_before_wait": group_closed,
            "forced_termination": command_status is None,
            "resource_grace_deadline_monotonic_ms": grace_end_ms}



def _http_object_file(path):
    # HTTP polling/publishing must reject a FIFO/device before any potentially blocking read.
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb", buffering=0) as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or not 0 <= before.st_size <= MAX_RECEIPT_BYTES:
            raise ValueError("http_receipt_not_regular_or_size_exceeded")
        # One bounded read plus a sentinel detects growth; no unbounded stream.read().
        data = stream.read(before.st_size + 1)
        after = os.fstat(stream.fileno())
        if (len(data) != before.st_size or before.st_size != after.st_size
                or (before.st_dev, before.st_ino, before.st_mtime_ns, before.st_ctime_ns)
                != (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns)):
            raise ValueError("http_receipt_changed_during_capture")
    value = json.loads(data.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("http_receipt_not_object")
    return value


HTTP_ROLE = re.compile(r"http-barrier-([1-9][0-9]{0,18})-([ab])\Z")
HTTP_DECLARATIONS = {"fetch_required_json", "deadline_remaining_s",
                     "p2wlan_diagnostics_curl", "p2wlan_read_diagnostics_token"}
HTTP_DRIVER = r"""
import os, signal, subprocess, sys
signal.signal(signal.SIGTERM, lambda *_: None)
writer = int(sys.argv[1])
os.set_inheritable(writer, False)
p = subprocess.Popen(sys.argv[2:], close_fds=False)
os.write(writer, ("B %d\n" % p.pid).encode())
rc = p.wait()
os.write(writer, ("C %d\n" % rc).encode())
os.kill(os.getpid(), signal.SIGSTOP)
"""


def _http_integer(value, minimum=0, maximum=(1 << 63) - 1):
    return isinstance(value, int) and not isinstance(value, bool) and minimum <= value <= maximum


def _http_role(role):
    match = HTTP_ROLE.fullmatch(role) if isinstance(role, str) else None
    if match is None or not _http_integer(int(match[1]), 1):
        raise ValueError("http_owner_role_invalid")
    return int(match[1]), match[2]


def _http_directory(value):
    directory = Path(value)
    if not directory.is_absolute() or not directory.is_dir():
        raise ValueError("http_round_directory_invalid")
    # Canonical round identity is shared by launch, cancellation and trusted publisher args.
    if len(str(directory).encode()) > 4096:
        raise ValueError("http_round_directory_invalid")
    return directory.resolve()


def _http_context(value, directory, run_id, context_pid):
    if (not _http_integer(value.get("schema_version"), 1, 1) or value.get("round_dir") != str(directory)
            or value.get("round_run_id") != run_id
            or not _http_integer(value.get("context_pid"), 1)
            or value.get("context_pid") != context_pid):
        raise ValueError("http_cancel_context_mismatch")
    published = value.get("published_monotonic_ms")
    endpoint = value.get("resource_end_ms")
    if (not _http_integer(published, 1) or not _http_integer(endpoint, 1)
            or not published < endpoint <= published + 15000):
        raise ValueError("http_cancel_endpoint_invalid")
    owners = value.get("owners")
    if not isinstance(owners, list) or not 1 <= len(owners) <= MAX_RECORDS:
        raise ValueError("http_cancel_owner_capacity_invalid")
    roles, pids = set(), set()
    for owner in owners:
        if not isinstance(owner, dict):
            raise ValueError("http_cancel_owner_invalid")
        sequence, side = _http_role(owner.get("owner_role"))
        pid = owner.get("owner_pid")
        if (not _http_integer(owner.get("pair_sequence"), 1)
                or owner.get("pair_sequence") != sequence or owner.get("side") != side
                or not _http_integer(pid, 1) or owner["owner_role"] in roles or pid in pids):
            raise ValueError("http_cancel_owner_invalid")
        roles.add(owner["owner_role"])
        pids.add(pid)
    return endpoint, owners


def http_cancel(args):
    try:
        directory = _http_directory(args.round_dir)
        if not _http_integer(args.context_pid, 1) or not SAFE_REASON.fullmatch(args.run_id):
            raise ValueError("http_cancel_context_invalid")
        data = sys.stdin.buffer.read(MAX_LINE_BYTES + 1)
        if len(data) > MAX_LINE_BYTES:
            raise ValueError("http_cancel_owner_capacity_invalid")
        owners = []
        for line in data.decode().splitlines():
            parts = line.split("\t")
            if len(parts) != 2 or len(owners) >= MAX_RECORDS or not parts[1].isdigit():
                raise ValueError("http_cancel_owner_invalid")
            sequence, side = _http_role(parts[0])
            owners.append({"owner_role": parts[0], "owner_pid": int(parts[1]),
                           "pair_sequence": sequence, "side": side})
        path = directory / ".http-barrier-cancel.json"
        if path.exists():
            existing = _http_object_file(path)
            endpoint, previous = _http_context(existing, directory, args.run_id, args.context_pid)
            if endpoint != args.grace_end_ms or previous != owners:
                raise ValueError("http_cancel_fence_renewal_rejected")
            return 0
        value = {"schema_version": 1, "round_dir": str(directory), "round_run_id": args.run_id,
                 "context_pid": args.context_pid, "resource_end_ms": args.grace_end_ms,
                 "published_monotonic_ms": now_ms(), "owners": owners}
        _http_context(value, directory, args.run_id, args.context_pid)
        atomic_json(path, value, deadline_ms=args.grace_end_ms)
        if now_ms() >= args.grace_end_ms:
            raise _FixedDeadlineExpired()
        return 0
    except (OSError, ValueError, UnicodeError, json.JSONDecodeError):
        print("[nat-sim] FAIL reason_code=http_cancel_fence_failed", file=sys.stderr)
        return 1


def _http_matching_fence(args, owner_pid):
    directory = _http_directory(args.round_dir)
    path = directory / ".http-barrier-cancel.json"
    try:
        value = _http_object_file(path)
    except FileNotFoundError:
        return None
    endpoint, owners = _http_context(value, directory, args.run_id, args.context_pid)
    for owner in owners:
        if owner["owner_role"] == args.owner_role:
            if (owner["owner_pid"] != owner_pid or owner["pair_sequence"] != args.pair_sequence
                    or owner["side"] != args.side):
                raise ValueError("http_cancel_owner_mismatch")
            return endpoint
    # A fixed valid fence for other owners does not authorize this leader.
    return None


def _http_shell_status(value):
    if not _http_integer(value, -127, 255):
        raise ValueError("http_command_wait_status_invalid")
    return value if value >= 0 else 128 - value


def _http_supervise(command, args, input_end_ms, environment):
    result = {"result": "unknown", "reason_code": "http_worker_not_started", "started": False,
              "pid": None, "command_pid": None, "wait_completed": False, "wait_status": None,
              "command_wait_completed": False, "command_wait_status": None,
              "owned_group_shutdown_requested_before_wait": False, "forced_termination": False,
              "cancel_fence_matched": False, "cancellation_resource_end_ms": None,
              "command_wait_observed_monotonic_ms": None,
              "group_shutdown_requested_monotonic_ms": None,
              "driver_wait_returned_monotonic_ms": None}
    cancel_signal = None

    def on_term(signum, _frame):
        nonlocal cancel_signal
        if cancel_signal is None:
            cancel_signal = signum

    # Dedicated HTTP exec leader: retain handler through atomic receipt publication and exit.
    signal.signal(signal.SIGTERM, on_term)
    reader = writer = None
    process = None
    buffer = b""
    close_end_ms = input_end_ms
    term_requested = False
    failure = None

    def limits():
        resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_SCAN_BYTES, MAX_SCAN_BYTES))

    try:
        _before_deadline(input_end_ms)
        reader, writer = os.pipe()
        os.set_inheritable(writer, True)
        # HTTP-only inheritance. No nonempty pass_fds, which would force close_fds=True.
        process = subprocess.Popen([sys.executable, "-S", "-c", HTTP_DRIVER, str(writer), *command],
                                   env=environment, close_fds=False, start_new_session=True,
                                   stdout=subprocess.DEVNULL, preexec_fn=limits)
        os.close(writer)
        writer = None
        result.update(started=True, pid=process.pid)
        while result["command_wait_status"] is None:
            fence_end = _http_matching_fence(args, os.getpid())
            if fence_end is not None:
                if (result["cancel_fence_matched"] is True
                        and fence_end != result["cancellation_resource_end_ms"]):
                    raise ValueError("http_cancel_fence_renewal_rejected")
                result.update(cancel_fence_matched=True, cancellation_resource_end_ms=fence_end)
                close_end_ms = fence_end
            if cancel_signal is not None and not result["cancel_fence_matched"]:
                failure = "http_cancel_fence_unavailable"
                break
            # Wait for driver's Popen identity before TERM; no command can spawn after its B frame.
            if result["cancel_fence_matched"] and result["command_pid"] is not None and not term_requested:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                term_requested = True
            cutoff = close_end_ms - 250 if result["cancel_fence_matched"] else input_end_ms
            remaining = cutoff - now_ms()
            if remaining <= 0:
                failure = ("http_command_cancel_deadline_exhausted" if result["cancel_fence_matched"]
                           else "http_input_deadline_exhausted")
                break
            if not select.select([reader], [], [], min(10, remaining) / 1000)[0]:
                continue
            chunk = os.read(reader, 128)
            if not chunk:
                failure = "http_driver_protocol_eof"
                break
            buffer += chunk
            if len(buffer) > 256:
                raise ValueError("http_driver_protocol_invalid")
            while b"\n" in buffer:
                frame, buffer = buffer.split(b"\n", 1)
                if re.fullmatch(rb"B [1-9][0-9]{0,18}", frame) and result["command_pid"] is None:
                    result["command_pid"] = int(frame[2:])
                elif (re.fullmatch(rb"C -?[0-9]{1,3}", frame) and result["command_pid"] is not None
                      and result["command_wait_status"] is None):
                    status_code = int(frame[2:])
                    _http_shell_status(status_code)
                    result.update(command_wait_completed=True, command_wait_status=status_code,
                                  command_wait_observed_monotonic_ms=now_ms())
                else:
                    raise ValueError("http_driver_protocol_invalid")
    except (OSError, ValueError, subprocess.SubprocessError):
        failure = "http_supervision_failed"
    finally:
        if writer is not None:
            os.close(writer)
        if process is not None:
            # Never poll/reap before this signalling: the held unreaped PID pins PGID identity.
            try:
                os.killpg(process.pid, signal.SIGKILL)
                result["owned_group_shutdown_requested_before_wait"] = True
            except ProcessLookupError:
                result["owned_group_shutdown_requested_before_wait"] = True
            except OSError:
                failure = "http_group_shutdown_request_failed"
            if result["owned_group_shutdown_requested_before_wait"]:
                result["group_shutdown_requested_monotonic_ms"] = now_ms()
            try:
                process.wait(timeout=max(0, (close_end_ms - now_ms()) / 1000))
                result.update(wait_completed=True, wait_status=process.returncode,
                              driver_wait_returned_monotonic_ms=now_ms())
            except (OSError, subprocess.TimeoutExpired):
                failure = "http_driver_unreaped"
            result["forced_termination"] = result["command_wait_completed"] is not True
        if reader is not None:
            os.close(reader)
    command_status = result["command_wait_status"]
    allowed_status = {0, 143} if result["cancel_fence_matched"] else {0}
    if (failure is None and result["started"] is True and command_status in allowed_status
            and result["wait_completed"] is True and result["command_wait_completed"] is True
            and result["owned_group_shutdown_requested_before_wait"] is True
            and result["forced_termination"] is False and now_ms() < close_end_ms):
        result.update(result="completed", reason_code=None)
    else:
        result["reason_code"] = failure or "http_worker_completion_invalid"
    return result, close_end_ms


def http_request(args):
    directory = None
    receipt_path = None
    owner_pid = os.getpid()
    receipt = {"schema_version": 1, "owner_role": args.owner_role, "owner_pid": owner_pid,
               "pair_sequence": args.pair_sequence, "side": args.side,
               "round_dir": args.round_dir, "round_run_id": args.run_id,
               "context_pid": args.context_pid, "input_deadline_monotonic_ms": args.deadline_ms,
               "round_deadline_monotonic_ms": args.round_end_ms,
               "work_deadline_monotonic_ms": args.work_end_ms,
               "receipt_prepublication_monotonic_ms": None,
               "result": "unknown", "reason_code": "http_request_invalid", "started": False}
    close_end_ms = 0
    try:
        directory = _http_directory(args.round_dir)
        args.round_dir = str(directory)
        receipt["round_dir"] = str(directory)
        sequence, side = _http_role(args.owner_role)
        receipt_path = directory / ("." + args.owner_role + "-result.json")
        if (sequence != args.pair_sequence or side != args.side
                or not _http_integer(args.context_pid, 1) or os.getppid() != args.context_pid
                or not SAFE_REASON.fullmatch(args.run_id)
                or not _http_integer(args.max_time, 1, 5)
                or not _http_integer(args.parent_round_remaining, 1)
                or not all(_http_integer(value, 1) for value in
                           (args.deadline_ms, args.round_end_ms, args.work_end_ms))
                or args.deadline_ms > min(args.round_end_ms, args.work_end_ms)):
            raise ValueError("http_request_identity_or_deadline_invalid")
        declarations = args.definitions.encode()
        names = re.findall(r"(?m)^([A-Za-z_][A-Za-z0-9_]*)\s*\(\)\s*\n\{", args.definitions)
        if (len(declarations) > MAX_LINE_BYTES or b"\x00" in declarations
                or len(names) != 4 or set(names) != HTTP_DECLARATIONS):
            raise ValueError("http_declarations_invalid")
        expected_output = directory / ("node-" + side + ".barrier.status.json")
        expected_meta = directory / (".barrier-" + side + "-fetch")
        if (Path(args.output).resolve() != expected_output or Path(args.metadata).resolve() != expected_meta
                or not Path(args.token_file).is_absolute()
                or not re.fullmatch(r"http://127\.0\.0\.1:[1-9][0-9]{0,4}/status", args.url)
                or not 1 <= int(args.url.split(":")[2].split("/")[0]) <= 65535):
            raise ValueError("http_request_paths_or_url_invalid")
        input_end_ms = min(args.deadline_ms, args.round_end_ms, args.work_end_ms)
        close_end_ms = input_end_ms
        receipt["input_deadline_monotonic_ms"] = input_end_ms
        _before_deadline(input_end_ms)
        environment = os.environ.copy()
        environment.update(ROUND_DEADLINE=str(args.parent_round_remaining),
                           STATUS_FAILURE_INJECTION=args.status_failure_injection,
                           METRICS_FAILURE_INJECTION=args.metrics_failure_injection,
                           STATUS_SCHEMA_INJECTION=args.status_schema_injection)
        # Functions stay original; fresh Bash SECONDS calibrates from parent launch integer.
        body = ("trap 'exit 143' TERM\n" + args.definitions + "\n"
                "http_fetch_body() {\n"
                "  local ok=0\n"
                "  if fetch_required_json \"$1\" \"$2\" status \"$3\" \"$4\"; then ok=1; fi\n"
                "  printf '%s\\n%s\\n%s\\n' \"$ok\" \"${FETCH_HTTP_STATUS:-000}\" "
                "\"${FETCH_REASON_CODE:-}\" >\"$5\"\n"
                "}\nhttp_fetch_body \"$@\"\n")
        command = ["bash", "-c", body, "http-fetch-body", args.url, args.output,
                   args.token_file, str(args.max_time), args.metadata]
        worker, close_end_ms = _http_supervise(command, args, input_end_ms, environment)
        receipt.update(worker)
        receipt["receipt_prepublication_monotonic_ms"] = now_ms()
        atomic_json(receipt_path, receipt, deadline_ms=close_end_ms)
        # Even a committed completed JSON is unusable if this leader's final native status disagrees.
        if now_ms() >= close_end_ms:
            print("[nat-sim] FAIL reason_code=http_receipt_deadline_exhausted", file=sys.stderr)
            command_status = receipt.get("command_wait_status")
            return 2 if command_status is not None and _http_shell_status(command_status) == 1 else 1
        if receipt["result"] == "completed":
            return _http_shell_status(receipt["command_wait_status"])
        return 1
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError, json.JSONDecodeError):
        print("[nat-sim] FAIL reason_code=http_request_or_receipt_failed", file=sys.stderr)
        # The registered original child still returns nonzero; missing receipt is unknown at publish.
        return 1


def _http_worker_valid(worker, row, args):
    try:
        sequence, side = _http_role(row["role"])
        trusted_context = getattr(args, "context_pid", 0)
        if (not _http_integer(worker.get("schema_version"), 1, 1)
                or worker.get("owner_role") != row["role"]
                or not _http_integer(worker.get("owner_pid"), 1)
                or worker.get("owner_pid") != row["pid"]
                or not _http_integer(worker.get("pair_sequence"), 1)
                or worker.get("pair_sequence") != sequence
                or worker.get("side") != side
                or worker.get("round_dir") != str(Path(args.round_dir).resolve())
                or worker.get("round_run_id") != args.run_id
                or not _http_integer(trusted_context, 1)
                or not _http_integer(worker.get("context_pid"), 1)
                or worker.get("context_pid") != trusted_context
                or worker.get("result") != "completed" or worker.get("reason_code") is not None
                or worker.get("started") is not True or not _http_integer(worker.get("pid"), 1)
                or not _http_integer(worker.get("command_pid"), 1)
                or worker.get("wait_completed") is not True
                or not _http_integer(worker.get("wait_status"), -127, 255)
                or worker.get("command_wait_completed") is not True
                or worker.get("owned_group_shutdown_requested_before_wait") is not True
                or worker.get("forced_termination") is not False
                or row["wait_completed"] is not True or row["forced_termination"] is not False
                or row["wait_status"] != _http_shell_status(worker.get("command_wait_status"))):
            return False
        input_end, round_end, work_end = (worker.get(key) for key in
            ("input_deadline_monotonic_ms", "round_deadline_monotonic_ms", "work_deadline_monotonic_ms"))
        if (not all(_http_integer(value, 1) for value in (input_end, round_end, work_end))
                or input_end > min(round_end, work_end)):
            return False
        if worker.get("cancel_fence_matched") is True:
            endpoint = _http_matching_fence_for_worker(worker, args)
            if endpoint != args.grace_end_ms or worker.get("command_wait_status") not in {0, 143}:
                return False
        elif worker.get("cancel_fence_matched") is False:
            endpoint = input_end
            if worker.get("cancellation_resource_end_ms") is not None or worker.get("command_wait_status") != 0:
                return False
        else:
            return False
        times = [worker.get(key) for key in ("command_wait_observed_monotonic_ms",
                 "group_shutdown_requested_monotonic_ms", "driver_wait_returned_monotonic_ms",
                 "receipt_prepublication_monotonic_ms")]
        return (all(_http_integer(value, 1) for value in times)
                and times == sorted(times) and times[-1] < endpoint)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        return False


def _http_matching_fence_for_worker(worker, args):
    directory = _http_directory(args.round_dir)
    value = _http_object_file(directory / ".http-barrier-cancel.json")
    endpoint, owners = _http_context(value, directory, args.run_id, args.context_pid)
    if worker.get("cancellation_resource_end_ms") != endpoint:
        raise ValueError("http_receipt_cancel_endpoint_mismatch")
    if not any(owner == {"owner_role": worker["owner_role"], "owner_pid": worker["owner_pid"],
                         "pair_sequence": worker["pair_sequence"], "side": worker["side"]} for owner in owners):
        raise ValueError("http_receipt_cancel_owner_missing")
    return endpoint


def capture(args):
    receipt = {"result": "unknown", "reason_code": "deadline_exhausted", "pid": args.pid,
               "identity_scope": "round_owned_pid_at_capture", "sha256": None,
               "owner_role": args.owner_role, "process_observation": args.process_observation,
               "worker": {"started": False}}
    output = Path(args.output)
    temporary = output.with_name(output.name + ".capture")
    try:
        if now_ms() >= args.deadline_ms:
            return receipt
        if args.pid <= 0:
            receipt["reason_code"] = "not_started"
            return receipt
        if args.process_observation == "wait_complete":
            receipt["reason_code"] = "process_gone"
            receipt["identity_scope"] = "round_original_owned_pid_after_actual_wait"
            return receipt
        if args.process_observation != "live_job":
            receipt["reason_code"] = "process_ownership_unknown"
            return receipt
        if args.owner_role != "node-" + args.side:
            receipt["reason_code"] = "side_owner_identity_mismatch"
            return receipt
        try:
            os.kill(args.pid, 0)
        except ProcessLookupError:
            receipt["reason_code"] = "process_gone"
            return receipt
        definitions = sys.stdin.buffer.read(MAX_LINE_BYTES + 1)
        if len(definitions) > MAX_LINE_BYTES:
            receipt["reason_code"] = "callback_definition_size_exceeded"
            return receipt
        reader, writer = os.pipe()
        os.set_blocking(reader, False)
        environment = {key: value for key, value in os.environ.items() if key in ENV_KEYS}
        remaining = max(1, math.ceil((args.deadline_ms - now_ms()) / 1000))
        environment.update({"ROUND_CAPTURE_FD": str(writer), "ROUND_DEADLINE": str(remaining),
                            "URL": args.url, "OUTPUT": str(temporary), "TOKEN_FILE": args.token_file,
                            "MAX_TIME": str(min(5, remaining)), "KIND": args.kind})
        script = definitions.decode() + '\nif fetch_required_json "$URL" "$OUTPUT" "$KIND" "$TOKEN_FILE" "$MAX_TIME"; then rc=0; else rc=$?; fi\nprintf "%s\\t%s\\n" "$rc" "${FETCH_REASON_CODE:-status_unavailable}" >&"$ROUND_CAPTURE_FD"\nexit "$rc"\n'
        try:
            worker = supervise(["bash", "-c", script], args.deadline_ms, args.grace_end_ms, environment=environment,
                               pass_fds=(writer,), file_cap=MAX_STATUS_BYTES)
        finally:
            os.close(writer)
        try:
            callback = os.read(reader, 256).decode().strip().split("\t", 1)
        except BlockingIOError:
            callback = []
        finally:
            os.close(reader)
        receipt["worker"] = worker
        if worker["result"] != "completed":
            receipt["reason_code"] = worker["reason_code"]
        elif worker["command_wait_status"] != 0:
            receipt["reason_code"] = reason(callback[1] if len(callback) == 2 else "", "status_read_failed")
        elif now_ms() >= args.deadline_ms:
            receipt["reason_code"] = "deadline_exhausted"
        else:
            data = bounded_bytes(temporary, MAX_STATUS_BYTES)
            value = json.loads(data)
            if not isinstance(value, dict) or not value:
                raise ValueError("status_schema_failure")
            if now_ms() >= args.deadline_ms:
                receipt["reason_code"] = "deadline_exhausted"
                return receipt
            os.chmod(temporary, 0o600)
            os.replace(temporary, output)
            receipt.update(result="available", reason_code=None, sha256=hashlib.sha256(data).hexdigest())
    except (OSError, ValueError, UnicodeError, json.JSONDecodeError):
        receipt["reason_code"] = "status_schema_or_capture_failure"
    finally:
        temporary.unlink(missing_ok=True)
        atomic_json(args.receipt, receipt)
    return receipt


def snapshot_inputs(directory, destination, deadline_ms):
    destination.mkdir(mode=0o700, exist_ok=True)
    rows = []
    names = {"node-a.baseline.status.json": MAX_STATUS_BYTES, "node-b.baseline.status.json": MAX_STATUS_BYTES,
             "node-a.status.json": MAX_STATUS_BYTES, "node-b.status.json": MAX_STATUS_BYTES,
             "node-a.log": MAX_SCAN_BYTES, "node-b.log": MAX_SCAN_BYTES, "nat-trace.jsonl": MAX_SCAN_BYTES,
             "nat-sim.out": MAX_STATUS_BYTES, "node-a.egress-stats": MAX_RECEIPT_BYTES,
             "node-b.egress-stats": MAX_RECEIPT_BYTES, "business-samples.jsonl": MAX_STATUS_BYTES}
    for name, cap in names.items():
        if now_ms() >= deadline_ms:
            raise ValueError("deadline_exhausted")
        source = directory / name
        if not source.exists():
            rows.append({"name": name, "result": "missing"})
            continue
        data = bounded_bytes(source, cap)
        if name.endswith((".log", ".jsonl", ".out")) and any(len(line) > MAX_LINE_BYTES for line in data.splitlines()):
            raise ValueError("input_line_size_exceeded")
        target = destination / name
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
        rows.append({"name": name, "result": "captured", "bytes": len(data),
                     "captured_sha256": hashlib.sha256(data).hexdigest(), "scope": "bytes_at_capture"})
    return rows


def run_bounded(args):
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    result = {"result": "unknown", "reason_code": "deadline_exhausted", "started": False}
    record_output = getattr(args, "record_output", "")
    try:
        if now_ms() >= args.deadline_ms:
            return result
        if record_output:
            if args.snapshot or record_output != "nat-evidence.json" or len(command) < 2:
                raise ValueError("original_collector_observation_arguments_invalid")
            entry = getattr(args, "entry_source", "")
            if not entry or Path(command[1]).resolve() != Path(entry).resolve():
                raise ValueError("original_collector_entry_mismatch")
            observation_end_ms = min(args.deadline_ms, args.grace_end_ms)
            _before_deadline(observation_end_ms)
            source = bounded_bytes(entry, MAX_SCAN_BYTES)
            _before_deadline(observation_end_ms)
            result["entry_source"] = {"path": entry, "scope": "bytes_at_capture", "bytes": len(source),
                                      "sha256": hashlib.sha256(source).hexdigest()}
            argv_bytes = json.dumps(command, ensure_ascii=True, separators=(",", ":")).encode()
            if len(argv_bytes) > MAX_LINE_BYTES:
                raise ValueError("original_collector_argv_size_exceeded")
            result["command_argv_sha256"] = hashlib.sha256(argv_bytes).hexdigest()
            _before_deadline(observation_end_ms)
        if args.snapshot:
            snapshot = Path(args.round_dir) / (".bounded-" + args.label)
            inputs = snapshot_inputs(Path(args.round_dir), snapshot, args.deadline_ms)
            command = [str(snapshot) if str(value) == args.round_dir else
                       str(snapshot / Path(value).name) if str(value).startswith(args.round_dir + os.sep)
                       else value for value in command]
            result["inputs"] = inputs
        result.update(supervise(command, args.deadline_ms, args.grace_end_ms,
                                environment={key: value for key, value in os.environ.items() if key in ENV_KEYS}))
        if (args.snapshot and result.get("result") == "completed"
                and result.get("wait_completed") is True and result.get("command_wait_completed") is True
                and result.get("command_wait_status") == 0):
            promotion_deadline_ms = min(args.deadline_ms, args.grace_end_ms)
            _before_deadline(promotion_deadline_ms)
            result["outputs"] = []
            for name in ("nat-evidence.json", "mapping-evidence.json", "continuity-evidence.json"):
                _before_deadline(promotion_deadline_ms)
                generated = snapshot / name
                if generated.is_file():
                    _before_deadline(promotion_deadline_ms)
                    data = bounded_bytes(generated, MAX_RECEIPT_BYTES)
                    _before_deadline(promotion_deadline_ms)
                    value = json.loads(data)
                    _before_deadline(promotion_deadline_ms)
                    if not isinstance(value, dict):
                        raise ValueError("input_not_object")
                    digest = atomic_json(Path(args.round_dir) / name, value,
                                         deadline_ms=promotion_deadline_ms)
                    result["outputs"].append({"name": name, "captured_sha256": digest})
                    _before_deadline(promotion_deadline_ms)
            _before_deadline(promotion_deadline_ms)
        if (record_output and result.get("result") == "completed"
                and result.get("wait_completed") is True and result.get("command_wait_completed") is True
                and result.get("command_wait_status") == 0
                and result.get("owned_group_shutdown_requested_before_wait") is True):
            observation_end_ms = min(args.deadline_ms, args.grace_end_ms)
            _before_deadline(observation_end_ms)
            data = bounded_bytes(Path(args.round_dir) / record_output, MAX_RECEIPT_BYTES)
            _before_deadline(observation_end_ms)
            value = json.loads(data)
            if not isinstance(value, dict):
                raise ValueError("original_collector_output_not_object")
            digest = hashlib.sha256(data).hexdigest()
            _before_deadline(observation_end_ms)
            result["outputs"] = [{"name": record_output, "captured_sha256": digest,
                                  "scope": "bytes_at_capture"}]
            _before_deadline(observation_end_ms)
    except _FixedDeadlineExpired:
        result.update(result="unknown", reason_code=("deadline_exhausted" if args.deadline_ms <= args.grace_end_ms
                                                    else "resource_grace_exhausted"))
    except (OSError, ValueError, json.JSONDecodeError):
        result.update(result="unknown", reason_code="bounded_input_or_collector_failure")
    finally:
        if record_output and result.get("result") == "completed" and result.get("command_wait_status") == 0:
            try:
                observation_end_ms = min(args.deadline_ms, args.grace_end_ms)
                _before_deadline(observation_end_ms)
                atomic_json(args.receipt, result, deadline_ms=observation_end_ms)
                _before_deadline(observation_end_ms)
            except _FixedDeadlineExpired:
                result.update(result="unknown", reason_code=("deadline_exhausted" if args.deadline_ms <= args.grace_end_ms
                                                            else "resource_grace_exhausted"))
                atomic_json(args.receipt, result)
        else:
            atomic_json(args.receipt, result)
    return result


def trace_summary(args):
    result = {"result": "unknown", "reason_code": "deadline_exhausted", "rows": None, "sha256": None}
    try:
        if now_ms() >= args.deadline_ms:
            return result
        data = bounded_bytes(Path(args.round_dir) / "nat-trace.jsonl", MAX_SCAN_BYTES)
        rows = 0
        for line in data.splitlines():
            if now_ms() >= args.deadline_ms:
                raise ValueError("deadline_exhausted")
            if len(line) > MAX_LINE_BYTES or not isinstance(json.loads(line), dict):
                raise ValueError("trace_line_invalid_or_oversize")
            rows += 1
        result.update(result="captured", reason_code=None, rows=rows, bytes=len(data),
                      sha256=hashlib.sha256(data).hexdigest(), scope="bytes_at_capture")
    except FileNotFoundError:
        result["reason_code"] = "trace_missing"
    except (OSError, ValueError, json.JSONDecodeError):
        result["reason_code"] = "trace_invalid_truncated_or_deadline"
    finally:
        atomic_json(args.receipt, result)
    return result


def read_or_unknown(path):
    try:
        return object_file(path)
    except (OSError, ValueError, json.JSONDecodeError):
        return {"result": "unknown", "reason_code": "not_captured"}


def publish(args):
    directory = Path(args.round_dir)
    rows = []
    data = sys.stdin.buffer.read(MAX_RECEIPT_BYTES + 1)
    if len(data) > MAX_RECEIPT_BYTES:
        raise ValueError("owner_receipt_input_size_exceeded")
    for line in data.decode().splitlines():
        parts = line.split("\t")
        if len(parts) != 5 or len(rows) >= MAX_RECORDS:
            raise ValueError("owner_receipt_schema_or_capacity_invalid")
        role, pid, completed, status_code, forced = parts
        if not SAFE_REASON.fullmatch(role) or not pid.isdigit() or completed not in {"0", "1"} or forced not in {"0", "1"}:
            raise ValueError("owner_receipt_type_invalid")
        if status_code != "unknown" and (not status_code.isdigit() or not 0 <= int(status_code) <= 255):
            raise ValueError("owner_wait_status_invalid")
        if completed == "1" and status_code in {"unknown", "127"}:
            raise ValueError("owner_wait_receipt_missing")
        rows.append({"role": role, "pid": int(pid), "wait_completed": completed == "1",
                     "wait_status": int(status_code) if status_code != "unknown" else None,
                     "forced_termination": forced == "1"})
    if (min(args.pending, args.started, args.wait_unknown, args.wait_completed, args.watchers) < 0
            or args.started < len(rows) or args.wait_completed + args.wait_unknown + args.pending != args.started
            or args.watchers > args.started):
        raise ValueError("owner_aggregate_counts_invalid")
    statuses = {side: read_or_unknown(directory / (".final-status-" + side + ".json")) for side in ("a", "b")}
    workers = []
    worker_unknown = 0
    for side, status_receipt in statuses.items():
        worker = status_receipt.get("worker")
        if not isinstance(worker, dict):
            worker_unknown += 1
        elif worker.get("started") is True:
            workers.append({"stage": "status-" + side, **worker})
            if (worker.get("wait_completed") is not True or worker.get("command_wait_completed") is not True
                    or worker.get("owned_group_shutdown_requested_before_wait") is not True):
                worker_unknown += 1
    for label in ("collector", "mapping", "continuity", "drain"):
        path = directory / ("." + label + "-result.json")
        if path.exists():
            worker = read_or_unknown(path)
            if worker.get("started") is True:
                workers.append({"stage": label, **worker})
                if (worker.get("wait_completed") is not True or worker.get("command_wait_completed") is not True
                        or worker.get("owned_group_shutdown_requested_before_wait") is not True):
                    worker_unknown += 1
            elif worker.get("started") is not False:
                worker_unknown += 1
    # HTTP paths come exclusively from the bounded authoritative owned rows; no directory scan.
    http_seen_roles, http_seen_pids = set(), set()
    for row in rows:
        if not row["role"].startswith("http-barrier-"):
            continue
        try:
            _http_role(row["role"])
            if row["role"] in http_seen_roles or row["pid"] in http_seen_pids:
                raise ValueError("http_owner_duplicate")
            http_seen_roles.add(row["role"])
            http_seen_pids.add(row["pid"])
            worker = _http_object_file(directory / ("." + row["role"] + "-result.json"))
        except (OSError, ValueError, json.JSONDecodeError):
            worker = {"result": "unknown", "reason_code": "http_worker_receipt_missing_or_invalid"}
        workers.append({**worker, "stage": row["role"]})
        if not _http_worker_valid(worker, row, args):
            worker_unknown += 1
    complete = (args.pending == 0 and args.wait_unknown == 0 and args.wait_completed == args.started
                and worker_unknown == 0)
    cleanup = {"schema_version": 1, "duration_ms": max(0, now_ms() - args.start_ms),
               "process_count": max(0, args.started - args.watchers),
               "started_process_count": args.started, "wait_completed_count": args.wait_completed,
               "unrecorded_process_count": max(0, args.started - len(rows)),
               "metadata_coverage": "complete" if args.started <= MAX_RECORDS else "capacity_exceeded",
               "all_reaped": complete, "forced_termination": args.forced or any(row.get("forced_termination") is True for row in workers),
               "pending_process_count": args.pending,
               "resource_grace_deadline_monotonic_ms": args.grace_end_ms, "owned_processes": rows}
    cleanup.update(owned_workers=workers, worker_unknown_count=worker_unknown)
    cleanup["resource_scope"] = "registered_children_and_supervised_synchronous_commands"
    failed = bool(args.exit_code) or not complete or cleanup["forced_termination"]
    terminal_reason = reason(args.reason_code, "completed")
    if not complete and terminal_reason == "completed":
        terminal_reason = "cleanup_incomplete"
    receipt = {"schema_version": 1, "round_run_id": args.run_id, "terminal_reason_code": terminal_reason,
               "original_exit_code": args.exit_code, "round_result": "invalid" if failed else "completed",
               "shell_exit_status": args.shell_exit_code if args.shell_exit_code >= 0 else None,
               "shell_exit_status_source": args.shell_exit_source,
               "capture_deadline_monotonic_ms": args.capture_end_ms, "statuses": statuses,
               "trace": read_or_unknown(directory / ".trace-summary.json"),
               "source_identity": read_or_unknown(directory / ".round-source-identity.json"),
               "collector": read_or_unknown(directory / ".collector-result.json"),
               "cleanup": {"all_reaped": complete, "forced_termination": cleanup["forced_termination"]}}
    if failed:
        previous = read_or_unknown(directory / "nat-evidence.json")
        actual_collector = receipt["collector"]
        outputs = actual_collector.get("outputs")
        if not isinstance(outputs, list) or len(outputs) > 3:
            outputs = []
        output_hash = next((row.get("captured_sha256") for row in outputs
                            if isinstance(row, dict) and row.get("name") == "nat-evidence.json"), None)
        collector_ran = False
        if (actual_collector.get("result") == "completed" and actual_collector.get("command_wait_status") == 0
                and actual_collector.get("wait_completed") is True and output_hash):
            try:
                previous_bytes = bounded_bytes(directory / "nat-evidence.json", MAX_RECEIPT_BYTES)
                captured = json.loads(previous_bytes)
                if isinstance(captured, dict):
                    previous = captured
                    collector_ran = hashlib.sha256(previous_bytes).hexdigest() == output_hash
            except (OSError, ValueError, json.JSONDecodeError):
                pass
        if (directory / "nat-evidence.json").is_file():
            atomic_json(directory / ".collector-nat-evidence.json", previous)
        atomic_json(directory / "nat-evidence.json", {
            "schema_version": 1, "executed": collector_ran and previous.get("executed") is True,
            "result": "fail", "decision": {"result": "fail", "reason_code": "harness:" + terminal_reason},
            "collector_observations": {"available": collector_ran and previous.get("schema_version") is not None,
                                       "reference": ".collector-nat-evidence.json" if previous.get("schema_version") is not None else None},
            "nat_terminal": None})
    atomic_json(directory / "cleanup.json", cleanup)
    atomic_json(directory / "round-finalization.json", receipt)
    return complete


def identity(args):
    value = {"result": "unknown", "reason_code": "source_or_artifact_identity_missing", "source": None,
             "artifact_set_sha256": None, "launch_records": [], "artifact_validation_scope": "declaration_only"}
    try:
        if now_ms() >= args.deadline_ms:
            value["reason_code"] = "deadline_exhausted"
            return
        owners = {}
        owner_data = sys.stdin.buffer.read(MAX_LINE_BYTES + 1)
        if len(owner_data) > MAX_LINE_BYTES:
            raise ValueError("owner_capacity_exceeded")
        for line in owner_data.decode().splitlines():
            role, pid = line.split("\t")
            if not SAFE_REASON.fullmatch(role) or not pid.isdigit() or role in owners or len(owners) >= MAX_RECORDS:
                raise ValueError("owner_identity_invalid")
            owners[role] = int(pid)
        source_data = bounded_bytes(Path(args.base_dir) / "source-at-build.json", MAX_RECEIPT_BYTES)
        source = json.loads(source_data)
        artifact_path = Path(args.base_dir) / "artifact-set.json"
        artifact_data = bounded_bytes(artifact_path, MAX_RECEIPT_BYTES)
        artifacts = json.loads(artifact_data)
        import launch_identity
        launch_identity.validate_source(source)
        launch_identity.validate_artifact_set(artifacts)
        if artifacts["source"] != source:
            raise ValueError("source_mismatch")
        value.update(result="captured", reason_code=None, source=source,
                     source_at_build_sha256=hashlib.sha256(source_data).hexdigest(),
                     artifact_set_sha256=hashlib.sha256(artifact_data).hexdigest())
        # Enumerate at most 129 entries, including irrelevant files. Do not
        # materialize/sort an unbounded directory before enforcing capacity.
        launch_dir = Path(args.round_dir) / "launches"
        if not stat.S_ISDIR(launch_dir.lstat().st_mode):
            raise ValueError("launch_directory_invalid")
        with os.scandir(launch_dir) as entries:
            paths = []
            for entry in entries:
                if len(paths) >= MAX_RECORDS or now_ms() >= args.deadline_ms:
                    raise ValueError("launch_capacity_or_deadline_exhausted")
                paths.append(Path(entry.path))
        seen = set()
        for path in paths:
            if len(value["launch_records"]) >= MAX_RECORDS or now_ms() >= args.deadline_ms:
                value.update(result="unknown", reason_code="launch_capacity_or_deadline_exhausted")
                break
            record_data = bounded_bytes(path, MAX_RECEIPT_BYTES)
            record = json.loads(record_data)
            launch_identity.validate_record(record, source)
            if (record["artifact_set_sha256"] != value["artifact_set_sha256"]
                    or record["artifact"] != artifacts["artifacts"].get(record["component"])
                    or owners.get(record["role"]) != record["pid"]
                    or record["role"] in seen or path.name != record["role"] + ".json"):
                raise ValueError("launch_artifact_set_mismatch")
            seen.add(record["role"])
            value["launch_records"].append({"role": record["role"], "pid": record["pid"],
                                             "monotonic_ns": record["monotonic_ns"], "state": record["state"],
                                             "sha256": hashlib.sha256(record_data).hexdigest(),
                                             "capture_stage": "round_finalization"})
        if now_ms() >= args.deadline_ms:
            value.update(result="unknown", reason_code="deadline_exhausted")
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        value.update(result="unknown", reason_code="source_or_launch_identity_invalid")
    finally:
        atomic_json(args.receipt, value)


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("action", choices=("now", "capture", "run", "trace", "publish", "identity", "http-request", "http-cancel"))
    parser.add_argument("--round-dir", default="")
    parser.add_argument("--base-dir", default="")
    parser.add_argument("--deadline-ms", type=int, default=0)
    parser.add_argument("--receipt", default="")
    parser.add_argument("--side", choices=("a", "b"), default="a")
    parser.add_argument("--owner-role", default="unknown")
    parser.add_argument("--process-observation", choices=("live_job", "wait_complete", "unknown", "not_started"),
                        default="unknown")
    parser.add_argument("--pid", type=int, default=0)
    parser.add_argument("--output", default="")
    parser.add_argument("--token-file", default="")
    parser.add_argument("--url", default="")
    parser.add_argument("--kind", default="status")
    parser.add_argument("--snapshot", action="store_true")
    parser.add_argument("--record-output", choices=("nat-evidence.json",), default="")
    parser.add_argument("--entry-source", default="")
    parser.add_argument("--label", default="collector")
    parser.add_argument("--run-id", default="")
    parser.add_argument("--reason-code", default="")
    parser.add_argument("--exit-code", type=int, default=0)
    parser.add_argument("--shell-exit-code", type=int, default=-1)
    parser.add_argument("--shell-exit-source", choices=("exit_trap", "deferred_signal", "not_observed"), default="not_observed")
    parser.add_argument("--start-ms", type=int, default=0)
    parser.add_argument("--capture-end-ms", type=int, default=0)
    parser.add_argument("--grace-end-ms", type=int, default=0)
    parser.add_argument("--pending", type=int, default=0)
    parser.add_argument("--started", type=int, default=0)
    parser.add_argument("--watchers", type=int, default=0)
    parser.add_argument("--wait-completed", type=int, default=0)
    parser.add_argument("--wait-unknown", type=int, default=0)
    parser.add_argument("--forced", action="store_true")
    parser.add_argument("--context-pid", type=int, default=0)
    parser.add_argument("--pair-sequence", type=int, default=0)
    parser.add_argument("--round-end-ms", type=int, default=0)
    parser.add_argument("--work-end-ms", type=int, default=0)
    parser.add_argument("--parent-round-remaining", type=int, default=0)
    parser.add_argument("--max-time", type=int, default=0)
    parser.add_argument("--definitions", default="")
    parser.add_argument("--metadata", default="")
    parser.add_argument("--status-failure-injection", default="0")
    parser.add_argument("--metrics-failure-injection", default="0")
    parser.add_argument("--status-schema-injection", default="0")
    args, args.command = parser.parse_known_args()
    if args.action == "now":
        print(now_ms())
    elif args.action == "http-request":
        return http_request(args)
    elif args.action == "http-cancel":
        return http_cancel(args)
    elif args.action == "capture":
        return 0 if capture(args)["result"] == "available" else 1
    elif args.action == "run":
        result = run_bounded(args)
        if args.record_output:
            print("completed" if result.get("result") == "completed" and result.get("command_wait_status") == 0
                  else reason(result.get("reason_code"), "collector_command_failed"))
            if (result.get("result") == "completed" and result.get("command_wait_completed") is True
                    and result.get("wait_completed") is True
                    and result.get("owned_group_shutdown_requested_before_wait") is True):
                status_code = result.get("command_wait_status")
                if isinstance(status_code, int) and not isinstance(status_code, bool):
                    if 0 <= status_code <= 255:
                        return status_code
                    if -127 <= status_code < 0:
                        return 128 - status_code
            return 1
        return 0 if result.get("result") == "completed" and result.get("command_wait_status") == 0 else 1
    elif args.action == "trace":
        trace_summary(args)
    elif args.action == "identity":
        identity(args)
    else:
        return 0 if publish(args) else 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
