#!/usr/bin/env python3
"""Bounded OS TCP echo on one connection; no TUN/path/canonical attribution.

Eight fixed requests by default, no reconnect or application retry. A response
deadline covers every partial write/read for that request. Stream failure keeps
all remaining requests in the original denominator. Reports are exclusive 0600
files outside checkouts, using the existing UDP tool's output contract.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import secrets
import socket
import struct
import time
from typing import Callable

from udp_business_probe import Config, NS_PER_MS, UNVERIFIED, validate_output_path, write_report

SCOPE = "os_tcp_echo"
MAGIC = b"P2WTCE1\x00"
HEADER = struct.Struct("!8sB16s16sI16sH")
REQUEST, RESPONSE = 0, 1
MAX_FRAME = 1200
MAX_FRAMES = 16_384
STATUSES = ("success", "timeout", "send_error", "not_sent", "cancelled")


def encode(config: Config, sequence: int, nonce: str, kind: int) -> bytes:
    return HEADER.pack(MAGIC, kind, bytes.fromhex(config.run_nonce),
                       bytes.fromhex(config.round_nonce), sequence, bytes.fromhex(nonce),
                       config.payload_bytes) + b"\xa5" * config.payload_bytes


def decode(data: bytes) -> tuple | None:
    if not HEADER.size <= len(data) <= MAX_FRAME:
        return None
    magic, kind, run, round_, sequence, nonce, size = HEADER.unpack_from(data)
    if magic != MAGIC or kind not in (REQUEST, RESPONSE):
        return None
    if size != len(data) - HEADER.size or data[HEADER.size:] != b"\xa5" * size:
        return None
    return kind, run.hex(), round_.hex(), sequence, nonce.hex(), size


def base_report(config: Config, role: str) -> dict:
    report = {"schema_version": 1, "scope": SCOPE, "role": role,
            "tool_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "run_nonce": config.run_nonce, "round_nonce": config.round_nonce,
            "configuration": config.as_dict(), "evidence": dict(UNVERIFIED),
            "clock": "local_tool_process_monotonic_ns",
            "received_frames": 0, "invalid_frames": 0}
    report["connection_attempts" if role == "probe" else "accepted_connections"] = 0
    return report


def remaining(deadline: int) -> float:
    left = deadline - time.monotonic_ns()
    if left <= 0:
        raise TimeoutError("absolute TCP deadline")
    return left / 1_000_000_000


def read_exact(sock: socket.socket, size: int, deadline: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        sock.settimeout(remaining(deadline))
        part = sock.recv(size - len(data))
        if not part:
            raise EOFError("TCP stream closed before complete frame")
        data.extend(part)
    return bytes(data)


def read_frame(sock: socket.socket, deadline: int) -> bytes:
    size = struct.unpack("!I", read_exact(sock, 4, deadline))[0]
    if not HEADER.size <= size <= MAX_FRAME:
        raise ValueError("TCP frame length outside fixed bound")
    return read_exact(sock, size, deadline)


def write_frame(sock: socket.socket, data: bytes, deadline: int) -> int:
    wire = struct.pack("!I", len(data)) + data
    written = 0
    while written < len(wire):
        sock.settimeout(remaining(deadline))
        count = sock.send(wire[written:])
        if count <= 0:
            raise OSError("zero TCP write")
        written += count
    return written


def bound_socket(config: Config, supplied: socket.socket | None) -> socket.socket:
    if supplied is not None:
        if supplied.getsockname() != config.bind:
            raise ValueError("provided socket does not match explicit bind")
        return supplied
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(config.bind)
        return sock
    except BaseException:
        sock.close()
        raise


def run_probe(config: Config, supplied_socket: socket.socket | None = None) -> dict:
    config.validate()
    report = base_report(config, "probe")
    records = [{"sequence": i, "request_nonce": secrets.token_hex(16),
                "planned_offset_ns": i * config.interval_ms * NS_PER_MS,
                "sent_offset_ns": None, "completed_offset_ns": None, "rtt_ns": None,
                "status": "not_sent", "reason": "scheduled"} for i in range(config.count)]
    report["requests"] = records
    started = time.monotonic_ns()
    end = started + config.duration_ms * NS_PER_MS
    sock = None
    termination = "completed"
    try:
        sock = bound_socket(config, supplied_socket)
        sock.settimeout(remaining(min(end, started + config.timeout_ms * NS_PER_MS)))
        report["connection_attempts"] += 1
        sock.connect(config.target)
        if sock.getpeername() != config.target:
            raise OSError("connected TCP peer differs from explicit target")
        for record in records:
            planned = started + record["planned_offset_ns"]
            if time.monotonic_ns() < planned:
                time.sleep(max(0, min(planned, end) - time.monotonic_ns()) / 1_000_000_000)
            if time.monotonic_ns() >= end:
                termination = "duration_deadline"
                break
            sent = time.monotonic_ns()
            deadline = min(end, sent + config.timeout_ms * NS_PER_MS)
            record.update(status="pending", sent_offset_ns=sent - started, reason="awaiting_echo")
            try:
                write_frame(sock, encode(config, record["sequence"], record["request_nonce"], REQUEST), deadline)
            except TimeoutError as error:
                record.update(status="timeout", reason="response_deadline", errno=error.errno)
                termination = "stream_deadline"
                break
            except OSError as error:
                record.update(status="send_error", reason="tcp_send_failed", errno=error.errno)
                termination = "stream_failed"
                break
            try:
                while report["received_frames"] < MAX_FRAMES:
                    frame = decode(read_frame(sock, deadline))
                    report["received_frames"] += 1
                    expected = (RESPONSE, config.run_nonce, config.round_nonce,
                                record["sequence"], record["request_nonce"], config.payload_bytes)
                    if frame == expected:
                        completed = time.monotonic_ns()
                        if completed >= deadline:
                            raise TimeoutError("late complete response")
                        record.update(status="success", reason="matched_echo",
                                      completed_offset_ns=completed - started, rtt_ns=completed - sent)
                        break
                    report["invalid_frames"] += 1
                else:
                    termination = "receive_budget_exhausted"
                    break
            except TimeoutError as error:
                record.update(status="timeout", reason="response_deadline", errno=error.errno)
                termination = "stream_deadline"
                break
            except (OSError, EOFError, ValueError) as error:
                if isinstance(error, OSError):
                    record["errno"] = error.errno
                termination = "stream_failed"
                break
    except KeyboardInterrupt:
        termination = "interrupted"
    except TimeoutError as error:
        report["socket_error_errno"] = error.errno
        termination = "connect_deadline"
    except OSError as error:
        report["socket_error_errno"] = error.errno
        termination = "bind_failed" if sock is None else "connect_failed"
    finally:
        elapsed = time.monotonic_ns() - started
        for record in records:
            if record["status"] in ("not_sent", "pending"):
                record.update(status="not_sent" if record["sent_offset_ns"] is None else "cancelled",
                              reason=termination)
            if record["completed_offset_ns"] is None:
                record["completed_offset_ns"] = elapsed
        if sock is not None and supplied_socket is None:
            sock.close()
    report.update(elapsed_ns=elapsed, termination_reason=termination)
    return report


def run_echo(config: Config, supplied_listener: socket.socket | None = None,
             on_ready: Callable[[], None] | None = None) -> dict:
    config.validate()
    report = base_report(config, "echo")
    report.update(responses_sent=0, send_errors=0)
    listener = connection = None
    started = time.monotonic_ns()
    deadline = started + config.duration_ms * NS_PER_MS
    seen = set()
    termination = "duration_deadline"
    try:
        listener = bound_socket(config, supplied_listener)
        listener.listen(1)
        if on_ready:
            on_ready()
        listener.settimeout(remaining(deadline))
        connection, source = listener.accept()
        report["accepted_connections"] += 1
        if source != config.target:
            termination = "wrong_source"
        else:
            while report["received_frames"] < MAX_FRAMES:
                frame = decode(read_frame(connection, deadline))
                report["received_frames"] += 1
                if frame is None or frame[:3] != (REQUEST, config.run_nonce, config.round_nonce) or (
                    frame[3] >= config.count or frame[3] in seen or frame[5] != config.payload_bytes
                ):
                    report["invalid_frames"] += 1
                    continue
                seen.add(frame[3])
                try:
                    write_frame(connection, encode(config, frame[3], frame[4], RESPONSE), deadline)
                except (TimeoutError, OSError):
                    report["send_errors"] += 1
                    raise
                report["responses_sent"] += 1
                if len(seen) == config.count:
                    termination = "request_budget_exhausted"
                    break
            else:
                termination = "receive_budget_exhausted"
    except TimeoutError as error:
        report["socket_error_errno"] = error.errno
        termination = "duration_deadline"
    except KeyboardInterrupt:
        termination = "interrupted"
    except (OSError, EOFError, ValueError) as error:
        if isinstance(error, OSError):
            report["socket_error_errno"] = error.errno
        termination = "bind_failed" if listener is None else "stream_failed"
    finally:
        if connection is not None:
            connection.close()
        if listener is not None and supplied_listener is None:
            listener.close()
    report.update(elapsed_ns=time.monotonic_ns() - started, termination_reason=termination)
    return report


def validate_probe(report: dict) -> list[dict]:
    if (report.get("scope"), report.get("schema_version"), report.get("role")) != (SCOPE, 1, "probe"):
        raise ValueError("unexpected TCP report scope")
    attempts = report.get("connection_attempts")
    if report.get("evidence") != UNVERIFIED or type(attempts) is not int or attempts not in (0, 1):
        raise ValueError("TCP report changed missing evidence or retried connection")
    if report.get("socket_error_errno") is not None and type(report["socket_error_errno"]) is not int:
        raise ValueError("TCP socket errno must be a numeric observation or null")
    c = report["configuration"]
    config = Config((c["bind_ip"], c["bind_port"]), (c["target_ip"], c["target_port"]),
                    report["run_nonce"], report["round_nonce"], c["count"], c["interval_ms"],
                    c["timeout_ms"], c["duration_ms"], c["payload_bytes"])
    config.validate()
    records = report["requests"]
    if len(records) != config.count:
        raise ValueError("TCP fixed denominator changed")
    if attempts == 0 and (any(r["status"] != "not_sent" or r["sent_offset_ns"] is not None for r in records)
                          or report["termination_reason"] not in ("bind_failed", "connect_deadline", "interrupted")):
        raise ValueError("TCP report credits requests without an actual connect attempt")
    nonces = set()
    for i, record in enumerate(records):
        if record.get("errno") is not None and type(record["errno"]) is not int:
            raise ValueError("TCP request errno must be a numeric observation or null")
        nonce = record["request_nonce"]
        if len(nonce) != 32 or any(x not in "0123456789abcdef" for x in nonce) or nonce in nonces:
            raise ValueError("invalid or duplicated TCP request nonce")
        nonces.add(nonce)
        if record["sequence"] != i or record["planned_offset_ns"] != i * config.interval_ms * NS_PER_MS:
            raise ValueError("TCP schedule changed")
        sent, done, rtt = record["sent_offset_ns"], record["completed_offset_ns"], record["rtt_ns"]
        if type(done) is not int or not 0 <= done <= report["elapsed_ns"] or record["status"] not in STATUSES:
            raise ValueError("TCP request lacks a valid terminal outcome")
        if record["status"] == "not_sent":
            if sent is not None:
                raise ValueError("unsent TCP request has attempted send")
        elif type(sent) is not int or not record["planned_offset_ns"] <= sent <= done or sent >= config.duration_ms * NS_PER_MS:
            raise ValueError("TCP send outside original schedule/deadline")
        if record["status"] == "success":
            if type(rtt) is not int or not 0 <= rtt < config.timeout_ms * NS_PER_MS or (
                done - sent != rtt or done >= config.duration_ms * NS_PER_MS or record["reason"] != "matched_echo"
            ):
                raise ValueError("TCP success outside matching response deadline")
        elif rtt is not None:
            raise ValueError("failed TCP request has RTT")
    return records


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("role", choices=("probe", "echo"))
    for name in ("bind-ip", "target-ip", "run-nonce", "round-nonce"):
        parser.add_argument("--" + name, required=True)
    for name in ("bind-port", "target-port"):
        parser.add_argument("--" + name, type=int, required=True)
    for name, default in (("count", 8), ("interval-ms", 100), ("timeout-ms", 1000),
                          ("duration-ms", 10000), ("payload-bytes", 128)):
        parser.add_argument("--" + name, type=int, default=default)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    config = Config((args.bind_ip, args.bind_port), (args.target_ip, args.target_port),
                    args.run_nonce, args.round_nonce, args.count, args.interval_ms,
                    args.timeout_ms, args.duration_ms, args.payload_bytes)
    try:
        config.validate()
        validate_output_path(args.output)
        if args.role == "probe":
            report = run_probe(config)
            validate_probe(report)
        else:
            report = run_echo(config, on_ready=lambda: print('{"event":"echo_ready","scope":"os_tcp_echo"}', flush=True))
        write_report(args.output, report)
    except (OSError, ValueError) as error:
        parser.exit(2, f"tcp-business-probe: {error}\n")
    if args.role == "probe":
        return int(any(r["status"] != "success" for r in report["requests"]))
    return int(report["termination_reason"] != "request_budget_exhausted" or report["send_errors"] != 0)


if __name__ == "__main__":
    raise SystemExit(main())
