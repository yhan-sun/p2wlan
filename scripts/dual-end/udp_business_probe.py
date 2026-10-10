#!/usr/bin/env python3
"""Bounded OS UDP echo measurement; this does not verify TUN or Direct routing.

Both endpoints must already have their addresses/routes configured. The tool
only opens an explicitly bound IPv4 UDP socket. It never starts a daemon,
changes a route, uses SSH, or retries a request. Use a new run and round nonce
for each independent measurement. Evidence outputs must be new absolute paths
outside Git checkouts and are created exclusively with mode 0600.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import secrets
import select
import socket
import struct
import sys
import time
from typing import Callable


SCOPE = "os_udp_echo"
SCHEMA_VERSION = 1
MAGIC = b"P2WUDE1\x00"
HEADER = struct.Struct("!8sB16s16sI16sH")
REQUEST, RESPONSE = 0, 1
MAX_DATAGRAM_BYTES = 1200
MAX_PAYLOAD_BYTES = MAX_DATAGRAM_BYTES - HEADER.size
MAX_REQUESTS = 1000
MAX_DURATION_MS = 120_000
MAX_RX_DATAGRAMS = 16_384
MAX_DRAIN_BATCH = 64
NS_PER_MS = 1_000_000
UNVERIFIED = {
    "real_tun_verified": None,
    "real_tun_reason": "os_socket_route_not_verified",
    "exact_direct_verified": None,
    "exact_direct_reason": "path_session_incarnation_owner_not_observed",
    "connection_start_attribution": None,
    "connection_start_reason": "connection_start_identity_unavailable",
}
RECEIVE_REASONS = (
    "accepted", "malformed", "wrong_source", "wrong_run", "wrong_round",
    "wrong_kind", "wrong_request", "duplicate", "late",
)


def bounded_int(value: int, lower: int, upper: int, name: str) -> None:
    if type(value) is not int or not lower <= value <= upper:
        raise ValueError(f"{name} must be in {lower}..{upper}")


def nonce_bytes(value: str) -> bytes:
    if not isinstance(value, str) or len(value) != 32 or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise ValueError("nonce must contain exactly 32 lowercase hex characters")
    return bytes.fromhex(value)


def endpoint(ip: str, port: int) -> tuple[str, int]:
    address = ipaddress.IPv4Address(ip)
    if address.is_unspecified or address.is_multicast or str(address) == "255.255.255.255":
        raise ValueError("use a concrete unicast IPv4 address")
    bounded_int(port, 1, 65535, "port")
    return str(address), port


@dataclass(frozen=True)
class Config:
    bind: tuple[str, int]
    target: tuple[str, int]
    run_nonce: str
    round_nonce: str
    count: int = 8
    interval_ms: int = 100
    timeout_ms: int = 1000
    duration_ms: int = 10_000
    payload_bytes: int = 128

    def validate(self) -> None:
        endpoint(*self.bind)
        endpoint(*self.target)
        nonce_bytes(self.run_nonce)
        nonce_bytes(self.round_nonce)
        bounded_int(self.count, 1, MAX_REQUESTS, "count")
        bounded_int(self.interval_ms, 1, 5000, "interval_ms")
        bounded_int(self.timeout_ms, 1, 10_000, "timeout_ms")
        bounded_int(self.duration_ms, 1, MAX_DURATION_MS, "duration_ms")
        bounded_int(self.payload_bytes, 0, MAX_PAYLOAD_BYTES, "payload_bytes")
        if (self.count - 1) * self.interval_ms + self.timeout_ms > self.duration_ms:
            raise ValueError("all prescheduled requests and their timeouts must fit duration_ms")

    def as_dict(self) -> dict:
        return {
            "bind_ip": self.bind[0], "bind_port": self.bind[1],
            "target_ip": self.target[0], "target_port": self.target[1],
            "count": self.count, "interval_ms": self.interval_ms,
            "timeout_ms": self.timeout_ms, "duration_ms": self.duration_ms,
            "payload_bytes": self.payload_bytes,
        }


def encode(config: Config, sequence: int, request_nonce: str, kind: int) -> bytes:
    return HEADER.pack(
        MAGIC, kind, nonce_bytes(config.run_nonce), nonce_bytes(config.round_nonce),
        sequence, nonce_bytes(request_nonce), config.payload_bytes,
    ) + b"\xa5" * config.payload_bytes


def decode(data: bytes) -> tuple | None:
    if not HEADER.size <= len(data) <= MAX_DATAGRAM_BYTES:
        return None
    magic, kind, run, round_, sequence, nonce, length = HEADER.unpack_from(data)
    if magic != MAGIC or kind not in (REQUEST, RESPONSE):
        return None
    if length != len(data) - HEADER.size or data[HEADER.size:] != b"\xa5" * length:
        return None
    return kind, run.hex(), round_.hex(), sequence, nonce.hex(), length


def base_report(config: Config, role: str) -> dict:
    return {
        "schema_version": SCHEMA_VERSION, "scope": SCOPE, "role": role,
        "tool_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "run_nonce": config.run_nonce, "round_nonce": config.round_nonce,
        "configuration": config.as_dict(), "evidence": dict(UNVERIFIED),
        "clock": "probe_process_monotonic_ns" if role == "probe" else "echo_process_monotonic_ns",
        "receive_counts": {reason: 0 for reason in RECEIVE_REASONS},
        "received_datagrams": 0,
    }


def open_socket(config: Config, supplied: socket.socket | None) -> socket.socket:
    if supplied is None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind(config.bind)
        except BaseException:
            sock.close()
            raise
    else:
        sock = supplied
        if sock.getsockname() != config.bind:
            raise ValueError("supplied socket does not match explicit bind endpoint")
    sock.setblocking(False)
    return sock


def frame_reason(config: Config, data: bytes, source: tuple) -> tuple[str | None, tuple | None]:
    if source != config.target:
        return "wrong_source", None
    frame = decode(data)
    if frame is None:
        return "malformed", None
    if frame[1] != config.run_nonce:
        return "wrong_run", frame
    if frame[2] != config.round_nonce:
        return "wrong_round", frame
    if frame[5] != config.payload_bytes:
        return "wrong_request", frame
    return None, frame


def observe_reply(config: Config, records: list[dict], data: bytes, source: tuple,
                  elapsed_ns: int) -> str:
    reason, frame = frame_reason(config, data, source)
    if reason:
        return reason
    kind, _run, _round, sequence, request_nonce, _length = frame
    if kind != RESPONSE:
        return "wrong_kind"
    if sequence >= len(records) or records[sequence]["request_nonce"] != request_nonce:
        return "wrong_request"
    record = records[sequence]
    if record["status"] == "success":
        return "duplicate"
    sent_ns = record["sent_offset_ns"]
    if record["status"] == "timeout" or (
        sent_ns is not None and elapsed_ns - sent_ns >= config.timeout_ms * NS_PER_MS
    ) or elapsed_ns >= config.duration_ms * NS_PER_MS:
        return "late"
    if record["status"] != "pending" or sent_ns is None or elapsed_ns < sent_ns:
        return "wrong_request"
    record.update(status="success", reason="matched_echo", completed_offset_ns=elapsed_ns,
                  rtt_ns=elapsed_ns - sent_ns)
    return "accepted"


def run_probe(config: Config, supplied_socket: socket.socket | None = None) -> dict:
    config.validate()
    report = base_report(config, "probe")
    records = [{
        "sequence": sequence, "request_nonce": secrets.token_hex(16),
        "planned_offset_ns": sequence * config.interval_ms * NS_PER_MS,
        "sent_offset_ns": None, "completed_offset_ns": None, "rtt_ns": None,
        "status": "not_sent", "reason": "scheduled",
    } for sequence in range(config.count)]
    report["requests"] = records
    sock = None
    started = time.monotonic_ns()
    termination = "completed"
    next_sequence = 0
    try:
        sock = open_socket(config, supplied_socket)
        # RTT and schedule start at this OS socket measurement, not a daemon
        # join/connection-start event. No cross-host timestamps are subtracted.
        started = time.monotonic_ns()
        end_ns = config.duration_ms * NS_PER_MS
        while True:
            elapsed = time.monotonic_ns() - started
            for record in records:
                if record["status"] == "pending" and (
                    elapsed - record["sent_offset_ns"] >= config.timeout_ms * NS_PER_MS
                ):
                    record.update(status="timeout", reason="response_deadline",
                                  completed_offset_ns=elapsed)
            if all(record["status"] in ("success", "timeout", "send_error") for record in records):
                break
            if elapsed >= end_ns:
                termination = "duration_deadline"
                break
            while next_sequence < config.count:
                record = records[next_sequence]
                elapsed = time.monotonic_ns() - started
                if elapsed >= end_ns or record["planned_offset_ns"] > elapsed:
                    break
                record["sent_offset_ns"] = elapsed
                try:
                    wire = encode(config, next_sequence, record["request_nonce"], REQUEST)
                    written = sock.sendto(wire, config.target)
                    if written != len(wire):
                        raise OSError("short UDP send")
                    record.update(status="pending", reason="awaiting_echo")
                except OSError:
                    record.update(status="send_error", reason="udp_send_failed",
                                  completed_offset_ns=time.monotonic_ns() - started)
                next_sequence += 1
            if all(record["status"] in ("success", "timeout", "send_error") for record in records):
                continue
            elapsed = time.monotonic_ns() - started
            deadlines = [end_ns]
            if next_sequence < config.count:
                deadlines.append(records[next_sequence]["planned_offset_ns"])
            deadlines.extend(record["sent_offset_ns"] + config.timeout_ms * NS_PER_MS
                             for record in records if record["status"] == "pending")
            wait_seconds = max(0, min(deadlines) - elapsed) / 1_000_000_000
            if not select.select([sock], [], [], wait_seconds)[0]:
                continue
            for _ in range(MAX_DRAIN_BATCH):
                try:
                    data, source = sock.recvfrom(MAX_DATAGRAM_BYTES + 1)
                except BlockingIOError:
                    break
                elapsed = time.monotonic_ns() - started
                reason = observe_reply(config, records, data, source, elapsed)
                report["receive_counts"][reason] += 1
                report["received_datagrams"] += 1
                if report["received_datagrams"] >= MAX_RX_DATAGRAMS:
                    termination = "receive_budget_exhausted"
                    break
            if termination != "completed":
                break
    except KeyboardInterrupt:
        termination = "interrupted"
    except OSError:
        termination = "bind_failed" if sock is None else "udp_receive_failed"
    finally:
        elapsed = time.monotonic_ns() - started
        for record in records:
            if record["status"] in ("not_sent", "pending"):
                record.update(status="not_sent" if record["sent_offset_ns"] is None else "cancelled",
                              reason=termination, completed_offset_ns=elapsed)
        if sock is not None and supplied_socket is None:
            sock.close()
    report.update(elapsed_ns=elapsed, termination_reason=termination)
    return report


def run_echo(config: Config, supplied_socket: socket.socket | None = None,
             on_ready: Callable[[], None] | None = None) -> dict:
    config.validate()
    report = base_report(config, "echo")
    sock = None
    started = time.monotonic_ns()
    seen = set()
    termination = "duration_deadline"
    report["responses_sent"] = 0
    report["response_bytes"] = 0
    report["send_errors"] = 0
    try:
        sock = open_socket(config, supplied_socket)
        started = time.monotonic_ns()
        if on_ready is not None:
            on_ready()
        while report["received_datagrams"] < MAX_RX_DATAGRAMS:
            remaining_ns = config.duration_ms * NS_PER_MS - (time.monotonic_ns() - started)
            if remaining_ns <= 0:
                break
            if not select.select([sock], [], [], remaining_ns / 1_000_000_000)[0]:
                continue
            data, source = sock.recvfrom(MAX_DATAGRAM_BYTES + 1)
            report["received_datagrams"] += 1
            reason, frame = frame_reason(config, data, source)
            if reason is None:
                kind, _run, _round, sequence, request_nonce, _length = frame
                if kind != REQUEST:
                    reason = "wrong_kind"
                elif sequence >= config.count:
                    reason = "wrong_request"
                elif sequence in seen:
                    reason = "duplicate"
                elif time.monotonic_ns() - started >= config.duration_ms * NS_PER_MS:
                    reason = "late"
                else:
                    seen.add(sequence)
                    reason = "accepted"
                    # Fixed peer destination, request-only, exactly equal size.
                    # Invalid frames get no reply; no reflection amplification.
                    response = encode(config, sequence, request_nonce, RESPONSE)
                    try:
                        if sock.sendto(response, config.target) != len(data):
                            raise OSError("short UDP send")
                        report["responses_sent"] += 1
                        report["response_bytes"] += len(response)
                    except OSError:
                        report["send_errors"] += 1
            report["receive_counts"][reason] += 1
            if len(seen) == config.count:
                termination = "request_budget_exhausted"
                break
        else:
            termination = "receive_budget_exhausted"
    except KeyboardInterrupt:
        termination = "interrupted"
    except OSError:
        termination = "bind_failed" if sock is None else "udp_receive_failed"
    finally:
        report.update(elapsed_ns=time.monotonic_ns() - started, termination_reason=termination)
        if sock is not None and supplied_socket is None:
            sock.close()
    return report


def validate_output_path(path: Path) -> None:
    if not path.is_absolute():
        raise ValueError("evidence output must be an absolute path outside Git checkouts")
    if path.exists() or path.is_symlink():
        raise ValueError("output already exists")
    parent = path.parent.resolve(strict=True)
    if not parent.is_dir():
        raise ValueError("output parent must be an existing directory")
    if any((directory / ".git").exists() for directory in (parent, *parent.parents)):
        raise ValueError("evidence output must be outside Git checkouts")


def write_report(path: Path, report: dict) -> None:
    validate_output_path(path)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        if os.name == "posix":
            os.fchmod(stream.fileno(), 0o600)
        json.dump(report, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write("\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("new-nonces", help="print fresh run and round nonces; no networking")
    for command in ("probe", "echo"):
        sub = subcommands.add_parser(command)
        sub.add_argument("--bind-ip", required=True)
        sub.add_argument("--bind-port", required=True, type=int)
        sub.add_argument("--target-ip", required=True)
        sub.add_argument("--target-port", required=True, type=int)
        sub.add_argument("--run-nonce", required=True)
        sub.add_argument("--round-nonce", required=True)
        sub.add_argument("--count", type=int, default=8)
        sub.add_argument("--interval-ms", type=int, default=100)
        sub.add_argument("--timeout-ms", type=int, default=1000)
        sub.add_argument("--duration-ms", type=int, default=10_000)
        sub.add_argument("--payload-bytes", type=int, default=128)
        sub.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    if args.command == "new-nonces":
        # These nonces are public correlation IDs, not authentication credentials.
        public_nonces = {"run_nonce": secrets.token_hex(16), "round_nonce": secrets.token_hex(16)}
        print(json.dumps(public_nonces))
        return 0
    config = Config((args.bind_ip, args.bind_port), (args.target_ip, args.target_port),
                    args.run_nonce, args.round_nonce, args.count, args.interval_ms,
                    args.timeout_ms, args.duration_ms, args.payload_bytes)
    try:
        config.validate()
        validate_output_path(args.output)
        report = run_probe(config) if args.command == "probe" else run_echo(
            config, on_ready=lambda: print(json.dumps({"scope": SCOPE, "event": "echo_ready"}), flush=True))
        write_report(args.output, report)
    except (OSError, ValueError) as error:
        print(f"udp-business-probe: {error}", file=sys.stderr)
        return 2
    print(json.dumps({"scope": SCOPE, "role": args.command,
                      "termination_reason": report["termination_reason"]}))
    if args.command == "probe":
        return int(any(record["status"] != "success" for record in report["requests"]))
    return int(report["termination_reason"] not in ("duration_deadline", "request_budget_exhausted")
               or report["send_errors"] != 0)


if __name__ == "__main__":
    raise SystemExit(main())
