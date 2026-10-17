"""Opt-in, bounded original socket-write observations to an owned POSIX pipe.

Every JSON line is one nonblocking atomic write. No queue, retry, thread, or
reader is created. Pipe acceptance alone proves neither TUN nor daemon owner.
The controller must own the producer/pipe and validate source, plan, ordinal,
clock, finish, and current daemon bindings before using any observations.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import time

from probe_process_identity import current_identity

MAX_EVENTS = 8192
MAX_BYTES = 4 * 1024 * 1024
MAX_RECORD_BYTES = 512


class WriteFacts:
    def __init__(self, descriptor: int, prepared, config, transport: str, tool_sha256: str):
        if os.name != "posix":
            raise ValueError("write facts require a nonblocking writable POSIX pipe")
        import fcntl
        if type(descriptor) is not int or descriptor < 0 or prepared is None:
            raise ValueError("write facts require a descriptor and an exact request plan")
        root = Path(__file__).resolve().parent
        helpers = {
            "shared_tool_sha256": hashlib.sha256((root / "udp_business_probe.py").read_bytes()).hexdigest(),
            "plan_loader_sha256": prepared.loader_sha256,
            "observer_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "identity_sha256": hashlib.sha256((root / "probe_process_identity.py").read_bytes()).hexdigest(),
        }
        self.fd = os.dup(descriptor)
        try:
            flags = fcntl.fcntl(self.fd, fcntl.F_GETFL)
            if (not stat.S_ISFIFO(os.fstat(self.fd).st_mode)
                    or not flags & os.O_NONBLOCK or flags & os.O_ACCMODE == os.O_RDONLY
                    or os.fpathconf(self.fd, "PC_PIPE_BUF") < MAX_RECORD_BYTES):
                raise ValueError("write facts descriptor must already be a nonblocking writable pipe")
            owner, clock = current_identity()
        except BaseException:
            os.close(self.fd)
            raise
        self.pid = owner["pid"]
        self.events = self.bytes = 0
        self.gap = None
        self.closed = False
        self.started = None
        self.emit("source", plan_sha256=prepared.sha256, capture_id=prepared.capture_id,
                  producer_scope=prepared.producer_scope, transport=transport,
                  tool_sha256=tool_sha256)
        self.emit("helpers", **helpers)
        self.emit("owner", **owner)
        self.emit("clock", **clock)
        self.emit("request_set", run_nonce=config.run_nonce, round_nonce=config.round_nonce,
                  count=config.count, interval_ms=config.interval_ms, timeout_ms=config.timeout_ms,
                  duration_ms=config.duration_ms, payload_bytes=config.payload_bytes)

    def emit(self, kind: str, **fields) -> None:
        if self.gap is not None or self.closed:
            return
        try:
            if os.getpid() != self.pid:
                self.gap = "producer_process_changed"
                return
            raw = (json.dumps({"v": 1, "n": self.events, "kind": kind, **fields},
                              separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")
            if (len(raw) > MAX_RECORD_BYTES or self.events >= MAX_EVENTS
                    or self.bytes + len(raw) > MAX_BYTES):
                self.gap = "observation_capacity"
                return
            count = os.write(self.fd, raw)
            if count != len(raw):
                self.gap = "observation_short_write"
                return
            self.events += 1
            self.bytes += count
        except BlockingIOError:
            self.gap = "observation_pipe_full"
        except OSError:
            self.gap = "observation_pipe_failed"
        except Exception:
            self.gap = "observation_encoding_failed"

    def start(self, started: int, duration_ms: int) -> None:
        self.started = started
        self.emit("start", original_started_ns=started,
                  original_end_ns=started + duration_ms * 1_000_000)

    def socket(self, sock, target) -> None:
        try:
            identity = os.fstat(sock.fileno())
            self.emit("socket", device=identity.st_dev, inode=identity.st_ino,
                      family=int(sock.family), socket_type=int(sock.type),
                      local=list(sock.getsockname()), target=list(target))
        except Exception:
            self.gap = self.gap or "socket_identity_unavailable"

    def send(self, sock, data: bytes, *, sequence: int, sent: int, deadline: int,
             frame: bytes, offset: int = 0, target=None) -> int:
        before = time.monotonic_ns()
        try:
            count = sock.sendto(data, target) if target is not None else sock.send(data)
        except OSError as error:
            after = time.monotonic_ns()
            self.write(sequence, sent, deadline, frame, offset, len(data), None,
                       error.errno, before, after)
            raise
        after = time.monotonic_ns()
        self.write(sequence, sent, deadline, frame, offset, len(data), count,
                   None, before, after)
        return count

    def write(self, sequence, sent, deadline, frame, offset, requested, accepted,
              error_number, before, after) -> None:
        try:
            self.emit("write", sequence=sequence, original_sent_ns=sent,
                      original_deadline_ns=deadline, before_ns=before, returned_ns=after,
                      frame_sha256=hashlib.sha256(frame).hexdigest(), frame_bytes=len(frame),
                      offset=offset, requested=requested, accepted=accepted, errno=error_number)
        except Exception:
            self.gap = self.gap or "write_observation_failed"

    def finish(self, termination: str) -> dict:
        self.emit("finish", termination_reason=termination)
        if not self.closed:
            try:
                os.close(self.fd)
            except OSError:
                self.gap = self.gap or "observation_close_failed"
            self.closed = True
        return {"schema_version": 1, "scope": "original_os_socket_write_observations_only",
                "records_emitted": self.events, "bytes_emitted": self.bytes,
                "emission_gap_reason": self.gap, "original_started_ns": self.started,
                "daemon_registration_verified": False, "kernel_tun_verified": False}
