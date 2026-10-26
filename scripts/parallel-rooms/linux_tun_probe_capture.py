"""Owned, bounded pipe observations for the original fixed-eight probe child.

This observes OS writes only. It cannot register a daemon request or grant TUN,
physical-send, or current-connection-owner authority.
"""
from __future__ import annotations

from dataclasses import asdict
import hashlib
import os
from pathlib import Path
import re
import secrets
import sys
import time

DUAL = Path(__file__).resolve().parents[1] / "dual-end"
if str(DUAL) not in sys.path:
    sys.path.insert(0, str(DUAL))
import probe_request_plan as plans
import probe_write_stream as streams
import udp_business_probe as udp
import probe_completion_barrier as handoff

MAX_PROBES = 4
MAX_FINAL_READS = streams.facts.MAX_BYTES // streams.MAX_CHUNK_BYTES + 2


def unavailable(reason: str) -> dict:
    return {
        "schema_version": 1, "scope": "original_child_os_write_stream_only",
        "request_count": 8, "stream_complete": False, "gap_reason": reason,
        "requests": [{"sequence": i, "request_nonce": None,
                      "accepted_in_original_deadline": False} for i in range(8)],
        "original_child_birth_namespace_matched": False,
        "original_same_boot_clock_matched": False,
        "daemon_registration_verified": False, "kernel_tun_verified": False,
        "physical_send_verified": False, "canonical_current_owner_verified": False,
    }


class ProbeCapture:
    def __init__(self, root: Path, stem: str, config, transport: str,
                 capture_id: str, producer_scope: str, namespace: str | None, *, defer_pipe=False):
        if not isinstance(stem, str) or re.fullmatch(r"[a-z0-9-]+", stem) is None:
            raise ValueError("original_capture_stem_invalid")
        self.reader = self.writer = None
        self.pipe_opened = False
        self.closed = False
        self.stream = None
        self.raw = bytearray()
        self.eof = False
        self.gap = None
        self.result = None
        self.live_window_bridge = None
        self.completion_barrier_path = None
        self.config, self.transport, self.namespace = config, transport, namespace
        self.plan_path = root / (stem + "-request-plan.json")
        self.raw_path = root / (stem + "-write-stream.jsonl")
        self.result_path = root / (stem + "-write-stream.json")
        document = plans.make_plan(config, transport, capture_id, producer_scope)
        udp.write_report(self.plan_path, document)
        self.prepared = plans.load_plan(self.plan_path, config, transport,
                                       document["tool_sha256"], document["shared_config_tool_sha256"])
        if not defer_pipe:
            self._open_pipe()

    def _open_pipe(self) -> None:
        if self.pipe_opened or self.closed or self.stream is not None or self.result is not None or self.gap is not None:
            raise ValueError("original_capture_pipe_already_admitted_or_closed")
        self.pipe_opened = True  # An acquisition failure never admits a retry.
        try:
            self.reader, self.writer = os.pipe()
            os.set_blocking(self.reader, False)
            os.set_blocking(self.writer, False)
        except BaseException:
            self.close()
            raise

    def arguments(self) -> list[str]:
        if self.writer is None or self.stream is not None:
            raise ValueError("original_capture_not_prepared")
        arguments = ["--request-plan", str(self.plan_path), "--write-facts-fd", str(self.writer)]
        if self.completion_barrier_path is not None:
            arguments.extend(["--completion-barrier", str(self.completion_barrier_path)])
        return arguments

    def _close(self, name: str) -> None:
        descriptor = getattr(self, name)
        if descriptor is not None:
            setattr(self, name, None)  # Never retry a possibly reused fd after close failure.
            try:
                os.close(descriptor)
            except OSError:
                self.gap = self.gap or "owned_capture_descriptor_close_failed"

    def close(self) -> None:
        self.closed = True
        if self.live_window_bridge is not None:
            self.live_window_bridge.seal()
        self._close("writer")
        self._close("reader")

    def enable_live_window_bridge(self, endpoints) -> None:
        from linux_tun_live_window import OriginalWriteWindows
        if self.live_window_bridge is not None or self.stream is not None:
            raise ValueError("original_window_bridge_already_bound")
        if self.transport == "tcp":
            self.completion_barrier_path = self.plan_path.with_name(
                self.plan_path.name.replace("-request-plan.json", "-window-handoff.json"))
            handoff.validate_destination(self.completion_barrier_path)
        self.live_window_bridge = OriginalWriteWindows(self, endpoints)

    def bind(self, groups, child) -> None:
        try:
            owners = [owner for owner in groups.owners if owner["child"] is child]
            if (len(owners) != 1 or child.returncode is not None
                    or owners[0]["anchor"].returncode is not None):
                raise ValueError("original_unreaped_probe_owner_missing")
            original = streams.OriginalChild.from_spawn(
                child, owners[0]["child_spawn_requested_monotonic_ns"], self.namespace)
            self.stream = streams.WriteStream(self.config, self.prepared, self.transport, original)
            if self.live_window_bridge is not None:
                self.live_window_bridge.bind(self, child)
        except (OSError, ValueError, KeyError) as error:
            self.gap = "original_capture_bind_failed:" + type(error).__name__
            self._close("reader")
        finally:
            self._close("writer")  # Only the original child retains the inherited write end.

    def drain(self, *, live: bool = True) -> None:
        """At most one nonblocking 4096-byte read; no sleep, poll, PID lookup or retry."""
        if self.reader is None or self.gap is not None:
            return
        try:
            raw = os.read(self.reader, streams.MAX_CHUNK_BYTES)
        except BlockingIOError:
            return
        except OSError:
            self.gap = "owned_capture_read_failed"
            self._close("reader")
            return
        if not raw:
            self.eof = True
            self._close("reader")
            return
        if self.stream is None or len(self.raw) + len(raw) > streams.facts.MAX_BYTES:
            self.gap = "owned_capture_stream_missing_or_capacity"
            self._close("reader")
            return
        self.raw.extend(raw)
        self.stream.feed(raw)
        if self.stream.gap is not None:
            self.gap = self.stream.gap
            self._close("reader")
        elif live and self.live_window_bridge is not None:
            self.live_window_bridge.observe(self, time.monotonic_ns())

    def finish(self, report: dict | None) -> dict:
        if self.result is not None:
            return self.result
        if self.live_window_bridge is not None:
            self.live_window_bridge.seal()
        # Called only after the original wait completed. Drain already-written
        # bytes without introducing a new deadline or waiting for another writer.
        for _ in range(MAX_FINAL_READS):
            before = len(self.raw)
            self.drain(live=False)
            if self.reader is None or len(self.raw) == before:
                break
        if not self.eof:
            self.gap = self.gap or "original_writer_EOF_missing"
        if report is None:
            self.gap = self.gap or "original_probe_report_missing"
        if self.stream is None:
            result = unavailable(self.gap or "original_stream_missing")
        else:
            self.stream.gap = self.stream.gap or self.gap
            result = self.stream.finish(report, time.monotonic_ns())
        self.close()
        if self.gap is not None:
            result.update(stream_complete=False, gap_reason=self.gap)
            for request in result["requests"]:
                request["accepted_in_original_deadline"] = False
        result.update(plan_file=self.plan_path.name, plan_sha256=self.prepared.sha256,
                      raw_file=self.raw_path.name, raw_sha256=hashlib.sha256(self.raw).hexdigest(),
                      producer_scope=self.prepared.producer_scope,
                      capture_id=self.prepared.capture_id,
                      original_child_binding=asdict(self.stream.child) if self.stream else None)
        try:
            udp.validate_output_path(self.raw_path)
            descriptor = os.open(self.raw_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as output:
                os.fchmod(output.fileno(), 0o600)
                output.write(self.raw)
            udp.write_report(self.result_path, result)
        except (OSError, ValueError):
            result.update(stream_complete=False, gap_reason="owned_capture_output_failed")
            for request in result["requests"]:
                request["accepted_in_original_deadline"] = False
        self.raw.clear()
        self.result = result
        return result


class WriteCaptures:
    def __init__(self, root: Path, expected_probes: int):
        if os.name != "posix" or expected_probes not in (2, 4):
            raise ValueError("fixed_original_POSIX_capture_scope_required")
        self.root, self.expected_probes = root, expected_probes
        self.capture_id = secrets.token_hex(16)
        self.scopes, self.nonces, self.captures = set(), set(), []

    def prepare(self, groups, entry: dict, transport: str, bind: tuple,
                target: tuple, stem: str, namespace_name: str, *, defer_pipe=False) -> ProbeCapture | None:
        capture = None
        if len(self.captures) >= self.expected_probes:
            entry["original_write_stream"] = unavailable("original_capture_registry_full")
            return None
        self.captures.append((entry, None))  # Admission precedes file/pipe acquisition.
        try:
            if not defer_pipe and any(c is not None and (c.reader is not None or c.writer is not None)
                                     for _, c in self.captures):
                raise ValueError("previous_original_capture_still_open")
            config = udp.Config(bind, target, entry["run_nonce"], entry["round_nonce"], entry["count"],
                                entry["interval_ms"], entry["timeout_ms"], entry["duration_ms"], entry["payload_bytes"])
            if (config.count, config.interval_ms, config.timeout_ms, config.duration_ms,
                    config.payload_bytes) != (8, 100, 1000, 10000, 128):
                raise ValueError("original_fixed8_configuration_changed")
            scope = secrets.token_hex(16)
            if scope in self.scopes:
                raise ValueError("producer_scope_collision_no_retry")
            namespace = None
            if sys.platform == "linux":
                if namespace_name not in getattr(groups, "owned_namespace_names", ()):
                    raise ValueError("original_created_namespace_missing")
                namespace = "net:[" + str(os.stat("/var/run/netns/" + namespace_name).st_ino) + "]"
            capture = ProbeCapture(self.root, stem, config, transport, self.capture_id, scope, namespace,
                                   defer_pipe=defer_pipe)
            if self.nonces.intersection(capture.prepared.nonces):
                raise ValueError("cross_probe_nonce_collision_no_retry")
            self.scopes.add(scope)
            self.nonces.update(capture.prepared.nonces)
            self.captures[-1] = entry, capture
            return capture
        except (OSError, ValueError) as error:
            if capture is not None:
                capture.close()
            entry["original_write_stream"] = unavailable("capture_prepare_failed:" + type(error).__name__)
            return None

    def activate(self, capture: ProbeCapture) -> None:
        # Plans may be registered before either phase sends traffic. Only the
        # original registry admits a pipe, after the previous pipe is closed.
        if (capture is None or sum(c is capture for _, c in self.captures) != 1
                or any(c is not None and (c.reader is not None or c.writer is not None)
                       for _, c in self.captures)):
            raise ValueError("original_capture_owner_missing_or_previous_pipe_open")
        capture._open_pipe()

    def close(self) -> None:
        for entry, capture in self.captures:
            if capture is not None:
                capture.close()
                if capture.result is None:
                    entry["original_write_stream"] = unavailable(capture.gap or "original_probe_report_missing")

    def persist_interrupted(self) -> None:
        # Run after original process/network cleanup; never delay a group signal
        # or use a received PID to reconstruct missing process identity.
        for entry, capture in self.captures:
            if capture is not None and capture.result is None:
                entry["original_write_stream"] = capture.finish(None)

    def summary(self, entries: list[dict]) -> dict:
        results = [entry.get("original_write_stream") for entry in entries]
        complete = len(entries) == self.expected_probes and all(
            isinstance(r, dict) and r["request_count"] == 8 and r["stream_complete"] is True
            and r["original_child_birth_namespace_matched"] is True
            and r["original_same_boot_clock_matched"] is True for r in results)
        return dict(scope="original_owned_probe_OS_writes_only", capture_id=self.capture_id,
                    prescheduled_requests=self.expected_probes * 8, admitted_probes=len(self.captures),
                    complete_probes=sum(isinstance(r, dict) and r["stream_complete"] is True for r in results),
                    passed=complete, daemon_registration_verified=False, kernel_tun_verified=False,
                    physical_send_verified=False, canonical_current_owner_verified=False)
