"""One-shot live delivery from the original owned pipe.

These are controller observations. Neither delivery nor their JSON creates a
native OS-write fact, TUN read, physical Full, current peer, or once authority.
After TCP's final window, one bounded terminal-metadata handoff precedes close.
"""
from __future__ import annotations

from pathlib import Path
import sys
import weakref

DUAL = Path(__file__).resolve().parents[1] / "dual-end"
if str(DUAL) not in sys.path:
    sys.path.insert(0, str(DUAL))
import probe_completion_barrier as handoff


class OriginalWriteWindows:
    def __init__(self, capture, endpoints):
        if len(endpoints) != 2 or endpoints[0] is endpoints[1]:
            raise ValueError("original_window_two_distinct_endpoints_required")
        self.capture = weakref.ref(capture)
        self.endpoints = tuple(endpoints)
        self.child = self.original = None
        self.closed = False
        self.gap = None
        self.requests = [dict(sequence=i, delivered=False, reason="original_complete_write_not_observed")
                         for i in range(8)]
        self.seen = set()
        self.handoff_published = False

    def bind(self, capture, child):
        if self.closed or self.child is not None or self.capture() is not capture or capture.stream is None:
            raise ValueError("original_window_bind_scope_or_lifecycle")
        self.child, self.original = child, capture.stream.child

    def observe(self, capture, observed_ns):
        # Called only after the existing single nonblocking pipe read/feed,
        # before the original poll/wait. No received PID is inspected here.
        if self.closed or self.gap is not None:
            return
        stream = capture.stream
        if (self.capture() is not capture or self.child is None or self.child.returncode is not None
                or stream is None or stream.child is not self.original or stream.gap is not None):
            self.gap = "original_window_owner_or_stream_unavailable"
            return
        if self.original.unavailable_reason is not None:
            self.gap = "original_window_birth_and_same_boot_unavailable"
            return
        # The ordered source/owner/clock headers can span original pipe reads.
        # Incomplete input has not established either identity or a failure;
        # it cannot deliver a window. Parser errors remain terminal above.
        if stream.records < len(stream.headers):
            return
        if not stream.owner_verified or not stream.clock_verified:
            self.gap = "original_window_birth_and_same_boot_unavailable"
            return
        if len(stream.requests) != 8 or [r["sequence"] for r in stream.requests] != list(range(8)):
            self.gap = "original_window_fixed_eight_missing"
            return
        for row in stream.requests:  # The original fixed eight, never a queue.
            i = row["sequence"]
            if i in self.seen or not stream.accepted_in_time(row):
                continue
            self.seen.add(i)  # First complete outcome cannot be repaired later.
            if not row["last_returned_ns"] <= observed_ns < row["original_deadline_ns"]:
                self.requests[i]["reason"] = "original_window_live_deadline_missed"
                continue
            size, digest = stream.expected_frames[i]
            window = dict(producer_scope=capture.prepared.producer_scope, sequence=i,
                          request_nonce=capture.prepared.nonces[i],
                          boot_id=self.original.boot_id, original_started_ns=stream.started,
                          original_sent_ns=row["original_sent_ns"], original_deadline_ns=row["original_deadline_ns"],
                          complete_returned_ns=row["last_returned_ns"], frame_bytes=size, frame_sha256=digest)
            self.requests[i] = self.deliver(window, observed_ns)
            if self.gap is not None:
                return
        path = getattr(capture, "completion_barrier_path", None)
        if (path is not None and len(self.seen) == 8 and not self.handoff_published
                and all(row["delivered"] is True for row in self.requests)):
            self.handoff_published = True  # First publication failure cannot rearm.
            try:
                deadline = self.requests[-1]["window"]["original_deadline_ns"]
                for endpoint in self.endpoints:
                    # Any recorded terminal, including refusal, releases close.
                    # No success flag is tested and no owner check is retried.
                    endpoint.wait_original_outcomes(capture.prepared.producer_scope, deadline)
                handoff.publish(path, capture.config.run_nonce, capture.config.round_nonce)
            except (OSError, ValueError):
                self.gap = "original_tcp_handoff_publication_failed"

    def deliver(self, window, observed_ns):
        delivered = 0
        try:
            for endpoint in self.endpoints:
                endpoint.observe_original_write_window(window)
                delivered += 1
        except (OSError, ValueError):
            self.gap = "original_window_nonblocking_delivery_failed"
        return dict(sequence=window["sequence"], delivered=delivered == 2,
                    delivered_endpoints=delivered, window=window,
                    controller_observed_ns=observed_ns,
                    reason=None if delivered == 2 else self.gap)

    def seal(self):
        # No final drain, control I/O, wait, retry or PID lookup after sealing.
        self.closed = True
        self.child = None
        self.endpoints = ()

    def summary(self):
        return dict(scope="original_controller_live_write_windows_only", request_count=8,
                    gap_reason=self.gap, requests=self.requests,
                    native_os_write_verified=False, physical_send_verified=False,
                    canonical_current_owner_verified=False)
