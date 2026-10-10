#!/usr/bin/env python3
"""Release the simulator's Direct gate for one shared Hard<->Hard plan."""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable


EVENT_RE = re.compile(r'\bevent="hard_hard_start_activated"')
FIELD_RE = re.compile(r'\b([a-z_]+)=(?:"([^"\\]*(?:\\.[^"\\]*)*)"|([^\s]+))')
REQUIRED_FIELDS = (
    "session_tag",
    "plan_tag",
    "role",
    "punch_at_ms",
    "punch_at_server_ms",
    "clock_domain",
    "network_generation",
    "remote_candidate_epoch",
    "local_profile_generation",
    "remote_profile_generation",
)
SHARED_HOST_CLOCK_DOMAIN = "host_unix_ms"


class GateError(ValueError):
    """A fail-closed rendezvous-gate validation error."""


class GatePending(GateError):
    """A missing or not-yet-paired activation within the original deadline."""


@dataclass(frozen=True)
class RendezvousMarker:
    session_tag: str
    plan_tag: str
    role: str
    punch_at_ms: int
    punch_at_server_ms: int
    clock_domain: str
    network_generation: int
    remote_candidate_epoch: int
    local_profile_generation: int
    remote_profile_generation: int
    remote_network_generation: int | None


@dataclass(frozen=True)
class RendezvousPair:
    node_a: RendezvousMarker
    node_b: RendezvousMarker


@dataclass(frozen=True)
class GatePlan:
    node_a_punch_at_ms: int
    node_b_punch_at_ms: int
    rendezvous_skew_ms: int
    release_at_ms: int
    planned_wait_ms: int
    lead_ms: int
    session_tag: str = ""
    plan_tag: str = ""
    node_a_role: str = "unknown"
    node_b_role: str = "unknown"
    node_a_network_generation: int | None = None
    node_b_network_generation: int | None = None
    node_a_remote_candidate_epoch: int | None = None
    node_b_remote_candidate_epoch: int | None = None
    node_a_local_profile_generation: int | None = None
    node_b_local_profile_generation: int | None = None
    node_a_remote_profile_generation: int | None = None
    node_b_remote_profile_generation: int | None = None
    punch_at_server_ms: int | None = None
    clock_domain: str = SHARED_HOST_CLOCK_DOMAIN


def _field_map(line: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for match in FIELD_RE.finditer(line):
        key = match.group(1)
        value = match.group(2) if match.group(2) is not None else match.group(3)
        result[key] = value
    return result


def _required_int(fields: dict[str, str], name: str, path: Path) -> int:
    value = fields.get(name)
    if value is None or len(value) > 20 or not value.isdecimal():
        raise GateError(f"rendezvous_field_invalid:{path.name}:{name}")
    return int(value)


def _parse_marker(line: str, path: Path, line_number: int) -> RendezvousMarker | None:
    if not EVENT_RE.search(line):
        return None
    fields = _field_map(line)
    for name in REQUIRED_FIELDS:
        if name not in fields:
            raise GateError(
                f"rendezvous_identity_missing:{path.name}:line_{line_number}:{name}"
            )
    for name in ("session_tag", "plan_tag"):
        if re.fullmatch(r"[0-9a-f]{16}", fields[name]) is None:
            raise GateError(f"rendezvous_tag_invalid:{path.name}:{name}")
    role = fields["role"]
    if role not in {"initiator", "responder"}:
        raise GateError(f"rendezvous_role_invalid:{path.name}")
    remote_network_generation = fields.get("remote_network_generation")
    if remote_network_generation in (None, "unknown", "none"):
        parsed_remote_network_generation = None
    elif len(remote_network_generation) <= 20 and remote_network_generation.isdecimal():
        parsed_remote_network_generation = int(remote_network_generation)
    else:
        raise GateError(f"rendezvous_field_invalid:{path.name}:remote_network_generation")
    return RendezvousMarker(
        session_tag=fields["session_tag"],
        plan_tag=fields["plan_tag"],
        role=role,
        punch_at_ms=_required_int(fields, "punch_at_ms", path),
        punch_at_server_ms=_required_int(fields, "punch_at_server_ms", path),
        clock_domain=fields["clock_domain"],
        network_generation=_required_int(fields, "network_generation", path),
        remote_candidate_epoch=_required_int(
            fields, "remote_candidate_epoch", path
        ),
        local_profile_generation=_required_int(
            fields, "local_profile_generation", path
        ),
        remote_profile_generation=_required_int(
            fields, "remote_profile_generation", path
        ),
        remote_network_generation=parsed_remote_network_generation,
    )


def extract_rendezvous_markers(path: Path) -> list[RendezvousMarker]:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        raise GateError(f"rendezvous_log_unreadable:{path.name}") from exc
    markers = [marker for number, line in enumerate(lines, 1)
               if (marker := _parse_marker(line, path, number)) is not None]
    if not markers:
        raise GatePending(f"rendezvous_marker_missing:{path.name}")
    return markers


class ActivationLog:
    """One bounded append-only observation, never daemon owner authority."""

    def __init__(self, path: Path, max_log_bytes: int, max_markers: int):
        self.path = path
        self.max_log_bytes = max_log_bytes
        self.max_markers = max_markers
        self.offset = 0
        self.identity = None
        self.partial = b""
        self.line_number = 0
        self.markers: list[RendezvousMarker] = []
        self.terminal = False

    def read(self) -> None:
        try:
            with self.path.open("rb") as source:
                stat = os.fstat(source.fileno())
                identity = (stat.st_dev, stat.st_ino)
                if self.identity is not None and (identity != self.identity or stat.st_size < self.offset):
                    raise GateError(f"rendezvous_coverage_log_replaced:{self.path.name}")
                self.identity = identity
                if stat.st_size > self.max_log_bytes:
                    raise GateError(f"rendezvous_coverage_log_bytes:{self.path.name}")
                source.seek(self.offset)
                while self.offset < stat.st_size:
                    data = source.read(min(65536, stat.st_size - self.offset))
                    if not data:
                        raise GateError(f"rendezvous_coverage_short_read:{self.path.name}")
                    self.offset += len(data)
                    lines = (self.partial + data).split(b"\n")
                    self.partial = lines.pop()
                    if len(self.partial) > 65536 or any(len(line) > 65536 for line in lines):
                        raise GateError(f"rendezvous_coverage_line_bytes:{self.path.name}")
                    for raw in lines:
                        self.line_number += 1
                        line = raw.decode("utf-8", errors="replace")
                        self.terminal |= bool(re.search(r'\bevent="hard_hard_attempt_report"', line))
                        marker = _parse_marker(line, self.path, self.line_number)
                        if marker is not None:
                            if len(self.markers) >= self.max_markers:
                                raise GateError(f"rendezvous_coverage_markers:{self.path.name}")
                            self.markers.append(marker)
        except FileNotFoundError as exc:
            if self.identity is not None:
                raise GateError(f"rendezvous_coverage_log_removed:{self.path.name}") from exc
        except OSError as exc:
            raise GateError(f"rendezvous_log_unreadable:{self.path.name}") from exc

    def has_partial_line(self) -> bool:
        return bool(self.partial)

    def require_complete_line(self, *, allow_pending: bool = False) -> None:
        # An unfinished line cannot establish absence of a later owner, even
        # if not enough of the activation tag has arrived to identify it yet.
        if self.has_partial_line():
            if allow_pending:
                raise GatePending(f"rendezvous_log_line_pending:{self.path.name}")
            raise GateError(f"rendezvous_coverage_partial_line:{self.path.name}")


def observed_pair(
    logs: tuple[ActivationLog, ActivationLog], *, allow_pending: bool = False,
) -> RendezvousPair:
    for log in logs:
        log.read()
    for log in logs:
        log.require_complete_line(allow_pending=allow_pending)
        if not log.markers:
            raise GatePending(f"rendezvous_marker_missing:{log.path.name}")
    return select_common_rendezvous(logs[0].markers, logs[1].markers)


def recheck_pair(logs: tuple[ActivationLog, ActivationLog], expected: RendezvousPair) -> None:
    # This snapshot is adjacent to gate creation, not an atomic lock on a
    # daemon that may append again. Runtime sender fences remain authoritative.
    if observed_pair(logs) != expected:
        raise GateError("rendezvous_owner_changed_before_write")


def _deduplicate_markers(markers: list[RendezvousMarker], side: str) -> list[RendezvousMarker]:
    by_plan: dict[str, RendezvousMarker] = {}
    ordered: list[RendezvousMarker] = []
    for marker in markers:
        previous = by_plan.get(marker.plan_tag)
        if previous is not None:
            if previous != marker:
                raise GateError(f"rendezvous_duplicate_conflict:{side}:{marker.plan_tag}")
            continue
        by_plan[marker.plan_tag] = marker
        ordered.append(marker)
    return ordered


def select_common_rendezvous(
    node_a_markers: list[RendezvousMarker], node_b_markers: list[RendezvousMarker]
) -> RendezvousPair:
    """Select the latest plan only when both sides record that exact owner."""
    node_a = _deduplicate_markers(node_a_markers, "a")
    node_b = _deduplicate_markers(node_b_markers, "b")
    latest_a = node_a[-1]
    latest_b = node_b[-1]
    if latest_a.plan_tag != latest_b.plan_tag:
        raise GatePending(
            "rendezvous_latest_plan_unpaired:"
            f"a={latest_a.plan_tag}:b={latest_b.plan_tag}"
        )
    if latest_a.session_tag != latest_b.session_tag:
        raise GateError("rendezvous_session_tag_mismatch")
    if latest_a.punch_at_server_ms != latest_b.punch_at_server_ms:
        raise GateError("rendezvous_server_deadline_mismatch")
    if latest_a.clock_domain != SHARED_HOST_CLOCK_DOMAIN or latest_b.clock_domain != SHARED_HOST_CLOCK_DOMAIN:
        raise GateError("rendezvous_clock_domain_not_shared_host")
    if latest_a.role == latest_b.role:
        raise GateError("rendezvous_roles_not_reciprocal")

    # These values are endpoint-local generations. Compare only the fields the
    # protocol reciprocally echoes; never compare two local attempt counters.
    for left, right, name in (
        (latest_a.local_profile_generation, latest_b.remote_profile_generation, "a_local_b_remote_profile"),
        (latest_a.remote_profile_generation, latest_b.local_profile_generation, "a_remote_b_local_profile"),
    ):
        if left != right:
            raise GateError(f"rendezvous_epoch_mismatch:{name}")
    if (
        latest_a.remote_network_generation is not None
        and latest_a.remote_network_generation != latest_b.network_generation
    ):
        raise GateError("rendezvous_epoch_mismatch:a_remote_b_local_network")
    if (
        latest_b.remote_network_generation is not None
        and latest_b.remote_network_generation != latest_a.network_generation
    ):
        raise GateError("rendezvous_epoch_mismatch:b_remote_a_local_network")
    return RendezvousPair(node_a=latest_a, node_b=latest_b)


def plan_gate(
    pair: RendezvousPair,
    now_ms: int,
    *,
    max_skew_ms: int,
    lead_ms: int,
    max_future_ms: int,
    max_late_ms: int,
) -> GatePlan:
    node_a = pair.node_a
    node_b = pair.node_b
    if min(node_a.punch_at_ms, node_b.punch_at_ms, now_ms) < 0:
        raise GateError("negative_timestamp")
    skew_ms = abs(node_a.punch_at_ms - node_b.punch_at_ms)
    if skew_ms > max_skew_ms:
        raise GateError(f"rendezvous_skew_exceeded:{skew_ms}")
    earliest_punch_at_ms = min(node_a.punch_at_ms, node_b.punch_at_ms)
    if now_ms > earliest_punch_at_ms + max_late_ms:
        raise GateError(f"rendezvous_deadline_elapsed:{now_ms - earliest_punch_at_ms}")
    release_at_ms = earliest_punch_at_ms - lead_ms
    wait_ms = max(0, release_at_ms - now_ms)
    if wait_ms > max_future_ms:
        raise GateError(f"rendezvous_deadline_too_far:{wait_ms}")
    return GatePlan(
        node_a_punch_at_ms=node_a.punch_at_ms,
        node_b_punch_at_ms=node_b.punch_at_ms,
        rendezvous_skew_ms=skew_ms,
        release_at_ms=release_at_ms,
        planned_wait_ms=wait_ms,
        lead_ms=lead_ms,
        session_tag=node_a.session_tag,
        plan_tag=node_a.plan_tag,
        node_a_role=node_a.role,
        node_b_role=node_b.role,
        node_a_network_generation=node_a.network_generation,
        node_b_network_generation=node_b.network_generation,
        node_a_remote_candidate_epoch=node_a.remote_candidate_epoch,
        node_b_remote_candidate_epoch=node_b.remote_candidate_epoch,
        node_a_local_profile_generation=node_a.local_profile_generation,
        node_b_local_profile_generation=node_b.local_profile_generation,
        node_a_remote_profile_generation=node_a.remote_profile_generation,
        node_b_remote_profile_generation=node_b.remote_profile_generation,
        punch_at_server_ms=node_a.punch_at_server_ms,
        clock_domain=node_a.clock_domain,
    )


def write_exclusive(path: Path, payload: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        pending = memoryview(payload)
        while pending:
            written = os.write(descriptor, pending)
            if written <= 0:
                raise OSError("gate_write_incomplete")
            pending = pending[written:]
    finally:
        os.close(descriptor)


def release_gate(
    plan: GatePlan,
    gate_path: Path,
    evidence_path: Path,
    *,
    max_late_ms: int,
    now_ms: Callable[[], int] = lambda: time.time_ns() // 1_000_000,
    sleep: Callable[[float], None] = time.sleep,
    revalidate: Callable[[], None] | None = None,
    deadline_ms: int | None = None,
) -> dict[str, int | str | None]:
    if deadline_ms is not None and plan.release_at_ms >= deadline_ms:
        raise GateError("rendezvous_watch_deadline_before_release")
    remaining_ms = plan.release_at_ms - now_ms()
    if remaining_ms > 0:
        sleep(remaining_ms / 1000)
    if revalidate is not None:
        revalidate()
    released_at_ms = now_ms()
    if deadline_ms is not None and released_at_ms >= deadline_ms:
        raise GateError("rendezvous_watch_deadline_elapsed")
    earliest_punch_at_ms = min(plan.node_a_punch_at_ms, plan.node_b_punch_at_ms)
    if released_at_ms > earliest_punch_at_ms + max_late_ms:
        raise GateError(
            f"rendezvous_release_late:{released_at_ms - earliest_punch_at_ms}"
        )
    write_exclusive(gate_path, b"")
    evidence: dict[str, int | str | None] = {
        "schema_version": 2,
        **asdict(plan),
        "released_at_ms": released_at_ms,
        "release_offset_from_earliest_punch_ms": (
            released_at_ms - earliest_punch_at_ms
        ),
        "result": "released",
    }
    write_exclusive(
        evidence_path,
        (json.dumps(evidence, sort_keys=True, indent=2) + "\n").encode("utf-8"),
    )
    return evidence


def watch_gate(
    *, node_a_log: Path, node_b_log: Path, gate_path: Path,
    evidence_path: Path, armed_path: Path, deadline_ms: int,
    max_skew_ms: int = 250, lead_ms: int = 10, max_future_ms: int = 5000,
    max_late_ms: int = 25, max_log_bytes: int = 16 * 1024 * 1024,
    max_markers: int = 128,
    now_ms: Callable[[], int] = lambda: time.time_ns() // 1_000_000,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
) -> dict:
    started_at_ms = now_ms()
    remaining_ms = deadline_ms - started_at_ms
    monotonic_deadline = monotonic() + max(0, remaining_ms) / 1000

    def check_deadline() -> None:
        if now_ms() >= deadline_ms or monotonic() >= monotonic_deadline:
            raise GateError("rendezvous_watch_deadline_elapsed")

    def bounded_release_sleep(seconds: float) -> None:
        check_deadline()
        remaining_seconds = monotonic_deadline - monotonic()
        if remaining_seconds <= 0:
            raise GateError("rendezvous_watch_deadline_elapsed")
        sleep(min(seconds, remaining_seconds))
        check_deadline()

    logs = (ActivationLog(node_a_log, max_log_bytes, max_markers),
            ActivationLog(node_b_log, max_log_bytes, max_markers))
    try:
        if not (0 < max_log_bytes <= 64 * 1024 * 1024 and 0 < max_markers <= 1024):
            raise GateError("rendezvous_watch_limit_invalid")
        if remaining_ms > 20_000:
            raise GateError("rendezvous_watch_deadline_too_far")
        check_deadline()
        write_exclusive(armed_path, b"armed\n")
        while now_ms() < deadline_ms and monotonic() < monotonic_deadline:
            try:
                pair = observed_pair(logs, allow_pending=True)
            except GatePending:
                if (all(log.terminal for log in logs) and not all(log.markers for log in logs)
                        and not any(log.has_partial_line() for log in logs)):
                    result = {"schema_version": 2, "result": "terminal_before_rendezvous",
                              "reason_code": "rendezvous_terminal_before_activation"}
                    break
                bounded_release_sleep(min(5, max(0, deadline_ms - now_ms())) / 1000)
                continue
            plan = plan_gate(pair, now_ms(), max_skew_ms=max_skew_ms,
                             lead_ms=lead_ms, max_future_ms=max_future_ms,
                             max_late_ms=max_late_ms)
            def revalidate() -> None:
                check_deadline()
                recheck_pair(logs, pair)
                check_deadline()

            return release_gate(plan, gate_path, evidence_path, max_late_ms=max_late_ms,
                                now_ms=now_ms, sleep=bounded_release_sleep, deadline_ms=deadline_ms,
                                revalidate=revalidate)
        else:
            raise GateError("rendezvous_watch_deadline_elapsed")
    except (GateError, OSError) as exc:
        result = {"schema_version": 2, "result": "rejected",
                  "reason_code": str(exc) if isinstance(exc, GateError) else "rendezvous_gate_io_failed"}
    write_exclusive(evidence_path, (json.dumps(result, sort_keys=True, indent=2) + "\n").encode())
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-a-log", required=True, type=Path)
    parser.add_argument("--node-b-log", required=True, type=Path)
    parser.add_argument("--gate-file", required=True, type=Path)
    parser.add_argument("--evidence-file", required=True, type=Path)
    parser.add_argument("--watch", action="store_true")
    parser.add_argument("--armed-file", type=Path)
    parser.add_argument("--deadline-ms", type=int)
    parser.add_argument("--max-log-bytes", type=int, default=16 * 1024 * 1024)
    parser.add_argument("--max-markers", type=int, default=128)
    parser.add_argument("--max-skew-ms", type=int, default=250)
    parser.add_argument("--lead-ms", type=int, default=10)
    parser.add_argument("--max-future-ms", type=int, default=5000)
    parser.add_argument("--max-late-ms", type=int, default=25)
    args = parser.parse_args()
    for name in ("max_skew_ms", "lead_ms", "max_future_ms", "max_late_ms"):
        if getattr(args, name) < 0:
            parser.error(f"--{name.replace('_', '-')} must be non-negative")
    if args.watch and (args.armed_file is None or args.deadline_ms is None):
        parser.error("--watch requires --armed-file and --deadline-ms")
    if not (0 < args.max_log_bytes <= 64 * 1024 * 1024 and 0 < args.max_markers <= 1024):
        parser.error("watch capacity exceeds bounded limits")
    return args


def main() -> int:
    args = parse_args()
    try:
        if args.watch:
            def cancel_watch(_signal, _frame):
                raise GateError("rendezvous_watch_cancelled")
            signal.signal(signal.SIGTERM, cancel_watch)
            evidence = watch_gate(node_a_log=args.node_a_log, node_b_log=args.node_b_log,
                                  gate_path=args.gate_file, evidence_path=args.evidence_file,
                                  armed_path=args.armed_file, deadline_ms=args.deadline_ms,
                                  max_skew_ms=args.max_skew_ms, lead_ms=args.lead_ms,
                                  max_future_ms=args.max_future_ms, max_late_ms=args.max_late_ms,
                                  max_log_bytes=args.max_log_bytes, max_markers=args.max_markers)
            print(json.dumps(evidence, sort_keys=True))
            return 0 if evidence["result"] in {"released", "terminal_before_rendezvous"} else 1
        logs = (ActivationLog(args.node_a_log, args.max_log_bytes, args.max_markers),
                ActivationLog(args.node_b_log, args.max_log_bytes, args.max_markers))
        pair = observed_pair(logs)
        now_ms = time.time_ns() // 1_000_000
        plan = plan_gate(
            pair,
            now_ms,
            max_skew_ms=args.max_skew_ms,
            lead_ms=args.lead_ms,
            max_future_ms=args.max_future_ms,
            max_late_ms=args.max_late_ms,
        )
        evidence = release_gate(
            plan,
            args.gate_file,
            args.evidence_file,
            max_late_ms=args.max_late_ms,
            revalidate=lambda: recheck_pair(logs, pair),
        )
    except (GateError, OSError) as exc:
        print(f"hard_hard_gate_error={exc}", file=os.sys.stderr)
        return 1
    print(
        "hard_hard_gate_released=1 "
        f"plan_tag={plan.plan_tag} "
        f"skew_ms={evidence['rendezvous_skew_ms']} "
        f"release_offset_ms={evidence['release_offset_from_earliest_punch_ms']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
