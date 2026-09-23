#!/usr/bin/env python3
"""Release the simulator's Direct gate for one shared Hard<->Hard plan."""

from __future__ import annotations

import argparse
import json
import os
import re
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable


EVENT_RE = re.compile(r'\bevent="hard_hard_rendezvous_scheduled"')
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
    if value is None or not value.isdecimal():
        raise GateError(f"rendezvous_field_invalid:{path.name}:{name}")
    return int(value)


def extract_rendezvous_markers(path: Path) -> list[RendezvousMarker]:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        raise GateError(f"rendezvous_log_unreadable:{path.name}") from exc

    markers: list[RendezvousMarker] = []
    for line_number, line in enumerate(lines, start=1):
        if not EVENT_RE.search(line):
            continue
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
        elif remote_network_generation.isdecimal():
            parsed_remote_network_generation = int(remote_network_generation)
        else:
            raise GateError(f"rendezvous_field_invalid:{path.name}:remote_network_generation")
        markers.append(
            RendezvousMarker(
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
        )
    if not markers:
        raise GateError(f"rendezvous_marker_missing:{path.name}")
    return markers


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
        raise GateError(
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
        os.write(descriptor, payload)
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
) -> dict[str, int | str | None]:
    remaining_ms = plan.release_at_ms - now_ms()
    if remaining_ms > 0:
        sleep(remaining_ms / 1000)
    released_at_ms = now_ms()
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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-a-log", required=True, type=Path)
    parser.add_argument("--node-b-log", required=True, type=Path)
    parser.add_argument("--gate-file", required=True, type=Path)
    parser.add_argument("--evidence-file", required=True, type=Path)
    parser.add_argument("--max-skew-ms", type=int, default=250)
    parser.add_argument("--lead-ms", type=int, default=10)
    parser.add_argument("--max-future-ms", type=int, default=5000)
    parser.add_argument("--max-late-ms", type=int, default=25)
    args = parser.parse_args()
    for name in ("max_skew_ms", "lead_ms", "max_future_ms", "max_late_ms"):
        if getattr(args, name) < 0:
            parser.error(f"--{name.replace('_', '-')} must be non-negative")
    return args


def main() -> int:
    args = parse_args()
    try:
        pair = select_common_rendezvous(
            extract_rendezvous_markers(args.node_a_log),
            extract_rendezvous_markers(args.node_b_log),
        )
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
        )
    except (GateError, FileExistsError) as exc:
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
