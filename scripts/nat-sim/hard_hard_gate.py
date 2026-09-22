#!/usr/bin/env python3
"""Release the simulator's Direct gate at a logged Hard<->Hard rendezvous."""

from __future__ import annotations

import argparse
import json
import os
import re
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable


RENDEZVOUS = re.compile(
    r'event="hard_hard_rendezvous_scheduled"[^\n]*\bpunch_at_ms=(\d+)'
)


class GateError(ValueError):
    """A fail-closed rendezvous-gate validation error."""


@dataclass(frozen=True)
class GatePlan:
    node_a_punch_at_ms: int
    node_b_punch_at_ms: int
    rendezvous_skew_ms: int
    release_at_ms: int
    planned_wait_ms: int
    lead_ms: int


def extract_punch_at_ms(path: Path) -> int:
    try:
        matches = RENDEZVOUS.findall(path.read_text(encoding="utf-8", errors="replace"))
    except OSError as exc:
        raise GateError(f"rendezvous_log_unreadable:{path.name}") from exc
    if not matches:
        raise GateError(f"rendezvous_marker_missing:{path.name}")
    return int(matches[-1])


def plan_gate(
    node_a_punch_at_ms: int,
    node_b_punch_at_ms: int,
    now_ms: int,
    *,
    max_skew_ms: int,
    lead_ms: int,
    max_future_ms: int,
    max_late_ms: int,
) -> GatePlan:
    if min(node_a_punch_at_ms, node_b_punch_at_ms, now_ms) < 0:
        raise GateError("negative_timestamp")
    skew_ms = abs(node_a_punch_at_ms - node_b_punch_at_ms)
    if skew_ms > max_skew_ms:
        raise GateError(f"rendezvous_skew_exceeded:{skew_ms}")
    earliest_punch_at_ms = min(node_a_punch_at_ms, node_b_punch_at_ms)
    if now_ms > earliest_punch_at_ms + max_late_ms:
        raise GateError(f"rendezvous_deadline_elapsed:{now_ms - earliest_punch_at_ms}")
    release_at_ms = earliest_punch_at_ms - lead_ms
    wait_ms = max(0, release_at_ms - now_ms)
    if wait_ms > max_future_ms:
        raise GateError(f"rendezvous_deadline_too_far:{wait_ms}")
    return GatePlan(
        node_a_punch_at_ms=node_a_punch_at_ms,
        node_b_punch_at_ms=node_b_punch_at_ms,
        rendezvous_skew_ms=skew_ms,
        release_at_ms=release_at_ms,
        planned_wait_ms=wait_ms,
        lead_ms=lead_ms,
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
) -> dict[str, int | str]:
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
    evidence: dict[str, int | str] = {
        "schema_version": 1,
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
        now_ms = time.time_ns() // 1_000_000
        plan = plan_gate(
            extract_punch_at_ms(args.node_a_log),
            extract_punch_at_ms(args.node_b_log),
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
        f"skew_ms={evidence['rendezvous_skew_ms']} "
        f"release_offset_ms={evidence['release_offset_from_earliest_punch_ms']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
