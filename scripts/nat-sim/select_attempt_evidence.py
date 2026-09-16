#!/usr/bin/env python3
"""Keep one attempt's evidence per scenario before the NAT aggregate runs.

NAT evidence artifacts were named ``nat-topology-<kind>-<run_id>`` with
``overwrite: true``, so re-running a failed topology job replaced the evidence
the failing attempt had produced. That is why a flaky NAT failure could not be
diagnosed afterwards: only the successful re-run survived.

The artifacts are now attempt-qualified. A full re-run publishes every kind
under the new attempt; a partial re-run publishes only the jobs it re-ran, so
this step picks, per scenario kind, the **highest attempt that has evidence**
and lays out exactly one copy for the aggregate. Every attempt's artifact stays
available on the run for post-mortem.

The aggregate still verifies ``source_head_sha`` and ``workflow_sha`` on every
record it consumes, so a record carried over from an earlier attempt is only
accepted if it belongs to the same commit and workflow blob.
"""

from __future__ import annotations

import argparse
import re
import shutil
import sys
from pathlib import Path
from typing import Iterable, Sequence

DIRECT = re.compile(r"^nat-topology-direct-(\d+)-(\d+)$")
RELAY = re.compile(r"^nat-topology-relay-(\d+)-(\d+)-(\d+)-of-5$")

DIRECT_KIND = "direct"
RELAY_KINDS = tuple(f"relay-blackhole-{index}" for index in range(1, 6))


class SelectionError(RuntimeError):
    """The evidence set cannot be laid out for the aggregate."""


def parse_artifact(name: str, run_id: int) -> tuple[str, int] | None:
    """Return (scenario kind, attempt) for an artifact of this run."""
    direct = DIRECT.fullmatch(name)
    if direct is not None:
        return (DIRECT_KIND, int(direct.group(2))) if int(direct.group(1)) == run_id else None
    relay = RELAY.fullmatch(name)
    if relay is not None:
        if int(relay.group(1)) != run_id:
            return None
        return (f"relay-blackhole-{int(relay.group(3))}", int(relay.group(2)))
    return None


def _choose(artifacts_root: Path, run_id: int, max_attempt: int | None) -> dict[str, tuple[int, Path]]:
    """Map scenario kind -> (attempt, directory) for the highest attempt seen."""
    chosen: dict[str, tuple[int, Path]] = {}
    for entry in sorted(artifacts_root.iterdir()) if artifacts_root.is_dir() else []:
        if not entry.is_dir():
            continue
        parsed = parse_artifact(entry.name, run_id)
        if parsed is None:
            continue
        kind, attempt = parsed
        if max_attempt is not None and attempt > max_attempt:
            continue
        prior = chosen.get(kind)
        if prior is None or attempt > prior[0]:
            chosen[kind] = (attempt, entry)
    return chosen


def select(artifacts_root: Path, run_id: int, *, max_attempt: int | None = None) -> dict[str, Path]:
    """Map scenario kind -> the directory of the highest attempt that has one."""
    return {kind: path for kind, (_, path) in _choose(artifacts_root, run_id, max_attempt).items()}


def expected_scenarios() -> list[str]:
    return [DIRECT_KIND, *RELAY_KINDS]


def lay_out(artifacts_root: Path, output_root: Path, run_id: int, *, max_attempt: int | None = None) -> dict[str, int]:
    chosen = _choose(artifacts_root, run_id, max_attempt)
    missing = [kind for kind in expected_scenarios() if kind not in chosen]
    if missing:
        seen = ",".join(sorted(chosen)) or "none"
        raise SelectionError(f"nat_evidence_missing:{','.join(missing)}:kinds_seen={seen}")

    for group in ("direct", "relay"):
        target = output_root / group
        if target.exists():
            shutil.rmtree(target)
        target.mkdir(parents=True)
    for kind, (_attempt, source) in chosen.items():
        group = DIRECT_KIND if kind == DIRECT_KIND else "relay"
        shutil.copytree(source, output_root / group / source.name)
    return {kind: chosen[kind][0] for kind in sorted(chosen)}


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts-root", required=True)
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--run-id", required=True, type=int)
    parser.add_argument("--current-attempt", type=int, default=None)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        chosen = lay_out(
            Path(args.artifacts_root),
            Path(args.output_root),
            args.run_id,
            max_attempt=args.current_attempt,
        )
    except (SelectionError, OSError) as error:
        print(f"nat evidence selection failed: {error}", file=sys.stderr)
        return 1
    for kind in sorted(chosen):
        print(f"nat evidence {kind}: attempt={chosen[kind]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
