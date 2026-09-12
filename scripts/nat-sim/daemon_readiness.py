#!/usr/bin/env python3
"""Bounded, poll-based daemon readiness gating for the NAT topology harness.

The status collector used to run on a fixed script schedule regardless of the
daemon's actual lifecycle, which turned slow daemon startup on a loaded CI
runner into `status_auth_token_missing` failures even though the daemon was
healthy and only starting late.  This module replaces that implicit coupling
with an explicit, monotonic readiness ladder:

    CREATED -> STARTING -> TOKEN_READY -> STATUS_READY -> RUNNING

`wait-token` waits for TOKEN_READY (the diagnostics session secret file is
published atomically by the daemon right after the instance lock is
acquired).  It polls on a fixed interval, never sleeps a fixed block before
the first check, fails fast when the daemon process dies, and always emits a
structured readiness record.  On failure the record carries the daemon pid,
liveness, token path, runtime directory state and log tail so a startup race
is diagnosable from the retained artifacts alone.

This is test-harness infrastructure only: it never changes daemon behaviour,
relay protocol, or acceptance criteria.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from enum import Enum
from pathlib import Path
from typing import Any, Callable


DEFAULT_TIMEOUT_S = 30.0
DEFAULT_POLL_S = 0.25
LOG_TAIL_LINES = 40
# Directory listing is capped so a pathological runtime dir cannot bloat the
# evidence record; names and sizes only, never file content.
DIR_LISTING_LIMIT = 64
TOKEN_MIN_BYTES = 1


class DaemonReadyState(str, Enum):
    """Monotonic daemon readiness ladder (never moves backwards)."""

    CREATED = "CREATED"
    STARTING = "STARTING"
    TOKEN_READY = "TOKEN_READY"
    STATUS_READY = "STATUS_READY"
    RUNNING = "RUNNING"


STATE_ORDER = {state: index for index, state in enumerate(DaemonReadyState)}


def advance(
    state: DaemonReadyState,
    *,
    process_alive: bool,
    token_present: bool,
    status_ok: bool = False,
    verification_running: bool = False,
) -> DaemonReadyState:
    """Pure transition function: the furthest state the observed signals allow.

    A dead process pins the state at STARTING (TOKEN_READY is unreachable by a
    process that no longer exists); readiness never regresses once observed.
    """
    if not process_alive:
        if STATE_ORDER[state] >= STATE_ORDER[DaemonReadyState.TOKEN_READY]:
            return state
        return DaemonReadyState.STARTING
    candidate = DaemonReadyState.STARTING
    if token_present:
        candidate = DaemonReadyState.TOKEN_READY
        if status_ok:
            candidate = DaemonReadyState.STATUS_READY
            if verification_running:
                candidate = DaemonReadyState.RUNNING
    if STATE_ORDER[candidate] > STATE_ORDER[state]:
        return candidate
    return state


def _tail_lines(path: Path, limit: int) -> list[str]:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    return lines[-limit:]


def _error_lines(path: Path, limit: int) -> list[str]:
    matched: list[str] = []
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            lowered = line.lower()
            if "error" in lowered or "panic" in lowered:
                matched.append(line)
                if len(matched) >= limit:
                    break
    except OSError:
        return []
    return matched


def _dir_listing(path: Path) -> list[dict[str, Any]]:
    listing: list[dict[str, Any]] = []
    try:
        for entry in sorted(path.iterdir())[:DIR_LISTING_LIMIT]:
            try:
                listing.append({"name": entry.name, "bytes": entry.stat().st_size})
            except OSError:
                listing.append({"name": entry.name, "bytes": None})
    except OSError:
        return []
    return listing


def _pid_alive(pid: int | None) -> bool | None:
    if pid is None or pid <= 0:
        return None
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return None
    return True


def build_diagnostics(
    *,
    result: str,
    state: DaemonReadyState,
    pid: int | None,
    token_path: Path,
    waited_ms: int,
    polls: int,
    log_path: Path | None,
    runtime_dir: Path | None,
    alive: Callable[[int | None], bool | None] = _pid_alive,
) -> dict[str, Any]:
    """Assemble the failure evidence bundle (never includes token content)."""
    token_present = False
    token_bytes: int | None = None
    try:
        token_bytes = token_path.stat().st_size
        token_present = token_bytes >= TOKEN_MIN_BYTES
    except OSError:
        token_present = False
    record: dict[str, Any] = {
        "state": state.value,
        "target": "TOKEN_READY",
        "result": result,
        "pid": pid,
        "process_alive": alive(pid),
        "token_path": str(token_path),
        "token_present": token_present,
        "token_bytes": token_bytes,
        "waited_ms": waited_ms,
        "polls": polls,
    }
    if runtime_dir is not None:
        record["runtime_dir"] = str(runtime_dir)
        record["runtime_dir_listing"] = _dir_listing(runtime_dir)
    if log_path is not None:
        record["log_path"] = str(log_path)
        record["log_tail"] = _tail_lines(log_path, LOG_TAIL_LINES)
        record["log_error_lines"] = _error_lines(log_path, LOG_TAIL_LINES)
    return record


def wait_for_token(
    *,
    token_path: Path,
    pid: int | None,
    timeout_s: float = DEFAULT_TIMEOUT_S,
    poll_s: float = DEFAULT_POLL_S,
    log_path: Path | None = None,
    runtime_dir: Path | None = None,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
    alive: Callable[[int | None], bool | None] = _pid_alive,
) -> dict[str, Any]:
    """Poll until the diagnostics token is published or the bound expires.

    The wait is strictly bounded by `timeout_s` regardless of poll duration,
    and a dead process fails fast instead of burning the whole budget.
    """
    started = monotonic()
    deadline = started + timeout_s
    polls = 0
    state = DaemonReadyState.STARTING
    while True:
        polls += 1
        alive_now = alive(pid)
        state = advance(
            state, process_alive=bool(alive_now), token_present=_token_present(token_path)
        )
        if state is DaemonReadyState.TOKEN_READY:
            return _record(
                result="ready",
                state=state,
                pid=pid,
                token_path=token_path,
                waited_ms=int((monotonic() - started) * 1000),
                polls=polls,
                log_path=log_path,
                runtime_dir=runtime_dir,
                alive=alive,
            )
        if alive_now is False:
            return _record(
                result="process_exited",
                state=state,
                pid=pid,
                token_path=token_path,
                waited_ms=int((monotonic() - started) * 1000),
                polls=polls,
                log_path=log_path,
                runtime_dir=runtime_dir,
                alive=alive,
            )
        now = monotonic()
        if now >= deadline:
            return _record(
                result="timeout",
                state=state,
                pid=pid,
                token_path=token_path,
                waited_ms=int((now - started) * 1000),
                polls=polls,
                log_path=log_path,
                runtime_dir=runtime_dir,
                alive=alive,
            )
        sleep(min(poll_s, max(0.0, deadline - now)))


def _token_present(token_path: Path) -> bool:
    try:
        return token_path.stat().st_size >= TOKEN_MIN_BYTES
    except OSError:
        return False


def _record(**kwargs: Any) -> dict[str, Any]:
    return build_diagnostics(
        result=kwargs["result"],
        state=kwargs["state"],
        pid=kwargs["pid"],
        token_path=kwargs["token_path"],
        waited_ms=kwargs["waited_ms"],
        polls=kwargs["polls"],
        log_path=kwargs["log_path"],
        runtime_dir=kwargs["runtime_dir"],
        alive=kwargs["alive"],
    )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    command = parser.add_subparsers(dest="command", required=True)
    wait = command.add_parser("wait-token", help="wait for the diagnostics token (TOKEN_READY)")
    wait.add_argument("--pid", type=int, default=None)
    # --token-file carries the token FILE PATH (never the secret itself);
    # the credential-scan argv rule permits exactly this transport form.
    wait.add_argument("--token-file", required=True)
    wait.add_argument("--log", default=None)
    wait.add_argument("--runtime-dir", default=None)
    wait.add_argument("--timeout-s", type=float, default=DEFAULT_TIMEOUT_S)
    wait.add_argument("--poll-s", type=float, default=DEFAULT_POLL_S)
    wait.add_argument("--output", required=True, help="readiness record JSON path")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    record = wait_for_token(
        token_path=Path(args.token_file),
        pid=args.pid,
        timeout_s=args.timeout_s,
        poll_s=args.poll_s,
        log_path=Path(args.log) if args.log else None,
        runtime_dir=Path(args.runtime_dir) if args.runtime_dir else None,
    )
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        f"[nat-readiness] result={record['result']} state={record['state']} "
        f"pid={record['pid']} waited_ms={record['waited_ms']} polls={record['polls']} "
        f"token_present={record['token_present']} record={output}"
    )
    return 0 if record["result"] == "ready" else 1


if __name__ == "__main__":
    raise SystemExit(main())
