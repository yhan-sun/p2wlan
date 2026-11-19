#!/usr/bin/env python3
"""Build or exec the test-only libc UDP shim; never install it globally."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import time


def build(output: Path) -> None:
    if sys.platform not in {"darwin", "linux"}:
        raise RuntimeError("UDP egress shim requires macOS or Linux")
    flags = ["-dynamiclib"] if sys.platform == "darwin" else ["-shared", "-fPIC", "-ldl"]
    subprocess.run(
        [os.environ.get("CC", "cc"), "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2",
         str(Path(__file__).with_name("udp_egress_shim.c")), "-o", str(output), "-pthread", *flags],
        check=True,
    )


def drain_capture(round_dir: Path, timeout_ms: int = 2000) -> bool:
    """Senders must already be stopped. Wait for their last datagrams, bounded."""
    if not 0 <= timeout_ms <= 5000:
        raise ValueError("egress drain timeout must be in 0..5000 ms")
    expected = {}
    try:
        for side in ("A", "B"):
            magic, packets, byte_count, _, _ = struct.unpack(
                "=8sQQQQ", (round_dir / f"node-{side.lower()}.egress-stats").read_bytes())
            if magic != b"P2CNT001":
                raise ValueError("shim counter header")
            expected[side] = (packets, byte_count)
    except (OSError, ValueError, struct.error):
        return False
    deadline = time.monotonic() + timeout_ms / 1000
    while True:
        actual = {"A": [0, 0], "B": [0, 0]}
        try:
            trace = round_dir / "nat-trace.jsonl"
            if trace.stat().st_size > 64 * 1024 * 1024:
                return False
            with trace.open() as stream:
                for line in stream:
                    row = json.loads(line)
                    if row.get("event") == "egress_captured" and row.get("nat") in actual:
                        side = row["nat"]
                        actual[side][0] += 1
                        actual[side][1] += row["bytes"]
            if all(tuple(actual[side]) == expected[side] for side in expected):
                return True
        except (OSError, ValueError, TypeError, KeyError):
            pass  # A writer may still be flushing its final JSON line.
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.01)


def environment(library: Path, port: int, stats_path: Path | None = None) -> dict[str, str]:
    if not library.is_file() or not 1 <= port <= 65535:
        raise ValueError("existing shim library and valid gateway port required")
    env = os.environ.copy()
    key = "DYLD_INSERT_LIBRARIES" if sys.platform == "darwin" else "LD_PRELOAD"
    env[key] = str(library.resolve())
    env["P2WLAN_NAT_SIM_GATEWAY_PORT"] = str(port)
    env.pop("P2WLAN_NAT_SIM_SENDER_PID", None)
    env.pop("P2WLAN_NAT_SIM_EGRESS_STATS", None)
    if stats_path is not None:
        env["P2WLAN_NAT_SIM_EGRESS_STATS"] = str(stats_path.resolve())
    return env


def recorder_environment(env: dict[str, str]) -> dict[str, str]:
    """Carry capture intent through Python; the verified final exec arms it."""
    result = env.copy()
    result.pop("DYLD_INSERT_LIBRARIES", None)
    result.pop("LD_PRELOAD", None)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path)
    parser.add_argument("--library", type=Path)
    parser.add_argument("--port", type=int)
    parser.add_argument("--stats", type=Path)
    parser.add_argument("--recorder", action="store_true",
                        help="defer injection to the verified final native exec recorder")
    parser.add_argument("--drain", type=Path)
    parser.add_argument("--drain-timeout-ms", type=int, default=2000)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.drain:
        raise SystemExit(0 if drain_capture(args.drain, args.drain_timeout_ms) else 1)
    if args.build:
        build(args.build)
        return
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not args.library or args.port is None or not command:
        parser.error("require --build or --library, --port and -- command")
    env = environment(args.library, args.port, args.stats)
    if args.recorder:
        env = recorder_environment(env)
    else:
        env["P2WLAN_NAT_SIM_SENDER_PID"] = str(os.getpid())
    os.execvpe(command[0], command, env)


if __name__ == "__main__":
    main()
