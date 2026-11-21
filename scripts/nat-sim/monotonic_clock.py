#!/usr/bin/env python3
"""One process-shared monotonic domain for local NAT harness deadlines."""

import sys
import time


def monotonic_ns():
    # Python before 3.10 subtracts a process-local origin on macOS. The raw
    # uptime clock preserves the same sleep semantics and a shared epoch.
    if sys.platform == "darwin":
        return time.clock_gettime_ns(time.CLOCK_UPTIME_RAW)
    return time.monotonic_ns()


def origin():
    monotonic_ms = monotonic_ns() // 1_000_000
    wall_ns = time.time_ns()
    return monotonic_ms, wall_ns // 1_000_000_000, (wall_ns + 999_999) // 1_000_000


if __name__ == "__main__":
    if sys.argv[1:] == ["origin"]:
        print(*origin())
    elif not sys.argv[1:]:
        print(monotonic_ns() // 1_000_000)
    else:
        raise SystemExit("usage: monotonic_clock.py [origin]")
