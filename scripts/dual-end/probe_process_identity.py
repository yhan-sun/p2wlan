"""Local producer observations; a controller must still bind its owned child.

Only the current process is inspected. Other platforms explicitly lack the
Linux birth/namespace tuple and cannot acquire it from caller-supplied JSON.
"""
from __future__ import annotations

import os
from pathlib import Path
import sys
import time


def bounded_text(path: str) -> str:
    with open(path, "r", encoding="ascii") as stream:
        value = stream.read(4097)
    if len(value) > 4096:
        raise ValueError("producer identity file exceeds bound")
    return value.strip()


def current_identity() -> tuple[dict, dict]:
    owner = {"pid": os.getpid(), "parent_pid": os.getppid(),
             "uid": os.getuid(), "linux_birth_available": False}
    info = time.get_clock_info("monotonic")
    clock = {"implementation": info.implementation, "monotonic": info.monotonic,
             "adjustable": info.adjustable, "same_boot_clock_available": False}
    if sys.platform != "linux":
        return owner, clock
    # /proc/self/stat's comm can contain whitespace and ')'. Field 22 is
    # nineteen fields after the final comm delimiter (field 3 is state).
    raw = bounded_text("/proc/self/stat")
    delimiter = raw.rfind(")")
    tail = raw[delimiter + 2:].split()
    if delimiter < 0 or int(raw.split("(", 1)[0]) != owner["pid"] or len(tail) < 20:
        raise ValueError("invalid current-process birth observation")
    ticks = int(tail[19])
    boot = bounded_text("/proc/sys/kernel/random/boot_id")
    if ticks < 0 or len(boot) != 36 or any(c not in "0123456789abcdef-" for c in boot):
        raise ValueError("invalid current-process boot or birth observation")
    owner.update(linux_birth_available=True, start_ticks=ticks, boot_id=boot,
                 pid_namespace=os.readlink("/proc/self/ns/pid"),
                 net_namespace=os.readlink("/proc/self/ns/net"))
    clock["same_boot_clock_available"] = (
        info.implementation == "clock_gettime(CLOCK_MONOTONIC)"
        and info.monotonic and not info.adjustable)
    if clock["same_boot_clock_available"]:
        clock["boot_id"] = boot
    return owner, clock
