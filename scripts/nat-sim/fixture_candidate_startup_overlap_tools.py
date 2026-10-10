#!/usr/bin/env python3
"""Bounded STUN-A-only transport for the startup cleanup fixture.

Old fixture_external_tools.py remains byteexact. The original nat input child,
handlers and lifetime are used; only its exact STUN_B print is withheld. Other
Python targets keep the original base.main default-site execv forwarding.
"""
from __future__ import annotations

import builtins
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys

CAP = 128 * 1024
CASE = "nat-stun-b-missing"
NAT_A = "STUN_A=127.0.0.1:31001"
NAT_B = "STUN_B=127.0.0.1:31002"


def regular_bytes(path, cap=CAP, mode=0o600):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
                or metadata.st_mode & 0o777 != mode or metadata.st_size > cap):
            raise ValueError("startup_adapter_regular_file_contract")
        data = bytearray()
        while len(data) <= cap:
            chunk = os.read(descriptor, min(8192, cap + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) > cap or len(data) != metadata.st_size:
            raise ValueError("startup_adapter_file_changed_or_cap")
        return bytes(data)
    finally:
        os.close(descriptor)


def load_base(root):
    settings = json.loads(regular_bytes(root / "fixture-config.json"))
    if settings.get("fixture_only") is not True or settings.get("case") != CASE or settings.get("rounds") != 1:
        raise ValueError("startup_adapter_case_invalid")
    repository = root / "private-source"
    if settings.get("private_repository") != str(repository):
        raise ValueError("startup_adapter_private_repository_invalid")
    record = settings["startup_overlap_transport"]
    base_path = root / "fixture-external-tools.py"
    payload = regular_bytes(base_path)
    expected = settings["original_sources"]["scripts/nat-sim/fixture_external_tools.py"]
    if (hashlib.sha256(payload).hexdigest() != expected
            or settings.get("external_tools_sha256") != expected
            or record.get("base_sha256") != expected or record.get("base_path") != str(base_path)):
        raise ValueError("startup_adapter_original_base_not_exact")
    own_path = Path(__file__).resolve()
    if own_path != root / "fixture-startup-overlap-tools.py":
        raise ValueError("startup_adapter_layout_invalid")
    if (record.get("adapter_path") != str(own_path)
            or hashlib.sha256(regular_bytes(own_path)).hexdigest() != record.get("adapter_sha256")):
        raise ValueError("startup_adapter_not_bound")
    launcher = root / "fake-path/python3"
    if (record.get("python3_launcher_path") != str(launcher)
            or hashlib.sha256(regular_bytes(launcher, 8192, 0o700)).hexdigest()
            != record.get("python3_launcher_sha256")):
        raise ValueError("startup_adapter_launcher_not_bound")
    specification = importlib.util.spec_from_file_location("b01_startup_original_base", base_path)
    if specification is None or specification.loader is None:
        raise ValueError("startup_adapter_original_module_missing")
    base = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(base)
    return base, settings


def main(argv):
    if len(argv) < 3:
        raise ValueError("startup_adapter_arguments_missing")
    root = Path(argv[0]).resolve()
    if not root.is_dir() or root.stat().st_mode & 0o777 != 0o700:
        raise ValueError("startup_adapter_root_invalid")
    base, settings = load_base(root)
    tool, arguments = argv[1], argv[2:]
    if tool != "python3":
        raise ValueError("startup_adapter_only_python_launcher")
    if arguments[0] in {"-", "-c"} or Path(arguments[0]).name != "nat_sim.py":
        return base.main(argv)
    # base.main still checks the original private script and captured SHA before
    # entering its child. The input event precedes the original flushed A print.
    original_print = getattr(base, "print", builtins.print)
    had_print = "print" in base.__dict__
    emitted_a = False
    suppressed_b = False

    def stun_a_only(*args, **kwargs):
        nonlocal emitted_a, suppressed_b
        if args == (NAT_A,) and kwargs == {"flush": True}:
            if emitted_a:
                raise ValueError("startup_adapter_duplicate_stun_a")
            emitted_a = True
            base.append_event(root, {"tool": "startup_input_enter", "input": CASE,
                                     "pid": os.getpid(), "component": "nat",
                                     "original_base_sha256": settings["external_tools_sha256"]})
            return original_print(*args, **kwargs)
        if args == (NAT_B,) and kwargs == {"flush": True}:
            if not emitted_a or suppressed_b:
                raise ValueError("startup_adapter_stun_order_invalid")
            suppressed_b = True
            # The original stdout intentionally receives no STUN_B line.
            return None
        return original_print(*args, **kwargs)

    base.print = stun_a_only
    try:
        return base.main(argv)
    finally:
        if had_print:
            base.print = original_print
        else:
            del base.print


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (ValueError, KeyError, OSError, IndexError, TypeError) as error:
        print("B01_FIXTURE_INFRA_FAILURE:" + type(error).__name__ + ":" + str(error), file=sys.stderr)
        raise SystemExit(92)
