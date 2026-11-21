#!/usr/bin/env python3
"""Delayed STUN-B fixture input with unchanged original tool forwarding."""
import builtins, hashlib, importlib.util, json, os, sys, time
from pathlib import Path


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main(argv):
    if len(argv) < 3 or argv[1] != "python3":
        raise ValueError("delayed_b_only_owned_python_launcher")
    root = Path(argv[0]).resolve()
    settings = json.loads((root / "fixture-config.json").read_text())
    declared = json.loads((root / "delayed-b-input.json").read_text())
    base_path = root / "fixture-external-tools.py"
    original_sources = settings["original_sources"]
    captured = (("original_assertions_relative_path", "original_assertions_sha256"),
                ("original_tools_relative_path", "original_tools_sha256"),
                ("test_source_relative_path", "test_source_sha256"),
                ("adapter_source_relative_path", "adapter_source_sha256"))
    if (not isinstance(original_sources, dict)
            or any(original_sources.get(declared[relative_key]) != declared[sha_key]
                   for relative_key, sha_key in captured)
            or settings["external_tools_sha256"] != declared["original_tools_sha256"]
            or digest(base_path) != declared["original_tools_sha256"]
            or declared["adapter_source_sha256"] != declared["adapter_sha256"]
            or declared["adapter_sha256"] != digest(Path(__file__).resolve())
            or declared["python_launcher_sha256"] != digest(root / "fake-path/python3")
            or declared["delay_seconds"] != 0.15):
        raise ValueError("delayed_b_private_transport_binding_mismatch")
    spec = importlib.util.spec_from_file_location("_delayed_b_original_tools", base_path)
    base = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(base)
    if Path(argv[2]).name == "nat_sim.py":
        if settings["case"] != "direct-barrier-unhealthy" or settings["rounds"] != 1:
            raise ValueError("delayed_b_undeclared_case")
        seen = []
        def output(*args, **kwargs):
            side = "a" if args == ("STUN_A=127.0.0.1:31001",) else "b" if args == ("STUN_B=127.0.0.1:31002",) else None
            if side is None:
                return builtins.print(*args, **kwargs)
            if kwargs != {"flush": True} or seen != ([] if side == "a" else ["a"]):
                raise ValueError("delayed_b_original_print_shape_or_order_changed")
            if side == "b":
                time.sleep(0.15)  # Input stall inside original CLI/WORK/ROUND; no renewed deadline.
            base.append_event(root, {"tool": "delayed_stun_print_enter", "side": side,
                                     "pid": os.getpid(), "phase": "before_original_flush"})
            builtins.print(*args, **kwargs)
            base.append_event(root, {"tool": "delayed_stun_flush", "side": side,
                                     "pid": os.getpid(), "phase": "original_flush_returned"})
            seen.append(side)
        base.print = output
    return base.main(argv)  # Exact argv/API; original default-site forwarding and all other tools.

if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except Exception as error:
        print("B01_FIXTURE_INFRA_FAILURE: " + str(error), file=sys.stderr, flush=True)
        raise SystemExit(90)
