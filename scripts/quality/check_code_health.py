#!/usr/bin/env python3
"""Check source-size budgets; this is not a proof of runtime correctness."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path
from typing import Mapping

ROOT = Path(__file__).resolve().parents[2]
RUST_PRODUCTION_MAX_BYTES = 96 * 1024
RUST_TEST_MAX_BYTES = 192 * 1024
LEGACY_RUST_BYTE_CEILINGS = {
    "client/daemon/src/lib/daemon/control_events.rs": 216_949,
    "client/daemon/src/lib/direct_runtime/hard_hard.rs": 229_837,
    "client/daemon/src/lib/direct_runtime/hole_punch.rs": 113_960,
    "client/daemon/src/peer/manager/peers.rs": 103_077,
    "client/daemon/src/peer/manager/relay.rs": 149_242,
    "client/daemon/src/lib/tests/part03.rs": 340_275,
    "client/daemon/src/lib/tests/part07.rs": 203_948,
}


def source_size(data: bytes) -> int:
    return len(data.replace(b"\r\n", b"\n"))


def is_rust_test(relative: str) -> bool:
    path = Path(relative)
    return "tests" in path.parts or path.name == "tests.rs" or path.name.startswith("test_")


def tracked_sizes(root: Path) -> dict[str, int]:
    result = subprocess.run(
        ["git", "ls-files", "-z"], cwd=root, check=True, capture_output=True
    )
    sizes = {}
    for raw in result.stdout.split(b"\0"):
        if not raw:
            continue
        relative = os.fsdecode(raw)
        path = root / relative
        if path.suffix == ".rs" and path.is_file():
            sizes[relative] = source_size(path.read_bytes())
    return sizes


def base_sizes(root: Path, ref: str) -> dict[str, int]:
    commit = subprocess.run(
        ["git", "rev-parse", "--verify", "--end-of-options", f"{ref}^{{commit}}"],
        cwd=root, check=True, capture_output=True, text=True,
    ).stdout.strip()
    result = subprocess.run(
        ["git", "ls-tree", "-r", "-l", "-z", commit, "--", *LEGACY_RUST_BYTE_CEILINGS],
        cwd=root, check=True, capture_output=True,
    )
    sizes = {}
    for record in result.stdout.split(b"\0"):
        if not record:
            continue
        metadata, relative = record.split(b"\t", 1)
        _, kind, blob, _ = metadata.split()
        if kind == b"blob":
            content = subprocess.run(
                ["git", "cat-file", "blob", blob.decode("ascii")],
                cwd=root, check=True, capture_output=True,
            ).stdout
            sizes[os.fsdecode(relative)] = source_size(content)
    return sizes


def validate_sizes(
    sizes: Mapping[str, int],
    legacy: Mapping[str, int],
    baseline: Mapping[str, int] | None = None,
) -> list[str]:
    errors = []
    for relative, size in sorted(sizes.items()):
        budget = RUST_TEST_MAX_BYTES if is_rust_test(relative) else RUST_PRODUCTION_MAX_BYTES
        ceiling = legacy.get(relative, budget)
        if relative in legacy:
            if size <= budget:
                errors.append(f"{relative}: remove the obsolete legacy exception (now within {budget} bytes)")
            if baseline is not None:
                if relative not in baseline:
                    errors.append(f"{relative}: a new legacy exception has no file in the base revision")
                else:
                    ceiling = min(ceiling, baseline[relative])
        if size > ceiling:
            errors.append(f"{relative}: {size} bytes exceeds {ceiling}; split responsibilities instead of raising the budget")
    for relative in sorted(legacy.keys() - sizes.keys()):
        errors.append(f"{relative}: legacy file is missing; remove the obsolete exception")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-ref", default=os.environ.get("P2WLAN_QUALITY_BASE") or None)
    args = parser.parse_args(argv)
    ref = args.base_ref
    if ref == "0" * 40:
        ref = None
    try:
        sizes = tracked_sizes(ROOT)
        baseline = base_sizes(ROOT, ref) if ref else None
        errors = validate_sizes(sizes, LEGACY_RUST_BYTE_CEILINGS, baseline)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"FAIL code health policy: cannot inspect the repository: {error}", file=sys.stderr)
        return 1
    if errors:
        print("FAIL code health policy")
        for error in errors:
            print(f"- {error}")
        return 1
    comparison = "base-relative ratchet" if baseline is not None else "static ceilings"
    print(f"PASS code health policy ({len(sizes)} Rust files; {len(LEGACY_RUST_BYTE_CEILINGS)} legacy exceptions; {comparison})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
