#!/usr/bin/env python3
"""Enforce P2WLAN code-health ratchets without pretending legacy debt is gone.

The policy is intentionally monotonic: known oversized production modules may
shrink, but they may not grow. New production modules must stay below the
shared size budget so future features are forced behind explicit boundaries.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# Production Rust files larger than this must either be split or appear in the
# legacy ratchet below. Tests are governed separately because large scenario
# suites are less dangerous than large state-owning production modules.
RUST_PRODUCTION_MAX_BYTES = 96 * 1024
RUST_TEST_MAX_BYTES = 192 * 1024

# These are debt ceilings, not targets. Lowering a ceiling after a split is
# encouraged; raising one is a policy regression and should require a visible
# review of this file.
LEGACY_RUST_BYTE_CEILINGS = {
    "client/daemon/src/transport.rs": 278_683,
    "client/daemon/src/dplpmtud.rs": 231_770,
    "client/daemon/src/network_outbound.rs": 156_974,
    "client/daemon/src/relay_runtime.rs": 125_879,
    "client/daemon/src/udp/core.rs": 133_201,
    "client/daemon/src/udp/dynamic_punch.rs": 207_336,
}


def tracked_files() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    return [
        ROOT / raw.decode("utf-8")
        for raw in result.stdout.split(b"\0")
        if raw
    ]


def is_rust_test(path: Path, relative: str) -> bool:
    return (
        "/tests/" in f"/{relative}/"
        or relative.endswith("/tests.rs")
        or path.name.startswith("test_")
    )


def main() -> int:
    errors: list[str] = []
    rust_files = 0

    for path in tracked_files():
        if not path.is_file() or path.suffix != ".rs":
            continue
        rust_files += 1
        relative = path.relative_to(ROOT).as_posix()
        size = path.stat().st_size

        if relative in LEGACY_RUST_BYTE_CEILINGS:
            ceiling = LEGACY_RUST_BYTE_CEILINGS[relative]
            if size > ceiling:
                errors.append(
                    f"{relative}: {size} bytes exceeds legacy ratchet {ceiling}; "
                    "split responsibilities instead of raising the ceiling"
                )
        elif is_rust_test(path, relative):
            if size > RUST_TEST_MAX_BYTES:
                errors.append(
                    f"{relative}: {size} bytes exceeds test-file budget "
                    f"{RUST_TEST_MAX_BYTES}; split scenarios by behavior"
                )
        elif size > RUST_PRODUCTION_MAX_BYTES:
            errors.append(
                f"{relative}: {size} bytes exceeds production-module budget "
                f"{RUST_PRODUCTION_MAX_BYTES}; introduce a focused submodule"
            )

    missing = [
        relative
        for relative in LEGACY_RUST_BYTE_CEILINGS
        if not (ROOT / relative).is_file()
    ]
    if missing:
        errors.extend(
            f"legacy ratchet references missing file {relative}; remove the obsolete ceiling"
            for relative in missing
        )

    if errors:
        print("FAIL code health policy")
        for error in errors:
            print(f"- {error}")
        return 1

    print(
        "PASS code health policy "
        f"({rust_files} Rust files; production max {RUST_PRODUCTION_MAX_BYTES} bytes; "
        f"{len(LEGACY_RUST_BYTE_CEILINGS)} legacy ratchets)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
