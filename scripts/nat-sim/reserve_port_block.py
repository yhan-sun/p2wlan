#!/usr/bin/env python3
"""Reserve a collision-free TCP port block for one NAT smoke invocation.

The directory reservation serializes concurrent copies of the harness. The
bind probe rejects ports already owned by unrelated processes. The caller
keeps the returned directory for its lifetime and removes it during cleanup.
"""

from __future__ import annotations

import argparse
import os
import socket
import sys
from pathlib import Path


def required_ports(base: int, relay_count: int) -> list[int]:
    relay_offsets = range(1, relay_count + 1)
    metrics_offsets = range(1001, 1001 + relay_count)
    return [
        base,
        base + 301,
        base + 302,
        *[base + offset for offset in relay_offsets],
        *[base + offset for offset in metrics_offsets],
    ]


def ports_are_available(ports: list[int]) -> bool:
    sockets: list[socket.socket] = []
    try:
        for port in ports:
            probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sockets.append(probe)
            probe.bind(("127.0.0.1", port))
            probe.listen(1)
        return True
    except OSError:
        return False
    finally:
        for probe in sockets:
            probe.close()


def release_port_block(reservation_dir: Path) -> None:
    manifest = reservation_dir / "port-locks"
    if manifest.is_file():
        for line in manifest.read_text(encoding="utf-8").splitlines():
            lock_dir = Path(line)
            try:
                lock_dir.rmdir()
            except FileNotFoundError:
                pass
        manifest.unlink()
    try:
        reservation_dir.rmdir()
    except FileNotFoundError:
        pass


def reserve_port_block(
    lock_root: Path,
    seed: int,
    relay_count: int,
    base: int,
    stride: int,
    slots: int,
) -> tuple[int, Path]:
    lock_root.mkdir(parents=True, exist_ok=True)
    for attempt in range(slots):
        candidate = base + ((seed + attempt) % slots) * stride
        ports = required_ports(candidate, relay_count)
        if min(ports) < 1024 or max(ports) > 65535:
            continue
        reservation_dir = lock_root / f"reservation-{candidate}.lock"
        try:
            reservation_dir.mkdir()
        except FileExistsError:
            continue
        acquired: list[Path] = []
        try:
            for port in sorted(set(ports)):
                port_lock = lock_root / f"port-{port}.lock"
                port_lock.mkdir()
                acquired.append(port_lock)
        except FileExistsError:
            for port_lock in reversed(acquired):
                port_lock.rmdir()
            reservation_dir.rmdir()
            continue
        if ports_are_available(ports):
            try:
                (reservation_dir / "port-locks").write_text(
                    "".join(f"{port_lock}\n" for port_lock in acquired),
                    encoding="utf-8",
                )
                return candidate, reservation_dir
            except OSError:
                for port_lock in reversed(acquired):
                    port_lock.rmdir()
                reservation_dir.rmdir()
                raise
        for port_lock in reversed(acquired):
            port_lock.rmdir()
        reservation_dir.rmdir()
    raise RuntimeError(
        f"no free NAT smoke port block in {slots} slots from base {base}"
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock-root", type=Path)
    parser.add_argument("--seed", type=int)
    parser.add_argument("--relay-count", type=int)
    parser.add_argument("--base", type=int, default=20080)
    parser.add_argument("--stride", type=int, default=10)
    parser.add_argument("--slots", type=int, default=300)
    parser.add_argument("--release", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.release is not None:
        try:
            release_port_block(args.release)
        except OSError as exc:
            print(f"failed to release NAT smoke ports: {exc}", file=sys.stderr)
            return 1
        return 0
    if args.lock_root is None or args.seed is None or args.relay_count is None:
        print("--lock-root, --seed and --relay-count are required", file=sys.stderr)
        return 2
    if args.relay_count < 1 or args.stride < 1 or args.slots < 1:
        print("relay count, stride and slots must be positive", file=sys.stderr)
        return 2
    try:
        port, lock_dir = reserve_port_block(
            args.lock_root,
            args.seed,
            args.relay_count,
            args.base,
            args.stride,
            args.slots,
        )
    except (OSError, RuntimeError) as exc:
        print(f"failed to reserve NAT smoke ports: {exc}", file=sys.stderr)
        return 1
    print(port)
    print(os.fspath(lock_dir))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
