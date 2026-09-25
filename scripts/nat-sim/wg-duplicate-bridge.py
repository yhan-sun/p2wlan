#!/usr/bin/env python3
"""Private test bridge that runs one real nat_sim UDP mapping with duplication."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path

from nat_sim import Nat, NatFabric, NatTrace


async def serve(args: argparse.Namespace) -> None:
    os.umask(0o077)
    trace = NatTrace(args.trace_file)
    fabric = NatFabric(trace)
    nat = Nat(
        "B",
        "127.0.0.1",
        step=1,
        seed=154,
        base_port=args.base_port,
        duplicate_rate=1.0,
    )
    try:
        await nat.start(fabric)
        receiver = (args.receiver_host, args.receiver_port)
        sender = (args.sender_host, args.sender_port)
        mapping = nat.mapping_for(receiver, sender)
        await nat.ensure_bound(mapping)
        print(
            json.dumps(
                {"public_ip": nat.public_ip, "public_port": mapping.port},
                sort_keys=True,
                separators=(",", ":"),
            ),
            flush=True,
        )
        await asyncio.Event().wait()
    finally:
        await nat.close()
        trace.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--receiver-host", required=True)
    parser.add_argument("--receiver-port", type=int, required=True)
    parser.add_argument("--sender-host", required=True)
    parser.add_argument("--sender-port", type=int, required=True)
    parser.add_argument("--trace-file", required=True)
    parser.add_argument("--base-port", type=int, default=42000)
    args = parser.parse_args()
    if Path(args.trace_file).exists():
        raise SystemExit("trace path already exists")
    asyncio.run(serve(args))


if __name__ == "__main__":
    main()
