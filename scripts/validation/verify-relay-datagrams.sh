#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.."

target_dir=$(cargo metadata --locked --format-version=1 --no-deps |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')
cargo build --locked -p p2pnet-relay --example verify_datagram_relay
export P2WLAN_RUST_RELAY_PROBE="$target_dir/debug/examples/verify_datagram_relay"
cd server
go test -race ./relay -run '^TestUDPFallbackWithRustClient$' -count=1 -v
