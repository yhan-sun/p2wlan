"""Require two real active TCP opens, bidirectional WireGuard data and Relay fallback."""

import argparse
import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
CASE = "udp::tests::negotiated_tcp::negotiated_simultaneous_tcp_carries_wg_then_returns_to_tls_relay"
CARGO = ["cargo", "test", "--locked", "-p", "p2wlan-daemon", "--lib"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--isolated-linux", action="store_true",
        help="use a private Linux network namespace with 2 ms one-way loopback delay",
    )
    args = parser.parse_args()
    command = [*CARGO, CASE, "--", "--exact", "--nocapture", "--test-threads=1"]
    env = dict(os.environ, P2WLAN_TEST_REQUIRE_TCP_SIMULTANEOUS="1")
    if args.isolated_linux:
        if not sys.platform.startswith("linux"):
            parser.error("--isolated-linux requires Linux user/network namespaces and iproute2")
        build = subprocess.run([*CARGO, "--no-run"], cwd=ROOT)
        if build.returncode:
            return build.returncode
        env["CARGO_NET_OFFLINE"] = "true"
        command = [
            "unshare", "--user", "--map-root-user", "--net", "--", "sh", "-ec",
            'ip link set lo up\ntc qdisc add dev lo root netem delay 2ms\nexec "$@"',
            "sh", *command,
        ]
    result = subprocess.run(command, cwd=ROOT, env=env, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    print(result.stdout, end="")
    if result.returncode:
        return result.returncode
    if result.stdout.count("test result: ok. 1 passed; 0 failed; 0 ignored;") != 1:
        print("G6 FAIL: the exact simultaneous-open test did not run", file=sys.stderr)
        return 1
    print("G6 PASS: both active sockets delivered authenticated traffic and the first Relay pair")
    return 0


if __name__ == "__main__":
    sys.exit(main())
