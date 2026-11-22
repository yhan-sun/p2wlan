"""Run and score all nine NAT pairs without a gateway lease."""

import itertools
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
TEST = "udp::tests::negotiated_matrix::negotiated_rootless_nat_matrix"
KINDS = ("Cone", "LinearSymmetric", "RandomSymmetric")
ROW = re.compile(
    r"NAT matrix (\w+) x (\w+) result=(bidirectional authenticated UDP|relay) "
    r"UDP challenges=(\d+) gateway_pcp=false\b"
)


def main() -> int:
    result = subprocess.run(
        [
            "cargo", "test", "--locked", "-p", "p2wlan-daemon", "--lib", TEST,
            "--", "--exact", "--nocapture", "--test-threads=1",
        ],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    print(result.stdout, end="", flush=True)
    if result.returncode:
        return result.returncode

    expected = set(itertools.product(KINDS, repeat=2))
    observed = {}
    for a, b, path, requests in ROW.findall(result.stdout):
        if (a, b) not in expected or (a, b) in observed:
            print(f"G4 invalid or duplicate measurement for {a} x {b}", file=sys.stderr)
            return 1
        observed[a, b] = path == "bidirectional authenticated UDP"
        if not 1 <= int(requests) <= 96:
            print(f"G4 invalid challenge budget for {a} x {b}", file=sys.stderr)
            return 1
    if set(observed) != expected:
        print(f"G4 missing measurements {sorted(expected - set(observed))}", file=sys.stderr)
        return 1
    required = expected - {("RandomSymmetric", "RandomSymmetric")}
    missing = sorted(pair for pair in required if not observed[pair])
    print(f"G4 verified {sum(observed.values())}/9 bidirectional direct pairs without PCP")
    if missing:
        print("G4 FAIL: " + ", ".join(f"{a} x {b}" for a, b in missing))
        return 1
    print("G4 PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
