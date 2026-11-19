"""Optional workloads on the two run-owned namespace links."""
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import time


def configure_daemon(lab, label, command):
    at = lambda key: command[command.index(key) + 1]
    path = Path(at("--config"))
    lab.cmd(label, [command[0], "--init", "--config", str(path), "--network", at("--network"),
                    "--control", at("--control")])
    config = json.loads(path.read_text())
    policy = lab.args.startup_policy
    if policy:
        config["relay"].update(path_policy=policy, prefer_direct=True)
    if lab.args.standby_failover:
        config["relay"].update(warm_failover=not lab.args.cold_reconnect, preferred_regions=["local"])
    if lab.args.early_candidates:
        config["network"]["early_candidate_signaling"] = True
    path.write_text(json.dumps(config))


def block_direct_udp(lab):
    for label, remote in [("a", "192.0.2.4"), ("b", "192.0.2.3")]:
        lab.cmd(label, ["iptables", "-I", "OUTPUT", "-o", "eth0", "-d", remote, "-p", "udp", "-j", "DROP"])


def configure_underlay_family(lab, report):
    healthy = lab.args.healthy_underlay_family
    for label, number in (("control", 2), ("a", 3), ("b", 4)):
        lab.cmd(label, ["ip", "-6", "addr", "add", f"2001:db8:7::{number}/64", "dev", "eth0", "nodad"])
    firewall = "iptables" if healthy == "ipv6" else "ip6tables"
    for label in ("a", "b"):
        # One rule counts and drops STUN to the isolated silent observer. The
        # other blocks any alternative peer UDP route on the same family.
        lab.cmd(label, [firewall, "-I", "OUTPUT", "-o", "eth0", "-p", "udp", "-j", "DROP"])
        lab.cmd(label, [firewall, "-I", "OUTPUT", "-o", "eth0", "-p", "udp", "--dport", "3478",
                        "-m", "comment", "--comment", "p2wlan-silent-stun", "-j", "DROP"])
    report["underlay_family"] = {"healthy": healthy, "silent_observer": "ipv4" if healthy == "ipv6" else "ipv6"}


def collect_underlay_family(lab, report):
    command = "iptables-save" if lab.args.healthy_underlay_family == "ipv6" else "ip6tables-save"
    totals = {}
    for label in ("a", "b"):
        lines = lab.cmd(label, [command, "-c", "-t", "filter"]).stdout.splitlines()
        rows = [re.match(r"^\[(\d+):(\d+)\]", line) for line in lines if "p2wlan-silent-stun" in line]
        if len(rows) != 1 or rows[0] is None:
            raise ValueError("silent_observer_rule_accounting_missing")
        totals[label] = int(rows[0][1])
    report["underlay_family"]["silent_observer_packets_dropped"] = totals


def relay_tcp_counters(lab):
    result = {}
    for label in ("a", "b", "control"):
        output = lab.cmd(label, ["ss", "-tinH", "( sport = :18081 or dport = :18081 or sport = :18082 or dport = :18082 )"]).stdout
        counts = [int(n) for n in re.findall(r"\bbytes_retrans:(\d+)", output)]
        result[label] = sum(counts) if counts else None
    return result


def begin_accounting(lab, report):
    scope = report["underlay_cost"] = {"scope": "run_owned_ipv4_eth0_output_ip_bytes", "peers": {}}
    for label in ("a", "b"):
        try:
            cmd = lambda args: lab.cmd(label, ["iptables", "-t", "mangle", *args])
            cmd(["-N", "P2WCOUNT"])
            cmd(["-A", "OUTPUT", "-o", "eth0", "-j", "P2WCOUNT"])
            for tag, match in [
                ("punch", ["-p", "udp", "-m", "u32", "--u32", "0>>22&0x3C@8=0x504E4348"]),
                ("stun", ["-p", "udp", "-m", "u32", "--u32", "0>>22&0x3C@12=0x2112A442"]),
                ("relay", ["-p", "tcp", "-m", "multiport", "--dports", "18081,18082"]),
                ("other", []),
            ]:
                cmd(["-A", "P2WCOUNT", *match, "-m", "comment", "--comment", tag, "-j", "RETURN"])
            scope["peers"][label] = {"installed": True}
        except (OSError, RuntimeError, subprocess.SubprocessError) as error:
            scope["peers"][label] = {"installed": False, "reason": type(error).__name__}
    scope["started_ns"] = time.monotonic_ns()


def finish_accounting(lab, report):
    scope = report["underlay_cost"]
    for label, state in scope["peers"].items():
        if state["installed"]:
            rules = lab.cmd(label, ["iptables-save", "-c", "-t", "mangle"]).stdout
            state["traffic"] = {}
            for line in rules.splitlines():
                hit = re.search(r'^\[(\d+):(\d+)\] -A P2WCOUNT .*?--comment "?([a-z]+)"? ', line)
                if hit:
                    packets, size, tag = hit.groups()
                    state["traffic"][tag] = {"ip_bytes": int(size), "ip_packets": int(packets)}
        pid = lab.daemons[label + "1"]["process"].pid
        stat = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        state["daemon_cpu_seconds_since_spawn"] = (int(stat[11]) + int(stat[12])) / os.sysconf("SC_CLK_TCK")
        state["daemon_rss_bytes_at_end"] = int(stat[21]) * os.sysconf("SC_PAGE_SIZE")
    scope["observed_ns"] = time.monotonic_ns()


def start_load(lab, snapshots, report):
    config = {"rate_mbit": 8, "delay_ms": 12, "loss_percent": lab.args.outer_loss}
    for label in ("a", "b", "control"):
        args = ["tc", "qdisc", "add", "dev", "eth0", "root", "netem", "delay", "12ms"]
        if lab.args.outer_loss:
            # Count only outer relay TCP segments, independently at each namespace.
            # nth is deterministic and also works with older iproute2 netem versions.
            port = "--sport" if label == "control" else "--dport"
            lab.cmd(label, ["iptables", "-I", "OUTPUT", "-o", "eth0", "-p", "tcp", port, "18081",
                            "-m", "statistic", "--mode", "nth", "--every", "100", "--packet", "99",
                            "-m", "comment", "--comment", "p2wlan-mixed-outer-loss", "-j", "DROP"])
        lab.cmd(label, [*args, "rate", "8mbit"])
    report["mixed_load"] = dict(outer=config, tcp_retransmitted_bytes_before=relay_tcp_counters(lab))
    a, b = (snapshots[name]["virtual_ip"] for name in ("a1", "b1"))
    tool = [sys.executable, str(Path(__file__).resolve())]
    lab.spawn("b", "bulk-receiver", [*tool, "receive", b, str(lab.root)])
    lab.wait("bulk listener", lambda: (lab.root / "bulk-ready").exists(), 4)
    lab.spawn("a", "bulk-sender", [*tool, "send", a, str(lab.root), b])
    lab.wait("first real bulk TUN bytes", lambda: (lab.root / "bulk-active").exists(), 8)


def finish_load(lab, report):
    (lab.root / "bulk-stop").touch()
    lab.wait("bulk receiver completion", lambda: (lab.root / "bulk-result").exists(), 10)
    report["mixed_load"].update(json.loads((lab.root / "bulk-result").read_text()),
                               tcp_retransmitted_bytes_after=relay_tcp_counters(lab))
    if lab.args.outer_loss:
        counters = {}
        for label in ("a", "b", "control"):
            rules = lab.cmd(label, ["iptables-save", "-c", "-t", "filter"]).stdout.splitlines()
            values = [re.match(r"^\[(\d+):(\d+)\]", line) for line in rules if "p2wlan-mixed-outer-loss" in line]
            if len(values) != 1 or values[0] is None:
                raise ValueError("outer_loss_rule_accounting_missing")
            counters[label] = dict(dropped_packets=int(values[0][1]), dropped_ip_bytes=int(values[0][2]))
        report["mixed_load"]["injected_outer_drops"] = counters
        if not any(row["dropped_packets"] for row in counters.values()):
            raise ValueError("outer_loss_never_exercised")


def bulk(role, address, root, target=None):
    root = Path(root)
    end = time.monotonic() + 40
    with socket.socket() as sock:
        sock.settimeout(5)
        sock.bind((address, 44440 if role == "receive" else 0))
        if role == "receive":
            sock.listen(1)
            (root / "bulk-ready").touch()
            conn, _ = sock.accept()
            received = 0
            with conn:
                conn.settimeout(5)
                while time.monotonic() < end:
                    buf = conn.recv(16384)
                    if not buf:
                        break
                    if not received:
                        (root / "bulk-active").touch()
                    received += len(buf)
            result = root / "bulk-tmp"
            result.write_text(json.dumps({"tcp_payload_received_bytes": received}))
            result.rename(root / "bulk-result")
        else:
            sock.connect((target, 44440))
            frame = bytes(4096)
            next_send = time.monotonic()
            while time.monotonic() < end and not (root / "bulk-stop").exists():
                sock.sendall(frame)
                next_send = max(next_send + .008, time.monotonic())
                time.sleep(max(0, next_send - time.monotonic()))


if __name__ == "__main__":
    bulk(*sys.argv[1:])
