"""Two INPUT DROP rules in one original, retained target namespace FD."""
from __future__ import annotations

import copy
import hashlib
import ipaddress
import os
import re
import shlex
import subprocess
import time

from linux_tun_fault_contract import PORTS, validate_manifest

MAX_RULES = 2
MAX_NAMESPACE_FDS = 1
SNAPSHOT_BYTES = 65536


def open_namespace(name: str, original_daemon_pid: int) -> tuple[int, dict]:
    fd = os.open("/var/run/netns/" + name, os.O_RDONLY | os.O_CLOEXEC)
    try:
        actual, daemon = os.fstat(fd), os.stat(f"/proc/{original_daemon_pid}/ns/net")
        if (actual.st_dev, actual.st_ino) != (daemon.st_dev, daemon.st_ino):
            raise RuntimeError("original daemon and named namespace identity differ")
        return fd, {"device": actual.st_dev, "inode": actual.st_ino}
    except BaseException:
        os.close(fd)
        raise


def decode_owned_rule(tokens: list[str]) -> dict:
    if tokens[:2] != ["-A", "INPUT"]:
        raise ValueError("owned rule moved outside INPUT")
    result, modules = {}, []
    for key, value in zip(tokens[2::2], tokens[3::2]):
        if key == "-m":
            modules.append(value)
        elif key in ("-s", "-d", "-i", "-p", "--dport", "--sports", "--comment", "-j") and key not in result:
            result[key] = str(ipaddress.ip_network(value)) if key in ("-s", "-d") else value
        else:
            raise ValueError("owned rule arguments changed")
    if len(tokens) % 2 or len(modules) != 3 or len(set(modules)) != 3:
        raise ValueError("owned rule grammar changed")
    result["modules"] = sorted(modules)
    return result


class FaultOwner:
    def __init__(self, namespace: str, plan: dict, created_namespaces: list[str], source: dict,
                 target: dict, entries: list[dict], *, runner=subprocess.run) -> None:
        validate_manifest(entries)
        if (not plan.get("preflight_all_absent") or namespace not in plan["namespaces"]
                or namespace not in created_namespaces or re.fullmatch(r"[a-z0-9-]+", namespace) is None):
            raise ValueError("fault namespace was not created/admitted by this original run")
        for endpoint, peer in ((source, target), (target, source)):
            kernel = endpoint["kernel"]
            if (kernel["kind"] != "tun" or kernel["vip"] != endpoint["virtual_ip"]
                    or kernel["route_to_peer"] != {"dst": peer["virtual_ip"], "dev": kernel["ifname"], "prefsrc": endpoint["virtual_ip"]}
                    or source["run_id"] != target["run_id"]):
                raise ValueError("fault endpoints no longer describe the original kernel TUN routes")
        kernel = target["kernel"]
        self.runner = runner
        self.rules = []
        for protocol in ("udp", "tcp"):
            ports = PORTS[protocol]
            marker = "p2wlan-d03-" + entries[0]["run_nonce"] + "-" + protocol
            args = ["-s", source["virtual_ip"] + "/32", "-d", target["virtual_ip"] + "/32",
                    "-i", kernel["ifname"], "-p", protocol, "-m", protocol, "--dport", str(ports[2]),
                    "-m", "multiport", "--sports", str(ports[0]) + "," + str(ports[1]),
                    "-m", "comment", "--comment", marker, "-j", "DROP"]
            self.rules.append({"protocol": protocol, "marker": marker, "args": args,
                               "decoded": decode_owned_rule(["-A", "INPUT", *args])})
        # Validate fixed rule data before acquiring the native descriptor.
        self.fd, pin = open_namespace(namespace, target["process_id"])
        self.origin = copy.deepcopy({"namespace": namespace, "namespace_identity": pin,
                                     "source": source, "target": target})
        self.registered = False
        self.closed = False
        self.evidence = {"origin": self.origin, "planned_rule_count": MAX_RULES,
                         "scope": "original_target_namespace_application_input_flow_rules_only"}

    def command(self, args: list[str], deadline: float | None = None):
        if self.closed:
            raise RuntimeError("original fault namespace descriptor already closed")
        timeout = 20 if deadline is None else min(20, deadline - time.monotonic())
        if timeout <= 0:
            raise TimeoutError("original shared network cleanup deadline")
        return self.runner(["nsenter", "--net=/proc/self/fd/" + str(self.fd), "--", *args],
                           pass_fds=(self.fd,), text=True, capture_output=True, timeout=timeout, check=False)

    def read_rules(self, deadline: float | None = None) -> dict:
        result = self.command(["iptables-save", "-c", "-t", "filter"], deadline)
        if result.returncode != 0 or len(result.stdout.encode()) > SNAPSHOT_BYTES:
            raise RuntimeError("original rule counter snapshot unavailable or oversized")
        found = {r["marker"]: [] for r in self.rules}
        lines = result.stdout.splitlines()
        if result.stdout.strip() and (lines.count("*filter") != 1 or lines.count("COMMIT") != 1
                                     or lines.index("*filter") >= lines.index("COMMIT")):
            raise ValueError("original filter snapshot incomplete")
        for index, line in enumerate(lines):
            if not line.startswith("["):
                if line.startswith("-A "):
                    raise ValueError("original rule counters missing")
                continue
            if not lines.index("*filter") < index < lines.index("COMMIT"):
                raise ValueError("original counter outside filter table")
            matched = re.fullmatch(r"\[(\d+):(\d+)\] (.+)", line)
            if matched is None:
                raise ValueError("original counter grammar changed")
            tokens = shlex.split(matched[3])
            comments = [i for i, token in enumerate(tokens) if token == "--comment"]
            if any(i + 1 >= len(tokens) for i in comments):
                raise ValueError("original rule comment value missing")
            markers = [tokens[i + 1] for i in comments if tokens[i + 1] in found]
            if markers:
                if len(comments) != 1 or len(markers) != 1:
                    raise ValueError("original marker mixed with another comment")
                marker = markers[0]
                rule = next(r for r in self.rules if r["marker"] == marker)
                if decode_owned_rule(tokens) != rule["decoded"]:
                    raise ValueError("same comment no longer matches the exact original rule")
                found[marker].append({"protocol": rule["protocol"], "marker": marker,
                                      "packets": int(matched[1]), "bytes": int(matched[2])})
        if any(len(rows) > 1 for rows in found.values()):
            raise ValueError("duplicate original fault rule identity")
        return {"observed_monotonic_ns": time.monotonic_ns(), "rules": [rows[0] for rows in found.values() if rows],
                "namespace_identity": self.origin["namespace_identity"],
                "raw_snapshot_sha256": hashlib.sha256(result.stdout.encode()).hexdigest()}

    def install(self) -> None:
        if self.registered:
            raise RuntimeError("original fault rules already registered")
        before = self.read_rules()
        self.evidence["preflight"] = before
        if before["rules"]:
            raise ValueError("fault marker existed before this owner registered")
        # Register before mutation, so timeout/partial add cannot orphan a rule.
        self.registered = True
        self.evidence["add_results"] = []
        for rule in self.rules:
            result = self.command(["iptables", "-t", "filter", "-A", "INPUT", *rule["args"]])
            self.evidence["add_results"].append({"protocol": rule["protocol"], "returncode": result.returncode})
            if result.returncode != 0:
                raise RuntimeError("original fault rule add failed")
        snapshot = self.read_rules()
        if len(snapshot["rules"]) != MAX_RULES or any(r["packets"] or r["bytes"] for r in snapshot["rules"]):
            raise RuntimeError("original fault rules not installed with empty initial counters")
        self.evidence["before_requests"] = snapshot

    def counter_snapshot(self) -> dict:
        snapshot = self.read_rules()
        if len(snapshot["rules"]) != MAX_RULES:
            raise RuntimeError("original fault disappeared before blocked requests settled")
        self.evidence["after_blackhole"] = snapshot
        return snapshot

    def remove(self, deadline: float | None, *, require_present: bool) -> dict:
        operations, errors = [], []
        try:
            before = self.read_rules(deadline)
            present = {r["marker"] for r in before["rules"]}
        except Exception as error:
            return {"complete": False, "remaining": ["rule_inventory_unknown"], "operations": [],
                    "error": type(error).__name__, "all_owned_rules_observed_absent": False}
        for rule in self.rules:
            if rule["marker"] not in present:
                if require_present:
                    errors.append(rule["protocol"] + "_missing_before_clear")
                continue
            try:
                result = self.command(["iptables", "-t", "filter", "-D", "INPUT", *rule["args"]], deadline)
                operations.append({"protocol": rule["protocol"], "returncode": result.returncode})
                if result.returncode != 0:
                    errors.append(rule["protocol"] + "_delete_failed")
            except Exception as error:
                operations.append({"protocol": rule["protocol"], "error": type(error).__name__})
                errors.append(rule["protocol"] + "_delete_unknown")
        try:
            after = self.read_rules(deadline)
            remaining = [r["marker"] for r in after["rules"]]
        except Exception as error:
            after, remaining = None, ["final_rule_inventory_unknown"]
            errors.append(type(error).__name__)
        return {"complete": not remaining and not errors, "remaining": remaining, "operations": operations,
                "errors": errors, "after": after, "all_owned_rules_observed_absent": not remaining,
                "observed_monotonic_ns": time.monotonic_ns()}

    def clear(self) -> dict:
        result = self.remove(None, require_present=True)
        self.evidence["normal_clear"] = result
        if not result["complete"]:
            raise RuntimeError("original fault rule clear incomplete")
        return result

    def cleanup(self, deadline: float) -> dict:
        if self.closed:
            return self.evidence["cleanup"]
        result = (self.remove(deadline, require_present=False) if self.registered else
                  {"complete": True, "admitted": False, "operations": [], "remaining": [],
                   "all_owned_rules_observed_absent": None})
        try:
            os.close(self.fd)
            result["original_namespace_fd_closed"] = True
        except OSError as error:
            result.update(complete=False, original_namespace_fd_closed=False, close_error=type(error).__name__)
        self.closed = True
        self.evidence["cleanup"] = result
        return result
