#!/usr/bin/env python3
"""One OS UDP echo socket, two fixed phases, one absolute ten-second lifetime."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import select
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "dual-end"))
import udp_business_probe as udp
from linux_tun_stall_contract import COUNT, PHASES, TIMING, validate_manifest


def configs(plan: dict) -> list[udp.Config]:
    validate_manifest(plan["entries"])
    result = [udp.Config((plan["target_ip"], entry["target_port"]), (plan["source_ip"], entry["source_port"]),
                         entry["run_nonce"], entry["round_nonce"], COUNT, **TIMING) for entry in plan["entries"]]
    for config in result:
        config.validate()
    return result


def accept_frame(configurations: list[udp.Config], seen: dict, data: bytes, source: tuple):
    for phase, config in zip(PHASES, configurations):
        reason, frame = udp.frame_reason(config, data, source)
        if reason is not None:
            continue
        if frame[0] != udp.REQUEST or frame[3] >= COUNT or frame[3] in seen[phase]:
            return None
        seen[phase][frame[3]] = frame[4]
        return phase, frame[3], udp.encode(config, frame[3], frame[4], udp.RESPONSE)
    return None


def run_echo(plan: dict, ready: Path, *, sock=None, now=time.monotonic_ns, select_ready=select.select) -> dict:
    configurations = configs(plan)
    supplied = sock is not None
    sock = udp.open_socket(configurations[0], sock)
    started = now()
    end = started + TIMING["duration_ms"] * udp.NS_PER_MS
    seen = {phase: {} for phase in PHASES}
    report = {"schema_version": 1, "scope": "os_udp_two_phase_echo", "process_id": os.getpid(),
              "tool_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "manifest_sha256": hashlib.sha256(json.dumps(plan, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
              "started_monotonic_ns": started, "end_monotonic_ns": end,
              "responses_sent_by_phase": {phase: 0 for phase in PHASES}, "send_errors": 0,
              "response_completed_monotonic_ns": {phase: {} for phase in PHASES},
              "received_datagrams": 0, "invalid_datagrams": 0,
              "termination_reason": "duration_deadline", "evidence": dict(udp.UNVERIFIED)}
    try:
        # Producer clock and PID are actual observations, not a log-control gate.
        temporary = ready.with_name(ready.name + ".pending")
        udp.write_report(temporary, {key: report[key] for key in (
            "process_id", "manifest_sha256", "tool_sha256", "started_monotonic_ns", "end_monotonic_ns")})
        os.link(temporary, ready)  # Complete exclusive receipt, no partially visible JSON.
        temporary.unlink()
        while report["received_datagrams"] < udp.MAX_RX_DATAGRAMS:
            remaining = end - now()
            if remaining <= 0:
                break
            if not select_ready([sock], [], [], remaining / 1_000_000_000)[0]:
                continue
            data, source = sock.recvfrom(udp.MAX_DATAGRAM_BYTES + 1)
            report["received_datagrams"] += 1
            # STOP/CONT never resets end; a queued old frame past it gets no credit.
            if now() >= end:
                break
            accepted = accept_frame(configurations, seen, data, source)
            if accepted is None:
                report["invalid_datagrams"] += 1
                continue
            phase, sequence, response = accepted
            try:
                if sock.sendto(response, source) != len(response):
                    raise OSError("stall_echo_short_send")
                report["responses_sent_by_phase"][phase] += 1
                report["response_completed_monotonic_ns"][phase][sequence] = now()
            except OSError:
                report["send_errors"] += 1
                raise
            if all(len(seen[phase]) == COUNT for phase in PHASES):
                report["termination_reason"] = "request_budget_exhausted"
                break
        else:
            report["termination_reason"] = "receive_budget_exhausted"
    except KeyboardInterrupt:
        report["termination_reason"] = "interrupted"
    except OSError as error:
        report.update(termination_reason="socket_failed", socket_error_errno=error.errno)
    finally:
        report["elapsed_ns"] = now() - started
        report["accepted_request_nonces"] = seen
        if not supplied:
            sock.close()
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--ready", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.manifest.stat().st_size > 8192:
        parser.error("stall_echo_manifest_too_large")
    udp.validate_output_path(args.ready)
    udp.validate_output_path(args.output)
    report = run_echo(json.loads(args.manifest.read_text()), args.ready)
    udp.write_report(args.output, report)
    return int(report["responses_sent_by_phase"] != {phase: COUNT for phase in PHASES}
               or report["send_errors"] != 0 or report["termination_reason"] != "request_budget_exhausted")


if __name__ == "__main__":
    raise SystemExit(main())
