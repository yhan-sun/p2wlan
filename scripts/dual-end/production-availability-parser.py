#!/usr/bin/env python3
"""Parse one daemon's production first-business relay evidence.

The parser deliberately uses the daemon's monotonic ``t_ms`` values.  A real
decrypted business ingress is the usability evidence; the baseline is the
same-generation per-peer relay-transport-ready milestone.  A locally initiated
relay probe ACK remains a separate relay-admission gate in the dual-end
harness and is never replaced by TCP connect, writer queue acceptance, or
relay metrics.
"""

from __future__ import print_function

import re
import sys


EVENT_RE = re.compile(
    r'event="(relay_transport_ready_peer|relay_peer_confirmed|'
    r'relay_first_business_(sent|received|exchange_confirmed)|'
    r'first_real_business_ingress)"'
)
TIMESTAMP_RE = re.compile(r"\bt_ms=(\d+)")
DETAIL_RE = re.compile(r'detail=(?:Some\()?"([^"]*)"')
PEER_RE = re.compile(r"\bpeer=([^ ]+)")
GENERATION_RE = re.compile(r"\bgeneration=(\d+)")
PATH_RE = re.compile(r'\bpath=(?:Some\()?"([^"]+)"')

# reason codes emitted by the parser; "ok" is the normal relay-first result.
REASON_OK = "ok"
REASON_DIRECT_FIRST_RELAY_CONFIRMED = "direct_first_relay_confirmed"


def first_business_info(log_file, target):
    relay_ready_at = {}
    relay_confirmed_at = {}
    relay_business_seen = {}
    first_business = {}
    try:
        stream = open(log_file, encoding="utf-8", errors="replace")
    except OSError:
        return "|missing|missing|first_business_missing"

    with stream:
        for line in stream:
            event = EVENT_RE.search(line)
            if not event:
                continue
            timestamp = TIMESTAMP_RE.search(line)
            detail = DETAIL_RE.search(line)
            if not timestamp or not detail:
                continue
            detail_text = detail.group(1)
            peer = PEER_RE.search(detail_text)
            generation = GENERATION_RE.search(detail_text)
            if not peer or not generation or peer.group(1) != target:
                continue
            generation_value = int(generation.group(1))
            event_name = event.group(1)
            at_ms = int(timestamp.group(1))
            if event_name == "relay_transport_ready_peer":
                relay_ready_at.setdefault(generation_value, at_ms)
            elif event_name == "relay_peer_confirmed":
                relay_confirmed_at.setdefault(generation_value, at_ms)
            elif event_name.startswith("relay_first_business"):
                relay_business_seen.setdefault(generation_value, at_ms)
            else:
                path = PATH_RE.search(line)
                if path:
                    first_business.setdefault(
                        generation_value, (path.group(1), at_ms)
                    )

    for generation in sorted(first_business):
        path, at_ms = first_business[generation]
        if generation not in relay_ready_at:
            return "|missing|%d|relay_transport_ready_missing" % generation
        delta = at_ms - relay_ready_at[generation]
        if delta < 0:
            return "|missing|%d|business_before_relay_transport_ready" % generation
        if path == "relay":
            return "%s|%d|%d|%s" % (path, delta, generation, REASON_OK)
        # First business arrived over Direct after the relay was already
        # confirmed and relay business was in flight.  The peer may have
        # completed its own relay-first exchange earlier and switched to
        # Direct outbound, so the relay inbound business never arrives even
        # though the relay path is fully usable.  Treat this as a positive
        # relay-confirmed result with the Direct-first note instead of a
        # hard failure.
        if (
            generation in relay_confirmed_at
            and generation in relay_business_seen
        ):
            return (
                "%s|%d|%d|%s" % (path, delta, generation, REASON_DIRECT_FIRST_RELAY_CONFIRMED)
            )
        return "|missing|%d|first_business_not_relay" % generation
    return "|missing|missing|first_business_missing"


def main(argv):
    if len(argv) != 3:
        raise SystemExit("usage: production-availability-parser.py LOG_FILE PEER_ID")
    print(first_business_info(argv[1], argv[2]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
