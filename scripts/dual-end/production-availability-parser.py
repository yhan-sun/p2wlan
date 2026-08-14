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
    r'event="(relay_transport_ready_peer|first_real_business_ingress)"'
)
TIMESTAMP_RE = re.compile(r"\bt_ms=(\d+)")
DETAIL_RE = re.compile(r'detail=(?:Some\()?"([^"]*)"')
PEER_RE = re.compile(r"\bpeer=([^ ]+)")
GENERATION_RE = re.compile(r"\bgeneration=(\d+)")
PATH_RE = re.compile(r'\bpath=(?:Some\()?"([^"]+)"')


def first_business_info(log_file, target):
    relay_ready_at = {}
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
            at_ms = int(timestamp.group(1))
            if event.group(1) == "relay_transport_ready_peer":
                relay_ready_at.setdefault(generation_value, at_ms)
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
        if path != "relay":
            return "|missing|%d|first_business_not_relay" % generation
        return "%s|%d|%d|ok" % (path, delta, generation)
    return "|missing|missing|first_business_missing"


def main(argv):
    if len(argv) != 3:
        raise SystemExit("usage: production-availability-parser.py LOG_FILE PEER_ID")
    print(first_business_info(argv[1], argv[2]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
