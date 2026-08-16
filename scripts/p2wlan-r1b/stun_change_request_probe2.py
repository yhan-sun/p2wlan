#!/usr/bin/env python3
"""R1b §4 capability probe — multi-iteration, NAT-confound-aware.

Key distinction:
  SAME      -> server responded from the EXACT sent-to addr => server IGNORED CHANGE-REQUEST (conclusive)
  CHANGED[x]-> server responded from a different addr      => server HONORED CHANGE-REQUEST (conclusive positive)
  NO_RESP   -> timeout/non-stun. AMBIGUOUS: either server unsupported AND dropped, or server honored but our NAT blackholed the changed-source response.
              (change-IP is almost always NAT-blackholed regardless of server support, so NO_RESP on change-IP tells us little.)

change-port is the robust primary signal (response stays on same external IP, so a lenient NAT lets it through).
"""
import socket, struct, sys
from collections import Counter

SERVERS = [
    ("stun.cloudflare.com", 3478),
    ("stun.miwifi.com", 3478),
    ("stun.l.google.com", 19302),
]
ITER = 6

def build(txn, change_value):
    attrs = b""
    if change_value is not None:
        attrs = struct.pack(">HH", 0x0003, 4) + struct.pack(">I", change_value)
    return struct.pack(">HH", 0x0001, len(attrs)) + b"\x21\x12\xa4\x42" + txn + attrs

def is_stun(data):
    if len(data) < 20: return None
    m = struct.unpack(">H", data[:2])[0]
    return m if m in (0x0101, 0x0111) else None

def rt(name, port, txn, change_value):
    try:
        sent_to = socket.getaddrinfo(name, port, socket.AF_INET, socket.SOCK_DGRAM)[0][4]
    except Exception as e:
        return ("SAME","NO_RESP","SAME"), f"resolve_fail {e}"
    per = {}
    for label, cv in [("base", None), ("cport", 0x02)]:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3.0)
        try:
            s.sendto(build(txn, cv), sent_to)
            try:
                data, src = s.recvfrom(4096)
            except socket.timeout:
                per[label] = "NO_RESP"
            else:
                if is_stun(data) is None:
                    per[label] = "NO_RESP"
                else:
                    per[label] = "SAME" if src == sent_to else "CHANGED"
        finally:
            s.close()
    return per, "ok"

def main():
    for name, port in SERVERS:
        cbase = Counter(); ccport = Counter()
        for i in range(ITER):
            txn = bytes(range(12))
            per, note = rt(name, port, txn, None)
            cbase[per["base"]] += 1
            ccport[per["cport"]] += 1
        print(f"\n{name}:{port}  ({ITER} iterations)")
        print(f"  baseline   : {dict(cbase)}")
        print(f"  change-port: {dict(ccport)}")
        honored = ccport.get("CHANGED", 0)
        ignored = ccport.get("SAME", 0)
        noresp  = ccport.get("NO_RESP", 0)
        if honored:
            print(f"  => HONORS CHANGE-REQUEST ({honored}/{ITER} changed-source)")
        else:
            print(f"  => NO changed-source. ignored={ignored} same-addr, ambiguous-noresp={noresp}")

    print("\n=== CONCLUSION ===")
    print("If no server shows CHANGED on change-port across iterations, production")
    print("STUN does not give a usable EIM/AD signal -> R1b active probe yields nothing.")

if __name__ == "__main__":
    main()
