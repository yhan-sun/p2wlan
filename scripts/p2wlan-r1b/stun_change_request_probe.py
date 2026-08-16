#!/usr/bin/env python3
"""R1b §4 capability probe: does each production STUN server honor RFC 5780
CHANGE-REQUEST?

For each server we:
  1. baseline: plain Binding Request  -> record response source (should == sent-to)
  2. change-ip+port (0x0003, value 0x00000006)
  3. change-port only (0x0003, value 0x00000002)

Verdict per server:
  CHANGED  -> response source differs from the address we sent to (server supports CHANGE-REQUEST)
  SAME     -> response came back from the exact sent-to address (server ignored CHANGE-REQUEST)
  NO_RESP  -> timeout / no STUN response
"""
import socket
import struct
import sys

MAGIC = b"\x21\x12\xa4\x42"
BINDING_REQ = 0x0001
BINDING_RESP = 0x0101
BINDING_ERR = 0x0111
ATTR_CHANGE_REQUEST = 0x0003

SERVERS = [
    ("stun.cloudflare.com", 3478),
    ("stun.miwifi.com", 3478),
    ("stun.l.google.com", 19302),
]

def build_request(txn_id, change_value=None):
    if change_value is None:
        attrs = b""
    else:
        attrs = struct.pack(">HH", ATTR_CHANGE_REQUEST, 4) + struct.pack(">I", change_value)
    length = len(attrs)
    hdr = struct.pack(">HH", BINDING_REQ, length) + MAGIC + txn_id
    return hdr + attrs

def is_stun(data):
    if len(data) < 20:
        return None
    mtype = struct.unpack(">H", data[:2])[0]
    if mtype not in (BINDING_RESP, BINDING_ERR):
        return None
    return mtype

def probe_one(name, port, txn_id):
    """Send 3 requests, return (baseline_src, cip_resp, cport_resp, cip_src, cport_src)."""
    # baseline
    results = {}
    for label, change_value in [("base", None), ("cip+port", 0x06), ("port", 0x02)]:
        # fresh socket per request to keep NAT mappings clean & compare against same sent-to
        results[label] = _roundtrip(name, port, txn_id, change_value)
    return results

def _roundtrip(name, port, txn_id, change_value):
    """Resolve, send one request on a throwaway socket, return (sent_to, resp_src or None, resp_type or None)."""
    addrs = socket.getaddrinfo(name, port, socket.AF_INET, socket.SOCK_DGRAM)
    if not addrs:
        return (None, None, None, "no A record")
    sent_to = addrs[0][4]  # (ip, port)
    pkt = build_request(txn_id, change_value)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3.0)
    try:
        s.sendto(pkt, sent_to)
        try:
            data, src = s.recvfrom(4096)
        except socket.timeout:
            return (sent_to, None, None, "timeout")
        mt = is_stun(data)
        if mt is None:
            return (sent_to, src, None, f"non-stun ({len(data)}b)")
        return (sent_to, src, mt, "ok")
    except OSError as e:
        return (None, None, None, f"oerror: {e}")
    finally:
        s.close()

def classify(sent_to, src, rtype):
    if src is None:
        return "NO_RESP"
    if rtype is None:
        return f"NO_RESP(non-stun)"
    # changed if src differs from sent_to in ip or port
    if src == sent_to:
        return "SAME"
    ip_changed = src[0] != sent_to[0]
    port_changed = src[1] != sent_to[1]
    parts = []
    if ip_changed: parts.append("ip")
    if port_changed: parts.append("port")
    return f"CHANGED[{'+'.join(parts)}]"

def main():
    print(f"{'SERVER':<26}{'sent_to':<22}{'baseline':<10}{'change-ip+port':<22}{'change-port':<22}")
    print("-" * 102)
    summary = {}
    for name, port in SERVERS:
        txn = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b"
        sent_to, src, rtype, note = _roundtrip(name, port, txn, None)
        base_c = classify(sent_to, src, rtype)
        st1, src1, rt1, _ = _roundtrip(name, port, txn, 0x06)
        cip_c = classify(st1, src1, rt1)
        st2, src2, rt2, _ = _roundtrip(name, port, txn, 0x02)
        cport_c = classify(st2, src2, rt2)
        summary[name] = (base_c, cip_c, cport_c)
        print(f"{name+':'+str(port):<26}{str(sent_to):<22}{base_c:<10}{cip_c:<22}{cport_c:<22}  {note}")
    print()
    print("=== R1b viability ===")
    any_support = False
    for name, (base_c, cip_c, cport_c) in summary.items():
        supports = cip_c.startswith("CHANGED") or cport_c.startswith("CHANGED")
        if supports:
            any_support = True
        print(f"  {name:<24} baseline={base_c:<8} change-ip+port={cip_c:<16} change-port={cport_c:<16} -> {'SUPPORTS CHANGE-REQUEST' if supports else 'no changed-source signal'}")
    print()
    if any_support:
        print("  VERDICT: at least one production STUN yields a changed-source response -> R1b active probe CAN obtain EIM/AD signal. PROCEED.")
    else:
        print("  VERDICT: NO production STUN honors CHANGE-REQUEST -> live-safe probe would never get EIM/AD -> R1b has no value. STOP / reconsider.")
    return 0 if any_support else 1

if __name__ == "__main__":
    sys.exit(main())
