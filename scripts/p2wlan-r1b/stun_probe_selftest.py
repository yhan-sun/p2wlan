#!/usr/bin/env python3
"""Self-test: prove the probe can DETECT a server that honors CHANGE-REQUEST.
If this script prints CHANGED for the local mock, and NOTHING printed CHANGED for
the production servers, then production STUN genuinely does not support CHANGE-REQUEST
(the probe is not broken)."""
import socket, struct, threading, time, sys

BASE = 35347

def parse_change(data):
    if len(data) < 20: return None
    off = 20
    while off + 4 <= len(data):
        t, l = struct.unpack(">HH", data[off:off+4])
        if t == 0x0003:
            return struct.unpack(">I", data[off+4:off+8])[0]
        off += 4 + l + ((4 - (l % 4)) % 4)
    return None

def resp_for(txn):
    return struct.pack(">HH", 0x0101, 0) + b"\x21\x12\xa4\x42" + txn  # minimal valid binding response

def server(sock_main, sock_alt, stop):
    sock_main.setblocking(False); sock_alt.setblocking(False)
    while not stop:
        for sock, main in [(sock_main, True), (sock_alt, False)]:
            try:
                data, addr = sock.recvfrom(4096)
            except BlockingIOError:
                continue
            except OSError:
                return
            if len(data) < 20: continue
            mtype = struct.unpack(">H", data[:2])[0]
            if mtype != 0x0001: continue
            txn = data[8:20]
            ch = parse_change(data)
            if ch is not None and (ch & 0x02):   # change-port honored -> reply from alt (port+1)
                sock_alt.sendto(resp_for(txn), addr)
            else:
                sock_main.sendto(resp_for(txn), addr)
        time.sleep(0.01)

def probe(name, port, change_value):
    txn = bytes(range(12))
    attrs = b""
    if change_value is not None:
        attrs = struct.pack(">HH", 0x0003, 4) + struct.pack(">I", change_value)
    pkt = struct.pack(">HH", 0x0001, len(attrs)) + b"\x21\x12\xa4\x42" + txn + attrs
    sent_to = (name, port)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2.0)
    try:
        s.sendto(pkt, sent_to)
        data, src = s.recvfrom(4096)
        mt = struct.unpack(">H", data[:2])[0]
        if mt not in (0x0101, 0x0111): return "NO_RESP"
        return "SAME" if src == sent_to else f"CHANGED[{'+'.join(['ip' if src[0]!=sent_to[0] else '' for _ in [0]] + ['port' if src[1]!=sent_to[1] else ''])}]"
    except socket.timeout:
        return "NO_RESP"
    finally:
        s.close()

def main():
    main_s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); main_s.bind(("127.0.0.1", BASE))
    alt_s  = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); alt_s.bind(("127.0.0.1", BASE+1))
    stop = threading.Event()
    th = threading.Thread(target=server, args=(main_s, alt_s, stop), daemon=True); th.start()
    time.sleep(0.2)
    for i in range(5):
        base = probe("127.0.0.1", BASE, None)
        cport = probe("127.0.0.1", BASE, 0x02)
        print(f"  iter{i}: baseline={base:<8} change-port={cport}")
    stop.set(); time.sleep(0.1)
    print("\nSELF-TEST: if change-port shows CHANGED[port] above, the probe correctly")
    print("detects a CHANGE-REQUEST-honoring server. Combined with 0x CHANGED on the")
    print("production STUNs, that is conclusive.")

if __name__ == "__main__":
    main()
