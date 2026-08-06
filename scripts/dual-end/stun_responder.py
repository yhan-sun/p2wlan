#!/usr/bin/env python3
"""Minimal STUN binding-response server for the loopback dual-end smoke.

Implements exactly the subset p2pnet_nat needs: echo the request's
transaction id and reflect the sender's source address as XOR-MAPPED-ADDRESS.
"""
import socket
import struct
import sys

MAGIC_COOKIE = 0x2112A442
BINDING_REQUEST = 0x0001
BINDING_RESPONSE = 0x0101
XOR_MAPPED_ADDRESS = 0x0020


def make_binding_response(transaction_id: bytes, source: tuple) -> bytes:
    # XOR-MAPPED-ADDRESS attribute: type(2) length(2) then the value layout
    # reserved(1) family(1) x-port(2) x-address(4).  Per RFC 5389 the SENDER
    # XORs the port and address with the magic cookie; the decoder XORs them
    # back.  The address is FIXED to 127.0.0.1: sandboxed environments NAT
    # the loopback egress, so the raw source of the request would be the
    # sandbox's public IP — an unreachable artifact.  A real STUN server on
    # the same host as a loopback-bound client observes 127.0.0.1, and the
    # peers can actually reach that on the shared loopback.
    addr = struct.unpack(">I", socket.inet_aton("127.0.0.1"))[0]
    x_addr = struct.pack(">I", MAGIC_COOKIE ^ addr)
    attr = (
        struct.pack(">HHBBH", XOR_MAPPED_ADDRESS, 8, 0x00, 0x01, source[1] ^ (MAGIC_COOKIE >> 16))
        + x_addr
    )
    header = struct.pack(">HHI", BINDING_RESPONSE, len(attr), MAGIC_COOKIE)
    return header + transaction_id + attr


def main() -> None:
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 3478
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    print(f"stun-responder listening on {host}:{port}", flush=True)
    while True:
        data, source = sock.recvfrom(2048)
        if len(data) < 20:
            continue
        msg_type, _length, cookie = struct.unpack(">HHI", data[:8])
        if cookie != MAGIC_COOKIE or msg_type != BINDING_REQUEST:
            continue
        transaction_id = data[8:20]
        sock.sendto(make_binding_response(transaction_id, source), source)


if __name__ == "__main__":
    main()
