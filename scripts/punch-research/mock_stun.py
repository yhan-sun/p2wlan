#!/usr/bin/env python3
"""mock_stun.py — 模拟 STUN 服务器（RFC 5389 Binding + RFC 5780 CHANGE-REQUEST）

用于在无公网 STUN 的环境下验证 puncher.py 的 NAT 检测（RFC 5780 行为探测）。

行为：
  - 收到 RFC 5389 Binding Request → 回 Binding Success Response，
    XOR-MAPPED-ADDRESS = 客户端来源地址（--report-as 可覆盖，模拟 NAT 出口观测）。
  - 收到带 CHANGE-REQUEST 的 Binding Request（--change-addr 已配置）→ 从变更地址
    发送响应（源地址变化，供 filtering 探测判定）。
  - 可选 --drop-source <ip:port>：丢弃来自指定源的请求（模拟上游过滤）。

用法：
  python3 mock_stun.py --port 3478                          # 回显客户端来源
  python3 mock_stun.py --port 3478 --report-as 203.0.113.9:7000   # 模拟 NAT 出口
  python3 mock_stun.py --port 3478 --change-addr 127.0.0.2:3479   # 支持 CHANGE-REQUEST
"""
import argparse
import socket
import struct
import threading
import time

MAGIC_COOKIE = 0x2112A442
BINDING_REQUEST = 0x0001
BINDING_RESPONSE = 0x0101
XOR_MAPPED = 0x0020
CHANGE_REQUEST = 0x0003


def ip_bytes(ip):
    return bytes(int(x) for x in ip.split("."))


def parse_binding(data):
    """解析 Binding Request，返回 (txn, change_mask) 或 None。"""
    if len(data) < 20:
        return None
    mtype, mlen, cookie = struct.unpack(">HHI", data[:8])
    if mtype != BINDING_REQUEST or cookie != MAGIC_COOKIE:
        return None
    txn = data[8:20]
    change = 0
    n = 20
    end = 20 + mlen
    while n + 4 <= end and n + 4 <= len(data):
        t, l = struct.unpack(">HH", data[n:n + 4])
        n += 4
        if n + l > len(data):
            break
        if t == CHANGE_REQUEST and l >= 4:
            change = struct.unpack(">I", data[n:n + 4])[0]
        n += (l + 3) & ~3
    return txn, change


def binding_response(txn, mapped_ip, mapped_port):
    xor_port = mapped_port ^ (MAGIC_COOKIE >> 16)
    cookie = struct.pack(">I", MAGIC_COOKIE)
    xor_ip = bytes(a ^ b for a, b in zip(ip_bytes(mapped_ip), cookie[:4]))
    attr = struct.pack(">HHBBH", XOR_MAPPED, 8, 0, 1, xor_port) + xor_ip
    return struct.pack(">HHI", BINDING_RESPONSE, len(attr), MAGIC_COOKIE) + txn + attr


class MockStunServer:
    def __init__(self, host, port, report_as=None, change_addr=None,
                 change_port=None, drop_sources=None, identity=""):
        self.host = host
        self.report_as = report_as            # (ip, port) 或 None
        self.change_addr = change_addr        # (ip, port) 变更响应源
        self.change_port = change_port        # 变更端口（同 IP 异端口）默认 change_addr.port+1
        self.drop_sources = set(drop_sources or [])
        self.identity = identity
        self._running = False

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port))
        self.port = self.sock.getsockname()[1]
        self.addr = (self.host, self.port)

        self.change_sock = None
        self.change_addr_resolved = None
        if self.change_addr is not None:
            cip, cport = self.change_addr
            if self.change_port is not None:
                cport = self.change_port
            self.change_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.change_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.change_sock.bind((cip, cport))
            self.change_addr_resolved = self.change_sock.getsockname()

        self.stats = {"requests": 0, "change_responses": 0, "dropped": 0}
        self._thread = None

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        return self

    def _mapped(self, client):
        if self.report_as:
            return self.report_as
        return client

    def _drop_check(self, client):
        if client in self.drop_sources or (client[0], None) in self.drop_sources:
            return True
        return False

    def _loop(self):
        while self._running:
            try:
                data, client = self.sock.recvfrom(512)
            except OSError:
                break
            parsed = parse_binding(data)
            if parsed is None:
                continue
            self.stats["requests"] += 1
            if self._drop_check(client):
                self.stats["dropped"] += 1
                continue
            txn, change = parsed
            mapped = self._mapped(client)
            if change and self.change_sock is not None:
                self.stats["change_responses"] += 1
                try:
                    self.change_sock.sendto(binding_response(txn, *mapped), client)
                except OSError:
                    pass
                continue
            try:
                self.sock.sendto(binding_response(txn, *mapped), client)
            except OSError:
                pass

    def ready_line(self):
        parts = [f"READY {self.host}:{self.port}"]
        if self.report_as:
            parts.append(f"report_as={self.report_as[0]}:{self.report_as[1]}")
        if self.change_addr_resolved:
            parts.append(f"change_addr={self.change_addr_resolved[0]}:{self.change_addr_resolved[1]}")
        return " ".join(parts)

    def close(self):
        self._running = False
        try:
            self.sock.close()
        except OSError:
            pass
        if self.change_sock is not None:
            try:
                self.change_sock.close()
            except OSError:
                pass


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=3478)
    ap.add_argument("--report-as", default=None, help="ip:port 覆盖 XOR-MAPPED（模拟 NAT 出口观测）")
    ap.add_argument("--change-addr", default=None, help="ip:port 变更响应源（支持 CHANGE-REQUEST）")
    ap.add_argument("--change-port", type=int, default=None, help="变更响应端口（默认 change-addr.port+1）")
    ap.add_argument("--drop-source", action="append", default=None, help="丢弃来自 ip:port 的请求（可重复）")
    ap.add_argument("--identity", default="")
    a = ap.parse_args()

    def _pair(s):
        ip, _, port = s.rpartition(":")
        return (ip, int(port))

    report_as = _pair(a.report_as) if a.report_as else None
    change_addr = _pair(a.change_addr) if a.change_addr else None
    drops = [_pair(s) for s in (a.drop_source or [])]
    srv = MockStunServer(a.host, a.port, report_as, change_addr, a.change_port, drops, a.identity)
    srv.start()
    print(srv.ready_line(), flush=True)
    print(f"LISTENING {srv.host}:{srv.port}", flush=True)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        srv.close()


if __name__ == "__main__":
    main()
