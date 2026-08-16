#!/usr/bin/env python3
"""nat_sim.py — 双 NAT 模拟器 + puncher 双端集成验证（确定性、可复现）

在两朵「真实 loopback socket + 用户态映射/分配/过滤」模拟 NAT 之间打通，并驱动双端
puncher 子进程完成 RFC 5780 检测 + 打洞，输出 JSON 报告。用于系统性矩阵验证。

设计（对齐用户确认的语义）：
  - binding 轴（--mapping=ei|ad|apd）：控制映射键 —— 同一五元组是否恒映射。
      ei  = 按客户端端口恒定映射（同 socket 跨目标复用公网端口）
      ad  = 按 (客户端, 目标IP) 映射（同 IP 复用、异 IP 新端口）
      apd = 按 (客户端, 目标IP, 目标端口) 映射（每目标新端口，symmetric）
  - allocation 轴（--allocation=stable|linear|random）：新映射的端口选择。
      stable = 同一键固定端口（现实中少见 —— ISP 级 port preservation，矩阵标注"低现实频率"）
      linear = 端口按 step 递增；random = 随机。
  - filtering 轴（--filtering=ei|ad|apd|none）：入站过滤。
      ei=端点无关放行；ad=同目标IP放行；apd=精确目标端点放行。

拓扑：所有 socket 绑 127.0.0.1（单 IP，无 lo 别名依赖）。
  - NAT A 私有客户端段 [priv_a, priv_a+512)，公网段 [pub_a, pub_a+800)（虚拟 IP 203.0.113.1）
  - NAT B 私有客户端段 [priv_b, priv_b+512)，公网段 [pub_b, pub_b+800)（虚拟 IP 203.0.113.2）
  - 第二 STUN 服务器身份用虚拟 IP 203.0.113.3（RFC 5780 "异 IP" 测试，通过 observer 端口分组）
  - observer 固定占 pub+1..pub+5；动态映射端口从 pub+100 起分配。

用法（单组合）：
  python3 nat_sim.py --mapping-a ei --allocation-a stable --filtering-a ei \
                     --mapping-b apd --allocation-b linear --step-b 3 --filtering-b ei \
                     --puncher puncher.py --json-out report.json

  run_matrix.py 循环调用本脚本跑全矩阵。
"""
import argparse
import asyncio
import collections
import errno
import json
import os
import random
import re
import struct
import sys
import time

# ===== 虚拟 IP =====
VIP_A = "203.0.113.1"
VIP_B = "203.0.113.2"
VIP_C = "203.0.113.3"      # 第二 STUN 服务器身份（异 IP 测试）

# ===== STUN =====
MAGIC_COOKIE = 0x2112A442
BINDING_REQUEST = 0x0001
BINDING_RESPONSE = 0x0101
XOR_MAPPED = 0x0020
CHANGE_REQUEST = 0x0003

MAPPING_MODES = ("ei", "ad", "apd")
ALLOC_MODES = ("stable", "linear", "random")
FILTER_MODES = ("ei", "ad", "apd", "none")


def ip_bytes(ip):
    return bytes(int(x) for x in ip.split("."))


def parse_stun(data):
    """解析 Binding Request，返回 (txn, change_mask) 或 (None, 0)。"""
    if len(data) < 20:
        return None, 0
    mtype, mlen, cookie = struct.unpack(">HHI", data[:8])
    if mtype != BINDING_REQUEST or cookie != MAGIC_COOKIE:
        return None, 0
    txn = data[8:20]
    change = 0
    n, end = 20, 20 + mlen
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


class Mapping:
    __slots__ = ("key", "client", "dest_vip", "dest_port", "port",
                 "transport", "bind_task", "send_task", "pending")

    def __init__(self, key, client, dest_vip, dest_port, port):
        self.key = key
        self.client = client
        self.dest_vip = dest_vip
        self.dest_port = dest_port
        self.port = port
        self.transport = None
        self.bind_task = None
        self.send_task = None
        self.pending = collections.deque()


class ObserverProtocol(asyncio.DatagramProtocol):
    def __init__(self, nat, port):
        self.nat = nat
        self.port = port
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.nat.handle_stun(addr, self.port, data)


class ForwarderProtocol(asyncio.DatagramProtocol):
    """公网映射端口收包。区分「私有客户端直发（需源 NAT 翻译）」与「公网源（直接入站）」。"""

    def __init__(self, nat, port):
        self.nat = nat
        self.port = port

    def datagram_received(self, data, addr):
        self.nat.handle_forward(self.port, data, addr)


class Fabric:
    """跨 NAT 拓扑：私有客户端归属 / 公网端点身份 / 虚拟 IP 解析。"""

    def __init__(self):
        self.nats = []
        self.priv_ranges = {}          # nat -> (lo, hi)
        self.trace = []

    def set_nats(self, nats, priv_ranges):
        self.nats = nats
        self.priv_ranges = priv_ranges

    def record(self, event, **fields):
        self.trace.append({"event": event, "t": round(time.time() * 1000), **fields})

    def owner_of_private(self, addr):
        if addr[0] != "127.0.0.1":
            return None
        for nat, (lo, hi) in self.priv_ranges.items():
            if lo <= addr[1] <= hi:
                return nat
        return None

    def vip_of_public_port(self, port):
        """端口 → 虚拟 IP（公网 forwarder 端口 = 所属 NAT 公网；observer 端口 = 配置的虚拟 IP）。"""
        for nat in self.nats:
            if port in nat.forwarders:
                return nat.vip_self
            if port in nat.observer_vip:
                return nat.observer_vip[port]
        return None

    def mapping_for_public_endpoint(self, addr):
        for nat in self.nats:
            if addr[0] == "127.0.0.1" and addr[1] in nat.mapping_by_port:
                m = nat.mapping_by_port[addr[1]]
                if m.transport is not None:
                    return nat, m
        return None, None


class SimNat:
    def __init__(self, name, vip_self, port_base, port_pool, mapping,
                 allocation, step, filtering, seed, fabric=None, hairpin=False):
        if mapping not in MAPPING_MODES:
            raise ValueError(f"--mapping must be one of {MAPPING_MODES}")
        if allocation not in ALLOC_MODES:
            raise ValueError(f"--allocation must be one of {ALLOC_MODES}")
        if filtering not in FILTER_MODES:
            raise ValueError(f"--filtering must be one of {FILTER_MODES}")
        self.name = name
        self.vip_self = vip_self
        self.port_base = port_base
        self.port_pool = port_pool
        self.mapping = mapping
        self.allocation = allocation
        self.step = step if allocation == "linear" else 0
        self.filtering = filtering
        self.hairpin = hairpin
        self.rng = random.Random(seed)
        self.fabric = fabric
        self.next_port = port_base + 100      # 动态映射端口从 pub+100 起
        self.stable_home = {}
        self.mappings = {}
        self.mapping_by_port = {}
        self.forwarders = {}
        self.observer_vip = {}                # 端口 -> 虚拟 IP
        self.observer_transports = {}         # 端口 -> transport
        self.change_port_partner = {}
        self.change_ip_partner = {}
        self.loop = None
        self.alloc_events = []

    # ---- 生命周期 ----
    async def start(self, fabric=None):
        self.loop = asyncio.get_running_loop()
        if fabric is not None:
            self.fabric = fabric
        return self

    async def add_observers(self):
        """绑定 5 个 observer（VIP 分组），返回 list[(vip, real_port)] 供 puncher --stun。"""
        ports = [self.port_base + 1, self.port_base + 2, self.port_base + 3,
                 self.port_base + 4, self.port_base + 5]
        vips = [self.vip_self, self.vip_self, VIP_C, self.vip_self, VIP_C]
        out = []
        for port, vip in zip(ports, vips):
            transport, _ = await self.loop.create_datagram_endpoint(
                lambda port=port: ObserverProtocol(self, port),
                local_addr=("127.0.0.1", port))
            self.observer_vip[port] = vip
            self.observer_transports[port] = transport
            out.append((vip, port))
        # change 伙伴：change-port → 同 VIP 异端口；change-ip → VIP_C（异 IP）observer
        p1, p2, p3, p4, p5 = ports
        self.change_port_partner = {p1: p2, p2: p1, p3: p5, p5: p3, p4: p1}
        self.change_ip_partner = {p1: p3, p2: p3, p3: p1, p4: p3, p5: p1}
        return out

    async def close(self):
        tasks = []
        for m in self.mappings.values():
            for t in (m.bind_task, m.send_task):
                if t is not None and not t.done():
                    t.cancel()
                    tasks.append(t)
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        for tr in self.observer_transports.values():
            tr.close()
        for tr in self.forwarders.values():
            tr.close()

    # ---- 映射 ----
    def mapping_key(self, client, dest_vip, dest_port):
        if self.mapping == "ei":
            return ("ei", client)
        if self.mapping == "ad":
            return ("ad", client, dest_vip)
        return ("apd", client, dest_vip, dest_port)

    def _raw_alloc_free(self):
        for _ in range(4096):
            if self.allocation == "linear":
                p = self.next_port
                self.next_port = (p - self.port_base + self.step) % self.port_pool + self.port_base
            else:
                # stable：同一键固定（home 缓存），新键走随机（低现实频率的稳定分配）
                # random：新映射随机端口
                p = self.rng.randint(self.port_base, self.port_base + self.port_pool - 1)
            if p in self.observer_vip or p in self.mapping_by_port or p in self.forwarders:
                continue
            return p
        raise RuntimeError(f"NAT {self.name} port pool exhausted")

    def alloc_port(self, client, key):
        if self.allocation == "stable":
            # stable 语义：同一内部会话（client）端口永久复用（跨目标、跨时间不变）。
            # 若按 key 缓存，同 socket 的多目标探测会得到顺序分配的假 linear 序列。
            if client not in self.stable_home:
                self.stable_home[client] = self._raw_alloc_free()
            return self.stable_home[client]
        return self._raw_alloc_free()

    def mapping_for(self, client, dest_vip, dest_port):
        key = self.mapping_key(client, dest_vip, dest_port)
        m = self.mappings.get(key)
        if m is not None:
            # 复用映射（EI/AD 同键）：更新「最近发送目标」——filtering 按最新目标判定入站
            m.dest_vip = dest_vip
            m.dest_port = dest_port
            return m
        port = self.alloc_port(client, key)
        m = Mapping(key, client, dest_vip, dest_port, port)
        self.mappings[key] = m
        self.mapping_by_port[port] = m
        self.alloc_events.append({
            "key": repr(key), "client": f"{client[0]}:{client[1]}",
            "dest_vip": dest_vip, "dest_port": dest_port, "port": port,
        })
        if self.loop is not None:
            m.bind_task = self.loop.create_task(self._bind_forwarder(m))
        return m

    async def _bind_forwarder(self, m):
        while m.transport is None:
            try:
                transport, _ = await self.loop.create_datagram_endpoint(
                    lambda m=m: ForwarderProtocol(self, m.port),
                    local_addr=("127.0.0.1", m.port))
                m.transport = transport
                self.forwarders[m.port] = transport
            except OSError as error:
                if error.errno != errno.EADDRINUSE:
                    raise
                # 端口被占用 → 重分配（保持确定性）
                old = m.port
                new = self._raw_alloc_free()
                if old in self.mapping_by_port:
                    del self.mapping_by_port[old]
                m.port = new
                self.mapping_by_port[new] = m

    async def _flush_mapping(self, m):
        try:
            if m.bind_task is not None:
                await asyncio.shield(m.bind_task)
            while m.pending:
                data, dst = m.pending.popleft()
                if m.transport is not None:
                    m.transport.sendto(data, dst)
                    if self.fabric is not None:
                        self.fabric.record("outbound_flushed", nat=self.name,
                                           mapping_port=m.port, dst=dst)
        except OSError:
            m.pending.clear()
        finally:
            m.send_task = None

    # ---- STUN 处理（observer） ----
    def handle_stun(self, client, obs_port, data):
        txn, change = parse_stun(data)
        if txn is None:
            return
        dest_vip = self.observer_vip.get(obs_port)
        if dest_vip is None:
            return
        mapping = self.mapping_for(client, dest_vip, obs_port)
        if change:
            resp = self.change_source(dest_vip, obs_port, change)
            if resp is None:
                self._reply_stun(client, obs_port, mapping, txn)
                return
            rvip, rport = resp
            # 模拟「服务器从变更地址响应」：源 (rvip, rport)，经本 NAT filtering 判定
            if not self.filtering_allows(mapping, rvip, rport):
                if self.fabric is not None:
                    self.fabric.record("stun_change_drop", nat=self.name,
                                       from_port=obs_port, to=(rvip, rport),
                                       filtering=self.filtering)
                return
            self._reply_stun(client, rport, mapping, txn)
            return
        self._reply_stun(client, obs_port, mapping, txn)

    def change_source(self, dest_vip, obs_port, change_mask):
        # change_mask: bit0=change-ip, bit1=change-port
        if change_mask & 1:
            partner = self.change_ip_partner.get(obs_port)
        elif change_mask & 2:
            partner = self.change_port_partner.get(obs_port)
        else:
            return None
        if partner is None:
            return None
        return (self.observer_vip.get(partner), partner)

    def _reply_stun(self, client, from_port, mapping, txn):
        tr = self.observer_transports.get(from_port)
        if tr is None:
            tr = self.forwarders.get(mapping.port)
        if tr is None:
            return
        tr.sendto(binding_response(txn, "127.0.0.1", mapping.port), client)

    # ---- 数据面 ----
    def handle_forward(self, port, data, src):
        owner = self.fabric.owner_of_private(src) if self.fabric else None
        if owner is not None:
            # src 是某 NAT 的私有客户端（含本 NAT 自身）→ 由该 NAT 源翻译后重发。
            # （之前 `owner is not self` 把「本端私有客户端发往本端公网 forwarder」
            #  误入 handle_inbound → hairpin/回环路径断裂）
            owner.translate_outbound(src, port, data)
            return
        self.handle_inbound(port, data, src)

    def translate_outbound(self, client, dst_port, data):
        dst_vip = self.fabric.vip_of_public_port(dst_port) if self.fabric else "loopback"
        if dst_vip is None:
            dst_vip = "loopback"
        mapping = self.mapping_for(client, dst_vip, dst_port)
        mapping.pending.append((data, ("127.0.0.1", dst_port)))
        if self.fabric is not None:
            self.fabric.record("outbound_translated", nat=self.name,
                               client=f"{client[0]}:{client[1]}", dst_port=dst_port,
                               mapping_port=mapping.port, transport=mapping.transport is not None)
        if mapping.send_task is None or mapping.send_task.done():
            mapping.send_task = self.loop.create_task(self._flush_mapping(mapping))

    def filtering_allows(self, mapping, src_vip, src_port):
        f = self.filtering
        if f in ("none", "ei"):
            return True
        if f == "ad":
            return src_vip == mapping.dest_vip
        if f == "apd":
            return src_vip == mapping.dest_vip and src_port == mapping.dest_port
        return True

    def handle_inbound(self, port, data, src):
        mapping = self.mapping_by_port.get(port)
        if mapping is None:
            return
        src_vip = self.fabric.vip_of_public_port(src[1]) if self.fabric else None
        if src_vip is None:
            return
        # S2 hairpin 轴：源 == 本 NAT 自身公网端点（自回环）。
        # 真实 NAT 的 hairpin 回环由 NAT 自身发起，不受外部入站 filtering 限制；
        # hairpin=no 时丢弃（模拟不支持回环）。
        if src_vip == self.vip_self:
            if not self.hairpin:
                if self.fabric is not None:
                    self.fabric.record("hairpin_drop", nat=self.name, port=port, src=src)
                return
            if self.fabric is not None:
                self.fabric.record("hairpin_admitted", nat=self.name, port=port, src=src)
            # hairpin echo：客户端向自身出口映射发 STUN Binding → 以本 NAT 公网端点
            # （即该映射端口）回显响应（XOR-MAPPED=客户端出口）→ 观察回环。
            txn, change = parse_stun(data)
            if txn is not None and mapping.transport is not None:
                mapping.transport.sendto(binding_response(txn, "127.0.0.1", mapping.port),
                                         mapping.client)
                return
            # 非 STUN：正常回环投递
        elif not self.filtering_allows(mapping, src_vip, src[1]):
            if self.fabric is not None:
                self.fabric.record("inbound_filter_drop", nat=self.name,
                                   port=port, src=src, expected=(
                                       f"{mapping.dest_vip}:{mapping.dest_port}"),
                                   filtering=self.filtering)
            return
        if self.fabric is not None:
            self.fabric.record("inbound_admitted", nat=self.name, port=port, src=src)
        # 投递：用发送方 NAT 的映射 socket 保持公网源（接收方私有客户端看到对端真实公网端点）
        sender_nat, sender_mapping = self.fabric.mapping_for_public_endpoint(src)
        if sender_nat is not None and sender_mapping.transport is not None:
            sender_mapping.transport.sendto(data, mapping.client)
        elif mapping.transport is not None:
            mapping.transport.sendto(data, mapping.client)


# ===== 子进程驱动与报告 =====
def build_puncher_cmd(puncher_path, role, name, signal_port, stun, priv_min,
                      retry_ms, window_s, probe_timeout, keepalive_s, hold_s,
                      cache_path, predict_n, random_m, filtering_probe, fw_dns,
                      fw_tcp, fw_timeout, window_w=2, pool=None, budget_s=2.0,
                      sweep=False, session_out=None, hairpin_probe=False):
    cmd = [
        sys.executable, puncher_path,
        "--role", role,
        "--port", str(signal_port),
        "--name", name,
        "--stun", stun,
        "--private-ip", "127.0.0.1",
        "--probe-port-min", str(priv_min),
        "--probe-port-max", str(priv_min + 511),
        "--retry-ms", str(retry_ms),
        "--window-s", str(window_s),
        "--probe-timeout", str(probe_timeout),
        "--keepalive-s", str(keepalive_s),
        "--hold-s", str(hold_s),
        "--cache", cache_path,
        "--predict-n", str(predict_n),
        "--random-m", str(random_m),
        "--fw-dns", fw_dns,
        "--fw-tcp", fw_tcp,
        "--fw-timeout", str(fw_timeout),
    ]
    if filtering_probe:
        cmd += ["--filtering-probe"]
    if hairpin_probe:
        cmd += ["--hairpin-probe"]
    if role == "connect":
        cmd += ["--host", "127.0.0.1"]
    if window_w != 2:
        cmd += ["--window-w", str(window_w)]
    if pool is not None:
        cmd += ["--pool", str(pool)]
    if budget_s != 2.0:
        cmd += ["--budget-s", str(budget_s)]
    if sweep:
        cmd += ["--sweep"]
    if session_out:
        cmd += ["--session-out", session_out]
    return cmd


def parse_peer_output(lines):
    data = {"lines": lines}
    for ln in lines:
        if "NAT profile:" in ln:
            m = re.search(r"mapping=(\S+) allocation=(\S+) step=(\S+) public=(\S+) confidence=([\d.]+) filtering=(\S+) filtering_state=(\S+) reuse=(\S+)", ln)
            if m:
                data["detected"] = {
                    "mapping": m.group(1), "allocation": m.group(2), "step": int(m.group(3)),
                    "public": m.group(4), "confidence": float(m.group(5)),
                    "filtering": m.group(6), "filtering_state": m.group(7),
                    "reuse": m.group(8) == "True",
                }
        if "result:" in ln:
            data["result"] = ln.split("result:")[1].strip()
        if "stats:" in ln:
            try:
                data["stats"] = json.loads(ln.split("stats:", 1)[1].strip())
            except ValueError:
                pass
        if "P2P ESTABLISHED via" in ln:
            m = re.search(r"via (\S+):(\d+)", ln)
            if m:
                data["p2p_peer"] = f"{m.group(1)}:{m.group(2)}"
        if "predict punch address:" in ln:
            data["predict_log"] = ln.strip()
        if "adaptive step re-estimate ->" in ln:
            data.setdefault("step_reestimates", []).append(ln.strip())
        if "pair cache hit for" in ln:
            data["cache_hit_log"] = ln.strip()
    return data


async def run_pair(args):
    fabric = Fabric()
    nat_a = SimNat("A", VIP_A, args.pub_a, args.pub_pool,
                   args.mapping_a, args.allocation_a, args.step_a, args.filtering_a, args.seed, fabric,
                   args.hairpin_a)
    nat_b = SimNat("B", VIP_B, args.pub_b, args.pub_pool,
                   args.mapping_b, args.allocation_b, args.step_b, args.filtering_b, args.seed + 1, fabric,
                   args.hairpin_b)
    await nat_a.start(fabric)
    await nat_b.start(fabric)
    fabric.set_nats([nat_a, nat_b],
                    {nat_a: (args.priv_a, args.priv_a + 511),
                     nat_b: (args.priv_b, args.priv_b + 511)})
    obs_a = await nat_a.add_observers()
    obs_b = await nat_b.add_observers()
    stun_a = ",".join(f"{vip}:{port}@127.0.0.1:{port}" for vip, port in obs_a)
    stun_b = ",".join(f"{vip}:{port}@127.0.0.1:{port}" for vip, port in obs_b)

    os.makedirs(args.workdir, exist_ok=True)
    cache_a = os.path.join(args.workdir, "cache_a.json")
    cache_b = os.path.join(args.workdir, "cache_b.json")
    fw_dns = args.fw_dns or "127.0.0.1:53,127.0.0.1:54"

    cmd_a = build_puncher_cmd(args.puncher, "listen", "A", args.signal_port, stun_a,
                              args.priv_a, args.retry_ms, args.window_s, args.probe_timeout,
                              args.keepalive_s, args.hold_s, cache_a,
                              args.predict_n, args.random_m, args.filtering_probe, fw_dns,
                              "127.0.0.1:443", 1.0,
                              args.window_w, args.pool, args.budget_s, args.sweep,
                              os.path.join(args.workdir, "session_a.json"),
                              args.hairpin_probe)
    cmd_b = build_puncher_cmd(args.puncher, "connect", "B", args.signal_port, stun_b,
                              args.priv_b, args.retry_ms, args.window_s, args.probe_timeout,
                              args.keepalive_s, args.hold_s, cache_b,
                              args.predict_n, args.random_m, args.filtering_probe, fw_dns,
                              "127.0.0.1:443", 1.0,
                              args.window_w, args.pool, args.budget_s, args.sweep,
                              os.path.join(args.workdir, "session_b.json"),
                              args.hairpin_probe)

    start_wall = time.time()
    proc_a = await asyncio.create_subprocess_exec(
        *cmd_a, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    await asyncio.sleep(0.9)   # A 监听就绪
    proc_b = await asyncio.create_subprocess_exec(
        *cmd_b, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)

    a_lines, b_lines = [], []
    timed_out = []

    async def collect(proc, lines):
        try:
            while True:
                line = await proc.stdout.readline()
                if not line:
                    break
                lines.append(line.decode(errors="replace"))
        except asyncio.CancelledError:
            pass

    async def wait(proc):
        try:
            await asyncio.wait_for(proc.wait(), timeout=args.timeout_s)
        except asyncio.TimeoutError:
            timed_out.append(proc)

    try:
        await asyncio.gather(collect(proc_a, a_lines), collect(proc_b, b_lines),
                             wait(proc_a), wait(proc_b))
    finally:
        for proc in timed_out:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
        for proc in (proc_a, proc_b):
            try:
                await asyncio.wait_for(proc.wait(), timeout=3)
            except (asyncio.TimeoutError, ProcessLookupError):
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass

    wall_ms = int((time.time() - start_wall) * 1000)
    # 保留 puncher 原始输出（含超时场景）供矩阵诊断
    try:
        with open(os.path.join(args.workdir, "peer_a.log"), "w", encoding="utf-8") as f:
            f.writelines(a_lines)
        with open(os.path.join(args.workdir, "peer_b.log"), "w", encoding="utf-8") as f:
            f.writelines(b_lines)
    except OSError:
        pass
    data_a = parse_peer_output(a_lines)
    data_b = parse_peer_output(b_lines)
    success = data_a.get("result") == "p2p" and data_b.get("result") == "p2p"

    report = {
        "combo": {
            "a": {"mapping": args.mapping_a, "allocation": args.allocation_a,
                  "step": args.step_a, "filtering": args.filtering_a},
            "b": {"mapping": args.mapping_b, "allocation": args.allocation_b,
                  "step": args.step_b, "filtering": args.filtering_b},
        },
        "a": data_a,
        "b": data_b,
        "success": success,
        "timed_out": bool(timed_out),
        "wall_ms": wall_ms,
        "trace": fabric.trace[-80:],
    }
    return report


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--puncher", default="puncher.py")
    ap.add_argument("--mapping-a", choices=MAPPING_MODES, default="ei")
    ap.add_argument("--mapping-b", choices=MAPPING_MODES, default="ei")
    ap.add_argument("--allocation-a", choices=ALLOC_MODES, default="stable")
    ap.add_argument("--allocation-b", choices=ALLOC_MODES, default="stable")
    ap.add_argument("--step-a", type=int, default=3)
    ap.add_argument("--step-b", type=int, default=3)
    ap.add_argument("--filtering-a", choices=FILTER_MODES, default="ei")
    ap.add_argument("--filtering-b", choices=FILTER_MODES, default="ei")
    ap.add_argument("--hairpin-a", action="store_true", help="NAT A 支持 hairpin（自回环）")
    ap.add_argument("--hairpin-b", action="store_true", help="NAT B 支持 hairpin（自回环）")
    ap.add_argument("--seed", type=int, default=20260816)
    ap.add_argument("--priv-a", type=int, default=30000)
    ap.add_argument("--priv-b", type=int, default=31000)
    ap.add_argument("--pub-a", type=int, default=33000)
    ap.add_argument("--pub-b", type=int, default=34000)
    ap.add_argument("--pub-pool", type=int, default=800)
    ap.add_argument("--signal-port", type=int, default=41000)
    ap.add_argument("--retry-ms", type=int, default=800)
    ap.add_argument("--window-s", type=float, default=12)
    ap.add_argument("--probe-timeout", type=float, default=1.5)
    ap.add_argument("--keepalive-s", type=float, default=3)
    ap.add_argument("--hold-s", type=float, default=6)
    ap.add_argument("--timeout-s", type=float, default=30)
    ap.add_argument("--filtering-probe", action="store_true")
    ap.add_argument("--predict-n", type=int, default=8)
    ap.add_argument("--random-m", type=int, default=64)
    ap.add_argument("--window-w", type=int, default=2)
    ap.add_argument("--pool", type=int, default=None)
    ap.add_argument("--budget-s", type=float, default=2.0)
    ap.add_argument("--sweep", action="store_true")
    ap.add_argument("--hairpin-probe", action="store_true", help="驱动 puncher 做 hairpin 回环探测")
    ap.add_argument("--fw-dns", default=None)
    ap.add_argument("--workdir", default="/tmp/punch_sim")
    ap.add_argument("--json-out", default=None)
    a = ap.parse_args()
    report = asyncio.run(run_pair(a))
    text = json.dumps(report, indent=2, sort_keys=True)
    if a.json_out:
        os.makedirs(os.path.dirname(a.json_out) or ".", exist_ok=True)
        with open(a.json_out, "w", encoding="utf-8") as f:
            f.write(text + "\n")
    print(text)


if __name__ == "__main__":
    main()
