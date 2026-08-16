#!/usr/bin/env python3
"""
puncher.py — UU远程打洞算法完整实现（RFC 5780 语义修正版）

依据 libstreamer.dylib (UURemote v4.35.0) 反汇编还原；NAT 行为检测按 RFC 5780 语义重写。

与原版 §7 实现的关键差异（详见 TEST_REPORT.md「与原版语义差异」）：
  1. NAT 检测观测「STUN 服务器回显的 XOR-MAPPED-ADDRESS」变化（服务器视角的映射），
     不再用单个 socket 的本地 getsockname() 端口序列（原实现四元组不变→恒定判 cone，linear/random 分支永远不可达）。
  2. 检测结果从整数枚举(1=cone 2=linear 3=random)扩展为 NatProfile(mapping + allocation + filtering + confidence)。
  3. 打洞策略按 (mapping, allocation) 分发；linear 预测为双向区间；random 用多 socket 并发；
     收包后学习对端真实映射(learned candidate)并回打所有候选（升级+重试循环），双向确认后才置 P2P（多 1 RTT，防假阳性）。
  4. 新增 keepalive、成功 pair 缓存、TCP:443 防火墙对照探测。

用法:
  python3 puncher.py --role=listen --port=9900 --name=A   # 端A(被控端)
  python3 puncher.py --role=connect --host=127.0.0.1 --port=9900 --name=B  # 端B
  python3 puncher.py --test                                # 单测
  # RFC5780 检测建议提供多个 STUN 地址（不同端口 / 不同 IP）:
  python3 puncher.py --role=listen --port=9900 --stun 119.29.29.29:3478,223.5.5.5:3478
  # mock 环境（nat_sim）使用 "逻辑IP:port@真实IP:port" 语法，供 RFC5780 分组探测:
  python3 puncher.py --role=listen --port=9900 --stun 203.0.113.1:33001@127.0.0.1:33001,203.0.113.1:33002@127.0.0.1:33002,203.0.113.3:33003@127.0.0.1:33003
"""
import argparse
import collections
import json
import os
import random
import socket
import struct
import sys
import threading
import time

# ===== 常量（[H] 反汇编确认） =====
STUN_MAGIC_COOKIE = 0x2112A442
ATTR_XOR_MAPPED = 0x0020            # 标准 XOR-MAPPED-ADDRESS
ATTR_CHANGE_REQUEST = 0x0003        # RFC 5780 CHANGE-REQUEST（filtering 探测）
ATTR_NR_PORT = 0xC057               # [H] 网易私有: 端口/步长通告
PUNCH_MSG_TYPE = 0x0009             # [H] "P2P punch" (type=9, 0x3df024)
BINDING_REQUEST = 0x0001            # RFC 5389
BINDING_RESPONSE = 0x0101
PUNCH_MAGIC = b"NRC_PUNCH_V1"       # [I] MAGIC_PUNCH_RESPONSE_STR (自定义,两端一致)
RETRY_US = 5_000_000                # [H] 5s 重试 (0x4c4b40)
PUNCH_WINDOW_S = 10                 # [H] 实测: 打洞10s无果→防火墙检测
KEEPALIVE_S = 20                    # [I] 保活间隔（NAT 映射过期前维持）
FIREWALL_DNS = [("119.29.29.29", 53), ("223.5.5.5", 53)]  # [H] 防火墙探测目标
FIREWALL_TCP_PORT = 443             # TCP 对照探测端口（避免 UDP 丢包/限速误判防火墙）

# [H] NAT 类型枚举 (三方印证, 兼容旧值)
NAT_UNKNOWN, NAT_CONE, NAT_LINEAR, NAT_RANDOM = 0, 1, 2, 3

# ===== RFC 5780 分类枚举 =====
MAPPING_EI = "endpoint_independent"       # 端点无关映射（cone）
MAPPING_AD = "address_dependent"          # 地址相关映射
MAPPING_APD = "address_port_dependent"    # 地址端口相关映射（symmetric）
MAPPING_UNKNOWN = "unknown"

ALLOC_STABLE = "stable"
ALLOC_LINEAR = "linear"
ALLOC_RANDOM = "random"

FILT_EI = "endpoint_independent"
FILT_AD = "address_dependent"
FILT_APD = "address_port_dependent"
FILT_UNKNOWN = "unknown"

# [H] 7 个策略名（字符串完整枚举）
STRATEGY_NAMES = (
    "BothLinearSymmericPunch",
    "BothRandomSymmericPunch",
    "ConePunchToLinearSymmeric",
    "ConePunchToRandomSymmeric",
    "LinearSymmericPunchToCone",
    "LinearSymmericPunchToRandomSymmeric",
    "RandomSymmericPunchToCone",
)
DIRECT_CONE = "DirectConePunch"   # cone×cone：标准 ICE 直连语义（原 default 分支）

# [H] 组合优先级表 (0x3e27d0)
def group_pair_priority(local_type, remote_type, lp, rp):
    base = (lp + rp) * 100
    if (remote_type, local_type) in ((1, 2), (2, 1)):
        return base + 10
    if (remote_type, local_type) in ((1, 3), (3, 1)):
        return base + 20
    if remote_type == 1 and local_type == 1:
        return base + 30
    if remote_type == 2 and local_type == 2:
        return base + 40
    if (remote_type, local_type) in ((3, 2), (2, 3)):
        return base + 50
    if remote_type == 3 and local_type == 3:
        return base + 60
    if local_type == 0 or remote_type == 0:
        return base + 70
    return 90


# ===== 工具 =====
def _split_host_port(s):
    """解析 "ip:port"（仅 IPv4）。"""
    s = s.strip()
    ip, _, port = s.rpartition(":")
    if not ip:
        raise ValueError(f"bad host:port: {s!r}")
    return ip, int(port)


# ===== STUN 消息编解码（保留原 §7 StunMsg，扩展 CHANGE-REQUEST） =====
class StunMsg:
    def __init__(self, mtype=PUNCH_MSG_TYPE):
        self.mtype = mtype
        self.txn = random.randbytes(12)
        self.attrs = {}

    def add(self, t, v):
        self.attrs[t] = v

    def encode(self):
        b = bytearray(20)
        struct.pack_into(">H", b, 0, self.mtype)
        struct.pack_into(">I", b, 4, STUN_MAGIC_COOKIE)
        b[8:20] = self.txn
        for t, v in self.attrs.items():
            b += struct.pack(">HH", t, len(v)) + v
            while len(b) & 3:
                b.append(0)
        struct.pack_into(">H", b, 2, len(b) - 20)
        return bytes(b)

    @staticmethod
    def decode(data):
        if len(data) < 20 or data[4:8] != struct.pack(">I", STUN_MAGIC_COOKIE):
            return None
        m = StunMsg(struct.unpack(">H", data[:2])[0])
        m.txn = data[8:20]
        n, end = 20, 20 + struct.unpack(">H", data[2:4])[0]
        while n + 4 <= end and n + 4 <= len(data):
            t, l = struct.unpack(">HH", data[n:n + 4])
            n += 4
            if n + l > len(data):
                break
            m.attrs[t] = data[n:n + l]
            n += (l + 3) & ~3
        return m

    def set_xor_mapped(self, ip, port):
        b = struct.pack(">H", 1)
        b += struct.pack(">H", port ^ (STUN_MAGIC_COOKIE >> 16))
        b += struct.pack(">I", ip ^ STUN_MAGIC_COOKIE)
        self.add(ATTR_XOR_MAPPED, b)

    def get_xor_mapped(self):
        v = self.attrs.get(ATTR_XOR_MAPPED)
        if not v or len(v) < 8:
            return None
        _, xport, xip = struct.unpack(">HHI", v[:8])
        return (xip ^ STUN_MAGIC_COOKIE, xport ^ (STUN_MAGIC_COOKIE >> 16))

    def set_change_request(self, change_ip=False, change_port=False):
        mask = (1 if change_ip else 0) | (2 if change_port else 0)
        self.add(ATTR_CHANGE_REQUEST, struct.pack(">I", mask))

    def get_change_request(self):
        v = self.attrs.get(ATTR_CHANGE_REQUEST)
        return struct.unpack(">I", v[:4])[0] if v and len(v) >= 4 else 0

    # 0xc057 通告：8 字节 (step u16, current_port u16, reserved u32)
    def set_nr_port(self, p):
        # 兼容原 §7 语义（单个端口通告）
        self.add(ATTR_NR_PORT, struct.pack(">HHHH", p & 0xFFFF, p & 0xFFFF, 0, 0))

    def set_nr(self, step, cur_port):
        self.add(ATTR_NR_PORT, struct.pack(">HHHH", step & 0xFFFF, cur_port & 0xFFFF, 0, 0))

    def get_nr(self):
        v = self.attrs.get(ATTR_NR_PORT)
        if not v or len(v) < 4:
            return (0, 0)
        return struct.unpack(">HH", v[:4])

    def get_nr_port(self):
        return self.get_nr()[0]

    def set_magic(self):
        self.add(0xC058, PUNCH_MAGIC)

    def check_magic(self):
        return self.attrs.get(0xC058) == PUNCH_MAGIC


# ===== RFC 5780 映射行为分类（纯函数，可单测） =====
class MappingObservation:
    """一次 STUN 回显观测（权威：服务器视角的 NAT 出口映射，即 XOR-MAPPED）。

    group 取值为：
      same_target  同 socket 同目标（可多次，验证映射稳定）
      diff_port    同 socket 同逻辑IP 不同目标端口
      diff_ip      同 socket 不同逻辑IP 目标
      new_socket   独立新 socket 同目标（验证新会话是否复用端口）
    target_logical_ip 用于 RFC5780 分组的逻辑服务器 IP（mock 环境可与真实 IP 分离）。
    """

    __slots__ = ("group", "target_logical_ip", "target_port", "socket_bind",
                 "stun_mapped_ip", "stun_mapped_port")

    def __init__(self, group, target_logical_ip, target_port, socket_bind,
                 stun_mapped_ip, stun_mapped_port):
        self.group = group
        self.target_logical_ip = target_logical_ip
        self.target_port = target_port
        self.socket_bind = socket_bind
        self.stun_mapped_ip = stun_mapped_ip
        self.stun_mapped_port = stun_mapped_port

    @property
    def mapped(self):
        return (self.stun_mapped_ip, self.stun_mapped_port)

    def as_dict(self):
        ip_s = socket.inet_ntoa(struct.pack(">I", self.stun_mapped_ip)) if self.stun_mapped_ip else None
        return {
            "group": self.group,
            "target": f"{self.target_logical_ip}:{self.target_port}",
            "socket_bind": f"{self.socket_bind[0]}:{self.socket_bind[1]}" if self.socket_bind else None,
            "mapped_ip": ip_s,
            "mapped_port": self.stun_mapped_port,
        }


def classify_mapping(observations):
    """RFC 5780 映射行为分类（纯函数）。

    规则（同 socket 观测）：
      - 全部映射相同 → EndpointIndependent（cone）
      - 同逻辑IP 不同端口映射相同、不同逻辑IP 映射不同 → AddressDependent
      - 其余（同IP 异端口映射即变等）→ AddressOrPortDependent
    返回 (MappingKind, sample_map: (ip_int, port)|None, confidence: float, port_reuse: bool)。
    confidence = 有效分组数 / 期望分组数；sample_map 取首目标映射（本端出口公网 ip:port）。
    """
    groups = collections.defaultdict(list)
    for o in observations:
        if o is None or o.stun_mapped_port is None:
            continue
        groups[o.group].append(o)
    valid_count = sum(len(v) for v in groups.values())
    expected_groups = {"same_target", "diff_port", "diff_ip", "new_socket"}
    present = set(groups)

    def _first_mapped():
        for o in observations:
            if o is not None and o.stun_mapped_port is not None:
                return (o.stun_mapped_ip, o.stun_mapped_port)
        return None

    if valid_count < 3:
        # 有效观测不足，无法形成三态判定 → unknown（低置信）
        return (MAPPING_UNKNOWN, _first_mapped(), valid_count / max(1, len(observations)), False)

    if "same_target" in groups:
        ref = groups["same_target"][0]
    else:
        ref = next(iter(groups.values()))[0]
    sample = (ref.stun_mapped_ip, ref.stun_mapped_port)

    # 稳定性：同目标连续观测映射须一致；漂移（每包新端口）→ 保守 APD
    for o in groups.get("same_target", []):
        if o.mapped != sample:
            return (MAPPING_APD, sample, len(present) / len(expected_groups), False)

    def rep(name):
        return groups[name][0].mapped if groups.get(name) else None

    dp = rep("diff_port")   # 同逻辑IP 不同端口
    di = rep("diff_ip")     # 不同逻辑IP
    # 新会话端口复用（独立新 socket 同目标）
    reuse = True
    ns = rep("new_socket")
    if ns is not None and ns != sample:
        reuse = False

    same_all = True
    for o in observations:
        if o is not None and o.stun_mapped_port is not None and o.mapped != sample:
            same_all = False
            break

    if same_all:
        kind = MAPPING_EI
    elif dp is not None and dp != sample:
        # 同 socket 同 IP 异端口即产生新映射 → 每目标新映射（地址端口相关）
        kind = MAPPING_APD
    elif di is not None and di != sample:
        # 同 IP 异端口仍复用、异 IP 变化 → 地址相关
        kind = MAPPING_AD
    elif ns is not None and ns != sample:
        # 同 socket 内映射端点无关；仅新会话不复用端口 → 仍视为 EI 映射（映射本身端点无关）
        kind = MAPPING_EI
    else:
        kind = MAPPING_UNKNOWN
    confidence = len(present) / len(expected_groups)
    return (kind, sample, confidence, reuse)


def classify_port_allocation(ports):
    """端口分配模式分类（纯函数）。差分众数：恒定/空 → STABLE；众数稳定 → LINEAR(step)；乱 → RANDOM。

    返回 (AllocationMode, step:int)。
    """
    if not ports or len(ports) < 2:
        return (ALLOC_STABLE, 0)
    if all(p == ports[0] for p in ports):
        return (ALLOC_STABLE, 0)
    diffs = [ports[i] - ports[i - 1] for i in range(1, len(ports))]
    counter = collections.Counter(diffs)
    mode, cnt = counter.most_common(1)[0]
    coverage = cnt / len(diffs)
    if mode != 0 and coverage >= 0.6:
        return (ALLOC_LINEAR, mode)
    return (ALLOC_RANDOM, 0)


# ===== 端口预测（[H] 0x3e1050: base+step*N, 16bit回绕） =====
def predict_ports(base_port, step, count, bidirectional=False):
    """[H] 0x3e1050: predicted_port = (base + step*N) & 0xffff，N 从 count 递减到 1。
    bidirectional=True 时返回双向区间 [base - step*count, base + step*count]（覆盖回拨），去重。
    16bit 回绕保护: 结果==0 时回退为 step（[H] csel）。"""
    out = []

    def wrap(p):
        p &= 0xFFFF
        return step if p == 0 else p

    if bidirectional:
        seen = set()
        for i in range(-count, 0):      # 回拨方向（-step）
            p = wrap(base_port + step * i)
            if p not in seen:
                seen.add(p)
                out.append(p)
        for i in range(1, count + 1):   # 前向（+step）
            p = wrap(base_port + step * i)
            if p not in seen:
                seen.add(p)
                out.append(p)
        return out
    for i in range(count, 0, -1):
        out.append(wrap(base_port + step * i))
    return out


def infer_step(observed_ports):
    """端口差分众数推断步长（差分稳定→linear，返回众数；混乱/无差分→0）。
    兼容旧 §7 接口：返回整数 step。"""
    if len(observed_ports) < 2:
        return 0
    diffs = []
    for i in range(1, len(observed_ports)):
        d = observed_ports[i] - observed_ports[i - 1]
        if d == 0:
            continue   # 复用端口（EI 映射）不算新会话分配
        diffs.append(d)
    if not diffs:
        return 0
    counter = collections.Counter(diffs)
    step, cnt = counter.most_common(1)[0]
    if cnt / len(diffs) >= 0.6:
        return step
    return 0


# ===== STUN 目标 =====
class StunTarget:
    """STUN 服务器目标。logical_ip 用于 RFC5780 分组（"目标 IP 身份"）；
    real_ip:real_port 是实际发包地址。真实环境两者相同；mock 环境分离。"""

    __slots__ = ("logical_ip", "logical_port", "real_ip", "real_port")

    def __init__(self, logical_ip, logical_port, real_ip, real_port):
        self.logical_ip = logical_ip
        self.logical_port = logical_port
        self.real_ip = real_ip
        self.real_port = real_port

    @staticmethod
    def parse(s):
        s = s.strip()
        if "@" in s:   # "逻辑ip:port@真实ip:port"
            left, right = s.split("@", 1)
            lip, lp = _split_host_port(left)
            rip, rp = _split_host_port(right)
            return StunTarget(lip, lp, rip, rp)
        ip, port = _split_host_port(s)
        return StunTarget(ip, port, ip, port)


def parse_stun_targets(raw):
    """解析 --stun 列表。返回 [] 表示未提供。"""
    raw = (raw or "").strip()
    if not raw:
        return []
    return [StunTarget.parse(s) for s in raw.split(",") if s.strip()]


# ===== 防火墙检测（[H] 0x3e2b48 PunchCheckFireWall + TCP 对照） =====
def check_firewall(dns_targets=None, tcp_targets=None, timeout=2.0):
    """UDP ping 公网DNS:53 双目标 + TCP:443 对照。仅 UDP 全失败 且 TCP 也失败 → 防火墙。
    返回 (blocked, results)。"""
    dns_targets = dns_targets or FIREWALL_DNS
    udp_results = []
    for ip, port in dns_targets:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            s.sendto(b"\x00" * 16, (ip, port))
            s.recvfrom(128)
            udp_results.append((f"{ip}:{port}", True))
            s.close()
        except (socket.timeout, OSError):
            udp_results.append((f"{ip}:{port}", False))
    tcp_targets = tcp_targets or [(FIREWALL_DNS[0][0], FIREWALL_TCP_PORT)]
    tcp_results = []
    for ip, port in tcp_targets:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, port))
            tcp_results.append((f"{ip}:{port}", True))
            s.close()
        except OSError:
            tcp_results.append((f"{ip}:{port}", False))
    udp_ok = any(r[1] for r in udp_results)
    tcp_ok = any(r[1] for r in tcp_results)
    blocked = (not udp_ok) and (not tcp_ok)
    return blocked, {"udp": udp_results, "tcp": tcp_results}


# ===== 成功 pair 缓存 =====
def _default_cache_path():
    return os.path.join(os.path.expanduser("~"), ".puncher_pair_cache.json")


def load_pair_cache(path):
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        pairs = data.get("pairs", [])
        return [p for p in pairs if isinstance(p, dict)]
    except (OSError, ValueError):
        return []


def save_pair_cache(path, pairs):
    try:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"pairs": pairs[:5]}, f)
        os.replace(tmp, path)
        return True
    except OSError:
        return False


# ===== 策略选择（[H] 0x3df05c switch 表语义，按 mapping/allocation 分发） =====
def choose_strategy(local, remote):
    """按 (local.mapping, local.allocation, remote.mapping, remote.allocation) 分发。

    保留原 7 策略名语义；任何一侧 allocation=LINEAR 优先进入预测分支（任务 §2.2）。
    返回策略名。
    """
    lm = local.get("mapping", MAPPING_UNKNOWN)
    rm = remote.get("mapping", MAPPING_UNKNOWN)
    la = local.get("allocation", ALLOC_STABLE)
    ra = remote.get("allocation", ALLOC_STABLE)

    if MAPPING_UNKNOWN in (lm, rm):
        return DIRECT_CONE   # 未知类型 → 标准直连 + peer-reflexive 引流（最通用）

    l_cone = lm == MAPPING_EI
    r_cone = rm == MAPPING_EI
    l_lin = la == ALLOC_LINEAR
    r_lin = ra == ALLOC_LINEAR
    l_ran = la == ALLOC_RANDOM
    r_ran = ra == ALLOC_RANDOM

    # linear 预测分支（任何一侧 linear）
    if l_lin or r_lin:
        if not l_cone and not r_cone:
            if l_lin and r_ran:
                return "LinearSymmericPunchToRandomSymmeric"
            if l_ran and r_lin:
                return "ConePunchToRandomSymmeric"   # [H] 原 (3,2) 表项
            return "BothLinearSymmericPunch"
        if l_cone and not r_cone:
            return "ConePunchToLinearSymmeric"
        if not l_cone and r_cone:
            return "LinearSymmericPunchToCone"
        # 双 cone 但 allocation linear（理论情形）→ 双向预测无副作用，仍可直连命中
        return "BothLinearSymmericPunch"
    # random 分支（任何一侧 random）
    if l_ran or r_ran:
        if not l_cone and not r_cone:
            return "BothRandomSymmericPunch"
        if l_cone and not r_cone:
            return "ConePunchToRandomSymmeric"
        if not l_cone and r_cone:
            return "RandomSymmericPunchToCone"
        return "BothRandomSymmericPunch"
    # 双方 cone / stable → 标准 ICE 直连
    if l_cone and r_cone:
        return DIRECT_CONE
    if l_cone and not r_cone:
        return "ConePunchToRandomSymmeric"
    if not l_cone and r_cone:
        return "RandomSymmericPunchToCone"
    return DIRECT_CONE


def legacy_nat_type(mapping, allocation):
    """将新分类映射回 UU 整数枚举（1=cone 2=linear 3=random）供信令兼容。"""
    if mapping == MAPPING_EI:
        return NAT_CONE
    if mapping in (MAPPING_AD, MAPPING_APD):
        return NAT_LINEAR if allocation == ALLOC_LINEAR else NAT_RANDOM
    return NAT_UNKNOWN


# ===== NAT 行为检测（RFC 5780，[H] 0x3ddd00） =====
class NatDetector:
    """RFC 5780 行为检测。

    观测「STUN 服务器回显的 XOR-MAPPED-ADDRESS」在 4 个分组下的变化（服务器视角的映射），
    而非本地 getsockname 端口序列。3 个独立 socket 并行探测 + 独立新 socket 验证新会话复用；
    判定 AD/APD（symmetric）后追加多目标采集端口序列，用于端口分配模式分类。
    """

    def __init__(self, timeout=2.0, private_ip="0.0.0.0",
                 probe_port_min=None, probe_port_max=None):
        self.timeout = timeout
        self.private_ip = private_ip
        self.probe_port_min = probe_port_min
        self.probe_port_max = probe_port_max
        self._next_probe_port = probe_port_min
        self._socks = []

    def close(self):
        for s in self._socks:
            try:
                s.close()
            except OSError:
                pass
        self._socks = []

    def _open_sock(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(self.timeout)
        if self.probe_port_min is not None:
            for _ in range(1024):
                p = self._next_probe_port
                self._next_probe_port += 1
                if self.probe_port_max is not None and p > self.probe_port_max:
                    break
                try:
                    s.bind((self.private_ip, p))
                    break
                except OSError:
                    continue
            else:
                s.bind((self.private_ip, 0))
        else:
            s.bind((self.private_ip, 0))
        self._socks.append(s)
        return s

    def _stun_probe_batch(self, sock, probes):
        """同一 socket 快速连续发送多个 Binding Request（RFC 5780：观测同 socket 跨目标映射变化），
        用 txn 匹配响应。probes: list[(target, change_ip, change_port)]。
        返回与 probes 等长的 list：(mapped:(ip_int,port)|None, src:addr|None)。"""
        txn_map = {}
        for i, (t, cip, cport) in enumerate(probes):
            m = StunMsg(BINDING_REQUEST)
            if cip or cport:
                m.set_change_request(change_ip=cip, change_port=cport)
            try:
                sock.sendto(m.encode(), (t.real_ip, t.real_port))
            except OSError:
                txn_map[m.txn] = i
                continue
            txn_map[m.txn] = i
        results = [None] * len(probes)
        deadline = time.time() + self.timeout
        pending = set(txn_map)
        while pending and time.time() < deadline:
            try:
                data, src = sock.recvfrom(512)
            except socket.timeout:
                continue
            except OSError:
                break
            m = StunMsg.decode(data)
            if m is None or m.txn not in pending:
                continue
            pending.discard(m.txn)
            idx = txn_map[m.txn]
            mapped = m.get_xor_mapped()
            results[idx] = (mapped, src)
        return results

    def detect(self, stun_targets=None, filtering_probe=False, sequence_len=4):
        """执行 RFC 5780 行为检测。

        返回 (NatProfile, listen_sock)。listen_sock 为同目标组的 socket，供打洞复用
        （其公网映射端口即 profile.public，对端可打）。
        """
        targets = list(stun_targets or [])
        if not targets:
            # 无 STUN 配置：无法做 RFC5780 分组，返回 unknown profile（标准直连打洞兜底）
            sock = self._open_sock()
            profile = self._empty_profile(sock)
            return profile, sock
        # 分组目标：t0 主目标 / t1 同逻辑IP异端口 / t2 异逻辑IP / extra 追加采集
        t0 = targets[0]
        t1 = next((t for t in targets[1:] if t.logical_ip == t0.logical_ip and t.logical_port != t0.logical_port), None)
        t2 = next((t for t in targets[1:] if t.logical_ip != t0.logical_ip), None)
        extra = [t for t in targets if t is not t0 and t is not t1 and t is not t2]
        degraded = t1 is None or t2 is None   # 缺同IP异端口 或 缺异IP 目标

        s1 = self._open_sock()   # 打洞复用 socket（RFC5780 全部映射观测用同一 socket）
        s4 = self._open_sock()   # 独立新 socket（验证新会话是否复用端口）

        # 同一 socket 多事务探测：同目标×2、同IP异端口、异IP —— 观测的是「同 socket 跨目标」映射
        probe_list = [("same_target", t0), ("same_target", t0)]
        if t1 is not None:
            probe_list.append(("diff_port", t1))
        if t2 is not None:
            probe_list.append(("diff_ip", t2))
        batch = {}

        def run_batch():
            res = self._stun_probe_batch(s1, [(t, False, False) for _, t in probe_list])
            for (tag, _), item in zip(probe_list, res):
                batch[tag] = item if item is not None else (None, None)

        def run_new():
            res = self._stun_probe_batch(s4, [(t0, False, False)])
            batch["new_socket"] = res[0] if res and res[0] is not None else (None, None)

        th1 = threading.Thread(target=run_batch)
        th2 = threading.Thread(target=run_new)
        th1.start()
        th2.start()
        th1.join()
        th2.join()

        observations = []
        for tag, t in probe_list:
            mapped, src = batch.get(tag, (None, None))
            if mapped is not None and mapped[1] is not None:
                observations.append(MappingObservation(tag, t.logical_ip, t.logical_port,
                                                       s1.getsockname(), mapped[0], mapped[1]))
        mapped_ns, src_ns = batch.get("new_socket", (None, None))
        if mapped_ns is not None and mapped_ns[1] is not None:
            observations.append(MappingObservation("new_socket", t0.logical_ip, t0.logical_port,
                                                   s4.getsockname(), mapped_ns[0], mapped_ns[1]))

        mapping, sample, confidence, reuse = classify_mapping(observations)

        # 端口分配模式：symmetric(AD/APD) 时追加多目标采集（打洞 socket 的新映射端口序列）
        port_sequence = []
        if observations:
            first = observations[0].stun_mapped_port
            port_sequence.append(first)
            by_group = {o.group: o for o in observations}
            if mapping == MAPPING_APD and "diff_port" in by_group:
                port_sequence.append(by_group["diff_port"].stun_mapped_port)
            if mapping in (MAPPING_AD, MAPPING_APD) and "diff_ip" in by_group:
                port_sequence.append(by_group["diff_ip"].stun_mapped_port)
        if mapping in (MAPPING_AD, MAPPING_APD):
            seq_targets = [(t, False, False) for t in extra[:sequence_len]]
            if seq_targets:
                for (mapped, _) in self._stun_probe_batch(s1, seq_targets):
                    if mapped is not None and mapped[1] is not None:
                        port_sequence.append(mapped[1])
        # 相邻去重（复用映射不产生新分配）
        dedup = []
        for p in port_sequence:
            if not dedup or dedup[-1] != p:
                dedup.append(p)
        allocation, step = classify_port_allocation(dedup)

        # filtering 尽力探测（CHANGE-REQUEST；依据「响应源地址变化」判定。
        # mock 环境按响应源端口归因到 t1(同IP异端口)/t2(异IP)；真实环境源端口 != t0 即视为 changed。
        # 仅在 --filtering-probe 显式开启时执行；服务器不支持 change 时保守判 APD。）
        filtering = FILT_UNKNOWN
        if filtering_probe:
            cp = self._stun_probe_batch(s1, [(t0, False, True)])[0]
            ci = self._stun_probe_batch(s1, [(t0, True, False)])[0]
            cp_src = cp[1] if cp else None
            ci_src = ci[1] if ci else None
            cp_changed = cp_src is not None and cp_src[1] != t0.real_port
            ci_changed = ci_src is not None and ci_src[1] != t0.real_port
            # 归因增强：mock 环境响应源端口精确匹配伙伴目标
            if ci_src is not None and t2 is not None and ci_src[1] == t2.real_port:
                ci_changed = True
            if cp_src is not None and t1 is not None and cp_src[1] == t1.real_port:
                cp_changed = True
            if ci_changed:
                filtering = FILT_EI
            elif cp_changed:
                filtering = FILT_AD
            else:
                filtering = FILT_APD

        # 公网端点（服务器视角映射，真实可路由地址）
        public_ip = None
        public_port = None
        if sample is not None:
            public_ip = socket.inet_ntoa(struct.pack(">I", sample[0]))
            public_port = sample[1]

        profile = {
            "mapping": mapping,
            "allocation": allocation,
            "step": step,
            "public": f"{public_ip}:{public_port}" if public_ip else None,
            "public_ip": public_ip,
            "public_port": public_port,
            "confidence": confidence,
            "filtering": filtering,
            "port_reuse": reuse,
            "legacy_nat_type": legacy_nat_type(mapping, allocation),
            "listen_port": s1.getsockname()[1],
            "degraded": degraded,
            "observations": [o.as_dict() for o in observations],
            "port_sequence": dedup,
        }
        s4.close()
        return profile, s1

    def _empty_profile(self, sock):
        return {
            "mapping": MAPPING_UNKNOWN,
            "allocation": ALLOC_STABLE,
            "step": 0,
            "public": None, "public_ip": None, "public_port": None,
            "confidence": 0.0,
            "filtering": FILT_UNKNOWN,
            "port_reuse": False,
            "legacy_nat_type": NAT_UNKNOWN,
            "listen_port": sock.getsockname()[1],
            "degraded": True,
            "observations": [],
            "port_sequence": [],
        }


def force_profile(profile, force_nat):
    """[H] 兼容：--force-nat=1|2|3 强制覆盖 allocation 语义。
    1→mapping EI + allocation STABLE；2→APD+LINEAR；3→APD+RANDOM。"""
    p = dict(profile)
    if force_nat == NAT_CONE:
        p.update(mapping=MAPPING_EI, allocation=ALLOC_STABLE, step=0, legacy_nat_type=NAT_CONE)
    elif force_nat == NAT_LINEAR:
        p.update(mapping=MAPPING_APD, allocation=ALLOC_LINEAR, step=1, legacy_nat_type=NAT_LINEAR)
    else:
        p.update(mapping=MAPPING_APD, allocation=ALLOC_RANDOM, step=0, legacy_nat_type=NAT_RANDOM)
    return p


# ===== 打洞引擎 =====
class PunchEngine:
    def __init__(self, name, local, remote, remote_candidate, candidates,
                 sock=None, private_ip="0.0.0.0", retry_s=5.0, window_s=PUNCH_WINDOW_S,
                 keepalive_s=KEEPALIVE_S, hold_s=0.0, cache_path=None,
                 predict_n=8, random_m=64, seed=None, force_mode=None,
                 probe_port_min=None, probe_port_max=None, fw_dns=None,
                 fw_tcp=None, fw_timeout=2.0,
                 log=None):
        self.name = name
        self.local = local
        self.remote = remote
        self.remote_candidate = remote_candidate          # 对端公网候选 (ip, port)
        self.candidates = candidates
        self.mode = force_mode or choose_strategy(local, remote)
        self.sock = sock
        self.private_ip = private_ip
        self.retry_s = retry_s
        self.window_s = window_s
        self.keepalive_s = keepalive_s
        self.hold_s = hold_s
        self.cache_path = cache_path
        self.predict_n = predict_n
        self.random_m = random_m
        self.rng = random.Random(seed)
        self.probe_port_min = probe_port_min
        self.probe_port_max = probe_port_max
        self.fw_dns = fw_dns
        self.fw_tcp = fw_tcp
        self.fw_timeout = fw_timeout
        self.extra_socks = []
        self.p2p = False
        self.p2p_peer = None
        self.p2p_ts = None
        self.start_ts = None
        self.learned = []                # 已学习的对端映射 (ip, port)
        self.remote_ports = []           # 对端 XOR-MAPPED 端口序列（用于差分重估）
        self.remote_step = 0             # 0xc057 通告或差分众数
        self.epoch = 0
        self.recv_count = 0
        self._lock = threading.Lock()
        self._stop = False
        self._keepalive_thread = None
        self.log = log if log is not None else (lambda m: print(f"[{self.name}] {m}", flush=True))
        self.local_public_ip = local.get("public_ip")
        self.local_public_port = local.get("public_port")
        self.local_bind = None
        self.cache_hint = None
        self.stats = {
            "punches_sent": 0, "punches_recv": 0, "learn_events": 0,
            "predicted_hits": 0, "keptalive": 0, "cache_hits": 0, "cache_saves": 0,
            "epoch": 0, "establish_ms": None, "step_history": [], "mode": self.mode,
        }

    # ---- socket 管理 ----
    def _make_sock(self, port=0):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1.0)
        if port:
            s.bind((self.private_ip, port))
        elif self.probe_port_min is not None:
            # 在私有端口段内找空闲（供 sim 的 NAT 归属识别）
            for p in range(self.probe_port_min, self.probe_port_max + 1):
                try:
                    s.bind((self.private_ip, p))
                    break
                except OSError:
                    continue
            else:
                s.bind((self.private_ip, 0))
        else:
            s.bind((self.private_ip, 0))
        return s

    def _all_socks(self):
        return [self.sock] + self.extra_socks

    def _open_extra_socks(self, want=3):
        while len(self.extra_socks) < want:
            try:
                s = self._make_sock(0)
            except OSError:
                break
            self.extra_socks.append(s)
            threading.Thread(target=self._recv_loop, args=(s,), daemon=True).start()

    # ---- 主流程 ----
    def start(self):
        self.start_ts = time.monotonic()
        self.start_wall = time.time()
        if self.sock is None:
            self.sock = self._make_sock(0)
        self.local_bind = self.sock.getsockname()
        self._load_cache_hint()
        if self.mode in ("BothRandomSymmericPunch", "ConePunchToRandomSymmeric",
                         "RandomSymmericPunchToCone"):
            self._open_extra_socks(3)
        self.log(f"Enhanced Hole Punching 1  mode={self.mode}  local_port={self.local_bind[1]}")
        self.log(f"start nat traversal analysis  local={self._short(self.local)}  "
                 f"remote={self._short(self.remote)}")
        threading.Thread(target=self._recv_loop, args=(self.sock,), daemon=True).start()
        deadline = time.time() + self.window_s
        while not self.p2p and time.time() < deadline:
            self._execute_once()
            self.epoch += 1
            self.stats["epoch"] = self.epoch
            self.log(f"retry in {self.retry_s:.1f}s (epoch {self.epoch})")
            time.sleep(self.retry_s)
        if not self.p2p:
            blocked, results = check_firewall(dns_targets=self.fw_dns, tcp_targets=self._tcp_targets(),
                                              timeout=self.fw_timeout)
            self.log(f"PunchCheckFireWall, punch_epoch: {self.epoch}")
            for r in results["udp"]:
                self.log(f"firewall check udp {r[0]} -> {'connected' if r[1] else 'blocked'}")
            for r in results["tcp"]:
                self.log(f"firewall check tcp {r[0]} -> {'connected' if r[1] else 'blocked'}")
            if blocked:
                self.log("found firewall, stop punch -> 转 TURN 中继")
                return "firewall"
            self.log("firewall check ok, but punch failed -> 转 TURN 中继")
            return "fail"
        self.p2p_ts = time.time()
        self.stats["establish_ms"] = int((time.time() - self.start_wall) * 1000)
        self._save_cache()
        self.log(f"★ P2P ESTABLISHED via {self.p2p_peer[0]}:{self.p2p_peer[1]} "
                 f"(bidirectional confirm, recv={self.recv_count})")
        if self.hold_s > 0:
            self.log(f"P2P established, holding {self.hold_s:.0f}s for keepalive validation")
            self._start_keepalive()
            end = time.time() + self.hold_s
            while time.time() < end and not self._stop:
                time.sleep(0.2)
            self._stop = True
        return "p2p"

    def _short(self, profile):
        return (f"m={profile.get('mapping')}/a={profile.get('allocation')}"
                f"/s={profile.get('step')}/f={profile.get('filtering')}")

    # ---- 策略执行 ----
    def _execute_once(self):
        self.log(f"execute: {self.mode}  (epoch {self.epoch + 1})")
        for c in self.candidates:
            self._send(self.sock, c[0], c[1])
        # 缓存预测区间入口优先
        if self.cache_hint is not None:
            for p in self.cache_hint:
                self._send(self.sock, self._remote_ip(), p)
            self.stats["cache_hits"] += 1
        if self.mode in ("BothLinearSymmericPunch", "ConePunchToLinearSymmeric",
                         "LinearSymmericPunchToCone", "LinearSymmericPunchToRandomSymmeric"):
            self._linear_predict_once()
        elif self.mode in ("BothRandomSymmericPunch", "ConePunchToRandomSymmeric",
                           "RandomSymmericPunchToCone"):
            self._random_punch_once()
        else:
            self._standard_punch_once()
        # learned 置底：本端 mapping.dest 停在「对端真实映射端口」——本端 APD filtering 只放行
        # 恰好命中 dest 的源；对端从该端口回包即命中（解决 dest 被预测区间覆盖导致的时序竞态）
        if self.learned:
            ip, p = self.learned[-1]
            self._send(self.sock, ip, p)

    def _remote_ip(self):
        return self.remote_candidate[0]

    def _remote_base(self):
        # base 取对端当前映射端口：优先最新 learned，其次信令交换的公网端口
        if self.learned:
            return self.learned[-1][1]
        return self.remote_candidate[1]

    def _remote_step_value(self):
        if self.remote_step:
            return self.remote_step           # 对端 0xc057 实时通告（最新）
        step = infer_step(self.remote_ports)
        if step:
            return step                        # 本地差分观测（自适应重估）
        if self.remote.get("step"):
            return self.remote.get("step")     # 对端信令通告的检测值
        return 1

    def _linear_predict_once(self):
        base = self._remote_base()
        step = self._remote_step_value()
        N = self.predict_n * (2 if self.remote.get("confidence", 0) >= 0.75 else 1)
        ports = predict_ports(base, step, N, bidirectional=True)
        self.log(f"predict punch address: base={base} step={step} N={N} first={ports[:8]}")
        for p in ports:
            self._send(self.sock, self._remote_ip(), p)
        # 本端若为 symmetric-linear：开新 socket 产生递增映射端口，供对端学习回打
        if self.local.get("mapping") in (MAPPING_AD, MAPPING_APD) and self.local.get("allocation") == ALLOC_LINEAR:
            self._spawn_local_session_socket()

    def _spawn_local_session_socket(self):
        try:
            s = self._make_sock(0)
        except OSError:
            return
        self.extra_socks.append(s)
        threading.Thread(target=self._recv_loop, args=(s,), daemon=True).start()
        for c in self.candidates:
            self._send(s, c[0], c[1])

    def _random_punch_once(self):
        self._open_extra_socks(3)
        self.log(f"find enough random remote ports for punching (M={self.random_m})")
        rp = self.remote
        if rp.get("mapping") == MAPPING_EI:
            target_ports = [rp.get("public_port") or self.remote_candidate[1]]
        else:
            base = self._remote_base()
            step = self._remote_step_value()
            target_ports = [self.remote_candidate[1]]
            target_ports += [p for (_, p) in self.learned]
            target_ports += predict_ports(base, step, 8, bidirectional=True)
            target_ports = list(dict.fromkeys(target_ports))
        for s in self._all_socks():
            for p in target_ports:
                self._send(s, self._remote_ip(), p)
            for _ in range(self.random_m):
                self._send(s, self._remote_ip(), self.rng.randint(1024, 65535))

    def _standard_punch_once(self):
        # 标准 ICE 直连 + 回包引流（peer-reflexive）
        for (ip, p) in list(self.learned):
            self._send(self.sock, ip, p)

    # ---- 发包/收包 ----
    def _send(self, sock, ip, port):
        m = StunMsg()
        ip_str = self.local_public_ip or (self.local_bind[0] if self.local_bind else None)
        if not ip_str or ip_str == "0.0.0.0":
            ip_str = "127.0.0.1"   # 兜底（loopback 场景）
        try:
            ip_int = struct.unpack(">I", socket.inet_aton(ip_str))[0]
        except OSError:
            ip_int = 0
        m.set_xor_mapped(ip_int, self.local_public_port or self.local_bind[1])
        # [H] 0xc057 通告本端步长（供对端预测本端未来端口）+ 对端当前映射端口
        local_step = self.local.get("step") or 0
        m.set_nr(local_step, self._remote_base())
        m.set_magic()
        try:
            sock.sendto(m.encode(), (ip, port))
            self.stats["punches_sent"] += 1
        except OSError:
            pass

    def _recv_loop(self, sock):
        while not self._stop:
            try:
                data, addr = sock.recvfrom(512)
            except socket.timeout:
                continue
            except OSError:
                break
            m = StunMsg.decode(data)
            if m is None:
                continue
            if m.mtype != PUNCH_MSG_TYPE:
                self.log(f"recv: is not MAGIC_PUNCH_RESPONSE_STR (type={m.mtype})")
                continue
            if not m.check_magic():
                self.log(f"recv: magic mismatch")
                continue
            if self.p2p:
                # P2P 已建立：不再回打（避免 loopback 下互喂雪崩），仅保持 keepalive 通道
                continue
            with self._lock:
                self.recv_count += 1
                self.stats["punches_recv"] += 1
            nr = m.get_nr()
            if nr and nr[0]:
                self.remote_step = nr[0]   # 对端 0xc057 通告的本端 step
            mapped = m.get_xor_mapped()
            if mapped:
                ip, port = mapped
                self._on_peer_observation(sock, addr, ip, port)
            if not self.p2p and self.recv_count >= 2:
                # 双向确认：收到对端第 2 个合法 punch 包。对端只在收到本端包后才回包，
                # 故收到第 2 个包证明「对端已收到本端回打」→ 双向数据面贯通（多 1 RTT 防假阳性）。
                with self._lock:
                    if not self.p2p:
                        self.p2p = True
                        self.p2p_peer = addr

    def _on_peer_observation(self, sock, addr, mapped_ip, mapped_port):
        # 学习对端真实映射（XOR-MAPPED 通告）+ peer-reflexive（包源地址）
        candidates = []
        try:
            candidates.append((socket.inet_ntoa(struct.pack(">I", mapped_ip)), mapped_port))
        except OSError:
            pass
        candidates.append((addr[0], addr[1]))
        for c in candidates:
            if c not in self.learned:
                self.learned.append(c)
                self.stats["learn_events"] += 1
                self.log(f"learned candidate {c[0]}:{c[1]} (upgrade)")
        self.remote_ports.append(mapped_port)
        # 自适应重估 step（差分众数）
        if len(self.remote_ports) >= 3:
            new_step = infer_step(self.remote_ports)
            if new_step and new_step != self.remote_step:
                self.remote_step = new_step
                self.stats["step_history"].append((self.epoch, list(self.remote_ports[-3:]), new_step))
                self.log(f"adaptive step re-estimate -> {new_step}")
        predicted = predict_ports(self._remote_base(), self._remote_step_value(),
                                  self.predict_n, bidirectional=True)
        if mapped_port in predicted:
            self.stats["predicted_hits"] += 1
        # 立即回打 learned + 所有候选（[H] 0x3f17e8: for addr in candidates: send_punch）
        self._reply_all(sock)

    def _reply_all(self, sock):
        # 回打候选 + 对端最新映射（避免全量 learned 回打导致 loopback 下包雪崩；
        # 真实 NAT 侧多余回打会被过滤，但这里保持有界）
        targets = list(self.candidates)
        if self.learned:
            targets.append(self.learned[-1])
        for (ip, p) in targets:
            self._send(sock, ip, p)

    def _tcp_targets(self):
        # TCP 对照探测：--fw-tcp 覆盖优先；否则用 STUN 服务器真实 IP 或对端 IP:443
        if self.fw_tcp:
            return self.fw_tcp
        ip = self.remote_candidate[0]
        if ip and not ip.startswith("127."):
            return [(ip, FIREWALL_TCP_PORT)]
        return []

    # ---- keepalive 与缓存 ----
    def _start_keepalive(self):
        def loop():
            end = time.time() + self.hold_s
            while self.p2p and not self._stop and time.time() < end:
                time.sleep(self.keepalive_s)
                if self.p2p_peer:
                    self._send(self.sock, self.p2p_peer[0], self.p2p_peer[1])
                    self.stats["keptalive"] += 1
                    self.log(f"keepalive to {self.p2p_peer[0]}:{self.p2p_peer[1]}")
        self._keepalive_thread = threading.Thread(target=loop, daemon=True)
        self._keepalive_thread.start()

    def _load_cache_hint(self):
        if not self.cache_path or not os.path.exists(self.cache_path):
            return
        rip = self.remote_candidate[0]
        for pair in load_pair_cache(self.cache_path):
            if pair.get("remote_ip") == rip:
                rng = pair.get("range") or []
                self.cache_hint = [int(p) & 0xFFFF for p in rng if 0 <= int(p) <= 0xFFFF]
                self.log(f"pair cache hit for {rip}: range={rng}")
                return

    def _save_cache(self):
        if not self.cache_path:
            return
        pairs = load_pair_cache(self.cache_path)
        rip = self.remote_candidate[0]
        base = self._remote_base()
        step = self._remote_step_value()
        rng = predict_ports(base, step, self.predict_n, bidirectional=True)
        new_pair = {
            "remote_ip": rip,
            "mapped_port": self.p2p_peer[1] if self.p2p_peer else None,
            "base": base,
            "step": step,
            "range": rng,
            "ts": int(time.time()),
        }
        pairs = [p for p in pairs if p.get("remote_ip") != rip]
        pairs.insert(0, new_pair)
        ok = save_pair_cache(self.cache_path, pairs[:5])
        self.stats["cache_saves"] = 1 if ok else 0
        self.log(f"saved pair cache ({rip})")


# ===== 信令（简化 TCP：交换候选+NAT类型+profile，模拟 WebSocket） =====
class Signal:
    @staticmethod
    def listen(port):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", port))
        srv.listen(1)
        return srv.accept()[0]

    @staticmethod
    def connect(host, port, retries=20, delay=0.3):
        # 对端可能仍在做 RFC5780 探测（filtering probe 更慢），重试等待其监听就绪
        last = None
        for _ in range(retries):
            c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            c.settimeout(10)
            try:
                c.connect((host, port))
                return c
            except OSError as e:
                last = e
                c.close()
                time.sleep(delay)
        raise last

    @staticmethod
    def recv(conn):
        data = b""
        while b"\n" not in data:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
        if not data:
            raise EOFError("signal closed")
        return json.loads(data.decode())

    @staticmethod
    def send(conn, obj):
        conn.sendall(json.dumps(obj).encode() + b"\n")


# ===== Peer 主流程 =====
def _profile_for_signal(p):
    return {k: p.get(k) for k in ("mapping", "allocation", "step", "public", "public_ip",
                                  "public_port", "confidence", "filtering", "legacy_nat_type")}


def _watchdog(seconds):
    """硬性退出兜底：避免卡住的 puncher 在测试矩阵中成为孤儿进程。"""
    time.sleep(seconds)
    os._exit(3)


def run_peer(role, host, port, name, args):
    # 兜底 watchdog：任何异常卡住（如对端崩溃、信令阻塞）时强制退出，防止在测试矩阵中
    # 因 nat_sim 被 kill 而成为孤儿进程占用端口（nat_sim 无法在 SIGKILL 后回收子进程）
    wd_secs = max(args.window_s + args.hold_s + 20.0, 45.0)
    threading.Thread(target=_watchdog, args=(wd_secs,), daemon=True).start()

    # 1. NAT 检测（RFC 5780）
    nd = NatDetector(timeout=args.probe_timeout, private_ip=args.private_ip,
                     probe_port_min=args.probe_port_min, probe_port_max=args.probe_port_max)
    profile, punch_sock = nd.detect(parse_stun_targets(args.stun),
                                    filtering_probe=args.filtering_probe)
    if args.force_nat is not None:
        profile = force_profile(profile, args.force_nat)
    print(f"[{name}] NAT profile: mapping={profile['mapping']} allocation={profile['allocation']} "
          f"step={profile['step']} public={profile['public']} confidence={profile['confidence']:.2f} "
          f"filtering={profile['filtering']} reuse={profile['port_reuse']} "
          f"legacy={profile['legacy_nat_type']} degraded={profile['degraded']}", flush=True)
    for o in profile["observations"]:
        print(f"[{name}]   obs {o['group']:<12} target={o['target']:<20} socket={o['socket_bind']:<15} "
              f"mapped={o['mapped_ip']}:{o['mapped_port']}", flush=True)

    # 2. 信令交换
    info = {"name": name, "nat": profile["legacy_nat_type"], "profile": _profile_for_signal(profile),
            "public": profile["public"], "public_ip": profile["public_ip"],
            "public_port": profile["public_port"], "listen_port": profile["listen_port"]}
    if role == "listen":
        conn = Signal.listen(port)
        peer_info = Signal.recv(conn)
        Signal.send(conn, info)
        conn.close()
        peer_public = (peer_info.get("public_ip"), peer_info.get("public_port"))
        peer_addr = peer_public if all(peer_public) else (peer_info.get("host", host), peer_info.get("listen_port"))
    else:
        info["host"] = host
        conn = Signal.connect(host, port)
        Signal.send(conn, info)
        peer_info = Signal.recv(conn)
        conn.close()
        peer_public = (peer_info.get("public_ip"), peer_info.get("public_port"))
        peer_addr = peer_public if all(peer_public) else (host, peer_info.get("listen_port"))
    peer_profile = peer_info.get("profile") or {}
    print(f"[{name}] peer: {peer_info.get('name')} nat={peer_info.get('nat')} "
          f"profile=({peer_profile.get('mapping')}/{peer_profile.get('allocation')}) addr={peer_addr}", flush=True)

    # 3. 打洞
    fw_dns = None
    if args.fw_dns:
        fw_dns = [_split_host_port(s) for s in args.fw_dns.split(",") if s.strip()]
    fw_tcp = None
    if args.fw_tcp:
        fw_tcp = [_split_host_port(s) for s in args.fw_tcp.split(",") if s.strip()]
    engine = PunchEngine(name, profile, peer_profile, peer_addr, [peer_addr],
                         sock=punch_sock, private_ip=args.private_ip,
                         retry_s=args.retry_ms / 1000.0, window_s=args.window_s,
                         keepalive_s=args.keepalive_s, hold_s=args.hold_s,
                         cache_path=args.cache, predict_n=args.predict_n, random_m=args.random_m,
                         probe_port_min=args.probe_port_min, probe_port_max=args.probe_port_max,
                         fw_dns=fw_dns, fw_tcp=fw_tcp, fw_timeout=args.fw_timeout)
    result = engine.start()
    print(f"[{name}] result: {result}", flush=True)
    print(f"[{name}] stats: {json.dumps(engine.stats, sort_keys=True)}", flush=True)
    return result


# ===== 单测 =====
def _obs(group, tip, tport, mapped_ip=0x0A000001, mapped_port=5000):
    return MappingObservation(group, tip, tport, ("127.0.0.1", 40000),
                              mapped_ip, mapped_port)


def run_tests():
    ok = lambda n, c: print(f"  {n}: {'PASS' if c else 'FAIL'}")
    # ---- 原 §7 13 项（保持全 PASS） ----
    ok("predict_ports", predict_ports(10000, 3, 4) == [10012, 10009, 10006, 10003])
    ok("overflow_protect", predict_ports(0xFFFE, 1, 2)[0] == 1)
    ok("switch(2,1)", choose_strategy({"mapping": MAPPING_APD, "allocation": ALLOC_LINEAR},
                                      {"mapping": MAPPING_EI, "allocation": ALLOC_STABLE}) == "LinearSymmericPunchToCone")
    ok("switch(3,3)", choose_strategy({"mapping": MAPPING_APD, "allocation": ALLOC_RANDOM},
                                      {"mapping": MAPPING_APD, "allocation": ALLOC_RANDOM}) == "BothRandomSymmericPunch")
    ok("priority(1,2)=+10", group_pair_priority(1, 2, 100, 200) == 30010)
    ok("priority(3,3)=+60", group_pair_priority(3, 3, 100, 200) == 30060)
    ok("infer_step", infer_step([50000, 50003, 50006]) == 3)
    m = StunMsg()
    m.set_xor_mapped(0x0A000001, 5000)
    m.set_nr_port(42)
    m.set_magic()
    d = StunMsg.decode(m.encode())
    ok("stun_xor_mapped", d.get_xor_mapped() == (0x0A000001, 5000))
    ok("stun_nr_port", d.get_nr_port() == 42)
    ok("stun_magic", d.check_magic())
    ok("classify_cone", classify_mapping([_obs("same_target", "1.1.1.1", 100, 0x0A000001, 5000),
                                          _obs("same_target", "1.1.1.1", 100, 0x0A000001, 5000),
                                          _obs("diff_port", "1.1.1.1", 101, 0x0A000001, 5000),
                                          _obs("diff_ip", "2.2.2.2", 100, 0x0A000001, 5000)])[0] == MAPPING_EI)
    ok("classify_linear", classify_port_allocation([5000, 5001, 5002]) == (ALLOC_LINEAR, 1))
    ok("classify_random", classify_port_allocation([5000, 5010, 5023]) == (ALLOC_RANDOM, 0))

    # ---- A1: classify_mapping ----
    ei = classify_mapping([_obs("same_target", "1.1.1.1", 100, 0x0A000001, 5000),
                           _obs("same_target", "1.1.1.1", 100, 0x0A000001, 5000),
                           _obs("diff_port", "1.1.1.1", 101, 0x0A000001, 5000),
                           _obs("diff_ip", "2.2.2.2", 100, 0x0A000001, 5000)])
    ok("A1_mapping_EI", ei[0] == MAPPING_EI and ei[1] == (0x0A000001, 5000))
    ad = classify_mapping([_obs("same_target", "1.1.1.1", 100, 0x0A000001, 5000),
                           _obs("same_target", "1.1.1.1", 100, 0x0A000001, 5000),
                           _obs("diff_port", "1.1.1.1", 101, 0x0A000001, 5000),
                           _obs("diff_ip", "2.2.2.2", 100, 0x0A000001, 5001)])
    ok("A1_mapping_AD", ad[0] == MAPPING_AD)
    apd = classify_mapping([_obs("same_target", "1.1.1.1", 100, 0x0A000001, 5000),
                            _obs("same_target", "1.1.1.1", 100, 0x0A000001, 5000),
                            _obs("diff_port", "1.1.1.1", 101, 0x0A000001, 5100),
                            _obs("diff_ip", "2.2.2.2", 100, 0x0A000001, 5200)])
    ok("A1_mapping_APD", apd[0] == MAPPING_APD)
    unk = classify_mapping([_obs("same_target", "1.1.1.1", 100, 0x0A000001, 5000),
                            _obs("same_target", "1.1.1.1", 100, 0x0A000001, 5000)])
    ok("A1_mapping_lt3_unknown", unk[0] == MAPPING_UNKNOWN)

    # ---- A2: classify_port_allocation ----
    ok("A2_alloc_stable", classify_port_allocation([5000, 5000, 5000]) == (ALLOC_STABLE, 0))
    ok("A2_alloc_linear3", classify_port_allocation([50000, 50003, 50006]) == (ALLOC_LINEAR, 3))
    ok("A2_alloc_random", classify_port_allocation([5000, 5010, 5023]) == (ALLOC_RANDOM, 0))
    ok("A2_alloc_empty", classify_port_allocation([]) == (ALLOC_STABLE, 0))

    # ---- A3: predict_ports 双向 + 16bit 回绕 + step 重估 ----
    bi = predict_ports(10000, 3, 2, bidirectional=True)
    ok("A3_predict_bi", bi == [9994, 9997, 10003, 10006])
    wrap = predict_ports(0xFFFE, 1, 2, bidirectional=True)
    ok("A3_predict_bi_wrap", wrap == [0xFFFC, 0xFFFD, 0xFFFF, 1])
    ok("A3_step_reestimate", infer_step([50000, 50003, 50006, 50009]) == 3)
    ok("A3_step_adaptive_reestimate", infer_step([50000, 50003, 50007, 50010, 50013]) == 3)

    # ---- A4: 策略选择 ----
    ei_stable = {"mapping": MAPPING_EI, "allocation": ALLOC_STABLE}
    apd_lin = {"mapping": MAPPING_APD, "allocation": ALLOC_LINEAR}
    apd_ran = {"mapping": MAPPING_APD, "allocation": ALLOC_RANDOM}
    ei_lin = {"mapping": MAPPING_EI, "allocation": ALLOC_LINEAR}
    ok("A4_bi_linear", choose_strategy(ei_lin, ei_lin) == "BothLinearSymmericPunch")
    ok("A4_random_vs_cone", choose_strategy(apd_ran, ei_stable) == "RandomSymmericPunchToCone")
    ok("A4_cone_vs_linear", choose_strategy(ei_stable, apd_lin) == "ConePunchToLinearSymmeric")
    ok("A4_both_random", choose_strategy(apd_ran, apd_ran) == "BothRandomSymmericPunch")
    ok("A4_cone_cone_direct", choose_strategy(ei_stable, ei_stable) == DIRECT_CONE)

    # ---- A5: keepalive 心跳构造/解析 + pair cache 读写 ----
    hb = StunMsg()
    hb.set_xor_mapped(0x0A000002, 6000)
    hb.set_nr(3, 6000)
    hb.set_magic()
    hbd = StunMsg.decode(hb.encode())
    ok("A5_keepalive_encode_decode", hbd is not None and hbd.check_magic()
       and hbd.get_xor_mapped() == (0x0A000002, 6000) and hbd.get_nr() == (3, 6000))
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "cache.json")
        save_pair_cache(path, [{"remote_ip": "1.2.3.4", "range": [9994, 9997, 10003, 10006]}])
        pairs = load_pair_cache(path)
        ok("A5_pair_cache_roundtrip", len(pairs) == 1 and pairs[0]["remote_ip"] == "1.2.3.4")
        save_pair_cache(path, pairs + [{"remote_ip": "5.6.7.8"}])
        ok("A5_pair_cache_bounded", len(load_pair_cache(path)) <= 5)
    print("全部单测完成")


# ===== 入口 =====
def main():
    ap = argparse.ArgumentParser(description="UU远程打洞算法实现（RFC 5780 修正版）")
    ap.add_argument("--role", choices=["listen", "connect"], default="listen")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9900)
    ap.add_argument("--name", default="peer")
    ap.add_argument("--force-nat", type=int, default=None, choices=[1, 2, 3])
    ap.add_argument("--test", action="store_true")
    ap.add_argument("--stun", default="", help="STUN 地址列表，逗号分隔；支持 逻辑IP:port@真实IP:port")
    ap.add_argument("--private-ip", default="0.0.0.0")
    ap.add_argument("--probe-port-min", type=int, default=None)
    ap.add_argument("--probe-port-max", type=int, default=None)
    ap.add_argument("--probe-timeout", type=float, default=2.0)
    ap.add_argument("--filtering-probe", action="store_true", help="尽力做 RFC5780 filtering 探测（需服务器支持 CHANGE-REQUEST）")
    ap.add_argument("--retry-ms", type=int, default=5000)
    ap.add_argument("--window-s", type=float, default=PUNCH_WINDOW_S)
    ap.add_argument("--keepalive-s", type=float, default=KEEPALIVE_S)
    ap.add_argument("--hold-s", type=float, default=0.0, help="P2P 后保持秒数（验证 keepalive）")
    ap.add_argument("--cache", default=None, help="pair 缓存路径（默认 ~/.puncher_pair_cache.json，--no-cache 禁用）")
    ap.add_argument("--no-cache", action="store_true")
    ap.add_argument("--predict-n", type=int, default=8)
    ap.add_argument("--random-m", type=int, default=64)
    ap.add_argument("--fw-dns", default=None, help="防火墙 UDP DNS 探测目标覆盖（ip:port,ip:port，供 mock 环境确定性）")
    ap.add_argument("--fw-tcp", default=None, help="防火墙 TCP 对照探测目标覆盖（ip:port,ip:port）")
    ap.add_argument("--fw-timeout", type=float, default=2.0, help="防火墙探测每目标超时（秒）")
    a = ap.parse_args()
    if a.test:
        run_tests()
        return
    if a.no_cache:
        a.cache = None
    elif a.cache is None:
        a.cache = _default_cache_path()
    run_peer(a.role, a.host, a.port, a.name, a)


if __name__ == "__main__":
    main()
