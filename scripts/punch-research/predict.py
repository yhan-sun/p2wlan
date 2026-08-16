#!/usr/bin/env python3
"""predict.py — S1 预测引擎升级（纯函数 + 轻量状态类，零第三方依赖）

S1.1 双向窗口预测：predict_ports(base, step, N, W=2, exclude=())
  - 区间 [base - W*N*step, base + W*N*step]（W 为窗口乘数；N 为每方向基准点数 8/16）
  - 区间内按 step 整数点降序探测（远端 → 近端），16bit 回绕保护，剔除 exclude
  - 工程化解释：原版 [H] base+step*N 单向前向；S1 双向窗口 = 每方向 N*W 个点，
    W=0 退化为单点 base（基准直连语义），W 默认 2。

S1.2 StepLearner：0xc057 通告（w=0.6）＋本端差分众数（w=0.4）→ 双通道 EWMA 融合。
  众数抗噪（差分序列先取窗口众数再入 EWMA）；输出 step_estimate / step_confidence /
  revision_count（学习轨迹）。

S1.3 ReverseDetector：差分符号窗口众数 → pattern=forward|reverse|mixed；reverse 时建议 W+1。

S1.4 BirthdayPool：生日悖论多 socket 并发模型。
  P(至少一源命中) = 1 - (1 - M/port_space)^K；recommend_pool() 求 K。
  命中记录 socket_index 证明源多样性收益。

S1.5 BudgetScanner：分层预算扫描（总预算 2s/轮）：精确→区间→随机→全端口降采样(步进8)；
  返回阶段计划 + budget_decomposition 记录。

S1.6 命中量化：hit_metrics()（pattern/偏差点数/区间偏移）+ precision_at_top_n()。

用法：python3 predict.py --test   （单测，不依赖网络）
"""
import collections
import random

# ===== S1.1 双向窗口预测 =====
PORT_SPACE = 0x10000  # 65536，16bit 端口空间


def predict_ports(base_port, step, N, W=2, exclude=()):
    """双向窗口预测（S1.1）。

    返回区间 [base - W*N*step, base + W*N*step] 内全部 step 整数点（不含 base 本身；
    base 由调用方作为主候选单独发送），按端口号降序（区间内降序探测，远端优先）。
    16bit 回绕保护：结果 == 0 时回退为 step（[H] csel 语义）。
    剔除 exclude 中的端口（已探测 / 已失败）。
    """
    if step <= 0 or W <= 0:
        return []
    exclude = set(int(p) & 0xFFFF for p in exclude)
    per_side = max(1, N * max(0, W))
    points = set()
    for i in range(1, per_side + 1):
        for sign in (1, -1):
            p = (base_port + sign * i * step) & 0xFFFF
            if p == 0:
                p = step
            if p not in exclude:
                points.add(p)
    return sorted(points, reverse=True)


def predict_interval(base_port, step, N, W=2):
    """预测区间描述（供日志/缓存/文档）：(lo, hi, count)。W<=0 时区间退化为单点。"""
    if step <= 0 or W <= 0:
        return (base_port, base_port, 0)
    per_side = max(1, N * max(0, W))
    lo = (base_port - per_side * step) & 0xFFFF
    hi = (base_port + per_side * step) & 0xFFFF
    return (lo, hi, 2 * per_side)


# ===== S1.2 StepLearner（EWMA 双通道融合） =====
class StepLearner:
    """步长学习器。

    通道 A：对端 0xc057 通告（单值，α=0.6 —— 通告权威性高）
    通道 B：本端差分众数（序列先取窗口众数抗噪，α=0.4）
    step_estimate = 0.6*A + 0.4*B（缺失通道用另一通道）。
    revision_count：估计值每次变化 +1（学习轨迹）。
    step_confidence：(0,1]，来自通道 B 众数覆盖率与 EWMA 稳定度。
    """

    ALPHA_ADVERT = 0.6
    ALPHA_DIFF = 0.4

    def __init__(self, mode_window=8):
        self.mode_window = mode_window
        self._advert_est = None
        self._diff_est = None
        self._diffs = collections.deque(maxlen=32)
        self.estimate = None
        self.confidence = 0.0
        self.revision_count = 0
        self.trace = []   # (kind, value, estimate)

    def _mode(self, values):
        if not values:
            return None, 0.0
        c = collections.Counter(values)
        v, n = c.most_common(1)[0]
        return v, n / len(values)

    def observe_diff(self, diff):
        """观测一个端口差分（源端口序列相邻差）。"""
        if diff <= 0:
            return
        self._diffs.append(diff)
        mode, cov = self._mode(list(self._diffs)[-self.mode_window:])
        if mode is None:
            return
        if self._diff_est is None:
            self._diff_est = float(mode)
        else:
            self._diff_est = self.ALPHA_DIFF * mode + (1 - self.ALPHA_DIFF) * self._diff_est
        self._recompute(cov, "diff", mode)

    def observe_advertised(self, step):
        """观测对端 0xc057 通告步长。"""
        if step <= 0:
            return
        if self._advert_est is None:
            self._advert_est = float(step)
        else:
            self._advert_est = self.ALPHA_ADVERT * step + (1 - self.ALPHA_ADVERT) * self._advert_est
        self._recompute(None, "advertised", step)

    def _recompute(self, diff_cov, kind, value):
        a, b = self._advert_est, self._diff_est
        if a is not None and b is not None:
            est = 0.6 * a + 0.4 * b
        else:
            est = a if a is not None else (b if b is not None else None)
        if est is None:
            return
        new = max(1, int(round(est)))
        if new != self.estimate:
            self.revision_count += 1
        self.estimate = new
        self.confidence = min(1.0, max(self.confidence, diff_cov or 0.0))
        self.trace.append((kind, value, new))

    def get(self):
        """返回 (step_estimate, step_confidence, revision_count)。"""
        return (self.estimate, self.confidence, self.revision_count)


# ===== S1.3 ReverseDetector（回拨模式识别） =====
class ReverseDetector:
    """对端映射端口回拨检测。

    差分符号窗口众数：全部/多数为正 → forward；为负 → reverse；正负交替 → mixed。
    reverse 模式（对端端口在回拨，即新会话端口 < 旧端口）时建议 W+1 扩大窗口。
    """

    def __init__(self, window=8):
        self.window = window
        self._ports = collections.deque(maxlen=32)
        self.pattern = "forward"

    def observe_port(self, port):
        if self._ports:
            d = (port - self._ports[-1]) & 0xFFFF
            # 大正差分可能是回绕：>32768 视为负（回拨）
            if d > 0x8000:
                d -= PORT_SPACE
        self._ports.append(port)
        if len(self._ports) < 3:
            return self.pattern
        signs = []
        prev = self._ports[0]
        for p in list(self._ports)[1:]:
            d = p - prev
            if d > 0x8000:
                d -= PORT_SPACE
            if d < -0x8000:
                d += PORT_SPACE
            if d != 0:
                signs.append(1 if d > 0 else -1)
            prev = p
        if not signs:
            self.pattern = "forward"
            return self.pattern
        c = collections.Counter(signs[-self.window:])
        pos, neg = c.get(1, 0), c.get(-1, 0)
        if pos > 0 and neg > 0:
            self.pattern = "mixed"
        elif neg > 0 and neg >= pos:
            self.pattern = "reverse"
        else:
            self.pattern = "forward"
        return self.pattern

    def suggest_window(self, W):
        """reverse 时建议 W+1（扩大窗口覆盖回拨漂移）。"""
        return W + 1 if self.pattern == "reverse" else W


# ===== S1.4 BirthdayPool（生日悖论多 socket 并发） =====
def birthday_success_prob(M, K, port_space=PORT_SPACE):
    """K 个源 socket 并发、每 socket 随机打 M 个对端端口：至少一个源映射被命中的概率。"""
    if M <= 0 or K <= 0:
        return 0.0
    p_single = min(1.0, M / port_space)
    return 1.0 - (1.0 - p_single) ** K


def recommend_pool(M, target_p=0.95, port_space=PORT_SPACE):
    """达到 target_p 命中率所需的最小源 socket 数 K（M 固定）。

    生日模型下 K 可能极大（random 对端每个映射端口被 M 个随机端口命中的概率仅 M/65536），
    返回 min(k, 128)（cap 说明该目标在该 M 下不可工程实现；调用方应结合多轮重试）。
    """
    if M <= 0:
        return 1
    import math
    p_single = min(1.0, M / port_space)
    if p_single >= target_p:
        return 1
    k = math.ceil(math.log(1.0 - target_p) / math.log(1.0 - p_single))
    return max(1, min(k, 128))


# ===== S1.5 BudgetScanner（分层预算扫描） =====
class BudgetScanner:
    """分层预算扫描器。

    plan()：给定总预算与各层端口集合，输出阶段执行计划（精确→窗口→随机→全端口降采样），
    每阶段附带预算占比与预算毫秒。命中即停由调用方（引擎收包）负责。
    budget_decomposition 记录实际执行比例，供 S4 汇总。
    """

    SWEEP_STEP = 8          # 全端口降采样步进
    PROBE_COST_MS = 0.2     # 单包成本估计（UDP loopback 量级，可配）

    def __init__(self, budget_s=2.0, probe_cost_ms=PROBE_COST_MS):
        self.budget_s = budget_s
        self.probe_cost_ms = probe_cost_ms
        self.last_decomposition = None

    def plan(self, candidates, window_ports, M, seed=None):
        """返回阶段列表 [(kind, ports, budget_ms), ...]。
        candidates: 精确候选端口（信令交换/learned）；window_ports: S1.1 窗口预测；
        M: 随机层端口数。全端口降采样：0..65535 步进 SWEEP_STEP。"""
        rng = random.Random(seed)
        total_budget_ms = max(1.0, self.budget_s * 1000.0)
        stages = []
        exact = [p for p in candidates if 0 <= p <= 0xFFFF]
        if exact:
            stages.append(("exact", exact, min(total_budget_ms, len(exact) * self.probe_cost_ms)))
        if window_ports:
            stages.append(("window", window_ports,
                           min(total_budget_ms, len(window_ports) * self.probe_cost_ms)))
        random_ports = []
        if M > 0:
            random_ports = [rng.randint(1024, 0xFFFF) for _ in range(M)]
            stages.append(("random", random_ports, min(total_budget_ms, M * self.probe_cost_ms)))
        sweep = list(range(0, PORT_SPACE, self.SWEEP_STEP))
        stages.append(("sweep", sweep, min(total_budget_ms, len(sweep) * self.probe_cost_ms)))
        self.last_decomposition = {k: round(v, 1) for k, _, v in stages}
        return stages


# ===== S1.6 命中量化 =====
def hit_metrics(hit_port, base, step, window_ports, sweep_step=BudgetScanner.SWEEP_STEP):
    """单次命中的量化指标。

    返回 {pattern, offset_steps, interval_offset}：
      pattern: exact|window_plus|window_minus|random|sweep|direct
      offset_steps: (hit - base) / step 的步数（step<=0 时为 None）
      interval_offset: (hit - base) 原始差值
    """
    delta = hit_port - base
    out = {"pattern": "random", "offset_steps": None, "interval_offset": delta}
    if step and step > 0:
        off = delta / step
        out["offset_steps"] = round(off, 1)
    if window_ports:
        if hit_port in window_ports:
            out["pattern"] = "window_plus" if delta > 0 else "window_minus"
        elif hit_port == base:
            out["pattern"] = "direct"
    elif hit_port == base:
        out["pattern"] = "direct"
    if out["pattern"] == "random" and sweep_step and hit_port % sweep_step == 0:
        out["pattern"] = "sweep"
    return out


def precision_at_top_n(hits, n, total_probes):
    """Precision@top-N：命中发生在「前 n 个探针」的比例。

    hits: 按时间顺序的探针命中序号列表（1-based）；total_probes: 该轮总探针数。
    返回 (precision, hits_in_top_n, total_hits)。
    """
    if not hits:
        return (0.0, 0, 0)
    top = sum(1 for h in hits if h <= n)
    return (top / len(hits), top, len(hits))


# ===== 单测 =====
def run_tests():
    ok = lambda n, c: print(f"  {n}: {'PASS' if c else 'FAIL'}")

    # P1: 双向窗口
    w = predict_ports(10000, 3, 2, W=2)          # 每方向 4 点，降序
    ok("P1_window_desc", w == sorted({10000 + 3 * i for i in (1, 2, 3, 4)} | {10000 - 3 * i for i in (1, 2, 3, 4)}, reverse=True))
    ok("P1_window_count", len(predict_ports(10000, 3, 8, W=2)) == 32)
    ok("P1_window_w0_empty", predict_ports(10000, 3, 8, W=0) == [])
    wr = predict_ports(0xFFFE, 1, 2, W=2)
    ok("P1_wrap", wr[0] == 0xFFFF and all(0 <= p <= 0xFFFF for p in wr) and 0x10002 not in wr)
    excl = predict_ports(10000, 3, 2, W=2, exclude=[10012])
    ok("P1_exclude", 10012 not in excl)
    ok("P1_step0_empty", predict_ports(10000, 0, 8, W=2) == [])
    lo, hi, cnt = predict_interval(10000, 3, 2, W=2)
    ok("P1_interval", lo == 10000 - 12 and hi == 10000 + 12 and cnt == 8)

    # P2: StepLearner
    sl = StepLearner()
    sl.observe_diff(3)
    sl.observe_diff(3)
    sl.observe_diff(4)     # 噪声
    sl.observe_diff(3)
    ok("P2_diff_mode3", sl.get()[0] == 3)
    r0 = sl.revision_count
    sl.observe_advertised(5)
    sl.observe_advertised(5)
    # 融合：0.6*5 + 0.4*3 = 4.2 → 4（通告主导 w=0.6，但不完全覆盖差分通道）
    ok("P2_advert_weight", sl.get()[0] == 4)
    ok("P2_revision_tracked", sl.revision_count >= r0)
    ok("P2_confidence", 0.0 < sl.get()[1] <= 1.0)
    sl2 = StepLearner()
    for _ in range(5):
        sl2.observe_diff(3)
    ok("P2_converge3", sl2.get()[0] == 3)

    # P3: ReverseDetector
    rd = ReverseDetector()
    for p in (5000, 5003, 5006, 5009):
        rd.observe_port(p)
    ok("P3_forward", rd.pattern == "forward" and rd.suggest_window(2) == 2)
    rd2 = ReverseDetector()
    for p in (5009, 5006, 5003, 5000):
        rd2.observe_port(p)
    ok("P3_reverse", rd2.pattern == "reverse" and rd2.suggest_window(2) == 3)
    rd3 = ReverseDetector()
    for p in (5000, 5003, 5000, 5003):
        rd3.observe_port(p)
    ok("P3_mixed", rd3.pattern == "mixed")

    # P4: BirthdayPool
    p1 = birthday_success_prob(64, 1)
    p3 = birthday_success_prob(64, 3)
    ok("P4_more_sockets_higher", p3 > p1)
    ok("P4_bound", 0 < p1 < 1 and p3 < 1)
    k = recommend_pool(64, 0.95)
    ok("P4_recommend", 1 <= k <= 128 and (k == 128 or birthday_success_prob(64, k) >= 0.95))

    # P5: BudgetScanner
    bs = BudgetScanner(budget_s=2.0)
    stages = bs.plan([5000], predict_ports(5000, 3, 8, W=2), 64, seed=7)
    kinds = [s[0] for s in stages]
    ok("P5_stage_order", kinds == ["exact", "window", "random", "sweep"])
    ok("P5_decomposition", bs.last_decomposition is not None and sum(bs.last_decomposition.values()) > 0)
    total_ms = sum(s[2] for s in stages)
    ok("P5_budget_bounded", total_ms <= 2000 + 1e-6)

    # P6: 命中量化
    hm = hit_metrics(10012, 10000, 3, predict_ports(10000, 3, 2, W=2))
    ok("P6_window_plus", hm["pattern"] == "window_plus" and hm["offset_steps"] == 4.0)
    hm2 = hit_metrics(10000, 10000, 3, [])
    ok("P6_direct", hm2["pattern"] == "direct")
    ok("P6_precision", precision_at_top_n([1, 40], 10, 100) == (0.5, 1, 2))
    print("全部 predict 单测完成")


if __name__ == "__main__":
    import sys
    if "--test" in sys.argv:
        run_tests()
    else:
        print("predict.py — S1 预测引擎模块（import 用；--test 跑单测）")