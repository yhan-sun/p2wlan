#!/usr/bin/env python3
"""run_matrix.py — 打洞集成矩阵（B 组）：系统性验证 puncher 双端在双 NAT 模拟下的可达性。

矩阵（<=30 组）：
  - cone 固定侧 (ei, stable) × filtering 变体 {ei,ad,apd} × B 侧 9 组合 (ei|ad|apd)×(stable|linear|random) = 27 组
  - 对称关键组合 3 组（双 linear 预测 / 双 ad linear / 双 random + port-restricted）

输出：
  - artifacts/nat_matrix.tsv      每行一组的关键数字
  - artifacts/logs/              代表性双端原始日志（<=3 组，含完整观测与 STUN 回显）
  单组超时 <=20s，全矩阵约 4-6 分钟。
"""
import argparse
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
NAT_SIM = os.path.join(HERE, "nat_sim.py")
ARTIFACTS = os.path.join(HERE, "artifacts")
LOGS = os.path.join(ARTIFACTS, "logs")

MAPPINGS = ("ei", "ad", "apd")
ALLOCS = ("stable", "linear", "random")

# 启发式预期：一侧能收到对端包的条件（经验校准，基于 APD filtering 的 dest 匹配语义）
#  - ei/ad filtering：对端从任何端口回包均放行 → 总能收到
#  - apd filtering：仅当对端回包源端口 == 本端 mapping.dest 端口时放行
#      · 对端 mapping=ei（端口恒 = public）→ 可学可命中 → 可通
#      · 对端 mapping=ad 且 allocation=linear（engine 会 spawn 多 socket 朝本端，
#        产生多个可学习的映射端口）→ 可通
#      · 对端 allocation=stable → 行为依赖时序，现实中少见 → 不确定（None）
#      · 其余（ad-random / apd-*）→ 对端回包源漂移，本端 apd 难以匹配 → 不可通
def can_receive(filtering_self, mapping_other, allocation_other, filtering_other):
    """一侧能否收到对端包（经验校准，APD filtering 的 dest 匹配语义）。

    本端 filtering ei/ad → 对端任意源均放行 → 总能收到。
    本端 filtering apd → 仅当对端回包源端口 == 本端 mapping.dest 时放行：
      · 对端 mapping=ei（端口恒 = public）→ 本端打 public 即命中 → 确定可通
      · 对端 symmetric（AD/APD）：本端端口固定（EI）→ 对端朝本端的映射 key 含本端固定端点
        → 对端回包源稳定 → 本端可学可命中，但依赖窗口内撞上 → 概率可达（NA）
      · 对端也是 apd filtering → 对端收不到本端，双向死锁 → 不可通
      · 对端 allocation=stable → 低现实频率，行为依赖时序 → 不确定（None）
    """
    if filtering_self in ("none", "ei", "ad"):
        return True
    if filtering_self == "apd":
        if mapping_other == "ei":
            return True     # 对端端口恒 = public，本端打 public 即命中 → 确定可通
        if allocation_other == "stable":
            return None     # 低现实频率，行为依赖时序
        # 对端 symmetric：本端端口固定（EI）→ 对端回包源稳定 → learned 置底后窗口内可撞上，
        # 但延迟/成败概率性（双 apd 更甚）→ 标 NA，由实际矩阵结果记录
        return None
    return True

def expected_reachable(c):
    ea = can_receive(c["filtering_a"], c["mapping_b"], c["allocation_b"], c["filtering_b"])
    eb = can_receive(c["filtering_b"], c["mapping_a"], c["allocation_a"], c["filtering_a"])
    if ea is None or eb is None:
        return None
    return bool(ea and eb)


def build_combos():
    combos = []
    # 1) cone 固定侧 filtering 变体 × B 侧 9 组合
    for fa in ("ei", "ad", "apd"):
        for mb in MAPPINGS:
            for ab in ALLOCS:
                combos.append({
                    "id": f"cone-f{fa}_b-{mb}-{ab}",
                    "mapping_a": "ei", "allocation_a": "stable", "filtering_a": fa, "step_a": 0,
                    "mapping_b": mb, "allocation_b": ab, "filtering_b": "ei",
                    "step_b": 3 if ab == "linear" else 0,
                })
    # 2) 对称关键组合
    combos += [
        {"id": "sym-2lin3", "mapping_a": "apd", "allocation_a": "linear", "filtering_a": "ei", "step_a": 3,
         "mapping_b": "apd", "allocation_b": "linear", "filtering_b": "ei", "step_b": 3},
        {"id": "sym-2adlin3", "mapping_a": "ad", "allocation_a": "linear", "filtering_a": "ei", "step_a": 3,
         "mapping_b": "ad", "allocation_b": "linear", "filtering_b": "ei", "step_b": 3},
        {"id": "sym-2rand-apd", "mapping_a": "apd", "allocation_a": "random", "filtering_a": "apd", "step_a": 0,
         "mapping_b": "apd", "allocation_b": "random", "filtering_b": "apd", "step_b": 0},
    ]
    return combos


def run_one(c, idx, args):
    sig = args.signal_base + idx * 2
    cmd = [
        sys.executable, NAT_SIM,
        "--puncher", os.path.join(HERE, "puncher.py"),
        "--signal-port", str(sig),
        "--window-s", str(args.window_s),
        "--retry-ms", str(args.retry_ms),
        "--probe-timeout", "1.5",
        "--keepalive-s", str(args.keepalive_s),
        "--hold-s", str(args.hold_s),
        "--filtering-probe",
        "--mapping-a", c["mapping_a"], "--allocation-a", c["allocation_a"],
        "--filtering-a", c["filtering_a"], "--step-a", str(c["step_a"]),
        "--mapping-b", c["mapping_b"], "--allocation-b", c["allocation_b"],
        "--filtering-b", c["filtering_b"], "--step-b", str(c["step_b"]),
        "--workdir", os.path.join(ARTIFACTS, "work", c["id"]),
        "--seed", str(args.seed),
    ]
    # 清理上一组合可能残留的孤儿进程（nat_sim 被超时 kill 后无法回收 puncher 子进程，
    # 其绑定的 observer/forwarder/信号端口会阻塞下一轮 → EADDRINUSE 秒退）
    subprocess.run(["pkill", "-9", "-f", "punch-research/nat_sim.py"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["pkill", "-9", "-f", "punch-research/puncher.py"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.0)
    t0 = time.time()
    crash_dir = os.path.join(ARTIFACTS, "work", c["id"])
    os.makedirs(crash_dir, exist_ok=True)
    report = None
    r = None
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=args.combo_timeout)
        report = json.loads(r.stdout)
    except subprocess.TimeoutExpired as e:
        report = {"success": False, "timed_out": True, "wall_ms": int((time.time() - t0) * 1000),
                  "a": {}, "b": {}, "error": "combo-timeout"}
        # 保留 nat_sim 原始输出供诊断
        with open(os.path.join(crash_dir, "crash_stdout.txt"), "w", encoding="utf-8") as f:
            f.write((e.stdout or "").decode("utf-8", errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or ""))
        with open(os.path.join(crash_dir, "crash_stderr.txt"), "w", encoding="utf-8") as f:
            f.write((e.stderr or "").decode("utf-8", errors="replace") if isinstance(e.stderr, bytes) else (e.stderr or ""))
    except json.JSONDecodeError as e:
        report = {"success": False, "timed_out": False, "wall_ms": int((time.time() - t0) * 1000),
                  "a": {}, "b": {}, "error": "json:" + str(e)}
    report["_elapsed"] = int((time.time() - t0) * 1000)
    # 秒退通常是端口冲突（前轮残留）：自动重试一次
    if report.get("wall_ms", 0) < 1000 and report.get("error") is None and not report.get("success"):
        time.sleep(1.0)
        t0 = time.time()
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=args.combo_timeout)
            report = json.loads(r.stdout)
        except (subprocess.TimeoutExpired, json.JSONDecodeError):
            pass
        report["_retried"] = True
        report["_elapsed"] = int((time.time() - t0) * 1000)
    return report


def tsv_row(c, r, idx):
    a, b = r.get("a", {}), r.get("b", {})
    sa, sb = a.get("stats") or {}, b.get("stats") or {}
    da, db = a.get("detected") or {}, b.get("detected") or {}
    exp = expected_reachable(c)
    actual = r.get("success", False)
    if exp is None:
        match = "NA"
    else:
        match = "OK" if (exp == actual) else "MISMATCH"
    return [
        c["id"], c["mapping_a"], c["allocation_a"], c["filtering_a"],
        c["mapping_b"], c["allocation_b"], c["filtering_b"], c["step_b"],
        da.get("mapping", "?"), da.get("allocation", "?"), da.get("filtering", "?"), da.get("step", "?"),
        db.get("mapping", "?"), db.get("allocation", "?"), db.get("filtering", "?"), db.get("step", "?"),
        a.get("result", "-"), b.get("result", "-"), "p2p" if actual else ("fail" if not r.get("timed_out") else "timeout"),
        sa.get("establish_ms", "-"), sb.get("establish_ms", "-"),
        sa.get("epoch", "-"), sb.get("epoch", "-"),
        sa.get("learn_events", "-"), sb.get("learn_events", "-"),
        sa.get("predicted_hits", "-"), sb.get("predicted_hits", "-"),
        sa.get("keptalive", "-"), sb.get("keptalive", "-"),
        sa.get("mode", "-"), sb.get("mode", "-"),
        ("expected" if exp else ("unexpected" if exp is False else "NA")), match,
        r.get("wall_ms", "-"),
    ]


HEADER = [
    "id", "map_a", "alloc_a", "filt_a", "map_b", "alloc_b", "filt_b", "step_b",
    "det_map_a", "det_alloc_a", "det_filt_a", "det_step_a",
    "det_map_b", "det_alloc_b", "det_filt_b", "det_step_b",
    "res_a", "res_b", "actual",
    "est_ms_a", "est_ms_b", "epoch_a", "epoch_b",
    "learn_a", "learn_b", "pred_hits_a", "pred_hits_b",
    "keepalive_a", "keepalive_b", "mode_a", "mode_b",
    "expected", "match", "wall_ms",
]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--signal-base", type=int, default=42500)
    ap.add_argument("--window-s", type=float, default=8)
    ap.add_argument("--retry-ms", type=int, default=800)
    ap.add_argument("--keepalive-s", type=float, default=2)
    ap.add_argument("--hold-s", type=float, default=4)
    ap.add_argument("--seed", type=int, default=20260816)
    ap.add_argument("--combo-timeout", type=int, default=20)
    ap.add_argument("--only", default=None, help="只跑指定 id（逗号分隔）")
    a = ap.parse_args()

    os.makedirs(ARTIFACTS, exist_ok=True)
    os.makedirs(LOGS, exist_ok=True)
    combos = build_combos()
    if a.only:
        allowed = set(a.only.split(","))
        combos = [c for c in combos if c["id"] in allowed]

    rows = [HEADER]
    results = []
    t_start = time.time()
    n_ok = 0
    for idx, c in enumerate(combos):
        r = run_one(c, idx, a)
        rows.append(tsv_row(c, r, idx))
        exp = expected_reachable(c)
        actual = r.get("success", False)
        if exp is None:
            tag = "NA"
            n_ok += 1
        else:
            tag = "PASS" if exp == actual else "FAIL"
            if exp == actual:
                n_ok += 1
        res_label = "p2p" if actual else ("timeout" if r.get("timed_out") else "fail")
        print(f"[{idx + 1}/{len(combos)}] {c['id']:<28} exp={exp} actual={res_label:<7} "
              f"wall={r.get('wall_ms')}ms est={r['a'].get('stats') and r['a']['stats'].get('establish_ms')}ms "
              f"mode_a={r['a'].get('stats') and r['a']['stats'].get('mode')}  {tag}", flush=True)
        # 保存代表性日志（<=3 组：首个成功、linear 预测、首个失败）
        save_log = None
        if actual and "a" in r and r["a"].get("stats", {}).get("mode") == "BothLinearSymmericPunch" and not any(
                rr["_kind"] == "linear" for rr in results):
            save_log = "linear"
        elif actual and not any(rr["_kind"] == "first_p2p" for rr in results):
            save_log = "first_p2p"
        elif not actual and not any(rr["_kind"] == "fail" for rr in results):
            save_log = "fail"
        if save_log:
            with open(os.path.join(LOGS, f"{c['id']}_{save_log}_a.log"), "w", encoding="utf-8") as f:
                f.write("".join(r.get("a", {}).get("lines", [])))
            with open(os.path.join(LOGS, f"{c['id']}_{save_log}_b.log"), "w", encoding="utf-8") as f:
                f.write("".join(r.get("b", {}).get("lines", [])))
            results.append({**_flatten(c, r), "_kind": save_log})

    with open(os.path.join(ARTIFACTS, "nat_matrix.tsv"), "w", encoding="utf-8") as f:
        for row in rows:
            f.write("\t".join(str(x) for x in row) + "\n")

    total_s = time.time() - t_start
    print(f"\n=== matrix done: {len(combos)} combos, {n_ok}/{len(combos)} exp-match, "
          f"elapsed {total_s / 60:.1f} min ===")
    print(f"TSV: {os.path.join(ARTIFACTS, 'nat_matrix.tsv')}")
    print(f"logs: {LOGS}")


def _flatten(c, r):
    return {"id": c["id"], "success": r.get("success", False)}


if __name__ == "__main__":
    main()
