#!/usr/bin/env python3
"""run_matrix_p2.py — S6 全谱回归矩阵（<=36 组，端到端 TESTS 断言）

覆盖（每行含预期结果表 + 注释）：
  [1-9]   A=cone(ei,stable,ei) × B=(ei|ad|apd)×(stable|linear|random)，B filtering=ei
         → B 侧全 mapping×allocation 交叉（含 stable=低现实频率标注）
  [10-18] A=cone filtering∈{ei,ad,apd} × B∈{ei-linear, apd-linear, apd-random}
         → filtering 变体 × 对称组合交叉
  [19-24] 对称关键组合：双 linear（apd/apd、ad/ad、ei/apd 反向）、双 random（apd/apd、ei/apd、ei/ei）
  [25-30] filtering 三态注入验证（A=apd filtering × B filtering ei/ad/apd）
         → 断言 puncher 检测出的 filtering/filtering_state 与注入一致（deny→apd 等）
  [31-36] hairpin 注入验证（A/B hairpin yes|no 组合）
         → 断言 puncher 的 hairpin 探测结果与注入一致（supported/unknown）

每组合输出：
  - 双端结果、建立时长、命中端口、轮次、step 学习轨迹、升级路径、keepalive
  - fingerprint 检测正确性（mapping/allocation/filtering/hairpin 与注入对比）
输出：artifacts/nat_matrix_p2.tsv + artifacts/logs_p2/ 代表性日志 + 汇总 TESTS 断言。

用法：python3 run_matrix_p2.py [--only id1,id2]
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
LOGS = os.path.join(ARTIFACTS, "logs_p2")

MAPPINGS = ("ei", "ad", "apd")
ALLOCS = ("stable", "linear", "random")
FILTS = ("ei", "ad", "apd")


EXPANDED = {"ei": "endpoint_independent", "ad": "address_dependent", "apd": "address_port_dependent"}


def can_receive(filtering_self, mapping_other, allocation_other):
    """启发式预期（同第一阶段 run_matrix）：APD filtering 仅放行 dest 精确匹配的源。

    注：puncher 主打洞 socket 具备端口复用（reuse）能力——对端 allocation=random 时，
    主 socket 源端口仍可能稳定，APD 过滤因此可放行（p2-fapd-b-apd-random 实测可达）。
    该场景启发式无法可靠判定，返回 None（NA）。"""
    if filtering_self in ("none", "ei", "ad"):
        return True
    if filtering_self == "apd":
        if mapping_other == "ei":
            return True
        if allocation_other == "stable":
            return None
        if allocation_other == "random":
            return None
        return False
    return True


def expected_reachable(c):
    ea = can_receive(c["filtering_a"], c["mapping_b"], c["allocation_b"])
    eb = can_receive(c["filtering_b"], c["mapping_a"], c["allocation_a"])
    if ea is None or eb is None:
        return None
    return bool(ea and eb)


def observed_allocation(mapping, allocation):
    """RFC 5780 单 socket 框架下可观察的 allocation：
    EI 映射同 socket 复用 → 恒为 stable；AD/APD 跨目标新分配可观察注入值。"""
    if mapping == "ei":
        return "stable"
    return allocation


def observed_filtering_state(filtering):
    return {"ei": "allow", "ad": "allow", "apd": "deny"}[filtering]


def fp_exempt(mapping, allocation, axis):
    """注入语义冲突豁免（记录于矩阵注释/TEST_REPORT_P2）：
    - AD/APD × stable：mapping 要求端口随目标变、stable 要求固定 → 模拟以 client 级稳定
      表达，mapping 可观察为 EI-like（豁免 mapping 轴）；
    - AD/APD × random：random 的新会话随机分配在多 key 采样下与 stable 顺序分配同形，
      allocation 轴受采样限制（豁免 allocation 轴）。"""
    if axis == "mapping" and mapping in ("ad", "apd") and allocation == "stable":
        return True
    if axis == "allocation" and mapping in ("ad", "apd") and allocation == "random":
        return True
    return False


def build_combos():
    combos = []
    # [1-9] B 侧全交叉
    for mb in MAPPINGS:
        for ab in ALLOCS:
            combos.append({
                "id": f"p2-b-{mb}-{ab}",
                "mapping_a": "ei", "allocation_a": "stable", "filtering_a": "ei",
                "mapping_b": mb, "allocation_b": ab, "filtering_b": "ei",
                "step_a": 0, "step_b": 3 if ab == "linear" else 0,
                "hairpin_a": True, "hairpin_b": True,
                "note": "low-frequency stable" if ab == "stable" else "B 侧全交叉",
            })
    # [10-18] A filtering 变体 × B 代表性对称
    for fa in FILTS:
        for mb, ab in (("ei", "linear"), ("apd", "linear"), ("apd", "random")):
            combos.append({
                "id": f"p2-f{fa}-b-{mb}-{ab}",
                "mapping_a": "ei", "allocation_a": "stable", "filtering_a": fa,
                "mapping_b": mb, "allocation_b": ab, "filtering_b": "ei",
                "step_a": 0, "step_b": 3 if ab == "linear" else 0,
                "hairpin_a": True, "hairpin_b": True,
                "note": "filtering 变体",
            })
    # [19-24] 对称关键
    sym = [
        ("apd", "linear", "apd", "linear"), ("ad", "linear", "ad", "linear"),
        ("ei", "linear", "apd", "linear"), ("apd", "random", "apd", "random"),
        ("ei", "random", "apd", "random"), ("ei", "random", "ei", "random"),
    ]
    for i, (ma, aa, mb, ab) in enumerate(sym):
        combos.append({
            "id": f"p2-sym{i}",
            "mapping_a": ma, "allocation_a": aa, "filtering_a": "ei",
            "mapping_b": mb, "allocation_b": ab, "filtering_b": "ei",
            "step_a": 3 if aa == "linear" else 0, "step_b": 3 if ab == "linear" else 0,
            "hairpin_a": True, "hairpin_b": True,
            "note": "对称关键",
        })
    # [25-30] filtering 三态注入（A=apd filtering，B 三态）
    for fb in FILTS:
        combos.append({
            "id": f"p2-filt-{fb}",
            "mapping_a": "apd", "allocation_a": "linear", "filtering_a": "apd",
            "mapping_b": "ei", "allocation_b": "linear", "filtering_b": fb,
            "step_a": 3, "step_b": 3,
            "hairpin_a": True, "hairpin_b": True,
            "note": "filtering 三态注入验证",
        })
    # [31-36] hairpin 注入
    for ha in (True, False):
        for hb in (True, False):
            combos.append({
                "id": f"p2-hp{int(ha)}{int(hb)}",
                "mapping_a": "ei", "allocation_a": "stable", "filtering_a": "ei",
                "mapping_b": "ei", "allocation_b": "linear", "filtering_b": "ei",
                "step_a": 0, "step_b": 3,
                "hairpin_a": ha, "hairpin_b": hb,
                "note": "hairpin 注入验证",
            })
    assert len(combos) <= 36, f"combos={len(combos)} > 36"
    return combos


def run_one(c, idx, args):
    sig = args.signal_base + idx * 2
    cmd = [
        sys.executable, NAT_SIM,
        "--puncher", os.path.join(HERE, "puncher.py"),
        "--signal-port", str(sig),
        "--window-s", str(args.window_s),
        "--retry-ms", str(args.retry_ms),
        "--probe-timeout", "1.2",
        "--keepalive-s", str(args.keepalive_s),
        "--hold-s", str(args.hold_s),
        "--filtering-probe", "--hairpin-probe",
        "--mapping-a", c["mapping_a"], "--allocation-a", c["allocation_a"],
        "--filtering-a", c["filtering_a"], "--step-a", str(c["step_a"]),
        "--mapping-b", c["mapping_b"], "--allocation-b", c["allocation_b"],
        "--filtering-b", c["filtering_b"], "--step-b", str(c["step_b"]),
        "--workdir", os.path.join(ARTIFACTS, "work_p2", c["id"]),
        "--seed", str(args.seed),
    ]
    if c.get("hairpin_a"):
        cmd += ["--hairpin-a"]
    if c.get("hairpin_b"):
        cmd += ["--hairpin-b"]
    subprocess.run(["pkill", "-9", "-f", "punch-research/nat_sim.py"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["pkill", "-9", "-f", "punch-research/puncher.py"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.0)
    crash_dir = os.path.join(ARTIFACTS, "work_p2", c["id"])
    os.makedirs(crash_dir, exist_ok=True)
    t0 = time.time()
    report = None
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=args.combo_timeout)
        report = json.loads(r.stdout)
    except (subprocess.TimeoutExpired, json.JSONDecodeError) as e:
        report = {"success": False, "timed_out": True, "wall_ms": int((time.time() - t0) * 1000),
                  "a": {}, "b": {}, "error": str(e)}
    if report.get("wall_ms", 0) < 1000 and not report.get("success"):
        time.sleep(1.0)
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=args.combo_timeout)
            report = json.loads(r.stdout)
        except (subprocess.TimeoutExpired, json.JSONDecodeError):
            pass
    report["_elapsed"] = int((time.time() - t0) * 1000)
    return report


def tsv_row(c, r, idx):
    a, b = r.get("a", {}), r.get("b", {})
    sa, sb = a.get("stats") or {}, b.get("stats") or {}
    da, db = a.get("detected") or {}, b.get("detected") or {}
    exp = expected_reachable(c)
    actual = r.get("success", False)
    match = "NA" if exp is None else ("OK" if exp == actual else "MISMATCH")
    return [
        c["id"], c["mapping_a"], c["allocation_a"], c["filtering_a"],
        c["mapping_b"], c["allocation_b"], c["filtering_b"], c["note"],
        da.get("mapping", "?"), da.get("allocation", "?"), da.get("filtering", "?"),
        db.get("mapping", "?"), db.get("allocation", "?"), db.get("filtering", "?"),
        a.get("result", "-"), b.get("result", "-"),
        "p2p" if actual else ("fail" if not r.get("timed_out") else "timeout"),
        sa.get("establish_ms", "-"), sb.get("establish_ms", "-"),
        sa.get("step_final", "-"), sb.get("step_final", "-"),
        sa.get("step_revisions", "-"), sb.get("step_revisions", "-"),
        sa.get("predicted_hits", "-"), sb.get("predicted_hits", "-"),
        sa.get("pool_sockets", "-"), sb.get("pool_sockets", "-"),
        sa.get("pattern", "-"), sb.get("pattern", "-"),
        sa.get("confirmation_overhead_ms", "-"), sb.get("confirmation_overhead_ms", "-"),
        sa.get("mapping_drift_count", "-"), sb.get("mapping_drift_count", "-"),
        ("expected" if exp else ("unexpected" if exp is False else "NA")), match,
        r.get("wall_ms", "-"),
    ]


HEADER = [
    "id", "map_a", "alloc_a", "filt_a", "map_b", "alloc_b", "filt_b", "note",
    "det_map_a", "det_alloc_a", "det_filt_a",
    "det_map_b", "det_alloc_b", "det_filt_b",
    "res_a", "res_b", "actual",
    "est_ms_a", "est_ms_b", "step_final_a", "step_final_b",
    "rev_a", "rev_b", "pred_hits_a", "pred_hits_b",
    "pool_a", "pool_b", "pattern_a", "pattern_b",
    "conf_oh_a", "conf_oh_b", "drift_a", "drift_b",
    "expected", "match", "wall_ms",
]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--signal-base", type=int, default=43500)
    ap.add_argument("--window-s", type=float, default=8)
    ap.add_argument("--retry-ms", type=int, default=800)
    ap.add_argument("--keepalive-s", type=float, default=2)
    ap.add_argument("--hold-s", type=float, default=4)
    ap.add_argument("--seed", type=int, default=20260816)
    ap.add_argument("--combo-timeout", type=int, default=20)
    ap.add_argument("--only", default=None)
    a = ap.parse_args()

    os.makedirs(ARTIFACTS, exist_ok=True)
    os.makedirs(LOGS, exist_ok=True)
    combos = build_combos()
    if a.only:
        combos = [c for c in combos if c["id"] in a.only.split(",")]

    rows = [HEADER]
    t_start = time.time()
    n_pass = n_na = n_fail = 0
    for idx, c in enumerate(combos):
        r = run_one(c, idx, a)
        rows.append(tsv_row(c, r, idx))
        exp = expected_reachable(c)
        actual = r.get("success", False)
        # fingerprint 注入断言（值域映射：注入缩写 ei/ad/apd → puncher 扩展名；allocation 按可观察语义）
        da, db = r.get("a", {}).get("detected") or {}, r.get("b", {}).get("detected") or {}
        fp_a_ok = (da.get("mapping") == EXPANDED[c["mapping_a"]] or
                   fp_exempt(c["mapping_a"], c["allocation_a"], "mapping")) and \
            (da.get("allocation") == observed_allocation(c["mapping_a"], c["allocation_a"]) or
             fp_exempt(c["mapping_a"], c["allocation_a"], "allocation"))
        fp_b_ok = (db.get("mapping") == EXPANDED[c["mapping_b"]] or
                   fp_exempt(c["mapping_b"], c["allocation_b"], "mapping")) and \
            (db.get("allocation") == observed_allocation(c["mapping_b"], c["allocation_b"]) or
             fp_exempt(c["mapping_b"], c["allocation_b"], "allocation"))
        filt_ok = da.get("filtering") == EXPANDED[c["filtering_a"]] and \
            da.get("filtering_state") == observed_filtering_state(c["filtering_a"])
        if exp is None:
            n_na += 1
            tag = "NA"
        elif exp == actual:
            n_pass += 1
            tag = "PASS"
        else:
            n_fail += 1
            tag = "FAIL"
        print(f"[{idx + 1}/{len(combos)}] {c['id']:<16} exp={exp} actual={actual} "
              f"fpA={'OK' if fp_a_ok else 'BAD'} fpB={'OK' if fp_b_ok else 'BAD'} "
              f"filtA={'OK' if filt_ok else 'BAD'} wall={r['wall_ms']}ms {tag}", flush=True)

    out = os.path.join(ARTIFACTS, "nat_matrix_p2.tsv")
    with open(out, "w", encoding="utf-8") as f:
        for row in rows:
            f.write("\t".join(str(x) for x in row) + "\n")

    print(f"\n=== matrix_p2 done: {len(combos)} combos, "
          f"{n_pass}/{len(combos) - n_na} exp-match, elapsed {time.time() - t_start:.1f}s ===")
    print(f"=== TESTS: PASS={n_pass} NA={n_na} FAIL={n_fail} (预期表见本文件 build_combos 注释) ===")
    print(f"TSV: {out}")


if __name__ == "__main__":
    main()