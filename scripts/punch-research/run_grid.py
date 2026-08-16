#!/usr/bin/env python3
"""run_grid.py — S5 超参数网格校准

维度：predict_n∈{8,12,16} × window_w∈{0,1,2,4} × random_m∈{32,64,128} × pool∈{1,3,6}
      × keepalive∈{10,20,40}
主场景：apd-linear × apd-linear（预测主导，最能区分 N/W）
辅助场景：ei × apd-random 子网格（随机主导，区分 M/pool）
每格 5 轮取中位数（keepalive 维度因 hold 时间成本，在代表性格上专项校准）。

输出：
  artifacts/grid_results.tsv       每格一行（成功率/中位建立/中位轮次/探测代价）
  （文本）边际命中率表：按各维度聚合成功率与 P50
  （文本）达标组合：成功率≥95% 且 P50≤1.5s；代价最小者即为推荐

探测代价（cost）：每轮包数 = 2*N*W（窗口，W=0 时 0）+ M（随机）+ 2（主候选），
socket 资源 = pool。代价 = 包数*0.2ms + pool。
"""
import argparse
import json
import os
import statistics
import subprocess
import sys
import time
from concurrent.futures import ProcessPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
NAT_SIM = os.path.join(HERE, "nat_sim.py")
ARTIFACTS = os.path.join(HERE, "artifacts")
GRID_TSV = os.path.join(ARTIFACTS, "grid_results.tsv")

MAIN_SCENE = {"_name": "main", "mapping_a": "apd", "allocation_a": "linear", "filtering_a": "ei", "step_a": 3,
              "mapping_b": "apd", "allocation_b": "linear", "filtering_b": "ei", "step_b": 3}
RAND_SCENE = {"_name": "random", "mapping_a": "ei", "allocation_a": "stable", "filtering_a": "ei", "step_a": 0,
              "mapping_b": "apd", "allocation_b": "random", "filtering_b": "ei", "step_b": 0}

GRID = {
    "predict_n": [8, 12, 16],
    "window_w": [0, 1, 2, 4],
    "random_m": [32, 64, 128],
    "pool": [1, 3, 6],
    "keepalive_s": [10, 20, 40],
}
REPS = 5
REPS_KA = 5      # keepalive 专项轮数
WINDOW_S = 5.0
RETRY_MS = 400
PROBE_TIMEOUT = 0.8
HOLD_S = 2.0
COMBO_TIMEOUT = 20


def probe_cost(predict_n, window_w, random_m, pool):
    window_ports = 2 * predict_n * max(0, window_w)
    packets = window_ports + random_m + 2
    return round(packets * 0.2 + pool, 1)


def _worker_slot():
    """按 worker 划分端口段：同一 worker 内串行（段内无冲突），不同 worker 段互不重叠。
    主进程/测试场景回退 idx%6。"""
    try:
        name = __import__("multiprocessing").current_process().name
        n = "".join(ch for ch in name if ch.isdigit())
        if n:
            return int(n) - 1
    except Exception:
        pass
    return None


def run_one(args):
    scene, params, idx, seed_base = args
    n, w, m, pool, ka = (params["predict_n"], params["window_w"], params["random_m"],
                         params["pool"], params["keepalive_s"])
    slot = _worker_slot()
    if slot is None:
        slot = idx % 6
    slot = max(0, min(slot, 5))
    workdir = os.path.join(ARTIFACTS, "grid_work", f"run_{idx}")
    os.makedirs(workdir, exist_ok=True)
    # 段间隔 4000 > priv 段长 512 + pub 段长 800 + observer 余量，段间零重叠；
    # signal 独立段 44000+，与 priv/pub 全错开。
    sig = 44000 + slot * 500
    priv_a = 20000 + slot * 4000
    priv_b = priv_a + 2000
    pub_a = 30000 + slot * 4000
    pub_b = pub_a + 2000
    hold = HOLD_S
    if scene == "ka":
        hold = 6.0     # keepalive 专项：固定 6s（含 ka=10 的 1+ 次保活发送；ka 影响仅在建立阶段之外）
    cmd = [
        sys.executable, NAT_SIM,
        "--puncher", os.path.join(HERE, "puncher.py"),
        "--signal-port", str(sig),
        "--priv-a", str(priv_a), "--priv-b", str(priv_b),
        "--pub-a", str(pub_a), "--pub-b", str(pub_b),
        "--window-s", str(WINDOW_S), "--retry-ms", str(RETRY_MS),
        "--probe-timeout", str(PROBE_TIMEOUT),
        "--keepalive-s", str(ka), "--hold-s", str(hold),
        "--filtering-probe",
        "--mapping-a", scene["mapping_a"], "--allocation-a", scene["allocation_a"],
        "--filtering-a", scene["filtering_a"], "--step-a", str(scene["step_a"]),
        "--mapping-b", scene["mapping_b"], "--allocation-b", scene["allocation_b"],
        "--filtering-b", scene["filtering_b"], "--step-b", str(scene["step_b"]),
        "--predict-n", str(n), "--window-w", str(w), "--random-m", str(m),
        "--pool", str(pool), "--seed", str(seed_base + idx),
        "--workdir", workdir,
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=COMBO_TIMEOUT)
        report = json.loads(r.stdout)
    except (subprocess.TimeoutExpired, json.JSONDecodeError, ValueError):
        report = {"success": False}
    if not report.get("success"):
        time.sleep(1.0)
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=COMBO_TIMEOUT)
            report = json.loads(r.stdout)
        except (subprocess.TimeoutExpired, json.JSONDecodeError, ValueError):
            report = {"success": False}
    a = report.get("a", {}).get("stats") or {}
    b = report.get("b", {}).get("stats") or {}
    return {
        "scene": scene.get("_name", "main"), "predict_n": n, "window_w": w,
        "random_m": m, "pool": pool, "keepalive_s": ka,
        "success": bool(report.get("success")),
        "establish_ms": a.get("establish_ms") or b.get("establish_ms"),
        "epoch": a.get("epoch") or b.get("epoch"),
    }


def build_tasks():
    tasks = []
    idx = 0
    for n in GRID["predict_n"]:
        for w in GRID["window_w"]:
            for m in GRID["random_m"]:
                for pool in GRID["pool"]:
                    params = {"predict_n": n, "window_w": w, "random_m": m,
                              "pool": pool, "keepalive_s": 10}
                    for _ in range(REPS):
                        tasks.append((MAIN_SCENE, params, idx, 20260816))
                        idx += 1
    # 辅助场景：随机主导（M/pool 维度，N/W 固定 8/2）
    for m in GRID["random_m"]:
        for pool in GRID["pool"]:
            params = {"predict_n": 8, "window_w": 2, "random_m": m,
                      "pool": pool, "keepalive_s": 10}
            for _ in range(REPS):
                tasks.append((RAND_SCENE, params, idx, 20260816))
                idx += 1
    # keepalive 专项：代表性格 (8,2,64,3)
    ka_scene = dict(MAIN_SCENE)
    ka_scene["_name"] = "ka"
    for ka in GRID["keepalive_s"]:
        params = {"predict_n": 8, "window_w": 2, "random_m": 64,
                  "pool": 3, "keepalive_s": ka}
        for _ in range(REPS_KA):
            tasks.append((ka_scene, params, idx, 20260816))
            idx += 1
    return tasks


def aggregate(rows):
    """按 (scene, n, w, m, pool, ka) 聚合：成功率 + 中位数建立时间 + 中位轮次。"""
    groups = {}
    for r in rows:
        key = (r["scene"], r["predict_n"], r["window_w"], r["random_m"], r["pool"], r["keepalive_s"])
        groups.setdefault(key, []).append(r)
    out = []
    for key, rs in groups.items():
        ok = [r for r in rs if r["success"]]
        est = [r["establish_ms"] for r in ok if r.get("establish_ms") is not None]
        epoch = [r["epoch"] for r in ok if r.get("epoch") is not None]
        out.append({
            "scene": key[0], "predict_n": key[1], "window_w": key[2],
            "random_m": key[3], "pool": key[4], "keepalive_s": key[5],
            "success_rate": len(ok) / len(rs),
            "median_est_ms": statistics.median(est) if est else None,
            "median_epoch": statistics.median(epoch) if epoch else None,
            "rounds": len(rs),
            "cost": probe_cost(key[1], key[2], key[3], key[4]),
        })
    return out


def marginal(agg, dim, scene="main"):
    """按维度聚合边际（其余维度平均）：返回 (dim_value, success_rate, median_est)。"""
    rows = [a for a in agg if a["scene"] == scene]
    by_dim = {}
    for a in rows:
        v = a[dim]
        by_dim.setdefault(v, []).append(a)
    out = []
    for v, rs in sorted(by_dim.items()):
        sr = statistics.mean(r["success_rate"] for r in rs)
        ests = [r["median_est_ms"] for r in rs if r["median_est_ms"] is not None]
        out.append((v, sr, statistics.median(ests) if ests else None))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--parallel", type=int, default=6, help="并行 worker 数")
    ap.add_argument("--dry-run", action="store_true", help="只打印任务清单与预计耗时")
    a = ap.parse_args()

    tasks = build_tasks()
    if a.dry_run:
        print(f"tasks: {len(tasks)}  (main {sum(1 for t in tasks if t[0] is MAIN_SCENE)}"
              f" + random {sum(1 for t in tasks if t[0] is RAND_SCENE)}"
              f" + keepalive {sum(1 for t in tasks if t[0].get('_name') == 'ka')})")
        est = len(tasks) * 7.0 / a.parallel
        print(f"est wall: {est / 60:.1f} min @ {a.parallel} workers (7s/run 估计)")
        return

    t0 = time.time()
    rows = []
    with ProcessPoolExecutor(max_workers=a.parallel) as ex:
        for i, r in enumerate(ex.map(run_one, tasks, chunksize=1), start=1):
            rows.append(r)
            if i % 50 == 0:
                print(f"  {i}/{len(tasks)}  ({time.time() - t0:.0f}s)", flush=True)

    agg = aggregate(rows)
    os.makedirs(ARTIFACTS, exist_ok=True)
    with open(GRID_TSV, "w", encoding="utf-8") as f:
        f.write("scene\tpredict_n\twindow_w\trandom_m\tpool\tkeepalive_s\t"
                "success_rate\tmedian_est_ms\tmedian_epoch\trounds\tcost\n")
        for x in agg:
            f.write(f"{x['scene']}\t{x['predict_n']}\t{x['window_w']}\t{x['random_m']}\t"
                    f"{x['pool']}\t{x['keepalive_s']}\t{x['success_rate']:.2f}\t"
                    f"{x['median_est_ms']}\t{x['median_epoch']}\t{x['rounds']}\t{x['cost']}\n")

    print("\n===== 边际命中率（主场景 apd-linear×apd-linear） =====")
    for dim in ("predict_n", "window_w", "random_m", "pool"):
        print(f"  {dim:>10}: " + "  ".join(f"{v}: {sr:.0%}/P50={est or '-'}ms"
              for v, sr, est in marginal(agg, dim)))
    print("\n===== 辅助场景（ei × apd-random） =====")
    for dim in ("random_m", "pool"):
        print(f"  {dim:>10}: " + "  ".join(f"{v}: {sr:.0%}/P50={est or '-'}ms"
              for v, sr, est in marginal(agg, dim, scene=RAND_SCENE)))
    print("\n===== keepalive 专项 =====")
    for x in [x for x in agg if x["scene"] == "ka"]:
        print(f"  ka={x['keepalive_s']:>2}s: {x['success_rate']:.0%} P50={x['median_est_ms']}ms")

    # 达标组合 + 代价最小
    qualified = [x for x in agg if x["scene"] == "main" and x["success_rate"] >= 0.95
                 and x["median_est_ms"] is not None and x["median_est_ms"] <= 1500]
    print("\n===== 达标组合（成功率≥95% 且 P50≤1.5s） =====")
    if not qualified:
        print("  无达标组合！需检查场景/参数域")
    else:
        best = min(qualified, key=lambda x: x["cost"])
        for x in sorted(qualified, key=lambda x: x["cost"])[:10]:
            print(f"  N={x['predict_n']} W={x['window_w']} M={x['random_m']} "
                  f"pool={x['pool']} : {x['success_rate']:.0%} P50={x['median_est_ms']}ms "
                  f"cost={x['cost']}")
        print(f"\n>>> 推荐组合: N={best['predict_n']} W={best['window_w']} "
              f"M={best['random_m']} pool={best['pool']} (cost={best['cost']})")
    print(f"\nelapsed: {time.time() - t0:.0f}s  ->  {GRID_TSV}")


if __name__ == "__main__":
    main()