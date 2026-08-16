#!/usr/bin/env python3
"""live_analyze.py — Gate2 真实网络会话分析

读取 puncher 的 --session-out JSON（或扫描目录），输出：
  - 指纹：mapping/allocation/filtering(三态)/hairpin/confidence + observations 摘要
  - 指标：establish_ms、预测命中、step 学习轨迹、预算拆分、确认开销、漂移
  - 时间线：事件序列（--timeline）
  - 多会话汇总：成功率 / P50 建立时间（对照达标线 ≥95% / ≤1.5s）

用法：
  python3 live_analyze.py --session /tmp/live_a.json
  python3 live_analyze.py --dir /tmp/live/ --timeline
"""
import argparse
import glob
import json
import os
import statistics
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from fingerprint import fingerprint_from_session  # noqa: E402


def summarize(s):
    st = s.get("stats") or {}
    pr = s.get("profile") or {}
    hm = st.get("hit_metrics") or {}
    return {
        "name": s.get("name"),
        "result": s.get("result"),
        "establish_ms": st.get("establish_ms"),
        "mode": st.get("mode"),
        "pattern": st.get("pattern"),
        "step_final": st.get("step_final"),
        "step_revisions": st.get("step_revisions"),
        "predicted_hits": st.get("predicted_hits"),
        "hit_offset": hm.get("offset_steps"),
        "pool_sockets": st.get("pool_sockets"),
        "confirmation_overhead": st.get("confirmation_overhead_ms"),
        "drift": st.get("mapping_drift_count"),
        "mapping": pr.get("mapping"),
        "allocation": pr.get("allocation"),
        "filtering": pr.get("filtering"),
        "filtering_state": pr.get("filtering_state"),
        "hairpin": pr.get("hairpin"),
        "public": pr.get("public"),
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--session", default=None, help="单会话 JSON")
    ap.add_argument("--dir", default=None, help="多会话目录（扫描 session_*.json）")
    ap.add_argument("--timeline", action="store_true", help="打印事件时间线")
    a = ap.parse_args()

    files = []
    if a.session:
        files.append(a.session)
    if a.dir:
        files += sorted(glob.glob(os.path.join(a.dir, "session_*.json")))
    if not files:
        ap.error("需要 --session 或 --dir")

    rows = []
    for f in files:
        with open(f, encoding="utf-8") as fh:
            s = json.load(fh)
        if a.timeline:
            print(f"== {f} ==")
            for ev in s.get("events") or []:
                extra = " ".join(f"{k}={v}" for k, v in ev.items() if k not in ("att", "evt"))
                print(f"  att=+{ev.get('att'):>6}ms  evt={ev.get('evt'):<18} {extra}")
        rows.append((f, s))

    print("\n===== 会话汇总 =====")
    for f, s in rows:
        r = summarize(s)
        print(f"{r['name'] or os.path.basename(f):<10} result={r['result']:<8} "
              f"est={r['establish_ms']}ms mode={r['mode']} pattern={r['pattern']} "
              f"step={r['step_final']} hits={r['predicted_hits']} pool={r['pool_sockets']}")
        print(f"    fp: mapping={r['mapping']} alloc={r['allocation']} "
              f"filtering={r['filtering']}({r['filtering_state']}) hairpin={r['hairpin']} "
              f"public={r['public']}")
    if len(rows) > 1:
        ok = [r[1] for r in rows if (r[1].get("stats") or {}).get("establish_ms") is not None]
        ests = sorted((r[1].get("stats") or {}).get("establish_ms") for r in rows
                      if (r[1].get("stats") or {}).get("establish_ms") is not None)
        sr = len(ok) / len(rows)
        p50 = statistics.median(ests) if ests else None
        print(f"\n===== 达标线对照：成功率 {sr:.0%} (≥95%)；"
              f"P50 建立 {p50}ms (≤1500ms) =====")
        print("PASS" if sr >= 0.95 and (p50 is None or p50 <= 1500) else "FAIL")


if __name__ == "__main__":
    main()