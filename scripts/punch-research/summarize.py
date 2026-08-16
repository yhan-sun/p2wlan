#!/usr/bin/env python3
"""summarize.py — S4 指标与日志汇总

扫描会话 JSON（artifacts/work/*/session_{a,b}.json 或 --sessions 指定目录），输出：
  - artifacts/summary.tsv    每会话一行（S4 字段集）
  - --timeline <json>        单个会话的时间线复盘（att/evt 序列）
  - --fingerprint <json>     NatFingerprint 结构化输出（复用 fingerprint.py）

用法：
  python3 summarize.py                                  # 汇总 artifacts/work/
  python3 summarize.py --sessions artifacts/sessions
  python3 summarize.py --timeline path/to/session_a.json
  python3 summarize.py --fingerprint path/to/session_a.json
"""
import argparse
import glob
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from fingerprint import fingerprint_from_session  # noqa: E402

COLUMNS = [
    "session", "side", "result", "establish_ms", "strategy",
    "predict_hit", "hit_offset", "step_final", "step_revisions",
    "pool_sockets", "budget_split", "confirmation_overhead",
    "mapping_drift_count", "pattern", "firewall",
    "mapping", "allocation", "filtering", "filtering_state", "hairpin",
]


def find_sessions(roots):
    files = []
    for root in roots:
        files += sorted(glob.glob(os.path.join(root, "**", "session_*.json"), recursive=True))
    return files


def row_from_session(path):
    try:
        with open(path, encoding="utf-8") as f:
            s = json.load(f)
    except (OSError, ValueError):
        return None
    st = s.get("stats") or {}
    pr = s.get("profile") or {}
    hm = st.get("hit_metrics") or {}
    return {
        "session": os.path.basename(os.path.dirname(path)),
        "side": s.get("name"),
        "result": s.get("result"),
        "establish_ms": st.get("establish_ms"),
        "strategy": st.get("mode"),
        "predict_hit": st.get("predicted_hits"),
        "hit_offset": hm.get("offset_steps"),
        "step_final": st.get("step_final"),
        "step_revisions": st.get("step_revisions"),
        "pool_sockets": st.get("pool_sockets"),
        "budget_split": json.dumps(st.get("budget_split")) if st.get("budget_split") else None,
        "confirmation_overhead": st.get("confirmation_overhead_ms"),
        "mapping_drift_count": st.get("mapping_drift_count"),
        "pattern": st.get("pattern"),
        "firewall": st.get("firewall"),
        "mapping": pr.get("mapping"),
        "allocation": pr.get("allocation"),
        "filtering": pr.get("filtering"),
        "filtering_state": pr.get("filtering_state"),
        "hairpin": pr.get("hairpin"),
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--sessions", default=None, help="会话 JSON 根目录（默认 artifacts/work）")
    ap.add_argument("--out", default=None, help="TSV 输出路径（默认 artifacts/summary.tsv）")
    ap.add_argument("--timeline", default=None, help="单会话 JSON 时间线复盘")
    ap.add_argument("--fingerprint", default=None, help="单会话 JSON 指纹输出")
    a = ap.parse_args()

    if a.timeline:
        with open(a.timeline, encoding="utf-8") as f:
            s = json.load(f)
        for ev in s.get("events") or []:
            extra = " ".join(f"{k}={v}" for k, v in ev.items() if k not in ("att", "evt"))
            print(f"att=+{ev.get('att'):>6}ms  evt={ev.get('evt'):<18} {extra}")
        return
    if a.fingerprint:
        with open(a.fingerprint, encoding="utf-8") as f:
            s = json.load(f)
        print(json.dumps(fingerprint_from_session(s), indent=2, sort_keys=True))
        return

    roots = [a.sessions] if a.sessions else [os.path.join(HERE, "artifacts", "work")]
    files = find_sessions(roots)
    rows = []
    for f in files:
        r = row_from_session(f)
        if r:
            rows.append(r)
    out_path = a.out or os.path.join(HERE, "artifacts", "summary.tsv")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\t".join(COLUMNS) + "\n")
        for r in rows:
            f.write("\t".join("" if r.get(c) is None else str(r.get(c)) for c in COLUMNS) + "\n")
    ok = sum(1 for r in rows if r["result"] == "p2p")
    print(f"summary: {len(rows)} sessions -> {out_path}  (p2p={ok}/{len(rows)})")


if __name__ == "__main__":
    main()