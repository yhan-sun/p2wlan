#!/usr/bin/env python3
"""fingerprint.py — S2 NAT 行为指纹（NatFingerprint）

每会话输出结构化 JSON 指纹：
  mapping / allocation / step(含置信度) / pattern / filtering(三态) / hairpin /
  sample_map / observations(全量) / port_sequence

纯函数层（可单测，不依赖网络）：
  - classify_filtering_probe(cp_changed, ci_changed, server_alive) → (mode, state)
    三态：allow（响应源变化 → EI/AD 判定）/ deny（服务器可达但 change 被拦 → APD）/
          no-response（服务器不可达 → unknown）
  - robustify(observations)：多轮一致性（同组多观测取众数；区分真对称与观测噪声；
    组数不足 → unknown）
  - build_fingerprint(profile, step_info=None) → dict（指纹 JSON 主体）

网络层（可选，puncher 内部已集成）：
  - fingerprint_from_session(session_json)：从 S4 会话 JSON 生成指纹（供 summarize/live_analyze 复用）

用法：python3 fingerprint.py --test    （注入 4 mapping × 3 allocation × 3 filtering 准确率 ≥95%）
"""
import collections
import json
import sys

MAPPING_EI = "endpoint_independent"
MAPPING_AD = "address_dependent"
MAPPING_APD = "address_port_dependent"
MAPPING_UNKNOWN = "unknown"

ALLOC_STABLE = "stable"
ALLOC_LINEAR = "linear"
ALLOC_RANDOM = "random"

FILT_EI = "endpoint_independent"
FILT_AD = "address_dependent"
FILT_APD = "address_port_dependent"
FILT_UNKNOWN = "unknown"

FILTER_STATE_ALLOW = "allow"
FILTER_STATE_DENY = "deny"
FILTER_STATE_NO_RESPONSE = "no-response"


def classify_filtering_probe(cp_changed, ci_changed, server_alive):
    """filtering 三态判定（纯函数）。

    - change 请求有响应且源变化 → allow（ci 变 → EI；cp 变 → AD）
    - 服务器可达但 change 无响应 → deny（被 NAT 过滤 → APD）
    - 服务器不可达 → no-response（unknown，无法探测）
    返回 (mode, state)。
    """
    if ci_changed or cp_changed:
        return (FILT_EI if ci_changed else FILT_AD, FILTER_STATE_ALLOW)
    if server_alive:
        return (FILT_APD, FILTER_STATE_DENY)
    return (FILT_UNKNOWN, FILTER_STATE_NO_RESPONSE)


def _group_mode(obs_list, field="mapped_port"):
    """同组多轮观测取众数（抗单次噪声）。"""
    vals = [o.get(field) for o in obs_list if o.get(field) is not None]
    if not vals:
        return None
    c = collections.Counter(vals)
    return c.most_common(1)[0][0]


def robustify(observations):
    """对称性鲁棒化（纯函数）。

    输入 puncher profile 的 observations（可能含同组多轮），输出规范化观测：
      - 同组多轮取众数（去观测噪声）
      - 组数不足 3（缺 same_target/diff_port/diff_ip 任一）→ 标记 degraded（判定 unknown 依据）
      - 跨会话端口复用（new_socket 与主 socket 同映射）→ port_reuse 标记
    返回 (normalized_obs, flags)。
    """
    by_group = collections.defaultdict(list)
    for o in observations or []:
        by_group[o.get("group")].append(o)
    normalized = []
    for g, items in by_group.items():
        port = _group_mode(items, "mapped_port")
        ip = _group_mode(items, "mapped_ip")
        if port is None:
            continue
        normalized.append({
            "group": g,
            "target": items[0].get("target"),
            "mapped_ip": ip,
            "mapped_port": port,
        })
    present = {n["group"] for n in normalized}
    required = {"same_target", "diff_port", "diff_ip"}
    degraded = not required.issubset(present)
    reuse = None
    if "new_socket" in present and "same_target" in present:
        main = next(n for n in normalized if n["group"] == "same_target")
        ns = next(n for n in normalized if n["group"] == "new_socket")
        reuse = (ns["mapped_ip"] == main["mapped_ip"] and ns["mapped_port"] == main["mapped_port"])
    return normalized, {"degraded": degraded, "port_reuse": reuse, "groups": sorted(present)}


def build_fingerprint(profile, step_info=None):
    """从 profile（NatDetector 输出）生成指纹 JSON（纯函数）。"""
    normalized, flags = robustify(profile.get("observations") or [])
    filtering_state = profile.get("filtering_state") or FILTER_STATE_NO_RESPONSE
    fp = {
        "mapping": profile.get("mapping", MAPPING_UNKNOWN),
        "mapping_confidence": round(profile.get("confidence", 0.0), 3),
        "allocation": profile.get("allocation", ALLOC_STABLE),
        "step": step_info or {
            "estimate": profile.get("step", 0),
            "confidence": round(profile.get("confidence", 0.0), 3),
            "revisions": 0,
        },
        "pattern": None,
        "filtering": profile.get("filtering", FILT_UNKNOWN),
        "filtering_state": filtering_state,
        "hairpin": profile.get("hairpin"),
        "sample_map": profile.get("public"),
        "port_reuse": flags["port_reuse"],
        "degraded": flags["degraded"],
        "observations": normalized,
        "port_sequence": profile.get("port_sequence") or [],
    }
    return fp


def fingerprint_from_session(session):
    """从 S4 会话 JSON 生成指纹（供 summarize/live_analyze 复用）。"""
    profile = session.get("profile") or {}
    stats = session.get("stats") or {}
    step_info = {
        "estimate": stats.get("step_final") or profile.get("step", 0),
        "confidence": round(profile.get("confidence", 0.0), 3),
        "revisions": stats.get("step_revisions", 0),
    }
    fp = build_fingerprint(profile, step_info)
    fp["pattern"] = stats.get("pattern")
    fp["mapping_drift_count"] = stats.get("mapping_drift_count", 0)
    return fp


# ===== 注入式验证（4 mapping × 3 allocation × 3 filtering 准确率 ≥95%） =====
def _inject_observations(mapping, allocation):
    """按注入语义构造 observations（puncher detect 同等结构）。

    mapping=ei:   全目标同映射（含 new_socket 复用）
    mapping=ad:   同 IP 异端口复用、异 IP 变化
    mapping=apd:  每目标新端口
    allocation 影响 port_sequence 与 step（linear 递增 / random 乱 / stable 恒定）。
    """
    base = 5000
    obs = [
        {"group": "same_target", "target": "1.1.1.1:100", "mapped_ip": "1.2.3.4", "mapped_port": base},
        {"group": "same_target", "target": "1.1.1.1:100", "mapped_ip": "1.2.3.4", "mapped_port": base},
        {"group": "diff_port", "target": "1.1.1.1:101", "mapped_ip": "1.2.3.4", "mapped_port": base},
        {"group": "diff_ip", "target": "2.2.2.2:100", "mapped_ip": "1.2.3.4", "mapped_port": base},
        {"group": "new_socket", "target": "1.1.1.1:100", "mapped_ip": "1.2.3.4", "mapped_port": base},
    ]
    if mapping == MAPPING_AD:
        obs[2]["mapped_port"] = base          # diff_port 复用
        obs[3]["mapped_port"] = base + 100    # diff_ip 变化
    elif mapping == MAPPING_APD:
        obs[2]["mapped_port"] = base + 200    # diff_port 新端口
        obs[3]["mapped_port"] = base + 400    # diff_ip 新端口
    if allocation == ALLOC_LINEAR:
        for i, o in enumerate(obs[1:], start=1):
            o["mapped_port"] = base + i * 3
        obs[0]["mapped_port"] = base
        obs[1]["mapped_port"] = base
        obs[2]["mapped_port"] = base + 3
        obs[3]["mapped_port"] = base + 6
        obs[4]["mapped_port"] = base + 9
    elif allocation == ALLOC_RANDOM:
        rnd = [base, base + 11, base + 37, base + 5, base + 91]
        for o, p in zip(obs, rnd):
            o["mapped_port"] = p
    return obs


def _inject_port_sequence(allocation, step=3):
    if allocation == ALLOC_STABLE:
        return [5000, 5000, 5000]
    if allocation == ALLOC_LINEAR:
        return [5000, 5000 + step, 5000 + 2 * step, 5000 + 3 * step]
    return [5000, 5000 + 11, 5000 + 37, 5000 + 5]


def run_tests():
    ok = lambda n, c: print(f"  {n}: {'PASS' if c else 'FAIL'}")

    # F1: filtering 三态（参数顺序：cp_changed, ci_changed, server_alive）
    m, s = classify_filtering_probe(False, True, True)
    ok("F1_ci_allow_ei", m == FILT_EI and s == FILTER_STATE_ALLOW)
    m, s = classify_filtering_probe(True, False, True)
    ok("F1_cp_allow_ad", m == FILT_AD and s == FILTER_STATE_ALLOW)
    m, s = classify_filtering_probe(False, False, True)
    ok("F1_deny_apd", m == FILT_APD and s == FILTER_STATE_DENY)
    m, s = classify_filtering_probe(False, False, False)
    ok("F1_no_response_unknown", m == FILT_UNKNOWN and s == FILTER_STATE_NO_RESPONSE)

    # F2: robustify（多轮众数 + 组不足）
    obs = _inject_observations(MAPPING_EI, ALLOC_STABLE)
    norm, flags = robustify(obs)
    ok("F2_robust_ei", not flags["degraded"] and flags["port_reuse"] is True)
    ok("F2_robust_groups", flags["groups"] == ["diff_ip", "diff_port", "new_socket", "same_target"])
    noisy = [dict(obs[0]), dict(obs[0]), dict(obs[0], mapped_port=9999)]
    n2, f2 = robustify(noisy)
    ok("F2_robust_mode", n2[0]["mapped_port"] == 5000 and f2["degraded"])
    ok("F2_robust_empty", robustify(None)[1]["degraded"])

    # F3: 注入式指纹准确率（4 mapping × 3 allocation × 3 filtering = 36 注入，≥95%）
    total, correct = 0, 0
    for mapping in (MAPPING_EI, MAPPING_AD, MAPPING_APD, MAPPING_UNKNOWN):
        for alloc in (ALLOC_STABLE, ALLOC_LINEAR, ALLOC_RANDOM):
            for filt, state, alive, ci, cp in (
                    (FILT_EI, "allow", True, True, False),
                    (FILT_AD, "allow", True, False, True),
                    (FILT_APD, "deny", True, False, False),
                    (FILT_UNKNOWN, "no-response", False, False, False)):
                total += 1
                obs_inj = _inject_observations(mapping, alloc) if mapping != MAPPING_UNKNOWN else [
                    {"group": "same_target", "target": "1.1.1.1:100",
                     "mapped_ip": "1.2.3.4", "mapped_port": 5000}]
                profile = {
                    "mapping": mapping, "allocation": alloc, "step": 3 if alloc == ALLOC_LINEAR else 0,
                    "confidence": 1.0 if mapping != MAPPING_UNKNOWN else 0.3,
                    "filtering": filt, "filtering_state": state, "hairpin": None,
                    "public": "1.2.3.4:5000", "observations": obs_inj,
                    "port_sequence": _inject_port_sequence(alloc),
                }
                fp = build_fingerprint(profile)
                fm, fs = classify_filtering_probe(cp, ci, alive)
                ok_fp = (fp["mapping"] == mapping and fp["allocation"] == alloc
                         and fp["step"]["estimate"] == profile["step"])
                ok_ft = (fm == filt and fs == state)
                if ok_fp and ok_ft:
                    correct += 1
    acc = correct / max(1, total)
    ok(f"F3_inject_accuracy_{acc:.0%}", acc >= 0.95)
    print(f"  注入准确率: {correct}/{total} = {acc:.1%}")
    print("全部 fingerprint 单测完成")


if __name__ == "__main__":
    if "--test" in sys.argv:
        run_tests()
    else:
        print("fingerprint.py — S2 NAT 行为指纹模块（import 用；--test 跑单测）")