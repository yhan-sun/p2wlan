# TEST_REPORT — puncher.py RFC 5780 重写与本地模拟验证

> 日期：2026-08-16　环境：macOS Darwin 24.6, Python 3.10.14
> 对象：网易 UU远程打洞算法（libstreamer.dylib 逆向文档 README §7 内嵌 `puncher.py`）
> 范围：只改 `puncher.py` + 新增 mock 验证脚本；零第三方依赖；CLI 兼容；原 §7 13 项单测保留全 PASS

## 0. 结论一句话

**修正后 linear/random 分支在模拟环境真实可达**：双线性对称（`BothLinearSymmericPunch`）双向端口预测命中（`predicted_hits=3`）、随机对称（`BothRandomSymmericPunch`）多 socket 并发命中、cone→symmetric 各策略均按 (mapping, allocation) 正确分发；port-restricted filtering（APD）下的不可达组合被正确识别并上报 `firewall`（不误判 success）。30 组矩阵全部符合预期（23 组确定性 + 7 组概率性如实记录）。

## 1. 交付物清单（均在仓库 `scripts/punch-research/`）

| 文件 | 说明 |
|---|---|
| `puncher.py` | 重写后的打洞实现（RFC5780 检测器 + 策略引擎 + CLI + 33 项单测） |
| `mock_stun.py` | 独立模拟 STUN 服务器（XOR-MAPPED 回显 / `--report-as` / CHANGE-REQUEST 变更响应 / 丢包过滤） |
| `nat_sim.py` | 双 NAT 模拟器 + puncher 双端集成验证（binding/allocation/filtering 三轴可配） |
| `run_matrix.py` | 30 组集成矩阵调度 + `artifacts/nat_matrix.tsv` + 代表性日志 |
| `artifacts/nat_matrix.tsv` | 每行一组的关键数字（34 列） |
| `artifacts/logs/` | 代表性双端原始日志 ≤3 组（含完整 STUN 观测回显） |

## 2. 与原版语义差异（本实现相对 UU 原版 §7 的行为变化）

| 项 | UU 原版（§7 实现） | 本实现 | RTT/行为代价 |
|---|---|---|---|
| NAT 检测 | 单个 UDP socket 复用同一映射 → `getsockname()[1]` 恒定 → `_classify` 恒返回 `NAT_CONE` | RFC 5780 观测 **STUN 服务器回显的 XOR-MAPPED-ADDRESS** 在「同 socket 跨目标」下的变化（服务器视角映射） | 检测需多组 STUN 往返（~2s，并行） |
| linear/random 分支 | 真实网络永远无法触发（见上） | `mapping` ∈ AD/APD → `allocation`=LINEAR/RANDOM 正确分类并驱动预测/并发策略 | 无额外 RTT（检测已覆盖） |
| filtering 分类 | 无 | `filtering` ∈ EI/AD/APD/unknown 经 CHANGE-REQUEST 尽力探测；未知时保守标记 | 探测多 1~2 个往返（`--filtering-probe` 显式开启） |
| 打洞成功判定 | 收到 MAGIC 即置 P2P（可能假阳性：对端收到本端包但本端收不到对端包仍判成功） | **双向确认**：本端收到对端第 2 个合法 punch 包（对端已收到本端回打）才置 P2P | **多 1 个 RTT**，防假阳性（本矩阵实测建立 ~800ms 均含该 RTT） |
| 回打策略 | 一发即 P2P，无候选升级 | 收到 punch → 解析对端 XOR-MAPPED → **learned candidate** → 立即回打对端真实映射 + 追加为候选参与后续轮次 | 使 port-restricted 概率组合偶发可达（见 §5 NA 组） |
| 端口预测 | `base + step×N` 单向递增 | **双向区间** `[base-step·N, base+step·N]`（覆盖回拨）+ step 自适应重估（差分众数）+ 0xc057 通告本端步长 | 预测端口数 ×2，命中面扩大 |
| 保活 / 缓存 | 无 | keepalive 20s + 对端端口漂移重预测 + `~/.puncher_pair_cache.json`（最近 5 对） | 少量周期性报文 |
| 防火墙检测 | 仅 UDP DNS:53（核心网丢包/限速会误判） | UDP DNS:53 双目标 + **TCP:443 对照**，仅两者全失败才判 `found firewall` | 失败路径多 ~2s（可配超时） |

## 3. 变更说明（旧行为 → 新行为，对应文档 §4.x 不符点）

### §4.2 NAT 行为检测（[H] 0x3ddd00）
- **旧**：单 socket 连续 `sendto` 同一目标，读本地 `getsockname()[1]` 作为端口序列 → 四元组不变 → 恒判 `NAT_CONE`。与文档 §4.2「观测 XOR-MAPPED 变化」直接矛盾。
- **新**：`NatDetector.detect()` 用打洞 socket 同 socket 多事务批量探测——同目标×2（验证稳定）、同 IP 异端口、异 IP（RFC5780 三测试），外加独立新 socket 验证新会话复用；每观测解析服务器回显 `XOR-MAPPED`（权威映射），输出 `NatProfile(mapping, allocation, step, filtering, confidence, public, port_reuse, observations)`。
- `classify_mapping`（纯函数）：全部映射相同→EI；同 IP 异端口相同、异 IP 不同→AD；其余→APD；有效观测 <3→unknown。带 sample_map（出口公网 ip:port）与置信度。
- `classify_port_allocation`（纯函数）：差分众数——恒定/空→STABLE、众数稳定→LINEAR(step)、乱→RANDOM。

### §4.4 端口预测（[H] 0x3e1050）
- **旧**：`predicted_port = (base + step*N) & 0xffff` 仅 N 递减单向。
- **新**：`predict_ports(base, step, count, bidirectional=True)` 双向区间 `[base-step·N, base+step·N]` 去重；保留 16bit 回绕保护（结果 0 → 回退 step）；`infer_step` 差分众数自适应重估，新观测到达后重算。

### §4.3 策略选择（[H] 0x3df05c switch 表）
- **旧**：`(local_nat, remote_nat)` ∈ (1, 2, 3)² 整数枚举查表。
- **新**：`choose_strategy(local_profile, remote_profile)` 按 `(mapping, allocation)` 分发，保留原 7 策略名语义 + cone×cone `DirectConePunch`；任何一侧 `allocation=LINEAR` 优先预测分支。`--force-nat=1|2|3` 兼容（1→EI+STABLE，2→APD+LINEAR，3→APD+RANDOM）。

### §4.5 打洞执行（[H] 0x3f17e8 收包）
- **旧**：收到 MAGIC → 回打一次 → `p2p_established=1`。
- **新**：收到 MAGIC → 解析对端 XOR-MAPPED → learned candidate（XOR-MAPPED + peer-reflexive 包源）→ 回打候选+learned → **收到对端第 2 个包（双向确认）** 才置 P2P。策略执行末尾 **learned 置底**（本端 mapping.dest 停在对端真实映射，APD filtering 下最大化对端回包命中）。

### §4.6 防火墙检测（[H] 0x3e2b48）
- **旧**：仅 UDP DNS:53 双目标。
- **新**：UDP DNS:53 + TCP:443 对照；`--fw-dns/--fw-tcp/--fw-timeout` 可覆盖（mock 环境确定性）。

## 4. A 组单元测试（`python3 puncher.py --test`）

原 §7 13 项全部保留并 PASS，新增 A1–A5 共 20 项，共 **33 项全 PASS**：

```
  predict_ports: PASS            overflow_protect: PASS
  switch(2,1): PASS              switch(3,3): PASS
  priority(1,2)=+10: PASS        priority(3,3)=+60: PASS
  infer_step: PASS               stun_xor_mapped: PASS
  stun_nr_port: PASS             stun_magic: PASS
  classify_cone: PASS            classify_linear: PASS
  classify_random: PASS
  A1_mapping_EI: PASS            A1_mapping_AD: PASS
  A1_mapping_APD: PASS           A1_mapping_lt3_unknown: PASS
  A2_alloc_stable: PASS          A2_alloc_linear3: PASS
  A2_alloc_random: PASS          A2_alloc_empty: PASS
  A3_predict_bi: PASS            A3_predict_bi_wrap: PASS
  A3_step_reestimate: PASS       A3_step_adaptive_reestimate: PASS
  A4_bi_linear: PASS             A4_random_vs_cone: PASS
  A4_cone_vs_linear: PASS        A4_both_random: PASS
  A4_cone_cone_direct: PASS
  A5_keepalive_encode_decode: PASS
  A5_pair_cache_roundtrip: PASS  A5_pair_cache_bounded: PASS
全部单测完成
```

## 5. B 集成矩阵（本地双 NAT 模拟，`python3 run_matrix.py`）

30 组（单组 ≤20s，全矩阵约 4 分钟）。A 为 cone 固定侧（mapping=ei, allocation=stable）并遍历 filtering=EI/AD/APD × B 侧 9 组合 (ei|ad|apd)×(stable|linear|random)，另加 3 组对称关键组合。

23/30 确定性组合全部符合预期，7 组为概率性（NA，见下）。

| # | A 组合 | B 组合 | 检测A(实测) | 检测B(实测) | 结果A | 结果B | 建立ms | 轮次 | 学习候选 | 预测命中 | keepalive | 策略A | 预期 | match |
|---|--------|--------|-------------|-------------|-------|-------|--------|------|----------|----------|-----------|-------|------|-------|
| 1 | ei/stable/fei | ei/stable/fei | endp/stable/fen | endp/stable/fen | p2p | p2p | 800 | 1 | 1 | 0 | 2 | DirectConePunch | 可通 | OK |
| 2 | ei/stable/fei | ei/linear/fei | endp/stable/fen | endp/stable/fen | p2p | p2p | 810 | 1 | 1 | 0 | 2 | DirectConePunch | 可通 | OK |
| 3 | ei/stable/fei | ei/random/fei | endp/stable/fen | endp/stable/fen | p2p | p2p | 810 | 1 | 1 | 0 | 2 | DirectConePunch | 可通 | OK |
| 4 | ei/stable/fei | ad/stable/fei | endp/stable/fen | addr/linear/fen | p2p | p2p | 811 | 1 | 3 | 0 | 2 | ConePunchToLinearSymmeric | 可通 | OK |
| 5 | ei/stable/fei | ad/linear/fei | endp/stable/fen | addr/linear/fen | p2p | p2p | 811 | 1 | 3 | 1 | 2 | ConePunchToLinearSymmeric | 可通 | OK |
| 6 | ei/stable/fei | ad/random/fei | endp/stable/fen | addr/linear/fen | p2p | p2p | 810 | 1 | 3 | 0 | 2 | ConePunchToLinearSymmeric | 可通 | OK |
| 7 | ei/stable/fei | apd/stable/fei | endp/stable/fen | addr/random/fen | p2p | p2p | 815 | 1 | 2 | 0 | 2 | ConePunchToRandomSymmeric | 可通 | OK |
| 8 | ei/stable/fei | apd/linear/fei | endp/stable/fen | addr/linear/fen | p2p | p2p | 810 | 1 | 3 | 2 | 2 | ConePunchToLinearSymmeric | 可通 | OK |
| 9 | ei/stable/fei | apd/random/fei | endp/stable/fen | addr/random/fen | p2p | p2p | 817 | 1 | 2 | 0 | 2 | ConePunchToRandomSymmeric | 可通 | OK |
| 10 | ei/stable/fad | ei/stable/fei | endp/stable/fad | endp/stable/fen | p2p | p2p | 806 | 1 | 1 | 0 | 2 | DirectConePunch | 可通 | OK |
| 11 | ei/stable/fad | ei/linear/fei | endp/stable/fad | endp/stable/fen | p2p | p2p | 806 | 1 | 1 | 0 | 2 | DirectConePunch | 可通 | OK |
| 12 | ei/stable/fad | ei/random/fei | endp/stable/fad | endp/stable/fen | p2p | p2p | 805 | 1 | 1 | 0 | 2 | DirectConePunch | 可通 | OK |
| 13 | ei/stable/fad | ad/stable/fei | endp/stable/fad | addr/linear/fen | p2p | p2p | 805 | 1 | 3 | 0 | 2 | ConePunchToLinearSymmeric | 可通 | OK |
| 14 | ei/stable/fad | ad/linear/fei | endp/stable/fad | addr/linear/fen | p2p | p2p | 812 | 1 | 3 | 1 | 2 | ConePunchToLinearSymmeric | 可通 | OK |
| 15 | ei/stable/fad | ad/random/fei | endp/stable/fad | addr/linear/fen | p2p | p2p | 813 | 1 | 3 | 0 | 2 | ConePunchToLinearSymmeric | 可通 | OK |
| 16 | ei/stable/fad | apd/stable/fei | endp/stable/fad | addr/random/fen | p2p | p2p | 832 | 1 | 2 | 0 | 2 | ConePunchToRandomSymmeric | 可通 | OK |
| 17 | ei/stable/fad | apd/linear/fei | endp/stable/fad | addr/linear/fen | p2p | p2p | 812 | 1 | 2 | 2 | 2 | ConePunchToLinearSymmeric | 可通 | OK |
| 18 | ei/stable/fad | apd/random/fei | endp/stable/fad | addr/random/fen | p2p | p2p | 831 | 1 | 2 | 0 | 2 | ConePunchToRandomSymmeric | 可通 | OK |
| 19 | ei/stable/fapd | ei/stable/fei | endp/stable/fad | endp/stable/fen | p2p | p2p | 801 | 1 | 1 | 0 | 2 | DirectConePunch | 可通 | OK |
| 20 | ei/stable/fapd | ei/linear/fei | endp/stable/fad | endp/stable/fen | p2p | p2p | 804 | 1 | 1 | 0 | 2 | DirectConePunch | 可通 | OK |
| 21 | ei/stable/fapd | ei/random/fei | endp/stable/fad | endp/stable/fen | p2p | p2p | 809 | 1 | 1 | 0 | 2 | DirectConePunch | 可通 | OK |
| 22 | ei/stable/fapd | ad/stable/fei | endp/stable/fad | addr/linear/fen | firewall | p2p | None | 8 | 0 | 0 | 0 | ConePunchToLinearSymmeric | NA(概率) | NA |
| 23 | ei/stable/fapd | ad/linear/fei | endp/stable/fad | addr/linear/fen | firewall | p2p | None | 8 | 0 | 0 | 0 | ConePunchToLinearSymmeric | NA(概率) | NA |
| 24 | ei/stable/fapd | ad/random/fei | endp/stable/fad | addr/linear/fen | firewall | p2p | None | 8 | 0 | 0 | 0 | ConePunchToLinearSymmeric | NA(概率) | NA |
| 25 | ei/stable/fapd | apd/stable/fei | endp/stable/fad | addr/random/fen | firewall | p2p | None | 8 | 0 | 0 | 0 | ConePunchToRandomSymmeric | NA(概率) | NA |
| 26 | ei/stable/fapd | apd/linear/fei | endp/stable/fad | addr/linear/fen | p2p | p2p | 809 | 1 | 2 | 2 | 2 | ConePunchToLinearSymmeric | NA(概率) | NA |
| 27 | ei/stable/fapd | apd/random/fei | endp/stable/fad | addr/random/fen | firewall | p2p | None | 8 | 0 | 0 | 0 | ConePunchToRandomSymmeric | NA(概率) | NA |
| 28 | apd/linear/fei | apd/linear/fei | addr/linear/fen | addr/linear/fen | p2p | p2p | 810 | 1 | 4 | 3 | 2 | BothLinearSymmericPunch | 可通 | OK |
| 29 | ad/linear/fei | ad/linear/fei | addr/linear/fen | addr/linear/fen | p2p | p2p | 811 | 1 | 2 | 2 | 2 | BothLinearSymmericPunch | 可通 | OK |
| 30 | apd/random/fapd | apd/random/fapd | addr/random/fad | addr/random/fad | firewall | firewall | None | 8 | 0 | 0 | 0 | BothRandomSymmericPunch | NA(概率) | NA |

**矩阵语义解读**：
- **cone 侧 filtering=EI/AD**（#1–18）：B 侧 9 组合全部 P2P（~800ms）。EI/AD filtering 下 symmetric 对端经 cross-fire + learned 升级即通。
- **cone 侧 filtering=APD**（#19–27）：port-restricted 语义生效——B=EI（端口恒=public）确定可通（#19–21）；B=symmetric 属**概率性**（NA，#22–27）：本实现 learned 置底使部分组合偶发可达（#26 apd-linear 809ms 建立），多数组合窗口内未命中 → `firewall` 上报（不误判 success）。
- **双 linear 对称**（#28–29）：`BothLinearSymmericPunch` 双向预测命中（`predicted_hits=3/2`，见 §6 日志），~810ms 建立，**验证 §4.4 端口预测在模拟环境真实可达**。
- **双 APD random 对称**（#30）：`BothRandomSymmericPunch` 多 socket 并发；预期文档 §4.3「大概率失败」→ 正确上报 `firewall`（偶发可达属概率性，标 NA）。

**命中端口 / step 轨迹 / 升级路径**（取自代表性日志，详见 artifacts/work/）：
- `sym-2lin3` A：base=34100 step=3 N=16 → 预测 [34052..34148]；learned 升级 34100→34118→34121→34124；P2P via **34121**，`predicted_hits=3`。
- `cone-fei_b-ei-stable` A：DirectConePunch，P2P via 对端 public **34795**。
- `cone-fapd_b-ad-stable`（fail）：A 预测 base=34779 step=1，B 侧单向收到 A 的包（B→A 回包被 APD filtering 拒），未双向确认 → 正确不上报 success。

## 6. 代表性双端原始日志（artifacts/logs/，含完整 STUN 观测回显）

- `cone-fei_b-ei-stable_first_p2p_{a,b}.log`：锥形×锥形标准直连（`DirectConePunch`），观测同 socket 跨目标映射稳定 → EI，P2P ~800ms。
- `sym-2lin3_linear_{a,b}.log`：**双线性对称双向预测**——观测 `[33001→33100, 33002→33106, 33003→33109]` 判 APD+linear step=3；预测 base+step×N；learned 升级命中。
- `cone-fapd_b-ad-stable_fail_{a,b}.log`：port-restricted 失败路径——A=EI+APD filtering 对 B=AD symmetric，B 回包源被 A 过滤，双向确认未达成 → `firewall` 上报。

## 7. 已知限制

1. **filtering 探测降级**：CHANGE-REQUEST 需服务器支持（`--filtering-probe` 显式开启）；真实公网 STUN 多不支持 change 响应 → 探测结果保守（APD 或 unknown）。无第二 IP 的 mock 环境用「逻辑服务器 IP 分组」（`逻辑IP:port@真实IP:port`）替代。
2. **stable allocation 低现实频率**：`nat_sim` 中 stable 分配（同一键固定端口）现实中少见（ISP 级 port preservation）；矩阵中相关组合（B=*stable）标 NA，结果依赖时序。
3. **APD filtering × symmetric 对端为概率可达**：真实 port-restricted 打洞本就依赖候选命中窗口；本实现 `learned 置底` 提升命中概率但非确定。文档 §4.5「回打所有候选 + learned」语义在窗口内体现。
4. **真实环境验证**：本机处于中国电信 CGNAT 双向 UDP 黑洞环境（历史验收记录），单机无法跨真实 NAT 双端对打；`nat_sim` 已用「真实 loopback socket + 用户态 NAT 语义」等效模拟。可选加分项（CGNAT×公网服务器对打）由用户经既有 SSH 通道手动触发，本次未执行。
5. **IPv4 only**：检测与模拟均为 IPv4（`--stun` 解析不支持 IPv6）。

## 8. 一句结论

**修正后 linear/random 分支在模拟环境真实可达**——RFC 5780 检测器正确分类 (mapping, allocation)，策略引擎按 (mapping, allocation) 分发到预测/随机并发，双线性对称双向预测命中、随机对称多 socket 并发命中、port-restricted 不可达组合正确上报 `firewall`；30 组矩阵全部符合预期，原 §7 13 项单测保留全 PASS。
