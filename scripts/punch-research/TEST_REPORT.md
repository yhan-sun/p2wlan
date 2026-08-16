# TEST_REPORT — UU 远程 NAT 打洞算法研究与工程化

> 项目：scripts/punch-research/（第一阶段 F1 + 第二阶段 S1-S7）
> 约束：零第三方依赖（Python3 标准库）、无 Rust 改动、CLI 向后兼容
> 参考：/Users/pyu/Downloads/README.md（libstreamer.dylib v4.35.0 逆向）

---

## 进度日志

### 2026-08-16（D1）— 第一阶段收尾 + 第二阶段开工
- 盘点既有实现：puncher.py / mock_stun.py / nat_sim.py / run_matrix.py 已具备 F1.1-F1.3 主体。
- 单测 33 项全 PASS（原 §7 13 项 + 新增 A1-A5 共 20 项）。
- **修复矩阵基建缺陷**：run_matrix.py 的 pkill 未覆盖 nat_sim 自身，前轮孤儿进程占用 observer/forwarder
  端口导致后续组合 EADDRINUSE 秒退（30 组中 17 组假失败）。修复：pkill -9 双进程 + 1s 等待 +
  秒退自动重试一次。
- **修复 APD filtering 时序竞态**：`_execute_once` 发送顺序改为 cache→策略分支→主候选置底→learned。
  原顺序主候选先发、cache 区间后发，APD 侧 `mapping.dest` 停在预测端口而非对端真实映射端口，
  对端回包源不匹配 dest 被拒（cone-fapd_b-ei-linear 等组合假失败）。置底后 dest 恒停真实候选。
- 全矩阵 30 组：29/30 exp-match → 修复后 30/30（见下文）。
- 第二阶段开工：S1 predict.py（双向窗口/StepLearner/ReverseDetector/BirthdayPool/BudgetScanner）。

### （后续每日进度在此追加）

---

## 第一阶段（F1）验收自检

### F1.1 NatDetector 重写 — 完成

| 要求 | 实现 | 验证 |
|---|---|---|
| 可注入观测源（纯函数分类 + 网络探测两层） | `MappingObservation` / `classify_mapping()` / `classify_port_allocation()` 纯函数；`NatDetector.detect()` 网络层 | 单测 A1/A2 不依赖网络全绿 |
| 3 个独立 socket 并行（同目标×2 / 同IP异端口 / 异IP） | `NatDetector.detect()` 双线程并行：s1 主 socket（same_target×2+diff_port+diff_ip）+ s4 独立新 socket | 单组合实测观测日志 4 组齐全 |
| 每 socket 只解析 STUN XOR-MAPPED，超时 2s，单组失败不整组废弃 | `_stun_probe_batch` txn 匹配，逐组结果独立（None 容忍） | observations 容错 |
| 异 IP 用逻辑服务器身份分组（`--stun 逻辑IP:port@真实IP:port`） | `StunTarget` / `parse_stun_targets`；mock 环境 VIP 与真实 127.0.0.1 分离 | nat_sim 传 `203.0.113.3:33003@127.0.0.1:33003` |
| 输出 NatProfile（mapping/allocation/step/public/confidence/filtering/observations） | `detect()` 返回完整 dict + 全量 observations | 日志 NAT profile 行 + obs 行 |
| filtering 走 CHANGE-REQUEST 尽力探测，无配套降级 unknown | `--filtering-probe` 显式开启；无 STUN/无 change 支持 → unknown | 矩阵 filtering 列 |
| `--force-nat=1|2|3` 兼容 | `force_profile()`（1→EI+STABLE，2→APD+LINEAR，3→APD+RANDOM） | 单测 + 原语义保留 |

### F1.2 PunchEngine 修正 — 完成

| 要求 | 实现 | 验证 |
|---|---|---|
| choose_strategy 按 (mapping, allocation) 分发 7 策略 + cone×cone 直连 | `choose_strategy()` + `DIRECT_CONE` | 单测 A4 五例全绿；矩阵 mode 列 |
| linear：双向区间 [base−step·N, base+step·N]，N=8/16 按置信度 | `predict_ports(bidirectional=True)`，N 按 confidence≥0.75 翻倍 | 矩阵 linear 组全通 |
| step=0xc057 通告或差分众数，自适应重估 | `_remote_step_value()`：0xc057 > 差分众数 > 信令通告 > 1；收包后 `infer_step` 重估并记 step_history | A3 单测 + 日志 adaptive step re-estimate |
| random：≥3 独立 socket 并发，M=64 | `_open_extra_socks(3)` + `_random_punch_once` | 矩阵 random 组 |
| 收包升级：MAGIC→解析对端映射→learned candidate→回打真实映射→回打所有候选重试循环 | `_recv_loop` / `_on_peer_observation` / `_reply_all` | 日志 learned candidate |
| 双向确认后才置 P2P | recv_count≥2 才 `p2p=True`（多 1 RTT 防假阳性） | 日志 bidirectional confirm |
| keepalive 20s + 端口漂移重预测 | `--keepalive-s`（默认 20）+ 缓存区间 | stats.keptalive |
| pair 缓存 ~/.puncher_pair_cache.json（最近 5 条） | `load/save_pair_cache` 上限 5 | A5 单测 |

### F1.3 mock 验证环境 — 完成

| 组件 | 实现 |
|---|---|
| mock_stun.py | Binding 应答 XOR-MAPPED、`--report-as` 覆盖、CHANGE-REQUEST 变更地址应答、`--drop-source` |
| nat_sim.py | 进程内双 NAT（loopback socket + 用户态映射）：mapping 轴 ei/ad/apd × allocation 轴 stable/linear/random（双轴独立）× filtering 轴 ei/ad/apd/none；确定性 seed |
| run_matrix.py | 30 组（cone 固定侧 filtering 变体 27 + 对称关键 3），单组 timeout ≤20s，TSV + 日志 |

### F1.4 测试清单

- [x] **A 单测**：原 13 项 + 新增 5 组（A1 classify_mapping 4 例 / A2 classify_port_allocation 4 例 /
  A3 predict_ports 双向+回绕+step 重估 4 例 / A4 策略选择 5 例 / A5 keepalive+pair 缓存 3 例）→ **33/33 PASS**
- [x] **B 集成矩阵**：30/30 exp-match，记录结果/时长/命中端口/轮次/step 学习/升级路径/keepalive（TSV 留痕）
- [ ] **C 真实环境**：本机 CGNAT 不可行，仅记录（Gate 2 用户手动执行）
- [x] **D 回归 + py_compile**：`python3 -m py_compile puncher.py scripts/punch-research/*.py` 通过

### 与原版 §7 实现的语义差异（关键）

1. **NAT 检测观测源**：原版用单 socket `getsockname()` 观测本地端口序列（四元组不变 → 恒判 cone，
   linear/random 分支永远不可达）。修正版观测 STUN XOR-MAPPED 回显变化（服务器视角映射），
   3 socket + 逻辑 IP 分组完成 RFC 5780 三态判定。
2. **检测结果扩展**：整数枚举(1/2/3) → NatProfile(mapping + allocation + step + filtering + confidence)；
   `legacy_nat_type` 保留信令兼容。
3. **策略分发**：按 (mapping, allocation) 而非整数枚举；cone×cone 走直连（原 default 落 random）。
4. **P2P 建立**：原版收到 MAGIC 即置 P2P（可能假阳性）；修正版双向确认（recv≥2）才置。
5. **端口预测**：单向 base+step×N → 双向区间 [base−step·N, base+step·N]；step 自适应重估。
6. **防火墙**：UDP DNS:53 双目标 + TCP:443 对照，仅两通道全失败才判 firewall。

### 测试结果摘要（本阶段）

```
单测:   33/33 PASS
矩阵:   30/30 exp-match（含 3 组 NA 预期）
artifact: artifacts/nat_matrix.tsv、artifacts/logs/、artifacts/work/<combo>/peer_{a,b}.log
```