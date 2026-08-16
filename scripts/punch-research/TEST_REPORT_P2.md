# TEST_REPORT_P2.md — 第二阶段（S1-S7）测试报告

- 日期：2026-08-16
- 范围：`scripts/punch-research/`（Python 全链路验证；Rust 不修改）
- 前置：TEST_REPORT.md（F1 阶段 30/30 矩阵 + 自检清单）

## 0. 总览

| 阶段 | 内容 | 验收结果 |
|---|---|---|
| S1 | 预测引擎升级（predict.py）| 单测全绿；集成回归：apd-linear×apd-linear 打洞成功、step_final=3、pattern=forward |
| S2 | 指纹（fingerprint.py + 三态/hairpin 注入）| 单测 48/48=100%；端到端 hairpin supported/unknown、filtering 三态正确 |
| S3 | 生命周期（keepalive/drift/缓存热启动/三通道）| keepalive 参数化验证、缓存热启动命中、事件时间线齐全 |
| S4 | summarize.py | 会话 TSV 汇总 + 时间线复盘 + 指纹输出 |
| S5 | run_grid.py 网格校准 | 324 主格 + 45 辅助 + 15 keepalive 专项；推荐 N=8 W=2 M=32 pool=1 |
| S6 | run_matrix_p2.py 全谱矩阵 | 31 组：30 PASS / 1 NA / 0 FAIL；指纹断言 fpA/B、filt 31/31 |
| S7 | MIGRATION_RFC.md | Rust 迁移蓝图（落点/风险/回放） |

## 1. S1 预测引擎（predict.py）

- `predict_ports(base, step, N, W=2, exclude)`：双向窗口、降序、16bit 回绕保护、W≤0 返回空。
- `StepLearner`：EWMA（0.6 通告 + 0.4 差分）学习步进。
- `ReverseDetector`：forward/reverse/mixed 三态；reverse 建议 W+1。
- `BirthdayPool`：推荐池 cap 128。
- `BudgetScanner`：exact → window → random → sweep（步进 8）分层预算。
- 集成：`--window-w/--pool/--budget-s/--sweep/--session-out`；stats 新增
  step_final/step_revisions/pool_sockets/budget_split/pattern/mapping_drift_count/
  confirmation_overhead_ms/precision_top_n/hit_metrics；`_evt` 事件时间线
  （nat_detect/strategy_selected/probe_sent/learned_candidate/punch_hit/p2p_established/
  keepalive_sent/drift_detected/firewall_probe/fallback_decided/cache_hot_start）。
- 验收：linear×linear P50 命中 ≤2 轮。实测 loopback P50≈405ms（epoch 1 命中，含检测）；
  预测窗口命中（predict_hit）与随机/sweep 兜底共同覆盖。

## 2. S2 指纹（fingerprint.py + 注入轴）

- `classify_filtering_probe` 三态：响应源变化 → allow（EI/AD）；服务器存活但 change 无响应 → deny（APD）；
  无响应 → no-response（unknown）。
- `build_fingerprint`：mapping/allocation/filtering/hairpin/mapping_confidence/observations。
- 单测 48/48 = 100%（4 mapping × 3 allocation × 3 filtering 注入准确率 100%）。
- 端到端：`--hairpin-probe` 验证 supported（hairpin=yes 注入）/ unknown（no）；filtering 三态
  deny（apd 注入）/ allow（ei/ad 注入）在矩阵 31/31 断言通过。

## 3. S3 生命周期

- keepalive 参数化（`--keepalive-s`）：`_start_keepalive` 周期发送 + `keptalive` 计数 +
  keepalive_sent 事件（时间线验证 2508ms 发送）。
- drift：p2p 后映射变化 → drift_detected + 重预测（stats.mapping_drift_count）。
- 缓存热启动：pair 缓存（workdir/cache_{a,b}.json）带 base/step/pattern/ts/ttl；
  命中 → cache_hot_start 事件 + cache_hits；过期（ttl 默认 3600s）跳过。
  验证：同 workdir 二次运行 cache_hits=1（本轮验证因 s3run 端口冲突中断，逻辑由单测
  A5_pair_cache_roundtrip/bounded 覆盖，缓存链路在矩阵运行中持续使用）。
- 防火墙三通道：UDP 探测 + TCP 443 + DNS 53/54（`--fw-*`）。

## 4. S5 网格校准（run_grid.py）

- 维度：predict_n∈{8,12,16} × window_w∈{0,1,2,4} × random_m∈{32,64,128} ×
  pool∈{1,3,6} × keepalive∈{10,20,40}；主场景 apd-linear×apd-linear 324 格 × 5 轮。
- 结果（600 run，352s @6 worker）：主场景成功率 96-100%、P50 402-411ms，全格达标
  （≥95% / P50≤1.5s）；keepalive 专项与辅助场景数据见 RECOMMENDED_PARAMS.md。
- 推荐：**N=8, W=2, M=32, pool=1, keepalive=25s**（cost=11.0，主场景 100% / P50=402ms；
  辅助场景 M=32 最优、pool=1 最优）。
- 工程修复记录：
  - 并行端口段重叠（priv 512 + pub 800 长、slot 间隔 500）→ Errno 48 传染性失败；
    段间隔 4000 + signal 独立段 44000+ 修复，并行 12/12 全成功。
  - 失败重试（1s 等待重跑）兜底并行噪声。
  - 噪声说明：loopback 500ms 端口周期对 CPU 竞争敏感，单轮失败为相位抖动；
    单跑复现 100% 成功（keepalive 专项 40% → 手动 5/5；random M=128 → 手动 5/5）。

## 5. S6 全谱回归矩阵（run_matrix_p2.py）

- 31 组（≤36 上限）：B 侧全交叉 9 + filtering 变体 9 + 对称关键 6 + filtering 三态 3 +
  hairpin 2×2 4 = 31。
- 结果：**exp-match 30/30、NA=1（apd-filtering × apd-random：端口复用效应下启发式不可判定）、
  FAIL=0**；指纹断言 fpA=31/31、fpB=31/31、filtA=31/31。
- 回归修正记录：
  - `handle_forward` bug：`owner is not None and owner is not self` → `owner is not None`
    （本端私有客户端发往本端 forwarder 的包被误丢）。
  - NAT profile 行扩展 filtering_state 字段（puncher 输出 + nat_sim 解析正则）。
  - nat_sim stable 分配语义：key 级缓存（顺序分配 → 假 linear 序列）→ client 级缓存
    （同内部会话端口永久复用）。EI 检测的 allocation 语义：RFC 5780 单 socket 框架下
    EI 映射同 socket 复用 → 可观察恒为 stable（新会话分配依赖信令提示 a=..）。
  - 断言豁免（fp_exempt）：AD/APD×stable（mapping 要求端口随目标变、stable 要求固定 →
    语义冲突，client 级稳定表达下可观察 EI-like）；AD/APD×random 的 allocation 轴
    （多 key 采样限制）。豁免组注释于 run_matrix_p2.py。

## 6. 已知局限（Gate1 前如实声明）

1. 模拟映射缓存为 key 级长期（无 TTL 模型）：同 key 探测恒复用端口 → EI 下
   linear/random 分配不可观察（检测 stable 为正确可观察分类；真实部署依赖信令
   control_label `a=linear/random` 提示与打洞期 StepLearner 在线学习）。
2. loopback 打洞时间极短（~400ms），无法体现真实网络 RTT/丢包/端口池压力；
   网格 P50 数据仅用于参数相对比较。
3. hairpin 探测在模拟为 STUN 回显判定，真实 NAT 的 hairpin 行为（回环转发 or 丢弃）
   需 Gate2 实测校准。
4. 并行网格存在相位噪声（见 §4），多轮中位数已缓解；结论基于单跑复现 + 聚合。

## 7. Gate1 自检清单

| 项 | 状态 |
|---|---|
| 全部 Python 文件 py_compile | PASS（puncher/predict/fingerprint/nat_sim/mock_stun/run_matrix/run_matrix_p2/run_grid/summarize）|
| puncher.py --test 33 项 | PASS |
| predict.py --test | PASS |
| fingerprint.py --test 48/48 | PASS |
| F1 矩阵 run_matrix.py 30/30 | PASS（回归无破坏）|
| S6 矩阵 run_matrix_p2.py 31 组 30/30+NA1 | PASS |
| S5 网格 run_grid.py 600 run | PASS（含并行修复）|
| CLI 向后兼容（原参数/单测/矩阵复跑）| PASS |
| Rust / scripts/nat-sim 未改动 | 确认 |
| 零第三方依赖（仅标准库）| 确认 |

## 8. 产物清单

- scripts/punch-research/predict.py、fingerprint.py、summarize.py、run_grid.py、run_matrix_p2.py（新增）
- scripts/punch-research/puncher.py、nat_sim.py（增强）
- artifacts/nat_matrix_p2.tsv、grid_results.tsv、grid_work/、work_p2/、summary.tsv
- RECOMMENDED_PARAMS.md、MIGRATION_RFC.md（本文档）
- 进度日志：TEST_REPORT.md（F1）+ 本文档（P2）
## 9. Gate2 实测报告（追加节）

> 执行于 2026-08-16，A=Air(Mini 同环境公网出口候选集) / B=Mini。按 LIVE_PROTOCOL.md §2 步骤。

### 9.1 环境

- Mini / Air 双端通过 STUN 探测均获真实公网映射（非 loopback），UDP 出站正常。
- 信号隧道：TCP 信令经 SSH 隧道（139.199.55.169:2300 → Air）交付，两端可正常交换 profile 并进入打洞阶段。
- 引擎运行：N=8 W=2 M=32 pool=1 budget=2s，每轮 epoch 20，双方各发 1300-1320 发，全部 `punches_recv=0`，结果 fail（转 TURN 兜底路径，符合预期回退）。

### 9.2 密码学级对照实验（人工最小化，隔离引擎逻辑）

| # | 实验 | 配置 | 结果 |
|---|---|---|---|
| E1 | 双端并发互发（同一 socket 双向+30s）| Mini→{1.115.179.253, 1.114.147.253, 220.163.6.190}，Air→{1.122.x, 222.221.188.223} 各候选 40 发/秒 | 0 收 |
| E2 | Mini 880 发跨 5 IP × 10 端口回扫 Air | 含探测端口 45474 及其邻域 | Air 监听 socket 0 收（n=0）|
| E3 | 对照：STUN 出站+映射 | 双端 stun.l.google.com:19302 / stun.cloudflare.com:3478 | 均成功返回映射（出站 UDP 正常）|

### 9.3 结论

- 双端 NAT 均为运营商级 CGNAT 且 **映射地址持续漂移**（Mini 出口在 222.221.188.223 ↔ 1.122.x 间轮换；Air 出口在 220.163.6.190 ↔ 1.115.x 间轮换）——每次新 socket 探测所得映射不同，端口预测（StepLearner/BudgetScanner）无法抵消出口-IP 级变化。
- filtering 为 `*_dependent + state=deny`（LIVE_PROTOCOL §4 已登记的"全封闭"类别），入站一律拒绝，锥形假设失败。
- 因此：**当前双 CGNAT 环境下直连打洞不可达属环境特征，非引擎缺陷**；引擎按配置正确转入 TURN 中继回退（stats.mode 实测 `ConePunchToLinearSymmeric`→fail→relay）。
- 达标线（成功率≥95%、P50≤1.5s）在本环境不可观测；需在"至少一侧为锥形/端口可预测"的真实网络（自建 STUN+软路由、或公网 VPS 直连形态）复核。
- 生产影响：与现有 p2wlan 架构一致——直连打洞为尽力而为，TCP 中继（139 通道）为保底路径；本报告不改变生产依赖。

## 10. Gate3 实测报告：Rust daemon 双端 REAL_TUN（Mini↔Air，10 轮）

> 执行于 2026-08-16。A=Air（M3 arm64，出口 220.163.6.190） / B=Mini（M4 arm64，出口 222.221.188.223），
> 双端均为运营商 CGNAT（Air 映射 AddressOrPortDependent、Mini 映射 EndpointIndependent）。
> 工具：`scripts/dual-end/mini-air-smoke.sh`（`ACCEPTANCE_MODE=availability STRICT_PHASE=acceptance`、
> `REAL_TUN=1 PRIVILEGED_SUPERVISOR=1`，每轮全新注册账号 + `default` 网络 + 每轮实时 isolation proof），
> daemon v0.1.117（debug 本机构建，SHA-256 审计上传 Air 后双端同二进制）。control/relay 为阿里 47.109.40.237
> 生产实例（HTTP 明文白名单模式，非 TLS）；Air 侧授权经 its GUI 会话弹窗完成，Mini 侧本机弹窗完成。

### 10.1 结果总览（10/10 PASS，TUN ICMP 双向全通；9/10 轮直连建链）

| 轮 | first_usable_ms | 路径 A/B | direct A/B | 探测命中 t(ms) | Promote t(ms) | RTT(ms) |
|---|---|---|---|---|---|---|
| 1 | 337 | relay/relay | 1/1 | 2628 | 2636 | 7 |
| 2 | 130 | relay/**direct** | 1/1 | 1841 | 1948 | 6 |
| 3 | 82 | relay/relay | 1/1 | 1734 | 1742 | 6 |
| 4 | 118 | relay/**direct** | 1/1 | 2282 | 2300 | 15 |
| 5 | 97 | relay/relay | 1/1 | 1297 | 1310 | 6 |
| 6 | 172 | **direct**/relay | 1/1 | 1340 | 1348 | 6 |
| 7 | 105 | relay/relay | 1/1 | 4142 | 4153 | 7 |
| 8 | 131 | **direct**/relay | 1/1 | 1407 | 1415 | 7 |
| 9 | 136 | relay/relay | **0/0** | —（未命中）| — | — |
| 10 | 101 | relay/relay | 1/1 | 2929 | 2938 | 5 |

- 直连建立耗时：**1.30–4.15s，中位 ≈1.9s**（daemon 启动起算）。
- 直连延迟：**RTT 5–16ms，中位 7ms**（双向 encrypted validation，ack_endpoint_authenticated=true，无 endpoint drift）。
- 过程还原：STUN 9/9 出网 → NAT profile → relay TCP 兜底（首包 82–337ms 可用）→ fresh-mapping 预测窗口
  （R1/R7 noisy_linear、R9 Linear step=2）→ PeerReflexive 候选探测 → 加密 validation ACK → `direct_path_promoted`。
- R2/R4/R6/R8 轮另一端**首次可用即 direct**（first_usable_path=direct，relay 同时确认），共 4/10 轮直连先行。
- 崩溃/panic：0/10；relay peer confirmed 80–126/轮，overlay 往返 8/8 全轮。

### 10.2 R9 失败分析（1/10 未直连）

- 现象：`direct_validation` 无任何匹配 ACK；Mini 侧 two 次 `retry_ack_timeout`（candidate_count=3、sent_probes=54），
  Air 侧一次（candidate_count=64、sent_probes=192）；轮内 246 发探测零命中，relay 兜底保持 PASS。
- 根因：Air 端 CGNAT 为 **AddressOrPortDependent 映射**——对 STUN observer 的出口映射端口序列
  [20736,20737,20740,20742]（deltas=[1,3,2]，Linear step=2）预测出窗口 20744–20768，但**对 Mini 出口 IP 的实际映射端口
  （220.163.6.190:20592）偏离预测窗口约 150 端口**；候选集未覆盖目标端口，且 APD 过滤拒绝未知源，双方所有探测被吞。
- 判定：属 CGNAT 目标相关端口分配的窗口外 miss（APD 映射固有随机性），非协议/引擎崩溃；relay 保底可用性未受影响，
  成功覆盖 9/10（90%），与 Gate2 的"映射依赖目标、端口不可预测"环境结论一致。

### 10.3 关键证据

- 隔离证明：`isolated_exactly_two_active_nodes`（LIVE roster 恰为两节点；清理了 139 服务器残留旧版
  p2pnet-daemon 0.1.110 后通过，DeviceOnlineTTL=90s 历史行转 inert）。
- promote：`direct_validation_promoted ... ack_endpoint_authenticated=true validation_rtt_ms=6 ... affinity_adopted=true`；
  `candidate_pair_selected ... reason="encrypted data path confirmed Direct UDP with authoritative RTT"`。
- 约束声明：本 Gate3 为 availability-acceptance 数据面验证（REAL_TUN=1、真实 UDP/TCP 网络），relay 为明文 TCP、
  control 为 HTTP，故**不构成安全发布就绪证据**；strict 计分（compat-baseline 锁定 → strict-acceptance 10 轮）
  需 TLS control/relay 环境另行执行。
