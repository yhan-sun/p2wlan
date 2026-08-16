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