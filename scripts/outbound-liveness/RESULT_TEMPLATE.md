# Outbound-UDP liveness — Gate 实测报告（模板）

> 对齐 `scripts/punch-research/TEST_REPORT_P2.md` §9/§10 的 Gate 段落写法。
> 用 `scripts/outbound-liveness/live_check.sh` 生成证据后填入本模板。
> 本次为**诊断/归因**特性验收，非 availability-acceptance；relay 全程保底，
> 本 Gate 不改变生产依赖。

## 0. 特性与验收口径

- **触发**：Direct 恢复状态机走到 `ScatterExtended`，宽扫窗口发满、0 matched ACK。
- **诊断**：合法 DNS A query 的 UDP 探测（非 UU 空包），并行轮次
  （`retries × timeout`，默认 2×1500ms ≤ 3s），三态 `ok / blocked / unknown`。
- **决策**：仅 `blocked` 触发「下一 tick admission 加速转 RelayBackoff +
  归因 `firewall_blocked`」；`ok`/`unknown` 只记录、不改变路径决策。
- **不变量**：liveness **从不** gate relay（relay 永远保底）、**从不**改 Direct
  提升的加密验证 ACK 逻辑。
- **误判率**：正常网络下「全部目标×全部重试全失败」判 `blocked` 的误判率应 ≈ 0
  （靠多目标冗余）。

## 1. 环境

- A=____ / B=____（机型、运营商、公网出口、NAT 映射行为：`EndpointIndependent` /
  `AddressOrPortDependent` / `UdpBlocked` 等）。
- daemon 版本（本机构建 debug）：____ ；SHA-256（双端同二进制）：____
- 信令/中继：____（relay-first 保底是否已拉起：____）
- liveness 配置：`udp_liveness_enabled=____` targets=____ `timeout_ms=____`
  `ttl_ms=____` `retries=____` `pre_flight=____`（默认 off）

## 2. 场景 A：出站被拦（期望 blocked → 转 relay + firewall_blocked）

> 前置：`udp_liveness_targets` 指向不可达 / 出站被拦目标（如 `192.0.2.1:53`
> TEST-NET，或某出口禁 UDP 53 的真实网络），触发一次 ScatterExtended 宽扫 0 ACK。

执行：
```
scripts/outbound-liveness/live_check.sh blocked \
  --log <daemon.log> --status <status.json> --peer <node_id> \
  --timeout-ms <t> --retries <r> --eps-ms <eps>
```

| 轮 | verdict | per-target (ip:port,responded,ms) | total_ms | 改变路径? | fail_reason |
|---|---|---|---|---|---|
| 1 |  |  |  |  |  |

**关键断言（live_check.sh 自动判，另在此记录证据行）：**
- [ ] 出现 `verdict=blocked`
- [ ] 探测 `total_elapsed_ms ≤ retries×timeout + ε`（即 ≤ ____ ms，**不是**再等一个
      完整 epoch 的 60s+ backoff）
- [ ] `outbound_liveness_applied` 出现（下一 tick admission 消费）
- [ ] `recovery_stage_relay_backoff reason=outbound_liveness_blocked` 出现（宽扫停止）
- [ ] `/status` 里该 peer `direct.last_error_code == firewall_blocked`、
      `direct.last_liveness == blocked`
- [ ] relay 数据面不受影响（业务包照常走 relay，无丢包/无 relay 断开）

**证据摘录（贴原始日志行）：**
```
event=outbound_liveness peer_id=... verdict="blocked" total_elapsed_ms=...
event=outbound_liveness_applied peer_id=...
event=recovery_stage_relay_backoff peer_id=... reason="outbound_liveness_blocked"
```

**从「全窗口扫满」到「转 relay」的额外延迟实测**：`____ ms`
（应 ≈ 探测时长，远小于一个 epoch 的 budget-exhausted backoff）。

## 3. 场景 B：正常网络（期望 ok，零误判 blocked）

> 前置：默认 targets（`223.5.5.5:53 / 119.29.29.29:53 / 114.114.114.114:53 /
> 8.8.8.8:53`），触发一次 ScatterExtended 宽扫（例如双 CGNAT 的 0 命中场景）。

执行：
```
scripts/outbound-liveness/live_check.sh normal \
  --log <daemon.log> --status <status.json> --peer <node_id>
```

| 轮 | verdict | per-target (ip:port,responded,ms) | total_ms | 改变路径? | fail_reason |
|---|---|---|---|---|---|
| 1 |  |  |  |  |  |

**关键断言：**
- [ ] 出现 `verdict=ok`（出站可达）
- [ ] **0 次** `verdict=blocked`（无误判）
- [ ] `direct.last_error_code` 保持 `direct_probe_failed`（NAT miss / C=0，
      未被误标 `firewall_blocked`）
- [ ] recovery stage **不**被 liveness 推进到 RelayBackoff（保持 ScatterExtended，
      继续按 flat cadence 重试）
- [ ] 若 Direct 能成，正常提升（加密验证 ACK 不受 liveness 影响）

**误判率统计**：`____ / ____`（`blocked` 误判次数 / 正常网络轮次）。目标 ≈ 0。

## 4. pre-flight（可选，默认关）

> 仅当 `udp_liveness_pre_flight=true` 时启用。记录是否观察到
> `outbound_liveness_pre_flight_skip`（被拦网络下跳过打洞、relay 保底）。

- 是否启用：____
- 观察到的 `pre_flight_skip`：____（relay 是否照常承载：____）

## 5. 结论

- 场景 A：____（PASS / FAIL，延迟归因是否准确）
- 场景 B：____（PASS / FAIL，误判率）
- 不变量核验：relay 是否全程保底 ____ ；加密验证提升是否未受影响 ____
- 已知局限/环境不可观测项：____
  （例：本网络出口 CGNAT 双向黑洞，无法稳定复现干净的「被拦 vs 未拦」对照，
  故场景 A 用 TEST-NET 目标模拟。）

## 6. 约束声明

- 本 Gate 为诊断/归因特性验收（REAL_TUN=1、真实 UDP 网络），relay 为明文 TCP、
  信令为 HTTP，故**不构成安全发布就绪证据**。
- 不改变生产依赖：relay-first 保底 + Direct 背景升级 + 加密验证提升 均维持原样；
  liveness 只在「何时/为何转 relay」上做诊断加速与归因。
