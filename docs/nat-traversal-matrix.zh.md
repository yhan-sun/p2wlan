# P2WLAN NAT 穿透验收矩阵

本文用于记录真实网络下的直连成功率、relay 回退和 MTU 行为。它不是一次性说明文档，而是每次发布前应该更新的验收台账。

## 目标

- 区分“STUN 能看到公网端口”和“对端真的能打进来”。
- 覆盖 full cone、restricted、port restricted、symmetric、CGNAT、校园网、企业网、移动热点等真实差异。
- 验证当前实现的 ICE-like 能力边界：host/server-reflexive/peer-reflexive/predicted/birthday/socket-pool 候选、direct nomination、relay fallback。
- 记录 relay 是 DERP-like TCP/TLS 密文转发，不等同标准 TURN allocation/permission/channel 语义。

## 默认验收拓扑

| ID | A 端网络 | B 端网络 | 预期路径 | 必测项 |
| --- | --- | --- | --- | --- |
| NAT-01 | 家庭宽带 NAT | 家庭宽带 NAT | direct 或 relay fallback | STUN 双 observer、候选数量、首次可用路径耗时 |
| NAT-02 | 家庭宽带 NAT | 云服务器公网 UDP | public UDP direct | 云安全组、系统防火墙、固定 UDP bind/advertise |
| NAT-03 | 校园网 | 家庭宽带 NAT | relay fallback 可用 | UDP blocked、STUN 超时、relay RTT |
| NAT-04 | 企业网 | 家庭宽带 NAT | relay fallback 可用 | UDP egress 限制、TLS relay 可达性 |
| NAT-05 | 移动热点 / CGNAT | 家庭宽带 NAT | relay fallback 可用，部分 direct 可能成功 | symmetric/address-or-port-dependent NAT 识别 |
| NAT-06 | 双 symmetric NAT | 任意受限 NAT | relay fallback 必须稳定 | birthday/socket-pool 探测预算和 cooldown |
| NAT-07 | relay-only 策略 | 任意网络 | relay | `relay-policy relay-only`、metadata 暴露说明 |
| NAT-08 | 高 MTU 路径 | relay 路径 | 无大包卡死 | 1420/1380/1280 降级 smoke test |

## 每次运行记录

| 字段 | 示例 | 说明 |
| --- | --- | --- |
| 日期 / 版本 | 2026-07-29 / v0.1.62 | 精确到提交或 release |
| 场景 ID | NAT-05 | 来自上表 |
| A/B 网络 | mobile hotspot / home NAT | 不记录敏感公网地址也可以，但要保留网络类型 |
| STUN observer | 3 configured, 2 success | 至少两个不同网络 observer 才能判断质量 |
| NAT profile | mapping=address_or_port_dependent filtering=address_or_port_dependent | 来自 `/status` 或 `p2wlan doctor` |
| 候选来源 | host, srflx, peer-reflexive, predicted | 记录 direct 尝试的实际来源 |
| 选中路径 | direct / relay | 包含 reason code |
| 首次可用路径 | 850ms | 从 daemon 启动或 peer joined 到可用路径 |
| relay 指标 | cn-east 43ms pong=ok | 记录 region、endpoint、RTT、错误码 |
| MTU 结果 | 1420 fail, 1380 pass | 记录 ping、小 TCP、大 TCP、UDP payload |
| 失败摘要 | direct_probe_failed | 保留日志摘要，不贴私钥、JWT、ticket |

## 最低通过标准

- NAT-01/NAT-02 至少一个场景能形成 direct，并可通过虚拟 IP 双向 ping、SSH 或 TCP smoke。
- NAT-03/NAT-04/NAT-05/NAT-06 在 direct 不可用时必须自动落到 relay，且 UI/CLI 能解释原因。
- STUN observer 少于两个时，doctor 必须提示观测质量不足。
- Relay 路径存在且 MTU 高于 `1380` 时，doctor 和 Diagnostics 页必须提示风险。
- 所有失败都必须有稳定 reason code 或日志摘要，不能只显示“unknown”。

## 建议命令

```bash
p2wlan doctor
p2wlan status --json
ping <peer-virtual-ip>
ssh <peer-virtual-ip>
p2wlan config set mtu 1380
p2wlan down && p2wlan up
```

## 后续实现门槛

- 引入完整 RFC8445 ICE 前，需要补 candidate priority、nomination、checklist state、role conflict 和 pair pruning 的可观测字段。
- 若实现标准 TURN，需要单独标注 TURN allocation、permission、channel、refresh 和 auth 语义；不能把当前 DERP-like relay 直接命名为 TURN。
- 自动 PMTU 探测上线前，需要保留手动 MTU 降级路径和失败回退证据。
