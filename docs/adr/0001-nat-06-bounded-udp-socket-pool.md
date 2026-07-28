# ADR 0001: NAT-06 的受限 UDP socket pool 实验

- Status: Accepted for an opt-in experiment
- Date: 2026-07-23
- Scope: address/port-dependent NAT 下的 Direct UDP candidate-pair 建立

## 背景

当前 Direct transport 只有一个长期 UDP socket。它已具备：多 STUN 行为探测、同步
Punch/ACK、受限 predicted candidate、birthday candidate、认证 Probe v2、路径确认和
Relay fallback。

本次实机基线显示本端 NAT 的公网 IP 稳定、映射端口在不同 STUN 目的地间变化，且
filtering 也是 address/port-dependent。同步打洞的初始候选、预测候选和受预算约束的
birthday 窗口均没有收到 ACK；在同一条件下 Relay 稳定可用。因而不能把更多端口扫描
当作默认策略，也不能把 STUN 映射端口误认为对远端 peer 可入站。

## 决策

实现前先建立一套可复核的 A/B 基准；只有基准显示有收益时，才将 socket pool 作为
**默认关闭**的实验性候选生成与 punch 方式。实现须满足：

1. 总 socket 数最多 4（主数据 socket 加最多 3 个实验 socket），默认 1。
2. 只有本地 NAT profile 同时报告 address/port-dependent mapping 与 filtering，且
   本轮 Direct 尚未确认时，才允许开启实验 pool。
3. 每个 socket 都必须有唯一的 receive owner；STUN、Probe v2、ACK 和 WireGuard
   数据不能并发抢读同一个 socket。
4. 收到认证 ACK 后记录 peer 到本地 socket 的亲和关系；该 peer 的后续 Direct 数据
   必须从同一个 socket 发送，避免再次改变 NAT 映射。
5. 每一轮 pool probe 的 socket 数、每 socket 发包数、ACK、首个 Direct 时间、映射
   端口和失败原因必须写入 diagnostics，且不记录 token、私钥或精确本地网络标识。
6. 任意 socket 出错、预算耗尽、超时或关闭 feature flag 时，立即收敛到现有单 socket
   策略和 Relay；不得影响已确认 Direct 或 Relay 数据面。

## A/B 基准

在相同两端网络、相同 STUN 集合和相同 Relay 条件下运行至少 20 次冷启动连接：

- A：现有单 socket；B：最多 4 socket 的实验 pool。
- 记录 Direct ACK 成功率、WireGuard 加密确认成功率、首次可用路径时间、Relay 首包时间、
  UDP socket 峰值、Probe 数及字节数。
- 只有 B 的 Direct 建立率有明确改善，且 P95 首路径时间、流量、socket 数均在预算内，
  才提高灰度比例；否则保持默认关闭并保留 Relay。

## 替代方案与取舍

- 继续扩大远端端口 birthday 窗口：已实施且在本次网络没有 ACK，继续扩大只增加无效
  流量和被 NAT/防火墙限速的风险。
- 固定端口或依赖 UPnP/PCP/NAT-PMP：已尝试映射协议；网关不支持或没有授权时不能作为
  可用性前提。
- 直接使用 Relay：可靠且保留为基础路径，但不能提升可预测 NAT 上的 Direct 比例。
- 无限制 socket pool：资源、耗电、攻击面和诊断复杂度不可接受，明确拒绝。

## 回滚

feature flag 关闭后不创建实验 socket，不改变信令 schema、主 socket、认证 Probe 或
Relay 行为。已建立的 Direct 会在 socket 生命周期结束前保持，失败时按现有逻辑切回
Relay。
