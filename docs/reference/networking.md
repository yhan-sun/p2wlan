# 网络参考

## 路径

默认 Direct-first 优先验证 LAN、IPv6 或 IPv4 UDP 直连；Relay 同时准备但只在有界直连窗口到期或已建立 Direct 明确失活后兜底。Direct 的确认必须来自当前网络 generation、peer session、候选 epoch 和加密业务路径；控制面可达或探测 ACK 不能单独证明业务互通。

## 服务端端口

| 组件 | 默认内部端口 | 公网边界 |
| --- | ---: | --- |
| Control | 18080 | 通过可信 HTTPS 反代公开 |
| Relay TLS | 18081 | 按需公开 |
| Relay metrics/readyz | 18082 | loopback only |
| UDP observer | 由配置指定 | 可选，不是 Relay 数据端口 |

Control 反向代理必须支持 WebSocket Upgrade。Relay TLS 不能用 Control 的普通 HTTP 代理规则代替；证书、audience、region、ticket keyring 和撤权 feed 必须同时匹配。

## MTU 与 DPLPMTUD

Relay 路径使用保守的业务报文预算。DPLPMTUD 从安全下限开始，成功后逐步提升，失败或取消时回退；Direct 与 Relay 的预算、网络 generation 和连接 epoch 不能混用。高于 1380 的 Relay 路径应提示 PMTU blackhole 风险。

诊断至少显示当前路径、selected MTU、探测状态、失败 reason code 和建议值。MTU smoke、真实 TUN、NAT、网络切换和业务流量是不同验证层，不能互相冒充。

## NAT 限制

STUN 观察到公网映射不代表对端可以入站。家庭宽带、校园网、企业网、移动热点、CGNAT 和双受限 NAT 的结果不同；Direct 失败时应回退 Relay 或明确提示环境限制。

## 探测成本与候选覆盖

前台 UDP 探测复用进程内全局预算，同时限制网络、peer、peer/目标 IP 和跨 peer 的目标 IP 聚合。目标 IP 聚合上限为每秒 448、每 60 秒 4500；原有进程上限每秒 512、每 60 秒 6000 不变。已确认路径的保活和加密业务不消耗这份前台扫描预算。该限制是单进程的，多房间独立 daemon 之间不宣称已经具备跨进程预算协调。

端口预测使用宽整数后取模，剔除端口 0 和重复候选；当前批次的首选端口不会被历史学习步长替换。历史同方向假设仅占用原有候选预算中的有限份额。学习覆盖率表示近期样本一致性，不是实际打洞成功概率。

Hard↔Hard 日志区分模型生成数量、归一化入口数量、进入信令数量和实际探测统计。`pre_normalization_reduced_count` 表示调用方在归一化之前已裁掉的候选数量；例如模型生成 96 个而当前策略只接受 32 个，不能报告为已经实际覆盖 96 个。现有 Hard↔Hard 协议、认证和发送上限未因增加日志而放宽。
