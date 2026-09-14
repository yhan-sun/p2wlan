# 网络参考

## 路径

连接依次尝试 LAN Direct、Public UDP Direct 和 Encrypted Relay。Direct 的确认必须来自当前网络 generation、peer session、候选 epoch 和加密业务路径；控制面可达或探测 ACK 不能单独证明业务互通。

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
