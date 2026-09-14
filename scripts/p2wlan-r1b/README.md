# STUN CHANGE-REQUEST 探测工具

本目录提供 RFC 5780 CHANGE-REQUEST 能力探测，不是客户端或服务端运行时依赖。工具用于确认 STUN 服务是否能返回 changed-source 响应；运行结果只作为外部诊断证据保存，不写入产品文档。

## 工具

| 脚本 | 用途 |
| --- | --- |
| `stun_change_request_probe.py` | 对每个 STUN 端点执行 baseline、change-ip+port 和 change-port 探测。 |
| `stun_change_request_probe2.py` | 多轮、NAT 混淆感知探测；以 change-port 作为主要观察项。 |
| `stun_probe_selftest.py` | 使用 loopback mock 验证探测器的正例路径。 |

运行示例：

```bash
python3 scripts/p2wlan-r1b/stun_change_request_probe2.py
python3 scripts/p2wlan-r1b/stun_probe_selftest.py
```

探测结果受 STUN 服务能力、本机 NAT、防火墙和网络路径影响。`SAME`、`CHANGED` 或 `NO_RESP` 不能单独证明生产网络的 Direct 可用性；生产路径仍须使用客户端的实际候选、加密确认和业务流量验证。
