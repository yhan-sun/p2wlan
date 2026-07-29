# P2WLAN 生产化验收清单

本文把 README 中的协议边界和网络限制转成可执行的验收项。目标不是阻止 Preview 使用，而是让每一次走向生产的改动都有明确证据。

## 状态分级

| 等级 | 含义 | 最低要求 |
| --- | --- | --- |
| Preview | 可真实测试，可自托管 | README 边界清晰，基础 CI 通过，能解释直连和中继路径 |
| Production Preview | 可用于低敏感生产流量 | 完成本文 P0/P1 验收，具备回滚和诊断手段 |
| Production | 可承载敏感生产流量 | 完成独立安全审计、长期稳定性测试和真实网络矩阵 |

## P0 协议与安全

- 明确数据面协议：当前是 WireGuard-like `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`，不声明官方 WireGuard 互操作兼容。
- 明确算法套件：X25519、ChaCha20-Poly1305、BLAKE2s/HKDF-BLAKE2s、Ed25519 challenge-response。
- 为握手、传输包、重放窗口、重密钥、异常包解析补充固定测试向量。
- 为控制面信令签名、candidate generation、candidate expiry、probe ephemeral key 绑定补充回归测试。
- 禁止在日志、诊断接口和崩溃输出中泄漏 X25519/Ed25519 私钥、relay ticket、JWT、device credential。
- 对自研密码协议路径做一次外部审计；审计前只能标记为 Preview 或 Production Preview。

## P1 NAT 穿透

- 记录并展示本地 NAT profile：mapping behavior、filtering behavior、hairpin、mapping lifetime、STUN 成功率、confidence。
- 至少用两个不同网络的 STUN observer 做默认生产配置；单 observer 只能作为有限诊断。
- 维护真实网络矩阵（模板见 [NAT 穿透验收矩阵](nat-traversal-matrix.zh.md)），至少覆盖：
  - 家庭宽带 NAT 到家庭宽带 NAT
  - 家庭宽带 NAT 到云服务器公网 UDP
  - 校园网到家庭宽带
  - 企业网到家庭宽带
  - 移动热点到家庭宽带
  - CGNAT 到云服务器
  - 双 symmetric/address-or-port-dependent NAT
- 每个场景记录 direct success、relay fallback、首次可用路径耗时、候选来源、失败原因和日志摘要。
- 对 peer-reflexive、predicted、birthday probing、socket pool 设置预算和冷却时间，避免探测风暴。
- 当 STUN 全失败或 UDP blocked 时，明确提示用户直连将高度依赖 relay 或手动端口映射。

## P1 Relay

- 明确 relay 是 DERP-like TCP/TLS 密文转发，不是标准 TURN。
- 公网 relay 默认启用 TLS；仅本地开发允许 plaintext TCP。
- relay ticket 必须有 audience、region、过期时间和撤销路径。
- relay 诊断至少展示选中区域、endpoint、连接 RTT、pong 时间、错误码、cooldown 和候选数量。
- 对 relay 做限速、连接数限制、认证失败速率限制和日志脱敏。
- 明确 relay 可见元数据：node id、时间、包大小、连接频率；不可见业务 payload 明文。

## P1 MTU 与性能

- 默认 MTU 保持保守值，并在 CLI/GUI 中解释 `1280`、`1380`、`1420`、`1500+` 的风险差异。
- 当存在 relay 路径且 MTU 高于 `1380` 时，诊断应提示大包丢失和 PMTU blackhole 风险。
- 使用 `scripts/mtu-smoke.sh` 做可重复的 ICMP MTU smoke；后续继续补小 TCP 流、大 TCP 流、UDP payload 和 relay path。
- 后续实现自动 PMTU 探测：从安全下限开始探测，成功后提升，失败时自动回退。
- 对 IPv4 fragment、DF、ICMP fragmentation-needed 缺失和 Windows 防火墙行为补充测试说明。

## P2 控制面与协议演进

- JSON-over-HTTPS/WSS 保持消息版本字段和向后兼容策略。
- `proto/` 中的 Protobuf 只能作为草案；若切换，必须提供迁移期双栈解析和黄金样例。
- 设备身份职责保持清晰：X25519 用于数据面，Ed25519 用于控制面认证和信令绑定。
- relay catalog、candidate source、candidate expiry、network generation 必须保留可观测字段。
- QUIC 若引入，应优先评估 relay transport 或 QUIC DATAGRAM；不要把透明 L3 VPN 流量强行拆成应用层 stream。

## 发布前检查

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets

cd server
go vet ./...
go test ./... -count=1
cd ..

pnpm audit --audit-level high
pnpm run build
./scripts/control-smoke.sh
```

真实网络发布前还需要：

- 至少两个不同 NAT 环境的双向虚拟 IP 测试。
- 至少一个 relay-only 环境测试。
- 至少一次 MTU 降级测试。
- 至少一次 daemon 重启、网络切换、relay 重连和控制面短暂不可用测试。
- 更新 README、release notes 和已知限制。
