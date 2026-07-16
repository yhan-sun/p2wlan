# P2WLAN

P2WLAN 是一个面向私有化部署的 P2P 虚拟内网系统设计稿。目标是实现高性能、跨平台、低内存、尽量原生调用系统网络 API 的虚拟局域网能力，支持节点间 P2P 通信、NAT 穿透、中继 fallback、端口映射和内网互访。

当前仓库处于文档设计阶段，后续实现建议按文档中的 MVP 路线逐步落地。

## 文档入口

- [P2PNet-Design.md](./P2PNet-Design.md): 项目总体设计文档，包含产品目标、架构、技术选型和验收标准。
- [docs/PROTOCOL.md](./docs/PROTOCOL.md): 协议与状态机草案，包含身份、信令、NAT 穿透、Relay 和端口映射协议。
- [docs/ROADMAP.md](./docs/ROADMAP.md): 分阶段开发路线图、验收标准、测试矩阵和风险控制。
- [docs/RESEARCH_NOTES.md](./docs/RESEARCH_NOTES.md): 参考项目与技术调研笔记。
- [docs/AI_IMPLEMENTATION_PROMPT.md](./docs/AI_IMPLEMENTATION_PROMPT.md): 可直接交给 Coding Agent 的实现提示词。

## 推荐实现路线

1. 先做 Rust 客户端核心：虚拟网卡抽象、Linux TUN、包读写测试。
2. 再接入用户态 WireGuard 引擎，完成同局域网内两节点虚拟 IP 通信。
3. 加入 STUN、信令服务和 UDP hole punching，实现真正 P2P。
4. 增加 Relay fallback，覆盖对称 NAT、企业网络和 UDP 受限环境。
5. 最后补齐 UI、DNS、ACL、子网路由和端口映射。

## 项目定位

P2WLAN 的目标不是一开始复制完整商业级 Tailscale/ZeroTier，而是先做一个可运行、可验证、可逐步扩展的虚拟内网内核：

- 数据面优先，确保两台机器能通过虚拟 IP 通信。
- P2P 优先，Relay 只作为失败兜底。
- 控制面集中管理，数据面端到端加密。
- 先支持 Linux/macOS/Windows 桌面端，再扩展移动端。

