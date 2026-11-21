# P2WLAN 文档中心

欢迎查阅 P2WLAN 官方文档。P2WLAN 是一款专注于异地设备互联、游戏联机与远程访问的虚拟局域网软件。无论你是初次尝试的用户、搭建私有服务的管理员，还是关注底层架构的开发者，都可以在这里找到所需的技术文档与操作指南。

## 快速导航

### 常用指南
- [快速开始](quickstart.md)：五分钟上手，完成客户端安装、服务器连接与房间互联。
- [客户端指南](guides/client.md)：桌面端、移动端与 CLI 的使用技巧、开机自启与日常配置。
- [房间指南](guides/rooms.md)：房间成员管理、权限分配与多人联机实践。
- [自托管指南](guides/self-hosting.md)：使用 Docker 或 Linux systemd 搭建自己的 Control 与 Relay 服务端。
- [运维指南](guides/operations.md)：服务端日常管理、Web 管理控制台（Admin UI）、证书续期与监控。
- [排障指南](guides/troubleshooting.md)：常见网络问题、连接状态排查与诊断支持包导出。
- [升级与恢复](guides/upgrade-and-recovery.md)：服务端平滑升级、数据库一致性备份与灾难恢复。
- [OpenWrt 路由器指南](guides/openwrt.md)：在 OpenWrt 路由器上部署 P2WLAN 原生节点。
- [Minecraft 交互采证工具](guides/minecraft-evidence.md)：面向 Minecraft 联机场景的自动化协议交互与验证工具。

### 技术参考
- [配置参考](reference/configuration.md)：Control、Relay 与客户端的全部配置选项及说明。
- [CLI 参考](reference/cli.md)：命令行工具命令与参数速查。
- [网络参考](reference/networking.md)：NAT 穿透原理、端口预测、路径选择与 MTU 探测。
- [路径可观测性](reference/path-observability.md)：路径状态机、遥测指标与诊断数据结构。
- [兼容性参考](reference/compatibility.md)：平台支持矩阵、系统权限要求与版本说明。
- [发布契约](reference/release-contract.md)：发布构建规范、版本命名与校验清单。

### 架构与设计
- [系统架构](explanation/architecture.md)：控制面、数据面、中继面与界面的分层设计与协作。
- [安全模型](explanation/security-model.md)：身份认证、端到端数据加密与遥测隐私边界。
- [连接生命周期](explanation/connection-lifecycle.md)：节点发现、NAT 打洞、会话协商与状态维护全流程。
- [工程质量与架构边界](explanation/engineering-quality.md)：状态所有权、模块边界划分与代码质量规范。

---

> [!NOTE]
> 文档中的配置示例与命令统一采用 `example.com` 和演示参数。在实际部署或使用时，请将其替换为您自己的真实域名、IP 或密钥。
